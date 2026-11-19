// Package store is the controller's file store (membership plan decision 12, P30).
//
// One controller instance per cluster: Open takes flock(LOCK_EX|LOCK_NB) on <dir>/store.lock and
// holds it until Close (the process lifetime); a second instance gets ErrLocked. There is no
// lease and no standby. State lives in <dir>/state.json, written atomically (tmp + fsync +
// rename + directory fsync). Every write is a compare-and-swap on the generation, under the lock.
//
// Backup (the operator's duty): copy the whole store directory (state.json; store.lock is only a
// lock) and the signing keys while the controller is stopped or between publishes; state.json is
// replaced atomically, so a copy of the file alone is always consistent. To rebuild a lost
// state.json run `mira-controller --recover-from <admin addr of the node with the highest
// sec_generation>`, which imports that node's bundle.current. The signing keys cannot be
// recovered from a node and must come from backup.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"miracache/controller/bundle"
)

// HistoryLen is how many published bodies the store keeps (for rollback, MB8b).
const HistoryLen = 16

var (
	// ErrLocked: another controller instance holds store.lock.
	ErrLocked = errors.New("store: another controller instance holds the store lock")
	// ErrConflict: the generation in the store is not the one the caller expected (CAS failed).
	ErrConflict = errors.New("store: generation conflict")
)

// DesiredNode is operator intent for one memory node, keyed by its admin address. The node ID is
// never stored as input: the controller learns it from GET /v1/identity.
type DesiredNode struct {
	Admin  string `json:"admin"`
	Weight uint64 `json:"weight"`
	Zone   string `json:"zone,omitempty"`
	State  string `json:"state"` // active | draining | readonly
	// DrainSince (RFC 3339) is when the drain started; the drain timers (MB9) run from it, so a
	// controller restart resumes mid-drain from the store.
	DrainSince string `json:"drain_since,omitempty"`
}

// State is the content of state.json.
type State struct {
	Generation    uint64             `json:"generation"`     // last committed bundle generation
	SecGeneration uint64             `json:"sec_generation"` // sec_generation of the last committed sec
	Nodes         []DesiredNode      `json:"nodes"`
	Principals    []bundle.Principal `json:"principals,omitempty"`
	RBAC          []bundle.RBAC      `json:"rbac,omitempty"`
	ConfigTOML    string             `json:"config_toml,omitempty"` // the config.* tables, as TOML under [config]
	History       [][]byte           `json:"history,omitempty"`     // the last HistoryLen published bodies, oldest first
	LastEnvelope  []byte             `json:"last_envelope,omitempty"`
	// Retiring lists nodes the last bundle removed; the reconcile loop keeps pushing them the
	// removing bundle for a few passes (Y10).
	Retiring []Retiring `json:"retiring,omitempty"`
	// Failed lists active nodes the failure detector removed (MB9): their address is still desired,
	// so a node that returns with health OK for rejoin_ms is re-added (auto-rejoin).
	Failed []FailedNode `json:"failed,omitempty"`
	// Replaced lists (RFC 3339) when the failure detector granted a node-ID replacement; they count
	// against static stability for the removal window (MB9).
	Replaced []string `json:"replaced,omitempty"`
	// Pending is the intent record written before a publish is pushed (Y13): if the controller
	// dies between push and commit, reconcile completes the commit when a node holds the bundle.
	Pending *Pending `json:"pending,omitempty"`
}

// Clone returns a deep copy.
func (s *State) Clone() State {
	c := *s
	c.Nodes = append([]DesiredNode(nil), s.Nodes...)
	c.Principals = append([]bundle.Principal(nil), s.Principals...)
	c.RBAC = append([]bundle.RBAC(nil), s.RBAC...)
	c.History = append([][]byte(nil), s.History...)
	c.LastEnvelope = append([]byte(nil), s.LastEnvelope...)
	c.Retiring = append([]Retiring(nil), s.Retiring...)
	c.Failed = append([]FailedNode(nil), s.Failed...)
	c.Replaced = append([]string(nil), s.Replaced...)
	if s.Pending != nil {
		p := *s.Pending
		if s.Pending.Next != nil {
			n := s.Pending.Next.Clone()
			p.Next = &n
		}
		c.Pending = &p
	}
	return c
}

// Store is an open, locked store.
type Store struct {
	dir   string
	lock  *os.File
	mu    sync.Mutex
	fault func(next State) error // test hook, see SetCommitFault
}

// SetCommitFault installs a hook that Commit calls first with the state it would write; a non-nil
// error is returned instead of writing. Tests only: it injects a store I/O failure where file
// permissions cannot (the dev container runs as root). nil removes the hook.
func (s *Store) SetCommitFault(f func(next State) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fault = f
}

// Open creates dir if needed and takes the exclusive store lock. It returns ErrLocked when
// another instance holds it.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "store.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return &Store{dir: dir, lock: f}, nil
}

// Close releases the lock.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close() // closing the descriptor drops the flock
	s.lock = nil
	return err
}

func (s *Store) path() string { return filepath.Join(s.dir, "state.json") }

// Load reads state.json; a missing file is an empty State (generation 0).
func (s *Store) Load() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (State, error) {
	var st State
	b, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, fmt.Errorf("store: state.json is corrupt: %w", err)
	}
	return st, nil
}

// Commit writes next if the generation currently on disk equals expected (CAS). next.Generation
// must not be below expected (an equal generation is a state edit that publishes nothing). The
// history is trimmed to HistoryLen.
func (s *Store) Commit(expected uint64, next State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lock == nil {
		return errors.New("store: closed")
	}
	if s.fault != nil {
		if err := s.fault(next); err != nil {
			return err
		}
	}
	cur, err := s.loadLocked()
	if err != nil {
		return err
	}
	if cur.Generation != expected {
		return fmt.Errorf("%w: store is at %d, expected %d", ErrConflict, cur.Generation, expected)
	}
	if next.Generation < expected {
		return fmt.Errorf("%w: next generation %d below %d", ErrConflict, next.Generation, expected)
	}
	if n := len(next.History); n > HistoryLen {
		next.History = next.History[n-HistoryLen:]
	}
	b, err := json.MarshalIndent(&next, "", " ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path(), b)
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// RetirePasses is how many reconcile passes (5 s each, so one minute) a removed node keeps being
// pushed the removing bundle.
const RetirePasses = 12

// Retiring is a node removed from the desired state that still has to learn about it.
type Retiring struct {
	Admin  string `json:"admin"`
	Passes int    `json:"passes"` // reconcile passes left
}

// Pending is the intent record of a publish that has not been committed yet. Next is the full
// state the commit will write (with Pending nil); BodyHash is the SHA-256 of the pushed body.
type Pending struct {
	BaseGeneration uint64 `json:"base_generation"` // the store generation the commit is a CAS on
	Generation     uint64 `json:"generation"`
	BodyHash       string `json:"body_hash"`
	Next           *State `json:"next"`
}

// FailedNode is an active node removed by the failure detector. Since (RFC 3339) is the removal
// time (it also feeds the static-stability window, so a restart does not forget recent removals).
type FailedNode struct {
	Admin  string `json:"admin"`
	NodeID uint64 `json:"node_id"`
	Weight uint64 `json:"weight"`
	Zone   string `json:"zone,omitempty"`
	Since  string `json:"since"`
}
