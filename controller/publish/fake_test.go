package publish

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"miracache/controller/bundle"
	"miracache/controller/store"
)

func seed(first byte) ed25519.PrivateKey {
	s := make([]byte, 32)
	for i := range s {
		s[i] = first + byte(i)
	}
	return ed25519.NewKeyFromSeed(s)
}

var (
	testPub = seed(0x01)
	testSec = seed(0x21)
)

func testTrust(t *testing.T) *bundle.TrustKeys {
	t.Helper()
	tr, err := bundle.NewTrustKeys(
		bundle.TrustKey{Public: testPub.Public().(ed25519.PublicKey), Roles: []string{bundle.RolePublish}},
		bundle.TrustKey{Public: testSec.Public().(ed25519.PublicKey), Roles: []string{bundle.RoleSecurity}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

type pushRec struct {
	gen uint64
	dry bool
	at  time.Time
}

// fakeNode is a memory node's admin API (bundle_store.cpp semantics for status codes) behind a
// TLS server that demands a client certificate.
type fakeNode struct {
	t     *testing.T
	srv   *httptest.Server
	trust *bundle.TrustKeys

	mu          sync.Mutex
	id          uint64
	host        string
	gen, secGen uint64
	epoch       uint64
	hash        string
	secHash     string
	env         []byte
	secFloor    uint64        // rejects a sec_generation below this
	delay       time.Duration // POST delay (the handler gives up when the request is cancelled)
	pushStatus  int           // non-zero: answer real pushes with this status (reason "persist")
	dryStatus   int           // non-zero: answer dry runs with this status
	dryReason   string
	pushes      []pushRec
	railsJSON   string // non-empty: replaces the default rails array in /v1/identity
	down        bool   // answers every request with 503 (an unreachable node that can come back)
}

func newFakeNode(t *testing.T, trust *bundle.TrustKeys, id uint64, host string) *fakeNode {
	n := &fakeNode{t: t, trust: trust, id: id, host: host}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/identity", n.handleIdentity)
	mux.HandleFunc("/v1/bundle", n.handleBundle)
	n.srv = httptest.NewUnstartedServer(mux)
	n.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	n.srv.StartTLS()
	t.Cleanup(n.srv.Close)
	return n
}

func (n *fakeNode) admin() string { return n.srv.Listener.Addr().String() }

func (n *fakeNode) client() *NodeClient {
	c := n.srv.Client() // trusts the test certificate
	tr := c.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{n.srv.TLS.Certificates[0]} // mTLS: present a client cert
	return &NodeClient{HTTP: &http.Client{Transport: tr}}
}

func (n *fakeNode) handleIdentity(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		reply(w, 503, "down", "node down")
		return
	}
	rails := n.railsJSON
	if rails == "" {
		rails = fmt.Sprintf(`[{"addr":"10.9.0.%d:7471","subnet":"10.9.0.0/24","protocol":"roce","up":true}]`, n.id%250)
	}
	fmt.Fprintf(w, `{"node_id":%d,"hostname":%q,"addr":"10.9.0.%d:7471","admin":%q,"rails":%s,"generation":%d,"applied_generation":%d,"applied_hash":%q,"sec_generation":%d,"sec_hash":%q,"epoch":%d}`,
		n.id, n.host, n.id%250, n.admin(), rails, n.gen, n.gen, n.hash, n.secGen, n.secHash, n.epoch)
}

func reply(w http.ResponseWriter, code int, reason, detail string) {
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q,"reason":%q}`, detail, reason)
}

func (n *fakeNode) handleBundle(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	down := n.down
	n.mu.Unlock()
	if down {
		reply(w, 503, "down", "node down")
		return
	}
	if r.Method == http.MethodGet {
		n.mu.Lock()
		env := n.env
		n.mu.Unlock()
		if env == nil {
			reply(w, 404, "no_bundle", "none")
			return
		}
		w.Write(env)
		return
	}
	body, _ := io.ReadAll(r.Body)
	dry := r.URL.Query().Get("dry_run") == "1"
	n.mu.Lock()
	delay := n.delay
	n.mu.Unlock()
	if delay > 0 && !dry {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	b, err := bundle.Open(n.trust, body)
	n.mu.Lock()
	defer n.mu.Unlock()
	if err != nil {
		reply(w, 400, bundle.ReasonOf(err), err.Error())
		return
	}
	n.pushes = append(n.pushes, pushRec{b.Body.Generation, dry, time.Now()})
	if dry && n.dryStatus != 0 {
		reply(w, n.dryStatus, n.dryReason, "dry run refused")
		return
	}
	if sg := b.Sec.SecGeneration; sg < max(n.secGen, n.secFloor) {
		reply(w, 409, bundle.ReasonSecGenerationLower, "sec_generation below the floor")
		return
	} else if sg == n.secGen && n.secHash != "" && n.secHash != b.SecHash {
		reply(w, 409, bundle.ReasonSecEqualGeneration, "sec differs at an equal sec_generation")
		return
	}
	switch g := b.Body.Generation; {
	case g < n.gen:
		reply(w, 409, bundle.ReasonGenerationLower, "generation below the floor")
		return
	case g == n.gen && n.hash != "" && n.hash != b.ContentHash:
		reply(w, 409, bundle.ReasonEqualGeneration, "equal generation, other hash")
		return
	}
	if dry {
		fmt.Fprint(w, `{"result":"dry_run_ok"}`)
		return
	}
	if n.pushStatus != 0 {
		reply(w, n.pushStatus, "persist", "cannot persist")
		return
	}
	n.gen, n.secGen, n.epoch = b.Body.Generation, b.Sec.SecGeneration, b.Body.Membership.Epoch
	n.hash, n.secHash, n.env = b.ContentHash, b.SecHash, append([]byte(nil), body...)
	fmt.Fprint(w, `{"result":"applied"}`)
}

func (n *fakeNode) set(f func(*fakeNode)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	f(n)
}

func (n *fakeNode) applied() (gen uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.gen
}

// realPushes returns the non-dry pushes received.
func (n *fakeNode) realPushes() []pushRec {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []pushRec
	for _, p := range n.pushes {
		if !p.dry {
			out = append(out, p)
		}
	}
	return out
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type rig struct {
	t     *testing.T
	st    *store.Store
	p     *Publisher
	log   *syncBuf
	nodes []*fakeNode
	now   time.Time
	dir   string
}

// newRig starts one fake node per host and a Publisher whose store already lists the first
// `members` nodes as desired members.
func newRig(t *testing.T, hosts []string, members int) *rig {
	t.Helper()
	trust := testTrust(t)
	r := &rig{t: t, log: &syncBuf{}, now: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)}
	for i, h := range hosts {
		r.nodes = append(r.nodes, newFakeNode(t, trust, uint64(1000+i), h))
	}
	r.dir = t.TempDir()
	st, err := store.Open(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r.st = st
	var desired []store.DesiredNode
	for _, n := range r.nodes[:members] {
		desired = append(desired, store.DesiredNode{Admin: n.admin(), Weight: 1, State: "active"})
	}
	if err := st.Commit(0, store.State{Nodes: desired}); err != nil {
		t.Fatal(err)
	}
	r.p = New(Config{Store: st, Trust: trust, PublishKey: testPub, SecurityKey: testSec,
		Client: r.nodes[0].client(), Author: "spiffe://ops/controller", AckWait: 400 * time.Millisecond,
		Now: func() time.Time { return r.now }, Log: slog.New(slog.NewTextHandler(r.log, nil))})
	return r
}

func (r *rig) publish(ch Change) (*Result, error) {
	return r.p.Publish(context.Background(), ch)
}

func (r *rig) state() store.State {
	s, err := r.st.Load()
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func mustJSON(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
