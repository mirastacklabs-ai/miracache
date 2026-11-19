package publish

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"

	"miracache/controller/bundle"
	"miracache/controller/rbac"
	"miracache/controller/store"
)

// ReconcilePeriod is how often the reconcile loop runs (decision 12): every 5 s.
const ReconcilePeriod = 5 * time.Second

// Defaults (decision 10 and 12).
const (
	DefaultAckWait   = 2000 * time.Millisecond // publish.ack_wait_ms
	DefaultClockSkew = 300 * time.Second       // publish.clock_skew_s
)

var (
	// ErrStopped: a node rejected a push for its sec section; publishing (reconcile included) is
	// stopped until the operator runs --recover-from.
	ErrStopped = errors.New("publishing is stopped after a sec reject; run mira-controller --recover-from <admin addr of the node with the highest sec_generation>")
	// ErrJoinAborted: the new node did not ack; nothing was pushed to the others and nothing was committed.
	ErrJoinAborted = errors.New("join aborted")
	// ErrBadEdit: the caller's edit failed input validation (e.g. a drop_before later than now +
	// skew). Only errors wrapping this are client errors; any other failure, including a
	// *bundle.Error from the controller's own signing or stored state, is a server fault.
	ErrBadEdit = errors.New("invalid edit")
	// ErrDryRun: a node rejected the bundle in its dry run; nothing was pushed.
	ErrDryRun = errors.New("dry run rejected")
	// ErrNoAck: no node acked the push; nothing was committed.
	ErrNoAck = errors.New("no node acked the push")
)

// Config configures a Publisher.
type Config struct {
	Store       *store.Store
	Trust       *bundle.TrustKeys
	PublishKey  ed25519.PrivateKey // holds the publish role in Trust
	SecurityKey ed25519.PrivateKey // holds the security role in Trust (v1: online, decision 12 / Q13)
	Client      *NodeClient
	Author      string
	AckWait     time.Duration // per node call (identity, dry run, push); 0 = DefaultAckWait
	ClockSkew   time.Duration // drop_before may be at most this far ahead of now; 0 = DefaultClockSkew
	Now         func() time.Time
	Log         *slog.Logger
}

// Change describes one publish.
type Change struct {
	Reason string
	// Join adds this node (by admin address, with weight and zone); it is pushed first.
	Join *store.DesiredNode
	// Edit changes the desired state (nodes, principals, rbac, config) before the bundle is built.
	Edit func(*store.State)
	// TolerateUnreachable lets the publish go ahead without nodes whose /v1/identity fails
	// (used by the reconcile republish; they are caught up later).
	TolerateUnreachable bool
	// AllowIDChange lists admin addresses whose reported node ID may replace the one in the current
	// bundle (a granted replacement, U2-10). For every other address a changed ID is not copied.
	AllowIDChange map[string]bool
}

// Result is a completed publish.
type Result struct {
	Generation    uint64
	SecGeneration uint64
	Epoch         uint64
	Envelope      []byte
	Acked         []string // admin addresses that acked within the wait
	Lagging       []string // admin addresses that did not (reconcile re-pushes them)
}

// Publisher is the single writer of the cluster. Publish and the reconcile loop share one mutex.
type Publisher struct {
	cfg     Config
	mu      sync.Mutex
	stopped atomic.Bool
	seen    map[string]Identity // last identity per admin address, for log lines
	visible []byte              // the envelope clients may see (after the ack wait)
}

// New returns a Publisher.
func New(cfg Config) *Publisher {
	if cfg.AckWait == 0 {
		cfg.AckWait = DefaultAckWait
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = DefaultClockSkew
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Publisher{cfg: cfg, seen: map[string]Identity{}}
}

// Stopped reports whether publishing was stopped by a sec reject.
func (p *Publisher) Stopped() bool { return p.stopped.Load() }

// Visible returns the envelope that became client-visible (decision 10 step 6): the last publish,
// after its ack wait.
func (p *Publisher) Visible() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.visible...)
}

// nodeAttrs are the log attributes of a memory node: ID, hostname and IP (decision 15).
func (p *Publisher) nodeAttrs(admin string) []any {
	id, ok := p.seen[admin]
	if !ok {
		return []any{"node_id", "unknown", "host", "unknown", "addr", hostOf(admin)}
	}
	return []any{"node_id", id.NodeID, "host", id.Hostname, "addr", hostOf(admin)}
}

func (p *Publisher) logNode(level slog.Level, admin, msg string, kv ...any) {
	p.cfg.Log.Log(context.Background(), level, msg, append(p.nodeAttrs(admin), kv...)...)
}

// fanout runs fn for every key concurrently.
func fanout[T any](keys []string, fn func(string) T) map[string]T {
	out := make(map[string]T, len(keys))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, k := range keys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v := fn(k)
			mu.Lock()
			out[k] = v
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

type idResult struct {
	id  *Identity
	err error
}

// identities polls GET /v1/identity on every admin address.
func (p *Publisher) identities(ctx context.Context, admins []string) map[string]idResult {
	res := fanout(admins, func(a string) idResult {
		cctx, cancel := context.WithTimeout(ctx, p.cfg.AckWait)
		defer cancel()
		id, err := p.cfg.Client.Identity(cctx, a)
		return idResult{id, err}
	})
	for a, r := range res {
		if r.err == nil {
			p.seen[a] = *r.id
		}
	}
	return res
}

func (p *Publisher) push(ctx context.Context, admin string, env []byte, dryRun bool) error {
	cctx, cancel := context.WithTimeout(ctx, p.cfg.AckWait)
	defer cancel()
	return p.cfg.Client.Push(cctx, admin, env, dryRun)
}

// stopForSec stops publishing and logs the remedy (Q06): the store is behind the cluster's
// security state. highest is the admin address of the node with the highest sec_generation.
func (p *Publisher) stopForSec(rejecter string, highest string, err error) error {
	p.stopped.Store(true)
	p.logNode(slog.LevelError, rejecter, "ALERT: node rejected the push for its sec section; the controller store is behind the cluster; publishing stopped",
		"err", err, "remedy", "mira-controller --recover-from "+highest)
	return fmt.Errorf("%w (rejected by %s: %v)", ErrStopped, rejecter, err)
}

// highestSec returns the admin address with the highest sec_generation among ids ("" if none).
func highestSec(ids map[string]idResult, exclude string) (string, uint64) {
	best, bestGen := "", uint64(0)
	keys := sortedKeys(ids)
	for _, a := range keys {
		r := ids[a]
		if a != exclude && r.err == nil && (best == "" || r.id.SecGeneration > bestGen) {
			best, bestGen = a, r.id.SecGeneration
		}
	}
	return best, bestGen
}

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for a := range m {
		k = append(k, a)
	}
	sort.Strings(k)
	return k
}

type viewEntry struct {
	id     uint64
	weight uint64
	zone   string
}

func viewOf(nodes []bundle.Node) []viewEntry {
	var v []viewEntry
	for _, n := range nodes {
		if n.State == "active" {
			v = append(v, viewEntry{n.NodeID, n.Weight, n.Zone})
		}
	}
	sort.Slice(v, func(i, j int) bool { return v[i].id < v[j].id })
	return v
}

func equalViews(a, b []viewEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// lastBundle parses the store's last envelope; nil if there is none.
func lastBundle(st *store.State) (*bundle.Envelope, *bundle.Body, error) {
	if len(st.LastEnvelope) == 0 {
		return nil, nil, nil
	}
	env, err := bundle.ParseEnvelope(st.LastEnvelope)
	if err != nil {
		return nil, nil, fmt.Errorf("store: last envelope: %w", err)
	}
	body, err := bundle.ParseBody(env.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("store: last envelope: %w", err)
	}
	return env, body, nil
}

func parseConfig(src string) (map[string]any, error) {
	if strings.TrimSpace(src) == "" {
		return nil, nil
	}
	var doc struct {
		Config map[string]any `toml:"config"`
	}
	if _, err := toml.Decode(src, &doc); err != nil {
		return nil, fmt.Errorf("store config_toml: %w", err)
	}
	return doc.Config, nil
}

// Publish builds, dry-runs, signs and pushes the next bundle (decisions 10 and 12).
func (p *Publisher) Publish(ctx context.Context, ch Change) (*Result, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.publishLocked(ctx, ch)
}

func (p *Publisher) publishLocked(ctx context.Context, ch Change) (*Result, error) {
	if p.stopped.Load() {
		return nil, ErrStopped
	}
	cur, err := p.cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	// Y13: finish or discard an earlier publish first. An unresolved record (a node unreachable, no
	// reachable node holding it) is superseded by this publish (Z03): it is replaced by this publish's
	// intent record, and this publish moves above its generation, sec_generation and epoch, so a node
	// that later returns holding it is simply behind (a re-push) and never sees a number reused.
	var floor *pendingFloor
	if cur.Pending != nil {
		if floor, err = p.resolvePending(ctx, &cur); err != nil {
			return nil, err
		}
	}
	next := cur.Clone()
	joinAdmin := ""
	if ch.Join != nil {
		j := *ch.Join
		for _, n := range next.Nodes {
			if n.Admin == j.Admin {
				return nil, fmt.Errorf("node %s is already a member", j.Admin)
			}
		}
		if j.Weight == 0 {
			j.Weight = 1
		}
		if j.State == "" {
			j.State = "active"
		}
		next.Nodes = append(next.Nodes, j)
		joinAdmin = j.Admin
	}
	if ch.Edit != nil {
		ch.Edit(&next)
	}
	if len(next.Nodes) == 0 {
		return nil, errors.New("no desired nodes")
	}
	sort.Slice(next.Nodes, func(i, j int) bool { return next.Nodes[i].Admin < next.Nodes[j].Admin })
	admins := make([]string, len(next.Nodes))
	for i, n := range next.Nodes {
		admins[i] = n.Admin
	}

	// 1. Learn every node's identity. An unreachable node aborts the publish (its ID is not
	// learnable), unless the change tolerates it and the node is not the one joining.
	ids := p.identities(ctx, admins)
	lastEnv, lastBody, err := lastBundle(&cur)
	if err != nil {
		return nil, err
	}
	var live []string
	for _, a := range admins {
		if ids[a].err != nil {
			if !ch.TolerateUnreachable || a == joinAdmin {
				return nil, fmt.Errorf("node %s unreachable: %w", a, ids[a].err)
			}
			p.logNode(slog.LevelWarn, a, "node unreachable; publishing without it", "err", ids[a].err)
			continue
		}
		live = append(live, a)
	}

	// 2. Next generation (P11) and next sec_generation (Q06).
	base := cur.Generation
	baseSec := cur.SecGeneration
	baseEpoch := uint64(0)
	if lastBody != nil {
		baseEpoch = lastBody.Membership.Epoch
	}
	for _, a := range live {
		id := ids[a].id
		base = max(base, id.AppliedGeneration)
		baseSec = max(baseSec, id.SecGeneration)
		baseEpoch = max(baseEpoch, id.Epoch)
	}
	if floor != nil {
		base = max(base, floor.gen)
		baseSec = max(baseSec, floor.sec)
		baseEpoch = max(baseEpoch, floor.epoch)
	}
	gen := base + 1
	if !bundle.ValidGeneration(gen) {
		return nil, fmt.Errorf("generation %d out of range 1..2^63-1", gen)
	}
	sec := &bundle.Sec{SecGeneration: cur.SecGeneration, Principals: next.Principals, RBAC: next.RBAC}
	secChanged := true
	var prevRBAC []bundle.RBAC
	prevDrop := map[string]string{} // principal name -> drop_before in the stored sec
	if lastEnv != nil {
		if lastSec, perr := bundle.ParseSec(lastEnv.Sec); perr == nil {
			sec.SecGeneration = lastSec.SecGeneration
			prevRBAC = lastSec.RBAC
			for _, lp := range lastSec.Principals {
				prevDrop[lp.Name] = lp.DropBefore
			}
			a, e1 := bundle.EmitSec(sec)
			b, e2 := bundle.EmitSec(lastSec)
			secChanged = e1 != nil || e2 != nil || string(a) != string(b)
		}
	}
	if floor != nil && floor.sec > cur.SecGeneration {
		// The superseded record carried a newer sec_generation: re-sign above it, or a node holding it
		// would refuse the old sec as lower.
		secChanged = true
	}
	if secChanged {
		sec.SecGeneration = baseSec + 1
		if !bundle.ValidGeneration(sec.SecGeneration) {
			return nil, fmt.Errorf("sec_generation %d out of range", sec.SecGeneration)
		}
	}
	if secChanged {
		// P03: every new sec keeps at least one security-admin, and only known roles.
		if err := rbac.CheckTransition(prevRBAC, next.RBAC); err != nil {
			return nil, err
		}
	}
	now := p.cfg.Now().UTC()
	// H09: only a drop_before this edit introduces or changes can be the caller's fault. A stored value that is
	// unchanged and now looks "in the future" (the controller clock stepped back) is accepted with a warning, so
	// the cluster stays publishable.
	edited := &bundle.Sec{SecGeneration: sec.SecGeneration, RBAC: sec.RBAC, Principals: make([]bundle.Principal, 0, len(sec.Principals))}
	for _, pr := range sec.Principals {
		if old, had := prevDrop[pr.Name]; had && old == pr.DropBefore && pr.DropBefore != "" {
			if err := bundle.CheckDropBeforeNotFuture(&bundle.Sec{Principals: []bundle.Principal{pr}}, now, p.cfg.ClockSkew); err != nil {
				p.cfg.Log.Warn("stored drop_before is later than now + skew (controller clock stepped back?); keeping it unchanged",
					"principal", pr.Name, "drop_before", pr.DropBefore, "now", now.Format(time.RFC3339), "err", err)
			}
			pr.DropBefore = ""
		}
		edited.Principals = append(edited.Principals, pr)
	}
	if err := bundle.CheckDropBeforeNotFuture(edited, now, p.cfg.ClockSkew); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadEdit, err)
	}

	// 3. Membership: IDs, hostnames and rails come from the nodes, never from the operator.
	var nodes []bundle.Node
	for _, d := range next.Nodes {
		n := bundle.Node{Admin: d.Admin, Weight: d.Weight, Zone: d.Zone, State: d.State}
		useOld := ids[d.Admin].err != nil
		if !useOld {
			id := ids[d.Admin].id
			rails, rerr := railsOf(id, d.Admin)
			switch {
			case rerr == nil && idChangeHeld(lastBody, d.Admin, id.NodeID, ch.AllowIDChange):
				// U2-10: the address reports another ID than the bundle has and nobody granted the
				// replacement (the failure detector holds it under static stability): keep the old entry.
				p.logNode(slog.LevelWarn, d.Admin, "node reports a new ID without a granted replacement; keeping its entry from the current bundle", "reported_id", id.NodeID)
				useOld = true
			case rerr == nil:
				n.NodeID, n.Hostname, n.Rails = id.NodeID, id.Hostname, rails
			case ch.TolerateUnreachable && d.Admin != joinAdmin && lastBundleHas(lastBody, d.Admin):
				// A reconcile republish keeps the node's existing entry from the current bundle.
				p.logNode(slog.LevelWarn, d.Admin, "node reports unusable rails; keeping its entry from the current bundle", "err", rerr)
				useOld = true
			default:
				return nil, fmt.Errorf("rails: %w", rerr)
			}
		}
		if useOld {
			found := false
			if lastBody != nil {
				for _, o := range lastBody.Membership.Nodes {
					if o.Admin == d.Admin {
						n.NodeID, n.Hostname, n.Rails, found = o.NodeID, o.Hostname, o.Rails, true
					}
				}
			}
			if !found {
				continue
			}
		}
		nodes = append(nodes, n)
	}
	m := bundle.Membership{Nodes: nodes}
	curView := viewOf(nodes)
	switch {
	case lastBody == nil:
		m.Epoch, m.PreviousEpoch = baseEpoch+1, baseEpoch
	case !equalViews(curView, viewOf(lastBody.Membership.Nodes)) || baseEpoch > lastBody.Membership.Epoch:
		// Y09: a node above the last body's epoch (a second writer) names another view at that
		// number, so an unchanged view still moves to baseEpoch + 1.
		m.Epoch, m.PreviousEpoch = baseEpoch+1, baseEpoch
		for _, v := range viewOf(lastBody.Membership.Nodes) {
			m.Previous = append(m.Previous, bundle.PreviousNode{NodeID: v.id, Weight: v.weight, Zone: v.zone})
		}
	default:
		m.Epoch = baseEpoch
		m.PreviousEpoch = lastBody.Membership.PreviousEpoch
		m.Previous = lastBody.Membership.Previous
	}
	cfgTables, err := parseConfig(next.ConfigTOML)
	if err != nil {
		return nil, err
	}
	body := &bundle.Body{SchemaVersion: 1, Generation: gen, CreatedAt: now.Format("2006-01-02T15:04:05Z"),
		Author: p.cfg.Author, Reason: ch.Reason, Membership: m, Config: cfgTables}
	if r, ok := body.Replicas(); ok {
		zones := map[string]bool{}
		for _, v := range curView {
			zones[v.zone] = true
		}
		if int(r) > len(curView)-1 || (curView != nil && curView[0].zone != "" && int(r) > len(zones)) {
			p.cfg.Log.Warn("replicas exceeds what the current view can place (a shorter owner set is used)",
				"replicas", r, "active_nodes", len(curView), "zones", len(zones))
		}
	}

	// 4. Build and sign. A publish-only bundle carries the old sec bytes and signature unchanged.
	bodyBytes, err := bundle.EmitBody(body)
	if err != nil {
		return nil, err
	}
	var env *bundle.Envelope
	if secChanged {
		secBytes, serr := bundle.EmitSec(sec)
		if serr != nil {
			return nil, serr
		}
		env = bundle.Sign(p.cfg.PublishKey, p.cfg.SecurityKey, secBytes, bodyBytes)
	} else {
		env = bundle.SignPublishOnly(p.cfg.PublishKey, lastEnv, bodyBytes)
	}
	raw := env.Marshal()
	if _, err := bundle.Open(p.cfg.Trust, raw); err != nil {
		return nil, fmt.Errorf("the controller built a bundle its own trust file refuses: %w", err)
	}
	highest, _ := highestSec(ids, joinAdmin)

	// 5. Dry run against every live node before anything is published (P16). A refusal by the
	// joining node aborts the join only (Y14); a sec reject from any other node stops publishing.
	dry := fanout(live, func(a string) error { return p.push(ctx, a, raw, true) })
	for _, a := range live {
		if err := dry[a]; err != nil {
			if a == joinAdmin {
				p.logNode(slog.LevelError, a, "join aborted: the new node refused the dry run; nothing was published", "err", err)
				return nil, fmt.Errorf("%w: new node %s: %v", ErrJoinAborted, a, err)
			}
			if pe := asPushError(err); pe != nil && pe.IsSecReject() {
				return nil, p.stopForSec(a, highest, err)
			}
			p.logNode(slog.LevelError, a, "dry run rejected; nothing was published", "err", err)
			return nil, fmt.Errorf("%w by %s: %v", ErrDryRun, a, err)
		}
	}

	// 6. The state the commit writes, and the intent record written before anything is pushed (Y13).
	// Nodes the last body had and this one does not still get the removing bundle (Y10).
	inNext := map[string]bool{}
	for _, d := range next.Nodes {
		inNext[d.Admin] = true
	}
	var removed []string
	if lastBody != nil {
		for _, o := range lastBody.Membership.Nodes {
			if !inNext[o.Admin] {
				removed = append(removed, o.Admin)
			}
		}
	}
	final := next.Clone()
	final.Generation, final.SecGeneration = gen, sec.SecGeneration
	final.History = append(final.History, bodyBytes)
	final.LastEnvelope = raw
	final.Pending = nil
	final.Retiring = nil
	for _, r := range cur.Retiring {
		if !inNext[r.Admin] {
			final.Retiring = append(final.Retiring, r)
		}
	}
	for _, a := range removed {
		final.Retiring = append(final.Retiring, store.Retiring{Admin: a, Passes: store.RetirePasses})
	}
	intent := cur.Clone()
	intent.Pending = &store.Pending{BaseGeneration: cur.Generation, Generation: gen, BodyHash: bundle.HashHex(bodyBytes), Next: &final}
	if err := p.cfg.Store.Commit(cur.Generation, intent); err != nil {
		return nil, fmt.Errorf("writing the intent record: %w", err)
	}
	clearPending := func() {
		// Restores the store as loaded: no record, or the unresolved one this publish superseded (Z03).
		if err := p.cfg.Store.Commit(cur.Generation, cur.Clone()); err != nil {
			p.cfg.Log.Error("could not clear the intent record", "err", err)
		}
	}
	commit := func() error { return p.cfg.Store.Commit(cur.Generation, final) }
	res := &Result{Generation: gen, SecGeneration: sec.SecGeneration, Epoch: m.Epoch, Envelope: raw}

	// 7. Join: the NEW node first; without its ack the join aborts (Q05). A sec reject from the new
	// node aborts the join only: the new node's state says nothing about the cluster's.
	rest := live
	if joinAdmin != "" {
		if err := p.push(ctx, joinAdmin, raw, false); err != nil {
			clearPending()
			p.logNode(slog.LevelError, joinAdmin, "join aborted: the new node did not ack; nothing was pushed to the others and nothing was committed", "err", err)
			return nil, fmt.Errorf("%w: new node %s: %v", ErrJoinAborted, joinAdmin, err)
		}
		res.Acked = append(res.Acked, joinAdmin)
		if err := commit(); err != nil {
			// The intent record stays: the reconcile loop sees the node holding it and completes the commit.
			p.logNode(slog.LevelError, joinAdmin, "ALERT: the new node acked but the store commit failed; reconcile will complete it from the intent record", "err", err)
			return nil, err
		}
		rest = nil
		for _, a := range live {
			if a != joinAdmin {
				rest = append(rest, a)
			}
		}
	}

	// 8. Push to the rest and wait for the acks.
	pushed := fanout(rest, func(a string) error { return p.push(ctx, a, raw, false) })
	var secErr error
	secNode := ""
	for _, a := range rest {
		err := pushed[a]
		if err == nil {
			res.Acked = append(res.Acked, a)
			continue
		}
		res.Lagging = append(res.Lagging, a)
		p.logNode(slog.LevelWarn, a, "push not acked; the reconcile loop will retry", "generation", gen, "err", err)
		if pe := asPushError(err); pe != nil && pe.IsSecReject() && secErr == nil {
			secErr, secNode = err, a
		}
	}
	if joinAdmin == "" {
		if len(res.Acked) == 0 {
			clearPending()
			if secErr != nil {
				return nil, p.stopForSec(secNode, highest, secErr)
			}
			return nil, fmt.Errorf("%w (generation %d)", ErrNoAck, gen)
		}
		if err := commit(); err != nil {
			p.cfg.Log.Error("ALERT: nodes acked but the store commit failed; reconcile will complete it from the intent record", "generation", gen, "err", err)
			return nil, err
		}
	}
	// Best effort: tell the removed nodes (no ack needed; the reconcile loop keeps trying for a while).
	if len(removed) > 0 {
		gone := fanout(removed, func(a string) error { return p.push(ctx, a, raw, false) })
		for _, a := range removed {
			if gone[a] != nil {
				p.logNode(slog.LevelWarn, a, "removing bundle not delivered; reconcile will retry", "err", gone[a])
			}
		}
	}
	sort.Strings(res.Acked)
	sort.Strings(res.Lagging)
	p.visible = raw // step 6 of the join: visible after the ack wait
	p.cfg.Log.Info("published", "generation", gen, "sec_generation", sec.SecGeneration, "epoch", m.Epoch,
		"acked", len(res.Acked), "lagging", len(res.Lagging))
	if secErr != nil {
		return res, p.stopForSec(secNode, highest, secErr)
	}
	return res, nil
}

// pendingFloor is what an unresolved intent record may have reached on an unreachable node: the
// numbers the next publish must move above (Z03).
type pendingFloor struct {
	gen, sec, epoch uint64
}

// resolvePending settles the intent record of an earlier publish (Y13). If a node holds exactly the
// pushed body, the push happened: the commit is completed (a store error other than a CAS conflict
// keeps the record and is returned, Z07). If every node was reached and none holds it, the record is
// discarded. Otherwise (a node unreachable) the record stays, st is unchanged, and the floor of the
// record is returned: reconcile carries on without completing it, and the next publish supersedes it.
func (p *Publisher) resolvePending(ctx context.Context, st *store.State) (*pendingFloor, error) {
	pd := st.Pending
	if pd == nil {
		return nil, nil
	}
	seen := map[string]bool{}
	var admins []string
	for _, n := range append(append([]store.DesiredNode(nil), st.Nodes...), pd.Next.Nodes...) {
		if !seen[n.Admin] {
			seen[n.Admin] = true
			admins = append(admins, n.Admin)
		}
	}
	ids := p.identities(ctx, admins)
	held, reached := "", true
	for _, a := range sortedKeys(ids) {
		r := ids[a]
		if r.err != nil {
			reached = false
			continue
		}
		if r.id.AppliedGeneration == pd.Generation && r.id.AppliedHash == pd.BodyHash && held == "" {
			held = a
		}
	}
	switch {
	case held != "":
		err := p.cfg.Store.Commit(pd.BaseGeneration, *pd.Next)
		switch {
		case err == nil:
			p.logNode(slog.LevelWarn, held, "ALERT: completed the store commit of a publish that was pushed before the controller stopped", "generation", pd.Generation)
		case errors.Is(err, store.ErrConflict):
			// The store moved past the record's base: the record can never be completed.
			c := st.Clone()
			c.Pending = nil
			if cerr := p.cfg.Store.Commit(st.Generation, c); cerr != nil {
				return nil, fmt.Errorf("intent record %d: %v; clearing it: %w", pd.Generation, err, cerr)
			}
			p.cfg.Log.Error("ALERT: intent record could not be completed and was discarded", "generation", pd.Generation, "err", err)
		default:
			// Z07: a node acked this body; discarding the record would revert an acked change. Keep it.
			p.logNode(slog.LevelError, held, "ALERT: could not complete the store commit of an acked publish; the intent record is kept", "generation", pd.Generation, "err", err)
			return nil, fmt.Errorf("completing intent record %d: %w", pd.Generation, err)
		}
	case reached:
		c := st.Clone()
		c.Pending = nil
		if err := p.cfg.Store.Commit(st.Generation, c); err != nil {
			return nil, err
		}
		p.cfg.Log.Warn("discarded an intent record no node holds", "generation", pd.Generation)
	default:
		f := &pendingFloor{gen: pd.Generation}
		if pd.Next != nil {
			f.sec = pd.Next.SecGeneration
			if _, b, err := lastBundle(pd.Next); err == nil && b != nil {
				f.epoch = b.Membership.Epoch
			}
		}
		p.cfg.Log.Warn("intent record unresolved (a node is unreachable); carrying on without completing it, the next publish supersedes it",
			"generation", pd.Generation)
		return f, nil
	}
	fresh, err := p.cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	*st = fresh
	return nil, nil
}

func lastBundleHas(b *bundle.Body, admin string) bool {
	if b == nil {
		return false
	}
	for _, n := range b.Membership.Nodes {
		if n.Admin == admin {
			return true
		}
	}
	return false
}

// idChangeHeld reports whether admin is in the last body under another node ID than reported and the
// change was not granted.
func idChangeHeld(b *bundle.Body, admin string, reported uint64, allow map[string]bool) bool {
	if b == nil || allow[admin] {
		return false
	}
	for _, n := range b.Membership.Nodes {
		if n.Admin == admin {
			return n.NodeID != reported
		}
	}
	return false
}
