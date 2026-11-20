// Package membership is the controller's failure detector and drain engine.
//
// A Monitor polls GET /v1/identity on every desired member once a second (800 ms timeout), takes
// client reports (attributed to the caller's mTLS identity by controller/api), applies the failure
// rules of design spec section 7.4 and runs the drain timers. Every change it makes (a removal, a
// rejoin, a drain step, a leave) is an ordinary publish through controller/publish, so each one is a
// signed, dry-run-checked bundle. The Monitor keeps only observations in memory; everything that
// must survive a controller restart (drain start, recently failed nodes) lives in the store.
//
// Failure rules, over membership.fail_timeout_ms (default 10 s), for every desired member:
//
//	(a) the health poll has been failing for the whole timeout AND no client reports a working rail;
//	(b) the node itself reports every rail down (identity rails[].up) for the whole timeout;
//	(c) at least half of the clients connected to it, and at least 2 distinct mTLS identities,
//	    report every rail unreachable while they still reach other nodes, for the whole timeout.
//
// One identity is one vote however many reports or hosts it claims. Static stability: at most
// max(1, floor(N * max_remove_fraction)) removals per window; beyond that a node is pending_removal
// until an operator confirms (ConfirmRemove). The last member is never removed.
package membership

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"miracache/controller/bundle"
	"miracache/controller/publish"
	"miracache/controller/store"
)

// Defaults.
const (
	DefaultPollEvery         = 1000 * time.Millisecond
	DefaultPollTimeout       = 800 * time.Millisecond
	DefaultFailTimeout       = 10 * time.Second  // membership.fail_timeout_ms
	DefaultMaxRemoveFraction = 1.0 / 3.0         // membership.max_remove_fraction
	DefaultRejoin            = 10 * time.Second  // rejoin_ms
	DefaultReportFresh       = 6 * time.Second   // three report periods (clients report every 2 s)
	DefaultDrainContinue     = 60 * time.Second  // drain.continue_ms
	DefaultDrainMax          = 900 * time.Second // drain.max_ms
	replacePolls             = 2                 // consecutive polls that must show the new ID
	DefaultMaxReporters      = 1024
	DefaultRemoveWindow      = 10 * time.Minute
)

// Publisher is the part of publish.Publisher the Monitor uses.
type Publisher interface {
	Publish(ctx context.Context, ch publish.Change) (*publish.Result, error)
}

// Config configures a Monitor.
type Config struct {
	Store  *store.Store
	Pub    Publisher
	Client *publish.NodeClient

	PollEvery   time.Duration
	PollTimeout time.Duration
	FailTimeout time.Duration
	// RemoveWindow is how long a replacement counts against the removal budget (default 10 min).
	// Failure removals count until the node rejoins or an operator forgets or confirms it.
	RemoveWindow time.Duration
	MaxReporters int // distinct report identities kept (default 1024)
	// Audit records the Monitor's automatic actions (actor "local"); nil = not audited.
	Audit             Auditor
	MaxRemoveFraction float64
	Rejoin            time.Duration
	ReportFresh       time.Duration
	DrainContinue     time.Duration
	DrainMax          time.Duration

	Now func() time.Time
	Log *slog.Logger
}

// Node states in mira_controller_node_state.
const (
	StateHealthy        = "healthy"
	StateSuspect        = "suspect" // a rule's clock is running
	StatePendingRemoval = "pending_removal"
	StateDraining       = "draining"
	StateReadonly       = "readonly"
	StateRemoved        = "removed" // failed; address still desired
	StateRejoining      = "rejoining"
)

type nodeRec struct {
	firstSeen      time.Time
	lastOK         time.Time
	pollOK         bool
	id             *publish.Identity // last successful reply
	railsDownSince time.Time
	healthySince   time.Time
	cSince         time.Time
	idDiff         int
	lastErr        error
}

type pendingInfo struct {
	rule     string
	replaced bool
}

type nodeStat struct {
	nodeID   uint64
	hostname string
	state    string
}

// Monitor is the failure detector and drain engine.
type Monitor struct {
	cfg    Config
	tickMu sync.Mutex // one decision at a time (ticks, ConfirmRemove, Drain)

	mu        sync.Mutex // guards everything below (readers: Submit, WriteMetrics)
	recs      map[string]*nodeRec
	reports   map[string]*clientReport
	pending   map[string]pendingInfo
	drainSeen map[string]time.Time // fallback drain start for a draining node the store has no stamp for
	stats     map[string]nodeStat
	removed   map[string]uint64 // removals by rule, for the counter
	aeadAcc   map[string]*aeadAcc
}

// New returns a Monitor.
func New(cfg Config) *Monitor {
	if cfg.PollEvery == 0 {
		cfg.PollEvery = DefaultPollEvery
	}
	if cfg.PollTimeout == 0 {
		cfg.PollTimeout = DefaultPollTimeout
	}
	if cfg.FailTimeout == 0 {
		cfg.FailTimeout = DefaultFailTimeout
	}
	if cfg.RemoveWindow == 0 {
		cfg.RemoveWindow = DefaultRemoveWindow
	}
	if cfg.MaxReporters == 0 {
		cfg.MaxReporters = DefaultMaxReporters
	}
	if cfg.MaxRemoveFraction == 0 {
		cfg.MaxRemoveFraction = DefaultMaxRemoveFraction
	}
	if cfg.Rejoin == 0 {
		cfg.Rejoin = DefaultRejoin
	}
	if cfg.ReportFresh == 0 {
		cfg.ReportFresh = DefaultReportFresh
	}
	if cfg.DrainContinue == 0 {
		cfg.DrainContinue = DefaultDrainContinue
	}
	if cfg.DrainMax == 0 {
		cfg.DrainMax = DefaultDrainMax
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Monitor{cfg: cfg, recs: map[string]*nodeRec{}, reports: map[string]*clientReport{},
		pending: map[string]pendingInfo{}, drainSeen: map[string]time.Time{}, stats: map[string]nodeStat{},
		removed: map[string]uint64{}, aeadAcc: map[string]*aeadAcc{}}
}

// Run ticks every PollEvery until ctx ends.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.PollEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := m.Tick(ctx); err != nil {
				m.cfg.Log.Warn("membership tick failed", "err", err)
			}
		}
	}
}

func hostOf(admin string) string {
	h, _, err := net.SplitHostPort(admin)
	if err != nil {
		return admin
	}
	return h
}

// logNode logs with node_id, host and addr.
func (m *Monitor) logNode(level slog.Level, admin, msg string, kv ...any) {
	m.mu.Lock()
	var id uint64
	host := "unknown"
	if r := m.recs[admin]; r != nil && r.id != nil {
		id, host = r.id.NodeID, r.id.Hostname
	} else if s, ok := m.stats[admin]; ok {
		id, host = s.nodeID, s.hostname
	}
	m.mu.Unlock()
	m.cfg.Log.Log(context.Background(), level, msg, append([]any{"node_id", id, "host", host, "addr", hostOf(admin)}, kv...)...)
}

// lastBody parses the store's last envelope body; nil if there is none.
func lastBody(st *store.State) *bundle.Body {
	if len(st.LastEnvelope) == 0 {
		return nil
	}
	env, err := bundle.ParseEnvelope(st.LastEnvelope)
	if err != nil {
		return nil
	}
	b, err := bundle.ParseBody(env.Body)
	if err != nil {
		return nil
	}
	return b
}

func (r *nodeRec) observe(now time.Time, id *publish.Identity, err error) {
	if err != nil {
		r.pollOK, r.lastErr = false, err
		r.healthySince, r.idDiff = time.Time{}, 0
		return
	}
	r.pollOK, r.lastErr, r.id, r.lastOK = true, nil, id, now
	up := 0
	for _, rl := range id.Rails {
		if rl.Up {
			up++
		}
	}
	if len(id.Rails) > 0 && up == 0 {
		if r.railsDownSince.IsZero() {
			r.railsDownSince = now
		}
	} else {
		r.railsDownSince = time.Time{}
	}
	if up > 0 {
		if r.healthySince.IsZero() {
			r.healthySince = now
		}
	} else {
		r.healthySince = time.Time{}
	}
}

type candidate struct {
	admin    string
	rule     string
	replaced bool
	// The desired state the decision was made on; the publish Edit re-checks it, so an
	// operator action in between wins.
	state      string
	drainSince string
	hold       bool // never automatic: pending_removal until an operator confirms (rule c)
}

// Tick polls every member once and acts on what it sees. now comes from Config.Now, so tests drive
// it with a fake clock.
func (m *Monitor) Tick(ctx context.Context) error {
	m.tickMu.Lock()
	defer m.tickMu.Unlock()
	now := m.cfg.Now()
	m.flushAEAD(now)
	st, err := m.cfg.Store.Load()
	if err != nil {
		return err
	}
	body := lastBody(&st)
	bundleID := map[string]uint64{}
	if body != nil {
		for _, n := range body.Membership.Nodes {
			bundleID[n.Admin] = n.NodeID
		}
	}
	var admins []string
	desired := map[string]store.DesiredNode{}
	for _, n := range st.Nodes {
		admins = append(admins, n.Admin)
		desired[n.Admin] = n
	}
	failed := map[string]store.FailedNode{}
	for _, f := range st.Failed {
		if _, ok := desired[f.Admin]; !ok {
			admins = append(admins, f.Admin)
			failed[f.Admin] = f
		}
	}

	type poll struct {
		id  *publish.Identity
		err error
	}
	polls := make(map[string]poll, len(admins))
	var pmu sync.Mutex
	var wg sync.WaitGroup
	for _, a := range admins {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, m.cfg.PollTimeout)
			defer cancel()
			id, err := m.cfg.Client.Identity(cctx, a)
			pmu.Lock()
			polls[a] = poll{id, err}
			pmu.Unlock()
		}()
	}
	wg.Wait()

	// Observe, then evaluate the rules, under the lock; act after releasing it.
	var cands []candidate
	var toReadonly, toLeave []candidate
	m.mu.Lock()
	for _, a := range admins {
		r := m.recs[a]
		if r == nil {
			r = &nodeRec{firstSeen: now}
			m.recs[a] = r
		}
		r.observe(now, polls[a].id, polls[a].err)
	}
	for a := range m.recs {
		if _, ok := desired[a]; !ok {
			if _, ok := failed[a]; !ok {
				delete(m.recs, a)
				delete(m.pending, a)
				delete(m.stats, a)
				delete(m.drainSeen, a)
			}
		}
	}
	for _, d := range st.Nodes {
		r := m.recs[d.Admin]
		nodeID := bundleID[d.Admin]
		if nodeID == 0 && r.id != nil {
			nodeID = r.id.NodeID
		}
		rule := ""
		silentBase := r.lastOK
		if silentBase.IsZero() {
			silentBase = r.firstSeen
		}
		connected, allDown, working := m.votesLocked(nodeID, now)
		cond := allDown >= 2 && 2*allDown >= connected
		switch {
		case !cond:
			r.cSince = time.Time{}
		case r.cSince.IsZero():
			r.cSince = now
		}
		switch {
		case !r.pollOK && now.Sub(silentBase) >= m.cfg.FailTimeout && !working:
			rule = "a"
		case r.pollOK && !r.railsDownSince.IsZero() && now.Sub(r.railsDownSince) >= m.cfg.FailTimeout:
			// Rule (b): every rail the node reports is down (its own verdict, rails[].up: port ACTIVE, listener alive, no
			// fatal async event in 10 s).
			rule = "b"
		case cond && now.Sub(r.cSince) >= m.cfg.FailTimeout:
			rule = "c"
		}
		replaced := false
		if rule == "" && r.pollOK && bundleID[d.Admin] != 0 && r.id.NodeID != bundleID[d.Admin] {
			if r.idDiff++; r.idDiff >= replacePolls {
				rule, replaced = "replaced", true
			}
		} else if rule == "" {
			r.idDiff = 0
		}
		if rule != "" {
			cands = append(cands, candidate{admin: d.Admin, rule: rule, replaced: replaced, state: d.State, drainSince: d.DrainSince,
				// Client reports alone (our own poll succeeds) never remove a node automatically.
				hold: rule == "c" && r.pollOK})
		} else if p, ok := m.pending[d.Admin]; ok {
			delete(m.pending, d.Admin)
			defer m.logNode(slog.LevelInfo, d.Admin, "pending_removal cleared: the node meets no failure rule any more", "was", p.rule)
		}

		// Drain timers.
		if d.State == "draining" || d.State == "readonly" {
			since := m.drainStartLocked(d, now)
			el := now.Sub(since)
			switch {
			case el >= m.cfg.DrainMax:
				toLeave = append(toLeave, candidate{admin: d.Admin, state: d.State, drainSince: d.DrainSince, rule: "drain.max_ms"})
			case d.State == "readonly" && r.pollOK && r.id.BytesUsed != nil && *r.id.BytesUsed == 0:
				toLeave = append(toLeave, candidate{admin: d.Admin, state: d.State, drainSince: d.DrainSince, rule: "bytes_used == 0"})
			case d.State == "draining" && el >= m.cfg.DrainContinue:
				toReadonly = append(toReadonly, candidate{admin: d.Admin, state: d.State, drainSince: d.DrainSince})
			}
		}
	}
	m.mu.Unlock()

	// Drain steps first: a node that is leaving anyway needs no failure removal.
	leaving := map[string]bool{}
	if len(toReadonly) > 0 {
		m.setReadonly(ctx, toReadonly)
	}
	if len(toLeave) > 0 {
		leaving = m.leave(ctx, st, toLeave)
	}

	// Failure removals and replacements under static stability, on the state after the drain steps.
	if len(toReadonly)+len(toLeave) > 0 {
		if st2, err := m.cfg.Store.Load(); err == nil {
			st = st2
		}
	}
	var fresh []candidate
	m.mu.Lock()
	for _, c := range cands {
		if _, held := m.pending[c.admin]; !held && !leaving[c.admin] {
			fresh = append(fresh, c)
		}
	}
	m.mu.Unlock()
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].admin < fresh[j].admin })
	if len(fresh) > 0 {
		m.removeOrHold(ctx, st, fresh, now)
	}

	m.rejoin(ctx, st, failed, desired, now)

	// Reload: the actions above changed the desired set.
	if st2, err := m.cfg.Store.Load(); err == nil {
		failed2 := map[string]store.FailedNode{}
		inDesired := map[string]bool{}
		for _, n := range st2.Nodes {
			inDesired[n.Admin] = true
		}
		for _, f := range st2.Failed {
			if !inDesired[f.Admin] {
				failed2[f.Admin] = f
			}
		}
		bundleID2 := map[string]uint64{}
		if b := lastBody(&st2); b != nil {
			for _, n := range b.Membership.Nodes {
				bundleID2[n.Admin] = n.NodeID
			}
		}
		m.mu.Lock()
		m.refreshStatsLocked(st2, failed2, bundleID2)
		m.mu.Unlock()
	}
	return nil
}

// drainStartLocked is the start of a drain: the store's stamp, else the first time this process saw
// the node draining (a state set without a stamp).
func (m *Monitor) drainStartLocked(d store.DesiredNode, now time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339, d.DrainSince); err == nil {
		return t
	}
	t, ok := m.drainSeen[d.Admin]
	if !ok {
		t = now
		m.drainSeen[d.Admin] = t
	}
	return t
}

// allowedRemovals is what static stability still allows now. The base is the desired
// members plus every failed node not yet rejoined, forgotten (POST /v1/members forget) or
// confirmed, so a lasting partition cannot erode the cluster window after window; failure removals
// count until one of those happens, replacements (st.Replaced, persisted) count for RemoveWindow.
// For 2 nodes or fewer nothing is automatic.
func (m *Monitor) allowedRemovals(st *store.State, now time.Time) int {
	desired := map[string]bool{}
	for _, n := range st.Nodes {
		desired[n.Admin] = true
	}
	used := 0
	for _, f := range st.Failed {
		if !desired[f.Admin] {
			used++
		}
	}
	total := len(st.Nodes) + used
	allowed := int(float64(total) * m.cfg.MaxRemoveFraction)
	if total <= 2 {
		allowed = 0
	}
	for _, s := range st.Replaced {
		if t, err := time.Parse(time.RFC3339, s); err == nil && now.Sub(t) < m.cfg.RemoveWindow {
			used++
		}
	}
	return allowed - used
}

// activeLeft counts the active members of st that stay when the nodes in gone are removed.
func activeLeft(st *store.State, gone map[string]bool) int {
	n := 0
	for _, d := range st.Nodes {
		if d.State == "active" && !gone[d.Admin] {
			n++
		}
	}
	return n
}

func (m *Monitor) removeOrHold(ctx context.Context, st store.State, fresh []candidate, now time.Time) {
	avail := m.allowedRemovals(&st, now)
	gone := map[string]bool{}
	var go_ []candidate
	for _, c := range fresh {
		gone[c.admin] = true
		ok := avail > 0 && !c.hold && activeLeft(&st, gone) >= 1 && len(st.Nodes)-len(gone) >= 1
		why := "held by static stability"
		switch {
		case c.hold:
			why = "client reports alone never remove a node; confirm_remove needed"
		case ok && m.auditor() == nil:
			ok, why = false, "no audit log is configured (--audit-dir); automatic actions are refused"
		}
		if ok {
			go_ = append(go_, c)
			avail--
			continue
		}
		delete(gone, c.admin)
		m.mu.Lock()
		m.pending[c.admin] = pendingInfo{c.rule, c.replaced}
		m.mu.Unlock()
		m.logNode(slog.LevelError, c.admin, "ALERT: node meets a failure rule but is held in pending_removal; an operator must confirm (confirm_remove)",
			"rule", c.rule, "why", why, "max_remove_fraction", m.cfg.MaxRemoveFraction)
		m.auditAuto("member.pending_removal", c.admin, "error", "rule "+c.rule+": "+why, nil)
	}
	var drop, replace []candidate
	for _, c := range go_ {
		if c.replaced {
			replace = append(replace, c)
		} else {
			drop = append(drop, c)
		}
	}
	if len(drop) > 0 {
		m.removeFailed(ctx, drop, now, true)
	}
	if len(replace) > 0 {
		m.refreshIDs(ctx, replace, true)
	}
}

// removeMatching removes from next.Nodes the nodes of want whose state and drain stamp are still
// the ones the decision was made on (an operator action in between wins). It returns the
// admins it removed.
func removeMatching(next *store.State, want map[string]candidate, on func(store.DesiredNode)) map[string]bool {
	applied := map[string]bool{}
	activeBefore, activeAfter, kept := 0, 0, 0
	for _, n := range next.Nodes {
		if n.State == "active" {
			activeBefore++
		}
		if c, ok := want[n.Admin]; ok && n.State == c.state && n.DrainSince == c.drainSince {
			applied[n.Admin] = true
			continue
		}
		kept++
		if n.State == "active" {
			activeAfter++
		}
	}
	// Never publish an empty view or an empty member list: the count is checked here, on the
	// state the publisher just loaded, not on the snapshot the tick took.
	if kept == 0 || (activeBefore > 0 && activeAfter == 0) {
		return map[string]bool{}
	}
	out := make([]store.DesiredNode, 0, kept)
	for _, n := range next.Nodes {
		if applied[n.Admin] {
			on(n)
			continue
		}
		out = append(out, n)
	}
	next.Nodes = out
	return applied
}

// removeFailed publishes a bundle without the given failed nodes (epoch + 1 when they were in the
// view). auto is false for an operator's confirm_remove, which the API audits itself.
func (m *Monitor) removeFailed(ctx context.Context, cs []candidate, now time.Time, auto bool) {
	want := map[string]candidate{}
	var names []string
	nodeIDs := map[string]uint64{}
	m.mu.Lock()
	for _, c := range cs {
		want[c.admin] = c
		names = append(names, c.admin)
		if r := m.recs[c.admin]; r != nil && r.id != nil {
			nodeIDs[c.admin] = r.id.NodeID
		}
	}
	m.mu.Unlock()
	var applied map[string]bool
	res, err := m.cfg.Pub.Publish(ctx, publish.Change{Reason: fmt.Sprintf("failure: remove %v", names), TolerateUnreachable: true, Edit: func(next *store.State) {
		applied = removeMatching(next, want, func(d store.DesiredNode) {
			if d.State == "active" {
				next.Failed = withFailed(next.Failed, store.FailedNode{Admin: d.Admin, NodeID: nodeIDs[d.Admin],
					Weight: d.Weight, Zone: d.Zone, Since: now.UTC().Format(time.RFC3339)})
			}
		})
	}})
	for _, c := range cs {
		switch {
		case err != nil:
			m.logNode(slog.LevelWarn, c.admin, "failure removal not published; retrying next tick", "rule", c.rule, "err", err)
		case !applied[c.admin]:
			m.logNode(slog.LevelWarn, c.admin, "failure removal skipped: the node's state changed meanwhile", "rule", c.rule)
		default:
			m.mu.Lock()
			m.removed[c.rule]++
			m.mu.Unlock()
			m.logNode(slog.LevelWarn, c.admin, "node removed after failure", "rule", c.rule, "generation", res.Generation, "epoch", res.Epoch)
			if auto {
				g := res.Generation
				m.auditAuto("member.failure_remove", c.admin, "ok", "rule "+c.rule, &g)
			}
		}
	}
}

func withFailed(list []store.FailedNode, f store.FailedNode) []store.FailedNode {
	out := make([]store.FailedNode, 0, len(list)+1)
	for _, x := range list {
		if x.Admin != f.Admin {
			out = append(out, x)
		}
	}
	return append(out, f)
}

// refreshIDs publishes with an unchanged desired state: the publisher learns every node's ID anew, so
// an address that reports a new ID swaps old for new in the view (new epoch, the old ID in previous).
func (m *Monitor) refreshIDs(ctx context.Context, cs []candidate, auto bool) {
	grant := map[string]bool{}
	for _, c := range cs {
		grant[c.admin] = true
	}
	now := m.cfg.Now()
	res, err := m.cfg.Pub.Publish(ctx, publish.Change{Reason: "replacement: an address reports a new node ID", TolerateUnreachable: true,
		AllowIDChange: grant, // only a granted replacement takes the reported ID
		Edit: func(next *store.State) {
			// The replacement joins the stability window, persisted with Failed.
			keep := next.Replaced[:0:0]
			for _, s := range next.Replaced {
				if t, e := time.Parse(time.RFC3339, s); e == nil && now.Sub(t) < m.cfg.RemoveWindow {
					keep = append(keep, s)
				}
			}
			for range cs {
				keep = append(keep, now.UTC().Format(time.RFC3339))
			}
			next.Replaced = keep
		}})
	for _, c := range cs {
		if err != nil {
			m.logNode(slog.LevelWarn, c.admin, "replacement not published; retrying next tick", "err", err)
			continue
		}
		m.mu.Lock()
		m.removed["replaced"]++
		m.mu.Unlock()
		m.logNode(slog.LevelWarn, c.admin, "node replaced: the address reports a new ID", "generation", res.Generation, "epoch", res.Epoch)
		if auto {
			g := res.Generation
			m.auditAuto("member.replace", c.admin, "ok", "rule replaced: the address reports a new node ID", &g)
		}
	}
}

// rejoin re-adds failed nodes that are back with health OK for Rejoin (auto-rejoin). A returned
// address with another ID is the replacement case; it joins under the ID it reports now.
func (m *Monitor) rejoin(ctx context.Context, st store.State, failed map[string]store.FailedNode, desired map[string]store.DesiredNode, now time.Time) {
	var names []string
	for a := range failed {
		names = append(names, a)
	}
	sort.Strings(names)
	for _, a := range names {
		f := failed[a]
		if _, ok := desired[a]; ok {
			continue
		}
		m.mu.Lock()
		r := m.recs[a]
		ready := r != nil && r.pollOK && !r.healthySince.IsZero() && now.Sub(r.healthySince) >= m.cfg.Rejoin
		newID := r != nil && r.id != nil && r.id.NodeID != f.NodeID
		m.mu.Unlock()
		if !ready {
			continue
		}
		res, err := m.cfg.Pub.Publish(ctx, publish.Change{Reason: "auto-rejoin " + a, TolerateUnreachable: true,
			Join: &store.DesiredNode{Admin: a, Weight: f.Weight, Zone: f.Zone, State: "active"},
			Edit: func(next *store.State) {
				kept := next.Failed[:0:0]
				for _, x := range next.Failed {
					if x.Admin != a {
						kept = append(kept, x)
					}
				}
				next.Failed = kept
			}})
		if err != nil {
			m.logNode(slog.LevelWarn, a, "auto-rejoin not published; retrying next tick", "err", err)
			continue
		}
		m.logNode(slog.LevelInfo, a, "node rejoined", "same_id", !newID)
		g := res.Generation
		m.auditAuto("member.auto_rejoin", a, "ok", fmt.Sprintf("health OK for %s; same_id=%v", m.cfg.Rejoin, !newID), &g)
	}
}

// ErrNotPending: confirm-remove for a node that is not in pending_removal.
var ErrNotPending = errors.New("node is not in pending_removal")

// ConfirmRemove removes a node held in pending_removal (mirctl node confirm-remove). The last
// member cannot be removed.
func (m *Monitor) ConfirmRemove(ctx context.Context, admin string) error {
	m.tickMu.Lock()
	defer m.tickMu.Unlock()
	m.mu.Lock()
	p, ok := m.pending[admin]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotPending, admin)
	}
	st, err := m.cfg.Store.Load()
	if err != nil {
		return err
	}
	c := candidate{admin: admin, rule: p.rule, replaced: p.replaced}
	found := false
	for _, n := range st.Nodes {
		if n.Admin == admin {
			c.state, c.drainSince, found = n.State, n.DrainSince, true
		}
	}
	if !found {
		m.mu.Lock()
		delete(m.pending, admin)
		m.mu.Unlock()
		return fmt.Errorf("%s is no longer a member", admin)
	}
	if !p.replaced && len(st.Nodes) <= 1 {
		return fmt.Errorf("%s is the last member and cannot be removed", admin)
	}
	if p.replaced {
		m.refreshIDs(ctx, []candidate{c}, false)
	} else {
		m.removeFailed(ctx, []candidate{c}, m.cfg.Now(), false)
		st, err = m.cfg.Store.Load()
		if err != nil {
			return err
		}
		for _, n := range st.Nodes {
			if n.Admin == admin {
				return fmt.Errorf("removal of %s was not published (see the log)", admin)
			}
		}
	}
	m.mu.Lock()
	delete(m.pending, admin)
	m.mu.Unlock()
	return nil
}

// PendingRemoval lists the nodes held by static stability.
func (m *Monitor) PendingRemoval() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for a := range m.pending {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}
