package membership

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"miracache/controller/audit"
	"miracache/controller/publish"
	"miracache/controller/store"
)

// A lasting partition erodes nothing beyond the budget, however long it lasts.
func TestLastingPartitionRemovesAtMostTheBudget(t *testing.T) {
	r := newRig(t, hosts(6), "", nil) // base 6: budget 2
	r.tick(0)
	for _, i := range []int{3, 4, 5} {
		r.nodes[i].set(func(n *fakeNode) { n.down = true })
	}
	for i := 0; i < 360; i++ { // 30 minutes of fake time in 5 s steps
		r.tick(5 * time.Second)
		if got := r.desiredCount(); got < 4 {
			t.Fatalf("%d members left at step %d: the partition ate more than the budget", got, i)
		}
	}
	st := r.state()
	if len(st.Failed) != 2 || len(st.Nodes) != 4 || len(r.mon.PendingRemoval()) != 1 {
		t.Fatalf("failed=%d members=%d pending=%v", len(st.Failed), len(st.Nodes), r.mon.PendingRemoval())
	}
}

// With two nodes or fewer nothing is automatic; the last member can never be removed.
func TestSmallClusterNeedsConfirmAndLastMemberStays(t *testing.T) {
	r := newRig(t, hosts(2), "", nil)
	r.tick(0)
	r.nodes[1].set(func(n *fakeNode) { n.down = true })
	r.ticks(30)
	if r.desiredCount() != 2 || len(r.mon.PendingRemoval()) != 1 {
		t.Fatalf("N=2 removed automatically; log:\n%s", r.log.String())
	}
	ctx := context.Background()
	if err := r.mon.ConfirmRemove(ctx, r.nodes[1].admin()); err != nil {
		t.Fatal(err)
	}
	r.nodes[0].set(func(n *fakeNode) { n.down = true })
	r.ticks(15)
	if r.desiredCount() != 1 || len(r.mon.PendingRemoval()) != 1 {
		t.Fatal("the last member was removed or not held")
	}
	if err := r.mon.ConfirmRemove(ctx, r.nodes[0].admin()); err == nil || !strings.Contains(err.Error(), "last member") {
		t.Fatalf("confirm of the last member: %v", err)
	}
}

// A replacement counts in the stability window.
func TestReplacementsCountAgainstBudget(t *testing.T) {
	r := newRig(t, hosts(6), "", nil) // budget 2
	r.tick(0)
	r.nodes[1].set(func(n *fakeNode) { n.id = 2001 })
	r.nodes[2].set(func(n *fakeNode) { n.id = 2002 })
	r.ticks(2)
	for _, n := range r.body().Membership.Nodes {
		if n.Admin == r.nodes[1].admin() && n.NodeID != 2001 {
			t.Fatal("first replacement not applied")
		}
	}
	e := r.epoch()
	r.nodes[3].set(func(n *fakeNode) { n.id = 2003 })
	r.ticks(3)
	if r.epoch() != e {
		t.Fatal("a third replacement inside the window went through")
	}
	if p := r.mon.PendingRemoval(); len(p) != 1 || p[0] != r.nodes[3].admin() {
		t.Fatalf("pending %v", p)
	}
}

// ---- Automatic actions are audited ---------------------------------------------------------------

func auditRig(t *testing.T, n int, cfgTOML string) (*rig, string) {
	dir := t.TempDir()
	aw, err := audit.Open(audit.Config{Dir: dir, Src: audit.Source{Controller: true, Host: "ctl-test", Addr: "127.0.0.1:9470"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { aw.Close() })
	return newRig(t, hosts(n), cfgTOML, func(c *Config) { c.Audit = aw }), dir
}

// auditLines verifies the chain and returns the lines of the audit files.
func auditLines(t *testing.T, dir string) []string {
	t.Helper()
	files, _ := audit.ListFiles(dir)
	if v := audit.VerifyPaths(files, nil); !v.OK {
		t.Fatalf("audit chain: %s", v.Text())
	}
	var out []string
	for _, f := range files {
		b, _ := os.ReadFile(f)
		out = append(out, strings.Split(strings.TrimSpace(string(b)), "\n")...)
	}
	return out
}

func countAction(lines []string, action string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l, `"action":"`+action+`"`) && strings.Contains(l, `"actor":"local"`) {
			n++
		}
	}
	return n
}

func TestAutomaticFailureActionsAreAudited(t *testing.T) {
	r, dir := auditRig(t, 6, "")
	r.tick(0)
	for _, i := range []int{3, 4, 5} {
		r.nodes[i].set(func(n *fakeNode) { n.down = true })
	}
	r.ticks(10)
	l := auditLines(t, dir)
	if countAction(l, "member.failure_remove") != 2 || countAction(l, "member.pending_removal") != 1 {
		t.Fatalf("failure_remove=%d pending_removal=%d\n%s", countAction(l, "member.failure_remove"), countAction(l, "member.pending_removal"), strings.Join(l, "\n"))
	}
	for _, x := range l {
		if strings.Contains(x, "member.failure_remove") && (!strings.Contains(x, `"reason":"rule a"`) || !strings.Contains(x, `"node_id"`) || !strings.Contains(x, `"host"`) || !strings.Contains(x, `"addr":"127.0.0.1"`)) {
			t.Errorf("entry lacks rule or node identity: %s", x)
		}
	}
	r.ticks(30) // still held: no second pending entry
	if countAction(auditLines(t, dir), "member.pending_removal") != 1 {
		t.Error("pending_removal audited again")
	}
	for _, i := range []int{3, 4, 5} {
		r.nodes[i].set(func(n *fakeNode) { n.down = false })
	}
	r.ticks(14)
	if got := countAction(auditLines(t, dir), "member.auto_rejoin"); got != 2 {
		t.Fatalf("auto_rejoin entries = %d", got)
	}
}

func TestAutomaticDrainReplacementAndAEADAreAudited(t *testing.T) {
	r, dir := auditRig(t, 4, r1)
	r.tick(0)
	n := r.nodes[3]
	n.set(func(f *fakeNode) { f.bytesUsed = u64(3) })
	if err := r.mon.Drain(context.Background(), n.admin()); err != nil {
		t.Fatal(err)
	}
	r.tick(60 * time.Second)
	n.set(func(f *fakeNode) { f.bytesUsed = u64(0) })
	r.tick(time.Second)
	r.nodes[1].set(func(f *fakeNode) { f.id = 2001 })
	r.ticks(2)
	// AEAD failures reported by a client: one entry per minute per identity, the delta summed.
	body := func(d uint64) []byte { b, _ := json.Marshal(Report{AEADFailDelta: d}); return b }
	for _, d := range []uint64{2, 3} {
		if err := r.mon.Submit("spiffe://client/1", body(d), r.now); err != nil {
			t.Fatal(err)
		}
	}
	r.now = r.now.Add(61 * time.Second)
	if err := r.mon.Submit("spiffe://client/1", body(1), r.now); err != nil {
		t.Fatal(err)
	}
	l := auditLines(t, dir)
	for action, want := range map[string]int{"drain.readonly": 1, "drain.leave": 1, "member.replace": 1, "client.aead_fail": 2} {
		if got := countAction(l, action); got != want {
			t.Errorf("%s entries = %d, want %d\n%s", action, got, want, strings.Join(l, "\n"))
		}
	}
	if !strings.Contains(strings.Join(l, "\n"), `"aead_fail_delta":4`) {
		t.Error("the held delta (3) and the next (1) are summed into the second entry")
	}
}

// ---- Operator action between decision and publish wins -------------------------------------------

type racePub struct {
	Publisher
	hook func()
}

func (p *racePub) Publish(ctx context.Context, ch publish.Change) (*publish.Result, error) {
	if p.hook != nil {
		h := p.hook
		p.hook = nil
		h()
	}
	return p.Publisher.Publish(ctx, ch)
}

func (r *rig) editState(f func(*store.State)) {
	r.t.Helper()
	st := r.state()
	f(&st)
	if err := r.st.Commit(st.Generation, st); err != nil {
		r.t.Fatal(err)
	}
}

func setNode(st *store.State, admin, state, since string) {
	for i := range st.Nodes {
		if st.Nodes[i].Admin == admin {
			st.Nodes[i].State, st.Nodes[i].DrainSince = state, since
		}
	}
}

func TestLeaveRechecksStateInsideTheEdit(t *testing.T) {
	r := newRig(t, hosts(3), r1, nil)
	rp := &racePub{Publisher: r.pub}
	r.cfg.Pub = rp
	r.mon = New(r.cfg)
	r.tick(0)
	n := r.nodes[2]
	n.set(func(f *fakeNode) { f.bytesUsed = u64(0) })
	if err := r.mon.Drain(context.Background(), n.admin()); err != nil {
		t.Fatal(err)
	}
	r.tick(60 * time.Second)                                                                         // readonly
	rp.hook = func() { r.editState(func(st *store.State) { setNode(st, n.admin(), "active", "") }) } // operator undoes the drain
	r.tick(time.Second)                                                                              // would leave: bytes_used == 0
	st := r.state()
	found := false
	for _, d := range st.Nodes {
		if d.Admin == n.admin() {
			found = true
			if d.State != "active" {
				t.Errorf("state %q", d.State)
			}
		}
	}
	if !found {
		t.Fatal("the operator's set-active lost against the leave")
	}
	if !strings.Contains(r.log.String(), "leave skipped") {
		t.Errorf("no skip logged:\n%s", r.log.String())
	}
}

func TestFailureRemovalRechecksStateInsideTheEdit(t *testing.T) {
	r := newRig(t, hosts(3), "", nil)
	rp := &racePub{Publisher: r.pub}
	r.cfg.Pub = rp
	r.mon = New(r.cfg)
	r.tick(0)
	n := r.nodes[2]
	n.set(func(f *fakeNode) { f.down = true })
	r.ticks(9)
	rp.hook = func() {
		r.editState(func(st *store.State) { setNode(st, n.admin(), "draining", "2026-11-12T09:00:09Z") })
	}
	r.tick(time.Second) // rule a fires; the operator started a drain first
	if r.desiredCount() != 3 || len(r.state().Failed) != 0 {
		t.Fatal("a failure removal overrode the operator's drain")
	}
}

// ---- One cap policy --------------------------------------------------------------------------------

func TestReportCapPolicy(t *testing.T) {
	r := newRig(t, hosts(2), "", func(c *Config) { c.MaxReporters = 2 })
	body := []byte(`{"nodes":[]}`)
	for _, id := range []string{"a", "b"} {
		if err := r.mon.Submit("spiffe://c/"+id, body, r.now); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.mon.Submit("spiffe://c/c", body, r.now); err != ErrReportsFull {
		t.Fatalf("third identity: %v", err)
	}
	if err := r.mon.Submit("spiffe://c/a", body, r.now); err != nil { // an existing identity may update
		t.Fatal(err)
	}
	if err := r.mon.Submit("spiffe://c/c", body, r.now.Add(7*time.Second)); err != nil { // stale ones make room
		t.Fatalf("after the reports went stale: %v", err)
	}
	if r.mon.ReportCount() != 1 {
		t.Errorf("reports kept: %d", r.mon.ReportCount())
	}
}
