package membership

import (
	"context"
	"testing"
	"time"

	"miracache/controller/publish"
	"miracache/controller/store"
)

func (r *rig) nodeIDInBundle(n *fakeNode) uint64 {
	for _, x := range r.body().Membership.Nodes {
		if x.Admin == n.admin() {
			return x.NodeID
		}
	}
	return 0
}

// U2-10: a replacement held in pending_removal is not copied by an unrelated publish.
func TestHeldReplacementIsNotCopiedByUnrelatedPublish(t *testing.T) {
	r := newRig(t, hosts(6), "", nil) // budget 2
	r.tick(0)
	r.nodes[1].set(func(n *fakeNode) { n.id = 2001 })
	r.nodes[2].set(func(n *fakeNode) { n.id = 2002 })
	r.ticks(2)
	r.nodes[3].set(func(n *fakeNode) { n.id = 2003 })
	r.ticks(3)
	if p := r.mon.PendingRemoval(); len(p) != 1 || p[0] != r.nodes[3].admin() {
		t.Fatalf("pending %v", p)
	}
	if _, err := r.pub.Publish(context.Background(), publish.Change{Reason: "unrelated", Edit: func(s *store.State) { s.ConfigTOML = "[config.cluster.placement]\nreplicas = 1\n" }}); err != nil {
		t.Fatal(err)
	}
	if got := r.nodeIDInBundle(r.nodes[3]); got != 1003 {
		t.Fatalf("the held replacement entered the bundle: node id %d", got)
	}
	if got := r.nodeIDInBundle(r.nodes[1]); got != 2001 {
		t.Fatalf("the granted replacement was lost: %d", got)
	}
	// Confirmed, it is granted.
	if err := r.mon.ConfirmRemove(context.Background(), r.nodes[3].admin()); err != nil {
		t.Fatal(err)
	}
	if got := r.nodeIDInBundle(r.nodes[3]); got != 2003 {
		t.Fatalf("confirmed replacement not applied: %d", got)
	}
}

// U2-30: replacements persist in the store, so a restarted controller still counts them.
func TestReplacementWindowSurvivesRestart(t *testing.T) {
	r := newRig(t, hosts(6), "", nil)
	r.tick(0)
	r.nodes[1].set(func(n *fakeNode) { n.id = 2001 })
	r.nodes[2].set(func(n *fakeNode) { n.id = 2002 })
	r.ticks(2)
	if len(r.state().Replaced) != 2 {
		t.Fatalf("replaced = %v", r.state().Replaced)
	}
	r.mon = New(r.cfg)
	r.nodes[3].set(func(n *fakeNode) { n.id = 2003 })
	r.ticks(3)
	if len(r.mon.PendingRemoval()) != 1 {
		t.Fatal("a restart forgot the replacements of the window")
	}
}

// U2-11: leaves and a failure in one tick never empty the view; the count is checked inside the Edit.
func TestLeavesAndFailureNeverEmptyTheView(t *testing.T) {
	r := newRig(t, hosts(3), r1, nil)
	r.tick(0)
	ctx := context.Background()
	for _, i := range []int{1, 2} {
		r.nodes[i].set(func(n *fakeNode) { n.bytesUsed = u64(5) })
		if err := r.mon.Drain(ctx, r.nodes[i].admin()); err != nil {
			t.Fatal(err)
		}
	}
	r.nodes[0].set(func(n *fakeNode) { n.down = true }) // the only active node fails
	activeInBundle := func() int {
		c := 0
		for _, n := range r.body().Membership.Nodes {
			if n.State == "active" {
				c++
			}
		}
		return c
	}
	r.tick(60 * time.Second) // both go readonly; node 0's rule a fires in the same tick
	if activeInBundle() != 1 || r.desiredCount() != 3 {
		t.Fatalf("view emptied or members lost: active=%d members=%d\n%s", activeInBundle(), r.desiredCount(), r.log.String())
	}
	for _, i := range []int{1, 2} {
		r.nodes[i].set(func(n *fakeNode) { n.bytesUsed = u64(0) })
	}
	r.ticks(3)
	if activeInBundle() != 1 || r.desiredCount() < 1 { // the leaves cannot be acked while node 0 is down: retried, never an empty view
		t.Fatalf("after the leaves: active=%d members=%d\n%s", activeInBundle(), r.desiredCount(), r.log.String())
	}
	if p := r.mon.PendingRemoval(); len(p) != 1 {
		t.Fatalf("the failed last node must be held: %v", p)
	}
}

func TestRemoveMatchingRefusesAnEmptyView(t *testing.T) {
	next := &store.State{Nodes: []store.DesiredNode{{Admin: "a", State: "active"}, {Admin: "b", State: "draining"}}}
	got := removeMatching(next, map[string]candidate{"a": {admin: "a", state: "active"}}, func(store.DesiredNode) { t.Fatal("removed") })
	if len(got) != 0 || len(next.Nodes) != 2 {
		t.Fatalf("emptied the view: %v %v", got, next.Nodes)
	}
	next = &store.State{Nodes: []store.DesiredNode{{Admin: "a", State: "active"}}}
	if got = removeMatching(next, map[string]candidate{"a": {admin: "a", state: "active"}}, func(store.DesiredNode) {}); len(got) != 0 {
		t.Fatal("removed the last member")
	}
}

// U2-12: without an audit log nothing automatic happens; the node is held.
func TestNoAuditorRefusesAutomaticActions(t *testing.T) {
	r := newRig(t, hosts(3), r1, func(c *Config) { c.Audit = nil })
	r.tick(0)
	r.nodes[2].set(func(n *fakeNode) { n.down = true })
	r.ticks(12)
	if r.desiredCount() != 3 || len(r.mon.PendingRemoval()) != 1 {
		t.Fatalf("removed without an audit log; log:\n%s", r.log.String())
	}
	n := r.nodes[1]
	if err := r.mon.Drain(context.Background(), n.admin()); err != nil {
		t.Fatal(err)
	}
	r.tick(61 * time.Second)
	if s, _ := r.inBundle(n); s != "draining" {
		t.Fatalf("drain step taken without an audit log: %q", s)
	}
}

// U2-13: rule c alone holds the node, no publish.
func TestRuleCNeverRemovesAutomatically(t *testing.T) {
	r := newRig(t, hosts(4), "", nil)
	r.tick(0)
	gen := r.state().Generation
	for i := 0; i < 30; i++ {
		r.report("spiffe://client/1", map[uint64][]bool{1003: {false}, 1000: {true}})
		r.report("spiffe://client/2", map[uint64][]bool{1003: {false}, 1000: {true}})
		r.tick(time.Second)
	}
	if p := r.mon.PendingRemoval(); len(p) != 1 || p[0] != r.nodes[3].admin() {
		t.Fatalf("pending %v", p)
	}
	if r.state().Generation != gen || r.desiredCount() != 4 {
		t.Fatal("a publish happened for a healthy node reported down by clients")
	}
}

// U2-28: a held AEAD sum is audited on a later tick even if no more reports come.
func TestHeldAEADSumFlushedOnTick(t *testing.T) {
	r, dir := auditRig(t, 3, "")
	r.tick(0)
	body := func(d uint64) []byte { return []byte(`{"nodes":[],"aead_fail_delta":` + string(rune('0'+d)) + `}`) }
	for _, d := range []uint64{2, 3} {
		if err := r.mon.Submit("spiffe://client/1", body(d), r.now); err != nil {
			t.Fatal(err)
		}
	}
	if got := countAction(auditLines(t, dir), "client.aead_fail"); got != 1 {
		t.Fatalf("entries before the flush: %d", got)
	}
	r.tick(61 * time.Second)
	if got := countAction(auditLines(t, dir), "client.aead_fail"); got != 2 {
		t.Fatalf("a burst followed by silence was not audited: %d", got)
	}
}
