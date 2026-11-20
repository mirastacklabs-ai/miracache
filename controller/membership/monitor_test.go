package membership

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func hosts(n int) []string { return []string{"a", "b", "c", "d", "e", "f", "g"}[:n] }

// ---- rule (a), (b), (c) ----------------------------------------------------------------------------

func TestRuleADetectionTiming(t *testing.T) {
	r := newRig(t, hosts(3), "", nil)
	r.tick(0)
	e0 := r.epoch()
	r.nodes[2].set(func(n *fakeNode) { n.down = true })
	for i := 1; i <= 9; i++ {
		r.tick(time.Second)
		if r.desiredCount() != 3 {
			t.Fatalf("removed at %d s, before fail_timeout (10 s)", i)
		}
	}
	if st := r.mon.State(r.nodes[2].admin()); st != StateSuspect {
		t.Errorf("state before the timeout = %q, want suspect", st)
	}
	r.tick(time.Second) // 10 s of silence
	if r.desiredCount() != 2 {
		t.Fatalf("not removed at fail_timeout; log:\n%s", r.log.String())
	}
	if _, in := r.inBundle(r.nodes[2]); in {
		t.Error("removed node is still in the bundle's nodes")
	}
	if r.epoch() != e0+1 {
		t.Errorf("epoch %d, want %d (a failure removal changes the view)", r.epoch(), e0+1)
	}
	st := r.state()
	if len(st.Failed) != 1 || st.Failed[0].NodeID != 1002 {
		t.Errorf("failed record: %+v", st.Failed)
	}
	// Identity in telemetry: ID + hostname + IP in the log line and the metric.
	log := r.log.String()
	if !strings.Contains(log, "node removed after failure") || !strings.Contains(log, "node_id=1002 host=c addr=127.0.0.1") {
		t.Errorf("removal log line lacks node_id/host/addr:\n%s", log)
	}
	var buf bytes.Buffer
	r.mon.WriteMetrics(&buf)
	if !strings.Contains(buf.String(), `mira_controller_node_state{node_id="1002",hostname="c",addr="127.0.0.1",state="removed"} 1`) {
		t.Errorf("metrics:\n%s", buf.String())
	}
}

func TestRuleAClientReportBlocksRemoval(t *testing.T) {
	r := newRig(t, hosts(3), "", nil)
	r.tick(0)
	r.nodes[2].set(func(n *fakeNode) { n.down = true }) // management network down, RDMA fine
	for i := 0; i < 30; i++ {
		r.report("spiffe://client/1", map[uint64][]bool{1002: {true}, 1000: {true}})
		r.tick(time.Second)
	}
	if r.desiredCount() != 3 {
		t.Fatal("removed although a client reports a working rail (rule a needs both)")
	}
	// The same client now sees the rails down too: silent AND no working rail.
	r.report("spiffe://client/1", map[uint64][]bool{1002: {false}, 1000: {true}})
	r.tick(time.Second)
	if r.desiredCount() != 2 {
		t.Fatal("not removed once the health stream is silent and no client sees a working rail")
	}
}

func TestRuleBAllRailsDown(t *testing.T) {
	r := newRig(t, hosts(3), "", nil)
	r.nodes[2].set(func(n *fakeNode) { n.railsUp = []bool{true, true} })
	r.tick(0)
	r.nodes[2].set(func(n *fakeNode) { n.railsUp = []bool{false, false} })
	r.ticks(5)
	r.nodes[2].set(func(n *fakeNode) { n.railsUp = []bool{false, true} }) // one rail back: the clock resets
	r.ticks(1)
	r.nodes[2].set(func(n *fakeNode) { n.railsUp = []bool{false, false} })
	r.ticks(10) // the poll that sees all rails down starts the clock; 10 s after it is the 10th tick
	if r.desiredCount() != 3 {
		t.Fatalf("removed too early; log:\n%s", r.log.String())
	}
	r.ticks(1)
	if r.desiredCount() != 2 {
		t.Fatalf("rule b did not fire; log:\n%s", r.log.String())
	}
}

func TestRuleCOneIdentityIsOneVoice(t *testing.T) {
	r := newRig(t, hosts(5), "", nil)
	r.tick(0)
	e0 := r.epoch()
	// One identity floods reports, each claiming a different "host", all saying node 1004 is unreachable.
	for i := 0; i < 25; i++ {
		for k := 0; k < 4; k++ {
			r.report("spiffe://client/evil", map[uint64][]bool{1004: {false}, 1000: {true}})
		}
		r.tick(time.Second)
	}
	if r.desiredCount() != 5 {
		t.Fatal("a single identity removed a node (rule c needs 2 distinct identities)")
	}
	// A second distinct identity agrees: both are all the clients there are, so rule (c) holds for 10 s.
	for i := 1; i <= 10; i++ {
		r.report("spiffe://client/evil", map[uint64][]bool{1004: {false}, 1000: {true}})
		r.report("spiffe://client/b", map[uint64][]bool{1004: {false}, 1001: {true}})
		r.tick(time.Second)
		if r.desiredCount() != 5 {
			t.Fatalf("removed after %d s, before fail_timeout", i)
		}
	}
	r.report("spiffe://client/evil", map[uint64][]bool{1004: {false}, 1000: {true}})
	r.report("spiffe://client/b", map[uint64][]bool{1004: {false}, 1001: {true}})
	r.tick(time.Second)
	// rule c alone, with our own poll succeeding, only ever holds the node.
	p := r.mon.PendingRemoval()
	if len(p) != 1 || p[0] != r.nodes[4].admin() {
		t.Fatalf("rule c did not hold the node in pending_removal; log:\n%s", r.log.String())
	}
	if r.desiredCount() != 5 || r.epoch() != e0 {
		t.Fatal("rule c published a removal")
	}
	for i := 0; i < 20; i++ {
		r.report("spiffe://client/evil", map[uint64][]bool{1004: {false}, 1000: {true}})
		r.report("spiffe://client/b", map[uint64][]bool{1004: {false}, 1001: {true}})
		r.tick(time.Second)
	}
	if r.desiredCount() != 5 {
		t.Fatal("a held node was removed without confirmation")
	}
	if err := r.mon.ConfirmRemove(context.Background(), r.nodes[4].admin()); err != nil {
		t.Fatal(err)
	}
	if _, in := r.inBundle(r.nodes[4]); in || r.desiredCount() != 4 {
		t.Error("confirm_remove did not remove the node")
	}
}

func TestRuleCNeedsHalfOfTheClients(t *testing.T) {
	r := newRig(t, hosts(4), "", nil)
	r.tick(0)
	for i := 0; i < 25; i++ {
		r.report("spiffe://client/1", map[uint64][]bool{1003: {false}, 1000: {true}})
		r.report("spiffe://client/2", map[uint64][]bool{1003: {false}, 1000: {true}})
		for _, c := range []string{"3", "4", "5"} { // three clients still reach it: 2 of 5 is under half
			r.report("spiffe://client/"+c, map[uint64][]bool{1003: {true}, 1000: {true}})
		}
		r.tick(time.Second)
	}
	if r.desiredCount() != 4 {
		t.Fatal("removed with fewer than half of the connected clients reporting it down")
	}
}

func TestRuleCAdvisoryWhenClientCannotReachOthers(t *testing.T) {
	// "while they still reach other nodes": a client that reaches nothing is a client problem.
	r := newRig(t, hosts(4), "", nil)
	r.tick(0)
	for i := 0; i < 25; i++ {
		r.report("spiffe://client/1", map[uint64][]bool{1003: {false}, 1000: {false}})
		r.report("spiffe://client/2", map[uint64][]bool{1003: {false}, 1000: {false}})
		r.tick(time.Second)
	}
	if r.desiredCount() != 4 {
		t.Fatal("removed on reports from clients that reach no node at all")
	}
}

func TestMalformedReports(t *testing.T) {
	r := newRig(t, hosts(2), "", nil)
	for name, c := range map[string]struct{ id, body string }{
		"not json":      {"spiffe://c/1", "nope"},
		"node id zero":  {"spiffe://c/1", `{"nodes":[{"node_id":0,"rails":[]}]}`},
		"node id large": {"spiffe://c/1", `{"nodes":[{"node_id":4294967296,"rails":[]}]}`},
		"no identity":   {"", `{"nodes":[]}`},
	} {
		if err := r.mon.Submit(c.id, []byte(c.body), r.now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := r.mon.Submit("spiffe://c/1", []byte(`{"generation":3,"nodes":[],"aead_fail_delta":0}`), r.now); err != nil {
		t.Errorf("valid empty report: %v", err)
	}
}

// ---- static stability, last member, rejoin, replacement -----------------------------------------------

func TestStaticStability(t *testing.T) {
	r := newRig(t, hosts(6), "", nil) // N=6: at most 2 removals per window
	r.tick(0)
	for _, i := range []int{3, 4, 5} {
		r.nodes[i].set(func(n *fakeNode) { n.down = true })
	}
	r.ticks(10)
	if got := r.desiredCount(); got != 4 {
		t.Fatalf("%d members left, want 4 (two removals, one held); log:\n%s", got, r.log.String())
	}
	pend := r.mon.PendingRemoval()
	if len(pend) != 1 {
		t.Fatalf("pending_removal = %v, want one node", pend)
	}
	if st := r.mon.State(pend[0]); st != StatePendingRemoval {
		t.Errorf("state %q", st)
	}
	if !strings.Contains(r.log.String(), "ALERT") {
		t.Error("no alert logged for the held node")
	}
	e := r.epoch()
	r.ticks(30)
	if r.desiredCount() != 4 || r.epoch() != e {
		t.Fatal("a pending_removal node was removed without confirmation")
	}
	if err := r.mon.ConfirmRemove(context.Background(), pend[0]); err != nil {
		t.Fatal(err)
	}
	if r.desiredCount() != 3 || len(r.mon.PendingRemoval()) != 0 {
		t.Fatal("confirm-remove did not remove the node")
	}
	if err := r.mon.ConfirmRemove(context.Background(), pend[0]); !errors.Is(err, ErrNotPending) {
		t.Errorf("second confirm: %v", err)
	}
}

func TestAutoRejoin(t *testing.T) {
	r := newRig(t, hosts(3), "", nil)
	r.tick(0)
	r.nodes[2].set(func(n *fakeNode) { n.down = true })
	r.ticks(10)
	if r.desiredCount() != 2 {
		t.Fatal("not removed")
	}
	eRemoved := r.epoch()
	r.nodes[2].set(func(n *fakeNode) { n.down = false })
	r.ticks(10) // first healthy poll at +1; rejoin needs 10 s of health OK
	if r.desiredCount() != 2 {
		t.Fatalf("rejoined before rejoin_ms; log:\n%s", r.log.String())
	}
	if st := r.mon.State(r.nodes[2].admin()); st != StateRejoining {
		t.Errorf("state %q, want rejoining", st)
	}
	r.ticks(1)
	if r.desiredCount() != 3 {
		t.Fatalf("not rejoined; log:\n%s", r.log.String())
	}
	if s, in := r.inBundle(r.nodes[2]); !in || s != "active" {
		t.Errorf("rejoined node in bundle: %v %q", in, s)
	}
	if r.epoch() != eRemoved+1 {
		t.Errorf("epoch %d, want %d (rejoin is a new epoch)", r.epoch(), eRemoved+1)
	}
	if len(r.state().Failed) != 0 {
		t.Error("failed record not cleared")
	}
}

func TestFlappingNodeDoesNotRejoin(t *testing.T) {
	r := newRig(t, hosts(3), "", nil)
	r.tick(0)
	r.nodes[2].set(func(n *fakeNode) { n.down = true })
	r.ticks(10)
	for i := 0; i < 4; i++ { // up 6 s, down 1 s, ...
		r.nodes[2].set(func(n *fakeNode) { n.down = false })
		r.ticks(6)
		r.nodes[2].set(func(n *fakeNode) { n.down = true })
		r.ticks(1)
	}
	if r.desiredCount() != 2 {
		t.Fatal("a flapping node rejoined")
	}
}

func TestReplacementNewIDAtSameAddress(t *testing.T) {
	r := newRig(t, hosts(3), "", nil)
	r.tick(0)
	e0 := r.epoch()
	r.nodes[1].set(func(n *fakeNode) { n.id = 2000 })
	r.tick(time.Second)
	if r.epoch() != e0 {
		t.Fatal("replacement on a single poll")
	}
	r.tick(time.Second)
	if r.epoch() != e0+1 {
		t.Fatalf("epoch %d, want %d; log:\n%s", r.epoch(), e0+1, r.log.String())
	}
	b := r.body()
	found := false
	for _, n := range b.Membership.Nodes {
		if n.Admin == r.nodes[1].admin() && n.NodeID == 2000 {
			found = true
		}
	}
	if !found {
		t.Error("bundle does not carry the new ID")
	}
	old := false
	for _, p := range b.Membership.Previous {
		old = old || p.NodeID == 1001
	}
	if !old {
		t.Error("previous view lacks the old ID")
	}
}

// ---- drain ---------------------------------------------------------------------------------------------

const r1 = "[config.cluster.placement]\nreplicas = 1\n"

func TestDrainToRemovalR1(t *testing.T) {
	r := newRig(t, hosts(3), r1, nil)
	r.tick(0)
	if rep, ok := r.body().Replicas(); !ok || rep != 1 {
		t.Fatalf("replicas %d %v", rep, ok)
	}
	n := r.nodes[2]
	n.set(func(f *fakeNode) { f.bytesUsed = u64(5) })
	e0 := r.epoch()
	if err := r.mon.Drain(context.Background(), n.admin()); err != nil {
		t.Fatal(err)
	}
	if r.epoch() != e0+1 {
		t.Fatalf("drain epoch %d, want %d", r.epoch(), e0+1)
	}
	if s, in := r.inBundle(n); !in || s != "draining" {
		t.Fatalf("after drain: in=%v state=%q", in, s)
	}
	if r.state().Nodes[2].DrainSince == "" && r.state().Nodes[1].DrainSince == "" && r.state().Nodes[0].DrainSince == "" {
		t.Fatal("drain start not stamped in the store")
	}
	e1 := r.epoch()
	r.tick(59 * time.Second)
	if s, _ := r.inBundle(n); s != "draining" {
		t.Fatalf("state %q at 59 s, want draining", s)
	}
	r.tick(time.Second) // drain.continue_ms
	if s, _ := r.inBundle(n); s != "readonly" {
		t.Fatalf("state %q at 60 s, want readonly", s)
	}
	if r.epoch() != e1 {
		t.Errorf("readonly changed the epoch: %d -> %d", e1, r.epoch())
	}
	r.ticks(5)
	if _, in := r.inBundle(n); !in {
		t.Fatal("left while bytes_used != 0")
	}
	n.set(func(f *fakeNode) { f.bytesUsed = u64(0) })
	r.tick(time.Second)
	if _, in := r.inBundle(n); in {
		t.Fatalf("still in nodes with bytes_used == 0; log:\n%s", r.log.String())
	}
	if r.epoch() != e1 {
		t.Errorf("leave bumped the epoch: %d -> %d", e1, r.epoch())
	}
	if len(r.state().Failed) != 0 {
		t.Error("a drained node must not be recorded as failed (no auto-rejoin)")
	}
	if r.desiredCount() != 2 {
		t.Errorf("%d members", r.desiredCount())
	}
	// Clients' view: R=1 chains whose previous owner left fall through; the bundle still names
	// the previous view and no longer lists the node.
	if len(r.body().Membership.Previous) == 0 {
		t.Error("previous view lost at leave")
	}
}

func TestDrainMaxMs(t *testing.T) {
	r := newRig(t, hosts(3), r1, nil)
	r.tick(0)
	n := r.nodes[1]
	n.set(func(f *fakeNode) { f.bytesUsed = u64(7) }) // never empties
	if err := r.mon.Drain(context.Background(), n.admin()); err != nil {
		t.Fatal(err)
	}
	r.tick(60 * time.Second)
	r.tick(838 * time.Second) // 898 s
	if _, in := r.inBundle(n); !in {
		t.Fatal("left before drain.max_ms")
	}
	r.tick(2 * time.Second) // 900 s
	if _, in := r.inBundle(n); in {
		t.Fatalf("still present at drain.max_ms; log:\n%s", r.log.String())
	}
}

func TestDrainResumesAfterControllerRestart(t *testing.T) {
	r := newRig(t, hosts(3), r1, nil)
	r.tick(0)
	n := r.nodes[2]
	n.set(func(f *fakeNode) { f.bytesUsed = u64(9) })
	if err := r.mon.Drain(context.Background(), n.admin()); err != nil {
		t.Fatal(err)
	}
	// The controller dies; a new Monitor (no memory of the drain) starts on the same store 60 s later.
	r.mon = New(r.cfg)
	r.tick(60 * time.Second)
	if s, _ := r.inBundle(n); s != "readonly" {
		t.Fatalf("restarted monitor: state %q, want readonly; log:\n%s", s, r.log.String())
	}
	// Dies again in readonly; the next instance sees bytes_used == 0 and finishes the drain.
	r.mon = New(r.cfg)
	n.set(func(f *fakeNode) { f.bytesUsed = u64(0) })
	r.tick(time.Second)
	if _, in := r.inBundle(n); in {
		t.Fatalf("restarted monitor did not finish the drain; log:\n%s", r.log.String())
	}
}

func TestMemberRemoveGatedOnDrained(t *testing.T) {
	r := newRig(t, hosts(3), r1, nil)
	r.tick(0)
	n := r.nodes[2]
	ctx := context.Background()
	if ok, why := r.mon.CanRemove(ctx, n.admin()); ok || !strings.Contains(why, "drain it first") {
		t.Fatalf("active node removable: %v %q", ok, why)
	}
	n.set(func(f *fakeNode) { f.bytesUsed = u64(5) })
	if err := r.mon.Drain(ctx, n.admin()); err != nil {
		t.Fatal(err)
	}
	if ok, _ := r.mon.CanRemove(ctx, n.admin()); ok {
		t.Fatal("draining node removable")
	}
	r.tick(60 * time.Second)
	if ok, why := r.mon.CanRemove(ctx, n.admin()); ok || !strings.Contains(why, "bytes_used=5") {
		t.Fatalf("readonly non-empty node removable: %v %q", ok, why)
	}
	n.set(func(f *fakeNode) { f.bytesUsed = nil })
	if ok, _ := r.mon.CanRemove(ctx, n.admin()); ok {
		t.Fatal("a node that does not report bytes_used was taken for empty")
	}
	n.set(func(f *fakeNode) { f.bytesUsed = u64(0) })
	if ok, why := r.mon.CanRemove(ctx, n.admin()); !ok {
		t.Fatalf("drained node refused: %q", why)
	}
}
