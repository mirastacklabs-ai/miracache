package publish

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"miracache/controller/bundle"
	"miracache/controller/store"
)

func principals() func(*store.State) {
	return func(s *store.State) {
		s.Principals = []bundle.Principal{{Name: "prod", Identities: []string{"spiffe://prod/vllm-1"}, QuotaBytes: 1 << 30, MaxScopes: 100}}
		s.RBAC = []bundle.RBAC{{Identity: "spiffe://ops/alice", Roles: []string{"security-admin"}}}
	}
}

// Next generation = max(store, max applied) + 1; next sec_generation likewise.
func TestGenerationChoice(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	r.nodes[0].set(func(n *fakeNode) { n.gen, n.secGen, n.epoch = 7, 4, 3 })
	r.nodes[1].set(func(n *fakeNode) { n.gen, n.secGen, n.epoch = 6, 2, 3 })

	res, err := r.publish(Change{Reason: "first", Edit: principals()})
	if err != nil {
		t.Fatal(err)
	}
	if res.Generation != 8 || res.SecGeneration != 5 {
		t.Fatalf("got gen %d sec %d, want 8 and 5 (max over nodes + 1)", res.Generation, res.SecGeneration)
	}
	if res.Epoch != 4 { // the nodes are at epoch 3 and the store is blank: never go backwards
		t.Fatalf("epoch %d, want 4", res.Epoch)
	}
	if st := r.state(); st.Generation != 8 || st.SecGeneration != 5 || len(st.History) != 1 {
		t.Fatalf("store not committed: %+v", st)
	}
	// Second publish: sec unchanged (publish-only bundle), generation +1, epoch unchanged.
	res, err = r.publish(Change{Reason: "second"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Generation != 9 || res.SecGeneration != 5 || res.Epoch != 4 {
		t.Fatalf("second: gen %d sec %d epoch %d, want 9 5 4", res.Generation, res.SecGeneration, res.Epoch)
	}
	// A node ahead of the store (another writer got to generation 20): we go above it.
	r.nodes[1].set(func(n *fakeNode) { n.gen, n.hash = 20, "" })
	res, err = r.publish(Change{Reason: "third"})
	if err != nil || res.Generation != 21 {
		t.Fatalf("third: %v %+v", err, res)
	}
	// Sec changed again: sec_generation also goes above the highest on any node.
	r.nodes[0].set(func(n *fakeNode) { n.secGen, n.secHash = 9, "" })
	res, err = r.publish(Change{Reason: "sec", Edit: func(s *store.State) {
		s.Principals = append(s.Principals, bundle.Principal{Name: "staging", Identities: []string{"spiffe://s/1"}, QuotaBytes: 1, MaxScopes: 1})
	}})
	if err != nil || res.SecGeneration != 10 {
		t.Fatalf("sec change: %v %+v", err, res)
	}
}

// Node IDs, hostnames and addresses come from /v1/identity; the view is the active nodes.
func TestMembershipLearnedFromNodes(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	res, err := r.publish(Change{Reason: "x", Edit: principals()})
	if err != nil {
		t.Fatal(err)
	}
	b, err := bundle.Open(testTrust(t), res.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[uint64]string{}
	for _, n := range b.Body.Membership.Nodes {
		ids[n.NodeID] = n.Hostname
		if len(n.Rails) == 0 || !strings.HasPrefix(n.Rails[0].Addr, "10.9.0.") {
			t.Fatalf("rails not from the node: %+v", n.Rails)
		}
	}
	if ids[1000] != "hostA" || ids[1001] != "hostB" || b.Body.Membership.Epoch != 1 || b.Body.Author != "spiffe://ops/controller" {
		t.Fatalf("bad membership %+v", b.Body.Membership)
	}
}

// Every node is dry-run before publish; one refusal aborts with no real push and no commit.
func TestDryRunAbort(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB", "hostC"}, 3)
	r.nodes[2].set(func(n *fakeNode) { n.dryStatus, n.dryReason = 400, bundle.ReasonSchema })
	_, err := r.publish(Change{Reason: "x", Edit: principals()})
	if !errors.Is(err, ErrDryRun) {
		t.Fatalf("got %v, want ErrDryRun", err)
	}
	for i, n := range r.nodes {
		if len(n.realPushes()) != 0 {
			t.Fatalf("node %d got a real push after a refused dry run", i)
		}
		n.mu.Lock()
		dry := len(n.pushes)
		n.mu.Unlock()
		if dry != 1 {
			t.Fatalf("node %d: %d dry runs, want 1", i, dry)
		}
	}
	if r.state().Generation != 0 {
		t.Fatal("the store was committed")
	}
}

func publishTwoThenJoin(t *testing.T) *rig {
	r := newRig(t, []string{"hostA", "hostB", "hostC"}, 2)
	if _, err := r.publish(Change{Reason: "base", Edit: principals()}); err != nil {
		t.Fatal(err)
	}
	return r
}

// The join pushes to the new node first; without its ack nothing else is pushed or committed.
func TestJoinAbortsWithoutNewNodeAck(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*fakeNode)
	}{
		{"error", func(n *fakeNode) { n.pushStatus = 500 }},
		{"slow", func(n *fakeNode) { n.delay = 3 * time.Second }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := publishTwoThenJoin(t)
			before := r.state().Generation
			r.nodes[2].set(tc.mod)
			_, err := r.publish(Change{Reason: "join", Join: &store.DesiredNode{Admin: r.nodes[2].admin(), Weight: 1}})
			if !errors.Is(err, ErrJoinAborted) {
				t.Fatalf("got %v, want ErrJoinAborted", err)
			}
			for i := 0; i < 2; i++ {
				if g := r.nodes[i].applied(); g != before {
					t.Fatalf("node %d moved to generation %d", i, g)
				}
				if n := len(r.nodes[i].realPushes()); n != 1 { // only the base publish
					t.Fatalf("node %d got %d real pushes, want 1", i, n)
				}
			}
			if st := r.state(); st.Generation != before || len(st.Nodes) != 2 {
				t.Fatalf("store changed: gen %d nodes %d", st.Generation, len(st.Nodes))
			}
			if !strings.Contains(r.log.String(), "join aborted") || !strings.Contains(r.log.String(), "node_id=1002") ||
				!strings.Contains(r.log.String(), "host=hostC") {
				t.Fatalf("log lacks ID + hostname of the new node:\n%s", r.log.String())
			}
		})
	}
}

func TestJoinPushesNewNodeFirst(t *testing.T) {
	r := publishTwoThenJoin(t)
	res, err := r.publish(Change{Reason: "join", Join: &store.DesiredNode{Admin: r.nodes[2].admin(), Weight: 2, Zone: ""}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Acked) != 3 || len(res.Lagging) != 0 || res.Epoch != 2 {
		t.Fatalf("result %+v", res)
	}
	c := r.nodes[2].realPushes()
	if len(c) != 1 {
		t.Fatalf("new node pushes: %d", len(c))
	}
	for i := 0; i < 2; i++ {
		ps := r.nodes[i].realPushes()
		last := ps[len(ps)-1]
		if last.gen != res.Generation || !last.at.After(c[0].at) {
			t.Fatalf("node %d was pushed (%v) before the new node (%v)", i, last.at, c[0].at)
		}
	}
	if st := r.state(); st.Generation != res.Generation || len(st.Nodes) != 3 {
		t.Fatalf("store: %+v", st)
	}
	b, _ := bundle.Open(testTrust(t), r.p.Visible())
	if b.Body.Membership.Epoch != 2 || b.Body.Membership.PreviousEpoch != 1 || len(b.Body.Membership.Previous) != 2 {
		t.Fatalf("epoch/previous view wrong: %+v", b.Body.Membership)
	}
}

// A slow node misses the ack wait: the publish succeeds, the node is lagging, reconcile re-pushes it.
func TestSlowAckThenReconcileRepush(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	r.nodes[1].set(func(n *fakeNode) { n.delay = 3 * time.Second })
	res, err := r.publish(Change{Reason: "x", Edit: principals()})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Acked) != 1 || len(res.Lagging) != 1 || res.Lagging[0] != r.nodes[1].admin() {
		t.Fatalf("result %+v", res)
	}
	if r.nodes[1].applied() != 0 {
		t.Fatal("slow node applied")
	}
	r.nodes[1].set(func(n *fakeNode) { n.delay = 0 })
	rep, err := r.p.ReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Repushed) != 1 || r.nodes[1].applied() != res.Generation || rep.Republished {
		t.Fatalf("report %+v, node gen %d", rep, r.nodes[1].applied())
	}
	// Nothing left to do.
	if rep, _ = r.p.ReconcileOnce(context.Background()); len(rep.Repushed) != 0 || rep.Republished {
		t.Fatalf("second pass did work: %+v", rep)
	}
}

// A node at the same generation with another applied_hash (a second writer) or ahead of the
// store gets the controller's content republished under a new generation, with an alert.
func TestReconcileSecondWriter(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(g uint64, n *fakeNode)
	}{
		{"same generation, other hash", func(g uint64, n *fakeNode) { n.hash = strings.Repeat("a", 64) }},
		{"ahead of the store", func(g uint64, n *fakeNode) { n.gen, n.hash = g+5, "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, []string{"hostA", "hostB"}, 2)
			res, err := r.publish(Change{Reason: "x", Edit: principals()})
			if err != nil {
				t.Fatal(err)
			}
			r.nodes[1].set(func(n *fakeNode) { tc.mod(res.Generation, n) })
			rep, err := r.p.ReconcileOnce(context.Background())
			if err != nil || !rep.Republished {
				t.Fatalf("%v %+v", err, rep)
			}
			st := r.state()
			if st.Generation <= res.Generation {
				t.Fatalf("store gen %d", st.Generation)
			}
			for i, n := range r.nodes {
				if n.applied() != st.Generation {
					t.Fatalf("node %d at %d, want %d", i, n.applied(), st.Generation)
				}
			}
			if !strings.Contains(r.log.String(), "ALERT") || !strings.Contains(r.log.String(), "host=hostB") {
				t.Fatalf("no alert naming the node:\n%s", r.log.String())
			}
		})
	}
}

// A push rejected for its sec section stops publishing, reconcile included, and the log
// names --recover-from with the node that has the highest sec_generation. The node below
// the highest sec_generation is alerted.
func TestSecRejectStops(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	res, err := r.publish(Change{Reason: "x", Edit: principals()})
	if err != nil {
		t.Fatal(err)
	}
	// hostB is the cluster's security authority (sec_generation 99, same content generation);
	// hostA lags and its floor is above the controller's sec section.
	r.nodes[1].set(func(n *fakeNode) { n.secGen = 99 })
	r.nodes[0].set(func(n *fakeNode) { n.gen, n.hash, n.secFloor = 0, "", 99 })
	rep, err := r.p.ReconcileOnce(context.Background())
	if !errors.Is(err, ErrStopped) {
		t.Fatalf("got %v, want ErrStopped", err)
	}
	if len(rep.SecBehind) != 1 || rep.SecBehind[0] != r.nodes[0].admin() {
		t.Fatalf("alert missing: %+v", rep)
	}
	if !r.p.Stopped() {
		t.Fatal("not stopped")
	}
	logs := r.log.String()
	if !strings.Contains(logs, "--recover-from "+r.nodes[1].admin()) {
		t.Fatalf("the remedy does not name the highest node:\n%s", logs)
	}
	if _, err := r.p.Publish(context.Background(), Change{Reason: "again"}); !errors.Is(err, ErrStopped) {
		t.Fatalf("publish after stop: %v", err)
	}
	if _, err := r.p.ReconcileOnce(context.Background()); !errors.Is(err, ErrStopped) {
		t.Fatalf("reconcile after stop: %v", err)
	}
	if r.state().Generation != res.Generation {
		t.Fatal("store moved after the stop")
	}
}

// The same reject during the dry run (before anything is published) also stops.
func TestSecRejectInDryRunStops(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	r.nodes[0].set(func(n *fakeNode) { n.secFloor = 50 })
	_, err := r.publish(Change{Reason: "x", Edit: principals()})
	if !errors.Is(err, ErrStopped) || !r.p.Stopped() {
		t.Fatalf("got %v", err)
	}
	if r.state().Generation != 0 {
		t.Fatal("committed")
	}
}

// A drop_before later than now + skew is rejected by the publisher.
func TestDropBeforeSkew(t *testing.T) {
	r := newRig(t, []string{"hostA"}, 1)
	bad := r.now.Add(10 * time.Minute).Format("2006-01-02T15:04:05Z")
	_, err := r.publish(Change{Reason: "x", Edit: func(s *store.State) {
		s.Principals = []bundle.Principal{{Name: "p", Identities: []string{"spiffe://p/1"}, QuotaBytes: 1, MaxScopes: 1, DropBefore: bad}}
		s.RBAC = []bundle.RBAC{{Identity: "spiffe://ops/a", Roles: []string{"security-admin"}}}
	}})
	if err == nil || !strings.Contains(err.Error(), "drop_before") {
		t.Fatalf("got %v", err)
	}
	ok := r.now.Add(time.Minute).Format("2006-01-02T15:04:05Z")
	if _, err := r.publish(Change{Reason: "x", Edit: func(s *store.State) {
		s.Principals = []bundle.Principal{{Name: "p", Identities: []string{"spiffe://p/1"}, QuotaBytes: 1, MaxScopes: 1, DropBefore: ok}}
		s.RBAC = []bundle.RBAC{{Identity: "spiffe://ops/a", Roles: []string{"security-admin"}}}
	}}); err != nil {
		t.Fatal(err)
	}
}

// After a controller clock step back, an UNCHANGED stored drop_before that is now in the future is accepted
// (the cluster stays publishable); one the caller's edit introduces or changes is still a bad edit.
func TestDropBeforeStoredAfterClockStepBack(t *testing.T) {
	const layout = "2006-01-02T15:04:05Z"
	r := newRig(t, []string{"hostA"}, 1)
	stored := r.now.Add(time.Minute).Format(layout)
	edit := func(drop string, quota uint64) func(*store.State) {
		return func(s *store.State) {
			s.Principals = []bundle.Principal{{Name: "p", Identities: []string{"spiffe://p/1"}, QuotaBytes: quota, MaxScopes: 1, DropBefore: drop}}
			s.RBAC = []bundle.RBAC{{Identity: "spiffe://ops/a", Roles: []string{"security-admin"}}}
		}
	}
	if _, err := r.publish(Change{Reason: "x", Edit: edit(stored, 1)}); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(-time.Hour) // the clock steps back: stored is now ~1 h in the future

	// Unchanged drop_before, another field edited: accepted.
	if _, err := r.publish(Change{Reason: "x", Edit: edit(stored, 2)}); err != nil {
		t.Fatalf("an unchanged stored drop_before must not be refused: %v", err)
	}
	// The caller changes it to another future value: still the caller's fault.
	_, err := r.publish(Change{Reason: "x", Edit: edit(r.now.Add(30*time.Minute).Format(layout), 2)})
	if !errors.Is(err, ErrBadEdit) {
		t.Fatalf("a changed future drop_before must be ErrBadEdit, got %v", err)
	}
	// The caller adds one to a principal that had none: also a bad edit.
	if _, err := r.publish(Change{Reason: "x", Edit: edit("", 2)}); err != nil {
		t.Fatal(err)
	}
	_, err = r.publish(Change{Reason: "x", Edit: edit(stored, 2)})
	if !errors.Is(err, ErrBadEdit) {
		t.Fatalf("a newly introduced future drop_before must be ErrBadEdit, got %v", err)
	}
}

// An unreachable member aborts an operator publish.
func TestUnreachableMemberAborts(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	r.nodes[1].srv.Close()
	if _, err := r.publish(Change{Reason: "x", Edit: principals()}); err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("got %v", err)
	}
	if r.state().Generation != 0 || len(r.nodes[0].realPushes()) != 0 {
		t.Fatal("something was published")
	}
}

// Decision 12: --recover-from imports a node's bundle.current into a fresh store, and the
// next publish continues from it with the sec section unchanged.
func TestRecoverFrom(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	res, err := r.publish(Change{Reason: "x", Edit: func(s *store.State) {
		principals()(s)
		s.ConfigTOML = "[config.cluster.placement]\nreplicas = 2\n"
	}})
	if err != nil {
		t.Fatal(err)
	}
	// A fresh store (lost state.json) and a new controller on it.
	st2, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	trust := testTrust(t)
	cl := r.nodes[0].client()
	if err := Recover(context.Background(), cl, trust, st2, r.nodes[1].admin(), nil); err != nil {
		t.Fatal(err)
	}
	got, _ := st2.Load()
	if got.Generation != res.Generation || got.SecGeneration != res.SecGeneration || len(got.Nodes) != 2 ||
		len(got.Principals) != 1 || got.Principals[0].Name != "prod" || len(got.RBAC) != 1 ||
		!strings.Contains(got.ConfigTOML, "replicas = 2") || string(got.LastEnvelope) != string(res.Envelope) {
		t.Fatalf("recovered state wrong: %+v", got)
	}
	p2 := New(Config{Store: st2, Trust: trust, PublishKey: testPub, SecurityKey: testSec, Client: cl,
		Author: "spiffe://ops/controller", AckWait: 400 * time.Millisecond, Now: func() time.Time { return r.now }})
	res2, err := p2.Publish(context.Background(), Change{Reason: "after recover"})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Generation != res.Generation+1 || res2.SecGeneration != res.SecGeneration || res2.Epoch != res.Epoch {
		t.Fatalf("after recover: %+v (was %+v)", res2, res)
	}
	b, _ := bundle.Open(trust, res2.Envelope)
	if r, ok := b.Body.Replicas(); !ok || r != 2 {
		t.Fatalf("config lost: %v", b.Body.Config)
	}
	// A node that is behind the store is refused.
	r.nodes[0].set(func(n *fakeNode) { n.env = res.Envelope })
	if err := Recover(context.Background(), cl, trust, st2, r.nodes[0].admin(), nil); err == nil {
		t.Fatal("recovering from a node behind the store must fail")
	}
	// A node that serves an envelope the trust file does not verify is refused.
	r.nodes[0].set(func(n *fakeNode) { n.env = []byte("garbage") })
	st3, _ := store.Open(t.TempDir())
	defer st3.Close()
	if err := Recover(context.Background(), cl, trust, st3, r.nodes[0].admin(), nil); err == nil {
		t.Fatal("garbage accepted")
	}
}

// Decision 12: two controllers on one store directory: the second fails the flock.
func TestTwoControllersOneStore(t *testing.T) {
	dir := t.TempDir()
	a, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := store.Open(dir); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("second controller: %v", err)
	}
}

// The reconcile period is the plan's 5 s.
func TestReconcilePeriod(t *testing.T) {
	if ReconcilePeriod != 5*time.Second {
		t.Fatal(ReconcilePeriod)
	}
}

// A CAS conflict (the store moved under us) fails the publish.
func TestPublishCASConflict(t *testing.T) {
	r := newRig(t, []string{"hostA"}, 1)
	r.nodes[0].set(func(n *fakeNode) { n.delay = 150 * time.Millisecond })
	done := make(chan error, 1)
	go func() { _, err := r.publish(Change{Reason: "x", Edit: principals()}); done <- err }()
	time.Sleep(60 * time.Millisecond) // past the dry run, inside the push
	if err := r.st.Commit(0, store.State{Generation: 50, Nodes: r.state().Nodes}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, store.ErrConflict) {
		t.Fatalf("got %v, want ErrConflict", err)
	}
}

// Rails come from the node's identity (addr, subnet, protocol); a node with unusable rails is refused.
func TestRailsRefused(t *testing.T) {
	for _, tc := range []struct{ name, rails, field string }{
		{"none", `[]`, "reports no rails"},
		{"empty subnet", `[{"addr":"10.9.0.1:7471","subnet":"","protocol":"roce","up":true}]`, "subnet is empty"},
		{"subnet not CIDR", `[{"addr":"10.9.0.1:7471","subnet":"a","protocol":"roce","up":true}]`, "not CIDR"},
		{"protocol ib", `[{"addr":"10.9.0.1:7471","subnet":"10.9.0.0/24","protocol":"ib","up":true}]`, "protocol"},
		{"empty addr", `[{"addr":"","subnet":"10.9.0.0/24","protocol":"iwarp","up":true}]`, "addr is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, []string{"hostA", "hostB"}, 2)
			r.nodes[1].set(func(n *fakeNode) { n.railsJSON = tc.rails })
			_, err := r.publish(Change{Reason: "x", Edit: principals()})
			if err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "node_id=1001") ||
				!strings.Contains(err.Error(), "host=hostB") || !strings.Contains(err.Error(), "addr=127.0.0.1") {
				t.Fatalf("got %v", err)
			}
			if r.state().Generation != 0 || len(r.nodes[0].realPushes()) != 0 {
				t.Fatal("something was published")
			}
		})
	}
}

func TestRailsRefusedOnJoin(t *testing.T) {
	r := publishTwoThenJoin(t)
	r.nodes[2].set(func(n *fakeNode) {
		n.railsJSON = `[{"addr":"10.9.0.3:7471","subnet":"10.9.0.0/24","protocol":"ib","up":true}]`
	})
	_, err := r.publish(Change{Reason: "join", Join: &store.DesiredNode{Admin: r.nodes[2].admin()}})
	if err == nil || !strings.Contains(err.Error(), "node_id=1002") || !strings.Contains(err.Error(), "protocol") {
		t.Fatalf("got %v", err)
	}
	if len(r.nodes[2].realPushes()) != 0 || len(r.state().Nodes) != 2 {
		t.Fatal("join went ahead")
	}
}

// A reconcile republish keeps a node's existing entry when its rails turn unusable.
func TestReconcileKeepsExistingRails(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	res, err := r.publish(Change{Reason: "x", Edit: principals()})
	if err != nil {
		t.Fatal(err)
	}
	r.nodes[1].set(func(n *fakeNode) { n.railsJSON = `[]`; n.hash = strings.Repeat("b", 64) })
	rep, err := r.p.ReconcileOnce(context.Background())
	if err != nil || !rep.Republished {
		t.Fatalf("%v %+v", err, rep)
	}
	b, err := bundle.Open(testTrust(t), r.p.Visible())
	if err != nil || b.Body.Generation <= res.Generation || len(b.Body.Membership.Nodes) != 2 {
		t.Fatalf("%v %+v", err, b)
	}
	for _, n := range b.Body.Membership.Nodes {
		if n.Rails[0].Protocol != "roce" || n.Rails[0].Subnet != "10.9.0.0/24" {
			t.Fatalf("rails %+v", n.Rails)
		}
	}
}

// writeState overwrites state.json directly (a simulated crash window).
func (r *rig) writeState(s store.State) {
	b, err := json.MarshalIndent(&s, "", " ")
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.dir, "state.json"), b, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// With a second writer's epoch above the last body's, an unchanged-view publish never reuses an
// epoch number; it moves to baseEpoch + 1 and records the old number as the previous epoch.
func TestEpochNeverReusedAfterSecondWriter(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	res, err := r.publish(Change{Reason: "x", Edit: principals()})
	if err != nil || res.Epoch != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	r.nodes[1].set(func(n *fakeNode) { n.epoch = 5; n.hash = "" })
	res2, err := r.publish(Change{Reason: "unchanged view"})
	if err != nil || res2.Epoch != 6 {
		t.Fatalf("epoch %d, want 6 (%v)", res2.Epoch, err)
	}
	b, _ := bundle.Open(testTrust(t), res2.Envelope)
	if b.Body.Membership.PreviousEpoch != 5 || len(b.Body.Membership.Previous) != 2 {
		t.Fatalf("membership %+v", b.Body.Membership)
	}
	// With every node at the last body's epoch the epoch is unchanged.
	res3, err := r.publish(Change{Reason: "again"})
	if err != nil || res3.Epoch != 6 {
		t.Fatalf("epoch %d, want 6 (%v)", res3.Epoch, err)
	}
}

// A node dropped from the desired state gets the removing bundle, and reconcile keeps trying
// for store.RetirePasses passes.
func TestRemovedNodeGetsRemovingBundle(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB", "hostC"}, 3)
	if _, err := r.publish(Change{Reason: "base", Edit: principals()}); err != nil {
		t.Fatal(err)
	}
	cAdmin := r.nodes[2].admin()
	drop := func(s *store.State) {
		var keep []store.DesiredNode
		for _, n := range s.Nodes {
			if n.Admin != cAdmin {
				keep = append(keep, n)
			}
		}
		s.Nodes = keep
	}
	res, err := r.publish(Change{Reason: "remove C", Edit: drop})
	if err != nil {
		t.Fatal(err)
	}
	if r.nodes[2].applied() != res.Generation {
		t.Fatalf("removed node at %d, want %d", r.nodes[2].applied(), res.Generation)
	}
	if st := r.state(); len(st.Retiring) != 1 || st.Retiring[0].Admin != cAdmin {
		t.Fatalf("retiring %+v", st.Retiring)
	}
	// The next reconcile sees it at the current generation: done.
	if _, err := r.p.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.state().Retiring) != 0 {
		t.Fatalf("retiring %+v", r.state().Retiring)
	}
}

func TestRemovedNodeRetriedThenGivenUp(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB", "hostC"}, 3)
	if _, err := r.publish(Change{Reason: "base", Edit: principals()}); err != nil {
		t.Fatal(err)
	}
	cAdmin := r.nodes[2].admin()
	r.nodes[2].set(func(n *fakeNode) { n.pushStatus = 500 })
	res, err := r.publish(Change{Reason: "remove C", Edit: dropAdmin(cAdmin)})
	if err != nil {
		t.Fatal(err)
	}
	if st := r.state(); len(st.Retiring) != 1 || st.Retiring[0].Passes != store.RetirePasses {
		t.Fatalf("retiring %+v", st.Retiring)
	}
	if _, err := r.p.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := r.state(); len(st.Retiring) != 1 || st.Retiring[0].Passes != store.RetirePasses-1 {
		t.Fatalf("after a pass: %+v", st.Retiring)
	}
	r.nodes[2].set(func(n *fakeNode) { n.pushStatus = 0 })
	if _, err := r.p.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.nodes[2].applied() != res.Generation || len(r.state().Retiring) != 0 {
		t.Fatalf("not delivered: gen %d retiring %+v", r.nodes[2].applied(), r.state().Retiring)
	}
	// A node that never answers is given up after RetirePasses passes.
	r2 := newRig(t, []string{"hostA", "hostB"}, 2)
	if _, err := r2.publish(Change{Reason: "base", Edit: principals()}); err != nil {
		t.Fatal(err)
	}
	r2.nodes[1].set(func(n *fakeNode) { n.pushStatus = 500 })
	if _, err := r2.publish(Change{Reason: "remove B", Edit: dropAdmin(r2.nodes[1].admin())}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < store.RetirePasses; i++ {
		if _, err := r2.p.ReconcileOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(r2.state().Retiring) != 0 {
		t.Fatalf("not given up: %+v", r2.state().Retiring)
	}
}

// The controller died after the nodes acked but before the store commit. Reconcile finds the
// intent record, sees a node holding exactly that body, and completes the commit instead of reverting.
func TestIntentRecordCompletedAfterCrash(t *testing.T) {
	for _, join := range []bool{false, true} {
		name := "publish"
		if join {
			name = "join"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t, []string{"hostA", "hostB", "hostC"}, 2)
			if _, err := r.publish(Change{Reason: "base", Edit: principals()}); err != nil {
				t.Fatal(err)
			}
			s1 := r.state()
			ch := Change{Reason: "next"}
			if join {
				ch = Change{Reason: "join", Join: &store.DesiredNode{Admin: r.nodes[2].admin(), Weight: 1}}
			}
			res, err := r.publish(ch)
			if err != nil {
				t.Fatal(err)
			}
			s2 := r.state()
			env, _ := bundle.ParseEnvelope(res.Envelope)
			crashed := s1.Clone()
			crashed.Pending = &store.Pending{BaseGeneration: s1.Generation, Generation: res.Generation, BodyHash: bundle.HashHex(env.Body), Next: &s2}
			r.writeState(crashed)
			if r.state().Generation != s1.Generation {
				t.Fatal("simulated crash failed")
			}
			rep, err := r.p.ReconcileOnce(context.Background())
			if err != nil || rep.Republished {
				t.Fatalf("%v %+v", err, rep)
			}
			st := r.state()
			if st.Generation != res.Generation || st.Pending != nil || string(st.LastEnvelope) != string(res.Envelope) {
				t.Fatalf("commit not completed: gen %d pending %v", st.Generation, st.Pending)
			}
			if join && len(st.Nodes) != 3 {
				t.Fatalf("joined node not in the store: %+v", st.Nodes)
			}
		})
	}
}

// A publish leaves no intent record behind, and a record no node holds is discarded (not completed).
func TestIntentRecordDiscardedWhenNobodyHoldsIt(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB"}, 2)
	if _, err := r.publish(Change{Reason: "base", Edit: principals()}); err != nil {
		t.Fatal(err)
	}
	s1 := r.state()
	if s1.Pending != nil {
		t.Fatal("pending left after a publish")
	}
	next := s1.Clone()
	next.Generation = s1.Generation + 1
	bad := s1.Clone()
	bad.Pending = &store.Pending{BaseGeneration: s1.Generation, Generation: next.Generation, BodyHash: strings.Repeat("c", 64), Next: &next}
	r.writeState(bad)
	if _, err := r.p.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := r.state(); st.Generation != s1.Generation || st.Pending != nil {
		t.Fatalf("%+v", st)
	}
}

// The controller died before any node acked (no node holds the record) and one node is dead.
// Reconcile carries on (re-pushing a lagging node) and keeps the record; a publish that removes the
// dead node succeeds, above the record's generation.
func TestUnresolvedIntentRecordDoesNotBlock(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB", "hostC"}, 3)
	if _, err := r.publish(Change{Reason: "base", Edit: principals()}); err != nil {
		t.Fatal(err)
	}
	s1 := r.state()
	next := s1.Clone()
	next.Generation = s1.Generation + 1
	rec := s1.Clone()
	rec.Pending = &store.Pending{BaseGeneration: s1.Generation, Generation: next.Generation, BodyHash: strings.Repeat("c", 64), Next: &next}
	r.writeState(rec)
	bAdmin, cAdmin := r.nodes[1].admin(), r.nodes[2].admin()
	r.nodes[2].set(func(n *fakeNode) { n.down = true })
	r.nodes[1].set(func(n *fakeNode) { n.gen, n.hash, n.env = 0, "", nil }) // B lost its bundle

	rep, err := r.p.ReconcileOnce(context.Background())
	if err != nil {
		t.Fatalf("reconcile blocked by the unresolved record: %v", err)
	}
	if len(rep.Repushed) != 1 || rep.Repushed[0] != bAdmin || len(rep.Unreachable) != 1 || rep.Unreachable[0] != cAdmin {
		t.Fatalf("report %+v", rep)
	}
	if r.nodes[1].applied() != s1.Generation {
		t.Fatalf("B at %d, want %d", r.nodes[1].applied(), s1.Generation)
	}
	if st := r.state(); st.Pending == nil || st.Generation != s1.Generation {
		t.Fatalf("record not kept: %+v", st)
	}

	res, err := r.publish(Change{Reason: "remove C", Edit: dropAdmin(cAdmin)})
	if err != nil {
		t.Fatalf("publish removing the dead node: %v", err)
	}
	if res.Generation < next.Generation+1 {
		t.Fatalf("generation %d reuses the record's %d", res.Generation, next.Generation)
	}
	if st := r.state(); st.Pending != nil || st.Generation != res.Generation || len(st.Nodes) != 2 {
		t.Fatalf("after the publish: %+v", st)
	}
}

// Only the (now dead) node C acked the record before the crash, and the record moved
// sec_generation. A tolerant publish supersedes it, above its generation and sec_generation; when C
// returns it is behind and takes a re-push: no equal-generation clash, no sec reject, no stop.
func TestUnresolvedIntentRecordNodeReturns(t *testing.T) {
	r := newRig(t, []string{"hostA", "hostB", "hostC"}, 3)
	if _, err := r.publish(Change{Reason: "base", Edit: principals()}); err != nil {
		t.Fatal(err)
	}
	s1 := r.state()
	type snap struct {
		gen, secGen, epoch uint64
		hash, secHash      string
		env                []byte
	}
	var saved [2]snap
	for i := range saved {
		r.nodes[i].set(func(n *fakeNode) { saved[i] = snap{n.gen, n.secGen, n.epoch, n.hash, n.secHash, n.env} })
	}
	res, err := r.publish(Change{Reason: "sec change", Edit: func(s *store.State) { s.Principals[0].QuotaBytes = 2 << 30 }})
	if err != nil || res.SecGeneration <= s1.SecGeneration {
		t.Fatalf("%v %+v", err, res)
	}
	s2 := r.state()
	env, _ := bundle.ParseEnvelope(res.Envelope)
	rec := s1.Clone()
	rec.Pending = &store.Pending{BaseGeneration: s1.Generation, Generation: res.Generation, BodyHash: bundle.HashHex(env.Body), Next: &s2}
	r.writeState(rec)
	for i := range saved { // A and B never got it; only C did
		r.nodes[i].set(func(n *fakeNode) {
			s := saved[i]
			n.gen, n.secGen, n.epoch, n.hash, n.secHash, n.env = s.gen, s.secGen, s.epoch, s.hash, s.secHash, s.env
		})
	}
	r.nodes[2].set(func(n *fakeNode) { n.down = true })
	if _, err := r.p.ReconcileOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	res2, err := r.publish(Change{Reason: "tolerant", TolerateUnreachable: true})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Generation <= res.Generation || res2.SecGeneration <= res.SecGeneration {
		t.Fatalf("gen %d sec %d, want above the record's %d / %d", res2.Generation, res2.SecGeneration, res.Generation, res.SecGeneration)
	}
	r.nodes[2].set(func(n *fakeNode) { n.down = false })
	rep, err := r.p.ReconcileOnce(context.Background())
	if err != nil || r.p.Stopped() || rep.Republished {
		t.Fatalf("%v stopped=%v %+v", err, r.p.Stopped(), rep)
	}
	if r.nodes[2].applied() != res2.Generation {
		t.Fatalf("C at %d, want %d", r.nodes[2].applied(), res2.Generation)
	}
	if st := r.state(); st.Pending != nil || st.Generation != res2.Generation {
		t.Fatalf("%+v", st)
	}
}

// A node holds the record's body but the store commit fails with an I/O error: the record is kept
// (discarding it would revert an acked change) and the error returned; the next pass completes it. A
// CAS conflict still discards it.
func TestIntentRecordKeptOnStoreFailure(t *testing.T) {
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "io", true: "conflict"}[conflict], func(t *testing.T) {
			r := newRig(t, []string{"hostA", "hostB"}, 2)
			if _, err := r.publish(Change{Reason: "base", Edit: principals()}); err != nil {
				t.Fatal(err)
			}
			s1 := r.state()
			res, err := r.publish(Change{Reason: "next"})
			if err != nil {
				t.Fatal(err)
			}
			s2 := r.state()
			env, _ := bundle.ParseEnvelope(res.Envelope)
			crashed := s1.Clone()
			crashed.Pending = &store.Pending{BaseGeneration: s1.Generation, Generation: res.Generation, BodyHash: bundle.HashHex(env.Body), Next: &s2}
			r.writeState(crashed)
			injected := errors.New("injected: disk I/O error")
			if conflict {
				injected = fmt.Errorf("%w: injected", store.ErrConflict)
			}
			r.st.SetCommitFault(func(n store.State) error {
				if n.Pending == nil && n.Generation == res.Generation && string(n.LastEnvelope) == string(res.Envelope) {
					return injected
				}
				return nil
			})
			_, err = r.p.ReconcileOnce(context.Background())
			if conflict {
				if err != nil {
					t.Fatal(err)
				}
				if st := r.state(); st.Pending != nil {
					t.Fatalf("conflict: record kept: %+v", st.Pending)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("got %v", err)
			}
			if st := r.state(); st.Pending == nil || st.Generation != s1.Generation {
				t.Fatalf("record discarded after an I/O error: pending %v gen %d", st.Pending, st.Generation)
			}
			r.st.SetCommitFault(nil)
			if _, err := r.p.ReconcileOnce(context.Background()); err != nil {
				t.Fatal(err)
			}
			if st := r.state(); st.Pending != nil || st.Generation != res.Generation {
				t.Fatalf("not completed: pending %v gen %d", st.Pending, st.Generation)
			}
		})
	}
}

// A sec reject from the JOINING node aborts the join only; publishing continues, and the
// remedy never names the joining node.
func TestJoinSecRejectAbortsJoinOnly(t *testing.T) {
	r := publishTwoThenJoin(t)
	before := r.state().Generation
	r.nodes[2].set(func(n *fakeNode) { n.secFloor = 99 })
	_, err := r.publish(Change{Reason: "join", Join: &store.DesiredNode{Admin: r.nodes[2].admin()}})
	if !errors.Is(err, ErrJoinAborted) || errors.Is(err, ErrStopped) || r.p.Stopped() {
		t.Fatalf("got %v stopped=%v", err, r.p.Stopped())
	}
	if r.state().Generation != before || r.state().Pending != nil {
		t.Fatal("store changed")
	}
	if _, err := r.publish(Change{Reason: "still works"}); err != nil {
		t.Fatalf("publishing stopped: %v", err)
	}
	// The recover-from source is never the joining node.
	ids := map[string]idResult{
		"a": {id: &Identity{SecGeneration: 3}},
		"j": {id: &Identity{SecGeneration: 99}},
	}
	if best, _ := highestSec(ids, "j"); best != "a" {
		t.Fatalf("highest = %q", best)
	}
}

func dropAdmin(admin string) func(*store.State) {
	return func(s *store.State) {
		var keep []store.DesiredNode
		for _, n := range s.Nodes {
			if n.Admin != admin {
				keep = append(keep, n)
			}
		}
		s.Nodes = keep
	}
}

// Only the caller's own invalid edit carries ErrBadEdit; a *bundle.Error from the
// controller's own trust file or a corrupt stored envelope is a server fault.
func TestBadEditVsServerFault(t *testing.T) {
	t.Run("future drop_before is a bad edit", func(t *testing.T) {
		r := newRig(t, []string{"hostA"}, 1)
		bad := r.now.Add(10 * time.Minute).Format("2006-01-02T15:04:05Z")
		_, err := r.publish(Change{Reason: "x", Edit: func(s *store.State) {
			s.Principals = []bundle.Principal{{Name: "p", Identities: []string{"spiffe://p/1"}, QuotaBytes: 1, MaxScopes: 1, DropBefore: bad}}
			s.RBAC = []bundle.RBAC{{Identity: "spiffe://ops/a", Roles: []string{"security-admin"}}}
		}})
		if !errors.Is(err, ErrBadEdit) || bundle.ReasonOf(err) == "" {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("own trust file refuses the signed bundle", func(t *testing.T) {
		r := newRig(t, []string{"hostA"}, 1)
		other, err := bundle.NewTrustKeys(
			bundle.TrustKey{Public: seed(0x41).Public().(ed25519.PublicKey), Roles: []string{bundle.RolePublish}},
			bundle.TrustKey{Public: testSec.Public().(ed25519.PublicKey), Roles: []string{bundle.RoleSecurity}},
		)
		if err != nil {
			t.Fatal(err)
		}
		p := New(Config{Store: r.st, Trust: other, PublishKey: testPub, SecurityKey: testSec, Client: r.nodes[0].client(),
			Author: "spiffe://ops/controller", AckWait: 400 * time.Millisecond, Now: func() time.Time { return r.now }})
		_, err = p.Publish(context.Background(), Change{Reason: "x"})
		if err == nil || errors.Is(err, ErrBadEdit) || bundle.ReasonOf(err) == "" {
			t.Fatalf("want a *bundle.Error that is not ErrBadEdit, got %v", err)
		}
	})
	t.Run("corrupt stored envelope", func(t *testing.T) {
		r := newRig(t, []string{"hostA"}, 1)
		if _, err := r.publish(Change{Reason: "first"}); err != nil {
			t.Fatal(err)
		}
		s := r.state()
		s.LastEnvelope = []byte("garbage")
		if err := r.st.Commit(s.Generation, s); err != nil {
			t.Fatal(err)
		}
		_, err := r.publish(Change{Reason: "second"})
		if err == nil || errors.Is(err, ErrBadEdit) || bundle.ReasonOf(err) == "" {
			t.Fatalf("want a *bundle.Error that is not ErrBadEdit, got %v", err)
		}
	})
}

// After a step back the controller keeps publishing the stored drop_before unchanged, so the bundle every node
// receives still carries a drop_before that looks like the future to a node with the same clock. The node (C++
// check_drop_before_not_future with the floor's stored maximum, covered by the C++ bundle tests and
// the bundle-apply tests) must accept it; this pins the controller side of that contract.
func TestStoredDropBeforeStillShippedAfterClockStepBack(t *testing.T) {
	const layout = "2006-01-02T15:04:05Z"
	r := newRig(t, []string{"hostA"}, 1)
	stored := r.now.Add(time.Minute).Format(layout)
	edit := func(quota uint64) func(*store.State) {
		return func(s *store.State) {
			s.Principals = []bundle.Principal{{Name: "p", Identities: []string{"spiffe://p/1"}, QuotaBytes: quota, MaxScopes: 1, DropBefore: stored}}
			s.RBAC = []bundle.RBAC{{Identity: "spiffe://ops/a", Roles: []string{"security-admin"}}}
		}
	}
	if _, err := r.publish(Change{Reason: "x", Edit: edit(1)}); err != nil {
		t.Fatal(err)
	}
	r.now = r.now.Add(-time.Hour)
	if _, err := r.publish(Change{Reason: "x", Edit: edit(2)}); err != nil {
		t.Fatal(err)
	}
	n := r.nodes[0]
	n.mu.Lock()
	env := append([]byte(nil), n.env...)
	n.mu.Unlock()
	b, err := bundle.Open(n.trust, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Sec.Principals) != 1 || b.Sec.Principals[0].DropBefore != stored {
		t.Fatalf("the shipped bundle must keep the stored drop_before %s, got %+v", stored, b.Sec.Principals)
	}
}
