package api

import (
	"testing"
	"time"

	"miracache/controller/audit"
	"miracache/controller/store"
)

// V03: a new second for the same key before the flush must not lose the unflushed window.
func TestCoalescerKeepsUnflushedWindow(t *testing.T) {
	c := newCoalescer()
	e := audit.Entry{Actor: "spiffe://x", Action: "api.call", Result: "denied"}
	t0 := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	c.add(e, t0)
	c.add(e, t0)
	c.add(e, t0.Add(time.Second)) // no flush in between
	out := c.flush(t0.Add(time.Second), false)
	if len(out) != 1 || out[0].Count != 2 {
		t.Fatalf("flush of the finished second: %+v", out)
	}
	out = c.flush(t0.Add(2*time.Second), false)
	if len(out) != 1 || out[0].Count != 1 {
		t.Fatalf("flush of the next second: %+v", out)
	}
	if out = c.flush(t0.Add(time.Hour), true); len(out) != 0 {
		t.Fatalf("left over: %+v", out)
	}
}

func (r *rig) failed(admin string) {
	r.t.Helper()
	st := r.state()
	st.Failed = append(st.Failed, store.FailedNode{Admin: admin, NodeID: 7, Weight: 1, Since: "2026-11-12T08:00:00Z"})
	if err := r.st.Commit(st.Generation, st); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) isFailed(admin string) bool {
	for _, f := range r.state().Failed {
		if f.Admin == admin {
			return true
		}
	}
	return false
}

// V04: operator actions clear the failed record, and forget clears it on request.
func TestOperatorActionsClearFailedRecords(t *testing.T) {
	r := newRig(t, 3, 2)
	r.seedPublish(cfg(1, ""))
	third, member := r.nodes[2].admin(), r.nodes[1].admin()
	// add of a failed address
	r.failed(third)
	r.must(opID, "POST", "/v1/members", map[string]any{"action": "add", "admin": third})
	if r.isFailed(third) {
		t.Error("member add left the failed record (an operator removal would auto-rejoin)")
	}
	// remove of a member with a stale record
	r.failed(member)
	r.must(opID, "POST", "/v1/members", map[string]any{"action": "remove", "admin": member})
	if r.isFailed(member) {
		t.Error("member remove left the failed record")
	}
	// forget
	r.failed(member)
	if code, _ := r.call(viewID, "POST", "/v1/members", map[string]any{"action": "forget", "admin": member}); code != 403 {
		t.Errorf("forget as viewer: %d", code)
	}
	r.must(opID, "POST", "/v1/members", map[string]any{"action": "forget", "admin": member})
	if r.isFailed(member) {
		t.Error("forget did not clear the record")
	}
	if code, _ := r.call(opID, "POST", "/v1/members", map[string]any{"action": "forget", "admin": member}); code != 404 {
		t.Errorf("second forget: %d", code)
	}
}

// V15: the drain start is stamped on a move from active to draining or readonly.
func TestDrainSinceStampedForReadonlyToo(t *testing.T) {
	r := newRig(t, 3, 3)
	r.seedPublish(cfg(1, ""))
	admin := r.nodes[2].admin()
	r.must(opID, "POST", "/v1/members", map[string]any{"action": "set", "admin": admin, "state": "readonly"})
	for _, n := range r.state().Nodes {
		if n.Admin == admin && n.DrainSince != r.now.UTC().Format(time.RFC3339) {
			t.Errorf("drain_since = %q after active -> readonly", n.DrainSince)
		}
	}
}

// V16: the API's own report storage follows the same cap policy (429, stale ones make room).
func TestReportCap429(t *testing.T) {
	r := newRig(t, 1, 1)
	r.srv.cfg.MaxReporters = 2
	body := map[string]any{"x": 1}
	r.must("spiffe://lab/c/1", "POST", "/v1/reports", body)
	r.must("spiffe://lab/c/2", "POST", "/v1/reports", body)
	if code, _ := r.call("spiffe://lab/c/3", "POST", "/v1/reports", body); code != 429 {
		t.Fatalf("third identity: %d", code)
	}
	r.now = r.now.Add(10 * time.Second)
	r.must("spiffe://lab/c/3", "POST", "/v1/reports", body)
}
