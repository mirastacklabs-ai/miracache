package api

import (
	"crypto/x509"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"miracache/controller/membership"
	"miracache/controller/publish"
)

// Wiring: member remove is gated on drained, drain start is stamped, reports reach the failure
// detector under the caller's identity, confirm_remove and the metrics route exist.
func TestMembershipGateAndRoutes(t *testing.T) {
	r := newRig(t, 2, 2)
	r.seedPublish(cfg(1, ""))
	pool := x509.NewCertPool()
	for _, n := range r.nodes {
		pool.AddCert(n.srv.Certificate())
	}
	mon := membership.New(membership.Config{Store: r.st, Pub: r.pub, Now: func() time.Time { return r.now },
		Client: &publish.NodeClient{HTTP: publish.NewMTLSClient(newCert(t, "spiffe://lab/controller"), pool)},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil))})
	r.srv.cfg.Mem = mon
	admin := r.nodes[1].admin()

	// An active node cannot be removed.
	code, out := r.call(opID, "POST", "/v1/members", map[string]any{"action": "remove", "admin": admin})
	if code != 409 || !strings.Contains(string(out), "not_drained") {
		t.Fatalf("remove of an active node: %d %s", code, out)
	}
	// Drain: state draining, the drain start stamped in the store (the timers run from it).
	r.must(opID, "POST", "/v1/members", map[string]any{"action": "set", "admin": admin, "state": "draining"})
	var since string
	for _, n := range r.state().Nodes {
		if n.Admin == admin {
			since = n.DrainSince
		}
	}
	if since != r.now.UTC().Format(time.RFC3339) {
		t.Fatalf("drain_since = %q", since)
	}
	if code, out = r.call(opID, "POST", "/v1/members", map[string]any{"action": "remove", "admin": admin}); code != 409 {
		t.Fatalf("remove of a draining node: %d %s", code, out)
	}
	// Reports: malformed bodies are 400; valid ones are accepted under the caller's identity.
	if code, _ = r.call(nodeID1, "POST", "/v1/reports", map[string]any{"nodes": []any{map[string]any{"node_id": 0}}}); code != 400 {
		t.Errorf("report with node_id 0: %d", code)
	}
	r.must(nodeID1, "POST", "/v1/reports", map[string]any{"generation": 1, "nodes": []any{
		map[string]any{"node_id": 100, "rails": []any{map[string]any{"addr": "10.9.0.100:7471", "reachable": true}}}}})
	// confirm_remove needs a pending_removal node; the operator role.
	if code, _ = r.call(opID, "POST", "/v1/members", map[string]any{"action": "confirm_remove", "admin": admin}); code != 409 {
		t.Errorf("confirm_remove of a node that is not pending: %d", code)
	}
	if code, _ = r.call(viewID, "POST", "/v1/members", map[string]any{"action": "confirm_remove", "admin": admin}); code != 403 {
		t.Errorf("confirm_remove as viewer: %d", code)
	}
	code, out = r.call(viewID, "GET", "/v1/metrics", nil)
	if code != 200 || !strings.Contains(string(out), "mira_controller_node_state") {
		t.Errorf("metrics: %d %s", code, out)
	}
}
