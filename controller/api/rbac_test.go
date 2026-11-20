package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"miracache/controller/audit"
	"miracache/controller/bundle"
	"miracache/controller/publish"
	"miracache/controller/rbac"
	"miracache/controller/store"
)

const (
	scopeID = "spiffe://lab/ops/scope"
	oddID   = "spiffe://lab/ops/odd" // bound to a role nobody defined
	aliceID = "spiffe://lab/ops/dave"
)

func (r *rig) bind(id string, roles ...string) {
	r.t.Helper()
	s := r.state()
	s.RBAC = append(s.RBAC, bundle.RBAC{Identity: id, Roles: roles})
	if err := r.st.Commit(s.Generation, s); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) auditText() string {
	r.t.Helper()
	r.srv.FlushAudit(true)
	files, _ := audit.ListFiles(r.auditD)
	if res := audit.VerifyPaths(files, nil); !res.OK {
		r.t.Fatal(res.Text())
	}
	var sb strings.Builder
	for _, f := range files {
		sb.WriteString(readAll(r.t, f))
	}
	return sb.String()
}

// The route table equals RBAC/audit plan decision 4 (controller column).
func TestRouteTable(t *testing.T) {
	want := map[string]string{
		"GET /v1/bundle": "", "GET /v1/metrics": "", "POST /v1/reports": "principal",
		"GET /v1/status": "viewer", "GET /v1/rbac": "viewer",
		"POST /v1/members": "operator", "POST /v1/config": "operator", "POST /v1/rollback": "operator",
		"POST /v1/principals": "security-admin", "POST /v1/rbac": "security-admin", "POST /v1/drop_principal": "security-admin",
	}
	got := RouteNeeds()
	if len(got) != len(want) {
		t.Fatalf("routes %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s needs %q, want %q", k, got[k], v)
		}
	}
}

// Every route x every role: 403 exactly when the role table says so. Allowed calls carry a body that
// the handler refuses (400/404), so nothing is published.
func TestRouteRoleMatrix(t *testing.T) {
	r := newRig(t, 1, 1)
	r.seedPublish(cfg(1, ""))
	r.bind(scopeID, "scope-provider")
	r.bind(oddID, "wizard")
	bodies := map[string]any{
		"POST /v1/reports": map[string]any{}, "POST /v1/members": map[string]any{},
		"POST /v1/config": map[string]any{"config_toml": "bad = ["}, "POST /v1/rollback": map[string]any{"generation": 999},
		"POST /v1/principals": map[string]any{}, "POST /v1/rbac": map[string]any{}, "POST /v1/drop_principal": map[string]any{},
	}
	who := []struct {
		id    string
		roles []string
	}{
		{viewID, []string{"viewer"}}, {opID, []string{"operator"}}, {secID, []string{"security-admin"}},
		{scopeID, []string{"scope-provider"}}, {oddID, []string{"wizard"}}, {noneID, nil},
	}
	before := r.state()
	for key, need := range RouteNeeds() {
		method, path, _ := strings.Cut(key, " ")
		for _, w := range who {
			allowed := need == "" || need == "principal"
			for _, role := range w.roles {
				allowed = allowed || rbac.Grants(role, rbac.Need(need))
			}
			code, out := r.call(w.id, method, path, bodies[key])
			if allowed && code == 403 {
				t.Errorf("%s as %v: 403 (%s), want allowed", key, w.roles, out)
			}
			if !allowed && (code != 403 || !strings.Contains(string(out), "role "+need+" required")) {
				t.Errorf("%s as %v: %d (%s), want 403 role %s required", key, w.roles, code, out, need)
			}
		}
	}
	if after := r.state(); after.Generation != before.Generation {
		t.Fatal("a probe published")
	}
	// Hard cases spelled out.
	if code, _ := r.call(secID, "POST", "/v1/members", map[string]any{}); code != 403 {
		t.Error("security-admin must not imply operator")
	}
	if code, _ := r.call(opID, "POST", "/v1/rbac", map[string]any{}); code != 403 {
		t.Error("operator must not change rbac")
	}
	text := r.auditText()
	if !strings.Contains(text, `"actor":"`+oddID+`","role":"wizard","action":"api.call"`) ||
		!strings.Contains(text, `"result":"denied"`) {
		t.Errorf("denied decisions not audited:\n%s", text)
	}
}

// A certificate without a spiffe:// URI SAN gets 403 on every route and every denial is audited.
func TestNoSANDeniedEverywhere(t *testing.T) {
	r := newRig(t, 1, 1)
	for key := range RouteNeeds() {
		method, path, _ := strings.Cut(key, " ")
		if code, _ := r.call("", method, path, map[string]any{}); code != 403 {
			t.Errorf("%s without SAN: %d, want 403", key, code)
		}
	}
	if text := r.auditText(); !strings.Contains(text, `"actor":"`+noIdentity+`"`) || !strings.Contains(text, `"result":"denied"`) {
		t.Errorf("no-SAN denial not audited:\n%s", text)
	}
}

func TestRBACSetListRemoveIsInTheBundle(t *testing.T) {
	r := newRig(t, 2, 2)
	r.seedPublish(cfg(1, ""))
	secBefore := r.nodes[0].last(t).Sec.SecGeneration
	res := r.must(secID, "POST", "/v1/rbac", map[string]any{"action": "set", "identity": aliceID, "roles": []string{"operator", "viewer"}})
	if res["sec_generation"].(float64) != float64(secBefore+1) {
		t.Fatalf("sec_generation %v, want %d", res["sec_generation"], secBefore+1)
	}
	// Alice may now run the operator routes; the same table is in the signed sec of every node.
	r.must(aliceID, "POST", "/v1/config", map[string]any{"config_toml": cfg(1, ""), "reason": "alice"})
	for _, n := range r.nodes {
		if got := rbac.RolesOf(n.last(t).Sec.RBAC, aliceID); len(got) != 2 || got[0] != "operator" {
			t.Errorf("node sec lacks alice's roles: %v", got)
		}
	}
	list := r.must(viewID, "GET", "/v1/rbac", nil)
	if bs := list["bindings"].([]any); len(bs) != 4 {
		t.Fatalf("bindings: %v", bs)
	}
	r.must(secID, "POST", "/v1/rbac", map[string]any{"action": "remove", "identity": aliceID})
	if code, _ := r.call(aliceID, "POST", "/v1/config", map[string]any{"config_toml": cfg(1, "")}); code != 403 {
		t.Errorf("removed binding still works: %d", code)
	}
	if rbac.RolesOf(r.nodes[1].last(t).Sec.RBAC, aliceID) != nil {
		t.Error("removed binding still in the node's sec")
	}
	if code, _ := r.call(secID, "POST", "/v1/rbac", map[string]any{"action": "remove", "identity": aliceID}); code != 404 {
		t.Errorf("removing an unbound identity: %d", code)
	}
	text := r.auditText()
	for _, w := range []string{`"actor":"` + secID + `","role":"security-admin","action":"rbac.set","target":"identity:` + aliceID + `","result":"ok"`,
		`"action":"rbac.remove"`, `"actor":"` + aliceID + `","role":"operator,viewer","action":"config.set"`} {
		if !strings.Contains(text, w) {
			t.Errorf("audit lacks %s:\n%s", w, text)
		}
	}
}

func TestLastSecurityAdminRefused(t *testing.T) {
	r := newRig(t, 1, 1)
	r.seedPublish(cfg(1, ""))
	before := r.state()
	for _, q := range []map[string]any{
		{"action": "remove", "identity": secID},
		{"action": "set", "identity": secID, "roles": []string{"operator"}},
	} {
		code, out := r.call(secID, "POST", "/v1/rbac", q)
		if code != 409 || !strings.Contains(string(out), "last_security_admin") {
			t.Errorf("%v: %d %s", q, code, out)
		}
	}
	if after := r.state(); after.Generation != before.Generation || len(after.RBAC) != len(before.RBAC) {
		t.Fatal("a refused change was applied")
	}
	// The publisher enforces it too, whatever the route does.
	_, err := r.pub.Publish(context.Background(), publish.Change{Reason: "clear", Edit: func(s *store.State) { s.RBAC = nil }})
	if !errors.Is(err, rbac.ErrLastSecurityAdmin) {
		t.Errorf("publisher accepted a sec without security-admin: %v", err)
	}
	// With a second admin the first can go.
	r.must(secID, "POST", "/v1/rbac", map[string]any{"action": "set", "identity": aliceID, "roles": []string{"security-admin"}})
	r.must(aliceID, "POST", "/v1/rbac", map[string]any{"action": "remove", "identity": secID})
	if text := r.auditText(); !strings.Contains(text, `"result":"error","reason":"last_security_admin`) {
		t.Errorf("refusal not audited:\n%s", text)
	}
}

func TestRBACBadInput(t *testing.T) {
	r := newRig(t, 1, 1)
	r.seedPublish(cfg(1, ""))
	for name, q := range map[string]map[string]any{
		"unknown role": {"action": "set", "identity": aliceID, "roles": []string{"root"}},
		"no roles":     {"action": "set", "identity": aliceID},
		"not spiffe":   {"action": "set", "identity": "alice", "roles": []string{"viewer"}},
		"bad action":   {"action": "grant", "identity": aliceID, "roles": []string{"viewer"}},
	} {
		if code, _ := r.call(secID, "POST", "/v1/rbac", q); code != 400 {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
	// scope-provider is accepted in bindings and grants nothing.
	r.must(secID, "POST", "/v1/rbac", map[string]any{"action": "set", "identity": scopeID, "roles": []string{"scope-provider"}})
	if code, _ := r.call(scopeID, "GET", "/v1/status", nil); code != 403 {
		t.Errorf("scope-provider read status: %d", code)
	}
}

// A publish-only key cannot sign a sec change: the nodes reject it and nothing is applied.
func TestPublishOnlyKeyCannotChangeSec(t *testing.T) {
	r := newRig(t, 2, 2)
	r.seedPublish(cfg(1, ""))
	bad := publish.New(publish.Config{Store: r.st, Trust: r.trust, PublishKey: testPub, SecurityKey: testPub,
		Client: r.client, Author: "spiffe://lab/controller", AckWait: 400 * time.Millisecond,
		Now: func() time.Time { return r.now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	r.hs.Config.Handler = New(Config{Store: r.st, Pub: bad, Audit: r.aw, Now: func() time.Time { return r.now }})
	secBefore := r.nodes[0].last(t).Sec
	code, out := r.call(secID, "POST", "/v1/rbac", map[string]any{"action": "set", "identity": aliceID, "roles": []string{"operator"}})
	if code == 200 {
		t.Fatalf("a publish-only key changed rbac: %s", out)
	}
	for _, n := range r.nodes {
		if got := n.last(t).Sec; got.SecGeneration != secBefore.SecGeneration || rbac.RolesOf(got.RBAC, aliceID) != nil {
			t.Errorf("node applied a sec signed by a publish-only key: %+v", got)
		}
	}
}

func TestPrincipalsAndDropPrincipal(t *testing.T) {
	r := newRig(t, 1, 1)
	r.seedPublish(cfg(1, ""))
	r.must(secID, "POST", "/v1/principals", map[string]any{"action": "set", "name": "batch", "identities": []string{"spiffe://prod/batch"}, "quota_bytes": 5, "max_scopes": 2})
	if got := r.nodes[0].last(t).Sec.Principals; len(got) != 2 {
		t.Fatalf("principals in the node's sec: %+v", got)
	}
	// Identity bound to two principals is refused with the node's own rule.
	if code, _ := r.call(secID, "POST", "/v1/principals", map[string]any{"action": "set", "name": "dup", "identities": []string{"spiffe://prod/batch"}}); code != 400 {
		t.Errorf("duplicate identity: %d", code)
	}
	r.must(secID, "POST", "/v1/drop_principal", map[string]any{"name": "batch", "drop_before": "2026-11-12T08:00:00Z"})
	var db string
	for _, p := range r.nodes[0].last(t).Sec.Principals {
		if p.Name == "batch" {
			db = p.DropBefore
		}
	}
	if db != "2026-11-12T08:00:00Z" {
		t.Fatalf("drop_before %q", db)
	}
	for name, c := range map[string]struct {
		q    map[string]any
		want int
	}{
		"lower":   {map[string]any{"name": "batch", "drop_before": "2026-11-12T07:00:00Z"}, 409},
		"unknown": {map[string]any{"name": "nope", "drop_before": "2026-11-12T08:00:00Z"}, 404},
		"format":  {map[string]any{"name": "batch", "drop_before": "yesterday"}, 400},
		"future":  {map[string]any{"name": "batch", "drop_before": "2027-01-01T00:00:00Z"}, 400},
	} {
		if code, out := r.call(secID, "POST", "/v1/drop_principal", c.q); code != c.want {
			t.Errorf("%s: %d %s, want %d", name, code, out, c.want)
		} else if name == "future" && !strings.Contains(fmt.Sprintf("%s", out), "later than now") {
			t.Errorf("future: error text %v lacks the \"later than now\" reason", out)
		}
	}
	// A principal edit keeps drop_before; removal works.
	r.must(secID, "POST", "/v1/principals", map[string]any{"action": "set", "name": "batch", "identities": []string{"spiffe://prod/batch"}, "quota_bytes": 9, "max_scopes": 2})
	for _, p := range r.nodes[0].last(t).Sec.Principals {
		if p.Name == "batch" && p.DropBefore != db {
			t.Errorf("edit cleared drop_before: %q", p.DropBefore)
		}
	}
	r.must(secID, "POST", "/v1/principals", map[string]any{"action": "remove", "name": "batch"})
	if code, _ := r.call(secID, "POST", "/v1/principals", map[string]any{"action": "remove", "name": "batch"}); code != 404 {
		t.Errorf("remove twice: %d", code)
	}
	if text := r.auditText(); !strings.Contains(text, `"action":"principal.drop"`) || !strings.Contains(text, `"action":"principal.remove"`) {
		t.Errorf("principal changes not audited:\n%s", text)
	}
}
