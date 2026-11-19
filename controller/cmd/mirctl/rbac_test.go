package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mirctl rbac set|list talk to /v1/rbac by identity and role names; nothing else is sent.
func TestRBACCommands(t *testing.T) {
	r := newRig(t, 1)
	var got []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path != "/v1/rbac" {
			http.Error(w, "bad", 404)
			return
		}
		if q.Method == http.MethodGet {
			w.Write([]byte(`{"bindings":[{"Identity":"spiffe://b","Roles":["viewer"]},{"Identity":"spiffe://a","Roles":["security-admin","operator"]}]}`))
			return
		}
		b, _ := io.ReadAll(q.Body)
		var m map[string]any
		json.Unmarshal(b, &m)
		got = append(got, m)
		if m["identity"] == "spiffe://last" {
			w.WriteHeader(409)
			w.Write([]byte(`{"reason":"last_security_admin"}`))
			return
		}
		w.Write([]byte(`{"generation":2}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	r.a.client = (&fakeNode{srv: srv}).factory()

	mustRun(t, r, "rbac", "set", "spiffe://carol", "--roles", "operator,viewer", "--controller", host)
	mustRun(t, r, "rbac", "set", "spiffe://carol", "--remove", "--controller", host)
	if len(got) != 2 || got[0]["action"] != "set" || got[0]["identity"] != "spiffe://carol" ||
		len(got[0]["roles"].([]any)) != 2 || got[1]["action"] != "remove" {
		t.Fatalf("requests: %v", got)
	}
	mustRun(t, r, "rbac", "list", "--controller", host)
	if out := r.out.String(); out != "spiffe://a security-admin,operator\nspiffe://b viewer\n" {
		t.Fatalf("list output %q", out)
	}
	wantFail(t, r, 1, "controller answered 409", "rbac", "set", "spiffe://last", "--remove", "--controller", host)
	wantFail(t, r, 1, "usage", "rbac", "set", "spiffe://x", "--controller", host)
	wantFail(t, r, 1, "usage", "rbac", "set", "spiffe://x", "--roles", "viewer", "--remove", "--controller", host)
	wantFail(t, r, 1, "--controller is required", "rbac", "list")
}

// --accept-id-change lets a replaced node's new ID into the bundle; without it the old entry is kept.
func TestAcceptIDChange(t *testing.T) {
	r := newRig(t, 2)
	src := r.source("c.toml", r.nodes, testPrincipals)
	mustRun(t, r, r.publishArgs(src, "--sec-key", r.secPath)...)
	idOf := func(n *fakeNode) uint64 {
		for _, m := range envOf(t, r.nodes[0]).Body.Membership.Nodes {
			if m.Admin == n.admin() {
				return m.NodeID
			}
		}
		t.Fatal("node not in bundle")
		return 0
	}
	old := idOf(r.nodes[1])
	r.nodes[1].set(func(n *fakeNode) { n.id = 4242 })

	mustRun(t, r, r.publishArgs(src)...)
	if got := idOf(r.nodes[1]); got != old {
		t.Fatalf("without the flag the node ID changed: %d -> %d", old, got)
	}
	wantFail(t, r, 1, "not a node in the source", r.publishArgs(src, "--accept-id-change", "10.9.9.9:1")...)
	mustRun(t, r, r.publishArgs(src, "--accept-id-change", r.nodes[1].admin())...)
	if got := idOf(r.nodes[1]); got != 4242 {
		t.Fatalf("with the flag the node ID is %d, want 4242", got)
	}
}
