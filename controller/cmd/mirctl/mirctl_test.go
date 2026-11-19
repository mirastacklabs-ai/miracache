package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"miracache/controller/bundle"
)

func mustRun(t *testing.T, r *rig, args ...string) {
	t.Helper()
	if code := r.run(args...); code != 0 {
		t.Fatalf("mirctl %v: exit %d\nstdout:\n%s\nstderr:\n%s", args, code, r.out.String(), r.errw.String())
	}
}

func wantFail(t *testing.T, r *rig, code int, contains string, args ...string) {
	t.Helper()
	got := r.run(args...)
	if got != code {
		t.Fatalf("mirctl %v: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", args, got, code, r.out.String(), r.errw.String())
	}
	if all := r.out.String() + r.errw.String(); !strings.Contains(all, contains) {
		t.Fatalf("mirctl %v: output lacks %q\nstdout:\n%s\nstderr:\n%s", args, contains, r.out.String(), r.errw.String())
	}
}

func envOf(t *testing.T, n *fakeNode) *bundle.Bundle {
	t.Helper()
	n.mu.Lock()
	raw := n.env
	n.mu.Unlock()
	b, err := bundle.Open(n.trust, raw)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// First publish to a blank cluster: --sec-key is required; with it every node ends at generation 1.
func TestFirstPublishNeedsSecKey(t *testing.T) {
	r := newRig(t, 2)
	src := r.source("c.toml", r.nodes, testPrincipals)
	wantFail(t, r, 1, "--sec-key is required", r.publishArgs(src)...)
	for _, n := range r.nodes {
		if len(n.realPushes()) != 0 {
			t.Fatal("a node was pushed without the first-publish key")
		}
	}
	mustRun(t, r, r.publishArgs(src, "--sec-key", r.secPath)...)
	for _, n := range r.nodes {
		g, s := n.applied()
		if g != 1 || s != 1 {
			t.Fatalf("node at generation %d sec %d, want 1/1", g, s)
		}
		b := envOf(t, n)
		if !strings.HasPrefix(b.Body.Author, "mirctl") || len(b.Sec.Principals) != 1 || b.Body.Membership.Epoch != 1 {
			t.Fatalf("unexpected bundle: author=%q epoch=%d", b.Body.Author, b.Body.Membership.Epoch)
		}
		// P33: IDs came from the node, never from the source; the key_id is computed.
		if b.Body.Membership.Nodes[0].NodeID < 1000 || b.Envelope.KeyID != bundle.KeyID(pubOf(testPub)) {
			t.Fatal("ids not computed")
		}
	}
	out := r.out.String()
	if !strings.Contains(out, "node_id=1000 host=hostA addr=127.0.0.1") || !strings.Contains(out, "published generation=1") {
		t.Fatalf("output lacks identities:\n%s", out)
	}
}

// Q06 + P11: sec comes from the node with the highest sec_generation; the next generation is above
// every applied one; a publish-only bundle keeps sec_generation.
func TestSecFromHighestAndNextGeneration(t *testing.T) {
	r := newRig(t, 2)
	src := r.source("c.toml", r.nodes, testPrincipals)
	mustRun(t, r, r.publishArgs(src, "--sec-key", r.secPath)...)
	// Change sec (second principal) with the security key: sec_generation 2 on both nodes.
	src2 := r.source("c2.toml", r.nodes, testPrincipals+"\n[[principals]]\nname = \"batch\"\nidentities = [\"spiffe://prod/batch\"]\nquota_bytes = 10\nmax_scopes = 1\n")
	mustRun(t, r, r.publishArgs(src2, "--sec-key", r.secPath)...)
	if g, s := r.nodes[1].applied(); g != 2 || s != 2 {
		t.Fatalf("got %d/%d, want 2/2", g, s)
	}
	// Node A falls back to generation 1 / sec 1 (a lagging node).
	a, b := r.nodes[0], r.nodes[1]
	first := envOf(t, a) // currently sec 2; rebuild the old state by hand below
	_ = first
	a.set(func(n *fakeNode) { n.env, n.gen, n.secGen, n.hash, n.secHash, n.epoch = nil, 0, 0, "", "", 0 })
	// The source matches sec 2 (held only by node B): taken from the highest sec_generation node.
	src3 := r.source("c3.toml", r.nodes, strings.Replace(testPrincipals, "100", "100", 1)+"\n[[principals]]\nname = \"batch\"\nidentities = [\"spiffe://prod/batch\"]\nquota_bytes = 10\nmax_scopes = 1\n")
	mustRun(t, r, r.publishArgs(src3)...)
	if g, s := a.applied(); g != 3 || s != 2 {
		t.Fatalf("node A at %d/%d, want generation 3 and sec_generation 2", g, s)
	}
	if g, s := b.applied(); g != 3 || s != 2 {
		t.Fatalf("node B at %d/%d, want 3/2", g, s)
	}
	if envOf(t, a).SecHash != envOf(t, b).SecHash {
		t.Fatal("sec bytes differ between nodes")
	}
}

// Q12: a source whose principals differ, without --sec-key, is an error naming the difference.
func TestSourceDiffersNeedsSecKey(t *testing.T) {
	r := newRig(t, 2)
	mustRun(t, r, r.publishArgs(r.source("c.toml", r.nodes, testPrincipals), "--sec-key", r.secPath)...)
	changed := strings.Replace(testPrincipals, "prod-llama", "prod-other", 1)
	src := r.source("c2.toml", r.nodes, changed)
	wantFail(t, r, 1, `principal "prod-llama": in the cluster, not in the source`, r.publishArgs(src)...)
	if g, _ := r.nodes[0].applied(); g != 1 {
		t.Fatal("a node was pushed despite the error")
	}
	// With --sec-key the change goes out under sec_generation 2.
	mustRun(t, r, r.publishArgs(src, "--sec-key", r.secPath)...)
	if g, s := r.nodes[0].applied(); g != 2 || s != 2 {
		t.Fatalf("got %d/%d, want 2/2", g, s)
	}
}

// A publish that would leave no security-admin is refused.
func TestSecKeyNeedsSecurityAdmin(t *testing.T) {
	r := newRig(t, 1)
	src := r.source("c.toml", r.nodes, "[[rbac]]\nidentity = \"spiffe://ops/bob\"\nroles = [\"operator\"]\n")
	wantFail(t, r, 1, "security-admin", r.publishArgs(src, "--sec-key", r.secPath)...)
}

// Stale keys: node ids and principal ids in the source are errors; overrides are by admin address.
func TestSourceStaleKeys(t *testing.T) {
	r := newRig(t, 1)
	for name, body := range map[string]string{
		"node id":      "[[nodes]]\nadmin = \"10.0.0.1:9465\"\nnode_id = 7\n",
		"id":           "[[nodes]]\nadmin = \"10.0.0.1:9465\"\nid = 7\n",
		"principal id": "[[nodes]]\nadmin = \"10.0.0.1:9465\"\n[[principals]]\nname = \"p\"\nprincipal_id = 3\nidentities = [\"x\"]\n",
		"override":     "[[nodes]]\nadmin = \"10.0.0.1:9465\"\n[config.node.\"3141592653\".memnode]\nfoo = 1\n",
		"unknown key":  "[[nodes]]\nadmin = \"10.0.0.1:9465\"\nbogus = 1\n",
	} {
		if _, err := ParseSource([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := "[[nodes]]\nadmin = \"10.0.0.1:9465\"\n[config.node.\"10.0.0.1:9465\".memnode]\nfoo = 1\n"
	if _, err := ParseSource([]byte(good)); err != nil {
		t.Errorf("override by admin address refused: %v", err)
	}
	_ = r
}

// The stale `id` key of a trust file is a stale-key error (key IDs are computed).
func TestTrustFileStaleID(t *testing.T) {
	r := newRig(t, 1)
	bad := filepath.Join(r.dir, "bad-trust.toml")
	os.WriteFile(bad, []byte("[[key]]\nid = \"0011223344556677\"\npublic = \""+strings.Repeat("a", 64)+"\"\nroles = [\"publish\"]\n"), 0o600)
	src := r.source("c.toml", r.nodes, "")
	args := r.publishArgs(src)
	for i, a := range args {
		if a == r.trustP {
			args[i] = bad
		}
	}
	wantFail(t, r, 1, "stale key", args...)
}

// One writer per cluster: a bundle authored by a controller is refused without --force-writer.
func TestWriterRefusal(t *testing.T) {
	r := newRig(t, 1)
	mustRun(t, r, r.publishArgs(r.source("c.toml", r.nodes, testPrincipals), "--sec-key", r.secPath)...)
	// Re-author the node's bundle as the controller would.
	n := r.nodes[0]
	b := envOf(t, n)
	body := *b.Body
	body.Generation, body.Author = 2, "spiffe://ops/mira-controller"
	bb, err := bundle.EmitBody(&body)
	if err != nil {
		t.Fatal(err)
	}
	env := bundle.SignPublishOnly(testPub, b.Envelope, bb).Marshal()
	n.set(func(f *fakeNode) {
		f.env, f.gen, f.hash = env, 2, bundle.HashHex(bb)
	})
	src := r.source("c2.toml", r.nodes, testPrincipals)
	wantFail(t, r, 1, "one writer per cluster", r.publishArgs(src)...)
	mustRun(t, r, r.publishArgs(src, "--force-writer")...)
	if g, _ := n.applied(); g != 3 {
		t.Fatalf("generation %d, want 3", g)
	}
}

// Join: the new node is pushed first; if it does not ack, the others get nothing real.
func TestJoinNewNodeFirst(t *testing.T) {
	r := newRig(t, 3)
	mustRun(t, r, r.publishArgs(r.source("c.toml", r.nodes[:2], testPrincipals), "--sec-key", r.secPath)...)
	src := r.source("c3.toml", r.nodes, testPrincipals)
	mustRun(t, r, r.publishArgs(src)...)
	nw := r.nodes[2].realPushes()
	if len(nw) != 1 || nw[0].gen != 2 {
		t.Fatalf("new node pushes: %+v", nw)
	}
	for _, n := range r.nodes[:2] {
		p := n.realPushes()
		if len(p) != 2 || !p[1].at.After(nw[0].at) {
			t.Fatalf("an existing node was pushed before the new node acked: %+v vs %+v", p, nw)
		}
		// Dry run happened on every node first.
		dry := 0
		for _, x := range n.pushes {
			if x.dry {
				dry++
			}
		}
		if dry == 0 {
			t.Fatal("no dry run on an existing node")
		}
	}
	if envOf(t, r.nodes[0]).Body.Membership.Epoch != 2 {
		t.Fatal("epoch did not move with the view")
	}
}

func TestJoinAbortsWithoutAck(t *testing.T) {
	r := newRig(t, 3)
	mustRun(t, r, r.publishArgs(r.source("c.toml", r.nodes[:2], testPrincipals), "--sec-key", r.secPath)...)
	r.nodes[2].set(func(n *fakeNode) { n.pushStatus = 500 })
	src := r.source("c3.toml", r.nodes, testPrincipals)
	wantFail(t, r, 1, "join aborted", r.publishArgs(src)...)
	for _, n := range r.nodes[:2] {
		if g, _ := n.applied(); g != 1 {
			t.Fatalf("an existing node moved to %d despite the aborted join", g)
		}
	}
}

func TestAddingTwoNodesAtOnceRefused(t *testing.T) {
	r := newRig(t, 3)
	mustRun(t, r, r.publishArgs(r.source("c.toml", r.nodes[:1], testPrincipals), "--sec-key", r.secPath)...)
	wantFail(t, r, 1, "one node per publish", r.publishArgs(r.source("c3.toml", r.nodes, testPrincipals))...)
}

// An unreachable node aborts the publish unless --allow-unreachable names a known node.
func TestUnreachable(t *testing.T) {
	r := newRig(t, 2)
	src := r.source("c.toml", r.nodes, testPrincipals)
	mustRun(t, r, r.publishArgs(src, "--sec-key", r.secPath)...)
	r.nodes[1].set(func(n *fakeNode) { n.down = true })
	wantFail(t, r, 1, "unreachable", r.publishArgs(src)...)
	mustRun(t, r, r.publishArgs(src, "--allow-unreachable")...)
	if g, _ := r.nodes[0].applied(); g != 2 {
		t.Fatalf("reachable node at %d, want 2", g)
	}
	if g, _ := r.nodes[1].applied(); g != 1 {
		t.Fatalf("down node at %d, want 1", g)
	}
}

// Q12: drop_before later than now + 300 s is rejected by the publisher.
func TestDropBeforeSkew(t *testing.T) {
	r := newRig(t, 1)
	extra := strings.Replace(testPrincipals, "max_scopes = 100", "max_scopes = 100\ndrop_before = \"2026-11-12T09:10:00Z\"", 1)
	wantFail(t, r, 1, "drop_before", r.publishArgs(r.source("c.toml", r.nodes, extra), "--sec-key", r.secPath)...)
	ok := strings.Replace(testPrincipals, "max_scopes = 100", "max_scopes = 100\ndrop_before = \"2026-11-12T09:04:00Z\"", 1)
	mustRun(t, r, r.publishArgs(r.source("c2.toml", r.nodes, ok), "--sec-key", r.secPath)...)
}

// Q06: a push rejected for its sec section stops the publish and names the node with the highest sec.
func TestSecRejectStops(t *testing.T) {
	r := newRig(t, 2)
	src := r.source("c.toml", r.nodes, testPrincipals)
	mustRun(t, r, r.publishArgs(src, "--sec-key", r.secPath)...)
	r.nodes[1].set(func(n *fakeNode) { n.secFloor = 50 })
	wantFail(t, r, 1, "publishing is stopped after a sec reject", r.publishArgs(src, "--allow-unreachable")...)
}

// Q07: bundle status exits 2 when a node is below the highest sec_generation seen.
func TestStatusAlert(t *testing.T) {
	r := newRig(t, 2)
	src := r.source("c.toml", r.nodes, testPrincipals)
	mustRun(t, r, r.publishArgs(src, "--sec-key", r.secPath)...)
	mustRun(t, r, "bundle", "status", "--source", src)
	if !strings.Contains(r.out.String(), "GENERATION") || !strings.Contains(r.out.String(), "1000") {
		t.Fatalf("status table:\n%s", r.out.String())
	}
	r.nodes[0].set(func(n *fakeNode) { n.secGen, n.secHash = 0, "" })
	wantFail(t, r, 2, "ALERT node_id=1000 host=hostA", "bundle", "status", "--source", src)
	// An unreachable node alone is exit 1.
	r.nodes[0].set(func(n *fakeNode) { n.secGen, n.secHash = 1, r.nodes[1].secHash })
	r.nodes[1].set(func(n *fakeNode) { n.down = true })
	wantFail(t, r, 1, "UNREACHABLE", "bundle", "status", "--source", src)
}

// bundle push brings a lagging node to the current envelope.
func TestPush(t *testing.T) {
	r := newRig(t, 2)
	src := r.source("c.toml", r.nodes, testPrincipals)
	mustRun(t, r, r.publishArgs(src, "--sec-key", r.secPath)...)
	r.nodes[1].set(func(n *fakeNode) { n.env, n.gen, n.secGen, n.hash, n.secHash, n.epoch = nil, 0, 0, "", "", 0 })
	mustRun(t, r, "bundle", "push", "--source", src, "--trust", r.trustP, "--ack-wait", "500ms")
	if g, s := r.nodes[1].applied(); g != 1 || s != 1 {
		t.Fatalf("lagging node at %d/%d", g, s)
	}
	if !strings.Contains(r.out.String(), "current ") || !strings.Contains(r.out.String(), "ack ") {
		t.Fatalf("push output:\n%s", r.out.String())
	}
}

// bundle diff reports what a publish would change, without pushing.
func TestDiff(t *testing.T) {
	r := newRig(t, 3)
	mustRun(t, r, r.publishArgs(r.source("c.toml", r.nodes[:2], testPrincipals), "--sec-key", r.secPath)...)
	mustRun(t, r, "bundle", "diff", "--source", r.source("same.toml", r.nodes[:2], testPrincipals), "--trust", r.trustP, "--ack-wait", "500ms")
	if !strings.Contains(r.out.String(), "no changes") {
		t.Fatalf("diff of an unchanged source:\n%s", r.out.String())
	}
	extra := strings.Replace(testPrincipals, "prod-llama", "prod-x", 1) + "[config.cluster.memnode]\nfoo = 1\n"
	mustRun(t, r, "bundle", "diff", "--source", r.source("d.toml", r.nodes, extra), "--trust", r.trustP, "--ack-wait", "500ms")
	out := r.out.String()
	for _, want := range []string{"+ node " + r.nodes[2].admin(), `sec: principal "prod-x": in the source`, "config + foo = 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff lacks %q:\n%s", want, out)
		}
	}
	if g, _ := r.nodes[2].applied(); g != 0 {
		t.Fatal("diff pushed")
	}
}

// node add/drain/remove/confirm-remove call the controller API by admin address.
func TestNodeCommands(t *testing.T) {
	r := newRig(t, 1)
	var got []map[string]any
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path != "/v1/members" || q.Method != http.MethodPost {
			http.Error(w, "bad", 404)
			return
		}
		b, _ := io.ReadAll(q.Body)
		var m map[string]any
		json.Unmarshal(b, &m)
		got = append(got, m)
		if m["admin"] == "bad:1" {
			w.WriteHeader(409)
		}
		w.Write([]byte(`{"result":"ok"}`))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	r.a.client = (&fakeNode{srv: srv}).factory()
	mustRun(t, r, "node", "add", "10.0.0.4:9465", "--controller", host, "--weight", "2", "--zone", "rack2")
	mustRun(t, r, "node", "drain", "10.0.0.4:9465", "--controller", host)
	mustRun(t, r, "node", "remove", "--controller", host, "10.0.0.4:9465")
	mustRun(t, r, "node", "confirm-remove", "10.0.0.4:9465", "--controller", host)
	mustRun(t, r, "node", "forget", "10.0.0.4:9465", "--controller", host)
	wantFail(t, r, 1, "controller answered 409", "node", "remove", "bad:1", "--controller", host)
	wantFail(t, r, 1, "--controller is required", "node", "drain", "10.0.0.4:9465")
	want := []string{`add`, `set`, `remove`, `confirm_remove`, `forget`}
	for i, w := range want {
		if got[i]["action"] != w || got[i]["admin"] != "10.0.0.4:9465" {
			t.Errorf("request %d = %v", i, got[i])
		}
	}
	if got[0]["weight"] != float64(2) || got[0]["zone"] != "rack2" || got[1]["state"] != "draining" {
		t.Errorf("add/drain fields: %v %v", got[0], got[1])
	}
	for _, m := range got {
		if _, typed := m["node_id"]; typed {
			t.Error("a node id was sent")
		}
	}
}

func TestKeysGen(t *testing.T) {
	r := newRig(t, 1)
	out := filepath.Join(r.dir, "new.key")
	mustRun(t, r, "keys", "gen", "--out", out, "--roles", "publish,security")
	st, err := os.Stat(out)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	priv, err := readSeed(out)
	if err != nil {
		t.Fatal(err)
	}
	pub := pubOf(priv)
	for _, want := range []string{"key_id: " + bundle.KeyID(pub), "public = \"" + hex.EncodeToString(pub) + "\"", `roles = ["publish", "security"]`} {
		if !strings.Contains(r.out.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, r.out.String())
		}
	}
	// The printed entry parses as a trust file entry.
	entry := r.out.String()[strings.Index(r.out.String(), "[[key]]"):]
	if _, err := bundle.ParseTrustFile([]byte(entry)); err != nil {
		t.Fatalf("trust entry: %v", err)
	}
	wantFail(t, r, 1, "already exists", "keys", "gen", "--out", out)
	if strings.Contains(r.out.String(), hex.EncodeToString(priv.Seed())) {
		t.Fatal("the seed was printed")
	}
}

// audit verify reuses controller/audit: the Go sample verifies; a tampered copy fails.
func TestAuditVerify(t *testing.T) {
	r := newRig(t, 1)
	sample := "../../../proto/golden/audit_v1/go_sample.jsonl"
	mustRun(t, r, "audit", "verify", sample)
	if !strings.HasPrefix(r.out.String(), "OK ") {
		t.Fatalf("output %q", r.out.String())
	}
	b, err := os.ReadFile(sample)
	if err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(r.dir, "audit-1.jsonl")
	os.WriteFile(bad, []byte(strings.Replace(string(b), "\"ok\"", "\"OK\"", 1)), 0o600)
	wantFail(t, r, 1, "FAIL", "audit", "verify", bad)
	wantFail(t, r, 1, "usage", "audit", "verify")
}

func TestUsage(t *testing.T) {
	r := newRig(t, 1)
	if code := r.run(); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if code := r.run("bogus", "cmd"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	_ = time.Second
}

// U2-31: a seed file readable by group or others is refused.
func TestReadSeedRefusesOpenMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(p, []byte(strings.Repeat("ab", 32)), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSeed(p); err == nil || !strings.Contains(err.Error(), "mode 0644") {
		t.Fatalf("mode 0644: %v", err)
	}
	os.Chmod(p, 0o600)
	if _, err := readSeed(p); err != nil {
		t.Fatal(err)
	}
}

// U2-35: the throw-away store directory goes away on SIGTERM.
func TestPlanTempDirRemovedOnSignal(t *testing.T) {
	dir, err := os.MkdirTemp("", "mirctl-sig-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	code := make(chan int, 1)
	stop := removeOnSignal(dir, func(c int) { code <- c })
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-code:
		if c != 143 {
			t.Errorf("exit code %d", c)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no exit after SIGTERM")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("temp dir still there")
	}
}

// The operator guide's example (cluster.toml.example) must load through the real parser.
func TestExampleClusterTomlParses(t *testing.T) {
	s, err := ReadSource(filepath.Join("..", "..", "..", "docs", "ops", "cluster.toml.example"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Nodes) != 2 || len(s.Principals) != 1 || !HasSecurityAdmin(s.RBAC) || s.ConfigTOML == "" {
		t.Fatalf("unexpected source: nodes=%d principals=%d config=%q", len(s.Nodes), len(s.Principals), s.ConfigTOML)
	}
}
