package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"miracache/controller/audit"
	"miracache/controller/bundle"
	"miracache/controller/publish"
	"miracache/controller/store"
)

const (
	opID    = "spiffe://lab/ops/alice"
	secID   = "spiffe://lab/sec/carol"
	viewID  = "spiffe://lab/ops/viewer"
	noneID  = "spiffe://lab/ops/none" // authenticated, no role
	nodeID1 = "spiffe://lab/node/1"
)

func seed(first byte) ed25519.PrivateKey {
	s := make([]byte, 32)
	for i := range s {
		s[i] = first + byte(i)
	}
	return ed25519.NewKeyFromSeed(s)
}

var (
	testPub = seed(0x01)
	testSec = seed(0x21)
)

func newCert(t *testing.T, uri string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, IsCA: true}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

type fakeNode struct {
	srv         *httptest.Server
	trust       *bundle.TrustKeys
	mu          sync.Mutex
	id          uint64
	gen, secGen uint64
	epoch       uint64
	hash, shash string
	env         []byte
	pushes      []uint64
}

func newFakeNode(t *testing.T, trust *bundle.TrustKeys, id uint64) *fakeNode {
	n := &fakeNode{trust: trust, id: id}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/identity", func(w http.ResponseWriter, r *http.Request) {
		n.mu.Lock()
		defer n.mu.Unlock()
		fmt.Fprintf(w, `{"node_id":%d,"hostname":"h%d","addr":"10.9.0.%d:7471","admin":%q,"rails":[{"addr":"10.9.0.%d:7471","subnet":"10.9.0.0/24","protocol":"roce","up":true}],"generation":%d,"applied_generation":%d,"applied_hash":%q,"sec_generation":%d,"sec_hash":%q,"epoch":%d}`,
			n.id, n.id, n.id, n.srv.Listener.Addr().String(), n.id, n.gen, n.gen, n.hash, n.secGen, n.shash, n.epoch)
	})
	mux.HandleFunc("/v1/bundle", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		b, err := bundle.Open(n.trust, body)
		n.mu.Lock()
		defer n.mu.Unlock()
		if err != nil {
			w.WriteHeader(400)
			fmt.Fprintf(w, `{"error":%q,"reason":%q}`, err.Error(), bundle.ReasonOf(err))
			return
		}
		if r.URL.Query().Get("dry_run") == "1" {
			fmt.Fprint(w, `{"result":"dry_run_ok"}`)
			return
		}
		if b.Body.Membership.Epoch < n.epoch { // receivers reject a lower epoch
			w.WriteHeader(409)
			fmt.Fprint(w, `{"error":"epoch backwards","reason":"epoch_backwards"}`)
			return
		}
		n.gen, n.secGen, n.epoch = b.Body.Generation, b.Sec.SecGeneration, b.Body.Membership.Epoch
		n.hash, n.shash, n.env = b.ContentHash, b.SecHash, body
		n.pushes = append(n.pushes, b.Body.Generation)
		fmt.Fprint(w, `{"result":"applied"}`)
	})
	n.srv = httptest.NewUnstartedServer(mux)
	n.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	n.srv.StartTLS()
	t.Cleanup(n.srv.Close)
	return n
}

func (n *fakeNode) admin() string { return n.srv.Listener.Addr().String() }

func (n *fakeNode) last(t *testing.T) *bundle.Bundle {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	b, err := bundle.Open(n.trust, n.env)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type rig struct {
	t      *testing.T
	st     *store.Store
	srv    *Server
	hs     *httptest.Server
	nodes  []*fakeNode
	auditD string
	aw     *audit.Writer
	pub    *publish.Publisher
	trust  *bundle.TrustKeys
	client *publish.NodeClient
	cert   map[string]tls.Certificate
	now    time.Time
}

func newRig(t *testing.T, nNodes int, members int) *rig {
	t.Helper()
	return newRigSec(t, nNodes, members, testSec)
}

// newRigSec is newRig with the controller's security key given (a publish-only key makes every sec change unsignable).
func newRigSec(t *testing.T, nNodes int, members int, secKey ed25519.PrivateKey) *rig {
	t.Helper()
	trust, err := bundle.NewTrustKeys(
		bundle.TrustKey{Public: testPub.Public().(ed25519.PublicKey), Roles: []string{bundle.RolePublish}},
		bundle.TrustKey{Public: testSec.Public().(ed25519.PublicKey), Roles: []string{bundle.RoleSecurity}})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, cert: map[string]tls.Certificate{}, now: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)}
	pool := x509.NewCertPool()
	var desired []store.DesiredNode
	for i := 0; i < nNodes; i++ {
		n := newFakeNode(t, trust, uint64(100+i))
		r.nodes = append(r.nodes, n)
		pool.AddCert(n.srv.Certificate())
		if i < members {
			desired = append(desired, store.DesiredNode{Admin: n.admin(), Weight: 1, State: "active"})
		}
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r.st = st
	// Operator binding through rbac; the viewer and the security admin have other or no operator role.
	err = st.Commit(0, store.State{Nodes: desired,
		RBAC: []bundle.RBAC{{Identity: opID, Roles: []string{"operator"}}, {Identity: secID, Roles: []string{"security-admin"}}, {Identity: viewID, Roles: []string{"viewer"}}}})
	if err != nil {
		t.Fatal(err)
	}
	r.trust, r.client = trust, &publish.NodeClient{HTTP: publish.NewMTLSClient(newCert(t, "spiffe://lab/controller"), pool)}
	r.pub = publish.New(publish.Config{Store: st, Trust: trust, PublishKey: testPub, SecurityKey: secKey,
		Client: r.client,
		Author: "spiffe://lab/controller", AckWait: 400 * time.Millisecond,
		Now: func() time.Time { return r.now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	r.auditD = t.TempDir()
	r.aw, err = audit.Open(audit.Config{Dir: r.auditD, Src: audit.Source{Controller: true, Host: "ctl-test", Addr: "127.0.0.1:9470"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.aw.Close() })
	r.srv = New(Config{Store: st, Pub: r.pub, Audit: r.aw, Now: func() time.Time { return r.now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	r.hs = httptest.NewUnstartedServer(r.srv)
	r.hs.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	r.hs.StartTLS()
	t.Cleanup(r.hs.Close)
	return r
}

// call performs a request as identity id ("" = a certificate without a spiffe URI SAN).
func (r *rig) call(id, method, path string, body any) (int, []byte) {
	r.t.Helper()
	c, ok := r.cert[id]
	if !ok {
		c = newCert(r.t, id)
		r.cert[id] = c
	}
	pool := x509.NewCertPool()
	pool.AddCert(r.hs.Certificate())
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{c}}}}
	defer hc.CloseIdleConnections()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, r.hs.URL+path, rd)
	resp, err := hc.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (r *rig) must(id, method, path string, body any) map[string]any {
	r.t.Helper()
	code, out := r.call(id, method, path, body)
	if code < 200 || code > 299 {
		r.t.Fatalf("%s %s as %s: %d %s", method, path, id, code, out)
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	return m
}

func (r *rig) state() store.State {
	s, err := r.st.Load()
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func cfg(replicas int, extra string) string {
	return fmt.Sprintf("[config.cluster.placement]\nreplicas = %d\n%s", replicas, extra)
}

// seedPublish gives the cluster a first bundle carrying principals, rbac and config A.
func (r *rig) seedPublish(config string) {
	r.t.Helper()
	_, err := r.pub.Publish(context.Background(), publish.Change{Reason: "seed", Edit: func(s *store.State) {
		s.Principals = []bundle.Principal{{Name: "prod", Identities: []string{"spiffe://prod/vllm-1"}, QuotaBytes: 1 << 30, MaxScopes: 10}}
		s.ConfigTOML = config
	}})
	if err != nil {
		r.t.Fatal(err)
	}
}

func TestAuthRoleMatrix(t *testing.T) {
	r := newRig(t, 2, 2)
	r.seedPublish(cfg(1, ""))
	type tc struct {
		method, path string
		body         any
		who          string
		want         int
	}
	cases := []tc{
		{"GET", "/v1/status", nil, viewID, 200},
		{"GET", "/v1/bundle", nil, viewID, 200},
		{"POST", "/v1/reports", map[string]any{"x": 1}, viewID, 202},
		{"POST", "/v1/members", map[string]any{"action": "set", "admin": r.nodes[0].admin(), "weight": 2}, viewID, 403},
		{"POST", "/v1/config", map[string]any{"config_toml": cfg(1, "")}, viewID, 403},
		{"POST", "/v1/rollback", map[string]any{"generation": 1}, viewID, 403},
		{"POST", "/v1/config", map[string]any{"config_toml": cfg(1, "")}, secID, 403}, // security-admin is not operator
		{"GET", "/v1/members", nil, opID, 405},
		{"GET", "/v1/nothing", nil, opID, 404},
	}
	for _, c := range cases {
		if code, out := r.call(c.who, c.method, c.path, c.body); code != c.want {
			t.Errorf("%s %s as %s: %d (%s), want %d", c.method, c.path, c.who, code, out, c.want)
		}
	}
	// A certificate without a spiffe URI SAN is refused outright.
	if code, _ := r.call("", "GET", "/v1/status", nil); code != 403 {
		t.Errorf("no identity: %d", code)
	}
	// The operator can use the operator routes.
	r.must(opID, "POST", "/v1/config", map[string]any{"config_toml": cfg(1, ""), "reason": "same"})
	// The TLS config demands a verified client certificate on TLS 1.3.
	tc13 := TLSConfig(newCert(t, "spiffe://x"), x509.NewCertPool())
	if tc13.MinVersion != tls.VersionTLS13 || tc13.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("tls config: %+v", tc13)
	}
}

func readAll(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestMembersAddSetRemove(t *testing.T) {
	r := newRig(t, 3, 2)
	r.seedPublish(cfg(1, ""))
	g0 := r.state().Generation

	m := r.must(opID, "POST", "/v1/members", map[string]any{"action": "add", "admin": r.nodes[2].admin(), "weight": 3, "zone": ""})
	if uint64(m["generation"].(float64)) != g0+1 {
		t.Fatalf("add: %v", m)
	}
	if got := len(r.state().Nodes); got != 3 {
		t.Fatalf("nodes after add: %d", got)
	}
	if code, _ := r.call(opID, "POST", "/v1/members", map[string]any{"action": "add", "admin": r.nodes[2].admin()}); code != 409 {
		t.Errorf("duplicate add: %d", code)
	}
	r.must(opID, "POST", "/v1/members", map[string]any{"action": "set", "admin": r.nodes[1].admin(), "state": "draining"})
	for _, n := range r.state().Nodes {
		if n.Admin == r.nodes[1].admin() && n.State != "draining" {
			t.Errorf("state not set: %+v", n)
		}
	}
	if code, _ := r.call(opID, "POST", "/v1/members", map[string]any{"action": "set", "admin": "9.9.9.9:1"}); code != 404 {
		t.Errorf("set on a non-member: %d", code)
	}
	if code, _ := r.call(opID, "POST", "/v1/members", map[string]any{"action": "set", "admin": r.nodes[0].admin(), "state": "bogus"}); code != 400 {
		t.Errorf("bad state: %d", code)
	}
	if code, _ := r.call(opID, "POST", "/v1/members", map[string]any{"action": "frob", "admin": r.nodes[0].admin()}); code != 400 {
		t.Errorf("bad action: %d", code)
	}
	if code, _ := r.call(opID, "POST", "/v1/members", map[string]any{"action": "x", "admin": r.nodes[0].admin(), "bogus": 1}); code != 400 {
		t.Errorf("unknown field: %d", code)
	}
	r.must(opID, "POST", "/v1/members", map[string]any{"action": "remove", "admin": r.nodes[1].admin()})
	if got := len(r.state().Nodes); got != 2 {
		t.Fatalf("nodes after remove: %d", got)
	}
	st := r.must(viewID, "GET", "/v1/status", nil)
	if len(st["nodes"].([]any)) != 2 {
		t.Fatalf("status: %v", st)
	}
}

// Decision 13: a rollback restores config.* only. Nothing else, however the stored body
// differs from the present.
func TestRollbackRestoresConfigOnly(t *testing.T) {
	r := newRig(t, 3, 2)
	r.seedPublish(cfg(1, "[config.cluster.memnode]\nlabel = \"A\"\n"))
	genA := r.state().Generation

	// Move on: new config B, a membership change (epoch bump) and a sec change.
	r.must(opID, "POST", "/v1/config", map[string]any{"config_toml": cfg(2, "[config.cluster.memnode]\nlabel = \"B\"\n")})
	r.must(opID, "POST", "/v1/members", map[string]any{"action": "add", "admin": r.nodes[2].admin()})
	if _, err := r.pub.Publish(context.Background(), publish.Change{Reason: "more principals", Edit: func(s *store.State) {
		s.Principals = append(s.Principals, bundle.Principal{Name: "batch", Identities: []string{"spiffe://prod/batch"}, QuotaBytes: 1, MaxScopes: 1})
		s.RBAC = append(s.RBAC, bundle.RBAC{Identity: "spiffe://lab/sec/dave", Roles: []string{"security-admin"}})
	}}); err != nil {
		t.Fatal(err)
	}
	cur := r.state()
	curEnv, _ := bundle.ParseEnvelope(cur.LastEnvelope)
	curBody, _ := bundle.ParseBody(curEnv.Body)
	curSec, _ := bundle.ParseSec(curEnv.Sec)

	// Forge the stored history body of generation genA: other membership and a higher epoch, so a
	// rollback that restored more than config.* would show up.
	forged := cur.Clone()
	for i, h := range forged.History {
		b, _ := bundle.ParseBody(h)
		if b.Generation == genA {
			b.Membership.Epoch = curBody.Membership.Epoch + 50
			b.Membership.Nodes = b.Membership.Nodes[:1]
			emitted, err := bundle.EmitBody(b)
			if err != nil {
				t.Fatal(err)
			}
			forged.History[i] = emitted
		}
	}
	if err := r.st.Commit(cur.Generation, forged); err != nil {
		t.Fatal(err)
	}

	res := r.must(opID, "POST", "/v1/rollback", map[string]any{"generation": genA})
	if uint64(res["generation"].(float64)) <= cur.Generation {
		t.Fatalf("rollback must publish a NEW generation: %v", res)
	}
	after := r.state()
	// Store: only the config changed.
	if after.ConfigTOML == cur.ConfigTOML || !strings.Contains(after.ConfigTOML, `label = "A"`) {
		t.Fatalf("config not restored: %q", after.ConfigTOML)
	}
	if fmt.Sprint(after.Nodes) != fmt.Sprint(cur.Nodes) || fmt.Sprint(after.Principals) != fmt.Sprint(cur.Principals) || fmt.Sprint(after.RBAC) != fmt.Sprint(cur.RBAC) {
		t.Fatal("rollback changed nodes, principals or rbac in the store")
	}
	// The published bundle: config A, current membership and epoch, byte-identical sec.
	env, _ := bundle.ParseEnvelope(after.LastEnvelope)
	body, _ := bundle.ParseBody(env.Body)
	sec, _ := bundle.ParseSec(env.Sec)
	if v, _ := body.Config["cluster"].(map[string]any)["memnode"].(map[string]any)["label"]; v != "A" {
		t.Fatalf("published config: %v", body.Config)
	}
	if body.Membership.Epoch != curBody.Membership.Epoch || len(body.Membership.Nodes) != len(curBody.Membership.Nodes) {
		t.Fatalf("membership/epoch restored: epoch %d (current %d), nodes %d (current %d)",
			body.Membership.Epoch, curBody.Membership.Epoch, len(body.Membership.Nodes), len(curBody.Membership.Nodes))
	}
	if sec.SecGeneration != curSec.SecGeneration || !bytes.Equal(env.Sec, curEnv.Sec) {
		t.Fatalf("sec changed by a rollback: sec_generation %d -> %d", curSec.SecGeneration, sec.SecGeneration)
	}
	if len(sec.Principals) != 2 || len(sec.RBAC) < 3 {
		t.Fatalf("principals/rbac regressed: %+v", sec)
	}
	// Every node that got the bundle accepted it (no epoch going backwards) and holds the same epoch.
	for _, n := range r.nodes[:3] {
		nb := n.last(t)
		if nb.Body.Membership.Epoch != curBody.Membership.Epoch || nb.Body.Generation != body.Generation {
			t.Errorf("node %d: epoch %d gen %d", n.id, nb.Body.Membership.Epoch, nb.Body.Generation)
		}
	}
	// Audit: the rollback names the actor, the source generation and the (new) generation.
	files, _ := audit.ListFiles(r.auditD)
	if v := audit.VerifyPaths(files, nil); !v.OK {
		t.Fatal(v.Text())
	}
	raw := readAll(t, files[0])
	if !strings.Contains(raw, `"action":"config.rollback","target":"generation:`+fmt.Sprint(genA)+`","result":"ok","reason":"config only","count":1,"generation":`+fmt.Sprint(after.Generation)) {
		t.Errorf("no rollback audit entry:\n%s", raw)
	}
	if strings.Contains(raw, "label") {
		t.Error("config values leaked into the audit log")
	}
}

func TestRollbackErrors(t *testing.T) {
	r := newRig(t, 1, 1)
	r.seedPublish(cfg(1, ""))
	g := r.state().Generation
	if code, _ := r.call(opID, "POST", "/v1/rollback", map[string]any{"generation": 9999}); code != 404 {
		t.Errorf("unknown generation: %d", code)
	}
	if r.state().Generation != g {
		t.Error("a failed rollback published")
	}
	if code, _ := r.call(opID, "POST", "/v1/rollback", map[string]any{"generation": 1, "sec": "old"}); code != 400 {
		t.Errorf("a rollback body with extra fields: %d", code)
	}
	if code, _ := r.call(opID, "POST", "/v1/config", map[string]any{"config_toml": "not = [valid"}); code != 400 {
		t.Errorf("bad toml: %d", code)
	}
	// A config the nodes' dry run (here: bundle validation) refuses is an error entry, not a publish.
	code, _ := r.call(opID, "POST", "/v1/config", map[string]any{"config_toml": "[config]\ncluster = 5\n"})
	if code == 200 {
		t.Error("an invalid config was published")
	}
	files, _ := audit.ListFiles(r.auditD)
	if raw := readAll(t, files[0]); !strings.Contains(raw, `"action":"config.set","target":"config","result":"error"`) {
		t.Errorf("no error entry:\n%s", raw)
	}
}

func TestReportsAttributedToIdentity(t *testing.T) {
	r := newRig(t, 1, 1)
	r.must(nodeID1, "POST", "/v1/reports", map[string]any{"node_id": 7, "from": "spiffe://evil"})
	if b, ok := r.srv.Report(nodeID1); !ok || !strings.Contains(string(b), "evil") {
		t.Fatalf("report not stored under the caller's identity: %q", b)
	}
	if _, ok := r.srv.Report("spiffe://evil"); ok {
		t.Fatal("report attributed to a body field")
	}
	if code, _ := r.call(nodeID1, "POST", "/v1/reports", "not an object"); code != 400 {
		t.Errorf("non-object report: %d", code)
	}
	if st := r.must(viewID, "GET", "/v1/status", nil); st["reports"].(float64) != 1 {
		t.Errorf("status: %v", st)
	}
}

func TestBundleRoute(t *testing.T) {
	r := newRig(t, 1, 1)
	if code, _ := r.call(viewID, "GET", "/v1/bundle", nil); code != 404 {
		t.Errorf("before any publish: %d", code)
	}
	r.seedPublish(cfg(1, ""))
	code, out := r.call(viewID, "GET", "/v1/bundle", nil)
	if code < 200 || code > 299 {
		t.Fatal(code)
	}
	if _, err := bundle.ParseEnvelope(out); err != nil {
		t.Fatal(err)
	}
}
