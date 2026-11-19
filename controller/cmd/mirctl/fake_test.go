package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"miracache/controller/bundle"
)

func seedKey(first byte) ed25519.PrivateKey {
	s := make([]byte, 32)
	for i := range s {
		s[i] = first + byte(i)
	}
	return ed25519.NewKeyFromSeed(s)
}

var (
	testPub = seedKey(0x01)
	testSec = seedKey(0x21)
)

type pushRec struct {
	gen uint64
	dry bool
	at  time.Time
}

// fakeNode is a memory node's admin API (bundle_store.cpp status codes) behind a TLS server that
// demands a client certificate: the controller/publish/fake_test.go pattern.
type fakeNode struct {
	t     *testing.T
	srv   *httptest.Server
	trust *bundle.TrustKeys

	mu          sync.Mutex
	id          uint64
	host        string
	gen, secGen uint64
	epoch       uint64
	hash        string
	secHash     string
	env         []byte
	secFloor    uint64
	pushStatus  int
	down        bool
	pushes      []pushRec
}

func newFakeNode(t *testing.T, trust *bundle.TrustKeys, id uint64, host string) *fakeNode {
	n := &fakeNode{t: t, trust: trust, id: id, host: host}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/identity", n.handleIdentity)
	mux.HandleFunc("/v1/bundle", n.handleBundle)
	n.srv = httptest.NewUnstartedServer(mux)
	n.srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert}
	n.srv.StartTLS()
	t.Cleanup(n.srv.Close)
	return n
}

func (n *fakeNode) admin() string { return n.srv.Listener.Addr().String() }

func (n *fakeNode) factory() clientFactory {
	return func(*tlsFlags) (*http.Client, *x509.Certificate, error) {
		c := n.srv.Client()
		tr := c.Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{n.srv.TLS.Certificates[0]}
		return &http.Client{Transport: tr}, nil, nil
	}
}

func reply(w http.ResponseWriter, code int, reason, detail string) {
	w.WriteHeader(code)
	fmt.Fprintf(w, `{"error":%q,"reason":%q}`, detail, reason)
}

func (n *fakeNode) handleIdentity(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		reply(w, 503, "down", "node down")
		return
	}
	rails := fmt.Sprintf(`[{"addr":"10.9.0.%d:7471","subnet":"10.9.0.0/24","protocol":"roce","up":true}]`, n.id%250)
	fmt.Fprintf(w, `{"node_id":%d,"hostname":%q,"addr":"10.9.0.%d:7471","admin":%q,"rails":%s,"applied_generation":%d,"applied_hash":%q,"sec_generation":%d,"sec_hash":%q,"epoch":%d}`,
		n.id, n.host, n.id%250, n.admin(), rails, n.gen, n.hash, n.secGen, n.secHash, n.epoch)
}

func (n *fakeNode) handleBundle(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	down := n.down
	n.mu.Unlock()
	if down {
		reply(w, 503, "down", "node down")
		return
	}
	if r.Method == http.MethodGet {
		n.mu.Lock()
		env := n.env
		n.mu.Unlock()
		if env == nil {
			reply(w, 404, "no_bundle", "none")
			return
		}
		w.Write(env)
		return
	}
	body, _ := io.ReadAll(r.Body)
	dry := r.URL.Query().Get("dry_run") == "1"
	b, err := bundle.Open(n.trust, body)
	n.mu.Lock()
	defer n.mu.Unlock()
	if err != nil {
		reply(w, 400, bundle.ReasonOf(err), err.Error())
		return
	}
	n.pushes = append(n.pushes, pushRec{b.Body.Generation, dry, time.Now()})
	if sg := b.Sec.SecGeneration; sg < max(n.secGen, n.secFloor) {
		reply(w, 409, bundle.ReasonSecGenerationLower, "sec_generation below the floor")
		return
	} else if sg == n.secGen && n.secHash != "" && n.secHash != b.SecHash {
		reply(w, 409, bundle.ReasonSecEqualGeneration, "sec differs at an equal sec_generation")
		return
	}
	switch g := b.Body.Generation; {
	case g < n.gen:
		reply(w, 409, bundle.ReasonGenerationLower, "generation below the floor")
		return
	case g == n.gen && n.hash != "" && n.hash != b.ContentHash:
		reply(w, 409, bundle.ReasonEqualGeneration, "equal generation, other hash")
		return
	}
	if dry {
		fmt.Fprint(w, `{"result":"dry_run_ok"}`)
		return
	}
	if n.pushStatus != 0 {
		reply(w, n.pushStatus, "persist", "cannot persist")
		return
	}
	n.gen, n.secGen, n.epoch = b.Body.Generation, b.Sec.SecGeneration, b.Body.Membership.Epoch
	n.hash, n.secHash, n.env = b.ContentHash, b.SecHash, append([]byte(nil), body...)
	fmt.Fprint(w, `{"result":"applied"}`)
}

func (n *fakeNode) set(f func(*fakeNode)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	f(n)
}

func (n *fakeNode) applied() (gen, sec uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.gen, n.secGen
}

func (n *fakeNode) realPushes() []pushRec {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []pushRec
	for _, p := range n.pushes {
		if !p.dry {
			out = append(out, p)
		}
	}
	return out
}

// seqReader yields next, next+1, ... as random bytes (golden output).
type seqReader struct{ next byte }

func (s *seqReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = s.next
		s.next++
	}
	return len(p), nil
}

// rig is a set of fake nodes, key files and a trust file in a temp dir.
type rig struct {
	t       *testing.T
	dir     string
	trust   *bundle.TrustKeys
	nodes   []*fakeNode
	keyPath string
	secPath string
	trustP  string
	out     *bytes.Buffer
	errw    *bytes.Buffer
	a       *app
}

func newRig(t *testing.T, n int) *rig {
	t.Helper()
	dir := t.TempDir()
	trust, err := bundle.NewTrustKeys(
		bundle.TrustKey{Public: testPub.Public().(ed25519.PublicKey), Roles: []string{bundle.RolePublish}},
		bundle.TrustKey{Public: testSec.Public().(ed25519.PublicKey), Roles: []string{bundle.RoleSecurity}})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, dir: dir, trust: trust, out: &bytes.Buffer{}, errw: &bytes.Buffer{}}
	for i := 0; i < n; i++ {
		r.nodes = append(r.nodes, newFakeNode(t, trust, uint64(1000+i), fmt.Sprintf("host%c", 'A'+i)))
	}
	r.keyPath = filepath.Join(dir, "op.key")
	r.secPath = filepath.Join(dir, "sec.key")
	r.trustP = filepath.Join(dir, "trust.toml")
	os.WriteFile(r.keyPath, []byte(hex.EncodeToString(testPub.Seed())+"\n"), 0o600)
	os.WriteFile(r.secPath, []byte(hex.EncodeToString(testSec.Seed())+"\n"), 0o600)
	tf := fmt.Sprintf("[[key]]\npublic = %q\nroles = [\"publish\"]\n\n[[key]]\npublic = %q\nroles = [\"security\"]\n",
		hex.EncodeToString(testPub.Public().(ed25519.PublicKey)), hex.EncodeToString(testSec.Public().(ed25519.PublicKey)))
	os.WriteFile(r.trustP, []byte(tf), 0o600)
	r.a = &app{out: r.out, err: r.errw, now: func() time.Time { return time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC) },
		rand: &seqReader{}, client: r.nodes[0].factory()}
	return r
}

// run executes mirctl with args and returns the exit code; output is in r.out / r.errw.
func (r *rig) run(args ...string) int {
	r.out.Reset()
	r.errw.Reset()
	return r.a.run(args)
}

const testPrincipals = `
[[principals]]
name = "prod-llama"
identities = ["spiffe://prod/vllm-host-1"]
quota_bytes = 1048576
max_scopes = 100

[[rbac]]
identity = "spiffe://ops/alice"
roles = ["security-admin"]
`

// source writes a cluster.toml for the given nodes (admin addresses) plus extra TOML.
func (r *rig) source(name string, nodes []*fakeNode, extra string) string {
	var b strings.Builder
	b.WriteString("reason = \"test\"\n")
	for _, n := range nodes {
		fmt.Fprintf(&b, "[[nodes]]\nadmin = %q\nweight = 1\n", n.admin())
	}
	if !strings.Contains(extra, "replicas") {
		b.WriteString("[config.cluster.placement]\nreplicas = 1\n")
	}
	b.WriteString(extra)
	p := filepath.Join(r.dir, name)
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return p
}

func (r *rig) publishArgs(src string, extra ...string) []string {
	return append([]string{"bundle", "publish", "--source", src, "--key", r.keyPath, "--trust", r.trustP, "--ack-wait", "500ms"}, extra...)
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }
