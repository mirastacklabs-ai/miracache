package membership

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"miracache/controller/audit"
	"miracache/controller/bundle"
	"miracache/controller/publish"
	"miracache/controller/store"
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

func testTrust(t *testing.T) *bundle.TrustKeys {
	t.Helper()
	tr, err := bundle.NewTrustKeys(
		bundle.TrustKey{Public: testPub.Public().(ed25519.PublicKey), Roles: []string{bundle.RolePublish}},
		bundle.TrustKey{Public: testSec.Public().(ed25519.PublicKey), Roles: []string{bundle.RoleSecurity}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// fakeNode is a memory node's admin API behind a TLS server that demands a client certificate.
type fakeNode struct {
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
	down        bool    // every request answers 503
	railsUp     []bool  // one entry per rail
	bytesUsed   *uint64 // nil = not reported
}

func newFakeNode(t *testing.T, trust *bundle.TrustKeys, id uint64, host string) *fakeNode {
	n := &fakeNode{trust: trust, id: id, host: host, railsUp: []bool{true}}
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

func (n *fakeNode) client() *publish.NodeClient {
	c := n.srv.Client()
	tr := c.Transport.(*http.Transport).Clone()
	tr.TLSClientConfig.Certificates = []tls.Certificate{n.srv.TLS.Certificates[0]}
	return &publish.NodeClient{HTTP: &http.Client{Transport: tr}}
}

func (n *fakeNode) handleIdentity(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.down {
		w.WriteHeader(503)
		return
	}
	var rails []map[string]any
	for i, up := range n.railsUp {
		rails = append(rails, map[string]any{"addr": fmt.Sprintf("10.9.%d.%d:7471", i, n.id%250), "subnet": fmt.Sprintf("10.9.%d.0/24", i),
			"protocol": "roce", "up": up, "port_state": "ACTIVE", "listener_ok": up})
	}
	out := map[string]any{"node_id": n.id, "hostname": n.host, "addr": "10.9.0.1:7471", "admin": n.admin(), "rails": rails,
		"applied_generation": n.gen, "applied_hash": n.hash, "sec_generation": n.secGen, "sec_hash": n.secHash, "epoch": n.epoch,
		"member_state": "active"}
	if n.bytesUsed != nil {
		out["bytes_used"] = *n.bytesUsed
	}
	json.NewEncoder(w).Encode(out)
}

func (n *fakeNode) handleBundle(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	down := n.down
	n.mu.Unlock()
	if down {
		w.WriteHeader(503)
		return
	}
	if r.Method == http.MethodGet {
		n.mu.Lock()
		env := n.env
		n.mu.Unlock()
		if env == nil {
			w.WriteHeader(404)
			return
		}
		w.Write(env)
		return
	}
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
	if b.Body.Membership.Epoch < n.epoch || b.Body.Generation < n.gen {
		w.WriteHeader(409)
		fmt.Fprint(w, `{"error":"older","reason":"generation_lower"}`)
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

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type rig struct {
	t     *testing.T
	st    *store.Store
	pub   *publish.Publisher
	mon   *Monitor
	log   *syncBuf
	nodes []*fakeNode
	now   time.Time
	cfg   Config
}

// newRig starts one fake node per host, all of them desired members, publishes generation 1 and
// returns a Monitor on a fake clock. extra is stored as the config.* TOML.
func newRig(t *testing.T, hosts []string, extra string, tweak func(*Config)) *rig {
	t.Helper()
	trust := testTrust(t)
	r := &rig{t: t, log: &syncBuf{}, now: time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)}
	var desired []store.DesiredNode
	for i, h := range hosts {
		n := newFakeNode(t, trust, uint64(1000+i), h)
		r.nodes = append(r.nodes, n)
		desired = append(desired, store.DesiredNode{Admin: n.admin(), Weight: 1, State: "active"})
	}
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	r.st = st
	if err := st.Commit(0, store.State{Nodes: desired, ConfigTOML: extra}); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(r.log, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r.pub = publish.New(publish.Config{Store: st, Trust: trust, PublishKey: testPub, SecurityKey: testSec,
		Client: r.nodes[0].client(), Author: "spiffe://ops/controller", AckWait: 400 * time.Millisecond,
		Now: func() time.Time { return r.now }, Log: logger})
	if _, err := r.pub.Publish(context.Background(), publish.Change{Reason: "init"}); err != nil {
		t.Fatal(err)
	}
	r.cfg = Config{Store: st, Pub: r.pub, Client: r.nodes[0].client(), PollTimeout: 400 * time.Millisecond,
		Now: func() time.Time { return r.now }, Log: logger, Audit: &memAudit{}}
	if tweak != nil {
		tweak(&r.cfg)
	}
	r.mon = New(r.cfg)
	return r
}

// tick advances the fake clock by d and runs one monitor tick.
func (r *rig) tick(d time.Duration) {
	r.t.Helper()
	r.now = r.now.Add(d)
	if err := r.mon.Tick(context.Background()); err != nil {
		r.t.Fatal(err)
	}
}

// ticks runs n ticks of 1 s.
func (r *rig) ticks(n int) {
	for i := 0; i < n; i++ {
		r.tick(time.Second)
	}
}

func (r *rig) state() store.State {
	s, err := r.st.Load()
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *rig) body() *bundle.Body {
	st := r.state()
	b := lastBody(&st)
	if b == nil {
		r.t.Fatal("no bundle")
	}
	return b
}

func (r *rig) epoch() uint64 { return r.body().Membership.Epoch }

func (r *rig) inBundle(n *fakeNode) (state string, ok bool) {
	for _, x := range r.body().Membership.Nodes {
		if x.Admin == n.admin() {
			return x.State, true
		}
	}
	return "", false
}

func (r *rig) desiredCount() int { return len(r.state().Nodes) }

// report submits a client report from an identity: for each node id, the reachability of its rails.
func (r *rig) report(identity string, seen map[uint64][]bool) {
	r.t.Helper()
	var rep Report
	for id, rails := range seen {
		rn := ReportNode{NodeID: id}
		for i, ok := range rails {
			rn.Rails = append(rn.Rails, ReportRail{Addr: fmt.Sprintf("10.9.%d.1:7471", i), Reachable: ok})
		}
		rep.Nodes = append(rep.Nodes, rn)
	}
	b, _ := json.Marshal(rep)
	if err := r.mon.Submit(identity, b, r.now); err != nil {
		r.t.Fatal(err)
	}
}

func u64(v uint64) *uint64 { return &v }

// memAudit is the default test auditor (automatic actions need one).
type memAudit struct {
	mu sync.Mutex
	es []string
}

func (a *memAudit) Append(e audit.Entry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.es = append(a.es, e.Action)
	return nil
}
