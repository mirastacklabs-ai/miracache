package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"miracache/controller/bundle"
	"miracache/controller/publish"
	"miracache/controller/store"
)

// authorPrefix marks bundles written by mirctl. One writer per cluster: mirctl only
// continues a bundle whose author starts with it, unless --force-writer is given.
const authorPrefix = "mirctl "

// publishFlags are the flags `bundle publish` and `bundle diff` share.
type publishFlags struct {
	tls          tlsFlags
	source       string
	keyPath      string
	secKeyPath   string
	trustPath    string
	author       string
	reason       string
	ackWait      time.Duration
	skew         time.Duration
	allowUnreach bool
	forceWriter  bool
	acceptID     idList // admin addresses whose reported node ID may replace the bundle's (a replaced node)
}

func (p *publishFlags) register(a *app, name string) *flag.FlagSet {
	fs := a.newFlags(name)
	p.tls.register(fs)
	fs.StringVar(&p.source, "source", "", "cluster.toml with the operator's intent (required)")
	fs.StringVar(&p.keyPath, "key", "", "publish signing key (64 hex seed file)")
	fs.StringVar(&p.secKeyPath, "sec-key", "", "security signing key (64 hex seed file); needed for the first publish and to change principals or rbac")
	fs.StringVar(&p.trustPath, "trust", "", "trust key file (the one the memory nodes use); optional when --sec-key is given")
	fs.StringVar(&p.author, "author", "", "bundle author (default: the first spiffe:// URI SAN of --cert)")
	fs.StringVar(&p.reason, "reason", "", "bundle reason (default: the source's reason)")
	fs.DurationVar(&p.ackWait, "ack-wait", publish.DefaultAckWait, "publish.ack_wait_ms, per node call")
	fs.DurationVar(&p.skew, "clock-skew", publish.DefaultClockSkew, "publish.clock_skew_s")
	fs.BoolVar(&p.allowUnreach, "allow-unreachable", false, "publish without nodes that are down (their IDs must already be in the cluster's bundle)")
	fs.BoolVar(&p.forceWriter, "force-writer", false, "continue a bundle that mirctl did not write (a controller was the writer)")
	fs.Var(&p.acceptID, "accept-id-change", "admin address (host:port) whose new node ID may replace the one in the bundle, for a replaced node; repeatable")
	return fs
}

// plan is the cluster as mirctl found it: the throw-away store seeded from the node with the
// highest sec_generation, and the current bundle.
type plan struct {
	pf      *publishFlags
	src     *Source
	client  *publish.NodeClient
	trust   *bundle.TrustKeys
	pubKey  ed25519.PrivateKey
	secKey  ed25519.PrivateKey // nil without --sec-key
	author  string
	ids     map[string]*publish.Identity // reachable nodes
	down    map[string]error
	best    string // admin address of the node with the highest sec_generation ("" = blank cluster)
	st      *store.Store
	cur     store.State    // the recovered state (empty for a blank cluster)
	curB    *bundle.Bundle // the recovered current bundle (nil for a blank cluster)
	cleanup func()
}

// prepare runs steps 1-3: identities of every node, the node with the highest
// sec_generation, and the current sec taken from it.
func (a *app) prepare(ctx context.Context, pf *publishFlags, needSigning bool) (*plan, error) {
	if pf.source == "" {
		return nil, errors.New("--source is required")
	}
	src, err := ReadSource(pf.source)
	if err != nil {
		return nil, err
	}
	hc, leaf, err := a.client(&pf.tls)
	if err != nil {
		return nil, err
	}
	p := &plan{pf: pf, src: src, client: &publish.NodeClient{HTTP: hc}, cleanup: func() {}}
	if needSigning {
		if pf.keyPath == "" {
			return nil, errors.New("--key is required")
		}
		if p.pubKey, err = readSeed(pf.keyPath); err != nil {
			return nil, err
		}
		if pf.secKeyPath != "" {
			if p.secKey, err = readSeed(pf.secKeyPath); err != nil {
				return nil, err
			}
		}
	}
	who := pf.author
	if who == "" {
		who = spiffeOf(leaf)
	}
	p.author = authorPrefix + who
	if strings.TrimSpace(p.author) == strings.TrimSpace(authorPrefix) {
		p.author = "mirctl"
	}
	if p.trust, err = a.buildTrust(pf, p); err != nil {
		return nil, err
	}

	// 1. GET /v1/identity on every node of the source.
	p.ids, p.down = map[string]*publish.Identity{}, map[string]error{}
	for _, adm := range src.Admins() {
		cctx, cancel := context.WithTimeout(ctx, pf.ackWait)
		id, err := p.client.Identity(cctx, adm)
		cancel()
		if err != nil {
			p.down[adm] = err
			continue
		}
		p.ids[adm] = id
	}
	if len(p.ids) == 0 {
		return nil, fmt.Errorf("no node is reachable (%s)", firstErr(p.down))
	}
	if len(p.down) > 0 && !pf.allowUnreach {
		return nil, fmt.Errorf("node %s is unreachable (%v); fix it or pass --allow-unreachable", firstKey(p.down), p.down[firstKey(p.down)])
	}

	// 3. The current sec comes from the node with the highest sec_generation.
	var bestGen, bestApplied uint64
	for _, adm := range sortedAdmins(p.ids) {
		id := p.ids[adm]
		if id.SecGeneration > bestGen || (id.SecGeneration == bestGen && bestGen > 0 && id.AppliedGeneration > bestApplied) {
			p.best, bestGen, bestApplied = adm, id.SecGeneration, id.AppliedGeneration
		}
	}
	dir, err := os.MkdirTemp("", "mirctl-")
	if err != nil {
		return nil, err
	}
	stopSig := removeOnSignal(dir, os.Exit)
	p.cleanup = func() { stopSig(); os.RemoveAll(dir) }
	if p.st, err = store.Open(dir); err != nil {
		p.cleanup()
		return nil, err
	}
	oldCleanup := p.cleanup
	p.cleanup = func() { p.st.Close(); oldCleanup() }
	if p.best == "" {
		return p, nil // blank cluster: no node has a sec
	}
	log := slog.New(slog.NewTextHandler(a.err, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cctx, cancel := context.WithTimeout(ctx, 4*pf.ackWait)
	defer cancel()
	if err := publish.Recover(cctx, p.client, p.trust, p.st, p.best, log); err != nil {
		p.cleanup()
		return nil, err
	}
	if p.cur, err = p.st.Load(); err != nil {
		p.cleanup()
		return nil, err
	}
	if p.curB, err = bundle.Open(p.trust, p.cur.LastEnvelope); err != nil {
		p.cleanup()
		return nil, err
	}
	return p, nil
}

func (a *app) buildTrust(pf *publishFlags, p *plan) (*bundle.TrustKeys, error) {
	if pf.trustPath != "" {
		return bundle.LoadTrustFile(pf.trustPath)
	}
	if p.pubKey == nil {
		return nil, errors.New("--trust is required (it verifies the bundle the cluster serves)")
	}
	if p.secKey == nil {
		return nil, errors.New("--trust is required when --sec-key is not given (the cluster's sec section must be verified)")
	}
	pub := p.pubKey.Public().(ed25519.PublicKey)
	sec := p.secKey.Public().(ed25519.PublicKey)
	if string(pub) == string(sec) {
		return bundle.NewTrustKeys(bundle.TrustKey{Public: pub, Roles: []string{bundle.RolePublish, bundle.RoleSecurity}})
	}
	return bundle.NewTrustKeys(
		bundle.TrustKey{Public: pub, Roles: []string{bundle.RolePublish}},
		bundle.TrustKey{Public: sec, Roles: []string{bundle.RoleSecurity}})
}

func firstKey(m map[string]error) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	if len(ks) == 0 {
		return ""
	}
	return ks[0]
}

func firstErr(m map[string]error) string {
	if k := firstKey(m); k != "" {
		return fmt.Sprintf("%s: %v", k, m[k])
	}
	return "no addresses"
}

func sortedAdmins(m map[string]*publish.Identity) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// secDiff names the differences between the cluster's current principals and rbac and the source's
// An empty result means they are equal. Both sides are compared in the emitted form.
func secDiff(cur *bundle.Sec, src *Source) []string {
	var out []string
	curP, srcP := map[string]bundle.Principal{}, map[string]bundle.Principal{}
	for _, p := range cur.Principals {
		curP[p.Name] = p
	}
	for _, p := range src.Principals {
		srcP[p.Name] = p
	}
	for _, n := range sortedNames(curP, srcP) {
		c, inCur := curP[n]
		s, inSrc := srcP[n]
		switch {
		case !inSrc:
			out = append(out, fmt.Sprintf("principal %q: in the cluster, not in the source", n))
		case !inCur:
			out = append(out, fmt.Sprintf("principal %q: in the source, not in the cluster", n))
		default:
			if emitOne(c) != emitOne(s) {
				out = append(out, fmt.Sprintf("principal %q: differs", n))
			}
		}
	}
	curR, srcR := map[string]bundle.RBAC{}, map[string]bundle.RBAC{}
	for _, r := range cur.RBAC {
		curR[r.Identity] = r
	}
	for _, r := range src.RBAC {
		srcR[r.Identity] = r
	}
	for _, n := range sortedNames(curR, srcR) {
		c, inCur := curR[n]
		s, inSrc := srcR[n]
		switch {
		case !inSrc:
			out = append(out, fmt.Sprintf("rbac %q: in the cluster, not in the source", n))
		case !inCur:
			out = append(out, fmt.Sprintf("rbac %q: in the source, not in the cluster", n))
		default:
			if strings.Join(c.Roles, ",") != strings.Join(s.Roles, ",") {
				out = append(out, fmt.Sprintf("rbac %q: roles differ (cluster %v, source %v)", n, c.Roles, s.Roles))
			}
		}
	}
	return out
}

func emitOne(p bundle.Principal) string {
	b, _ := bundle.EmitSec(&bundle.Sec{SecGeneration: 1, Principals: []bundle.Principal{p}})
	return string(b)
}

func sortedNames[V any](a, b map[string]V) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]V{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

func isMirctlAuthor(a string) bool { return a == "mirctl" || strings.HasPrefix(a, authorPrefix) }

// removeOnSignal deletes dir (the throw-away store) when SIGINT or SIGTERM arrives, then exits with
// 128+signal. The returned function stops the watcher.
func removeOnSignal(dir string, exit func(int)) (stop func()) {
	ch := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case s := <-ch:
			os.RemoveAll(dir)
			code := 130
			if s == syscall.SIGTERM {
				code = 143
			}
			exit(code)
		case <-done:
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			signal.Stop(ch)
			close(done)
		})
	}
}
