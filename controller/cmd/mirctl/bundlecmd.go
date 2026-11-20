package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"miracache/controller/bundle"
	"miracache/controller/publish"
	"miracache/controller/store"
)

// who is the log identity of a node: ID, hostname and IP (goal 10).
func who(id *publish.Identity, admin string) string {
	if id == nil {
		return fmt.Sprintf("node_id=unknown host=unknown addr=%s", hostPart(admin))
	}
	return fmt.Sprintf("node_id=%d host=%s addr=%s", id.NodeID, id.Hostname, hostPart(admin))
}

func hostPart(admin string) string {
	if i := strings.LastIndex(admin, ":"); i > 0 {
		return admin[:i]
	}
	return admin
}

// bundlePublish is `mirctl bundle publish`: without a controller, direct to the nodes,
// through the controller's publish pipeline (dry run on every node, new node first on a join).
func (a *app) bundlePublish(args []string) error {
	var pf publishFlags
	fs := pf.register(a, "bundle publish")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	ctx := context.Background()
	p, err := a.prepare(ctx, &pf, true)
	if err != nil {
		return err
	}
	defer p.cleanup()

	// One writer per cluster.
	if p.curB != nil && !isMirctlAuthor(p.curB.Body.Author) && !pf.forceWriter {
		return fmt.Errorf("the current bundle (generation %d) was written by %q, not by mirctl: one writer per cluster; "+
			"use the controller, or pass --force-writer if it is retired", p.curB.Body.Generation, p.curB.Body.Author)
	}
	// The first publish to a blank cluster needs the security key.
	if p.best == "" && p.secKey == nil {
		return errors.New("first publish: no node has a sec section yet, so --sec-key is required")
	}
	// A source whose principals or rbac differ from the cluster's, without --sec-key, is an error.
	var curRBAC []bundle.RBAC
	if p.curB != nil {
		curRBAC = p.curB.Sec.RBAC
		if d := secDiff(p.curB.Sec, p.src); len(d) > 0 && p.secKey == nil {
			return fmt.Errorf("the source's principals or rbac differ from the cluster's current sec (sec_generation %d) and no --sec-key was given; "+
				"mirctl never silently drops a change:\n  %s", p.curB.Sec.SecGeneration, strings.Join(d, "\n  "))
		}
	}
	if p.secKey != nil {
		if (HasSecurityAdmin(curRBAC) || len(p.src.RBAC) > 0) && !HasSecurityAdmin(p.src.RBAC) {
			return errors.New("the source would leave the cluster without a security-admin in rbac")
		}
	}
	// A node that is down must already be in the cluster's bundle (its ID cannot be learned).
	for _, adm := range sortedKeys(p.down) {
		if !bundleHasAdmin(p.curB, adm) {
			return fmt.Errorf("node %s is unreachable and not in the cluster's current bundle: its ID cannot be learned", adm)
		}
	}
	// New nodes: exactly one joins at a time (it is pushed first and must ack).
	known := map[string]bool{}
	for _, n := range p.cur.Nodes {
		known[n.Admin] = true
	}
	var join *store.DesiredNode
	if len(p.cur.Nodes) > 0 {
		var added []store.DesiredNode
		for _, n := range p.src.Nodes {
			if !known[n.Admin] {
				added = append(added, n)
			}
		}
		if len(added) > 1 {
			return fmt.Errorf("the source adds %d nodes at once; add one node per publish (it is pushed first and must ack)", len(added))
		}
		if len(added) == 1 {
			j := added[0]
			join = &j
		}
	}

	allowID := map[string]bool{}
	for _, adm := range pf.acceptID {
		if !slices.Contains(p.src.Admins(), adm) {
			return fmt.Errorf("--accept-id-change %s: not a node in the source", adm)
		}
		allowID[adm] = true
	}
	secKey := p.secKey
	if secKey == nil {
		// Never used for signing: the sec section is carried unchanged. A throw-away key makes any
		// unexpected re-signing fail the publisher's own trust check instead of crashing.
		_, secKey, _ = ed25519.GenerateKey(rand.Reader)
	}
	now := a.now()
	reason := pf.reason
	if reason == "" {
		reason = p.src.Reason
	}
	pub := publish.New(publish.Config{Store: p.st, Trust: p.trust, PublishKey: p.pubKey, SecurityKey: secKey,
		Client: p.client, Author: p.author, AckWait: pf.ackWait, ClockSkew: pf.skew,
		Now: func() time.Time { return now }, Log: slog.New(slog.NewTextHandler(a.err, &slog.HandlerOptions{Level: slog.LevelInfo}))})
	ch := publish.Change{Reason: reason, Join: join, TolerateUnreachable: pf.allowUnreach, AllowIDChange: allowID,
		Edit: func(next *store.State) {
			old := map[string]store.DesiredNode{}
			for _, n := range p.cur.Nodes {
				old[n.Admin] = n
			}
			next.Nodes = nil
			for _, n := range p.src.Nodes {
				if o, ok := old[n.Admin]; ok && o.State == n.State {
					n.DrainSince = o.DrainSince
				} else if n.State == "draining" {
					n.DrainSince = ts(now)
				}
				next.Nodes = append(next.Nodes, n)
			}
			if p.secKey != nil {
				next.Principals, next.RBAC = p.src.Principals, p.src.RBAC
			}
			next.ConfigTOML = p.src.ConfigTOML
		}}
	res, err := pub.Publish(ctx, ch)
	if err != nil {
		if errors.Is(err, publish.ErrStopped) {
			return fmt.Errorf("%w\n(a node already holds a newer sec section than the one built: the node with the highest sec_generation was %s)", err, p.best)
		}
		return err
	}
	fmt.Fprintf(a.out, "published generation=%d sec_generation=%d epoch=%d\n", res.Generation, res.SecGeneration, res.Epoch)
	for _, adm := range res.Acked {
		fmt.Fprintf(a.out, "ack %s admin=%s\n", who(p.ids[adm], adm), adm)
	}
	for _, adm := range res.Lagging {
		fmt.Fprintf(a.out, "lagging %s admin=%s\n", who(p.ids[adm], adm), adm)
	}
	if len(res.Lagging) > 0 {
		return fmt.Errorf("%d node(s) did not ack; run `mirctl bundle push` to catch them up", len(res.Lagging))
	}
	return nil
}

func bundleHasAdmin(b *bundle.Bundle, admin string) bool {
	if b == nil {
		return false
	}
	for _, n := range b.Body.Membership.Nodes {
		if n.Admin == admin {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// bundleDiff is `mirctl bundle diff`: what publishing the source would change in the cluster.
func (a *app) bundleDiff(args []string) error {
	var pf publishFlags
	fs := pf.register(a, "bundle diff")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	p, err := a.prepare(context.Background(), &pf, false)
	if err != nil {
		return err
	}
	defer p.cleanup()
	changed := false
	line := func(f string, v ...any) { changed = true; fmt.Fprintf(a.out, f+"\n", v...) }
	if p.best == "" {
		line("cluster: blank (no node has a sec section); the whole source is new")
	}
	old := map[string]store.DesiredNode{}
	for _, n := range p.cur.Nodes {
		old[n.Admin] = n
	}
	inSrc := map[string]bool{}
	for _, n := range p.src.Nodes {
		inSrc[n.Admin] = true
		o, ok := old[n.Admin]
		switch {
		case !ok:
			line("+ node %s weight=%d zone=%q state=%s", n.Admin, n.Weight, n.Zone, n.State)
		case o.Weight != n.Weight || o.Zone != n.Zone || o.State != n.State:
			line("~ node %s weight %d->%d zone %q->%q state %s->%s", n.Admin, o.Weight, n.Weight, o.Zone, n.Zone, o.State, n.State)
		}
	}
	for _, n := range p.cur.Nodes {
		if !inSrc[n.Admin] {
			line("- node %s", n.Admin)
		}
	}
	if p.curB != nil {
		for _, d := range secDiff(p.curB.Sec, p.src) {
			line("sec: %s", d)
		}
	} else {
		for _, pr := range p.src.Principals {
			line("+ principal %q", pr.Name)
		}
		for _, r := range p.src.RBAC {
			line("+ rbac %q", r.Identity)
		}
	}
	for _, l := range lineDiff(p.cur.ConfigTOML, p.src.ConfigTOML) {
		line("config %s", l)
	}
	if !changed {
		fmt.Fprintln(a.out, "no changes")
	}
	return nil
}

// lineDiff lists the lines only in a ("-") and only in b ("+").
func lineDiff(a, b string) []string {
	set := func(s string) map[string]bool {
		m := map[string]bool{}
		for _, l := range strings.Split(s, "\n") {
			if l = strings.TrimSpace(l); l != "" {
				m[l] = true
			}
		}
		return m
	}
	sa, sb := set(a), set(b)
	var out []string
	for _, k := range sortedKeys(sa) {
		if !sb[k] {
			out = append(out, "- "+k)
		}
	}
	for _, k := range sortedKeys(sb) {
		if !sa[k] {
			out = append(out, "+ "+k)
		}
	}
	return out
}

// probe reads the identities of the given admin addresses.
func (a *app) probe(ctx context.Context, ts *tlsFlags, admins []string, wait time.Duration) (*publish.NodeClient, map[string]*publish.Identity, map[string]error, error) {
	hc, _, err := a.client(ts)
	if err != nil {
		return nil, nil, nil, err
	}
	c := &publish.NodeClient{HTTP: hc}
	ids, down := map[string]*publish.Identity{}, map[string]error{}
	for _, adm := range admins {
		cctx, cancel := context.WithTimeout(ctx, wait)
		id, err := c.Identity(cctx, adm)
		cancel()
		if err != nil {
			down[adm] = err
		} else {
			ids[adm] = id
		}
	}
	return c, ids, down, nil
}

// bundlePush is `mirctl bundle push`: re-push the current envelope (the highest generation any
// node serves) to every node that does not hold it.
func (a *app) bundlePush(args []string) error {
	var (
		t     tlsFlags
		ns    nodeSet
		trust string
		wait  = publish.DefaultAckWait
	)
	fs := a.newFlags("bundle push")
	t.register(fs)
	ns.register(fs)
	fs.StringVar(&trust, "trust", "", "trust key file (verifies the envelope before it is pushed; required)")
	fs.DurationVar(&wait, "ack-wait", publish.DefaultAckWait, "per node call")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if trust == "" {
		return errors.New("--trust is required")
	}
	tk, err := bundle.LoadTrustFile(trust)
	if err != nil {
		return err
	}
	admins, _, err := ns.admins()
	if err != nil {
		return err
	}
	ctx := context.Background()
	c, ids, down, err := a.probe(ctx, &t, admins, wait)
	if err != nil {
		return err
	}
	best := ""
	for _, adm := range sortedAdmins(ids) {
		id := ids[adm]
		if best == "" || id.AppliedGeneration > ids[best].AppliedGeneration ||
			(id.AppliedGeneration == ids[best].AppliedGeneration && id.SecGeneration > ids[best].SecGeneration) {
			best = adm
		}
	}
	if best == "" || ids[best].AppliedGeneration == 0 {
		return errors.New("no node serves a bundle; publish one first")
	}
	cctx, cancel := context.WithTimeout(ctx, 4*wait)
	raw, err := c.GetBundle(cctx, best)
	cancel()
	if err != nil {
		return fmt.Errorf("fetching the bundle from %s: %w", best, err)
	}
	b, err := bundle.Open(tk, raw)
	if err != nil {
		return fmt.Errorf("the bundle %s serves does not verify against --trust: %w", best, err)
	}
	fmt.Fprintf(a.out, "pushing generation=%d sec_generation=%d epoch=%d from %s\n",
		b.Body.Generation, b.Sec.SecGeneration, b.Body.Membership.Epoch, who(ids[best], best))
	bad := 0
	for _, adm := range sortedAdmins(ids) {
		id := ids[adm]
		if id.AppliedGeneration == b.Body.Generation && id.AppliedHash == b.ContentHash && id.SecHash == b.SecHash {
			fmt.Fprintf(a.out, "current %s admin=%s\n", who(id, adm), adm)
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, wait)
		err := c.Push(cctx, adm, raw, false)
		cancel()
		if err != nil {
			bad++
			fmt.Fprintf(a.out, "FAILED %s admin=%s: %v\n", who(id, adm), adm, err)
			continue
		}
		fmt.Fprintf(a.out, "ack %s admin=%s\n", who(id, adm), adm)
	}
	for _, adm := range sortedKeys(down) {
		bad++
		fmt.Fprintf(a.out, "unreachable admin=%s: %v\n", adm, down[adm])
	}
	if bad > 0 {
		return fmt.Errorf("%d node(s) did not take the bundle", bad)
	}
	return nil
}

// bundleStatus is `mirctl bundle status`: one line per node, and exit code 2 when a node is below
// the highest sec_generation seen.
func (a *app) bundleStatus(args []string) error {
	var (
		t    tlsFlags
		ns   nodeSet
		wait = publish.DefaultAckWait
	)
	fs := a.newFlags("bundle status")
	t.register(fs)
	ns.register(fs)
	fs.DurationVar(&wait, "ack-wait", publish.DefaultAckWait, "per node call")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	admins, _, err := ns.admins()
	if err != nil {
		return err
	}
	_, ids, down, err := a.probe(context.Background(), &t, admins, wait)
	if err != nil {
		return err
	}
	var maxSec, maxGen uint64
	for _, id := range ids {
		maxSec = max(maxSec, id.SecGeneration)
		maxGen = max(maxGen, id.AppliedGeneration)
	}
	tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE_ID\tHOST\tADDR\tADMIN\tGENERATION\tAPPLIED_HASH\tSEC_GENERATION\tSEC_HASH\tEPOCH")
	for _, adm := range admins {
		id, ok := ids[adm]
		if !ok {
			fmt.Fprintf(tw, "unknown\tunknown\t%s\t%s\tUNREACHABLE\t-\t-\t-\t-\n", hostPart(adm), adm)
			continue
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%d\t%s\t%d\t%s\t%d\n", id.NodeID, id.Hostname, hostPart(adm), adm,
			id.AppliedGeneration, orDash(id.AppliedHash), id.SecGeneration, orDash(id.SecHash), id.Epoch)
	}
	tw.Flush()
	alert := false
	for _, adm := range sortedAdmins(ids) {
		id := ids[adm]
		if id.SecGeneration < maxSec {
			alert = true
			fmt.Fprintf(a.out, "ALERT %s: sec_generation %d is below the highest seen (%d); `mirctl bundle push` brings it to the current sec\n",
				who(id, adm), id.SecGeneration, maxSec)
		}
		if id.AppliedGeneration < maxGen {
			fmt.Fprintf(a.out, "WARN %s: generation %d is behind the highest seen (%d)\n", who(id, adm), id.AppliedGeneration, maxGen)
		}
	}
	for _, adm := range sortedKeys(down) {
		fmt.Fprintf(a.out, "WARN node_id=unknown host=unknown addr=%s: unreachable: %v\n", hostPart(adm), down[adm])
	}
	if alert {
		return &errExit{2, ""}
	}
	if len(down) > 0 {
		return &errExit{1, ""}
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
