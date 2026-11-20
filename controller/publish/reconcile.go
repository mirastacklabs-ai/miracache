package publish

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"miracache/controller/bundle"
	"miracache/controller/store"
)

// ReconcileReport is what one reconcile pass did.
type ReconcileReport struct {
	Repushed    []string // lagging nodes that were re-pushed
	Republished bool     // a hash mismatch (second writer or store behind) triggered a republish
	SecBehind   []string // nodes below the highest sec_generation seen; alerted
	Unreachable []string
}

// ReconcileOnce is one pass of the reconcile loop:
//   - a node whose applied_generation is lower gets a re-push;
//   - a node at the same generation with another applied_hash, or ahead of the store (a second
//     writer), triggers a republish of the controller's content under a new generation, plus an alert;
//   - a node whose sec_generation is below the highest seen anywhere raises an alert;
//   - a push rejected for its sec section stops publishing and names --recover-from.
func (p *Publisher) ReconcileOnce(ctx context.Context) (*ReconcileReport, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stopped.Load() {
		return nil, ErrStopped
	}
	st, err := p.cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if st.Pending != nil { // settle the intent record of a publish that was cut short
		// Unresolved (a node unreachable): the pass goes on with the committed state.
		if _, err := p.resolvePending(ctx, &st); err != nil {
			return &ReconcileReport{}, err
		}
	}
	rep := &ReconcileReport{}
	p.reconcileRetiring(ctx, &st)
	if len(st.LastEnvelope) == 0 {
		return rep, nil
	}
	env, err := bundle.ParseEnvelope(st.LastEnvelope)
	if err != nil {
		return nil, fmt.Errorf("store: last envelope: %w", err)
	}
	wantHash := bundle.HashHex(env.Body)
	admins := make([]string, len(st.Nodes))
	for i, n := range st.Nodes {
		admins[i] = n.Admin
	}
	ids := p.identities(ctx, admins)

	var maxSec uint64
	for _, a := range admins {
		if ids[a].err == nil {
			maxSec = max(maxSec, ids[a].id.SecGeneration)
		}
	}
	mismatch := ""
	var lagging []string
	for _, a := range admins {
		r := ids[a]
		if r.err != nil {
			rep.Unreachable = append(rep.Unreachable, a)
			p.logNode(slog.LevelWarn, a, "reconcile: node unreachable", "err", r.err)
			continue
		}
		if r.id.SecGeneration < maxSec {
			rep.SecBehind = append(rep.SecBehind, a)
			p.logNode(slog.LevelError, a, "ALERT: node is below the highest sec_generation seen",
				"sec_generation", r.id.SecGeneration, "highest", maxSec)
		}
		switch {
		case r.id.AppliedGeneration < st.Generation:
			lagging = append(lagging, a)
		case r.id.AppliedGeneration > st.Generation, r.id.AppliedGeneration == st.Generation && r.id.AppliedHash != wantHash:
			if mismatch == "" {
				mismatch = a
			}
		}
	}

	if mismatch != "" {
		r := ids[mismatch].id
		p.logNode(slog.LevelError, mismatch, "ALERT: node holds other content than the store (second writer or a store behind the cluster); republishing under a new generation",
			"node_generation", r.AppliedGeneration, "node_hash", r.AppliedHash, "store_generation", st.Generation, "store_hash", wantHash)
		_, err := p.publishLocked(ctx, Change{Reason: "reconcile: republish after a hash mismatch", TolerateUnreachable: true})
		rep.Republished = err == nil
		return rep, err
	}

	pushed := fanout(lagging, func(a string) error { return p.push(ctx, a, st.LastEnvelope, false) })
	highest, _ := highestSec(ids, "")
	for _, a := range lagging {
		err := pushed[a]
		if err == nil {
			rep.Repushed = append(rep.Repushed, a)
			p.logNode(slog.LevelInfo, a, "reconcile: re-pushed", "generation", st.Generation)
			continue
		}
		if pe := asPushError(err); pe != nil && pe.IsSecReject() {
			return rep, p.stopForSec(a, highest, err)
		}
		p.logNode(slog.LevelWarn, a, "reconcile: re-push failed", "err", err)
	}
	sort.Strings(rep.Repushed)
	sort.Strings(rep.SecBehind)
	sort.Strings(rep.Unreachable)
	return rep, nil
}

// RunReconcile runs ReconcileOnce every `every` (ReconcilePeriod when zero) until ctx is done
// or publishing is stopped.
func (p *Publisher) RunReconcile(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = ReconcilePeriod
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := p.ReconcileOnce(ctx); err != nil {
				p.cfg.Log.Warn("reconcile pass failed", "err", err)
				if p.Stopped() {
					return
				}
			}
		}
	}
}

// reconcileRetiring keeps pushing the removing bundle to nodes the last bundle dropped, for
// store.RetirePasses passes. A node that holds the current generation, or acks the push, is done.
func (p *Publisher) reconcileRetiring(ctx context.Context, st *store.State) {
	if len(st.Retiring) == 0 || len(st.LastEnvelope) == 0 {
		return
	}
	in := map[string]bool{}
	for _, n := range st.Nodes {
		in[n.Admin] = true
	}
	var admins []string
	for _, r := range st.Retiring {
		admins = append(admins, r.Admin)
	}
	ids := p.identities(ctx, admins)
	var keep []store.Retiring
	for _, r := range st.Retiring {
		if in[r.Admin] {
			continue // re-added since
		}
		done := false
		if id := ids[r.Admin]; id.err == nil {
			if id.id.AppliedGeneration >= st.Generation {
				done = true
			} else if err := p.push(ctx, r.Admin, st.LastEnvelope, false); err == nil {
				done = true
				p.logNode(slog.LevelInfo, r.Admin, "reconcile: removing bundle delivered", "generation", st.Generation)
			}
		}
		if done {
			continue
		}
		if r.Passes--; r.Passes > 0 {
			keep = append(keep, r)
		} else {
			p.logNode(slog.LevelWarn, r.Admin, "reconcile: gave up delivering the removing bundle")
		}
	}
	ns := st.Clone()
	ns.Retiring = keep
	if err := p.cfg.Store.Commit(st.Generation, ns); err != nil {
		p.cfg.Log.Warn("could not update the retiring list", "err", err)
		return
	}
	st.Retiring = keep
}
