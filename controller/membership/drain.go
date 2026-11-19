package membership

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"miracache/controller/publish"
	"miracache/controller/store"
)

// Drain state machine (decision 10), one desired node at a time, state kept in the store:
//
//	active --Drain--> draining      epoch + 1 (out of the current view; still serves reads and continuations)
//	draining --drain.continue_ms--> readonly   same epoch
//	draining|readonly --drain.max_ms--> leave
//	readonly --bytes_used == 0 (from /v1/identity)--> leave
//	leave = absent from nodes; NO epoch bump (the current view does not change, P31)
//
// The drain start is store.DesiredNode.DrainSince, so a restarted controller resumes mid-drain.
// bytes_used == 0 ends the drain only in readonly: during draining continuations are still accepted.

// Drain starts a drain: state draining (new epoch) with the drain start stamped in the store.
func (m *Monitor) Drain(ctx context.Context, admin string) error {
	m.tickMu.Lock()
	defer m.tickMu.Unlock()
	now := m.cfg.Now().UTC().Format(time.RFC3339)
	found := false
	_, err := m.cfg.Pub.Publish(ctx, publish.Change{Reason: "drain " + admin, TolerateUnreachable: true, Edit: func(next *store.State) {
		for i := range next.Nodes {
			if next.Nodes[i].Admin == admin && next.Nodes[i].State == "active" {
				next.Nodes[i].State, next.Nodes[i].DrainSince = "draining", now
				found = true
			}
		}
	}})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s is not an active member", admin)
	}
	m.logNode(slog.LevelInfo, admin, "drain started")
	return nil
}

func (m *Monitor) setReadonly(ctx context.Context, cs []candidate) {
	if m.auditor() == nil {
		m.cfg.Log.Error("drain: readonly refused, no audit log is configured (--audit-dir); automatic actions need one")
		return
	}
	want := map[string]candidate{}
	var names []string
	for _, c := range cs {
		want[c.admin] = c
		names = append(names, c.admin)
	}
	applied := map[string]bool{}
	res, err := m.cfg.Pub.Publish(ctx, publish.Change{Reason: fmt.Sprintf("drain: readonly %v", names), TolerateUnreachable: true, Edit: func(next *store.State) {
		for i := range next.Nodes {
			n := &next.Nodes[i]
			// Re-check (V05): still draining with the same drain start.
			if c, ok := want[n.Admin]; ok && n.State == "draining" && n.DrainSince == c.drainSince {
				n.State = "readonly"
				applied[n.Admin] = true
			}
		}
	}})
	for _, c := range cs {
		switch {
		case err != nil:
			m.logNode(slog.LevelWarn, c.admin, "drain: readonly not published; retrying next tick", "err", err)
		case !applied[c.admin]:
			m.logNode(slog.LevelWarn, c.admin, "drain: readonly skipped, the node's state changed meanwhile")
		default:
			m.logNode(slog.LevelInfo, c.admin, "drain: node is readonly", "continue_ms", m.cfg.DrainContinue.Milliseconds())
			g := res.Generation
			m.auditAuto("drain.readonly", c.admin, "ok", "drain.continue_ms elapsed", &g)
		}
	}
}

// leave removes drained nodes from nodes (no epoch bump). It returns the admins that left.
func (m *Monitor) leave(ctx context.Context, st store.State, cs []candidate) map[string]bool {
	out := map[string]bool{}
	if m.auditor() == nil {
		m.cfg.Log.Error("drain: leave refused, no audit log is configured (--audit-dir); automatic actions need one")
		return out
	}
	want := map[string]candidate{}
	var names []string
	remaining := len(st.Nodes)
	for _, c := range cs {
		if remaining <= 1 {
			m.logNode(slog.LevelWarn, c.admin, "drain complete but this is the last member; not removed")
			continue
		}
		remaining--
		want[c.admin] = c
		names = append(names, c.admin)
	}
	if len(want) == 0 {
		return out
	}
	var applied map[string]bool
	res, err := m.cfg.Pub.Publish(ctx, publish.Change{Reason: fmt.Sprintf("drain: leave %v", names), TolerateUnreachable: true, Edit: func(next *store.State) {
		applied = removeMatching(next, want, func(store.DesiredNode) {})
	}})
	for _, c := range want {
		switch {
		case err != nil:
			m.logNode(slog.LevelWarn, c.admin, "drain: leave not published; retrying next tick", "err", err)
		case !applied[c.admin]:
			m.logNode(slog.LevelWarn, c.admin, "drain: leave skipped, the node's state changed meanwhile")
		default:
			out[c.admin] = true
			m.logNode(slog.LevelInfo, c.admin, "drain complete: node left", "because", c.rule, "generation", res.Generation, "epoch", res.Epoch)
			g := res.Generation
			m.auditAuto("drain.leave", c.admin, "ok", c.rule, &g)
		}
	}
	return out
}

// CanRemove gates an operator's member remove on the node being drained: readonly and empty
// (bytes_used == 0 from a fresh /v1/identity), or drain.max_ms elapsed. An active or still
// draining node is refused; a node that is down is removed by the failure rules or confirm-remove.
func (m *Monitor) CanRemove(ctx context.Context, admin string) (bool, string) {
	st, err := m.cfg.Store.Load()
	if err != nil {
		return false, err.Error()
	}
	for _, d := range st.Nodes {
		if d.Admin != admin {
			continue
		}
		if d.State != "draining" && d.State != "readonly" {
			return false, "node " + admin + " is active; drain it first (state draining), then remove it when drained"
		}
		m.mu.Lock()
		since := m.drainStartLocked(d, m.cfg.Now())
		m.mu.Unlock()
		if m.cfg.Now().Sub(since) >= m.cfg.DrainMax {
			return true, ""
		}
		if d.State != "readonly" {
			return false, "node " + admin + " is draining; it is removable when readonly and empty, or after drain.max_ms"
		}
		cctx, cancel := context.WithTimeout(ctx, m.cfg.PollTimeout)
		defer cancel()
		id, err := m.cfg.Client.Identity(cctx, admin)
		switch {
		case err != nil:
			return false, "node " + admin + " is not reachable, so bytes_used is unknown: " + err.Error()
		case id.BytesUsed == nil:
			return false, "node " + admin + " does not report bytes_used"
		case *id.BytesUsed != 0:
			return false, fmt.Sprintf("node %s is not drained: bytes_used=%d", admin, *id.BytesUsed)
		}
		return true, ""
	}
	return true, ""
}
