package membership

import (
	"time"

	"miracache/controller/audit"
)

// Auditor records controller actions (controller/audit.Writer).
type Auditor interface {
	Append(audit.Entry) error
}

// SetAuditor sets the audit sink after construction (the writer is opened with the API).
func (m *Monitor) SetAuditor(a Auditor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Audit = a
}

func (m *Monitor) auditor() Auditor {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg.Audit
}

// auditAuto records an automatic action of the Monitor: actor "local", reason = the rule, with the
// node's ID, hostname and IP in the detail.
func (m *Monitor) auditAuto(action, admin, result, reason string, gen *uint64) {
	a := m.auditor()
	if a == nil {
		return
	}
	m.mu.Lock()
	var id uint64
	host := "unknown"
	if r := m.recs[admin]; r != nil && r.id != nil {
		id, host = r.id.NodeID, r.id.Hostname
	} else if s, ok := m.stats[admin]; ok {
		id, host = s.nodeID, s.hostname
	}
	m.mu.Unlock()
	e := audit.Entry{Actor: "local", Role: "", Action: action, Target: "node:" + admin, Result: result, Reason: reason, Generation: gen,
		Detail: []audit.Field{{Key: "node_id", Val: id}, {Key: "host", Val: host}, {Key: "addr", Val: hostOf(admin)}}}
	if err := a.Append(e); err != nil {
		m.cfg.Log.Error("audit append failed", "comp", "audit", "action", action, "err", err)
	}
}

// aeadAcc sums a client's aead_fail_delta between audit entries (at most one entry a minute per identity).
type aeadAcc struct {
	sum  uint64
	last time.Time
}

const aeadAuditEvery = time.Minute

// noteAEAD adds a report's AEAD failure delta and, at most once a minute per identity, returns the
// sum to audit (0 = nothing to write now). Caller holds m.mu.
func (m *Monitor) noteAEADLocked(identity string, delta uint64, now time.Time) uint64 {
	a := m.aeadAcc[identity]
	if a == nil {
		if delta == 0 {
			return 0
		}
		a = &aeadAcc{}
		m.aeadAcc[identity] = a
	}
	a.sum += delta
	if a.sum == 0 || (!a.last.IsZero() && now.Sub(a.last) < aeadAuditEvery) {
		return 0
	}
	s := a.sum
	a.sum, a.last = 0, now
	return s
}

func (m *Monitor) auditAEAD(identity string, sum uint64) {
	a := m.auditor()
	m.cfg.Log.Error("ALERT: client reports AEAD failures", "client", identity, "aead_fail_delta", sum)
	if a == nil {
		return
	}
	e := audit.Entry{Actor: "local", Action: "client.aead_fail", Target: "client:" + identity, Result: "error",
		Reason: "aead_fail_delta in a client report", Detail: []audit.Field{{Key: "aead_fail_delta", Val: sum}}}
	if err := a.Append(e); err != nil {
		m.cfg.Log.Error("audit append failed", "comp", "audit", "action", e.Action, "err", err)
	}
}

// flushAEAD audits AEAD sums that were held back by the one-a-minute limit once the minute is over,
// so a burst followed by silence is still recorded. Called on every tick.
func (m *Monitor) flushAEAD(now time.Time) {
	type item struct {
		id  string
		sum uint64
	}
	var due []item
	m.mu.Lock()
	for id, a := range m.aeadAcc {
		if a.sum > 0 && !a.last.IsZero() && now.Sub(a.last) >= aeadAuditEvery {
			due = append(due, item{id, a.sum})
			a.sum, a.last = 0, now
		}
	}
	m.mu.Unlock()
	for _, d := range due {
		m.auditAEAD(d.id, d.sum)
	}
}
