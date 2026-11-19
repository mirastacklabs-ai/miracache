package membership

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Report is the body of POST /v1/reports (decision 9): what one client sees. The reporter is the
// caller's mTLS identity, never a field in the body (P18).
type Report struct {
	Generation    uint64       `json:"generation"`
	Nodes         []ReportNode `json:"nodes"`
	AEADFailDelta uint64       `json:"aead_fail_delta"`
}

// ReportNode is one node as a client sees it.
type ReportNode struct {
	NodeID uint64       `json:"node_id"`
	Rails  []ReportRail `json:"rails"`
}

// ReportRail is one rail's reachability.
type ReportRail struct {
	Addr      string `json:"addr"`
	Reachable bool   `json:"reachable"`
}

type clientReport struct {
	at    time.Time
	nodes map[uint64][]ReportRail
}

// Submit stores the latest report of an mTLS identity. There is one slot per identity: many
// reports, or reports about many hosts, from one identity are still one voice. A malformed report
// is an error and changes nothing.
func (m *Monitor) Submit(identity string, body []byte, at time.Time) error {
	if identity == "" {
		return fmt.Errorf("a report needs an authenticated identity")
	}
	var rep Report
	if err := json.Unmarshal(body, &rep); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	if len(rep.Nodes) > 64 {
		return fmt.Errorf("report: %d nodes (at most 64)", len(rep.Nodes))
	}
	cr := &clientReport{at: at, nodes: map[uint64][]ReportRail{}}
	for _, n := range rep.Nodes {
		if n.NodeID == 0 || n.NodeID > 0xffffffff {
			return fmt.Errorf("report: node_id %d invalid", n.NodeID)
		}
		if len(n.Rails) > 16 {
			return fmt.Errorf("report: node %d has %d rails (at most 16)", n.NodeID, len(n.Rails))
		}
		cr.nodes[n.NodeID] = n.Rails
	}
	m.mu.Lock()
	if _, ok := m.reports[identity]; !ok && len(m.reports) >= m.cfg.MaxReporters {
		// One cap policy for the controller (V16): drop reports too old to count, else refuse the new identity.
		for id, r := range m.reports {
			if at.Sub(r.at) > m.cfg.ReportFresh {
				delete(m.reports, id)
				delete(m.aeadAcc, id)
			}
		}
		if len(m.reports) >= m.cfg.MaxReporters {
			m.mu.Unlock()
			return ErrReportsFull
		}
	}
	m.reports[identity] = cr
	var sum uint64
	if _, tracked := m.aeadAcc[identity]; tracked || (rep.AEADFailDelta > 0 && len(m.aeadAcc) < m.cfg.MaxReporters) {
		sum = m.noteAEADLocked(identity, rep.AEADFailDelta, at)
	}
	m.mu.Unlock()
	if sum > 0 {
		m.auditAEAD(identity, sum)
	}
	return nil
}

// ReportCount is the number of identities with a stored report.
func (m *Monitor) ReportCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.reports)
}

// votesLocked counts, over fresh reports, how many distinct identities are connected to the node
// (they list it with rails), how many of those report every rail unreachable while they still reach
// another node, and whether any identity reports a working rail.
func (m *Monitor) votesLocked(nodeID uint64, now time.Time) (connected, allDown int, working bool) {
	if nodeID == 0 {
		return
	}
	for _, r := range m.reports {
		if now.Sub(r.at) > m.cfg.ReportFresh {
			continue
		}
		rails := r.nodes[nodeID]
		if len(rails) == 0 {
			continue
		}
		connected++
		up := false
		for _, rl := range rails {
			up = up || rl.Reachable
		}
		if up {
			working = true
			continue
		}
		for id, other := range r.nodes {
			if id == nodeID {
				continue
			}
			ok := false
			for _, rl := range other {
				ok = ok || rl.Reachable
			}
			if ok {
				allDown++
				break
			}
		}
	}
	return
}

// ErrReportsFull: the report store holds MaxReporters fresh identities (the API answers 429).
var ErrReportsFull = errors.New("report storage is full")
