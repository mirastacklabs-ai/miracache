package membership

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"miracache/controller/store"
)

func sortedKeys[V any](m map[string]V) []string {
	k := make([]string, 0, len(m))
	for a := range m {
		k = append(k, a)
	}
	sort.Strings(k)
	return k
}

// refreshStatsLocked recomputes the per-node state shown in mira_controller_node_state.
func (m *Monitor) refreshStatsLocked(st store.State, failed map[string]store.FailedNode, bundleID map[string]uint64) {
	m.stats = map[string]nodeStat{}
	for _, d := range st.Nodes {
		r := m.recs[d.Admin]
		s := nodeStat{nodeID: bundleID[d.Admin], hostname: "unknown", state: StateHealthy}
		if r != nil && r.id != nil {
			s.hostname = r.id.Hostname
			if s.nodeID == 0 {
				s.nodeID = r.id.NodeID
			}
		}
		switch {
		case m.pending[d.Admin] != (pendingInfo{}):
			s.state = StatePendingRemoval
		case d.State == "draining":
			s.state = StateDraining
		case d.State == "readonly":
			s.state = StateReadonly
		case r != nil && (!r.pollOK || !r.railsDownSince.IsZero() || !r.cSince.IsZero() || r.idDiff > 0):
			s.state = StateSuspect
		}
		m.stats[d.Admin] = s
	}
	for a, f := range failed {
		s := nodeStat{nodeID: f.NodeID, hostname: "unknown", state: StateRemoved}
		if r := m.recs[a]; r != nil {
			if r.id != nil {
				s.hostname = r.id.Hostname
			}
			if r.pollOK && !r.healthySince.IsZero() {
				s.state = StateRejoining
			}
		}
		m.stats[a] = s
	}
}

func esc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// WriteMetrics writes Prometheus text: mira_controller_node_state{node_id,hostname,addr,state} (1 for
// the node's current state) and mira_controller_node_removed_total{rule}.
func (m *Monitor) WriteMetrics(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintln(w, "# TYPE mira_controller_node_state gauge")
	for _, a := range sortedKeys(m.stats) {
		s := m.stats[a]
		fmt.Fprintf(w, "mira_controller_node_state{node_id=\"%d\",hostname=\"%s\",addr=\"%s\",state=\"%s\"} 1\n",
			s.nodeID, esc(s.hostname), esc(hostOf(a)), s.state)
	}
	fmt.Fprintln(w, "# TYPE mira_controller_node_removed_total counter")
	for _, r := range sortedKeys(m.removed) {
		fmt.Fprintf(w, "mira_controller_node_removed_total{rule=\"%s\"} %d\n", esc(r), m.removed[r])
	}
}

// State returns the current state label of a node by admin address ("" if unknown).
func (m *Monitor) State(admin string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats[admin].state
}
