package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"miracache/controller/bundle"
	"miracache/controller/store"
)

// Source is the operator's cluster.toml: intent only. Node IDs, hostnames and rails
// are learned from the nodes; principal IDs and key IDs are computed. Overrides under
// [config.node."<admin addr>"] are keyed by admin address.
//
//	reason = "add hostD"
//	[[nodes]]            admin, weight, zone, state
//	[[principals]]       name, identities, quota_bytes, max_scopes, drop_before
//	[[rbac]]             identity, roles
//	[config.cluster.placement] replicas = 2     (and the other config.* tables)
type Source struct {
	Reason     string
	Nodes      []store.DesiredNode
	Principals []bundle.Principal
	RBAC       []bundle.RBAC
	Config     map[string]any
	ConfigTOML string // the config tables as TOML under [config] ("" = none)
}

type sourceFile struct {
	Reason     string             `toml:"reason"`
	Nodes      []sourceNode       `toml:"nodes"`
	Principals []bundle.Principal `toml:"principals"`
	RBAC       []bundle.RBAC      `toml:"rbac"`
	Config     map[string]any     `toml:"config"`
}

type sourceNode struct {
	Admin  string `toml:"admin"`
	Weight uint64 `toml:"weight"`
	Zone   string `toml:"zone"`
	State  string `toml:"state"`
}

// ReadSource reads and checks a cluster.toml.
func ReadSource(path string) (*Source, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s, err := ParseSource(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// ParseSource parses cluster.toml bytes; unknown keys are errors, and typed IDs are stale keys.
func ParseSource(data []byte) (*Source, error) {
	var raw map[string]any
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return nil, err
	}
	if nodes, ok := raw["nodes"].([]map[string]any); ok {
		for i, n := range nodes {
			for _, k := range []string{"id", "node_id"} {
				if _, typed := n[k]; typed {
					return nil, fmt.Errorf("nodes[%d]: `%s` is a stale key: node ids are learned from the nodes", i, k)
				}
			}
		}
	}
	if ps, ok := raw["principals"].([]map[string]any); ok {
		for i, p := range ps {
			for _, k := range []string{"id", "principal_id"} {
				if _, typed := p[k]; typed {
					return nil, fmt.Errorf("principals[%d]: `%s` is a stale key: principal ids are computed from the name", i, k)
				}
			}
		}
	}
	var f sourceFile
	md, err := toml.Decode(string(data), &f)
	if err != nil {
		return nil, err
	}
	if un := md.Undecoded(); len(un) > 0 {
		var names []string
		for _, k := range un {
			if len(k) > 0 && k[0] == "config" {
				continue // config.* is opaque to mirctl; the nodes' dry run validates it
			}
			names = append(names, k.String())
		}
		if len(names) > 0 {
			return nil, fmt.Errorf("unknown keys: %s", strings.Join(names, ", "))
		}
	}
	s := &Source{Reason: f.Reason, Principals: f.Principals, RBAC: f.RBAC, Config: f.Config}
	seen := map[string]bool{}
	for i, n := range f.Nodes {
		if n.Admin == "" || strings.ContainsAny(n.Admin, "/ \t\n") {
			return nil, fmt.Errorf("nodes[%d]: admin must be a host:port", i)
		}
		if seen[n.Admin] {
			return nil, fmt.Errorf("nodes[%d]: duplicate admin %s", i, n.Admin)
		}
		seen[n.Admin] = true
		if n.Weight == 0 {
			n.Weight = 1
		}
		switch n.State {
		case "":
			n.State = "active"
		case "active", "draining", "readonly":
		default:
			return nil, fmt.Errorf("nodes[%d]: state %q must be active, draining or readonly", i, n.State)
		}
		s.Nodes = append(s.Nodes, store.DesiredNode{Admin: n.Admin, Weight: n.Weight, Zone: n.Zone, State: n.State})
	}
	if len(s.Nodes) == 0 {
		return nil, fmt.Errorf("no [[nodes]]")
	}
	// Overrides are addressed by admin address: a typed node ID there is a mistake.
	if nodes, ok := f.Config["node"].(map[string]any); ok {
		for k := range nodes {
			if !strings.Contains(k, ":") {
				return nil, fmt.Errorf("config.node.%q: overrides are addressed by admin address (host:port), never by node ID", k)
			}
		}
	}
	if len(f.Config) > 0 {
		var buf bytes.Buffer
		if err := toml.NewEncoder(&buf).Encode(map[string]any{"config": f.Config}); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
		s.ConfigTOML = buf.String()
	}
	// Principals and rbac are checked with the same rules the nodes apply (sec_generation is a
	// placeholder here; the real one is assigned at publish).
	if len(s.Principals) > 0 || len(s.RBAC) > 0 {
		sec := bundle.Sec{SecGeneration: 1, Principals: s.Principals, RBAC: s.RBAC}
		if err := sec.Validate(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Admins returns the source's admin addresses, sorted.
func (s *Source) Admins() []string {
	out := make([]string, len(s.Nodes))
	for i, n := range s.Nodes {
		out[i] = n.Admin
	}
	sort.Strings(out)
	return out
}

// HasSecurityAdmin reports whether the rbac table binds the security-admin role to someone.
func HasSecurityAdmin(r []bundle.RBAC) bool {
	for _, e := range r {
		for _, role := range e.Roles {
			if role == "security-admin" {
				return true
			}
		}
	}
	return false
}
