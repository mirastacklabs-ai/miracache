package bundle

// Sec is the security section ("sec"): sec_generation, principals and rbac.
type Sec struct {
	SecGeneration uint64      `toml:"sec_generation"`
	Principals    []Principal `toml:"principals"`
	RBAC          []RBAC      `toml:"rbac"`
}

// Principal is one [[principals]] entry; its ID is computed (PrincipalID), never typed.
type Principal struct {
	Name       string   `toml:"name"`
	Identities []string `toml:"identities"`
	QuotaBytes uint64   `toml:"quota_bytes"`
	MaxScopes  uint64   `toml:"max_scopes"`
	DropBefore string   `toml:"drop_before"` // RFC 3339, optional ("" = none)
}

// RBAC is one [[rbac]] entry.
type RBAC struct {
	Identity string   `toml:"identity"`
	Roles    []string `toml:"roles"`
}

// Body is the bundle body (schema v1). Config holds the opaque config.* tables.
type Body struct {
	SchemaVersion uint64         `toml:"schema_version"`
	Generation    uint64         `toml:"generation"`
	CreatedAt     string         `toml:"created_at"`
	Author        string         `toml:"author"`
	Reason        string         `toml:"reason"`
	Membership    Membership     `toml:"membership"`
	Config        map[string]any `toml:"config"`
}

// Membership is the strict [membership] section.
type Membership struct {
	Epoch         uint64         `toml:"epoch"`
	PreviousEpoch uint64         `toml:"previous_epoch"`
	Nodes         []Node         `toml:"nodes"`
	Previous      []PreviousNode `toml:"previous"`
}

// Node is one [[membership.nodes]] entry.
type Node struct {
	NodeID   uint64 `toml:"node_id"`
	Hostname string `toml:"hostname"`
	Admin    string `toml:"admin"`
	Rails    []Rail `toml:"rails"`
	Weight   uint64 `toml:"weight"`
	Zone     string `toml:"zone"` // optional; all nodes or none
	State    string `toml:"state"`
}

// Rail is one rail of a node.
type Rail struct {
	Addr     string `toml:"addr"`
	Subnet   string `toml:"subnet"`
	Protocol string `toml:"protocol"`
}

// PreviousNode is one [[membership.previous]] entry (the view of previous_epoch).
type PreviousNode struct {
	NodeID uint64 `toml:"node_id"`
	Weight uint64 `toml:"weight"`
	Zone   string `toml:"zone"`
}
