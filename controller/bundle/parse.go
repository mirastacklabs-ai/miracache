package bundle

import (
	"bytes"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// The parsers below decode into untyped maps and validate by hand. Struct decoding would match
// keys case-insensitively and could not tell a missing key from a zero value; the C++ parser
// (core/control/bundle.cpp) does neither, and both sides must accept exactly the same bytes.

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// decodeTable decodes TOML text into a map. A leading UTF-8 BOM is refused (as in C++).
func decodeTable(data []byte, what string) (map[string]any, error) {
	if bytes.HasPrefix(data, utf8BOM) {
		return nil, reject(ReasonSchema, "%s: leading UTF-8 BOM", what)
	}
	// BurntSushi/toml v1.5.0 switches to unreleased TOML 1.1 syntax when BURNTSUSHI_TOML_110 is
	// set in the environment (parse.go, read on every Decode); C++ would reject that syntax.
	if _, set := os.LookupEnv("BURNTSUSHI_TOML_110"); set {
		return nil, reject(ReasonSchema, "%s: BURNTSUSHI_TOML_110 is set; TOML 1.1 syntax is refused", what)
	}
	var m map[string]any
	if _, err := toml.Decode(string(data), &m); err != nil {
		return nil, reject(ReasonSchema, "%s: %v", what, err)
	}
	return m, nil
}

// onlyKeys requires every key of t to be one of allowed (exact, case-sensitive match).
func onlyKeys(t map[string]any, what string, allowed ...string) error {
	ks := make([]string, 0, len(t))
	for k := range t {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		ok := false
		for _, a := range allowed {
			ok = ok || k == a
		}
		if !ok {
			return reject(ReasonSchema, "unknown key %q in %s", k, what)
		}
	}
	return nil
}

// getInt reads an optional integer in [lo, hi]; a wrong type or range is an error.
func getInt(t map[string]any, key string, lo, hi int64, what string) (v int64, present bool, err error) {
	raw, ok := t[key]
	if !ok {
		return 0, false, nil
	}
	n, isInt := raw.(int64)
	if !isInt || n < lo || n > hi {
		return 0, false, reject(ReasonSchema, "%s %s must be an integer in %d..%d", what, key, lo, hi)
	}
	return n, true, nil
}

func getStr(t map[string]any, key, what string) (s string, present bool, err error) {
	raw, ok := t[key]
	if !ok {
		return "", false, nil
	}
	s, isStr := raw.(string)
	if !isStr {
		return "", false, reject(ReasonSchema, "%s %s must be a string", what, key)
	}
	return s, true, nil
}

// reqStr reads a required non-empty string.
func reqStr(t map[string]any, key, what string) (string, error) {
	s, present, err := getStr(t, key, what)
	if err != nil {
		return "", err
	}
	if !present || s == "" {
		return "", reject(ReasonSchema, "%s %s is required and must not be empty", what, key)
	}
	return s, nil
}

// optZone reads an optional zone; present-but-empty is an error.
func optZone(t map[string]any, what string) (string, error) {
	z, present, err := getStr(t, "zone", what)
	if err != nil {
		return "", err
	}
	if present && z == "" {
		return "", reject(ReasonSchema, "%s zone must not be empty", what)
	}
	return z, nil
}

// tableArray returns the elements of a non-empty array of tables (the C++ is_homogeneous check;
// an empty array is refused too).
func tableArray(v any) ([]map[string]any, bool) {
	switch x := v.(type) {
	case []map[string]any:
		return x, len(x) > 0
	case []any:
		out := make([]map[string]any, 0, len(x))
		for _, e := range x {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, false
			}
			out = append(out, m)
		}
		return out, len(out) > 0
	}
	return nil, false
}

// stringArray returns a non-empty array of non-empty strings.
func stringArray(v any) ([]string, bool) {
	var out []string
	switch x := v.(type) {
	case []string:
		out = append(out, x...)
	case []any:
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
	default:
		return nil, false
	}
	if len(out) == 0 {
		return nil, false
	}
	for _, s := range out {
		if s == "" {
			return nil, false
		}
	}
	return out, true
}

// ParseSec parses and validates the sec bytes strictly with the same rules as the C++ parser:
// exact keys, quota_bytes and max_scopes required (>= 0), identities and roles non-empty, empty
// principals/rbac arrays and empty drop_before refused.
func ParseSec(data []byte) (*Sec, error) {
	root, err := decodeTable(data, "sec")
	if err != nil {
		return nil, err
	}
	if err := onlyKeys(root, "sec", "sec_generation", "principals", "rbac"); err != nil {
		return nil, err
	}
	g, present, err := getInt(root, "sec_generation", 1, math.MaxInt64, "sec")
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, reject(ReasonSchema, "sec_generation is required")
	}
	s := Sec{SecGeneration: uint64(g)}
	if raw, ok := root["principals"]; ok {
		arr, ok := tableArray(raw)
		if !ok {
			return nil, reject(ReasonSchema, "principals must be a non-empty array of tables")
		}
		for _, t := range arr {
			if err := onlyKeys(t, "[[principals]]", "name", "identities", "quota_bytes", "max_scopes", "drop_before"); err != nil {
				return nil, err
			}
			var p Principal
			if p.Name, err = reqStr(t, "name", "principal"); err != nil {
				return nil, err
			}
			ids, ok := stringArray(t["identities"])
			if !ok {
				return nil, reject(ReasonSchema, "principal %q: identities must be a non-empty array of non-empty strings", p.Name)
			}
			p.Identities = ids
			q, present, err := getInt(t, "quota_bytes", 0, math.MaxInt64, "principal")
			if err != nil {
				return nil, err
			}
			if !present {
				return nil, reject(ReasonSchema, "principal %q: quota_bytes is required", p.Name)
			}
			m, present, err := getInt(t, "max_scopes", 0, math.MaxInt64, "principal")
			if err != nil {
				return nil, err
			}
			if !present {
				return nil, reject(ReasonSchema, "principal %q: max_scopes is required", p.Name)
			}
			p.QuotaBytes, p.MaxScopes = uint64(q), uint64(m)
			db, present, err := getStr(t, "drop_before", "principal")
			if err != nil {
				return nil, err
			}
			if present {
				if !validDropBefore(db) {
					return nil, reject(ReasonSchema, "principal %q: drop_before must be YYYY-MM-DDTHH:MM:SSZ", p.Name)
				}
				p.DropBefore = db
			}
			s.Principals = append(s.Principals, p)
		}
	}
	if raw, ok := root["rbac"]; ok {
		arr, ok := tableArray(raw)
		if !ok {
			return nil, reject(ReasonSchema, "rbac must be a non-empty array of tables")
		}
		for _, t := range arr {
			if err := onlyKeys(t, "[[rbac]]", "identity", "roles"); err != nil {
				return nil, err
			}
			var r RBAC
			if r.Identity, err = reqStr(t, "identity", "rbac"); err != nil {
				return nil, err
			}
			roles, ok := stringArray(t["roles"])
			if !ok {
				return nil, reject(ReasonSchema, "rbac %q: roles must be a non-empty array of non-empty strings", r.Identity)
			}
			r.Roles = roles
			s.RBAC = append(s.RBAC, r)
		}
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// validDropBefore accepts exactly YYYY-MM-DDTHH:MM:SSZ (UTC, no offset, no fraction).
func validDropBefore(s string) bool {
	if len(s) != 20 {
		return false
	}
	_, err := time.Parse("2006-01-02T15:04:05Z", s)
	return err == nil
}

// toInt64 reads an integer config value of any Go integer type.
func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	}
	return 0, false
}

// Replicas returns config.cluster.placement.replicas, or 1 when absent. ok is false when the
// key is present but not an integer in 1..2^32-1.
func (b *Body) Replicas() (r uint32, ok bool) {
	cl, _ := b.Config["cluster"].(map[string]any)
	pl, _ := cl["placement"].(map[string]any)
	v, present := pl["replicas"]
	if !present {
		return 1, true
	}
	n, isInt := toInt64(v)
	if !isInt || n < 1 || n > 0xffffffff {
		return 0, false
	}
	return uint32(n), true
}

// ParseBody parses and validates body bytes. membership is strict; any unknown key outside
// config.* is rejected, and config.* is kept as raw tables (unknown keys there are the caller's
// to ignore and count).
func ParseBody(data []byte) (*Body, error) {
	root, err := decodeTable(data, "body")
	if err != nil {
		return nil, err
	}
	if err := onlyKeys(root, "body", "schema_version", "generation", "created_at", "author", "reason", "membership", "config"); err != nil {
		return nil, err
	}
	var b Body
	v, present, err := getInt(root, "schema_version", 1, 1, "body")
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, reject(ReasonSchema, "schema_version is required")
	}
	b.SchemaVersion = uint64(v)
	if v, present, err = getInt(root, "generation", 1, math.MaxInt64, "body"); err != nil {
		return nil, err
	}
	if !present {
		return nil, reject(ReasonSchema, "generation is required")
	}
	b.Generation = uint64(v)
	for _, f := range []struct {
		key string
		dst *string
	}{{"created_at", &b.CreatedAt}, {"author", &b.Author}, {"reason", &b.Reason}} {
		if *f.dst, _, err = getStr(root, f.key, "body"); err != nil {
			return nil, err
		}
	}
	mt, ok := root["membership"].(map[string]any)
	if !ok {
		return nil, reject(ReasonSchema, "[membership] is required and must be a table")
	}
	if b.Membership, err = parseMembership(mt); err != nil {
		return nil, err
	}
	if raw, ok := root["config"]; ok {
		cfg, ok := raw.(map[string]any)
		if !ok {
			return nil, reject(ReasonSchema, "config must be a table")
		}
		b.Config = cfg
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

func parseMembership(m map[string]any) (Membership, error) {
	var out Membership
	if err := onlyKeys(m, "[membership]", "epoch", "previous_epoch", "nodes", "previous"); err != nil {
		return out, err
	}
	e, present, err := getInt(m, "epoch", 1, 0xffffffff, "membership")
	if err != nil {
		return out, err
	}
	if !present {
		return out, reject(ReasonSchema, "membership.epoch is required")
	}
	out.Epoch = uint64(e)
	pe, _, err := getInt(m, "previous_epoch", 0, 0xffffffff, "membership")
	if err != nil {
		return out, err
	}
	out.PreviousEpoch = uint64(pe)

	nodes, ok := tableArray(m["nodes"])
	if !ok {
		return out, reject(ReasonSchema, "membership.nodes must be a non-empty array of tables")
	}
	for _, t := range nodes {
		if err := onlyKeys(t, "[[membership.nodes]]", "node_id", "hostname", "admin", "rails", "weight", "zone", "state"); err != nil {
			return out, err
		}
		var n Node
		id, present, err := getInt(t, "node_id", 1, 0xffffffff, "node")
		if err != nil {
			return out, err
		}
		if !present {
			return out, reject(ReasonSchema, "node_id is required")
		}
		n.NodeID = uint64(id)
		if n.Hostname, err = reqStr(t, "hostname", "node"); err != nil {
			return out, err
		}
		if n.Admin, err = reqStr(t, "admin", "node"); err != nil {
			return out, err
		}
		w, present, err := getInt(t, "weight", 1, 0xffffffff, "node")
		if err != nil {
			return out, err
		}
		if !present {
			return out, reject(ReasonSchema, "node weight is required")
		}
		n.Weight = uint64(w)
		if n.Zone, err = optZone(t, "node"); err != nil {
			return out, err
		}
		if n.State, err = reqStr(t, "state", "node"); err != nil {
			return out, err
		}
		rails, ok := tableArray(t["rails"])
		if !ok || len(rails) > 4 {
			return out, reject(ReasonSchema, "rails must be 1..4 tables")
		}
		for _, rt := range rails {
			if err := onlyKeys(rt, "a rail", "addr", "subnet", "protocol"); err != nil {
				return out, err
			}
			var r Rail
			if r.Addr, err = reqStr(rt, "addr", "rail"); err != nil {
				return out, err
			}
			if r.Subnet, err = reqStr(rt, "subnet", "rail"); err != nil {
				return out, err
			}
			if r.Protocol, err = reqStr(rt, "protocol", "rail"); err != nil {
				return out, err
			}
			n.Rails = append(n.Rails, r)
		}
		out.Nodes = append(out.Nodes, n)
	}

	// "No previous view" is `previous` absent; an empty array is refused.
	if raw, ok := m["previous"]; ok {
		prev, ok := tableArray(raw)
		if !ok {
			return out, reject(ReasonSchema, "membership.previous must be a non-empty array of tables")
		}
		for _, t := range prev {
			if err := onlyKeys(t, "[[membership.previous]]", "node_id", "weight", "zone"); err != nil {
				return out, err
			}
			var p PreviousNode
			id, present, err := getInt(t, "node_id", 1, 0xffffffff, "previous")
			if err != nil {
				return out, err
			}
			if !present {
				return out, reject(ReasonSchema, "previous node_id is required")
			}
			p.NodeID = uint64(id)
			w, present, err := getInt(t, "weight", 1, 0xffffffff, "previous")
			if err != nil {
				return out, err
			}
			if !present {
				return out, reject(ReasonSchema, "previous weight is required")
			}
			p.Weight = uint64(w)
			if p.Zone, err = optZone(t, "previous"); err != nil {
				return out, err
			}
			out.Previous = append(out.Previous, p)
		}
	}
	return out, nil
}

// Validate checks sec_generation range, principal names, identities, ID collisions, drop_before
// and the rbac entries, as the C++ parser does.
func (s *Sec) Validate() error {
	if !ValidGeneration(s.SecGeneration) {
		return reject(ReasonSchema, "sec_generation %d out of range 1..2^63-1", s.SecGeneration)
	}
	if s.Principals != nil && len(s.Principals) == 0 {
		return reject(ReasonSchema, "principals must not be an empty array")
	}
	if s.RBAC != nil && len(s.RBAC) == 0 {
		return reject(ReasonSchema, "rbac must not be an empty array")
	}
	names := map[string]bool{}
	ids := map[uint32]string{}
	idents := map[string]string{}
	for _, p := range s.Principals {
		if p.Name == "" {
			return reject(ReasonSchema, "principal with an empty name")
		}
		if !nameOK(p.Name, 64) {
			return reject(ReasonSchema, "principal %q: name has invalid characters or is too long", p.Name)
		}
		if names[p.Name] {
			return reject(ReasonSchema, "duplicate principal %q", p.Name)
		}
		names[p.Name] = true
		id := PrincipalID(p.Name)
		if other, dup := ids[id]; dup {
			return reject(ReasonSchema, "principal ID collision between %q and %q", other, p.Name)
		}
		ids[id] = p.Name
		if len(p.Identities) == 0 {
			return reject(ReasonSchema, "principal %q: identities must not be empty", p.Name)
		}
		for _, i := range p.Identities {
			if i == "" {
				return reject(ReasonSchema, "principal %q: empty identity", p.Name)
			}
			if o, dup := idents[i]; dup {
				return reject(ReasonSchema, "identity %q bound to both %q and %q", i, o, p.Name)
			}
			idents[i] = p.Name
		}
		if p.DropBefore != "" && !validDropBefore(p.DropBefore) {
			return reject(ReasonSchema, "principal %q: drop_before must be YYYY-MM-DDTHH:MM:SSZ", p.Name)
		}
	}
	seen := map[string]bool{}
	for _, r := range s.RBAC {
		if r.Identity == "" || seen[r.Identity] {
			return reject(ReasonSchema, "rbac: empty or duplicate identity %q", r.Identity)
		}
		seen[r.Identity] = true
		if len(r.Roles) == 0 {
			return reject(ReasonSchema, "rbac %q: no roles", r.Identity)
		}
		for _, role := range r.Roles {
			if !nameOK(role, 64) {
				return reject(ReasonSchema, "rbac %q: role name empty, too long or with invalid characters", r.Identity)
			}
		}
	}
	return nil
}

// Validate checks schema_version, generation range, epochs (u32), the membership tables and the
// shape of the known config.* tables: every check the C++ parser makes.
func (b *Body) Validate() error {
	if b.SchemaVersion != 1 {
		return reject(ReasonSchema, "schema_version %d, want 1", b.SchemaVersion)
	}
	if !ValidGeneration(b.Generation) {
		return reject(ReasonSchema, "generation %d out of range 1..2^63-1", b.Generation)
	}
	m := &b.Membership
	if m.Epoch < 1 || m.Epoch > 0xffffffff {
		return reject(ReasonSchema, "membership.epoch must be in 1..2^32-1")
	}
	if m.PreviousEpoch >= m.Epoch {
		return reject(ReasonSchema, "membership.previous_epoch must be below epoch")
	}
	if len(m.Nodes) == 0 {
		return reject(ReasonSchema, "membership.nodes must not be empty")
	}
	ids := map[uint64]bool{}
	admins := map[string]bool{}
	zones := 0
	for i, n := range m.Nodes {
		if n.NodeID == 0 || n.NodeID > 0xffffffff || ids[n.NodeID] {
			return reject(ReasonSchema, "node %d: node_id %d invalid or duplicate", i, n.NodeID)
		}
		ids[n.NodeID] = true
		if n.Hostname == "" {
			return reject(ReasonSchema, "node %d: hostname is required", i)
		}
		if !nameOK(n.Hostname, 253) {
			return reject(ReasonSchema, "node %d: hostname has invalid characters or is too long", i)
		}
		if !hostPortOK(n.Admin) {
			return reject(ReasonSchema, "node %d: admin must be printable ASCII host:port, at most 255 bytes", i)
		}
		if n.Zone != "" && !nameOK(n.Zone, 64) {
			return reject(ReasonSchema, "node %d: zone has invalid characters or is too long", i)
		}
		if admins[n.Admin] {
			return reject(ReasonSchema, "node %d: duplicate admin", i)
		}
		admins[n.Admin] = true
		if n.Weight < 1 || n.Weight > 0xffffffff {
			return reject(ReasonSchema, "node %d: weight must be in 1..2^32-1", i)
		}
		if len(n.Rails) < 1 || len(n.Rails) > 4 {
			return reject(ReasonSchema, "node %d: rails must be 1..4", i)
		}
		for j, r := range n.Rails {
			if r.Addr == "" || r.Subnet == "" || r.Protocol == "" {
				return reject(ReasonSchema, "node %d rail %d: addr, subnet and protocol are required", i, j)
			}
			if !hostPortOK(r.Addr) {
				return reject(ReasonSchema, "node %d rail %d: addr must be printable ASCII host:port, at most 255 bytes", i, j)
			}
			if !cidrOK(r.Subnet) {
				return reject(ReasonSchema, "node %d rail %d: subnet must be CIDR text", i, j)
			}
			if r.Protocol != "roce" && r.Protocol != "iwarp" {
				return reject(ReasonSchema, "node %d rail %d: protocol must be roce or iwarp", i, j)
			}
		}
		switch n.State {
		case "active", "draining", "readonly":
		default:
			return reject(ReasonSchema, "node %d: state %q", i, n.State)
		}
		if n.Zone != "" {
			zones++
		}
	}
	if zones != 0 && zones != len(m.Nodes) {
		return reject(ReasonSchema, "zone must be set on all nodes or none")
	}
	if m.Previous != nil && len(m.Previous) == 0 {
		return reject(ReasonSchema, "membership.previous must not be an empty array")
	}
	pids := map[uint64]bool{}
	pzones := 0
	for i, p := range m.Previous {
		if p.NodeID == 0 || p.NodeID > 0xffffffff || pids[p.NodeID] {
			return reject(ReasonSchema, "previous %d: node_id %d invalid or duplicate", i, p.NodeID)
		}
		pids[p.NodeID] = true
		if p.Weight < 1 || p.Weight > 0xffffffff {
			return reject(ReasonSchema, "previous %d: weight must be in 1..2^32-1", i)
		}
		if p.Zone != "" {
			if !nameOK(p.Zone, 64) {
				return reject(ReasonSchema, "previous %d: zone has invalid characters or is too long", i)
			}
			pzones++
		}
	}
	if pzones != 0 && pzones != len(m.Previous) {
		return reject(ReasonSchema, "previous zone must be set on all entries or none")
	}
	return b.validateConfig()
}

// validateConfig checks the shape of the config tables the receiver knows; everything else in
// config.* is opaque.
func (b *Body) validateConfig() error {
	for k, v := range b.Config {
		switch k {
		case "cluster":
			cl, ok := v.(map[string]any)
			if !ok {
				return reject(ReasonSchema, "config.cluster must be a table")
			}
			for ck, cv := range cl {
				switch ck {
				case "placement":
					if _, ok := cv.(map[string]any); !ok {
						return reject(ReasonSchema, "config.cluster.placement must be a table")
					}
				case "memnode", "client":
					if _, ok := cv.(map[string]any); !ok {
						return reject(ReasonSchema, "config.cluster.%s must be a table", ck)
					}
				}
			}
		case "node":
			nodes, ok := v.(map[string]any)
			if !ok {
				return reject(ReasonSchema, "config.node must be a table")
			}
			for admin, nv := range nodes {
				nt, ok := nv.(map[string]any)
				if !ok {
					return reject(ReasonSchema, "config.node.%q must be a table", admin)
				}
				for ek, ov := range nt {
					if ek == "memnode" || ek == "client" {
						if _, isTable := ov.(map[string]any); !isTable {
							return reject(ReasonSchema, "config.node.%q.%s must be a table", admin, ek)
						}
					}
				}
			}
		}
	}
	if _, ok := b.Replicas(); !ok {
		return reject(ReasonSchema, "config.cluster.placement.replicas must be an integer in 1..2^32-1")
	}
	return nil
}

// ConfigKeys lists the dotted paths of every leaf in the config tables, sorted; callers use it
// to find unknown keys.
func (b *Body) ConfigKeys() []string {
	var out []string
	var walk func(prefix string, t map[string]any)
	walk = func(prefix string, t map[string]any) {
		for k, v := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			if sub, ok := v.(map[string]any); ok {
				walk(p, sub)
			} else {
				out = append(out, p)
			}
		}
	}
	walk("", b.Config)
	sort.Strings(out)
	return out
}

// Character rules; the C++ parser applies the same ones (core/control/bundle.cpp).

// nameOK reports whether s is [A-Za-z0-9._-], 1..max bytes: zone, principal name, role names
// and hostname.
func nameOK(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// hostPortOK reports whether s is printable ASCII (0x21..0x7e) "host:port", port 1..65535, at
// most 255 bytes: admin and rail addr.
func hostPortOK(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	colon := strings.LastIndexByte(s, ':')
	if colon <= 0 || colon+1 >= len(s) {
		return false
	}
	port := s[colon+1:]
	if len(port) > 5 {
		return false
	}
	p := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
		p = p*10 + int(port[i]-'0')
	}
	return p >= 1 && p <= 65535
}

// cidrOK reports whether s is <addr>/<prefix>: addr made of hex digits, '.' and ':' and holding
// a '.' or ':'; prefix 1..3 digits, at most 32 without ':' and at most 128 with.
func cidrOK(s string) bool {
	slash := strings.IndexByte(s, '/')
	if slash <= 0 || strings.IndexByte(s[slash+1:], '/') >= 0 {
		return false
	}
	addr, pre := s[:slash], s[slash+1:]
	if pre == "" || len(pre) > 3 {
		return false
	}
	colon, dot := false, false
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		hex := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
		if !hex && c != '.' && c != ':' {
			return false
		}
		colon = colon || c == ':'
		dot = dot || c == '.'
	}
	if !colon && !dot {
		return false
	}
	p := 0
	for i := 0; i < len(pre); i++ {
		if pre[i] < '0' || pre[i] > '9' {
			return false
		}
		p = p*10 + int(pre[i]-'0')
	}
	if colon {
		return p <= 128
	}
	return p <= 32
}
