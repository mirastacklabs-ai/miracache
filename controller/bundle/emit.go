package bundle

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// EmitSec writes the deterministic TOML bytes of s. The same value always gives the same bytes.
func EmitSec(s *Sec) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "sec_generation = %d\n", s.SecGeneration)
	for _, p := range s.Principals {
		b.WriteString("\n[[principals]]\n")
		fmt.Fprintf(&b, "name = %s\n", quote(p.Name))
		fmt.Fprintf(&b, "identities = %s\n", strArray(p.Identities))
		fmt.Fprintf(&b, "quota_bytes = %d\n", p.QuotaBytes)
		fmt.Fprintf(&b, "max_scopes = %d\n", p.MaxScopes)
		if p.DropBefore != "" {
			if !validDropBefore(p.DropBefore) {
				return nil, reject(ReasonSchema, "principal %q: drop_before must be YYYY-MM-DDTHH:MM:SSZ", p.Name)
			}
			fmt.Fprintf(&b, "drop_before = %s\n", quote(p.DropBefore))
		}
	}
	for _, r := range s.RBAC {
		b.WriteString("\n[[rbac]]\n")
		fmt.Fprintf(&b, "identity = %s\n", quote(r.Identity))
		fmt.Fprintf(&b, "roles = %s\n", strArray(r.Roles))
	}
	return []byte(b.String()), nil
}

// EmitBody writes the deterministic TOML bytes of body: fixed key order, config tables with
// sorted keys, LF only. Config values may be int64/int/uint64, float64, bool, string, []any,
// []string, []map[string]any and map[string]any.
func EmitBody(body *Body) ([]byte, error) {
	if err := body.Validate(); err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "schema_version = %d\n", body.SchemaVersion)
	fmt.Fprintf(&b, "generation = %d\n", body.Generation)
	fmt.Fprintf(&b, "created_at = %s\n", quote(body.CreatedAt))
	fmt.Fprintf(&b, "author = %s\n", quote(body.Author))
	fmt.Fprintf(&b, "reason = %s\n", quote(body.Reason))
	m := &body.Membership
	b.WriteString("\n[membership]\n")
	fmt.Fprintf(&b, "epoch = %d\n", m.Epoch)
	fmt.Fprintf(&b, "previous_epoch = %d\n", m.PreviousEpoch)
	for _, n := range m.Nodes {
		b.WriteString("\n[[membership.nodes]]\n")
		fmt.Fprintf(&b, "node_id = %d\n", n.NodeID)
		fmt.Fprintf(&b, "hostname = %s\n", quote(n.Hostname))
		fmt.Fprintf(&b, "admin = %s\n", quote(n.Admin))
		rails := make([]string, len(n.Rails))
		for i, r := range n.Rails {
			rails[i] = fmt.Sprintf("{ addr = %s, subnet = %s, protocol = %s }", quote(r.Addr), quote(r.Subnet), quote(r.Protocol))
		}
		fmt.Fprintf(&b, "rails = [%s]\n", strings.Join(rails, ", "))
		fmt.Fprintf(&b, "weight = %d\n", n.Weight)
		if n.Zone != "" {
			fmt.Fprintf(&b, "zone = %s\n", quote(n.Zone))
		}
		fmt.Fprintf(&b, "state = %s\n", quote(n.State))
	}
	for _, p := range m.Previous {
		b.WriteString("\n[[membership.previous]]\n")
		fmt.Fprintf(&b, "node_id = %d\n", p.NodeID)
		fmt.Fprintf(&b, "weight = %d\n", p.Weight)
		if p.Zone != "" {
			fmt.Fprintf(&b, "zone = %s\n", quote(p.Zone))
		}
	}
	if len(body.Config) > 0 {
		if err := emitTable(&b, []string{"config"}, body.Config); err != nil {
			return nil, err
		}
	}
	return []byte(b.String()), nil
}

func emitTable(b *strings.Builder, path []string, t map[string]any) error {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var scalars, subs []string
	for _, k := range keys {
		if _, ok := t[k].(map[string]any); ok {
			subs = append(subs, k)
		} else {
			scalars = append(scalars, k)
		}
	}
	if len(scalars) > 0 || (len(subs) == 0 && len(path) > 1) {
		b.WriteString("\n[" + joinKeys(path) + "]\n")
		for _, k := range scalars {
			v, err := value(t[k])
			if err != nil {
				return fmt.Errorf("config %s.%s: %w", joinKeys(path), k, err)
			}
			fmt.Fprintf(b, "%s = %s\n", key(k), v)
		}
	}
	for _, k := range subs {
		if err := emitTable(b, append(append([]string(nil), path...), k), t[k].(map[string]any)); err != nil {
			return err
		}
	}
	return nil
}

func value(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return quote(x), nil
	case bool:
		return strconv.FormatBool(x), nil
	case int:
		return strconv.FormatInt(int64(x), 10), nil
	case int64:
		return strconv.FormatInt(x, 10), nil
	case uint64:
		return strconv.FormatUint(x, 10), nil
	case float64:
		switch {
		case math.IsNaN(x):
			return "nan", nil
		case math.IsInf(x, 1):
			return "inf", nil
		case math.IsInf(x, -1):
			return "-inf", nil
		}
		s := strconv.FormatFloat(x, 'g', -1, 64)
		if !strings.ContainsAny(s, ".eE") {
			s += ".0"
		}
		return s, nil
	case time.Time:
		// TOML datetimes are bare (unquoted). Local-date and local-time kinds decode to the same
		// Go type and come back as offset datetimes.
		return x.Format(time.RFC3339Nano), nil
	case []string:
		return strArray(x), nil
	case []any:
		parts := make([]string, len(x))
		for i, e := range x {
			s, err := value(e)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case []map[string]any:
		parts := make([]string, len(x))
		for i, e := range x {
			s, err := value(e)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		parts := make([]string, len(ks))
		for i, k := range ks {
			s, err := value(x[k])
			if err != nil {
				return "", err
			}
			parts[i] = key(k) + " = " + s
		}
		return "{ " + strings.Join(parts, ", ") + " }", nil
	}
	return "", fmt.Errorf("unsupported value type %T", v)
}

func joinKeys(path []string) string {
	p := make([]string, len(path))
	for i, k := range path {
		p[i] = key(k)
	}
	return strings.Join(p, ".")
}

// key writes a bare key when it is [A-Za-z0-9_-]+, a quoted key otherwise.
func key(k string) string {
	if k == "" {
		return `""`
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return quote(k)
		}
	}
	return k
}

func strArray(s []string) string {
	parts := make([]string, len(s))
	for i, e := range s {
		parts[i] = quote(e)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// quote writes a TOML basic string: escapes for ", \, control characters (as \b \t \n \f \r or
// \u00XX) and DEL; other characters are written as UTF-8.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04x`, r)
		case r == utf8.RuneError:
			b.WriteString(`�`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
