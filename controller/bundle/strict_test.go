package bundle

import (
	"bytes"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A rejectCase is invalid content that C++ and Go must both refuse; it is signed with the test
// seeds so only the content is wrong.
type rejectCase struct {
	name string
	file string                    // file name stem; "reject_go_"+name when empty
	sec  func(valid string) string // nil keeps the valid sec
	body func(valid string) string // nil keeps the valid body
}

func cutBetween(s, from, to string) string {
	i := strings.Index(s, from)
	j := strings.Index(s, to)
	if i < 0 || j < i {
		panic("cutBetween: markers not found")
	}
	return s[:i] + s[j:]
}

func replaceOnce(s, old, new string) string {
	if !strings.Contains(s, old) {
		panic("replaceOnce: " + old + " not in text")
	}
	return strings.Replace(s, old, new, 1)
}

var rejectCases = []rejectCase{
	{name: "no_nodes", body: func(b string) string { return cutBetween(b, "\n[[membership.nodes]]", "\n[[membership.previous]]") }},
	{name: "empty_hostname", body: func(b string) string { return replaceOnce(b, `hostname = "hostA"`, `hostname = ""`) }},
	{name: "weight_zero", body: func(b string) string { return replaceOnce(b, "weight = 1\n", "weight = 0\n") }},
	{name: "weight_missing", body: func(b string) string { return replaceOnce(b, "weight = 1\n", "") }},
	{name: "rail_empty_addr", body: func(b string) string { return replaceOnce(b, `addr = "10.0.0.10:7471"`, `addr = ""`) }},
	{name: "previous_duplicate_node", body: func(b string) string {
		blk := "[[membership.previous]]\nnode_id = 3141592653\nweight = 1\nzone = \"rack1\"\n"
		return replaceOnce(b, blk, blk+"\n"+blk)
	}},
	{name: "previous_empty_array", body: func(b string) string {
		b = cutBetween(b, "\n[[membership.previous]]", "\n[config")
		return replaceOnce(b, "previous_epoch = 6\n", "previous_epoch = 6\nprevious = []\n")
	}},
	{name: "zone_empty", body: func(b string) string { return replaceOnce(b, `zone = "rack1"`, `zone = ""`) }},
	{name: "config_cluster_not_table", body: func(b string) string {
		return cutBetween(b, "\n[config.cluster", "\n[config.node") + "\n[config]\ncluster = 1\n"
	}},
	{name: "body_bom", body: func(b string) string { return "\xEF\xBB\xBF" + b }},
	{name: "body_key_case", body: func(b string) string { return replaceOnce(b, "generation = 42", "Generation = 42") }},
	{name: "body_table_case", body: func(b string) string { return replaceOnce(b, "[membership]", "[Membership]\n[membership]") }},
	{name: "sec_principals_empty", sec: func(string) string { return "sec_generation = 5\nprincipals = []\n" }},
	{name: "sec_rbac_empty", sec: func(string) string { return "sec_generation = 5\nrbac = []\n" }},
	{name: "sec_principal_no_identities", sec: func(s string) string {
		return replaceOnce(s, "identities = [\"spiffe://staging/sglang-1\"]\n", "")
	}},
	{name: "sec_drop_before_empty", sec: func(s string) string {
		return replaceOnce(s, "max_scopes = 100000\n", "max_scopes = 100000\ndrop_before = \"\"\n")
	}},
	{name: "sec_empty_role", sec: func(s string) string { return replaceOnce(s, `roles = ["security-admin"]`, `roles = [""]`) }},
	// X19: character rules (shared with C++).
	{name: "charset_hostname_ctrl", file: "reject_charset_hostname_ctrl", body: func(b string) string { return replaceOnce(b, `"hostA"`, `"host\u0007A"`) }},
	{name: "charset_hostname_space", file: "reject_charset_hostname_space", body: func(b string) string { return replaceOnce(b, `"hostA"`, `"host A"`) }},
	{name: "charset_hostname_long", file: "reject_charset_hostname_long", body: func(b string) string {
		return replaceOnce(b, `"hostA"`, `"`+strings.Repeat("a", 254)+`"`)
	}},
	{name: "charset_admin_space", file: "reject_charset_admin_space", body: func(b string) string { return replaceOnce(b, `"10.0.0.10:9465"`, `"10.0.0.10 :9465"`) }},
	{name: "charset_admin_no_port", file: "reject_charset_admin_no_port", body: func(b string) string { return replaceOnce(b, `"10.0.0.10:9465"`, `"10.0.0.10"`) }},
	{name: "charset_zone_slash", file: "reject_charset_zone_slash", body: func(b string) string { return replaceOnce(b, `"rack2"`, `"rack/2"`) }},
	{name: "charset_addr_ctrl", file: "reject_charset_addr_ctrl", body: func(b string) string { return replaceOnce(b, `"10.0.0.10:7471"`, `"10.0.0.10:74\u000071"`) }},
	{name: "charset_subnet_not_cidr", file: "reject_charset_subnet_not_cidr", body: func(b string) string { return replaceOnce(b, `"10.0.0.0/24"`, `"a"`) }},
	{name: "charset_subnet_prefix", file: "reject_charset_subnet_prefix", body: func(b string) string { return replaceOnce(b, `"10.0.0.0/24"`, `"10.0.0.0/33"`) }},
	{name: "charset_protocol", file: "reject_charset_protocol", body: func(b string) string { return replaceOnce(b, `"iwarp"`, `"tcp"`) }},
	{name: "charset_principal_name", file: "reject_charset_principal_name", sec: func(s string) string { return replaceOnce(s, `"staging"`, `"stag ing"`) }},
	{name: "charset_role", file: "reject_charset_role", sec: func(s string) string { return replaceOnce(s, `"auditor"`, `"audit\nor"`) }},
	// X21: TOML 1.1 syntax (a trailing comma in an inline table) is not accepted.
	{name: "toml11_inline_trailing_comma", file: "reject_toml11_inline_trailing_comma", body: func(b string) string {
		return replaceOnce(b, `protocol = "roce" }]`, `protocol = "roce", }]`)
	}},
	{name: "sec_bom", sec: func(s string) string { return "\xEF\xBB\xBF" + s }},
	{name: "sec_key_case", sec: func(s string) string { return replaceOnce(s, "sec_generation = 5", "Sec_Generation = 5") }},
}

func rejectEnvelope(t *testing.T, c rejectCase) []byte {
	t.Helper()
	sec := string(mustSec(t, goldenSec()))
	body := string(mustEmit(t, goldenBody()))
	if c.sec != nil {
		sec = c.sec(sec)
	}
	if c.body != nil {
		body = c.body(body)
	}
	return Sign(publishKey, securityKey, []byte(sec), []byte(body)).Marshal()
}

// TestGoRejectCorpus regenerates proto/golden/bundle_v1/reject_go_*.envelope, requires them
// byte-equal to the committed files and rejected with reason schema. GO_WRITE_GOLDEN=1 rewrites
// them. The C++ suite rejects every reject*.envelope in that directory as well.
func TestGoRejectCorpus(t *testing.T) {
	tr := testTrust(t)
	for _, c := range rejectCases {
		t.Run(c.name, func(t *testing.T) {
			raw := rejectEnvelope(t, c)
			stem := c.file
			if stem == "" {
				stem = "reject_go_" + c.name
			}
			path := filepath.Join(goldenDir, stem+".envelope")
			if os.Getenv("GO_WRITE_GOLDEN") == "1" {
				if err := os.WriteFile(path, raw, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, raw) {
				t.Fatalf("%s differs from the regenerated bytes (GO_WRITE_GOLDEN=1 rewrites it): %v", path, err)
			}
			_, err := Open(tr, raw)
			if err == nil {
				t.Fatalf("%s accepted, want reject", path)
			}
			checkRejectExpect(t, filepath.Base(path), err)
		})
	}
}

func TestCaseSensitiveKeys(t *testing.T) {
	base := string(mustEmit(t, goldenBody()))
	for name, txt := range map[string]string{
		"Generation":      replaceOnce(base, "generation = 42", "Generation = 9"),
		"both":            replaceOnce(base, "generation = 42", "generation = 42\nGeneration = 9"),
		"[Membership]":    replaceOnce(base, "[membership]", "[Membership]"),
		"Schema_Version":  replaceOnce(base, "schema_version", "Schema_Version"),
		"node Hostname":   replaceOnce(base, "hostname =", "Hostname ="),
		"rail Addr":       replaceOnce(base, "addr =", "Addr ="),
		"previous Weight": replaceOnce(base, "[[membership.previous]]\nnode_id = 3141592653\nweight", "[[membership.previous]]\nnode_id = 3141592653\nWeight"),
	} {
		t.Run("body "+name, func(t *testing.T) { wantReason(t, errOf(ParseBody([]byte(txt))), ReasonSchema) })
	}
	sec := string(mustSec(t, goldenSec()))
	for name, txt := range map[string]string{
		"Sec_Generation": replaceOnce(sec, "sec_generation", "Sec_Generation"),
		"Principals":     replaceOnce(sec, "[[principals]]", "[[Principals]]"),
		"Quota_Bytes":    replaceOnce(sec, "quota_bytes", "Quota_Bytes"),
	} {
		t.Run("sec "+name, func(t *testing.T) { wantReason(t, errOf(ParseSec([]byte(txt))), ReasonSchema) })
	}
	tf := goldenTrustFile()
	for name, txt := range map[string]string{
		"[[Key]]": replaceOnce(tf, "[[key]]", "[[Key]]"),
		"Public":  replaceOnce(tf, "public =", "Public ="),
		"Roles":   replaceOnce(tf, "roles =", "Roles ="),
	} {
		t.Run("trust "+name, func(t *testing.T) { wantReason(t, errOf(ParseTrustFile([]byte(txt))), ReasonTrustFile) })
	}
}

func TestEmitValidates(t *testing.T) {
	for name, mut := range map[string]func(*Body){
		"no nodes":       func(b *Body) { b.Membership.Nodes = nil },
		"empty hostname": func(b *Body) { b.Membership.Nodes[0].Hostname = "" },
		"weight 0":       func(b *Body) { b.Membership.Nodes[0].Weight = 0 },
		"weight > u32":   func(b *Body) { b.Membership.Nodes[0].Weight = 1 << 32 },
		"rail no subnet": func(b *Body) { b.Membership.Nodes[0].Rails[0].Subnet = "" },
		"rail no proto":  func(b *Body) { b.Membership.Nodes[0].Rails[0].Protocol = "" },
		"previous dup":   func(b *Body) { b.Membership.Previous = append(b.Membership.Previous, b.Membership.Previous[0]) },
		"previous w 0":   func(b *Body) { b.Membership.Previous[0].Weight = 0 },
		"previous id 0":  func(b *Body) { b.Membership.Previous[0].NodeID = 0 },
		"previous mixed": func(b *Body) {
			b.Membership.Previous = append(b.Membership.Previous, PreviousNode{NodeID: 5, Weight: 1})
		},
		"previous empty":  func(b *Body) { b.Membership.Previous = []PreviousNode{} },
		"cluster scalar":  func(b *Body) { b.Config["cluster"] = int64(1) },
		"placement array": func(b *Body) { b.Config["cluster"].(map[string]any)["placement"] = []any{} },
		"memnode scalar":  func(b *Body) { b.Config["cluster"].(map[string]any)["memnode"] = "x" },
		"client scalar":   func(b *Body) { b.Config["cluster"].(map[string]any)["client"] = int64(3) },
		"node scalar":     func(b *Body) { b.Config["node"] = "x" },
		"node child":      func(b *Body) { b.Config["node"].(map[string]any)["10.0.0.10:9465"] = int64(1) },
		"node memnode": func(b *Body) {
			b.Config["node"].(map[string]any)["10.0.0.10:9465"].(map[string]any)["memnode"] = int64(1)
		},
	} {
		t.Run("body "+name, func(t *testing.T) {
			b := goldenBody()
			mut(b)
			_, err := EmitBody(b)
			wantReason(t, err, ReasonSchema)
		})
	}
	for name, mut := range map[string]func(*Sec){
		"no identities":  func(s *Sec) { s.Principals[0].Identities = nil },
		"empty role":     func(s *Sec) { s.RBAC[0].Roles = []string{""} },
		"empty rbac":     func(s *Sec) { s.RBAC = []RBAC{} },
		"empty princ":    func(s *Sec) { s.Principals = []Principal{} },
		"sec_generation": func(s *Sec) { s.SecGeneration = 0 },
	} {
		t.Run("sec "+name, func(t *testing.T) {
			s := goldenSec()
			mut(s)
			_, err := EmitSec(s)
			wantReason(t, err, ReasonSchema)
		})
	}
}

func TestConfigNanInfAndDatetime(t *testing.T) {
	when := time.Date(2026, 11, 12, 9, 0, 0, 500, time.UTC)
	b := goldenBody()
	b.Config["cluster"].(map[string]any)["memnode"].(map[string]any)["nan"] = math.NaN()
	b.Config["cluster"].(map[string]any)["memnode"].(map[string]any)["pinf"] = math.Inf(1)
	b.Config["cluster"].(map[string]any)["memnode"].(map[string]any)["ninf"] = math.Inf(-1)
	b.Config["cluster"].(map[string]any)["memnode"].(map[string]any)["when"] = when
	out := mustEmit(t, b)
	for _, want := range []string{"nan = nan\n", "pinf = inf\n", "ninf = -inf\n", "when = 2026-11-12T09:00:00.0000005Z\n"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	p, err := ParseBody(out)
	if err != nil {
		t.Fatal(err)
	}
	mn := p.Config["cluster"].(map[string]any)["memnode"].(map[string]any)
	if !math.IsNaN(mn["nan"].(float64)) || !math.IsInf(mn["pinf"].(float64), 1) || !math.IsInf(mn["ninf"].(float64), -1) {
		t.Fatalf("%v", mn)
	}
	if got, ok := mn["when"].(time.Time); !ok || !got.Equal(when) {
		t.Fatalf("when = %v", mn["when"])
	}
	if !bytes.Equal(mustEmit(t, p), out) {
		t.Fatal("re-emit differs")
	}
}

func TestLookupOrder(t *testing.T) {
	// The publish key is not a trust key at all and the security key lacks the security role:
	// the unknown key is reported before any role problem, whichever field it is in.
	tr, err := NewTrustKeys(TrustKey{Public: pubOf(securityKey), Roles: []string{RolePublish}})
	if err != nil {
		t.Fatal(err)
	}
	_, raw := goldenEnvelope(t)
	_, err = Verify(tr, raw)
	wantReason(t, err, ReasonUnknownKey)
	// Publish key present but without the publish role, sec key unknown: unknown_key first.
	tr, err = NewTrustKeys(TrustKey{Public: pubOf(publishKey), Roles: []string{RoleSecurity}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(tr, raw)
	wantReason(t, err, ReasonUnknownKey)
}

func TestSecSignatureReason(t *testing.T) {
	e, _ := goldenEnvelope(t)
	e.SecSig = append([]byte(nil), e.SecSig...)
	e.SecSig[0] ^= 1
	_, err := Verify(testTrust(t), e.Marshal())
	wantReason(t, err, ReasonBadSecSignature)
}

func TestToml11EnvIsRefused(t *testing.T) {
	body := mustEmit(t, goldenBody())
	if _, err := ParseBody(body); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BURNTSUSHI_TOML_110", "1")
	wantReason(t, errOf(ParseBody(body)), ReasonSchema)
	wantReason(t, errOf(ParseSec(mustSec(t, goldenSec()))), ReasonSchema)
	wantReason(t, errOf(ParseTrustFile([]byte(goldenTrustFile()))), ReasonTrustFile)
}

func TestCharsetRules(t *testing.T) {
	for s, ok := range map[string]bool{"a": true, "Rack-1_b.c": true, "": false, "a b": false, "a/b": false, "é": false, "a\n": false, strings.Repeat("a", 64): true, strings.Repeat("a", 65): false} {
		if nameOK(s, 64) != ok {
			t.Errorf("nameOK(%q) != %v", s, ok)
		}
	}
	for s, ok := range map[string]bool{"10.0.0.1:80": true, "[::1]:9465": true, "h:65535": true, "h:0": false, "h:65536": false, ":80": false, "h": false, "h:": false, "h :80": false, "h:8x": false} {
		if hostPortOK(s) != ok {
			t.Errorf("hostPortOK(%q) != %v", s, ok)
		}
	}
	for s, ok := range map[string]bool{"10.0.0.0/24": true, "fd00::/64": true, "10.0.0.0/33": false, "fd00::/129": false, "10.0.0.0": false, "a": false, "/24": false, "10.0.0.0/": false, "10.0.0.0/2/4": false, "zz.1/8": false} {
		if cidrOK(s) != ok {
			t.Errorf("cidrOK(%q) != %v", s, ok)
		}
	}
}
