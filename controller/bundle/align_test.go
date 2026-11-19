package bundle

import (
	"strings"
	"testing"
)

// Rules aligned with the C++ parser (MB2): validation must be identical on both sides.

func TestDropBeforeExactForm(t *testing.T) {
	sec := string(mustSec(t, goldenSec()))
	good := "2026-11-01T00:00:00Z"
	for name, v := range map[string]string{
		"offset":       "2026-11-01T00:00:00+00:00",
		"offset minus": "2026-11-01T00:00:00-08:00",
		"fraction":     "2026-11-01T00:00:00.5Z",
		"lower z":      "2026-11-01T00:00:00z",
		"space":        "2026-11-01 00:00:00Z",
		"no seconds":   "2026-11-01T00:00Z",
		"bad date":     "2026-02-30T00:00:00Z",
		"hour 24":      "2026-11-01T24:00:00Z",
		"date only":    "2026-11-01",
	} {
		t.Run("parse "+name, func(t *testing.T) {
			wantReason(t, errOf(ParseSec([]byte(strings.Replace(sec, good, v, 1)))), ReasonSchema)
		})
		t.Run("emit "+name, func(t *testing.T) {
			s := goldenSec()
			s.Principals[0].DropBefore = v
			_, err := EmitSec(s)
			wantReason(t, err, ReasonSchema)
		})
	}
	if _, err := ParseSec([]byte(sec)); err != nil {
		t.Fatal(err)
	}
}

func TestPrincipalQuotaAndScopesRequired(t *testing.T) {
	sec := string(mustSec(t, goldenSec()))
	for name, txt := range map[string]string{
		"no quota_bytes": strings.Replace(sec, "quota_bytes = 549755813888\n", "", 1),
		"no max_scopes":  strings.Replace(sec, "max_scopes = 100000\n", "", 1),
		"negative quota": strings.Replace(sec, "quota_bytes = 549755813888", "quota_bytes = -1", 1),
		"negative scope": strings.Replace(sec, "max_scopes = 100000", "max_scopes = -1", 1),
	} {
		t.Run(name, func(t *testing.T) { wantReason(t, errOf(ParseSec([]byte(txt))), ReasonSchema) })
	}
	z := strings.Replace(strings.Replace(sec, "quota_bytes = 549755813888", "quota_bytes = 0", 1), "max_scopes = 100000", "max_scopes = 0", 1)
	if _, err := ParseSec([]byte(z)); err != nil {
		t.Fatalf("zero is allowed: %v", err)
	}
}

func TestEpochRules(t *testing.T) {
	base := string(mustEmit(t, goldenBody()))
	for name, txt := range map[string]string{
		"epoch 0":                 strings.Replace(strings.Replace(base, "epoch = 7", "epoch = 0", 1), "previous_epoch = 6", "previous_epoch = 0", 1),
		"epoch missing":           strings.Replace(base, "\nepoch = 7", "", 1),
		"previous_epoch == epoch": strings.Replace(base, "previous_epoch = 6", "previous_epoch = 7", 1),
		"previous_epoch > epoch":  strings.Replace(base, "previous_epoch = 6", "previous_epoch = 8", 1),
		"epoch beyond u32":        strings.Replace(base, "epoch = 7", "epoch = 4294967296", 1),
	} {
		t.Run(name, func(t *testing.T) { wantReason(t, errOf(ParseBody([]byte(txt))), ReasonSchema) })
	}
	// previous_epoch is optional (default 0) when epoch is 1.
	ok := strings.Replace(strings.Replace(base, "epoch = 7", "epoch = 1", 1), "previous_epoch = 6\n", "", 1)
	if _, err := ParseBody([]byte(ok)); err != nil {
		t.Fatal(err)
	}
}

func TestReplicasOptionalDefaultOne(t *testing.T) {
	b := goldenBody()
	delete(b.Config["cluster"].(map[string]any), "placement")
	p, err := ParseBody(mustEmit(t, b))
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := p.Replicas(); !ok || r != 1 {
		t.Fatalf("default replicas = %d %v", r, ok)
	}
	b.Config = nil
	if p, err = ParseBody(mustEmit(t, b)); err != nil {
		t.Fatal(err)
	}
	if r, ok := p.Replicas(); !ok || r != 1 {
		t.Fatal("no config at all")
	}
	g, _ := ParseBody(mustEmit(t, goldenBody()))
	if r, _ := g.Replicas(); r != 2 {
		t.Fatalf("replicas = %d", r)
	}
	valid := string(mustEmit(t, goldenBody()))
	for _, v := range []string{"0", "-1", "4294967296", `"2"`, "2.0"} {
		txt := strings.Replace(valid, "replicas = 2", "replicas = "+v, 1)
		if _, err := ParseBody([]byte(txt)); err == nil {
			t.Fatalf("replicas %v accepted", v)
		}
		b := goldenBody()
		b.Config["cluster"].(map[string]any)["placement"] = map[string]any{"replicas": v}
		if _, err := EmitBody(b); err == nil {
			t.Fatalf("replicas %v emitted", v)
		}
	}
}

func TestTrustFileTopLevelPin(t *testing.T) {
	pk := hexLower(pubOf(publishKey))
	sk := hexLower(pubOf(securityKey))
	keys := "[[key]]\npublic = \"" + pk + "\"\nroles = [\"publish\"]\n\n[[key]]\npublic = \"" + sk + "\"\nroles = [\"security\"]\n"
	top := func(n string) string { return "min_sec_generation = " + n + "\n\n" + keys }
	inKey := keys + "min_sec_generation = 4\n" // belongs to the last [[key]]
	cases := []struct {
		name string
		txt  string
		want uint64
	}{
		{"none", keys, 0},
		{"top only", top("3"), 3},
		{"key only", inKey, 4},
		{"top higher", top("9") + "min_sec_generation = 4\n", 9},
		{"key higher", top("2") + "min_sec_generation = 4\n", 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr, err := ParseTrustFile([]byte(c.txt))
			if c.name == "top higher" || c.name == "key higher" {
				// the trailing key is appended after the last [[key]] table
				if err != nil {
					t.Fatal(err)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if tr.MinSecGeneration() != c.want {
				t.Fatalf("pin = %d, want %d", tr.MinSecGeneration(), c.want)
			}
		})
	}
	for _, v := range []string{"0", "-1", "9223372036854775808"} {
		if _, err := ParseTrustFile([]byte(top(v))); err == nil {
			t.Fatalf("top-level pin %s accepted", v)
		}
	}
	if _, err := ParseTrustFile([]byte("min_sec_generation = 3\n")); err == nil {
		t.Fatal("trust file without any [[key]] accepted")
	}
	if _, err := ParseTrustFile([]byte("bogus = 1\n\n" + keys)); err == nil {
		t.Fatal("unknown top-level key accepted")
	}
}
