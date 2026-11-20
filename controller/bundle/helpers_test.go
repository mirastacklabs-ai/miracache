package bundle

import (
	"crypto/ed25519"
	"testing"
)

// Shared test seeds (the bundle goldens use the same): publish key seed bytes 0x01..0x20, security key seed
// bytes 0x21..0x40. A third key (0x41..0x60) holds both roles.
func seedFrom(first byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = first + byte(i)
	}
	return s
}

var (
	publishKey  = ed25519.NewKeyFromSeed(seedFrom(0x01))
	securityKey = ed25519.NewKeyFromSeed(seedFrom(0x21))
	bothKey     = ed25519.NewKeyFromSeed(seedFrom(0x41))
)

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func testTrust(t *testing.T) *TrustKeys {
	t.Helper()
	tr, err := NewTrustKeys(
		TrustKey{Public: pubOf(publishKey), Roles: []string{RolePublish}},
		TrustKey{Public: pubOf(securityKey), Roles: []string{RoleSecurity}},
		TrustKey{Public: pubOf(bothKey), Roles: []string{RolePublish, RoleSecurity}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func goldenSec() *Sec {
	return &Sec{
		SecGeneration: 5,
		Principals: []Principal{
			{Name: "prod-llama", Identities: []string{"spiffe://prod/vllm-host-1", "spiffe://prod/vllm-host-2"},
				QuotaBytes: 2199023255552, MaxScopes: 4000000, DropBefore: "2026-11-01T00:00:00Z"},
			{Name: "staging", Identities: []string{"spiffe://staging/sglang-1"}, QuotaBytes: 549755813888, MaxScopes: 100000},
		},
		RBAC: []RBAC{
			{Identity: "spiffe://ops/alice", Roles: []string{"security-admin"}},
			{Identity: "spiffe://ops/bob", Roles: []string{"operator", "auditor"}},
		},
	}
}

func goldenBody() *Body {
	return &Body{
		SchemaVersion: 1,
		Generation:    42,
		CreatedAt:     "2026-11-12T09:00:00Z",
		Author:        "spiffe://ops/alice",
		Reason:        "add hostB",
		Membership: Membership{
			Epoch:         7,
			PreviousEpoch: 6,
			Nodes: []Node{
				{NodeID: 3141592653, Hostname: "hostA", Admin: "10.0.0.10:9465", Weight: 1, Zone: "rack1", State: "active",
					Rails: []Rail{{Addr: "10.0.0.10:7471", Subnet: "10.0.0.0/24", Protocol: "roce"}}},
				{NodeID: 2718281828, Hostname: "hostB", Admin: "10.0.0.11:9465", Weight: 2, Zone: "rack2", State: "draining",
					Rails: []Rail{{Addr: "10.0.0.11:7471", Subnet: "10.0.0.0/24", Protocol: "roce"}, {Addr: "10.1.0.11:7471", Subnet: "10.1.0.0/24", Protocol: "iwarp"}}},
			},
			Previous: []PreviousNode{{NodeID: 3141592653, Weight: 1, Zone: "rack1"}},
		},
		Config: map[string]any{
			"cluster": map[string]any{
				"placement": map[string]any{"replicas": int64(2)},
				"memnode":   map[string]any{"pool_bytes": int64(1073741824), "label": "café \"x\"\n"},
				"client":    map[string]any{"poll_s": int64(30), "ratio": 0.5, "on": true, "tags": []any{"a", "b"}},
			},
			"node": map[string]any{
				"10.0.0.10:9465": map[string]any{"memnode": map[string]any{"pool_bytes": int64(2147483648)}},
			},
		},
	}
}

func mustEmit(t *testing.T, b *Body) []byte {
	t.Helper()
	out, err := EmitBody(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// goldenEnvelope signs the golden sec/body with the shared test seeds.
func goldenEnvelope(t *testing.T) (*Envelope, []byte) {
	t.Helper()
	e := Sign(publishKey, securityKey, mustSec(t, goldenSec()), mustEmit(t, goldenBody()))
	return e, e.Marshal()
}

func mustSec(t *testing.T, s *Sec) []byte {
	t.Helper()
	out, err := EmitSec(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
