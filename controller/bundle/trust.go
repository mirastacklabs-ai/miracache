package bundle

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
)

// Roles a trust key can hold.
const (
	RolePublish  = "publish"
	RoleSecurity = "security"
)

// TrustKey is one [[key]] entry. The key_id is computed, never typed.
type TrustKey struct {
	Public ed25519.PublicKey
	KeyID  string
	Roles  []string
	// MinSecGeneration is the optional pin (0 = none).
	MinSecGeneration uint64
}

// Has reports whether the key holds role.
func (k *TrustKey) Has(role string) bool {
	for _, r := range k.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// TrustKeys is a parsed trust file.
type TrustKeys struct {
	keys map[string]*TrustKey
	list []*TrustKey
	pin  uint64 // top-level min_sec_generation (0 = none)
}

// Lookup returns the key with the given computed key_id.
func (t *TrustKeys) Lookup(keyID string) *TrustKey { return t.keys[keyID] }

// Keys returns the keys in file order.
func (t *TrustKeys) Keys() []*TrustKey { return t.list }

// MinSecGeneration is the pinned security floor: the maximum pin over all entries (0 = none).
func (t *TrustKeys) MinSecGeneration() uint64 {
	m := t.pin
	for _, k := range t.list {
		if k.MinSecGeneration > m {
			m = k.MinSecGeneration
		}
	}
	return m
}

// NewTrustKeys builds a trust set from keys (computing key IDs); used by tests and tools.
func NewTrustKeys(keys ...TrustKey) (*TrustKeys, error) {
	t := &TrustKeys{keys: map[string]*TrustKey{}}
	for i := range keys {
		k := keys[i]
		if len(k.Public) != ed25519.PublicKeySize {
			return nil, reject(ReasonTrustFile, "trust key %d: public key must be 32 bytes", i)
		}
		if err := checkRoles(k.Roles); err != nil {
			return nil, fmt.Errorf("trust key %d: %w", i, err)
		}
		if k.MinSecGeneration != 0 && !ValidGeneration(k.MinSecGeneration) {
			return nil, reject(ReasonTrustFile, "trust key %d: min_sec_generation out of range", i)
		}
		k.KeyID = KeyID(k.Public)
		if _, dup := t.keys[k.KeyID]; dup {
			return nil, reject(ReasonTrustFile, "trust key %d: duplicate key (key_id %s)", i, k.KeyID)
		}
		kk := k
		t.keys[k.KeyID] = &kk
		t.list = append(t.list, &kk)
	}
	return t, nil
}

func checkRoles(roles []string) error {
	if len(roles) == 0 {
		return reject(ReasonTrustFile, "roles must not be empty")
	}
	seen := map[string]bool{}
	for _, r := range roles {
		if r != RolePublish && r != RoleSecurity {
			return reject(ReasonTrustFile, "unknown role %q", r)
		}
		if seen[r] {
			return reject(ReasonTrustFile, "duplicate role %q", r)
		}
		seen[r] = true
	}
	return nil
}

// ParseTrustFile parses the trust file contents with the C++ rules: exact keys, a typed `id`
// (stale key) or any other unknown key is an error (key IDs are computed, never typed, goal 10).
// Every refusal carries the reason trust_file.
func ParseTrustFile(data []byte) (*TrustKeys, error) {
	t, err := parseTrustFile(data)
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return nil, reject(ReasonTrustFile, "%s", e.Msg)
		}
		return nil, reject(ReasonTrustFile, "%v", err)
	}
	return t, nil
}

func trustPin(t map[string]any, what string) (uint64, error) {
	v, present, err := getInt(t, "min_sec_generation", 1, math.MaxInt64, what)
	if err != nil || !present {
		return 0, err
	}
	return uint64(v), nil
}

func parseTrustFile(data []byte) (*TrustKeys, error) {
	root, err := decodeTable(data, "trust file")
	if err != nil {
		return nil, err
	}
	if err := onlyKeys(root, "trust file", "key", "min_sec_generation"); err != nil {
		return nil, err
	}
	pin, err := trustPin(root, "trust file")
	if err != nil {
		return nil, err
	}
	arr, ok := tableArray(root["key"])
	if !ok {
		return nil, reject(ReasonTrustFile, "trust file needs at least one [[key]]")
	}
	keys := make([]TrustKey, 0, len(arr))
	for i, e := range arr {
		if _, typed := e["id"]; typed {
			return nil, reject(ReasonTrustFile, "trust file: typed `id` is a stale key: key IDs are computed")
		}
		if err := onlyKeys(e, "[[key]]", "public", "roles", "min_sec_generation"); err != nil {
			return nil, err
		}
		kpin, err := trustPin(e, "key")
		if err != nil {
			return nil, err
		}
		pub, present, err := getStr(e, "public", "key")
		if err != nil {
			return nil, err
		}
		if !present || len(pub) != 64 || !isLowerHex(pub) {
			return nil, reject(ReasonTrustFile, "trust file: key %d: public must be 64 lower-case hex", i)
		}
		raw, _ := hex.DecodeString(pub)
		roles, ok := stringArray(e["roles"])
		if !ok {
			return nil, reject(ReasonTrustFile, "trust file: key %d: roles must be a non-empty array of strings", i)
		}
		keys = append(keys, TrustKey{Public: ed25519.PublicKey(raw), Roles: roles, MinSecGeneration: kpin})
	}
	t, err := NewTrustKeys(keys...)
	if err != nil {
		return nil, err
	}
	t.pin = pin
	return t, nil
}

// LoadTrustFile reads and parses the trust file at path.
func LoadTrustFile(path string) (*TrustKeys, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseTrustFile(data)
}

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
