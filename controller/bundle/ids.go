package bundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// MaxGeneration is the largest generation / sec_generation (TOML's signed range, rule 9).
const MaxGeneration = uint64(1)<<63 - 1

// ValidGeneration reports whether g is in 1..2^63-1.
func ValidGeneration(g uint64) bool { return g >= 1 && g <= MaxGeneration }

// KeyID is the first 8 bytes of SHA-256 of the raw 32-byte public key, as 16 lower-case hex.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8])
}

// PrincipalID is u32be(SHA-256("mira-principal-v1" || name)[0..4]); 0 maps to 1 (decision 6).
func PrincipalID(name string) uint32 {
	h := sha256.New()
	h.Write([]byte("mira-principal-v1"))
	h.Write([]byte(name))
	id := binary.BigEndian.Uint32(h.Sum(nil)[:4])
	if id == 0 {
		return 1
	}
	return id
}

// HashHex is the SHA-256 of b as 64 lower-case hex (content_hash, applied_hash, sec_hash).
func HashHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
