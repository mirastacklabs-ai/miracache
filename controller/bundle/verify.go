package bundle

import (
	"crypto/ed25519"
)

// Verified is an envelope whose format, roles and both signatures have been checked.
type Verified struct {
	Envelope    *Envelope
	Raw         []byte
	SecHash     string // 64 hex, SHA-256 of the sec bytes
	ContentHash string // 64 hex, SHA-256 of the body bytes (applied_hash)
}

// Verify checks raw statelessly, before anything is parsed: byte-exact format, key_id names a
// trust key holding `publish`, sec_key_id one holding `security` (role binding, rule 8), then
// both Ed25519 signatures.
func Verify(trust *TrustKeys, raw []byte) (*Verified, error) {
	e, err := ParseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	pk := trust.Lookup(e.KeyID)
	if pk == nil {
		return nil, reject(ReasonUnknownKey, "key_id %s is not a trust key", e.KeyID)
	}
	sk := trust.Lookup(e.SecKeyID)
	if sk == nil {
		return nil, reject(ReasonUnknownKey, "sec_key_id %s is not a trust key", e.SecKeyID)
	}
	// Same order as the C++ verifier: both keys must exist before any role is checked.
	if !pk.Has(RolePublish) {
		return nil, reject(ReasonKeyRole, "key_id %s does not hold the publish role", e.KeyID)
	}
	if !sk.Has(RoleSecurity) {
		return nil, reject(ReasonKeyRole, "sec_key_id %s does not hold the security role", e.SecKeyID)
	}
	if !ed25519.Verify(pk.Public, PublishMessage(e.Sec, e.Body), e.Sig) {
		return nil, reject(ReasonBadSignature, "publish signature does not verify")
	}
	if !ed25519.Verify(sk.Public, SecurityMessage(e.Sec), e.SecSig) {
		return nil, reject(ReasonBadSecSignature, "security signature does not verify")
	}
	return &Verified{Envelope: e, Raw: raw, SecHash: HashHex(e.Sec), ContentHash: HashHex(e.Body)}, nil
}

// Bundle is a verified and parsed bundle.
type Bundle struct {
	Verified
	Body *Body
	Sec  *Sec
}

// Open verifies raw, parses sec and body strictly, validates them, and enforces the trust file's
// pinned min_sec_generation.
func Open(trust *TrustKeys, raw []byte) (*Bundle, error) {
	v, err := Verify(trust, raw)
	if err != nil {
		return nil, err
	}
	sec, err := ParseSec(v.Envelope.Sec)
	if err != nil {
		return nil, err
	}
	body, err := ParseBody(v.Envelope.Body)
	if err != nil {
		return nil, err
	}
	if min := trust.MinSecGeneration(); sec.SecGeneration < min {
		return nil, reject(ReasonSecGenerationLower, "sec_generation %d below the pinned min_sec_generation %d", sec.SecGeneration, min)
	}
	return &Bundle{Verified: *v, Body: body, Sec: sec}, nil
}
