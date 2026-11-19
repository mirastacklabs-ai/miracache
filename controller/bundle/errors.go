// Package bundle implements the signed cluster bundle "mira-bundle-v1" (membership plan
// decision 2): the byte-exact two-part envelope, the deterministic body emitter, signing,
// verification with role binding, parsing, the trust file and computed identities.
package bundle

import (
	"errors"
	"fmt"
)

// Reject reasons. They match the miracache_bundle_reject_total{reason} label values.
// The set is exactly core/control/reject.h's reason_string() values.
const (
	ReasonEnvelopeFormat     = "envelope_format"
	ReasonUnknownKey         = "unknown_key"
	ReasonKeyRole            = "key_role"
	ReasonBadSignature       = "bad_signature"
	ReasonBadSecSignature    = "bad_sec_signature"
	ReasonSchema             = "schema"
	ReasonGenerationLower    = "generation_lower"
	ReasonEqualGeneration    = "equal_generation"
	ReasonEpochBackwards     = "epoch_backwards"
	ReasonSecGenerationLower = "sec_generation_lower"
	ReasonSecEqualGeneration = "sec_equal_generation"
	ReasonTrustFile          = "trust_file"
)

// Error is a rejected bundle (or trust file); Reason is one of the Reason* constants.
type Error struct {
	Reason string
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("bundle: %s: %s", e.Reason, e.Msg) }

func reject(reason, format string, a ...any) *Error {
	return &Error{Reason: reason, Msg: fmt.Sprintf(format, a...)}
}

// ReasonOf returns the reject reason of err, or "" if err is not an *Error.
func ReasonOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason
	}
	return ""
}
