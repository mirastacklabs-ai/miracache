package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"strconv"
)

// MaxEnvelope is the largest whole envelope in bytes (1 MiB).
const MaxEnvelope = 1 << 20

const (
	magic        = "mira-bundle-v1"
	publishTag   = "mira-bundle-v1\x00"
	securityTag  = "mira-bundle-sec-v1\x00"
	hdrKeyID     = "key_id"
	hdrSig       = "sig"
	hdrSecKeyID  = "sec_key_id"
	hdrSecSig    = "sec_sig"
	hdrSecLen    = "sec_len"
	keyIDHexLen  = 16
	sigHexLen    = 128
	maxSecLenDig = 7
)

// Envelope is a parsed (not yet verified) bundle envelope.
type Envelope struct {
	KeyID    string // 16 lower-case hex
	Sig      []byte // 64 bytes
	SecKeyID string
	SecSig   []byte
	Sec      []byte // exact bytes of the sec section
	Body     []byte // exact bytes of the body
}

// Marshal writes the envelope in the byte-exact form:
//
//	mira-bundle-v1\n key_id: <16>\n sig: <128>\n sec_key_id: <16>\n sec_sig: <128>\n sec_len: <n>\n \n <sec><body>
func (e *Envelope) Marshal() []byte {
	var b bytes.Buffer
	b.WriteString(magic + "\n")
	b.WriteString(hdrKeyID + ": " + e.KeyID + "\n")
	b.WriteString(hdrSig + ": " + hex.EncodeToString(e.Sig) + "\n")
	b.WriteString(hdrSecKeyID + ": " + e.SecKeyID + "\n")
	b.WriteString(hdrSecSig + ": " + hex.EncodeToString(e.SecSig) + "\n")
	b.WriteString(hdrSecLen + ": " + strconv.Itoa(len(e.Sec)) + "\n")
	b.WriteString("\n")
	b.Write(e.Sec)
	b.Write(e.Body)
	return b.Bytes()
}

// PublishMessage is the signed message of the publish signature:
// "mira-bundle-v1\0" || u32be(len(sec)) || sec || body.
func PublishMessage(sec, body []byte) []byte {
	m := make([]byte, 0, len(publishTag)+4+len(sec)+len(body))
	m = append(m, publishTag...)
	m = binary.BigEndian.AppendUint32(m, uint32(len(sec)))
	m = append(m, sec...)
	m = append(m, body...)
	return m
}

// SecurityMessage is the signed message of the security signature: "mira-bundle-sec-v1\0" || sec.
func SecurityMessage(sec []byte) []byte {
	m := make([]byte, 0, len(securityTag)+len(sec))
	m = append(m, securityTag...)
	m = append(m, sec...)
	return m
}

// Sign builds a fully signed envelope: the publish key signs sec+body, the security key signs sec.
func Sign(pub, secKey ed25519.PrivateKey, sec, body []byte) *Envelope {
	return &Envelope{
		KeyID:    KeyID(pub.Public().(ed25519.PublicKey)),
		Sig:      ed25519.Sign(pub, PublishMessage(sec, body)),
		SecKeyID: KeyID(secKey.Public().(ed25519.PublicKey)),
		SecSig:   ed25519.Sign(secKey, SecurityMessage(sec)),
		Sec:      sec,
		Body:     body,
	}
}

// SignPublishOnly builds a publish-only bundle: the sec bytes, sec_key_id and sec_sig are carried
// unchanged from prev; only the publish signature is new.
func SignPublishOnly(pub ed25519.PrivateKey, prev *Envelope, body []byte) *Envelope {
	return &Envelope{
		KeyID:    KeyID(pub.Public().(ed25519.PublicKey)),
		Sig:      ed25519.Sign(pub, PublishMessage(prev.Sec, body)),
		SecKeyID: prev.SecKeyID,
		SecSig:   append([]byte(nil), prev.SecSig...),
		Sec:      prev.Sec,
		Body:     body,
	}
}

// ParseEnvelope parses raw with every byte-exact envelope rule (rules 1-6); any deviation is
// an envelope_format reject. It does not verify signatures.
func ParseEnvelope(raw []byte) (*Envelope, error) {
	if len(raw) > MaxEnvelope {
		return nil, reject(ReasonEnvelopeFormat, "envelope larger than 1 MiB")
	}
	rest := raw
	line := func() ([]byte, bool) {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			return nil, false
		}
		l := rest[:i]
		rest = rest[i+1:]
		return l, true
	}
	// Rule 2: no CR anywhere in the header. The header ends at the first empty line; scan lines.
	l, ok := line()
	if !ok || string(l) != magic {
		return nil, reject(ReasonEnvelopeFormat, "first line must be %q", magic)
	}
	vals := map[string]string{}
	for _, name := range []string{hdrKeyID, hdrSig, hdrSecKeyID, hdrSecSig, hdrSecLen} {
		l, ok = line()
		if !ok {
			return nil, reject(ReasonEnvelopeFormat, "truncated header before %s", name)
		}
		if bytes.IndexByte(l, '\r') >= 0 {
			return nil, reject(ReasonEnvelopeFormat, "CR in header")
		}
		prefix := name + ": " // rule 3: exactly one space
		if !bytes.HasPrefix(l, []byte(prefix)) {
			return nil, reject(ReasonEnvelopeFormat, "header line %q: want %q", trunc(l), prefix)
		}
		v := l[len(prefix):]
		if len(v) == 0 || v[0] == ' ' || bytes.IndexAny(v, " \t") >= 0 {
			return nil, reject(ReasonEnvelopeFormat, "%s: bad value spacing", name)
		}
		vals[name] = string(v)
	}
	l, ok = line()
	if !ok || len(l) != 0 {
		return nil, reject(ReasonEnvelopeFormat, "header must end with one empty line")
	}
	// Rule 4: lower-case hex, exact lengths.
	e := &Envelope{KeyID: vals[hdrKeyID], SecKeyID: vals[hdrSecKeyID]}
	for _, c := range []struct {
		name string
		n    int
	}{{hdrKeyID, keyIDHexLen}, {hdrSecKeyID, keyIDHexLen}, {hdrSig, sigHexLen}, {hdrSecSig, sigHexLen}} {
		v := vals[c.name]
		if len(v) != c.n || !isLowerHex(v) {
			return nil, reject(ReasonEnvelopeFormat, "%s must be exactly %d lower-case hex characters", c.name, c.n)
		}
	}
	e.Sig, _ = hex.DecodeString(vals[hdrSig])
	e.SecSig, _ = hex.DecodeString(vals[hdrSecSig])
	// Rule 5: sec_len decimal, no sign, no leading zeros, never 0, at most 7 digits.
	sl := vals[hdrSecLen]
	if len(sl) == 0 || len(sl) > maxSecLenDig || sl[0] < '1' || sl[0] > '9' {
		return nil, reject(ReasonEnvelopeFormat, "sec_len must be decimal, no sign, no leading zero, not 0, at most 7 digits")
	}
	for i := 0; i < len(sl); i++ {
		if sl[i] < '0' || sl[i] > '9' {
			return nil, reject(ReasonEnvelopeFormat, "sec_len must be decimal digits")
		}
	}
	n, _ := strconv.Atoi(sl)
	if n > len(rest) {
		return nil, reject(ReasonEnvelopeFormat, "sec_len %d exceeds the %d bytes after the header", n, len(rest))
	}
	e.Sec = rest[:n]
	e.Body = rest[n:]
	return e, nil
}

func trunc(b []byte) string {
	if len(b) > 40 {
		b = b[:40]
	}
	return string(b)
}
