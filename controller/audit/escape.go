package audit

import (
	"bytes"
	"unicode/utf8"
)

// bs is a backslash. The escapes below are built from it so no source line holds a literal
// unicode escape sequence.
const bs = "\\"

// appendString appends s as a JSON string (with quotes) in the canonical form of the RBAC/audit
// plan decision 5, which is Go's encoding/json (v1 semantics) with SetEscapeHTML(false): the
// characters < > & and all non-ASCII stay raw, line and paragraph separator (U+2028, U+2029) are
// escaped, each invalid UTF-8 byte becomes the ASCII escape for U+FFFD, control characters are
// escaped as bs+u00xx (lower-case hex) or the short forms, and 0x7f stays raw.
//
// It is hand-written because the toolchain's encoding/json may write U+FFFD raw for an invalid
// byte (its v2 semantics), which would differ from the C++ writer (audit_escape_json).
func appendString(b *bytes.Buffer, s string) {
	const hexd = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\':
				b.WriteString(bs)
				b.WriteByte(c)
			case c == '\n':
				b.WriteString(bs + "n")
			case c == '\r':
				b.WriteString(bs + "r")
			case c == '\t':
				b.WriteString(bs + "t")
			case c == '\b':
				b.WriteString(bs + "b")
			case c == '\f':
				b.WriteString(bs + "f")
			case c < 0x20:
				b.WriteString(bs + "u00")
				b.WriteByte(hexd[c>>4])
				b.WriteByte(hexd[c&0xF])
			default:
				b.WriteByte(c)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			b.WriteString(bs + "ufffd")
		case r == 0x2028:
			b.WriteString(bs + "u2028")
		case r == 0x2029:
			b.WriteString(bs + "u2029")
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	b.WriteByte('"')
}
