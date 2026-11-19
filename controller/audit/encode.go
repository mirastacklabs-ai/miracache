// Package audit is the Go side of the hash-chained audit log `mira-audit-v1` (RBAC/audit plan
// decision 5; C++ twin: core/control/audit.{h,cpp}). The writer produces files byte-identical to
// the C++ writer for the same entries; the verifier accepts every file the C++ writer produces.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"
)

const (
	// HashSuffixBytes is len(`,"hash":"`) + 64 hex + len(`"}`).
	HashSuffixBytes = 75
	// MaxLineBytes is the longest line (without newline); a larger entry is refused.
	MaxLineBytes = 16 * 1024
	// GenesisPrev is the prev of seq 1.
	GenesisPrev = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Source says where an entry comes from: a memory node (NodeID, Host, Addr) or the controller
// (Host is its hostname, Addr its address; goal 10).
type Source struct {
	Controller bool
	NodeID     uint64
	Host       string
	Addr       string
}

// Field is one ordered key of the detail object; Val is a string or a uint64.
type Field struct {
	Key string
	Val any
}

// Entry is one audit entry before seq, ts and the chain are added.
type Entry struct {
	Actor      string // SPIFFE ID or "local"
	Role       string
	Action     string
	Target     string
	Result     string // ok | denied | error
	Reason     string
	Count      uint64 // 0 is written as 1
	Generation *uint64
	Detail     []Field // never secrets
}

// FormatTS renders unix milliseconds as YYYY-MM-DDTHH:MM:SS.mmmZ (UTC).
func FormatTS(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

// Body serialises an entry without its hash (the bytes that are hashed), in the fixed field order.
func Body(src Source, seq uint64, tsMS int64, e Entry, prev string) []byte {
	var b bytes.Buffer
	b.WriteString(`{"v":1,"seq":`)
	b.WriteString(strconv.FormatUint(seq, 10))
	b.WriteString(`,"ts":"`)
	b.WriteString(FormatTS(tsMS))
	b.WriteString(`","src":`)
	if src.Controller {
		b.WriteString(`{"controller":`)
		appendString(&b, src.Host)
		b.WriteString(`,"addr":`)
		appendString(&b, src.Addr)
	} else {
		b.WriteString(`{"node_id":`)
		b.WriteString(strconv.FormatUint(src.NodeID, 10))
		b.WriteString(`,"host":`)
		appendString(&b, src.Host)
		b.WriteString(`,"addr":`)
		appendString(&b, src.Addr)
	}
	b.WriteString(`},"actor":`)
	appendString(&b, e.Actor)
	b.WriteString(`,"role":`)
	appendString(&b, e.Role)
	b.WriteString(`,"action":`)
	appendString(&b, e.Action)
	b.WriteString(`,"target":`)
	appendString(&b, e.Target)
	b.WriteString(`,"result":`)
	appendString(&b, e.Result)
	b.WriteString(`,"reason":`)
	appendString(&b, e.Reason)
	b.WriteString(`,"count":`)
	count := e.Count
	if count == 0 {
		count = 1
	}
	b.WriteString(strconv.FormatUint(count, 10))
	if e.Generation != nil {
		b.WriteString(`,"generation":`)
		b.WriteString(strconv.FormatUint(*e.Generation, 10))
	}
	b.WriteString(`,"detail":{`)
	for i, f := range e.Detail {
		if i > 0 {
			b.WriteByte(',')
		}
		appendString(&b, f.Key)
		b.WriteByte(':')
		switch v := f.Val.(type) {
		case string:
			appendString(&b, v)
		case uint64:
			b.WriteString(strconv.FormatUint(v, 10))
		case int:
			if v < 0 { // review w4 V13: a negative would wrap to a huge uint64 in the log
				panic("audit: detail integers must not be negative")
			}
			b.WriteString(strconv.FormatUint(uint64(v), 10))
		default:
			panic("audit: detail values are strings or unsigned integers")
		}
	}
	b.WriteString(`},"prev":"`)
	b.WriteString(prev)
	b.WriteString(`"`)
	return b.Bytes()
}

// Seal returns the stored line (without newline) and its hash: hash = SHA-256(body + "}"), and
// the line is body + `,"hash":"<hex>"}`.
func Seal(body []byte) (line []byte, hash string) {
	full := append(append([]byte(nil), body...), '}')
	sum := sha256.Sum256(full)
	hash = hex.EncodeToString(sum[:])
	line = append(append([]byte(nil), body...), `,"hash":"`+hash+`"}`...)
	return line, hash
}
