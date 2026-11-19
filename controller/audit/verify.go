package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// FileBytes is one file of a chain.
type FileBytes struct {
	Name  string
	Bytes []byte
}

// Anchor is a (seq, head) recorded earlier (e.g. from /v1/identity audit_seq / audit_head).
type Anchor struct {
	Seq  uint64
	Head string
}

// Result is the outcome of Verify.
type Result struct {
	OK      bool
	Entries uint64
	File    string
	Line    uint64 // 1-based
	Seq     uint64
	Message string
	// The verified range: first and last seq read and the hash of the last entry.
	FirstSeq, LastSeq uint64
	Head              string
}

// Text is `OK <n> entries` or `FAIL <file>:<line> seq=<seq>: <message>`.
func (r Result) Text() string {
	if r.OK {
		return fmt.Sprintf("OK %d entries", r.Entries)
	}
	return fmt.Sprintf("FAIL %s:%d seq=%d: %s", r.File, r.Line, r.Seq, r.Message)
}

type checked struct {
	seq          uint64
	prev, hash   string
	action       string
	firstKeptSeq uint64
	hasKept      bool
}

func parseU64(raw []byte) (uint64, bool) {
	s := string(raw)
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

func isHash64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

type member struct {
	key string
	raw []byte
}

// members splits a JSON object into its ordered (key, raw value) pairs; the whole input must be
// that one object.
func members(b []byte) ([]member, bool) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, false
	}
	var out []member
	for dec.More() {
		t, err := dec.Token()
		k, ok := t.(string)
		if err != nil || !ok {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		out = append(out, member{k, raw})
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return nil, false
	}
	if _, err := dec.Token(); err == nil {
		return nil, false // trailing data
	}
	return out, true
}

func isStr(r []byte) bool { return len(r) >= 2 && r[0] == '"' && r[len(r)-1] == '"' }

// checkLine validates one stored line (no newline). It returns "" on success. It never
// re-serialises: it hashes the bytes it reads.
func checkLine(line []byte) (checked, string) {
	var out checked
	if len(line) < HashSuffixBytes+2 {
		return out, "line too short"
	}
	suffix := line[len(line)-HashSuffixBytes:]
	if string(suffix[:9]) != `,"hash":"` || string(suffix[73:]) != `"}` || !isHash64(string(suffix[9:73])) {
		return out, "bad hash suffix"
	}
	hash := string(suffix[9:73])
	body := append(append([]byte(nil), line[:len(line)-HashSuffixBytes]...), '}')
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != hash {
		return out, "hash mismatch"
	}
	out.hash = hash
	m, ok := members(body)
	if !ok {
		return out, "malformed JSON"
	}
	head := []string{"v", "seq", "ts", "src", "actor", "role", "action", "target", "result", "reason", "count"}
	k := 0
	for _, want := range head {
		if k >= len(m) || m[k].key != want {
			return out, "field order: expected " + want
		}
		k++
	}
	if k < len(m) && m[k].key == "generation" {
		k++
	}
	if k+2 != len(m) || m[k].key != "detail" || m[k+1].key != "prev" {
		return out, "field order: expected detail, prev"
	}
	if v, ok := parseU64(m[0].raw); !ok || v != 1 {
		return out, "unsupported version"
	}
	if v, ok := parseU64(m[1].raw); !ok || v == 0 {
		return out, "bad seq"
	} else {
		out.seq = v
	}
	if v, ok := parseU64(m[10].raw); !ok || v == 0 {
		return out, "bad count"
	}
	for _, i := range []int{2, 4, 5, 6, 7, 8, 9} {
		if !isStr(m[i].raw) {
			return out, "field " + m[i].key + " is not a string"
		}
	}
	sm, ok := members(m[3].raw)
	if !ok {
		return out, "src is not an object"
	}
	srcOK := false
	switch {
	case len(sm) == 3 && sm[0].key == "node_id" && sm[1].key == "host" && sm[2].key == "addr":
		_, n := parseU64(sm[0].raw)
		srcOK = n && isStr(sm[1].raw) && isStr(sm[2].raw)
	case len(sm) == 2 && sm[0].key == "controller" && sm[1].key == "addr":
		srcOK = isStr(sm[0].raw) && isStr(sm[1].raw)
	}
	if !srcOK {
		return out, "bad src"
	}
	if m[k-1].key == "generation" {
		if _, ok := parseU64(m[k-1].raw); !ok {
			return out, "bad generation"
		}
	}
	if len(m[k].raw) == 0 || m[k].raw[0] != '{' {
		return out, "detail is not an object"
	}
	prev := m[len(m)-1].raw
	if len(prev) != 66 || prev[0] != '"' || prev[65] != '"' || !isHash64(string(prev[1:65])) {
		return out, "bad prev"
	}
	out.prev = string(prev[1:65])
	// The action is compared raw (escapes not decoded); the audit.* names contain none.
	out.action = string(m[6].raw[1 : len(m[6].raw)-1])
	if out.action == "audit.truncate" {
		dm, ok := members(m[k].raw)
		if !ok {
			return out, "bad detail"
		}
		for _, d := range dm {
			if d.key == "first_kept_seq" {
				v, ok := parseU64(d.raw)
				if !ok || v == 0 {
					return out, "bad first_kept_seq"
				}
				out.firstKeptSeq, out.hasKept = v, true
			}
		}
		if !out.hasKept {
			return out, "audit.truncate without first_kept_seq"
		}
	}
	return out, ""
}

// Verify checks the bytes of one or more files in chain order: v, field order, hash, seq
// continuity, prev links across files, and that every file after the first begins with
// audit.rotate. audit.truncate's first_kept_seq must name the first seq of a given file (or lie
// before the first given file). The first entry of the first file anchors the chain. A partial
// last line is a failure. With an anchor, the chain must contain that seq with exactly that hash.
func Verify(files []FileBytes, anchor *Anchor) Result {
	var r Result
	fail := func(file string, line, seq uint64, msg string) Result {
		r.OK, r.File, r.Line, r.Seq, r.Message = false, file, line, seq, msg
		return r
	}
	if len(files) == 0 {
		return fail("", 0, 0, "no files")
	}
	type trunc struct {
		file      int
		line, seq uint64
		kept      uint64
	}
	var truncs []trunc
	var firstSeqs []uint64
	var lastHash string
	var lastSeq uint64
	haveLast := false
	for fi, f := range files {
		b := f.Bytes
		if len(b) == 0 {
			return fail(f.Name, 0, 0, "file has no entries")
		}
		if b[len(b)-1] != '\n' {
			return fail(f.Name, 0, 0, "partial last line (no trailing newline)")
		}
		var lineno uint64
		firstInFile := true
		for pos := 0; pos < len(b); {
			nl := bytes.IndexByte(b[pos:], '\n') + pos
			line := b[pos:nl]
			pos = nl + 1
			lineno++
			if len(line) > MaxLineBytes {
				return fail(f.Name, lineno, 0, "line too long")
			}
			ck, msg := checkLine(line)
			if msg != "" {
				return fail(f.Name, lineno, ck.seq, msg)
			}
			if haveLast {
				if ck.seq != lastSeq+1 {
					return fail(f.Name, lineno, ck.seq, fmt.Sprintf("seq gap (expected %d)", lastSeq+1))
				}
				if ck.prev != lastHash {
					return fail(f.Name, lineno, ck.seq, "prev does not match the previous entry")
				}
				if firstInFile && ck.action != "audit.rotate" {
					return fail(f.Name, lineno, ck.seq, "file does not begin with audit.rotate")
				}
			} else if ck.seq == 1 && ck.prev != GenesisPrev {
				return fail(f.Name, lineno, ck.seq, "seq 1 must chain from the genesis prev")
			}
			if firstInFile {
				firstSeqs = append(firstSeqs, ck.seq)
				if named, ok := parseName(filepath.Base(f.Name)); ok && named != ck.seq {
					return fail(f.Name, lineno, ck.seq, "file name does not match its first seq")
				}
			}
			if ck.hasKept {
				truncs = append(truncs, trunc{fi, lineno, ck.seq, ck.firstKeptSeq})
			}
			firstInFile, haveLast = false, true
			lastSeq, lastHash = ck.seq, ck.hash
			if r.Entries == 0 {
				r.FirstSeq = ck.seq
			}
			r.LastSeq, r.Head = ck.seq, ck.hash
			if anchor != nil && ck.seq == anchor.Seq && ck.hash != anchor.Head {
				return fail(f.Name, lineno, ck.seq, "hash differs from the anchor (log rewritten)")
			}
			r.Entries++
		}
	}
	for _, t := range truncs {
		isStart := false
		for _, s := range firstSeqs {
			if s == t.kept {
				isStart = true
			}
		}
		if t.kept > t.seq || !(isStart || t.kept < firstSeqs[0]) {
			return fail(files[t.file].Name, t.line, t.seq, "audit.truncate first_kept_seq names no file")
		}
	}
	if anchor != nil {
		if anchor.Seq < r.FirstSeq {
			return fail(files[0].Name, 0, anchor.Seq, "anchor seq precedes the first kept entry (oldest files deleted)")
		}
		if anchor.Seq > r.LastSeq {
			return fail(files[len(files)-1].Name, 0, r.LastSeq, "log ends before the anchor seq (tail truncated)")
		}
	}
	r.OK = true
	return r
}

// VerifyPaths is Verify reading the files from disk.
func VerifyPaths(paths []string, anchor *Anchor) Result {
	fs := make([]FileBytes, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return Result{File: p, Message: "cannot read: " + err.Error()}
		}
		fs = append(fs, FileBytes{p, b})
	}
	return Verify(fs, anchor)
}
