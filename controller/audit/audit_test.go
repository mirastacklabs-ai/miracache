package audit

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var writeSample = flag.Bool("write-sample", false, "regenerate proto/golden/audit_v1/go_sample.jsonl")

const goldenDir = "../../proto/golden/audit_v1"

func u64(v uint64) *uint64 { return &v }

// fixedClock returns 2026-01-01T00:00:00.373Z, then +250 ms per call (the C++ golden generator's clock).
func fixedClock() func() time.Time {
	t := time.Date(2026, 1, 1, 0, 0, 0, 373e6, time.UTC)
	return func() time.Time { r := t; t = t.Add(250 * time.Millisecond); return r }
}

func readGolden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(goldenDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeEntries writes entries with the Go writer into a fresh dir and returns the file bytes.
func writeEntries(t *testing.T, src Source, es []Entry) []byte {
	t.Helper()
	dir := t.TempDir()
	w, err := Open(Config{Dir: dir, Src: src, Now: fixedClock()})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		if err := w.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	return mustRead(t, filepath.Join(dir, "audit-1.jsonl"))
}

// The Go writer reproduces the C++ goldens byte for byte (same hashes).
func TestGoWriterReproducesCppGoldens(t *testing.T) {
	basic := []Entry{
		{Actor: "spiffe://lab/ops/alice", Role: "operator", Action: "bundle.apply", Target: "node:3", Result: "ok",
			Reason: "accepted", Count: 1, Generation: u64(42), Detail: []Field{{"changed", "config,nodes"}, {"nodes", uint64(3)}}},
		{Actor: "spiffe://lab/ops/alice", Role: "viewer", Action: "admin.call", Target: "POST /v1/drain", Result: "denied",
			Reason: "role <operator> & \"admin\" required \\ path\tTab \x01 é 日本   end", Count: 17},
		{Actor: "local", Action: "bundle.apply", Target: "node:3", Result: "error", Reason: "generation_lower", Generation: u64(41)},
		{Actor: "spiffe://lab/ops/alice", Role: "operator", Action: "drop_principal", Target: "node:3", Result: "ok",
			Detail: []Field{{"name", "p<1>"}, {"drop_before", uint64(1767225600)}}},
	}
	got := writeEntries(t, Source{NodeID: 7, Host: "hostA", Addr: "10.0.0.10:7471"}, basic)
	if want := readGolden(t, "basic.jsonl"); !bytes.Equal(got, want) {
		t.Fatalf("basic.jsonl differs:\n got %s\nwant %s", got, want)
	}
	ctl := []Entry{
		{Actor: "spiffe://lab/ops/alice", Role: "operator", Action: "bundle.publish", Target: "node:3", Result: "ok",
			Reason: "rollout", Generation: u64(7), Detail: []Field{{"keys", "membership.nodes"}, {"node_ids", "1,2,3"}}},
		{Actor: "local", Role: "operator", Action: "member.remove", Target: "node:9", Result: "ok", Reason: "fail_timeout"},
	}
	got = writeEntries(t, Source{Controller: true, Host: "ctl-1.example", Addr: "10.0.0.2:9470"}, ctl)
	if want := readGolden(t, "controller.jsonl"); !bytes.Equal(got, want) {
		t.Fatalf("controller.jsonl differs:\n got %s\nwant %s", got, want)
	}
}

// Every C++ golden (single files, and directories as one chain) verifies with the Go verifier.
func TestGoVerifierAcceptsEveryGolden(t *testing.T) {
	chains := 0
	var walk func(dir string)
	walk = func(dir string) {
		set, err := ListFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		isSet := map[string]bool{}
		if len(set) > 0 {
			if r := VerifyPaths(set, nil); !r.OK {
				t.Errorf("%s: %s", dir, r.Text())
			}
			chains++
			for _, p := range set {
				isSet[p] = true
			}
		}
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			p := filepath.Join(dir, e.Name())
			switch {
			case e.IsDir():
				walk(p)
			case strings.HasSuffix(e.Name(), ".jsonl") && !isSet[p]:
				if r := VerifyPaths([]string{p}, nil); !r.OK {
					t.Errorf("%s: %s", p, r.Text())
				}
				chains++
			}
		}
	}
	walk(goldenDir)
	if chains < 6 {
		t.Fatalf("only %d chains found", chains)
	}
}

func sampleEntries() []Entry {
	return []Entry{
		{Actor: "spiffe://lab/ops/alice", Role: "operator", Action: "bundle.publish", Target: "cluster", Result: "ok",
			Reason: "join 10.0.0.4:7471", Generation: u64(12), Detail: []Field{{"keys", "membership.nodes,config.engine"}, {"node_ids", "1,2,3,4"}, {"epoch", uint64(5)}}},
		{Actor: "spiffe://lab/ops/alice", Role: "operator", Action: "config.set", Target: "config", Result: "error",
			Reason: "dry run rejected: <schema> & \"quotes\" \\ back\tslash\nnewline \x01 \x7f é 日本     bad:\xff\xfe end"},
		{Actor: "spiffe://lab/ops/bob", Role: "viewer", Action: "api.call", Target: "POST /v1/rollback", Result: "denied",
			Reason: "role_required operator", Count: 41},
		{Actor: "spiffe://lab/ops/alice", Role: "operator", Action: "config.rollback", Target: "generation:9", Result: "ok",
			Reason: "config only", Generation: u64(13), Detail: []Field{{"from_generation", uint64(9)}, {"keys", "config.engine"}}},
		{Actor: "local", Role: "operator", Action: "member.remove", Target: "node:9", Result: "ok", Reason: "fail_timeout", Generation: u64(14)},
		{Actor: "spiffe://lab/security/carol", Role: "security-admin", Action: "principals.set", Target: "sec", Result: "denied", Reason: "sec routes deny by default until RB3"},
	}
}

func TestNegativeDetailIntPanics(t *testing.T) {
	src := Source{Controller: true, Host: "h", Addr: "a"}
	if got := Body(src, 1, 0, Entry{Detail: []Field{{"n", 7}}}, "p"); !bytes.Contains(got, []byte(`"n":7`)) {
		t.Fatalf("non-negative int not written: %s", got)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("negative int in a detail field did not panic")
		}
	}()
	Body(src, 1, 0, Entry{Detail: []Field{{"n", -1}}}, "p")
}

func TestGoSampleFile(t *testing.T) {
	got := writeEntries(t, Source{Controller: true, Host: "ctl-1.example", Addr: "10.0.0.2:9470"}, sampleEntries())
	path := filepath.Join(goldenDir, "go_sample.jsonl")
	if *writeSample {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want := mustRead(t, path)
	if !bytes.Equal(got, want) {
		t.Fatalf("go_sample.jsonl is stale; regenerate with: go test ./audit -args -write-sample")
	}
	if r := VerifyPaths([]string{path}, nil); !r.OK {
		t.Fatal(r.Text())
	}
	s := string(got)
	bs := "\\"
	for _, must := range []string{`<schema> & \"quotes\"`, bs + "u2028 " + bs + "u2029", bs + "ufffd" + bs + "ufffd", bs + "u0001", "\x7f", "é 日本", `\n`} {
		if !strings.Contains(s, must) {
			t.Errorf("sample lacks %q", must)
		}
	}
}

func TestVerifierRejects(t *testing.T) {
	good := writeEntries(t, Source{Controller: true, Host: "h", Addr: "a"}, sampleEntries())
	lines := bytes.SplitAfter(good, []byte("\n"))
	cases := map[string][]byte{
		"flip a byte":    bytes.Replace(good, []byte("fail_timeout"), []byte("fail_timeouT"), 1),
		"drop line 2":    append(append([]byte(nil), lines[0]...), bytes.Join(lines[2:], nil)...),
		"partial tail":   good[:len(good)-10],
		"empty":          nil,
		"no trailing nl": bytes.TrimSuffix(good, []byte("\n")),
		"swap two lines": bytes.Join([][]byte{lines[1], lines[0], bytes.Join(lines[2:], nil)}, nil),
	}
	for name, b := range cases {
		if r := Verify([]FileBytes{{"audit-1.jsonl", b}}, nil); r.OK {
			t.Errorf("%s: accepted", name)
		}
	}
	r := Verify([]FileBytes{{"audit-1.jsonl", good}}, nil)
	if !r.OK || r.Entries != 6 {
		t.Fatal(r.Text())
	}
	if x := Verify([]FileBytes{{"audit-1.jsonl", good}}, &Anchor{3, strings.Repeat("0", 64)}); x.OK {
		t.Error("wrong anchor hash accepted")
	}
	if x := Verify([]FileBytes{{"audit-1.jsonl", good}}, &Anchor{99, r.Head}); x.OK {
		t.Error("anchor past the end accepted")
	}
	if x := Verify([]FileBytes{{"audit-1.jsonl", good}}, &Anchor{6, r.Head}); !x.OK {
		t.Error(x.Text())
	}
}

func TestRotationTruncateAndRecover(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Dir: dir, Src: Source{Controller: true, Host: "h", Addr: "a"}, MaxBytes: 1200, MaxTotalBytes: 6000, Now: fixedClock()}
	w, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(cfg); err != ErrBusy {
		t.Fatalf("second writer: %v", err)
	}
	for i := 0; i < 60; i++ {
		if err := w.Append(Entry{Actor: "local", Action: "x", Target: "t", Result: "ok", Reason: strings.Repeat("r", 100), Generation: u64(uint64(i))}); err != nil {
			t.Fatal(err)
		}
	}
	files, _ := ListFiles(dir)
	if len(files) < 2 {
		t.Fatalf("no rotation: %v", files)
	}
	r := VerifyPaths(files, nil)
	if !r.OK {
		t.Fatal(r.Text())
	}
	if r.FirstSeq == 1 {
		t.Fatalf("total cap never deleted a file (first seq %d)", r.FirstSeq)
	}
	if w.Seq() != r.LastSeq || w.Head() != r.Head {
		t.Fatal("writer state differs from the verified chain")
	}
	w.Close()

	// A partial tail is dropped and an audit.recover entry chains from the last whole entry.
	newest := files[len(files)-1]
	f, _ := os.OpenFile(newest, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"v":1,"seq":99,"ts":"partial`)
	f.Close()
	seqBefore := r.LastSeq
	w, err = Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if w.RecoveredBytes() == 0 || w.Seq() != seqBefore+1 {
		t.Fatalf("recovered=%d seq=%d want %d", w.RecoveredBytes(), w.Seq(), seqBefore+1)
	}
	files, _ = ListFiles(dir)
	if r := VerifyPaths(files, nil); !r.OK || !strings.Contains(string(mustRead(t, files[len(files)-1])), `"action":"audit.recover"`) {
		t.Fatal(r.Text())
	}
	if err := w.Append(Entry{Actor: "local", Action: "y", Target: "t", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Entry{Actor: "local", Action: "y", Target: "t", Result: "ok", Reason: strings.Repeat("z", MaxLineBytes)}); err != ErrTooLarge {
		t.Fatalf("oversize: %v", err)
	}
}

// The escape table mirrored from the C++ audit tests.
func TestEscapeTable(t *testing.T) {
	esc := func(s string) string { var b bytes.Buffer; appendString(&b, s); return b.String() }
	cases := []struct{ in, want string }{
		{"a<b>&c", `"a<b>&c"`},
		{"\x7f", "\"\x7f\""},
		{"\x01\x1f", `"` + bs + "u0001" + bs + "u001f" + `"`},
		{"\n\r\t\b\f", `"` + bs + "n" + bs + "r" + bs + "t" + bs + "b" + bs + "f" + `"`},
		{"\xff", `"` + bs + `ufffd"`},
		{"\xc3", `"` + bs + `ufffd"`},
		{"\xed\xa0\x80", `"` + bs + "ufffd" + bs + "ufffd" + bs + `ufffd"`},
		{"\xc0\x80", `"` + bs + "ufffd" + bs + `ufffd"`},
		{string([]rune{0x2028, 0x2029}), `"` + bs + "u2028" + bs + `u2029"`},
		{"é日", `"é日"`},
		{"q\"b\\", `"q` + bs + `"b` + bs + bs + `"`},
	}
	for _, c := range cases {
		if got := esc(c.in); got != c.want {
			t.Errorf("esc(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}
