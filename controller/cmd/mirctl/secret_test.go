package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixtures = "../../../proto/golden/"

func secretApp(start byte) (*app, *bytes.Buffer, *bytes.Buffer) {
	out, errw := &bytes.Buffer{}, &bytes.Buffer{}
	return &app{out: out, err: errw, now: time.Now, rand: &seqReader{next: start}}, out, errw
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The loader rules accept the shared golden: current=2, kvers {1,2,7} (hex case-insensitive).
func TestParseSecretGolden(t *testing.T) {
	f, err := parseSecretFile(readFile(t, fixtures+"secret_golden.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if f.current != 2 || len(f.keys) != 3 {
		t.Fatalf("current=%d keys=%d", f.current, len(f.keys))
	}
	for _, k := range []uint32{1, 2, 7} {
		if _, ok := f.keys[k]; !ok {
			t.Errorf("kver %d missing", k)
		}
	}
	if f.keys[2] != strings.ToLower(f.keys[2]) {
		t.Error("hex not normalised")
	}
}

// The loader's refusals (engine_native.cpp / preflight/secret.py rule for rule).
func TestParseSecretRejects(t *testing.T) {
	h := strings.Repeat("ab", 32)
	for name, text := range map[string]string{
		"no current":     "1 = " + h + "\n",
		"current absent": "current = 2\n1 = " + h + "\n",
		"dup current":    "current = 1\ncurrent = 1\n1 = " + h + "\n",
		"zero kver":      "current = 1\n0 = " + h + "\n1 = " + h + "\n",
		"dup kver":       "current = 1\n1 = " + h + "\n1 = " + h + "\n",
		"short hex":      "current = 1\n1 = abcd\n",
		"non-hex":        "current = 1\n1 = " + strings.Repeat("zz", 32) + "\n",
		"no equals":      "current = 1\n1 " + h + "\n",
		"signed kver":    "current = 1\n+1 = " + h + "\n",
		"u32 overflow":   "current = 1\n1 = " + h + "\n4294967296 = " + h + "\n",
		"inline comment": "current = 1 # x\n1 = " + h + "\n",
	} {
		if _, err := parseSecretFile(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSecretGenGolden(t *testing.T) {
	a, out, errw := secretApp(0)
	p := filepath.Join(t.TempDir(), "secret.txt")
	if code := a.run([]string{"secret", "gen", "--out", p}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got, want := readFile(t, p), readFile(t, fixtures+"secret_gen_golden.txt"); got != want {
		t.Fatalf("secret gen output differs from the golden:\n%s\nwant:\n%s", got, want)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", st.Mode().Perm())
	}
	if strings.Contains(out.String()+errw.String(), "0001020304") {
		t.Fatal("a key was printed")
	}
	if _, err := parseSecretFile(readFile(t, p)); err != nil {
		t.Fatal(err)
	}
	// No clobber, and no tmp files left behind.
	if code := a.run([]string{"secret", "gen", "--out", p}); code != 1 {
		t.Fatalf("overwrite exit %d", code)
	}
	if got := readFile(t, p); got != readFile(t, fixtures+"secret_gen_golden.txt") {
		t.Fatal("existing file was changed")
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 1 {
		t.Fatalf("leftover files: %v", ents)
	}
}

func TestSecretAddKverGolden(t *testing.T) {
	a, out, errw := secretApp(0x40)
	p := filepath.Join(t.TempDir(), "secret.txt")
	// The output keeps the input's comment lines, so the input takes the first two comment lines of the
	// golden (the stale "Expect:" text of secret_golden.txt, U2-33, stays out of the golden).
	gl := strings.SplitN(readFile(t, fixtures+"secret_add_kver_golden.txt"), "\n", 3)
	sl := strings.SplitN(readFile(t, fixtures+"secret_golden.txt"), "\n", 3)
	if err := os.WriteFile(p, []byte(gl[0]+"\n"+gl[1]+"\n"+sl[2]), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := a.run([]string{"secret", "add-kver", "--file", p}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if got, want := readFile(t, p), readFile(t, fixtures+"secret_add_kver_golden.txt"); got != want {
		t.Fatalf("add-kver output differs from the golden:\n%s\nwant:\n%s", got, want)
	}
	st, _ := os.Stat(p)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %04o", st.Mode().Perm())
	}
	if strings.Contains(out.String()+errw.String(), "4041424344") {
		t.Fatal("a key was printed")
	}
	f, err := parseSecretFile(readFile(t, p))
	if err != nil || f.current != 8 || len(f.keys) != 4 {
		t.Fatalf("result: %+v %v", f, err)
	}
	ents, _ := os.ReadDir(filepath.Dir(p))
	if len(ents) != 2 { // the secret and its flock sidecar
		t.Fatalf("leftover tmp files: %v", ents)
	}
	// Explicit kver, kept current; a duplicate kver and a bad mode are refused.
	if code := a.run([]string{"secret", "add-kver", "--file", p, "--kver", "20", "--keep-current"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	f, _ = parseSecretFile(readFile(t, p))
	if f.current != 8 || len(f.keys) != 5 {
		t.Fatalf("keep-current: %+v", f)
	}
	if code := a.run([]string{"secret", "add-kver", "--file", p, "--kver", "20"}); code != 1 {
		t.Fatal("duplicate kver accepted")
	}
	os.Chmod(p, 0o644)
	if code := a.run([]string{"secret", "add-kver", "--file", p}); code != 1 {
		t.Fatal("mode 0644 accepted")
	}
}

// U2-32: concurrent add-kver runs on one file lose no key.
func TestSecretAddKverConcurrentRunsKeepEveryKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(p, []byte(readFile(t, fixtures+"secret_golden.txt")), 0o600); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, _, _ := secretApp(byte(0x10 * (i + 1)))
			if code := a.run([]string{"secret", "add-kver", "--file", p}); code != 0 {
				t.Errorf("add-kver %d: exit %d", i, code)
			}
		}()
	}
	wg.Wait()
	f, err := parseSecretFile(readFile(t, p))
	if err != nil || len(f.keys) != 3+n {
		t.Fatalf("keys = %d (want %d): %v", len(f.keys), 3+n, err)
	}
}
