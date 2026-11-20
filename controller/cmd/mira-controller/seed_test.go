package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const goodSeed = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"

// The controller refuses a seed that group or others can read, like mirctl does.
func TestReadSeedModeCheck(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(goodSeed), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := readSeed(write("ok.seed", 0o600)); err != nil {
		t.Fatalf("0600 seed refused: %v", err)
	}
	if _, err := readSeed(write("ro.seed", 0o400)); err != nil {
		t.Fatalf("0400 seed refused: %v", err)
	}
	for _, m := range []os.FileMode{0o640, 0o604, 0o644, 0o660} {
		_, err := readSeed(write("bad.seed", m))
		if err == nil || !strings.Contains(err.Error(), "must not be accessible by group or others") {
			t.Errorf("mode %04o accepted or wrong error: %v", m, err)
		}
	}
	if _, err := readSeed(filepath.Join(dir, "missing.seed")); err == nil {
		t.Error("missing seed accepted")
	}
	bad := filepath.Join(dir, "short.seed")
	if err := os.WriteFile(bad, []byte("abcd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSeed(bad); err == nil {
		t.Error("short seed accepted")
	}
}
