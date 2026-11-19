package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"miracache/controller/audit"
	"miracache/controller/store"
)

// The bootstrap seeds once, is audited, and is ignored (and not audited) when bindings exist.
func TestBootstrapRBAC(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	dir := t.TempDir()
	aw, err := audit.Open(audit.Config{Dir: dir, Src: audit.Source{Controller: true, Host: "h", Addr: "a"}})
	if err != nil {
		t.Fatal(err)
	}
	defer aw.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := bootstrapRBAC(st, aw, "spiffe://boss", log); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapRBAC(st, aw, "spiffe://mallory", log); err != nil {
		t.Fatal(err)
	}
	s, _ := st.Load()
	if len(s.RBAC) != 1 || s.RBAC[0].Identity != "spiffe://boss" {
		t.Fatalf("bindings %+v", s.RBAC)
	}
	files, _ := audit.ListFiles(dir)
	b, _ := os.ReadFile(files[0])
	if n := strings.Count(string(b), `"action":"rbac.bootstrap"`); n != 1 {
		t.Fatalf("bootstrap audited %d times:\n%s", n, b)
	}
	if err := bootstrapRBAC(st, aw, "boss", log); err == nil {
		t.Error("a non-spiffe identity was accepted")
	}
	if err := bootstrapRBAC(st, nil, "spiffe://x", log); err == nil {
		t.Error("bootstrap without an audit log")
	}
}
