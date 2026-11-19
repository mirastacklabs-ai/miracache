package store

import (
	"errors"
	"testing"
)

func TestSecondInstanceRefused(t *testing.T) {
	dir := t.TempDir()
	a, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open: got %v, want ErrLocked", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	b.Close()
}

func TestCommitCASAndPersistence(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st, err := s.Load()
	if err != nil || st.Generation != 0 {
		t.Fatalf("empty load: %v %+v", err, st)
	}
	next := State{Generation: 5, SecGeneration: 2, Nodes: []DesiredNode{{Admin: "10.0.0.1:9465", Weight: 1, State: "active"}}, LastEnvelope: []byte("x")}
	if err := s.Commit(0, next); err != nil {
		t.Fatal(err)
	}
	// A stale writer (expects 0, the store is at 5) loses the CAS.
	if err := s.Commit(0, State{Generation: 6}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale commit: got %v, want ErrConflict", err)
	}
	// A generation below the expected one is refused too.
	if err := s.Commit(5, State{Generation: 4}); !errors.Is(err, ErrConflict) {
		t.Fatalf("backwards commit: got %v, want ErrConflict", err)
	}
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got, err := s2.Load()
	if err != nil || got.Generation != 5 || got.SecGeneration != 2 || len(got.Nodes) != 1 || string(got.LastEnvelope) != "x" {
		t.Fatalf("reload: %v %+v", err, got)
	}
}

func TestHistoryTrimmed(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var h [][]byte
	for i := 0; i < HistoryLen+5; i++ {
		h = append(h, []byte{byte(i)})
	}
	if err := s.Commit(0, State{Generation: 1, History: h}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Load()
	if len(got.History) != HistoryLen || got.History[0][0] != 5 {
		t.Fatalf("history len %d first %v", len(got.History), got.History[0])
	}
}
