package rbac

import (
	"errors"
	"testing"

	"miracache/controller/bundle"
	"miracache/controller/store"
)

func TestGrants(t *testing.T) {
	needs := []Need{NeedAuthenticated, NeedPrincipal, NeedViewer, NeedOperator, NeedSecAdmin}
	// want[role] = needs granted (same table as server/runtime/rbac.cpp).
	want := map[string][]Need{
		Viewer:        {NeedAuthenticated, NeedPrincipal, NeedViewer},
		Operator:      {NeedAuthenticated, NeedPrincipal, NeedViewer, NeedOperator},
		SecurityAdmin: {NeedAuthenticated, NeedPrincipal, NeedViewer, NeedSecAdmin},
		ScopeProvider: {NeedAuthenticated, NeedPrincipal},
		"bogus":       {NeedAuthenticated, NeedPrincipal},
	}
	for role, ok := range want {
		for _, n := range needs {
			exp := false
			for _, o := range ok {
				exp = exp || o == n
			}
			if got := Grants(role, n); got != exp {
				t.Errorf("Grants(%q,%q)=%v want %v", role, n, got, exp)
			}
		}
	}
	if Known("bogus") || !Known(ScopeProvider) {
		t.Error("Known")
	}
}

func TestCheckTransition(t *testing.T) {
	admin := []bundle.RBAC{{Identity: "spiffe://a", Roles: []string{SecurityAdmin}}}
	both := append([]bundle.RBAC{{Identity: "spiffe://b", Roles: []string{Operator}}}, admin...)
	if err := CheckTransition(nil, nil); err != nil {
		t.Errorf("lab cluster without rbac: %v", err)
	}
	if err := CheckTransition(admin, nil); !errors.Is(err, ErrLastSecurityAdmin) {
		t.Errorf("clearing rbac: %v", err)
	}
	if err := CheckTransition(admin, Set(admin, "spiffe://a", []string{Operator})); !errors.Is(err, ErrLastSecurityAdmin) {
		t.Errorf("demoting the only admin: %v", err)
	}
	if err := CheckTransition(nil, []bundle.RBAC{{Identity: "spiffe://b", Roles: []string{Operator}}}); !errors.Is(err, ErrLastSecurityAdmin) {
		t.Errorf("first table without admin: %v", err)
	}
	if err := CheckTransition(both, admin); err != nil {
		t.Errorf("removing a non-admin: %v", err)
	}
	if err := CheckTransition(admin, Set(admin, "spiffe://b", []string{"root"})); err == nil {
		t.Error("unknown role accepted")
	}
}

func TestSetSortsAndDedups(t *testing.T) {
	b := Set(nil, "spiffe://z", []string{Viewer, Operator, Viewer})
	b = Set(b, "spiffe://a", []string{Viewer})
	if len(b) != 2 || b[0].Identity != "spiffe://a" || len(b[1].Roles) != 2 || b[1].Roles[0] != Operator {
		t.Fatalf("%+v", b)
	}
	if b = Set(b, "spiffe://a", nil); len(b) != 1 {
		t.Fatalf("remove: %+v", b)
	}
}

func TestBootstrapOnlyOnEmptyStore(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if seeded, err := Bootstrap(st, nil); seeded || err != nil {
		t.Fatalf("empty list: %v %v", seeded, err)
	}
	seeded, err := Bootstrap(st, []string{"spiffe://boss"})
	if !seeded || err != nil {
		t.Fatalf("first: %v %v", seeded, err)
	}
	s, _ := st.Load()
	if !HasSecurityAdmin(s.RBAC) || !Allowed(s.RBAC, "spiffe://boss", NeedOperator) {
		t.Fatalf("bindings %+v", s.RBAC)
	}
	// A different list is ignored once bindings exist.
	if seeded, err := Bootstrap(st, []string{"spiffe://mallory"}); seeded || err != nil {
		t.Fatalf("second: %v %v", seeded, err)
	}
	s, _ = st.Load()
	if len(s.RBAC) != 1 || s.RBAC[0].Identity != "spiffe://boss" {
		t.Fatalf("bootstrap changed existing bindings: %+v", s.RBAC)
	}
}
