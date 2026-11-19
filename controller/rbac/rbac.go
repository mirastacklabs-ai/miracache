// Package rbac is the controller's role model (RBAC/audit plan decisions 2-4, RB3). The roles and
// what they grant equal the memory node's table (server/runtime/rbac.*): viewer, operator,
// security-admin, scope-provider. The bindings live in the signed bundle's sec section; the
// controller keeps them in its store and writes them into every new sec.
package rbac

import (
	"errors"
	"fmt"
	"sort"

	"miracache/controller/bundle"
	"miracache/controller/store"
)

// Roles.
const (
	Viewer        = "viewer"
	Operator      = "operator"
	SecurityAdmin = "security-admin"
	ScopeProvider = "scope-provider" // accepted in bindings, grants nothing in v1
)

// Need is what a route requires.
type Need string

const (
	// NeedAuthenticated: any identity with a spiffe:// URI SAN (the signatures are the gate).
	NeedAuthenticated Need = ""
	// NeedPrincipal: a principal identity; the controller treats it as authenticated (POST /v1/reports).
	NeedPrincipal Need = "principal"
	NeedViewer    Need = Viewer
	NeedOperator  Need = Operator
	NeedSecAdmin  Need = SecurityAdmin
)

// Known reports whether role is one of the four roles.
func Known(role string) bool {
	switch role {
	case Viewer, Operator, SecurityAdmin, ScopeProvider:
		return true
	}
	return false
}

// Grants reports whether role satisfies need. As on the memory node: operator and security-admin
// each also read (viewer); security-admin does not imply operator; scope-provider and unknown
// roles grant nothing.
func Grants(role string, need Need) bool {
	switch need {
	case NeedAuthenticated, NeedPrincipal:
		return true
	case NeedViewer:
		return role == Viewer || role == Operator || role == SecurityAdmin
	case NeedOperator:
		return role == Operator
	case NeedSecAdmin:
		return role == SecurityAdmin
	}
	return false
}

// RolesOf are the roles bound to identity.
func RolesOf(bindings []bundle.RBAC, identity string) []string {
	var roles []string
	for _, b := range bindings {
		if b.Identity == identity {
			roles = append(roles, b.Roles...)
		}
	}
	return roles
}

// Allowed reports whether identity holds a role that satisfies need.
func Allowed(bindings []bundle.RBAC, identity string, need Need) bool {
	if need == NeedAuthenticated || need == NeedPrincipal {
		return true
	}
	for _, r := range RolesOf(bindings, identity) {
		if Grants(r, need) {
			return true
		}
	}
	return false
}

// ErrLastSecurityAdmin: a change would leave the cluster without a security-admin (P03).
var ErrLastSecurityAdmin = errors.New("rbac: at least one security-admin must remain")

// HasSecurityAdmin reports whether some binding holds security-admin.
func HasSecurityAdmin(b []bundle.RBAC) bool {
	for _, e := range b {
		for _, r := range e.Roles {
			if r == SecurityAdmin {
				return true
			}
		}
	}
	return false
}

// CheckTransition validates the bindings a new sec would carry: known roles only, the usual sec
// rules, and at least one security-admin. An empty table is allowed only when prev had none
// either (a lab cluster that never configured RBAC).
func CheckTransition(prev, next []bundle.RBAC) error {
	for _, b := range next {
		for _, r := range b.Roles {
			if !Known(r) {
				return fmt.Errorf("rbac %q: unknown role %q (want viewer, operator, security-admin or scope-provider)", b.Identity, r)
			}
		}
	}
	if len(next) > 0 || HasSecurityAdmin(prev) {
		if !HasSecurityAdmin(next) {
			return ErrLastSecurityAdmin
		}
	}
	if len(next) > 0 {
		s := bundle.Sec{SecGeneration: 1, RBAC: next}
		if err := s.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Set returns the bindings with identity bound to roles (nil roles removes the binding), sorted by
// identity. Roles are de-duplicated and sorted.
func Set(bindings []bundle.RBAC, identity string, roles []string) []bundle.RBAC {
	out := make([]bundle.RBAC, 0, len(bindings)+1)
	for _, b := range bindings {
		if b.Identity != identity {
			out = append(out, b)
		}
	}
	if len(roles) > 0 {
		seen := map[string]bool{}
		var rs []string
		for _, r := range roles {
			if !seen[r] {
				seen[r] = true
				rs = append(rs, r)
			}
		}
		sort.Strings(rs)
		out = append(out, bundle.RBAC{Identity: identity, Roles: rs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	return out
}

// Bootstrap seeds the store's bindings from the configured identities (security-admin and
// operator, so the first administrator can also run the cluster) but only while the store has no
// bindings at all. Once any binding exists the list is ignored, whatever the flag says. It returns
// whether it seeded. The seeded bindings enter the bundle with the next publish.
func Bootstrap(st *store.Store, identities []string) (bool, error) {
	if len(identities) == 0 {
		return false, nil
	}
	cur, err := st.Load()
	if err != nil {
		return false, err
	}
	if len(cur.RBAC) > 0 {
		return false, nil
	}
	next := cur.Clone()
	for _, id := range identities {
		next.RBAC = Set(next.RBAC, id, []string{SecurityAdmin, Operator})
	}
	if err := CheckTransition(nil, next.RBAC); err != nil {
		return false, err
	}
	if err := st.Commit(cur.Generation, next); err != nil {
		return false, err
	}
	return true, nil
}
