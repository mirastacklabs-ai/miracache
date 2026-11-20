package api

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"miracache/controller/audit"
	"miracache/controller/bundle"
	"miracache/controller/publish"
	"miracache/controller/rbac"
	"miracache/controller/store"
)

// The sec-changing routes. Each one is a publish: the controller holds
// the security key online in v1, builds the new sec from the store, and a publish-only key could
// not have signed it. Every change is audited with the caller's roles.

type rbacReply struct {
	Bindings []bundle.RBAC `json:"bindings"`
}

func (s *Server) getRBAC(w http.ResponseWriter, r *http.Request, _ string) {
	st, err := s.cfg.Store.Load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", err.Error())
		return
	}
	out := append([]bundle.RBAC{}, st.RBAC...)
	sort.Slice(out, func(i, j int) bool { return out[i].Identity < out[j].Identity })
	writeJSON(w, http.StatusOK, rbacReply{Bindings: out})
}

type rbacReq struct {
	Action   string   `json:"action"` // set | remove
	Identity string   `json:"identity"`
	Roles    []string `json:"roles"`
}

func (s *Server) postRBAC(w http.ResponseWriter, r *http.Request, id string) {
	var q rbacReq
	if !decode(w, r, &q) {
		return
	}
	if !strings.HasPrefix(q.Identity, "spiffe://") || len(q.Identity) == len("spiffe://") {
		writeErr(w, http.StatusBadRequest, "bad_request", "identity must be a spiffe:// ID")
		return
	}
	cur, err := s.cfg.Store.Load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", err.Error())
		return
	}
	var roles []string
	switch q.Action {
	case "set":
		if len(q.Roles) == 0 {
			writeErr(w, http.StatusBadRequest, "bad_request", "roles must not be empty (use action remove)")
			return
		}
		for _, role := range q.Roles {
			if !rbac.Known(role) {
				writeErr(w, http.StatusBadRequest, "unknown_role", "unknown role "+role)
				return
			}
		}
		roles = q.Roles
	case "remove":
		if len(rbac.RolesOf(cur.RBAC, q.Identity)) == 0 {
			writeErr(w, http.StatusNotFound, "not_bound", q.Identity+" has no binding")
			return
		}
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "action must be set or remove")
		return
	}
	if err := rbac.CheckTransition(cur.RBAC, rbac.Set(cur.RBAC, q.Identity, roles)); err != nil {
		code, why := publishStatus(err)
		if code == http.StatusInternalServerError {
			code, why = http.StatusBadRequest, "bad_rbac"
		}
		s.recordRefused(id, "rbac."+q.Action, "identity:"+q.Identity, why+": "+err.Error())
		writeErr(w, code, why, err.Error())
		return
	}
	ch := publish.Change{Reason: "rbac " + q.Action + " " + q.Identity,
		Edit: func(next *store.State) { next.RBAC = rbac.Set(next.RBAC, q.Identity, roles) }}
	s.publishAndRecord(w, r, id, "rbac."+q.Action, "identity:"+q.Identity, ch.Reason,
		[]audit.Field{{Key: "identity", Val: q.Identity}, {Key: "roles", Val: strings.Join(roles, ",")}}, ch)
}

// recordRefused audits a sec change the controller refused before publishing.
func (s *Server) recordRefused(id, action, target, reason string) {
	s.record(audit.Entry{Actor: id, Role: strings.Join(s.rolesOf(id), ","), Action: action, Target: target,
		Result: "error", Reason: reason})
}

type principalsReq struct {
	Action     string   `json:"action"` // set | remove
	Name       string   `json:"name"`
	Identities []string `json:"identities"`
	QuotaBytes uint64   `json:"quota_bytes"`
	MaxScopes  uint64   `json:"max_scopes"`
}

func (s *Server) postPrincipals(w http.ResponseWriter, r *http.Request, id string) {
	var q principalsReq
	if !decode(w, r, &q) {
		return
	}
	cur, err := s.cfg.Store.Load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", err.Error())
		return
	}
	var edit func(list []bundle.Principal) []bundle.Principal
	switch q.Action {
	case "set":
		edit = func(list []bundle.Principal) []bundle.Principal {
			p := bundle.Principal{Name: q.Name, Identities: q.Identities, QuotaBytes: q.QuotaBytes, MaxScopes: q.MaxScopes}
			out := make([]bundle.Principal, 0, len(list)+1)
			for _, o := range list {
				if o.Name == q.Name {
					p.DropBefore = o.DropBefore // a principal edit never lowers or clears drop_before
					continue
				}
				out = append(out, o)
			}
			return append(out, p)
		}
	case "remove":
		found := false
		for _, o := range cur.Principals {
			found = found || o.Name == q.Name
		}
		if !found {
			writeErr(w, http.StatusNotFound, "not_principal", "no principal "+q.Name)
			return
		}
		edit = func(list []bundle.Principal) []bundle.Principal {
			out := make([]bundle.Principal, 0, len(list))
			for _, o := range list {
				if o.Name != q.Name {
					out = append(out, o)
				}
			}
			return out
		}
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "action must be set or remove")
		return
	}
	if !s.checkPrincipals(w, id, "principal."+q.Action, q.Name, edit(cur.Principals), cur.RBAC) {
		return
	}
	ch := publish.Change{Reason: "principal " + q.Action + " " + q.Name,
		Edit: func(next *store.State) { next.Principals = edit(next.Principals) }}
	s.publishAndRecord(w, r, id, "principal."+q.Action, "principal:"+q.Name, ch.Reason,
		[]audit.Field{{Key: "name", Val: q.Name}, {Key: "identities", Val: len(q.Identities)}}, ch)
}

// checkPrincipals applies the node's own sec rules to the principal list a change would produce.
func (s *Server) checkPrincipals(w http.ResponseWriter, id, action, name string, list []bundle.Principal, rb []bundle.RBAC) bool {
	sec := bundle.Sec{SecGeneration: 1, Principals: list, RBAC: rb}
	if len(list) == 0 {
		sec.Principals = nil // an empty array is invalid, none is fine
	}
	if err := sec.Validate(); err != nil {
		s.recordRefused(id, action, "principal:"+name, "bad_principal: "+err.Error())
		writeErr(w, http.StatusBadRequest, "bad_principal", err.Error())
		return false
	}
	return true
}

type dropReq struct {
	Name       string `json:"name"`
	DropBefore string `json:"drop_before"` // YYYY-MM-DDTHH:MM:SSZ
}

// postDropPrincipal raises a principal's drop_before in a new sec (the nodes drop every entry of that
// principal written before it). It can only raise it.
func (s *Server) postDropPrincipal(w http.ResponseWriter, r *http.Request, id string) {
	var q dropReq
	if !decode(w, r, &q) {
		return
	}
	cur, err := s.cfg.Store.Load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", err.Error())
		return
	}
	idx := -1
	for i, p := range cur.Principals {
		if p.Name == q.Name {
			idx = i
		}
	}
	if idx < 0 {
		writeErr(w, http.StatusNotFound, "not_principal", "no principal "+q.Name)
		return
	}
	if q.DropBefore == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "drop_before is required (YYYY-MM-DDTHH:MM:SSZ)")
		return
	}
	if old := cur.Principals[idx].DropBefore; old != "" && q.DropBefore < old {
		err := errors.New("drop_before can only be raised (current " + old + ")")
		s.recordRefused(id, "principal.drop", "principal:"+q.Name, "drop_before_lowered: "+err.Error())
		writeErr(w, http.StatusConflict, "drop_before_lowered", err.Error())
		return
	}
	edit := func(list []bundle.Principal) []bundle.Principal {
		out := append([]bundle.Principal(nil), list...)
		for i := range out {
			if out[i].Name == q.Name {
				out[i].DropBefore = q.DropBefore
			}
		}
		return out
	}
	if !s.checkPrincipals(w, id, "principal.drop", q.Name, edit(cur.Principals), cur.RBAC) {
		return
	}
	ch := publish.Change{Reason: "drop_principal " + q.Name + " before " + q.DropBefore,
		Edit: func(next *store.State) { next.Principals = edit(next.Principals) }}
	s.publishAndRecord(w, r, id, "principal.drop", "principal:"+q.Name, ch.Reason,
		[]audit.Field{{Key: "name", Val: q.Name}, {Key: "drop_before", Val: q.DropBefore}}, ch)
}
