package api

import (
	"net/http"
	"strings"

	"miracache/controller/audit"
	"miracache/controller/bundle"
	"miracache/controller/rbac"
)

// route is one row of the code table that drives authorization and the route x role tests.
type route struct {
	need rbac.Need
	h    func(s *Server, w http.ResponseWriter, r *http.Request, id string)
}

// routeTable maps "METHOD /path" to its row. A path with no row is 404; a known path with another
// method is 405; a missing role is 403 (deny by default, never a default role).
var routeTable = map[string]route{
	"GET /v1/bundle":          {rbac.NeedAuthenticated, (*Server).getBundle},
	"GET /v1/metrics":         {rbac.NeedAuthenticated, (*Server).getMetrics},
	"POST /v1/reports":        {rbac.NeedPrincipal, (*Server).postReports},
	"GET /v1/status":          {rbac.NeedViewer, (*Server).getStatus},
	"GET /v1/rbac":            {rbac.NeedViewer, (*Server).getRBAC},
	"POST /v1/members":        {rbac.NeedOperator, (*Server).postMembers},
	"POST /v1/config":         {rbac.NeedOperator, (*Server).postConfig},
	"POST /v1/rollback":       {rbac.NeedOperator, (*Server).postRollback},
	"POST /v1/principals":     {rbac.NeedSecAdmin, (*Server).postPrincipals},
	"POST /v1/rbac":           {rbac.NeedSecAdmin, (*Server).postRBAC},
	"POST /v1/drop_principal": {rbac.NeedSecAdmin, (*Server).postDropPrincipal},
}

// RouteNeeds returns the route table as "METHOD /path" -> required role ("" = authenticated only),
// for tests and docs.
func RouteNeeds() map[string]string {
	out := make(map[string]string, len(routeTable))
	for k, v := range routeTable {
		out[k] = string(v.need)
	}
	return out
}

// noIdentity is the audit actor of a certificate without a spiffe:// URI SAN.
const noIdentity = "(no spiffe identity)"

// ServeHTTP authenticates, authorizes (deny by default) and dispatches.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := Identity(r)
	target := r.Method + " " + r.URL.Path
	if id == "" {
		// a certificate without a spiffe:// URI SAN gets 403.
		s.deny(noIdentity, nil, target, "no spiffe:// URI SAN")
		writeErr(w, http.StatusForbidden, "denied", "a client certificate with a spiffe:// URI SAN is required")
		return
	}
	rt, ok := routeTable[target]
	if !ok {
		var allow []string
		for k := range routeTable {
			if m, p, _ := strings.Cut(k, " "); p == r.URL.Path {
				allow = append(allow, m)
			}
		}
		if len(allow) == 0 {
			writeErr(w, http.StatusNotFound, "not_found", "no such route")
			return
		}
		w.Header().Set("Allow", strings.Join(allow, ", "))
		writeErr(w, http.StatusMethodNotAllowed, "method_not_allowed", "use "+strings.Join(allow, " or "))
		return
	}
	roles := s.rolesOf(id)
	if rt.need != rbac.NeedAuthenticated && rt.need != rbac.NeedPrincipal && !rbac.Allowed(s.bindings(), id, rt.need) {
		s.deny(id, roles, target, "role_required "+string(rt.need))
		writeErr(w, http.StatusForbidden, "denied", "role "+string(rt.need)+" required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	rt.h(s, w, r, id)
}

// bindings are the store's rbac bindings (empty if the store cannot be read: deny by default).
func (s *Server) bindings() []bundle.RBAC {
	st, err := s.cfg.Store.Load()
	if err != nil {
		return nil
	}
	return st.RBAC
}

// rolesOf are the roles bound to id in the store.
func (s *Server) rolesOf(id string) []string { return rbac.RolesOf(s.bindings(), id) }

// deny records a denied call (coalesced per actor, action and result per second).
func (s *Server) deny(id string, roles []string, target, reason string) {
	s.co.add(audit.Entry{Actor: id, Role: strings.Join(roles, ","), Action: "api.call", Target: target,
		Result: "denied", Reason: reason}, s.cfg.Now())
}
