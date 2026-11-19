// Package api is the controller's HTTPS API (membership plan decisions 5, 12, 13; MB8b; RB3).
//
// Transport: TLS 1.3 with mTLS; the caller's identity is the first spiffe:// URI SAN of its client
// certificate (none: 403). Authorization is deny by default; the code table is routeTable
// (middleware.go) and the roles equal the memory node's:
//
//	GET  /v1/bundle, /v1/metrics, POST /v1/reports   any authenticated identity
//	GET  /v1/status, GET /v1/rbac                    viewer
//	POST /v1/members, /v1/config, /v1/rollback       operator
//	POST /v1/principals, /v1/rbac, /v1/drop_principal  security-admin (a publish with a new sec)
//
// Roles come from the store's rbac bindings only (seeded once by rbac.Bootstrap on an empty store);
// an identity without a role gets 403, never a default.
package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"miracache/controller/audit"
	"miracache/controller/bundle"
	"miracache/controller/membership"
	"miracache/controller/publish"
	"miracache/controller/rbac"
	"miracache/controller/store"
)

const maxBody = 1 << 20

// Publisher is the part of publish.Publisher the API uses.
type Publisher interface {
	Publish(ctx context.Context, ch publish.Change) (*publish.Result, error)
	Visible() []byte
	Stopped() bool
}

// Auditor records controller actions (controller/audit.Writer).
type Auditor interface {
	Append(audit.Entry) error
	Seq() uint64
	Head() string
}

// Membership is the failure detector and drain engine (controller/membership, MB9). Optional: with
// none, client reports are only stored and member remove is not gated.
type Membership interface {
	// Submit attributes a client report to the caller's mTLS identity (never to a field in the
	// body); an error means a malformed report.
	Submit(identity string, body []byte, at time.Time) error
	// CanRemove says whether a member may be removed by an operator: it must be drained.
	CanRemove(ctx context.Context, admin string) (ok bool, why string)
	// ConfirmRemove removes a node held in pending_removal (static stability).
	ConfirmRemove(ctx context.Context, admin string) error
	// WriteMetrics writes the Prometheus text of the per-node series.
	WriteMetrics(w io.Writer)
	// ReportCount is the number of identities with a stored report.
	ReportCount() int
}

// Config configures a Server.
type Config struct {
	Store *store.Store
	Pub   Publisher
	Mem   Membership // optional (MB9)
	// MaxReporters and ReportFresh are the one report-storage policy (V16): at most MaxReporters
	// identities (default 1024); when full, reports older than ReportFresh (default 6 s) are dropped
	// first, then a new identity is refused with 429. The same values go to membership.Config.
	MaxReporters int
	ReportFresh  time.Duration
	Audit        Auditor // required: an action that cannot be recorded is still reported to the caller
	Now          func() time.Time
	Log          *slog.Logger
}

// Server is the HTTP handler of the controller API.
type Server struct {
	cfg     Config
	co      *coalescer
	reports *reportStore
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.MaxReporters == 0 {
		cfg.MaxReporters = membership.DefaultMaxReporters
	}
	if cfg.ReportFresh == 0 {
		cfg.ReportFresh = membership.DefaultReportFresh
	}
	return &Server{cfg: cfg, co: newCoalescer(), reports: newReportStore()}
}

// TLSConfig is the server TLS configuration: TLS 1.3, client certificate required and verified
// against clientCA.
func TLSConfig(cert tls.Certificate, clientCA *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCA}
}

// Identity returns the first spiffe:// URI SAN of the peer certificate, or "".
func Identity(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return ""
	}
	for _, u := range r.TLS.PeerCertificates[0].URIs {
		if u.Scheme == "spiffe" {
			return u.String()
		}
	}
	return ""
}

// FlushAudit writes the coalesced denied entries of finished seconds (all of them with all).
func (s *Server) FlushAudit(all bool) {
	for _, e := range s.co.flush(s.cfg.Now(), all) {
		if err := s.cfg.Audit.Append(e); err != nil {
			s.cfg.Log.Error("audit append failed", "comp", "audit", "err", err)
		}
	}
}

// RunAuditFlush flushes the coalescer every second until ctx ends, then once more.
func (s *Server) RunAuditFlush(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.FlushAudit(true)
			return
		case <-t.C:
			s.FlushAudit(false)
		}
	}
}

// record appends an audit entry for a completed action; it returns an error text for the reply
// when the entry could not be written (the action itself already happened).
func (s *Server) record(e audit.Entry) string {
	if err := s.cfg.Audit.Append(e); err != nil {
		s.cfg.Log.Error("audit append failed", "comp", "audit", "action", e.Action, "err", err)
		return err.Error()
	}
	s.cfg.Log.Info("audit", "comp", "audit", "actor", e.Actor, "role", e.Role, "action", e.Action,
		"target", e.Target, "result", e.Result, "reason", e.Reason)
	return ""
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, reason, detail string) {
	writeJSON(w, code, map[string]string{"error": detail, "reason": reason})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "bad_request", "trailing data after the JSON body")
		return false
	}
	return true
}

// ---- GET /v1/bundle, GET /v1/status -----------------------------------------------------------

func (s *Server) getBundle(w http.ResponseWriter, r *http.Request, _ string) {
	env := s.cfg.Pub.Visible()
	if len(env) == 0 {
		st, err := s.cfg.Store.Load()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "store", err.Error())
			return
		}
		env = st.LastEnvelope
	}
	if len(env) == 0 {
		writeErr(w, http.StatusNotFound, "no_bundle", "nothing has been published yet")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(env)
}

type statusNode struct {
	Admin      string `json:"admin"`
	Weight     uint64 `json:"weight"`
	Zone       string `json:"zone,omitempty"`
	State      string `json:"state"`
	DrainSince string `json:"drain_since,omitempty"`
}

type statusReply struct {
	Generation    uint64       `json:"generation"`
	SecGeneration uint64       `json:"sec_generation"`
	Epoch         uint64       `json:"epoch"`
	Nodes         []statusNode `json:"nodes"`
	History       []uint64     `json:"history"` // generations available for rollback, oldest first
	Pending       bool         `json:"pending"`
	Stopped       bool         `json:"stopped"`
	Reports       int          `json:"reports"`
	AuditSeq      uint64       `json:"audit_seq"`
	AuditHead     string       `json:"audit_head"`
}

func (s *Server) getStatus(w http.ResponseWriter, r *http.Request, _ string) {
	st, err := s.cfg.Store.Load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", err.Error())
		return
	}
	out := statusReply{Generation: st.Generation, SecGeneration: st.SecGeneration, Pending: st.Pending != nil,
		Stopped: s.cfg.Pub.Stopped(), Reports: s.reportCount(), AuditSeq: s.cfg.Audit.Seq(), AuditHead: s.cfg.Audit.Head(),
		Nodes: []statusNode{}, History: []uint64{}}
	for _, n := range st.Nodes {
		out.Nodes = append(out.Nodes, statusNode(n))
	}
	for _, h := range st.History {
		if b, err := bundle.ParseBody(h); err == nil {
			out.History = append(out.History, b.Generation)
		}
	}
	if len(st.LastEnvelope) > 0 {
		if env, err := bundle.ParseEnvelope(st.LastEnvelope); err == nil {
			if b, err := bundle.ParseBody(env.Body); err == nil {
				out.Epoch = b.Membership.Epoch
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- publishing routes ------------------------------------------------------------------------

// publishAndRecord runs one publish for an operator action and writes the audit entry.
func (s *Server) publishAndRecord(w http.ResponseWriter, r *http.Request, id, action, target, reason string, detail []audit.Field, ch publish.Change) {
	roles := strings.Join(s.rolesOf(id), ",")
	res, err := s.cfg.Pub.Publish(r.Context(), ch)
	e := audit.Entry{Actor: id, Role: roles, Action: action, Target: target, Detail: detail}
	if err != nil {
		code, why := publishStatus(err)
		e.Result, e.Reason = "error", why+": "+err.Error()
		auditErr := s.record(e)
		body := map[string]string{"error": err.Error(), "reason": why}
		if auditErr != "" {
			body["audit_error"] = auditErr
		}
		writeJSON(w, code, body)
		return
	}
	gen := res.Generation
	e.Result, e.Reason, e.Generation = "ok", reason, &gen
	out := map[string]any{"generation": res.Generation, "sec_generation": res.SecGeneration, "epoch": res.Epoch,
		"acked": nonNil(res.Acked), "lagging": nonNil(res.Lagging)}
	if auditErr := s.record(e); auditErr != "" {
		out["audit_error"] = auditErr
	}
	writeJSON(w, http.StatusOK, out)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func publishStatus(err error) (int, string) {
	switch {
	case errors.Is(err, publish.ErrStopped):
		return http.StatusServiceUnavailable, "publishing_stopped"
	case errors.Is(err, publish.ErrDryRun):
		return http.StatusUnprocessableEntity, "dry_run_rejected"
	case errors.Is(err, publish.ErrJoinAborted):
		return http.StatusBadGateway, "join_aborted"
	case errors.Is(err, publish.ErrNoAck):
		return http.StatusBadGateway, "no_ack"
	case errors.Is(err, store.ErrConflict):
		return http.StatusConflict, "conflict"
	case errors.Is(err, rbac.ErrLastSecurityAdmin):
		return http.StatusConflict, "last_security_admin"
	case errors.Is(err, publish.ErrBadEdit):
		// The operator's edit failed input validation (e.g. a drop_before later than now + skew,
		// the same rule the memory node applies): a client error. A *bundle.Error without this
		// marker (own trust file refusing the signed bundle, corrupt stored envelope) stays 500.
		return http.StatusBadRequest, "bad_bundle"
	}
	return http.StatusInternalServerError, "publish_failed"
}

type membersReq struct {
	Action string `json:"action"` // add | set | remove
	Admin  string `json:"admin"`
	Weight uint64 `json:"weight"`
	Zone   string `json:"zone"`
	State  string `json:"state"` // active | draining | readonly
}

func (s *Server) postMembers(w http.ResponseWriter, r *http.Request, id string) {
	var q membersReq
	if !decode(w, r, &q) {
		return
	}
	if q.Admin == "" || strings.ContainsAny(q.Admin, "/ \t\n") {
		writeErr(w, http.StatusBadRequest, "bad_request", "admin must be a host:port")
		return
	}
	if q.State != "" && q.State != "active" && q.State != "draining" && q.State != "readonly" {
		writeErr(w, http.StatusBadRequest, "bad_request", "state must be active, draining or readonly")
		return
	}
	st, err := s.cfg.Store.Load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", err.Error())
		return
	}
	member := -1
	for i, n := range st.Nodes {
		if n.Admin == q.Admin {
			member = i
		}
	}
	target := "node:" + q.Admin
	detail := []audit.Field{{Key: "admin", Val: q.Admin}}
	var ch publish.Change
	switch q.Action {
	case "add":
		if member >= 0 {
			writeErr(w, http.StatusConflict, "already_member", q.Admin+" is already a member")
			return
		}
		weight := q.Weight
		if weight == 0 {
			weight = 1
		}
		ch = publish.Change{Reason: "member add " + q.Admin, Edit: func(next *store.State) { next.Failed = dropFailed(next.Failed, q.Admin) }, // V04
			Join: &store.DesiredNode{Admin: q.Admin, Weight: weight, Zone: q.Zone, State: "active"}}
		detail = append(detail, audit.Field{Key: "weight", Val: weight})
	case "set":
		if member < 0 {
			writeErr(w, http.StatusNotFound, "not_member", q.Admin+" is not a member")
			return
		}
		ch = publish.Change{Reason: "member set " + q.Admin, Edit: func(next *store.State) {
			for i := range next.Nodes {
				if next.Nodes[i].Admin != q.Admin {
					continue
				}
				if (q.State == "draining" || q.State == "readonly") && next.Nodes[i].State == "active" {
					// The drain timers (MB9) run from this stamp, kept in the store.
					next.Nodes[i].DrainSince = s.cfg.Now().UTC().Format(time.RFC3339)
				}
				if q.State == "active" {
					next.Nodes[i].DrainSince = ""
				}
				if q.Weight != 0 {
					next.Nodes[i].Weight = q.Weight
				}
				if q.Zone != "" {
					next.Nodes[i].Zone = q.Zone
				}
				if q.State != "" {
					next.Nodes[i].State = q.State
				}
			}
		}}
		if q.State != "" {
			detail = append(detail, audit.Field{Key: "state", Val: q.State})
		}
	case "remove":
		if member < 0 {
			writeErr(w, http.StatusNotFound, "not_member", q.Admin+" is not a member")
			return
		}
		if len(st.Nodes) == 1 {
			writeErr(w, http.StatusConflict, "last_member", "the last member cannot be removed")
			return
		}
		if s.cfg.Mem != nil {
			if ok, why := s.cfg.Mem.CanRemove(r.Context(), q.Admin); !ok {
				writeErr(w, http.StatusConflict, "not_drained", why)
				return
			}
		}
		ch = publish.Change{Reason: "member remove " + q.Admin, Edit: func(next *store.State) {
			next.Failed = dropFailed(next.Failed, q.Admin) // V04: an operator removal must not auto-rejoin
			kept := next.Nodes[:0]
			for _, n := range next.Nodes {
				if n.Admin != q.Admin {
					kept = append(kept, n)
				}
			}
			next.Nodes = kept
		}}
	case "forget":
		// A node the failure detector removed: stop counting it against the removal budget and never
		// auto-rejoin it (MB10 mirctl node forget).
		inFailed := false
		for _, f := range st.Failed {
			inFailed = inFailed || f.Admin == q.Admin
		}
		if !inFailed {
			writeErr(w, http.StatusNotFound, "not_failed", q.Admin+" is not in the failed list")
			return
		}
		ch = publish.Change{Reason: "forget failed node " + q.Admin, Edit: func(next *store.State) {
			next.Failed = dropFailed(next.Failed, q.Admin)
		}}
	case "confirm_remove":
		// A node held in pending_removal by static stability (decision 11); mirctl node confirm-remove.
		if s.cfg.Mem == nil {
			writeErr(w, http.StatusNotImplemented, "no_membership", "failure detection is not running")
			return
		}
		err := s.cfg.Mem.ConfirmRemove(r.Context(), q.Admin)
		e := audit.Entry{Actor: id, Role: strings.Join(s.rolesOf(id), ","), Action: "member.confirm_remove", Target: target, Detail: detail}
		if err != nil {
			code, why := http.StatusConflict, "not_pending"
			if _, rs := publishStatus(err); rs != "publish_failed" {
				code, why = publishStatus(err)
			}
			e.Result, e.Reason = "error", why+": "+err.Error()
			s.record(e)
			writeErr(w, code, why, err.Error())
			return
		}
		e.Result, e.Reason = "ok", "confirm-remove"
		out := map[string]any{"result": "removed"}
		if auditErr := s.record(e); auditErr != "" {
			out["audit_error"] = auditErr
		}
		writeJSON(w, http.StatusOK, out)
		return
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "action must be add, set, remove, forget or confirm_remove")
		return
	}
	s.publishAndRecord(w, r, id, "member."+q.Action, target, ch.Reason, detail, ch)
}

type configReq struct {
	ConfigTOML string `json:"config_toml"` // the config.* tables as TOML under [config]; "" clears them
	Reason     string `json:"reason"`
}

// configKeys lists the top-level config.* keys of a [config] document (names only, never values).
func configKeys(src string) ([]string, error) {
	var doc struct {
		Config map[string]any `toml:"config"`
	}
	if strings.TrimSpace(src) == "" {
		return nil, nil
	}
	if _, err := toml.Decode(src, &doc); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(doc.Config))
	for k := range doc.Config {
		keys = append(keys, "config."+k)
	}
	sort.Strings(keys)
	return keys, nil
}

func (s *Server) postConfig(w http.ResponseWriter, r *http.Request, id string) {
	var q configReq
	if !decode(w, r, &q) {
		return
	}
	keys, err := configKeys(q.ConfigTOML)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_config", err.Error())
		return
	}
	reason := q.Reason
	if reason == "" {
		reason = "config set"
	}
	ch := publish.Change{Reason: reason, Edit: func(next *store.State) { next.ConfigTOML = q.ConfigTOML }}
	s.publishAndRecord(w, r, id, "config.set", "config", reason,
		[]audit.Field{{Key: "keys", Val: strings.Join(keys, ",")}}, ch)
}

type rollbackReq struct {
	Generation uint64 `json:"generation"`
}

// ConfigFromBody renders the config.* tables of a stored body as the TOML the store keeps
// ([config] document), so a rollback can put them back.
func ConfigFromBody(b *bundle.Body) (string, error) {
	if len(b.Config) == 0 {
		return "", nil
	}
	var buf bytes.Buffer
	doc := struct {
		Config map[string]any `toml:"config"`
	}{b.Config}
	if err := toml.NewEncoder(&buf).Encode(doc); err != nil {
		return "", fmt.Errorf("encoding config: %w", err)
	}
	return buf.String(), nil
}

// postRollback restores config.* from a stored body and nothing else (decision 13, P01): the edit
// below touches ConfigTOML only, so membership, principals, rbac, drop_before and the epoch come
// from the current state and the publisher derives the epoch itself (receivers also refuse a
// lower one).
func (s *Server) postRollback(w http.ResponseWriter, r *http.Request, id string) {
	var q rollbackReq
	if !decode(w, r, &q) {
		return
	}
	st, err := s.cfg.Store.Load()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "store", err.Error())
		return
	}
	var old *bundle.Body
	for _, h := range st.History {
		if b, err := bundle.ParseBody(h); err == nil && b.Generation == q.Generation {
			old = b
		}
	}
	if old == nil {
		writeErr(w, http.StatusNotFound, "generation_not_stored", fmt.Sprintf("generation %d is not among the last %d stored bodies", q.Generation, store.HistoryLen))
		return
	}
	cfg, err := ConfigFromBody(old)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "rollback", err.Error())
		return
	}
	keys, _ := configKeys(cfg)
	reason := fmt.Sprintf("rollback config.* to generation %d", q.Generation)
	ch := publish.Change{Reason: reason, Edit: func(next *store.State) { next.ConfigTOML = cfg }}
	s.publishAndRecord(w, r, id, "config.rollback", fmt.Sprintf("generation:%d", q.Generation), "config only",
		[]audit.Field{{Key: "from_generation", Val: q.Generation}, {Key: "keys", Val: strings.Join(keys, ",")}}, ch)
}

// dropFailed returns list without the failed-node record of admin.
func dropFailed(list []store.FailedNode, admin string) []store.FailedNode {
	out := make([]store.FailedNode, 0, len(list))
	for _, f := range list {
		if f.Admin != admin {
			out = append(out, f)
		}
	}
	return out
}

func (s *Server) reportCount() int {
	if s.cfg.Mem != nil {
		return s.cfg.Mem.ReportCount()
	}
	return s.reports.count()
}
