package api

import (
	"encoding/json"
	"errors"
	"io"
	"miracache/controller/membership"
	"net/http"
	"sync"
	"time"
)

// Storage for POST /v1/reports. The raw latest body per identity is kept for inspection; MB9's
// membership.Monitor (Config.Mem) parses it and applies the failure rules. A report is attributed to the caller's mTLS identity, never to a field in the body; only
// the latest report per identity is kept and the number of identities is bounded.
const (
	maxReportBytes = 64 << 10
)

type storedReport struct {
	At   time.Time
	Body []byte
}

type reportStore struct {
	mu sync.Mutex
	m  map[string]storedReport
}

func newReportStore() *reportStore { return &reportStore{m: map[string]storedReport{}} }

func (rs *reportStore) put(id string, body []byte, at time.Time, max int, fresh time.Duration) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if _, ok := rs.m[id]; !ok && len(rs.m) >= max {
		for k, r := range rs.m { // the same policy as the monitor (V16): stale reports go first
			if at.Sub(r.At) > fresh {
				delete(rs.m, k)
			}
		}
	}
	if _, ok := rs.m[id]; !ok && len(rs.m) >= max {
		return false
	}
	rs.m[id] = storedReport{At: at, Body: body}
	return true
}

func (rs *reportStore) count() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return len(rs.m)
}

// Report returns the latest stored report body of an identity (for MB9 and tests).
func (s *Server) Report(id string) ([]byte, bool) {
	s.reports.mu.Lock()
	defer s.reports.mu.Unlock()
	r, ok := s.reports.m[id]
	return r.Body, ok
}

func (s *Server) postReports(w http.ResponseWriter, r *http.Request, id string) {
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) > maxReportBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, "too_large", "report too large")
		return
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "a report is a JSON object")
		return
	}
	if s.cfg.Mem != nil {
		// The monitor holds the reports (and the one cap policy); the raw stub is only for no-monitor runs.
		if err := s.cfg.Mem.Submit(id, body, s.cfg.Now()); err != nil {
			if errors.Is(err, membership.ErrReportsFull) {
				writeErr(w, http.StatusTooManyRequests, "too_many_reporters", "report storage is full")
				return
			}
			writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"result": "stored"})
		return
	}
	if !s.reports.put(id, body, s.cfg.Now(), s.cfg.MaxReporters, s.cfg.ReportFresh) {
		writeErr(w, http.StatusTooManyRequests, "too_many_reporters", "report storage is full")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"result": "stored"})
}

func (s *Server) getMetrics(w http.ResponseWriter, r *http.Request, _ string) {
	if s.cfg.Mem == nil {
		writeErr(w, http.StatusNotFound, "no_membership", "failure detection is not running")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	s.cfg.Mem.WriteMetrics(w)
}
