// Package publish is the controller's publish pipeline and reconcile loop (membership plan
// decisions 10 and 12; MB8a): the mTLS client to the memory nodes' admin APIs, publish with the
// next-generation rules, join with the new node first, the reconcile loop and --recover-from.
package publish

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"miracache/controller/bundle"
)

// maxReply bounds what is read from a node (an envelope is at most 1 MiB).
const maxReply = bundle.MaxEnvelope + 4096

// Rail is a rail as a node reports it (when its /v1/identity carries rails).
type Rail struct {
	Addr     string `json:"addr"`
	Subnet   string `json:"subnet"`
	Protocol string `json:"protocol"`
	// Health (MB9): up is the node's own verdict (port ACTIVE, listener alive, no fatal async event
	// in the last 10 s); port_state and listener_ok are informational.
	Up         bool   `json:"up"`
	PortState  string `json:"port_state,omitempty"`
	ListenerOK bool   `json:"listener_ok,omitempty"`
}

// Identity is a memory node's GET /v1/identity reply (server/runtime/bundle_store.cpp).
type Identity struct {
	NodeID            uint64 `json:"node_id"`
	Hostname          string `json:"hostname"`
	Addr              string `json:"addr"` // "host:port[,host:port...]"
	Admin             string `json:"admin"`
	Rails             []Rail `json:"rails"`
	AppliedGeneration uint64 `json:"applied_generation"`
	AppliedHash       string `json:"applied_hash"`
	SecGeneration     uint64 `json:"sec_generation"`
	SecHash           string `json:"sec_hash"`
	Epoch             uint64 `json:"epoch"`
	MemberState       string `json:"member_state,omitempty"`
	// BytesUsed is a pointer so that a node that does not report it is never taken for an empty one.
	BytesUsed *uint64 `json:"bytes_used,omitempty"`
}

// PushError is a non-200 answer to POST /v1/bundle.
type PushError struct {
	Status int
	Reason string // the node's reject reason ("" if the body had none)
	Detail string
}

func (e *PushError) Error() string {
	return fmt.Sprintf("node answered %d reason=%q: %s", e.Status, e.Reason, e.Detail)
}

// IsSecReject reports whether the node rejected the push for its sec section (sec_generation below
// the node's floor, or equal with another sec_hash): the controller's store is behind the cluster.
func (e *PushError) IsSecReject() bool {
	return e.Reason == bundle.ReasonSecGenerationLower || e.Reason == bundle.ReasonSecEqualGeneration
}

// NodeClient talks HTTPS (TLS 1.3, mTLS) to memory-node admin APIs. The http.Client carries the
// client certificate and the trust roots; it is built by the caller (see NewMTLSClient).
type NodeClient struct {
	HTTP *http.Client
}

func url(admin, path string) string { return "https://" + admin + path }

func (c *NodeClient) do(ctx context.Context, method, u string, body []byte) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxReply))
	return resp.StatusCode, b, err
}

// Identity calls GET /v1/identity.
func (c *NodeClient) Identity(ctx context.Context, admin string) (*Identity, error) {
	code, b, err := c.do(ctx, http.MethodGet, url(admin, "/v1/identity"), nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET /v1/identity: status %d", code)
	}
	var id Identity
	if err := json.Unmarshal(b, &id); err != nil {
		return nil, fmt.Errorf("GET /v1/identity: %w", err)
	}
	if id.NodeID == 0 || id.NodeID > 0xffffffff {
		return nil, fmt.Errorf("GET /v1/identity: node_id %d invalid", id.NodeID)
	}
	return &id, nil
}

// Push calls POST /v1/bundle (with ?dry_run=1 when dryRun). A non-200 answer is a *PushError.
func (c *NodeClient) Push(ctx context.Context, admin string, envelope []byte, dryRun bool) error {
	path := "/v1/bundle"
	if dryRun {
		path += "?dry_run=1"
	}
	code, b, err := c.do(ctx, http.MethodPost, url(admin, path), envelope)
	if err != nil {
		return err
	}
	if code == http.StatusOK {
		return nil
	}
	pe := &PushError{Status: code}
	var j struct{ Error, Reason string }
	if json.Unmarshal(b, &j) == nil {
		pe.Reason, pe.Detail = j.Reason, j.Error
	} else {
		pe.Detail = strings.TrimSpace(string(b))
	}
	return pe
}

// GetBundle calls GET /v1/bundle (the node's current envelope).
func (c *NodeClient) GetBundle(ctx context.Context, admin string) ([]byte, error) {
	code, b, err := c.do(ctx, http.MethodGet, url(admin, "/v1/bundle"), nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("GET /v1/bundle: status %d", code)
	}
	return b, nil
}

// asPushError returns err as a *PushError, or nil.
func asPushError(err error) *PushError {
	var pe *PushError
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

// hostOf returns the IP/host part of an admin address, for log lines.
func hostOf(admin string) string {
	h, _, err := net.SplitHostPort(admin)
	if err != nil {
		return admin
	}
	return h
}

// NewMTLSClient builds the HTTPS client for the memory nodes' admin APIs: TLS 1.3, the controller's
// client certificate, and the CA bundle that signed the nodes' server certificates.
func NewMTLSClient(cert tls.Certificate, roots *x509.CertPool) *http.Client {
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
		},
		MaxIdleConnsPerHost: 2,
	}}
}

// railsOf builds membership rails from the rails a node reports (addr, subnet, protocol). A node
// that reports no rails, an empty address or subnet (or a subnet that is not CIDR text), or a
// protocol other than roce/iwarp is refused: the error names the node (ID, hostname, IP) and the field.
func railsOf(id *Identity, admin string) ([]bundle.Rail, error) {
	who := fmt.Sprintf("node_id=%d host=%s addr=%s", id.NodeID, id.Hostname, hostOf(admin))
	if len(id.Rails) == 0 {
		return nil, fmt.Errorf("%s: /v1/identity reports no rails", who)
	}
	out := make([]bundle.Rail, 0, len(id.Rails))
	for i, r := range id.Rails {
		if r.Addr == "" {
			return nil, fmt.Errorf("%s: rails[%d].addr is empty", who, i)
		}
		if r.Subnet == "" {
			return nil, fmt.Errorf("%s: rails[%d].subnet is empty", who, i)
		}
		if _, err := netip.ParsePrefix(r.Subnet); err != nil {
			return nil, fmt.Errorf("%s: rails[%d].subnet %q is not CIDR text", who, i, r.Subnet)
		}
		if r.Protocol != "roce" && r.Protocol != "iwarp" {
			return nil, fmt.Errorf("%s: rails[%d].protocol %q is not roce or iwarp", who, i, r.Protocol)
		}
		out = append(out, bundle.Rail{Addr: r.Addr, Subnet: r.Subnet, Protocol: r.Protocol})
	}
	return out, nil
}
