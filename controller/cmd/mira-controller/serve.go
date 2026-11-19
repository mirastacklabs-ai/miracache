package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"miracache/controller/api"
	"miracache/controller/audit"
	"miracache/controller/membership"
	"miracache/controller/publish"
	"miracache/controller/rbac"
	"miracache/controller/store"
)

type apiFlags struct {
	listen, cert, key, clientCA, auditDir string
}

// startAPI opens the audit log and serves the HTTPS API until ctx ends. If the audit log cannot be
// opened the API is not started (an action that cannot be recorded must not happen); the caller
// gets the error and decides (the reconcile loop is independent of the API).
func startAPI(ctx context.Context, f apiFlags, st *store.Store, p *publish.Publisher, mem *membership.Monitor, aw *audit.Writer, maxReporters int, log *slog.Logger) (func(), error) {
	if aw == nil {
		return nil, errors.New("--api-listen needs --audit-dir")
	}
	cert, err := tls.LoadX509KeyPair(f.cert, f.key)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(f.clientCA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("%s: no certificates", f.clientCA)
	}
	host, _ := os.Hostname()
	ln, err := net.Listen("tcp", f.listen)
	if err != nil {
		return nil, err
	}
	srv := api.New(api.Config{Store: st, Pub: p, Mem: mem, MaxReporters: maxReporters, Audit: aw, Log: log})
	hs := &http.Server{Handler: srv, TLSConfig: api.TLSConfig(cert, pool), ReadHeaderTimeout: 10 * time.Second}
	go srv.RunAuditFlush(ctx)
	go func() {
		if err := hs.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("api server stopped", "err", err)
		}
	}()
	log.Info("API listening", "addr", ln.Addr().String(), "host", host, "audit_dir", f.auditDir)
	return func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
		srv.FlushAudit(true)
	}, nil
}

// bootstrapRBAC seeds the first security-admin(s) once, while the store holds no rbac bindings
// (RBAC/audit plan decision 3). Afterwards the flag is ignored. It needs the audit log: a role
// change that cannot be recorded does not happen. The bindings enter the bundle's sec with the
// next publish.
func bootstrapRBAC(st *store.Store, aw *audit.Writer, list string, log *slog.Logger) error {
	var ids []string
	for _, o := range strings.Split(list, ",") {
		if o = strings.TrimSpace(o); o != "" {
			if !strings.HasPrefix(o, "spiffe://") {
				return fmt.Errorf("--bootstrap-security-admins: %q is not a spiffe:// ID", o)
			}
			ids = append(ids, o)
		}
	}
	if aw == nil {
		return errors.New("--bootstrap-security-admins needs --audit-dir")
	}
	seeded, err := rbac.Bootstrap(st, ids)
	if err != nil {
		return fmt.Errorf("bootstrap rbac: %w", err)
	}
	if !seeded {
		log.Info("rbac bindings exist; --bootstrap-security-admins ignored")
		return nil
	}
	if err := aw.Append(audit.Entry{Actor: "local", Action: "rbac.bootstrap", Target: "store", Result: "ok",
		Reason: "bootstrap-security-admins on an empty store", Detail: []audit.Field{{Key: "identities", Val: strings.Join(ids, ",")}}}); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	log.Info("rbac bootstrapped", "identities", ids)
	return nil
}
