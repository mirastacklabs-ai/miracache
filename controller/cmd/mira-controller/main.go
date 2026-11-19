// Command mira-controller is the single cluster controller (membership plan decision 12; MB8a).
//
// It holds flock(store.lock) for its lifetime (a second instance refuses to start), publishes
// signed bundles to the memory nodes' admin APIs over mTLS and runs the reconcile loop every 5 s.
// With --api-listen it serves the HTTPS API (controller/api: bundle, status, members, config,
// rollback; sec routes denied until RB3) and writes the audit log (--audit-dir).
//
// Backup: copy the whole --store-dir and the two signing key files (the operator's duty). To
// rebuild a lost state.json, run `mira-controller --recover-from <admin addr of the node with the
// highest sec_generation> ...`; it imports that node's bundle.current and exits.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"miracache/controller/audit"
	"miracache/controller/bundle"
	"miracache/controller/membership"
	"miracache/controller/publish"
	"miracache/controller/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mira-controller:", err)
		os.Exit(1)
	}
}

func readSeed(path string) (ed25519.PrivateKey, error) {
	// A signing key must not be readable by group or others (K12): the same check as mirctl's readSeed, so one
	// file (mira:mira 0600) serves both.
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s has mode %04o; a key file must not be accessible by group or others (chmod 600)", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: want 64 hex characters (a 32-byte Ed25519 seed)", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func run() error {
	var (
		storeDir      = flag.String("store-dir", "", "controller store directory (state.json, store.lock)")
		trustPath     = flag.String("trust-keys", "", "trust key file (the same file the memory nodes use)")
		pubKeyPath    = flag.String("publish-key", "", "file with the publish key seed (64 hex)")
		secKeyPath    = flag.String("security-key", "", "file with the security key seed (64 hex)")
		certPath      = flag.String("cert", "", "client certificate (PEM) for the nodes' admin APIs")
		keyPath       = flag.String("key", "", "client certificate key (PEM)")
		caPath        = flag.String("ca", "", "CA bundle (PEM) that signed the nodes' server certificates")
		author        = flag.String("author", "", "bundle author (default: the first spiffe:// URI SAN of --cert)")
		ackWait       = flag.Duration("ack-wait", publish.DefaultAckWait, "publish.ack_wait_ms")
		skew          = flag.Duration("clock-skew", publish.DefaultClockSkew, "publish.clock_skew_s")
		recoverFrom   = flag.String("recover-from", "", "import this node's bundle.current into the store, then exit")
		join          = flag.String("join", "", "admin address of a node to add (new node first), then continue")
		weight        = flag.Uint64("weight", 1, "weight of the joining node")
		zone          = flag.String("zone", "", "zone of the joining node")
		once          = flag.Bool("once", false, "exit after the --join (no reconcile loop)")
		apiListen     = flag.String("api-listen", "", "serve the HTTPS API (mTLS) on this address, e.g. :9470 (needs --audit-dir)")
		apiCert       = flag.String("api-cert", "", "API server certificate (PEM; default --cert)")
		apiKey        = flag.String("api-key", "", "API server certificate key (PEM; default --key)")
		apiClientCA   = flag.String("api-client-ca", "", "CA bundle (PEM) for API client certificates (default --ca)")
		auditDir      = flag.String("audit-dir", "", "audit log directory (hash-chained, fsynced per entry)")
		failTimeout   = flag.Duration("fail-timeout", membership.DefaultFailTimeout, "membership.fail_timeout_ms")
		drainContinue = flag.Duration("drain-continue", membership.DefaultDrainContinue, "drain.continue_ms")
		drainMax      = flag.Duration("drain-max", membership.DefaultDrainMax, "drain.max_ms")
		rejoin        = flag.Duration("rejoin", membership.DefaultRejoin, "rejoin_ms")
		removeWindow  = flag.Duration("remove-window", membership.DefaultRemoveWindow, "how long a replacement counts against the removal budget (failure removals count until rejoin or forget)")
		maxReporters  = flag.Int("max-reporters", membership.DefaultMaxReporters, "client report identities kept (API and failure detector)")
		bootstrapSec  = flag.String("bootstrap-security-admins", "", "comma-separated spiffe:// IDs seeded as security-admin+operator ONLY while the store has no rbac bindings (ignored afterwards)")
	)
	flag.Parse()
	for name, v := range map[string]string{"store-dir": *storeDir, "trust-keys": *trustPath, "cert": *certPath, "key": *keyPath, "ca": *caPath} {
		if v == "" {
			return fmt.Errorf("--%s is required", name)
		}
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))

	st, err := store.Open(*storeDir)
	if errors.Is(err, store.ErrLocked) {
		return fmt.Errorf("another mira-controller holds %s/store.lock; there is one controller per cluster", *storeDir)
	}
	if err != nil {
		return err
	}
	defer st.Close()

	trust, err := bundle.LoadTrustFile(*trustPath)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("%s: no certificates", *caPath)
	}
	client := &publish.NodeClient{HTTP: publish.NewMTLSClient(cert, roots)}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *recoverFrom != "" {
		return publish.Recover(ctx, client, trust, st, *recoverFrom, log)
	}

	if *pubKeyPath == "" || *secKeyPath == "" {
		return errors.New("--publish-key and --security-key are required")
	}
	pubKey, err := readSeed(*pubKeyPath)
	if err != nil {
		return err
	}
	secKey, err := readSeed(*secKeyPath)
	if err != nil {
		return err
	}
	who := *author
	if who == "" {
		if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
			for _, u := range leaf.URIs {
				if u.Scheme == "spiffe" {
					who = u.String()
					break
				}
			}
		}
	}
	if who == "" {
		return errors.New("--author is required when --cert has no spiffe:// URI SAN")
	}
	p := publish.New(publish.Config{Store: st, Trust: trust, PublishKey: pubKey, SecurityKey: secKey,
		Client: client, Author: who, AckWait: *ackWait, ClockSkew: *skew, Now: time.Now, Log: log})

	if *join != "" {
		res, err := p.Publish(ctx, publish.Change{Reason: "join " + *join,
			Join: &store.DesiredNode{Admin: *join, Weight: *weight, Zone: *zone, State: "active"}})
		if err != nil {
			return err
		}
		log.Info("join published", "generation", res.Generation, "acked", res.Acked, "lagging", res.Lagging)
		if *once {
			return nil
		}
	}
	mon := membership.New(membership.Config{Store: st, Pub: p, Client: client, Log: log,
		RemoveWindow: *removeWindow, MaxReporters: *maxReporters, FailTimeout: *failTimeout, DrainContinue: *drainContinue, DrainMax: *drainMax, Rejoin: *rejoin})
	// The audit log is opened before the monitor runs (U2-12): without one the monitor refuses its
	// automatic removals, replacements and drain steps and holds them as pending_removal.
	var aw *audit.Writer
	if *auditDir != "" {
		host, _ := os.Hostname()
		aw, err = audit.Open(audit.Config{Dir: *auditDir, Src: audit.Source{Controller: true, Host: host, Addr: *apiListen}})
		if err != nil {
			return fmt.Errorf("audit log: %w", err)
		}
		defer aw.Close()
		mon.SetAuditor(aw)
	} else {
		log.Warn("no --audit-dir: automatic membership actions are refused and held as pending_removal")
	}
	if *bootstrapSec != "" {
		if err := bootstrapRBAC(st, aw, *bootstrapSec, log); err != nil {
			return err
		}
	}
	go mon.Run(ctx)
	if *apiListen != "" {
		af := apiFlags{listen: *apiListen, cert: *apiCert, key: *apiKey, clientCA: *apiClientCA, auditDir: *auditDir}
		if af.cert == "" {
			af.cert = *certPath
		}
		if af.key == "" {
			af.key = *keyPath
		}
		if af.clientCA == "" {
			af.clientCA = *caPath
		}
		stopAPI, err := startAPI(ctx, af, st, p, mon, aw, *maxReporters, log)
		if err != nil {
			return fmt.Errorf("API not started: %w", err)
		}
		defer stopAPI()
	}
	log.Info("reconcile loop running", "period", publish.ReconcilePeriod.String())
	p.RunReconcile(ctx, publish.ReconcilePeriod)
	if p.Stopped() {
		return publish.ErrStopped
	}
	return nil
}
