package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"miracache/controller/audit"
	"miracache/controller/bundle"
)

// nodeCmd is `mirctl node add|drain|remove|confirm-remove|forget <admin addr>`: membership changes go
// through the controller API (POST /v1/members). Node IDs are never typed: the node is addressed by
// its admin address and the controller learns the ID from the node itself.
func (a *app) nodeCmd(sub string, args []string) error {
	var (
		t          tlsFlags
		controller string
		weight     uint64
		zone       string
	)
	fs := a.newFlags("node " + sub)
	t.register(fs)
	fs.StringVar(&controller, "controller", "", "controller API address (host:port; required)")
	if sub == "add" {
		fs.Uint64Var(&weight, "weight", 1, "weight of the new node")
		fs.StringVar(&zone, "zone", "", "zone of the new node")
	}
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("usage: mirctl node %s <admin addr host:port> --controller host:port ...", sub)
	}
	if controller == "" {
		return errors.New("--controller is required (without a controller, edit the source and run `mirctl bundle publish`)")
	}
	req := map[string]any{"admin": pos[0]}
	switch sub {
	case "add":
		req["action"], req["weight"], req["zone"] = "add", weight, zone
	case "drain":
		req["action"], req["state"] = "set", "draining"
	case "remove":
		req["action"] = "remove"
	case "confirm-remove":
		req["action"] = "confirm_remove"
	case "forget":
		req["action"] = "forget" // removed by the failure detector: stop counting it, never auto-rejoin it
	}
	hc, _, err := a.client(&t)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+controller+"/v1/members", bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(hr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("controller answered %d: %s", resp.StatusCode, strings.TrimSpace(string(out)))
	}
	fmt.Fprintf(a.out, "node %s %s: %s\n", pos[0], sub, strings.TrimSpace(string(out)))
	return nil
}

// keysGen is `mirctl keys gen`: a new Ed25519 signing key. The seed file is 64 hex characters
// (mode 0600, tmp + rename, never overwritten); the key_id and the trust-file entry are computed.
func (a *app) keysGen(args []string) error {
	var out, roles string
	fs := a.newFlags("keys gen")
	fs.StringVar(&out, "out", "", "seed file to write (required)")
	fs.StringVar(&roles, "roles", "publish", "roles for the trust-file entry: publish, security or publish,security")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if out == "" {
		return errors.New("--out is required")
	}
	var rl []string
	for _, r := range strings.Split(roles, ",") {
		r = strings.TrimSpace(r)
		if r != bundle.RolePublish && r != bundle.RoleSecurity {
			return fmt.Errorf("role %q: want publish or security", r)
		}
		rl = append(rl, r)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(a.rand, seed); err != nil {
		return err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if err := writeFileAtomic(out, []byte(hex.EncodeToString(seed)+"\n"), true); err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Fprintf(a.out, "wrote %s (mode 0600)\nkey_id: %s\nadd this to the trust file of every memory node and controller:\n\n[[key]]\npublic = %q\nroles = [%s]\n",
		out, bundle.KeyID(pub), hex.EncodeToString(pub), quoteAll(rl))
	return nil
}

func quoteAll(s []string) string {
	q := make([]string, len(s))
	for i, v := range s {
		q[i] = fmt.Sprintf("%q", v)
	}
	return strings.Join(q, ", ")
}

// auditVerify is `mirctl audit verify <file>...` (files in chain order): controller/audit's verifier.
func (a *app) auditVerify(args []string) error {
	var anchorSeq uint64
	var anchorHead string
	fs := a.newFlags("audit verify")
	fs.Uint64Var(&anchorSeq, "anchor-seq", 0, "an earlier audit_seq (from /v1/status or /v1/identity); the chain must contain it")
	fs.StringVar(&anchorHead, "anchor-head", "", "the audit_head recorded with --anchor-seq")
	files, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("usage: mirctl audit verify [--anchor-seq N --anchor-head H] <audit file>... (in chain order)")
	}
	var anchor *audit.Anchor
	if anchorSeq != 0 || anchorHead != "" {
		if anchorSeq == 0 || anchorHead == "" {
			return errors.New("--anchor-seq and --anchor-head go together")
		}
		anchor = &audit.Anchor{Seq: anchorSeq, Head: anchorHead}
	}
	r := audit.VerifyPaths(files, anchor)
	fmt.Fprintln(a.out, r.Text())
	if !r.OK {
		return &errExit{1, ""}
	}
	return nil
}
