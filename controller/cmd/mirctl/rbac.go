package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// rbacCmd is `mirctl rbac set|list` (RB3): the controller's role bindings. Every change is a new
// sec signed with the controller's security key; the controller refuses to remove the last
// security-admin and the bundle carries the same table to every memory node.
//
//	mirctl rbac list --controller host:port ...
//	mirctl rbac set <spiffe id> --roles operator,viewer --controller host:port ...
//	mirctl rbac set <spiffe id> --remove --controller host:port ...
func (a *app) rbacCmd(sub string, args []string) error {
	var (
		t          tlsFlags
		controller string
		roles      string
		remove     bool
	)
	fs := a.newFlags("rbac " + sub)
	t.register(fs)
	fs.StringVar(&controller, "controller", "", "controller API address (host:port; required)")
	if sub == "set" {
		fs.StringVar(&roles, "roles", "", "comma-separated roles: viewer, operator, security-admin, scope-provider")
		fs.BoolVar(&remove, "remove", false, "remove the identity's binding")
	}
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if controller == "" {
		return errors.New("--controller is required")
	}
	hc, _, err := a.client(&t)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		if len(pos) != 0 {
			return errors.New("usage: mirctl rbac list --controller host:port ...")
		}
		out, err := controllerCall(hc, http.MethodGet, controller, "/v1/rbac", nil)
		if err != nil {
			return err
		}
		var rep struct {
			Bindings []struct {
				Identity string   `json:"Identity"`
				Roles    []string `json:"Roles"`
			} `json:"bindings"`
		}
		if err := json.Unmarshal(out, &rep); err != nil {
			return fmt.Errorf("controller reply: %w", err)
		}
		sort.Slice(rep.Bindings, func(i, j int) bool { return rep.Bindings[i].Identity < rep.Bindings[j].Identity })
		for _, b := range rep.Bindings {
			fmt.Fprintf(a.out, "%s %s\n", b.Identity, strings.Join(b.Roles, ","))
		}
		return nil
	case "set":
		if len(pos) != 1 || (remove == (roles != "")) {
			return errors.New("usage: mirctl rbac set <spiffe id> (--roles r1,r2 | --remove) --controller host:port ...")
		}
		req := map[string]any{"identity": pos[0], "action": "set"}
		if remove {
			req["action"] = "remove"
		} else {
			var rs []string
			for _, r := range strings.Split(roles, ",") {
				if r = strings.TrimSpace(r); r != "" {
					rs = append(rs, r)
				}
			}
			req["roles"] = rs
		}
		out, err := controllerCall(hc, http.MethodPost, controller, "/v1/rbac", req)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.out, "ok %s\n", strings.TrimSpace(string(out)))
		return nil
	}
	return fmt.Errorf("unknown rbac command %q", sub)
}

// controllerCall sends one request to the controller API and returns the body of a 200 reply.
func controllerCall(hc *http.Client, method, controller, path string, body any) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, method, "https://"+controller+path, rd)
	if err != nil {
		return nil, err
	}
	hr.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("controller answered %d: %s", resp.StatusCode, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// idList is a repeatable (and comma-separated) string flag.
type idList []string

func (l *idList) String() string { return strings.Join(*l, ",") }
func (l *idList) Set(v string) error {
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			*l = append(*l, s)
		}
	}
	return nil
}
