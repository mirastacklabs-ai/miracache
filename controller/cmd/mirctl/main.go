// Command mirctl is the miracache operator tool.
//
//	mirctl bundle diff|publish|push|status   publish and inspect signed bundles, with or without a controller
//	mirctl node add|drain|remove|confirm-remove|forget   membership changes through the controller API
//	mirctl rbac set|list                   controller role bindings
//	mirctl keys gen                          generate an Ed25519 signing key
//	mirctl secret gen|add-kver               engine-native deployment secret files
//	mirctl audit verify                      verify the controller's audit chain
//
// `bundle publish` works without a controller: it talks to the memory nodes' admin APIs directly and
// runs the controller's publish pipeline (controller/publish) against a throw-away store seeded from
// the cluster itself. One writer per cluster: either the controller or mirctl.
//
// Exit codes: 0 ok, 1 error, 2 `bundle status` found a node below the highest sec_generation.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// app holds what tests replace: output, the clock, the random source and the HTTP client factory.
type app struct {
	out, err io.Writer
	now      func() time.Time
	rand     io.Reader
	client   clientFactory
}

func main() {
	a := &app{out: os.Stdout, err: os.Stderr, now: time.Now, client: mtlsClient}
	a.rand = cryptoRand{}
	os.Exit(a.run(os.Args[1:]))
}

const usage = `usage: mirctl <command> [flags]

  bundle diff|publish|push|status
  node add|drain|remove|confirm-remove|forget
  rbac set|list
  keys gen
  secret gen|add-kver
  audit verify

Run "mirctl <command> <subcommand> -h" for the flags.
`

// errExit carries an exit code through the command functions.
type errExit struct {
	code int
	msg  string
}

func (e *errExit) Error() string { return e.msg }

func fail(format string, a ...any) error { return &errExit{1, fmt.Sprintf(format, a...)} }

func (a *app) run(args []string) int {
	if len(args) < 2 {
		fmt.Fprint(a.err, usage)
		return 1
	}
	group, sub, rest := args[0], args[1], args[2:]
	var err error
	switch group + " " + sub {
	case "bundle diff":
		err = a.bundleDiff(rest)
	case "bundle publish":
		err = a.bundlePublish(rest)
	case "bundle push":
		err = a.bundlePush(rest)
	case "bundle status":
		err = a.bundleStatus(rest)
	case "node add", "node drain", "node remove", "node confirm-remove", "node forget":
		err = a.nodeCmd(sub, rest)
	case "rbac set", "rbac list":
		err = a.rbacCmd(sub, rest)
	case "keys gen":
		err = a.keysGen(rest)
	case "secret gen":
		err = a.secretGen(rest)
	case "secret add-kver":
		err = a.secretAddKver(rest)
	case "audit verify":
		err = a.auditVerify(rest)
	default:
		fmt.Fprint(a.err, usage)
		return 1
	}
	if err == nil {
		return 0
	}
	if e, ok := err.(*errExit); ok {
		if e.msg != "" {
			fmt.Fprintln(a.err, "mirctl:", strings.TrimSpace(e.msg))
		}
		return e.code
	}
	if err == errHelp {
		return 0
	}
	fmt.Fprintln(a.err, "mirctl:", err)
	return 1
}
