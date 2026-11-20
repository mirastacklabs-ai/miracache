package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"miracache/controller/publish"
)

var errHelp = errors.New("help")

type cryptoRand struct{}

func (cryptoRand) Read(p []byte) (int, error) { return rand.Read(p) }

// newFlags returns a FlagSet whose messages go to the app's error stream.
func (a *app) newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("mirctl "+name, flag.ContinueOnError)
	fs.SetOutput(a.err)
	return fs
}

// parse parses args allowing flags after positional arguments; it returns the positionals.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, errHelp
			}
			return nil, &errExit{1, ""}
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// tlsFlags are the mTLS flags every command that talks to the nodes or the controller takes.
type tlsFlags struct{ cert, key, ca string }

func (t *tlsFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&t.cert, "cert", "", "client certificate (PEM) for the admin APIs")
	fs.StringVar(&t.key, "tls-key", "", "client certificate key (PEM)")
	fs.StringVar(&t.ca, "ca", "", "CA bundle (PEM) that signed the servers' certificates")
}

// clientFactory builds the HTTPS client (tests replace it).
type clientFactory func(t *tlsFlags) (*http.Client, *x509.Certificate, error)

// mtlsClient builds the real TLS 1.3 mTLS client; it also returns the client certificate's leaf.
func mtlsClient(t *tlsFlags) (*http.Client, *x509.Certificate, error) {
	if t.cert == "" || t.key == "" || t.ca == "" {
		return nil, nil, errors.New("--cert, --tls-key and --ca are required")
	}
	cert, err := tls.LoadX509KeyPair(t.cert, t.key)
	if err != nil {
		return nil, nil, err
	}
	caPEM, err := os.ReadFile(t.ca)
	if err != nil {
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, nil, fmt.Errorf("%s: no certificates", t.ca)
	}
	leaf, _ := x509.ParseCertificate(cert.Certificate[0])
	return publish.NewMTLSClient(cert, roots), leaf, nil
}

// spiffeOf returns the first spiffe:// URI SAN of c ("" if none).
func spiffeOf(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	for _, u := range c.URIs {
		if u.Scheme == "spiffe" {
			return u.String()
		}
	}
	return ""
}

// readSeed reads an Ed25519 seed file (64 hex characters), as mira-controller does.
func readSeed(path string) (ed25519.PrivateKey, error) {
	// A signing key must not be readable by group or others, as add-kver demands of secrets.
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

// writeFileAtomic writes data to path through a tmp file in the same directory (mode 0600, fsync)
// and a rename; with noClobber it links instead, so an existing path is never replaced.
func writeFileAtomic(path string, data []byte, noClobber bool) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*") // created 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() { os.Remove(tmp) }
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return err
	}
	if noClobber {
		err = os.Link(tmp, path)
		cleanup()
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists; refusing to overwrite it", path)
		}
		if err != nil {
			return err
		}
	} else if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// nodeSet is the --nodes / --source admin address selection.
type nodeSet struct {
	nodes  string
	source string
}

func (n *nodeSet) register(fs *flag.FlagSet) {
	fs.StringVar(&n.nodes, "nodes", "", "comma-separated admin addresses (host:port) of the memory nodes")
	fs.StringVar(&n.source, "source", "", "cluster.toml; its nodes are used when --nodes is not given")
}

// admins returns the admin addresses and, when --source was read, the parsed source.
func (n *nodeSet) admins() ([]string, *Source, error) {
	var src *Source
	if n.source != "" {
		s, err := ReadSource(n.source)
		if err != nil {
			return nil, nil, err
		}
		src = s
	}
	var out []string
	if n.nodes != "" {
		for _, a := range strings.Split(n.nodes, ",") {
			if a = strings.TrimSpace(a); a != "" {
				out = append(out, a)
			}
		}
	} else if src != nil {
		for _, d := range src.Nodes {
			out = append(out, d.Admin)
		}
	}
	if len(out) == 0 {
		return nil, nil, errors.New("give --nodes or --source")
	}
	return out, src, nil
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }
