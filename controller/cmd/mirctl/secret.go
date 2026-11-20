package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
)

// The engine-native deployment secret file (client/scope/engine_native.cpp load_secret_file,
// python/miracache/preflight/secret.py, and the golden fixture):
//
//	# comment                (first non-blank char '#'; no inline comments)
//	current = <kver>         (decimal u32, non-zero, exactly once)
//	<kver> = <64 hex>        (decimal u32, non-zero, unique; hex is case-insensitive)
//
// Blank, space, tab and CR around lines, keys and values are ignored. The file must be a regular
// file with mode exactly 0600. mirctl writes it canonically (comments, current, kvers ascending,
// lower-case hex), through a tmp file in the same directory and a rename, and never prints
// a key.

const secretHeader = `# miracache engine-native secret file. Keep it mode 0600; never commit it.
# "current = <kver>" names the key version new scopes use; "<kver> = <64 hex>" are the 32-byte keys.
`

type secretFile struct {
	comments []string
	current  uint32
	keys     map[uint32]string // kver -> 64 lower-case hex
}

func parseU32(s string) (uint32, bool) {
	if len(s) == 0 || len(s) > 10 {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		v = v*10 + uint64(s[i]-'0')
	}
	if v == 0 || v > 0xffffffff {
		return 0, false
	}
	return uint32(v), true
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// parseSecretFile applies the loader's rules line for line.
func parseSecretFile(text string) (*secretFile, error) {
	f := &secretFile{keys: map[uint32]string{}}
	haveCurrent := false
	for n, raw := range strings.Split(text, "\n") {
		line := strings.Trim(raw, " \t\r")
		if line == "" {
			continue
		}
		if line[0] == '#' {
			f.comments = append(f.comments, line)
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected '<key> = <value>'", n+1)
		}
		k, v = strings.Trim(k, " \t\r"), strings.Trim(v, " \t\r")
		if k == "current" {
			if haveCurrent {
				return nil, fmt.Errorf("line %d: duplicate \"current\"", n+1)
			}
			c, ok := parseU32(v)
			if !ok {
				return nil, fmt.Errorf("line %d: current must be a non-zero decimal kver", n+1)
			}
			f.current, haveCurrent = c, true
			continue
		}
		kver, ok := parseU32(k)
		if !ok {
			return nil, fmt.Errorf("line %d: kver %q must be a non-zero decimal number", n+1, k)
		}
		if !isHex64(v) {
			return nil, fmt.Errorf("line %d: the secret for kver %s must be 32 bytes as 64 hex characters", n+1, k)
		}
		if _, dup := f.keys[kver]; dup {
			return nil, fmt.Errorf("line %d: duplicate kver %d", n+1, kver)
		}
		f.keys[kver] = strings.ToLower(v)
	}
	if !haveCurrent {
		return nil, errors.New(`secret file needs a "current = <kver>" line`)
	}
	if _, ok := f.keys[f.current]; !ok {
		return nil, fmt.Errorf("current kver %d has no secret entry", f.current)
	}
	return f, nil
}

// render writes the canonical form.
func (f *secretFile) render() []byte {
	var b strings.Builder
	for _, c := range f.comments {
		b.WriteString(c + "\n")
	}
	fmt.Fprintf(&b, "current = %d\n", f.current)
	kv := make([]uint32, 0, len(f.keys))
	for k := range f.keys {
		kv = append(kv, k)
	}
	sort.Slice(kv, func(i, j int) bool { return kv[i] < kv[j] })
	for _, k := range kv {
		fmt.Fprintf(&b, "%d = %s\n", k, f.keys[k])
	}
	return []byte(b.String())
}

func (a *app) newSecretKey() (string, error) {
	k := make([]byte, 32)
	if _, err := io.ReadFull(a.rand, k); err != nil {
		return "", err
	}
	return hex.EncodeToString(k), nil
}

// secretGen is `mirctl secret gen --out FILE [--kver N]`: a new file with one 32-byte key. It never
// overwrites an existing file.
func (a *app) secretGen(args []string) error {
	var out string
	var kver uint64 = 1
	fs := a.newFlags("secret gen")
	fs.StringVar(&out, "out", "", "secret file to create (required; must not exist)")
	fs.Uint64Var(&kver, "kver", 1, "key version (decimal u32, non-zero)")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if out == "" {
		return errors.New("--out is required")
	}
	if kver == 0 || kver > 0xffffffff {
		return errors.New("--kver must be in 1..4294967295")
	}
	key, err := a.newSecretKey()
	if err != nil {
		return err
	}
	f := &secretFile{comments: strings.Split(strings.TrimRight(secretHeader, "\n"), "\n"),
		current: uint32(kver), keys: map[uint32]string{uint32(kver): key}}
	if err := writeFileAtomic(out, f.render(), true); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "wrote %s (mode 0600): current=%d\n", out, kver)
	return nil
}

// secretAddKver is `mirctl secret add-kver --file FILE [--kver N] [--keep-current]`: adds a new key
// version (default: the highest + 1) and makes it current. Existing kvers stay, so scopes sealed
// under them still open. The file must be a valid secret file with mode 0600.
func (a *app) secretAddKver(args []string) error {
	var path string
	var kver uint64
	var keep bool
	fs := a.newFlags("secret add-kver")
	fs.StringVar(&path, "file", "", "existing secret file (required)")
	fs.Uint64Var(&kver, "kver", 0, "key version to add (default: highest + 1)")
	fs.BoolVar(&keep, "keep-current", false, "add the key but keep the current kver")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if path == "" {
		return errors.New("--file is required")
	}
	// Two add-kver runs on one file would each read the same highest kver and one would lose its
	// key: serialise them with an flock on a sidecar file (the secret itself is replaced by
	// rename, so it cannot carry the lock).
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close() // closing drops the flock
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	if st.Mode().Perm() != 0o600 {
		return fmt.Errorf("%s has mode %04o; it must be exactly 0600", path, st.Mode().Perm())
	}
	text, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f, err := parseSecretFile(string(text))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if kver == 0 {
		var hi uint32
		for k := range f.keys {
			hi = max(hi, k)
		}
		if hi == 0xffffffff {
			return errors.New("no kver above 4294967295")
		}
		kver = uint64(hi) + 1
	}
	if kver > 0xffffffff {
		return errors.New("--kver must be in 1..4294967295")
	}
	if _, dup := f.keys[uint32(kver)]; dup {
		return fmt.Errorf("kver %d already exists in %s", kver, path)
	}
	key, err := a.newSecretKey()
	if err != nil {
		return err
	}
	f.keys[uint32(kver)] = key
	if !keep {
		f.current = uint32(kver)
	}
	if err := writeFileAtomic(path, f.render(), false); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "added kver %d to %s: current=%d kvers=%d\n", kver, path, f.current, len(f.keys))
	return nil
}
