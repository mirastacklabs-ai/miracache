package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrBusy: another writer holds the audit directory.
var ErrBusy = errors.New("audit: directory is locked by another writer")

// ErrTooLarge: the entry's line exceeds MaxLineBytes; nothing was written.
var ErrTooLarge = errors.New("audit: entry too large")

const maxRecoverBytes = 512 << 20

// Config configures a Writer.
type Config struct {
	Dir           string // created (one level, 0700) if missing
	Src           Source
	MaxBytes      uint64           // rotate above this (default 64 MiB)
	MaxTotalBytes uint64           // default 1 GiB; MaxBytes is clamped to a quarter of it
	Now           func() time.Time // default time.Now
}

// Writer is the single-writer append-only log of the controller; every entry is fsynced.
type Writer struct {
	mu       sync.Mutex
	cfg      Config
	maxBytes uint64
	maxTotal uint64
	lock     *os.File
	f        *os.File
	curFirst uint64
	curSize  uint64
	seq      uint64
	head     string
	recov    uint64
	broken   bool
}

func fileName(first uint64) string { return "audit-" + strconv.FormatUint(first, 10) + ".jsonl" }

func parseName(base string) (uint64, bool) {
	if !strings.HasPrefix(base, "audit-") || !strings.HasSuffix(base, ".jsonl") {
		return 0, false
	}
	n := base[6 : len(base)-6]
	v, err := strconv.ParseUint(n, 10, 64)
	if err != nil || v == 0 || strconv.FormatUint(v, 10) != n {
		return 0, false
	}
	return v, true
}

// ListFiles returns the paths of audit-<first seq>.jsonl in dir, ordered by first seq.
func ListFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type pf struct {
		first uint64
		path  string
	}
	var v []pf
	for _, e := range ents {
		if first, ok := parseName(e.Name()); ok && e.Type().IsRegular() {
			v = append(v, pf{first, filepath.Join(dir, e.Name())})
		}
	}
	sort.Slice(v, func(i, j int) bool { return v[i].first < v[j].first })
	out := make([]string, len(v))
	for i := range v {
		out[i] = v[i].path
	}
	return out, nil
}

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// Open takes the directory lock, recovers the tail (a partial or unverifiable tail is dropped and
// an audit.recover entry is written) and returns the writer.
func Open(cfg Config) (*Writer, error) {
	if cfg.Dir == "" {
		return nil, errors.New("audit: dir empty")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = 64 << 20
	}
	if cfg.MaxTotalBytes == 0 {
		cfg.MaxTotalBytes = 1 << 30
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, err
	}
	lock, err := os.Open(cfg.Dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	w := &Writer{cfg: cfg, lock: lock, head: GenesisPrev}
	w.maxTotal = cfg.MaxTotalBytes
	w.maxBytes = min(cfg.MaxBytes, w.maxTotal/4)
	if w.maxBytes == 0 {
		w.maxBytes = 1
	}
	if err := w.recover(); err != nil {
		lock.Close()
		return nil, err
	}
	return w, nil
}

// Close syncs and releases the lock.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		_ = w.f.Sync()
		w.f.Close()
		w.f = nil
	}
	if w.lock != nil {
		err := w.lock.Close()
		w.lock = nil
		return err
	}
	return nil
}

// Seq is the last written seq (0 = empty log); Head is the last hash (genesis zeros when empty).
func (w *Writer) Seq() uint64  { w.mu.Lock(); defer w.mu.Unlock(); return w.seq }
func (w *Writer) Head() string { w.mu.Lock(); defer w.mu.Unlock(); return w.head }

// RecoveredBytes is how many bytes Open dropped from a partial tail.
func (w *Writer) RecoveredBytes() uint64 { return w.recov }

type prepared struct {
	line []byte // with newline
	hash string
}

func (w *Writer) prepare(e Entry) (prepared, error) {
	body := Body(w.cfg.Src, w.seq+1, w.cfg.Now().UnixMilli(), e, w.head)
	line, hash := Seal(body)
	if len(line) > MaxLineBytes {
		return prepared{}, ErrTooLarge
	}
	return prepared{append(line, '\n'), hash}, nil
}

// writeLine appends p at offset `at` of the current file and fsyncs; on a failed write nothing
// advances (the file is cut back, or the writer reopens through recovery next time).
func (w *Writer) writeLine(p prepared) error {
	if _, err := w.f.Write(p.line); err != nil {
		if terr := w.f.Truncate(int64(w.curSize)); terr != nil {
			w.broken = true
		}
		return err
	}
	w.seq++
	w.head = p.hash
	w.curSize += uint64(len(p.line))
	return w.f.Sync()
}

func (w *Writer) openNew(first uint64) error {
	f, err := os.OpenFile(filepath.Join(w.cfg.Dir, fileName(first)), os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	w.f, w.curFirst, w.curSize = f, first, 0
	return nil
}

// Append writes one entry (rotating first when the file would pass MaxBytes) and fsyncs.
func (w *Writer) Append(e Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.lock == nil {
		return errors.New("audit: closed")
	}
	if w.broken {
		if err := w.recover(); err != nil {
			return err
		}
		w.broken = false
	}
	if w.f == nil {
		if err := w.openNew(w.seq + 1); err != nil {
			return err
		}
		syncDir(w.cfg.Dir)
	}
	p, err := w.prepare(e)
	if err != nil {
		return err
	}
	if w.curSize > 0 && w.curSize+uint64(len(p.line)) > w.maxBytes {
		if err := w.rotate(); err != nil {
			return err
		}
		if p, err = w.prepare(e); err != nil {
			return err
		}
	}
	return w.writeLine(p)
}

func (w *Writer) rotate() error {
	// The old file must be durable before the new one exists.
	if err := w.f.Sync(); err != nil {
		return err
	}
	oldFirst, oldSeq, oldF := w.curFirst, w.seq, w.f
	if err := w.openNew(oldSeq + 1); err != nil {
		w.f, w.curFirst = oldF, oldFirst
		return err
	}
	newF := w.f
	r := Entry{Actor: "local", Action: "audit.rotate", Target: fileName(oldSeq + 1), Result: "ok",
		Reason: "max_bytes", Detail: []Field{{"prev_file", fileName(oldFirst)}}}
	p, err := w.prepare(r)
	if err == nil {
		err = w.writeLine(p)
	}
	if err != nil {
		newF.Close()
		_ = os.Remove(filepath.Join(w.cfg.Dir, fileName(oldSeq+1)))
		w.f, w.curFirst = oldF, oldFirst
		w.curSize = fileSize(oldF)
		return err
	}
	oldF.Close()
	syncDir(w.cfg.Dir)
	return w.enforceTotal()
}

func fileSize(f *os.File) uint64 {
	if st, err := f.Stat(); err == nil {
		return uint64(st.Size())
	}
	return 0
}

// enforceTotal keeps sum(files except the newest) + maxBytes <= maxTotal by deleting the oldest
// files, then writes audit.truncate.
func (w *Writer) enforceTotal() error {
	files, err := ListFiles(w.cfg.Dir)
	if err != nil {
		return err
	}
	if len(files) < 2 {
		return nil
	}
	sizes := make([]uint64, 0, len(files)-1)
	var sum uint64
	for _, p := range files[:len(files)-1] {
		st, err := os.Stat(p)
		if err != nil {
			return err
		}
		sizes = append(sizes, uint64(st.Size()))
		sum += sizes[len(sizes)-1]
	}
	del := 0
	for del < len(sizes) && sum+w.maxBytes > w.maxTotal {
		if err := os.Remove(files[del]); err != nil {
			return err
		}
		sum -= sizes[del]
		del++
	}
	if del == 0 {
		return nil
	}
	syncDir(w.cfg.Dir)
	kept, _ := parseName(filepath.Base(files[del]))
	t := Entry{Actor: "local", Action: "audit.truncate", Target: "audit", Result: "ok", Reason: "max_total_bytes",
		Detail: []Field{{"first_kept_seq", kept}, {"deleted_files", uint64(del)}}}
	p, err := w.prepare(t)
	if err != nil {
		return err
	}
	return w.writeLine(p)
}

// recover finds the last verifying line of the newest file, drops everything after it, falls back
// to the predecessor when a file is left empty, and writes audit.recover if anything was dropped.
func (w *Writer) recover() error {
	if w.f != nil {
		w.f.Close()
		w.f = nil
	}
	w.seq, w.head, w.curFirst, w.curSize = 0, GenesisPrev, 0, 0
	files, err := ListFiles(w.cfg.Dir)
	if err != nil {
		return err
	}
	var dropped uint64
	for len(files) > 0 {
		path := files[len(files)-1]
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		if st.Size() > maxRecoverBytes {
			return errors.New("audit: file too large to recover")
		}
		buf, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		size := len(buf)
		end := size
		var ck checked
		found := false
		for end > 0 {
			nl := lastIndexByte(buf[:end], '\n')
			if nl < 0 {
				end = 0
				break
			}
			end = nl + 1 // drop a partial tail
			prevNL := -1
			if end >= 2 {
				prevNL = lastIndexByte(buf[:end-1], '\n')
			}
			lstart := prevNL + 1
			if c, cerr := checkLine(buf[lstart : end-1]); cerr == "" {
				ck, found = c, true
				break
			}
			end = lstart // this line does not verify: drop it too
		}
		if end < size {
			dropped += uint64(size - end)
			if err := os.Truncate(path, int64(end)); err != nil {
				return err
			}
		}
		if !found {
			if err := os.Remove(path); err != nil {
				return err
			}
			syncDir(w.cfg.Dir)
			files = files[:len(files)-1]
			continue
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			return err
		}
		_ = f.Sync()
		first, _ := parseName(filepath.Base(path))
		w.f, w.curFirst, w.curSize, w.seq, w.head = f, first, uint64(end), ck.seq, ck.hash
		break
	}
	if dropped > 0 {
		w.recov += dropped
		if w.f == nil {
			if err := w.openNew(1); err != nil {
				return err
			}
		}
		p, err := w.prepare(Entry{Actor: "local", Action: "audit.recover", Target: "audit", Result: "ok",
			Reason: "partial_tail", Detail: []Field{{"dropped_bytes", dropped}}})
		if err != nil {
			return err
		}
		if err := w.writeLine(p); err != nil {
			return fmt.Errorf("audit: recover entry: %w", err)
		}
	}
	if w.f != nil {
		return w.enforceTotal()
	}
	return nil
}

func lastIndexByte(b []byte, c byte) int {
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == c {
			return i
		}
	}
	return -1
}
