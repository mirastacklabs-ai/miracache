package api

import (
	"sort"
	"sync"
	"time"

	"miracache/controller/audit"
)

// coalescer folds denied calls into one entry per (actor, action, result) per second with a count.
// Beyond maxKeys distinct keys per second the rest fold into actor
// "(other)".
type coalescer struct {
	mu    sync.Mutex
	wins  map[string]*window
	ready []audit.Entry // finished windows replaced by a newer second before a flush
}

type window struct {
	second int64
	entry  audit.Entry
}

const maxCoalesceKeys = 1024

func newCoalescer() *coalescer { return &coalescer{wins: map[string]*window{}} }

func (c *coalescer) add(e audit.Entry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sec := now.Unix()
	key := e.Actor + "\x00" + e.Action + "\x00" + e.Result
	if w, ok := c.wins[key]; ok && w.second == sec {
		w.entry.Count++
		return
	} else if !ok && len(c.wins) >= maxCoalesceKeys {
		e.Actor = "(other)"
		key = "(other)\x00" + e.Action + "\x00" + e.Result
		if w, ok := c.wins[key]; ok && w.second == sec {
			w.entry.Count++
			return
		}
	}
	e.Count = 1
	if old, ok := c.wins[key]; ok {
		c.ready = append(c.ready, old.entry) // never overwrite an unflushed window: its count would be lost
	}
	c.wins[key] = &window{second: sec, entry: e}
}

// flush returns the entries of windows whose second ended before now's second (all of them with all).
func (c *coalescer) flush(now time.Time, all bool) []audit.Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.ready
	c.ready = nil
	for k, w := range c.wins {
		if all || w.second < now.Unix() {
			out = append(out, w.entry)
			delete(c.wins, k)
		}
	}
	sortEntries(out)
	return out
}

func sortEntries(es []audit.Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Actor != es[j].Actor {
			return es[i].Actor < es[j].Actor
		}
		return es[i].Target < es[j].Target
	})
}
