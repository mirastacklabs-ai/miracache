package bundle

import (
	"testing"
	"time"
)

func TestCheckDropBeforeNotFuture(t *testing.T) {
	now := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	mk := func(db string) *Sec { return &Sec{Principals: []Principal{{Name: "p", DropBefore: db}}} }
	for _, c := range []struct {
		db   string
		ok   bool
		name string
	}{
		{"", true, "none"},
		{"2026-11-11T00:00:00Z", true, "past"},
		{"2026-11-12T00:05:00Z", true, "exactly now+skew"},
		{"2026-11-12T00:05:01Z", false, "one second over"},
		{"2099-01-01T00:00:00Z", false, "far future"},
	} {
		err := CheckDropBeforeNotFuture(mk(c.db), now, 0)
		if c.ok != (err == nil) {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
		if err != nil && ReasonOf(err) != ReasonSchema {
			t.Errorf("%s: reason %q, want schema", c.name, ReasonOf(err))
		}
	}
}
