// SPDX-License-Identifier: Apache-2.0
package bundle

import "time"

// DefaultDropBeforeSkew is how far ahead of the wall clock a drop_before may be (publish.clock_skew_s).
const DefaultDropBeforeSkew = 300 * time.Second

// CheckDropBeforeNotFuture refuses a principal drop_before later than now + skew (reason schema). A
// future drop_before is stored max-only by every node but converted to the node clock once (clamped to
// "now"), so a later real cutoff below it would be a silent no-op. Parsing stays pure
// (no clock); this runs at publish time, and the memory node runs the same rule at apply time
// (control::check_drop_before_not_future). skew <= 0 means DefaultDropBeforeSkew.
func CheckDropBeforeNotFuture(s *Sec, now time.Time, skew time.Duration) error {
	if skew <= 0 {
		skew = DefaultDropBeforeSkew
	}
	for _, p := range s.Principals {
		if p.DropBefore == "" {
			continue
		}
		t, err := time.Parse("2006-01-02T15:04:05Z", p.DropBefore)
		if err != nil {
			return reject(ReasonSchema, "principal %q: drop_before: %v", p.Name, err)
		}
		if t.After(now.Add(skew)) {
			return reject(ReasonSchema, "principal %q: drop_before %s is later than now + %s", p.Name, p.DropBefore, skew)
		}
	}
	return nil
}
