//go:build sidecar_testhooks

// FS-9 on T2 (EVS1-M2-41): the registered case under every rule §22.8 gives the row, and the unfolded listing clause
// (fs9.go) under the same rules. The schedules run the evs world's instances under the barrier driver, so they need
// the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs9(t *testing.T) {
	RunRow(t, "FS-9", "", nil)
}

// A directory at its bound in one push in parts, listed whole and a child refused 409 DIRECTORY_FULL before any fold
// (QD-662). Before the read reply carried its delta in a frame of its own, every run's listing ended before its last
// frame.
//
// The push in parts holds writerA's baton from its build through all four parts, which the evs world serves on
// writerA's own goroutines (EvsWorld.serveHelper) with no actor waiting behind it: one span of about 0.5 s of CPU, half
// of step 2's. On a host at load 100 to 150 on 14 cores that span outran the driver's 2 s stall bound while the parts'
// barriers kept passing, and until the driver told a working holder from a blocked one this clause ran with a bound of
// its own, 8 s. It runs on the default now: with the bound at 5 ms, a hundredth of the span, every one of its runs
// passed with writerA and evs1 found working and the baton kept, where the bound alone had stalled all of them.
func TestFs9UnfoldedListing(t *testing.T) {
	RunClause(t, "FS-9", "unfolded listing", Fs9UnfoldedListing, nil)
}
