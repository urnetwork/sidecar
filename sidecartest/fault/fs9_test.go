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
func TestFs9UnfoldedListing(t *testing.T) {
	RunClause(t, "FS-9", "unfolded listing", Fs9UnfoldedListing, nil)
}
