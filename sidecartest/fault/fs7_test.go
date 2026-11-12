//go:build sidecar_testhooks

// FS-7 on T2 (EVS1-M2-40): the registered case under every rule §22.8 gives the row, and the evacuated-window clause
// (fs7.go) under the same rules. The schedules hold evs instances at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs7(t *testing.T) {
	RunRow(t, "FS-7", "", nil)
}

// A window version's record that evacuation moved, read by the reader's instance's newest rule through pidx/ before
// and after its restart (QD-664). Without the read route's fallback every run of the clause answers the reader 503.
func TestFs7EvacuatedWindowAfterRestart(t *testing.T) {
	RunClause(t, "FS-7", "evacuated window after a restart", Fs7EvacuatedWindowAfterRestart, nil)
}
