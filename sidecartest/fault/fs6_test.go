//go:build sidecar_testhooks

// FS-6 on T2 (EVS1-M2-41): the registered case under every rule §22.8 gives the row, and each clause of fs6.go under
// the same rules. The schedules hold evs instances and the shred at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs6(t *testing.T) {
	RunRow(t, "FS-6", "", nil)
}

func TestFs6SevenDayStart(t *testing.T) {
	RunClause(t, "FS-6", "seven-day start", Fs6SevenDayStart, nil)
}

func TestFs6KilledAtEachPhase(t *testing.T) {
	RunClause(t, "FS-6", "killed at each phase", Fs6KilledAtEachPhase, nil)
}

func TestFs6StaleJob(t *testing.T) {
	RunClause(t, "FS-6", "stale job", Fs6StaleJob, nil)
}
