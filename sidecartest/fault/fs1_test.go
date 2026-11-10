//go:build sidecar_testhooks

// FS-1 on T2 (EVS1-M2-40): the registered case under every rule §22.8 gives the row, and each clause of fs1.go under
// the same rules. The schedules hold evs instances at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs1(t *testing.T) {
	RunRow(t, "FS-1", "", nil)
}

func TestFs1ConcurrentRetriesCommitOnce(t *testing.T) {
	RunClause(t, "FS-1", "concurrent retries", Fs1ConcurrentRetries, nil)
}

func TestFs1UnknownDeletesNothing(t *testing.T) {
	RunClause(t, "FS-1", "unknown deletes nothing", Fs1UnknownDeletesNothing, nil)
}
