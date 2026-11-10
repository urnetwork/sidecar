//go:build sidecar_testhooks

// FS-57 on T2 (EVS1-M2-40): the registered case under every rule §22.8 gives the row, and each clause of fs57.go under the same rules. The schedules hold evs instances at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs57(t *testing.T) {
	RunRow(t, "FS-57", "", nil)
}

func TestFs57StoreUnreachableCommitsNothing(t *testing.T) {
	RunClause(t, "FS-57", "store unreachable", Fs57StoreUnreachable, nil)
}
