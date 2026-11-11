//go:build sidecar_testhooks

// FS-58 on T2 (EVS1-M2-41): the registered case under every rule §22.8 gives the row, and each clause of fs58.go under
// the same rules. The schedules hold evs instances and folds at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs58(t *testing.T) {
	RunRow(t, "FS-58", "", nil)
}

func TestFs58FoldKilledAndRaced(t *testing.T) {
	RunClause(t, "FS-58", "folds killed and raced", Fs58FoldKilledAndRaced, nil)
}
