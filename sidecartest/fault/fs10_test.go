//go:build sidecar_testhooks

// FS-10 on T2 (EVS1-M2-41): the registered case and its twin under every rule §22.8 gives the row, and the rollback
// clause of fs10.go under the same rules. The evs world's schedules run in the sidecar_testhooks build.

package fault

import (
	"testing"
)

func TestFs10(t *testing.T) {
	RunRow(t, "FS-10", "", nil)
}

func TestFs10RollbackRefused(t *testing.T) {
	RunClause(t, "FS-10", "rollback refused", Fs10RollbackRefused, nil)
}
