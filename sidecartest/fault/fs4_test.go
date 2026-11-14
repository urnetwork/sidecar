//go:build sidecar_testhooks

// FS-4 on T2 (EVS1-M2-41): the registered case under every rule §22.8 gives the row, and the three-source clause
// (fs4_sources.go) and the batched-epoch clauses (fs4_batched.go), the second reading before the copy (QD-666), under
// the same rules. The schedules hold evs instances at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs4(t *testing.T) {
	RunRow(t, "FS-4", "", nil)
}

func TestFs4ThreeSources(t *testing.T) {
	RunClause(t, "FS-4", "three sources", Fs4ThreeSources, nil)
}

func TestFs4BatchedEpoch(t *testing.T) {
	RunClause(t, "FS-4", "batched epoch", Fs4BatchedEpoch, nil)
}

func TestFs4BatchedEpochReadBeforeCopy(t *testing.T) {
	RunClause(t, "FS-4", "batched epoch read before copy", Fs4BatchedEpochReadBeforeCopy, nil)
}
