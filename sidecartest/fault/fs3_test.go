//go:build sidecar_testhooks

// FS-3 on T2 (EVS1-M2-40): the registered case under every rule §22.8 gives the row, and the step-7 clause (fs3.go)
// under the same rules. The schedules hold evs instances at barriers, so they need the sidecar_testhooks tag.

package fault

import (
	"testing"
)

func TestFs3(t *testing.T) {
	RunRow(t, "FS-3", "", nil)
}

// A's step 7 past 5 s of its step 4, held 25 s while a reader leaves with no other commit: its rerun judges 5d
// against the newest gate view evs holds and refuses GATE_CLOSED (§11.8's timing row; QD-660). With the view bound
// at arrival the rerun commits under the excluded generation.
func TestFs3StepSevenPastFiveSeconds(t *testing.T) {
	RunClause(t, "FS-3", "step 7 past 5 s", Fs3StepSevenPastFiveSeconds, nil)
}
