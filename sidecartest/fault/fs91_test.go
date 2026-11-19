//go:build sidecar_testhooks

// FS-91's races (a) and (b) on T2 (EVS2-M10-31): the reuse copy released after the DROP beside its twin, the copy
// released before it, and the copy released within §11.8's window after it (fs91.go), under every rule §22.8 gives
// the row. The schedules hold an evs instance at a barrier, so this needs the sidecar_testhooks tag.

package fault

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs91(t *testing.T) {
	RunRow(t, "FS-91", "", nil)
}

func TestFs91WithinTheWindow(t *testing.T) {
	RunClause(t, "FS-91", "within the window", Fs91ReleasedWithinTheWindow, nil)
}

// FI-27 lets the copy through only within §11.8's window (QD-1105): read with a window of 1 s, the same run, whose
// copy commits 2 s after the DROP, is a violation where the copy commits.
func TestFs91WithinTheWindowIsHeldToTheWindow(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	settings := DefaultFi27Settings()
	settings.StepSevenWindow = time.Second
	SetFi27Settings(net, settings)
	result := Run(t.Context(), Fs91ReleasedWithinTheWindow(net), net)
	fiRequireViolation(t, result, result.FailedStep, "FI-27", "no version commits naming a listed version as a reuse source after its fence")
}
