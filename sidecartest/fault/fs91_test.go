//go:build sidecar_testhooks

// FS-91's races (a) and (b) on T2 (EVS2-M10-31): the reuse copy released after the DROP beside its twin, the copy
// released before it, and the copy released within §11.8's window after it (fs91.go), under every rule §22.8 gives
// the row; and on the last run, FI-27 held to the window and to a push validated before the fence (QD-1105). The
// schedules hold an evs instance at a barrier, so this needs the sidecar_testhooks tag.

package fault

import (
	"context"
	"errors"
	"slices"
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

// FI-27 lets the copy through only on a push validated before the fence (QD-1105): the same run, with the ledger's
// record of the copy's push moved past the DROP's head write right after its 200, as a push that reached evs after
// the fence reads, is a violation at that step, the copy still committed within the window.
func TestFs91WithinTheWindowIsHeldToAPushValidatedBeforeTheFence(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	var moved *Step
	schedule := fs91Schedule(net, fs91ReleaseWithinTheWindow, func(world *EvsWorld, posted *EvsWorldPosted) []*Step {
		moved = &Step{Actor: "check", Action: fs91ArrivesNow(world, posted)}
		return []*Step{moved}
	})
	result := Run(t.Context(), schedule, net)
	fiRequireViolation(t, result, slices.Index(schedule.Steps, moved), "FI-27", "no version commits naming a listed version as a reuse source after its fence")
}

// A step action: every attempt of posted's push arrives, in the ledger's record, at the blob history as it stands now,
// past every request before this step.
func fs91ArrivesNow(world *EvsWorld, posted *EvsWorldPosted) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		arrival := net.BlobHistoryCount()
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		moved := false
		for _, attempt := range world.attempts {
			if attempt.PushId == posted.PushId {
				attempt.StoreArrival = arrival
				moved = true
			}
		}
		if !moved {
			return errors.New("the copy's push made no attempt")
		}
		return nil
	}
}
