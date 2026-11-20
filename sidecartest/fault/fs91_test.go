//go:build sidecar_testhooks

// FS-91's races (a), (b) and (c)'s cached head on T2 (EVS2-M10-31): the reuse copy released after the DROP beside its
// twin, the copy released before it, the copy released within §11.8's window after it, and the copy validated after
// the DROP on a cached head from before it (fs91.go), under every rule §22.8 gives the row; on the within-window run,
// FI-27 held to the window and to a push validated before the fence (QD-1105); and on the cached-head run, FI-27 held
// to the cache's age and to the push's own read of the cached head (QD-1146). The held schedules hold an evs instance
// at a barrier, so this needs the sidecar_testhooks tag.

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

func TestFs91OnACachedHead(t *testing.T) {
	RunClause(t, "FS-91", "on a cached head", Fs91ValidatedOnACachedHead, nil)
}

// FI-27 lets the cached-head copy through only on an entry younger than §11.9's cache age when the push read it
// (QD-1146): read with an age of 1 min, the same run, whose copy reads an entry written 2 min before, is a violation
// where the copy commits.
func TestFs91OnACachedHeadIsHeldToTheCacheAge(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	settings := DefaultFi27Settings()
	settings.HeadCacheServeAge = time.Minute
	SetFi27Settings(net, settings)
	var after *Step
	schedule := fs91Schedule(net, fs91ValidatedOnACachedHead, func(world *EvsWorld, posted *EvsWorldPosted) []*Step {
		after = &Step{Actor: "check", Action: func(ctx context.Context, net *Net) error { return nil }}
		return []*Step{after}
	})
	result := Run(t.Context(), schedule, net)
	// the copy's post comes right before its 200's check, which comes right before after
	fiRequireViolation(t, result, slices.Index(schedule.Steps, after)-2, "FI-27", "no version commits naming a listed version as a reuse source after its fence")
}

// FI-27 lets the cached-head copy through only on a cached read its own push made (QD-1146): the same run, with the
// ledger's record of the copy's arrival moved past its reads and the DROP's head write right after its 200, as a push
// validated on the cluster's head, which shows the DROP, reads, is a violation at that step, the copy still having
// committed.
func TestFs91OnACachedHeadIsHeldToItsRead(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	var moved *Step
	schedule := fs91Schedule(net, fs91ValidatedOnACachedHead, func(world *EvsWorld, posted *EvsWorldPosted) []*Step {
		moved = &Step{Actor: "check", Action: fs91ArrivesNow(world, posted)}
		return []*Step{moved}
	})
	result := Run(t.Context(), schedule, net)
	fiRequireViolation(t, result, slices.Index(schedule.Steps, moved), "FI-27", "no version commits naming a listed version as a reuse source after its fence")
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

// A step action: every attempt of posted's push arrives, in the ledger's record, at the blob history and the head
// cache's record as they stand now, past every request before this step.
func fs91ArrivesNow(world *EvsWorld, posted *EvsWorldPosted) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		arrival := net.BlobHistoryCount()
		cacheArrival := net.HeadCacheHistoryCount()
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		moved := false
		for _, attempt := range world.attempts {
			if attempt.PushId == posted.PushId {
				attempt.StoreArrival = arrival
				attempt.CacheArrival = cacheArrival
				moved = true
			}
		}
		if !moved {
			return errors.New("the copy's push made no attempt")
		}
		return nil
	}
}
