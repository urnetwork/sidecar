//go:build sidecar_testhooks

package fault

// FS-97's resync-during-a-retry row (TestFs97AWorkerThatResyncsBeforeThePostOrDuringARetryIsNotRevoked) with the
// owner's device's first generation's repost of pending statements held at its start (sidecar_generation.go's
// sidecar.generation.repost.before) until an admission act's post has failed, then run to its end before the Worker
// resyncs: the repost posts nothing of an act kept after its start, so the stale revocation the resync then drops never
// lands, and the row's retry lands the admission alone. Before, a repost the scheduler ran that late read the act's
// statements and posted the revocation while the Worker was still stale, which is how the row once failed under
// landcheck's load ("no verdict at 6": the revocation landed after the retry's admission and the row's sync). Nothing
// sleeps: the repost is held at its barriers until the schedule lets it go.

import (
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The device's repost barriers (sidecar_generation.go).
const (
	fs97RepostBefore = "sidecar.generation.repost.before"
	fs97RepostAfter  = "sidecar.generation.repost.after"
)

// A repost the scheduler runs only after an admission act's post failed posts none of that act's statements, and the
// retry after the Worker resyncs lands the admission alone.
func TestFs97ARepostRunLateLeavesTheActToItsRetry(t *testing.T) {
	var barriers *sidecartest.BarrierDriver
	world := newFs97WorldOn(t, func(net *sidecartest.Net) {
		// the device's first generation is the only one in the world, so its repost is the first arrival
		barriers = net.Barriers()
		if err := barriers.Arm(fs97RepostBefore, "", 0); err != nil {
			t.Fatal(err)
		}
	})
	if err := barriers.AwaitHeld(world.ctx, fs97RepostBefore, ""); err != nil {
		t.Fatal(err)
	}
	early := world.enroll("owner page worker early")
	world.groups.Advance(fs97StaleAfter)
	world.setLeaves(early.SidecarId, sidecar.SidecarStaleLeafRemoved, world.groups.Now().Add(-fs97StaleAfter))
	tip := world.suite.Tip().GetVersion()
	if _, err := world.net.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpHttp, KeyPrefix: "/network/config/delta", Result: sidecartest.FailBeforeApply,
	}); err != nil {
		t.Fatal(err)
	}
	second := world.suite.Device("owner page worker second", world.memberId)
	if err := world.admit(second); !errors.Is(err, sidecar.ErrSidecarActPending) {
		t.Fatalf("a post that never reached api: %v", err)
	}

	// the repost goes on now, the Worker still stale, and runs to its end
	if err := barriers.Arm(fs97RepostAfter, "", 0); err != nil {
		t.Fatal(err)
	}
	if err := barriers.Release(fs97RepostBefore); err != nil {
		t.Fatal(err)
	}
	if err := barriers.AwaitHeld(world.ctx, fs97RepostAfter, ""); err != nil {
		t.Fatal(err)
	}
	if err := barriers.Release(fs97RepostAfter); err != nil {
		t.Fatal(err)
	}
	world.suite.Sync()
	if landed := world.landedAfter(tip); len(landed) != 0 {
		t.Fatalf("the repost landed %+v of an act kept after its start", landed)
	}

	// the Worker resyncs, and the row's retry drops the revocation and lands the admission alone
	world.setLeaves(early.SidecarId, sidecar.SidecarStaleLeafLive, world.groups.Now())
	if err := world.device.Sidecar().PostPendingStatements(world.ctx); err != nil {
		t.Fatal(err)
	}
	world.suite.Sync()
	world.requireAct("resynced during the retry", world.landedAfter(tip), nil, second.SidecarId)
}
