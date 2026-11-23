//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// Under the tag, the barrier a writer passes between its plan and its signing (config_writer.sign.tip, keyed by the
// network) is where an entry landing moves the tip between them: a schedule holding a save there while a rival
// writer's base lands sees the save plan again and land at that base without signing again, and one landing a
// statement at every pass sees the save keep its plan, pass the barrier again at each new tip, and give up once
// PublishAttemptCount plans met a moved tip.

package sidecar_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Installs a hook on the writer's signing barrier for world's network, which runs pass with each pass's number, from
// 1, and removes it at cleanup. A signing while a pass runs, a rival's that pass lands, is no pass: the barrier's key
// is the network, which the rival shares. Answers the passes so far.
func testSignStaleBarrier(t *testing.T, world *testWriterWorld, pass func(pass int)) func() int {
	networkId := world.networkId.String()
	var stateLock sync.Mutex
	passes, inside := 0, false
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != sidecar.ConfigWriterBarrierSignTip || key != networkId {
			return
		}
		current, nested := func() (int, bool) {
			stateLock.Lock()
			defer stateLock.Unlock()
			if inside {
				return 0, true
			}
			passes += 1
			inside = true
			return passes, false
		}()
		if nested {
			return
		}
		pass(current)
		stateLock.Lock()
		inside = false
		stateLock.Unlock()
	}})
	return func() int {
		stateLock.Lock()
		defer stateLock.Unlock()
		return passes
	}
}

// A save held at its signing barrier while a rival writer's save lands its base, on a head pushed past the save's,
// plans again, finds that base names a head past its push with the fold it would publish, and lands at it: it passes
// the barrier once and signs nothing more.
func TestASaveHeldAtItsSigningBarrierWhileARivalBaseLandsLandsAtThatBase(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	rival := world.signStaleRival()
	writer := world.tipMovedWriter(client, world.heads.For(world.owner.sidecarId, world.owner.key), nil, nil)
	var landedLock sync.Mutex
	var landed *bridge.AuthPin
	passes := testSignStaleBarrier(t, world, func(pass int) {
		if pass == 1 {
			pin := rival.land(client, testSignStaleRivalSave)
			landedLock.Lock()
			landed = pin
			landedLock.Unlock()
		}
	})
	edits := 0
	pin, err := writer.SaveHead(world.ctx, testTipMovedEdit(&edits))
	sidecar.SetTestHooks(nil)
	if err != nil {
		t.Fatalf("the save: %v", err)
	}
	landedLock.Lock()
	defer landedLock.Unlock()
	if landed == nil || passes() != 1 || edits != 1 {
		t.Fatalf("the barrier passed %d times, the edit made %d times, a rival base landed: %v", passes(), edits, landed != nil)
	}
	if pin.GetVersion() != landed.GetVersion() {
		t.Fatalf("the save answered the base at %d, the rival's landed at %d", pin.GetVersion(), landed.GetVersion())
	}
	if base := world.caughtUp(client).Base(); base.GetVersion() != landed.GetVersion() {
		t.Fatalf("a base at %d past the rival's at %d", base.GetVersion(), landed.GetVersion())
	}
}

// A save held at its signing barrier at every pass while a member is admitted and applied keeps its plan, which no base
// overtook, passes the barrier again at each new tip, and gives up once PublishAttemptCount plans met a moved tip, with
// ErrConfigTipMoved under ErrConfigWriterGaveUp: one edit, one push, no base, every statement landed.
func TestASaveWhoseTipMovesAtEverySigningGivesUpWithTipMoved(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	heads := world.tipMovedHeads()
	writer := world.tipMovedWriter(client, heads, nil, func(settings *sidecar.ConfigWriterSettings) {
		settings.PublishAttemptCount = 3
	})
	passes := testSignStaleBarrier(t, world, func(pass int) {
		world.landAndApply(world.ctx, client, fmt.Sprintf("late %d", pass))
	})
	versionBefore := world.heads.Version()
	edits := 0
	_, err := writer.SaveHead(testTipMovedSaveContext(world.ctx), testTipMovedEdit(&edits))
	sidecar.SetTestHooks(nil)
	if !errors.Is(err, sidecar.ErrConfigTipMoved) || !errors.Is(err, sidecar.ErrConfigWriterGaveUp) {
		t.Fatalf("a save whose tip kept moving: %v", err)
	}
	if reads := heads.readCount(); passes() != 3 || reads != 1 || edits != 1 {
		t.Fatalf("the barrier passed %d times, the save read the head %d times and made its edit %d times", passes(), reads, edits)
	}
	if version := world.heads.Version(); version != versionBefore+1 {
		t.Fatalf("the ref at %d, %d before the save", version, versionBefore)
	}
	state := world.caughtUp(client)
	if base := state.Base(); base.GetVersion() != 1 {
		t.Fatalf("a base at %d", base.GetVersion())
	}
	for pass := 1; pass <= 3; pass += 1 {
		if state.Member(testWriterId(fmt.Sprintf("late %d", pass))) == nil {
			t.Errorf("the statement at pass %d did not land", pass)
		}
	}
}
