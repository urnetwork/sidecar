//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// Under the tag, the barrier a writer's plan passes between reading the config head and judging under the follow lock
// whether the log moved (config_writer.plan.tip, keyed by the network) is where an entry landing moves the tip under
// the plan: a schedule holding a save's first plan there while a statement lands and its client applies it sees the
// save plan again, pass the barrier once more, and land on the new tip.

package sidecar_test

import (
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A save held at its plan's tip barrier while a member is admitted and applied plans again and lands past the member.
func TestASaveHeldAtItsPlanTipBarrierWhileAStatementLandsLandsOnTheNewTip(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	writer := world.tipMovedWriter(client, world.heads.For(world.owner.sidecarId, world.owner.key), nil, nil)
	networkId := world.networkId.String()
	var stateLock sync.Mutex
	passes := 0
	var late *bridge.AuthPin
	t.Cleanup(func() { sidecar.SetTestHooks(nil) })
	sidecar.SetTestHooks(&sidecar.TestHooks{Barrier: func(name string, key string) {
		if name != sidecar.ConfigWriterBarrierPlanTip || key != networkId {
			return
		}
		stateLock.Lock()
		passes += 1
		first := passes == 1
		stateLock.Unlock()
		if first {
			pin := world.landAndApply(world.ctx, client, "late")
			stateLock.Lock()
			late = pin
			stateLock.Unlock()
		}
	}})
	edits := 0
	pin, err := writer.SaveHead(world.ctx, testTipMovedEdit(&edits))
	sidecar.SetTestHooks(nil)
	if err != nil {
		t.Fatalf("the save: %v", err)
	}
	stateLock.Lock()
	defer stateLock.Unlock()
	if late == nil || passes != 2 || edits != 1 {
		t.Fatalf("the barrier passed %d times, the edit made %d times, a statement landed: %v", passes, edits, late != nil)
	}
	if pin.GetVersion() != late.GetVersion()+1 {
		t.Fatalf("the base landed at %d, the statement at %d", pin.GetVersion(), late.GetVersion())
	}
	if state := world.caughtUp(client); state.Base().GetVersion() != pin.GetVersion() || state.Member(testWriterId("late")) == nil {
		t.Fatalf("the client's base at %d", state.Base().GetVersion())
	}
}
