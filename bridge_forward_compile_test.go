// The Forwarder's transient compile on the root's fakes (BRIDGE-M8-05; DESIGN-DETAILS 4.2.4, 4.2.5): the admission
// rule's two refusals and their alarms, a kill at each step, the head a base names, and a store trimmed to its newest
// base's retention point.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A compile whose estimate is past the cap never runs: compile_over_budget is raised once, nothing is pending beyond
// the anchor, and no timer tries it again.
func TestACompileOverBudgetIsRefusedAndAlarmsOnce(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.settings.CompileMemoryMaxByteCount = 1
	forwarder := world.forwarder()
	status := forwarder.Status()
	if status.Admission != ForwarderCompileOverBudget || status.CompileRefusedCount != 1 || status.CompileCount != 0 || status.Decision.State != BridgeSinkPending {
		t.Fatalf("status %+v", status)
	}
	if !testForwarderAlarmStands(status, ForwarderAlarmCompileOverBudget) || world.stateCount() != 0 {
		t.Fatalf("no alarm, or a state: %v", world.events.list())
	}
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	world.net.consentedMember("one more entry")
	world.hint(forwarder)
	if status := forwarder.Status(); status.CompileRefusedCount != 2 || world.stateCount() != 0 {
		t.Fatalf("a later entry's compile: %+v", status)
	}
	if count := world.count(func(event string) bool { return event == "alarm "+ForwarderAlarmCompileOverBudget }); count != 1 {
		t.Errorf("compile_over_budget raised %d times", count)
	}
}

// A compile the heap ceiling defers keeps the state as it is and is retried at CompileRetryInterval, doubling;
// compile_deferred is raised once it has been deferred CompileDeferredAlarmTimeout, and the compile that fits runs and
// clears it.
func TestACompileUnderTheHeapCeilingIsDeferredThenRuns(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.settings.CompileHeapCeilingByteCount = 8 * 1024 * 1024
	world.heapInUse.Store(8 * 1024 * 1024)
	forwarder := world.forwarder()
	if status := forwarder.Status(); status.Admission != ForwarderCompileDeferred || status.CompileRefusedCount != 1 || len(status.Alarms) != 0 {
		t.Fatalf("status %+v", status)
	}
	refused := uint64(1)
	for _, wait := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute} {
		if testForwarderAlarmStands(forwarder.Status(), ForwarderAlarmCompileDeferred) {
			t.Fatalf("compile_deferred before its timeout, at the wait of %s", wait)
		}
		world.advance(forwarder, wait-time.Second)
		if got := forwarder.Status().CompileRefusedCount; got != refused {
			t.Fatalf("a retry before %s: %d", wait, got)
		}
		world.advance(forwarder, time.Second)
		refused += 1
		if got := forwarder.Status().CompileRefusedCount; got != refused {
			t.Fatalf("no retry at %s: %d", wait, got)
		}
	}
	if status := forwarder.Status(); !testForwarderAlarmStands(status, ForwarderAlarmCompileDeferred) || world.stateCount() != 0 || status.Decision.State != BridgeSinkPending {
		t.Fatalf("after %s deferred: %+v", world.settings.CompileDeferredAlarmTimeout, status)
	}
	world.heapInUse.Store(0)
	world.advance(forwarder, world.settings.CompileRetryMaxInterval)
	if status := forwarder.Status(); status.Admission != ForwarderCompileAdmitted || len(status.Alarms) != 0 || world.stateCount() != 1 {
		t.Fatalf("the compile that fits: %+v", status)
	}
}

// The trap: an error anywhere in a compile changes nothing. A Forwarder killed while it reads gkm, while it reads the
// head, as it hands the state, or before it records the compile leaves a store a new Forwarder follows and compiles
// from, and the sink with no state but a whole one.
func TestAKillAtEachCompileStepLeavesTheStoreLoadable(t *testing.T) {
	for _, step := range []string{"keys", "head", "hand", "record"} {
		world := newTestForwarderWorld(t)
		world.rotate(world.recipient())
		ctx, cancel := context.WithCancel(context.Background())
		killed := errors.New("the test killed the component")
		switch step {
		case "keys":
			world.gkm.onGenerations = func(ctx context.Context) error {
				cancel()
				return killed
			}
		case "head":
			world.forwardHeads.onRead = func(ctx context.Context) error {
				cancel()
				return killed
			}
		case "hand":
			world.sink.onState = func(state *bridge.BridgeState) error {
				cancel()
				return killed
			}
		case "record":
			world.forwardStore.onCreate = func(name string) error {
				if name != forwarderCompiledName {
					return nil
				}
				cancel()
				return killed
			}
		}
		forwarder := world.forwarderIn(ctx)
		<-forwarder.done
		wantStates := 0
		if step == "record" {
			wantStates = 1
		}
		if world.stateCount() != wantStates || len(world.stored(forwarderCompiledName)) != 0 {
			t.Fatalf("%s: the killed compile left %v and %v", step, world.events.list(), world.stored(""))
		}
		if _, inForce := forwarder.LinkTargets(); inForce && step != "record" {
			t.Fatalf("%s: a state in force", step)
		}

		world.gkm.onGenerations, world.forwardHeads.onRead, world.sink.onState, world.forwardStore.onCreate = nil, nil, nil, nil
		restarted := world.forwarder()
		status := restarted.Status()
		if !proto.Equal(status.CompiledPin, world.net.log.State().Pin()) || status.GenerationCount != 1 || len(world.stored(forwarderCompiledName)) != 1 {
			t.Fatalf("%s: the restart's status %+v", step, status)
		}
		if from, through, err := restarted.records.logRange(); err != nil || from != 1 || through != world.net.n {
			t.Fatalf("%s: the store's log is %d to %d: %v", step, from, through, err)
		}
		if _, inForce := restarted.LinkTargets(); !inForce {
			t.Fatalf("%s: no state in force after the restart", step)
		}
		restarted.Close()
		cancel()
	}
}

// Step 3: a head that is not the one the anchored network's base names is head_alarm and no state, and is not kept;
// the base's own head then compiles.
func TestACompileTakesOnlyTheHeadOfItsOwnNetwork(t *testing.T) {
	world := newTestForwarderWorld(t)
	other := newTestConfigNetNamed(t, "another")
	forged, err := NewConfigHead(map[string][]byte{ConfigHeadGenesisPath: other.signedGenesis})
	if err != nil {
		t.Fatal(err)
	}
	world.forwardHeads.forged.Store(forged)
	forwarder := world.forwarder()
	status := forwarder.Status()
	if world.stateCount() != 0 || status.CompileErrorCount != 1 || status.Decision.State != BridgeSinkPending || len(world.stored(forwarderHeadPrefix)) != 0 {
		t.Fatalf("another network's head: %+v, %v", status, world.events.list())
	}
	if world.count(func(event string) bool { return event == "head_alarm "+string(SidecarHeadAlarmFork) }) != 1 {
		t.Fatalf("no head_alarm: %v", world.events.list())
	}
	world.forwardHeads.forged.Store(nil)
	world.advance(forwarder, world.settings.CompileRetryInterval)
	if status := forwarder.Status(); world.stateCount() != 1 || status.CompileCount != 1 || len(world.stored(forwarderHeadPrefix)) != 1 {
		t.Fatalf("the base's own head: %+v", status)
	}
}

// A compile restores at the newest base with its tail, reads that base's head, and trims the store to the base's
// retention point, its rows and the newest heads; a restart compiles from what is left, and the links a folded
// address gives stand at every one.
func TestACompileRestoresAtTheNewestBaseAndTrimsTheStore(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.rotate(world.recipient())
	world.bind(world.peer)
	forwarder := world.forwarder()
	net := world.net
	linked := func(forwarder *Forwarder, what string) {
		t.Helper()
		targets, inForce := forwarder.LinkTargets()
		if status := forwarder.Status(); !inForce || !slices.Equal(targets, []Id{world.peer.sidecarId}) || status.CompiledPin.GetVersion() != net.n {
			t.Fatalf("%s: links %v in force %t, status %+v", what, targets, inForce, status)
		}
	}
	linked(forwarder, "at base 1")

	world.ledger.foldLedger(net.n, nil)
	world.hint(forwarder)
	linked(forwarder, "at base 2")
	if len(world.stored(forwarderRowsPrefix)) != 1 || len(world.stored(forwarderHeadPrefix)) != 2 || len(world.stored(forwarderLogPrefix)) != int(net.n) {
		t.Fatalf("after base 2 the store holds %v", world.stored(""))
	}
	second := net.n
	net.consentedMember("after base 2")
	world.ledger.foldLedger(net.n, nil)
	world.hint(forwarder)
	linked(forwarder, "at base 3")
	if len(world.stored(forwarderRowsPrefix)) != 1 || len(world.stored(forwarderHeadPrefix)) != 2 || len(world.stored(forwarderLogPrefix)) != int(net.n-second+1) {
		t.Fatalf("after base 3 the store holds %v", world.stored(""))
	}

	forwarder.Close()
	restarted := world.forwarder()
	net.consentedMember("after the restart")
	world.hint(restarted)
	linked(restarted, "after a restart")
	if status := restarted.Status(); status.CompileCount != 1 || status.CompileErrorCount != 0 {
		t.Errorf("the restart's compiles: %+v", status)
	}
}
