//go:build !sidecar_http && !ios_extension

// The order in which the gate cache tells what it installed, in the race tip-check caught at sidecar ed6b9300
// (sidecartest's TestGkmReconcilerStateIsToldOnceTheGateInstalls): one entry reaches Changed twice, as api's script
// INCRs {acl_}v and then EXPIREs it and FakeRedis publishes both on a key's first increment, and the second lands after
// the first load took its due, so one more load is owed; the log moves before that load reads it. Each install is told
// once, after its snapshot and the sidecar index are in place, and OnLoad comes after the tell; the owed load tells the
// moved state; a load at the held position tells nothing. CloseAndWait returns only once every loader has, so nothing
// is told or loaded after it, and a closed cache starts no load.
//
// A held read stands for the scheduler's luck: no sleeps. acl_gate_loader_order_hooks_test.go holds the same order at
// the install's own barriers, in sidecar_testhooks builds.

package sidecar

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the cache did on a network's loading goroutine, in the order it did it: an install callback's tell, or OnLoad.
type aclGateLoaderOrderEvent struct {
	told bool
	pin  *bridge.AuthPin
	err  error
	// for a tell: the snapshot told, what State answered inside the callback, and whether the index then held the
	// sidecar the test watches
	snapshot *AclGateSnapshot
	current  *AclGateSnapshot
	indexed  bool
}

// A cache over source, PollInterval and FailureBackoff off, whose install callback and OnLoad report on one channel in
// the order the cache calls them; the callback reads State and whether the index holds watchedSidecarId as it is told.
// The test's cleanup closes it and waits for its loaders.
func newAclGateLoaderOrderCache(t *testing.T, source AclGateSource, watchedSidecarId Id) (*AclGateCache, chan aclGateLoaderOrderEvent) {
	settings := DefaultAclGateSettings()
	settings.Log = NewNoopLogger()
	settings.PollInterval = 0
	settings.FailureBackoff = 0
	events := make(chan aclGateLoaderOrderEvent, 64)
	settings.OnLoad = func(networkId Id, pin *bridge.AuthPin, err error) {
		events <- aclGateLoaderOrderEvent{pin: pin, err: err}
	}
	cache := NewAclGateCache(context.Background(), source, newAclGateTestClock(), settings)
	t.Cleanup(cache.CloseAndWait)
	cache.AddInstallCallback(func(networkId Id, snapshot *AclGateSnapshot) {
		current, _ := cache.State(networkId)
		_, indexed := cache.SidecarNetwork(watchedSidecarId)
		events <- aclGateLoaderOrderEvent{told: true, pin: snapshot.Pin, snapshot: snapshot, current: current, indexed: indexed}
	})
	return cache, events
}

// Fails the test unless the cache's next event is a tell (told) or a clean load, at pin, and a tell's callback read
// the snapshot it was told from State and found the watched sidecar indexed exactly when indexed.
func aclGateLoaderOrderExpect(t *testing.T, events chan aclGateLoaderOrderEvent, told bool, pin *bridge.AuthPin, indexed bool) {
	t.Helper()
	var event aclGateLoaderOrderEvent
	select {
	case event = <-events:
	case <-time.After(30 * time.Second):
		t.Fatalf("no event, want told %t at %d", told, pin.GetVersion())
	}
	if event.told != told || !proto.Equal(event.pin, pin) {
		t.Fatalf("told %t at %d, want told %t at %d", event.told, event.pin.GetVersion(), told, pin.GetVersion())
	}
	if !told {
		if event.err != nil {
			t.Fatalf("the load at %d: %v", pin.GetVersion(), event.err)
		}
		return
	}
	if event.current != event.snapshot {
		t.Errorf("told %d while State answered %d", pin.GetVersion(), event.current.Pin.GetVersion())
	}
	if event.indexed != indexed {
		t.Errorf("told %d with the watched sidecar indexed %t, want %t", pin.GetVersion(), event.indexed, indexed)
	}
}

// The race's order: the first load's read is held with the log as it stood, a second trigger lands after that load
// took its due, and the log moves before the owed load reads. The first install is told the held position, the owed
// load the moved one, each after its snapshot and the index moved and before its OnLoad; a load at the held position
// tells nothing; and with every loader returned, nothing more was told or loaded.
func TestAclGateOwedLoadTellsTheMovedStateAfterItsInstall(t *testing.T) {
	net := newTestConfigNet(t)
	source := newAclGateTestSource()
	source.publish(net)
	source.hold = make(chan struct{})
	held := net.log.Pin()
	// the device the moved log admits, so only its state holds the row
	lateSidecarId := testConfigId("owed load device")
	cache, events := newAclGateLoaderOrderCache(t, source, lateSidecarId)

	// the entry's first event: the load's read takes the log as it stands, and is held
	cache.Changed(net.networkId)
	<-source.started
	// its second event, after that load took its due: one more load is owed
	cache.Changed(net.networkId)
	// the log moves before the owed load reads it
	net.admitMemberDevice("owed load")
	source.publish(net)
	moved := net.log.Pin()
	if moved.GetVersion() <= held.GetVersion() {
		t.Fatalf("the log did not move: %d to %d", held.GetVersion(), moved.GetVersion())
	}
	close(source.hold)

	aclGateLoaderOrderExpect(t, events, true, held, false)
	aclGateLoaderOrderExpect(t, events, false, held, false)
	aclGateLoaderOrderExpect(t, events, true, moved, true)
	aclGateLoaderOrderExpect(t, events, false, moved, false)

	// a trigger with nothing new: a load, and no tell
	cache.Changed(net.networkId)
	aclGateLoaderOrderExpect(t, events, false, moved, false)

	cache.CloseAndWait()
	select {
	case event := <-events:
		t.Fatalf("an event after every loader returned: told %t at %d", event.told, event.pin.GetVersion())
	default:
	}
	if calls := source.calls(); calls != 3 {
		t.Errorf("%d reads, want the first load's, the owed load's and the last", calls)
	}
}

// CloseAndWait ends a load held in its source, whose OnLoad has run by the time it returns, and the poll; a closed
// cache then starts no load for a trigger, a new network or a resync, and a second CloseAndWait returns at once.
func TestAclGateCloseAndWaitReturnsAfterEveryLoader(t *testing.T) {
	net := newTestConfigNet(t)
	source := newAclGateTestSource()
	source.publish(net)
	// never released: only the close ends the read
	source.hold = make(chan struct{})
	clock := newAclGateTestClock()
	settings := DefaultAclGateSettings()
	settings.Log = NewNoopLogger()
	settings.FailureBackoff = 0
	// written on the loader's goroutine, read once CloseAndWait has waited for it
	loadCount := 0
	var loadErr error
	settings.OnLoad = func(networkId Id, pin *bridge.AuthPin, err error) {
		loadCount += 1
		loadErr = err
	}
	cache := NewAclGateCache(context.Background(), source, clock, settings)
	// the poll waits on the clock
	<-clock.armed
	cache.Changed(net.networkId)
	<-source.started

	cache.CloseAndWait()
	if loadCount != 1 || !errors.Is(loadErr, context.Canceled) {
		t.Fatalf("after the wait: %d loads, %v", loadCount, loadErr)
	}

	cache.Changed(net.networkId)
	cache.Changed(NewId())
	cache.Resync()
	cache.CloseAndWait()
	if loadCount != 1 || source.calls() != 1 {
		t.Errorf("a closed cache loaded: %d loads, %d reads", loadCount, source.calls())
	}
	if snapshot, status := cache.State(net.networkId); snapshot != nil || status != AclGateNotLoaded {
		t.Errorf("after the close: %v, %d", snapshot, status)
	}
}
