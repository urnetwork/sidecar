//go:build !sidecar_http && !js

// §5.9's Failed for a client generation's start on the network's subprotocol store (owner decision 616): the sidecar
// stays Offline at the generation with subprotocol_store_failed, raises refused once and waits for a wake, which
// retries, and the wake after the store reads again brings it online. The machine's half is here too: that reason is
// Offline's alone.

package sidecar

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

// A host whose store is the instance's, reporting no credential store on this machine, which counts the run loop's
// scans for one. The loop scans as its first pass ends and then each SyncRefetchInterval, an hour here, and reconciles
// again after each scan, so the first scan is when a failed start's second try comes.
type testScanCountingHost struct {
	store SidecarStore
	scans *MonitorValue[int]
}

func (self *testScanCountingHost) Store() SidecarStore {
	return self.store
}

func (self *testScanCountingHost) KeyStore() SidecarKeyStore {
	return nil
}

func (self *testScanCountingHost) TokenSource() SidecarTokenSource {
	return nil
}

func (self *testScanCountingHost) HostCredentialStores() []SidecarHostCredentialStore {
	self.scans.Update(func(count int) int { return count + 1 })
	return nil
}

// Waits until the run loop has scanned count times.
func (self *testScanCountingHost) awaitScans(t *testing.T, count int) {
	t.Helper()
	deadline := time.After(sidecarTestTimeout)
	for {
		scans, changed := self.scans.Get()
		if count <= scans {
			return
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatalf("%d scans, want %d", scans, count)
		}
	}
}

// A testSidecarPlatform whose clients open only once gate is closed. The leg opens its client before it reads the
// store, so a callback added before the gate closes sees everything a failed start raises.
type testGatedSidecarPlatform struct {
	*testSidecarPlatform
	gate chan struct{}
}

func (self *testGatedSidecarPlatform) OpenClient(ctx context.Context, args *SidecarPlatformClientArgs) (*SidecarPlatformClient, error) {
	select {
	case <-self.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return self.testSidecarPlatform.OpenClient(ctx, args)
}

// An enrolled sidecar whose network's subprotocol store held push versions, then a damaged copy of them, running with
// its events recorded from before its first start read the store.
type storeFailedTestWorld struct {
	instance *SidecarInstance
	host     *testScanCountingHost
	platform *testSidecarPlatform
	sidecar  *Sidecar
	events   *alarmTestEvents
	// the team topic's version the store held before the damage
	teamVersion uint64
	// the backend path of the push versions file, and its sealed bytes before the damage
	versionsPath  string
	versionsBytes []byte
}

// A world whose versions file is what damage makes of its sealed bytes, which damage may change in place.
func newStoreFailedTestWorld(t *testing.T, damage func(sealed []byte) []byte) *storeFailedTestWorld {
	t.Helper()
	instance, enrollment := newTestEnrolledInstance(t)
	world := &storeFailedTestWorld{instance: instance, events: &alarmTestEvents{}, teamVersion: 7}
	store, err := instance.Store(&enrollment.networkId).Directory(sidecarSubprotocolStoreName, sidecarSubprotocolStoreName)
	if err != nil {
		t.Fatal(err)
	}
	if err := storePushVersions(store, map[string]uint64{PushTopicTeam: world.teamVersion}); err != nil {
		t.Fatal(err)
	}
	world.versionsPath = networkFilePath(enrollment.networkId, sidecarSubprotocolStoreName+"/"+pushVersionsFileName)
	reader, err := instance.backend.Open(world.versionsPath)
	if err != nil {
		t.Fatal(err)
	}
	world.versionsBytes, err = io.ReadAll(reader)
	reader.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeBackendFile(instance.backend, world.versionsPath, damage(bytes.Clone(world.versionsBytes))); err != nil {
		t.Fatal(err)
	}

	world.host = &testScanCountingHost{store: instance.Store(&enrollment.networkId), scans: NewMonitorValue(0)}
	world.platform = newTestSidecarPlatform()
	gated := &testGatedSidecarPlatform{testSidecarPlatform: world.platform, gate: make(chan struct{})}
	sidecar, err := NewSidecar(context.Background(), world.host, nil, testSidecarSettings(gated))
	if err != nil {
		t.Fatal(err)
	}
	world.sidecar = sidecar
	t.Cleanup(func() {
		world.close(t)
	})
	sidecar.AddEventCallback(world.events.add)
	close(gated.gate)
	return world
}

// Closes the sidecar and joins its run loop, so everything the loop did is done and nothing more starts.
func (self *storeFailedTestWorld) close(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), sidecarTestTimeout)
	defer cancel()
	if err := self.sidecar.CloseAndWait(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// Waits until the platform has opened count clients and the newest has closed, as a failed start closes its client.
func (self *storeFailedTestWorld) awaitClosedClient(t *testing.T, count int) {
	t.Helper()
	client := self.platform.awaitOpened(t, count)
	select {
	case <-client.closed:
	case <-time.After(sidecarTestTimeout):
		t.Fatalf("client %d stayed open", count)
	}
}

// The state events from the first that named the failed store on, in their order.
func (self *storeFailedTestWorld) statesSinceFailure() []SidecarEvent {
	self.events.stateLock.Lock()
	defer self.events.stateLock.Unlock()
	states := []SidecarEvent{}
	for _, event := range self.events.events {
		if event.Kind != SidecarEventState {
			continue
		}
		if 0 < len(states) || event.Reason == SidecarReasonSubprotocolStoreFailed {
			states = append(states, event)
		}
	}
	return states
}

// Whether the status is Offline with the failed store's reason.
func atSubprotocolStoreFailed(status SidecarStatus) bool {
	return status.State == SidecarStateOffline && status.Reason == SidecarReasonSubprotocolStoreFailed
}

// A file that is no sealed file, the kill test's torn write, in place of the sealed versions.
func damageToNoSealedFile(sealed []byte) []byte {
	return bytes.Repeat([]byte("synthetic damage "), 8)
}

// A start that fails on a damaged subprotocol-store file, one that is no sealed file or one whose AEAD fails, is §5.9's
// Failed: the sidecar stays Offline at the generation with subprotocol_store_failed and raises refused once. Nothing
// wakes the loop: the scan's pass and a wake each try once more and fail again, raising nothing and moving nothing, and
// no other start runs (owner decision 616).
func TestSubprotocolStoreFailureRefusesOnceAndWaits(t *testing.T) {
	for _, c := range []struct {
		name   string
		damage func(sealed []byte) []byte
	}{
		{name: "no sealed file", damage: damageToNoSealedFile},
		{name: "a failed AEAD", damage: func(sealed []byte) []byte {
			sealed[len(sealed)-1] ^= 0x01
			return sealed
		}},
	} {
		world := newStoreFailedTestWorld(t, c.damage)
		status := awaitSidecarStatus(t, world.sidecar, atSubprotocolStoreFailed)
		if status.Generation != 1 {
			t.Errorf("%s: generation %d", c.name, status.Generation)
		}
		// the first pass's start failed before its scan ran, and woke nothing; the scan's pass tried again
		world.host.awaitScans(t, 1)
		if wakes := world.sidecar.wakes.Value(); wakes != 0 {
			t.Errorf("%s: the failed start woke the loop %d times", c.name, wakes)
		}
		world.awaitClosedClient(t, 2)
		// a wake tries once more, and fails the same way
		world.sidecar.wake()
		world.awaitClosedClient(t, 3)
		world.close(t)

		if opened := len(world.platform.openedClients()); opened != 3 {
			t.Errorf("%s: %d starts, want the first pass's, the scan's and the wake's", c.name, opened)
		}
		if wakes := world.sidecar.wakes.Value(); wakes != 1 {
			t.Errorf("%s: %d wakes, want the test's one", c.name, wakes)
		}
		refused := world.events.of(SidecarEventRefused)
		if len(refused) != 1 {
			t.Fatalf("%s: %d refused events, want 1: %+v", c.name, len(refused), refused)
		}
		if refused[0].Generation != 1 || refused[0].State != SidecarStateOffline || refused[0].Reason != SidecarReasonSubprotocolStoreFailed {
			t.Errorf("%s: refused %+v", c.name, refused[0])
		}
		// the retries that failed again moved nothing: no state between tries, and no reason dropped and raised again
		states := world.statesSinceFailure()
		if len(states) != 1 || states[0].State != SidecarStateOffline || states[0].Generation != 1 {
			t.Errorf("%s: state events %+v", c.name, states)
		}
		if status := world.sidecar.Status(); !atSubprotocolStoreFailed(status) || status.Generation != 1 {
			t.Errorf("%s: status %+v", c.name, status)
		}
		if world.sidecar.runningGeneration() != nil || world.sidecar.Stats().GenerationCount != 0 {
			t.Errorf("%s: a generation ran on the damaged store", c.name)
		}
		if world.sidecar.sidecarApi.currentByJwt() != "" {
			t.Errorf("%s: the token stayed in the api client with no generation running", c.name)
		}
	}
}

// The wake after the store reads again brings the sidecar online: that start reads the restored versions, the reason
// ends at Offline before the client is published, and the client comes online, with no other refused (owner decision
// 616).
func TestRestoredSubprotocolStoreStartsAtTheNextWake(t *testing.T) {
	world := newStoreFailedTestWorld(t, damageToNoSealedFile)
	world.platform.connected.Set(true)
	awaitSidecarStatus(t, world.sidecar, atSubprotocolStoreFailed)
	world.host.awaitScans(t, 1)
	world.awaitClosedClient(t, 2)

	if err := writeBackendFile(world.instance.backend, world.versionsPath, world.versionsBytes); err != nil {
		t.Fatal(err)
	}
	world.sidecar.wake()
	status := awaitSidecarStatus(t, world.sidecar, atStatus(SidecarStateOnline, 1))
	if status.Reason != "" {
		t.Errorf("online with reason %q", status.Reason)
	}
	generation := world.sidecar.runningGeneration()
	if generation == nil || generation.leg == nil {
		t.Fatal("no generation runs")
	}
	if version := generation.leg.(*sidecarConnectGeneration).pushClient.Version(PushTopicTeam); version != world.teamVersion {
		t.Errorf("the push client holds version %d, not the restored store's", version)
	}
	world.close(t)

	if opened := len(world.platform.openedClients()); opened != 3 {
		t.Errorf("%d starts, want the two that failed and the wake's", opened)
	}
	if refused := world.events.of(SidecarEventRefused); len(refused) != 1 {
		t.Errorf("refused events %+v", refused)
	}
	want := []sidecarLifecycle{
		{state: SidecarStateOffline, reason: SidecarReasonSubprotocolStoreFailed, generation: 1},
		{state: SidecarStateOffline, generation: 1},
		{state: SidecarStateOnline, generation: 1},
	}
	states := world.statesSinceFailure()
	if len(states) != len(want) {
		t.Fatalf("state events %+v", states)
	}
	for i, event := range states {
		if got := (sidecarLifecycle{state: event.State, reason: event.Reason, generation: event.Generation}); got != want[i] {
			t.Errorf("state event %d: %+v, want %+v", i, got, want[i])
		}
	}
}

// Entering the failure raises its state and one refused; standing in it raises nothing more; once a start clears it,
// the next failure raises again; and an older generation's failure is dropped.
func TestSubprotocolStoreFailedRaisesRefusedAsItEnters(t *testing.T) {
	sidecar := newTestSidecar(t)
	for _, transition := range []sidecarTransition{
		{to: SidecarStateUnenrolled},
		{to: SidecarStateOffline, generation: 2},
	} {
		if !sidecar.applyTransition(transition) {
			t.Fatalf("%+v did not move", transition)
		}
	}
	events := recordEvents(sidecar)
	sidecar.subprotocolStoreFailed(2)
	sidecar.subprotocolStoreFailed(2)
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 2}) {
		t.Fatal("the reason did not clear")
	}
	sidecar.subprotocolStoreFailed(2)
	sidecar.subprotocolStoreFailed(1)

	failedState := SidecarEvent{Kind: SidecarEventState, Generation: 2, State: SidecarStateOffline, Reason: SidecarReasonSubprotocolStoreFailed}
	failedRefused := SidecarEvent{Kind: SidecarEventRefused, Generation: 2, State: SidecarStateOffline, Reason: SidecarReasonSubprotocolStoreFailed}
	want := []SidecarEvent{
		failedState,
		failedRefused,
		{Kind: SidecarEventState, Generation: 2, State: SidecarStateOffline},
		failedState,
		failedRefused,
	}
	if len(*events) != len(want) {
		t.Fatalf("events %+v", *events)
	}
	for i, event := range *events {
		if event.Kind != want[i].Kind || event.Generation != want[i].Generation || event.State != want[i].State || event.Reason != want[i].Reason {
			t.Errorf("event %d: %+v, want %+v", i, event, want[i])
		}
	}
}

// subprotocol_store_failed is Offline's alone (§18.5's GetStateReason): every other state refuses it, Offline takes it
// at its generation, a retry that fails again changes nothing, and it clears, or leaves for a lock or a refusal, as a
// plain Offline does.
func TestSubprotocolStoreReasonIsOfflineAlone(t *testing.T) {
	for _, from := range sidecarStates {
		for _, to := range sidecarStates {
			if to == SidecarStateOffline {
				continue
			}
			current := plainLifecycleAt(from, 3)
			transition := plainTransitionTo(to, 3)
			transition.reason = SidecarReasonSubprotocolStoreFailed
			if next, result := nextSidecarLifecycle(current, transition); result != sidecarTransitionRefused || next != current {
				t.Errorf("%s to %s with the store's reason: result %d, at %+v", from, to, result, next)
			}
		}
	}

	failed := sidecarLifecycle{state: SidecarStateOffline, reason: SidecarReasonSubprotocolStoreFailed, generation: 3}
	toFailed := sidecarTransition{to: SidecarStateOffline, reason: SidecarReasonSubprotocolStoreFailed, generation: 3}
	if next, result := nextSidecarLifecycle(plainLifecycleAt(SidecarStateOffline, 3), toFailed); result != sidecarTransitionApplied || next != failed {
		t.Errorf("offline to the store's reason: result %d, at %+v", result, next)
	}
	if next, result := nextSidecarLifecycle(failed, toFailed); result != sidecarTransitionUnchanged || next != failed {
		t.Errorf("a retry that failed again: result %d, at %+v", result, next)
	}
	for _, to := range []SidecarState{SidecarStateOffline, SidecarStateOnline, SidecarStateLocked, SidecarStateUnenrolled} {
		if next, result := nextSidecarLifecycle(failed, plainTransitionTo(to, 3)); result != sidecarTransitionApplied || next != plainLifecycleAt(to, 3) {
			t.Errorf("the store's reason to %s: result %d, at %+v", to, result, next)
		}
	}
}
