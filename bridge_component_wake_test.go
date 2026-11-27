//go:build !ios_extension && !sidecar_http

// The bridge component's wanted compiles, and a failed one's retry, dated before their causes could be seen
// (bridge_component.go's comment, wantCompileAt), as the Forwarder's are (bridge_forward_wake_test.go, whose holds
// these use): each test holds the component's goroutine, or its binding fetcher's, just after the role, Status or the
// store shows a cause, moves the clock there as an observer that saw it would, from another goroutine, and lets the
// component go on. A time dated after the move lands past it by the move, which the clock, moved once, never reaches.
// Every harness runs the component at CompileDelay 0, where none of this can show; these run it at 2 s. Each test fails
// on the code before that change. No sleeps: the holds are channels, and settle is a barrier on the loop's goroutine.

package sidecar

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The world's role, holding the component after a call that shows a cause: its anchor, which shows the role pending,
// or its take of entries, which shows their pin before ApplyDeltas returns, as the posture's adoption does.
type testBridgeComponentWakeSink struct {
	*testBridgeSink
	armed atomic.Pointer[testForwarderWakeHold]
}

// A wake sink over the world's role, which a test sets as the component's device role.
func newTestBridgeComponentWakeSink(world *testBridgeComponentWorld) *testBridgeComponentWakeSink {
	return &testBridgeComponentWakeSink{testBridgeSink: world.sink}
}

// Arms a hold in call, "pending" or "deltas", at its next such call.
func (self *testBridgeComponentWakeSink) hold(call string) *testForwarderWakeHold {
	hold := newTestForwarderWakeHold(call, nil)
	self.armed.Store(hold)
	return hold
}

func (self *testBridgeComponentWakeSink) holdIn(call string) {
	testForwarderWakeHoldIf(&self.armed, func(hold *testForwarderWakeHold) bool {
		return hold.at == call
	})
}

func (self *testBridgeComponentWakeSink) SetPending(pending *bridge.Pending) error {
	err := self.testBridgeSink.SetPending(pending)
	self.holdIn("pending")
	return err
}

func (self *testBridgeComponentWakeSink) ApplyDeltas(log *BridgeStateLog) error {
	err := self.testBridgeSink.ApplyDeltas(log)
	self.holdIn("deltas")
	return err
}

// A generation's store, holding the binding fetcher once a save of the cache has committed, which shows it.
type testBridgeComponentWakeStore struct {
	*testConfigClientStore
	armed atomic.Pointer[testForwarderWakeHold]
}

// Arms a hold at the next save of the binding cache.
func (self *testBridgeComponentWakeStore) hold() *testForwarderWakeHold {
	hold := newTestForwarderWakeHold(bridgeBindingCacheName, nil)
	self.armed.Store(hold)
	return hold
}

func (self *testBridgeComponentWakeStore) Create(name string) (SidecarStoreWriter, error) {
	writer, err := self.testConfigClientStore.Create(name)
	if err != nil {
		return nil, err
	}
	return &testBridgeComponentWakeWriter{SidecarStoreWriter: writer, store: self, name: name}, nil
}

// A file the wake store writes, holding at the armed hold once it has committed.
type testBridgeComponentWakeWriter struct {
	SidecarStoreWriter
	store *testBridgeComponentWakeStore
	name  string
}

func (self *testBridgeComponentWakeWriter) Commit() error {
	err := self.SidecarStoreWriter.Commit()
	testForwarderWakeHoldIf(&self.store.armed, func(hold *testForwarderWakeHold) bool {
		return hold.at == self.name
	})
	return err
}

// Heads that answer nothing, as an api out of reach does.
type testBridgeComponentUnreachableHeads struct{}

func (self testBridgeComponentUnreachableHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	return nil, errors.New("the test's heads are unreachable")
}

// Waits until component's loop is idle: no entry waiting for it, and no compile due at the clock's time. A barrier on
// the loop's own goroutine, never a sleep.
func (self *testBridgeComponentWorld) settle(component *BridgeComponent) {
	self.t.Helper()
	for {
		idle := false
		err := component.onRun(func() {
			pendingCount := func() int {
				component.stateLock.Lock()
				defer component.stateLock.Unlock()
				return len(component.pending)
			}()
			idle = pendingCount == 0 && (!component.compileWanted || component.compileDueAt().After(component.clock.Now()))
		})
		if err != nil {
			self.t.Fatal(err)
		}
		if idle {
			return
		}
	}
}

// A device role set before its first state wants its compile from before it was set: an observer that saw the role
// anchored pending and moved the clock CompileDelay past it finds the first state handed then. The want was dated
// after the anchor, so the compile came due CompileDelay past the move and never ran.
func TestACompileADeviceRoleWantsComesItsDelayAfterTheRoleWasAnchored(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	world.settings.CompileDelay = 2 * time.Second
	component := world.component()
	sink := newTestBridgeComponentWakeSink(world)
	hold := sink.hold("pending")
	set := make(chan error, 1)
	go func() {
		set <- component.SetDeviceRole(sink)
	}()
	hold.meet(func() {
		if decision := world.sink.Decision(); decision.State != BridgeSinkPending {
			t.Errorf("the role at the hold: %+v", decision)
		}
		world.clock.Advance(world.settings.CompileDelay)
	})
	if err := <-set; err != nil {
		t.Fatal(err)
	}
	world.settle(component)
	if status := component.Status(); status.CompileCount != 1 || status.CompiledPin.GetVersion() != world.net.n {
		t.Fatalf("the role's first state did not come CompileDelay after its anchor: %+v, %v", status, world.events.list())
	}
}

// The daemon's side of the app host's stall (bridge_forward_wake_test.go's first test): an entry the role took, whose
// new pin an observer saw and moved the clock CompileDelay past, as an app host's step did once the posture showed the
// grant's pin, is compiled at that time with no further move. The want was dated after the take, so the compile came
// due CompileDelay past the move and never ran.
func TestACompileAnEntryWantsComesItsDelayAfterTheRoleTookTheEntry(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	world.settings.CompileDelay = 2 * time.Second
	component := world.component()
	sink := newTestBridgeComponentWakeSink(world)
	if err := component.SetDeviceRole(sink); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(world.settings.CompileDelay)
	world.settle(component)
	if status := component.Status(); status.CompileCount != 1 {
		t.Fatalf("the first state: %+v, %v", status, world.events.list())
	}
	hold := sink.hold("deltas")
	n := world.post(world.peer, bridge.SignedType_SIGNED_BRIDGE_EGRESS, world.net.bridgeEgress(world.peer.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, nil))
	hold.meet(func() {
		// what an observer of the role reads: the entry taken, no state at it yet
		if decision := world.sink.Decision(); decision.Pin.GetVersion() != n || decision.StatePin.GetVersion() == n {
			t.Errorf("the role at the hold: %+v", decision)
		}
		world.clock.Advance(world.settings.CompileDelay)
	})
	world.settle(component)
	if status := component.Status(); status.CompileCount != 2 || status.CompiledPin.GetVersion() != n {
		t.Fatalf("the entry was not compiled CompileDelay after the role took it: %+v, %v", status, world.events.list())
	}
}

// A compile that failed retries CompileRetryInterval after the failure Status counted: an observer that saw the count
// and moved the clock by the interval finds the retry run then. The retry was dated after the count, so it came the
// interval past the move and never ran.
func TestAFailedComponentCompileRetriesItsIntervalAfterStatusCountedIt(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	log := &testForwarderWakeLog{}
	// the line the compile logs just after Status counts its failure
	hold := log.hold("did not run")
	component := world.componentOver(testBridgeComponentUnreachableHeads{}, log)
	if err := component.SetDeviceRole(world.sink); err != nil {
		t.Fatal(err)
	}
	hold.meet(func() {
		if status := component.Status(); status.CompileErrorCount != 1 {
			t.Errorf("the status at the hold: %+v", status)
		}
		world.clock.Advance(world.settings.CompileRetryInterval)
	})
	world.settle(component)
	if status := component.Status(); status.CompileErrorCount != 2 {
		t.Fatalf("the retry did not come CompileRetryInterval after the failure: %+v", status)
	}
}

// A binding pass that changed the cache wants its compile from before its first fetch: an observer that saw the cache
// saved and moved the clock CompileDelay past it finds the compile run then. The want was dated on the component's
// goroutine once the pass had saved, after the move, so the compile came due CompileDelay past the move and never ran.
func TestACompileABindingPassWantsComesItsDelayAfterThePassBegan(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	world.settings.CompileDelay = 2 * time.Second
	world.settings.BindingRetainTimeout = time.Second
	component := world.component()
	store := &testBridgeComponentWakeStore{testConfigClientStore: newTestConfigClientStore()}
	env, end := world.generation()
	defer end()
	env.Store = store
	if err := component.Attach(env); err != nil {
		t.Fatal(err)
	}
	// a subject whose first client stopped being current twice the retain timeout ago, which the first pass drops
	subject := NewId()
	stoppedAt := world.clock.Now().Add(-2 * world.settings.BindingRetainTimeout)
	component.bindings.Record(&BridgeBinding{SidecarId: subject, ClientId: NewId(), Generation: 1, Signed: []byte{1}}, stoppedAt)
	component.bindings.Record(&BridgeBinding{SidecarId: subject, ClientId: NewId(), Generation: 2, Signed: []byte{2}}, stoppedAt)
	hold := store.hold()
	// the generation's catch-up compiles at once, and that compile wakes the pass
	if err := component.SetDeviceRole(world.sink); err != nil {
		t.Fatal(err)
	}
	hold.meet(func() {
		if _, err := store.Open(bridgeBindingCacheName); err != nil {
			t.Errorf("the cache at the hold: %v", err)
		}
		if status := component.Status(); status.CompileCount != 1 {
			t.Errorf("the status at the hold: %+v", status)
		}
		// the waits armed so far, so that the next refresh wait is the one the fetcher sets once it has filed the want
		for 0 < len(world.clock.armed) {
			<-world.clock.armed
		}
		world.clock.Advance(world.settings.CompileDelay)
	})
	for timeout := range world.clock.armed {
		if timeout == world.settings.BindingRefreshInterval {
			break
		}
	}
	world.settle(component)
	if status := component.Status(); status.CompileCount != 2 {
		t.Fatalf("the pass's compile did not come CompileDelay after the pass began: %+v", status)
	}
}
