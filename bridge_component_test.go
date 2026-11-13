//go:build !ios_extension && !sidecar_http

// The bridge component (bridge_component.go, bridge_provider.go; DESIGN-DETAILS 12.6's component row) over a real
// ConfigClient on the test network: a device role anchored pending before its first state and then given a state at
// the client's tip; a denial handed at its own position, never 0, after the entries that carry it; the generation's
// NAT built with the role's hook and its provider only after the catch-up; a restart's gate replaying a judged denial
// before the provider; and the gate waiting for a lagging store, with catch_up_waiting. That an entry is kept in the
// client's store before its callback runs is config_client_test.go's TestEntriesAreStoredBeforeTheirCallbacks.

package sidecar

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What happened, in order, across a test's sink and provider, with a monitor a test waits on.
type testBridgeEvents struct {
	stateLock sync.Mutex
	events    []string
	count     *MonitorValue[int]
}

func newTestBridgeEvents() *testBridgeEvents {
	return &testBridgeEvents{count: NewMonitorValue(0)}
}

func (self *testBridgeEvents) add(event string) {
	self.stateLock.Lock()
	self.events = append(self.events, event)
	count := len(self.events)
	self.stateLock.Unlock()
	self.count.Set(count)
}

func (self *testBridgeEvents) list() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// Waits until the events hold one for which match holds, failing the test after a minute of no such event. The wait
// is on the recorder's monitor, never a sleep.
func (self *testBridgeEvents) waitFor(t testing.TB, what string, match func(event string) bool) {
	t.Helper()
	timeout := time.After(time.Minute)
	for {
		_, changed := self.count.Get()
		if slices.ContainsFunc(self.list(), match) {
			return
		}
		select {
		case <-changed:
		case <-timeout:
			t.Fatalf("no %s among %v", what, self.list())
		}
	}
}

// The index of the first event match holds for, -1 for none.
func (self *testBridgeEvents) index(match func(event string) bool) int {
	return slices.IndexFunc(self.list(), match)
}

// A hook that denies everything, standing in for the device role's.
type testBridgeHook struct{}

func (self testBridgeHook) VerifyPrincipal(source connect.TransferPath, peer connect.Peer) *connect.BridgePrincipal {
	return nil
}
func (self testBridgeHook) ResolveEgress(flow *connect.EgressFlow) connect.EgressDecision {
	return connect.EgressDecision{}
}
func (self testBridgeHook) PolicyGeneration() uint64     { return 1 }
func (self testBridgeHook) FriendsAndFamilyEgress() bool { return false }

// A device role that holds what it is handed as a posture would and records each call.
type testBridgeSink struct {
	events    *testBridgeEvents
	hook      connect.EgressHook
	stateLock sync.Mutex
	decision  BridgeSinkDecision
}

func (self *testBridgeSink) SetPending(pending *bridge.Pending) error {
	self.stateLock.Lock()
	if self.decision.State == BridgeSinkLegacy {
		self.decision.State = BridgeSinkPending
	}
	self.stateLock.Unlock()
	self.events.add(fmt.Sprintf("pending %x", pending.GetNetworkId()))
	return nil
}

func (self *testBridgeSink) SetState(state *bridge.BridgeState, log *BridgeStateLog) error {
	n := state.GetAuth().GetVersion()
	refused := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if n < self.decision.StatePin.GetVersion() {
			return true
		}
		self.decision.State = BridgeSinkEnforcing
		self.decision.StatePin = proto.Clone(state.GetAuth()).(*bridge.AuthPin)
		if self.decision.Pin.GetVersion() < n {
			self.decision.Pin = proto.Clone(state.GetAuth()).(*bridge.AuthPin)
		}
		return false
	}()
	if refused {
		self.events.add(fmt.Sprintf("state %d dropped", n))
		return nil
	}
	self.events.add(fmt.Sprintf("state %d of %d entries", n, len(log.Entries)))
	return nil
}

func (self *testBridgeSink) ApplyDeltas(log *BridgeStateLog) error {
	positions := []string{}
	last := uint64(0)
	for _, entryBytes := range log.Entries {
		entry := &bridge.AuthEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return err
		}
		positions = append(positions, fmt.Sprint(entry.GetN()))
		last = entry.GetN()
	}
	self.stateLock.Lock()
	if self.decision.Pin.GetVersion() < last {
		self.decision.Pin = &bridge.AuthPin{Version: last, Chain: make([]byte, 32)}
	}
	self.stateLock.Unlock()
	self.events.add("deltas " + strings.Join(positions, ","))
	return nil
}

func (self *testBridgeSink) SetFork(fork bool) error {
	self.events.add(fmt.Sprint("fork ", fork))
	return nil
}

func (self *testBridgeSink) Decision() BridgeSinkDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.decision
}

func (self *testBridgeSink) Revoke(statementType bridge.SignedType, id []byte, n uint64) error {
	if n == 0 {
		self.events.add("revoke at 0")
		return fmt.Errorf("%w: position 0", ErrBridgeComponentClosed)
	}
	self.events.add(fmt.Sprintf("revoke %s %x at %d", statementType, id, n))
	return nil
}

func (self *testBridgeSink) EgressHook() connect.EgressHook {
	return self.hook
}

// The component's world: a config client world, with its member devices, a sink and stand-ins for connect's NAT and
// provider that record what they were given.
type testBridgeComponentWorld struct {
	*testConfigClientWorld
	client    *ConfigClient
	host      testConfigDevice
	peer      testConfigDevice
	events    *testBridgeEvents
	sink      *testBridgeSink
	settings  *BridgeComponentSettings
	stateLock sync.Mutex
	// the NAT settings each gate built with
	natSettings []*connect.LocalUserNatSettings
	alarms      []SidecarBridgeAlarm
}

func newTestBridgeComponentWorld(t *testing.T) *testBridgeComponentWorld {
	clientWorld := newTestConfigClientWorld(t)
	_, laptop, desktop := testBridgeCast(clientWorld.net)
	clientWorld.publish()
	self := &testBridgeComponentWorld{
		testConfigClientWorld: clientWorld,
		host:                  laptop,
		peer:                  desktop,
		events:                newTestBridgeEvents(),
		settings:              DefaultBridgeComponentSettings(),
	}
	self.settings.CompileDelay = 0
	self.settings.CompileMinInterval = 0
	self.sink = &testBridgeSink{events: self.events, hook: testBridgeHook{}, decision: BridgeSinkDecision{State: BridgeSinkLegacy}}
	self.client = clientWorld.client(nil)
	clientWorld.caughtUp(self.client)
	return self
}

// A component over the world's client, closed at the test's end.
func (self *testBridgeComponentWorld) component() *BridgeComponent {
	self.t.Helper()
	component, err := NewBridgeComponent(context.Background(), &BridgeComponentArgs{
		NetworkId: self.net.networkId,
		Identity: func() *SidecarIdentity {
			return &SidecarIdentity{NetworkId: self.net.networkId, SidecarId: self.host.sidecarId, IdentityPublicKey: self.host.publicKey()}
		},
		Config: self.client,
		Heads:  self.heads,
		Rows:   self.net.source,
		Emit: func(event SidecarEvent) {
			if event.Kind == SidecarEventBridgeAlarm {
				self.stateLock.Lock()
				self.alarms = append(self.alarms, event.BridgeAlarm)
				self.stateLock.Unlock()
				self.events.add("alarm " + string(event.BridgeAlarm))
			}
		},
		Clock:    self.clock,
		Log:      NewNoopLogger(),
		Settings: self.settings,
		parts: &bridgeProviderParts{
			newNat: func(ctx context.Context, settings *connect.LocalUserNatSettings) *connect.LocalUserNat {
				self.stateLock.Lock()
				self.natSettings = append(self.natSettings, settings)
				self.stateLock.Unlock()
				self.events.add("nat")
				return nil
			},
			newProvider: func(client *connect.Client, nat *connect.LocalUserNat) (func(), error) {
				self.events.add("provider")
				return func() { self.events.add("provider closed") }, nil
			},
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(component.Close)
	return component
}

// Sequences a statement and follows the client to it, as a team hint would.
func (self *testBridgeComponentWorld) post(signer testConfigDevice, signedType bridge.SignedType, body proto.Message) uint64 {
	self.t.Helper()
	n := self.net.mustPost(signer, signedType, body).Pin.GetVersion()
	self.publish()
	self.caughtUp(self.client)
	return n
}

// A generation's env, ending with the returned function.
func (self *testBridgeComponentWorld) generation() (*SidecarEnv, func()) {
	ctx, cancel := context.WithCancel(context.Background())
	return &SidecarEnv{Ctx: ctx, Log: NewNoopLogger()}, cancel
}

// A device role set before its first state is anchored pending at the network, then takes a state at the client's tip
// with the log run from its base; an entry after it rises to a state at the new tip, and no state is ever handed below
// one in force.
func TestTheComponentAnchorsThenCompilesARisingState(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	component := world.component()
	if err := component.SetDeviceRole(world.sink); err != nil {
		t.Fatal(err)
	}
	tip := world.net.n
	world.events.waitFor(t, "the first state", func(event string) bool { return strings.HasPrefix(event, fmt.Sprintf("state %d ", tip)) })
	events := world.events.list()
	if !strings.HasPrefix(events[0], "pending ") {
		t.Fatalf("the first call %q, want the anchor", events[0])
	}
	if err := component.SetDeviceRole(world.sink); err == nil {
		t.Error("a second device role was taken")
	}

	n := world.post(world.peer, bridge.SignedType_SIGNED_BRIDGE_EGRESS, world.net.bridgeEgress(world.peer.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, nil))
	world.events.waitFor(t, "a state at the new tip", func(event string) bool { return strings.HasPrefix(event, fmt.Sprintf("state %d ", n)) })
	if status := component.Status(); status.CompiledPin.GetVersion() != n || !status.DeviceRole || status.CompileCount < 2 {
		t.Errorf("status %+v", status)
	}
	if slices.ContainsFunc(world.events.list(), func(event string) bool { return strings.HasSuffix(event, " dropped") }) {
		t.Errorf("a state below the one in force was handed: %v", world.events.list())
	}
}

// 12.2.5's "a denial is held at its own position": a revocation's entry reaches the sink as a delta and then as a
// Revoke at that entry's own position, never 0.
func TestADenialIsRevokedAtItsOwnPosition(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	component := world.component()
	if err := component.SetDeviceRole(world.sink); err != nil {
		t.Fatal(err)
	}
	world.events.waitFor(t, "the first state", func(event string) bool { return strings.HasPrefix(event, "state ") })
	n := world.post(world.host, bridge.SignedType_SIGNED_SIDECAR_REVOKE, world.net.revocation(world.peer, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	revoke := fmt.Sprintf("revoke %s %x at %d", bridge.SignedType_SIGNED_SIDECAR_REVOKE, world.peer.sidecarId.Bytes(), n)
	world.events.waitFor(t, "the revocation", func(event string) bool { return event == revoke })
	deltas := world.events.index(func(event string) bool {
		return strings.HasPrefix(event, "deltas ") && strings.HasSuffix(event, fmt.Sprint(n))
	})
	if deltas == -1 || world.events.index(func(event string) bool { return event == revoke }) < deltas {
		t.Errorf("the revocation before its entry's delta: %v", world.events.list())
	}
	if world.events.index(func(event string) bool { return event == "revoke at 0" }) != -1 {
		t.Error("a denial was handed at position 0")
	}
}

// 12.2.5's gate: the generation's NAT is built with the device role's hook in its settings, and the provider only
// after the catch-up's state; the provider ends with its generation.
func TestNoProviderBeforeHook(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	component := world.component()
	if err := component.SetDeviceRole(world.sink); err != nil {
		t.Fatal(err)
	}
	env, end := world.generation()
	if err := component.Attach(env); err != nil {
		t.Fatal(err)
	}
	world.events.waitFor(t, "the provider", func(event string) bool { return event == "provider" })
	nat := world.events.index(func(event string) bool { return event == "nat" })
	state := world.events.index(func(event string) bool { return strings.HasPrefix(event, "state ") })
	provider := world.events.index(func(event string) bool { return event == "provider" })
	if nat == -1 || state == -1 || !(nat < provider && state < provider) {
		t.Fatalf("events %v", world.events.list())
	}
	world.stateLock.Lock()
	natSettings := slices.Clone(world.natSettings)
	world.stateLock.Unlock()
	if len(natSettings) != 1 || natSettings[0].EgressHook != world.sink.hook {
		t.Fatalf("the NAT's settings %v", natSettings)
	}
	end()
	world.events.waitFor(t, "the provider's close", func(event string) bool { return event == "provider closed" })
}

// 12.2.5's restart: a device role restored at a state below the client's tip, with a judged revocation above it that the
// posture held only in memory, gets that denial again, at its position, before the provider is built.
func TestTheGateReplaysJudgedDenialsBeforeTheProvider(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	restoredAt := world.net.n
	n := world.post(world.host, bridge.SignedType_SIGNED_SIDECAR_REVOKE, world.net.revocation(world.peer, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	pin := &bridge.AuthPin{Version: restoredAt, Chain: make([]byte, 32)}
	world.sink.decision = BridgeSinkDecision{State: BridgeSinkEnforcing, Pin: pin, StatePin: pin}
	component := world.component()
	if err := component.SetDeviceRole(world.sink); err != nil {
		t.Fatal(err)
	}
	env, end := world.generation()
	defer end()
	if err := component.Attach(env); err != nil {
		t.Fatal(err)
	}
	world.events.waitFor(t, "the provider", func(event string) bool { return event == "provider" })
	revoke := fmt.Sprintf("revoke %s %x at %d", bridge.SignedType_SIGNED_SIDECAR_REVOKE, world.peer.sidecarId.Bytes(), n)
	at := world.events.index(func(event string) bool { return event == revoke })
	if at == -1 || world.events.index(func(event string) bool { return event == "provider" }) < at {
		t.Fatalf("the judged denial after the provider: %v", world.events.list())
	}
}

// 12.2.5's lagging store: a device role whose pin is past the client's builds no provider, alarms catch_up_waiting once
// CatchUpAlarmTimeout passes, and serves once the client's follow reaches its pin.
func TestTheGateWaitsForALaggingStore(t *testing.T) {
	world := newTestBridgeComponentWorld(t)
	ahead := world.net.n + 2
	pin := &bridge.AuthPin{Version: ahead, Chain: make([]byte, 32)}
	world.sink.decision = BridgeSinkDecision{State: BridgeSinkEnforcing, Pin: pin, StatePin: pin}
	component := world.component()
	if err := component.SetDeviceRole(world.sink); err != nil {
		t.Fatal(err)
	}
	env, end := world.generation()
	defer end()
	if err := component.Attach(env); err != nil {
		t.Fatal(err)
	}
	// the gate waits, its alarm armed on the clock
	for timeout := range world.clock.armed {
		if timeout == world.settings.CatchUpAlarmTimeout {
			break
		}
	}
	if !component.Status().CatchUpWaiting || world.events.index(func(event string) bool { return event == "provider" }) != -1 {
		t.Fatalf("a provider while the store lags: %v", world.events.list())
	}
	world.clock.Advance(world.settings.CatchUpAlarmTimeout)
	world.events.waitFor(t, "catch_up_waiting", func(event string) bool { return event == "alarm "+string(SidecarBridgeAlarmCatchUpWaiting) })
	for range 2 {
		world.net.mustPost(world.peer, bridge.SignedType_SIGNED_BRIDGE_EGRESS, world.net.bridgeEgress(world.peer.sidecarId, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO, nil))
	}
	world.publish()
	if err := world.client.CatchUp(context.Background()); err != nil {
		t.Fatal(err)
	}
	world.events.waitFor(t, "the provider", func(event string) bool { return event == "provider" })
}
