// From posture to enforcement (bridge_state.go): a bridge's hook follows what its posture decides through SetPending,
// SetState and verified ApplyDeltas; the restored state is in force before NewBridge returns; a forged has_document
// changes nothing; a covered denial between states narrows until the next state confirms or reverses it; Revoke narrows
// at once and holds until a state passes it; and the hook binds the NATs it is installed on.

package device_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A fake NAT's closer: it records each tag CloseFlows is called with, and the published generation at the call.
type stateTestCloser struct {
	hook connect.EgressHook

	stateLock   sync.Mutex
	tags        []uint64
	generations []uint64
}

// connect.EgressFlowCloser.
func (self *stateTestCloser) CloseFlows(ruleTag uint64) int {
	generation := self.hook.PolicyGeneration()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.tags = append(self.tags, ruleTag)
	self.generations = append(self.generations, generation)
	return 0
}

// The tags closed since the last take, sorted, and the generations the hook had published at each.
func (self *stateTestCloser) take() ([]uint64, []uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	tags, generations := self.tags, self.generations
	self.tags, self.generations = nil, nil
	slices.Sort(tags)
	return tags, generations
}

// A host bridge on a fake clock, taken from legacy to enforcing by a signed log, its hook bound to a fake closer.
type stateTest struct {
	t       *testing.T
	clock   *sidecartest.FakeClock
	log     *device.BridgeLogFixtureForTest
	bridge  *device.Bridge
	closer  *stateTestCloser
	changes chan struct{}
}

// The subjects of the state tests: egress_test's untagged and tagged ones, with each's identity in the state.
func stateTestIdentities(fixture *sidecartest.BridgeRulesFixture) []*bridge.BridgeIdentity {
	identities := []*bridge.BridgeIdentity{}
	for _, subject := range fixture.Subjects {
		identities = append(identities, &bridge.BridgeIdentity{
			SidecarId:         sidecartest.BridgeFixtureSidecarId(subject.Sidecar),
			IdentityPublicKey: sidecartest.BridgeFixtureIdentityKey(subject.Sidecar).Public().(ed25519.PublicKey),
		})
	}
	return identities
}

// A bridge enforcing fixture's rules on a base saying hasDocument.
func newStateTest(t *testing.T, fixture *sidecartest.BridgeRulesFixture, hasDocument bool) *stateTest {
	t.Helper()
	return newStateTestWithSettings(t, fixture, hasDocument, nil)
}

// The same, its settings adjusted by edit first.
func newStateTestWithSettings(
	t *testing.T,
	fixture *sidecartest.BridgeRulesFixture,
	hasDocument bool,
	edit func(settings *device.BridgeSettings),
) *stateTest {
	t.Helper()
	clock := sidecartest.NewFakeClock(time.UnixMilli(egressTestTimeMs))
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	if edit != nil {
		edit(settings)
	}
	log := device.NewBridgeLogFixtureForTest(t)
	log.Base(hasDocument)
	log.Tick()
	bridgeBridge, err := device.NewBridge(context.Background(), log.EmptyStore(), nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridgeBridge.Close)
	self := &stateTest{
		t:       t,
		clock:   clock,
		log:     log,
		bridge:  bridgeBridge,
		closer:  &stateTestCloser{hook: bridgeBridge.EgressHook()},
		changes: make(chan struct{}, 64),
	}
	unbind := bridgeBridge.EgressHook().(connect.EgressHookBinder).BindFlowCloser(self.closer)
	t.Cleanup(unbind)
	t.Cleanup(bridgeBridge.AddChangeCallback(func() {
		// never blocks the publisher, run's goroutine included; a full buffer has a change to read already
		select {
		case self.changes <- struct{}{}:
		default:
		}
	}))
	if err := bridgeBridge.SetPending(log.Pending()); err != nil {
		t.Fatal(err)
	}
	self.setState(fixture, hasDocument)
	self.closer.take()
	self.drainChanges()
	return self
}

// Sends a state of fixture's rules at the log's newest position, with its subjects' identities and this host's
// listeners.
func (self *stateTest) setState(fixture *sidecartest.BridgeRulesFixture, hasDocument bool) {
	self.t.Helper()
	state, stateLog := self.log.State(fixture.Bytes(), hasDocument)
	state.Identities = stateTestIdentities(fixture)
	state.DaemonListeners = egressTestListeners
	if err := self.bridge.SetState(state, stateLog); err != nil {
		self.t.Fatal(err)
	}
}

// Forgets the changes so far.
func (self *stateTest) drainChanges() {
	for {
		select {
		case <-self.changes:
		default:
			return
		}
	}
}

// Waits for the bridge's next publish, which run's timer makes on its own goroutine. The context is the guard that
// fails a test the publish never comes to.
func (self *stateTest) awaitChange() {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case <-self.changes:
	case <-ctx.Done():
		self.t.Fatal("no publish")
	}
}

// Advances the clock to at, once run waits on a timer for it, and waits for the publish it makes.
func (self *stateTest) advanceTo(at time.Time) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for {
		pending, added := self.clock.WatchTimers()
		if 0 < len(pending) && !pending[0].After(at) {
			break
		}
		select {
		case <-added:
		case <-ctx.Done():
			self.t.Fatalf("no timer by %v; pending %v", at, pending)
		}
	}
	// a publish before this one is not the one awaited
	self.drainChanges()
	self.clock.AdvanceTo(at)
	self.awaitChange()
}

// A flow of the subject's with a principal of the log's network that outlives every test's clock.
func (self *stateTest) flow(subjectSeed byte, ipProtocol connect.IpProtocol, to string) *connect.EgressFlow {
	flow := egressTestFlow(subjectSeed, ipProtocol, to)
	flow.SourceNetwork = connect.Id(self.log.NetworkId())
	flow.Principal.Network = connect.Id(self.log.NetworkId())
	flow.Principal.NotAfter = time.UnixMilli(egressTestTimeMs + 24*egressTestHourMs)
	return flow
}

// The verdict the bridge's hook gives a flow.
func (self *stateTest) verdict(flow *connect.EgressFlow) connect.EgressVerdict {
	return self.bridge.EgressHook().ResolveEgress(flow).Verdict
}

// Legacy at a host denies, pending denies every Network flow, and the first verified state opens what its rules allow.
func TestBridgeHookFollowsThePosturesStates(t *testing.T) {
	clock := sidecartest.NewFakeClock(time.UnixMilli(egressTestTimeMs))
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	log := device.NewBridgeLogFixtureForTest(t)
	log.Base(false)
	log.Tick()
	bridgeBridge, err := device.NewBridge(context.Background(), log.EmptyStore(), nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridgeBridge.Close)
	test := &stateTest{t: t, clock: clock, log: log, bridge: bridgeBridge}
	lan := func() *connect.EgressFlow {
		return test.flow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:443")
	}
	if test.verdict(lan()) != connect.EgressVerdictDeny || bridgeBridge.Status().State != device.PostureLegacy {
		t.Fatal("legacy at a host")
	}
	if err := bridgeBridge.SetPending(log.Pending()); err != nil {
		t.Fatal(err)
	}
	if test.verdict(lan()) != connect.EgressVerdictDeny || bridgeBridge.Status().State != device.PosturePending {
		t.Fatal("pending")
	}
	pendingGeneration := bridgeBridge.Status().PolicyGeneration
	test.setState(egressTestFixture(), false)
	status := bridgeBridge.Status()
	if status.State != device.PostureEnforcingNoDocument || status.PolicyGeneration <= pendingGeneration {
		t.Fatalf("%+v", status)
	}
	if test.verdict(lan()) != connect.EgressVerdictPass {
		t.Fatal("enforcing{nodoc}: an untagged subject's LAN")
	}
	if test.verdict(test.flow(egressTestUntagged, connect.IpProtocolTcp, "127.0.0.1:8443")) != connect.EgressVerdictDeny {
		t.Fatal("the daemon's listener")
	}
}

// A posture store whose first Open waits at a gate, so a test sees what a bridge does while it restores.
type stateTestGatedStore struct {
	device.PostureStore
	opened chan struct{}
	gate   chan struct{}
	once   sync.Once
}

func (self *stateTestGatedStore) Open(name string) (io.ReadCloser, error) {
	self.once.Do(func() {
		close(self.opened)
		<-self.gate
	})
	return self.PostureStore.Open(name)
}

// DP1: no hook exists before the restored state applies, since NewBridge has not returned while its store is held, and
// the hook it returns already enforces that state, with no other call. An sdk provider's profile, since the stored state
// carries no identities: the untagged subject's exit row passes and the LAN, under the document, is denied.
func TestBridgeGivesNoHookBeforeTheRestoredState(t *testing.T) {
	store := &stateTestGatedStore{
		PostureStore: device.EnforcingPostureStoreForTest(t, egressTestFixture().Bytes(), true),
		opened:       make(chan struct{}),
		gate:         make(chan struct{}),
	}
	settings := device.DefaultBridgeSettings()
	settings.Clock = sidecartest.NewFakeClock(time.UnixMilli(egressTestTimeMs))
	settings.PolicyProfile = device.BridgePolicyProfileSdkProvider
	built := make(chan *device.Bridge, 1)
	go func() {
		bridgeBridge, err := device.NewBridge(context.Background(), store, nil, settings)
		if err != nil {
			t.Error(err)
		}
		built <- bridgeBridge
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case <-store.opened:
	case <-ctx.Done():
		t.Fatal("the store was never opened")
	}
	select {
	case <-built:
		t.Fatal("a bridge before its store was read")
	default:
	}
	close(store.gate)
	var bridgeBridge *device.Bridge
	select {
	case bridgeBridge = <-built:
	case <-ctx.Done():
		t.Fatal("no bridge")
	}
	if bridgeBridge == nil {
		t.FailNow()
	}
	t.Cleanup(bridgeBridge.Close)
	hook := bridgeBridge.EgressHook()
	if hook.PolicyGeneration() == 0 || bridgeBridge.Status().State != device.PostureEnforcingDocument {
		t.Fatalf("generation %d, %+v", hook.PolicyGeneration(), bridgeBridge.Status())
	}
	sdkFlow := func(to string) *connect.EgressFlow {
		flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to)
		flow.Principal = nil
		return flow
	}
	if decision := hook.ResolveEgress(sdkFlow("203.0.113.9:443")); decision.Verdict != connect.EgressVerdictPass {
		t.Fatalf("an exit row: %+v", decision)
	}
	if decision := hook.ResolveEgress(sdkFlow("192.168.77.20:443")); decision.Verdict != connect.EgressVerdictDeny {
		t.Fatalf("LAN: %+v", decision)
	}
}

// A forged has_document = false, a state whose verified rows say true, changes nothing published: the posture refuses
// it, and the hook keeps the document's rules at its generation.
func TestBridgeForgedNoDocumentLeavesThePolicy(t *testing.T) {
	test := newStateTest(t, egressTestFixture(), true)
	generation := test.bridge.Status().PolicyGeneration
	lan := test.flow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:443")
	if test.verdict(lan) != connect.EgressVerdictDeny {
		t.Fatal("LAN under a document")
	}
	test.log.Tick()
	state, stateLog := test.log.State(egressTestFixture().Bytes(), false)
	state.Identities = stateTestIdentities(egressTestFixture())
	if err := test.bridge.SetState(state, stateLog); !errors.Is(err, device.ErrPostureRefused) {
		t.Fatalf("a forged has_document: %v", err)
	}
	status := test.bridge.Status()
	if status.PolicyGeneration != generation || status.State != device.PostureEnforcingDocument {
		t.Fatalf("%+v", status)
	}
	if test.verdict(lan) != connect.EgressVerdictDeny {
		t.Fatal("LAN opened by an unsigned has_document")
	}
	if tags, _ := test.closer.take(); 0 < len(tags) {
		t.Fatalf("closed %v", tags)
	}
}

// A covered SidecarRevoke between states narrows at once, the posture having applied it on its identity signature
// alone; a next state past it that does not revoke reverses it, and one that does confirms it.
func TestBridgeCoveredDenialNarrowsUntilTheNextState(t *testing.T) {
	fixture := egressTestFixture()
	exit := func(test *stateTest) *connect.EgressFlow {
		return test.flow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	}
	for _, confirm := range []bool{false, true} {
		test := newStateTest(t, fixture, true)
		if test.verdict(exit(test)) != connect.EgressVerdictPass {
			t.Fatal("the exit before")
		}
		pin := test.log.Tip()
		revoke := test.log.SidecarRevoke(sidecartest.BridgeFixtureSidecarId(egressTestUntagged))
		if err := test.bridge.ApplyDeltas(test.log.Deltas(pin+1, revoke)); err != nil {
			t.Fatal(err)
		}
		if test.verdict(exit(test)) != connect.EgressVerdictDeny {
			t.Fatal("the exit after a covered revoke")
		}
		if tags, _ := test.closer.take(); !slices.Contains(tags, egressTestTag(egressTestUntagged, []byte{device.BridgeRuleExit})) {
			t.Fatalf("closed %v", tags)
		}
		test.log.Tick()
		state, stateLog := test.log.State(fixture.Bytes(), true)
		state.Identities = stateTestIdentities(fixture)
		state.Identities[0].Revoked = confirm
		if err := test.bridge.SetState(state, stateLog); err != nil {
			t.Fatal(err)
		}
		want := connect.EgressVerdictPass
		if confirm {
			want = connect.EgressVerdictDeny
		}
		if got := test.verdict(exit(test)); got != want {
			t.Fatalf("confirm %v: %v", confirm, got)
		}
	}
}

// Revoke narrows at once and ends the subject's flows, holds across a state below its position, and a state at its
// position, which carries it or reverses it, takes over; what it cannot name is refused.
func TestBridgeRevokeNarrowsUntilAStatePassesIt(t *testing.T) {
	fixture := egressTestFixture()
	test := newStateTest(t, fixture, true)
	exit := test.flow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	sibling := test.flow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:443")
	revokedAt := test.log.Tip() + 2
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_SUSPEND, sidecartest.BridgeFixtureSidecarId(egressTestUntagged), revokedAt); err != nil {
		t.Fatal(err)
	}
	if test.verdict(exit) != connect.EgressVerdictDeny || test.verdict(sibling) != connect.EgressVerdictMap {
		t.Fatal("after Revoke")
	}
	tags, generations := test.closer.take()
	if !slices.Contains(tags, egressTestTag(egressTestUntagged, []byte{device.BridgeRuleExit})) ||
		slices.Contains(tags, egressTestHostedTag(egressTestTagged, "100.80.1.2")) {
		t.Fatalf("closed %v", tags)
	}
	// every close ran after the swap
	for _, generation := range generations {
		if generation != test.bridge.Status().PolicyGeneration {
			t.Fatalf("a close at generation %d", generation)
		}
	}
	// a state below its position leaves it in force
	test.log.Tick()
	test.setState(fixture, true)
	if test.verdict(exit) != connect.EgressVerdictDeny {
		t.Fatal("a state below the revocation reopened it")
	}
	// a state at its position, which does not suspend, reverses it
	test.log.Tick()
	test.setState(fixture, true)
	if test.verdict(exit) != connect.EgressVerdictPass {
		t.Fatal("a state at the revocation's position")
	}

	// each refusal beside its twin, which differs only where the refusal does
	refusals := []struct {
		statementType bridge.SignedType
		id            []byte
	}{
		{statementType: bridge.SignedType_SIGNED_GRANT_ACTIVATE, id: sidecartest.BridgeFixtureGrantId(1)},
		{statementType: bridge.SignedType_SIGNED_SUSPEND, id: nil},
		{statementType: bridge.SignedType_SIGNED_SUSPEND, id: make([]byte, 65)},
	}
	for _, refusal := range refusals {
		if err := test.bridge.Revoke(refusal.statementType, refusal.id, test.log.Tip()+1); !errors.Is(err, device.ErrBridgeRevocationRefused) {
			t.Errorf("%v: %v", refusal.statementType, err)
		}
	}
	twins := []struct {
		statementType bridge.SignedType
		id            []byte
	}{
		{statementType: bridge.SignedType_SIGNED_GRANT_REVOKE, id: sidecartest.BridgeFixtureGrantId(1)},
		{statementType: bridge.SignedType_SIGNED_SUSPEND, id: make([]byte, 64)},
	}
	for _, twin := range twins {
		if err := test.bridge.Revoke(twin.statementType, twin.id, test.log.Tip()+1); err != nil {
			t.Errorf("the twin %v: %v", twin.statementType, err)
		}
	}
}

// A denial is held at its own position (DESIGN-DETAILS 12.2.5): Revoke at 0, which the bridge once read as the state's
// pin plus one, is refused and narrows, publishes and closes nothing, and its twin at a real position narrows at once.
func TestBridgeRevokeRefusesPositionZero(t *testing.T) {
	test := newStateTest(t, egressTestFixture(), true)
	exit := test.flow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	generation := test.bridge.Status().PolicyGeneration
	err := test.bridge.Revoke(bridge.SignedType_SIGNED_SIDECAR_REVOKE, sidecartest.BridgeFixtureSidecarId(egressTestUntagged), 0)
	if !errors.Is(err, device.ErrBridgeRevocationRefused) {
		t.Fatalf("at 0: %v", err)
	}
	if test.verdict(exit) != connect.EgressVerdictPass || test.bridge.Status().PolicyGeneration != generation {
		t.Fatal("a revocation refused at 0 narrowed or published")
	}
	if tags, _ := test.closer.take(); 0 < len(tags) {
		t.Fatalf("a revocation refused at 0 closed %v", tags)
	}
	n := test.bridge.Status().PinN + 1
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_SIDECAR_REVOKE, sidecartest.BridgeFixtureSidecarId(egressTestUntagged), n); err != nil {
		t.Fatal(err)
	}
	if test.verdict(exit) != connect.EgressVerdictDeny {
		t.Fatal("the twin at its own position")
	}
}

// DenialsOutlive (DESIGN-DETAILS 12.3): a denial applied at n stands across the timer's publishes and a state compiled
// below n that arrives after it, as a late compile's does, and only a state at n takes it over.
func TestBridgeRevokeOutlivesTimersAndALateState(t *testing.T) {
	start := time.UnixMilli(egressTestTimeMs)
	fixture := egressTestFixture()
	fixture.Maps[0].Expires = egressTestTimeMs + 10_000
	test := newStateTest(t, fixture, true)
	exit := test.flow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	// the entry the judge decided lands two past the state in force; the compile before it captured one past
	n := test.log.Tip() + 2
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_SIDECAR_REVOKE, sidecartest.BridgeFixtureSidecarId(egressTestUntagged), n); err != nil {
		t.Fatal(err)
	}
	// the map's expiry publishes on the timer
	test.advanceTo(start.Add(10 * time.Second))
	if test.verdict(exit) != connect.EgressVerdictDeny {
		t.Fatal("a timer's publish dropped the denial")
	}
	test.log.Tick()
	test.setState(fixture, true)
	if test.verdict(exit) != connect.EgressVerdictDeny {
		t.Fatal("a state compiled below the denial dropped it")
	}
	test.log.Tick()
	test.setState(fixture, true)
	if test.verdict(exit) != connect.EgressVerdictPass {
		t.Fatal("a state at the denial's position, which does not revoke, did not take it over")
	}
}

// Revoke past the bound is refused, and the next state, which carries the revocation, is the backstop.
func TestBridgeRevokeRefusesPastItsBound(t *testing.T) {
	clock := sidecartest.NewFakeClock(time.UnixMilli(egressTestTimeMs))
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	settings.RevocationMaxCount = 2
	// pending, which holds them; legacy drops every one, as a wipe does
	bridgeBridge, err := device.NewBridge(context.Background(), device.PendingPostureStoreForTest(t), nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridgeBridge.Close)
	// pending has no state, so any position stands above it
	const revokedAt = 5
	for seed := byte(1); seed <= 2; seed += 1 {
		if err := bridgeBridge.Revoke(bridge.SignedType_SIGNED_GRANT_REVOKE, sidecartest.BridgeFixtureGrantId(seed), revokedAt); err != nil {
			t.Fatal(err)
		}
	}
	// the same one again is held already
	if err := bridgeBridge.Revoke(bridge.SignedType_SIGNED_GRANT_REVOKE, sidecartest.BridgeFixtureGrantId(2), revokedAt); err != nil {
		t.Fatal(err)
	}
	if err := bridgeBridge.Revoke(bridge.SignedType_SIGNED_GRANT_REVOKE, sidecartest.BridgeFixtureGrantId(3), revokedAt); !errors.Is(err, device.ErrBridgeRevocationRefused) {
		t.Fatalf("past the bound: %v", err)
	}
}

// EgressHook is one value that binds: a bound closer hears each close, and once unbound hears none.
func TestBridgeHookBindsTheNatsItIsInstalledOn(t *testing.T) {
	test := newStateTest(t, egressTestFixture(), true)
	if test.bridge.EgressHook() != test.bridge.EgressHook() {
		t.Fatal("two hooks")
	}
	second := &stateTestCloser{hook: test.bridge.EgressHook()}
	unbind := test.bridge.EgressHook().(connect.EgressHookBinder).BindFlowCloser(second)
	n := test.bridge.Status().PinN + 1
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_SIDECAR_REVOKE, sidecartest.BridgeFixtureSidecarId(egressTestUntagged), n); err != nil {
		t.Fatal(err)
	}
	first, _ := test.closer.take()
	both, _ := second.take()
	if len(first) == 0 || !slices.Equal(first, both) {
		t.Fatalf("closers heard %v and %v", first, both)
	}
	unbind()
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_SIDECAR_REVOKE, sidecartest.BridgeFixtureSidecarId(egressTestTagged), n); err != nil {
		t.Fatal(err)
	}
	if tags, _ := second.take(); 0 < len(tags) {
		t.Fatalf("an unbound closer heard %v", tags)
	}
	if tags, _ := test.closer.take(); len(tags) == 0 {
		t.Fatal("the bound closer heard nothing")
	}
}

// Change callbacks run after each publish, and a removed one no longer runs.
func TestBridgeChangeCallbacksRunAfterEachPublish(t *testing.T) {
	test := newStateTest(t, egressTestFixture(), true)
	count := 0
	remove := test.bridge.AddChangeCallback(func() {
		count += 1
	})
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_GRANT_REVOKE, sidecartest.BridgeFixtureGrantId(1), test.bridge.Status().PinN+1); err != nil {
		t.Fatal(err)
	}
	test.log.Tick()
	test.setState(egressTestFixture(), true)
	if count != 2 {
		t.Fatalf("%d calls", count)
	}
	remove()
	test.log.Tick()
	test.setState(egressTestFixture(), true)
	if count != 2 {
		t.Fatalf("%d calls after removal", count)
	}
}
