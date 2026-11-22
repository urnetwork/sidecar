//go:build !ios_extension && !sidecar_http && !js

// A share host's FriendsAndFamily (bridge_share.go; §17.9's isolation row, §6.10.1 items 4 and 5; PROTO-M6-01): held
// on each generation's dispatcher while a state the device role holds in force serves a share whose grant stands,
// released at a GrantRevoke of that grant before any compile, at the grant's expiry, when no state serves the share,
// when its generation ends and at the hold's end; never Public. And through the bridge component over the share world's
// real compile: a host serving an activated share provides FriendsAndFamily beside Network to the platform, a device
// the share names in no target never does, and the share's revocation takes the mode away again.

package sidecar

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A share the rules serve, its grant named by label, with one target; expires zero for a grant with no end.
func testBridgeServedShare(label string, expires time.Time) *bridge.BridgeRuleShare {
	share := &bridge.BridgeRuleShare{
		ShareId:            testConfigId("share " + label).Bytes(),
		AcceptingNetworkId: testConfigId("the accepting network").Bytes(),
		SharePublicKey:     make([]byte, 32),
		GrantId:            testBridgeShareGrantId(label),
		Targets: []*bridge.BridgeRuleShareTarget{
			{Index: 0, AliasHostBits: 0x8001, Length: 32, Target: testBridgePrefix(192, 168, 9, 9, 32)},
		},
	}
	if !expires.IsZero() {
		share.Expires = expires.UnixMilli()
	}
	return share
}

// The grant id of the share label names.
func testBridgeShareGrantId(label string) []byte {
	return testConfigId("grant " + label).Bytes()
}

// A state whose rules serve shares.
func testBridgeShareState(t testing.TB, shares ...*bridge.BridgeRuleShare) *bridge.BridgeState {
	t.Helper()
	rules, err := proto.Marshal(&bridge.BridgeRules{Shares: shares})
	if err != nil {
		t.Fatal(err)
	}
	return &bridge.BridgeState{Auth: &bridge.AuthPin{Version: 7, Chain: make([]byte, 32)}, Rules: rules}
}

// Waits until the hold's goroutine has applied every input given it so far, and answers how many generations it holds
// the mode on. The wait is on the hold's monitor, never a sleep.
func testBridgeShareModeApplied(t testing.TB, mode *bridgeShareMode) int {
	t.Helper()
	mode.stateLock.Lock()
	version := mode.version
	mode.stateLock.Unlock()
	timeout := time.After(time.Minute)
	for {
		applied, changed := mode.applied.Get()
		if version <= applied.version {
			return applied.heldCount
		}
		select {
		case <-changed:
		case <-timeout:
			t.Fatalf("the hold applied version %d, not %d", applied.version, version)
		}
	}
}

// Waits until the hold's goroutine holds the mode on heldCount generations, failing with what describe answers. The
// wait is on the hold's monitor, never a sleep.
func testBridgeShareModeHeld(t testing.TB, mode *bridgeShareMode, heldCount int, describe func() string) {
	t.Helper()
	timeout := time.After(time.Minute)
	for {
		applied, changed := mode.applied.Get()
		if applied.heldCount == heldCount {
			return
		}
		select {
		case <-changed:
		case <-timeout:
			t.Fatalf("the hold holds on %d generations, not %d: %s", applied.heldCount, heldCount, describe())
		}
	}
}

// The modes a dispatcher's client provides, as its provide frame lists them to the platform, sorted.
func testBridgeShareProvided(fixture *testSubprotocol) []connectprotocol.ProvideMode {
	provided := []connectprotocol.ProvideMode{}
	for mode, on := range fixture.client.ContractManager().GetProvideModes() {
		if on {
			provided = append(provided, mode)
		}
	}
	slices.Sort(provided)
	return provided
}

// What a dispatcher provides with a share and without one, sorted as testBridgeShareProvided answers.
var (
	testBridgeShareNetworkOnly = []connectprotocol.ProvideMode{connectprotocol.ProvideMode_Network}
	testBridgeShareShared      = slices.Sorted(slices.Values([]connectprotocol.ProvideMode{connectprotocol.ProvideMode_Network, connectprotocol.ProvideMode_FriendsAndFamily}))
)

// A hold over a fresh test clock, ending with the test.
func newTestBridgeShareMode(t testing.TB) (*bridgeShareMode, *testConfigClock, context.CancelFunc) {
	t.Helper()
	clock := newTestConfigClock()
	ctx, cancel := context.WithCancel(context.Background())
	mode := newBridgeShareMode(ctx, testConfigId("the sharing network"), clock, NewNoopLogger())
	t.Cleanup(func() {
		cancel()
		<-mode.done
	})
	return mode, clock, cancel
}

// The mode is held only while a state in force serves a share: none before, FriendsAndFamily beside Network once a
// state serves one, both at the client the platform reads, and gone again at a state that serves none; rules that do
// not parse serve none; and Public is never among them (D-PROTO-6).
func TestAShareHostHoldsFriendsAndFamilyOnlyWhileAShareStands(t *testing.T) {
	mode, _, _ := newTestBridgeShareMode(t)
	fixture := newTestSubprotocol(t, nil)
	mode.attach(context.Background(), fixture.subprotocol)
	// the fixture's client provides nothing until its dispatcher's first change, where a sidecar's starts on Network
	if held := testBridgeShareModeApplied(t, mode); held != 0 || slices.Contains(testBridgeShareProvided(fixture), connectprotocol.ProvideMode_FriendsAndFamily) {
		t.Fatalf("before any share: held on %d, provided %v", held, testBridgeShareProvided(fixture))
	}
	mode.serve(testBridgeShareState(t, testBridgeServedShare("a", time.Time{})))
	if held := testBridgeShareModeApplied(t, mode); held != 1 || !slices.Equal(testBridgeShareProvided(fixture), testBridgeShareShared) {
		t.Fatalf("a share served: held on %d, provided %v", held, testBridgeShareProvided(fixture))
	}
	if !fixture.subprotocol.providedModes()[connectprotocol.ProvideMode_FriendsAndFamily] {
		t.Error("the dispatcher counts no FriendsAndFamily hold")
	}
	// the same share again holds once
	mode.serve(testBridgeShareState(t, testBridgeServedShare("a", time.Time{})))
	testBridgeShareModeApplied(t, mode)
	if count := fixture.subprotocol.provideModes.heldModeCounts[connectprotocol.ProvideMode_FriendsAndFamily]; count != 1 {
		t.Errorf("%d holds of one share", count)
	}
	mode.serve(testBridgeShareState(t))
	if held := testBridgeShareModeApplied(t, mode); held != 0 || !slices.Equal(testBridgeShareProvided(fixture), testBridgeShareNetworkOnly) {
		t.Fatalf("no share served: held on %d, provided %v", held, testBridgeShareProvided(fixture))
	}
	mode.serve(&bridge.BridgeState{Rules: []byte{0xff, 0xff, 0xff}})
	if held := testBridgeShareModeApplied(t, mode); held != 0 {
		t.Errorf("rules that do not parse held the mode on %d", held)
	}
	if fixture.subprotocol.providedModes()[connectprotocol.ProvideMode_Public] || fixture.client.ContractManager().GetProvideModes()[connectprotocol.ProvideMode_Public] {
		t.Error("Public was provided")
	}
}

// §17.9's revocation: a GrantRevoke of a served share's grant ends that share at once, with no state after it; a grant
// no served share names, or one share of two, leaves the mode held; the last one releases it. A later state that still
// lists a revoked grant keeps it revoked, and one serving a new share holds again.
func TestARevokedShareGrantReleasesFriendsAndFamilyAtOnce(t *testing.T) {
	mode, _, _ := newTestBridgeShareMode(t)
	fixture := newTestSubprotocol(t, nil)
	mode.attach(context.Background(), fixture.subprotocol)
	mode.serve(testBridgeShareState(t, testBridgeServedShare("a", time.Time{}), testBridgeServedShare("b", time.Time{})))
	if held := testBridgeShareModeApplied(t, mode); held != 1 {
		t.Fatalf("two shares served: held on %d", held)
	}
	mode.revoke(testBridgeShareGrantId("unserved"))
	mode.revoke(nil)
	if held := testBridgeShareModeApplied(t, mode); held != 1 {
		t.Fatalf("an unserved grant's revocation: held on %d", held)
	}
	mode.revoke(testBridgeShareGrantId("a"))
	if held := testBridgeShareModeApplied(t, mode); held != 1 || !slices.Equal(testBridgeShareProvided(fixture), testBridgeShareShared) {
		t.Fatalf("one of two shares revoked: held on %d, provided %v", held, testBridgeShareProvided(fixture))
	}
	mode.revoke(testBridgeShareGrantId("b"))
	if held := testBridgeShareModeApplied(t, mode); held != 0 || !slices.Equal(testBridgeShareProvided(fixture), testBridgeShareNetworkOnly) {
		t.Fatalf("both shares revoked: held on %d, provided %v", held, testBridgeShareProvided(fixture))
	}
	mode.serve(testBridgeShareState(t, testBridgeServedShare("b", time.Time{})))
	if held := testBridgeShareModeApplied(t, mode); held != 0 {
		t.Fatalf("a state still listing a revoked grant held the mode on %d", held)
	}
	mode.serve(testBridgeShareState(t, testBridgeServedShare("b", time.Time{}), testBridgeServedShare("c", time.Time{})))
	if held := testBridgeShareModeApplied(t, mode); held != 1 || !slices.Equal(testBridgeShareProvided(fixture), testBridgeShareShared) {
		t.Fatalf("a new share served: held on %d, provided %v", held, testBridgeShareProvided(fixture))
	}
}

// Waits until the hold's loop arms the wake for an end timeout away on clock, which it does once an end, so the test
// moves the clock only once the loop waits for it. The wait is on the clock's arming, never a sleep.
func testBridgeShareModeArmed(t testing.TB, clock *testConfigClock, timeout time.Duration) {
	t.Helper()
	deadline := time.After(time.Minute)
	for {
		select {
		case armed := <-clock.armed:
			if armed == timeout {
				return
			}
		case <-deadline:
			t.Fatalf("no wake armed %v away", timeout)
		}
	}
}

// A share stands until its grant's expires, on the component's clock: the mode is held while it runs and released
// once the clock reaches it, with no state after it; a state served already past its share's end holds nothing; and
// past one share's end the loop arms the next one's and holds on while a share with no end, or a later one, stands.
func TestAShareGrantsExpiryReleasesFriendsAndFamily(t *testing.T) {
	mode, clock, _ := newTestBridgeShareMode(t)
	fixture := newTestSubprotocol(t, nil)
	mode.attach(context.Background(), fixture.subprotocol)
	ends := clock.Now().Add(time.Hour)
	mode.serve(testBridgeShareState(t, testBridgeServedShare("a", ends)))
	if held := testBridgeShareModeApplied(t, mode); held != 1 {
		t.Fatalf("a share before its end: held on %d", held)
	}
	testBridgeShareModeArmed(t, clock, time.Hour)
	clock.Advance(time.Hour)
	testBridgeShareModeHeld(t, mode, 0, func() string { return fmt.Sprint(testBridgeShareProvided(fixture)) })
	if !slices.Equal(testBridgeShareProvided(fixture), testBridgeShareNetworkOnly) {
		t.Fatalf("a share past its end: provided %v", testBridgeShareProvided(fixture))
	}
	mode.serve(testBridgeShareState(t, testBridgeServedShare("b", clock.Now().Add(-time.Minute))))
	if held := testBridgeShareModeApplied(t, mode); held != 0 {
		t.Fatalf("a share served past its end: held on %d", held)
	}
	mode.serve(testBridgeShareState(t, testBridgeServedShare("c", clock.Now().Add(time.Minute)), testBridgeServedShare("d", time.Time{}),
		testBridgeServedShare("e", clock.Now().Add(2*time.Minute))))
	if held := testBridgeShareModeApplied(t, mode); held != 1 {
		t.Fatalf("three shares: held on %d", held)
	}
	testBridgeShareModeArmed(t, clock, time.Minute)
	clock.Advance(time.Minute)
	// the pass past c's end arms e's, a minute on, and holds for d and e
	testBridgeShareModeArmed(t, clock, time.Minute)
	if held := mode.applied.Value().heldCount; held != 1 || !slices.Equal(testBridgeShareProvided(fixture), testBridgeShareShared) {
		t.Fatalf("past one share's end: held on %d, provided %v", held, testBridgeShareProvided(fixture))
	}
	clock.Advance(time.Minute)
	mode.poke()
	if held := testBridgeShareModeApplied(t, mode); held != 1 || !slices.Equal(testBridgeShareProvided(fixture), testBridgeShareShared) {
		t.Fatalf("a share with no end past the others': held on %d, provided %v", held, testBridgeShareProvided(fixture))
	}
}

// Each live generation's dispatcher holds the mode: one attached while a share stands holds at once, one whose
// generation ends releases its own hold and leaves the other's, a generation with no dispatcher holds nothing, and the
// hold's end releases every one.
func TestEachGenerationsDispatcherHoldsWhileItLives(t *testing.T) {
	mode, _, cancel := newTestBridgeShareMode(t)
	first, second := newTestSubprotocol(t, nil), newTestSubprotocol(t, nil)
	firstCtx, endFirst := context.WithCancel(context.Background())
	defer endFirst()
	mode.attach(firstCtx, first.subprotocol)
	mode.attach(context.Background(), nil)
	mode.serve(testBridgeShareState(t, testBridgeServedShare("a", time.Time{})))
	if held := testBridgeShareModeApplied(t, mode); held != 1 {
		t.Fatalf("one generation: held on %d", held)
	}
	mode.attach(context.Background(), second.subprotocol)
	if held := testBridgeShareModeApplied(t, mode); held != 2 || !slices.Equal(testBridgeShareProvided(second), testBridgeShareShared) {
		t.Fatalf("a generation attached while the share stands: held on %d, provided %v", held, testBridgeShareProvided(second))
	}
	endFirst()
	testBridgeShareModeHeld(t, mode, 1, func() string { return fmt.Sprint(testBridgeShareProvided(first)) })
	if !slices.Equal(testBridgeShareProvided(first), testBridgeShareNetworkOnly) || !slices.Equal(testBridgeShareProvided(second), testBridgeShareShared) {
		t.Fatalf("the first generation ended: it provides %v, the second %v", testBridgeShareProvided(first), testBridgeShareProvided(second))
	}
	cancel()
	<-mode.done
	if !slices.Equal(testBridgeShareProvided(second), testBridgeShareNetworkOnly) {
		t.Fatalf("the hold ended: the second generation provides %v", testBridgeShareProvided(second))
	}
}

// A dispatcher that has closed refuses the hold: the generation holds nothing and is not asked again until its
// generation ends, while another generation's dispatcher still holds.
func TestAClosedDispatcherHoldsNothing(t *testing.T) {
	mode, _, _ := newTestBridgeShareMode(t)
	closed, open := newTestSubprotocol(t, nil), newTestSubprotocol(t, nil)
	closed.subprotocol.Close()
	mode.attach(context.Background(), closed.subprotocol)
	mode.attach(context.Background(), open.subprotocol)
	mode.serve(testBridgeShareState(t, testBridgeServedShare("a", time.Time{})))
	if held := testBridgeShareModeApplied(t, mode); held != 1 || !slices.Equal(testBridgeShareProvided(open), testBridgeShareShared) {
		t.Fatalf("one dispatcher closed: held on %d, the open one provides %v", held, testBridgeShareProvided(open))
	}
	var refused []bool
	func() {
		mode.stateLock.Lock()
		defer mode.stateLock.Unlock()
		for _, generation := range mode.generations {
			refused = append(refused, generation.refused)
		}
	}()
	if !slices.Equal(refused, []bool{true, false}) {
		t.Errorf("the generations refused %v", refused)
	}
}

// The share world's net as a bridge component's config (BridgeConfigSource): its own log, its entries' callbacks run as
// a follower runs them, once a post the test made under the follow lock returns, and its kept entries read under that
// lock, so no read meets a write.
type testBridgeShareModeConfig struct {
	net *testConfigNet

	followLock sync.Mutex
	// the newest position the callbacks ran for
	followed uint64

	stateLock    sync.Mutex
	callbacks    map[int]SidecarAuthorityEntryFunction
	callbackNext int
}

var _ BridgeConfigSource = (*testBridgeShareModeConfig)(nil)

func newTestBridgeShareModeConfig(net *testConfigNet) *testBridgeShareModeConfig {
	return &testBridgeShareModeConfig{net: net, followed: net.log.Pin().GetVersion(), callbacks: map[int]SidecarAuthorityEntryFunction{}}
}

func (self *testBridgeShareModeConfig) Log() *ConfigLog {
	return self.net.log
}

func (self *testBridgeShareModeConfig) AddEntryCallback(callback SidecarAuthorityEntryFunction) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := self.callbackNext
	self.callbackNext += 1
	self.callbacks[key] = callback
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.callbacks, key)
	}
}

// The log's state once it holds n; a log behind n waits for ctx, since this log moves only by the test's posts.
func (self *testBridgeShareModeConfig) WaitFor(ctx context.Context, n uint64) (*ConfigState, error) {
	if state := self.net.log.State(); n <= state.Pin().GetVersion() {
		return state, nil
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (self *testBridgeShareModeConfig) BridgeEntries(from uint64, through uint64) []*BridgeConfigEntry {
	self.followLock.Lock()
	defer self.followLock.Unlock()
	log := self.net.log
	reads := []*BridgeConfigEntry{}
	for n := max(from, log.keptFrom); n <= min(through, log.Pin().GetVersion()); n += 1 {
		read := bridgeConfigEntryOf(log, n)
		if read == nil {
			break
		}
		reads = append(reads, read)
	}
	return reads
}

// Runs act, which writes the log, under the follow lock, then each callback for every position it added, in order.
func (self *testBridgeShareModeConfig) post(act func()) {
	self.followLock.Lock()
	defer self.followLock.Unlock()
	act()
	callbacks := func() []SidecarAuthorityEntryFunction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		keys := []int{}
		for key := range self.callbacks {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		callbacks := []SidecarAuthorityEntryFunction{}
		for _, key := range keys {
			callbacks = append(callbacks, self.callbacks[key])
		}
		return callbacks
	}()
	for n := self.followed + 1; n <= self.net.log.Pin().GetVersion(); n += 1 {
		for _, callback := range callbacks {
			callback(&SidecarAuthorityEntry{Pin: &bridge.AuthPin{Version: n}})
		}
	}
	self.followed = self.net.log.Pin().GetVersion()
}

// One device's bridge component over the share world's net, heads and share rows, its device role the test sink and
// its provider connect's stand-ins, with one generation whose dispatcher is a test Subprotocol; closed at the test's
// end.
type testBridgeShareModeHost struct {
	component  *BridgeComponent
	sink       *testBridgeSink
	dispatcher *testSubprotocol
}

func newTestBridgeShareModeHost(t *testing.T, world *testBridgeShareWorld, config *testBridgeShareModeConfig, identity *SidecarIdentity) *testBridgeShareModeHost {
	t.Helper()
	settings := DefaultBridgeComponentSettings()
	settings.CompileDelay = 0
	settings.CompileMinInterval = 0
	// the share's grant runs on the net's clock
	clock := newTestConfigClock()
	clock.now = time.UnixMilli(world.net.timeMs)
	events := newTestBridgeEvents()
	host := &testBridgeShareModeHost{
		sink:       &testBridgeSink{events: events, hook: testBridgeHook{}, decision: BridgeSinkDecision{State: BridgeSinkLegacy}},
		dispatcher: newTestSubprotocol(t, nil),
	}
	component, err := NewBridgeComponent(context.Background(), &BridgeComponentArgs{
		NetworkId: world.net.networkId,
		Identity:  func() *SidecarIdentity { return identity },
		Config:    config,
		Heads:     world.heads,
		Rows:      world.net.source,
		RepoKeyAt: testConfigSealKeyAt(testConfigSealKey(1)),
		ShareRows: world.server,
		Clock:     clock,
		Log:       NewNoopLogger(),
		Settings:  settings,
		parts: &bridgeProviderParts{
			newNat: func(ctx context.Context, settings *connect.LocalUserNatSettings) *connect.LocalUserNat { return nil },
			newProvider: func(client *connect.Client, nat *connect.LocalUserNat) (func(), error) {
				return func() {}, nil
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(component.Close)
	host.component = component
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if err := component.Attach(&SidecarEnv{Ctx: ctx, Subprotocol: host.dispatcher.subprotocol, Log: NewNoopLogger()}); err != nil {
		t.Fatal(err)
	}
	if err := component.SetDeviceRole(host.sink); err != nil {
		t.Fatal(err)
	}
	return host
}

// What the host's component compiled, for a failure's message.
func (self *testBridgeShareModeHost) describe() string {
	status := self.component.Status()
	return fmt.Sprintf("compiled at %d, %d compiles, %d refused, waits %v, alarms %v, provided %v", status.CompiledPin.GetVersion(),
		status.CompileCount, status.CompileErrorCount, status.Waits, status.Alarms, testBridgeShareProvided(self.dispatcher))
}

// Through the component over the real compile: the share's host provides FriendsAndFamily beside Network once its
// state serves the activated share, from its grant file and pinned row, and a device of the network that hosts none
// of the share's targets never does; the sharing network's GrantRevoke takes the mode away at the host at once, the
// denial handed to the device role at its position, and the mode stays away.
func TestTheComponentHoldsFriendsAndFamilyWhileItsShareStands(t *testing.T) {
	world := newTestBridgeShareWorld(t, true)
	// the rule the share's grant is asked under, before any component reads the heads it changes
	world.withSharesRule()
	config := newTestBridgeShareModeConfig(world.net)
	host := newTestBridgeShareModeHost(t, world, config, world.sidecar.currentIdentity())
	laptop := newTestBridgeShareModeHost(t, world, config, &SidecarIdentity{
		NetworkId: world.net.networkId, SidecarId: world.laptop.sidecarId, IdentityPublicKey: world.laptop.publicKey(),
	})
	if held := testBridgeShareModeApplied(t, host.component.shareMode); held != 0 {
		t.Fatalf("before any share the host holds the mode on %d", held)
	}

	// activatedShare's acts past its rule: a share of two targets the host hosts, which the other network completed at
	// two aliases, previewed and activated
	var invite *BridgeShareInvite
	var filing *BridgeFiling
	config.post(func() {
		ctx := context.Background()
		var err error
		invite, err = world.filer.Invite(ctx, world.confirmed(), &BridgeShareInviteRequest{Targets: []*BridgeShareTargetRequest{
			{Host: world.hostId, Prefix: netip.MustParsePrefix("192.168.7.0/24"), Protocol: 6, Ports: []*bridge.BridgePortRange{{First: 443, Last: 443}}},
			{Host: world.hostId, Prefix: netip.MustParsePrefix("192.168.9.9/32")},
		}})
		if err != nil {
			t.Fatal(err)
		}
		world.completed(invite, 0x8100, 0x8001)
		preview, err := world.filer.PreviewShare(ctx, world.confirmed(), invite.ShareId)
		if err != nil {
			t.Fatal(err)
		}
		filing, err = world.filer.ActivateShare(ctx, world.confirmed(), preview, 0)
		if err != nil {
			t.Fatal(err)
		}
		world.install()
	})
	testBridgeShareModeHeld(t, host.component.shareMode, 1, host.describe)
	if !slices.Equal(testBridgeShareProvided(host.dispatcher), testBridgeShareShared) {
		t.Fatalf("the host serving the share provides %v", testBridgeShareProvided(host.dispatcher))
	}
	compiled := host.component.Compiled()
	if served := bridgeServedShares(compiled.State); len(served) != 1 || served[0].shareId != invite.ShareId || string(served[0].grantId) != string(filing.GrantId) {
		t.Fatalf("the host's state serves %v", served)
	}
	// the laptop compiled the same tip and serves nothing of the share
	tip := world.net.log.Pin().GetVersion()
	laptop.sink.events.waitFor(t, "the laptop's state at the share's tip", func(event string) bool {
		return strings.HasPrefix(event, fmt.Sprintf("state %d ", tip))
	})
	if held := testBridgeShareModeApplied(t, laptop.component.shareMode); held != 0 || slices.Contains(testBridgeShareProvided(laptop.dispatcher), connectprotocol.ProvideMode_FriendsAndFamily) {
		t.Fatalf("a device hosting no target holds the mode on %d, provides %v", held, testBridgeShareProvided(laptop.dispatcher))
	}

	compileCount := host.component.Status().CompileCount
	config.post(func() {
		if _, err := world.filer.RevokeShare(context.Background(), world.confirmed(), invite.ShareId); err != nil {
			t.Fatal(err)
		}
	})
	revoked := world.net.log.Pin().GetVersion()
	host.sink.events.waitFor(t, "the GrantRevoke at its position", func(event string) bool {
		return event == fmt.Sprintf("revoke %s %x at %d", bridge.SignedType_SIGNED_GRANT_REVOKE, filing.GrantId, revoked)
	})
	testBridgeShareModeHeld(t, host.component.shareMode, 0, host.describe)
	if !slices.Equal(testBridgeShareProvided(host.dispatcher), testBridgeShareNetworkOnly) {
		t.Fatalf("the revoked share's host provides %v", testBridgeShareProvided(host.dispatcher))
	}
	if count := host.component.Status().CompileCount; count != compileCount {
		t.Logf("the revocation's release came with %d compiles after it", count-compileCount)
	}
}
