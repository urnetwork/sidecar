// Links (bridge_link.go) on sidecartest's FakeBridgeHost and a fake clock: one build per target under concurrent first
// packets, the target's binding verified against the pin before any build, the sidecar role's sign as each window
// client's, a failed sign or build failing closed, idle close at 600 s, rebuild at 6 days with the old link draining to
// its strict_exp, room made by closing the least recently used idle link and never a busy one, no count cap, links off
// at LinkCountMax 0, and Close joining everything.

package device_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// When the link tests start: a synthetic time, ms since the epoch.
const linkTestTimeMs = 1_900_000_000_000

// This network and this device's sidecar, which links sign as.
var (
	linkTestNetworkId = bytes.Repeat([]byte{0x7E, 0x01}, 8)
	linkTestSidecarId = sidecartest.BridgeFixtureSidecarId(9)
)

// The client key of a target's client, by its seed.
func linkTestClientKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xC7, seed}, 16))
}

// A target as the rules pin it, by its seed.
func linkTestTarget(seed byte) device.BridgeLinkTarget {
	target := device.BridgeLinkTarget{
		ClientId:  sidecartest.BridgeFixtureClientId(seed),
		SidecarId: connect.Id(sidecartest.BridgeFixtureSidecarId(seed)),
	}
	copy(target.IdentityPublicKey[:], sidecartest.BridgeFixtureIdentityKey(seed).Public().(ed25519.PublicKey))
	return target
}

// The binding of a target's client, edit applied to its body, signed by identityKey and the client key.
func linkTestSignedBinding(t *testing.T, seed byte, identityKey ed25519.PrivateKey, edit func(body *bridge.SidecarIdentityBinding)) []byte {
	t.Helper()
	clientKey := linkTestClientKey(seed)
	clientId := sidecartest.BridgeFixtureClientId(seed)
	body := &bridge.SidecarIdentityBinding{
		NetworkId:         linkTestNetworkId,
		SidecarId:         sidecartest.BridgeFixtureSidecarId(seed),
		ClientId:          clientId[:],
		Generation:        1,
		ClientPublicKey:   clientKey.Public().(ed25519.PublicKey),
		IdentityPublicKey: sidecartest.BridgeFixtureIdentityKey(seed).Public().(ed25519.PublicKey),
		IssuedAtMs:        linkTestTimeMs,
	}
	if edit != nil {
		edit(body)
	}
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	signed := &bridge.SignedSidecarIdentityBinding{
		Body: bodyBytes,
		ClientSignature: ed25519.Sign(clientKey,
			bridge.SignedBytes("binding-client", bridge.SignedType_SIGNED_SIDECAR_BINDING, bodyBytes)),
		IdentitySignature: ed25519.Sign(identityKey,
			bridge.SignedBytes("binding-identity", bridge.SignedType_SIGNED_SIDECAR_BINDING, bodyBytes)),
	}
	signedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return signedBytes
}

// A target's binding as its host would fetch it.
func linkTestBinding(t *testing.T, seed byte) []byte {
	t.Helper()
	return linkTestSignedBinding(t, seed, sidecartest.BridgeFixtureIdentityKey(seed), nil)
}

// A manager on FakeBridgeHost and a fake clock, signing as this device's sidecar, whose fetch answers from bindings.
type linkTest struct {
	t       *testing.T
	clock   *sidecartest.FakeClock
	host    *sidecartest.FakeBridgeHost
	manager *device.BridgeLinkManager
	passes  <-chan struct{}
	downs   chan device.BridgeLinkId
	changes chan struct{}

	stateLock sync.Mutex
	bindings  map[connect.Id][]byte
	signed    []*bridge.WindowDelegation
	signErr   error
}

// A link test whose settings edit adjusts, its window clients expiring 7 days after the start.
func newLinkTest(t *testing.T, edit func(settings *device.BridgeSettings)) *linkTest {
	t.Helper()
	clock := sidecartest.NewFakeClock(time.UnixMilli(linkTestTimeMs))
	self := &linkTest{
		t:        t,
		clock:    clock,
		host:     sidecartest.NewFakeBridgeHost(clock.Now().Add(7 * 24 * time.Hour)),
		downs:    make(chan device.BridgeLinkId, 256),
		changes:  make(chan struct{}, 1),
		bindings: map[connect.Id][]byte{},
	}
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	settings.LinkSign = self.sign
	settings.LinkTargetKey = self.targetKey
	if edit != nil {
		edit(settings)
	}
	self.manager = device.NewBridgeLinkManager(context.Background(), self.host, settings)
	t.Cleanup(self.manager.Close)
	self.passes = self.manager.WatchForTest()
	self.manager.AddDownCallback(func(link device.BridgeLinkId) {
		self.downs <- link
	})
	self.manager.AddChangeCallback(func() {
		select {
		case self.changes <- struct{}{}:
		default:
		}
	})
	self.manager.SetIdentity(linkTestNetworkId, linkTestSidecarId)
	return self
}

// The sidecar role's sign: a synthetic Signed per window client, or the error set.
func (self *linkTest) sign(ctx context.Context, delegation *bridge.WindowDelegation) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.signErr != nil {
		return nil, self.signErr
	}
	self.signed = append(self.signed, proto.Clone(delegation).(*bridge.WindowDelegation))
	return append([]byte("signed delegation of "), delegation.GetWindowClientId()...), nil
}

// The host's fetch: the binding the test gave the client, or an error.
func (self *linkTest) targetKey(ctx context.Context, targetSidecarId connect.Id, targetClientId connect.Id) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	binding := self.bindings[targetClientId]
	if binding == nil {
		return nil, errors.New("no binding")
	}
	return binding, nil
}

// Gives the target its binding, as api would answer it.
func (self *linkTest) setBinding(seed byte, binding []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.bindings[sidecartest.BridgeFixtureClientId(seed)] = binding
}

func (self *linkTest) setSignErr(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.signErr = err
}

func (self *linkTest) signedDelegations() []*bridge.WindowDelegation {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*bridge.WindowDelegation(nil), self.signed...)
}

// Waits until done says so, checking again after each pass of the manager and each build's end.
func (self *linkTest) await(what string, done func() bool) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for !done() {
		select {
		case <-self.passes:
		case <-ctx.Done():
			self.t.Fatalf("%s did not happen", what)
		}
	}
}

// Waits until the manager's run has a timer at at, so moving the clock there fires it.
func (self *linkTest) awaitTimerAt(at time.Time) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for {
		pending, added := self.clock.WatchTimers()
		for _, timer := range pending {
			if timer.Equal(at) {
				return
			}
		}
		select {
		case <-added:
		case <-ctx.Done():
			self.t.Fatalf("no timer at %v; pending %v", at, pending)
		}
	}
}

// The link of a target with a binding, as Retain gives it.
func (self *linkTest) link(seed byte) device.BridgeLinkId {
	self.t.Helper()
	self.setBinding(seed, linkTestBinding(self.t, seed))
	return self.retainedLink(seed)
}

// The current link Retain gives the target now, keeping the targets of seeds only.
func (self *linkTest) retainedLink(seed byte, otherSeeds ...byte) device.BridgeLinkId {
	self.t.Helper()
	targets := []device.BridgeLinkTarget{linkTestTarget(seed)}
	for _, other := range otherSeeds {
		targets = append(targets, linkTestTarget(other))
	}
	uses := self.manager.Retain(targets)[linkTestTarget(seed)]
	for _, use := range uses {
		if use.DrainingSince.IsZero() {
			return use.Link
		}
	}
	self.t.Fatalf("target %d has no current link: %v", seed, uses)
	return 0
}

// Routes a packet to link until it has a client and returns it, sealed so no connect timeout marks it down.
func (self *linkTest) open(link device.BridgeLinkId) *sidecartest.FakeBridgeLink {
	self.t.Helper()
	if _, route := self.manager.RouteForTest(link); route == "reject" {
		self.t.Fatalf("link %d rejects", link)
	}
	self.await("the build", func() bool { return self.manager.LinkBuiltForTest(link) })
	self.manager.SealForTest(link)
	client, route := self.manager.RouteForTest(link)
	if route != "client" {
		self.t.Fatalf("link %d routes %s once built", link, route)
	}
	return client.(*sidecartest.FakeBridgeLink)
}

// Takes the next link reported down.
func (self *linkTest) awaitDown() device.BridgeLinkId {
	self.t.Helper()
	select {
	case link := <-self.downs:
		return link
	case <-time.After(time.Minute):
		self.t.Fatal("no link was reported down")
		return 0
	}
}

// Many first packets at once build one link, its client's bypass off, signed for as this device's sidecar.
func TestBridgeLinkBuildsOncePerTargetUnderConcurrentFirstPackets(t *testing.T) {
	test := newLinkTest(t, nil)
	link := test.link(4)
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	for range 32 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			if _, route := test.manager.RouteForTest(link); route == "reject" {
				t.Error("a first packet was rejected")
			}
		}()
	}
	close(start)
	waitGroup.Wait()
	client := test.open(link)
	for range 8 {
		test.manager.RouteForTest(link)
	}
	target := linkTestTarget(4)
	if count := test.host.BuildCount(target.ClientId); count != 1 {
		t.Fatalf("%d builds, want 1", count)
	}
	if client.LocalSecurityBypass() {
		t.Fatal("the link kept the local security bypass on")
	}
	builds := test.host.Builds()
	if builds[0].Subject != connect.Id(linkTestSidecarId) || builds[0].ShareAliases != nil {
		t.Fatalf("built for subject %v with aliases %v", builds[0].Subject, builds[0].ShareAliases)
	}
	signed := test.signedDelegations()
	if len(signed) != 1 {
		t.Fatalf("%d delegations signed, want 1", len(signed))
	}
	delegation := signed[0]
	if !bytes.Equal(delegation.GetNetworkId(), linkTestNetworkId) || !bytes.Equal(delegation.GetSubjectSidecarId(), linkTestSidecarId) ||
		!bytes.Equal(delegation.GetTargetSidecarId(), target.SidecarId.Bytes()) ||
		!bytes.Equal(delegation.GetWindowClientId(), builds[0].WindowClientId.Bytes()) ||
		len(delegation.GetWindowClientPublicKey()) != ed25519.PublicKeySize ||
		delegation.GetNotAfterMs() != linkTestTimeMs+7*24*3600*1000 || 0 < len(delegation.GetShareId()) {
		t.Fatalf("delegation %v", delegation)
	}
	if !bytes.Equal(builds[0].Delegation, append([]byte("signed delegation of "), delegation.GetWindowClientId()...)) {
		t.Fatal("the window client did not get what the sidecar role signed")
	}
}

// Each fault of a binding alone refuses the build before the host is asked, so no window client exists, and the
// link rejects until LinkDownTimeout has passed; the positive twin builds.
func TestBridgeLinkRefusesATargetWhoseBindingDoesNotVerify(t *testing.T) {
	otherIdentityKey := sidecartest.BridgeFixtureIdentityKey(5)
	faults := []struct {
		name    string
		binding func(t *testing.T) []byte
	}{
		{name: "another network", binding: func(t *testing.T) []byte {
			return linkTestSignedBinding(t, 4, sidecartest.BridgeFixtureIdentityKey(4), func(body *bridge.SidecarIdentityBinding) {
				body.NetworkId = bytes.Repeat([]byte{0x7E, 0x02}, 8)
			})
		}},
		{name: "another sidecar", binding: func(t *testing.T) []byte {
			return linkTestSignedBinding(t, 4, sidecartest.BridgeFixtureIdentityKey(4), func(body *bridge.SidecarIdentityBinding) {
				body.SidecarId = sidecartest.BridgeFixtureSidecarId(5)
			})
		}},
		{name: "another client", binding: func(t *testing.T) []byte {
			return linkTestSignedBinding(t, 4, sidecartest.BridgeFixtureIdentityKey(4), func(body *bridge.SidecarIdentityBinding) {
				clientId := sidecartest.BridgeFixtureClientId(5)
				body.ClientId = clientId[:]
			})
		}},
		{name: "a substituted identity key", binding: func(t *testing.T) []byte {
			return linkTestSignedBinding(t, 4, otherIdentityKey, func(body *bridge.SidecarIdentityBinding) {
				body.IdentityPublicKey = otherIdentityKey.Public().(ed25519.PublicKey)
			})
		}},
		{name: "an identity signature by another key", binding: func(t *testing.T) []byte {
			return linkTestSignedBinding(t, 4, otherIdentityKey, nil)
		}},
		{name: "the identity key as client key", binding: func(t *testing.T) []byte {
			return linkTestSignedBinding(t, 4, sidecartest.BridgeFixtureIdentityKey(4), func(body *bridge.SidecarIdentityBinding) {
				body.ClientPublicKey = body.IdentityPublicKey
			})
		}},
		{name: "a generation of 0", binding: func(t *testing.T) []byte {
			return linkTestSignedBinding(t, 4, sidecartest.BridgeFixtureIdentityKey(4), func(body *bridge.SidecarIdentityBinding) {
				body.Generation = 0
			})
		}},
		{name: "a client signature that does not verify", binding: func(t *testing.T) []byte {
			signedBytes := linkTestBinding(t, 4)
			signed := &bridge.SignedSidecarIdentityBinding{}
			if err := proto.Unmarshal(signedBytes, signed); err != nil {
				t.Fatal(err)
			}
			signed.ClientSignature[0] ^= 0xFF
			encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
			if err != nil {
				t.Fatal(err)
			}
			return encoded
		}},
		{name: "an unknown field", binding: func(t *testing.T) []byte {
			return append(linkTestBinding(t, 4), 0x78, 0x01)
		}},
		{name: "nothing", binding: func(t *testing.T) []byte {
			return []byte{}
		}},
	}
	for _, fault := range faults {
		test := newLinkTest(t, nil)
		link := test.retainedLink(4)
		test.setBinding(4, fault.binding(t))
		if _, route := test.manager.RouteForTest(link); route != "wait" {
			t.Fatalf("%s: the first packet routes %s", fault.name, route)
		}
		if down := test.awaitDown(); down != link {
			t.Fatalf("%s: link %d down, want %d", fault.name, down, link)
		}
		if builds := test.host.Builds(); len(builds) != 0 {
			t.Fatalf("%s: the host was asked for %d builds", fault.name, len(builds))
		}
		if _, route := test.manager.RouteForTest(link); route != "reject" {
			t.Fatalf("%s: routes %s while the build waits to try again", fault.name, route)
		}
	}
	test := newLinkTest(t, nil)
	test.open(test.link(4))
	if count := test.host.BuildCount(linkTestTarget(4).ClientId); count != 1 {
		t.Fatalf("the positive twin built %d links", count)
	}
}

// A sign the sidecar role refuses leaves the link with no client, so no contract can be made, and it rejects; after
// LinkDownTimeout a packet builds it again.
func TestBridgeLinkSignErrorFailsClosed(t *testing.T) {
	test := newLinkTest(t, nil)
	link := test.link(4)
	test.setSignErr(errors.New("the sidecar role is asleep"))
	test.manager.RouteForTest(link)
	if down := test.awaitDown(); down != link {
		t.Fatalf("link %d down, want %d", down, link)
	}
	builds := test.host.Builds()
	if len(builds) != 1 || builds[0].Link != nil || builds[0].Err == nil || builds[0].Delegation != nil {
		t.Fatalf("builds %+v", builds)
	}
	if _, route := test.manager.RouteForTest(link); route != "reject" {
		t.Fatalf("routes %s after a failed sign", route)
	}
	test.setSignErr(nil)
	test.clock.Advance(30 * time.Second)
	test.open(link)
	if count := test.host.BuildCount(linkTestTarget(4).ClientId); count != 1 {
		t.Fatalf("%d links built once the role signed", count)
	}
}

// A link that carried nothing for 600 s closes, one that carried a packet since stays open until 600 s after it, and
// a closed link builds again at its next packet.
func TestBridgeLinkIdlesOutAt600Seconds(t *testing.T) {
	test := newLinkTest(t, nil)
	start := test.clock.Now()
	link := test.link(4)
	first := test.open(link)
	test.awaitTimerAt(start.Add(600 * time.Second))
	test.clock.Advance(300 * time.Second)
	test.manager.RouteForTest(link)
	test.clock.AdvanceTo(start.Add(600 * time.Second))
	test.awaitTimerAt(start.Add(900 * time.Second))
	if first.Closed() {
		t.Fatal("a link that carried a packet 300 s ago closed")
	}
	test.clock.AdvanceTo(start.Add(900 * time.Second))
	test.await("the idle close", func() bool { return first.Closed() && !test.manager.LinkBuiltForTest(link) })
	second := test.open(link)
	if second == first || test.host.BuildCount(linkTestTarget(4).ClientId) != 2 {
		t.Fatal("the next packet did not build the link again")
	}
}

// At 6 days a link is replaced: the new one takes new pairs while the old one drains until its window clients'
// strict_exp, then closes and leaves its target.
func TestBridgeLinkRebuildsAfterSixDaysAndDrainsUntilStrictExp(t *testing.T) {
	test := newLinkTest(t, func(settings *device.BridgeSettings) {
		settings.LinkIdleTimeout = 8 * 24 * time.Hour
	})
	start := test.clock.Now()
	link := test.link(4)
	old := test.open(link)
	test.awaitTimerAt(start.Add(6 * 24 * time.Hour))
	test.clock.AdvanceTo(start.Add(6 * 24 * time.Hour))
	test.await("the replacement", func() bool {
		uses := test.manager.Retain([]device.BridgeLinkTarget{linkTestTarget(4)})[linkTestTarget(4)]
		return len(uses) == 2
	})
	uses := test.manager.Retain([]device.BridgeLinkTarget{linkTestTarget(4)})[linkTestTarget(4)]
	if uses[0].Link != link || !uses[0].DrainingSince.Equal(start.Add(6*24*time.Hour)) ||
		!uses[0].DrainUntil.Equal(start.Add(7*24*time.Hour)) {
		t.Fatalf("the old link's use %+v", uses[0])
	}
	successor := uses[1].Link
	if !uses[1].DrainingSince.IsZero() || successor == link {
		t.Fatalf("the new link's use %+v", uses[1])
	}
	test.await("the new link's build", func() bool { return test.manager.LinkBuiltForTest(successor) })
	if client, route := test.manager.RouteForTest(link); route != "client" || client != old || old.Closed() {
		t.Fatal("the old link stopped serving its pairs while it drains")
	}
	test.awaitTimerAt(start.Add(7 * 24 * time.Hour))
	test.clock.AdvanceTo(start.Add(7 * 24 * time.Hour))
	test.await("the drain's end", func() bool { return old.Closed() })
	uses = test.manager.Retain([]device.BridgeLinkTarget{linkTestTarget(4)})[linkTestTarget(4)]
	if len(uses) != 1 || uses[0].Link != successor {
		t.Fatalf("uses after the drain %+v", uses)
	}
	if _, route := test.manager.RouteForTest(link); route != "reject" {
		t.Fatalf("the drained link routes %s", route)
	}
}

// Past LinkCountMax, a build closes the least recently used link idle for LinkRoomIdleTimeout, never a busy one.
func TestBridgeLinkRoomClosesTheLeastRecentlyUsedIdleLink(t *testing.T) {
	test := newLinkTest(t, func(settings *device.BridgeSettings) {
		settings.LinkCountMax = 2
	})
	for _, seed := range []byte{4, 5, 6} {
		test.setBinding(seed, linkTestBinding(t, seed))
	}
	idle := test.open(test.retainedLink(4, 5, 6))
	busy := test.open(test.retainedLink(5, 4, 6))
	test.clock.Advance(61 * time.Second)
	test.manager.RouteForTest(test.retainedLink(5, 4, 6))
	third := test.open(test.retainedLink(6, 4, 5))
	if !idle.Closed() || busy.Closed() || third.Closed() {
		t.Fatalf("closed: idle %v, busy %v, new %v", idle.Closed(), busy.Closed(), third.Closed())
	}
	if openCount, _ := test.manager.CountsForTest(); openCount != 2 {
		t.Fatalf("%d links open, want 2", openCount)
	}
}

// LinkCountMax is no cap (R-BRIDGE-11): with every link busy, builds past it go ahead and none closes.
func TestBridgeLinkCountIsNoCap(t *testing.T) {
	test := newLinkTest(t, func(settings *device.BridgeSettings) {
		settings.LinkCountMax = 2
	})
	seeds := []byte{4, 5, 6, 7, 8}
	clients := []*sidecartest.FakeBridgeLink{}
	for i, seed := range seeds {
		test.setBinding(seed, linkTestBinding(t, seed))
		others := append(append([]byte(nil), seeds[:i]...), seeds[i+1:]...)
		clients = append(clients, test.open(test.retainedLink(seed, others...)))
	}
	for i, client := range clients {
		if client.Closed() {
			t.Fatalf("busy link %d closed for room", i)
		}
	}
	if openCount, _ := test.manager.CountsForTest(); openCount != len(seeds) {
		t.Fatalf("%d links open, want %d", openCount, len(seeds))
	}
}

// LinkCountMax 0, the iOS tunnel's setting, builds no link, and neither does a bridge with no signer or fetch: each
// link rejects, which fails closed.
func TestBridgeLinkBuildsNothingWithoutWhatABuildNeeds(t *testing.T) {
	edits := map[string]func(settings *device.BridgeSettings){
		"links off":  func(settings *device.BridgeSettings) { settings.LinkCountMax = 0 },
		"no signer":  func(settings *device.BridgeSettings) { settings.LinkSign = nil },
		"no fetcher": func(settings *device.BridgeSettings) { settings.LinkTargetKey = nil },
	}
	for name, edit := range edits {
		test := newLinkTest(t, edit)
		link := test.link(4)
		if client, route := test.manager.RouteForTest(link); route != "reject" || client != nil {
			t.Fatalf("%s: routes %s", name, route)
		}
		if builds := test.host.Builds(); len(builds) != 0 {
			t.Fatalf("%s: %d builds", name, len(builds))
		}
	}
	test := newLinkTest(t, nil)
	test.manager.SetIdentity(nil, nil)
	if _, route := test.manager.RouteForTest(test.link(4)); route != "reject" {
		t.Fatalf("with no identity to sign as, routes %s", route)
	}
}

// A target that leaves the rules takes its link with it: its client closes, and its id rejects.
func TestBridgeLinkLeavesWithItsTarget(t *testing.T) {
	test := newLinkTest(t, nil)
	link := test.link(4)
	client := test.open(link)
	test.manager.Retain(nil)
	test.await("the close", func() bool { return client.Closed() })
	if _, route := test.manager.RouteForTest(link); route != "reject" {
		t.Fatalf("a link whose target left routes %s", route)
	}
}

// Close joins run and every build and closes every client; nothing of the manager runs after it.
func TestBridgeLinkCloseJoinsEverything(t *testing.T) {
	test := newLinkTest(t, nil)
	clients := []*sidecartest.FakeBridgeLink{}
	for _, seed := range []byte{4, 5} {
		test.setBinding(seed, linkTestBinding(t, seed))
	}
	clients = append(clients, test.open(test.retainedLink(4, 5)), test.open(test.retainedLink(5, 4)))
	test.manager.Close()
	for i, client := range clients {
		if !client.Closed() {
			t.Fatalf("client %d left open", i)
		}
	}
	var stacks strings.Builder
	if err := pprof.Lookup("goroutine").WriteTo(&stacks, 1); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stacks.String(), "device.(*BridgeLinkManager)") {
		t.Fatalf("a goroutine of the manager outlived Close:\n%s", stacks.String())
	}
}

// The settings both hosts build from: one fixed window client, Required, relayed, ICMP on, the target alone, no parked
// identity; and the guard refuses DefaultMultiClientSettings.
func TestBridgeLinkSettings(t *testing.T) {
	settings := device.DefaultBridgeSettings()
	multiClientSettings := device.BridgeLinkMultiClientSettings(settings)
	if err := device.CheckBridgeLinkMultiClientSettings(multiClientSettings, false); err != nil {
		t.Fatal(err)
	}
	profile := multiClientSettings.DefaultPerformanceProfile
	if profile.WindowSize.FixedWindowSize != 1 || profile.WindowSize.WindowSizeMax != 1 || !profile.PostQuantumEncryption {
		t.Fatalf("profile %+v", profile)
	}
	if multiClientSettings.OverrideAllowDirect == nil || *multiClientSettings.OverrideAllowDirect || !multiClientSettings.EnableIcmp {
		t.Fatal("direct mode is not overridden off, or ICMP is off")
	}
	if err := device.CheckBridgeLinkMultiClientSettings(connect.DefaultMultiClientSettings(), false); !errors.Is(err, device.ErrBridgeLinkSettingsInvalid) {
		t.Fatalf("the guard took DefaultMultiClientSettings: %v", err)
	}
	direct := device.DefaultBridgeSettings()
	direct.LinkAllowDirect = true
	if err := device.CheckBridgeLinkMultiClientSettings(device.BridgeLinkMultiClientSettings(direct), false); err == nil {
		t.Fatal("the guard took direct mode where the bridge sets it off")
	}
	target := sidecartest.BridgeFixtureClientId(4)
	specs := device.BridgeLinkProviderSpecs(target)
	if len(specs) != 1 || specs[0].ClientId == nil || *specs[0].ClientId != target || specs[0].BestAvailable {
		t.Fatalf("specs %+v", specs)
	}
	base := connect.DefaultApiMultiClientGeneratorSettings()
	generatorSettings := device.BridgeLinkApiMultiClientGeneratorSettings(base)
	if generatorSettings.ReuseFixedDestinationIdentities || !base.ReuseFixedDestinationIdentities {
		t.Fatal("the link's generator parks identities, or the host's settings changed")
	}
}
