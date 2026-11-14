// The sender's router (bridge_route.go) on a bridge enforcing a fixture's rules, its links on FakeBridgeHost and its
// clock fake: the default route untouched, a link entry's packet refused while its link builds and carried once it is
// built, unassigned and service addresses rejected, TCP/25 to a link rejected and to the default route untouched, a
// carve taking the default route, an entry whose advertiser is revoked rejecting for 600 s and then leaving, the egress
// spec's exits and none, and RouteBurst's order, sameness and ownership.

package device_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// When the route tests start: a synthetic time, ms since the epoch.
const routeTestTimeMs = 1_900_000_000_000

// The posture fixture's network, which a state's links sign for and their targets' bindings name.
var routeTestNetworkId = bytes.Repeat([]byte{0x01}, 16)

// The rules the route tests run on: the block with its services and unassigned addresses, a host with one link, a host
// with two advertisers, and a subnet route.
func routeTestFixture() *sidecartest.BridgeRulesFixture {
	return &sidecartest.BridgeRulesFixture{
		Block:     "100.80.0.0/16",
		Addresses: []string{"100.80.1.2"},
		Entries: []sidecartest.BridgeRulesFixtureEntry{
			{Prefix: "100.80.0.0/16", Kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_UNASSIGNED},
			{Prefix: "100.80.0.0/24", Kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE},
			{Prefix: "100.80.1.4", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 4}}},
			{Prefix: "100.80.1.5", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 5}, {Target: 6}}},
			{Prefix: "192.0.2.0/24", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 7, Route: 1}}},
		},
	}
}

// A bridge enforcing fixture's rules, as the route tests drive it.
type routeTest struct {
	t      testing.TB
	clock  *sidecartest.FakeClock
	host   *sidecartest.FakeBridgeHost
	bridge *device.Bridge
	passes <-chan struct{}

	stateLock sync.Mutex
	received  [][]byte
}

// A route test on fixture, settings adjusted by edit, with no local network unless edit gives one.
func newRouteTest(t testing.TB, fixture *sidecartest.BridgeRulesFixture, edit func(settings *device.BridgeSettings)) *routeTest {
	t.Helper()
	clock := sidecartest.NewFakeClock(time.UnixMilli(routeTestTimeMs))
	self := &routeTest{t: t, clock: clock, host: sidecartest.NewFakeBridgeHost(clock.Now().Add(7 * 24 * time.Hour))}
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	settings.LinkSign = func(ctx context.Context, delegation *bridge.WindowDelegation) ([]byte, error) {
		return []byte("signed"), nil
	}
	settings.LinkTargetKey = func(ctx context.Context, targetSidecarId connect.Id, targetClientId connect.Id) ([]byte, error) {
		// a fixture client's id alternates its mark and its seed
		seed := targetClientId[1]
		return linkTestSignedBinding(t, routeTestNetworkId, seed, sidecartest.BridgeFixtureIdentityKey(seed), nil), nil
	}
	settings.LocalIpv4Networks = func() []netip.Prefix { return nil }
	if edit != nil {
		edit(settings)
	}
	store := device.EnforcingPostureStoreForTest(t, fixture.Bytes(), true)
	bridgeBridge, err := device.NewBridge(context.Background(), store, self.host, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bridgeBridge.Close)
	self.bridge = bridgeBridge
	self.passes = bridgeBridge.LinksForTest().WatchForTest()
	bridgeBridge.SetReceivePacket(func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.received = append(self.received, bytes.Clone(packet))
	})
	return self
}

// Waits until the clock has a timer at at, so moving the clock there fires it.
func (self *routeTest) awaitTimerAt(at time.Time) {
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

// The packets the bridge wrote into the tun since the last take.
func (self *routeTest) takeReceived() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	received := self.received
	self.received = nil
	return received
}

// Routes packet until a link carries it, and returns that link: the first packet asks for the build.
func (self *routeTest) awaitLink(packet []byte) *sidecartest.FakeBridgeLink {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for {
		if link, ok := self.bridge.Route(packet).(*sidecartest.FakeBridgeLink); ok {
			return link
		}
		select {
		case <-self.passes:
		case <-ctx.Done():
			self.t.Fatal("no link came to carry the packet")
			return nil
		}
	}
}

// An IPv4 packet of protocol from source to destination, carrying transport.
func routeTestPacket(protocolNumber byte, source string, destination string, transport []byte) []byte {
	packet := make([]byte, 20+len(transport))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocolNumber
	sourceOctets := netip.MustParseAddr(source).As4()
	copy(packet[12:16], sourceOctets[:])
	destinationOctets := netip.MustParseAddr(destination).As4()
	copy(packet[16:20], destinationOctets[:])
	copy(packet[20:], transport)
	return packet
}

// A TCP SYN from source port 40000 to destination's port.
func routeTestTcp(source string, destination string, port uint16) []byte {
	transport := make([]byte, 20)
	binary.BigEndian.PutUint16(transport[0:2], 40000)
	binary.BigEndian.PutUint16(transport[2:4], port)
	transport[12] = 0x50
	transport[13] = 0x02
	return routeTestPacket(6, source, destination, transport)
}

// A UDP datagram from source port 40000 to destination's port.
func routeTestUdp(source string, destination string, port uint16) []byte {
	transport := make([]byte, 12)
	binary.BigEndian.PutUint16(transport[0:2], 40000)
	binary.BigEndian.PutUint16(transport[2:4], port)
	binary.BigEndian.PutUint16(transport[4:6], 12)
	return routeTestPacket(17, source, destination, transport)
}

const routeTestSource = "100.80.1.2"

// Whether client refuses a packet, leaving it the caller's: a link still building.
func routeTestRefuses(client connect.UserNatClient) bool {
	if client == nil {
		return false
	}
	if _, ok := client.(*device.BridgeRejectClient); ok {
		return false
	}
	return !client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, routeTestUdp(routeTestSource, "100.80.1.4", 9), time.Second)
}

// A destination no entry holds takes the default route; a non-IPv4 or short packet does too.
func TestBridgeRouteLeavesTheDefaultRouteAlone(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	for _, packet := range [][]byte{
		routeTestUdp(routeTestSource, "203.0.113.9", 443),
		routeTestTcp(routeTestSource, "203.0.113.9", 25),
		{0x60, 0, 0, 0},
		{0x45, 0},
	} {
		if client := test.bridge.Route(packet); client != nil {
			t.Fatalf("a default packet routed to %T", client)
		}
	}
}

// A host's packet waits behind a refusal while its link builds, then rides the link, which was built once.
func TestBridgeRouteCarriesALinkEntryOverItsLink(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	packet := routeTestUdp(routeTestSource, "100.80.1.4", 9)
	if client := test.bridge.Route(packet); !routeTestRefuses(client) {
		t.Fatalf("the first packet routed to %T, not a refusal", client)
	}
	link := test.awaitLink(packet)
	if link.Target != sidecartest.BridgeFixtureClientId(4) {
		t.Fatalf("carried to %v", link.Target)
	}
	if !link.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, packet, time.Second) || len(link.Packets()) != 1 {
		t.Fatal("the link did not take the packet")
	}
	if count := test.host.BuildCount(sidecartest.BridgeFixtureClientId(4)); count != 1 {
		t.Fatalf("%d builds", count)
	}
}

// An unassigned block address and the services' other addresses answer with a reject, sent into the tun.
func TestBridgeRouteRejectsUnassignedAndServiceAddresses(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	for _, destination := range []string{"100.80.9.9", "100.80.0.7"} {
		client := test.bridge.Route(routeTestTcp(routeTestSource, destination, 80))
		reject, ok := client.(*device.BridgeRejectClient)
		if !ok {
			t.Fatalf("%s routed to %T", destination, client)
		}
		reject.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, routeTestTcp(routeTestSource, destination, 80), time.Second)
	}
	received := test.takeReceived()
	if len(received) != 2 {
		t.Fatalf("%d rejects written", len(received))
	}
	for _, reply := range received {
		// a reset back to the source, from the destination
		if reply[9] != 6 || netip.AddrFrom4([4]byte(reply[16:20])) != netip.MustParseAddr(routeTestSource) || reply[33]&0x04 == 0 {
			t.Fatalf("reply %x is not a reset to the source", reply)
		}
	}
}

// TCP to port 25 of a link entry answers with a reset and never reaches a link (plan-BRIDGE-small-readings #3); to the
// default route it is untouched; UDP to port 25 of a link entry rides the link.
func TestBridgeRouteRefusesBridgedSmtp(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	if _, ok := test.bridge.Route(routeTestTcp(routeTestSource, "100.80.1.4", 25)).(*device.BridgeRejectClient); !ok {
		t.Fatal("bridged TCP/25 was not rejected")
	}
	if _, ok := test.bridge.Route(routeTestTcp(routeTestSource, "192.0.2.10", 25)).(*device.BridgeRejectClient); !ok {
		t.Fatal("TCP/25 over a subnet route was not rejected")
	}
	if client := test.bridge.Route(routeTestTcp(routeTestSource, "203.0.113.9", 25)); client != nil {
		t.Fatalf("TCP/25 on the default route routed to %T", client)
	}
	if builds := test.host.Builds(); len(builds) != 0 {
		t.Fatalf("TCP/25 built %d links", len(builds))
	}
	test.awaitLink(routeTestUdp(routeTestSource, "100.80.1.4", 25))
}

// A local /32 the physical path needs takes the default route, however an entry covers it, and one that is a host's
// overlay address warns in the status (D-BRIDGE-16).
func TestBridgeRouteCarvedAddressTakesTheDefaultRoute(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	test.bridge.SetLocalAddresses([]netip.Addr{netip.MustParseAddr("100.80.1.4"), netip.MustParseAddr("192.0.2.1")})
	for _, destination := range []string{"100.80.1.4", "192.0.2.1"} {
		if client := test.bridge.Route(routeTestUdp(routeTestSource, destination, 9)); client != nil {
			t.Fatalf("carved %s routed to %T", destination, client)
		}
	}
	if _, ok := test.bridge.Route(routeTestUdp(routeTestSource, "192.0.2.2", 9)).(*device.BridgeRejectClient); ok {
		t.Fatal("a neighbor of a carve was rejected")
	}
	status := test.bridge.Status()
	found := false
	for _, alarm := range status.Alarms {
		found = found || alarm.Kind == device.BridgeAlarmCarvedAddress
	}
	if !found {
		t.Fatalf("no warning for a carved host address: %v", status.Alarms)
	}
}

// An entry whose last advertiser is revoked rejects at once, its pins dropped, for RejectEntryHoldTimeout, then leaves
// the table: a subnet route outside the block then takes the default route (§17.8's revocation row).
func TestBridgeRouteRevokedEntryRejectsThenLeaves(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	packet := routeTestUdp(routeTestSource, "192.0.2.10", 9)
	test.awaitLink(packet)
	if err := test.bridge.Revoke(bridge.SignedType_SIGNED_SIDECAR_REVOKE, sidecartest.BridgeFixtureSidecarId(7), test.bridge.Status().PinN+1); err != nil {
		t.Fatal(err)
	}
	if _, ok := test.bridge.Route(packet).(*device.BridgeRejectClient); !ok {
		t.Fatal("an entry with its advertiser revoked did not reject")
	}
	if status := test.bridge.Status(); status.HeldRejectCount != 1 {
		t.Fatalf("held %d entries", status.HeldRejectCount)
	}
	changes := make(chan struct{}, 1)
	test.bridge.AddChangeCallback(func() {
		select {
		case changes <- struct{}{}:
		default:
		}
	})
	holdEnd := time.UnixMilli(routeTestTimeMs).Add(600 * time.Second)
	test.awaitTimerAt(holdEnd)
	test.clock.AdvanceTo(holdEnd.Add(-time.Millisecond))
	if _, ok := test.bridge.Route(packet).(*device.BridgeRejectClient); !ok {
		t.Fatal("the entry left before its hold ended")
	}
	test.clock.AdvanceTo(holdEnd)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for test.bridge.Route(packet) != nil {
		select {
		case <-changes:
		case <-ctx.Done():
			t.Fatal("after its hold the entry still routes")
		}
	}
	// the host's own link entry never left
	test.awaitLink(routeTestUdp(routeTestSource, "100.80.1.4", 9))
}

// Under the egress spec's exits, a destination no entry holds rides an exit, a carve keeps the default route and TCP/25
// rejects; under none it rejects.
func TestBridgeRouteFollowsTheEgressSpec(t *testing.T) {
	fixture := routeTestFixture()
	fixture.Egress = &sidecartest.BridgeRulesFixtureEgress{
		Mode:  bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS,
		Exits: []sidecartest.BridgeRulesFixtureLink{{Target: 8, Route: 2}},
	}
	test := newRouteTest(t, fixture, nil)
	exit := test.awaitLink(routeTestUdp(routeTestSource, "203.0.113.9", 443))
	if exit.Target != sidecartest.BridgeFixtureClientId(8) {
		t.Fatalf("exited over %v", exit.Target)
	}
	if _, ok := test.bridge.Route(routeTestTcp(routeTestSource, "203.0.113.9", 25)).(*device.BridgeRejectClient); !ok {
		t.Fatal("TCP/25 rode an exit")
	}
	test.bridge.SetLocalAddresses([]netip.Addr{netip.MustParseAddr("203.0.113.1")})
	if client := test.bridge.Route(routeTestUdp(routeTestSource, "203.0.113.1", 53)); client != nil {
		t.Fatalf("a carve under exits routed to %T", client)
	}
	if status := test.bridge.Status(); status.EgressMode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS {
		t.Fatalf("egress mode %v", status.EgressMode)
	}

	none := routeTestFixture()
	none.Egress = &sidecartest.BridgeRulesFixtureEgress{Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE}
	test = newRouteTest(t, none, nil)
	if _, ok := test.bridge.Route(routeTestUdp(routeTestSource, "203.0.113.9", 443)).(*device.BridgeRejectClient); !ok {
		t.Fatal("under none a public destination was not rejected")
	}
}

// With LinkCountMax 0, the iOS tunnel's setting, a link entry answers with a reject, failing closed.
func TestBridgeRouteRejectsWhereNoLinkCanBeBuilt(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), func(settings *device.BridgeSettings) {
		settings.LinkCountMax = 0
	})
	if _, ok := test.bridge.Route(routeTestUdp(routeTestSource, "100.80.1.4", 9)).(*device.BridgeRejectClient); !ok {
		t.Fatal("a link entry with links off was not rejected")
	}
}

// A burst splits by route keeping each route's packets in order, routes in the order they first appear; a burst all of
// one route passes as the same slice; and each packet reaches exactly one send, the pool balanced after.
func TestBridgeRouteBurstKeepsOrderAndOwnership(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	link := test.awaitLink(routeTestUdp(routeTestSource, "100.80.1.4", 9))
	takenBefore, returnedBefore, _ := connect.MessagePoolCounts()
	violationsBefore := connect.MessagePoolViolationCount()
	pooled := func(packet []byte) []byte {
		copied := connect.MessagePoolGet(len(packet))
		copy(copied, packet)
		return copied
	}
	packets := [][]byte{}
	for i := range 70 {
		switch i % 3 {
		case 0:
			packets = append(packets, pooled(routeTestUdp(routeTestSource, "100.80.1.4", uint16(1000+i))))
		case 1:
			packets = append(packets, pooled(routeTestUdp(routeTestSource, "203.0.113.9", uint16(1000+i))))
		default:
			packets = append(packets, pooled(routeTestUdp(routeTestSource, "100.80.9.9", uint16(1000+i))))
		}
	}
	type sent struct {
		client connect.UserNatClient
		ports  []uint16
	}
	sends := []sent{}
	test.bridge.RouteBurst(packets, func(client connect.UserNatClient, batch [][]byte) {
		ports := []uint16{}
		for _, packet := range batch {
			ports = append(ports, binary.BigEndian.Uint16(packet[22:24]))
			if client == nil {
				connect.MessagePoolReturn(packet)
			} else if !client.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, packet, time.Second) {
				connect.MessagePoolReturn(packet)
			}
		}
		sends = append(sends, sent{client: client, ports: ports})
	})
	// 64 then 6: each split sends the link's, the default's and the rejects' in that order
	if len(sends) != 6 {
		t.Fatalf("%d sends, want 6", len(sends))
	}
	for i, send := range sends {
		for j := 1; j < len(send.ports); j += 1 {
			if send.ports[j] <= send.ports[j-1] {
				t.Fatalf("send %d out of order: %v", i, send.ports)
			}
		}
	}
	if sends[0].client != link || sends[1].client != nil {
		t.Fatalf("first split sent to %T then %T", sends[0].client, sends[1].client)
	}
	if _, ok := sends[2].client.(*device.BridgeRejectClient); !ok {
		t.Fatalf("third send went to %T", sends[2].client)
	}
	takenAfter, returnedAfter, _ := connect.MessagePoolCounts()
	if takenAfter-takenBefore != returnedAfter-returnedBefore {
		t.Fatalf("pool: %d taken, %d returned", takenAfter-takenBefore, returnedAfter-returnedBefore)
	}
	if connect.MessagePoolViolationCount() != violationsBefore {
		t.Fatal("a pool buffer was returned twice")
	}

	defaults := [][]byte{}
	for i := range 130 {
		defaults = append(defaults, routeTestUdp(routeTestSource, "203.0.113.9", uint16(i)))
	}
	sendCount := 0
	test.bridge.RouteBurst(defaults, func(client connect.UserNatClient, batch [][]byte) {
		sendCount += 1
		if client != nil || len(batch) != len(defaults) || &batch[0] != &defaults[0] {
			t.Fatalf("an all-default burst was split: %T, %d packets", client, len(batch))
		}
	})
	if sendCount != 1 {
		t.Fatalf("%d sends of an all-default burst", sendCount)
	}
}

// Route allocates nothing: on a default packet, on a link and on a pin hit.
func TestBridgeRouteAllocatesNothing(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	single := routeTestUdp(routeTestSource, "100.80.1.4", 9)
	test.awaitLink(single)
	pinned := routeTestUdp(routeTestSource, "100.80.1.5", 9)
	test.awaitLink(pinned)
	for name, packet := range map[string][]byte{
		"default": routeTestUdp(routeTestSource, "203.0.113.9", 9),
		"link":    single,
		"pin hit": pinned,
	} {
		if allocs := testing.AllocsPerRun(1000, func() { test.bridge.Route(packet) }); allocs != 0 {
			t.Fatalf("%s: %v allocations a route", name, allocs)
		}
	}
}

// A link entry to an app host carries the client key the rules pin (BridgeRuleLink.target_client_public_key) into
// its link, which is then built with no binding fetched (§17.9's target row; owner decision 197).
func TestBridgeRouteBuildsAnAppHostsLinkFromThePinnedClientKey(t *testing.T) {
	fixture := routeTestFixture()
	fixture.Entries[2].Links[0].HostClientKey = linkTestClientKey(4).Public().(ed25519.PublicKey)
	var fetchCount atomic.Int64
	test := newRouteTest(t, fixture, func(settings *device.BridgeSettings) {
		settings.LinkTargetKey = func(ctx context.Context, targetSidecarId connect.Id, targetClientId connect.Id) ([]byte, error) {
			fetchCount.Add(1)
			return nil, errors.New("an app host's binding is never fetched")
		}
	})
	packet := routeTestUdp(routeTestSource, "100.80.1.4", 9)
	if client := test.bridge.Route(packet); !routeTestRefuses(client) {
		t.Fatalf("the first packet routed to %T, not a refusal", client)
	}
	link := test.awaitLink(packet)
	if link.Target != sidecartest.BridgeFixtureClientId(4) {
		t.Fatalf("carried to %v", link.Target)
	}
	if fetchCount.Load() != 0 {
		t.Fatalf("%d bindings fetched for an app host", fetchCount.Load())
	}
}
