// Reach events (bridge_reach.go): a flow a granted row admits reaches the bridge's reach callbacks with its grant and
// its peer, a forward by a dial grant and a route by a route or an exit grant; a policy rule's row, the allow-all with
// no document and a deny report nothing; a share flow's event names its source network; the report costs the packet
// path no allocation, with room in the ring and with none; a full ring and a full waiting table drop and count; events
// wait for the sidecar role's callback; and an event holds no address of the flow it reports.

package device_test

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The grants of the reach tests' rows.
const (
	reachTestForwardGrant byte = 1
	reachTestRangeGrant   byte = 2
	reachTestRouteGrant   byte = 3
	reachTestRemapGrant   byte = 4
	reachTestExitGrant    byte = 5
	reachTestTaggedGrant  byte = 6
)

// A host's rules whose rows carry grants: maps onto loopback and a LAN range, a served subnet, a remapped one and an
// exit; the untagged subject's granted dial, route and exit rows beside one policy rule's row; and the tagged
// subject's policy row ahead of a granted row for the same port.
func reachTestFixture() *sidecartest.BridgeRulesFixture {
	return &sidecartest.BridgeRulesFixture{
		Block:     "100.80.0.0/16",
		Addresses: []string{"100.80.1.2"},
		Maps: []sidecartest.BridgeRulesFixtureMap{
			{Map: 1, Match: "100.80.1.2", Ports: "tcp:5432", Target: "127.0.0.1:5432"},
			{Map: 2, Match: "100.80.1.2", Ports: "tcp:8000-8010", Target: "192.168.1.20:9000"},
		},
		Served: []sidecartest.BridgeRulesFixtureServed{
			{Route: 1, Prefix: "192.168.50.0/24"},
			{Route: 2, Prefix: "192.168.60.0/24", Exposed: "100.80.200.0/24"},
			{Route: 3, Exit: true},
		},
		Subjects: []sidecartest.BridgeRulesFixtureSubject{
			{
				Sidecar: egressTestUntagged,
				Dial: []sidecartest.BridgeRulesFixtureReach{
					{Ports: "tcp:5432", Grant: reachTestForwardGrant},
					{Ports: "tcp:8000-8010", Grant: reachTestRangeGrant, Expires: egressTestTimeMs + egressTestHourMs},
					{Ports: "tcp:22"},
				},
				Route: []sidecartest.BridgeRulesFixtureReach{
					{Prefix: "192.168.50.0/24", Ports: "tcp:443", Grant: reachTestRouteGrant},
					{Prefix: "100.80.200.0/24", Ports: "tcp:443", Grant: reachTestRemapGrant},
				},
				Exit: []sidecartest.BridgeRulesFixtureReach{{Ports: "tcp:443", Grant: reachTestExitGrant}},
			},
			{
				Sidecar: egressTestTagged,
				Tagged:  true,
				Dial: []sidecartest.BridgeRulesFixtureReach{
					{Ports: "tcp:5432"},
					{Ports: "tcp:5432", Grant: reachTestTaggedGrant},
				},
			},
		},
	}
}

// A host bridge enforcing the reach fixture under a document, and the events its reach callback took.
type reachTest struct {
	*stateTest
	events chan device.BridgeReachEvent
}

// The bridge, its settings adjusted by edit, with a reach callback that queues each event.
func newReachTest(t *testing.T, edit func(settings *device.BridgeSettings)) *reachTest {
	t.Helper()
	self := &reachTest{
		stateTest: newStateTestWithSettings(t, reachTestFixture(), true, edit),
		events:    make(chan device.BridgeReachEvent, 256),
	}
	return self
}

// Adds the queueing callback, removed with the test.
func (self *reachTest) follow() {
	self.t.Cleanup(self.bridge.AddReachCallback(func(event device.BridgeReachEvent) {
		self.events <- event
	}))
}

// The next event the callback took. The context is the guard that fails a test no event comes to.
func (self *reachTest) next() device.BridgeReachEvent {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	select {
	case event := <-self.events:
		return event
	case <-ctx.Done():
		self.t.Fatal("no reach event")
		return device.BridgeReachEvent{}
	}
}

// Decides flow, which must not be denied.
func (self *reachTest) admit(flow *connect.EgressFlow) {
	self.t.Helper()
	if self.verdict(flow) == connect.EgressVerdictDeny {
		self.t.Fatalf("%v denied", flow.To)
	}
}

// The synthetic grant id as an event carries it.
func reachTestGrantId(seed byte) [32]byte {
	return [32]byte(sidecartest.BridgeFixtureGrantId(seed))
}

// The peer a subject's events name.
func reachTestPeer(subjectSeed byte) connect.Id {
	return connect.Id(sidecartest.BridgeFixtureSidecarId(subjectSeed))
}

// A decided flow reaches the callback with its grant and its peer: a map by a dial grant is a forward naming the
// target's port, with the row's expiry and the state's log position.
func TestBridgeReachForwardNamesItsGrantAndPeer(t *testing.T) {
	test := newReachTest(t, nil)
	test.follow()
	test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"))
	event := test.next()
	want := device.BridgeReachEvent{
		Kind:          device.BridgeReachKindForward,
		GrantId:       reachTestGrantId(reachTestForwardGrant),
		Peer:          reachTestPeer(egressTestUntagged),
		TargetPort:    5432,
		PolicyVersion: test.log.Tip(),
		StreamCount:   1,
	}
	if event != want {
		t.Fatalf("event %+v, want %+v", event, want)
	}

	// a range map: the port past the map, and the row's expiry
	test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:8003"))
	event = test.next()
	want = device.BridgeReachEvent{
		Kind:               device.BridgeReachKindForward,
		GrantId:            reachTestGrantId(reachTestRangeGrant),
		Peer:               reachTestPeer(egressTestUntagged),
		TargetPort:         9003,
		PolicyVersion:      test.log.Tip(),
		GrantExpiresMillis: egressTestTimeMs + egressTestHourMs,
		StreamCount:        1,
	}
	if event != want {
		t.Fatalf("event %+v, want %+v", event, want)
	}
	if status := test.bridge.Status(); status.ReachNotedCount != 2 || status.ReachDroppedCount != 0 {
		t.Fatalf("noted %d, dropped %d", status.ReachNotedCount, status.ReachDroppedCount)
	}
}

// A served prefix, its remap and an exit report a route under their own grants, with no port.
func TestBridgeReachRouteNamesItsGrantAndPeer(t *testing.T) {
	test := newReachTest(t, nil)
	test.follow()
	cases := []struct {
		to    string
		grant byte
	}{
		{to: "192.168.50.9:443", grant: reachTestRouteGrant},
		{to: "100.80.200.9:443", grant: reachTestRemapGrant},
		{to: "203.0.113.9:443", grant: reachTestExitGrant},
	}
	for _, c := range cases {
		test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, c.to))
		event := test.next()
		want := device.BridgeReachEvent{
			Kind:          device.BridgeReachKindRoute,
			GrantId:       reachTestGrantId(c.grant),
			Peer:          reachTestPeer(egressTestUntagged),
			PolicyVersion: test.log.Tip(),
			StreamCount:   1,
		}
		if event != want {
			t.Errorf("%s: event %+v, want %+v", c.to, event, want)
		}
	}
}

// A flow a requested grant admits is reported under it though a policy rule's row stands ahead of it; a flow only a
// policy rule's row admits, and a denied one, report nothing.
func TestBridgeReachReportsOnlyGrantedRows(t *testing.T) {
	test := newReachTest(t, nil)
	test.follow()
	// a policy rule's row alone: rule 3's hosted address, port 22
	test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:22"))
	// denied: no row for the port, and a subject with no route row
	for _, flow := range []*connect.EgressFlow{
		test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:23"),
		test.flow(egressTestTagged, connect.IpProtocolTcp, "192.168.50.9:443"),
	} {
		if verdict := test.verdict(flow); verdict != connect.EgressVerdictDeny {
			t.Fatalf("%v: verdict %v", flow.To, verdict)
		}
	}
	// the tagged subject's granted row, behind its policy row: the one event, so nothing above reported
	test.admit(test.flow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:5432"))
	event := test.next()
	if event.GrantId != reachTestGrantId(reachTestTaggedGrant) || event.Peer != reachTestPeer(egressTestTagged) ||
		event.Kind != device.BridgeReachKindForward || event.StreamCount != 1 {
		t.Fatalf("event %+v", event)
	}
	if status := test.bridge.Status(); status.ReachNotedCount != 1 || status.ReachWaitingCount != 0 || status.ReachDroppedCount != 0 {
		t.Fatalf("noted %d, waiting %d, dropped %d", status.ReachNotedCount, status.ReachWaitingCount, status.ReachDroppedCount)
	}
}

// With no document an untagged subject's flows pass by rule 4 and rule 3 with no row, so no grant is enforced and
// nothing is reported, though the rows carry grants.
func TestBridgeReachAllowAllReportsNothing(t *testing.T) {
	fixture := reachTestFixture()
	test := &reachTest{
		stateTest: newStateTestWithSettings(t, fixture, false, nil),
		events:    make(chan device.BridgeReachEvent, 256),
	}
	test.follow()
	for _, to := range []string{"192.168.77.20:443", "100.80.1.2:22", "100.80.200.9:443"} {
		test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, to))
	}
	// a map still goes by its dial row, the one event
	test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"))
	if event := test.next(); event.GrantId != reachTestGrantId(reachTestForwardGrant) {
		t.Fatalf("event %+v", event)
	}
	if status := test.bridge.Status(); status.ReachNotedCount != 1 {
		t.Fatalf("noted %d", status.ReachNotedCount)
	}
}

// A share flow's event names its source network, read from the verified principal, and a same-network flow's names
// none (§17.9). The hook admits no share principal until BRIDGE-M6-05, so this holds the fill a share's row will use.
func TestBridgeReachShareNamesTheSourceNetwork(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, reachTestFixture())
	sourceNetwork := connect.Id(sidecartest.BridgeFixtureSidecarId(0xC1))
	flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432")
	flow.Principal.Network = sourceNetwork
	flow.Principal.ShareId = connect.Id(sidecartest.BridgeFixtureSidecarId(0xC2))
	grantId := sidecartest.BridgeFixtureGrantId(reachTestForwardGrant)
	event := test.policy.ReachEventForTest(device.BridgeReachKindForward, grantId, reachTestPeer(egressTestUntagged), flow, 5432)
	if event.SourceNetwork != sourceNetwork || event.Peer != reachTestPeer(egressTestUntagged) ||
		event.GrantId != reachTestGrantId(reachTestForwardGrant) || event.StreamCount != 1 {
		t.Fatalf("share event %+v", event)
	}
	// the twin: this network's own flow names no source network, whatever network its seal carries
	own := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432")
	event = test.policy.ReachEventForTest(device.BridgeReachKindForward, grantId, reachTestPeer(egressTestUntagged), own, 5432)
	if event.SourceNetwork != (connect.Id{}) || event.StreamCount != 1 {
		t.Fatalf("own event %+v", event)
	}
	// a row with no grant, and a flow with no peer to name, fill nothing
	if event := test.policy.ReachEventForTest(device.BridgeReachKindForward, nil, reachTestPeer(egressTestUntagged), own, 5432); event != (device.BridgeReachEvent{}) {
		t.Fatalf("no grant: %+v", event)
	}
	unsealed := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	unsealed.SourceSubject = connect.Id{}
	if event := test.policy.ReachEventForTest(device.BridgeReachKindRoute, grantId, connect.Id{}, unsealed, 0); event != (device.BridgeReachEvent{}) {
		t.Fatalf("no peer: %+v", event)
	}
}

// At an sdk provider another client, which no subject binds, is named by the client id C13 sealed, under the untagged
// rows' grant, and a client a subject binds by that subject's sidecar.
func TestBridgeReachSdkProviderNamesAnotherClient(t *testing.T) {
	fixture := reachTestFixture()
	fixture.Untagged = &sidecartest.BridgeRulesFixtureUntagged{
		Exit: []sidecartest.BridgeRulesFixtureReach{{Ports: "tcp:443", Grant: reachTestTaggedGrant}},
	}
	test := &reachTest{
		stateTest: newStateTestWithSettings(t, fixture, true, func(settings *device.BridgeSettings) {
			settings.PolicyProfile = device.BridgePolicyProfileSdkProvider
		}),
		events: make(chan device.BridgeReachEvent, 256),
	}
	test.follow()
	other := test.flow(0x7F, connect.IpProtocolTcp, "203.0.113.9:443")
	other.Principal = nil
	test.admit(other)
	event := test.next()
	if event.Peer != sidecartest.BridgeFixtureClientId(0x7F) || event.Kind != device.BridgeReachKindRoute ||
		event.GrantId != reachTestGrantId(reachTestTaggedGrant) || event.StreamCount != 1 {
		t.Fatalf("another client's event %+v", event)
	}
	bound := test.flow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	bound.Principal = nil
	test.admit(bound)
	event = test.next()
	if event.Peer != reachTestPeer(egressTestUntagged) || event.GrantId != reachTestGrantId(reachTestExitGrant) {
		t.Fatalf("a bound client's event %+v", event)
	}
}

// A bare policy on settings, published from fixture's rules under a document, with each subject's identity.
func newReachPolicy(t *testing.T, settings *device.BridgeSettings, fixture *sidecartest.BridgeRulesFixture) *device.BridgeEgressPolicy {
	t.Helper()
	rules, err := device.ParseBridgeRules(fixture.Bytes(), settings)
	if err != nil {
		t.Fatal(err)
	}
	policy := device.NewBridgeEgressPolicy(device.BridgePolicyProfileHost, settings)
	policy.Publish(&device.BridgePolicyInput{
		State:          device.PostureEnforcingDocument,
		BridgeState:    &bridge.BridgeState{DaemonListeners: egressTestListeners, Identities: stateTestIdentities(fixture)},
		Rules:          rules,
		NetworkId:      egressTestNetworkId,
		SidecarId:      egressTestHostId,
		LocalAddresses: []netip.Addr{netip.MustParseAddr("192.168.77.10")},
	})
	return policy
}

// Zero packet-path allocation: ResolveEgress on flows granted rows admit allocates nothing while the ring has room,
// and nothing once it is full, where each report is dropped and counted.
func TestBridgeReachReportAllocatesNothing(t *testing.T) {
	clock := &egressTestClock{now: time.UnixMilli(egressTestTimeMs)}
	fixture := reachTestFixture()
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	// room for every report of the first measurement: AllocsPerRun calls once to warm up, then 100 times a flow
	settings.ReachQueueCount = 1024
	policy := newReachPolicy(t, settings, fixture)
	flows := []*connect.EgressFlow{
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"),
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.9:443"),
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.200.9:443"),
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443"),
		egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:5432"),
	}
	for _, flow := range flows {
		if allocations := testing.AllocsPerRun(100, func() { policy.ResolveEgress(flow) }); allocations != 0 {
			t.Errorf("%v with room: %v allocations", flow.To, allocations)
		}
	}
	if dropped := policy.ReachDroppedCountForTest(); dropped != 0 {
		t.Fatalf("%d reports dropped with room in the ring", dropped)
	}
	// nothing drains a bare policy's ring, so the rest of its 1,024 slots fill and every report past them drops
	for range 1024 {
		policy.ResolveEgress(flows[0])
	}
	before := policy.ReachDroppedCountForTest()
	if before == 0 {
		t.Fatal("the ring never filled")
	}
	for _, flow := range flows {
		if allocations := testing.AllocsPerRun(100, func() { policy.ResolveEgress(flow) }); allocations != 0 {
			t.Errorf("%v with a full ring: %v allocations", flow.To, allocations)
		}
	}
	if after := policy.ReachDroppedCountForTest(); after != before+uint64(len(flows))*101 {
		t.Fatalf("dropped %d, want %d", after, before+uint64(len(flows))*101)
	}
	// a full ring changes no decision
	if decision := policy.ResolveEgress(flows[0]); decision.Verdict != connect.EgressVerdictMap {
		t.Fatalf("verdict %v with a full ring", decision.Verdict)
	}
}

// A policy whose settings turn reach off reports nothing and decides as before.
func TestBridgeReachOffReportsNothing(t *testing.T) {
	test := newReachTest(t, func(settings *device.BridgeSettings) {
		settings.ReachQueueCount = 0
	})
	test.follow()
	test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"))
	// with no ring nothing is ever reported, so there is nothing to wait out
	if status := test.bridge.Status(); status.ReachNotedCount != 0 || status.ReachWaitingCount != 0 || status.ReachDroppedCount != 0 {
		t.Fatalf("noted %d, waiting %d, dropped %d", status.ReachNotedCount, status.ReachWaitingCount, status.ReachDroppedCount)
	}
	select {
	case event := <-test.events:
		t.Fatalf("event %+v with reach off", event)
	default:
	}
}

// One event of the reach tests' own making.
func reachTestEvent(grantSeed byte, peerSeed byte) device.BridgeReachEvent {
	return device.BridgeReachEvent{
		Kind:        device.BridgeReachKindForward,
		GrantId:     reachTestGrantId(grantSeed),
		Peer:        reachTestPeer(peerSeed),
		TargetPort:  5432,
		StreamCount: 1,
	}
}

// Overflow counted, the ring's: offers past its slots are refused and counted, the events it holds are delivered
// whole, and the ring takes offers again once drained.
func TestBridgeReachFullRingDropsAndCounts(t *testing.T) {
	settings := device.DefaultBridgeSettings()
	settings.ReachQueueCount = 3
	reach := device.NewBridgeReachForTest(settings)
	if reach.SlotCount() != 4 {
		t.Fatalf("%d slots, want 3 rounded up to 4", reach.SlotCount())
	}
	for i := range 7 {
		if took := reach.Offer(reachTestEvent(byte(1+i), egressTestUntagged)); took != (i < 4) {
			t.Fatalf("offer %d: %v", i, took)
		}
	}
	if _, _, dropped := reach.Counts(); dropped != 3 {
		t.Fatalf("dropped %d, want 3", dropped)
	}
	events := []device.BridgeReachEvent{}
	reach.AddCallback(func(event device.BridgeReachEvent) { events = append(events, event) })
	reach.Drain()
	if len(events) != 4 {
		t.Fatalf("%d events, want 4", len(events))
	}
	for i, event := range events {
		// in the order decided
		if event != reachTestEvent(byte(1+i), egressTestUntagged) {
			t.Fatalf("event %d: %+v", i, event)
		}
	}
	// two turns of the ring more, each taken whole
	for turn := range 2 {
		for i := range 4 {
			if !reach.Offer(reachTestEvent(byte(10+i), egressTestUntagged)) {
				t.Fatalf("turn %d offer %d refused after a drain", turn, i)
			}
		}
		reach.Drain()
	}
	noted, waiting, dropped := reach.Counts()
	if len(events) != 12 || noted != 12 || waiting != 0 || dropped != 3 {
		t.Fatalf("%d events, noted %d, waiting %d, dropped %d", len(events), noted, waiting, dropped)
	}
}

// Many flows' goroutines report at once while the drain runs: every report is either delivered once or counted
// dropped, none lost and none twice.
func TestBridgeReachConcurrentReportsAreDeliveredOrCounted(t *testing.T) {
	settings := device.DefaultBridgeSettings()
	settings.ReachQueueCount = 8
	reach := device.NewBridgeReachForTest(settings)
	delivered := map[[32]byte]uint64{}
	reach.AddCallback(func(event device.BridgeReachEvent) { delivered[event.GrantId] += event.StreamCount })
	const producerCount = 8
	const offerCount = 2000
	refused := make([]uint64, producerCount)
	done := make(chan struct{})
	var producers sync.WaitGroup
	for producer := range producerCount {
		producers.Add(1)
		go func() {
			defer producers.Done()
			for range offerCount {
				if !reach.Offer(reachTestEvent(byte(1+producer), egressTestUntagged)) {
					refused[producer] += 1
				}
			}
		}()
	}
	go func() {
		producers.Wait()
		close(done)
	}()
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		reach.Drain()
	}
	reach.Drain()
	noted, waiting, dropped := reach.Counts()
	refusedCount := uint64(0)
	for producer := range producerCount {
		refusedCount += refused[producer]
		if got := delivered[reachTestGrantId(byte(1+producer))] + refused[producer]; got != offerCount {
			t.Errorf("producer %d: %d delivered or refused, want %d", producer, got, offerCount)
		}
	}
	if waiting != 0 || dropped != refusedCount || noted+dropped != producerCount*offerCount {
		t.Fatalf("noted %d, waiting %d, dropped %d, refused %d", noted, waiting, dropped, refusedCount)
	}
}

// A keyless role's events wait for its sidecar role in bounded memory: with no callback they coalesce per (grant,
// peer), one more distinct event than ReachWaitingCount is dropped and counted, and the first callback takes what
// waited, each pair's flows summed.
func TestBridgeReachWaitsForACallbackInBoundedMemory(t *testing.T) {
	settings := device.DefaultBridgeSettings()
	settings.ReachQueueCount = 16
	settings.ReachWaitingCount = 2
	reach := device.NewBridgeReachForTest(settings)
	// three flows of one pair, two of a second, then a third pair the table has no room for, twice
	offers := []device.BridgeReachEvent{
		reachTestEvent(1, egressTestUntagged), reachTestEvent(1, egressTestUntagged), reachTestEvent(2, egressTestUntagged),
		reachTestEvent(1, egressTestUntagged), reachTestEvent(3, egressTestUntagged), reachTestEvent(2, egressTestUntagged),
		reachTestEvent(3, egressTestUntagged),
	}
	for i, event := range offers {
		// a later state's reading of the first pair's grant
		if i == 3 {
			event.PolicyVersion = 9
			event.GrantExpiresMillis = egressTestTimeMs
		}
		if !reach.Offer(event) {
			t.Fatalf("offer %d refused", i)
		}
	}
	reach.Drain()
	if noted, waiting, dropped := reach.Counts(); noted != 0 || waiting != 2 || dropped != 2 {
		t.Fatalf("noted %d, waiting %d, dropped %d", noted, waiting, dropped)
	}
	// the same pair's peer under another grant is another pair, and so is the same grant's other peer
	if !reach.Offer(reachTestEvent(1, egressTestTagged)) {
		t.Fatal("offer refused")
	}
	reach.Drain()
	if _, waiting, dropped := reach.Counts(); waiting != 2 || dropped != 3 {
		t.Fatalf("waiting %d, dropped %d", waiting, dropped)
	}

	events := []device.BridgeReachEvent{}
	remove := reach.AddCallback(func(event device.BridgeReachEvent) { events = append(events, event) })
	reach.Drain()
	first := reachTestEvent(1, egressTestUntagged)
	first.StreamCount = 3
	first.PolicyVersion = 9
	first.GrantExpiresMillis = egressTestTimeMs
	second := reachTestEvent(2, egressTestUntagged)
	second.StreamCount = 2
	if len(events) != 2 || events[0] != first || events[1] != second {
		t.Fatalf("events %+v", events)
	}
	if noted, waiting, dropped := reach.Counts(); noted != 5 || waiting != 0 || dropped != 3 {
		t.Fatalf("noted %d, waiting %d, dropped %d", noted, waiting, dropped)
	}

	// with a callback standing a full table is delivered, never dropped
	for seed := byte(20); seed < 26; seed += 1 {
		if !reach.Offer(reachTestEvent(seed, egressTestUntagged)) {
			t.Fatal("offer refused")
		}
	}
	reach.Drain()
	if noted, waiting, dropped := reach.Counts(); len(events) != 8 || noted != 11 || waiting != 0 || dropped != 3 {
		t.Fatalf("%d events, noted %d, waiting %d, dropped %d", len(events), noted, waiting, dropped)
	}

	// the callback removed, events wait again
	remove()
	if !reach.Offer(reachTestEvent(30, egressTestUntagged)) {
		t.Fatal("offer refused")
	}
	reach.Drain()
	if _, waiting, _ := reach.Counts(); len(events) != 8 || waiting != 1 {
		t.Fatalf("%d events, waiting %d", len(events), waiting)
	}
}

// A waiting table that holds none drops every event while no callback stands, counted, and hands each to a callback
// that does.
func TestBridgeReachTableOfNoneHoldsNothing(t *testing.T) {
	settings := device.DefaultBridgeSettings()
	settings.ReachWaitingCount = 0
	reach := device.NewBridgeReachForTest(settings)
	reach.Offer(reachTestEvent(1, egressTestUntagged))
	reach.Drain()
	if noted, waiting, dropped := reach.Counts(); noted != 0 || waiting != 0 || dropped != 1 {
		t.Fatalf("noted %d, waiting %d, dropped %d", noted, waiting, dropped)
	}
	taken := []device.BridgeReachEvent{}
	reach.AddCallback(func(event device.BridgeReachEvent) { taken = append(taken, event) })
	reach.Offer(reachTestEvent(1, egressTestUntagged))
	reach.Offer(reachTestEvent(2, egressTestUntagged))
	reach.Drain()
	if len(taken) != 2 || taken[0] != reachTestEvent(1, egressTestUntagged) || taken[1] != reachTestEvent(2, egressTestUntagged) {
		t.Fatalf("taken %+v", taken)
	}
	if noted, waiting, dropped := reach.Counts(); noted != 2 || waiting != 0 || dropped != 1 {
		t.Fatalf("noted %d, waiting %d, dropped %d", noted, waiting, dropped)
	}
}

// On a bridge, flows decided before the sidecar role's callback stands wait for it and reach it once it is added,
// every flow counted.
func TestBridgeReachDeliversWhatWaitedToTheFirstCallback(t *testing.T) {
	test := newReachTest(t, nil)
	for range 3 {
		test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"))
	}
	test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.9:443"))
	test.follow()
	streamCounts := map[[32]byte]uint64{}
	for total := uint64(0); total < 4; {
		event := test.next()
		streamCounts[event.GrantId] += event.StreamCount
		total += event.StreamCount
	}
	if streamCounts[reachTestGrantId(reachTestForwardGrant)] != 3 || streamCounts[reachTestGrantId(reachTestRouteGrant)] != 1 || len(streamCounts) != 2 {
		t.Fatalf("stream counts %v", streamCounts)
	}
	if status := test.bridge.Status(); status.ReachNotedCount != 4 || status.ReachWaitingCount != 0 || status.ReachDroppedCount != 0 {
		t.Fatalf("noted %d, waiting %d, dropped %d", status.ReachNotedCount, status.ReachWaitingCount, status.ReachDroppedCount)
	}
}

// On a bridge, a callback that holds the drain fills the ring, whose overflow is counted and delays no decision, and
// the events the ring held arrive once the callback returns.
func TestBridgeReachSlowCallbackNeverHoldsADecision(t *testing.T) {
	test := newReachTest(t, func(settings *device.BridgeSettings) {
		settings.ReachQueueCount = 4
	})
	entered := make(chan struct{})
	release := make(chan struct{})
	events := make(chan device.BridgeReachEvent, 64)
	first := true
	t.Cleanup(test.bridge.AddReachCallback(func(event device.BridgeReachEvent) {
		// only the drain's goroutine calls, so first needs no lock
		if first {
			first = false
			close(entered)
			<-release
		}
		events <- event
	}))
	test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"))
	<-entered
	// the drain is held in the callback: four reports fill the ring and three more drop, each decided at once
	for range 7 {
		test.admit(test.flow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.9:443"))
	}
	if status := test.bridge.Status(); status.ReachDroppedCount != 3 {
		t.Fatalf("dropped %d, want 3", status.ReachDroppedCount)
	}
	close(release)
	streamCount := uint64(0)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for streamCount < 5 {
		select {
		case event := <-events:
			streamCount += event.StreamCount
		case <-ctx.Done():
			t.Fatalf("%d flows reported, want 5", streamCount)
		}
	}
	if status := test.bridge.Status(); status.ReachNotedCount != 5 || status.ReachDroppedCount != 3 {
		t.Fatalf("noted %d, dropped %d", status.ReachNotedCount, status.ReachDroppedCount)
	}
}

// Canaries absent (I-13): an event holds none of the addresses or ports of the flow it reports, in its bytes or its
// text, only ids, the target's port and counts.
func TestBridgeReachEventHoldsNoFlowAddress(t *testing.T) {
	test := newReachTest(t, nil)
	test.follow()
	flow := test.flow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.77:443")
	flow.From = netip.MustParseAddrPort("100.80.1.77:40077")
	test.admit(flow)
	event := test.next()
	text := fmt.Sprintf("%+v %v", event, event)
	held := bytes.Join([][]byte{event.GrantId[:], event.Peer[:], event.SourceNetwork[:]}, nil)
	for _, canary := range []netip.Addr{flow.From.Addr(), flow.To.Addr()} {
		if strings.Contains(text, canary.String()) {
			t.Errorf("the event's text holds %v: %s", canary, text)
		}
		if bytes.Contains(held, canary.AsSlice()) {
			t.Errorf("the event's ids hold %v", canary)
		}
	}
	if strings.Contains(text, "40077") || event.TargetPort != 0 {
		t.Errorf("the event holds a port of a route's flow: %s", text)
	}
}
