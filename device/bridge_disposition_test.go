// §17.8's disposition on the provider side (bridge_disposition.go): each revocation a delta carries closes exactly its
// tags and leaves a sibling subject's, §22.5's reset against drain on a fake clock, a retargeted map keeping only the
// flows it opened, and a map's expiry resetting at once.

package device_test

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The disposition fixture: egress_test's rules with the untagged subject's route row under grant 1.
func dispositionTestFixture() *sidecartest.BridgeRulesFixture {
	fixture := egressTestFixture()
	fixture.Subjects[0].Route[0].Grant = 1
	return fixture
}

// The tags a subject's flows carry under a document in the disposition fixture: every map, rule 3, the routes its rows
// meet, and the exit for the subject that has exit rows.
func dispositionTestTags(subjectSeed byte) []uint64 {
	fixture := dispositionTestFixture()
	tags := []uint64{egressTestTag(subjectSeed, []byte{device.BridgeRuleHosted})}
	for _, fixtureMap := range fixture.Maps {
		tags = append(tags, egressTestTag(subjectSeed, sidecartest.BridgeFixtureMapId(fixtureMap.Map)))
	}
	if subjectSeed == egressTestUntagged {
		tags = append(tags,
			egressTestTag(subjectSeed, sidecartest.BridgeFixtureRouteId(1)),
			egressTestTag(subjectSeed, sidecartest.BridgeFixtureRouteId(2)),
			egressTestTag(subjectSeed, []byte{device.BridgeRuleExit}))
	}
	slices.Sort(tags)
	return tags
}

// A SidecarRevoke, MemberRevoke, Suspend, GrantRevoke and BridgeWithdraw, each a verified delta alone, close exactly
// their tags, and the sibling subject's flows survive.
func TestBridgeRevocationsCloseExactlyTheirTags(t *testing.T) {
	untaggedId := sidecartest.BridgeFixtureSidecarId(egressTestUntagged)
	mapTags := []uint64{
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(1)),
		egressTestTag(egressTestTagged, sidecartest.BridgeFixtureMapId(1)),
	}
	slices.Sort(mapTags)
	cases := []struct {
		name string
		file func(log *device.BridgeLogFixtureForTest) uint64
		want []uint64
	}{
		{name: "SidecarRevoke", file: func(log *device.BridgeLogFixtureForTest) uint64 {
			return log.SidecarRevoke(untaggedId)
		}, want: dispositionTestTags(egressTestUntagged)},
		{name: "MemberRevoke", file: func(log *device.BridgeLogFixtureForTest) uint64 {
			return log.MemberRevoke(sidecartest.BridgeFixtureMemberId(egressTestUntagged))
		}, want: dispositionTestTags(egressTestUntagged)},
		{name: "Suspend", file: func(log *device.BridgeLogFixtureForTest) uint64 {
			return log.Suspend(untaggedId, sidecartest.BridgeFixtureGrantId(9))
		}, want: dispositionTestTags(egressTestUntagged)},
		{name: "GrantRevoke", file: func(log *device.BridgeLogFixtureForTest) uint64 {
			return log.GrantRevoke(sidecartest.BridgeFixtureGrantId(1))
		}, want: []uint64{egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1))}},
		{name: "BridgeWithdraw reset", file: func(log *device.BridgeLogFixtureForTest) uint64 {
			return log.BridgeWithdraw(sidecartest.BridgeFixtureMapId(1), bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET)
		}, want: mapTags},
		{name: "BridgeWithdraw drain of a route", file: func(log *device.BridgeLogFixtureForTest) uint64 {
			return log.BridgeWithdraw(sidecartest.BridgeFixtureRouteId(1), bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN)
		}, want: []uint64{}},
	}
	for _, testCase := range cases {
		test := newStateTest(t, dispositionTestFixture(), true)
		pin := test.log.Tip()
		n := testCase.file(test.log)
		if err := test.bridge.ApplyDeltas(test.log.Deltas(pin+1, n)); err != nil {
			t.Fatalf("%s: %v", testCase.name, err)
		}
		tags, _ := test.closer.take()
		if !slices.Equal(tags, testCase.want) {
			t.Errorf("%s: closed %v, want %v", testCase.name, tags, testCase.want)
		}
		sibling := test.flow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:443")
		if test.verdict(sibling) != connect.EgressVerdictMap {
			t.Errorf("%s: the sibling's flow", testCase.name)
		}
	}
}

// §22.5's reset against drain: a route withdrawn to drain keeps admitting until max(drain_seconds, 600 s) from its
// start, then the bridge publishes and closes its tag; withdrawn with reset, it closes at once.
func TestBridgeResetAgainstDrain(t *testing.T) {
	routed := egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1))
	start := time.UnixMilli(egressTestTimeMs)
	draining := dispositionTestFixture()
	draining.Served[0].DrainingSince = egressTestTimeMs
	draining.Served[0].DrainUntil = egressTestTimeMs + 30_000

	drain := newStateTest(t, dispositionTestFixture(), true)
	drain.log.Tick()
	drain.setState(draining, true)
	if tags, _ := drain.closer.take(); 0 < len(tags) {
		t.Fatalf("a drain closed %v at once", tags)
	}
	flow := drain.flow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443")
	// past drain_until, still inside 600 s from the drain's start
	drain.clock.AdvanceTo(start.Add(300 * time.Second))
	if drain.verdict(flow) != connect.EgressVerdictPass {
		t.Fatal("a draining route stopped admitting before its floor")
	}
	if tags, _ := drain.closer.take(); 0 < len(tags) {
		t.Fatalf("closed %v during the drain", tags)
	}
	drain.advanceTo(start.Add(600 * time.Second))
	if tags, _ := drain.closer.take(); !slices.Equal(tags, []uint64{routed}) {
		t.Fatalf("the drain's end closed %v", tags)
	}
	if drain.verdict(flow) != connect.EgressVerdictDeny {
		t.Fatal("a drained route still admits")
	}

	reset := newStateTest(t, dispositionTestFixture(), true)
	pin := reset.log.Tip()
	n := reset.log.BridgeWithdraw(sidecartest.BridgeFixtureRouteId(1), bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET)
	if err := reset.bridge.ApplyDeltas(reset.log.Deltas(pin+1, n)); err != nil {
		t.Fatal(err)
	}
	if tags, _ := reset.closer.take(); !slices.Equal(tags, []uint64{routed}) {
		t.Fatalf("a reset closed %v", tags)
	}
}

// A retargeted map: the old map drains, keeping the flows it opened and taking no new one, new flows take the new map
// at once, and at the old map's drain end only its tag closes.
func TestBridgeRetargetedMapKeepsOnlyItsOwnFlows(t *testing.T) {
	start := time.UnixMilli(egressTestTimeMs)
	test := newStateTest(t, dispositionTestFixture(), true)
	retargeted := dispositionTestFixture()
	retargeted.Maps[1].DrainingSince = egressTestTimeMs
	retargeted.Maps[1].DrainUntil = egressTestTimeMs + 60_000
	retargeted.Maps = append(retargeted.Maps, sidecartest.BridgeRulesFixtureMap{
		Map: 9, Match: "100.80.1.2", Ports: "tcp:8000-8010", Target: "192.168.1.30:9000",
	})
	test.log.Tick()
	test.setState(retargeted, true)
	if tags, _ := test.closer.take(); 0 < len(tags) {
		t.Fatalf("a retarget closed %v at once", tags)
	}
	decision := test.bridge.EgressHook().ResolveEgress(test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:8003"))
	if decision.Verdict != connect.EgressVerdictMap || decision.Target.String() != "192.168.1.30:9003" ||
		decision.RuleTag != egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(9)) {
		t.Fatalf("a new flow: %+v", decision)
	}
	test.advanceTo(start.Add(600 * time.Second))
	want := []uint64{
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(2)),
		egressTestTag(egressTestTagged, sidecartest.BridgeFixtureMapId(2)),
	}
	slices.Sort(want)
	if tags, _ := test.closer.take(); !slices.Equal(tags, want) {
		t.Fatalf("the old map's drain end closed %v, want %v", tags, want)
	}
}

// A map's expiry resets at once: at that instant the bridge publishes and closes its tags, and nothing else.
func TestBridgeMapExpiryResetsAtOnce(t *testing.T) {
	start := time.UnixMilli(egressTestTimeMs)
	test := newStateTest(t, dispositionTestFixture(), true)
	expiring := dispositionTestFixture()
	expiring.Maps[0].Expires = egressTestTimeMs + 10_000
	test.log.Tick()
	test.setState(expiring, true)
	test.closer.take()
	test.advanceTo(start.Add(10 * time.Second))
	want := []uint64{
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(1)),
		egressTestTag(egressTestTagged, sidecartest.BridgeFixtureMapId(1)),
	}
	slices.Sort(want)
	if tags, _ := test.closer.take(); !slices.Equal(tags, want) {
		t.Fatalf("the expiry closed %v, want %v", tags, want)
	}
}

// A document arriving ends the allow-all: the untagged subject's rule 4 and rule 3 flows close, and its remap's.
func TestBridgeDocumentEndsTheAllowAll(t *testing.T) {
	test := newStateTest(t, dispositionTestFixture(), false)
	test.log.Base(true)
	test.log.Tick()
	test.setState(dispositionTestFixture(), true)
	tags, _ := test.closer.take()
	for _, want := range []uint64{
		egressTestTag(egressTestUntagged, []byte{device.BridgeRuleAllowAll}),
		egressTestTag(egressTestUntagged, []byte{device.BridgeRuleHosted}),
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(2)),
	} {
		if !slices.Contains(tags, want) {
			t.Errorf("closed %v, missing %d", tags, want)
		}
	}
	if slices.Contains(tags, egressTestTag(egressTestTagged, []byte{device.BridgeRuleHosted})) {
		t.Errorf("closed the tagged subject's rule 3, which never stood on the allow-all")
	}
}
