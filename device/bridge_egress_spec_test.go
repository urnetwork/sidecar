// §17.9's egress spec on an app device (BRIDGE-M8-02; D-BRIDGE-13, §18.17, owner decision 197): with
// BridgeSettings.EgressSpecOff a destination no entry holds takes today's route under exits and under none alike, no
// link to an exit is built and the status reads auto, while entries route as ever; the same rules with the spec on send
// it to the exit and reject it under none, so the switch is what moves an app's default route; and LinkCountMax 0, the
// iOS tunnel's, builds no link at all and answers each link entry and each exit with a reject.

package device_test

import (
	"testing"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The route fixture with an egress spec in mode, under exits the exit at fixture client 8.
func egressSpecTestFixture(mode bridge.BridgeEgressMode) *sidecartest.BridgeRulesFixture {
	fixture := routeTestFixture()
	fixture.Egress = &sidecartest.BridgeRulesFixtureEgress{Mode: mode}
	if mode == bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS {
		fixture.Egress.Exits = []sidecartest.BridgeRulesFixtureLink{{Target: 8, Route: 2}}
	}
	return fixture
}

// With the spec off, the default route is today's under exits and under none, nothing builds to the exit, the status
// reads auto, and an entry still takes its link.
func TestEgressSpecOffKeepsTodaysRoute(t *testing.T) {
	for _, mode := range []bridge.BridgeEgressMode{bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE} {
		test := newRouteTest(t, egressSpecTestFixture(mode), func(settings *device.BridgeSettings) {
			settings.EgressSpecOff = true
		})
		if client := test.bridge.Route(routeTestUdp(routeTestSource, "203.0.113.9", 443)); client != nil {
			t.Errorf("%v off: a public destination routed to %T, want today's route", mode, client)
		}
		if status := test.bridge.Status(); status.EgressMode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO {
			t.Errorf("%v off: the status reads %v", mode, status.EgressMode)
		}
		if link := test.awaitLink(routeTestUdp(routeTestSource, "100.80.1.4", 9)); link.Target != sidecartest.BridgeFixtureClientId(4) {
			t.Errorf("%v off: the entry rode %v", mode, link.Target)
		}
		if count := test.host.BuildCount(sidecartest.BridgeFixtureClientId(8)); count != 0 {
			t.Errorf("%v off: %d links built to the exit", mode, count)
		}
	}
}

// With the spec on, the same rules send a destination no entry holds to the exit under exits, and only there, and
// reject it under none, so nothing reaches today's route.
func TestEgressSpecOnSendsOnlyToAnExitOrNowhere(t *testing.T) {
	exits := newRouteTest(t, egressSpecTestFixture(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS), nil)
	exit := exits.awaitLink(routeTestUdp(routeTestSource, "203.0.113.9", 443))
	if exit.Target != sidecartest.BridgeFixtureClientId(8) {
		t.Fatalf("exited over %v", exit.Target)
	}
	for _, destination := range []string{"198.51.100.7", "203.0.113.77"} {
		if client := exits.bridge.Route(routeTestUdp(routeTestSource, destination, 443)); client != exit {
			t.Errorf("under exits %s routed to %T, want the exit", destination, client)
		}
	}
	none := newRouteTest(t, egressSpecTestFixture(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE), nil)
	for _, destination := range []string{"203.0.113.9", "198.51.100.7"} {
		if _, ok := none.bridge.Route(routeTestUdp(routeTestSource, destination, 443)).(*device.BridgeRejectClient); !ok {
			t.Errorf("under none %s was not rejected", destination)
		}
	}
	if builds := none.host.Builds(); len(builds) != 0 {
		t.Errorf("under none %d links were built", len(builds))
	}
}

// LinkCountMax 0, the iOS tunnel's until §22.9 measures a link (owner decision 100): no link is ever built, and a link
// entry and the exits each answer with a reject, never today's route.
func TestLinkCountMaxZeroBuildsNothingAndRejects(t *testing.T) {
	test := newRouteTest(t, egressSpecTestFixture(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS), func(settings *device.BridgeSettings) {
		settings.LinkCountMax = 0
	})
	for _, destination := range []string{"100.80.1.4", "100.80.1.5", "192.0.2.9", "203.0.113.9"} {
		for range 3 {
			if _, ok := test.bridge.Route(routeTestUdp(routeTestSource, destination, 9)).(*device.BridgeRejectClient); !ok {
				t.Errorf("%s was not rejected", destination)
			}
		}
	}
	if builds := test.host.Builds(); len(builds) != 0 {
		t.Errorf("%d links were built", len(builds))
	}
}
