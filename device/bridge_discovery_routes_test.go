// What §17.7.1's discovery reads of the state in force (bridge_discovery_routes.go; owner decision 778): the host's
// blocks, addresses, served subnets with their remaps and TCP and UDP maps, and the hosts its links reach with what
// each advertises, share links and draining links left out.

package device_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestBridgeDiscoveryRoutesReadTheState(t *testing.T) {
	fixture := &sidecartest.BridgeRulesFixture{
		Block:     "100.80.0.0/16",
		Addresses: []string{"100.80.1.2"},
		Entries: []sidecartest.BridgeRulesFixtureEntry{
			{Prefix: "100.80.0.0/24", Kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE},
			{Prefix: "100.80.1.4", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 4}}},
			{Prefix: "192.0.2.0/24", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 4, Route: 1}, {Target: 5, Route: 2, DrainingSince: routeTestTimeMs - 1000, DrainUntil: routeTestTimeMs + 1000}}},
		},
		Maps: []sidecartest.BridgeRulesFixtureMap{
			{Map: 1, Match: "100.80.1.2", Ports: "tcp:8631", Target: "192.168.70.9:631"},
			{Map: 2, Match: "100.80.1.2", Ports: "icmp", Target: "192.168.70.9:0"},
		},
		Served: []sidecartest.BridgeRulesFixtureServed{
			{Route: 3, Prefix: "192.168.50.0/24"},
			{Route: 4, Prefix: "192.168.60.0/24", Exposed: "100.80.200.0/24"},
			{Route: 5, Exit: true},
		},
	}
	test := newRouteTest(t, fixture, nil)
	routes := test.bridge.DiscoveryRoutes()
	if routes == nil {
		t.Fatal("no routes from an enforcing state")
	}
	if !slices.Equal(routes.Blocks, []netip.Prefix{netip.MustParsePrefix("100.80.0.0/16")}) ||
		!slices.Equal(routes.Addresses, []netip.Addr{netip.MustParseAddr("100.80.1.2")}) {
		t.Errorf("blocks %v, addresses %v", routes.Blocks, routes.Addresses)
	}
	wantServed := []device.BridgeDiscoveryServed{
		{Prefix: netip.MustParsePrefix("192.168.50.0/24")},
		{Prefix: netip.MustParsePrefix("192.168.60.0/24"), Exposed: netip.MustParsePrefix("100.80.200.0/24")},
	}
	if !slices.Equal(routes.Served, wantServed) {
		t.Errorf("served %v", routes.Served)
	}
	wantMaps := []device.BridgeDiscoveryMap{{
		Address: netip.MustParseAddr("100.80.1.2"), Protocol: connect.IpProtocolTcp, FirstPort: 8631, LastPort: 8631,
		Target: netip.MustParseAddr("192.168.70.9"), TargetPort: 631,
	}}
	if !slices.Equal(routes.Maps, wantMaps) {
		t.Errorf("maps %v", routes.Maps)
	}
	if len(routes.Hosts) != 1 || routes.Hosts[0].SidecarId != connect.Id(sidecartest.BridgeFixtureSidecarId(4)) ||
		!slices.Equal(routes.Hosts[0].Prefixes, []netip.Prefix{netip.MustParsePrefix("100.80.1.4/32"), netip.MustParsePrefix("192.0.2.0/24")}) {
		t.Errorf("hosts %+v", routes.Hosts)
	}
}
