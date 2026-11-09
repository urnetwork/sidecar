// The route export (bridge_export.go): per-peer /32s while this device's local /32s are unknown; once known, a block in
// RFC 1918 whole but for its carves, a 100.64/10 block by its hosts, and every exported prefix split around the carves,
// gateway and resolver /32s included, with §22.9's CGNAT fixture at T1; a subnet route overlapping a local network
// dropped and reported while the block is not; and a carved host address warning.

package device_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Prefixes from their literals.
func routesTestPrefixes(literals ...string) []netip.Prefix {
	prefixes := []netip.Prefix{}
	for _, literal := range literals {
		prefixes = append(prefixes, netip.MustParsePrefix(literal))
	}
	return prefixes
}

// Addresses from their literals.
func routesTestAddrs(literals ...string) []netip.Addr {
	addrs := []netip.Addr{}
	for _, literal := range literals {
		addrs = append(addrs, netip.MustParseAddr(literal))
	}
	return addrs
}

// Whether routes holds addr in some prefix.
func routesTestCovers(routes []netip.Prefix, addr string) bool {
	return slices.ContainsFunc(routes, func(prefix netip.Prefix) bool { return prefix.Contains(netip.MustParseAddr(addr)) })
}

// While the local /32s are unknown the export names each host's /32, the resolver and the subnet routes, never the
// block; once they are known, a 100.64/10 block still exports by its hosts, minus the carves.
func TestBridgeRoutesPerPeerWhileLocalAddressesAreUnknown(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	want := routesTestPrefixes("100.80.0.53/32", "100.80.1.4/32", "100.80.1.5/32", "192.0.2.0/24")
	if routes := test.bridge.Routes(); !slices.Equal(routes, want) {
		t.Fatalf("routes %v, want %v", routes, want)
	}
	test.bridge.SetLocalAddresses(routesTestAddrs("192.0.2.1", "100.80.1.5"))
	routes := test.bridge.Routes()
	if slices.Contains(routes, netip.MustParsePrefix("100.80.0.0/16")) || routesTestCovers(routes, "100.80.9.9") {
		t.Fatalf("a 100.64/10 block was exported whole: %v", routes)
	}
	if routesTestCovers(routes, "192.0.2.1") || routesTestCovers(routes, "100.80.1.5") {
		t.Fatalf("a carve was exported: %v", routes)
	}
	if !routesTestCovers(routes, "192.0.2.2") || !routesTestCovers(routes, "192.0.2.255") || !routesTestCovers(routes, "100.80.1.4") {
		t.Fatalf("a carve took more than its /32: %v", routes)
	}
}

// §22.9's CGNAT fixture at T1: a block chosen in RFC 1918 exports whole but for every local /32 the physical path
// needs, the interface's, the gateway's and the resolver's among them, and never as the whole block.
func TestBridgeRoutesRfc1918BlockMinusItsCarves(t *testing.T) {
	fixture := &sidecartest.BridgeRulesFixture{
		Block: "10.77.0.0/16",
		Entries: []sidecartest.BridgeRulesFixtureEntry{
			{Prefix: "10.77.0.0/16", Kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_UNASSIGNED},
			{Prefix: "10.77.0.0/24", Kind: bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_SERVICE},
			{Prefix: "10.77.1.4", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 4}}},
			{Prefix: "198.51.100.0/24", Links: []sidecartest.BridgeRulesFixtureLink{{Target: 5, Route: 1}}},
		},
	}
	test := newRouteTest(t, fixture, nil)
	if routesTestCovers(test.bridge.Routes(), "10.77.9.9") {
		t.Fatal("the block was exported before the local /32s were known")
	}
	// a carrier interface address, its gateway and its resolver, all inside the block
	carves := []string{"10.77.200.17", "10.77.200.1", "10.77.0.2"}
	test.bridge.SetLocalAddresses(routesTestAddrs(carves...))
	routes := test.bridge.Routes()
	if slices.Contains(routes, netip.MustParsePrefix("10.77.0.0/16")) {
		t.Fatalf("the whole block was exported: %v", routes)
	}
	for _, carve := range carves {
		if routesTestCovers(routes, carve) {
			t.Fatalf("carve %s was exported: %v", carve, routes)
		}
	}
	for _, kept := range []string{"10.77.0.0", "10.77.0.1", "10.77.0.3", "10.77.0.53", "10.77.1.4", "10.77.200.16", "10.77.200.18", "10.77.255.255", "198.51.100.7"} {
		if !routesTestCovers(routes, kept) {
			t.Fatalf("%s was left out: %v", kept, routes)
		}
	}
	for i := 1; i < len(routes); i += 1 {
		if routes[i-1].Overlaps(routes[i]) {
			t.Fatalf("overlapping prefixes %v and %v", routes[i-1], routes[i])
		}
	}
	// a carved address takes the default route in the table too
	if client := test.bridge.Route(routeTestUdp("10.77.1.2", "10.77.200.1", 53)); client != nil {
		t.Fatalf("the carved gateway routed to %T", client)
	}
}

// A subnet route overlapping a local network yields to the LAN: dropped from the table and the export, and reported;
// the block, which only carves, stays.
func TestBridgeRoutesDropASubnetRouteOverAThisDeviceLan(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), func(settings *device.BridgeSettings) {
		settings.LocalIpv4Networks = func() []netip.Prefix {
			return routesTestPrefixes("192.0.2.0/25", "100.80.0.0/12")
		}
	})
	routes := test.bridge.Routes()
	if routesTestCovers(routes, "192.0.2.10") {
		t.Fatalf("a route over a local network was exported: %v", routes)
	}
	if client := test.bridge.Route(routeTestUdp(routeTestSource, "192.0.2.10", 9)); client != nil {
		t.Fatalf("a route over a local network routed to %T", client)
	}
	if !routesTestCovers(routes, "100.80.1.4") {
		t.Fatalf("the block's hosts were dropped with it: %v", routes)
	}
	status := test.bridge.Status()
	if status.RouteConflictCount != 1 || !slices.ContainsFunc(status.Alarms, func(alarm device.BridgeAlarm) bool {
		return alarm.Kind == device.BridgeAlarmRouteConflict
	}) {
		t.Fatalf("conflicts %d, alarms %v", status.RouteConflictCount, status.Alarms)
	}
}

// Before a state there is nothing to export.
func TestBridgeRoutesNoneBeforeAState(t *testing.T) {
	test := newRouteTest(t, &sidecartest.BridgeRulesFixture{}, nil)
	if routes := test.bridge.Routes(); len(routes) != 0 {
		t.Fatalf("rules with nothing exported %v", routes)
	}
	pending := bridgeTestNew(t, device.PendingPostureStoreForTest(t), nil)
	if routes := pending.Routes(); routes != nil {
		t.Fatalf("pending exported %v", routes)
	}
	if client := pending.Route(routeTestUdp(routeTestSource, "100.80.1.4", 9)); client != nil {
		t.Fatalf("pending routed to %T", client)
	}
}
