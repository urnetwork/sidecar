//go:build !ios_extension

// What the route rows let reach a shared device's address (bridge_discovery_ports.go; §17.7.1, owner decision 778):
// narrowed rows name their protocol and ports, an address no row covers names none, a row of every protocol, or of
// both TCP and UDP whole, reaches every port, and with no document every port is reached.

package device_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestBridgeDiscoveryRoutePortsNameANarrowing(t *testing.T) {
	// the fixture's untagged subject routes the exposed 100.80.200.0/24 on tcp:443 alone
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	if all, ports := test.policy.DiscoveryRoutePorts(netip.MustParseAddr("100.80.200.9")); all || !slices.Equal(ports, []string{"tcp:443"}) {
		t.Fatalf("a narrowed route: %v %v", all, ports)
	}
	if all, ports := test.policy.DiscoveryRoutePorts(netip.MustParseAddr("192.168.77.9")); all || len(ports) != 0 {
		t.Fatalf("an address no row covers: %v %v", all, ports)
	}
	wide := egressTestFixture()
	wide.Subjects[0].Route = append(wide.Subjects[0].Route,
		sidecartest.BridgeRulesFixtureReach{Prefix: "100.80.200.0/24", Ports: "udp:5353-5354"},
		sidecartest.BridgeRulesFixtureReach{Prefix: "100.80.200.9/32", Ports: "tcp"},
	)
	test = newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, wide)
	if all, ports := test.policy.DiscoveryRoutePorts(netip.MustParseAddr("100.80.200.9")); all ||
		!slices.Equal(ports, []string{"tcp", "udp:5353-5354"}) {
		t.Fatalf("TCP whole and UDP narrowed: %v %v", all, ports)
	}
	wide.Subjects[0].Route = append(wide.Subjects[0].Route, sidecartest.BridgeRulesFixtureReach{Prefix: "100.80.200.9/32", Ports: "udp"})
	test = newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, wide)
	if all, _ := test.policy.DiscoveryRoutePorts(netip.MustParseAddr("100.80.200.9")); !all {
		t.Fatal("TCP and UDP whole did not reach every port")
	}
	every := egressTestFixture()
	every.Subjects[1].Route = []sidecartest.BridgeRulesFixtureReach{{Prefix: "100.80.200.0/24", Ports: "*"}}
	test = newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, every)
	if all, _ := test.policy.DiscoveryRoutePorts(netip.MustParseAddr("100.80.200.9")); !all {
		t.Fatal("a row of every protocol did not reach every port")
	}
	noDocument := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	if all, _ := noDocument.policy.DiscoveryRoutePorts(netip.MustParseAddr("192.168.77.9")); !all {
		t.Fatal("with no document a port was closed")
	}
}
