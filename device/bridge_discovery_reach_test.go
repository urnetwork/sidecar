// §17.7.1's seams on the device role (bridge_discovery_reach.go; owner decision 778): a host's answer for a viewer equals
// its hook's verdict for that viewer, rule by rule, so a viewer with no route to a shared device, or no dial on a port,
// sees none of it; and a viewer's checks read the advertisers its own router sends an address to.

package device_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The hook's verdict, rule by rule, with the viewer as the source: rule 3 for a hosted port its dial row names, rule 1
// for a map, rule 6's remap and route for an exposed and a served address, rule 0 refusing a daemon listener, and
// nothing for an unknown viewer, a pending state, an sdk profile or a protocol with no ports.
func TestBridgeDiscoveryReachIsTheHooksVerdict(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	untagged := connect.Id(sidecartest.BridgeFixtureSidecarId(egressTestUntagged))
	tagged := connect.Id(sidecartest.BridgeFixtureSidecarId(egressTestTagged))
	stranger := connect.Id(sidecartest.BridgeFixtureSidecarId(9))
	cases := []struct {
		name       string
		viewer     connect.Id
		address    string
		ipProtocol connect.IpProtocol
		want       bool
	}{
		{name: "rule 3, dial row", viewer: untagged, address: "100.80.1.2:22", ipProtocol: connect.IpProtocolTcp, want: true},
		{name: "rule 3, no row", viewer: untagged, address: "100.80.1.2:23", ipProtocol: connect.IpProtocolTcp},
		{name: "rule 1, a map", viewer: untagged, address: "100.80.1.2:8005", ipProtocol: connect.IpProtocolTcp, want: true},
		{name: "rule 1, a udp map", viewer: untagged, address: "100.80.1.2:6000", ipProtocol: connect.IpProtocolUdp, want: true},
		{name: "rule 0 behind a map", viewer: untagged, address: "100.80.1.2:7000", ipProtocol: connect.IpProtocolTcp},
		{name: "rule 2, another host's map", viewer: untagged, address: "100.80.1.2:7001", ipProtocol: connect.IpProtocolTcp},
		{name: "rule 6's remap", viewer: untagged, address: "100.80.200.9:443", ipProtocol: connect.IpProtocolTcp, want: true},
		{name: "rule 6's remap, no row", viewer: untagged, address: "100.80.200.9:80", ipProtocol: connect.IpProtocolTcp},
		{name: "rule 6", viewer: untagged, address: "192.168.50.9:443", ipProtocol: connect.IpProtocolTcp, want: true},
		{name: "rule 6, no row", viewer: untagged, address: "192.168.50.9:80", ipProtocol: connect.IpProtocolTcp},
		{name: "rule 8", viewer: untagged, address: "192.168.70.9:443", ipProtocol: connect.IpProtocolTcp},
		{name: "tagged, its row", viewer: tagged, address: "100.80.1.2:443", ipProtocol: connect.IpProtocolTcp, want: true},
		{name: "tagged, no row", viewer: tagged, address: "100.80.1.2:22", ipProtocol: connect.IpProtocolTcp},
		{name: "a stranger", viewer: stranger, address: "100.80.1.2:22", ipProtocol: connect.IpProtocolTcp},
		{name: "icmp", viewer: untagged, address: "100.80.1.2:0", ipProtocol: connect.IpProtocolIcmp},
	}
	for _, c := range cases {
		if got := test.policy.DiscoveryReach(c.viewer, netip.MustParseAddrPort(c.address), c.ipProtocol); got != c.want {
			t.Errorf("%s: %t, want %t", c.name, got, c.want)
		}
	}

	// with no document an untagged viewer reaches every hosted port and the exposed prefix, a tagged one its rows alone
	open := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	if !open.policy.DiscoveryReach(untagged, netip.MustParseAddrPort("100.80.1.2:23"), connect.IpProtocolTcp) ||
		!open.policy.DiscoveryReach(untagged, netip.MustParseAddrPort("100.80.200.9:80"), connect.IpProtocolTcp) {
		t.Errorf("an untagged viewer with no document reaches less than the allow-all")
	}
	if open.policy.DiscoveryReach(tagged, netip.MustParseAddrPort("100.80.1.2:23"), connect.IpProtocolTcp) {
		t.Errorf("a tagged viewer with no document reaches past its rows")
	}
	pending := newEgressTest(t, device.BridgePolicyProfileHost, device.PosturePending, egressTestFixture())
	if pending.policy.DiscoveryReach(untagged, netip.MustParseAddrPort("100.80.1.2:22"), connect.IpProtocolTcp) {
		t.Errorf("a pending state reaches")
	}
	sdk := newEgressTest(t, device.BridgePolicyProfileSdkHost, device.PostureEnforcingDocument, egressTestFixture())
	if sdk.policy.DiscoveryReach(untagged, netip.MustParseAddrPort("100.80.1.2:22"), connect.IpProtocolTcp) {
		t.Errorf("an sdk host's discovery reaches")
	}
}

// A viewer's checks read its router: the advertisers of the entry that holds an address, none for a service, an
// unassigned address or the default route.
func TestBridgeRouteTargetsNameTheEntrysAdvertisers(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	id := func(seed byte) connect.Id {
		return connect.Id(sidecartest.BridgeFixtureSidecarId(seed))
	}
	cases := []struct {
		address string
		want    []connect.Id
	}{
		{address: "100.80.1.4", want: []connect.Id{id(4)}},
		{address: "100.80.1.5", want: []connect.Id{id(5), id(6)}},
		{address: "192.0.2.77", want: []connect.Id{id(7)}},
		{address: "100.80.0.53"},
		{address: "100.80.9.9"},
		{address: "203.0.113.1"},
		{address: "2001:db8::1"},
	}
	for _, c := range cases {
		got := test.bridge.RouteTargets(netip.MustParseAddr(c.address))
		slices.SortFunc(got, func(a connect.Id, b connect.Id) int { return slices.Compare(a[:], b[:]) })
		if !slices.Equal(got, c.want) {
			t.Errorf("%s routes to %v, want %v", c.address, got, c.want)
		}
	}
}
