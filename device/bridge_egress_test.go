// BridgeEgressPolicy rule by rule (§17.6): each rule's positive case beside its negative twin, the rows before the
// numbered rules, the sdk provider's profile, the pending, enforcing{doc} and enforcing{nodoc} states, §22.7's S8 at
// unit level, the idle each verdict sets, and the hot path's cost. bridge_egress_reference_test.go holds the policy to a
// second walk of the table over generated states.

package device_test

import (
	"crypto/ed25519"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The time every policy test runs at, and an hour.
const (
	egressTestTimeMs = 1_800_000_000_000
	egressTestHourMs = 3_600_000
)

// The network and this host, synthetic.
var (
	egressTestNetworkId = sidecartest.BridgeFixtureSidecarId(0xB1)
	egressTestHostId    = sidecartest.BridgeFixtureSidecarId(0xB2)
)

// Subjects: an untagged member device, and a tagged agent with one dial row.
const (
	egressTestUntagged byte = 6
	egressTestTagged   byte = 7
)

// The daemon's listeners this host's state lists (rule 0).
var egressTestListeners = []string{"0.0.0.0:8443", "[::]:9443"}

// A host's rules: an address with maps onto loopback, a LAN range by offset, the daemon and another host; a plain served
// subnet, a remapped one and an exit; the untagged subject's dial, route and exit rows, and the tagged one's single row.
func egressTestFixture() *sidecartest.BridgeRulesFixture {
	return &sidecartest.BridgeRulesFixture{
		Block:     "100.80.0.0/16",
		Addresses: []string{"100.80.1.2"},
		Maps: []sidecartest.BridgeRulesFixtureMap{
			{Map: 1, Match: "100.80.1.2", Ports: "tcp:5432", Target: "127.0.0.1:5432"},
			{Map: 2, Match: "100.80.1.2", Ports: "tcp:8000-8010", Target: "192.168.1.20:9000"},
			{Map: 3, Match: "100.80.1.2", Ports: "tcp:7000", Target: "127.0.0.1:8443"},
			{Map: 4, Match: "100.80.1.2", Ports: "tcp:7001", Target: "100.80.1.3:7001"},
			{Map: 5, Match: "100.80.1.2", Ports: "udp:6000", Target: "192.168.1.21:0"},
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
					{Ports: "tcp:5432"}, {Ports: "tcp:8000-8010"}, {Ports: "tcp:7000-7001"}, {Ports: "tcp:22"},
					{Ports: "udp:6000"}, {Ports: "icmp"},
				},
				Route: []sidecartest.BridgeRulesFixtureReach{
					{Prefix: "192.168.50.0/24", Ports: "tcp:443"},
					{Prefix: "100.80.200.0/24", Ports: "tcp:443"},
				},
				Exit: []sidecartest.BridgeRulesFixtureReach{{Ports: "*"}},
			},
			{Sidecar: egressTestTagged, Tagged: true, Dial: []sidecartest.BridgeRulesFixtureReach{{Ports: "tcp:443"}}},
		},
	}
}

// One policy on a settable clock, and what it was published from.
type egressTest struct {
	t      *testing.T
	clock  *egressTestClock
	policy *device.BridgeEgressPolicy
	input  *device.BridgePolicyInput
}

// A policy of profile published from fixture's rules in state, each subject's identity in it, this host's listeners,
// and its one known local address.
func newEgressTest(t *testing.T, profile device.BridgePolicyProfile, state device.PostureState, fixture *sidecartest.BridgeRulesFixture) *egressTest {
	t.Helper()
	clock := &egressTestClock{now: time.UnixMilli(egressTestTimeMs)}
	settings := device.DefaultBridgeSettings()
	settings.Clock = clock
	rules, err := device.ParseBridgeRules(fixture.Bytes(), settings)
	if err != nil {
		t.Fatal(err)
	}
	bridgeState := &bridge.BridgeState{DaemonListeners: egressTestListeners}
	for _, subject := range fixture.Subjects {
		bridgeState.Identities = append(bridgeState.Identities, &bridge.BridgeIdentity{
			SidecarId:         sidecartest.BridgeFixtureSidecarId(subject.Sidecar),
			IdentityPublicKey: sidecartest.BridgeFixtureIdentityKey(subject.Sidecar).Public().(ed25519.PublicKey),
		})
	}
	self := &egressTest{
		t:      t,
		clock:  clock,
		policy: device.NewBridgeEgressPolicy(profile, settings),
		input: &device.BridgePolicyInput{
			State:          state,
			BridgeState:    bridgeState,
			Rules:          rules,
			NetworkId:      egressTestNetworkId,
			SidecarId:      egressTestHostId,
			LocalAddresses: []netip.Addr{netip.MustParseAddr("192.168.77.10")},
		},
	}
	self.policy.Publish(self.input)
	return self
}

// Publishes the input again, after a test changed it.
func (self *egressTest) republish() {
	self.policy.Publish(self.input)
}

// A flow of the subject's, well formed for a host: Network mode, the data class, sealed, with a principal that verified
// to the subject and lapses in an hour.
func egressTestFlow(subjectSeed byte, ipProtocol connect.IpProtocol, to string) *connect.EgressFlow {
	return &connect.EgressFlow{
		ProvideMode:   protocol.ProvideMode_Network,
		ContractClass: connect.ContractClassData,
		SourceSubject: sidecartest.BridgeFixtureClientId(subjectSeed),
		SourceNetwork: connect.Id(egressTestNetworkId),
		Principal: &connect.BridgePrincipal{
			Subject:  connect.Id(sidecartest.BridgeFixtureSidecarId(subjectSeed)),
			Network:  connect.Id(egressTestNetworkId),
			NotAfter: time.UnixMilli(egressTestTimeMs + egressTestHourMs),
		},
		Sealed:   true,
		Protocol: ipProtocol,
		From:     netip.MustParseAddrPort("100.80.1.7:40000"),
		To:       netip.MustParseAddrPort(to),
	}
}

// The tag of the subject's flows under a rule.
func egressTestTag(subjectSeed byte, ruleId []byte) uint64 {
	return device.BridgeRuleTag(connect.Id(sidecartest.BridgeFixtureSidecarId(subjectSeed)), ruleId)
}

// The tag of the subject's rule 3 flows to a hosted address: rule 3's byte, then the address's four
// (DESIGN-DETAILS 12.2.2).
func egressTestHostedTag(subjectSeed byte, address string) uint64 {
	octets := netip.MustParseAddr(address).As4()
	return egressTestTag(subjectSeed, append([]byte{device.BridgeRuleHosted}, octets[:]...))
}

// Fails unless the flow is denied, with nothing else set but the generation.
func (self *egressTest) expectDeny(name string, flow *connect.EgressFlow) {
	self.t.Helper()
	decision := self.policy.ResolveEgress(flow)
	if decision.Verdict != connect.EgressVerdictDeny || decision.RuleTag != 0 || decision.IdleTimeout != 0 ||
		decision.PolicyGeneration != self.policy.PolicyGeneration() {
		self.t.Errorf("%s: %+v, want a deny", name, decision)
	}
}

// Fails unless the flow passes under tag.
func (self *egressTest) expectPass(name string, flow *connect.EgressFlow, tag uint64) {
	self.t.Helper()
	decision := self.policy.ResolveEgress(flow)
	if decision.Verdict != connect.EgressVerdictPass || decision.RuleTag != tag || decision.Target.IsValid() {
		self.t.Errorf("%s: %+v, want a pass tagged %d", name, decision, tag)
	}
}

// Fails unless the flow maps to target under tag.
func (self *egressTest) expectMap(name string, flow *connect.EgressFlow, target string, tag uint64) {
	self.t.Helper()
	decision := self.policy.ResolveEgress(flow)
	if decision.Verdict != connect.EgressVerdictMap || decision.Target != netip.MustParseAddrPort(target) || decision.RuleTag != tag {
		self.t.Errorf("%s: %+v, want a map to %s tagged %d", name, decision, target, tag)
	}
}

// Rule 0 (D-BRIDGE-19): a daemon listener's port on loopback, on an unspecified address and on this device's own
// address is denied whatever the state, even where rule 4 would pass; the same port elsewhere, and another loopback
// port, pass.
func TestBridgeEgressRuleZeroDeniesTheDaemonsListeners(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	for _, to := range []string{"127.0.0.1:8443", "127.0.0.9:8443", "0.0.0.0:8443", "192.168.77.10:8443", "[::1]:9443", "[::1]:8443"} {
		test.expectDeny(to, egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to))
	}
	// the twins: rule 4's allow-all, with no document, for an untagged subject
	allowAll := egressTestTag(egressTestUntagged, []byte{device.BridgeRuleAllowAll})
	for _, to := range []string{"127.0.0.1:8444", "192.168.77.11:8443", "192.168.77.10:22"} {
		test.expectPass(to, egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to), allowAll)
	}
}

// Rule 0 holds a map's target and rule 3's 127.0.0.1:port too, so no map reaches the daemon.
func TestBridgeEgressRuleZeroHoldsEveryMapTarget(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	test.expectDeny("a map onto a listener", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:7000"))
	test.expectDeny("rule 3 onto a listener", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:8443"))
	test.expectMap("a map onto another loopback port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"),
		"127.0.0.1:5432", egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(1)))
	test.expectMap("rule 3 onto another loopback port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:8444"),
		"127.0.0.1:8444", egressTestHostedTag(egressTestUntagged, "100.80.1.2"))
}

// Rule 0 before this device has named its addresses: a listener's port is refused on every address, the stricter.
func TestBridgeEgressRuleZeroWithoutLocalAddressesRefusesTheirPortsEverywhere(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	exit := egressTestTag(egressTestUntagged, []byte{device.BridgeRuleExit})
	test.expectPass("an exit to a listener's port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "198.51.100.7:8443"), exit)
	test.input.LocalAddresses = nil
	test.republish()
	test.expectDeny("an exit to a listener's port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "198.51.100.7:8443"))
	test.expectPass("an exit to another port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "198.51.100.7:443"), exit)
}

// A listener that does not parse makes every port of a local address the daemon's.
func TestBridgeEgressRuleZeroReadsAListenerItCannotParseAsEveryPort(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	test.input.BridgeState.DaemonListeners = append([]string{"no port here"}, egressTestListeners...)
	test.republish()
	test.expectDeny("loopback, any port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "127.0.0.1:8444"))
	test.expectPass("a LAN host", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:8444"),
		egressTestTag(egressTestUntagged, []byte{device.BridgeRuleAllowAll}))
}

// Rule 1: a map takes the destination as sent, with AllowDial; a range maps by offset, port 0 keeps the port, and a map
// never targets another host's overlay address. Without the dial row, the twin is denied.
func TestBridgeEgressRuleOneMapsTheDestinationAsSent(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	test.expectMap("a port map", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"),
		"127.0.0.1:5432", egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(1)))
	test.expectMap("a range by offset", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:8007"),
		"192.168.1.20:9007", egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(2)))
	test.expectMap("port 0 keeps the port", egressTestFlow(egressTestUntagged, connect.IpProtocolUdp, "100.80.1.2:6000"),
		"192.168.1.21:6000", egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(5)))
	test.expectDeny("onto another host's address", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:7001"))
	// the tagged subject's one row is tcp:443
	test.expectDeny("no dial row", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:5432"))
	test.expectDeny("another protocol's map", egressTestFlow(egressTestUntagged, connect.IpProtocolUdp, "100.80.1.2:5432"))
}

// A range of addresses maps by offset too.
func TestBridgeEgressRuleOneMapsAnAddressRangeByOffset(t *testing.T) {
	fixture := egressTestFixture()
	fixture.Maps = append(fixture.Maps, sidecartest.BridgeRulesFixtureMap{Map: 6, Match: "100.80.2.4/30", Ports: "tcp:22", Target: "192.168.1.40:0"})
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, fixture)
	test.expectMap("the third of the range", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.2.6:22"),
		"192.168.1.42:22", egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(6)))
	test.expectDeny("past the range", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.2.8:22"))
}

// Rule 2: an address of the block that this host does not hold is never dialed, even under the allow-all.
func TestBridgeEgressRuleTwoNeverDialsAnotherHostsAddress(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	test.expectDeny("another host", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.3:22"))
	test.expectDeny("the block's services", egressTestFlow(egressTestUntagged, connect.IpProtocolUdp, "100.80.0.53:53"))
	test.expectMap("this host", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:22"), "127.0.0.1:22",
		egressTestHostedTag(egressTestUntagged, "100.80.1.2"))
}

// Rule 3: a hosted address maps to loopback with AllowDial, or with no document for an untagged subject; a tagged
// subject with no row is denied either way.
func TestBridgeEgressRuleThreeMapsAHostedAddressToLoopback(t *testing.T) {
	hosted := egressTestHostedTag(egressTestUntagged, "100.80.1.2")
	document := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	document.expectMap("a dial row", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:22"), "127.0.0.1:22", hosted)
	document.expectDeny("no dial row", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:2222"))
	document.expectMap("the tagged subject's row", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:443"),
		"127.0.0.1:443", egressTestHostedTag(egressTestTagged, "100.80.1.2"))

	noDocument := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	noDocument.expectMap("untagged, no row", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:2222"), "127.0.0.1:2222", hosted)
	noDocument.expectDeny("tagged, no row", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:2222"))
}

// Rule 4: with no document an untagged subject keeps today's reach (owner decisions 50, 105, 120); a document, or a
// tagged subject, takes it away.
func TestBridgeEgressRuleFourIsTheAllowAllWithoutADocument(t *testing.T) {
	lan := "192.168.77.20:80"
	noDocument := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	noDocument.expectPass("untagged", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, lan),
		egressTestTag(egressTestUntagged, []byte{device.BridgeRuleAllowAll}))
	noDocument.expectDeny("tagged", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, lan))
	document := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	document.expectDeny("untagged under a document", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, lan))
}

// Rule 5: loopback, link-local, multicast and unspecified destinations are denied once rule 4 does not pass them.
func TestBridgeEgressRuleFiveDeniesLoopbackAndLinkLocal(t *testing.T) {
	document := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	noDocument := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	for _, to := range []string{"127.0.0.9:80", "169.254.1.1:80", "224.0.0.5:80", "[fe80::1]:80", "[::1]:80"} {
		document.expectDeny(to, egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to))
		noDocument.expectPass(to, egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to),
			egressTestTag(egressTestUntagged, []byte{device.BridgeRuleAllowAll}))
	}
}

// Rule 6: a served prefix passes with AllowRoute on the destination's port, and a remapped one maps back keeping host
// bits; another port, or no route row, is denied.
func TestBridgeEgressRuleSixRoutesAServedPrefix(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	test.expectPass("a routed port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.9:443"),
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1)))
	test.expectDeny("another port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.9:80"))
	test.expectDeny("no route row", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "192.168.50.9:443"))
	test.expectMap("a remap", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.200.9:443"), "192.168.60.9:443",
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(2)))
	test.expectDeny("a remap's other port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.200.9:80"))
	// with no document an untagged subject reaches a remap's LAN as it reaches any LAN, and never unmapped
	noDocument := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	noDocument.expectMap("a remap under the allow-all", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.200.9:80"),
		"192.168.60.9:80", egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(2)))
}

// Rule 7: public unicast passes with AllowExit through a host that serves an exit; a subject with no exit row, or a
// host that serves none, is denied.
func TestBridgeEgressRuleSevenExitsOnlyByRule(t *testing.T) {
	exit := egressTestTag(egressTestUntagged, []byte{device.BridgeRuleExit})
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	test.expectPass("an exit row", egressTestFlow(egressTestUntagged, connect.IpProtocolUdp, "203.0.113.9:53"), exit)
	test.expectPass("an exit row, IPv6", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "[2001:db8::5]:443"), exit)
	test.expectDeny("no exit row", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "203.0.113.9:443"))
	fixture := egressTestFixture()
	fixture.Served = fixture.Served[:2]
	noExit := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, fixture)
	noExit.expectDeny("a host serving no exit", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443"))
}

// Rule 8: with a document, a LAN address no route serves is denied; one a route serves passes by rule 6.
func TestBridgeEgressRuleEightDeniesLanWithoutARoute(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	for _, to := range []string{"192.168.77.20:443", "10.1.2.3:443", "100.99.1.1:443", "[fd00::5]:443", "240.0.0.1:443"} {
		test.expectDeny(to, egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to))
	}
	test.expectPass("a served LAN", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443"),
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1)))
}

// Control and unset contract classes carry no IP (D-PROTO-18, plan-BRIDGE-small-readings #6), at a host and at an sdk
// provider alike; the data class twin passes.
func TestBridgeEgressDeniesControlAndUnsetClasses(t *testing.T) {
	for _, profile := range []device.BridgePolicyProfile{device.BridgePolicyProfileHost, device.BridgePolicyProfileSdkProvider} {
		test := newEgressTest(t, profile, device.PostureEnforcingNoDocument, egressTestFixture())
		for _, contractClass := range []protocol.ContractClass{connect.ContractClassControl, connect.ContractClassUnset, protocol.ContractClass(9)} {
			flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:80")
			flow.ContractClass = contractClass
			test.expectDeny(profile.String()+" "+contractClass.String(), flow)
		}
		test.expectPass(profile.String()+" data", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:80"),
			egressTestTag(egressTestUntagged, []byte{device.BridgeRuleAllowAll}))
	}
}

// At a host every mode but Network and FriendsAndFamily denies, Service (mode 6) before C9 names it among them, and
// FriendsAndFamily denies until shares land; at an sdk provider every mode but Network and Service passes to today's
// public-only rules, and Service denies (plan-BRIDGE-small-readings #7).
func TestBridgeEgressProvideModes(t *testing.T) {
	host := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	sdk := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureEnforcingNoDocument, egressTestFixture())
	for _, mode := range []protocol.ProvideMode{protocol.ProvideMode_None, protocol.ProvideMode_Public, protocol.ProvideMode_Stream,
		protocol.ProvideMode_PublicStream, protocol.ProvideMode_Service, protocol.ProvideMode_FriendsAndFamily, protocol.ProvideMode(9)} {
		flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
		flow.ProvideMode = mode
		host.expectDeny("host "+mode.String(), flow)
		if mode == protocol.ProvideMode_Service {
			sdk.expectDeny("sdk "+mode.String(), flow)
		} else {
			sdk.expectPass("sdk "+mode.String(), flow, 0)
		}
	}
}

// The principal row: none, an unknown subject, another network, a share, a lapsed one, a revoked or suspended subject
// and an unsealed source each deny, beside a twin that passes; and a revocation between states denies at once.
func TestBridgeEgressNeedsAVerifiedPrincipalAndASealedSource(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	to := "203.0.113.9:443"
	exit := egressTestTag(egressTestUntagged, []byte{device.BridgeRuleExit})
	test.expectPass("the twin", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to), exit)
	mutations := map[string]func(flow *connect.EgressFlow){
		"no principal": func(flow *connect.EgressFlow) { flow.Principal = nil },
		"unknown subject": func(flow *connect.EgressFlow) {
			flow.Principal.Subject = connect.Id(sidecartest.BridgeFixtureSidecarId(0x70))
		},
		"another network": func(flow *connect.EgressFlow) {
			flow.Principal.Network = connect.Id(sidecartest.BridgeFixtureSidecarId(0xB3))
		},
		"a share": func(flow *connect.EgressFlow) {
			flow.Principal.ShareId = connect.Id(sidecartest.BridgeFixtureSidecarId(0xB4))
		},
		"lapsed":           func(flow *connect.EgressFlow) { flow.Principal.NotAfter = time.UnixMilli(egressTestTimeMs) },
		"unsealed":         func(flow *connect.EgressFlow) { flow.Sealed = false },
		"unknown protocol": func(flow *connect.EgressFlow) { flow.Protocol = connect.IpProtocolUnknown },
	}
	for name, mutate := range mutations {
		flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to)
		mutate(flow)
		test.expectDeny(name, flow)
	}
	for _, flags := range []struct{ revoked, suspended bool }{{revoked: true}, {suspended: true}} {
		test.input.BridgeState.Identities[0].Revoked = flags.revoked
		test.input.BridgeState.Identities[0].Suspended = flags.suspended
		test.republish()
		test.expectDeny("revoked or suspended in the state", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to))
	}
	test.input.BridgeState.Identities[0].Revoked, test.input.BridgeState.Identities[0].Suspended = false, false
	overlays := []device.PostureOverlayEntry{
		{Kind: device.PostureOverlaySidecarRevoke, Id: sidecartest.BridgeFixtureSidecarId(egressTestUntagged)},
		{Kind: device.PostureOverlayMemberRevoke, Id: sidecartest.BridgeFixtureMemberId(egressTestUntagged)},
		{Kind: device.PostureOverlaySuspend, Id: sidecartest.BridgeFixtureSidecarId(egressTestUntagged)},
		{Kind: device.PostureOverlaySuspend, Id: sidecartest.BridgeFixtureMemberId(egressTestUntagged)},
	}
	for _, entry := range overlays {
		test.input.Overlay = []device.PostureOverlayEntry{entry}
		test.republish()
		test.expectDeny("narrowed between states", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to))
		// a sibling subject is untouched
		test.expectMap("the sibling", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:443"), "127.0.0.1:443",
			egressTestHostedTag(egressTestTagged, "100.80.1.2"))
	}
	test.input.Overlay = nil
	test.republish()
	test.expectPass("the twin again", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to), exit)
}

// §17.8's states: pending, and rules that were refused, deny every Network flow at a host and at an sdk provider;
// legacy denies at a host, which serves nothing without a sidecar role, and at an sdk provider passes, as no hook does.
func TestBridgeEgressStates(t *testing.T) {
	flow := func() *connect.EgressFlow {
		return egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	}
	for _, profile := range []device.BridgePolicyProfile{device.BridgePolicyProfileHost, device.BridgePolicyProfileSdkProvider} {
		test := newEgressTest(t, profile, device.PosturePending, egressTestFixture())
		test.expectDeny(profile.String()+" pending", flow())
		test.input.State = device.PostureEnforcingDocument
		test.input.Rules = nil
		test.republish()
		test.expectDeny(profile.String()+" refused rules", flow())
	}
	host := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureLegacy, egressTestFixture())
	host.expectDeny("host legacy", flow())
	sdk := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureLegacy, egressTestFixture())
	sdk.expectPass("sdk legacy", flow(), 0)
	unpublished := device.NewBridgeEgressPolicy(device.BridgePolicyProfileSdkProvider, nil)
	if decision := unpublished.ResolveEgress(flow()); decision.Verdict != connect.EgressVerdictDeny || unpublished.PolicyGeneration() != 0 {
		t.Fatalf("before the first publish: %+v", decision)
	}
	if decision := unpublished.ResolveEgress(nil); decision.Verdict != connect.EgressVerdictDeny {
		t.Fatalf("no flow: %+v", decision)
	}
}

// The sdk provider until C16: no principal or seal is needed, its subject is C13's sealed client resolved through the
// rows, and it keeps rules 0, 4, 5, 7 and 8 and the block deny. With no document untagged sources keep today's LAN; with
// one they lose LAN, loopback and overlay reach and keep the exits their rows allow.
func TestBridgeEgressSdkProviderSkipsRulesOneToThreeAndSix(t *testing.T) {
	sdkFlow := func(clientSeed byte, to string) *connect.EgressFlow {
		flow := egressTestFlow(clientSeed, connect.IpProtocolTcp, to)
		flow.Principal = nil
		flow.Sealed = false
		return flow
	}
	allowAll := egressTestTag(egressTestUntagged, []byte{device.BridgeRuleAllowAll})
	noDocument := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureEnforcingNoDocument, egressTestFixture())
	noDocument.expectPass("LAN", sdkFlow(egressTestUntagged, "192.168.77.20:80"), allowAll)
	noDocument.expectPass("loopback", sdkFlow(egressTestUntagged, "127.0.0.1:80"), allowAll)
	noDocument.expectDeny("the daemon", sdkFlow(egressTestUntagged, "127.0.0.1:8443"))
	noDocument.expectDeny("a hosted address", sdkFlow(egressTestUntagged, "100.80.1.2:5432"))
	noDocument.expectDeny("another address of the block", sdkFlow(egressTestUntagged, "100.80.1.3:22"))
	noDocument.expectDeny("tagged, LAN", sdkFlow(egressTestTagged, "192.168.77.20:80"))
	// another client, in no row: untagged, the zero subject
	noDocument.expectPass("another client", sdkFlow(0x7F, "192.168.77.20:80"), device.BridgeRuleTag(connect.Id{}, []byte{device.BridgeRuleAllowAll}))

	document := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureEnforcingDocument, egressTestFixture())
	document.expectDeny("LAN", sdkFlow(egressTestUntagged, "192.168.77.20:80"))
	document.expectDeny("a served prefix, which rule 6 does not reach here", sdkFlow(egressTestUntagged, "192.168.50.9:443"))
	document.expectDeny("loopback", sdkFlow(egressTestUntagged, "127.0.0.1:80"))
	document.expectPass("an exit row", sdkFlow(egressTestUntagged, "203.0.113.9:443"), egressTestTag(egressTestUntagged, []byte{device.BridgeRuleExit}))
	document.expectDeny("no exit row", sdkFlow(egressTestTagged, "203.0.113.9:443"))
	document.expectDeny("another client holds no rows", sdkFlow(0x7F, "203.0.113.9:443"))
	// a revoked subject denies here too
	document.input.Overlay = []device.PostureOverlayEntry{{Kind: device.PostureOverlaySidecarRevoke, Id: sidecartest.BridgeFixtureSidecarId(egressTestUntagged)}}
	document.republish()
	document.expectDeny("revoked", sdkFlow(egressTestUntagged, "203.0.113.9:443"))
	if principal := document.policy.VerifyPrincipal(connect.TransferPath{}, connect.Peer{ProvideMode: protocol.ProvideMode_Network}); principal != nil {
		t.Fatal("an sdk provider verified a principal")
	}
}

// Another client at an sdk provider, a sealed subject no row binds, holds BridgeRules.untagged's rows
// (bridge-m4-09-other-client-rows): under a document its exit rows pass it out under the zero subject's tag, while a
// port no row holds, the LAN and the block stay denied and a revoked grant's row admits nothing; with no field it holds
// none. A bound subject keeps its own rows, and a host never gives the untagged rows to a principal no row names.
func TestOtherClientsHoldUntaggedRows(t *testing.T) {
	sdkFlow := func(clientSeed byte, ipProtocol connect.IpProtocol, to string) *connect.EgressFlow {
		flow := egressTestFlow(clientSeed, ipProtocol, to)
		flow.Principal = nil
		flow.Sealed = false
		return flow
	}
	const otherClient byte = 0x7F
	exit := device.BridgeRuleTag(connect.Id{}, []byte{device.BridgeRuleExit})
	fixture := egressTestFixture()
	fixture.Untagged = &sidecartest.BridgeRulesFixtureUntagged{
		Dial:  []sidecartest.BridgeRulesFixtureReach{{Ports: "*"}},
		Route: []sidecartest.BridgeRulesFixtureReach{{Prefix: "192.168.50.0/24", Ports: "*"}},
		Exit:  []sidecartest.BridgeRulesFixtureReach{{Ports: "tcp:443", Grant: 2}, {Ports: "udp:53"}},
	}
	document := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureEnforcingDocument, fixture)
	document.expectPass("an exit row", sdkFlow(otherClient, connect.IpProtocolTcp, "203.0.113.9:443"), exit)
	document.expectPass("another exit row", sdkFlow(otherClient, connect.IpProtocolUdp, "203.0.113.9:53"), exit)
	document.expectDeny("a port no row holds", sdkFlow(otherClient, connect.IpProtocolTcp, "203.0.113.9:80"))
	// rules 1 to 3 and 6 do not run here, so the dial and route rows open nothing
	document.expectDeny("a served LAN", sdkFlow(otherClient, connect.IpProtocolTcp, "192.168.50.9:443"))
	document.expectDeny("a hosted address", sdkFlow(otherClient, connect.IpProtocolTcp, "100.80.1.2:443"))
	document.expectDeny("the tagged subject, which has no exit row", sdkFlow(egressTestTagged, connect.IpProtocolTcp, "203.0.113.9:443"))
	document.input.Overlay = []device.PostureOverlayEntry{{Kind: device.PostureOverlayGrantRevoke, Id: sidecartest.BridgeFixtureGrantId(2)}}
	document.republish()
	document.expectDeny("the revoked grant's row", sdkFlow(otherClient, connect.IpProtocolTcp, "203.0.113.9:443"))
	document.expectPass("the row of no grant", sdkFlow(otherClient, connect.IpProtocolUdp, "203.0.113.9:53"), exit)

	none := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureEnforcingDocument, egressTestFixture())
	none.expectDeny("no field", sdkFlow(otherClient, connect.IpProtocolTcp, "203.0.113.9:443"))
	none.expectDeny("no field, another exit", sdkFlow(otherClient, connect.IpProtocolUdp, "203.0.113.9:53"))

	host := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, fixture)
	unknown := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	unknown.Principal.Subject = connect.Id(sidecartest.BridgeFixtureSidecarId(otherClient))
	host.expectDeny("a principal no row names, at a host", unknown)
}

// §22.7's S8 at unit level: with a document only a rule opens the LAN; without one the LAN stays open to untagged
// sources, but never the provider's own 127.0.0.1 daemon ports, while an unrelated loopback service passes.
func TestBridgeEgressS8(t *testing.T) {
	document := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	document.expectDeny("LAN with no rule", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:443"))
	document.expectPass("LAN by rule", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443"),
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1)))
	noDocument := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	allowAll := egressTestTag(egressTestUntagged, []byte{device.BridgeRuleAllowAll})
	noDocument.expectPass("LAN, untagged", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:443"), allowAll)
	noDocument.expectDeny("the daemon's port", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "127.0.0.1:8443"))
	noDocument.expectPass("an unrelated loopback service", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "127.0.0.1:6379"), allowAll)
}

// A flow with a principal is held for the link's idles, TCP's 600 s and 5 min otherwise (§17.5); an sdk provider's
// flows keep the NAT's.
func TestBridgeEgressSetsTheLinksIdles(t *testing.T) {
	host := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	cases := []struct {
		ipProtocol connect.IpProtocol
		to         string
		idle       time.Duration
	}{
		{ipProtocol: connect.IpProtocolTcp, to: "192.168.77.20:443", idle: 600 * time.Second},
		{ipProtocol: connect.IpProtocolUdp, to: "192.168.77.20:53", idle: 5 * time.Minute},
		{ipProtocol: connect.IpProtocolIcmp, to: "100.80.1.2:0", idle: 5 * time.Minute},
	}
	for _, testCase := range cases {
		if decision := host.policy.ResolveEgress(egressTestFlow(egressTestUntagged, testCase.ipProtocol, testCase.to)); decision.IdleTimeout != testCase.idle {
			t.Errorf("%v to %s: idle %v", testCase.ipProtocol, testCase.to, decision.IdleTimeout)
		}
	}
	sdk := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureEnforcingNoDocument, egressTestFixture())
	flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:443")
	if decision := sdk.policy.ResolveEgress(flow); decision.Verdict != connect.EgressVerdictPass || decision.IdleTimeout != 0 {
		t.Fatalf("sdk: %+v", decision)
	}
}

// ICMP has no port: a row naming ports never admits it, while a row of ICMP or of every protocol does, and an echo to a
// hosted address follows rule 3.
func TestBridgeEgressIcmpHasNoPort(t *testing.T) {
	fixture := egressTestFixture()
	fixture.Subjects[1].Dial = append(fixture.Subjects[1].Dial, sidecartest.BridgeRulesFixtureReach{Ports: "tcp:1-65535"})
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, fixture)
	test.expectDeny("ports only", egressTestFlow(egressTestTagged, connect.IpProtocolIcmp, "100.80.1.2:0"))
	test.expectMap("an icmp row", egressTestFlow(egressTestUntagged, connect.IpProtocolIcmp, "100.80.1.2:0"), "127.0.0.1:0",
		egressTestHostedTag(egressTestUntagged, "100.80.1.2"))
	fixture.Subjects[1].Dial = []sidecartest.BridgeRulesFixtureReach{{Ports: "*"}}
	everything := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, fixture)
	everything.expectMap("every protocol", egressTestFlow(egressTestTagged, connect.IpProtocolIcmp, "100.80.1.2:0"), "127.0.0.1:0",
		egressTestHostedTag(egressTestTagged, "100.80.1.2"))
}

// Time: a row or map past its expiry admits nothing; a draining served prefix admits until its drain's end, no sooner
// than 600 s from its start; a draining map admits no new flow; an address of the previous block admits until that
// block's drain ends.
func TestBridgeEgressReadsTimes(t *testing.T) {
	fixture := egressTestFixture()
	fixture.PreviousBlock = "100.81.0.0/16"
	fixture.PreviousBlockDrainUntil = egressTestTimeMs + egressTestHourMs
	fixture.Addresses = append(fixture.Addresses, "100.81.1.2")
	fixture.Maps[0].Expires = egressTestTimeMs + egressTestHourMs
	fixture.Maps[1].DrainingSince = egressTestTimeMs - 1000
	fixture.Maps[1].DrainUntil = egressTestTimeMs + 1000
	fixture.Served[0].DrainingSince = egressTestTimeMs
	fixture.Served[0].DrainUntil = egressTestTimeMs + 30_000
	fixture.Subjects[0].Exit[0].Expires = egressTestTimeMs + egressTestHourMs
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, fixture)

	test.expectMap("before the map expires", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"), "127.0.0.1:5432",
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(1)))
	// a draining map takes no new flow, which falls to rule 3's loopback, never the map's target
	test.expectMap("a draining map", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:8005"), "127.0.0.1:8005",
		egressTestHostedTag(egressTestUntagged, "100.80.1.2"))
	test.expectPass("a draining route admits", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443"),
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1)))
	test.expectMap("the previous block's address", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.81.1.2:22"), "127.0.0.1:22",
		egressTestHostedTag(egressTestUntagged, "100.81.1.2"))

	// its drain_until passed, the route still admits until 600 s from its start
	test.clock.now = time.UnixMilli(egressTestTimeMs + 300_000)
	test.expectPass("within the drain's floor", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443"),
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1)))
	test.clock.now = time.UnixMilli(egressTestTimeMs + 600_000)
	test.expectDeny("the drain ended", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443"))

	test.clock.now = time.UnixMilli(egressTestTimeMs + egressTestHourMs)
	late := func(to string) *connect.EgressFlow {
		flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to)
		flow.Principal.NotAfter = time.UnixMilli(egressTestTimeMs + 2*egressTestHourMs)
		return flow
	}
	// the map expired, so the hosted address falls to rule 3, whose dial row maps it to loopback all the same
	test.expectMap("the expired map's port, by rule 3", late("100.80.1.2:5432"), "127.0.0.1:5432",
		egressTestHostedTag(egressTestUntagged, "100.80.1.2"))
	test.expectDeny("the exit row expired", late("203.0.113.9:443"))
	test.expectDeny("the previous block drained", late("100.81.1.2:22"))
	test.expectDeny("the principal lapsed", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:22"))
}

// A withdraw between states: reset stops a map or a route at once; drain stops a map's new flows and leaves a route
// admitting until the next state times its drain; a revoked grant's rows admit nothing.
func TestBridgeEgressAppliesWithdrawsAndGrantRevokes(t *testing.T) {
	fixture := egressTestFixture()
	fixture.Subjects[0].Route[0].Grant = 1
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, fixture)
	routed := egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1))
	test.input.Overlay = []device.PostureOverlayEntry{
		{Kind: device.PostureOverlayBridgeWithdraw, Id: sidecartest.BridgeFixtureMapId(1), WithdrawMode: bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET},
		{Kind: device.PostureOverlayBridgeWithdraw, Id: sidecartest.BridgeFixtureMapId(2), WithdrawMode: bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN},
		{Kind: device.PostureOverlayBridgeWithdraw, Id: sidecartest.BridgeFixtureRouteId(1), WithdrawMode: bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN},
	}
	test.republish()
	test.expectMap("a reset map falls to rule 3", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"), "127.0.0.1:5432",
		egressTestHostedTag(egressTestUntagged, "100.80.1.2"))
	test.expectMap("a drained map takes no new flow, which falls to rule 3", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp,
		"100.80.1.2:8005"), "127.0.0.1:8005", egressTestHostedTag(egressTestUntagged, "100.80.1.2"))
	test.expectPass("a drained route admits", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443"), routed)
	test.input.Overlay = []device.PostureOverlayEntry{
		{Kind: device.PostureOverlayBridgeWithdraw, Id: sidecartest.BridgeFixtureRouteId(1)},
	}
	test.republish()
	test.expectDeny("a route withdrawn in an unknown mode resets", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443"))
	test.input.Overlay = []device.PostureOverlayEntry{{Kind: device.PostureOverlayGrantRevoke, Id: sidecartest.BridgeFixtureGrantId(1)}}
	test.republish()
	test.expectDeny("the grant's row", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443"))
	test.expectMap("another row survives", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.200.9:443"), "192.168.60.9:443",
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(2)))
}

// Each publish raises the generation by one, and every decision names the generation it used.
func TestBridgeEgressPublishRaisesTheGeneration(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, egressTestFixture())
	if test.policy.PolicyGeneration() != 1 {
		t.Fatalf("generation %d after one publish", test.policy.PolicyGeneration())
	}
	for want := uint64(2); want <= 4; want += 1 {
		if generation := test.policy.Publish(test.input); generation != want || test.policy.PolicyGeneration() != want {
			t.Fatalf("publish %d gave %d", want, generation)
		}
		decision := test.policy.ResolveEgress(egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443"))
		if decision.PolicyGeneration != want {
			t.Fatalf("a decision of generation %d at %d", decision.PolicyGeneration, want)
		}
	}
	if test.policy.FriendsAndFamilyEgress() {
		t.Fatal("FriendsAndFamily egress before shares")
	}
}

// The tag of reading 11: the first 8 bytes of SHA-256(subject_id || rule_id), big-endian; pseudo rules hash their one
// byte, and rule 3 that byte and the hosted address's four (DESIGN-DETAILS 12.2.2), so none equals a 32-byte rule id's
// tag.
func TestBridgeRuleTagIsReadingElevens(t *testing.T) {
	subjectId := connect.Id(sidecartest.BridgeFixtureSidecarId(egressTestUntagged))
	mapId := sidecartest.BridgeFixtureMapId(1)
	if device.BridgeRuleTag(subjectId, mapId) != egressReferenceTag(subjectId, mapId) {
		t.Fatal("a map's tag")
	}
	if device.BridgeRuleTag(subjectId, []byte{device.BridgeRuleExit}) != egressReferenceTag(subjectId, []byte{7}) {
		t.Fatal("rule 7's tag")
	}
	if egressTestHostedTag(egressTestUntagged, "100.80.1.2") != egressReferenceTag(subjectId, []byte{3, 100, 80, 1, 2}) {
		t.Fatal("rule 3's tag")
	}
	long := make([]byte, 40)
	if device.BridgeRuleTag(subjectId, long) != egressReferenceTag(subjectId, long) {
		t.Fatal("a long rule id's tag")
	}
	if device.BridgeRuleTag(subjectId, mapId) == device.BridgeRuleTag(connect.Id(sidecartest.BridgeFixtureSidecarId(egressTestTagged)), mapId) {
		t.Fatal("two subjects share a tag")
	}
	// rule 3's tags split by address, and none is the tag of the rule's bare number
	if egressTestHostedTag(egressTestUntagged, "100.80.1.2") == egressTestHostedTag(egressTestUntagged, "100.81.1.2") ||
		egressTestHostedTag(egressTestUntagged, "100.80.1.2") == egressTestTag(egressTestUntagged, []byte{device.BridgeRuleHosted}) {
		t.Fatal("two hosted addresses, or an address and none, share a tag")
	}
}

// Rule 3's tag names the address the flow was sent to: a host with two addresses gives each its own tag, the same for
// every port and protocol of it, and another subject's flows to the same address take that subject's.
func TestBridgeEgressRuleThreeTagsSplitByAddress(t *testing.T) {
	fixture := egressTestFixture()
	fixture.Addresses = append(fixture.Addresses, "100.80.1.4")
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, fixture)
	first := egressTestHostedTag(egressTestUntagged, "100.80.1.2")
	second := egressTestHostedTag(egressTestUntagged, "100.80.1.4")
	test.expectMap("the first address", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:22"), "127.0.0.1:22", first)
	test.expectMap("the first address, ICMP", egressTestFlow(egressTestUntagged, connect.IpProtocolIcmp, "100.80.1.2:0"), "127.0.0.1:0", first)
	test.expectMap("the second address", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.4:22"), "127.0.0.1:22", second)
	test.expectMap("another subject at the second", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.4:443"),
		"127.0.0.1:443", egressTestHostedTag(egressTestTagged, "100.80.1.4"))
	if first == second {
		t.Fatal("two addresses share a tag")
	}
}

// The hot path allocates nothing, for each verdict: a map, rule 3's tag by address, a pass, a deny and a remap at a
// host, and another client's exit by the untagged rows at an sdk provider.
func TestBridgeEgressResolveAllocatesNothing(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingNoDocument, egressTestFixture())
	flows := []*connect.EgressFlow{
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"),
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:22"),
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:443"),
		egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "192.168.77.20:443"),
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.200.9:443"),
	}
	for _, flow := range flows {
		if allocations := testing.AllocsPerRun(100, func() { test.policy.ResolveEgress(flow) }); allocations != 0 {
			t.Errorf("%v: %v allocations", flow.To, allocations)
		}
	}
	fixture := egressTestFixture()
	fixture.Untagged = &sidecartest.BridgeRulesFixtureUntagged{Exit: []sidecartest.BridgeRulesFixtureReach{{Ports: "tcp:443"}}}
	sdk := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureEnforcingDocument, fixture)
	other := egressTestFlow(0x7F, connect.IpProtocolTcp, "203.0.113.9:443")
	other.Principal = nil
	if allocations := testing.AllocsPerRun(100, func() { sdk.policy.ResolveEgress(other) }); allocations != 0 {
		t.Errorf("another client's exit: %v allocations", allocations)
	}
}

// §22.5: ResolveEgress on the enabled production path, with effective settings, a map, a pass, a deny and a remap in
// turn. Reports allocations, which must be 0; it takes no lock, by its construction (one atomic load).
func BenchmarkBridgeEgressPolicy(b *testing.B) {
	settings := device.DefaultBridgeSettings()
	fixture := egressTestFixture()
	rules, err := device.ParseBridgeRules(fixture.Bytes(), settings)
	if err != nil {
		b.Fatal(err)
	}
	bridgeState := &bridge.BridgeState{DaemonListeners: egressTestListeners}
	for _, subject := range fixture.Subjects {
		bridgeState.Identities = append(bridgeState.Identities, &bridge.BridgeIdentity{
			SidecarId:         sidecartest.BridgeFixtureSidecarId(subject.Sidecar),
			IdentityPublicKey: sidecartest.BridgeFixtureIdentityKey(subject.Sidecar).Public().(ed25519.PublicKey),
		})
	}
	policy := device.NewBridgeEgressPolicy(device.BridgePolicyProfileHost, settings)
	policy.Publish(&device.BridgePolicyInput{
		State:          device.PostureEnforcingDocument,
		BridgeState:    bridgeState,
		Rules:          rules,
		NetworkId:      egressTestNetworkId,
		SidecarId:      egressTestHostId,
		LocalAddresses: []netip.Addr{netip.MustParseAddr("192.168.77.10")},
	})
	flows := []*connect.EgressFlow{
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"),
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443"),
		egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "192.168.77.20:443"),
		egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.200.9:443"),
	}
	// the real clock's time, and a principal that outlives the run
	for _, flow := range flows {
		flow.Principal.NotAfter = time.Now().Add(time.Hour)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i += 1 {
		policy.ResolveEgress(flows[i%len(flows)])
	}
}
