// BridgePolicyProfileSdkHost, an app device's exit NAT after C16 in its device client's network (BRIDGE-M8-01;
// D-BRIDGE-5, D-BRIDGE-17, §17.6's sdk exit NAT, §18.6's host row): its public role is the sdk provider's, decision for
// decision, so public exit flows pass exactly as with no hook; its Network flows take a host's rows whole, a verified
// principal over a sealed session before maps, hosted addresses and served prefixes, each refusal beside its twin; a
// principal's flow holds the link's idles while a public one keeps the NAT's; it serves no share; and a move to legacy
// ends what its host rows admitted, where an sdk provider's ends nothing.

package device_test

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The public role is the sdk provider's: for every mode but Network and Service, in every state, whatever the flow
// carries, the sdk host passes with no target, tag or idle, as the sdk provider does and as no hook would; at legacy
// every flow passes, Network ones too.
func TestSdkHostPublicRoleIsTheSdkProvidersDecisionForDecision(t *testing.T) {
	modes := []protocol.ProvideMode{protocol.ProvideMode_None, protocol.ProvideMode_Public, protocol.ProvideMode_Stream,
		protocol.ProvideMode_PublicStream, protocol.ProvideMode_FriendsAndFamily, protocol.ProvideMode(9)}
	destinations := []string{"203.0.113.9:443", "192.168.77.20:80", "127.0.0.1:8443", "100.80.1.2:5432", "[2001:db8::9]:443"}
	states := []device.PostureState{device.PostureLegacy, device.PosturePending, device.PostureEnforcingDocument,
		device.PostureEnforcingNoDocument}
	for _, state := range states {
		sdkHost := newEgressTest(t, device.BridgePolicyProfileSdkHost, state, egressTestFixture())
		sdkProvider := newEgressTest(t, device.BridgePolicyProfileSdkProvider, state, egressTestFixture())
		for _, mode := range modes {
			for _, to := range destinations {
				for _, ipProtocol := range []connect.IpProtocol{connect.IpProtocolTcp, connect.IpProtocolUdp, connect.IpProtocolIcmp} {
					flows := []*connect.EgressFlow{egressTestFlow(egressTestUntagged, ipProtocol, to)}
					bare := egressTestFlow(egressTestTagged, ipProtocol, to)
					bare.Principal, bare.Sealed, bare.ContractClass = nil, false, connect.ContractClassUnset
					flows = append(flows, bare)
					for _, flow := range flows {
						flow.ProvideMode = mode
						got := sdkHost.policy.ResolveEgress(flow)
						want := sdkProvider.policy.ResolveEgress(flow)
						if got.Verdict != connect.EgressVerdictPass || got.Target.IsValid() || got.RuleTag != 0 || got.IdleTimeout != 0 ||
							got.Verdict != want.Verdict || got.RuleTag != want.RuleTag || got.IdleTimeout != want.IdleTimeout {
							t.Errorf("%v, %v to %s: sdk host %+v, sdk provider %+v", state, mode, to, got, want)
						}
					}
				}
			}
		}
	}
	legacy := newEgressTest(t, device.BridgePolicyProfileSdkHost, device.PostureLegacy, egressTestFixture())
	unsealed := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:80")
	unsealed.Principal, unsealed.Sealed = nil, false
	legacy.expectPass("legacy, a Network flow with nothing", unsealed, 0)
	service := newEgressTest(t, device.BridgePolicyProfileSdkHost, device.PostureEnforcingNoDocument, egressTestFixture())
	serviceFlow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
	serviceFlow.ProvideMode = protocol.ProvideMode_Service
	service.expectDeny("Service", serviceFlow)
}

// D-BRIDGE-17 at an app device from C16: a Network flow is admitted only with a verified principal of this network
// over a sealed session; each refusal alone denies beside its twin, and the sdk provider, which skips the row until
// C16, passes the bare flow the sdk host denies.
func TestSdkHostAdmitsOnlyAVerifiedPrincipalOverASealedSession(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileSdkHost, device.PostureEnforcingDocument, egressTestFixture())
	hosted := egressTestHostedTag(egressTestUntagged, "100.80.1.2")
	to := "100.80.1.2:22"
	test.expectMap("the twin", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to), "127.0.0.1:22", hosted)
	mutations := map[string]func(flow *connect.EgressFlow){
		"no principal": func(flow *connect.EgressFlow) { flow.Principal = nil },
		"a plaintext peer": func(flow *connect.EgressFlow) {
			flow.Sealed = false
		},
		"unknown subject": func(flow *connect.EgressFlow) {
			flow.Principal.Subject = connect.Id(sidecartest.BridgeFixtureSidecarId(0x70))
		},
		"another network": func(flow *connect.EgressFlow) {
			flow.Principal.Network = connect.Id(sidecartest.BridgeFixtureSidecarId(0xB3))
		},
		"a share's": func(flow *connect.EgressFlow) {
			flow.Principal.ShareId = connect.Id(sidecartest.BridgeFixtureSidecarId(0xB4))
		},
		"lapsed":        func(flow *connect.EgressFlow) { flow.Principal.NotAfter = time.UnixMilli(egressTestTimeMs) },
		"control class": func(flow *connect.EgressFlow) { flow.ContractClass = connect.ContractClassControl },
		"unset class":   func(flow *connect.EgressFlow) { flow.ContractClass = connect.ContractClassUnset },
	}
	for name, mutate := range mutations {
		flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to)
		mutate(flow)
		test.expectDeny(name, flow)
	}
	// an exit row the sdk provider honors for C13's sealed client alone, which the sdk host denies without a principal
	bare := func() *connect.EgressFlow {
		flow := egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443")
		flow.Principal, flow.Sealed = nil, false
		return flow
	}
	sdkProvider := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureEnforcingDocument, egressTestFixture())
	sdkProvider.expectPass("the sdk provider before C16", bare(), egressTestTag(egressTestUntagged, []byte{device.BridgeRuleExit}))
	test.expectDeny("the sdk host from C16", bare())
	// a revocation between states denies at once, the sibling untouched
	test.input.Overlay = []device.PostureOverlayEntry{{Kind: device.PostureOverlaySidecarRevoke, Id: sidecartest.BridgeFixtureSidecarId(egressTestUntagged)}}
	test.republish()
	test.expectDeny("revoked between states", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to))
	test.expectMap("the sibling", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:443"), "127.0.0.1:443",
		egressTestHostedTag(egressTestTagged, "100.80.1.2"))
}

// Maps and hosted addresses on an app device (§17.6's rules 0 to 3 and 6, which the sdk provider skips): a port map onto
// loopback, a range by offset onto the LAN, the hosted address onto loopback, a served and a remapped prefix, while a
// daemon listener, another host's address and a map onto one stay denied; the sdk provider refuses every one of these
// destinations, holding the block deny in place of rules 1 to 3.
func TestSdkHostMapsAndHostsAddresses(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileSdkHost, device.PostureEnforcingDocument, egressTestFixture())
	test.expectMap("a port map onto loopback", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:5432"),
		"127.0.0.1:5432", egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(1)))
	test.expectMap("a range by offset onto the LAN", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:8007"),
		"192.168.1.20:9007", egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureMapId(2)))
	test.expectMap("the hosted address", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:22"),
		"127.0.0.1:22", egressTestHostedTag(egressTestUntagged, "100.80.1.2"))
	test.expectPass("a served prefix", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.50.20:443"),
		egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(1)))
	test.expectMap("a remapped prefix", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.200.7:443"),
		"192.168.60.7:443", egressTestTag(egressTestUntagged, sidecartest.BridgeFixtureRouteId(2)))
	test.expectPass("an exit this device serves", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "203.0.113.9:443"),
		egressTestTag(egressTestUntagged, []byte{device.BridgeRuleExit}))
	test.expectDeny("a map onto the daemon", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:7000"))
	test.expectDeny("a map onto another host", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:7001"))
	test.expectDeny("another host's address", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.3:22"))
	test.expectDeny("the daemon's listener", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "127.0.0.1:8443"))
	test.expectDeny("the tagged subject's port with no row", egressTestFlow(egressTestTagged, connect.IpProtocolTcp, "100.80.1.2:5432"))
	test.expectDeny("the LAN with no route", egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, "192.168.77.20:443"))

	sdkProvider := newEgressTest(t, device.BridgePolicyProfileSdkProvider, device.PostureEnforcingDocument, egressTestFixture())
	for _, to := range []string{"100.80.1.2:5432", "100.80.1.2:8007", "100.80.1.2:22", "192.168.50.20:443", "100.80.200.7:443"} {
		sdkProvider.expectDeny("the sdk provider at "+to, egressTestFlow(egressTestUntagged, connect.IpProtocolTcp, to))
	}
}

// A principal's flow holds the link's idles, TCP's 600 s and 5 min otherwise (§17.5's idle row), and a public flow
// keeps the NAT's own, so the exit's public flows are untouched (§22.9's link cell holds the same on a NAT).
func TestSdkHostHoldsPrincipalFlowsForTheLinksIdles(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileSdkHost, device.PostureEnforcingNoDocument, egressTestFixture())
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
		decision := test.policy.ResolveEgress(egressTestFlow(egressTestUntagged, testCase.ipProtocol, testCase.to))
		if decision.Verdict == connect.EgressVerdictDeny || decision.IdleTimeout != testCase.idle {
			t.Errorf("%v to %s: %+v, want idle %v", testCase.ipProtocol, testCase.to, decision, testCase.idle)
		}
		public := egressTestFlow(egressTestUntagged, testCase.ipProtocol, "203.0.113.9:443")
		public.ProvideMode = protocol.ProvideMode_Public
		if decision := test.policy.ResolveEgress(public); decision.Verdict != connect.EgressVerdictPass || decision.IdleTimeout != 0 {
			t.Errorf("a public %v flow: %+v", testCase.ipProtocol, decision)
		}
	}
}

// Shares host only on sidecar-owned clients (§17.9's isolation row): an sdk host holding a share in its state never
// turns FriendsAndFamilyEgress on, and a FriendsAndFamily flow carrying the share's principal passes as Public to the
// address it was sent to, never to the target a host maps its alias onto.
func TestSdkHostServesNoShare(t *testing.T) {
	test := newEgressTest(t, device.BridgePolicyProfileSdkHost, device.PostureEnforcingDocument, shareTestFixture())
	if test.policy.FriendsAndFamilyEgress() {
		t.Fatal("an sdk host hands FriendsAndFamily flows to the hook")
	}
	host := newEgressTest(t, device.BridgePolicyProfileHost, device.PostureEnforcingDocument, shareTestFixture())
	if !host.policy.FriendsAndFamilyEgress() {
		t.Fatal("CONTROL FAILED: the host with the same share serves none")
	}
	alias := "100.90.129.7:443"
	if decision := host.policy.ResolveEgress(shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, alias)); decision.Verdict != connect.EgressVerdictMap {
		t.Fatalf("CONTROL FAILED: the host does not map the alias: %+v", decision)
	}
	test.expectPass("the share's flow, as Public", shareTestFlow(shareTestShareA, shareTestNetworkY, connect.IpProtocolTcp, alias), 0)
	if principal := test.policy.VerifyPrincipal(connect.TransferPath{}, connect.Peer{ProvideMode: protocol.ProvideMode_FriendsAndFamily}); principal != nil {
		t.Fatal("an sdk host verified a share principal")
	}
}

// A move to legacy, this sidecar's own sign-out, ends every tag the sdk host's rows admitted, a mapped flow into
// loopback's among them, and a new flow then passes as sent, never mapped; an admin's revocation of a subject closes
// exactly that subject's tags, as at a host. The sdk provider's move to legacy ends nothing.
func TestSdkHostEndsItsAdmittedFlowsAtLegacy(t *testing.T) {
	sdkHost := func(settings *device.BridgeSettings) {
		settings.PolicyProfile = device.BridgePolicyProfileSdkHost
	}
	revoked := newStateTestWithSettings(t, dispositionTestFixture(), true, sdkHost)
	pin := revoked.log.Tip()
	n := revoked.log.SidecarRevoke(sidecartest.BridgeFixtureSidecarId(egressTestUntagged))
	if err := revoked.bridge.ApplyDeltas(revoked.log.Deltas(pin+1, n)); err != nil {
		t.Fatal(err)
	}
	if tags, _ := revoked.closer.take(); !slices.Equal(tags, dispositionTestTags(egressTestUntagged)) {
		t.Errorf("a SidecarRevoke closed %v, want %v", tags, dispositionTestTags(egressTestUntagged))
	}

	test := newStateTestWithSettings(t, dispositionTestFixture(), true, sdkHost)
	hosted := test.flow(egressTestUntagged, connect.IpProtocolTcp, "100.80.1.2:22")
	if decision := test.bridge.EgressHook().ResolveEgress(hosted); decision.Verdict != connect.EgressVerdictMap {
		t.Fatalf("CONTROL FAILED: the hosted address before the sign-out: %+v", decision)
	}
	pin = test.log.Tip()
	n = test.log.OwnSignOut()
	if err := test.bridge.ApplyDeltas(test.log.Deltas(pin+1, n)); err != nil {
		t.Fatal(err)
	}
	if state := test.bridge.Status().State; state != device.PostureLegacy {
		t.Fatalf("after the own sign-out: %v", state)
	}
	tags, _ := test.closer.take()
	want := slices.Concat(dispositionTestTags(egressTestUntagged), dispositionTestTags(egressTestTagged))
	slices.Sort(want)
	if !slices.Equal(tags, want) {
		t.Errorf("the sign-out closed %v, want every subject's tags %v", tags, want)
	}
	if decision := test.bridge.EgressHook().ResolveEgress(hosted); decision.Verdict != connect.EgressVerdictPass || decision.Target.IsValid() {
		t.Errorf("a new flow at legacy: %+v, want a pass as sent", decision)
	}

	provider := newStateTestWithSettings(t, dispositionTestFixture(), true, func(settings *device.BridgeSettings) {
		settings.PolicyProfile = device.BridgePolicyProfileSdkProvider
	})
	pin = provider.log.Tip()
	n = provider.log.OwnSignOut()
	if err := provider.bridge.ApplyDeltas(provider.log.Deltas(pin+1, n)); err != nil {
		t.Fatal(err)
	}
	if tags, _ := provider.closer.take(); len(tags) != 0 {
		t.Errorf("the sdk provider's sign-out closed %v", tags)
	}
}
