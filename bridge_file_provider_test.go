//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

// Resolve the authorized flow at the actual host hook on the original, folded, restored and withdrawn state.
func TestActivatedForwardReachesItsExactProviderPort(t *testing.T) {
	sidecar.CheckActivatedForwardProvider(t, func(fixture sidecar.ForwardProviderFixture, live bool) {
		t.Helper()
		settings := device.DefaultBridgeSettings()
		settings.Clock = fixture.Clock
		rules, err := device.ParseBridgeRules(fixture.State.GetRules(), settings)
		if err != nil {
			t.Fatal(err)
		}
		policy := device.NewBridgeEgressPolicy(device.BridgePolicyProfileHost, settings)
		policy.Publish(&device.BridgePolicyInput{
			State: device.PostureEnforcingDocument, BridgeState: fixture.State, Rules: rules,
			NetworkId: fixture.NetworkId.Bytes(), SidecarId: fixture.TargetId.Bytes(),
		})
		flow := &connect.EgressFlow{
			ProvideMode: protocol.ProvideMode_Network, ContractClass: connect.ContractClassData,
			Principal: &connect.BridgePrincipal{Subject: connect.Id(fixture.SubjectId), Network: connect.Id(fixture.NetworkId),
				NotAfter: fixture.Clock.Now().Add(time.Hour)},
			Sealed: true, Protocol: connect.IpProtocolUdp, To: fixture.Target,
		}
		decision := policy.ResolveEgress(flow)
		loopback := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), fixture.Target.Port())
		if live && (decision.Verdict != connect.EgressVerdictMap || decision.Target != loopback) ||
			!live && decision.Verdict != connect.EgressVerdictDeny {
			t.Fatalf("provider decision with live grant %t: %+v", live, decision)
		}
		flow.Protocol = connect.IpProtocolTcp
		if policy.ResolveEgress(flow).Verdict != connect.EgressVerdictDeny {
			t.Fatal("the provider admitted the unapproved protocol")
		}
		flow.Protocol, flow.To = connect.IpProtocolUdp, netip.AddrPortFrom(fixture.Target.Addr(), fixture.Target.Port()+1)
		if policy.ResolveEgress(flow).Verdict != connect.EgressVerdictDeny {
			t.Fatal("the provider admitted the neighboring port")
		}
	})
}
