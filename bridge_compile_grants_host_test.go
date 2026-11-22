//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

package sidecar_test

import (
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

// An activated route grant at the host's actual hook (§17.6's rule 6): the desktop's device role, given the state its
// compile gave under the grant, passes the laptop's flows to the grant's prefix at the grant's port and denies another
// port, another protocol, the served route's part the grant does not name and another served route; given the state
// after the grant's GrantRevoke it denies them all.
func TestAnActivatedRouteGrantAdmitsExactlyItsDetailAtTheHostsHook(t *testing.T) {
	fixture := sidecar.CompileActivatedRouteGrantHost(t)
	for _, c := range []struct {
		name string
		live bool
	}{
		{name: "granted", live: true},
		{name: "revoked", live: false},
	} {
		state, clock := fixture.Granted, fixture.GrantedClock
		if !c.live {
			state, clock = fixture.Revoked, fixture.RevokedClock
		}
		settings := device.DefaultBridgeSettings()
		settings.Clock = clock
		rules, err := device.ParseBridgeRules(state.GetRules(), settings)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		policy := device.NewBridgeEgressPolicy(device.BridgePolicyProfileHost, settings)
		policy.Publish(&device.BridgePolicyInput{
			State: device.PostureEnforcingDocument, BridgeState: state, Rules: rules,
			NetworkId: fixture.NetworkId.Bytes(), SidecarId: fixture.HostId.Bytes(),
		})
		resolve := func(flow sidecar.RouteGrantFlow) connect.EgressVerdict {
			// connect's own protocol values, not the IP protocol numbers the fixture names
			ipProtocol := map[uint32]connect.IpProtocol{6: connect.IpProtocolTcp, 17: connect.IpProtocolUdp}[flow.Protocol]
			if ipProtocol == connect.IpProtocolUnknown {
				t.Fatalf("a fixture flow of protocol %d", flow.Protocol)
			}
			return policy.ResolveEgress(&connect.EgressFlow{
				ProvideMode: protocol.ProvideMode_Network, ContractClass: connect.ContractClassData,
				Principal: &connect.BridgePrincipal{Subject: connect.Id(fixture.SubjectId), Network: connect.Id(fixture.NetworkId),
					NotAfter: clock.Now().Add(time.Hour)},
				Sealed: true, Protocol: ipProtocol, To: flow.To,
			}).Verdict
		}
		for _, flow := range fixture.Admitted {
			want := connect.EgressVerdictDeny
			if c.live {
				want = connect.EgressVerdictPass
			}
			if verdict := resolve(flow); verdict != want {
				t.Errorf("%s: protocol %d to %s: verdict %v, want %v", c.name, flow.Protocol, flow.To, verdict, want)
			}
		}
		for _, flow := range fixture.Refused {
			if verdict := resolve(flow); verdict != connect.EgressVerdictDeny {
				t.Errorf("%s: protocol %d to %s, which the grant does not name: verdict %v", c.name, flow.Protocol, flow.To, verdict)
			}
		}
	}
}
