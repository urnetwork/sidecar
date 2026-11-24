// What §17.7.1's discovery asks of the device role (owner decision 778), which the root cannot import (D-SDK-20), so the
// composition root installs these into its discovery component as seams:
//
//	answer   a host answers each viewer's watch with the instances whose address, protocol and port its own hook
//	         would pass with that viewer as the source: DiscoveryReach is the hook's own code, §17.6's rules in order
//	         over the published state, for a synthetic flow from the viewer's verified principal over a sealed data
//	         contract in Network mode, so a viewer sees only what it may reach and discovery opens nothing
//	checks   a viewer keeps an instance only at an address its own router sends to the instance's host: RouteTargets
//	         names the advertisers of the table's entry for an address, a LAN prefix of the device's own having won its
//	         conflict already (§17.7's sender conflicts), and none for an address no link entry holds
//
// Both read one atomic load of what the bridge publishes, take no lock and change nothing: no reach event is reported
// and no flow registered, so an evaluation is never a flow. Safe for concurrent use.

package device

import (
	"net/netip"
	"slices"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// Whether the host's hook would pass, or map, a flow of protocol (TCP or UDP) from viewer, a sidecar of this network,
// to address: what §17.7.1's answer row reads for each instance (BridgeEgressPolicy.DiscoveryReach).
func (self *Bridge) DiscoveryReach(viewer connect.Id, address netip.AddrPort, ipProtocol connect.IpProtocol) bool {
	return self.policy.DiscoveryReach(viewer, address, ipProtocol)
}

// Whether ResolveEgress would pass, or map, a flow of protocol (TCP or UDP) from viewer's verified principal over a
// sealed data contract in Network mode to address, at now. False on every profile but a sidecar-owned host's, before a
// state, for a viewer the state does not admit, and for any other protocol. Reports no reach event.
func (self *BridgeEgressPolicy) DiscoveryReach(viewer connect.Id, address netip.AddrPort, ipProtocol connect.IpProtocol) bool {
	if self.profile != BridgePolicyProfileHost || (ipProtocol != connect.IpProtocolTcp && ipProtocol != connect.IpProtocolUdp) {
		return false
	}
	state := self.state.Load()
	if state == nil || state.networkId == (connect.Id{}) || !address.IsValid() || !address.Addr().Unmap().Is4() {
		return false
	}
	now := self.clock.Now()
	flow := &connect.EgressFlow{
		ProvideMode:   protocol.ProvideMode_Network,
		ContractClass: connect.ContractClassData,
		Principal: &connect.BridgePrincipal{
			Subject: viewer,
			Network: state.networkId,
			// a synthetic principal's lapse, past now so the evaluation reads the rows alone
			NotAfter: now.Add(self.settings.PinIdleTimeout),
		},
		Sealed:   true,
		Protocol: ipProtocol,
		To:       netip.AddrPortFrom(address.Addr().Unmap(), address.Port()),
	}
	decision := state.resolve(self.profile, self.settings, flow, nil, now, nil)
	return decision.Verdict == connect.EgressVerdictPass || decision.Verdict == connect.EgressVerdictMap
}

// The sidecars this device's router sends address to now: the advertisers of the table's entry that holds it, revoked
// and share links left out; none where no link entry holds it, a carve, a service, an unassigned range, a held reject
// or the default route. What §17.7.1's checks row reads.
func (self *Bridge) RouteTargets(address netip.Addr) []connect.Id {
	state := self.routeState.Load()
	address = address.Unmap()
	if state == nil || !address.Is4() {
		return nil
	}
	entry := state.table.Lookup(bridgeIpv4Value(address))
	if entry == nil || entry.RuleIndex < 0 || len(state.entries) <= entry.RuleIndex {
		return nil
	}
	routeEntry := state.entries[entry.RuleIndex]
	if routeEntry.state == nil {
		return nil
	}
	return slices.Clone(routeEntry.targets)
}
