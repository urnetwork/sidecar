// What §17.7.1's discovery reads of the state in force (owner decision 778), beside bridge_discovery_reach.go's seams:
//
//	host     this host's overlay addresses, the subnets it serves with each remap's exposed prefix, and its maps, which
//	         decide the address a shared LAN device is published at: a served prefix's, its exposed prefix's with the host
//	         bits kept, else a map's at the host's own address and the map's port (§17.7.1's shared row)
//	viewer   the hosts this device's links reach, each with the prefixes it advertises here and its private name, which
//	         a viewer watches, its own member's hosts first (§17.7.1's viewer row)
//
// Read from the rules the bridge adopted, under its stateLock, as a copy the caller owns: none outside enforcing.
// Revoked and share links are left out, since a share's source watches nothing (17.9). Safe for concurrent use.

package device

import (
	"bytes"
	"net/netip"
	"slices"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A subnet this host serves.
type BridgeDiscoveryServed struct {
	Prefix netip.Prefix
	// Where senders reach it, host bits kept; invalid for none.
	Exposed netip.Prefix
}

// A map this host holds, TCP or UDP: Address's ports FirstPort to LastPort reach Target from TargetPort on, by offset,
// or at the same ports where TargetPort is 0.
type BridgeDiscoveryMap struct {
	Address    netip.Addr
	Protocol   connect.IpProtocol
	FirstPort  uint16
	LastPort   uint16
	Target     netip.Addr
	TargetPort uint16
}

// A host this device's links reach, and what it advertises here.
type BridgeDiscoveryHostRoute struct {
	SidecarId connect.Id
	ClientId  connect.Id
	// zero for a tagged host
	MemberId connect.Id
	Prefixes []netip.Prefix
	// the private name of one of its overlay addresses, empty for none
	Name string
}

// What discovery reads of the state in force.
type BridgeDiscoveryRoutes struct {
	// the state's block and the one draining
	Blocks    []netip.Prefix
	Addresses []netip.Addr
	Served    []BridgeDiscoveryServed
	Maps      []BridgeDiscoveryMap
	Hosts     []BridgeDiscoveryHostRoute
}

// What discovery reads of the state in force, nil outside enforcing or before rules.
func (self *Bridge) DiscoveryRoutes() *BridgeDiscoveryRoutes {
	decision, rules := func() (PostureDecision, *bridge.BridgeRules) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.decision, self.rules
	}()
	if !decision.State.Enforcing() || rules == nil || decision.BridgeState == nil {
		return nil
	}
	overlay := newBridgePolicyOverlay(decision.Overlay)
	return bridgeDiscoveryRoutesOf(rules, decision.BridgeState.GetNames(), overlay)
}

// The routes rules give, names naming the overlay addresses and overlay narrowing them.
func bridgeDiscoveryRoutesOf(rules *bridge.BridgeRules, names map[string]uint32, overlay *bridgePolicyOverlay) *BridgeDiscoveryRoutes {
	routes := &BridgeDiscoveryRoutes{}
	for _, prefix := range []*bridge.BridgeIpv4Prefix{rules.GetBlock(), rules.GetPreviousBlock()} {
		if block, ok := bridgeRulePrefix(prefix); ok {
			routes.Blocks = append(routes.Blocks, block)
		}
	}
	for _, address := range rules.GetAddresses() {
		routes.Addresses = append(routes.Addresses, bridgeRuleAddr(address))
	}
	for _, served := range rules.GetServed() {
		if served.GetKind() != bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET || served.GetDrainingSince() != 0 {
			continue
		}
		prefix, ok := bridgeRulePrefix(served.GetPrefix())
		if !ok {
			continue
		}
		routeServed := BridgeDiscoveryServed{Prefix: prefix}
		if exposed, ok := bridgeRulePrefix(served.GetExposedPrefix()); ok {
			routeServed.Exposed = exposed
		}
		routes.Served = append(routes.Served, routeServed)
	}
	for _, ruleMap := range rules.GetMaps() {
		if ruleMap.GetDrainingSince() != 0 {
			continue
		}
		var ipProtocol connect.IpProtocol
		switch ruleMap.GetProtocol() {
		case bridgeProtocolTcp:
			ipProtocol = connect.IpProtocolTcp
		case bridgeProtocolUdp:
			ipProtocol = connect.IpProtocolUdp
		default:
			continue
		}
		match, ok := bridgeRulePrefix(ruleMap.GetMatchPrefix())
		target, targetOk := netip.AddrFromSlice(ruleMap.GetTarget())
		if !ok || !match.IsSingleIP() || !targetOk {
			continue
		}
		ranges := ruleMap.GetPorts()
		if len(ranges) == 0 {
			ranges = []*bridge.BridgePortRange{{First: 1, Last: 0xFFFF}}
		}
		for _, ports := range ranges {
			routes.Maps = append(routes.Maps, BridgeDiscoveryMap{
				Address:    match.Addr(),
				Protocol:   ipProtocol,
				FirstPort:  uint16(ports.GetFirst()),
				LastPort:   uint16(ports.GetLast()),
				Target:     target.Unmap(),
				TargetPort: uint16(ruleMap.GetTargetPort()),
			})
		}
	}
	addressNames := map[netip.Addr]string{}
	nameKeys := make([]string, 0, len(names))
	for name := range names {
		nameKeys = append(nameKeys, name)
	}
	slices.Sort(nameKeys)
	for _, name := range nameKeys {
		address := bridgeRuleAddr(names[name])
		if _, held := addressNames[address]; !held {
			addressNames[address] = name
		}
	}
	for _, entry := range rules.GetEntries() {
		if entry.GetKind() != bridge.BridgeRuleEntryKind_BRIDGE_RULE_ENTRY_KIND_LINK {
			continue
		}
		prefix, ok := bridgeRulePrefix(entry.GetPrefix())
		if !ok {
			continue
		}
		for _, link := range entry.GetLinks() {
			if len(link.GetShareId()) != 0 || link.GetDrainingSince() != 0 || len(link.GetTargetSidecarId()) != 16 ||
				len(link.GetTargetClientId()) != 16 ||
				(overlay != nil && overlay.narrows(link.GetTargetSidecarId(), link.GetTargetMemberId())) {
				continue
			}
			sidecarId := connect.Id(link.GetTargetSidecarId())
			index := slices.IndexFunc(routes.Hosts, func(host BridgeDiscoveryHostRoute) bool {
				return host.SidecarId == sidecarId
			})
			if index < 0 {
				host := BridgeDiscoveryHostRoute{SidecarId: sidecarId, ClientId: connect.Id(link.GetTargetClientId())}
				if len(link.GetTargetMemberId()) == 16 {
					host.MemberId = connect.Id(link.GetTargetMemberId())
				}
				routes.Hosts = append(routes.Hosts, host)
				index = len(routes.Hosts) - 1
			}
			host := &routes.Hosts[index]
			if !slices.Contains(host.Prefixes, prefix) {
				host.Prefixes = append(host.Prefixes, prefix)
			}
			if name, named := addressNames[prefix.Addr()]; named && prefix.IsSingleIP() && host.Name == "" {
				host.Name = name
			}
		}
	}
	slices.SortFunc(routes.Hosts, func(a BridgeDiscoveryHostRoute, b BridgeDiscoveryHostRoute) int {
		return bytes.Compare(a.SidecarId[:], b.SidecarId[:])
	})
	return routes
}
