//go:build !ios_extension

// What §17.6's route rows let reach a shared device through this host, for §17.7.1's listing of it (owner decision
// 778): a /32 share's route carries every port and protocol, as a device's tunnel on ports it picks per connection
// needs, unless an admin narrows the route's ports, which ur bridge devices then names on the device's line. Reads one
// atomic load of what the bridge publishes, takes no lock and changes nothing. Safe for concurrent use. Off the iOS
// extension's leg, which runs no ur daemon.

package device

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// What any subject's route rows reach of address through this host now (BridgeEgressPolicy.DiscoveryRoutePorts).
func (self *Bridge) DiscoveryRoutePorts(address netip.Addr) (all bool, ports []string) {
	return self.policy.DiscoveryRoutePorts(address)
}

// Whether a subject reaches every port and protocol of address through this host: true with no document, where an
// untagged subject reaches anything (rule 4), or where an admitted subject's live route row covering address names no
// protocol, or one protocol with no ports, for each of TCP and UDP; else false, with each covering row's protocol and
// ports, "tcp:62078", "udp:5353-5354" or "icmp", sorted, once each. False and none on every profile but a sidecar-owned
// host's, and before a state.
func (self *BridgeEgressPolicy) DiscoveryRoutePorts(address netip.Addr) (bool, []string) {
	if self.profile != BridgePolicyProfileHost {
		return false, nil
	}
	state := self.state.Load()
	address = address.Unmap()
	if state == nil || !address.IsValid() {
		return false, nil
	}
	if state.posture == PostureEnforcingNoDocument {
		return true, nil
	}
	now := self.clock.Now()
	held := map[string]bool{}
	wholeTcp, wholeUdp := false, false
	for _, subject := range state.subjectBySidecarId {
		if !subject.admitted {
			continue
		}
		for i := range subject.route {
			row := &subject.route[i]
			if !row.prefix.Contains(address) || row.revoked || (!row.expires.IsZero() && !now.Before(row.expires)) {
				continue
			}
			switch {
			case row.protocol == 0:
				return true, nil
			case len(row.ports) == 0:
				wholeTcp = wholeTcp || row.protocol == bridgeProtocolTcp
				wholeUdp = wholeUdp || row.protocol == bridgeProtocolUdp
				held[bridgeDiscoveryProtocolName(row.protocol)] = true
			default:
				for _, portRange := range row.ports {
					text := fmt.Sprintf("%s:%d", bridgeDiscoveryProtocolName(row.protocol), portRange.first)
					if portRange.last != portRange.first {
						text = fmt.Sprintf("%s-%d", text, portRange.last)
					}
					held[text] = true
				}
			}
		}
	}
	if wholeTcp && wholeUdp {
		return true, nil
	}
	ports := []string{}
	for text := range held {
		// a protocol reached whole needs no port of it named
		if (wholeTcp && strings.HasPrefix(text, "tcp:")) || (wholeUdp && strings.HasPrefix(text, "udp:")) {
			continue
		}
		ports = append(ports, text)
	}
	slices.Sort(ports)
	return false, ports
}

// A row's protocol as the listing names it.
func bridgeDiscoveryProtocolName(protocolNumber uint32) string {
	switch protocolNumber {
	case bridgeProtocolTcp:
		return "tcp"
	case bridgeProtocolUdp:
		return "udp"
	case bridgeProtocolIcmp:
		return "icmp"
	}
	return fmt.Sprintf("protocol %d", protocolNumber)
}
