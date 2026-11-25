// The links §17.7.1's gatherer reads on every platform (owner decision 778): each interface that is up,
// multicast-capable and not point-to-point, never loopback, ur tun's link or another tun, nor Apple's peer-to-peer
// links (AWDL and low-latency WLAN), which mDNSResponder leaves out of its own default browses as point-to-point; and
// this host's own IPv4 addresses, which name an instance its own.

package main

import (
	"net"
	"net/netip"
	"strings"
)

// The name prefixes of the links the gatherer never reads beside what their flags say: ur tun's, other tuns and
// VPNs', and Apple's peer-to-peer links. Identifiers of the platforms' naming, so constants.
var urDiscoveryExcludedLinkPrefixes = []string{"ur-", "tun", "utun", "wg", "tap", "ipsec", "ppp", "awdl", "llw"}

// Whether an interface is one the gatherer reads (the file's comment).
func urMdnsEligible(iface net.Interface) bool {
	flags := iface.Flags
	if flags&net.FlagUp == 0 || flags&net.FlagMulticast == 0 || flags&net.FlagLoopback != 0 || flags&net.FlagPointToPoint != 0 {
		return false
	}
	for _, prefix := range urDiscoveryExcludedLinkPrefixes {
		if strings.HasPrefix(iface.Name, prefix) {
			return false
		}
	}
	return true
}

// This host's own IPv4 addresses, which name an instance its own.
func urMdnsLocalAddresses() []netip.Addr {
	addresses := []netip.Addr{}
	interfaceAddresses, err := net.InterfaceAddrs()
	if err != nil {
		return addresses
	}
	for _, interfaceAddress := range interfaceAddresses {
		if prefix, err := netip.ParsePrefix(interfaceAddress.String()); err == nil && prefix.Addr().Is4() {
			addresses = append(addresses, prefix.Addr())
		}
	}
	return addresses
}
