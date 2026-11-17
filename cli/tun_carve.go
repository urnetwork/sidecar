// The carve as each platform passes it back to the host's own route under exits (§17.4, §17.11; owner decision 480:
// QD-808, QD-869, QD-971). ur tun hands the platform the addresses its local read last gave the bridge, this host's
// interface, gateway and resolver addresses of both families (tun_device.go's urTunCarvedInterface), and each
// platform takes them family by family: Linux by throw routes in its exits table (tun_linux.go), macOS and Windows by
// host routes by each family's default route (tun_host_routes.go). An IPv6 address is passed back only where a route
// could take it off the host at all: a link-local one stays on its link, as IPv6's gateways do, and the host's own
// link routes keep it.

package main

import (
	"net/netip"
	"slices"
)

// The addresses of one family of addresses, IPv4's where ipv4 and IPv6's otherwise, as the platforms follow the carve:
// unmapped, an IPv4-mapped address counting as IPv4, with no zone, sorted, with no repeats.
func urTunCarvedAddrs(addresses []netip.Addr, ipv4 bool) []netip.Addr {
	carvedAddrs := []netip.Addr{}
	for _, address := range addresses {
		address = address.Unmap().WithZone("")
		if address.IsValid() && address.Is4() == ipv4 && !slices.Contains(carvedAddrs, address) {
			carvedAddrs = append(carvedAddrs, address)
		}
	}
	slices.SortFunc(carvedAddrs, netip.Addr.Compare)
	return carvedAddrs
}

// Whether address, of the carve's IPv6 addresses, is one a route may take off the host, so that a throw or a host
// route by the IPv6 default route can pass it back to the host's own (QD-971): not an unspecified, loopback or
// multicast address, nor a link-local one, which never leaves its link.
func urTunCarvedIpv6Leaves(address netip.Addr) bool {
	return address.Is6() && !address.Is4In6() && !address.IsUnspecified() && !address.IsLoopback() &&
		!address.IsMulticast() && !address.IsLinkLocalUnicast()
}
