//go:build !sidecar_http && !ios_extension

// The CGNAT fixture's carrier path (§17.4, D-BRIDGE-12; TEST-M8-01, closing ledger T4-16: "the CGNAT fixture lacks a
// carrier resolver in the block"). A carrier that numbers its subscribers from 100.64/10 hands a phone an interface
// address, a gateway and a resolver that can all lie inside a network's block. The device carves each /32 its physical
// path needs out of the router's table and every exported route, from the platform's routes and DNS settings
// (§18.6's SetBridgeLocalAddresses); a resolver left uncarved is captured by the block, which black-holes the
// device's DNS. BridgeNetCarrier names such a path, and CarrierErrors reads a sender's router and export against it,
// by DNS's own packets: UDP and TCP to port 53.

package sidecartest

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// The port a resolver answers on.
const bridgeNetDnsPort = 53

// The host part of the overlay resolver's address in a block: <block>.0.53 (§17.4).
const bridgeNetResolverHost = 53

// A device's carrier path: the local addresses its physical path needs.
type BridgeNetCarrier struct {
	// The address the carrier gave the device's interface.
	Interface netip.Addr
	// The carrier's gateway.
	Gateway netip.Addr
	// The carrier's resolver, as the platform's DNS settings name it.
	Resolver netip.Addr
}

// A carrier path inside block, clear of the overlay resolver and of the low addresses the fixture's hosts take: the
// interface at <block>.200.1, the gateway at .200.2 and the resolver at .200.53.
func DefaultBridgeNetCarrier(block netip.Prefix) *BridgeNetCarrier {
	return &BridgeNetCarrier{
		Interface: bridgeNetBlockAddr(block, 200<<8|1),
		Gateway:   bridgeNetBlockAddr(block, 200<<8|2),
		Resolver:  bridgeNetBlockAddr(block, 200<<8|53),
	}
}

// The address host past block's first.
func bridgeNetBlockAddr(block netip.Prefix, host uint32) netip.Addr {
	octets := block.Masked().Addr().As4()
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], binary.BigEndian.Uint32(octets[:])|host)
	return netip.AddrFrom4(out)
}

// The overlay resolver's address in block.
func BridgeNetOverlayResolver(block netip.Prefix) netip.Addr {
	return bridgeNetBlockAddr(block, bridgeNetResolverHost)
}

// What the platform's routes and DNS settings report for the path: every address of it.
func (self *BridgeNetCarrier) LocalAddresses() []netip.Addr {
	return []netip.Addr{self.Interface, self.Gateway, self.Resolver}
}

// Puts the sender on carrier, as its platform reports the path on a change: each address is carved.
func (self *BridgeNetSender) SetCarrier(carrier *BridgeNetCarrier) {
	self.Bridge.SetLocalAddresses(carrier.LocalAddresses())
}

// An IPv4 UDP datagram of payload from source to destination.
func bridgeNetUdp(source netip.AddrPort, destination netip.AddrPort, payload []byte) []byte {
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], source.Port())
	binary.BigEndian.PutUint16(udp[2:4], destination.Port())
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	sourceOctets := source.Addr().As4()
	destinationOctets := destination.Addr().As4()
	pseudo := append(append(append([]byte{}, sourceOctets[:]...), destinationOctets[:]...), 0, 17, byte(len(udp)>>8), byte(len(udp)))
	binary.BigEndian.PutUint16(udp[6:8], bridgeNetChecksum(append(pseudo, udp...)))
	packet := make([]byte, 20+len(udp))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 17
	copy(packet[12:16], sourceOctets[:])
	copy(packet[16:20], destinationOctets[:])
	binary.BigEndian.PutUint16(packet[10:12], bridgeNetChecksum(packet[:20]))
	copy(packet[20:], udp)
	return packet
}

// A DNS query's header for one question, with no question in it: enough for a router, which reads no further than the
// ports.
func bridgeNetDnsQuery() []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], 0x5a17)
	// recursion desired
	query[2] = 0x01
	return query
}

// Whether the sender's router sends DNS to resolver down the default route, over each transport a stub resolver uses:
// a UDP query and a TCP SYN to port 53. Both must, or the answer is what the one that does not says.
func (self *BridgeNetSender) DnsTakesDefaultRoute(resolver netip.Addr) (udp bool, tcp bool) {
	source := netip.AddrPortFrom(self.source, 40053)
	destination := netip.AddrPortFrom(resolver, bridgeNetDnsPort)
	udp = self.Bridge.Route(bridgeNetUdp(source, destination, bridgeNetDnsQuery())) == nil
	tcp = self.Bridge.Route(bridgeNetSyn(source, destination)) == nil
	return udp, tcp
}

// What of §17.4's carve the sender's router and export break on carrier, nil when the carrier path is whole and the
// overlay still resolves:
//
//   - DNS to the carrier's resolver, UDP and TCP, takes the default route, and so does a connection to its interface
//     address and its gateway
//   - no exported route covers an address of the path, so an app that captures the export leaves the path alone
//   - the overlay resolver in block still takes DNS and is still exported, unless the carrier's resolver is that very
//     address, where the physical path wins it
func (self *BridgeNetSender) CarrierErrors(block netip.Prefix, carrier *BridgeNetCarrier) []error {
	errs := []error{}
	routes := self.Bridge.Routes()
	covered := func(addr netip.Addr) (netip.Prefix, bool) {
		for _, route := range routes {
			if route.Contains(addr) {
				return route, true
			}
		}
		return netip.Prefix{}, false
	}
	udp, tcp := self.DnsTakesDefaultRoute(carrier.Resolver)
	if !udp {
		errs = append(errs, fmt.Errorf("a UDP query to the carrier's resolver %s leaves the carrier path: its DNS is black-holed", carrier.Resolver))
	}
	if !tcp {
		errs = append(errs, fmt.Errorf("a TCP query to the carrier's resolver %s leaves the carrier path", carrier.Resolver))
	}
	for _, local := range []struct {
		name string
		addr netip.Addr
	}{{"interface address", carrier.Interface}, {"gateway", carrier.Gateway}} {
		if !self.TakesDefaultRoute(netip.AddrPortFrom(local.addr, 443)) {
			errs = append(errs, fmt.Errorf("the carrier's %s %s leaves the carrier path", local.name, local.addr))
		}
	}
	for _, addr := range carrier.LocalAddresses() {
		if route, found := covered(addr); found {
			errs = append(errs, fmt.Errorf("the exported route %s covers the carrier path's %s", route, addr))
		}
	}
	overlay := BridgeNetOverlayResolver(block)
	if overlay != carrier.Resolver {
		if udp, tcp := self.DnsTakesDefaultRoute(overlay); udp || tcp {
			errs = append(errs, fmt.Errorf("DNS to the overlay resolver %s takes the default route", overlay))
		}
		if route, found := covered(overlay); !found || !route.IsSingleIP() {
			errs = append(errs, fmt.Errorf("the export holds no /32 for the overlay resolver %s: %v", overlay, routes))
		}
	}
	return errs
}
