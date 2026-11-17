//go:build darwin || windows

// The carved addresses' host routes under exits on macOS and Windows (§17.4, §17.11; owner decision 480: QD-869,
// QD-971), the part the two platforms share (tun_darwin.go, tun_windows.go). There the exits ride IPv4's two halves and
// IPv6's in the host's main table, so an address the bridge carves, this host's interface addresses, gateways and
// resolvers, that the host reaches only by its default route of that family matches a half and enters the tun, where
// the bridge sends an IPv4 one to today's route, which a tun can only drop, and rejects an IPv6 one (QD-970): an
// off-link resolver above all. Each such address takes a host route by its family's default route's gateway and
// interface, as wg-quick on macOS and WireGuard for Windows route an endpoint's /32, so the host's own traffic to it
// leaves outside the exits, as Linux's throw routes have it (QD-808).
//
//	which    the addresses of the carve SetCarved last gave, of either family, that no route of the host's own but
//	         its default route of that family holds. One an on-link or local route reaches takes none, since a host
//	         route by the gateway would move it off its own link; nor does one inside a route of the tun's own, which
//	         stays the bridge's to judge, as on Linux, where the throws sit in the exits table alone; nor the gateway
//	         itself, a loopback or a multicast address, nor a link-local IPv6 one, which never leaves its link, as
//	         IPv6's gateways do not. A family with no default route of its own takes none. Nothing is added by the
//	         platform's addresses (QD-800): only the bridge's carve names one
//	when     while a half of the address's family is on: before the halves go on, at each SetCarved, and at each
//	         sync's SetExits, which reads the default routes again, so a route that moved takes them with it, the old
//	         ones off and new ones on by the gateway it has now. A family's come off once no half of that family is
//	         left, and all of them at close
//	whose    only a route this interface put on is ever removed. One whose address another route already holds is
//	         left to that route. A host route leaves by an interface that outlives the tun, so one a daemon that
//	         died left behind stays until the host restarts or a person removes it, and reads here as another
//	         program's route
//
// No address reaches an error or a log (I-13).

package main

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

// The host route of one carved address: the next hop it goes by, the host's own default route's of the address's
// family, not valid where that route names none, and the interface it leaves by, its index on macOS and its luid on
// Windows.
type urTunHostRoute struct {
	address netip.Addr
	gateway netip.Addr
	link    uint64
}

// What the platform does for a host route.
type urTunHostRouteCalls struct {
	// Puts one on, and takes off one this interface put on.
	add    func(hostRoute urTunHostRoute) error
	remove func(hostRoute urTunHostRoute) error
	// Whether add's error says a route already holds the address, and remove's that none is there.
	held func(err error) bool
	gone func(err error) bool
}

// The host routes the carved addresses of one family take, IPv4's where ipv4 and IPv6's otherwise (QD-971): one for
// each address of carvedAddrs of that family that reached does not hold, by gateway through link, the host's own
// default route's of that family. reached answers whether a route of the host's own other than its default routes
// holds an address. None for an address inside ownRoutes, the tun's own, for gateway itself, for an unspecified,
// loopback or multicast address, or for an IPv6 one no route takes off the host (urTunCarvedIpv6Leaves).
func urTunHostRoutes(carvedAddrs []netip.Addr, ipv4 bool, gateway netip.Addr, link uint64, ownRoutes []netip.Prefix,
	reached func(address netip.Addr) bool) []urTunHostRoute {
	hostRoutes := []urTunHostRoute{}
	for _, address := range carvedAddrs {
		if address.Is4() != ipv4 || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() ||
			address == gateway || (!ipv4 && !urTunCarvedIpv6Leaves(address)) {
			continue
		}
		if slices.ContainsFunc(ownRoutes, func(prefix netip.Prefix) bool { return prefix.Contains(address) }) {
			continue
		}
		if slices.ContainsFunc(hostRoutes, func(hostRoute urTunHostRoute) bool { return hostRoute.address == address }) ||
			reached(address) {
			continue
		}
		hostRoutes = append(hostRoutes, urTunHostRoute{address: address, gateway: gateway, link: link})
	}
	return hostRoutes
}

// Takes off each of onRoutes, the host routes this interface put on, that wanted does not hold as it is, the address
// or the gateway and interface it goes by, then puts on each of wanted that is not on, and answers what is on after.
// One already gone is taken as off. One whose address another route has come to hold is left to that route, and is
// not this interface's to remove; one whose old route would not come off waits for it. What would not go on or come
// off is counted in the error, and kept as it is for the next call.
func urTunSetHostRoutes(onRoutes []urTunHostRoute, wanted []urTunHostRoute, calls *urTunHostRouteCalls) ([]urTunHostRoute, error) {
	removeCount := 0
	var removeErr error
	kept := []urTunHostRoute{}
	for _, on := range onRoutes {
		if slices.Contains(wanted, on) {
			kept = append(kept, on)
			continue
		}
		if err := calls.remove(on); err != nil && !calls.gone(err) {
			if removeCount == 0 {
				removeErr = err
			}
			removeCount += 1
			kept = append(kept, on)
		}
	}
	addCount := 0
	var addErr error
	for _, hostRoute := range wanted {
		if slices.ContainsFunc(kept, func(on urTunHostRoute) bool { return on.address == hostRoute.address }) {
			continue
		}
		err := calls.add(hostRoute)
		switch {
		case err == nil:
			kept = append(kept, hostRoute)
		case calls.held(err):
			// another's route came to hold the address since the table was read
		default:
			if addCount == 0 {
				addErr = err
			}
			addCount += 1
		}
	}
	var setErr error
	if 0 < removeCount {
		setErr = errors.Join(setErr, fmt.Errorf("%d host routes of addresses no longer carved did not come off (%v)",
			removeCount, removeErr))
	}
	if 0 < addCount {
		setErr = errors.Join(setErr, fmt.Errorf("%d host routes of carved addresses did not go on, so the tun drops "+
			"what the host sends them (%v)", addCount, addErr))
	}
	return kept, setErr
}

// Those of hostRoutes in the families that stand, IPv4's where ipv4 and IPv6's where ipv6, in their order: what a
// clear keeps of a family whose halves have not all come off, since a lookup of its addresses still needs them.
func urTunStandingHostRoutes(hostRoutes []urTunHostRoute, ipv4 bool, ipv6 bool) []urTunHostRoute {
	standing := []urTunHostRoute{}
	for _, hostRoute := range hostRoutes {
		if (hostRoute.address.Is4() && ipv4) || (!hostRoute.address.Is4() && ipv6) {
			standing = append(standing, hostRoute)
		}
	}
	return standing
}

// The carve as the host routes follow it, both families: IPv4's addresses, then IPv6's (urTunCarvedAddrs).
func urTunCarvedHostAddrs(addresses []netip.Addr) []netip.Addr {
	return append(urTunCarvedAddrs(addresses, true), urTunCarvedAddrs(addresses, false)...)
}
