// The route export (§17.4, D-BRIDGE-12, §18.6's Routes): what a tun owner routes into the bridge. Apps capture 0/0 and
// leave out RFC 1918 (§17.3), and Apple's overlap semantics are undocumented, so the export names what the bridge
// serves rather than trusting a default route to reach it:
//
//	block     a block chosen in RFC 1918 (owner decision 132), which an app's capture leaves out otherwise, once this
//	          device's local /32s are known; a 100.64/10 block is captured already and is not exported whole
//	hosted    every host's overlay /32 and remapped range in a block not exported whole, and per-peer /32s in place of
//	          any block while the local /32s are unknown
//	granted   each subnet route the rules give this device, but one overlapping a local network, which yields to the
//	          LAN (§17.7)
//	resolver  each block's <block>.0.53, which `ur tun`'s resolver answers (§12.9)
//	carve     every local /32 the physical path needs is left out of all of these, splitting what holds it, so the block
//	          is never dropped wholesale and a captured carrier resolver never black-holes DNS
//
// Aliases join at M6 with shares.

package device

import (
	"cmp"
	"net/netip"
	"slices"
)

// RFC 1918's ranges, where a block exports whole.
var bridgeRfc1918Prefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// §18.6's deviceBridge.Routes: the export, by the file's rows, from the state in force and SetLocalAddresses; nil before
// a state names a block or a route. The caller owns what it returns.
func (self *Bridge) Routes() []netip.Prefix {
	state := self.routeState.Load()
	if state == nil {
		return nil
	}
	return slices.Clone(state.routes)
}

// §18.6's SetBridgeLocalAddresses: the local addresses this device's physical path needs, its interfaces', gateways'
// and system resolvers', from the platform's routes and DNS settings, on each path change, since
// connect.LocalIpv4Networks sees only interface subnets (§17.4). Nil while they are unknown, which exports per-peer
// /32s in place of a block; empty for known and none. Each IPv4 one is carved: it takes the default route, whatever
// entry covers it, and the export leaves it out. The provider hook's rule 0 reads all of them as this device's own,
// refusing a daemon listener's port on each (D-BRIDGE-19). Publishes, then calls the change callbacks.
func (self *Bridge) SetLocalAddresses(addresses []netip.Addr) {
	self.apply(func() (PostureDecision, bool, error) {
		if addresses == nil {
			self.localAddrs = nil
		} else {
			self.localAddrs = make([]netip.Addr, 0, len(addresses))
			for _, addr := range addresses {
				if addr.IsValid() {
					self.localAddrs = append(self.localAddrs, addr.Unmap())
				}
			}
		}
		return self.posture.Decision(), true, nil
	})
}

// The export, by the file's rows, from the blocks, the link entries the table keeps and the local addresses, nil while
// unknown. Sorted, and with no prefix another covers.
func bridgeExportRoutes(blocks []netip.Prefix, linkPrefixes []netip.Prefix, localAddrs []netip.Addr) []netip.Prefix {
	known := localAddrs != nil
	carves := []netip.Addr{}
	for _, addr := range localAddrs {
		if addr = addr.Unmap(); addr.Is4() {
			carves = append(carves, addr)
		}
	}
	wholeBlocks := []netip.Prefix{}
	exported := []netip.Prefix{}
	for _, block := range blocks {
		if known && slices.ContainsFunc(bridgeRfc1918Prefixes, func(rfc1918 netip.Prefix) bool {
			return bridgePrefixCovers(rfc1918, block)
		}) {
			wholeBlocks = append(wholeBlocks, block)
			exported = append(exported, block)
		}
		resolver := bridgeIpv4Value(block.Addr()) | bridgeResolverHost
		exported = append(exported, netip.PrefixFrom(bridgeRuleAddr(resolver), 32))
	}
	for _, prefix := range linkPrefixes {
		if slices.ContainsFunc(wholeBlocks, func(block netip.Prefix) bool { return bridgePrefixCovers(block, prefix) }) {
			continue
		}
		exported = append(exported, prefix)
	}
	routes := []netip.Prefix{}
	for _, prefix := range exported {
		routes = append(routes, bridgePrefixMinus(prefix, carves)...)
	}
	slices.SortFunc(routes, func(a netip.Prefix, b netip.Prefix) int {
		if order := a.Addr().Compare(b.Addr()); order != 0 {
			return order
		}
		return cmp.Compare(a.Bits(), b.Bits())
	})
	routes = slices.Compact(routes)
	// a prefix inside another adds nothing; sorted by address, then broader first, so a covering one comes first
	covered := []netip.Prefix{}
	for _, prefix := range routes {
		if 0 < len(covered) && bridgePrefixCovers(covered[len(covered)-1], prefix) {
			continue
		}
		covered = append(covered, prefix)
	}
	return covered
}

// prefix without the /32s of holes: the fewest prefixes covering the rest, by halving each that holds a hole.
func bridgePrefixMinus(prefix netip.Prefix, holes []netip.Addr) []netip.Prefix {
	if !slices.ContainsFunc(holes, prefix.Contains) {
		return []netip.Prefix{prefix}
	}
	if prefix.Bits() == 32 {
		return nil
	}
	lower := netip.PrefixFrom(prefix.Addr(), prefix.Bits()+1)
	upperValue := bridgeIpv4Value(prefix.Addr()) | uint32(1)<<(31-prefix.Bits())
	upper := netip.PrefixFrom(bridgeRuleAddr(upperValue), prefix.Bits()+1)
	return append(bridgePrefixMinus(lower, holes), bridgePrefixMinus(upper, holes)...)
}
