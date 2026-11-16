// What the external tests of the router reach in this package: the bridge's link manager, whose passes they wait on,
// and the client that drops IPv6 under exits.

package device

import (
	"github.com/urnetwork/connect"
)

// The bridge's link manager.
func (self *Bridge) LinksForTest() *BridgeLinkManager {
	return self.links
}

// What Route hands an IPv6 packet under exits.
func (self *Bridge) Ipv6DropForTest() connect.UserNatClient {
	return self.ipv6Drop
}
