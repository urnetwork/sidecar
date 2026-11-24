package device

import (
	"net/netip"
)

// withBlocks, for the external tests of the reverse zone.
func (self *BridgeZone) WithBlocksForTest(blocks []netip.Prefix) *BridgeZone {
	return self.withBlocks(blocks)
}

// The view a resolver built outside a bridge answers DNS-SD names from.
func (self *BridgeResolverClient) SetDiscoveryForTest(discovery func() *BridgeDiscoveryView) {
	self.discovery = discovery
}
