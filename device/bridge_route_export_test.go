// What the external tests of the router reach in this package: the bridge's link manager, whose passes they wait on.

package device

// The bridge's link manager.
func (self *Bridge) LinksForTest() *BridgeLinkManager {
	return self.links
}
