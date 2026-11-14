// What the external tests of links reach in this package: a link's route as Route takes it, a seal as a window
// client's event would mark it, and a signal after each pass of the manager's run and each build's end.

package device

import (
	"github.com/urnetwork/connect"
)

// What carries a packet to link now, and the route's name: "client", "wait" or "reject".
func (self *BridgeLinkManager) RouteForTest(link BridgeLinkId) (connect.UserNatClient, string) {
	client, route := self.route(link, self.clock.Now())
	return client, [...]string{"client", "wait", "reject"}[route]
}

// Marks the link's build sealed, as a sealed session's event marks it; false when the link has no build.
func (self *BridgeLinkManager) SealForTest(link BridgeLinkId) bool {
	held := (*self.links.Load())[link]
	if held == nil {
		return false
	}
	built := held.built.Load()
	if built == nil {
		return false
	}
	built.sealed.Store(true)
	return true
}

// A channel that receives after each pass of run and each build's end, never blocking the manager: a test waits on
// it, then reads what it waits for, and waits again if that has not happened yet.
func (self *BridgeLinkManager) WatchForTest() <-chan struct{} {
	passes := make(chan struct{}, 1)
	passed := func() {
		select {
		case passes <- struct{}{}:
		default:
		}
	}
	self.passedForTest.Store(&passed)
	return passes
}

// A contract's destination check as the link's window clients run it (connect.ContractDestinationCheckFunction), and
// false for a link with no build.
func (self *BridgeLinkManager) DestinationAllowedForTest(link BridgeLinkId, destinationId connect.Id, destinationClientPublicKey []byte) (allowed bool, built bool) {
	held := (*self.links.Load())[link]
	if held == nil {
		return false, false
	}
	linkBuilt := held.built.Load()
	if linkBuilt == nil {
		return false, false
	}
	return linkBuilt.destinationAllowed(destinationId, destinationClientPublicKey), true
}

// The links open and building now.
func (self *BridgeLinkManager) CountsForTest() (openCount int, buildingCount int) {
	return self.counts()
}

// Whether the link has a client now, read without routing to it.
func (self *BridgeLinkManager) LinkBuiltForTest(link BridgeLinkId) bool {
	held := (*self.links.Load())[link]
	return held != nil && held.built.Load() != nil
}
