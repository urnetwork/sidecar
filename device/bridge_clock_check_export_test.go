// What the external tests of the clock's seam reach in this package: the link manager's own check, which
// Bridge.CheckClock calls beside run's, and the time a link's build counts its age from.

package device

import (
	"time"
)

// Has the manager's run take a pass at the clock's now and arm its timer again, as Bridge.CheckClock does.
func (self *BridgeLinkManager) CheckClockForTest() {
	self.checkClock()
}

// When link's build in force was built, and false while it has none.
func (self *BridgeLinkManager) LinkBuiltAtForTest(link BridgeLinkId) (time.Time, bool) {
	held := (*self.links.Load())[link]
	if held == nil {
		return time.Time{}, false
	}
	built := held.built.Load()
	if built == nil {
		return time.Time{}, false
	}
	return built.builtAt, true
}
