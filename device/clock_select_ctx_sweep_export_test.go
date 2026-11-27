// What the sweep's external cases (clock_select_ctx_sweep_test.go) reach of the link manager: the channel its run
// closes as it returns, so a case knows the pass it judges has run, or has not, before Close sets the manager closed.
// Tests only.

package device

// Closed once the manager's run has returned.
func (self *BridgeLinkManager) RunDoneForTest() <-chan struct{} {
	return self.done
}
