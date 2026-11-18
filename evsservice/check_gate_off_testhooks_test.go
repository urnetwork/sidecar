//go:build sidecar_testhooks

package evsservice

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// D-TEST-6: with the gate switched off, as the revocation suite runs, 5d passes a push it would refuse, and switched
// back on it refuses again.
func TestCheckGateSwitchedOffForTheRevocationSuite(t *testing.T) {
	fixture := newCheckFixture(t)
	plan := fixture.plan()
	plan.Changes = nil
	plan.Changes = append(plan.Changes, fixture.change(plan, checkTestPath("a"), 0, 1))
	view := fixture.view(plan)
	view.Generation = &protocol.GenRotate{}
	requireCheckRefusal(t, "the gate on", CheckGate(view), EvsCheckReasonPinForked)
	SwitchGateOffForTest(true)
	t.Cleanup(func() { SwitchGateOffForTest(false) })
	requireCheckPass(t, "the gate off", CheckGate(view))
	SwitchGateOffForTest(false)
	requireCheckRefusal(t, "the gate on again", CheckGate(view), EvsCheckReasonPinForked)
}
