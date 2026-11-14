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

// D-TEST-6 and the rules clause (DESIGN-DETAILS 16.2.13's first row of what is left): with the gate switched off, a
// push that creates a shared ref at a pin below the repo's newest rule set passes 5d, and step 5 whole, and switched
// back on it is refused again.
func TestCheckGateSwitchedOffPassesAStalePinCreation(t *testing.T) {
	fixture, pins := newCheckRulesFixture(t)
	view := fixture.rulesView(pins[2], nil)
	requireCheckRefusal(t, "the gate on", CheckGate(view), EvsCheckReasonPinBelowRules)
	SwitchGateOffForTest(true)
	t.Cleanup(func() { SwitchGateOffForTest(false) })
	requireCheckPass(t, "the gate off", CheckGate(view))
	requireCheckPass(t, "step 5 with the gate off", CheckPush(view))
	SwitchGateOffForTest(false)
	requireCheckRefusal(t, "the gate on again", CheckGate(view), EvsCheckReasonPinBelowRules)
}
