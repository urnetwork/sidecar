// FS-29 (§22.8; §16.6; D-MCP-12, AD3, FI-3, FI-7; MCP-M3-24) on T2: an approval decided under pin P; the pin moves to
// P', which drops its approver, the member no longer eligible and its phone no longer approval-capable: the approval
// authorizes nothing under P', no Reserve and no effect. Its twin moves the pin keeping the approver, and the use
// spends under P'. FI-7 checks after every step; FI-3, commit-point authorization, is TEST-M2-05's oracle, unbound, so
// the judge states this row's part of it: a use spends only where the pin now admits its approver.

package fault

import (
	"context"
	"errors"
	"fmt"
)

var Fs29 = Register("FS-29", "", []Tier{TierT2}, Twin(Fs29PinDropsApprover, Fs29PinKeepsApprover))

// See the file header.
func Fs29PinDropsApprover(net *Net) *Schedule {
	schedule := fs29(true)
	schedule.Refuses = "a decision whose approver the pin it is spent under no longer admits"
	return schedule
}

// See the file header.
func Fs29PinKeepsApprover(net *Net) *Schedule {
	return fs29(false)
}

// The approval of an exact action under P, the pin moved, then the action presented.
func fs29(drop bool) *Schedule {
	state := &fs25State{}
	return &Schedule{
		Steps: []*Step{
			state.setup(1),
			{Actor: "authority", Action: func(ctx context.Context, net *Net) error {
				state.world.MovePin(drop)
				return nil
			}},
			{Actor: "callerA", Action: state.call("callerA", 0)},
			{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
				if !drop {
					return errors.Join(state.done("callerA"), state.effects(1))
				}
				answer, err := state.answer("callerA")
				if err != nil {
					return err
				}
				if answer.err == nil {
					return fmt.Errorf("the approval spent under a pin that dropped its approver: %+v", answer.action.Outcome)
				}
				ledger, err := state.world.LedgerState(state.approvalId)
				if err != nil {
					return err
				}
				if len(ledger.Reserves) != 0 {
					return fmt.Errorf("%d Reserves under a pin that dropped the approver", len(ledger.Reserves))
				}
				return state.effects(0)
			}},
			state.reconcile(),
		},
		Check: fs25Checks(),
		Tiers: []Tier{TierT2},
	}
}
