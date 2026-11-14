// FI-7, effects (§22.8; §16.6; D-MCP-11, AU1-AU4, TS1; MCP-M3-24): read after every step from every requesting
// daemon's approval world the Net holds (sidecartest.ApprovalWorld.CheckEffects), around every fault: an approval use
// is reserved before its effect, each effect under a key some Reserve holds, never more Reserves than the decision's
// uses nor more effects than Reserves; a Reserve once seen stays, so a use stays consumed or explicitly uncertain after
// any crash; at most one effect per key; the run's taint never clears and every decision names this requester; and at
// the end every Reserve has its Outcome. A schedule with no approval world reads nothing here.

package fault

import (
	"context"
	"fmt"
)

var _ = RegisterInvariant(7, func(ctx context.Context, oracle *Oracle) error {
	for _, world := range oracle.Net.ApprovalWorlds() {
		if err := world.CheckEffects(oracle.Final); err != nil {
			return fmt.Errorf("%s: %w", world.Name(), err)
		}
	}
	return nil
})
