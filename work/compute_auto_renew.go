// compute_auto_renew's work (DESIGN-COMPUTE §14.5, §9.8; BAL-M12-11): taskworker's job, every minute at the settings'
// AutoRenewInterval, which CSRV-M12-05's registry and schedule call. A run reads the process's global Env (owner
// decision 594) and passes it to sidecar/controller's ComputeAutoRenewRun, which charges each network with threshold on
// whose balance, holds left out, is below its T, by an indexed cursor a batch at a time. A run that examined a full
// batch answers its cursor as the args of the run that continues it at once; a pass that reached its end answers none.

package work

import (
	"context"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

func init() {
	RegisterJob(&Job{Name: ComputeJobAutoRenew, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		cursor, err := controller.ParseComputeAutoRenewCursor(args)
		if err != nil {
			return nil, err
		}
		reached, err := ComputeAutoRenewTask(ctx, computeJobSettings().Ledger, cursor)
		return controller.ComputeAutoRenewCursorArgs(reached), err
	}})
}

// One run of compute_auto_renew from cursor, nil beginning a pass, on the process's Env: the cursor its continuation
// starts from, nil once the pass reached its end.
func ComputeAutoRenewTask(ctx context.Context, settings *model.ComputeLedgerSettings, cursor *operator.Id) (*operator.Id, error) {
	result, err := controller.ComputeAutoRenewRun(operator.GlobalEnv(), ctx, settings, cursor)
	if result == nil {
		return nil, err
	}
	return result.Cursor, err
}
