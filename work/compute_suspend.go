// compute_suspend's work (DESIGN-COMPUTE §14.5, §9.9; BAL-M12-12): taskworker's job, every minute at the settings'
// SuspendInterval, which CSRV-M12-05's registry and schedule call. A run reads the process's global Env (owner decision
// 594) and passes it to sidecar/controller's ComputeSuspendRun, which reviews §9.9's state of each account not active,
// and of each whose balance moved within the settings' lookback, by an indexed cursor a batch at a time. A run that
// examined a full batch answers its cursor as the args of the run that continues it at once; a pass that reached its
// end answers none.

package work

import (
	"context"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

func init() {
	RegisterJob(&Job{Name: ComputeJobSuspend, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		cursor, err := controller.ParseComputeAutoRenewCursor(args)
		if err != nil {
			return nil, err
		}
		reached, err := ComputeSuspendTask(ctx, computeJobSettings().Ledger, cursor)
		return controller.ComputeAutoRenewCursorArgs(reached), err
	}})
}

// One run of compute_suspend from cursor, nil beginning a pass, on the process's Env: the cursor its continuation
// starts from, nil once the pass reached its end.
func ComputeSuspendTask(ctx context.Context, settings *model.ComputeLedgerSettings, cursor *operator.Id) (*operator.Id, error) {
	result, err := controller.ComputeSuspendRun(operator.GlobalEnv(), ctx, settings, cursor)
	if result == nil {
		return nil, err
	}
	return result.Cursor, err
}
