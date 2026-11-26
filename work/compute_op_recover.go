// compute_op_recover's work (DESIGN-COMPUTE §14.5, §9.7; BAL-M12-04): taskworker's job, every minute, which
// CSRV-M12-05's registry calls. A run reads the process's global Env (owner decision 594) and passes it to
// sidecar/controller's ComputeRecover, which finishes the rows whose producer stopped through each kind's
// ComputeRecoverSource and releases any row open a day at no charge.

package work

import (
	"context"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

// One run of compute_op_recover, on the process's Env.
func ComputeOpRecoverTask(ctx context.Context, settings *model.ComputeLedgerSettings) error {
	_, err := controller.ComputeRecover(operator.GlobalEnv(), ctx, settings)
	return err
}
