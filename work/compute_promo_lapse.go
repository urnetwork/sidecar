// compute_promo_lapse's work (DESIGN-COMPUTE §14.5, §9.11; BAL-M12-13): taskworker's job, hourly at the settings'
// PromoLapseInterval, which CSRV-M12-05's registry and schedule call (sidecar/work's registry and taskworker's chain
// are that task's). A run reads the process's global Env (owner decision 594) and passes it to sidecar/controller's
// ComputeLapsePromos, which lapses up to the settings' batch of promotional lots past their expiry, each network's in
// one transaction under its fence, never as a charge. A run that leaves lots past their expiry, a full batch or a
// network that failed, leaves them for the next, which lists them again.

package work

import (
	"context"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

// One run of compute_promo_lapse, on the process's Env.
func ComputePromoLapseTask(ctx context.Context, settings *model.ComputeLedgerSettings) error {
	_, err := controller.ComputeLapsePromos(operator.GlobalEnv(), ctx, settings)
	return err
}
