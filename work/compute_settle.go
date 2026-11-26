// compute_settle's work (DESIGN-COMPUTE §14.5, §9.7; BAL-M12-04): taskworker's job, every 2 s, one run a shard, which
// CSRV-M12-05's registry and loops call (sidecar/work's registry, its design table and taskworker's per-shard loop are
// that task's). A run reads the process's global Env (owner decision 594) and passes it to sidecar/controller's
// ComputeBook, which books up to the settings' 500 settled rows of the shard and drops them from the projection.

package work

import (
	"context"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

// One run of compute_settle for shard, on the process's Env.
func ComputeSettleTask(ctx context.Context, settings *model.ComputeLedgerSettings, shard int16) error {
	_, err := controller.ComputeBook(operator.GlobalEnv(), ctx, settings, shard)
	return err
}

// The shards compute_settle runs, 0 to the settings' SettleShardCount less one: one loop each.
func ComputeSettleShards(settings *model.ComputeLedgerSettings) []int16 {
	shards := []int16{}
	for shard := 0; shard < settings.SettleShardCount; shard += 1 {
		shards = append(shards, int16(shard))
	}
	return shards
}
