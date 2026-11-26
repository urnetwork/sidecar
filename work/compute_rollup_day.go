// compute_rollup_day's work (DESIGN-COMPUTE §14.5, §9.13; BAL-M12-05): taskworker's job, daily at the settings'
// RollupDayOffset past 00:00 UTC (02:00), which CSRV-M12-05's registry and schedule call (sidecar/work's registry and
// taskworker's chain are that task's). A run reads the process's global Env (owner decision 594) and passes it to
// sidecar/controller's ComputeRollupDay, which makes the partitions ahead, checks and prunes the networks' rollups
// over one closed UTC day, and drops the charge partitions past their retention.
//
// A run answers the cursor it reached: done, or where it stopped, which the job keeps in its run's args
// (ComputeRollupCursor.Args, ParseComputeRollupCursor) so a failed run's retry resumes there. Each difference is logged
// here, by its network, kind and day, never an amount; the alarm's counter is the controller's.

package work

import (
	"context"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

// One run of compute_rollup_day from cursor, nil beginning a pass over the UTC day before today's, on the process's
// Env: the cursor the run reached, which a retry passes back. log takes one line a difference; nil logs nothing.
func ComputeRollupDayTask(ctx context.Context, settings *model.ComputeLedgerSettings, log sidecar.Logger, cursor *controller.ComputeRollupCursor) (*controller.ComputeRollupCursor, error) {
	return computeRollupDayRun(operator.GlobalEnv(), ctx, settings, log, cursor)
}

// One run on env.
func computeRollupDayRun(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, log sidecar.Logger, cursor *controller.ComputeRollupCursor) (*controller.ComputeRollupCursor, error) {
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	result, err := controller.ComputeRollupDay(env, ctx, settings, cursor)
	if result == nil {
		return cursor, err
	}
	for _, mismatch := range result.Mismatches {
		switch mismatch.Check {
		case controller.ComputeRollupCheckDay:
			log.Errorf("[compute-rollup]the day rows of network %s's %s charges on %s differ from its charges\n",
				sidecar.EvsKeyId(mismatch.NetworkId), mismatch.Kind, mismatch.Day.Format("2006-01-02"))
		case controller.ComputeRollupCheckTotal:
			log.Errorf("[compute-rollup]the totals of network %s's %s charges differ from its day rows and pruned sums\n",
				sidecar.EvsKeyId(mismatch.NetworkId), mismatch.Kind)
		}
	}
	return result.Cursor, err
}
