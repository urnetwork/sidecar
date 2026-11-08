// §22.8's twins: every refusal schedule has a twin that must succeed, the same setup with the refused
// act made legal. A feature switched off refuses everything, so its refusal schedules pass alone; the
// twin is what fails then. A refusal schedule says what it expects refused in Schedule.Refuses, Run
// fails one that names no twin, and Twin is how one names it. A forged schedule's twin carries T3,
// where it runs on server's real exchange, though the forged row names T2 alone.

package fault

import (
	"context"
	"fmt"
	"slices"

	"github.com/urnetwork/sidecar/sidecartest"
)

// refusal's schedule, naming success as the twin that must succeed beside it. Panics without both: a
// refusal registered with no twin fails to register, at its package-level var.
func Twin(refusal Builder, success Builder) Builder {
	if refusal == nil || success == nil {
		panic("a refusal schedule names the twin that must succeed beside it (§22.8's twins)")
	}
	return func(net *Net) *Schedule {
		schedule := refusal(net)
		schedule.Twin = success
		return schedule
	}
}

// The twin of a schedule, as it runs: it must succeed, so one that expects a refusal fails, and a
// forged schedule's twin names T3.
func twinBuilder(schedule *Schedule) Builder {
	return func(net *Net) *Schedule {
		twin := schedule.Twin(net)
		if twin.Id == "" || twin.Id == schedule.Id {
			twin.Id = schedule.Id + " twin"
		}
		if schedule.Forged && !slices.Contains(twin.Tiers, TierT3) {
			twin.Tiers = append(slices.Clone(twin.Tiers), TierT3)
		}
		return twin
	}
}

// Runs a schedule's twin on a fresh Net. A twin that expects a refusal itself fails without running:
// a twin is what must succeed.
func RunTwin(ctx context.Context, schedule *Schedule, settings *sidecartest.NetSettings) *Result {
	if schedule.Twin == nil {
		return &Result{Id: schedule.Id + " twin", FailedStep: -1, Err: fmt.Errorf("%s names no twin", schedule.Id)}
	}
	net := sidecartest.NewNet(ctx, settings)
	defer net.Close()
	twin := twinBuilder(schedule)(net)
	if twin.Refuses != "" {
		return &Result{Id: twin.Id, FailedStep: -1, Err: fmt.Errorf("%s expects %s refused, and a twin must succeed", twin.Id, twin.Refuses)}
	}
	return Run(ctx, twin, net)
}
