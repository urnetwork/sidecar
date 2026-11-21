// §22.8's unknown rule: every write in a row on the unknown list also runs with ApplyThenDrop, its
// effect applied and its response lost. One dry run counts the writes the schedule issues, PUTs,
// DELETEs, Redis writes, the fake hosts' writing calls and, on T3, Postgres commits; then the schedule
// runs again once per write, a fresh build each time, with that write's response lost, and every run
// checks the row's invariants after every step, so a run that cleans up on an unknown outcome is caught
// by the invariant that forbids it (FI-2's, UnknownDeletesNothing).
//
// A fake host's writing call is one its fake declares a write (sidecartest's fake_host.go; QD-1155): the
// Quota's ReportUsage, CountRate, a Lease that draws and a lease's settling Close, Tasks' Schedule and
// Push's Hint and HintSidecars. Its answer is lost as a store's is, so a usage batch, a lease draw or an
// enqueued task whose caller treats the unknown outcome as a failure fails its row here. On T3 the hosts
// the Net keeps as fakes, Push and Quota, are counted the same way, and the real ones' writes are their
// stores' Redis calls and Postgres commits.

package fault

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The operations whose writes the rule loses one at a time.
var everyWriteOps = []string{
	sidecartest.FaultOpPut,
	sidecartest.FaultOpDelete,
	sidecartest.FaultOpRedis,
	sidecartest.FaultOpPgCommit,
	sidecartest.FaultOpHost,
}

// One write a rerun loses: the nth write of op.
type LostWrite struct {
	Op  string
	Nth int
}

// Runs builder once to count its writes, then once for each with its response lost, and returns every
// failure, the dry run's included, with the writes the reruns lost. Writes are counted where a plan
// counts them, at the fault queue, so a write the schedule's own plan faults counts as well as one a
// store served. A write the schedule fails before apply runs with its response lost instead, its plan
// counting as fired there, since a caller cannot tell the two apart; one the schedule delays, holds,
// crashes or already drops keeps that fault, which is the row's own. A fake counts the writes, so this
// is T2's; a T3 row sets its own plans. settings nil takes the defaults.
func EveryWrite(ctx context.Context, builder Builder, settings *sidecartest.NetSettings) (failures []*Result, lostWrites []LostWrite) {
	opResults := map[string][]FaultResult{}
	func() {
		net := sidecartest.NewNet(ctx, settings)
		defer net.Close()
		result := Run(ctx, builder(net), net)
		if result.Err != nil {
			failures = append(failures, result)
		}
		for _, op := range everyWriteOps {
			opResults[op] = net.Faults().WriteResults(op)
		}
	}()
	if 0 < len(failures) {
		return failures, nil
	}
	for _, op := range everyWriteOps {
		for index, result := range opResults[op] {
			if result != 0 && result != FailBeforeApply {
				continue
			}
			lost := LostWrite{Op: op, Nth: index + 1}
			lostWrites = append(lostWrites, lost)
			result := runBuilt(ctx, builder, settings, func(schedule *Schedule) {
				plan := &FaultPlan{Op: lost.Op, Nth: lost.Nth, Result: ApplyThenDrop, Displaces: true, WritesOnly: true}
				schedule.Steps = append([]*Step{{Fault: plan}}, schedule.Steps...)
				schedule.Id = fmt.Sprintf("%s with %s write %d's response lost", schedule.Id, lost.Op, lost.Nth)
			})
			if result.Err != nil {
				failures = append(failures, result)
			}
		}
	}
	return failures, lostWrites
}
