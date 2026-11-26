// A lost cache's rebuild (DESIGN-COMPUTE §9.7, D-BAL-13; BAL-M12-04): a network whose projection is absent, or marked
// because its shard's master changed and may have lost its last writes, admits nothing until it is rebuilt, its calls
// answering held with the settings' one-second retry meanwhile. The rebuild runs under the network's fence, which every
// booking and drop of the network also takes, so it sees a batch before its booking or after its drop, never between:
//
//	the fence     the network's transaction-scoped advisory lock (compute-plan-settle-fence-pooling, QD-1376)
//	the check     the projection read again under the fence: one present and unmarked was rebuilt by another caller
//	the snapshot  the network's open and settled rows in one statement, so a row moving from open to settled is in one
//	              and only one; then the account, its promotional credit, and this UTC month's booked charges of
//	              calls and searches by subject, which change only under the fence
//	the script    the projection, its holds, unsettled charges and budget counters, written whole in one script, the
//	              mark cleared, after which the network admits again
//
// A reading (recorded in the report): the snapshot runs at READ COMMITTED after the lock statement, where §9.7 says one
// REPEATABLE READ snapshot. PostgreSQL takes a repeatable-read snapshot when the transaction's first statement starts,
// which is the lock statement itself, before it waits, so a repeatable-read rebuild that waited on a batch would read
// the batch from before its booking and lose its drop. After the lock, the one statement that reads the rows is one
// snapshot, and the rest change only under the fence.
//
// The budget counters come back from the booked days and the unbooked rows, each resolved to its lines by the caller's
// ComputeBudgetLines, as the broker resolves a call's; a caller with none cannot rebuild, and the network stays held.
// Holds are rewritten confirmed, since their rows committed; a hold whose row is void or applied is not rewritten.

package controller

import (
	"context"
	"errors"
	"slices"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// A rebuild with no ComputeBudgetLines: the counters cannot be resolved, so the projection is left as it is and the
// network stays held, never admitting past a budget it has not read.
var ErrComputeRebuildNoBudgets = errors.New("compute rebuild: no budget lines to resolve the counters by")

// Whether a kind's operations count to budgets: calls and searches, never an enclave's running time (§16.4).
func computeKindHasBudgets(kind model.ComputeChargeKind) bool {
	return kind == model.ComputeChargeKindInference || kind == model.ComputeChargeKindWebSearch
}

// Rebuilds networkId's projection where it is absent or marked (see the file header): whether this call wrote it. A
// projection present and unmarked under the fence is left, false.
func ComputeRebuild(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, budgets ComputeBudgetLines) (bool, error) {
	if budgets == nil {
		return false, ErrComputeRebuildNoBudgets
	}
	clock, err := env.Clock()
	if err != nil {
		return false, err
	}
	db, err := env.Db()
	if err != nil {
		return false, err
	}
	rebuilt := false
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		rebuilt = false
		if err := model.ComputeFenceInTx(env, ctx, tx, networkId); err != nil {
			return err
		}
		projection, err := model.ComputeProjectionRead(env, ctx, networkId)
		if err != nil {
			return err
		}
		if projection.Present && !projection.Marked {
			return nil
		}
		now := clock.Now()
		ops, err := model.ComputeRebuildOpsInTx(env, ctx, tx, networkId)
		if err != nil {
			return err
		}
		account, err := model.ComputeAccountProjectionInTx(env, ctx, tx, networkId, now)
		if err != nil {
			return err
		}
		days, err := model.ComputeRebuildDaysInTx(env, ctx, tx, networkId, model.ComputeUtcMonth(now))
		if err != nil {
			return err
		}
		snapshot, err := computeRebuildSnapshot(ctx, networkId, account, ops, days, budgets, now)
		if err != nil {
			return err
		}
		testHookBarrier("compute_rebuild.script.before", networkId.String())
		if err := model.ComputeProjectionRebuild(env, ctx, settings, snapshot); err != nil {
			return err
		}
		testHookBarrier("compute_rebuild.script.after", networkId.String())
		rebuilt = true
		return nil
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return false, err
	}
	return rebuilt, nil
}

// One counter a rebuild writes: a subject's budget for a UTC day or month.
type computeRebuildCounterKey struct {
	subjectId operator.Id
	budget    string
	period    model.ComputeBudgetPeriod
}

// The snapshot a rebuild writes, from what it read at now: open rows as confirmed holds with their lines, settled rows
// with a charge as unsettled charges, and the counters of this UTC day and month, from the booked days and the
// unbooked rows' charges, each by its lines.
func computeRebuildSnapshot(ctx context.Context, networkId operator.Id, account *model.ComputeProjectionAccount, ops []*model.ComputeOp, days []*model.ComputeBookedDay, budgets ComputeBudgetLines, now time.Time) (*model.ComputeProjectionSnapshot, error) {
	today := model.ComputeUtcDay(now)
	month := model.ComputeUtcMonth(now)
	keyCharged := map[computeRebuildCounterKey]int64{}
	keys := []computeRebuildCounterKey{}
	count := func(lines []*model.ComputeBudgetLine, at time.Time, amount int64) {
		if amount <= 0 {
			return
		}
		for _, line := range lines {
			switch line.Period {
			case model.ComputeBudgetPeriodDay:
				if !model.ComputeUtcDay(at).Equal(today) {
					continue
				}
			case model.ComputeBudgetPeriodMonth:
				if !model.ComputeUtcMonth(at).Equal(month) {
					continue
				}
			default:
				continue
			}
			key := computeRebuildCounterKey{subjectId: line.SubjectId, budget: line.Budget, period: line.Period}
			if _, ok := keyCharged[key]; !ok {
				keys = append(keys, key)
			}
			keyCharged[key] += amount
		}
	}
	resolve := func(kind model.ComputeChargeKind, sidecarId operator.Id, agentId *operator.Id, memberId *operator.Id) ([]*model.ComputeBudgetLine, error) {
		if !computeKindHasBudgets(kind) {
			return nil, nil
		}
		return budgets(ctx, &ComputeBudgetSubjects{NetworkId: networkId, Kind: kind, SidecarId: sidecarId, AgentId: agentId, MemberId: memberId})
	}
	snapshot := &model.ComputeProjectionSnapshot{NetworkId: networkId, Account: account}
	for _, op := range ops {
		lines, err := resolve(op.Kind, op.SidecarId, op.AgentId, op.MemberId)
		if err != nil {
			return nil, err
		}
		switch op.State {
		case model.ComputeOpStateOpen:
			snapshot.Holds = append(snapshot.Holds, &model.ComputeProjectionHoldRow{
				OpKey: op.OpKey, Kind: op.Kind, HoldNanoUsd: op.HoldNanoUsd, ReserveNanoUsd: op.ReserveNanoUsd,
				StartTime: op.StartTime, Lines: lines,
			})
		case model.ComputeOpStateSettled:
			// a refund and a credit reach settled through their booking, never as an unsettled charge
			if op.Outcome == nil || op.Outcome.AmountNanoUsd <= 0 {
				continue
			}
			snapshot.Charges = append(snapshot.Charges, &model.ComputeProjectionChargeRow{OpKey: op.OpKey, Kind: op.Kind, AmountNanoUsd: op.Outcome.AmountNanoUsd})
			count(lines, op.StartTime, min(op.Outcome.AmountNanoUsd, op.ReserveNanoUsd))
		}
	}
	for _, day := range days {
		lines, err := resolve(day.Kind, day.SidecarId, day.AgentId, day.MemberId)
		if err != nil {
			return nil, err
		}
		count(lines, day.Day, day.ChargedNanoUsd)
	}
	slices.SortFunc(keys, func(a computeRebuildCounterKey, b computeRebuildCounterKey) int {
		if c := a.subjectId.Cmp(b.subjectId); c != 0 {
			return c
		}
		if a.budget != b.budget {
			if a.budget < b.budget {
				return -1
			}
			return 1
		}
		return int(a.period) - int(b.period)
	})
	for _, key := range keys {
		at := today
		if key.period == model.ComputeBudgetPeriodMonth {
			at = month
		}
		snapshot.Counters = append(snapshot.Counters, &model.ComputeProjectionCounter{
			SubjectId: key.subjectId, Budget: key.budget, Period: key.period, At: at, ChargedNanoUsd: keyCharged[key],
		})
	}
	return snapshot, nil
}
