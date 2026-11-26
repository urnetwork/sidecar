// compute_rollup_day (DESIGN-COMPUTE §9.4, §9.13, §14.5, D-BAL-6; BAL-M12-05): daily at 02:00 UTC, one pass over one
// closed UTC day, the day before the one the pass began on, in two phases after the partitions ahead:
//
//	partitions  compute_charge's partitions for today and the settings' 7 days ahead, each bounded at UTC midnights,
//	            made where none stands; first in every run, so a booking never waits on a pass
//	networks    the networks with an account, in batches of the settings' 100 by an indexed cursor over their ids,
//	            each batch in two transactions:
//	              the check  one REPEATABLE READ snapshot, read only: the closed day's compute_charge_day rows
//	                         re-derived from its charges, grouped by their stored columns, against the rows as
//	                         compute_settle wrote them; and per network and kind, compute_charge_total against the
//	                         day rows plus compute_charge_pruned, which holds in every snapshot since the booking writes
//	                         a charge to both rollups in one transaction and the prune below moves each day row in one
//	              the prune  the day rows past the settings' 400 days moved into compute_charge_pruned, summed per
//	                         network and kind, in the one statement that deletes them
//	drops       each charge partition whose whole day ended past the settings' 90 days, in a transaction of its own
//	            with a short lock wait: the operation rows kept once booked that name its charges (a search's, a
//	            refund's, an adjustment's), its charges' lot draws, then the partition, detached and dropped
//
// Each difference is an alarm: urnetwork_compute_alarms_total, by the check (rollup_day, rollup_total), counted once a
// pass for each network and kind, which §14.7's page reads (CSRV C§14.7), and the result's mismatches, which name the
// network, the kind and the day and never an amount, for the job's log line. A difference is never repaired here:
// compute_settle writes the rollups, and a difference is a hand edit or a bug for a person to read.
//
// Bounded work (connect/CODESTYLE.md's load rules): one day a pass; a batch's reads go by network through the rollups'
// keys and one day's partition; a run that fails stops at the batch it failed in and answers the cursor it reached,
// which the job's retry passes back, so the pass resumes there and no batch is checked twice.
//
// An open day is never re-derived: a cursor naming today or later is refused. A kind whose charges the day may no
// longer hold is left out of the day check, never compared against a partial set: a web search's, whose charges
// compute_search_purge deletes from 71 h 55 min (§14.5), once the day's first minute is that old, and every kind once
// the day's partition is past its retention.

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// The alarm counter the ledger's checks raise, by kind of alarm: compute's one alarm family (computeservice's
// engine_log.go declares it too, with the same label), which §14.7's signals read.
const computeAlarmsMetric = "urnetwork_compute_alarms_total"

// The rollup's alarm kinds, as the counter's kind label holds them.
const (
	ComputeAlarmRollupDay   = "rollup_day"
	ComputeAlarmRollupTotal = "rollup_total"
)

// Where a pass stands.
type ComputeRollupPhase string

const (
	// Checking and pruning the networks' rollups, batch by batch.
	ComputeRollupPhaseNetworks ComputeRollupPhase = "networks"
	// Dropping the charge partitions past their retention.
	ComputeRollupPhaseDrops ComputeRollupPhase = "drops"
	// The pass is over.
	ComputeRollupPhaseDone ComputeRollupPhase = "done"
)

// A pass's resumable progress: what a failed run's retry passes back, as taskworker keeps a job's position in its
// args. Holds a day, a phase and a network id, never an amount.
type ComputeRollupCursor struct {
	// The closed UTC day the pass re-derives.
	Day   time.Time          `json:"day"`
	Phase ComputeRollupPhase `json:"phase"`
	// The last network whose batch the pass finished; nil before the first.
	After *operator.Id `json:"after,omitempty"`
}

// A cursor that begins a pass at now: over the UTC day before now's, its networks from the first.
func NewComputeRollupCursor(now time.Time) *ComputeRollupCursor {
	return &ComputeRollupCursor{Day: model.ComputeUtcDay(now).AddDate(0, 0, -1), Phase: ComputeRollupPhaseNetworks}
}

// The cursor as a run's args.
func (self *ComputeRollupCursor) Args() ([]byte, error) {
	return json.Marshal(self)
}

// A cursor from a run's args; empty args begin a pass, nil.
func ParseComputeRollupCursor(args []byte) (*ComputeRollupCursor, error) {
	if len(args) == 0 {
		return nil, nil
	}
	cursor := &ComputeRollupCursor{}
	if err := json.Unmarshal(args, cursor); err != nil {
		return nil, fmt.Errorf("%w: a rollup cursor: %w", ErrComputeLedgerArgs, err)
	}
	if cursor.Day.IsZero() || !cursor.Day.Equal(model.ComputeUtcDay(cursor.Day)) {
		return nil, fmt.Errorf("%w: a rollup cursor's day is a UTC day", ErrComputeLedgerArgs)
	}
	switch cursor.Phase {
	case ComputeRollupPhaseNetworks, ComputeRollupPhaseDrops, ComputeRollupPhaseDone:
	default:
		return nil, fmt.Errorf("%w: a rollup cursor's phase %q", ErrComputeLedgerArgs, cursor.Phase)
	}
	cursor.Day = cursor.Day.UTC()
	return cursor, nil
}

// Which check found a difference.
type ComputeRollupCheck string

const (
	// The closed day's day rows against its charges.
	ComputeRollupCheckDay ComputeRollupCheck = "day"
	// The lifetime totals against the day rows and the pruned sums.
	ComputeRollupCheckTotal ComputeRollupCheck = "total"
)

// One alarm: a network and kind whose rollup differs. Names no amount.
type ComputeRollupMismatch struct {
	Check     ComputeRollupCheck
	NetworkId operator.Id
	Kind      model.ComputeChargeKind
	// The day re-derived, for a day check.
	Day time.Time
}

// What one run of a pass did.
type ComputeRollupResult struct {
	// Where the pass stands after the run: done, or where it stopped, for the retry.
	Cursor *ComputeRollupCursor
	// The UTC days whose partitions stand after the run's partitions step.
	PartitionDays []time.Time
	// Networks checked and pruned.
	NetworkCount int
	// Every difference the run found, in the order found.
	Mismatches []*ComputeRollupMismatch
	// The kinds the day check left out, their charges no longer all kept.
	SkippedKinds []model.ComputeChargeKind
	// Day rows moved into compute_charge_pruned.
	PrunedRowCount int64
	// Charge partitions dropped, with what went with them.
	Dropped []*model.ComputeChargePartitionDropped
}

// Makes compute_charge's partitions for now's UTC day and the settings' days ahead where none stands, each bounded at
// UTC midnights (§14.5): the days ensured, today's first.
func ComputeEnsurePartitions(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, now time.Time) ([]time.Time, error) {
	today := model.ComputeUtcDay(now)
	days := []time.Time{}
	for ahead := 0; ahead <= settings.ChargePartitionDaysAhead; ahead += 1 {
		days = append(days, today.AddDate(0, 0, ahead))
	}
	if err := model.ComputeChargePartitionsEnsure(env, ctx, days); err != nil {
		return nil, err
	}
	return days, nil
}

// The kinds the day check compares for day at now, and those it leaves out: none once the day's partition is past
// its retention, and no web search once the day's first minute is past the age its purge deletes from.
func computeRollupDayKinds(settings *model.ComputeLedgerSettings, day time.Time, now time.Time) (compared []model.ComputeChargeKind, skipped []model.ComputeChargeKind) {
	kept := now.Before(day.AddDate(0, 0, 1).Add(settings.ChargeRetention))
	for _, kind := range model.ComputeChargeKinds() {
		switch {
		case !kept:
			skipped = append(skipped, kind)
		case kind == model.ComputeChargeKindWebSearch && !now.Before(day.Add(settings.SearchChargePurgeAge)):
			skipped = append(skipped, kind)
		default:
			compared = append(compared, kind)
		}
	}
	return compared, skipped
}

// Runs a pass of compute_rollup_day from cursor, nil beginning one at the env's now (see the file header). The result
// holds the cursor reached, done or where the run stopped, whether or not it errs.
func ComputeRollupDay(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, cursor *ComputeRollupCursor) (*ComputeRollupResult, error) {
	if settings.RollupNetworkBatchCount <= 0 || settings.RollupDropLockTimeout <= 0 {
		return nil, fmt.Errorf("%w: the rollup's batch and lock wait are positive", ErrComputeLedgerArgs)
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	if cursor == nil {
		cursor = NewComputeRollupCursor(now)
	}
	position := *cursor
	position.Day = model.ComputeUtcDay(position.Day)
	if !position.Day.Before(model.ComputeUtcDay(now)) {
		return nil, fmt.Errorf("%w: %s is not a closed day", ErrComputeLedgerArgs, position.Day.Format(time.DateOnly))
	}
	result := &ComputeRollupResult{Cursor: &position}
	result.PartitionDays, err = ComputeEnsurePartitions(env, ctx, settings, now)
	if err != nil {
		return result, err
	}
	alarm := computeRollupAlarm(env)
	compared, skipped := computeRollupDayKinds(settings, position.Day, now)
	result.SkippedKinds = skipped
	for position.Phase == ComputeRollupPhaseNetworks {
		networkIds, err := model.ComputeRollupNetworks(env, ctx, position.After, settings.RollupNetworkBatchCount)
		if err != nil {
			return result, err
		}
		if len(networkIds) == 0 {
			position.Phase = ComputeRollupPhaseDrops
			break
		}
		mismatches, err := computeRollupCheck(env, ctx, networkIds, position.Day, compared)
		if err != nil {
			return result, err
		}
		for _, mismatch := range mismatches {
			alarm(mismatch)
		}
		result.Mismatches = append(result.Mismatches, mismatches...)
		pruned, err := computeRollupPrune(env, ctx, settings, networkIds, now)
		if err != nil {
			return result, err
		}
		result.PrunedRowCount += pruned
		result.NetworkCount += len(networkIds)
		last := networkIds[len(networkIds)-1]
		position.After = &last
		if len(networkIds) < settings.RollupNetworkBatchCount {
			position.Phase = ComputeRollupPhaseDrops
		}
	}
	if position.Phase == ComputeRollupPhaseDrops {
		dropped, err := computeRollupDrops(env, ctx, settings, now)
		result.Dropped = dropped
		if err != nil {
			return result, err
		}
		position.Phase = ComputeRollupPhaseDone
	}
	return result, nil
}

// What raises one mismatch's alarm: the counter, where the env holds metrics. A process without them still answers
// the mismatches in its result.
func computeRollupAlarm(env operator.Env) func(mismatch *ComputeRollupMismatch) {
	metrics, err := env.Metrics()
	if err != nil {
		return func(mismatch *ComputeRollupMismatch) {}
	}
	counter := metrics.Counter(computeAlarmsMetric, "compute faults that alarm, by kind", "kind")
	return func(mismatch *ComputeRollupMismatch) {
		switch mismatch.Check {
		case ComputeRollupCheckDay:
			counter.Add(1, ComputeAlarmRollupDay)
		case ComputeRollupCheckTotal:
			counter.Add(1, ComputeAlarmRollupTotal)
		}
	}
}

// One batch's check, in one REPEATABLE READ snapshot, read only: the day rows of day re-derived for the kinds
// compared, and every network and kind's totals.
func computeRollupCheck(env operator.Env, ctx context.Context, networkIds []operator.Id, day time.Time, compared []model.ComputeChargeKind) ([]*ComputeRollupMismatch, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	var mismatches []*ComputeRollupMismatch
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		mismatches = nil
		if 0 < len(compared) {
			derived, err := model.ComputeRollupDerivedDayInTx(env, ctx, tx, networkIds, day)
			if err != nil {
				return err
			}
			stored, err := model.ComputeRollupStoredDayInTx(env, ctx, tx, networkIds, day)
			if err != nil {
				return err
			}
			for _, key := range model.ComputeRollupDayDifferences(derived, stored, compared) {
				mismatches = append(mismatches, &ComputeRollupMismatch{Check: ComputeRollupCheckDay, NetworkId: key.NetworkId, Kind: key.Kind, Day: day})
			}
		}
		sums, err := model.ComputeRollupSumsInTx(env, ctx, tx, networkIds)
		if err != nil {
			return err
		}
		for _, sum := range sums {
			if !sum.Balanced() {
				mismatches = append(mismatches, &ComputeRollupMismatch{Check: ComputeRollupCheckTotal, NetworkId: sum.NetworkId, Kind: sum.Kind})
			}
		}
		return nil
	}, operator.DbIsolationRepeatableRead, operator.DbReadOnly)
	return mismatches, err
}

// One batch's prune: its day rows past the settings' retention, moved into compute_charge_pruned.
func computeRollupPrune(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkIds []operator.Id, now time.Time) (int64, error) {
	db, err := env.Db()
	if err != nil {
		return 0, err
	}
	before := model.ComputeUtcDay(now).Add(-settings.DayRowRetention)
	moved := int64(0)
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		moved, err = model.ComputeRollupPruneInTx(env, ctx, tx, networkIds, before)
		return err
	}, operator.DbIsolationReadCommitted)
	return moved, err
}

// The drops phase: each charge partition whose day ended the settings' retention ago, oldest first, each in its own
// transaction under the settings' short lock wait. A partition that waited past it stops the phase, which the next
// run takes up again.
func computeRollupDrops(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, now time.Time) ([]*model.ComputeChargePartitionDropped, error) {
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	days, err := model.ComputeChargePartitionDays(env, ctx)
	if err != nil {
		return nil, err
	}
	cutoff := now.Add(-settings.ChargeRetention)
	dropped := []*model.ComputeChargePartitionDropped{}
	for _, day := range days {
		if cutoff.Before(day.AddDate(0, 0, 1)) {
			// this day and every later one hold a charge inside the retention
			break
		}
		var one *model.ComputeChargePartitionDropped
		err := db.Tx(ctx, func(tx operator.DbTx) error {
			var err error
			one, err = model.ComputeChargePartitionDropInTx(env, ctx, tx, day)
			return err
		}, operator.DbIsolationReadCommitted, operator.DbLockTimeout(settings.RollupDropLockTimeout))
		if err != nil {
			if errors.Is(err, operator.ErrDbLockTimeout) {
				return dropped, fmt.Errorf("compute rollup: the partition of %s waited past its lock bound: %w", day.Format(time.DateOnly), err)
			}
			return dropped, err
		}
		dropped = append(dropped, one)
	}
	return dropped, nil
}
