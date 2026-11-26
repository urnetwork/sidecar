// compute_settle's booking (DESIGN-COMPUTE §9.4, §9.7, §9.13, §14.5, D-BAL-1, D-BAL-6, D-BAL-13; BAL-M12-04): one run
// for one shard, every 2 s, in three steps.
//
//  1. What a run before left between its booking and its drop, booked rows not yet deleted, is dropped and deleted.
//  2. Up to the settings' 500 settled rows of the shard, in one transaction under each of their networks' fences:
//     their charges inserted ON CONFLICT DO NOTHING RETURNING, and only the rows returned booked, so a charge
//     delivered twice meets its (start_time, charge_id) and adds one debit in all; the lots drawn in §9.4's order into
//     compute_charge_lot; compute_account's settled, version, update_time and first_charge_day; each charge added to
//     its compute_charge_day and compute_charge_total rows in key order; and every row moved to applied.
//  3. Per network, under its fence again: one drop script, which drops the booked operations' unsettled charges and
//     sets settled from the committed account where its version is newer, then the booked rows deleted, but a
//     search's, a refund's and an adjustment's, which are kept (§9.7).
//
// The fence is the network's transaction-scoped advisory lock (compute-plan-settle-fence-pooling, QD-1376): taken in
// the booking's transaction and again around the drop script, with the drop script's version guard, so a rebuild sees
// a batch before its booking or after its drop, never between. A batch's networks' fences are taken in network order,
// so two batches never wait on each other in a cycle.
//
// The draws (§9.4): a charge draws unexpired promotions by nearest expiry, then subscription grants, then purchases,
// oldest first, then adjustment lots, a web search passing over promotions (§9.11); what no lot covers, the overrun,
// stays in the account's negative settled and is drawn from the next lot credited (BAL-M12-07). A refund, a negative
// charge of the kind it returns, gives its amount back to the lots its charge drew, in reverse draw order, as negative
// draws: nothing to a reversed lot, and a promotion past its expiry forfeits its part, which lapses as expiry does
// (Q-BAL-4); settled rises by the refund less what it forfeited. A support credit, a negative adjustment, names no charge
// and draws no lot: settled rises by it.
//
// The charge partitions a batch needs are made before it where none stands (a reading: compute_rollup_day keeps the
// days ahead, BAL-M12-05, and a booking that met a missing day would otherwise fail until it ran).

package controller

import (
	"context"
	"slices"
	"strconv"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// What one run of compute_settle did for its shard.
type ComputeBookResult struct {
	// Rows a run before left booked and undropped, dropped and deleted now.
	RedroppedCount int
	// Rows this run moved to applied, and of them the charges it inserted, the rest having met their charge already.
	AppliedCount int
	BookedCount  int
	// Networks this run dropped for.
	NetworkCount int
}

// The rows of ops by network, in network order, each network's in key order.
func computeBookByNetwork(ops []*model.ComputeOp) ([]operator.Id, map[operator.Id][]*model.ComputeOp) {
	networkIdOps := map[operator.Id][]*model.ComputeOp{}
	networkIds := []operator.Id{}
	for _, op := range ops {
		if _, ok := networkIdOps[op.NetworkId]; !ok {
			networkIds = append(networkIds, op.NetworkId)
		}
		networkIdOps[op.NetworkId] = append(networkIdOps[op.NetworkId], op)
	}
	slices.SortFunc(networkIds, operator.Id.Cmp)
	for _, networkId := range networkIds {
		slices.SortFunc(networkIdOps[networkId], func(a *model.ComputeOp, b *model.ComputeOp) int { return a.OpKey.Cmp(b.OpKey) })
	}
	return networkIds, networkIdOps
}

// Books one run of shard (see the file header).
func ComputeBook(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, shard int16) (*ComputeBookResult, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	result := &ComputeBookResult{}
	// 1. what a run before left between its booking and its drop
	undropped, err := model.ComputeOpListUndropped(env, ctx, shard, settings.SettleBatchRowCount)
	if err != nil {
		return nil, err
	}
	networkIds, networkIdOps := computeBookByNetwork(undropped)
	for _, networkId := range networkIds {
		if err := computeBookDrop(env, ctx, settings, networkId, networkIdOps[networkId], clock.Now()); err != nil {
			return nil, err
		}
		result.RedroppedCount += len(networkIdOps[networkId])
	}
	// 2. the batch, its days' partitions made first
	days, err := model.ComputeBookDays(env, ctx, shard)
	if err != nil {
		return nil, err
	}
	if err := model.ComputeChargePartitionsEnsure(env, ctx, days); err != nil {
		return nil, err
	}
	applied, bookedCount, err := computeBookBatch(env, ctx, settings, shard, clock.Now())
	if err != nil {
		return nil, err
	}
	result.AppliedCount = len(applied)
	result.BookedCount = bookedCount
	// 3. each network's drop
	networkIds, networkIdOps = computeBookByNetwork(applied)
	for _, networkId := range networkIds {
		if err := computeBookDrop(env, ctx, settings, networkId, networkIdOps[networkId], clock.Now()); err != nil {
			// the rows stay applied and undropped, and the next run drops them first
			return result, err
		}
		result.NetworkCount += 1
	}
	return result, nil
}

// Step 2's transaction: the rows it moved to applied and how many charges it inserted.
func computeBookBatch(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, shard int16, now time.Time) ([]*model.ComputeOp, int, error) {
	db, err := env.Db()
	if err != nil {
		return nil, 0, err
	}
	var applied []*model.ComputeOp
	bookedCount := 0
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		applied = nil
		bookedCount = 0
		ops, err := model.ComputeBookSelectInTx(env, ctx, tx, shard, settings.SettleBatchRowCount)
		if err != nil || len(ops) == 0 {
			return err
		}
		networkIds, networkIdOps := computeBookByNetwork(ops)
		for _, networkId := range networkIds {
			if err := model.ComputeFenceInTx(env, ctx, tx, networkId); err != nil {
				return err
			}
		}
		charges := []*model.ComputeCharge{}
		for _, op := range ops {
			charge, err := model.ComputeChargeOf(op)
			if err != nil {
				return err
			}
			charges = append(charges, charge)
		}
		inserted, err := model.ComputeChargeInsertInTx(env, ctx, tx, charges)
		if err != nil {
			return err
		}
		adds := []*model.ComputeRollupAdd{}
		for _, networkId := range networkIds {
			booked := []*model.ComputeCharge{}
			for _, op := range networkIdOps[networkId] {
				if inserted[op.OpKey] {
					charge, _ := model.ComputeChargeOf(op)
					booked = append(booked, charge)
				}
			}
			if len(booked) == 0 {
				continue
			}
			networkAdds, err := computeBookNetwork(env, ctx, tx, networkId, booked, now)
			if err != nil {
				return err
			}
			adds = append(adds, networkAdds...)
			bookedCount += len(booked)
		}
		if err := model.ComputeRollupsUpsertInTx(env, ctx, tx, adds); err != nil {
			return err
		}
		opKeys := []operator.Id{}
		for _, op := range ops {
			opKeys = append(opKeys, op.OpKey)
		}
		if err := model.ComputeOpApplyInTx(env, ctx, tx, opKeys); err != nil {
			return err
		}
		applied = ops
		testHookBarrier("compute_book.commit.before", shardKey(shard))
		return nil
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, 0, err
	}
	testHookBarrier("compute_book.commit.after", shardKey(shard))
	return applied, bookedCount, nil
}

// A shard's number as a barrier's key.
func shardKey(shard int16) string {
	return "shard:" + strconv.Itoa(int(shard))
}

// One network's booked charges in tx: the lots they draw, the account and the rollups they add, which the batch upserts
// with every network's.
func computeBookNetwork(env operator.Env, ctx context.Context, tx operator.DbTx, networkId operator.Id, booked []*model.ComputeCharge, now time.Time) ([]*model.ComputeRollupAdd, error) {
	// in start order, so a refund follows the charge it returns where both are in the batch
	slices.SortFunc(booked, func(a *model.ComputeCharge, b *model.ComputeCharge) int {
		if c := a.StartTime.Compare(b.StartTime); c != 0 {
			return c
		}
		return a.ChargeId.Cmp(b.ChargeId)
	})
	lots, err := model.ComputeLotsForDrawInTx(env, ctx, tx, networkId, now)
	if err != nil {
		return nil, err
	}
	refundedIds := []operator.Id{}
	for _, charge := range booked {
		if computeChargeIsRefund(charge) {
			refundedIds = append(refundedIds, charge.SubjectRef)
		}
	}
	priorDraws, err := model.ComputeChargeDrawsInTx(env, ctx, tx, refundedIds)
	if err != nil {
		return nil, err
	}
	drawableIds := map[operator.Id]bool{}
	for _, lot := range lots {
		drawableIds[lot.LotId] = true
	}
	otherLotIds := []operator.Id{}
	for _, draws := range priorDraws {
		for _, draw := range draws {
			if !drawableIds[draw.LotId] && !slices.Contains(otherLotIds, draw.LotId) {
				otherLotIds = append(otherLotIds, draw.LotId)
			}
		}
	}
	otherLots, err := model.ComputeLotsGetInTx(env, ctx, tx, otherLotIds)
	if err != nil {
		return nil, err
	}
	plan := computeDrawPlan(lots, otherLots, priorDraws, booked, now)
	if err := model.ComputeDrawsInsertInTx(env, ctx, tx, plan.draws); err != nil {
		return nil, err
	}
	if err := model.ComputeLotsChangeInTx(env, ctx, tx, plan.lotChanges()); err != nil {
		return nil, err
	}
	firstDay := booked[0].StartTime
	for _, charge := range booked {
		if charge.StartTime.Before(firstDay) {
			firstDay = charge.StartTime
		}
	}
	if _, err := model.ComputeAccountBookInTx(env, ctx, tx, networkId, plan.settledDelta, firstDay, now); err != nil {
		return nil, err
	}
	adds := []*model.ComputeRollupAdd{}
	for _, charge := range booked {
		adds = append(adds, model.ComputeRollupAddOf(charge))
	}
	return adds, nil
}

// Whether charge is a refund: a negative charge of the kind it returns, never an adjustment.
func computeChargeIsRefund(charge *model.ComputeCharge) bool {
	return charge.AmountNanoUsd < 0 && charge.Kind != model.ComputeChargeKindAdjustment
}

// A lot as a batch's draws move it.
type computeDrawLot struct {
	lot       *model.ComputeLot
	remaining int64
	drawable  bool
}

// What a network's booked charges draw: the draws, each lot's change, and how far settled falls (a refund's and a
// credit's negative raise it).
type computeDraws struct {
	draws        []*model.ComputeChargeDraw
	changes      map[operator.Id]*model.ComputeLotChange
	settledDelta int64
}

// The changes, in lot order.
func (self *computeDraws) lotChanges() []*model.ComputeLotChange {
	changes := []*model.ComputeLotChange{}
	for _, change := range self.changes {
		if change.RemainingDelta != 0 || change.LapsedAddNanoUsd != 0 {
			changes = append(changes, change)
		}
	}
	slices.SortFunc(changes, func(a *model.ComputeLotChange, b *model.ComputeLotChange) int { return a.LotId.Cmp(b.LotId) })
	return changes
}

func (self *computeDraws) change(lotId operator.Id) *model.ComputeLotChange {
	change, ok := self.changes[lotId]
	if !ok {
		change = &model.ComputeLotChange{LotId: lotId}
		self.changes[lotId] = change
	}
	return change
}

// The draws of charges, in their order, over lots in §9.4's draw order (see the file header). otherLots holds the lots
// a refund returns to that are no longer drawable; priorDraws the refunded charges' draws already booked.
func computeDrawPlan(lots []*model.ComputeLot, otherLots map[operator.Id]*model.ComputeLot, priorDraws map[operator.Id][]*model.ComputeChargeDraw, charges []*model.ComputeCharge, now time.Time) *computeDraws {
	plan := &computeDraws{changes: map[operator.Id]*model.ComputeLotChange{}}
	ordered := []*computeDrawLot{}
	lotIdLots := map[operator.Id]*computeDrawLot{}
	for _, lot := range lots {
		drawLot := &computeDrawLot{lot: lot, remaining: lot.RemainingNanoUsd, drawable: true}
		ordered = append(ordered, drawLot)
		lotIdLots[lot.LotId] = drawLot
	}
	for lotId, lot := range otherLots {
		if _, ok := lotIdLots[lotId]; !ok {
			lotIdLots[lotId] = &computeDrawLot{lot: lot, remaining: lot.RemainingNanoUsd}
		}
	}
	batchDraws := map[operator.Id][]*model.ComputeChargeDraw{}
	for _, charge := range charges {
		amount := charge.AmountNanoUsd
		switch {
		case 0 < amount:
			left := amount
			index := int16(0)
			for _, drawLot := range ordered {
				if left == 0 {
					break
				}
				if drawLot.remaining <= 0 {
					continue
				}
				// a search draws only subscription and purchased lots (§9.11)
				if charge.Kind == model.ComputeChargeKindWebSearch && drawLot.lot.Kind == model.ComputeLotKindPromotion {
					continue
				}
				take := min(left, drawLot.remaining)
				drawLot.remaining -= take
				left -= take
				draw := &model.ComputeChargeDraw{ChargeId: charge.ChargeId, LotId: drawLot.lot.LotId, AmountNanoUsd: take, DrawIndex: index}
				index += 1
				plan.draws = append(plan.draws, draw)
				batchDraws[charge.ChargeId] = append(batchDraws[charge.ChargeId], draw)
				plan.change(drawLot.lot.LotId).RemainingDelta -= take
			}
			// what no lot covered stays in settled's negative, drawn from the next lot credited
			plan.settledDelta += amount
		case amount < 0 && charge.Kind == model.ComputeChargeKindAdjustment:
			// a support credit names no charge and draws no lot
			plan.settledDelta += amount
		case amount < 0:
			left := -amount
			prior := append(slices.Clone(priorDraws[charge.SubjectRef]), batchDraws[charge.SubjectRef]...)
			index := int16(0)
			forfeited := int64(0)
			for i := len(prior) - 1; 0 <= i && 0 < left; i -= 1 {
				draw := prior[i]
				if draw.AmountNanoUsd <= 0 {
					continue
				}
				give := min(left, draw.AmountNanoUsd)
				left -= give
				drawLot, ok := lotIdLots[draw.LotId]
				if !ok || drawLot.lot.ReversedTime != nil {
					// never back to a reversed lot: its part cancels what its reversal left owed
					continue
				}
				plan.draws = append(plan.draws, &model.ComputeChargeDraw{ChargeId: charge.ChargeId, LotId: draw.LotId, AmountNanoUsd: -give, DrawIndex: index})
				index += 1
				lot := drawLot.lot
				if lot.Kind == model.ComputeLotKindPromotion && lot.ExpireTime != nil && !lot.ExpireTime.After(now) {
					// a promotion past its expiry forfeits its part, which lapses as expiry does (Q-BAL-4)
					plan.change(lot.LotId).LapsedAddNanoUsd += give
					forfeited += give
					continue
				}
				plan.change(lot.LotId).RemainingDelta += give
				drawLot.remaining += give
			}
			plan.settledDelta += amount + forfeited
		}
	}
	return plan
}

// Step 3 for one network, under its fence: the drop script with the committed account, then the rows' delete, but the
// kept ones'. A drop that fails leaves the rows applied, for the next run.
func computeBookDrop(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, ops []*model.ComputeOp, now time.Time) error {
	db, err := env.Db()
	if err != nil {
		return err
	}
	dropOps := []*model.ComputeDropOp{}
	subjectIds := []operator.Id{}
	deleteKeys := []operator.Id{}
	for _, op := range ops {
		amount := int64(0)
		if op.Outcome != nil {
			amount = max(op.Outcome.AmountNanoUsd, 0)
		}
		dropOps = append(dropOps, &model.ComputeDropOp{OpKey: op.OpKey, AmountNanoUsd: amount})
		for _, subjectId := range op.SubjectIds() {
			if !slices.Contains(subjectIds, subjectId) {
				subjectIds = append(subjectIds, subjectId)
			}
		}
		if !model.ComputeOpKeptOnceBooked(op) {
			deleteKeys = append(deleteKeys, op.OpKey)
		}
	}
	return db.Tx(ctx, func(tx operator.DbTx) error {
		if err := model.ComputeFenceInTx(env, ctx, tx, networkId); err != nil {
			return err
		}
		account, err := model.ComputeAccountProjectionInTx(env, ctx, tx, networkId, now)
		if err != nil {
			return err
		}
		testHookBarrier("compute_book.drop.before", networkId.String())
		if _, err := model.ComputeProjectionDrop(env, ctx, settings, &model.ComputeDropRequest{
			NetworkId: networkId, Account: account, Ops: dropOps, SubjectIds: subjectIds,
		}); err != nil {
			return err
		}
		testHookBarrier("compute_book.drop.after", networkId.String())
		return model.ComputeOpDeleteAppliedInTx(env, ctx, tx, deleteKeys)
	}, operator.DbIsolationReadCommitted)
}
