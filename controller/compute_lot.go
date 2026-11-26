// Lots (DESIGN-COMPUTE §9.4, §9.5, §9.11, §9.12, D-BAL-10, IC-4; BAL-M12-07): crediting a lot once and reversing one,
// each in one transaction under the network's fence, which compute_settle's booking and the lost cache's rebuild also
// take, then the projection through the drop script's version guard, as a booking's drop does.
//
//	ComputeCreditLot   a lot under UNIQUE (market, market_ref), so a webhook replayed twice credits once: a replay
//	                   answers the lot that stands and credits nothing. The account's settled balance rises by the
//	                   lot and its version by one; any overrun, charges no lot paid that left settled below the lots'
//	                   remaining, is drawn from the new lot at once, its draws written for the charges it pays, so a
//	                   later refund knows what the lot paid for (§9.4's "drawn from the next lot credited"); a
//	                   purchase is counted to its payer. A store purchase, whose payer was known only after the store
//	                   took the money, is credited whatever the limits say, and flagged for review past one.
//	ComputeReverseLot  a store's refund or a chargeback (§9.12): the lot's reversed_time set and its remaining
//	                   removed, while what it paid for stays charged and is owed, so settled falls by the lot's whole
//	                   paid amount and may go negative; what other unreversed lots have left pays what it can of that
//	                   at once, as booking would have drawn them. A chargeback also suspends the network's compute and
//	                   lapses its promotional lots at once (§9.11).
//
// A promotion pays no overrun: it pays no search (§9.11), and a reversed purchase's debt is not free credit's to settle,
// so a promotion's credit leaves the overrun where it stands, and what of the promotion is left lapses with it.
//
// The compute and the transfer balance share no table, and nothing here converts between them (IC-4). A lot names no
// payer, and no row joins a payer to a network.

package controller

import (
	"context"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// The alarm kind of a store purchase flagged for review.
const ComputeAlarmPurchaseFlagged = "purchase_flagged"

// One credit to write (§9.4, §9.5).
type ComputeCreditRequest struct {
	NetworkId operator.Id
	Kind      model.ComputeLotKind
	Market    model.ComputeMarket
	// The PaymentIntent's id, the App Store's transaction id, Play's order id (never its purchase token, which a
	// subscription keeps across renewals), a redemption's id, or an operator's case.
	MarketRef     string
	AmountNanoUsd int64
	// A promotion's lapse; nil for the rest.
	ExpireTime *time.Time
	// The payer's keyed hash (ComputePayerHash), whose limits a purchase counts to: a Stripe card's or an App Store
	// account's. nil for a Play purchase, which counts to its network alone, a promotion and an operator's credit.
	PayerHash []byte
	// A store purchase: the store took the money before its payer was known, so it is credited whatever the limits
	// say and flagged for review past one. A Stripe purchase was checked before payment (ComputePurchaseCheck).
	Store bool
}

// What a credit did.
type ComputeCreditAnswer struct {
	// The lot of the request's (market, market_ref): credited now, or by an earlier delivery of a replay.
	Lot *model.ComputeLot
	// This call credited it; false for a replay, which credits nothing.
	Credited bool
	// What of the lot paid the network's overrun at once (§9.4).
	OverrunDrawnNanoUsd int64
	// A store purchase past a limit: credited, and flagged for review; the limits it passed.
	Flagged  bool
	Breaches []*ComputeLimitBreach
	// The account the credit left.
	Account *model.ComputeAccount
	// The projection took the account; where it did not, the next booking's drop or a rebuild brings it.
	Projected bool
}

// Checks request as one of §9.4's lots.
func computeCreditCheck(request *ComputeCreditRequest) error {
	var zero operator.Id
	if request.NetworkId == zero || !request.Kind.Valid() || !request.Market.Valid() || request.MarketRef == "" {
		return fmt.Errorf("%w: a credit names its network, kind, market and reference", ErrComputeLedgerArgs)
	}
	if request.AmountNanoUsd <= 0 {
		return fmt.Errorf("%w: a credit's amount is positive", ErrComputeLedgerArgs)
	}
	promotion := request.Kind == model.ComputeLotKindPromotion
	if promotion != (request.Market == model.ComputeMarketPromotion) || promotion != (request.ExpireTime != nil) {
		return fmt.Errorf("%w: a promotion, and only one, is the promotion market's and lapses", ErrComputeLedgerArgs)
	}
	if request.PayerHash != nil && !request.Kind.Paid() {
		return fmt.Errorf("%w: only a purchase counts to a payer", ErrComputeLedgerArgs)
	}
	if request.Store && request.Market != model.ComputeMarketAppStore && request.Market != model.ComputeMarketGooglePlay {
		return fmt.Errorf("%w: a store purchase is the App Store's or Play's", ErrComputeLedgerArgs)
	}
	return nil
}

// Credits request's lot in tx, which holds the network's fence (see the file header): the one place a lot is written,
// for a purchase, a subscription's grant, a promotion's redemption and an operator's credit.
func computeCreditLotInTx(env operator.Env, ctx context.Context, tx operator.DbTx, settings *model.ComputeLedgerSettings, request *ComputeCreditRequest, now time.Time) (*ComputeCreditAnswer, error) {
	answer := &ComputeCreditAnswer{}
	if request.Store {
		// read before the lot is written, so the purchase counts once among what the limits sum
		breaches, err := computeLoadBreachesInTx(env, ctx, tx, settings, &computeLoad{
			networkId: request.NetworkId, payerHash: request.PayerHash, amount: request.AmountNanoUsd, purchase: request.Kind.Paid(),
		}, now)
		if err != nil {
			return nil, err
		}
		answer.Breaches = breaches
	}
	lot := &model.ComputeLot{
		LotId:            sidecar.NewId(),
		NetworkId:        request.NetworkId,
		Kind:             request.Kind,
		Market:           request.Market,
		MarketRef:        request.MarketRef,
		AmountNanoUsd:    request.AmountNanoUsd,
		RemainingNanoUsd: request.AmountNanoUsd,
		CreateTime:       now.UTC(),
	}
	if request.ExpireTime != nil {
		expire := request.ExpireTime.UTC()
		lot.ExpireTime = &expire
	}
	inserted, stands, err := model.ComputeLotInsertInTx(env, ctx, tx, lot)
	if err != nil {
		return nil, err
	}
	if !inserted {
		// a replay: the first delivery's lot, nothing credited, nothing flagged again
		return &ComputeCreditAnswer{Lot: stands}, nil
	}
	if _, err := model.ComputeAccountForUpdateInTx(env, ctx, tx, request.NetworkId, now); err != nil {
		return nil, err
	}
	account, err := model.ComputeAccountMoveInTx(env, ctx, tx, request.NetworkId, request.AmountNanoUsd, nil, now)
	if err != nil {
		return nil, err
	}
	if request.Kind != model.ComputeLotKindPromotion {
		drawn, err := computeDrawOverrunInTx(env, ctx, tx, settings, request.NetworkId, account.SettledNanoUsd, []*model.ComputeLot{stands}, now)
		if err != nil {
			return nil, err
		}
		answer.OverrunDrawnNanoUsd = drawn
		stands.RemainingNanoUsd -= drawn
	}
	if request.PayerHash != nil {
		if err := model.ComputePayerRecordInTx(env, ctx, tx, request.PayerHash, request.AmountNanoUsd, now); err != nil {
			return nil, err
		}
	}
	answer.Lot = stands
	answer.Credited = true
	answer.Account = account
	answer.Flagged = 0 < len(answer.Breaches)
	return answer, nil
}

// Draws what it can of networkId's overrun from sources in tx: the overrun is what the lots have left past settled,
// which after the change in hand is the charges no unreversed lot paid; sources pay the oldest of those charges first,
// each in its order, up to what they have left and what the overrun is, and each draw is written for the charge it
// pays, after the charge's own. What it drew in all. An overrun no charge is found for within the settings' bound and
// the charges' retention stays in settled's negative, for the next lot.
func computeDrawOverrunInTx(env operator.Env, ctx context.Context, tx operator.DbTx, settings *model.ComputeLedgerSettings, networkId operator.Id, settled int64, sources []*model.ComputeLot, now time.Time) (int64, error) {
	remaining, err := model.ComputeLotsRemainingInTx(env, ctx, tx, networkId)
	if err != nil {
		return 0, err
	}
	overrun := remaining - settled
	available := int64(0)
	for _, source := range sources {
		available += max(source.RemainingNanoUsd, 0)
	}
	budget := min(overrun, available)
	if budget <= 0 {
		return 0, nil
	}
	charges, err := model.ComputeUncoveredChargesInTx(env, ctx, tx, networkId, now.Add(-settings.ChargeRetention), settings.OverrunDrawMaxChargeCount)
	if err != nil {
		return 0, err
	}
	left := map[operator.Id]int64{}
	for _, source := range sources {
		left[source.LotId] = max(source.RemainingNanoUsd, 0)
	}
	draws := []*model.ComputeChargeDraw{}
	changes := map[operator.Id]*model.ComputeLotChange{}
	drawn := int64(0)
	for _, charge := range charges {
		owed := charge.UncoveredNanoUsd
		index := charge.LastDrawIndex + 1
		for _, source := range sources {
			if budget <= 0 || owed <= 0 {
				break
			}
			take := min(owed, left[source.LotId], budget)
			if take <= 0 {
				continue
			}
			draws = append(draws, &model.ComputeChargeDraw{ChargeId: charge.ChargeId, LotId: source.LotId, AmountNanoUsd: take, DrawIndex: index})
			index += 1
			left[source.LotId] -= take
			owed -= take
			budget -= take
			drawn += take
			change, ok := changes[source.LotId]
			if !ok {
				change = &model.ComputeLotChange{LotId: source.LotId}
				changes[source.LotId] = change
			}
			change.RemainingDelta -= take
		}
		if budget <= 0 {
			break
		}
	}
	if err := model.ComputeDrawsInsertInTx(env, ctx, tx, draws); err != nil {
		return 0, err
	}
	lotChanges := []*model.ComputeLotChange{}
	for _, change := range changes {
		lotChanges = append(lotChanges, change)
	}
	if err := model.ComputeLotsChangeInTx(env, ctx, tx, lotChanges); err != nil {
		return 0, err
	}
	return drawn, nil
}

// Credits request's lot (see the file header): in one transaction under the network's fence, then the projection.
// A replay answers the lot that stands, credited false.
func ComputeCreditLot(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeCreditRequest) (*ComputeCreditAnswer, error) {
	if err := computeCreditCheck(request); err != nil {
		return nil, err
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	var answer *ComputeCreditAnswer
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		if err := model.ComputeFenceInTx(env, ctx, tx, request.NetworkId); err != nil {
			return err
		}
		var err error
		answer, err = computeCreditLotInTx(env, ctx, tx, settings, request, now)
		return err
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	if answer.Flagged {
		computeAlarm(env)(ComputeAlarmPurchaseFlagged)
	}
	if answer.Credited {
		answer.Projected = computeProjectionRefresh(env, ctx, settings, request.NetworkId, now, false)
	}
	return answer, nil
}

// Takes networkId's committed account into its projection through the drop script's version guard, under the
// network's fence, as a booking's drop does: a projection with a newer version is left, an absent one waits for its
// rebuild. Whether the projection now holds the account. Where a fall in the balance (lower) did not reach it, the
// projection is marked for a rebuild, so it admits nothing on credit it no longer has.
func computeProjectionRefresh(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, now time.Time, lower bool) bool {
	db, err := env.Db()
	if err != nil {
		return false
	}
	projected := false
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		projected = false
		if err := model.ComputeFenceInTx(env, ctx, tx, networkId); err != nil {
			return err
		}
		account, err := model.ComputeAccountProjectionInTx(env, ctx, tx, networkId, now)
		if err != nil {
			return err
		}
		testHookBarrier("compute_lot.projection.before", networkId.String())
		if _, err := model.ComputeProjectionDrop(env, ctx, settings, &model.ComputeDropRequest{NetworkId: networkId, Account: account}); err != nil {
			return err
		}
		testHookBarrier("compute_lot.projection.after", networkId.String())
		projected = true
		return nil
	}, operator.DbIsolationReadCommitted)
	if err != nil && lower {
		model.ComputeProjectionMarkRebuild(env, ctx, networkId)
	}
	return err == nil && projected
}

// One reversal (§9.12).
type ComputeReverseRequest struct {
	Market    model.ComputeMarket
	MarketRef string
	// A chargeback: beside the reversal, the network's compute suspended and its promotional lots lapsed at once
	// (§9.11). A store's refund is no chargeback.
	Chargeback bool
}

// What a reversal did.
type ComputeReverseAnswer struct {
	// The lot of the reference, as it stands after; nil where no lot was credited for it, which reverses nothing.
	Lot *model.ComputeLot
	// This call reversed it; false where it stood reversed, which changes nothing.
	Reversed bool
	// What the lot had left, removed, and what it had paid for, which stays charged and is owed.
	RemovedNanoUsd int64
	OwedNanoUsd    int64
	// What other lots paid of that at once, and what of the network's promotions a chargeback lapsed.
	OverrunDrawnNanoUsd int64
	LapsedNanoUsd       int64
	// The account the reversal left.
	Account   *model.ComputeAccount
	Projected bool
}

// Reverses request's lot (see the file header): a store's refund or a chargeback. A lot already reversed is answered as
// it stands; no lot for the reference answers a nil Lot, reversing nothing. A promotion is no market's money and is
// never reversed: it lapses.
func ComputeReverseLot(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeReverseRequest) (*ComputeReverseAnswer, error) {
	if !request.Market.Valid() || request.Market == model.ComputeMarketPromotion || request.MarketRef == "" {
		return nil, fmt.Errorf("%w: a reversal names a market's money and its reference", ErrComputeLedgerArgs)
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	var answer *ComputeReverseAnswer
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		answer = &ComputeReverseAnswer{}
		// the network first, unlocked, so the fence is taken before any row lock, as a booking takes them
		found, err := model.ComputeLotByMarketRefInTx(env, ctx, tx, request.Market, request.MarketRef, false)
		if err != nil || found == nil {
			return err
		}
		if err := model.ComputeFenceInTx(env, ctx, tx, found.NetworkId); err != nil {
			return err
		}
		lot, err := model.ComputeLotByMarketRefInTx(env, ctx, tx, request.Market, request.MarketRef, true)
		if err != nil {
			return err
		}
		answer.Lot = lot
		if lot.ReversedTime != nil {
			return nil
		}
		if _, err := model.ComputeAccountForUpdateInTx(env, ctx, tx, lot.NetworkId, now); err != nil {
			return err
		}
		removed := lot.RemainingNanoUsd
		owed := lot.AmountNanoUsd - lot.RemainingNanoUsd
		if lot.LapsedNanoUsd != nil {
			owed -= *lot.LapsedNanoUsd
		}
		if lot.RefundedNanoUsd != nil {
			owed -= *lot.RefundedNanoUsd
		}
		owed = max(owed, 0)
		reversed, err := model.ComputeLotReverseInTx(env, ctx, tx, lot.LotId, now)
		if err != nil {
			return err
		}
		lapsed := int64(0)
		var state *model.ComputeAccountState
		if request.Chargeback {
			promotions, err := model.ComputeNetworkPromotionsInTx(env, ctx, tx, lot.NetworkId)
			if err != nil {
				return err
			}
			for _, promotion := range promotions {
				lapsedNow, err := model.ComputeLotLapseInTx(env, ctx, tx, promotion.LotId)
				if err != nil {
					return err
				}
				lapsed += lapsedNow
			}
			suspended := model.ComputeAccountStateSuspended
			state = &suspended
		}
		account, err := model.ComputeAccountMoveInTx(env, ctx, tx, lot.NetworkId, -(removed + owed + lapsed), state, now)
		if err != nil {
			return err
		}
		sources, err := model.ComputeOverrunLotsInTx(env, ctx, tx, lot.NetworkId, nil)
		if err != nil {
			return err
		}
		drawn, err := computeDrawOverrunInTx(env, ctx, tx, settings, lot.NetworkId, account.SettledNanoUsd, sources, now)
		if err != nil {
			return err
		}
		*answer = ComputeReverseAnswer{
			Lot: reversed, Reversed: true, RemovedNanoUsd: removed, OwedNanoUsd: owed, OverrunDrawnNanoUsd: drawn,
			LapsedNanoUsd: lapsed, Account: account,
		}
		return nil
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	if answer.Reversed {
		answer.Projected = computeProjectionRefresh(env, ctx, settings, answer.Lot.NetworkId, now, true)
	}
	return answer, nil
}

// Whether a chargeback suspended networkId's compute (§9.11): what the promotion route refuses by, and what §9.9's
// states (BAL-M12-12) keep suspended whatever the balance says, until a person's review.
func ComputeChargebackSuspended(env operator.Env, ctx context.Context, networkId operator.Id) (bool, error) {
	db, err := env.Db()
	if err != nil {
		return false, err
	}
	suspended := false
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		suspended, err = model.ComputeChargebackSuspendedInTx(env, ctx, tx, networkId)
		return err
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	return suspended, err
}
