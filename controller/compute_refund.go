// Refunds and adjustments (DESIGN-COMPUTE §9.6, §9.12, D-BAL-14; BAL-M12-14): two different things, a lot's money back
// and a charge's credit back, and a support case's credit or debit.
//
//	ComputeRefundLot     a self-serve refund (§9.12): a Stripe lot's unspent remaining, within the settings' 30 days of
//	                     its purchase, back to its card, for an Owner or a Billing admin (the route's frame checks the
//	                     role and the untagged member device). In one transaction under the network's fence the lot
//	                     keeps the amount (refunded_nano_usd, compute-plan-money-schema-gaps, QD-1252), its remaining
//	                     falls by it and so does settled; then the host's partial refund on the lot's PaymentIntent,
//	                     idempotent by the lot, so a retry answers its first result and refunds nothing twice. Whole
//	                     cents go back; a part of a cent stays in the lot to spend. A store's lot, a promotion, an
//	                     operator's credit, a reversed lot and one past 30 days are refused not_refundable: a store's
//	                     refunds are the store's, which reverse the lot (§9.12)
//	ComputeRefundCharge  a charge's credit back (§9.6): `sidecarctl compute adjust --refund` and an upheld dispute write
//	                     a negative charge of the refunded kind, its subject the refunded charge, carrying its member,
//	                     agent, model, provider and enclave, under the refunded charge's UUIDv5 key and its first
//	                     write's time, so a retry, a dispute's refund racing an operator's, or a retry past UTC midnight
//	                     meets the claim and books once at its first time, never reopening a closed day; the booking
//	                     returns it to the lots the charge drew, in reverse draw order (compute_book.go). Its cost moves
//	                     only as far as the provider's bill moved, zero at URnetwork's cost. A charge whose row is gone
//	                     (its 90 days, a search's 72 hours) is answered gone: a support credit instead. A dispute's
//	                     refund names its request, and a charge of another subject is refused
//	ComputeAdjust        a support credit or debit (kind 5): its subject the support case, a nil sidecar, provider 0,
//	                     the network's own line, its key the UUIDv5 of the case and its number, so the same number run
//	                     again adds nothing
//
// The Stripe refund is the host's (ComputeStripeRefunds, server's ComputeServerStripe), since this repository links no
// Stripe client; a host that registered none refuses every self-serve refund before anything moves (fails closed).
// Every refund the ledger makes names itself in its metadata, so its charge.refunded books nothing more.

package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// Why a refund was refused (§9.12), the code the device's client reads.
type ComputeRefundRefusal string

const (
	// Not a Stripe purchase or subscription grant, a promotion, reversed, past its window, another network's, or with
	// nothing unspent.
	ComputeRefundRefusalNotRefundable ComputeRefundRefusal = "not_refundable"
)

// Why the ledger asks a refund of the host: identifiers its metadata carries.
const (
	ComputeRefundReasonSelfServe = "self_serve"
	ComputeRefundReasonClosure   = "closure"
)

var (
	// A refund or adjustment the ledger cannot take: no lot, no charge, an amount out of its bounds.
	ErrComputeRefundArgs = errors.New("compute refund: arguments refused")
	// The host registered no Stripe refunds: no self-serve or closure refund moves (fails closed).
	ErrComputeStripeRefundUnavailable = errors.New("compute refund: this host holds no Stripe refunds")
)

// One lot's money back to its card.
type ComputeStripeLotRefund struct {
	// The lot's PaymentIntent (its market_ref), the lot, and the whole cents back.
	PaymentIntentId string
	LotId           operator.Id
	AmountCents     int64
	// self_serve or closure.
	Reason string
}

// The host's Stripe refunds (server's ComputeServerStripe). Implementations are safe for concurrent use.
type ComputeStripeRefunds interface {
	// Refunds request on its PaymentIntent, once a lot: a lot refunded before is no second refund.
	RefundLot(ctx context.Context, request *ComputeStripeLotRefund) error
}

var (
	computeRefundLock    sync.Mutex
	computeStripeRefunds ComputeStripeRefunds
)

// Registers the host's Stripe refunds, once a process. A second registration, or a nil one, panics.
func RegisterComputeStripeRefunds(refunds ComputeStripeRefunds) {
	if refunds == nil {
		panic("compute refund: nil Stripe refunds")
	}
	computeRefundLock.Lock()
	defer computeRefundLock.Unlock()
	if computeStripeRefunds != nil {
		panic("compute refund: the Stripe refunds are registered once")
	}
	computeStripeRefunds = refunds
}

// The registered Stripe refunds, nil until registered.
func ComputeRegisteredStripeRefunds() ComputeStripeRefunds {
	computeRefundLock.Lock()
	defer computeRefundLock.Unlock()
	return computeStripeRefunds
}

// nano-USD in whole cents, rounded down: what a card can be given back.
func computeWholeCents(nanoUsd int64) int64 {
	return max(nanoUsd, 0) / (model.ComputeCreditNanoUsd / 100)
}

// Whether lot is a Stripe lot that money bought, a purchase or a subscription grant, and not reversed.
func computeLotStripePaid(lot *model.ComputeLot) bool {
	return lot.Market == model.ComputeMarketStripe && lot.Kind.Paid() && lot.ReversedTime == nil
}

// One self-serve refund (POST api/compute/refund), as the route reads it.
type ComputeRefundLotRequest struct {
	NetworkId operator.Id
	LotId     operator.Id
}

// What a self-serve refund came to.
type ComputeRefundLotAnswer struct {
	Refusal ComputeRefundRefusal
	// The lot as it stands after.
	Lot *model.ComputeLot
	// What went back to the card, this call's or the first's.
	RefundedNanoUsd int64
	// Whether this call refunded it; false for a retry, which answers the first result.
	Refunded bool
}

// Refunds request's lot (see the file header).
func ComputeRefundLot(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeRefundLotRequest) (*ComputeRefundLotAnswer, error) {
	var zero operator.Id
	if request.NetworkId == zero || request.LotId == zero {
		return nil, fmt.Errorf("%w: a refund names its network and lot", ErrComputeRefundArgs)
	}
	refunds := ComputeRegisteredStripeRefunds()
	if refunds == nil {
		return nil, ErrComputeStripeRefundUnavailable
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
	answer := &ComputeRefundLotAnswer{}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		*answer = ComputeRefundLotAnswer{}
		if err := model.ComputeFenceInTx(env, ctx, tx, request.NetworkId); err != nil {
			return err
		}
		lot, err := model.ComputeLotForUpdateInTx(env, ctx, tx, request.LotId)
		if err != nil {
			return err
		}
		if lot == nil || lot.NetworkId != request.NetworkId || !computeLotStripePaid(lot) {
			answer.Refusal = ComputeRefundRefusalNotRefundable
			return nil
		}
		answer.Lot = lot
		if lot.RefundedNanoUsd != nil {
			// a retry: the first result, whose Stripe refund is asked again below, once a lot
			answer.RefundedNanoUsd = *lot.RefundedNanoUsd
			return nil
		}
		amount := computeWholeCents(lot.RemainingNanoUsd) * (model.ComputeCreditNanoUsd / 100)
		if amount <= 0 || !now.Before(lot.CreateTime.Add(settings.RefundWindow)) {
			answer.Refusal = ComputeRefundRefusalNotRefundable
			return nil
		}
		if _, err := model.ComputeAccountForUpdateInTx(env, ctx, tx, request.NetworkId, now); err != nil {
			return err
		}
		refunded, moved, err := model.ComputeLotRefundInTx(env, ctx, tx, lot.LotId, amount)
		if err != nil {
			return err
		}
		if !moved {
			return fmt.Errorf("compute refund: the lot locked for its refund did not move")
		}
		if _, err := model.ComputeAccountMoveInTx(env, ctx, tx, request.NetworkId, -amount, nil, now); err != nil {
			return err
		}
		*answer = ComputeRefundLotAnswer{Lot: refunded, RefundedNanoUsd: amount, Refunded: true}
		return nil
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	if answer.Refusal != "" {
		return answer, nil
	}
	if answer.Refunded {
		computeProjectionRefresh(env, ctx, settings, request.NetworkId, now, true)
		computeStateReview(env, ctx, settings, request.NetworkId)
	}
	// the money back to the card, after the ledger holds it: a failure is answered, and a retry asks again
	if err := refunds.RefundLot(ctx, &ComputeStripeLotRefund{
		PaymentIntentId: answer.Lot.MarketRef, LotId: answer.Lot.LotId, AmountCents: computeWholeCents(answer.RefundedNanoUsd),
		Reason: ComputeRefundReasonSelfServe,
	}); err != nil {
		return nil, err
	}
	return answer, nil
}

// One charge's credit back (§9.6).
type ComputeRefundChargeRequest struct {
	// The charge's network, where the caller knows it; nil looks the charge up by its id alone.
	NetworkId *operator.Id
	ChargeId  operator.Id
	// How much of the charge to return; zero for all of it.
	AmountNanoUsd int64
	// How far URnetwork's cost moves back: what the provider's bill moved; zero for a refund at URnetwork's cost.
	CostBackNanoUsd int64
	// Where set, the charge must be this request's: an upheld dispute refunds only the charge of the call it disputed,
	// never another charge its device named.
	SubjectRef *operator.Id
}

// What a charge's refund came to.
type ComputeRefundChargeAnswer struct {
	// The charge's row is gone, past its retention: a support credit refunds it instead.
	Gone bool
	// The refunded charge.
	Charge *model.ComputeCharge
	// The refund's row, written now or claimed before, with its first write's start and outcome.
	Write *ComputeWriteAnswer
}

// Refunds request's charge (see the file header).
func ComputeRefundCharge(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeRefundChargeRequest) (*ComputeRefundChargeAnswer, error) {
	var zero operator.Id
	if request.ChargeId == zero || request.AmountNanoUsd < 0 || request.CostBackNanoUsd < 0 {
		return nil, fmt.Errorf("%w: a charge's refund names its charge, with no negative amount", ErrComputeRefundArgs)
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
	var charge *model.ComputeCharge
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		charge, err = model.ComputeChargeGetInTx(env, ctx, tx, request.NetworkId, request.ChargeId, now.Add(-settings.ChargeRetention))
		return err
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	if err != nil {
		return nil, err
	}
	if charge == nil {
		return &ComputeRefundChargeAnswer{Gone: true}, nil
	}
	if charge.AmountNanoUsd <= 0 || charge.Kind == model.ComputeChargeKindAdjustment {
		return nil, fmt.Errorf("%w: only a positive charge of a service is refunded; a support debit takes a support credit", ErrComputeRefundArgs)
	}
	if request.SubjectRef != nil && charge.SubjectRef != *request.SubjectRef {
		return nil, fmt.Errorf("%w: the charge is not the disputed request's", ErrComputeRefundArgs)
	}
	amount := request.AmountNanoUsd
	if amount == 0 {
		amount = charge.AmountNanoUsd
	}
	if charge.AmountNanoUsd < amount || charge.CostNanoUsd < request.CostBackNanoUsd {
		return nil, fmt.Errorf("%w: a refund returns at most its charge and its cost", ErrComputeRefundArgs)
	}
	write, err := ComputeWriteSettled(env, ctx, settings, &ComputeSettledWrite{
		NetworkId:  charge.NetworkId,
		OpKey:      ComputeOpKeyForRefund(charge.ChargeId),
		Kind:       charge.Kind,
		SubjectRef: charge.ChargeId,
		SidecarId:  charge.SidecarId,
		AgentId:    charge.AgentId,
		MemberId:   charge.MemberId,
		EnclaveId:  charge.EnclaveId,
		CatalogId:  charge.CatalogId,
		Provider:   charge.Provider,
		StartTime:  now,
		Outcome: &ComputeOutcome{
			AmountNanoUsd: -amount, CostNanoUsd: -request.CostBackNanoUsd, EndTime: now, SettleTime: now,
		},
	})
	if err != nil {
		return nil, err
	}
	return &ComputeRefundChargeAnswer{Charge: charge, Write: write}, nil
}

// One support credit or debit (kind 5).
type ComputeAdjustRequest struct {
	NetworkId operator.Id
	// The support case and the adjustment's number in it: its key.
	CaseId operator.Id
	Number uint32
	// A debit positive, a credit negative; at most the settings' balance cap either way.
	AmountNanoUsd int64
}

// Writes request's adjustment (see the file header): its row written now, or the claim of the case and number made
// before, answered with its first write.
func ComputeAdjust(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeAdjustRequest) (*ComputeWriteAnswer, error) {
	var zero operator.Id
	if request.NetworkId == zero || request.CaseId == zero || request.AmountNanoUsd == 0 ||
		settings.BalanceCapNanoUsd < request.AmountNanoUsd || request.AmountNanoUsd < -settings.BalanceCapNanoUsd {
		return nil, fmt.Errorf("%w: an adjustment names its network and case, and a credit or debit within the balance cap", ErrComputeRefundArgs)
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	return ComputeWriteSettled(env, ctx, settings, &ComputeSettledWrite{
		NetworkId:  request.NetworkId,
		OpKey:      ComputeOpKeyForAdjustment(request.CaseId, request.Number),
		Kind:       model.ComputeChargeKindAdjustment,
		SubjectRef: request.CaseId,
		StartTime:  now,
		Outcome:    &ComputeOutcome{AmountNanoUsd: request.AmountNanoUsd, EndTime: now, SettleTime: now},
	})
}
