// A deleted network's compute balance (DESIGN-COMPUTE §9.9's closed, §9.12; BAL-M12-14): ComputeCloseNetwork, the step
// of server's network removal (server's defaultNetworkRemoveSteps) that runs before the network is removed, while its
// billing contacts still read, and refuses the removal where it cannot finish, so a person retries.
//
// In one transaction under the network's fence: the account closed, so nothing credits it (ComputeCreditLot answers
// ErrComputeAccountClosed) and the projection's state refuses every hold; each Stripe lot that money bought,
// unreversed, within the settings' 90 days of its purchase, refunded its unspent whole cents (the lot keeping the
// amount, as a self-serve refund does); every other unspent credit forfeited, a store's whose refunds are the store's, an
// older lot's, a promotion's and the parts of a cent, which stay in their lots, unspendable; both auto-renew modes off;
// and the closure's notice owed to the billing contacts with what went back and what was forfeited. After the commit:
// the projection, the host's refunds, each once a lot, and the plan's subscription cancelled and the saved card
// detached, as Pro's subscriptions are cancelled at deletion. A closed account closes again as a retry: the same
// refunds and cancellations asked again, each once, and no second notice.
//
// A closed account is never reopened; ENC's removal stops a network's enclaves beside this step.

package controller

import (
	"context"
	"fmt"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// What a closure came to.
type ComputeCloseAnswer struct {
	// The network has an account, closed now or before.
	Closed bool
	// This call closed it; false for a retry or a network with no account.
	ClosedNow bool
	// What went back to cards, and what was forfeited.
	RefundedNanoUsd  int64
	ForfeitedNanoUsd int64
	// The lots refunded.
	RefundedLots []*model.ComputeLot
}

// Closes networkId's compute account (see the file header). A network with no account has nothing to close.
func ComputeCloseNetwork(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) (*ComputeCloseAnswer, error) {
	var zero operator.Id
	if networkId == zero {
		return nil, fmt.Errorf("%w: a closure names its network", ErrComputeRefundArgs)
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
	answer := &ComputeCloseAnswer{}
	var renewals []*model.ComputeAutoRenew
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		*answer = ComputeCloseAnswer{}
		renewals = nil
		if err := model.ComputeFenceInTx(env, ctx, tx, networkId); err != nil {
			return err
		}
		account, err := model.ComputeAccountInTx(env, ctx, tx, networkId)
		if err != nil || account == nil {
			return err
		}
		if _, err := model.ComputeAccountForUpdateInTx(env, ctx, tx, networkId, now); err != nil {
			return err
		}
		lots, err := model.ComputeNetworkLotsInTx(env, ctx, tx, networkId)
		if err != nil {
			return err
		}
		answer.Closed = true
		if account.State == model.ComputeAccountStateClosed {
			// a retry: the refunds its closure kept are asked of the host again below, once a lot
			for _, lot := range lots {
				if lot.RefundedNanoUsd != nil && computeLotStripePaid(lot) && now.Before(lot.CreateTime.Add(settings.ClosureRefundWindow)) {
					answer.RefundedLots = append(answer.RefundedLots, lot)
					answer.RefundedNanoUsd += *lot.RefundedNanoUsd
				}
			}
			renewals, err = model.ComputeAutoRenewOffInTx(env, ctx, tx, networkId, now)
			return err
		}
		refunded := int64(0)
		for _, lot := range lots {
			if lot.ReversedTime != nil || lot.RemainingNanoUsd <= 0 {
				continue
			}
			amount := computeWholeCents(lot.RemainingNanoUsd) * (model.ComputeCreditNanoUsd / 100)
			if computeLotStripePaid(lot) && lot.RefundedNanoUsd == nil && 0 < amount && now.Before(lot.CreateTime.Add(settings.ClosureRefundWindow)) {
				lot, moved, err := model.ComputeLotRefundInTx(env, ctx, tx, lot.LotId, amount)
				if err != nil {
					return err
				}
				if !moved {
					return fmt.Errorf("compute close: the lot locked for its refund did not move")
				}
				refunded += amount
				answer.RefundedLots = append(answer.RefundedLots, lot)
				answer.ForfeitedNanoUsd += lot.RemainingNanoUsd
				continue
			}
			answer.ForfeitedNanoUsd += lot.RemainingNanoUsd
		}
		answer.RefundedNanoUsd = refunded
		closed := model.ComputeAccountStateClosed
		if _, err := model.ComputeAccountMoveInTx(env, ctx, tx, networkId, -refunded, &closed, now); err != nil {
			return err
		}
		if renewals, err = model.ComputeAutoRenewOffInTx(env, ctx, tx, networkId, now); err != nil {
			return err
		}
		answer.ClosedNow = true
		return computeNoticeInTx(env, ctx, tx, &ComputeNotice{
			NetworkId: networkId, Kind: ComputeNoticeClosed, Key: "closed/" + networkId.String(),
			RefundedNanoUsd: answer.RefundedNanoUsd, ForfeitedNanoUsd: answer.ForfeitedNanoUsd,
		})
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	if !answer.Closed {
		return answer, nil
	}
	if answer.ClosedNow {
		computeProjectionRefresh(env, ctx, settings, networkId, now, true)
		computeHintDevices(env, ctx, networkId)
	}
	if 0 < len(answer.RefundedLots) {
		refunds := ComputeRegisteredStripeRefunds()
		if refunds == nil {
			return nil, ErrComputeStripeRefundUnavailable
		}
		for _, lot := range answer.RefundedLots {
			if err := refunds.RefundLot(ctx, &ComputeStripeLotRefund{
				PaymentIntentId: lot.MarketRef, LotId: lot.LotId, AmountCents: computeWholeCents(*lot.RefundedNanoUsd), Reason: ComputeRefundReasonClosure,
			}); err != nil {
				return nil, err
			}
		}
	}
	for _, renewal := range renewals {
		if renewal.Market != model.ComputeMarketStripe {
			continue
		}
		stripe := ComputeRegisteredStripeRenew()
		if (renewal.StripeSubscriptionId != nil || renewal.StripePaymentMethodId != nil) && stripe == nil {
			return nil, ErrComputeStripeRenewUnavailable
		}
		if renewal.StripeSubscriptionId != nil {
			if err := stripe.CancelSubscription(ctx, *renewal.StripeSubscriptionId); err != nil {
				return nil, err
			}
		}
		if renewal.StripePaymentMethodId != nil {
			if err := stripe.DetachCard(ctx, *renewal.StripePaymentMethodId); err != nil {
				return nil, err
			}
		}
	}
	return answer, nil
}
