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
// The stores' compute subscriptions are stopped before it, by the removal's store steps, as Pro's are
// (ComputeStoreSubscriptionsOf): each Play subscription cancelled, and the deletion held while an App Store one may
// renew, since only its holder can cancel it. The closure is handed what those steps checked and refuses, closing
// nothing, where its network names a store subscription they did not: one credited or reported since they read, as
// Pro's removal refuses a renewal credited during it (ErrComputeCloseStoresChanged). Once closed, the account takes no
// store grant or plan, so none can be added after.
//
// A closed account is never reopened; ENC's removal stops a network's enclaves beside this step.

package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// A store subscription the removal's store steps did not check stands for the network: a grant or a plan reported
// since they read, or a closure no store steps ran before. Nothing is closed, and the removal's retry checks it.
var ErrComputeCloseStoresChanged = errors.New("compute close: a store subscription the deletion's store steps did not check")

// The store subscriptions a network's closure stops or waits for (§9.12), as Pro's are at deletion (server's
// network_remove_providers.go): a Play subscription is cancelled, and an App Store one, which only its holder cancels,
// holds the deletion until the App Store says it will not renew.
type ComputeStoreSubscriptions struct {
	// A transaction of each App Store compute subscription that may still bill, by which the App Store's status API
	// answers for its subscription: the monthly row's original transaction id, then each App Store grant within the
	// settings' window, newest first, at most the settings' count.
	AppStoreTransactionIds []string
	// The monthly row's Play subscription.
	GooglePlayPurchaseTokens []string
	// More App Store grants in the window than the settings let a closure ask about: the App Store check counts the
	// network's subscriptions as renewing, so its deletion waits (fails closed).
	Truncated bool
}

// The store subscriptions monthly, the network's monthly row (nil for none), and lots, any of its lots in any order,
// name at now (see ComputeStoreSubscriptions): of the lots, the App Store's monthly grants within the window.
func computeStoreSubscriptionsOf(settings *model.ComputeLedgerSettings, monthly *model.ComputeAutoRenew, lots []*model.ComputeLot, now time.Time) *ComputeStoreSubscriptions {
	subscriptions := &ComputeStoreSubscriptions{AppStoreTransactionIds: []string{}, GooglePlayPurchaseTokens: []string{}}
	if monthly != nil && monthly.StoreRef != nil {
		switch monthly.Market {
		case model.ComputeMarketAppStore:
			subscriptions.AppStoreTransactionIds = append(subscriptions.AppStoreTransactionIds, *monthly.StoreRef)
		case model.ComputeMarketGooglePlay:
			subscriptions.GooglePlayPurchaseTokens = append(subscriptions.GooglePlayPurchaseTokens, *monthly.StoreRef)
		}
	}
	since := now.Add(-settings.ClosureStoreWindow)
	grants := []*model.ComputeLot{}
	for _, lot := range lots {
		if lot.Kind == model.ComputeLotKindSubscription && lot.Market == model.ComputeMarketAppStore && !lot.CreateTime.Before(since) {
			grants = append(grants, lot)
		}
	}
	// newest first, as ComputeStoreGrantsInTx reads them
	slices.SortStableFunc(grants, func(a *model.ComputeLot, b *model.ComputeLot) int {
		if c := b.CreateTime.Compare(a.CreateTime); c != 0 {
			return c
		}
		return bytes.Compare(a.LotId[:], b.LotId[:])
	})
	grantMaxCount := max(settings.ClosureStoreGrantMaxCount, 0)
	if grantMaxCount < len(grants) {
		grants = grants[:grantMaxCount]
		subscriptions.Truncated = true
	}
	for _, grant := range grants {
		if !slices.Contains(subscriptions.AppStoreTransactionIds, grant.MarketRef) {
			subscriptions.AppStoreTransactionIds = append(subscriptions.AppStoreTransactionIds, grant.MarketRef)
		}
	}
	return subscriptions
}

// Whether covered names every subscription self does: what a closure checks of the subscriptions it finds under its
// fence against those the removal's store steps checked. A network with none needs nothing covered; otherwise nil
// covers nothing, and a truncated read is never covered.
func (self *ComputeStoreSubscriptions) coveredBy(covered *ComputeStoreSubscriptions) bool {
	if len(self.AppStoreTransactionIds) == 0 && len(self.GooglePlayPurchaseTokens) == 0 && !self.Truncated {
		return true
	}
	if covered == nil || self.Truncated || covered.Truncated {
		return false
	}
	for _, transactionId := range self.AppStoreTransactionIds {
		if !slices.Contains(covered.AppStoreTransactionIds, transactionId) {
			return false
		}
	}
	for _, purchaseToken := range self.GooglePlayPurchaseTokens {
		if !slices.Contains(covered.GooglePlayPurchaseTokens, purchaseToken) {
			return false
		}
	}
	return true
}

// networkId's store subscriptions as they stand (see ComputeStoreSubscriptions): what the removal's store steps check
// before the closure, read once for all of them.
func ComputeStoreSubscriptionsOf(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id) (*ComputeStoreSubscriptions, error) {
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
	var subscriptions *ComputeStoreSubscriptions
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		monthly, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, networkId, model.ComputeAutoRenewModeMonthly, false)
		if err != nil {
			return err
		}
		// one past the count, so a window holding more reads as truncated
		grants, err := model.ComputeStoreGrantsInTx(env, ctx, tx, networkId, model.ComputeMarketAppStore, now.Add(-settings.ClosureStoreWindow), max(settings.ClosureStoreGrantMaxCount, 0)+1)
		if err != nil {
			return err
		}
		subscriptions = computeStoreSubscriptionsOf(settings, monthly, grants, now)
		return nil
	}, operator.DbIsolationReadCommitted, operator.DbReadOnly)
	if err != nil {
		return nil, err
	}
	return subscriptions, nil
}

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

// Closes networkId's compute account (see the file header). covered is what the removal's store steps checked, nil for
// none, which a network with a store subscription refuses (ErrComputeCloseStoresChanged). A network with no account
// has nothing to close.
func ComputeCloseNetwork(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, covered *ComputeStoreSubscriptions) (*ComputeCloseAnswer, error) {
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
		// a store grant or plan the removal's store steps did not check refuses the closure, which then changes nothing
		monthly, err := model.ComputeAutoRenewGetInTx(env, ctx, tx, networkId, model.ComputeAutoRenewModeMonthly, true)
		if err != nil {
			return err
		}
		if !computeStoreSubscriptionsOf(settings, monthly, lots, now).coveredBy(covered) {
			return ErrComputeCloseStoresChanged
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
