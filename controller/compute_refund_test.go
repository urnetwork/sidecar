package controller

// Refunds, adjustments, disputes and closure as the sidecar repo sees them (BAL-M12-14): what each refuses before any
// store is asked, whole cents, the refund's and the adjustment's keys, and the store subscriptions a closure names and
// what covers them. The paths on real PostgreSQL and Redis run in server/computet3/compute_refund_t3_test.go.

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// A refund, a charge's refund, an adjustment, a dispute and a closure the ledger cannot take are refused before the
// database is asked.
func TestComputeRefundsRefuseBeforeAnyStore(t *testing.T) {
	env := newTestLedgerEnv()
	settings := model.DefaultComputeLedgerSettings()
	ctx := context.Background()
	networkId := sidecar.NewId()
	if _, err := ComputeRefundLot(env, ctx, settings, &ComputeRefundLotRequest{NetworkId: networkId}); !errors.Is(err, ErrComputeRefundArgs) {
		t.Errorf("a refund with no lot: %v", err)
	}
	if ComputeRegisteredStripeRefunds() == nil {
		if _, err := ComputeRefundLot(env, ctx, settings, &ComputeRefundLotRequest{NetworkId: networkId, LotId: sidecar.NewId()}); !errors.Is(err, ErrComputeStripeRefundUnavailable) {
			t.Errorf("a refund with no Stripe refunds: %v", err)
		}
	}
	for name, request := range map[string]*ComputeRefundChargeRequest{
		"no charge":         {},
		"a negative amount": {ChargeId: sidecar.NewId(), AmountNanoUsd: -1},
		"a negative cost":   {ChargeId: sidecar.NewId(), CostBackNanoUsd: -1},
	} {
		if _, err := ComputeRefundCharge(env, ctx, settings, request); !errors.Is(err, ErrComputeRefundArgs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	caseId := sidecar.NewId()
	for name, request := range map[string]*ComputeAdjustRequest{
		"no network":       {CaseId: caseId, Number: 1, AmountNanoUsd: 1},
		"no case":          {NetworkId: networkId, Number: 1, AmountNanoUsd: 1},
		"nothing":          {NetworkId: networkId, CaseId: caseId, Number: 1},
		"past the cap":     {NetworkId: networkId, CaseId: caseId, Number: 1, AmountNanoUsd: settings.BalanceCapNanoUsd + 1},
		"a credit past it": {NetworkId: networkId, CaseId: caseId, Number: 1, AmountNanoUsd: -settings.BalanceCapNanoUsd - 1},
	} {
		if _, err := ComputeAdjust(env, ctx, settings, request); !errors.Is(err, ErrComputeRefundArgs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, request := range map[string]*ComputeDisputeRequest{
		"no request":       {NetworkId: networkId, Provider: 1},
		"no provider":      {NetworkId: networkId, RequestId: sidecar.NewId()},
		"a negative count": {NetworkId: networkId, RequestId: sidecar.NewId(), Provider: 1, DeviceUnits: model.ComputeUnits{InputTokens: -1}},
	} {
		if _, err := ComputeDispute(env, ctx, settings, request); !errors.Is(err, ErrComputeRefundArgs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ComputeCloseNetwork(env, ctx, settings, sidecar.Id{}, nil); !errors.Is(err, ErrComputeRefundArgs) {
		t.Errorf("a closure of no network: %v", err)
	}
	if _, err := ComputeStoreSubscriptionsOf(env, ctx, settings, sidecar.Id{}); !errors.Is(err, ErrComputeRefundArgs) {
		t.Errorf("the store subscriptions of no network: %v", err)
	}
	if env.db.callCount != 0 {
		t.Fatalf("a refused call asked the database %d times", env.db.callCount)
	}
}

// Whole cents round down, so a part of a cent never goes back to a card; a refund's key is its charge's alone and an
// adjustment's its case's and number's.
func TestComputeRefundCentsAndKeys(t *testing.T) {
	for nanoUsd, cents := range map[int64]int64{0: 0, 9_999_999: 0, 10_000_000: 1, 4_996_000_000: 499, -5: 0} {
		if got := computeWholeCents(nanoUsd); got != cents {
			t.Errorf("%d nano-USD is %d cents, want %d", nanoUsd, got, cents)
		}
	}
	chargeId, caseId := sidecar.NewId(), sidecar.NewId()
	if ComputeOpKeyForRefund(chargeId) != ComputeOpKeyForRefund(chargeId) || ComputeOpKeyForRefund(chargeId) == ComputeOpKeyForRefund(sidecar.NewId()) {
		t.Error("a refund's key is not its charge's alone")
	}
	if ComputeOpKeyForAdjustment(caseId, 1) == ComputeOpKeyForAdjustment(caseId, 2) {
		t.Error("two numbers of a case share a key")
	}
}

// A closure's store subscriptions are the monthly row's, an App Store one by its original transaction id and a Play one
// by its token, and each App Store monthly grant within the window, newest first, once; other markets, kinds and older
// grants name none, and more grants than the count read as truncated.
func TestComputeStoreSubscriptionsNameTheRowAndRecentAppStoreGrants(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	settings.ClosureStoreGrantMaxCount = 3
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	networkId := sidecar.NewId()
	lot := func(kind model.ComputeLotKind, market model.ComputeMarket, marketRef string, age time.Duration) *model.ComputeLot {
		return &model.ComputeLot{LotId: sidecar.NewId(), NetworkId: networkId, Kind: kind, Market: market, MarketRef: marketRef, CreateTime: now.Add(-age)}
	}
	day := 24 * time.Hour
	lots := []*model.ComputeLot{
		lot(model.ComputeLotKindSubscription, model.ComputeMarketAppStore, "t-old", settings.ClosureStoreWindow+time.Second),
		lot(model.ComputeLotKindSubscription, model.ComputeMarketAppStore, "t-31", 31*day),
		lot(model.ComputeLotKindSubscription, model.ComputeMarketAppStore, "t-1", day),
		lot(model.ComputeLotKindPurchase, model.ComputeMarketAppStore, "t-consumable", day),
		lot(model.ComputeLotKindSubscription, model.ComputeMarketGooglePlay, "GPA.1", day),
		lot(model.ComputeLotKindSubscription, model.ComputeMarketStripe, "pi_x", day),
	}
	storeRef := "1000"
	apple := &model.ComputeAutoRenew{NetworkId: networkId, Mode: model.ComputeAutoRenewModeMonthly, Market: model.ComputeMarketAppStore, StoreRef: &storeRef}
	got := computeStoreSubscriptionsOf(settings, apple, lots, now)
	if !slices.Equal(got.AppStoreTransactionIds, []string{"1000", "t-1", "t-31"}) || len(got.GooglePlayPurchaseTokens) != 0 || got.Truncated {
		t.Fatalf("an App Store plan: %+v", got)
	}
	token := "token-a"
	play := &model.ComputeAutoRenew{NetworkId: networkId, Mode: model.ComputeAutoRenewModeMonthly, Market: model.ComputeMarketGooglePlay, StoreRef: &token}
	got = computeStoreSubscriptionsOf(settings, play, nil, now)
	if len(got.AppStoreTransactionIds) != 0 || !slices.Equal(got.GooglePlayPurchaseTokens, []string{"token-a"}) || got.Truncated {
		t.Fatalf("a Play plan: %+v", got)
	}
	// a grant named twice, as a plan change and its own row might, is asked about once
	lots = append(lots, lot(model.ComputeLotKindSubscription, model.ComputeMarketAppStore, "t-1", 2*day))
	got = computeStoreSubscriptionsOf(settings, nil, lots, now)
	if !slices.Equal(got.AppStoreTransactionIds, []string{"t-1", "t-31"}) || got.Truncated {
		t.Fatalf("a grant twice: %+v", got)
	}
	lots = append(lots, lot(model.ComputeLotKindSubscription, model.ComputeMarketAppStore, "t-2", 3*day))
	got = computeStoreSubscriptionsOf(settings, nil, lots, now)
	if !slices.Equal(got.AppStoreTransactionIds, []string{"t-1", "t-2"}) || !got.Truncated {
		t.Fatalf("past the count: %+v", got)
	}
	settings.ClosureStoreGrantMaxCount = 0
	if got := computeStoreSubscriptionsOf(settings, nil, lots, now); len(got.AppStoreTransactionIds) != 0 || !got.Truncated {
		t.Fatalf("a count of none: %+v", got)
	}
}

// What a closure finds is covered only by a read that names every subscription of it: none needs nothing, nil and a
// truncated read cover none, and one subscription more than was checked refuses.
func TestComputeStoreSubscriptionsCoveredOnlyByWhatWasChecked(t *testing.T) {
	none := &ComputeStoreSubscriptions{}
	checked := &ComputeStoreSubscriptions{AppStoreTransactionIds: []string{"1000", "t-1"}, GooglePlayPurchaseTokens: []string{"token-a"}}
	if !none.coveredBy(nil) || !none.coveredBy(checked) {
		t.Fatal("a network with no store subscription needs nothing covered")
	}
	for name, c := range map[string]struct {
		found   *ComputeStoreSubscriptions
		covered *ComputeStoreSubscriptions
		want    bool
	}{
		"the same":             {checked, checked, true},
		"fewer":                {&ComputeStoreSubscriptions{AppStoreTransactionIds: []string{"t-1"}}, checked, true},
		"nothing checked":      {checked, nil, false},
		"a grant since":        {&ComputeStoreSubscriptions{AppStoreTransactionIds: []string{"t-0", "1000", "t-1"}}, checked, false},
		"a Play plan since":    {&ComputeStoreSubscriptions{GooglePlayPurchaseTokens: []string{"token-b"}}, checked, false},
		"a truncated find":     {&ComputeStoreSubscriptions{Truncated: true}, checked, false},
		"a truncated checking": {&ComputeStoreSubscriptions{AppStoreTransactionIds: []string{"t-1"}}, &ComputeStoreSubscriptions{AppStoreTransactionIds: []string{"t-1"}, Truncated: true}, false},
	} {
		if got := c.found.coveredBy(c.covered); got != c.want {
			t.Errorf("%s: covered %v, want %v", name, got, c.want)
		}
	}
}
