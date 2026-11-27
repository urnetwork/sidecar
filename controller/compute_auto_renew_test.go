package controller

// Auto-renew as the sidecar repo sees it (BAL-M12-11): threshold's figures and their bounds, the day's and month's
// counts rolling over at UTC midnight and month, a top-up's idempotency key fixed by its network, day, attempt and pack,
// the run's cursor round trip, what a change refuses before any store is asked, and what a store subscription's report
// does to the network's monthly row. The runs on real PostgreSQL and Redis, with a fake Stripe and clock, are
// server/computet3/compute_auto_renew_t3_test.go's.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// A zero figure takes the fallback's; T and L stay within the balance cap, P is a positive pack up to the largest one
// sold, and L holds at least one P.
func TestComputeThresholdFiguresKeepTheirBounds(t *testing.T) {
	settings := model.DefaultComputeLedgerSettings()
	defaults := computeThresholdDefaults(settings)
	figures, err := computeThresholdFiguresOf(settings, defaults, 0, 0, 0)
	if err != nil || *figures != *defaults {
		t.Fatalf("all zero: %+v %v", figures, err)
	}
	if figures, err := computeThresholdFiguresOf(settings, defaults, 7*model.ComputeCreditNanoUsd, 30, 0); err != nil ||
		figures.belowNanoUsd != 7*model.ComputeCreditNanoUsd || figures.packCredits != 30 || figures.monthLimitNanoUsd != settings.ThresholdMonthLimitNanoUsd {
		t.Fatalf("T and P given: %+v %v", figures, err)
	}
	for name, args := range map[string][3]int64{
		"a pack past the largest":   {0, 501, 0},
		"L below one P":             {0, 100, 50 * model.ComputeCreditNanoUsd},
		"T past the cap":            {settings.BalanceCapNanoUsd + 1, 0, 0},
		"L past the cap":            {0, 0, settings.BalanceCapNanoUsd + 1},
		"a negative T":              {-1, 0, 0},
		"a pack below one credit":   {0, -1, 0},
		"L below the default's one": {0, 0, model.ComputeCreditNanoUsd},
	} {
		if _, err := computeThresholdFiguresOf(settings, defaults, args[0], args[1], args[2]); !errors.Is(err, ErrComputeAutoRenewArgs) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The day's top-ups and failures count only on their UTC day and the month's sum only in its UTC month, so a run after
// midnight starts the day at zero.
func TestComputeThresholdCountsRollOverInUtc(t *testing.T) {
	day := time.Date(2026, 11, 30, 0, 0, 0, 0, time.UTC)
	month := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	row := &model.ComputeAutoRenew{TopUpDay: &day, TopUpDayCount: 2, FailureDayCount: 1, TopUpMonth: &month, TopUpMonthNanoUsd: 40}
	if counts := computeThresholdCountsOf(row, time.Date(2026, 11, 30, 23, 59, 0, 0, time.UTC)); counts.topUpsToday != 2 || counts.failuresToday != 1 || counts.monthNanoUsd != 40 {
		t.Errorf("the same day: %+v", counts)
	}
	if counts := computeThresholdCountsOf(row, time.Date(2026, 12, 1, 0, 0, 1, 0, time.UTC)); counts.topUpsToday != 0 || counts.failuresToday != 0 || counts.monthNanoUsd != 0 {
		t.Errorf("past UTC midnight into a new month: %+v", counts)
	}
	// 23:30 at UTC-8 on November 30 is December 1 in UTC
	if counts := computeThresholdCountsOf(row, time.Date(2026, 11, 30, 23, 30, 0, 0, time.FixedZone("UTC-8", -8*60*60))); counts.topUpsToday != 0 {
		t.Errorf("a zone's evening read in its own day: %+v", counts)
	}
	written := &model.ComputeAutoRenew{}
	(&computeThresholdCounts{topUpsToday: 1, monthNanoUsd: 20}).into(written, time.Date(2026, 11, 30, 13, 0, 0, 0, time.UTC))
	if !written.TopUpDay.Equal(day) || !written.TopUpMonth.Equal(month) || written.TopUpDayCount != 1 || written.TopUpMonthNanoUsd != 20 {
		t.Errorf("written: %+v", written)
	}
}

// A top-up's key is a function of its network, UTC day, attempt and pack alone, so a run retried after a crash sends
// the same one and another attempt or pack another.
func TestComputeTopUpKeyIsFixedByItsAttempt(t *testing.T) {
	networkId := sidecar.NewId()
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	key := computeTopUpKey(networkId, now, 1, 20)
	if computeTopUpKey(networkId, now.Add(13*time.Hour), 1, 20) != key {
		t.Error("one UTC day's attempt changed its key")
	}
	for _, other := range []string{
		computeTopUpKey(networkId, now.Add(14*time.Hour), 1, 20),
		computeTopUpKey(networkId, now, 2, 20),
		computeTopUpKey(networkId, now, 1, 25),
		computeTopUpKey(sidecar.NewId(), now, 1, 20),
	} {
		if other == key {
			t.Errorf("another attempt shares the key %s", key)
		}
	}
}

// A run's cursor comes back from its args, and empty args begin a pass.
func TestComputeAutoRenewCursorRoundTrips(t *testing.T) {
	if cursor, err := ParseComputeAutoRenewCursor(nil); err != nil || cursor != nil {
		t.Fatalf("no args: %v %v", cursor, err)
	}
	id := sidecar.NewId()
	cursor, err := ParseComputeAutoRenewCursor(ComputeAutoRenewCursorArgs(&id))
	if err != nil || cursor == nil || *cursor != id {
		t.Fatalf("a cursor: %v %v", cursor, err)
	}
	if _, err := ParseComputeAutoRenewCursor([]byte("not an id")); !errors.Is(err, ErrComputeAutoRenewArgs) {
		t.Fatalf("args that are no id: %v", err)
	}
}

// A change §9.8 does not take is refused before any store is asked: no mode, one mode's figures on the other, a
// monthly plan not sold, a negative figure.
func TestComputeSetAutoRenewRefusesBeforeAnyStore(t *testing.T) {
	env := newTestLedgerEnv()
	settings := model.DefaultComputeLedgerSettings()
	networkId := sidecar.NewId()
	for name, change := range map[string]*ComputeAutoRenewChange{
		"no network":                    {Mode: model.ComputeAutoRenewModeThreshold, On: true},
		"no mode":                       {NetworkId: networkId, On: true},
		"a plan on threshold":           {NetworkId: networkId, Mode: model.ComputeAutoRenewModeThreshold, On: true, Credits: 25},
		"threshold's figures on a plan": {NetworkId: networkId, Mode: model.ComputeAutoRenewModeMonthly, On: true, PackCredits: 20},
		"a plan not sold":               {NetworkId: networkId, Mode: model.ComputeAutoRenewModeMonthly, On: true, Credits: 30},
		"a negative T":                  {NetworkId: networkId, Mode: model.ComputeAutoRenewModeThreshold, On: true, BelowNanoUsd: -1},
	} {
		if _, err := ComputeSetAutoRenew(env, context.Background(), settings, change); !errors.Is(err, ErrComputeAutoRenewArgs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if env.db.callCount != 0 {
		t.Fatalf("a refused change asked the database %d times", env.db.callCount)
	}
}

// A saved card that names no threshold, no payer or no card is refused, and so is a plan that names no subscription or
// a plan not sold; none reaches a store.
func TestComputeAutoRenewRecordsRefuseWhatTheyCannotTake(t *testing.T) {
	env := newTestLedgerEnv()
	settings := model.DefaultComputeLedgerSettings()
	networkId, memberId := sidecar.NewId(), sidecar.NewId()
	for name, saved := range map[string]*ComputeCardSaved{
		"monthly":    {NetworkId: networkId, PayerMemberId: memberId, Mode: model.ComputeAutoRenewModeMonthly, StripeCustomerId: "cus_x", StripePaymentMethodId: "pm_x"},
		"no payer":   {NetworkId: networkId, Mode: model.ComputeAutoRenewModeThreshold, StripeCustomerId: "cus_x", StripePaymentMethodId: "pm_x"},
		"no card":    {NetworkId: networkId, PayerMemberId: memberId, Mode: model.ComputeAutoRenewModeThreshold, StripeCustomerId: "cus_x"},
		"no network": {PayerMemberId: memberId, Mode: model.ComputeAutoRenewModeThreshold, StripeCustomerId: "cus_x", StripePaymentMethodId: "pm_x"},
	} {
		if err := (computeAutoRenewCardTaker{}).CardSaved(env, context.Background(), saved); !errors.Is(err, ErrComputeAutoRenewArgs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, subscription := range map[string]*ComputeMonthlySubscription{
		"no subscription": {NetworkId: networkId, PayerMemberId: memberId, Credits: 25, StripeCustomerId: "cus_x"},
		"a plan not sold": {NetworkId: networkId, PayerMemberId: memberId, Credits: 30, StripeCustomerId: "cus_x", StripeSubscriptionId: "sub_x"},
	} {
		if err := ComputeMonthlySubscribed(env, context.Background(), settings, subscription); !errors.Is(err, ErrComputeAutoRenewArgs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ComputeMonthlyGrant(env, context.Background(), settings, &ComputeMonthlyGrantRequest{NetworkId: networkId, PaymentIntentId: "pi_x", Credits: 30}); !errors.Is(err, ErrComputeAutoRenewArgs) {
		t.Errorf("a grant of a plan not sold: %v", err)
	}
	long := strings.Repeat("t", settings.StoreSubscriptionRefMaxByteCount+1)
	for name, report := range map[string]*ComputeStoreSubscriptionReport{
		"no network":          {Market: model.ComputeMarketGooglePlay, StoreRef: "token", Credits: 25, Renews: true},
		"Stripe's":            {NetworkId: networkId, Market: model.ComputeMarketStripe, StoreRef: "sub_x", Credits: 25, Renews: true},
		"no subscription":     {NetworkId: networkId, Market: model.ComputeMarketAppStore, Credits: 25, Renews: true},
		"no plan":             {NetworkId: networkId, Market: model.ComputeMarketAppStore, StoreRef: "1000", Renews: true},
		"a token past bounds": {NetworkId: networkId, Market: model.ComputeMarketGooglePlay, StoreRef: long, Credits: 25, Renews: true},
		"a replaced token past bounds": {
			NetworkId: networkId, Market: model.ComputeMarketGooglePlay, StoreRef: "token", ReplacesStoreRef: long, Credits: 25, Renews: true,
		},
	} {
		if _, err := ComputeMonthlyStoreReport(env, context.Background(), settings, report); !errors.Is(err, ErrComputeAutoRenewArgs) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if env.db.callCount != 0 {
		t.Fatalf("a refused record asked the database %d times", env.db.callCount)
	}
}

// A store subscription's report takes the network's monthly row where no plan renews or the row stands for it (or for
// the one it replaced), turning it on or off as it renews; leaves a renewing plan the row's, but for a Play
// subscription over an App Store one; and never records a stopped subscription the row does not stand for.
func TestComputeStoreReportKeepsOnePlanAndPrefersPlayOverTheAppStore(t *testing.T) {
	networkId := sidecar.NewId()
	ref := func(text string) *string {
		return &text
	}
	credits := func(count int64) *int64 {
		return &count
	}
	stripe := &model.ComputeAutoRenew{
		NetworkId: networkId, Mode: model.ComputeAutoRenewModeMonthly, Enabled: true, Market: model.ComputeMarketStripe,
		MonthlyCredits: credits(50), PayerMemberId: &networkId, StripeCustomerId: ref("cus_x"), StripeSubscriptionId: ref("sub_x"),
	}
	apple := &model.ComputeAutoRenew{
		NetworkId: networkId, Mode: model.ComputeAutoRenewModeMonthly, Enabled: true, Market: model.ComputeMarketAppStore,
		MonthlyCredits: credits(25), StoreRef: ref("1000"),
	}
	play := &model.ComputeAutoRenew{
		NetworkId: networkId, Mode: model.ComputeAutoRenewModeMonthly, Enabled: true, Market: model.ComputeMarketGooglePlay,
		MonthlyCredits: credits(25), StoreRef: ref("token-a"),
	}
	clone := func(row *model.ComputeAutoRenew, enabled bool) *model.ComputeAutoRenew {
		copied := *row
		copied.Enabled = enabled
		return &copied
	}
	report := func(market model.ComputeMarket, storeRef string, replaces string, plan int64, renews bool) *ComputeStoreSubscriptionReport {
		return &ComputeStoreSubscriptionReport{NetworkId: networkId, Market: market, StoreRef: storeRef, ReplacesStoreRef: replaces, Credits: plan, Renews: renews}
	}
	type want struct {
		recorded   bool
		concurrent bool
		// the row written: its store, subscription, plan and whether it renews
		market  model.ComputeMarket
		ref     string
		credits int64
		enabled bool
	}
	for name, c := range map[string]struct {
		monthly *model.ComputeAutoRenew
		report  *ComputeStoreSubscriptionReport
		want    want
	}{
		"no row, a plan that renews": {nil, report(model.ComputeMarketAppStore, "1000", "", 25, true),
			want{recorded: true, market: model.ComputeMarketAppStore, ref: "1000", credits: 25, enabled: true}},
		"no row, a stopped plan": {nil, report(model.ComputeMarketAppStore, "1000", "", 25, false), want{}},
		"its own row turned off": {apple, report(model.ComputeMarketAppStore, "1000", "", 25, false),
			want{recorded: true, market: model.ComputeMarketAppStore, ref: "1000", credits: 25, enabled: false}},
		"its own row downgraded": {apple, report(model.ComputeMarketAppStore, "1000", "", 10, true),
			want{recorded: true, market: model.ComputeMarketAppStore, ref: "1000", credits: 10, enabled: true}},
		"a Play replacement": {play, report(model.ComputeMarketGooglePlay, "token-b", "token-a", 50, true),
			want{recorded: true, market: model.ComputeMarketGooglePlay, ref: "token-b", credits: 50, enabled: true}},
		"over an ended Stripe plan": {clone(stripe, false), report(model.ComputeMarketGooglePlay, "token-a", "", 25, true),
			want{recorded: true, market: model.ComputeMarketGooglePlay, ref: "token-a", credits: 25, enabled: true}},
		"over a running Stripe plan":    {stripe, report(model.ComputeMarketGooglePlay, "token-a", "", 25, true), want{concurrent: true}},
		"a second App Store plan":       {apple, report(model.ComputeMarketAppStore, "2000", "", 25, true), want{concurrent: true}},
		"an App Store plan over Play's": {play, report(model.ComputeMarketAppStore, "1000", "", 25, true), want{concurrent: true}},
		"a second Play plan":            {play, report(model.ComputeMarketGooglePlay, "token-c", "", 25, true), want{concurrent: true}},
		"another subscription stops":    {apple, report(model.ComputeMarketAppStore, "2000", "", 25, false), want{}},
		"another store's plan over one off": {clone(apple, false), report(model.ComputeMarketGooglePlay, "token-a", "", 25, true),
			want{recorded: true, market: model.ComputeMarketGooglePlay, ref: "token-a", credits: 25, enabled: true}},
		"Play's over the App Store's": {apple, report(model.ComputeMarketGooglePlay, "token-a", "", 50, true),
			want{recorded: true, concurrent: true, market: model.ComputeMarketGooglePlay, ref: "token-a", credits: 50, enabled: true}},
	} {
		var monthly *model.ComputeAutoRenew
		if c.monthly != nil {
			monthly = clone(c.monthly, c.monthly.Enabled)
		}
		row, answer := computeStoreReportRow(monthly, c.report)
		if answer.Recorded != c.want.recorded || answer.Concurrent != c.want.concurrent || answer.Closed {
			t.Errorf("%s: %+v", name, answer)
			continue
		}
		if !c.want.recorded {
			if row != nil {
				t.Errorf("%s: wrote %+v", name, row)
			}
			continue
		}
		if row == nil || row.Market != c.want.market || row.StoreRef == nil || *row.StoreRef != c.want.ref || row.MonthlyCredits == nil ||
			*row.MonthlyCredits != c.want.credits || row.Enabled != c.want.enabled || row.Mode != model.ComputeAutoRenewModeMonthly {
			t.Errorf("%s: wrote %+v", name, row)
			continue
		}
		if row.PayerMemberId != nil || row.StripeCustomerId != nil || row.StripePaymentMethodId != nil || row.StripeSubscriptionId != nil {
			t.Errorf("%s: a store's plan keeps a card or a Stripe subscription: %+v", name, row)
		}
	}
}

// With no Stripe for auto-renew registered, the monthly plan's checkout refuses before anything is read.
func TestComputeMonthlyCheckoutRefusesWithoutStripe(t *testing.T) {
	if ComputeRegisteredStripeRenew() != nil {
		t.Skip("this test binary registered a Stripe for auto-renew")
	}
	env := newTestLedgerEnv()
	_, err := (computeMonthlyCheckoutTaker{}).MonthlyCheckout(env, context.Background(), model.DefaultComputeLedgerSettings(), &ComputeCheckoutRequest{
		NetworkId: sidecar.NewId(), MemberId: sidecar.NewId(), AutoRenew: model.ComputeAutoRenewModeMonthly, MonthlyCredits: 25,
	})
	if !errors.Is(err, ErrComputeStripeUnavailable) || env.db.callCount != 0 {
		t.Fatalf("no Stripe: %v, %d calls", err, env.db.callCount)
	}
}
