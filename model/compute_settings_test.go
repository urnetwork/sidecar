package model

// The ledger's settings (BAL-M12-01): each default equals the figure §9, §14 and §16.5 give it.

import (
	"slices"
	"testing"
	"time"
)

// Each default is the design's figure, field by field.
func TestComputeLedgerSettingsDefaults(t *testing.T) {
	settings := DefaultComputeLedgerSettings()
	usd := func(dollars int64) int64 {
		return dollars * 1_000_000_000
	}
	day := 24 * time.Hour
	type figure struct {
		name string
		got  any
		want any
	}
	for _, f := range []figure{
		// §9.6: 1.20 on every model and shape, and the steps
		{name: "MarkupNumerator", got: settings.MarkupNumerator, want: int64(6)},
		{name: "MarkupDenominator", got: settings.MarkupDenominator, want: int64(5)},
		{name: "TokenPriceStepNanoUsd", got: settings.TokenPriceStepNanoUsd, want: int64(1_000_000)},
		{name: "HourPriceStepNanoUsd", got: settings.HourPriceStepNanoUsd, want: int64(1_000_000)},
		{name: "SearchPriceStepNanoUsd", got: settings.SearchPriceStepNanoUsd, want: int64(100_000)},
		// §9.11
		{name: "BalanceCapNanoUsd", got: settings.BalanceCapNanoUsd, want: usd(10_000)},
		{name: "NewAccountDayNanoUsd", got: settings.NewAccountDayNanoUsd, want: usd(100)},
		{name: "NewAccountWindowNanoUsd", got: settings.NewAccountWindowNanoUsd, want: usd(200)},
		{name: "NewAccountWindow", got: settings.NewAccountWindow, want: 7 * day},
		{name: "DailyLoadNanoUsd", got: settings.DailyLoadNanoUsd, want: usd(1_500)},
		{name: "ThreeDSecureAboveNanoUsd", got: settings.ThreeDSecureAboveNanoUsd, want: usd(50)},
		// §9.8
		{name: "ThresholdBelowNanoUsd", got: settings.ThresholdBelowNanoUsd, want: usd(5)},
		{name: "ThresholdPackCredits", got: settings.ThresholdPackCredits, want: int64(20)},
		{name: "ThresholdMonthLimitNanoUsd", got: settings.ThresholdMonthLimitNanoUsd, want: usd(200)},
		{name: "ThresholdDayMaxCount", got: settings.ThresholdDayMaxCount, want: 3},
		{name: "ThresholdFailureMaxCount", got: settings.ThresholdFailureMaxCount, want: 3},
		// §9.11's promotions
		{name: "PromoMaxNanoUsd", got: settings.PromoMaxNanoUsd, want: usd(10)},
		{name: "PromoLapse", got: settings.PromoLapse, want: 30 * day},
		{name: "PromoNetworkInterval", got: settings.PromoNetworkInterval, want: 30 * day},
		{name: "PromoFailureDayMaxCount", got: settings.PromoFailureDayMaxCount, want: 5},
		{name: "PromoCodeMinCharacterCount", got: settings.PromoCodeMinCharacterCount, want: 8},
		{name: "PromoCodeMaxCharacterCount", got: settings.PromoCodeMaxCharacterCount, want: 32},
		{name: "PromoNetworkCodeCharacterCount", got: settings.PromoNetworkCodeCharacterCount, want: 16},
		// §9.12
		{name: "RefundWindow", got: settings.RefundWindow, want: 30 * day},
		{name: "ClosureRefundWindow", got: settings.ClosureRefundWindow, want: 90 * day},
		// §9.4 and §14.6's retention
		{name: "ChargeRetention", got: settings.ChargeRetention, want: 90 * day},
		{name: "SearchChargeRetention", got: settings.SearchChargeRetention, want: 72 * time.Hour},
		{name: "SearchChargePurgeAge", got: settings.SearchChargePurgeAge, want: 71*time.Hour + 55*time.Minute},
		{name: "DayRowRetention", got: settings.DayRowRetention, want: 400 * day},
		{name: "FinancialRecordRetention", got: settings.FinancialRecordRetention, want: 7 * 365 * day},
		{name: "PayerRetention", got: settings.PayerRetention, want: 2 * 365 * day},
		{name: "PayerDayRetention", got: settings.PayerDayRetention, want: 30 * day},
		{name: "DisputeRetention", got: settings.DisputeRetention, want: 400 * day},
		// §9.7 and §14.5
		{name: "SettleInterval", got: settings.SettleInterval, want: 2 * time.Second},
		{name: "SettleBatchRowCount", got: settings.SettleBatchRowCount, want: 500},
		{name: "UnconfirmedHoldMaxAge", got: settings.UnconfirmedHoldMaxAge, want: 60 * time.Second},
		{name: "SettledUnbookedPageAge", got: settings.SettledUnbookedPageAge, want: 60 * time.Second},
		{name: "TeeRecoverAfter", got: settings.TeeRecoverAfter, want: 10 * time.Minute},
		{name: "OpReleaseAfter", got: settings.OpReleaseAfter, want: 24 * time.Hour},
		{name: "RecoverInterval", got: settings.RecoverInterval, want: time.Minute},
		{name: "AutoRenewInterval", got: settings.AutoRenewInterval, want: time.Minute},
		{name: "SuspendInterval", got: settings.SuspendInterval, want: time.Minute},
		{name: "PromoLapseInterval", got: settings.PromoLapseInterval, want: time.Hour},
		{name: "RollupDayOffset", got: settings.RollupDayOffset, want: 2 * time.Hour},
		{name: "DirectExposureNanoUsd", got: settings.DirectExposureNanoUsd, want: usd(5)},
		{name: "AbsorbedPageDayNanoUsd", got: settings.AbsorbedPageDayNanoUsd, want: usd(50)},
		{name: "DirectMismatchWindow", got: settings.DirectMismatchWindow, want: 30 * day},
		// §9.9
		{name: "FloorMaxNanoUsd", got: settings.FloorMaxNanoUsd, want: usd(5)},
		{name: "FloorEnclaveTime", got: settings.FloorEnclaveTime, want: time.Hour},
		{name: "GraceMaxAge", got: settings.GraceMaxAge, want: time.Hour},
		{name: "BurnWindow", got: settings.BurnWindow, want: 24 * time.Hour},
		{name: "LowBurnTime", got: settings.LowBurnTime, want: 24 * time.Hour},
		{name: "IndexerReserveTime", got: settings.IndexerReserveTime, want: 7 * day},
		{name: "IndexerGraceTime", got: settings.IndexerGraceTime, want: 72 * time.Hour},
		// §9.11's searches and enclaves
		{name: "SearchCapNew", got: settings.SearchCapNew, want: int64(200)},
		{name: "SearchCapEstablished", got: settings.SearchCapEstablished, want: int64(2_000)},
		{name: "SearchCapAge", got: settings.SearchCapAge, want: 7 * day},
		{name: "EnclaveNewAccountCpuCount", got: settings.EnclaveNewAccountCpuCount, want: 1},
		{name: "EnclaveNewAccountWait", got: settings.EnclaveNewAccountWait, want: 24 * time.Hour},
		{name: "EnclaveGpuPurchasesNanoUsd", got: settings.EnclaveGpuPurchasesNanoUsd, want: usd(50)},
		{name: "EnclaveInterval", got: settings.EnclaveInterval, want: 10 * time.Minute},
		// D-BAL-11
		{name: "DisputeNetworkDayMaxCount", got: settings.DisputeNetworkDayMaxCount, want: 10},
		{name: "DisputePageNetworkCount", got: settings.DisputePageNetworkCount, want: 3},
		{name: "DisputePageBasisPoints", got: settings.DisputePageBasisPoints, want: int64(50)},
		// §16.5's broker defaults
		{name: "DefaultAgentDayNanoUsd", got: settings.DefaultAgentDayNanoUsd, want: usd(5)},
		{name: "DefaultAgentMonthNanoUsd", got: settings.DefaultAgentMonthNanoUsd, want: usd(50)},
		{name: "DefaultDeviceDayNanoUsd", got: settings.DefaultDeviceDayNanoUsd, want: usd(20)},
		{name: "DefaultDeviceMonthNanoUsd", got: settings.DefaultDeviceMonthNanoUsd, want: usd(200)},
		{name: "DefaultDeviceCeilingDayNanoUsd", got: settings.DefaultDeviceCeilingDayNanoUsd, want: usd(50)},
		// §9.7's lost cache answers held with a one-second retry
		{name: "ProjectionRebuildRetry", got: settings.ProjectionRebuildRetry, want: time.Second},
		// §9.13 and §14.3
		{name: "SpendDayCount", got: settings.SpendDayCount, want: 7},
		{name: "ChargesPageRowCount", got: settings.ChargesPageRowCount, want: 100},
	} {
		if f.got != f.want {
			t.Errorf("%s defaults to %v, want %v", f.name, f.got, f.want)
		}
	}
	for name, credits := range map[string][]int64{
		"StripePackCredits":        {10, 25, 50, 100, 250, 500},
		"StoreConsumableCredits":   {10, 25, 50, 100},
		"StoreSubscriptionCredits": {10, 25, 50, 100},
		"MonthlyPlanCredits":       {10, 25, 50, 100, 250},
	} {
		got := map[string][]int64{
			"StripePackCredits":        settings.StripePackCredits,
			"StoreConsumableCredits":   settings.StoreConsumableCredits,
			"StoreSubscriptionCredits": settings.StoreSubscriptionCredits,
			"MonthlyPlanCredits":       settings.MonthlyPlanCredits,
		}[name]
		if !slices.Equal(got, credits) {
			t.Errorf("%s defaults to %v, want %v", name, got, credits)
		}
	}
	if !slices.Equal(settings.ThresholdRetryIntervals, []time.Duration{time.Hour, 6 * time.Hour}) {
		t.Errorf("the threshold's retries default to %v", settings.ThresholdRetryIntervals)
	}
	// no pack of 5, on which Stripe's fees take 9% (§9.5)
	if slices.Contains(settings.StripePackCredits, 5) {
		t.Error("a pack of 5 credits")
	}
	// each defaults constructor returns its own instance, so a caller's change reaches no other
	settings.StripePackCredits[0] = 1
	if DefaultComputeLedgerSettings().StripePackCredits[0] != 10 {
		t.Error("the defaults share a slice between instances")
	}
}
