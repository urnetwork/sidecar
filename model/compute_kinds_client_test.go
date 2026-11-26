//go:build !ios_extension && !sidecar_http && !js

package model

// The ledger and the device's compute client read the same numbers (BAL-M12-01 beside BAL-M12-17): §9.6's charge
// kinds, §9.4's lot kinds and markets, §9.9's states by their words, the units' JSON and the format values both sides'
// settings carry. The client's files build only on the legs that run compute, so this file does too.

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
)

// Each identifier means one thing on both sides.
func TestComputeKindsMatchTheClient(t *testing.T) {
	for _, kind := range ComputeChargeKinds() {
		if kind.String() != sidecar.ComputeChargeKind(kind).String() {
			t.Errorf("charge kind %d is %s here and %s on the device", kind, kind, sidecar.ComputeChargeKind(kind))
		}
	}
	for market := ComputeMarketStripe; market <= ComputeMarketPromotion; market += 1 {
		if market.String() != sidecar.ComputeMarket(market).String() {
			t.Errorf("market %d is %s here and %s on the device", market, market, sidecar.ComputeMarket(market))
		}
	}
	for _, pair := range [][2]int16{
		{int16(ComputeLotKindPurchase), int16(sidecar.ComputeLotKindPurchase)},
		{int16(ComputeLotKindSubscription), int16(sidecar.ComputeLotKindSubscription)},
		{int16(ComputeLotKindPromotion), int16(sidecar.ComputeLotKindPromotion)},
		{int16(ComputeLotKindAdjustment), int16(sidecar.ComputeLotKindAdjustment)},
	} {
		if pair[0] != pair[1] {
			t.Errorf("a lot kind is %d here and %d on the device", pair[0], pair[1])
		}
	}
	// the account's state by its number here and its word on the wire (the balance route, compute_low)
	for state := ComputeAccountStateActive; state <= ComputeAccountStateClosed; state += 1 {
		word := sidecar.ComputeAccountState(state.String())
		if !word.Valid() {
			t.Errorf("state %d's word %s is none the device takes", state, state)
		}
		if word.CanPay() != state.CanPay() {
			t.Errorf("state %s pays here %v and on the device %v", state, state.CanPay(), word.CanPay())
		}
		if parsed, err := ParseComputeAccountState(string(word)); err != nil || parsed != state {
			t.Errorf("the word %s reads as %d, %v", word, parsed, err)
		}
	}

	// the units' JSON reads whole on the device
	units := ComputeUnits{InputTokens: 1, OutputTokens: 2, CachedTokens: 3, Seconds: 4, EgressBytes: 5, Searches: 6}
	data, err := units.Json()
	if err != nil {
		t.Fatal(err)
	}
	read := sidecar.ComputeUnits{}
	if err := json.Unmarshal(data, &read); err != nil {
		t.Fatal(err)
	}
	if read != (sidecar.ComputeUnits{InputTokens: 1, OutputTokens: 2, CachedTokens: 3, Seconds: 4, EgressBytes: 5, Searches: 6}) {
		t.Errorf("the device reads %+v", read)
	}
}

// The format values the routes and the device share keep one default on both sides.
func TestComputeLedgerSettingsMatchTheClient(t *testing.T) {
	ledger := DefaultComputeLedgerSettings()
	client := sidecar.DefaultComputeClientSettings()
	if !slices.Equal(ledger.StripePackCredits, client.StripePackCredits) {
		t.Errorf("the Stripe packs are %v here and %v on the device", ledger.StripePackCredits, client.StripePackCredits)
	}
	if !slices.Equal(ledger.MonthlyPlanCredits, client.MonthlyPlanCredits) {
		t.Errorf("the monthly plans are %v here and %v on the device", ledger.MonthlyPlanCredits, client.MonthlyPlanCredits)
	}
	for _, pair := range [][3]any{
		{"PromoCodeMinCharacterCount", ledger.PromoCodeMinCharacterCount, client.PromoCodeMinCharacterCount},
		{"PromoCodeMaxCharacterCount", ledger.PromoCodeMaxCharacterCount, client.PromoCodeMaxCharacterCount},
		{"SpendDayCount", ledger.SpendDayCount, client.SpendDayCount},
		{"ChargesPageRowCount", ledger.ChargesPageRowCount, client.ChargesPageRowCount},
		{"AnswerMaxRowCount", ledger.AnswerMaxRowCount, client.AnswerMaxRowCount},
	} {
		if pair[1] != pair[2] {
			t.Errorf("%s is %v here and %v on the device", pair[0], pair[1], pair[2])
		}
	}
}
