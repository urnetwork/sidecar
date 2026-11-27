//go:build !ios_extension && !sidecar_http && !js

package sidecar

// The read routes' answers as the device reads them (BAL-M12-15 against BAL-M12-17): each golden in
// testdata/compute_read_routes is what sidecar/handler's routes answer for fixed figures (handler/compute_spend_test.go
// holds the two equal), and here the device's own parsers take each one whole, so a field either side names or bounds
// differently fails one of the two tests rather than the first device that meets it.

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// One golden's text.
func testComputeReadRoutesGolden(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "compute_read_routes", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// The balance, a page of charges and a statement, as the routes answer them, parse whole with their figures.
func TestComputeReadRouteGoldensParseAsTheDeviceReadsThem(t *testing.T) {
	ctx := context.Background()
	balance, err := newTestSidecarApi(t, answerWith(http.StatusOK, testComputeReadRoutesGolden(t, "balance"))).ComputeBalance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if balance.State != ComputeAccountStateLow || balance.AvailableNanoUsd != 4_920_000_000 || balance.HeldNanoUsd != 2_580_000_000 ||
		balance.BalanceNanoUsd != 7_500_000_000 || balance.PromoNanoUsd != 1_000_000_000 || balance.Version != 42 ||
		!balance.MayBuy || balance.SalesOpen || len(balance.AtRiskEnclaveIds) != 1 || balance.IndexerDaysLeft == nil ||
		*balance.IndexerDaysLeft != 3 || !balance.AutoRenew.Threshold.On || balance.AutoRenew.Threshold.PayerMemberId == nil ||
		balance.UpdateTime.IsZero() {
		t.Errorf("the balance read %+v", balance)
	}

	charges, err := newTestSidecarApi(t, answerWith(http.StatusOK, testComputeReadRoutesGolden(t, "charges"))).ComputeCharges(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(charges.Charges) != 2 || charges.NextCursor == "" || charges.Charges[0].Kind != ComputeChargeKindInference ||
		charges.Charges[0].AgentId == nil || charges.Charges[0].CatalogId == "" || charges.Charges[1].EnclaveId == nil ||
		charges.Charges[1].Units.Seconds != 600 || charges.Charges[0].StartTime.IsZero() {
		t.Errorf("the charges read %+v", charges)
	}
	if !computeCursorValid(charges.NextCursor, DefaultComputeClientSettings()) {
		t.Errorf("the cursor %q is not one the device sends back", charges.NextCursor)
	}

	statement, err := newTestSidecarApi(t, answerWith(http.StatusOK, testComputeReadRoutesGolden(t, "statement"))).ComputeStatement(ctx, "2026-11")
	if err != nil {
		t.Fatal(err)
	}
	if len(statement.Rows) != 2 || len(statement.Lots) != 2 || statement.Rows[0].RefundedNanoUsd != 25_000_000 ||
		statement.Rows[1].Kind != ComputeChargeKindAdjustment || statement.Rows[1].AmountNanoUsd != -1_000_000_000 ||
		statement.Lots[1].LapsedNanoUsd == nil || *statement.Lots[1].LapsedNanoUsd != 400_000_000 || statement.Lots[1].ExpireTime == nil {
		t.Errorf("the statement read %+v", statement)
	}
}

// The spend view of every breakdown parses whole: 7 UTC days, each line a kind once with its total and days, each row
// keyed by its breakdown alone, and by agent no row's total.
func TestComputeSpendGoldensParseAsTheDeviceReadsThem(t *testing.T) {
	for _, by := range []ComputeSpendBy{ComputeSpendByNone, ComputeSpendByProvider, ComputeSpendByModel, ComputeSpendByEnclave,
		ComputeSpendByMember, ComputeSpendByAgent} {
		name := "spend_" + string(by)
		if by == ComputeSpendByNone {
			name = "spend"
		}
		spend, err := newTestSidecarApi(t, answerWith(http.StatusOK, testComputeReadRoutesGolden(t, name))).ComputeSpend(context.Background(), by)
		if err != nil {
			t.Errorf("by %q: %v", by, err)
			continue
		}
		if len(spend.Days) != 7 || spend.Days[6] != "2026-11-24" || spend.FirstChargeDay != "2026-11-02" || spend.HeldNanoUsd != 2_580_000_000 ||
			len(spend.Lines) != 4 || spend.UpdateTime.IsZero() {
			t.Errorf("by %q read %+v", by, spend)
			continue
		}
		for _, line := range spend.Lines {
			if by == ComputeSpendByNone && len(line.Rows) != 0 {
				t.Errorf("by none, line %s has rows", line.Kind)
			}
			// by agent a line has rows only where its kind was charged in the window
			if by != ComputeSpendByNone && by != ComputeSpendByAgent && len(line.Rows) == 0 {
				t.Errorf("by %q, line %s has no rows", by, line.Kind)
			}
		}
		if inference := spend.Lines[0]; inference.Total.AmountNanoUsd != 11_250_000_000 || inference.Total.RefundedNanoUsd != 500_000_000 {
			t.Errorf("by %q, inference's total %+v", by, inference.Total)
		}
	}
}
