package controller

// Refunds, adjustments, disputes and closure as the sidecar repo sees them (BAL-M12-14): what each refuses before any
// store is asked, whole cents, and the refund's and the adjustment's keys. The paths on real PostgreSQL and Redis run in
// server/computet3/compute_refund_t3_test.go.

import (
	"context"
	"errors"
	"testing"

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
	if _, err := ComputeCloseNetwork(env, ctx, settings, sidecar.Id{}); !errors.Is(err, ErrComputeRefundArgs) {
		t.Errorf("a closure of no network: %v", err)
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
