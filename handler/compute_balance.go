// GET /compute/balance (DESIGN-COMPUTE §9.7, §9.9, §9.10, §14.3, Q-BAL-13; BAL-M12-15): the network's balance as a
// sidecar of it, or the network's own credential, may read it, registered with the api/compute frame (compute_api.go),
// which has checked the caller by then: every member device polls it for compute_low (§9.9), so any admitted sidecar
// reads it, while no agent's or MCP's credential does. What an agent learns of it is §7.5's compute_balance, the
// network's state alone, never these figures (BAL-M12-20).
//
//	answer  ComputeBalanceAnswer, the device's computeBalanceAnswer (sidecar/compute_client_api.go): available,
//	        held, the balance the states read, promo, §9.9's state by its word and the account's version, both
//	        auto-renew modes with whether threshold is off and why, whether this caller may buy (§9.10) and whether
//	        credits are on sale (Q-BAL-13), so the apps offer credit only where both hold, and from low on the
//	        enclaves a suspension would stop and the indexer enclave's days left
//
// The figures are ids and typed numbers only (I-13): no card, customer or subscription id, the payer an opaque member
// id. Times are Unix milliseconds.

package handler

import (
	"context"
	"net/http"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

func init() {
	RegisterComputeApiHandler(http.MethodGet, "/compute/balance", NewComputeBalanceHandler(nil))
}

// GET /compute/balance's answer.
type ComputeBalanceAnswer struct {
	AvailableNanoUsd int64                 `json:"available_nano_usd"`
	HeldNanoUsd      int64                 `json:"held_nano_usd"`
	BalanceNanoUsd   int64                 `json:"balance_nano_usd"`
	PromoNanoUsd     int64                 `json:"promo_nano_usd"`
	State            string                `json:"state"`
	Version          int64                 `json:"version"`
	AutoRenew        *ComputeAutoRenewBody `json:"auto_renew"`
	MayBuy           bool                  `json:"may_buy"`
	SalesOpen        bool                  `json:"sales_open"`
	AtRiskEnclaveIds []operator.Id         `json:"at_risk_enclave_ids"`
	IndexerDaysLeft  *int64                `json:"indexer_days_left,omitempty"`
	UpdateTimeMs     int64                 `json:"update_time_ms"`
}

// The answer of a balance, its auto-renew and the caller's rights.
func ComputeBalanceAnswerOf(balance *controller.ComputeBalanceState, autoRenew *controller.ComputeAutoRenewState, mayBuy bool, salesOpen bool) *ComputeBalanceAnswer {
	answer := &ComputeBalanceAnswer{
		AvailableNanoUsd: balance.AvailableNanoUsd,
		HeldNanoUsd:      max(0, balance.HeldNanoUsd),
		BalanceNanoUsd:   balance.BalanceNanoUsd,
		PromoNanoUsd:     max(0, balance.PromoNanoUsd),
		State:            balance.State.String(),
		Version:          max(0, balance.Version),
		AutoRenew:        ComputeAutoRenewBodyOf(autoRenew),
		MayBuy:           mayBuy,
		SalesOpen:        salesOpen,
		AtRiskEnclaveIds: append([]operator.Id{}, balance.AtRiskEnclaveIds...),
		IndexerDaysLeft:  balance.IndexerDaysLeft,
	}
	if !balance.UpdateTime.IsZero() {
		answer.UpdateTimeMs = balance.UpdateTime.UnixMilli()
	}
	return answer
}

// The route's handler over the ledger's settings, nil taking the defaults.
func NewComputeBalanceHandler(settings *model.ComputeLedgerSettings) ComputeApiHandler {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		balance, err := controller.ComputeBalanceOf(env, ctx, settings, caller.NetworkId)
		if err != nil {
			return nil, err
		}
		autoRenew, err := controller.ComputeAutoRenew(env, ctx, settings, caller.NetworkId)
		if err != nil {
			return nil, err
		}
		return ComputeBalanceAnswerOf(balance, autoRenew, caller.MayBuy(), controller.ComputeSalesOpen(env, ctx, caller.NetworkId)), nil
	}
}
