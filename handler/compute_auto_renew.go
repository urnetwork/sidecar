// GET and POST /compute/auto-renew (DESIGN-COMPUTE §9.8, §14.3; BAL-M12-11): api's auto-renew routes, registered with
// the api/compute frame (compute_api.go), which has checked by then that the caller may buy (§9.10: an Owner, a
// Billing admin or a member the policy grants compute:buy, from an untagged member device or the network's own
// credential), so no agent, MCP, tagged sidecar or enclave reaches either, and, for the POST, that the body is a JSON
// object of bounded size with no query beside it.
//
//	GET       both modes as they stand
//	POST      the device's ComputeAutoRenewChange, no other field: {"mode": "threshold"|"monthly", "on", and threshold's
//	          "below_nano_usd", "pack_credits", "month_limit_nano_usd" or monthly's "credits"}, a zero figure keeping
//	          the one in force; answered with both modes as they now stand
//	answer    {"threshold": {"on", "below_nano_usd", "pack_credits", "month_limit_nano_usd", "off_reason",
//	          "payer_member_id", "top_ups_today", "failures_today", "month_nano_usd"}, "monthly": {"on", "credits",
//	          "market", "payer_member_id"}}, the device's computeAutoRenewAnswer
//	refusal   409 card_required where a mode turned on, or threshold's figures changed, names no card the caller saved
//	          for it (they buy a pack with the mode on, which saves their own); 409 store_subscription for a store's
//	          plan; 501 not_built for a running Stripe plan's change of credits; 400 bad_request for a mode or figure
//	          §9.8 does not take; 503 unavailable where the host holds no Stripe for auto-renew
//
// No card, customer or subscription id is answered: the payer is an opaque member id.

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

func init() {
	RegisterComputeApiHandler(http.MethodGet, "/compute/auto-renew", NewComputeAutoRenewHandler(nil))
	RegisterComputeApiHandler(http.MethodPost, "/compute/auto-renew", NewComputeSetAutoRenewHandler(nil))
}

// threshold's body, as the device reads it.
type computeThresholdBody struct {
	On                bool         `json:"on"`
	BelowNanoUsd      int64        `json:"below_nano_usd"`
	PackCredits       int64        `json:"pack_credits"`
	MonthLimitNanoUsd int64        `json:"month_limit_nano_usd"`
	OffReason         string       `json:"off_reason"`
	PayerMemberId     *operator.Id `json:"payer_member_id"`
	TopUpsToday       int64        `json:"top_ups_today"`
	FailuresToday     int64        `json:"failures_today"`
	MonthNanoUsd      int64        `json:"month_nano_usd"`
}

// monthly's body.
type computeMonthlyBody struct {
	On            bool         `json:"on"`
	Credits       int64        `json:"credits"`
	Market        int16        `json:"market"`
	PayerMemberId *operator.Id `json:"payer_member_id"`
}

// Both modes' body: the auto-renew routes' answer, and the balance route's auto_renew.
type ComputeAutoRenewBody struct {
	Threshold *computeThresholdBody `json:"threshold"`
	Monthly   *computeMonthlyBody   `json:"monthly"`
}

// The body of state.
func ComputeAutoRenewBodyOf(state *controller.ComputeAutoRenewState) *ComputeAutoRenewBody {
	threshold, monthly := state.Threshold, state.Monthly
	return &ComputeAutoRenewBody{
		Threshold: &computeThresholdBody{
			On:                threshold.On,
			BelowNanoUsd:      threshold.BelowNanoUsd,
			PackCredits:       threshold.PackCredits,
			MonthLimitNanoUsd: threshold.MonthLimitNanoUsd,
			OffReason:         controller.ComputeAutoRenewOffCode(threshold.OffReason),
			PayerMemberId:     threshold.PayerMemberId,
			TopUpsToday:       threshold.TopUpsToday,
			FailuresToday:     threshold.FailuresToday,
			MonthNanoUsd:      threshold.MonthNanoUsd,
		},
		Monthly: &computeMonthlyBody{
			On:            monthly.On,
			Credits:       monthly.Credits,
			Market:        int16(monthly.Market),
			PayerMemberId: monthly.PayerMemberId,
		},
	}
}

// GET's handler over the ledger's settings, nil taking the defaults.
func NewComputeAutoRenewHandler(settings *model.ComputeLedgerSettings) ComputeApiHandler {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		state, err := controller.ComputeAutoRenew(env, ctx, settings, caller.NetworkId)
		if err != nil {
			return nil, err
		}
		return ComputeAutoRenewBodyOf(state), nil
	}
}

// POST's handler over the ledger's settings, nil taking the defaults.
func NewComputeSetAutoRenewHandler(settings *model.ComputeLedgerSettings) ComputeApiHandler {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		body := struct {
			Mode              string `json:"mode"`
			On                *bool  `json:"on"`
			BelowNanoUsd      int64  `json:"below_nano_usd"`
			PackCredits       int64  `json:"pack_credits"`
			MonthLimitNanoUsd int64  `json:"month_limit_nano_usd"`
			Credits           int64  `json:"credits"`
		}{}
		decoder := json.NewDecoder(bytes.NewReader(request.Body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || decoder.More() || body.On == nil {
			return nil, computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
		}
		var mode model.ComputeAutoRenewMode
		switch body.Mode {
		case model.ComputeAutoRenewModeThreshold.String():
			mode = model.ComputeAutoRenewModeThreshold
		case model.ComputeAutoRenewModeMonthly.String():
			mode = model.ComputeAutoRenewModeMonthly
		default:
			return nil, computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
		}
		answer, err := controller.ComputeSetAutoRenew(env, ctx, settings, &controller.ComputeAutoRenewChange{
			NetworkId:         caller.NetworkId,
			MemberId:          caller.MemberId,
			Mode:              mode,
			On:                *body.On,
			BelowNanoUsd:      body.BelowNanoUsd,
			PackCredits:       body.PackCredits,
			MonthLimitNanoUsd: body.MonthLimitNanoUsd,
			Credits:           body.Credits,
		})
		switch {
		case errors.Is(err, controller.ErrComputeAutoRenewArgs):
			return nil, computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
		case errors.Is(err, controller.ErrComputeStripeRenewUnavailable):
			return nil, computeApiRefusal(http.StatusServiceUnavailable, ComputeApiRefusalUnavailable)
		case err != nil:
			return nil, err
		}
		switch answer.Refusal {
		case "":
		case controller.ComputeAutoRenewRefusalNotBuilt:
			return nil, computeApiRefusal(http.StatusNotImplemented, ComputeApiRefusalNotBuilt)
		default:
			return nil, computeApiRefusal(http.StatusConflict, string(answer.Refusal))
		}
		return ComputeAutoRenewBodyOf(answer.State), nil
	}
}
