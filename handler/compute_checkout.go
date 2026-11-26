// POST /compute/checkout (DESIGN-COMPUTE §9.5, §9.11, §14.3; BAL-M12-08): api's Stripe Checkout route, registered with
// the api/compute frame (compute_api.go), which has checked by then that the caller may buy (§9.10: an Owner, a
// Billing admin or a member the policy grants compute:buy, from an untagged member device or the network's own
// credential), so no agent, MCP, tagged sidecar or enclave reaches it, and that the body is a JSON object of bounded
// size with no query beside it.
//
//	request   the device's ComputeCheckoutArgs, no other field: {"pack_credits", "auto_renew", "below_nano_usd",
//	          "top_up_pack_credits", "month_limit_nano_usd", "monthly_credits"}, a pack with threshold turned on in the
//	          same act or not, or the monthly plan alone
//	answer    {"url", "expire_time_ms"}: Stripe Checkout's hosted url, which the person opens in their browser
//	refusal   409 sales_closed, balance_cap, daily_limit; 400 bad_request for a pack or plan §9.5 does not sell; 501
//	          not_built for what auto-renew (BAL-M12-11) builds; 403 credential_refused for a caller whose mount names
//	          no paying member; 503 unavailable where the host holds no Stripe checkout or no payer key
//
// The session's url is answered once and logged nowhere; the card is Stripe's alone.

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

// The auto-renew modes as the device's ComputeAutoRenewMode spells them.
const (
	computeCheckoutAutoRenewThreshold = "threshold"
	computeCheckoutAutoRenewMonthly   = "monthly"
)

func init() {
	RegisterComputeApiHandler(http.MethodPost, "/compute/checkout", NewComputeCheckoutHandler(nil, controller.ComputeRegisteredLedgerSecrets, controller.ComputeRegisteredStripeCheckout))
}

// The route's handler over the ledger's settings, nil taking the defaults, the host's secrets and its Stripe checkout
// as secrets and stripe answer them at each call.
func NewComputeCheckoutHandler(settings *model.ComputeLedgerSettings, secrets func() controller.ComputeLedgerSecrets, stripe func() controller.ComputeStripeCheckout) ComputeApiHandler {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		body := struct {
			PackCredits       int64  `json:"pack_credits"`
			AutoRenew         string `json:"auto_renew"`
			BelowNanoUsd      int64  `json:"below_nano_usd"`
			TopUpPackCredits  int64  `json:"top_up_pack_credits"`
			MonthLimitNanoUsd int64  `json:"month_limit_nano_usd"`
			MonthlyCredits    int64  `json:"monthly_credits"`
		}{}
		decoder := json.NewDecoder(bytes.NewReader(request.Body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || decoder.More() {
			return nil, computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
		}
		var autoRenew model.ComputeAutoRenewMode
		switch body.AutoRenew {
		case "":
		case computeCheckoutAutoRenewThreshold:
			autoRenew = model.ComputeAutoRenewModeThreshold
		case computeCheckoutAutoRenewMonthly:
			autoRenew = model.ComputeAutoRenewModeMonthly
		default:
			return nil, computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
		}
		if caller.MemberId == nil {
			// the customer, card and mandate are a member's: a mount naming none has no payer to name
			return nil, computeApiRefusal(http.StatusForbidden, ComputeApiRefusalCredentialRefused)
		}
		answer, err := controller.ComputeCheckout(env, ctx, settings, secrets(), stripe(), &controller.ComputeCheckoutRequest{
			NetworkId:         caller.NetworkId,
			MemberId:          *caller.MemberId,
			PackCredits:       body.PackCredits,
			AutoRenew:         autoRenew,
			BelowNanoUsd:      body.BelowNanoUsd,
			TopUpPackCredits:  body.TopUpPackCredits,
			MonthLimitNanoUsd: body.MonthLimitNanoUsd,
			MonthlyCredits:    body.MonthlyCredits,
		})
		switch {
		case errors.Is(err, controller.ErrComputeCheckoutArgs):
			return nil, computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
		case errors.Is(err, controller.ErrComputeLedgerSecretsUnset), errors.Is(err, controller.ErrComputeStripeUnavailable):
			return nil, computeApiRefusal(http.StatusServiceUnavailable, ComputeApiRefusalUnavailable)
		case err != nil:
			return nil, err
		}
		switch answer.Refusal {
		case "":
		case controller.ComputeCheckoutRefusalNotBuilt:
			return nil, computeApiRefusal(http.StatusNotImplemented, ComputeApiRefusalNotBuilt)
		default:
			return nil, computeApiRefusal(http.StatusConflict, string(answer.Refusal))
		}
		session := answer.Session
		if session == nil || session.Url == "" || session.ExpireTime.IsZero() {
			return nil, errors.New("compute checkout: a session answered no url or expiry")
		}
		return &struct {
			Url          string `json:"url"`
			ExpireTimeMs int64  `json:"expire_time_ms"`
		}{
			Url:          session.Url,
			ExpireTimeMs: session.ExpireTime.UnixMilli(),
		}, nil
	}
}
