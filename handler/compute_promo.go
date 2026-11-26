// POST /compute/promo/redeem (DESIGN-COMPUTE §9.11, §14.3; BAL-M12-13): api's promotion code route, registered with
// the api/compute frame (compute_api.go), which has checked by then that the caller may buy (§9.10: an Owner, a
// Billing admin or a member the policy grants compute:buy, from an untagged member device or the network's own
// credential), so no agent, MCP, tagged sidecar or enclave reaches it, and that the body is a JSON object of bounded
// size with no query beside it, so a code never travels in a URL.
//
//	request   {"code": "<8 to 32 letters and digits>"}, no other field
//	answer    {"lot_id", "credit_nano_usd", "expire_time_ms"}: the redemption's lot, a retry's the first one's
//	refusal   409 code_unknown, code_ended, code_redeemed, redeemed_recently, paid_lot_required, daily_limit,
//	          balance_cap; 402 compute_balance for a chargeback's suspension; 429 rate_limited until the next UTC
//	          midnight; 503 unavailable where the host holds no promotion key or the day's failures do not read
//
// The code is the ledger's to fold and hash (sidecar/controller's ComputeRedeemPromo); this file neither logs nor keeps
// it, and no refusal carries it.

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

// The route's own refusal: the host holds no promotion key, or the day's failed codes did not read.
const ComputeApiRefusalUnavailable = "unavailable"

func init() {
	RegisterComputeApiHandler(http.MethodPost, "/compute/promo/redeem", NewComputePromoRedeemHandler(nil, controller.ComputeRegisteredLedgerSecrets))
}

// The route's handler over the ledger's settings, nil taking the defaults, and the host's secrets as secrets answers
// them at each call.
func NewComputePromoRedeemHandler(settings *model.ComputeLedgerSettings, secrets func() controller.ComputeLedgerSecrets) ComputeApiHandler {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		body := struct {
			Code *string `json:"code"`
		}{}
		decoder := json.NewDecoder(bytes.NewReader(request.Body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || body.Code == nil || decoder.More() {
			return nil, computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
		}
		answer, err := controller.ComputeRedeemPromo(env, ctx, settings, secrets(), &controller.ComputeRedeemRequest{
			NetworkId: caller.NetworkId, SidecarId: caller.SidecarId, Code: *body.Code,
		})
		if errors.Is(err, controller.ErrComputeLedgerSecretsUnset) || errors.Is(err, controller.ErrComputePromoUnavailable) {
			return nil, computeApiRefusal(http.StatusServiceUnavailable, ComputeApiRefusalUnavailable)
		}
		if err != nil {
			return nil, err
		}
		switch answer.Refusal {
		case "":
		case controller.ComputePromoRefusalRateLimited:
			retryAfterMs := answer.RetryAfter.Milliseconds()
			return nil, &ComputeApiRefusal{Status: http.StatusTooManyRequests, Code: string(answer.Refusal), RetryAfterMs: uint32(min(max(retryAfterMs, 0), int64(^uint32(0))))}
		case controller.ComputePromoRefusalSuspended:
			return nil, computeApiRefusal(http.StatusPaymentRequired, string(answer.Refusal))
		default:
			return nil, computeApiRefusal(http.StatusConflict, string(answer.Refusal))
		}
		lot := answer.Lot
		if lot == nil || lot.ExpireTime == nil {
			return nil, errors.New("compute promo: a redemption answered no lot")
		}
		return &struct {
			LotId         operator.Id `json:"lot_id"`
			CreditNanoUsd int64       `json:"credit_nano_usd"`
			ExpireTimeMs  int64       `json:"expire_time_ms"`
		}{
			LotId:         lot.LotId,
			CreditNanoUsd: lot.AmountNanoUsd,
			ExpireTimeMs:  lot.ExpireTime.UnixMilli(),
		}, nil
	}
}
