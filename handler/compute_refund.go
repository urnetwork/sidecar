// POST /compute/refund (DESIGN-COMPUTE §9.12, §14.3; BAL-M12-14): api's self-serve refund route, registered with the
// api/compute frame (compute_api.go), which has checked by then that the caller is an Owner or a Billing admin on a
// person's surface (an untagged member device, neither an enclave nor admitted by a Delegation, or the network's own
// credential), so no agent, MCP, tagged sidecar or enclave reaches it, and that the body is a JSON object of bounded
// size with no query beside it.
//
//	request   {"lot_id"}, no other field: the Stripe lot whose unspent part goes back to its card
//	answer    {"lot_id", "refunded_nano_usd"}: what went back, a retry's the first refund's
//	refusal   409 not_refundable for a store's lot, a promotion, an operator's credit, a reversed lot, one past its 30
//	          days, another network's or one with nothing unspent; 400 bad_request; 503 unavailable where the host holds
//	          no Stripe refunds
//
// The lot is an opaque id; no card, PaymentIntent or refund id is answered or logged.

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
	RegisterComputeApiHandler(http.MethodPost, "/compute/refund", NewComputeRefundHandler(nil))
}

// The route's handler over the ledger's settings, nil taking the defaults.
func NewComputeRefundHandler(settings *model.ComputeLedgerSettings) ComputeApiHandler {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return func(env operator.Env, ctx context.Context, caller *ComputeApiCaller, request *ComputeApiRequest) (any, error) {
		body := struct {
			LotId *operator.Id `json:"lot_id"`
		}{}
		decoder := json.NewDecoder(bytes.NewReader(request.Body))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil || decoder.More() || body.LotId == nil || *body.LotId == (operator.Id{}) {
			return nil, computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
		}
		answer, err := controller.ComputeRefundLot(env, ctx, settings, &controller.ComputeRefundLotRequest{NetworkId: caller.NetworkId, LotId: *body.LotId})
		switch {
		case errors.Is(err, controller.ErrComputeStripeRefundUnavailable):
			return nil, computeApiRefusal(http.StatusServiceUnavailable, ComputeApiRefusalUnavailable)
		case errors.Is(err, controller.ErrComputeRefundArgs):
			return nil, computeApiRefusal(http.StatusBadRequest, ComputeApiRefusalBadRequest)
		case err != nil:
			return nil, err
		}
		if answer.Refusal != "" {
			return nil, computeApiRefusal(http.StatusConflict, string(answer.Refusal))
		}
		return &struct {
			LotId           operator.Id `json:"lot_id"`
			RefundedNanoUsd int64       `json:"refunded_nano_usd"`
		}{
			LotId:           answer.Lot.LotId,
			RefundedNanoUsd: answer.RefundedNanoUsd,
		}, nil
	}
}
