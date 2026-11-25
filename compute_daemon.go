//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's compute methods (DESIGN-COMPUTE §9, §15.1, §15.3; BAL-M12-17): what `ur compute` (BAL-M12-18) and a
// remote-mode app's Compute() (BAL-M12-19) call, on desktop legs only, each acting on its call's network (§5.8's
// network rule) through its Sidecar's ComputeClient:
//
//	compute.balance          the balance, held, the state, auto-renew, may_buy and sales_open
//	compute.low              the newest compute_low notice, in full, or none
//	compute.packs            what a market sells: Stripe's packs and plans, a store's products
//	compute.checkout         a Checkout url for a pack or the monthly plan; the person pays in the browser
//	compute.redeem           a promotion code: Confirm (D-CORE-13)
//	compute.auto_renew       §9.8's two modes
//	compute.auto_renew.set   one mode's change: Confirm
//	compute.charges          a page of charges, named on the device
//	compute.statement        a month's statement, named on the device
//	compute.spend            §9.13's spend view by one dimension, named on the device
//	compute.refund           a Stripe lot's unspent part: Confirm, an act on money only a person takes
//	compute.budget.raise     kind 21 through the gate, approval_pending until a person decides
//
// Redemption, auto-renew's changes and refunds run only from a control call whose ur confirmed on /dev/tty or in an
// app's UI, never from mcp or hook; `ur compute redeem` also refuses a caller with a harness process among its
// ancestors (§9.11), which the command checks before it calls. A budget raise is not a Confirm method: kind 21's
// approval is the gate's, decided on an approval-capable device, and the caller's word adds nothing.
//
// A refusal api answered with a code is the reply, {"refusal": {"code", "retry_after_ms"}}, not an rpc error, so a
// surface prints the code and its fix without reading a message. Params are read strictly. A reply carries ids,
// numbers, the device's names and words, never a card, a token, a store receipt or a promotion code (I-7), which the
// reply walk holds it to. ur daemon registers the methods (BAL-M12-18's cmd_compute_methods.go); ur native-host relays
// none of them. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

// The methods.
const (
	DaemonMethodComputeBalance      = "compute.balance"
	DaemonMethodComputeLow          = "compute.low"
	DaemonMethodComputePacks        = "compute.packs"
	DaemonMethodComputeCheckout     = "compute.checkout"
	DaemonMethodComputeRedeem       = "compute.redeem"
	DaemonMethodComputeAutoRenew    = "compute.auto_renew"
	DaemonMethodComputeAutoRenewSet = "compute.auto_renew.set"
	DaemonMethodComputeCharges      = "compute.charges"
	DaemonMethodComputeStatement    = "compute.statement"
	DaemonMethodComputeSpend        = "compute.spend"
	DaemonMethodComputeRefund       = "compute.refund"
	DaemonMethodComputeBudgetRaise  = "compute.budget.raise"
)

// Params that name the call's network alone.
type DaemonComputeParams struct {
	// The call's network, empty for .ur's or the only one (§5.8).
	Network string `json:"network,omitempty"`
}

// compute.packs's params.
type DaemonComputePacksParams struct {
	Network string `json:"network,omitempty"`
	// stripe, app_store or google_play.
	Market string `json:"market"`
}

// compute.checkout's params: the purchase, as POST /compute/checkout takes it.
type DaemonComputeCheckoutParams struct {
	Network string `json:"network,omitempty"`
	ComputeCheckoutArgs
}

// compute.redeem's params.
type DaemonComputeRedeemParams struct {
	Network string `json:"network,omitempty"`
	// The promotion code, as the person typed it; never logged.
	Code string `json:"code"`
}

// compute.auto_renew.set's params: one mode's change.
type DaemonComputeAutoRenewSetParams struct {
	Network string `json:"network,omitempty"`
	ComputeAutoRenewChange
}

// compute.charges's params.
type DaemonComputeChargesParams struct {
	Network string `json:"network,omitempty"`
	// The page's cursor, as the last page answered it; empty for the first.
	Cursor string `json:"cursor,omitempty"`
}

// compute.statement's params.
type DaemonComputeStatementParams struct {
	Network string `json:"network,omitempty"`
	// YYYY-MM, UTC.
	Month string `json:"month"`
}

// compute.spend's params.
type DaemonComputeSpendParams struct {
	Network string `json:"network,omitempty"`
	// provider, model, enclave, member or agent; empty for none.
	By string `json:"by,omitempty"`
}

// compute.refund's params.
type DaemonComputeRefundParams struct {
	Network string `json:"network,omitempty"`
	LotId   *Id    `json:"lot_id"`
}

// compute.budget.raise's params: the raise, as ComputeClient.RaiseBudget takes it.
type DaemonComputeBudgetRaiseParams struct {
	Network string `json:"network,omitempty"`
	ComputeBudgetRaiseArgs
}

// A refusal api answered: its code and retry hint, never its text.
type DaemonComputeRefusal struct {
	Code         string `json:"code"`
	RetryAfterMs uint32 `json:"retry_after_ms,omitempty"`
}

// The reply of a call api refused with a code.
type DaemonComputeRefusalReply struct {
	Refusal *DaemonComputeRefusal `json:"refusal"`
}

// compute.packs's reply.
type DaemonComputePacksReply struct {
	Packs []*ComputePack `json:"packs"`
}

// compute.low's reply: the newest notice, or none.
type DaemonComputeLowReply struct {
	Notice *ComputeLowNotice `json:"notice,omitempty"`
}

// What the compute methods act through: a nil Client takes the call's Sidecar's ComputeClient.
type DaemonComputeBackends struct {
	Client func(sidecar *Sidecar) (*ComputeClient, error)
}

// The params of a call that do not decode, or of an unbound call: the text names nothing they held.
var errDaemonComputeParams = errors.New("the compute params do not decode")

// The daemon's compute methods over backends, each on its call's network; redeem, auto_renew.set and refund Confirm
// methods (the file header). The daemon's composition registers them with RegisterMethod.
func DaemonComputeMethods(backends *DaemonComputeBackends) []*DaemonMethod {
	if backends == nil {
		backends = &DaemonComputeBackends{}
	}
	clientOf := backends.Client
	if clientOf == nil {
		clientOf = func(sidecar *Sidecar) (*ComputeClient, error) {
			return sidecar.ComputeClient()
		}
	}
	// the params, strictly, and the call's client
	open := func(call *DaemonCall, params any) (*ComputeClient, error) {
		if err := decodeDaemonSocketParams(call, params); err != nil {
			return nil, fmt.Errorf("%w: %w", errDaemonComputeParams, err)
		}
		if call.Sidecar == nil {
			return nil, fmt.Errorf("%w: no network's sidecar", errDaemonComputeParams)
		}
		return clientOf(call.Sidecar)
	}
	// a refusal with a code as the reply; any other error stands
	answer := func(result any, err error) (any, error) {
		var apiErr *SidecarApiError
		if errors.As(err, &apiErr) && apiErr.Code != "" {
			return &DaemonComputeRefusalReply{Refusal: &DaemonComputeRefusal{Code: apiErr.Code, RetryAfterMs: apiErr.RetryAfterMs}}, nil
		}
		if err != nil {
			return nil, err
		}
		return result, nil
	}
	return []*DaemonMethod{
		{
			Name:    DaemonMethodComputeBalance,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				client, err := open(call, &DaemonComputeParams{})
				if err != nil {
					return nil, err
				}
				return answer(client.Balance(ctx))
			},
		},
		{
			Name:    DaemonMethodComputeLow,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				client, err := open(call, &DaemonComputeParams{})
				if err != nil {
					return nil, err
				}
				return &DaemonComputeLowReply{Notice: client.LowNotice()}, nil
			},
		},
		{
			Name:    DaemonMethodComputePacks,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonComputePacksParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				market, err := ParseComputeMarket(params.Market)
				if err != nil {
					return nil, err
				}
				packs, err := client.Packs(market)
				if err != nil {
					return nil, err
				}
				return &DaemonComputePacksReply{Packs: packs}, nil
			},
		},
		{
			Name:    DaemonMethodComputeCheckout,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonComputeCheckoutParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				return answer(client.Checkout(ctx, &params.ComputeCheckoutArgs))
			},
		},
		{
			Name:    DaemonMethodComputeRedeem,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				if !call.Confirmed {
					return nil, errDaemonComputeUnconfirmed
				}
				params := &DaemonComputeRedeemParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				return answer(client.Redeem(ctx, params.Code))
			},
		},
		{
			Name:    DaemonMethodComputeAutoRenew,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				client, err := open(call, &DaemonComputeParams{})
				if err != nil {
					return nil, err
				}
				return answer(client.AutoRenew(ctx))
			},
		},
		{
			Name:    DaemonMethodComputeAutoRenewSet,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				if !call.Confirmed {
					return nil, errDaemonComputeUnconfirmed
				}
				params := &DaemonComputeAutoRenewSetParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				return answer(client.SetAutoRenew(ctx, &params.ComputeAutoRenewChange))
			},
		},
		{
			Name:    DaemonMethodComputeCharges,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonComputeChargesParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				return answer(client.Charges(ctx, params.Cursor))
			},
		},
		{
			Name:    DaemonMethodComputeStatement,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonComputeStatementParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				return answer(client.Statement(ctx, params.Month))
			},
		},
		{
			Name:    DaemonMethodComputeSpend,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonComputeSpendParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				by, err := ParseComputeSpendBy(params.By)
				if err != nil {
					return nil, err
				}
				return answer(client.Spend(ctx, by))
			},
		},
		{
			Name:    DaemonMethodComputeRefund,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				if !call.Confirmed {
					return nil, errDaemonComputeUnconfirmed
				}
				params := &DaemonComputeRefundParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				if params.LotId == nil {
					return nil, fmt.Errorf("%w: a refund names its lot", errDaemonComputeParams)
				}
				return answer(client.Refund(ctx, *params.LotId))
			},
		},
		{
			Name:    DaemonMethodComputeBudgetRaise,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonComputeBudgetRaiseParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				return answer(client.RaiseBudget(ctx, &params.ComputeBudgetRaiseArgs))
			},
		},
	}
}

// A Confirm method's handler reached without the person's confirmation, which the dispatcher refuses first: the
// handler refuses it again, so no path runs an act a person did not confirm.
var errDaemonComputeUnconfirmed = errors.New("this compute act needs a person's confirmation on /dev/tty or in an app")
