//go:build !ios_extension && !sidecar_http

// The limited_use check (DESIGN-COMPUTE §25.10, §6.4, IC-20): a run that read a connected service under a definition
// whose model rule is limited_use carries the mark for good, and its calls reach only local models and the remote
// models the signed policy's limited_use line lists, of any label, AP included, since at AP the provider's own code
// reads the request; any other answers service_model. A gateway call is checked against the union of the marks of
// every run its binding may name, the marks GW's binder unions, and a call without a handle against those of every
// run of its grant's live harness processes (§8.9). A call with neither a run nor a binding, such as ur infer at a
// terminal, carries no run's mark.
//
// Marks that do not read refuse the call, model_refused naming the marks, so an unreadable mark never lets a marked
// run's words out.

package sidecar

import (
	"context"
	"slices"
)

// A run's mark that limits which models it reaches (§25.10), as the run store keeps it.
const inferMarkLimitedUse = "limited_use"

// The marks a call carries: its binding's union, else its run's, else none.
func (self *inferSourceChecker) callMarks(ctx context.Context, request *InferRequest) ([]string, error) {
	switch {
	case request == nil:
		return nil, nil
	case request.Binding != nil:
		return self.sources.Marks.BindingMarks(ctx, request.Binding)
	case request.RunId != nil:
		return self.sources.Marks.RunMarks(ctx, *request.RunId)
	}
	return nil, nil
}

// service_model where call carries limited_use and policy's limited_use line does not list its model; a local model,
// which nothing leaves, is never refused here, and the checks never ask the marks of one.
func (self *inferSourceChecker) checkMarks(ctx context.Context, call *InferCall, policy *ComputePolicy) error {
	marks, err := self.callMarks(ctx, call.Request)
	if err != nil {
		return inferRefused(call, InferRefusedRuleMarks, "the run's marks do not read: %s", err)
	}
	if !slices.Contains(marks, inferMarkLimitedUse) || policy.LimitedUse(call.Entry.Provider, call.Entry.Model) {
		return nil
	}
	return &InferError{
		Code:    InferErrorServiceModel,
		Model:   call.Name,
		Message: "the run read a connected service under limited use, which this model's provider is not listed for: use a local model or one the policy lists for limited use",
	}
}
