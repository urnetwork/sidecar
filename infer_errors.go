//go:build !ios_extension && !sidecar_http

// The router's errors (DESIGN-COMPUTE §6.4, §6.6): one InferError, coded, for a refusal before dispatch, which Infer and
// Check return, and for a dispatched call's failure, which its stream's error event carries. The codes are §6.4's and
// §25.10's, and each carries what its caller acts on: insufficient_quota its reason (balance, budget naming the budget
// and its period, or held with a retry time), disclosure_required the disclosure's id and version, model_refused the
// rule that refused. The Harness and the gateway turn a code into §7.4's choice or each API's own error; nothing turns
// one into a call to another model (R-INFER-3).
//
// A message is the router's or a path's own words, never text a provider or a server sent.

package sidecar

import (
	"context"
	"errors"
	"fmt"
)

// What went wrong (§6.4).
type InferErrorCode string

const (
	// No instance passed §5's checks: the message names the failed ones (§6.6).
	InferErrorTeeUnverified InferErrorCode = "tee_unverified"
	// The provider is at capacity, or its account cannot cover the hold, with a retry time where one is known.
	InferErrorCapacity InferErrorCode = "capacity"
	// The balance, a budget or open holds stand in the way: Reason says which (§6.6).
	InferErrorInsufficientQuota InferErrorCode = "insufficient_quota"
	// The request is too large for the model, or for the direct path's window.
	InferErrorContextLength InferErrorCode = "context_length"
	// The model may not be called: not in the catalog, unavailable here, or refused by a rule that Reason names.
	InferErrorModelRefused InferErrorCode = "model_refused"
	// The engine failed: a local engine's crash, a hostile model file, or a remote engine's error.
	InferErrorEngineFailed InferErrorCode = "engine_failed"
	// The caller's context ended, or its reader fell too far behind.
	InferErrorCanceled InferErrorCode = "canceled"
	// A model labeled none waits for its provider's disclosure to be acknowledged (§2.8, CO-34).
	InferErrorDisclosureRequired InferErrorCode = "disclosure_required"
	// A run carrying a connected service's limited_use mark may not reach this model (§25.10).
	InferErrorServiceModel InferErrorCode = "service_model"
)

// insufficient_quota's reasons (§6.6).
const (
	// The network cannot pay (§9.9).
	InferQuotaReasonBalance = "balance"
	// A budget ran out: Budget and Period name it (§16.4).
	InferQuotaReasonBudget = "budget"
	// The balance would pay, but open holds stand in the way until RetryAtMs (§9.7).
	InferQuotaReasonHeld = "held"
)

// disclosure_required's reasons (§2.8).
const (
	// No acknowledgment covers the disclosure's current version, or its previous one within the grace, and no person is
	// attached to the run to ask.
	InferDisclosureReasonUnacknowledged = "unacknowledged"
	// The person attached to the run was asked and answered "Not now": the call fails with §7.4's choice of another
	// model or local, and the run goes on.
	InferDisclosureReasonDeclined = "declined"
)

// One error of the router or of a call (§6.4).
type InferError struct {
	Code InferErrorCode `json:"code"`
	// Why, in the router's or the path's own words.
	Message string `json:"message"`
	// The canonical name the call ran under, or the name asked where none resolved.
	Model string `json:"model,omitempty"`
	// insufficient_quota's reason; disclosure_required's; model_refused's rule, where a rule refused.
	Reason string `json:"reason,omitempty"`
	// insufficient_quota's budget and its period (day, month or run), where a budget ran out.
	Budget string `json:"budget,omitempty"`
	Period string `json:"period,omitempty"`
	// held and capacity: when to try again, in unix milliseconds; 0 for no time given.
	RetryAtMs int64 `json:"retry_at_ms,omitempty"`
	// disclosure_required: the disclosure and its current version.
	DisclosureId      string `json:"disclosure_id,omitempty"`
	DisclosureVersion uint32 `json:"disclosure_version,omitempty"`
}

// The code and why.
func (self *InferError) Error() string {
	if self.Model == "" {
		return fmt.Sprintf("inference %s: %s", self.Code, self.Message)
	}
	return fmt.Sprintf("inference %s: %s: %s", self.Code, self.Model, self.Message)
}

// errors.Is matches another *InferError of the same code, whatever its other fields: errors.Is(err,
// &InferError{Code: InferErrorCanceled}).
func (self *InferError) Is(target error) bool {
	other, ok := target.(*InferError)
	return ok && other.Code == self.Code
}

// A copy.
func (self *InferError) clone() *InferError {
	clone := *self
	return &clone
}

// An error of code, its message from format.
func newInferError(code InferErrorCode, format string, a ...any) *InferError {
	return &InferError{Code: code, Message: fmt.Sprintf(format, a...)}
}

// The code of the *InferError err holds, or empty for none.
func InferErrorCodeOf(err error) InferErrorCode {
	var inferError *InferError
	if errors.As(err, &inferError) {
		return inferError.Code
	}
	return ""
}

// What a call's failure answers: the *InferError err holds, a copy; canceled for a context's end; and engine_failed for
// anything else, which says only that the engine failed, since another error's text may carry what an engine read.
func inferErrorOf(err error) *InferError {
	var inferError *InferError
	switch {
	case errors.As(err, &inferError):
		return inferError.clone()
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return newInferError(InferErrorCanceled, "the call's context ended")
	}
	return newInferError(InferErrorEngineFailed, "the engine failed")
}
