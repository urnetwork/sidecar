// What the ledger refuses an admission for, and how the broker answers each (DESIGN-COMPUTE §6.6, §9.7, §9.9, §16.4;
// BAL-M12-03):
//
//	balance   the network cannot pay, or is in grace or worse: insufficient_quota, reason balance, 402 (§9.9's
//	          COMPUTE_BALANCE); the Harness offers "add credit" to a person who may buy
//	budget    a budget would be passed: insufficient_quota, reason budget, naming the budget and its period (§16.4);
//	          the Harness offers "raise the budget", kind 21
//	held      the balance would pay but open holds or reservations stand in the way, or the projection is being
//	          rebuilt: insufficient_quota, reason held, with its retry time, 429 as the gateway answers it; the
//	          Harness waits and asks again, so no one is asked for credit they have
//	capacity  PostgreSQL could not take the operation's row, or the provider's account could not cover the hold
//	          (§10.4): capacity, with its retry time, 503
//
// The broker (computeservice) writes the reply through its own refusal frame, which this package does not import, so
// the reply carries the code and reason as their words.

package controller

import (
	"net/http"
	"time"

	"github.com/urnetwork/sidecar/model"
)

// Why an admission was refused.
type ComputeRefusalReason string

const (
	ComputeRefusalBalance  ComputeRefusalReason = "balance"
	ComputeRefusalBudget   ComputeRefusalReason = "budget"
	ComputeRefusalHeld     ComputeRefusalReason = "held"
	ComputeRefusalCapacity ComputeRefusalReason = "capacity"
)

// The broker's codes for a refusal, as its frame spells them (computeservice's ComputeRefusalCode).
const (
	ComputeRefusalCodeInsufficientQuota = "insufficient_quota"
	ComputeRefusalCodeCapacity          = "capacity"
)

// One refused admission.
type ComputeRefusal struct {
	Reason ComputeRefusalReason
	// For budget, the line that refused: its subject, budget, period and cap.
	Line *model.ComputeBudgetLine
	// For held and capacity, when to ask again.
	RetryAfter time.Duration
}

// The ledger's refusal as the broker replies with it.
type ComputeRefusalReply struct {
	Status int
	// insufficient_quota or capacity.
	Code string
	// insufficient_quota's reason: balance, budget or held; empty for capacity.
	Reason string
	// For budget: the budget's name and its period, day or month.
	Budget string
	Period string
	// For held and capacity: when to ask again, which Retry-After repeats.
	RetryAfter time.Duration
}

// Maps refusal to the broker's reply (§6.6): see the file header.
func ComputeRefusalAnswer(refusal *ComputeRefusal) *ComputeRefusalReply {
	switch refusal.Reason {
	case ComputeRefusalBalance:
		return &ComputeRefusalReply{Status: http.StatusPaymentRequired, Code: ComputeRefusalCodeInsufficientQuota, Reason: string(ComputeRefusalBalance)}
	case ComputeRefusalBudget:
		reply := &ComputeRefusalReply{Status: http.StatusPaymentRequired, Code: ComputeRefusalCodeInsufficientQuota, Reason: string(ComputeRefusalBudget)}
		if refusal.Line != nil {
			reply.Budget = refusal.Line.Budget
			reply.Period = refusal.Line.Period.String()
		}
		return reply
	case ComputeRefusalHeld:
		return &ComputeRefusalReply{Status: http.StatusTooManyRequests, Code: ComputeRefusalCodeInsufficientQuota, Reason: string(ComputeRefusalHeld), RetryAfter: refusal.RetryAfter}
	}
	// capacity, and any reason this package does not name, which refuses as capacity does rather than admit
	return &ComputeRefusalReply{Status: http.StatusServiceUnavailable, Code: ComputeRefusalCodeCapacity, RetryAfter: refusal.RetryAfter}
}
