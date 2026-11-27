//go:build !ios_extension && !sidecar_http && !js

// Kind 21's effect and lookup on the device (DESIGN-COMPUTE §14.3, §16.3's kind 21 rows, D-BAL-8; BAL-M12-16), so
// Sidecar.Authorize can reserve a compute_budget_raise and run it: ComputeClient.RaiseBudget (BAL-M12-17), the
// compute_budget_raise tool (BAL-M12-20) and a gateway grant raised above the server's default (§8.6) each file one,
// which a person approves on an approval-capable device, never an agent's own (the classifier never decides kind 21,
// §27.4).
//
//	effect  POST compute/v1/budget/raise through the Sidecar's compute service client, under Idempotency-Key: the
//	        use's effect key in base64url, carrying the decisions the use spends and the action they hash, as stored
//	        (protocol/compute.proto's ComputeBudgetRaiseRequest), which the broker verifies and keeps with the raise in
//	        one transaction; its reference is the broker's stored result, ComputeBudgetRaiseAnswer as it came
//	lookup  the same request again under the same key, which the broker answers from the use's row once it committed:
//	        done with that result; anything else leaves the use uncertain, since only the broker's gate knows a first
//	        presentation (§16.6's gate row). Registered on every Sidecar of a compute leg as a component, so a restart
//	        reconciles a reserved use with no caller alive (RegisterComputeBudgetRaiseLookup)
//
// Kind 21 is a server gate's kind (record_effect.go), so its use reserves until its decision's not_after less §8.6's
// skew, and a refusal proves nothing done only at its first presentation. The effect answers ErrSidecarEffectNotDone
// for a request the broker refused (a 4xx but 429), and for one it never sent: no use's key or spend, a template, which
// no version-5 action has, or no compute service to send to; a 429, a 5xx or a lost connection leaves it uncertain,
// and the gate's retry completes it under the same key. An answer that is not this raise's (another approval, period or
// amount) is refused as the broker's fault and leaves the use uncertain.
//
// A raise of period run, and a gateway grant's, which names no agent the broker reads, come back device_only: the
// broker kept the use and raised nothing, and the Harness's run budget or the grant's own takes the raise (CACL's and
// HARN's budgets read the outcome). Nothing here logs a decision or the action.

package sidecar

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The route, as the broker's table names it, and the component that keeps the lookup registered.
const (
	computeBudgetRaisePath          = "/v1/budget/raise"
	computeBudgetRaiseComponentName = "compute-budget-raise"
	computeBudgetRaiseKeyHeader     = "Idempotency-Key"
)

// Registers kind 21's effect for the compute client and its lookup on every Sidecar of a compute leg.
func init() {
	registerComputeBudgetRaiseEffect(func(client *ComputeClient, action *StoredCanonicalAction) SidecarEffect {
		broker, ok := client.host.(ComputeBudgetRaiseBroker)
		if !ok || action == nil {
			return nil
		}
		return NewComputeBudgetRaiseEffect(broker, action.Bytes)
	})
	registerComputeComponent(computeBudgetRaiseComponentName, newSidecarComputeBudgetRaiseLookup, func(lookup *computeBudgetRaiseLookup) {
		lookup.unregister()
	})
}

// What kind 21's effect and lookup reach the broker through: a Sidecar's compute service client, read at use.
type ComputeBudgetRaiseBroker interface {
	ComputeServiceClient() (*ComputeServiceClient, error)
}

// An answer that is not the raise's: another approval, period or amount, or one that does not decode.
var ErrComputeBudgetRaiseAnswer = errors.New("the broker's answer is not this raise's")

// Kind 21's effect for one stored action. See the file header.
type ComputeBudgetRaiseEffect struct {
	broker ComputeBudgetRaiseBroker
	// the use's CanonicalAction as stored
	canonical []byte
}

var _ SidecarEffect = (*ComputeBudgetRaiseEffect)(nil)

// The effect of the stored compute_budget_raise action canonical, posting through broker.
func NewComputeBudgetRaiseEffect(broker ComputeBudgetRaiseBroker, canonical []byte) *ComputeBudgetRaiseEffect {
	return &ComputeBudgetRaiseEffect{broker: broker, canonical: bytes.Clone(canonical)}
}

// The raise, idempotent per effectKey through the broker's use row (see the file header).
func (self *ComputeBudgetRaiseEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	reference, err := computeBudgetRaisePresent(ctx, self.broker, self.canonical, effectKey)
	if err != nil {
		var refusal *ComputeServiceError
		if errors.As(err, &refusal) && refusal.Status/100 == 4 && refusal.Status != http.StatusTooManyRequests {
			return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
		}
		return nil, err
	}
	return reference, nil
}

// The request a use presents, nil and an error wrapping ErrSidecarEffectNotDone for one that cannot be sent.
func computeBudgetRaiseRequestOf(ctx context.Context, canonical []byte, effectKey []byte) (*protocol.ComputeBudgetRaiseRequest, *StoredCanonicalAction, *ApprovalSpend, error) {
	if len(effectKey) == 0 {
		// kind 21 takes no standing grant: every raise is a person's decision
		return nil, nil, nil, fmt.Errorf("%w: a budget raise runs only under a decision", ErrSidecarEffectNotDone)
	}
	spend, ok := ApprovalSpendFromContext(ctx)
	if !ok || len(spend.Decisions) == 0 {
		return nil, nil, nil, fmt.Errorf("%w: a use's key with no spend", ErrSidecarEffectNotDone)
	}
	if !bytes.Equal(spend.Action, canonical) {
		return nil, nil, nil, fmt.Errorf("%w: a version-5 action takes no template", ErrSidecarEffectNotDone)
	}
	action, err := ParseStoredCanonicalAction(canonical)
	if err != nil || SidecarActionKind(action.Action.GetKind()) != SidecarActionComputeBudgetRaise || action.Action.GetBudget() == nil {
		return nil, nil, nil, fmt.Errorf("%w: no compute_budget_raise action", ErrSidecarEffectNotDone)
	}
	return &protocol.ComputeBudgetRaiseRequest{Decisions: spend.Decisions, Action: bytes.Clone(canonical)}, action, spend, nil
}

// Presents a use's raise to the broker under effectKey: the stored result's bytes, or why there is none.
func computeBudgetRaisePresent(ctx context.Context, broker ComputeBudgetRaiseBroker, canonical []byte, effectKey []byte) ([]byte, error) {
	request, action, spend, err := computeBudgetRaiseRequestOf(ctx, canonical, effectKey)
	if err != nil {
		return nil, err
	}
	client, err := broker.ComputeServiceClient()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
	}
	answer := &protocol.ComputeBudgetRaiseAnswer{}
	if err := client.PostIdempotent(ctx, computeBudgetRaisePath, base64.RawURLEncoding.EncodeToString(effectKey), request, answer, 0); err != nil {
		if errors.Is(err, ErrComputeServiceUnconfigured) || errors.Is(err, ErrComputeServiceRequest) {
			return nil, fmt.Errorf("%w: %w", ErrSidecarEffectNotDone, err)
		}
		return nil, err
	}
	budget := action.Action.GetBudget()
	if !bytes.Equal(answer.GetApprovalId(), spend.ApprovalId.Bytes()) || answer.GetPeriod() != budget.GetPeriod() || answer.GetAmount() != budget.GetAmount() {
		return nil, ErrComputeBudgetRaiseAnswer
	}
	reference, err := proto.MarshalOptions{Deterministic: true}.Marshal(answer)
	if err != nil {
		return nil, err
	}
	return reference, nil
}

// The broker's stored result a use's reference holds.
func ParseComputeBudgetRaiseReference(reference []byte) (*protocol.ComputeBudgetRaiseAnswer, error) {
	answer := &protocol.ComputeBudgetRaiseAnswer{}
	if err := proto.Unmarshal(reference, answer); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrComputeBudgetRaiseAnswer, err)
	}
	return answer, nil
}

// Kind 21's Lookup through broker: the request again under its key, done with the stored result, anything else
// uncertain.
func ComputeBudgetRaiseLookup(broker ComputeBudgetRaiseBroker) SidecarEffectLookup {
	return func(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
		reference, err := computeBudgetRaisePresent(ctx, broker, canonical, effectKey)
		if err != nil {
			return &SidecarOutcome{State: ApprovalOutcomeUncertain, Err: err}, nil
		}
		return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: reference}, nil
	}
}

// Registers kind 21's Lookup on sidecar's gate, through its own compute service client; the answer removes it.
func RegisterComputeBudgetRaiseLookup(sidecar *Sidecar) func() {
	return sidecar.RegisterEffectLookup(SidecarActionComputeBudgetRaise, ComputeBudgetRaiseLookup(sidecar))
}

// The component that keeps kind 21's Lookup registered for its Sidecar's life.
type computeBudgetRaiseLookup struct {
	unregister func()
}

func newSidecarComputeBudgetRaiseLookup(sidecar *Sidecar) (*computeBudgetRaiseLookup, error) {
	return &computeBudgetRaiseLookup{unregister: RegisterComputeBudgetRaiseLookup(sidecar)}, nil
}
