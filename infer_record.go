//go:build !ios_extension && !sidecar_http

// A call's model receipt (DESIGN-COMPUTE §6.8, R-INFER-6, R-ATTEST-5, D-INFER-4; RECORD.md section 12): InferModelCall
// builds the model_call entry's ModelCallBody from a finished call, which the Harness and the gateway write into the
// call's run (§7.7, §8.9), so this is the builder and the rule, never a writer of its own. A hook's model_call for the
// same request id keeps merging with the gateway's as §8.9 says.
//
// The body names the canonical name the call ran under as its model, the provider's slug, the request id, the usage
// and, for a remote call, the broker's charge as reported_micro_usd, and §6.8's fields: the route, local, tee or direct;
// the catalog version a remote call named; and for a TEE call whose evidence §5 verified, the AttestationResult and the
// platform field at evidence 4, attested, naming the policy profile the TEE booted, while the model stays as the
// provider names it, reported, since no provider's evidence covers the serving code or the weights (§4.5, D-RECORD-11).
// A direct call records its route and the provider's usage and no attestation: its label, none, is the route's
// (compute-plan-inference-small-readings). record_body.go's rule (recordModelCallValidate) holds every body to that, the
// builder's first.
//
// Safe for concurrent use: a function of its arguments.

package sidecar

import (
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A body the builder refuses: a call it cannot record as it ran.
var ErrInferModelCallInvalid = errors.New("model call not recordable")

// What a finished call's receipt is built from.
type InferModelCallArgs struct {
	// The call as the router resolved it: its canonical name, its entry's provider and kind.
	Call *InferCall
	// The provider's request id as it reports it, or the router's own for a local call.
	RequestId string
	// The call's usage, with a remote call's charge; nil for none.
	Usage *InferUsage
	// A TEE call's attestation, as its attestation event carried it from §5's checks; nil for a local or direct call.
	Attestation *protocol.AttestationResult
	// The broker's catalog version the call named; 0 for a local call.
	CatalogVersion uint64
	// When the call began, and how long it took.
	StartedAt time.Time
	Duration  time.Duration
}

// A model_call's route for a catalog kind.
func inferModelCallRoute(kind InferCatalogKind) (string, error) {
	switch kind {
	case InferCatalogKindLocal:
		return RecordModelCallRouteLocal, nil
	case InferCatalogKindTee:
		return RecordModelCallRouteTee, nil
	case InferCatalogKindDirect:
		return RecordModelCallRouteDirect, nil
	}
	return "", fmt.Errorf("%w: a %s entry is no model's", ErrInferModelCallInvalid, kind)
}

// nanoUsd in micro-USD, rounded up, so a charge is never recorded as free.
func inferMicroUsd(nanoUsd uint64) uint64 {
	micro := nanoUsd / 1000
	if nanoUsd%1000 != 0 {
		micro += 1
	}
	return micro
}

// The model_call body of a finished call, held to record_body.go's rule: refuses a call with no entry, a TEE call with
// no verified attestation, since §6.4 sends it before the first token, an attestation on any other route, and a body
// the rule refuses.
func InferModelCall(args *InferModelCallArgs) (*protocol.ModelCallBody, error) {
	if args == nil || args.Call == nil || args.Call.Entry == nil {
		return nil, fmt.Errorf("%w: no call", ErrInferModelCallInvalid)
	}
	call := args.Call
	route, err := inferModelCallRoute(call.Entry.Kind)
	if err != nil {
		return nil, err
	}
	body := &protocol.ModelCallBody{
		Model:     call.Name,
		Provider:  call.Entry.Provider,
		RequestId: args.RequestId,
		Route:     route,
	}
	if !args.StartedAt.IsZero() {
		body.StartedMillis = args.StartedAt.UnixMilli()
	}
	if 0 < args.Duration {
		body.DurationMillis = uint32(min(args.Duration.Milliseconds(), int64(^uint32(0))))
	}
	if usage := args.Usage; usage != nil {
		body.InputTokens = usage.InputTokens
		body.OutputTokens = usage.OutputTokens
		body.CacheReadTokens = usage.CachedTokens
		if route != RecordModelCallRouteLocal {
			body.ReportedMicroUsd = inferMicroUsd(usage.ChargeNanoUsd)
		}
	}
	if route != RecordModelCallRouteLocal {
		body.CatalogVersion = args.CatalogVersion
	}
	switch {
	case route == RecordModelCallRouteTee && args.Attestation == nil:
		return nil, fmt.Errorf("%w: a TEE call with no verified attestation", ErrInferModelCallInvalid)
	case route != RecordModelCallRouteTee && args.Attestation != nil:
		return nil, fmt.Errorf("%w: an attestation on a %s call", ErrInferModelCallInvalid, route)
	case route == RecordModelCallRouteTee:
		body.Attestation = proto.Clone(args.Attestation).(*protocol.AttestationResult)
		// the platform the policy profile names, attested; the model stays as the provider names it
		body.Platform = &protocol.ModelField{Value: args.Attestation.GetProfileId(), Evidence: RecordModelEvidenceAttested}
	}
	if err := recordModelCallValidate(body); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInferModelCallInvalid, err)
	}
	return body, nil
}
