//go:build !ios_extension && !sidecar_http

// The disclosure check (DESIGN-COMPUTE §6.4, §2.8; CO-34, D-INFER-6, R-INFER-8): before any call to a model labeled
// none, the router reads the acknowledgments that cover the caller, the person's compute.disclosures on their own
// devices, an enclave's sponsor's, or on a tagged or cloud sidecar the network's (CO-41), which CTRUST's source decides,
// and the call passes only where they cover its provider's disclosure, inference:<provider>, at the newest verified
// policy's current version, or at the previous version while the current one's grace runs (§2.8's new version: grace
// days from the instant the version took effect, compute-plan-disclosure-grace-start; a grace of 0 refuses at once).
//
// Otherwise, where a person is attached to the run, the router asks them through the run (§7.6's disclosure request,
// naming the id and version alone) and waits: their acknowledgment must then have landed in the acknowledgments the
// source reads, since the router takes no answer on its word, and "Not now" fails the call disclosure_required with
// reason declined, which the Harness answers with §7.4's choice of another model or local. Any other caller gets
// disclosure_required, reason unacknowledged, naming the id and version and the fix, before the broker is asked or a
// byte leaves the device: a child agent, a run its inbox woke, an enclave's agent with no session attached, an MCP or a
// gateway call, ur without a terminal. A gateway call never asks: a harness behind the gateway has no one to show the
// request to.
//
// The text of the disclosure is never here: CTRUST renders it from the signed policy by its id (D-ATTEST-7). A policy
// that carries no disclosure for the provider refuses its models, since no one could acknowledge it.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The length of one of a disclosure's grace days: a unit, not a tunable.
const inferDisclosureGraceDay = 24 * time.Hour

// Whether the acknowledged version covers disclosure at now: its current version or a later one, or the previous one
// while the current version's grace runs.
func inferDisclosureCovered(acknowledged uint32, disclosure *ComputePolicyDisclosure, now time.Time) bool {
	switch {
	case disclosure.Version <= acknowledged:
		return true
	case acknowledged == 0 || acknowledged+1 != disclosure.Version || disclosure.GraceDays == 0:
		return false
	}
	graceEnd := time.UnixMilli(disclosure.SinceMs).Add(time.Duration(disclosure.GraceDays) * inferDisclosureGraceDay)
	return now.Before(graceEnd)
}

// Whether the acknowledgments that cover the caller cover disclosure now, and whose they are.
func (self *inferSourceChecker) disclosureCovered(ctx context.Context, disclosure *ComputePolicyDisclosure) (bool, InferAcknowledgmentScope, error) {
	set, err := self.sources.Acknowledgments.Covering(ctx)
	if err != nil {
		return false, "", err
	}
	if set == nil {
		return false, "", errors.New("no acknowledgments")
	}
	return inferDisclosureCovered(set.Versions[disclosure.Id], disclosure, self.sources.Policy.Now()), set.Scope, nil
}

// disclosure_required for call's disclosure, saying who may acknowledge it and how (§2.8's refusal row).
func inferDisclosureRequired(call *InferCall, disclosure *ComputePolicyDisclosure, scope InferAcknowledgmentScope, reason string) *InferError {
	fix := fmt.Sprintf("acknowledge %s in the app's settings, or with ur disclosures ack %s", disclosure.Id, disclosure.Id)
	switch scope {
	case InferAcknowledgmentNetwork:
		fix = fmt.Sprintf("an Owner or Admin acknowledges %s for the network, in its settings or with ur disclosures ack %s --network", disclosure.Id, disclosure.Id)
	case InferAcknowledgmentSponsor:
		fix = fmt.Sprintf("the enclave's sponsor acknowledges %s on one of their devices", disclosure.Id)
	}
	message := fmt.Sprintf("%s's provider runs outside any TEE, and its disclosure %s version %d is not acknowledged: %s", call.Name, disclosure.Id, disclosure.Version, fix)
	if reason == InferDisclosureReasonDeclined {
		message = fmt.Sprintf("the disclosure %s version %d was not acknowledged (Not now)", disclosure.Id, disclosure.Version)
	}
	return &InferError{
		Code:              InferErrorDisclosureRequired,
		Model:             call.Name,
		Reason:            reason,
		Message:           message,
		DisclosureId:      disclosure.Id,
		DisclosureVersion: disclosure.Version,
	}
}

// A none model's disclosure check, over policy's text for its provider.
func (self *inferSourceChecker) checkDisclosure(ctx context.Context, call *InferCall, policy *ComputePolicy) error {
	id := call.Entry.DisclosureId()
	disclosure := policy.Disclosure(id)
	if disclosure == nil {
		return inferRefused(call, InferRefusedRuleDisclosure, "the policy carries no disclosure %s, which a model labeled none waits for", id)
	}
	covered, scope, err := self.disclosureCovered(ctx, disclosure)
	if err != nil {
		return inferRefused(call, InferRefusedRuleSource, "the disclosure acknowledgments do not read: %s", err)
	}
	if covered {
		return nil
	}
	request := call.Request
	asker := self.sources.Asker
	if request == nil || request.Binding != nil || request.RunId == nil || asker == nil || !asker.Attached(*request.RunId) {
		return inferDisclosureRequired(call, disclosure, scope, InferDisclosureReasonUnacknowledged)
	}
	testHookBarrier("infer.disclosure.ask.before", disclosure.Id)
	acknowledged, err := asker.Ask(ctx, &InferDisclosureAsk{
		RunId:             *request.RunId,
		AgentId:           request.AgentId,
		DisclosureId:      disclosure.Id,
		DisclosureVersion: disclosure.Version,
	})
	switch {
	case ctx.Err() != nil:
		return &InferError{Code: InferErrorCanceled, Model: call.Name, Message: "the call's context ended while its disclosure was asked"}
	case err != nil:
		return inferDisclosureRequired(call, disclosure, scope, InferDisclosureReasonUnacknowledged)
	case !acknowledged:
		return inferDisclosureRequired(call, disclosure, scope, InferDisclosureReasonDeclined)
	}
	// the answer's word is not taken: the acknowledgment must have landed
	covered, scope, err = self.disclosureCovered(ctx, disclosure)
	if err != nil {
		return inferRefused(call, InferRefusedRuleSource, "the disclosure acknowledgments do not read: %s", err)
	}
	if !covered {
		return inferDisclosureRequired(call, disclosure, scope, InferDisclosureReasonUnacknowledged)
	}
	return nil
}
