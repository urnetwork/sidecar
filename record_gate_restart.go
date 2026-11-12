//go:build !ios_extension

// §16.6's restart row (MCP-M3-06; D-MCP-11, AU2, AU3, FI-7): each Reserve with no done or not_done Outcome, across the
// network's approvals, reconciles by its kind's Lookup(effect_key), read from the stored action alone so no caller need
// be alive: done or not_done as the component proves it, else uncertain, which a retry of the same action completes
// under the same key. A Reserve is never undone and an uncertain use stays consumed. A file that does not read is
// reported and spends nothing (D-CORE-15).
//
// The host runs Reconcile once before the gate serves, so no retry of the same use races its Outcome. On every leg but
// the ios_extension legs.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// Reconciles every unresolved use, as the file header says. Answers how many Outcomes it recorded and the failures,
// each file that does not read among them, the rest having run.
func (self *ApprovalGate) Reconcile(ctx context.Context) (int, error) {
	unresolved, err := self.args.Ledger.Unresolved()
	if err != nil {
		return 0, err
	}
	recordedCount := 0
	errs := []error{}
	for _, item := range unresolved {
		if err := ctx.Err(); err != nil {
			return recordedCount, err
		}
		if item.Err != nil {
			errs = append(errs, fmt.Errorf("approval %s does not read, and nothing spends from it: %w", item.ApprovalId, item.Err))
			continue
		}
		recorded, err := self.reconcileReserve(ctx, item)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if recorded {
			recordedCount += 1
		}
	}
	return recordedCount, errors.Join(errs...)
}

// One unresolved use: its kind's Lookup from the stored action, its answer recorded where it proves done or not_done,
// and uncertain recorded where no Outcome was. Answers whether an Outcome was recorded.
func (self *ApprovalGate) reconcileReserve(ctx context.Context, item *ApprovalUnresolved) (bool, error) {
	state, err := self.args.Ledger.State(item.ApprovalId)
	if err != nil {
		return false, err
	}
	var request *StoredApprovalRequest
	if state.Request != nil {
		request, _ = ParseStoredApprovalRequest(state.Request)
	}
	canonical := item.Reserve.Canonical
	if len(canonical) == 0 && request != nil {
		if payloadSha256 := request.Action.PayloadSha256(); bytes.Equal(payloadSha256[:], item.Reserve.PayloadSha256) {
			canonical = request.Action.Bytes
		}
	}
	found := &SidecarOutcome{State: ApprovalOutcomeUncertain}
	if stored, err := ParseStoredCanonicalAction(canonical); err == nil {
		if lookup := self.lookup(SidecarActionKind(stored.Action.GetKind())); lookup != nil {
			spend := &ApprovalSpend{ApprovalId: item.ApprovalId, Action: canonical}
			if request != nil {
				spend.Action = request.Action.Bytes
			}
			kept, _ := approvalKeptDecisions(state)
			for _, decision := range kept {
				spend.Decisions = append(spend.Decisions, decision.stored)
			}
			answer, err := lookup(withApprovalSpend(ctx, spend), canonical, bytes.Clone(item.Reserve.EffectKey))
			if err == nil && answer != nil && answer.State.final() {
				found = &SidecarOutcome{State: answer.State, EffectRef: bytes.Clone(answer.EffectRef)}
			}
		}
	}
	if !found.State.final() && item.Uncertain {
		// its uncertain Outcome stands, for a retry to complete
		return false, nil
	}
	var runId *Id
	if request != nil && len(request.Request.GetRunId()) != 0 {
		id := recordIdOf(request.Request.GetRunId())
		runId = &id
	}
	if err := self.recordOutcome(item.ApprovalId, item.Reserve, found, runId); err != nil {
		return false, err
	}
	return true, nil
}
