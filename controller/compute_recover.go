// compute_op_recover (DESIGN-COMPUTE §9.7, §14.5, D-BAL-13; BAL-M12-04): every minute, the operation rows whose
// producer stopped are finished through each kind's ComputeRecoverSource, which the areas that make the operations
// register from their own files at init:
//
//	inference    INFER's (C§6.6): a TEE call open the settings' 10 minutes, from its provider's usage record by its
//	             instance and provider nonce; a direct call is left to INFER's compute_direct_settle
//	enclave_run  ENC's (C§11.6): an interval from the enclave's committed transitions
//	web_search   SRCH's (C§21.5): a search as §21.5 says
//
// A source answers finished, with the outcome, which settles the row as its producer would have; unknown, never served,
// which releases it at no charge; or wait. A row whose kind has no source waits. Any row open the settings' 24 hours is
// released at no charge whatever its source says: its cost, where the provider bills it, is URnetwork's, and the run
// answers those by provider for §10.7's reconciliation.
//
// A void row's hold is dropped again before its row is deleted, once it started past the memo's window and on a run
// after the one that released it, so a release whose script did not reach Redis leaves no room held; a search's void
// row stays for its purge (§14.5).

package controller

import (
	"context"
	"fmt"
	"sync"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// What a source says of an open row whose producer stopped.
type ComputeRecoverState int

const (
	// It cannot say yet, or the operation is still running: the row stays open.
	ComputeRecoverWait ComputeRecoverState = 1
	// It finished: settle it with the outcome.
	ComputeRecoverFinished ComputeRecoverState = 2
	// It was never served: release it at no charge.
	ComputeRecoverUnknown ComputeRecoverState = 3
)

// A source's answer for one row.
type ComputeRecoverAnswer struct {
	State ComputeRecoverState
	// For finished: the outcome, at the prices of the catalog version the row records, and the path the operation
	// was held by.
	Outcome *ComputeOutcome
	Path    model.ComputeHoldPath
}

// What finishes a kind's rows whose producer stopped: INFER's, ENC's and SRCH's, each registered by kind.
type ComputeRecoverSource interface {
	Recover(env operator.Env, ctx context.Context, op *model.ComputeOp) (*ComputeRecoverAnswer, error)
}

var (
	computeRecoverSourcesLock sync.Mutex
	computeRecoverSources     = map[model.ComputeChargeKind]ComputeRecoverSource{}
)

// Registers kind's source, from its area's own file at init. A kind no hold path takes, and a second source for a
// kind, panic: a build that registers wrongly does not start.
func RegisterComputeRecoverSource(kind model.ComputeChargeKind, source ComputeRecoverSource) {
	if kind != model.ComputeChargeKindInference && kind != model.ComputeChargeKindEnclaveRun && kind != model.ComputeChargeKindWebSearch {
		panic(fmt.Errorf("compute recover: kind %s has no hold, so nothing to recover", kind))
	}
	computeRecoverSourcesLock.Lock()
	defer computeRecoverSourcesLock.Unlock()
	if _, ok := computeRecoverSources[kind]; ok {
		panic(fmt.Errorf("compute recover: a second source for kind %s", kind))
	}
	computeRecoverSources[kind] = source
}

// kind's source, nil while none is registered.
func computeRecoverSource(kind model.ComputeChargeKind) ComputeRecoverSource {
	computeRecoverSourcesLock.Lock()
	defer computeRecoverSourcesLock.Unlock()
	return computeRecoverSources[kind]
}

// What one run of compute_op_recover did.
type ComputeRecoverResult struct {
	// Rows settled from their source, released as never served, and left open.
	SettledCount  int
	ReleasedCount int
	WaitingCount  int
	// Rows released at no charge for being open the settings' 24 hours, by provider: URnetwork's cost where the
	// provider bills them (§10.7).
	ExpiredProviderCounts map[int16]int
	// Void rows dropped from Redis again and deleted.
	VoidDeletedCount int
}

// Runs one pass of compute_op_recover (see the file header). A row its source fails on waits for the next run.
func ComputeRecover(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings) (*ComputeRecoverResult, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	now := clock.Now()
	result := &ComputeRecoverResult{ExpiredProviderCounts: map[int16]int{}}
	ops, err := model.ComputeOpListOpen(env, ctx, now.Add(-settings.TeeRecoverAfter), settings.RecoverBatchRowCount)
	if err != nil {
		return nil, err
	}
	// the rows this run releases stay for the next run's void pass, which drops their holds again
	released := map[operator.Id]bool{}
	for _, op := range ops {
		if !op.StartTime.After(now.Add(-settings.OpReleaseAfter)) {
			state, err := ComputeRelease(env, ctx, settings, op.NetworkId, op.OpKey)
			if err != nil {
				result.WaitingCount += 1
				continue
			}
			if state == ComputeReleaseReleased {
				result.ExpiredProviderCounts[op.Provider] += 1
				released[op.OpKey] = true
			}
			continue
		}
		source := computeRecoverSource(op.Kind)
		if source == nil {
			result.WaitingCount += 1
			continue
		}
		answer, err := source.Recover(env, ctx, op)
		if err != nil || answer == nil {
			result.WaitingCount += 1
			continue
		}
		switch answer.State {
		case ComputeRecoverFinished:
			settled, err := ComputeSettle(env, ctx, settings, &ComputeSettleRequest{
				NetworkId: op.NetworkId, OpKey: op.OpKey, Path: answer.Path, Outcome: answer.Outcome,
			})
			if err != nil || settled.State != ComputeSettleSettled {
				result.WaitingCount += 1
				continue
			}
			result.SettledCount += 1
		case ComputeRecoverUnknown:
			if _, err := ComputeRelease(env, ctx, settings, op.NetworkId, op.OpKey); err != nil {
				result.WaitingCount += 1
				continue
			}
			result.ReleasedCount += 1
			released[op.OpKey] = true
		default:
			result.WaitingCount += 1
		}
	}
	// void rows past the memo's window: their holds dropped again where a release's script missed, then deleted
	voids, err := model.ComputeOpListVoid(env, ctx, now.Add(-settings.ProjectionMemoTtl), settings.RecoverBatchRowCount)
	if err != nil {
		return result, err
	}
	deleteKeys := []operator.Id{}
	for _, op := range voids {
		if released[op.OpKey] {
			continue
		}
		if _, err := model.ComputeProjectionVoid(env, ctx, settings, op.NetworkId, op.OpKey, op.SubjectIds()); err != nil {
			continue
		}
		deleteKeys = append(deleteKeys, op.OpKey)
	}
	if err := model.ComputeOpDeleteVoid(env, ctx, deleteKeys); err != nil {
		return result, err
	}
	result.VoidDeletedCount = len(deleteKeys)
	return result, nil
}
