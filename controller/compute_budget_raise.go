// Kind 21's raise at the broker (DESIGN-COMPUTE §9.7, §14.3, §16.3, §16.4, D-BAL-8, D-CACL-6; BAL-M12-16): what POST
// compute/v1/budget/raise does once its handler has parsed the request and checked its action and effect key
// (computeservice's ledger_budget_raise.go), as DESIGN §16.6's gate does for a server-gated effect, in one transaction
// under the network's fence (model.ComputeFenceInTx), which a rebuild of the projection holds through its snapshot and
// its script, so a raise is in a rebuild's snapshot or written after its script, never lost between the two:
//
//	1  the use the request's effect key took answers it, past its decision's expiry too, while its row lasts: a
//	   raise approved once and retried adds nothing
//	2  else the spend check at server time, the caller's, which refuses writing nothing
//	3  the first free use of the approval is claimed with the raise in its row: the new amount, its subject, its period
//	   and its expiry; a racing request with the same key answers the first's row, and none left is spent
//	4  COMMIT, the linearization point
//
// then, after the commit, the raised cap into the subject's counters in the projection (ComputeProjectionRaise), every
// time, a repeat included, so a raise whose commit outlived its script is applied by the device's retry; a network
// with no projection takes it from its rebuild. A script that fails answers an error, which the route answers
// unavailable, so the device's effect stays uncertain and its retry completes it.
//
// What a raise raises (§16.4): the subject's budgets for the UTC day or month it is taken in, each capped at the larger
// of its own cap and the raise, until the period ends. A raise of period run acts only on the device, in the Harness's
// run budget, since the broker counts days and months (a reading, reported); so does one whose action names no agent, a
// gateway grant's, its grant sealed where no gate reads it, which the broker keeps for its use and raises nothing by
// (compute-plan question bal-m12-15-grant-raise-broker-subject; failing closed). Its expiry is its period's end, or its
// decision set's expiry where that is later, so no row is deleted while its decision could still be presented.

package controller

import (
	"context"
	"errors"
	"fmt"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

var (
	// The spend check refused the decisions: nothing was written (§16.6's gate step 1).
	ErrComputeBudgetRaiseRefused = errors.New("compute budget raise: the decisions do not spend")
	// A raise the gate cannot take: no approval or key, a period §16.3 does not name, an amount out of range, or a
	// stored row of another approval under the key.
	ErrComputeBudgetRaiseArgs = errors.New("compute budget raise: arguments refused")
)

// What the spend check at server time answers: the uses the decisions spend for and their earliest expiry.
type ComputeBudgetRaiseSpend struct {
	Uses           uint32
	NotAfterMillis int64
}

// One raise the route asks for.
type ComputeBudgetRaiseRequest struct {
	NetworkId  operator.Id
	ApprovalId operator.Id
	// The use's effect key's column, ComputeBudgetRaiseEffectKeyId of the key the action derives.
	EffectKey operator.Id
	// The subject whose budgets rise; nil for a raise only the device applies (a gateway grant's).
	SubjectId *operator.Id
	Period    model.ComputeBudgetPeriod
	// The raised cap, nano-USD.
	AmountNanoUsd int64
	// The spend check at server time, which runs in the claim's transaction only where no use of the key stands; a
	// refusal wraps ErrComputeBudgetRaiseRefused.
	Spend func(now time.Time) (*ComputeBudgetRaiseSpend, error)
}

// What a raise came to.
type ComputeBudgetRaiseAnswer struct {
	// The row the key's use stands as: the stored result a repeat answers.
	Raise *model.ComputeBudgetRaise
	// An earlier request committed it: no spend check ran and nothing was written.
	Replayed bool
	// The broker applies it: a day's or month's naming a subject. A run's, and a grant's, the device alone applies.
	AtBroker bool
}

// The end of the UTC day or month now falls in, for a raise of period; the decision's expiry for a run, which has no
// broker period. The later of that and notAfter.
func computeBudgetRaiseExpire(period model.ComputeBudgetPeriod, now time.Time, notAfter time.Time) time.Time {
	end := notAfter
	switch period {
	case model.ComputeBudgetPeriodDay:
		end = model.ComputeUtcDay(now).AddDate(0, 0, 1)
	case model.ComputeBudgetPeriodMonth:
		end = model.ComputeUtcMonth(now).AddDate(0, 1, 0)
	}
	if end.Before(notAfter) {
		end = notAfter
	}
	return end.UTC()
}

// Takes request's raise (see the file header).
func ComputeBudgetRaiseTake(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeBudgetRaiseRequest) (*ComputeBudgetRaiseAnswer, error) {
	var zero operator.Id
	if request == nil || request.NetworkId == zero || request.ApprovalId == zero || request.EffectKey == zero || request.Spend == nil {
		return nil, fmt.Errorf("%w: a raise names its network, approval, key and spend check", ErrComputeBudgetRaiseArgs)
	}
	switch request.Period {
	case model.ComputeBudgetPeriodDay, model.ComputeBudgetPeriodMonth, model.ComputeBudgetPeriodRun:
	default:
		return nil, fmt.Errorf("%w: period %s", ErrComputeBudgetRaiseArgs, request.Period)
	}
	if request.SubjectId != nil && *request.SubjectId == zero {
		return nil, fmt.Errorf("%w: a subject is no nil id", ErrComputeBudgetRaiseArgs)
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	answer := &ComputeBudgetRaiseAnswer{}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		*answer = ComputeBudgetRaiseAnswer{}
		if err := model.ComputeFenceInTx(env, ctx, tx, request.NetworkId); err != nil {
			return err
		}
		now := clock.Now()
		stands, err := model.ComputeBudgetRaiseByEffectKeyInTx(env, ctx, tx, request.NetworkId, request.EffectKey)
		if err != nil {
			return err
		}
		if stands != nil {
			answer.Raise, answer.Replayed = stands, true
			return nil
		}
		spend, err := request.Spend(now)
		if err != nil {
			return err
		}
		if spend == nil || spend.Uses == 0 {
			return fmt.Errorf("%w: no use to spend", ErrComputeBudgetRaiseRefused)
		}
		testHookBarrier("compute_budget_raise.claim.before", request.ApprovalId.String())
		subjectId := zero
		if request.SubjectId != nil {
			subjectId = *request.SubjectId
		}
		claimed, taken, err := model.ComputeBudgetRaiseClaimInTx(env, ctx, tx, &model.ComputeBudgetRaise{
			ApprovalId:    request.ApprovalId,
			EffectKey:     request.EffectKey,
			NetworkId:     request.NetworkId,
			SubjectId:     subjectId,
			Period:        request.Period,
			AmountNanoUsd: request.AmountNanoUsd,
			ExpireTime:    computeBudgetRaiseExpire(request.Period, now, time.UnixMilli(spend.NotAfterMillis)),
			CreateTime:    now.UTC(),
		}, spend.Uses)
		if err != nil {
			return err
		}
		answer.Raise, answer.Replayed = claimed, !taken
		return nil
	}, operator.DbIsolationReadCommitted)
	testHookBarrier("compute_budget_raise.claim.after", request.ApprovalId.String())
	if err != nil {
		return nil, err
	}
	if answer.Raise.ApprovalId != request.ApprovalId {
		// a key's row is its approval's own: one of another names another action, which no request reads
		return nil, fmt.Errorf("%w: the key's row is another approval's", ErrComputeBudgetRaiseArgs)
	}
	answer.AtBroker = answer.Raise.AtBroker()
	if !answer.AtBroker {
		return answer, nil
	}
	if _, err := model.ComputeProjectionRaise(env, ctx, settings, answer.Raise); err != nil {
		return nil, err
	}
	return answer, nil
}

// Deletes the raises past their expiry at now: compute_rollup_day's sweep, so none outlives compute-6's ttl by more than
// the job's day.
func ComputeBudgetRaisePrune(env operator.Env, ctx context.Context, now time.Time) (int64, error) {
	db, err := env.Db()
	if err != nil {
		return 0, err
	}
	pruned := int64(0)
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		var err error
		pruned, err = model.ComputeBudgetRaisePruneInTx(env, ctx, tx, now)
		return err
	}, operator.DbIsolationReadCommitted)
	return pruned, err
}
