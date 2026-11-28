// ComputeSearchLedger: what web search's admission, settlement and jobs ask of BAL's ledger (DESIGN-COMPUTE §9.7, §9.9,
// §9.11, §21.8, §21.9, D-BAL-14; SRCH-M13-07, SRCH-M13-08). The broker is the only place a search is charged, and every
// charge goes through these:
//
//	ClauseAccepted  the compute terms' web search clause, which the network's projection carries once BAL-M13-03
//	                lands ComputeSearchClauseAccepted; until then no network has accepted it, and every search
//	                answers search_off naming the fix
//	SearchCap       §9.11's search cap (controller.ComputeSearchCap), which no day_max passes
//	SearchCount     the network's search rows since a time, which rebuilds {cmpr_<network_id>}'s day after a loss
//	                (§9.7's lost cache)
//	Hold            one search's price held by the search path's script on {cmp_<network_id>}, under D-BAL-14's key, the
//	                UUIDv5 of the network, request id and attempt timed to the authorization's minute, its row committed
//	                before the answer admits (controller.ComputeHold, §9.7's handoff). BAL-M13-02 lands the search
//	                path's script; until then the ledger refuses the path (model.ErrComputeHoldPathUnbuilt) and every
//	                search answers capacity, never held some other way
//	Settle          a settled authorization's outcome committed to its row, then its hold turned into an unsettled
//	                kind-6 charge (controller.ComputeSettle)
//	Release         a lapsed or refused authorization's row voided and its hold dropped (controller.ComputeRelease)
//	OpenBefore      the open search rows past a time, for compute_search_tickets
//	DeleteBefore    every web search's charge, its lot draws and its row, a search refund's with them, from before a
//	                time, for compute_search_purge: BAL-M13-02's ComputeDeleteSearchRows, which has not landed, so the
//	                purge answers ErrComputeSearchLedgerUnbuilt and alarms until it does
//
// A refusal is an answer, never an error; an error means the ledger could not say, and the caller forwards nothing.
// The key and every row name the network, request id, attempt and minute alone: never a ticket, a nonce, a payee or a
// transaction (R2-08). Safe for concurrent use.

package computeservice

import (
	"context"
	"errors"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
)

// A ledger call whose part BAL has not landed: the purge's deletion (BAL-M13-02's ComputeDeleteSearchRows).
var ErrComputeSearchLedgerUnbuilt = errors.New("compute search: this part of the ledger is not built")

// One search's hold, as the admission asks for it.
type ComputeSearchHoldRequest struct {
	NetworkId sidecar.Id
	RequestId sidecar.Id
	// 1 to 3.
	Attempt int16
	// D-BAL-14's key, which the admission derived (controller.ComputeOpKeyForSearch), and the admission's minute it is
	// timed to, the charge's start.
	OpKey     sidecar.Id
	Minute    time.Time
	SidecarId sidecar.Id
	AgentId   *sidecar.Id
	// The member it counts to: an untagged sidecar's; nil for a tagged one.
	MemberId *sidecar.Id
	Tagged   bool
	// The network's policy names budgets of its own, which only CACL's resolver reads (C§16.4).
	PolicyNamesBudgets bool
	// The catalog version the request named, which priced it (§9.6).
	CatalogVersion int64
	// The authorization's value times the markup, rounded up to the search step (§21.8).
	HoldNanoUsd int64
}

// What a hold came to.
type ComputeSearchHoldAnswer struct {
	// Held, its row committed open and the hold confirmed: the ticket may go to the signer now.
	Admitted bool
	// D-BAL-14's key: its charge's charge_id.
	OpKey sidecar.Id
	// Why not, where neither admitted nor finished.
	Refusal *ComputeRefusal
	// The key's operation finished before: released, settled or booked. Nothing is held for it again.
	Finished bool
}

// One settled authorization's charge.
type ComputeSearchSettleRequest struct {
	NetworkId sidecar.Id
	OpKey     sidecar.Id
	// One search, its amount the hold (a charge never passes it), its cost the value paid, its end and settle times
	// to the minute (compute-10).
	Outcome *model.ComputeOpOutcome
}

// The searches' rows the purge deleted.
type ComputeSearchPurged struct {
	// Searches whose rows went.
	DeletedCount int
	// The oldest search row kept, its minute; nil for none.
	OldestTime *time.Time
}

// The ledger's search calls. See the file header.
type ComputeSearchLedger interface {
	ClauseAccepted(ctx context.Context, networkId sidecar.Id) (bool, error)
	SearchCap(ctx context.Context, networkId sidecar.Id) (int64, error)
	SearchCount(ctx context.Context, networkId sidecar.Id, since time.Time) (int64, error)
	Hold(ctx context.Context, request *ComputeSearchHoldRequest) (*ComputeSearchHoldAnswer, error)
	Settle(ctx context.Context, request *ComputeSearchSettleRequest) (controller.ComputeSettleState, error)
	Release(ctx context.Context, networkId sidecar.Id, opKey sidecar.Id) (controller.ComputeReleaseState, error)
	OpenBefore(ctx context.Context, before time.Time, limit int) ([]*model.ComputeOp, error)
	DeleteBefore(ctx context.Context, before time.Time, limit int) (*ComputeSearchPurged, error)
}

// BAL's ledger over an Env (owner decision 594).
type envComputeSearchLedger struct {
	env      operator.Env
	settings *model.ComputeLedgerSettings
}

// The real ledger over env, under the ledger's settings.
func NewComputeSearchLedger(env operator.Env, settings *model.ComputeLedgerSettings) ComputeSearchLedger {
	if settings == nil {
		settings = model.DefaultComputeLedgerSettings()
	}
	return &envComputeSearchLedger{env: env, settings: settings}
}

// See ComputeSearchLedger: false until BAL-M13-03's ComputeSearchClauseAccepted carries the clause in the network's
// projection, so no search is admitted for a network whose acceptance the broker cannot read.
func (self *envComputeSearchLedger) ClauseAccepted(ctx context.Context, networkId sidecar.Id) (bool, error) {
	return false, nil
}

// See ComputeSearchLedger.
func (self *envComputeSearchLedger) SearchCap(ctx context.Context, networkId sidecar.Id) (int64, error) {
	return controller.ComputeSearchCap(self.env, ctx, self.settings, networkId)
}

// See ComputeSearchLedger.
func (self *envComputeSearchLedger) SearchCount(ctx context.Context, networkId sidecar.Id, since time.Time) (int64, error) {
	return model.ComputeSearchOpCountSince(self.env, ctx, networkId, since)
}

// §16.5's budget lines for a search's subjects, until CACL's resolver gives the policy's (C§16.4).
func (self *envComputeSearchLedger) budgetLines(tagged bool, policyNamesBudgets bool) controller.ComputeBudgetLines {
	return func(ctx context.Context, subjects *controller.ComputeBudgetSubjects) ([]*model.ComputeBudgetLine, error) {
		return model.ComputeDefaultBudgetLines(self.settings, &model.ComputeBudgetCaller{
			SidecarId:          subjects.SidecarId,
			AgentId:            subjects.AgentId,
			Tagged:             tagged,
			PolicyNamesBudgets: policyNamesBudgets,
		})
	}
}

// See ComputeSearchLedger.
func (self *envComputeSearchLedger) Hold(ctx context.Context, request *ComputeSearchHoldRequest) (*ComputeSearchHoldAnswer, error) {
	opKey, start, err := controller.ComputeOpKeyForSearch(self.settings, request.NetworkId, request.RequestId, request.Attempt, request.Minute)
	if err != nil {
		return nil, err
	}
	if opKey != request.OpKey || !start.Equal(request.Minute) {
		// a key the ledger would not derive for this search: nothing is held under it
		return nil, errors.New("compute search: the hold's key is not D-BAL-14's for its search")
	}
	budgets := self.budgetLines(request.Tagged, request.PolicyNamesBudgets)
	lines, err := budgets(ctx, &controller.ComputeBudgetSubjects{
		NetworkId: request.NetworkId, Kind: model.ComputeChargeKindWebSearch, SidecarId: request.SidecarId,
		AgentId: request.AgentId, MemberId: request.MemberId,
	})
	if errors.Is(err, model.ErrComputeBudgetsUnread) {
		// a policy's own budgets the ledger cannot read yet: refused budget, as every call is (C§16.4)
		return &ComputeSearchHoldAnswer{OpKey: opKey, Refusal: &ComputeRefusal{Code: ComputeRefusalInsufficientQuota, Reason: string(controller.ComputeRefusalBudget)}}, nil
	}
	if err != nil {
		return nil, err
	}
	attempt := request.Attempt
	catalogVersion := request.CatalogVersion
	answer, err := controller.ComputeHold(self.env, ctx, self.settings, &controller.ComputeHoldRequest{
		NetworkId:      request.NetworkId,
		Kind:           model.ComputeChargeKindWebSearch,
		Path:           model.ComputeHoldPathSearch,
		OpKey:          &opKey,
		StartTime:      start,
		SubjectRef:     request.RequestId,
		Attempt:        &attempt,
		SidecarId:      request.SidecarId,
		AgentId:        request.AgentId,
		MemberId:       request.MemberId,
		CatalogVersion: &catalogVersion,
		Provider:       int16(ComputeProviderCodeParallel),
		HoldNanoUsd:    request.HoldNanoUsd,
		ReserveNanoUsd: request.HoldNanoUsd,
		Lines:          lines,
		Budgets:        budgets,
	})
	if err != nil {
		// the search path's script not landed (BAL-M13-02), or a ledger that could not say: nothing is held
		return nil, err
	}
	result := &ComputeSearchHoldAnswer{Admitted: answer.Admitted, OpKey: answer.OpKey, Finished: answer.Finished}
	if answer.Refusal != nil {
		reply := controller.ComputeRefusalAnswer(answer.Refusal)
		result.Refusal = &ComputeRefusal{Code: ComputeRefusalCode(reply.Code), Reason: reply.Reason, RetryAfter: reply.RetryAfter}
	}
	return result, nil
}

// See ComputeSearchLedger.
func (self *envComputeSearchLedger) Settle(ctx context.Context, request *ComputeSearchSettleRequest) (controller.ComputeSettleState, error) {
	answer, err := controller.ComputeSettle(self.env, ctx, self.settings, &controller.ComputeSettleRequest{
		NetworkId: request.NetworkId,
		OpKey:     request.OpKey,
		Path:      model.ComputeHoldPathSearch,
		Outcome:   request.Outcome,
	})
	if err != nil {
		return "", err
	}
	return answer.State, nil
}

// See ComputeSearchLedger.
func (self *envComputeSearchLedger) Release(ctx context.Context, networkId sidecar.Id, opKey sidecar.Id) (controller.ComputeReleaseState, error) {
	return controller.ComputeRelease(self.env, ctx, self.settings, networkId, opKey)
}

// See ComputeSearchLedger.
func (self *envComputeSearchLedger) OpenBefore(ctx context.Context, before time.Time, limit int) ([]*model.ComputeOp, error) {
	return model.ComputeSearchOpListOpen(self.env, ctx, before, limit)
}

// See ComputeSearchLedger: BAL-M13-02's ComputeDeleteSearchRows, which has not landed.
func (self *envComputeSearchLedger) DeleteBefore(ctx context.Context, before time.Time, limit int) (*ComputeSearchPurged, error) {
	return nil, ErrComputeSearchLedgerUnbuilt
}
