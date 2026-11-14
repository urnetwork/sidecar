//go:build !ios_extension

// §16.6's spend steps for one use (MCP-M3-06; D-MCP-11, D-MCP-12, AU1-AU4, TS1, owner decision 142), which
// ApprovalGate.Authorize runs once it holds an approval for the action:
//
//	1  the approval's mutex (ApprovalLedger.Hold); the request binds this requester, run, agent, action and the
//	   action's detail, the socket name, local port, weight and ALPNs request_sha256 covers (QD-740, QD-772);
//	   spendable over the kept
//	   approving decisions, each approver's first, as §16.6's k approvers set (SpendableSet), its expiry test left out
//	   when this action's use is reserved already
//	2  that Reserve exists: the retry path, after the mutex
//	3  refuse: cancelled; spent at uses Reserves; stale in a tainted run on an untainted request, where a tainted
//	   request is filed and the answer is pending; a harness decision in a tainted run whose rule's own list does not
//	   name harness (owner decision 142); expired past not_after, or for a gate kind past not_after minus §8.6's skew,
//	   so a prompt presentation meets the gate's clock; a kind with no registered Lookup
//	4  Reserve{use_index = the count}, fsynced, the action's bytes kept in it: the linearization point of a local use
//	5  after the mutex: the effect under effect_key, the spend on its context (ApprovalSpendFromContext), record.effect's
//	   barriers around it
//	6  Outcome, fsynced between record.outcome's barriers: done with the effect's reference; not_done only where the
//	   effect proved it, never on a gate kind's second presentation, since the first may still commit; else uncertain;
//	   then the use's approval_use entry
//
// A retry finds its outcome: done or not_done answers it, the effect not run again (AU4); uncertain, or none after a
// kill, runs the effect again under the same key, which its component holds idempotent, until not_after plus
// ApprovalCompleteTimeout, past which it only reconciles by the kind's Lookup. Two callers of one action at once join
// one flight, keyed by effect_key, so both get one effect. A Reserve is never undone, and an uncertain use stays
// consumed: a different action never takes it (AU3).

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What the mutex's steps decided for one use.
type approvalSpendPlan struct {
	request *StoredApprovalRequest
	// the use's Reserve, taken now or before
	reserve *ApprovalReserve
	// this action's use was reserved before this call: the retry path
	retry bool
	// the use's standing outcome before this call, nil for none
	outcome *ApprovalOutcome
	// the decisions the use spends on, each its Signed as stored, and their earliest not_after
	decisions      [][]byte
	notAfterMillis int64
	// step 3's stale: the run is tainted and the request was not
	stale bool
}

// The action a reserved use acts on: the bytes its Reserve keeps, else its request's own.
func (self *approvalSpendPlan) canonical() []byte {
	if len(self.reserve.Canonical) != 0 {
		return self.reserve.Canonical
	}
	return self.request.Action.Bytes
}

// The spend of one use of approvalId by action, joined by every caller of the same action while it runs. Sets
// action.Outcome and answers nil once the effect has an outcome.
func (self *ApprovalGate) spend(ctx context.Context, action *SidecarAction, stored *StoredCanonicalAction, approvalId Id, tainted bool) error {
	actionId := stored.ActionId(approvalId)
	effectKey := ApprovalEffectKey(approvalId, actionId)
	outcome, err := self.flights.do(ctx, string(effectKey[:]), func() (*SidecarOutcome, error) {
		return self.spendOnce(ctx, action, stored, approvalId, actionId, effectKey, tainted)
	})
	if err != nil {
		return err
	}
	action.Outcome = outcome
	return nil
}

// One flight of the spend: steps 1 to 4 under the approval's mutex, then the effect and its Outcome after it.
func (self *ApprovalGate) spendOnce(ctx context.Context, action *SidecarAction, stored *StoredCanonicalAction, approvalId Id,
	actionId [sha256.Size]byte, effectKey [sha256.Size]byte, tainted bool) (*SidecarOutcome, error) {
	kind := SidecarActionKind(stored.Action.GetKind())
	plan, err := func() (*approvalSpendPlan, error) {
		hold := self.args.Ledger.Hold(approvalId)
		defer hold.Release()
		return self.planWithHold(hold, action, stored, approvalId, actionId, effectKey, tainted)
	}()
	if err != nil {
		return nil, err
	}
	if plan.stale {
		// TS1: a decision on an untainted request spends nothing in a tainted run, so the run asks afresh, tainted
		request, err := self.router.findOrFile(ctx, action, stored, true)
		if err != nil {
			return nil, err
		}
		return nil, &ApprovalPendingError{ApprovalId: request.ApprovalId()}
	}
	if plan.outcome != nil && plan.outcome.State.final() {
		// AU4: the original outcome, the effect not run again
		return &SidecarOutcome{State: plan.outcome.State, EffectRef: bytes.Clone(plan.outcome.EffectRef)}, nil
	}
	spendCtx := withApprovalSpend(ctx, &ApprovalSpend{
		ApprovalId: approvalId, Decisions: plan.decisions, Action: plan.request.Action.Bytes, Detail: plan.request.Detail(),
	})
	completeBy := time.UnixMilli(plan.notAfterMillis).Add(self.args.Settings.ApprovalCompleteTimeout)
	if plan.retry && self.args.Clock.Now().After(completeBy) {
		return self.reconcileUse(spendCtx, approvalId, plan, kind, action.RunId)
	}
	return self.runEffect(spendCtx, action, approvalId, plan, kind)
}

// Steps 1 to 4 under the approval's mutex: the request binds this requester, run, agent and action; spendable; the
// retry path where this action's use is reserved; step 3's refusals; and the Reserve.
func (self *ApprovalGate) planWithHold(hold *ApprovalHold, action *SidecarAction, stored *StoredCanonicalAction, approvalId Id,
	actionId [sha256.Size]byte, effectKey [sha256.Size]byte, tainted bool) (*approvalSpendPlan, error) {
	state, err := hold.State()
	if err != nil {
		return nil, err
	}
	if state.Request == nil {
		return nil, fmt.Errorf("%w: %s", ErrApprovalUnknown, approvalId)
	}
	request, err := ParseStoredApprovalRequest(state.Request)
	if err != nil {
		return nil, err
	}
	if recordIdOf(request.Request.GetRequesterSidecarId()) != self.args.SidecarId ||
		recordIdOf(request.Request.GetRunId()) != approvalIdOrZero(action.RunId) ||
		recordIdOf(request.Request.GetAgentId()) != approvalIdOrZero(action.AgentId) {
		// request_sha256 binds the run and agent, so a decision on another run's request spends nothing here
		return nil, fmt.Errorf("%w: a decision on another requester's, run's or agent's request", ErrApprovalRefused)
	}
	if !bytes.Equal(request.Action.Bytes, stored.Bytes) &&
		!(request.Action.Action.GetScope() && ActionMatchesTemplate(request.Action, stored)) {
		return nil, fmt.Errorf("%w: a decision on another action", ErrApprovalRefused)
	}
	if !request.Detail().Equal(action.Detail) {
		// request_sha256 binds the socket name, local port, weight and ALPNs the approver saw (QD-740, QD-772), so a
		// decision spends on no other
		return nil, fmt.Errorf("%w: a decision on another socket name, local port, weight or alpn", ErrApprovalRefused)
	}
	plan := &approvalSpendPlan{request: request}
	kept, denied := approvalKeptDecisions(state)
	existing := state.FindReserve(actionId[:])
	if existing != nil {
		plan.retry = true
		plan.reserve = existing
		plan.outcome = state.Outcome(actionId[:])
		if plan.outcome != nil && plan.outcome.State.final() {
			return plan, nil
		}
	} else if denied {
		return nil, fmt.Errorf("%w: approval %s", ErrApprovalDenied, approvalId)
	}
	if len(kept) == 0 {
		return nil, &ApprovalPendingError{ApprovalId: approvalId}
	}

	// 1: spendable, its expiry test left to step 3 and the retry window where a use is reserved
	states, err := self.args.states()
	if err != nil {
		return nil, err
	}
	now := self.args.Clock.Now()
	decisions := make([]*StoredApprovalDecision, 0, len(kept))
	for _, decision := range kept {
		decisions = append(decisions, decision.decision)
		plan.decisions = append(plan.decisions, bytes.Clone(decision.stored))
	}
	input := &SpendInput{Action: request.Action, Spender: self.args.SidecarId, Now: now, Reserved: existing != nil}
	budget, err := spendableSet(decisions, input, states, self.args.spendSettings().decisionSkew())
	if err != nil {
		return nil, err
	}
	plan.notAfterMillis = budget.NotAfterMillis

	// 2: the retry path
	if existing != nil {
		return plan, nil
	}

	// 3: the refusals
	kind := SidecarActionKind(stored.Action.GetKind())
	switch {
	case state.Cancel != nil || self.inbox.logCancelled(approvalId):
		return nil, fmt.Errorf("%w: approval %s", ErrApprovalCancelled, approvalId)
	case budget.Uses <= uint32(len(state.Reserves)):
		return nil, fmt.Errorf("%w: approval %s", ErrApprovalSpent, approvalId)
	case tainted && !request.Request.GetTainted():
		plan.stale = true
		return plan, nil
	}
	if tainted && !states.RuleNamesHarness(request.Action) {
		for _, decision := range decisions {
			if protocol.ApprovalChannel(decision.Decision.GetChannel()) == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS {
				return nil, spendRefuse(SpendRefusalEvidence, errors.New("harness evidence counts in a tainted run only where its requests rule names harness"))
			}
		}
	}
	reserveBy := time.UnixMilli(budget.NotAfterMillis)
	if sidecarActionServerGated(kind) {
		reserveBy = reserveBy.Add(-self.args.spendSettings().decisionSkew())
	}
	if now.After(reserveBy) {
		return nil, fmt.Errorf("%w: approval %s", ErrApprovalExpired, approvalId)
	}
	if self.lookup(kind) == nil {
		return nil, fmt.Errorf("%w: kind %d", ErrApprovalNoLookup, kind)
	}

	// 4: the Reserve, fsynced before the mutex is released
	payloadSha256 := stored.PayloadSha256()
	reserve, created, err := hold.ReserveUse(stored.Bytes, actionId[:], payloadSha256[:], effectKey[:], budget.Uses)
	if err != nil {
		return nil, err
	}
	plan.reserve = reserve
	plan.retry = !created
	return plan, nil
}

// Steps 5 and 6: the effect under the use's key, then its Outcome and approval_use entry.
func (self *ApprovalGate) runEffect(ctx context.Context, action *SidecarAction, approvalId Id, plan *approvalSpendPlan, kind SidecarActionKind) (*SidecarOutcome, error) {
	barrierKey := approvalId.String()
	testHookBarrier("record.effect.before", barrierKey)
	effectRef, runErr := action.Effect.Run(ctx, bytes.Clone(plan.reserve.EffectKey))
	testHookBarrier("record.effect.after", barrierKey)
	outcome := approvalOutcomeOfRun(effectRef, runErr, plan.retry && sidecarActionServerGated(kind))
	if err := self.recordOutcome(approvalId, plan.reserve, outcome, action.RunId); err != nil {
		return nil, err
	}
	return outcome, nil
}

// A retry past its completion window: only the kind's Lookup, its answer recorded where it proves done or not_done,
// and uncertain recorded once where none was. The answer carries ErrApprovalExpired as its error.
func (self *ApprovalGate) reconcileUse(ctx context.Context, approvalId Id, plan *approvalSpendPlan, kind SidecarActionKind, runId *Id) (*SidecarOutcome, error) {
	found := &SidecarOutcome{State: ApprovalOutcomeUncertain}
	if lookup := self.lookup(kind); lookup != nil {
		if answer, err := lookup(ctx, plan.canonical(), bytes.Clone(plan.reserve.EffectKey)); err == nil && answer != nil && answer.State.final() {
			found = &SidecarOutcome{State: answer.State, EffectRef: bytes.Clone(answer.EffectRef)}
		}
	}
	if found.State.final() || plan.outcome == nil {
		if err := self.recordOutcome(approvalId, plan.reserve, found, runId); err != nil {
			return nil, err
		}
	}
	found.Err = fmt.Errorf("%w: approval %s's use only reconciles past not_after and its completion window", ErrApprovalExpired, approvalId)
	return found, nil
}

// Appends the use's Outcome between record.outcome's barriers, then files its approval_use entry. An Outcome not
// recorded leaves the use for a retry or a restart to complete; an entry not filed is logged, the Outcome standing.
func (self *ApprovalGate) recordOutcome(approvalId Id, reserve *ApprovalReserve, outcome *SidecarOutcome, runId *Id) error {
	row := &ApprovalOutcome{
		ActionId: bytes.Clone(reserve.ActionId),
		State:    outcome.State,
		Millis:   self.args.Clock.Now().UnixMilli(),
	}
	if outcome.State == ApprovalOutcomeDone {
		row.EffectRef = bytes.Clone(outcome.EffectRef)
	}
	barrierKey := approvalId.String()
	testHookBarrier("record.outcome.before", barrierKey)
	err := self.args.Ledger.Append(approvalId, row)
	testHookBarrier("record.outcome.after", barrierKey)
	if err != nil {
		return fmt.Errorf("approval %s's use %d has no recorded outcome, so a retry completes it: %w", approvalId, reserve.UseIndex, err)
	}
	if err := self.router.FileUse(approvalId, reserve, row, runId); err != nil {
		self.log.Warningf("[approval]approval %s's use %d has its outcome and no approval_use entry: %s", approvalId, reserve.UseIndex, err)
	}
	return nil
}

// The outcome of one run of an effect: done; not_done where the effect proved it and no earlier presentation of a
// gate kind can still commit; else uncertain.
func approvalOutcomeOfRun(effectRef []byte, runErr error, presentedBefore bool) *SidecarOutcome {
	switch {
	case runErr == nil:
		return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: bytes.Clone(effectRef)}
	case errors.Is(runErr, ErrSidecarEffectNotDone) && !presentedBefore:
		return &SidecarOutcome{State: ApprovalOutcomeNotDone, Err: runErr}
	}
	return &SidecarOutcome{State: ApprovalOutcomeUncertain, Err: runErr}
}

// One spend in flight per effect key, which every caller of the same action joins (§16.6's retry row).
type approvalFlights struct {
	stateLock  sync.Mutex
	keyFlights map[string]*approvalFlight
	// called, in tests alone, as a caller joins a flight already running
	onJoin func(key string)
}

// One flight, and its answer once done is closed.
type approvalFlight struct {
	done    chan struct{}
	outcome *SidecarOutcome
	err     error
}

// No flight.
func newApprovalFlights() *approvalFlights {
	return &approvalFlights{keyFlights: map[string]*approvalFlight{}}
}

// Runs run once for key while callers wait on it: the first caller runs it, each that comes while it runs waits for
// its answer or its own ctx, and a caller after it ends runs it again, which finds the recorded outcome. Each caller
// gets its own copy of the outcome.
func (self *approvalFlights) do(ctx context.Context, key string, run func() (*SidecarOutcome, error)) (*SidecarOutcome, error) {
	flight, leader, onJoin := func() (*approvalFlight, bool, func(string)) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if flight, ok := self.keyFlights[key]; ok {
			return flight, false, self.onJoin
		}
		flight := &approvalFlight{done: make(chan struct{}), err: errors.New("the spend ended without an answer")}
		self.keyFlights[key] = flight
		return flight, true, nil
	}()
	if leader {
		func() {
			defer func() {
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					delete(self.keyFlights, key)
				}()
				close(flight.done)
			}()
			flight.outcome, flight.err = run()
		}()
	} else {
		if onJoin != nil {
			onJoin(key)
		}
		select {
		case <-flight.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if flight.outcome == nil {
		return nil, flight.err
	}
	outcome := *flight.outcome
	outcome.EffectRef = bytes.Clone(flight.outcome.EffectRef)
	return &outcome, flight.err
}
