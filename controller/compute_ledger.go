// The ledger's calls the broker's handlers make (DESIGN-COMPUTE §9.7, D-BAL-13, D-BAL-14; BAL-M12-03): INFER's infer
// and prepare, SRCH's search authorize and ENC's orchestrator take holds, settle and release through these, with the
// amounts they compute from the catalog version a request named. The broker is the only place a charge is made.
//
// The handoff (D-BAL-13), each step a linearization point a fault schedule can stop on either side of:
//
//	ComputeHold          the hold, unconfirmed, in the network's script (balance, floor, budgets); the operation's row
//	                     committed open in PostgreSQL; the hold confirmed; then the provider's capacity (§10.4). Only
//	                     an admitted answer lets the caller forward, since the row precedes the liability. A
//	                     PostgreSQL that cannot take the row voids the hold and answers capacity with a retry, so
//	                     nothing reaches a provider without its row; a caller stopped between the hold and its row
//	                     strands no room, since a hold unconfirmed past the settings' 60 s is dropped by the
//	                     network's next script. A projection lost or marked after a failover is rebuilt first, under
//	                     the network's fence, where the caller gives its budget lines (ComputeRebuild); until then
//	                     its calls answer held with the settings' one-second retry
//	ComputeSettle        the outcome committed to the row, open to settled, then the hold turned into an unsettled
//	                     charge; compute_settle books the row from PostgreSQL and drops the charge after (BAL-M12-04)
//	ComputeRelease       the row moved open to void, then the hold dropped
//	ComputeWriteSettled  a host egress hour's, a refund's or an adjustment's row, written already settled, its derived
//	                     key claiming its subject once
//
// Every move is conditional on the row's state before it, so a repeated receipt, report or interval changes nothing
// and one whose row is gone books nothing; each script acts once per operation key. Until the last script the
// operation's room stays reserved in Redis and in its row, so stopping any party on either side of any step, or losing
// Redis, leaves every liability counted and recoverable, and none booked twice.
//
// Built here: a remote TEE call's hold (path tee, kind inference). The direct call's (BAL-M12-21), the search's
// (BAL-M13-02) and the enclave interval's (BAL-M14-01) hold paths are refused with model.ErrComputeHoldPathUnbuilt
// until their scripts land, never held some other way. A kind with no remote path is refused: local inference never
// reaches the ledger (R-BAL-5, IC-5), and budgets bound calls and searches, never an enclave's running time.
//
// No request, row, outcome or log line here names content (R-BAL-6): a request holds ids, amounts, codes and times,
// and the two strings a row keeps, a catalog id and a TEE call's provider reference, are held to printable ASCII
// without spaces within the settings' bounds before any hold is taken. Each function takes the Env first (owner
// decision 594). Safe for concurrent use: the network's scripts and the rows' conditional moves are the
// serialization.

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
	// A ledger call the ledger cannot take: a kind the path does not hold, no remote provider, a missing id.
	ErrComputeLedgerArgs = errors.New("compute ledger: arguments refused")
)

// Who an operation counts to, for the budgets it is charged against.
type ComputeBudgetSubjects struct {
	NetworkId operator.Id
	Kind      model.ComputeChargeKind
	SidecarId operator.Id
	AgentId   *operator.Id
	MemberId  *operator.Id
}

// The budget lines an operation's subjects count to, as the broker resolves them for a call: CACL's resolver (C§16.4)
// once it lands, §16.5's defaults (model.ComputeDefaultBudgetLines) until then. A settlement whose hold is gone counts
// its charge to them, and a rebuild re-resolves every open and settled row's lines and every booked day's subjects with
// them (BAL-M12-04). Calls and searches have lines; an enclave's kinds have none.
type ComputeBudgetLines func(ctx context.Context, subjects *ComputeBudgetSubjects) ([]*model.ComputeBudgetLine, error)

// The provider's capacity (§10.4): GAMMA-M12-05's GammaProviderCapacity, a script on the provider's own key after the
// network's hold admits. A refusal undoes the network's hold. nil admits: until it lands nothing refuses for capacity.
type ComputeProviderCapacity interface {
	// Reserves holdNanoUsd of provider's account for opKey: false, with when to ask again, where the account as last
	// read, less what it served and the holds open there, cannot cover it.
	Reserve(env operator.Env, ctx context.Context, provider int16, opKey operator.Id, holdNanoUsd int64) (reserved bool, retryAfter time.Duration, err error)
}

// One admission the broker asks the ledger to hold (§9.7).
type ComputeHoldRequest struct {
	NetworkId operator.Id
	// What the hold is for, and which of §9.7's paths takes it: inference by tee or direct, web_search by search,
	// enclave_run by interval.
	Kind model.ComputeChargeKind
	Path model.ComputeHoldPath
	// The key a search or an interval derives (ComputeOpKeyForSearch, ComputeOpKeyForInterval), with StartTime the time
	// that key is timed to. nil for a call, whose key is drawn here and whose start is its hold's Redis TIME.
	OpKey     *operator.Id
	StartTime time.Time
	// The request id of a call or a search, or the enclave of an interval.
	SubjectRef operator.Id
	// A search's attempt; nil for the rest.
	Attempt *int16
	// Its subjects: who caused it, the agent the call names, the member it counts to as the projection gave it at the
	// hold (a sidecar's member, or a tagged sidecar's or enclave's sponsor), and the enclave.
	SidecarId operator.Id
	AgentId   *operator.Id
	MemberId  *operator.Id
	EnclaveId *operator.Id
	// What admitted it: the model or shape, the catalog version the request named, the provider's code (§4.6) and the
	// provider price read, which the row records so the charge is the price the caller was shown.
	CatalogId      *string
	CatalogVersion *int64
	Provider       int16
	PriceRead      *int64
	// A TEE call's instance and provider nonce, which compute_op_recover looks its usage up by.
	ProviderRef *string
	// The balance hold, the worst case, and the budget reservation, which for a TEE call is the hold.
	HoldNanoUsd    int64
	ReserveNanoUsd int64
	// The budget lines the call is checked and reserved against.
	Lines []*model.ComputeBudgetLine
	// What resolves every row's lines where the network's projection is lost and this call rebuilds it
	// (ComputeRebuild, BAL-M12-04); nil leaves a lost projection as it is, and the call answers held.
	Budgets ComputeBudgetLines
	// The provider's capacity check; nil admits.
	Capacity ComputeProviderCapacity
}

// What an admission came to.
type ComputeHoldAnswer struct {
	// The hold is taken, its row committed open and the hold confirmed: the caller forwards only now.
	Admitted bool
	// The operation's key and start, its charge's charge_id and start_time.
	OpKey     operator.Id
	StartTime time.Time
	// Why not, where neither admitted nor finished.
	Refusal *ComputeRefusal
	// A derived key's operation that has already finished, released or booked: a repeat, and nothing to forward.
	Finished bool
}

// A refused admission's answer.
func computeHoldRefused(opKey operator.Id, refusal *ComputeRefusal) *ComputeHoldAnswer {
	return &ComputeHoldAnswer{OpKey: opKey, Refusal: refusal}
}

// The paths each kind holds by.
func computeHoldPathTakes(kind model.ComputeChargeKind, path model.ComputeHoldPath) bool {
	switch path {
	case model.ComputeHoldPathTee, model.ComputeHoldPathDirect:
		return kind == model.ComputeChargeKindInference
	case model.ComputeHoldPathSearch:
		return kind == model.ComputeChargeKindWebSearch
	case model.ComputeHoldPathInterval:
		return kind == model.ComputeChargeKindEnclaveRun
	}
	return false
}

// The open row request asks for, under opKey from start.
func computeHoldRow(request *ComputeHoldRequest, opKey operator.Id, start time.Time) *model.ComputeOp {
	return &model.ComputeOp{
		OpKey:          opKey,
		NetworkId:      request.NetworkId,
		State:          model.ComputeOpStateOpen,
		Kind:           request.Kind,
		SubjectRef:     request.SubjectRef,
		Attempt:        request.Attempt,
		SidecarId:      request.SidecarId,
		AgentId:        request.AgentId,
		MemberId:       request.MemberId,
		EnclaveId:      request.EnclaveId,
		CatalogId:      request.CatalogId,
		CatalogVersion: request.CatalogVersion,
		Provider:       request.Provider,
		PriceRead:      request.PriceRead,
		ProviderRef:    request.ProviderRef,
		HoldNanoUsd:    request.HoldNanoUsd,
		ReserveNanoUsd: request.ReserveNanoUsd,
		StartTime:      start.UTC(),
	}
}

// Checks request before any store is asked, so a request the ledger would refuse holds nothing.
func computeHoldCheck(settings *model.ComputeLedgerSettings, request *ComputeHoldRequest) error {
	if !computeHoldPathTakes(request.Kind, request.Path) {
		return fmt.Errorf("%w: kind %s holds by no path %d", ErrComputeLedgerArgs, request.Kind, request.Path)
	}
	if request.Provider <= 0 {
		// local inference never reaches the ledger (R-BAL-5, IC-5), nor does any work with no remote provider
		return fmt.Errorf("%w: a hold names a remote provider", ErrComputeLedgerArgs)
	}
	var zero operator.Id
	if request.NetworkId == zero || request.SidecarId == zero || request.SubjectRef == zero {
		return fmt.Errorf("%w: a hold names its network, sidecar and subject", ErrComputeLedgerArgs)
	}
	call := request.Path == model.ComputeHoldPathTee || request.Path == model.ComputeHoldPathDirect
	if call != (request.OpKey == nil) {
		return fmt.Errorf("%w: a call's key is drawn here, and a search's or interval's is derived", ErrComputeLedgerArgs)
	}
	if call != request.StartTime.IsZero() {
		return fmt.Errorf("%w: a call starts at its hold, and a derived key comes with the time it is timed to", ErrComputeLedgerArgs)
	}
	if request.Path != model.ComputeHoldPathDirect && request.ReserveNanoUsd != request.HoldNanoUsd {
		return fmt.Errorf("%w: a hold held at its worst case reserves its hold", ErrComputeLedgerArgs)
	}
	if (request.Path == model.ComputeHoldPathSearch) != (request.Attempt != nil) {
		return fmt.Errorf("%w: a search's hold, and only it, carries its attempt", ErrComputeLedgerArgs)
	}
	start := request.StartTime
	if start.IsZero() {
		// the row's own start is its hold's; any time checks the rest of the row
		start = time.Unix(0, 0)
	}
	return model.ComputeOpCheck(settings, computeHoldRow(request, operator.Id{}, start))
}

// The network's hold script for request under opKey.
func computeHoldScript(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeHoldRequest, opKey operator.Id) (*model.ComputeHoldResult, error) {
	testHookBarrier("compute_ledger.hold.before", opKey.String())
	result, err := model.ComputeProjectionHold(env, ctx, settings, &model.ComputeHoldRequest{
		NetworkId:      request.NetworkId,
		OpKey:          opKey,
		Kind:           request.Kind,
		Path:           request.Path,
		HoldNanoUsd:    request.HoldNanoUsd,
		ReserveNanoUsd: request.ReserveNanoUsd,
		Lines:          request.Lines,
	})
	testHookBarrier("compute_ledger.hold.after", opKey.String())
	return result, err
}

// Takes request's hold, commits its row and confirms it (see the file header). A refusal is an answer, never an
// error; an error means the ledger could not say, and the caller forwards nothing.
func ComputeHold(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeHoldRequest) (*ComputeHoldAnswer, error) {
	if err := computeHoldCheck(settings, request); err != nil {
		return nil, err
	}
	var opKey operator.Id
	if request.OpKey != nil {
		opKey = *request.OpKey
	} else {
		var err error
		if opKey, err = ComputeOpKeyForCall(); err != nil {
			return nil, err
		}
	}
	result, err := computeHoldScript(env, ctx, settings, request, opKey)
	if err != nil {
		return nil, err
	}
	if result.Outcome == model.ComputeHoldHeld && request.Budgets != nil {
		// a lost or marked projection admits nothing until it is rebuilt (D-BAL-13): rebuild it here, under the
		// network's fence, and ask once more; where the rebuild cannot run, the call stays held with its retry
		projection, err := model.ComputeProjectionRead(env, ctx, request.NetworkId)
		if err == nil && (!projection.Present || projection.Marked) {
			if _, err := ComputeRebuild(env, ctx, settings, request.NetworkId, request.Budgets); err == nil {
				if again, err := computeHoldScript(env, ctx, settings, request, opKey); err == nil {
					result = again
				}
			}
		}
	}
	switch result.Outcome {
	case model.ComputeHoldHeld:
		return computeHoldRefused(opKey, &ComputeRefusal{Reason: ComputeRefusalHeld, RetryAfter: result.RetryAfter}), nil
	case model.ComputeHoldBalance:
		return computeHoldRefused(opKey, &ComputeRefusal{Reason: ComputeRefusalBalance}), nil
	case model.ComputeHoldBudget:
		return computeHoldRefused(opKey, &ComputeRefusal{Reason: ComputeRefusalBudget, Line: result.Line}), nil
	case model.ComputeHoldVoid, model.ComputeHoldDropped:
		return &ComputeHoldAnswer{OpKey: opKey, Finished: true}, nil
	case model.ComputeHoldTaken:
	default:
		return nil, fmt.Errorf("%w: the hold outcome %q", model.ErrComputeProjectionReply, result.Outcome)
	}
	if result.Time.IsZero() {
		// a derived key whose hold has already become an unsettled charge: settled, nothing to forward
		return &ComputeHoldAnswer{OpKey: opKey, Finished: true}, nil
	}
	start := request.StartTime
	if start.IsZero() {
		start = result.Time
	}
	// the row, before anything can bind URnetwork to a provider for the call; bounded well inside the unconfirmed
	// hold's age, so the confirm below follows its hold
	inserted, stands, err := func() (bool, *model.ComputeOp, error) {
		testHookBarrier("compute_ledger.row.before", opKey.String())
		defer testHookBarrier("compute_ledger.row.after", opKey.String())
		rowCtx, cancel := context.WithTimeout(ctx, settings.OpRowWriteMaxTime)
		defer cancel()
		return model.ComputeOpInsertOpen(env, rowCtx, settings, computeHoldRow(request, opKey, start))
	}()
	if err != nil {
		// a PostgreSQL that cannot take the row refuses the call: the hold is voided now where Redis answers, and
		// dropped at its age by the network's next script where it does not
		computeHoldUndo(env, ctx, settings, request, opKey)
		return computeHoldRefused(opKey, &ComputeRefusal{Reason: ComputeRefusalCapacity, RetryAfter: settings.CapacityRetry}), nil
	}
	if !inserted {
		// a derived key's repeat: the first admission's row stands
		if stands.State != model.ComputeOpStateOpen {
			return &ComputeHoldAnswer{OpKey: opKey, Finished: true}, nil
		}
		start = stands.StartTime
	}
	testHookBarrier("compute_ledger.confirm.before", opKey.String())
	confirmed, err := model.ComputeProjectionConfirm(env, ctx, settings, request.NetworkId, opKey, computeHoldSubjects(request))
	testHookBarrier("compute_ledger.confirm.after", opKey.String())
	if err != nil || confirmed != model.ComputeScriptConfirmed {
		// the room is not held for certain: dropped past its age, lost with the projection, or unanswered. Nothing is
		// forwarded, and the row goes to void so nothing is booked for it
		computeHoldReleaseRow(env, ctx, settings, request.NetworkId, opKey)
		if err == nil && confirmed == model.ComputeScriptAbsent {
			return computeHoldRefused(opKey, &ComputeRefusal{Reason: ComputeRefusalHeld, RetryAfter: settings.ProjectionRebuildRetry}), nil
		}
		return computeHoldRefused(opKey, &ComputeRefusal{Reason: ComputeRefusalCapacity, RetryAfter: settings.CapacityRetry}), nil
	}
	if request.Capacity != nil {
		reserved, retryAfter, err := request.Capacity.Reserve(env, ctx, request.Provider, opKey, request.HoldNanoUsd)
		if err != nil || !reserved {
			computeHoldReleaseRow(env, ctx, settings, request.NetworkId, opKey)
			if err != nil || retryAfter <= 0 {
				retryAfter = settings.CapacityRetry
			}
			return computeHoldRefused(opKey, &ComputeRefusal{Reason: ComputeRefusalCapacity, RetryAfter: retryAfter}), nil
		}
	}
	return &ComputeHoldAnswer{Admitted: true, OpKey: opKey, StartTime: start}, nil
}

// The subjects a request's hold may name, a superset of its lines' subjects: their counters are where its
// reservations move.
func computeHoldSubjects(request *ComputeHoldRequest) []operator.Id {
	subjectIds := []operator.Id{request.SidecarId, request.NetworkId}
	for _, id := range []*operator.Id{request.AgentId, request.MemberId, request.EnclaveId} {
		if id != nil {
			subjectIds = append(subjectIds, *id)
		}
	}
	for _, line := range request.Lines {
		subjectIds = append(subjectIds, line.SubjectId)
	}
	return subjectIds
}

// Voids an unconfirmed hold whose row PostgreSQL did not take. Where Redis does not answer either, the network's next
// script drops it at its age, so its failure is no error.
func computeHoldUndo(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeHoldRequest, opKey operator.Id) {
	model.ComputeProjectionVoid(env, ctx, settings, request.NetworkId, opKey, computeHoldSubjects(request))
}

// Releases an admission's row and hold after its confirm or its capacity failed. Where PostgreSQL does not answer, the
// row stays open and compute_op_recover releases it (BAL-M12-04), so its failure is no error.
func computeHoldReleaseRow(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, opKey operator.Id) {
	ComputeRelease(env, ctx, settings, networkId, opKey)
}

// A settlement's outcome (§9.7, step 4): units, amount, cost, absorbed, and the end and settle times, which the
// producer commits to the operation's row. The amount is usage times the prices of the catalog version the request
// named, the cost what URnetwork pays the provider.
type ComputeOutcome = model.ComputeOpOutcome

// One settlement.
type ComputeSettleRequest struct {
	NetworkId operator.Id
	OpKey     operator.Id
	// The path the operation was held by: a direct call settles by BAL-M12-21's rules and is refused here until it
	// lands.
	Path    model.ComputeHoldPath
	Outcome *ComputeOutcome
	// Where the hold is gone from the projection, the lines its charge counts to; nil counts it to the hold's lines
	// where the hold stands, and to none where it is gone.
	Budgets ComputeBudgetLines
}

// What a settlement did.
type ComputeSettleState string

const (
	// The outcome is committed now: the row is settled, and compute_settle books it.
	ComputeSettleSettled ComputeSettleState = "settled"
	// The row was already settled or booked: this delivery changed nothing.
	ComputeSettleRepeat ComputeSettleState = "repeat"
	// The row was released at no charge: nothing is booked for it.
	ComputeSettleReleased ComputeSettleState = "released"
	// No row of the key: never admitted, or booked and deleted, so nothing is booked for this delivery.
	ComputeSettleGone ComputeSettleState = "gone"
)

// What a settlement came to.
type ComputeSettleAnswer struct {
	State ComputeSettleState
	// For settled and repeat: the outcome the row holds, its amount cut to the hold where it passed it.
	Outcome *ComputeOutcome
	// For settled and repeat: whether the hold became an unsettled charge in the projection by this call. Where it
	// did not (Redis did not answer, or the script was late), compute_settle's drop releases the hold with its charge
	// counted, so the settlement stands either way.
	Projected bool
}

// Settles request's operation (see the file header): the outcome committed to the row first, conditional on open,
// then the hold turned into the unsettled charge. A repeat whose row is still settled runs the script again, which
// acts once per key, so a first script that failed is made good.
func ComputeSettle(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, request *ComputeSettleRequest) (*ComputeSettleAnswer, error) {
	if request.Path == model.ComputeHoldPathDirect {
		return nil, model.ErrComputeHoldPathUnbuilt
	}
	if request.Outcome == nil {
		return nil, fmt.Errorf("%w: a settlement carries its outcome", ErrComputeLedgerArgs)
	}
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	testHookBarrier("compute_ledger.outcome.before", request.OpKey.String())
	moved, err := model.ComputeOpSettle(env, ctx, request.NetworkId, request.OpKey, false, request.Outcome)
	testHookBarrier("compute_ledger.outcome.after", request.OpKey.String())
	if errors.Is(err, model.ErrComputeOpNotFound) {
		return &ComputeSettleAnswer{State: ComputeSettleGone}, nil
	}
	if err != nil {
		return nil, err
	}
	op := moved.Op
	switch op.State {
	case model.ComputeOpStateVoid:
		return &ComputeSettleAnswer{State: ComputeSettleReleased}, nil
	case model.ComputeOpStateApplied:
		return &ComputeSettleAnswer{State: ComputeSettleRepeat, Outcome: op.Outcome}, nil
	case model.ComputeOpStateSettled:
	default:
		return nil, fmt.Errorf("compute ledger: a settlement left its row %s", op.State)
	}
	answer := &ComputeSettleAnswer{State: ComputeSettleRepeat, Outcome: op.Outcome}
	committedAt := op.Outcome.SettleTime
	if moved.Moved {
		answer.State = ComputeSettleSettled
		committedAt = clock.Now()
	}
	if settings.SettleScriptWindow < clock.Now().Sub(committedAt) {
		// late: a booking may already have dropped this operation, and its memo gone; the drop counts it instead
		return answer, nil
	}
	answer.Projected = computeSettleScript(env, ctx, settings, request.Path, request.Budgets, op)
	return answer, nil
}

// The settlement's script for a settled row: whether it ran and answered.
func computeSettleScript(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, path model.ComputeHoldPath, budgets ComputeBudgetLines, op *model.ComputeOp) bool {
	lines := []*model.ComputeBudgetLine{}
	if budgets != nil {
		resolved, err := budgets(ctx, &ComputeBudgetSubjects{
			NetworkId: op.NetworkId, Kind: op.Kind, SidecarId: op.SidecarId, AgentId: op.AgentId, MemberId: op.MemberId,
		})
		if err != nil {
			return false
		}
		lines = resolved
	}
	subjectIds := op.SubjectIds()
	for _, line := range lines {
		subjectIds = append(subjectIds, line.SubjectId)
	}
	testHookBarrier("compute_ledger.settle.before", op.OpKey.String())
	outcome, err := model.ComputeProjectionSettle(env, ctx, settings, &model.ComputeSettleRequest{
		NetworkId:      op.NetworkId,
		OpKey:          op.OpKey,
		Kind:           op.Kind,
		Path:           path,
		AmountNanoUsd:  op.Outcome.AmountNanoUsd,
		ReserveNanoUsd: op.ReserveNanoUsd,
		StartTime:      op.StartTime,
		Lines:          lines,
		SubjectIds:     subjectIds,
	})
	testHookBarrier("compute_ledger.settle.after", op.OpKey.String())
	return err == nil && outcome == model.ComputeScriptSettled
}

// What a release did.
type ComputeReleaseState string

const (
	// The row is void, released at no charge, and the hold dropped where Redis answered.
	ComputeReleaseReleased ComputeReleaseState = "released"
	// The row was settled or booked: its charge stands, and the release changed nothing.
	ComputeReleaseSettled ComputeReleaseState = "settled"
	// No row of the key.
	ComputeReleaseGone ComputeReleaseState = "gone"
)

// Releases opKey's operation at no charge (§9.7): its row from open to void, then its hold dropped. A row already void
// runs the drop again, which acts once per key, so a first that failed is made good; a settled or booked row is left
// as it is.
func ComputeRelease(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, networkId operator.Id, opKey operator.Id) (ComputeReleaseState, error) {
	testHookBarrier("compute_ledger.release.before", opKey.String())
	moved, err := model.ComputeOpVoid(env, ctx, networkId, opKey)
	testHookBarrier("compute_ledger.release.after", opKey.String())
	if errors.Is(err, model.ErrComputeOpNotFound) {
		return ComputeReleaseGone, nil
	}
	if err != nil {
		return "", err
	}
	if moved.Op.State != model.ComputeOpStateVoid {
		return ComputeReleaseSettled, nil
	}
	// the row is void, so nothing is booked for it whatever the script does; where Redis does not answer, the hold is
	// dropped by a later release, or by a rebuild, which reads no void row
	model.ComputeProjectionVoid(env, ctx, settings, networkId, opKey, moved.Op.SubjectIds())
	return ComputeReleaseReleased, nil
}

// One operation written already settled (§9.7): a host egress hour, a refund or a support adjustment.
type ComputeSettledWrite struct {
	NetworkId operator.Id
	// Its derived key: ComputeOpKeyForEgressHour, ComputeOpKeyForRefund (of SubjectRef, the charge it returns) or
	// ComputeOpKeyForAdjustment.
	OpKey operator.Id
	// enclave_host_egress, adjustment, or for a refund the kind of the charge it returns.
	Kind model.ComputeChargeKind
	// The enclave, the charge a refund returns, or the support case.
	SubjectRef operator.Id
	// As the charge's: the nil id and provider 0 for an adjustment; for a refund, the refunded charge's.
	SidecarId operator.Id
	AgentId   *operator.Id
	MemberId  *operator.Id
	EnclaveId *operator.Id
	CatalogId *string
	Provider  int16
	// Its charge's start: the egress hour's start; a refund's or an adjustment's first write, which the claim keeps.
	StartTime time.Time
	// A refund's amount is negative; a host egress hour's is a charge; an adjustment's is a debit or a credit.
	Outcome *ComputeOutcome
}

// What a settled write came to.
type ComputeWriteAnswer struct {
	// The row is written now.
	Written bool
	// The row of its key, written now or claimed before, with the start and outcome its first write fixed.
	StartTime time.Time
	Outcome   *ComputeOutcome
}

// Checks write as one of §9.7's settled writes.
func computeWriteCheck(write *ComputeSettledWrite) error {
	if write.Outcome == nil {
		return fmt.Errorf("%w: a settled write carries its outcome", ErrComputeLedgerArgs)
	}
	amount := write.Outcome.AmountNanoUsd
	var zero operator.Id
	switch {
	case write.Kind == model.ComputeChargeKindEnclaveHostEgress && 0 <= amount:
		if write.EnclaveId == nil || write.Provider <= 0 {
			return fmt.Errorf("%w: a host egress hour names its enclave and provider", ErrComputeLedgerArgs)
		}
	case write.Kind == model.ComputeChargeKindAdjustment:
		if write.SidecarId != zero || write.Provider != 0 || write.MemberId != nil || write.AgentId != nil {
			return fmt.Errorf("%w: an adjustment counts to the network's own line", ErrComputeLedgerArgs)
		}
	case amount < 0 && write.Kind.Written():
		// a refund: a negative charge of the kind it returns, keyed by the charge it names
		if write.OpKey != ComputeOpKeyForRefund(write.SubjectRef) {
			return fmt.Errorf("%w: a refund's key is the UUIDv5 of the charge it returns", ErrComputeLedgerArgs)
		}
	default:
		return fmt.Errorf("%w: kind %s is no settled write", ErrComputeLedgerArgs, write.Kind)
	}
	if write.NetworkId == zero || write.SubjectRef == zero || write.StartTime.IsZero() {
		return fmt.Errorf("%w: a settled write names its network, subject and start", ErrComputeLedgerArgs)
	}
	return nil
}

// Writes write's row already settled (§9.7), its key claiming its subject once: a repeat, a refund racing another, or a
// retry past UTC midnight meets the claim, adds nothing, and is answered the first write's start and outcome. A host
// egress hour's charge is then counted in the projection, as a settlement's is; a refund's and an adjustment's reach
// the projection's settled through compute_settle's drop.
func ComputeWriteSettled(env operator.Env, ctx context.Context, settings *model.ComputeLedgerSettings, write *ComputeSettledWrite) (*ComputeWriteAnswer, error) {
	if err := computeWriteCheck(write); err != nil {
		return nil, err
	}
	outcome := *write.Outcome
	op := &model.ComputeOp{
		OpKey:      write.OpKey,
		NetworkId:  write.NetworkId,
		State:      model.ComputeOpStateSettled,
		Kind:       write.Kind,
		SubjectRef: write.SubjectRef,
		SidecarId:  write.SidecarId,
		AgentId:    write.AgentId,
		MemberId:   write.MemberId,
		EnclaveId:  write.EnclaveId,
		CatalogId:  write.CatalogId,
		Provider:   write.Provider,
		StartTime:  write.StartTime.UTC(),
		Outcome:    &outcome,
	}
	testHookBarrier("compute_ledger.write.before", write.OpKey.String())
	inserted, stands, err := model.ComputeOpInsertSettled(env, ctx, settings, op)
	testHookBarrier("compute_ledger.write.after", write.OpKey.String())
	if err != nil {
		return nil, err
	}
	if !inserted {
		return &ComputeWriteAnswer{StartTime: stands.StartTime, Outcome: stands.Outcome}, nil
	}
	if write.Kind == model.ComputeChargeKindEnclaveHostEgress {
		// an enclave's kind holds no budget line; a failure leaves the charge to compute_settle's booking
		computeSettleScript(env, ctx, settings, model.ComputeHoldPathInterval, nil, op)
	}
	return &ComputeWriteAnswer{Written: true, StartTime: op.StartTime, Outcome: op.Outcome}, nil
}
