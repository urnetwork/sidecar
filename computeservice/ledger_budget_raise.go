// POST compute/v1/budget/raise (DESIGN-COMPUTE §14.3, §16.3's kind 21, §16.4, D-BAL-8; BAL-M12-16): the broker's half
// of kind 21, registered by route name (routes.go) behind the whole guard, which has by then authenticated a sidecar
// of the network, held the compute gate, required Idempotency-Key and run this kind's approval check
// (approval_kinds.go). The route takes the version-5 compute_budget_raise action a person approved with its decisions
// (protocol/compute.proto's ComputeBudgetRaiseRequest), as stored, and:
//
//	parse    every decision and the action as their bytes arrived, at most the ledger's BudgetRaiseDecisionMaxCount
//	         decisions; the action of kind 21 at version 5, holding only its server column, fields 38 and 43
//	         (CheckCanonicalActionForServer), field 38's sealed detail never opened, so no gate reads a grant
//	key      Idempotency-Key, base64url of §16.6's effect key, the one the action derives with the decisions'
//	         approval, so no request spends two uses on one action or reads another action's result
//	subject  field 43's agent_id: the agent whose budgets rise, or the requesting sidecar's own id, its device's
//	         budgets and its $50 ceiling (D-CACL-6: "raised the same way, by its subject"); a raise naming another
//	         sidecar or a member of the network is refused, since kind 21 lifts the defaults a device's calls count to
//	         and never a member's or the network's policy budget; none, a gateway grant's raise, its grant sealed, is
//	         kept for the device alone (controller's file header)
//	spend    §16.6's spend check at server time on the caller's verified state, its own clock allowing no skew, only
//	         the rule's named approvers counting toward k (sidecar.SpendableSet), run in the claim's transaction only
//	         where no use of the key stands
//
// then controller.ComputeBudgetRaiseTake keeps the use and the raise in one transaction and raises the subject's cap in
// the projection, and the answer is the stored row (ComputeBudgetRaiseAnswer), which a repeat under the key answers
// again: the device's effect lookup (§16.3's table, sidecar/compute_budget_raise.go).
//
// Refusals: 400 invalid for a body, action or key that does not read; 403 approval_refused, its reason the spend
// check's code or subject, for decisions that do not spend or a subject no raise lifts, writing nothing; 409 spent once
// every use is taken; 503 unavailable for a store or state that did not answer, the device's retry completing what
// committed. A raise approved once and retried adds nothing (§16.3's trap). Nothing here reads or logs the decisions'
// summaries, which no Signed carries, or anything sealed; the service log notes the approval's id alone.

package computeservice

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

func init() {
	registerComputeRoutes(map[string]ComputeHandler{
		ComputeRouteBudgetRaise: computeBudgetRaiseHandler,
	})
	registerComputeApprovalKind(ComputeApprovalKindBudgetRaise, computeBudgetRaiseAdmit)
}

// The version of kind 21's action, version 5 (DESIGN-COMPUTE §16.3's CanonicalActionDetail5 rows), the only one a raise
// arrives at.
const computeBudgetRaiseActionVersion = 5

// The reasons a budget raise's approval_refused names, beside the spend check's own codes (sidecar.SpendRefusalCode).
const (
	// The raise names another sidecar or a member of the network, whose budgets no kind 21 lifts.
	computeBudgetRaiseReasonSubject = "subject"
)

// Kind 21's check before its handler: the caller's verified state must be loaded, since the spend check judges on it.
// The rest of the gate runs in the handler, in the effect's own transaction (approval_kinds.go).
func computeBudgetRaiseAdmit(request *ComputeRequest) *ComputeRefusal {
	if request.Caller == nil || request.Caller.Snapshot == nil || request.Caller.Snapshot.Config == nil {
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	return nil
}

// A request the route parsed: the decisions and the action, the approval, the effect key's column and the raise.
type computeBudgetRaiseParsed struct {
	decisions  []*sidecar.StoredApprovalDecision
	action     *sidecar.StoredCanonicalAction
	approvalId sidecar.Id
	effectKey  [32]byte
	budget     *protocol.BudgetFields
}

// Parses body and the request's key (see the file header): nil and the refusal where they do not read.
func computeBudgetRaiseParse(request *ComputeRequest, body *protocol.ComputeBudgetRaiseRequest, ledger *model.ComputeLedgerSettings) (*computeBudgetRaiseParsed, *ComputeRefusal) {
	invalid := NewComputeRefusal(ComputeRefusalInvalid)
	if len(body.GetDecisions()) == 0 || ledger.BudgetRaiseDecisionMaxCount < len(body.GetDecisions()) {
		return nil, invalid
	}
	parsed := &computeBudgetRaiseParsed{}
	for _, signed := range body.GetDecisions() {
		decision, err := sidecar.ParseStoredApprovalDecision(signed)
		if err != nil {
			return nil, invalid
		}
		parsed.decisions = append(parsed.decisions, decision)
	}
	action, err := sidecar.ParseStoredCanonicalAction(body.GetAction())
	if err != nil {
		return nil, invalid
	}
	if sidecar.SidecarActionKind(action.Action.GetKind()) != sidecar.SidecarActionComputeBudgetRaise || action.Action.GetVersion() != computeBudgetRaiseActionVersion {
		return nil, invalid
	}
	if err := sidecar.CheckCanonicalActionForServer(action); err != nil {
		return nil, invalid
	}
	parsed.action = action
	parsed.budget = action.Action.GetBudget()
	if parsed.budget == nil || parsed.budget.GetAmount() == 0 || uint64(1<<53-1) < parsed.budget.GetAmount() {
		return nil, invalid
	}
	approvalId, err := sidecar.IdFromBytes(parsed.decisions[0].Decision.GetApprovalId())
	if err != nil {
		return nil, invalid
	}
	parsed.approvalId = approvalId
	parsed.effectKey = sidecar.ApprovalEffectKey(approvalId, action.ActionId(approvalId))
	presented, err := base64.RawURLEncoding.DecodeString(request.IdempotencyKey())
	if err != nil || len(presented) != len(parsed.effectKey) || [32]byte(presented) != parsed.effectKey {
		return nil, invalid
	}
	return parsed, nil
}

// What the subject's check reads of the caller's verified config: which ids are the network's sidecars and members.
type computeBudgetRaiseConfig interface {
	SidecarRow(sidecarId sidecar.Id) *bridge.SidecarRow
	Member(memberId sidecar.Id) *bridge.MemberRow
}

// The subject the raise lifts at the broker, nil for one only the device applies (a gateway grant's), or the refusal
// of a subject no raise lifts: another sidecar or a member of the caller's network, config's.
func computeBudgetRaiseSubject(caller *ComputeCaller, config computeBudgetRaiseConfig, budget *protocol.BudgetFields) (*sidecar.Id, *ComputeRefusal) {
	if len(budget.GetAgentId()) == 0 {
		return nil, nil
	}
	subjectId, err := sidecar.IdFromBytes(budget.GetAgentId())
	if err != nil {
		return nil, NewComputeRefusal(ComputeRefusalInvalid)
	}
	if subjectId == caller.SidecarId {
		return &subjectId, nil
	}
	if subjectId == caller.MemberId || config.SidecarRow(subjectId) != nil || config.Member(subjectId) != nil {
		return nil, &ComputeRefusal{Code: ComputeRefusalApprovalRefused, Reason: computeBudgetRaiseReasonSubject}
	}
	return &subjectId, nil
}

// A refusal of a spend: approval_refused with the spend check's code as its reason.
type computeBudgetRaiseRefusal struct {
	code sidecar.SpendRefusalCode
}

func (self *computeBudgetRaiseRefusal) Error() string {
	return fmt.Sprintf("%s: %s", controller.ErrComputeBudgetRaiseRefused, self.code)
}

func (self *computeBudgetRaiseRefusal) Unwrap() error {
	return controller.ErrComputeBudgetRaiseRefused
}

// The spend state of caller's verified config, which the engine loaded before the handler (computeBudgetRaiseAdmit).
func computeBudgetRaiseConfigState(caller *ComputeCaller) (sidecar.SpendState, error) {
	if caller.Snapshot == nil || caller.Snapshot.Config == nil {
		return nil, sidecar.ErrSpendStateInvalid
	}
	return sidecar.NewConfigSpendState(caller.Snapshot.Config, false)
}

// The spend check at server time on caller's verified state, stateOf's (DESIGN §16.6's gate step 1): the gate's clock
// allows no skew, and only the rule's named approvers count toward k. A state that does not answer is an error the
// route answers unavailable, never a refusal.
func computeBudgetRaiseSpend(caller *ComputeCaller, parsed *computeBudgetRaiseParsed, stateOf func(caller *ComputeCaller) (sidecar.SpendState, error)) func(now time.Time) (*controller.ComputeBudgetRaiseSpend, error) {
	return func(now time.Time) (*controller.ComputeBudgetRaiseSpend, error) {
		state, err := stateOf(caller)
		if err != nil {
			return nil, err
		}
		budget, err := sidecar.SpendableSet(parsed.decisions, &sidecar.SpendInput{Action: parsed.action, Spender: caller.SidecarId, Now: now},
			state, &sidecar.SpendSettings{DecisionSkew: 0})
		if err != nil {
			code := sidecar.SpendRefusalCodeOf(err)
			if code == "" {
				code = sidecar.SpendRefusalState
			}
			return nil, &computeBudgetRaiseRefusal{code: code}
		}
		return &controller.ComputeBudgetRaiseSpend{Uses: budget.Uses, NotAfterMillis: budget.NotAfterMillis}, nil
	}
}

// The stored row as the route answers it.
func computeBudgetRaiseAnswerOf(raise *model.ComputeBudgetRaise) *protocol.ComputeBudgetRaiseAnswer {
	answer := &protocol.ComputeBudgetRaiseAnswer{
		ApprovalId: raise.ApprovalId.Bytes(),
		UseIndex:   uint32(raise.ApprovalUse),
		Period:     uint32(raise.Period),
		Amount:     uint64(raise.AmountNanoUsd),
		ExpireMs:   raise.ExpireTime.UnixMilli(),
		DeviceOnly: !raise.AtBroker(),
	}
	if raise.SubjectId != (sidecar.Id{}) {
		answer.SubjectId = raise.SubjectId.Bytes()
	}
	return answer
}

// The route's handler (see the file header).
func computeBudgetRaiseHandler(request *ComputeRequest) {
	ledger := request.Engine().Settings().Broker.ledger()
	body := &protocol.ComputeBudgetRaiseRequest{}
	if !request.ReadMessage(body) {
		return
	}
	parsed, refusal := computeBudgetRaiseParse(request, body, ledger)
	if refusal != nil {
		request.Refuse(refusal)
		return
	}
	subjectId, refusal := computeBudgetRaiseSubject(request.Caller, request.Caller.Snapshot.Config, parsed.budget)
	if refusal != nil {
		request.Refuse(refusal)
		return
	}
	request.NoteRowIds(parsed.approvalId)
	answer, err := controller.ComputeBudgetRaiseTake(request.Engine().Env(), request.Ctx, ledger, &controller.ComputeBudgetRaiseRequest{
		NetworkId:     request.Caller.NetworkId,
		ApprovalId:    parsed.approvalId,
		EffectKey:     model.ComputeBudgetRaiseEffectKeyId(parsed.effectKey),
		SubjectId:     subjectId,
		Period:        model.ComputeBudgetPeriod(parsed.budget.GetPeriod()),
		AmountNanoUsd: int64(parsed.budget.GetAmount()),
		Spend:         computeBudgetRaiseSpend(request.Caller, parsed, computeBudgetRaiseConfigState),
	})
	var spendRefusal *computeBudgetRaiseRefusal
	switch {
	case errors.As(err, &spendRefusal):
		request.Refuse(&ComputeRefusal{Code: ComputeRefusalApprovalRefused, Reason: string(spendRefusal.code)})
		return
	case errors.Is(err, model.ErrComputeBudgetRaiseSpent):
		request.RefuseCode(ComputeRefusalSpent)
		return
	case errors.Is(err, controller.ErrComputeBudgetRaiseArgs), errors.Is(err, model.ErrComputeBudgetRaiseArgs):
		request.RefuseCode(ComputeRefusalInvalid)
		return
	case err != nil:
		request.Unavailable()
		return
	}
	request.Reply(computeBudgetRaiseAnswerOf(answer.Raise))
}
