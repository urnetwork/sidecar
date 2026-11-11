//go:build !ios_extension

// §16.6's requester half (MCP-M3-05; R-MCP-6, R-MCP-7, R-MCP-9, D-MCP-4, D-MCP-12, I-8), on RECORD-M3-07's
// RecordApprovals, which picks the log a request goes to and reads a decision back, so this file holds no second
// route table:
//
//	file    ApprovalRouter: the approvers P names for the action (ApprovalStates.Approvers), then the ApprovalRequest,
//	        tainted as the run file reads at this moment and not_after ApprovalRequestTimeout away, or the action's
//	        own expiry where sooner (MCP.md's reading 3), written as stored into the ledger and fsynced before
//	        FileRequest files it; a filed row then notes that the log took it, so a request the log refused (no team
//	        record, say) stays pending and is filed again at the next retry
//	find    the same action, run and agent while a request of theirs waits answer that request, through a fresh MCP
//	        session too, so a retry files nothing; a tainted run finds only a request it filed tainted (TS1)
//	intake  ApprovalInbox: a decision from the log's poll or handed to Receive is kept only once it names a request
//	        this ledger holds by its stored bytes, verifies under the key P names for its channel and, for a
//	        webauthn-es256 presence key, carries a signCount above the one stored (§16.6's per use); then its Signed
//	        is fsynced as a decision row and the update callbacks run, ur://approval/{id}'s resources/updated. A
//	        decision for a request this ledger never held is ignored, never trusted, and one that does not verify is
//	        not kept. Whether a kept decision spends is §16.6's spend check, at the gate.
//	cancel  ReceiveCancel keeps an approver's ApprovalCancel once CheckApprovalCancel passes against a kept decision;
//	        a cancel the log reports through Decision, which hands back no bytes to check, stops new uses without a
//	        ledger row, the closed direction
//	use     after each Outcome, FileUse: the approval_use entry carries the use's action_id, which links it to the
//	        decision entry whose header names the channel, so a receipt names its evidence (R-MCP-7)
//	status  pending, approved, denied, cancelled, expired, spent, uncertain (ApprovalStatus)
//
// summary is the agent's text and stays only that: nothing here logs it, a preview or a recipient, and
// ApprovalPendingError carries the id alone. A deposit-only requester's non-grant decision stays pending, since the log
// answers it undeliverable until the owner's ApprovalDelivery delta is built (plan-RECORD-deposit-only-decisions); its
// grant decisions arrive as §8.8's GrantActivate deltas, which ACL-M4-02 files.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret; the ledger's barriers sit at its
// own fsyncs. Safe for concurrent use. On every leg but the ios_extension legs, whose forwarding role files nothing.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §5.9's directory and file for the presence counts a requester keeps: a local store's, under the approval class,
// beside approvals/ (MCP.md's reading 9 places local §16 files by component).
const (
	approvalPresenceDirectoryName = "presence"
	approvalPresenceCountsName    = "counts"
)

var (
	// No request with that approval id is in this sidecar's ledger: a decision naming it is ignored, never trusted.
	ErrApprovalUnknown = errors.New("approval unknown")
	// A decision or cancel that does not name its request by its stored bytes, or does not verify under the key P
	// names for its channel: not kept.
	ErrApprovalRefused = errors.New("approval answer refused")
	// No verified state answers for approvals: none installed, or it failed, so no request is filed and no decision
	// is kept.
	ErrApprovalNoState = errors.New("no verified state for approvals")
)

// What the requester's daemon reads of its network at each approval step: P as §16.6's spend check reads it, and who
// approves an action there. NewConfigApprovalStates answers from §7.9's verified state and the compiled policy. Answers
// never change for one value, and a value is safe for concurrent use.
type ApprovalStates interface {
	SpendState
	// The members who approve action for requester at P at time now (§8.6's approvers, ApprovalRequest.approvers):
	// every member the governing rule finds eligible, a role autogroup's members listed out, sorted. An error where
	// a rule should govern and none takes the action, or where no member approves.
	Approvers(action *StoredCanonicalAction, requester Id, now time.Time) ([]Id, error)
	// Whether the requests rule governing action names harness in its own evidence list, the one place a harness
	// decision counts in a tainted run (owner decision 142): false for an action no rule names, and where the state
	// cannot tell.
	RuleNamesHarness(action *StoredCanonicalAction) bool
}

// ApprovalStates over §7.9's S(n) and the policy the daemon compiled from it (ACL-M2-04's AclLocalPolicy).
type ConfigApprovalStates struct {
	*ConfigSpendState
	// nil where no document compiled
	local *AclLocalPolicy
}

// The approval states of config: forked and evidenceDefault as NewConfigSpendState takes them, local the policy
// compiled at config's head, nil for none, which names harness in no rule.
func NewConfigApprovalStates(config *ConfigState, forked bool, evidenceDefault []protocol.ApprovalChannel, local *AclLocalPolicy) (*ConfigApprovalStates, error) {
	spendState, err := NewConfigSpendState(config, forked, evidenceDefault)
	if err != nil {
		return nil, err
	}
	return &ConfigApprovalStates{ConfigSpendState: spendState, local: local}, nil
}

// Every member of the state the governing rule finds eligible, sorted.
func (self *ConfigApprovalStates) Approvers(action *StoredCanonicalAction, requester Id, now time.Time) ([]Id, error) {
	rule, err := self.Govern(action, requester, now)
	if err != nil {
		return nil, err
	}
	return approvalEligibleMembers(rule, self.config.MemberIds())
}

// The compiled requests rule's own list, from its detail.
func (self *ConfigApprovalStates) RuleNamesHarness(action *StoredCanonicalAction) bool {
	if action == nil || action.Action == nil || len(action.Action.GetRuleId()) == 0 {
		return false
	}
	request := self.local.Request(action.Action.GetRuleId())
	return request != nil && request.NamesHarness
}

// The members of memberIds rule finds eligible, sorted and once each, or an error where none is.
func approvalEligibleMembers(rule SpendRule, memberIds []Id) ([]Id, error) {
	approvers := []Id{}
	for _, memberId := range memberIds {
		if rule.Eligible(memberId) {
			approvers = append(approvers, memberId)
		}
	}
	slices.SortFunc(approvers, Id.Cmp)
	approvers = slices.Compact(approvers)
	if len(approvers) == 0 {
		return nil, fmt.Errorf("%w: no member approves the action", ErrAclRequestNoMatch)
	}
	return approvers, nil
}

// The approval family's log as the requester uses it: RecordApprovals (RECORD-M3-07), or a test's.
type ApprovalLog interface {
	// Files the request, as the ledger stores it, in the log its approver reads.
	FileRequest(request *StoredApprovalRequest) (*RecordEntryRef, error)
	// The first decision on the approval in its request's log: ErrRecordApprovalPending while none is,
	// ErrRecordApprovalCancelled once a cancel is, ErrRecordApprovalUndeliverable to a deposit-only requester.
	Decision(ctx context.Context, approvalId Id) (*StoredApprovalDecision, error)
	// Files one use's approval_use entry after its Outcome.
	FileUse(use *protocol.ApprovalUseBody, runId *Id, actionId []byte) (*RecordEntryRef, error)
}

var _ ApprovalLog = (*RecordApprovals)(nil)

// What the requester's approval state runs on, which Sidecar.ApprovalArgs fills from the sidecar's own state and a test
// from fakes.
type ApprovalArgs struct {
	// s: this sidecar, which files every request and spends every decision.
	SidecarId Id
	Ledger    *ApprovalLedger
	// The approval family's log: Sidecar.Record's Approvals.
	Approvals ApprovalLog
	// Each run's taint, failing closed: the Sidecar.
	Runs RecordRunView
	// P now. Nil, or one answering an error, files no request and keeps no decision.
	States func() (ApprovalStates, error)
	// Where webauthn-es256 presence keys' newest signCounts are kept, durably: ApprovalPresenceCounts.
	Counter  PresenceCounter
	Clock    Clock
	Settings *SidecarMcpSettings
	// The spend check's; DefaultSpendSettings when nil.
	Spend *SpendSettings
	Log   Logger
}

// Refuses args missing what every approval step needs.
func (self *ApprovalArgs) check() error {
	if self == nil || self.Ledger == nil || self.Approvals == nil || self.Runs == nil || self.Counter == nil || self.Settings == nil {
		return fmt.Errorf("%w: approvals need a ledger, a log, a run view, a counter and settings", errInvalidSettings)
	}
	return nil
}

// P now, or ErrApprovalNoState.
func (self *ApprovalArgs) states() (ApprovalStates, error) {
	if self.States == nil {
		return nil, ErrApprovalNoState
	}
	states, err := self.States()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrApprovalNoState, err)
	}
	if states == nil {
		return nil, ErrApprovalNoState
	}
	return states, nil
}

// The spend check's settings.
func (self *ApprovalArgs) spendSettings() *SpendSettings {
	if self.Spend == nil {
		return DefaultSpendSettings()
	}
	return self.Spend
}

// Where an approval stands for its requester (§16.6's status, ur://approval/{id}).
type ApprovalStatusState string

const (
	// Filed, and no decision kept yet.
	ApprovalStatusPending ApprovalStatusState = "pending"
	// An approving decision is kept, with uses left and before its not_after.
	ApprovalStatusApproved ApprovalStatusState = "approved"
	// An approver denied it.
	ApprovalStatusDenied ApprovalStatusState = "denied"
	// An approver cancelled it: no new use is taken.
	ApprovalStatusCancelled ApprovalStatusState = "cancelled"
	// Past its not_after with no use left to take.
	ApprovalStatusExpired ApprovalStatusState = "expired"
	// Every use is reserved, each with its outcome.
	ApprovalStatusSpent ApprovalStatusState = "spent"
	// A reserved use's effect is not known to have happened or not: a retry of the same action completes it (AU3).
	ApprovalStatusUncertain ApprovalStatusState = "uncertain"
)

// One approval as its requester holds it: ids, counts, channels and times, never a summary, a preview or a recipient,
// so an agent reading ur://approval/{id} learns where its request stands and nothing an approver wrote (I-13).
type ApprovalStatus struct {
	ApprovalId Id
	State      ApprovalStatusState
	// The request's action_id: §16.6's one id from proposal to execution for uses = 1 (R-MCP-6).
	ActionId []byte
	// Whether the request was filed in a tainted run.
	Tainted bool
	// The earliest kept approving decision's not_after, else the request's.
	NotAfter time.Time
	// The uses the kept approving decisions grant, the smallest of them; 0 before any.
	Uses uint32
	// Uses reserved, each consumed for good.
	UsedCount int
	// The channel of each kept approving decision, in the order kept: the evidence a use spends on (R-MCP-7).
	Channels []protocol.ApprovalChannel
}

// The status of an approval's rows: request its first request row parsed, logCancelled whether its log reported a
// cancel, at time now.
func approvalStatusOf(state *ApprovalLedgerState, request *StoredApprovalRequest, logCancelled bool, now time.Time) *ApprovalStatus {
	status := &ApprovalStatus{
		ApprovalId: state.ApprovalId,
		ActionId:   bytes.Clone(request.Request.GetActionId()),
		Tainted:    request.Request.GetTainted(),
		NotAfter:   time.UnixMilli(request.Request.GetNotAfterMillis()),
		UsedCount:  len(state.Reserves),
	}
	approves, denied := approvalKeptDecisions(state)
	for i, kept := range approves {
		decision := kept.decision.Decision
		if i == 0 || decision.GetUses() < status.Uses {
			status.Uses = decision.GetUses()
		}
		if notAfter := time.UnixMilli(decision.GetNotAfterMillis()); i == 0 || notAfter.Before(status.NotAfter) {
			status.NotAfter = notAfter
		}
		status.Channels = append(status.Channels, protocol.ApprovalChannel(decision.GetChannel()))
	}
	uncertain := false
	for _, reserve := range state.Reserves {
		if outcome := state.Outcome(reserve.ActionId); outcome == nil || !outcome.State.final() {
			uncertain = true
		}
	}
	switch {
	case uncertain:
		status.State = ApprovalStatusUncertain
	case 0 < len(approves) && status.Uses <= uint32(len(state.Reserves)):
		status.State = ApprovalStatusSpent
	case state.Cancel != nil || logCancelled:
		status.State = ApprovalStatusCancelled
	case denied:
		status.State = ApprovalStatusDenied
	case now.After(status.NotAfter):
		status.State = ApprovalStatusExpired
	case 0 < len(approves):
		status.State = ApprovalStatusApproved
	default:
		status.State = ApprovalStatusPending
	}
	return status
}

// Whether an approval has a use left for a new action at now: an approving decision kept, none denying, no cancel,
// fewer Reserves than the smallest uses and before the earliest not_after. An uncertain use of another action does not
// stop it, since that use stays its own (AU3); the spend check decides the rest.
func approvalUsable(state *ApprovalLedgerState, logCancelled bool, now time.Time) bool {
	approves, denied := approvalKeptDecisions(state)
	if len(approves) == 0 || denied || state.Cancel != nil || logCancelled {
		return false
	}
	uses := approves[0].decision.Decision.GetUses()
	notAfterMillis := approves[0].decision.Decision.GetNotAfterMillis()
	for _, kept := range approves[1:] {
		uses = min(uses, kept.decision.Decision.GetUses())
		notAfterMillis = min(notAfterMillis, kept.decision.Decision.GetNotAfterMillis())
	}
	return uint32(len(state.Reserves)) < uses && now.UnixMilli() <= notAfterMillis
}

// One kept decision, parsed, with its Signed as stored.
type approvalKeptDecision struct {
	decision *StoredApprovalDecision
	stored   []byte
}

// The kept decisions of an approval's rows that parse: each approving one, its approver's first only, so a set never
// holds an approver twice, and whether any denies. A kept row that no longer parses counts for nothing.
func approvalKeptDecisions(state *ApprovalLedgerState) ([]*approvalKeptDecision, bool) {
	approves := []*approvalKeptDecision{}
	approverIds := []Id{}
	denied := false
	for _, storedSigned := range state.Decisions {
		decision, err := ParseStoredApprovalDecision(storedSigned)
		if err != nil {
			continue
		}
		if protocol.ApprovalVerdict(decision.Decision.GetDecision()) == protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY {
			denied = true
			continue
		}
		approver := recordIdOf(decision.Decision.GetApproverMemberId())
		if slices.Contains(approverIds, approver) {
			continue
		}
		approverIds = append(approverIds, approver)
		approves = append(approves, &approvalKeptDecision{decision: decision, stored: storedSigned})
	}
	return approves, denied
}

// A ledger row noting that the approval family's log took the request, so a retry files it again only until one has.
const ApprovalLedgerFiled ApprovalLedgerRowKind = "filed"

// Where FileRequest put the request.
type ApprovalFiledRow struct {
	// The log and entry, zero while the entry waits in the spool.
	LogId   Id    `json:"log_id"`
	EntryId Id    `json:"entry_id"`
	Spooled bool  `json:"spooled,omitempty"`
	Millis  int64 `json:"millis"`
}

// See ApprovalLedgerRowBody.
func (self *ApprovalFiledRow) ApprovalLedgerRowKind() ApprovalLedgerRowKind {
	return ApprovalLedgerFiled
}

// Called with an approval's id whenever what its requester holds of it changes: a decision or a cancel kept, a cancel
// the log reported, a use's outcome. ur://approval/{id}'s resources/updated hangs on it (MCP-M3-14). It runs on the
// caller's goroutine with no lock held, and must not block.
type ApprovalUpdateFunction func(approvalId Id)

// One request the ledger holds, as the inbox indexes it.
type approvalIndexed struct {
	request *StoredApprovalRequest
	// the request's run and agent, the zero Id for none
	runId   Id
	agentId Id
	// whether the approval family's log took it
	filed bool
	// whether a decision is kept for it, approving or denying
	decided bool
}

// The index entry of a stored request, filed and decided as its rows say.
func newApprovalIndexed(request *StoredApprovalRequest, state *ApprovalLedgerState) *approvalIndexed {
	indexed := &approvalIndexed{request: request}
	if runId := request.Request.GetRunId(); len(runId) != 0 {
		indexed.runId = recordIdOf(runId)
	}
	if agentId := request.Request.GetAgentId(); len(agentId) != 0 {
		indexed.agentId = recordIdOf(agentId)
	}
	if state != nil {
		indexed.decided = 0 < len(state.Decisions)
		for _, row := range state.Rows {
			if row.Kind == ApprovalLedgerFiled {
				indexed.filed = true
			}
		}
	}
	return indexed
}

// The zero Id for nil, else the id.
func approvalIdOrZero(id *Id) Id {
	if id == nil {
		return Id{}
	}
	return *id
}

// The requester's inbox: every request this sidecar filed, as its ledger holds them, and the decisions and cancels
// that come back for them. One per approval state. Safe for concurrent use.
type ApprovalInbox struct {
	args      *ApprovalArgs
	log       Logger
	callbacks *CallbackList[ApprovalUpdateFunction]
	// one intake at a time, held across the ledger's read and its decision row's fsync, so one decision is kept once
	// and a set never holds an approver twice: never stateLock
	intakeLock sync.Mutex

	stateLock sync.Mutex
	// whether approvalIdRequests holds every request the ledger did when it was read
	loaded             bool
	approvalIdRequests map[Id]*approvalIndexed
	// approvals whose log reported a cancel, which no kept cancel verified: they take no new use
	logCancelledApprovalIds map[Id]bool
}

// An inbox over args.
func NewApprovalInbox(args *ApprovalArgs) (*ApprovalInbox, error) {
	if err := args.check(); err != nil {
		return nil, err
	}
	return &ApprovalInbox{
		args:                    args,
		log:                     loggerOrDefault(args.Log),
		callbacks:               NewCallbackList[ApprovalUpdateFunction](),
		approvalIdRequests:      map[Id]*approvalIndexed{},
		logCancelledApprovalIds: map[Id]bool{},
	}, nil
}

// Calls callback with each approval whose state changes from now on; the answer removes it.
func (self *ApprovalInbox) AddUpdateCallback(callback ApprovalUpdateFunction) func() {
	callbackId := self.callbacks.Add(callback)
	var once sync.Once
	return func() {
		once.Do(func() {
			self.callbacks.Remove(callbackId)
		})
	}
}

// Runs each update callback for approvalId.
func (self *ApprovalInbox) notify(approvalId Id) {
	for _, callback := range self.callbacks.Get() {
		callback(approvalId)
	}
}

// Reads every request the ledger holds into the index, once. A file that fails to read indexes nothing: no decision
// for it is kept and nothing spends from it (D-CORE-15).
func (self *ApprovalInbox) ensureLoaded() error {
	loaded := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.loaded
	}()
	if loaded {
		return nil
	}
	approvalIds, err := self.args.Ledger.approvalIds()
	if err != nil {
		return err
	}
	read := map[Id]*approvalIndexed{}
	for _, approvalId := range approvalIds {
		state, err := self.args.Ledger.State(approvalId)
		if err != nil {
			self.log.Warningf("[approval]approval %s does not read, and nothing spends from it: %s", approvalId, err)
			continue
		}
		if state.Request == nil {
			continue
		}
		request, err := ParseStoredApprovalRequest(state.Request)
		if err != nil {
			self.log.Warningf("[approval]approval %s holds a request that does not parse: %s", approvalId, err)
			continue
		}
		read[approvalId] = newApprovalIndexed(request, state)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.loaded {
		for approvalId, indexed := range read {
			// an entry indexed meanwhile, by a filing, is newer than the read
			if _, ok := self.approvalIdRequests[approvalId]; !ok {
				self.approvalIdRequests[approvalId] = indexed
			}
		}
		self.loaded = true
	}
	return nil
}

// Adds a request this sidecar just wrote to its ledger.
func (self *ApprovalInbox) index(indexed *approvalIndexed) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.approvalIdRequests[indexed.request.ApprovalId()] = indexed
}

// Notes that the log took the request.
func (self *ApprovalInbox) markFiled(approvalId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if indexed, ok := self.approvalIdRequests[approvalId]; ok {
		indexed.filed = true
	}
}

// Notes that a decision is kept for the request.
func (self *ApprovalInbox) markDecided(approvalId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if indexed, ok := self.approvalIdRequests[approvalId]; ok {
		indexed.decided = true
	}
}

// Whether the approval's log reported a cancel.
func (self *ApprovalInbox) logCancelled(approvalId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.logCancelledApprovalIds[approvalId]
}

// The requests for this action in this run by this agent, newest first: the action itself, or a template
// (scope = true) the action falls inside (§16.6's multi-use row).
func (self *ApprovalInbox) candidates(action *StoredCanonicalAction, runId *Id, agentId *Id) []*approvalIndexed {
	run := approvalIdOrZero(runId)
	agent := approvalIdOrZero(agentId)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	candidates := []*approvalIndexed{}
	for _, indexed := range self.approvalIdRequests {
		if indexed.runId != run || indexed.agentId != agent {
			continue
		}
		requested := indexed.request.Action
		if bytes.Equal(requested.Bytes, action.Bytes) ||
			(requested.Action.GetScope() && ActionMatchesTemplate(requested, action)) {
			copied := *indexed
			candidates = append(candidates, &copied)
		}
	}
	// ids are ULIDs, so this is newest first
	slices.SortFunc(candidates, func(a *approvalIndexed, b *approvalIndexed) int {
		return b.request.ApprovalId().Cmp(a.request.ApprovalId())
	})
	return candidates
}

// The request for exactly this action, run and agent that still waits for a decision at now: filed tainted when the
// run is tainted, since a decision on an untainted request spends nothing in a tainted run (TS1). Nil for none.
func (self *ApprovalInbox) waitingFor(action *StoredCanonicalAction, runId *Id, agentId *Id, tainted bool, now time.Time) *approvalIndexed {
	for _, candidate := range self.candidates(action, runId, agentId) {
		request := candidate.request
		approvalId := request.ApprovalId()
		if !bytes.Equal(request.Action.Bytes, action.Bytes) || candidate.decided || self.logCancelled(approvalId) ||
			request.Request.GetTainted() != tainted || request.Request.GetNotAfterMillis() <= now.UnixMilli() {
			continue
		}
		return candidate
	}
	return nil
}

// Takes a decision the log or a hint delivered, its Signed as stored, and answers its approval id: kept, and the
// update callbacks run, once it names a request this ledger holds by its stored bytes and verifies under the key P
// names for its channel, a webauthn-es256 presence key's signCount above the one stored. ErrApprovalUnknown for a
// request this ledger never held, which is ignored; ErrApprovalRefused, or the *SpendRefusal of the check that failed,
// for one not kept; ErrApprovalNoState while no state can check it, which a later intake retries; nil, keeping nothing
// new, for a decision already kept.
func (self *ApprovalInbox) Receive(ctx context.Context, storedSigned []byte) (Id, error) {
	if err := ctx.Err(); err != nil {
		return Id{}, err
	}
	decision, err := ParseStoredApprovalDecision(storedSigned)
	if err != nil {
		return Id{}, fmt.Errorf("%w: %w", ErrApprovalRefused, err)
	}
	approvalId := recordIdOf(decision.Decision.GetApprovalId())
	kept, err := self.intake(decision, storedSigned)
	if err != nil {
		return approvalId, err
	}
	if kept {
		self.markDecided(approvalId)
		self.notify(approvalId)
	}
	return approvalId, nil
}

// Checks and keeps one decision under the intake lock, answering whether a new row was written.
func (self *ApprovalInbox) intake(decision *StoredApprovalDecision, storedSigned []byte) (bool, error) {
	self.intakeLock.Lock()
	defer self.intakeLock.Unlock()
	approvalId := recordIdOf(decision.Decision.GetApprovalId())
	state, err := self.args.Ledger.State(approvalId)
	if err != nil {
		return false, err
	}
	if state.Request == nil {
		return false, fmt.Errorf("%w: %s", ErrApprovalUnknown, approvalId)
	}
	request, err := ParseStoredApprovalRequest(state.Request)
	if err != nil {
		return false, err
	}
	if !decision.Binds(request) {
		return false, fmt.Errorf("%w: a decision that does not name its request's stored bytes", ErrApprovalRefused)
	}
	for _, keptSigned := range state.Decisions {
		if kept, err := ParseStoredApprovalDecision(keptSigned); err == nil && bytes.Equal(kept.Bytes, decision.Bytes) {
			return false, nil
		}
	}
	states, err := self.args.states()
	if err != nil {
		return false, err
	}
	if err := approvalVerifyDecision(decision, states, self.args.SidecarId, self.args.Counter); err != nil {
		return false, err
	}
	if err := self.args.Ledger.Append(approvalId, &ApprovalDecisionRow{Decision: bytes.Clone(storedSigned)}); err != nil {
		return false, err
	}
	return true, nil
}

// That a decision is its channel's at P, as spendable's signer steps judge it: verified under the key the channel
// names, and that key's holder the channel's (a device: an approval-capable device of the approver other than the
// spender; harness: the spender itself, an approval-capable device of the approver; presence: a key registered to the
// approver), so an approver's decision is never crowded out by one its signer could not give. A webauthn-es256
// presence key's signCount is compared against counter and stored there: the one place a count is compared, since a
// decision is spent many times over (record_spend.go). Nil, or the *SpendRefusal of the step that failed.
func approvalVerifyDecision(decision *StoredApprovalDecision, states SpendState, spender Id, counter PresenceCounter) error {
	approver := recordIdOf(decision.Decision.GetApproverMemberId())
	channel := protocol.ApprovalChannel(decision.Decision.GetChannel())
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE {
		key := states.PresenceKey(decision.Signed.GetKeyId(), approver)
		if key == nil {
			return spendRefuse(SpendRefusalSigner, errors.New("no live presence key of the approver under its key_id"))
		}
		if err := VerifyPresenceUse(decision.Signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key, counter); err != nil {
			return spendRefuse(SpendRefusalSignature, err)
		}
		return nil
	}
	if refusal := spendVerifyDecision(decision, states); refusal != nil {
		return refusal
	}
	signerId, err := IdFromBytes(decision.Signed.GetSignerId())
	if err != nil {
		return spendRefuse(SpendRefusalSigner, err)
	}
	switch {
	case channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE && signerId == spender:
		return spendRefuse(SpendRefusalSigner, errors.New("a device decision the requester signed itself"))
	case channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS && signerId != spender:
		return spendRefuse(SpendRefusalSigner, errors.New("a harness decision another sidecar signed"))
	case !states.ApprovalCapable(signerId, approver):
		return spendRefuse(SpendRefusalSigner, fmt.Errorf("sidecar %s is no approval-capable device of member %s", signerId, approver))
	}
	return nil
}

// Takes an approver's ApprovalCancel, its Signed as stored, and answers its approval id: a Cancel row appended under
// the approval's hold, and the update callbacks run, once CheckApprovalCancel passes against a decision this ledger
// keeps. A use reserved before it still completes (§16.6's cancel row). ErrApprovalUnknown for a request this ledger
// never held or one with no decision kept, whose cancel has nothing to take away; a *SpendRefusal for one not kept;
// nil, writing nothing, when a Cancel is kept already.
func (self *ApprovalInbox) ReceiveCancel(ctx context.Context, storedSigned []byte) (Id, error) {
	if err := ctx.Err(); err != nil {
		return Id{}, err
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(storedSigned, signed); err != nil {
		return Id{}, fmt.Errorf("%w: a cancel that does not parse", ErrApprovalRefused)
	}
	cancel := &protocol.ApprovalCancel{}
	if err := proto.Unmarshal(signed.GetBody(), cancel); err != nil || len(cancel.GetApprovalId()) != recordIdByteCount {
		return Id{}, fmt.Errorf("%w: a cancel's body", ErrApprovalRefused)
	}
	approvalId := recordIdOf(cancel.GetApprovalId())
	written, err := func() (bool, error) {
		self.intakeLock.Lock()
		defer self.intakeLock.Unlock()
		state, err := self.args.Ledger.State(approvalId)
		if err != nil {
			return false, err
		}
		if state.Request == nil || len(state.Decisions) == 0 {
			return false, fmt.Errorf("%w: %s", ErrApprovalUnknown, approvalId)
		}
		states, err := self.args.states()
		if err != nil {
			return false, err
		}
		var checkErr error
		verified := false
		for _, keptSigned := range state.Decisions {
			decision, err := ParseStoredApprovalDecision(keptSigned)
			if err != nil {
				continue
			}
			if checkErr = CheckApprovalCancel(signed, decision, states); checkErr == nil {
				verified = true
				break
			}
		}
		if !verified {
			if checkErr == nil {
				checkErr = fmt.Errorf("%w: no kept decision to check the cancel against", ErrApprovalRefused)
			}
			return false, checkErr
		}
		signerId := Id{}
		if len(signed.GetKeyId()) == 0 {
			signerId, _ = IdFromBytes(signed.GetSignerId())
		}
		hold := self.args.Ledger.Hold(approvalId)
		defer hold.Release()
		held, err := hold.State()
		if err != nil {
			return false, err
		}
		if held.Cancel != nil {
			return false, nil
		}
		return true, hold.Cancel(signerId)
	}()
	if err != nil {
		return approvalId, err
	}
	if written {
		self.notify(approvalId)
	}
	return approvalId, nil
}

// Asks the approval family's log for the decision of each request still waiting, keeping each that checks, and notes
// each the log reports cancelled. A request the log has no decision for, or will not deliver to a deposit-only
// requester, stays pending. Answers the errors of the asks that failed, the rest having run.
func (self *ApprovalInbox) Poll(ctx context.Context) error {
	if err := self.ensureLoaded(); err != nil {
		return err
	}
	now := self.args.Clock.Now()
	waiting := func() []Id {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		approvalIds := []Id{}
		for approvalId, indexed := range self.approvalIdRequests {
			if !indexed.decided && !self.logCancelledApprovalIds[approvalId] &&
				now.UnixMilli() < indexed.request.Request.GetNotAfterMillis() {
				approvalIds = append(approvalIds, approvalId)
			}
		}
		slices.SortFunc(approvalIds, Id.Cmp)
		return approvalIds
	}()
	errs := []error{}
	for _, approvalId := range waiting {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := self.pollOne(ctx, approvalId); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Asks the log for one approval's decision, as Poll does.
func (self *ApprovalInbox) pollOne(ctx context.Context, approvalId Id) error {
	decision, err := self.args.Approvals.Decision(ctx, approvalId)
	switch {
	case err == nil:
		storedSigned, err := proto.Marshal(decision.Signed)
		if err != nil {
			return err
		}
		if _, err := self.Receive(ctx, storedSigned); err != nil {
			if errors.Is(err, ErrApprovalNoState) {
				return err
			}
			// a decision that does not check is not kept, and the request keeps waiting for one that does
			self.log.Warningf("[approval]a decision on approval %s was not kept: %s", approvalId, err)
		}
		return nil
	case errors.Is(err, ErrRecordApprovalCancelled):
		changed := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.logCancelledApprovalIds[approvalId] {
				return false
			}
			self.logCancelledApprovalIds[approvalId] = true
			return true
		}()
		if changed {
			self.notify(approvalId)
		}
		return nil
	case errors.Is(err, ErrRecordApprovalPending), errors.Is(err, ErrRecordApprovalUndeliverable),
		errors.Is(err, ErrRecordApprovalUnknown), errors.Is(err, ErrRecordApprovalTeamRoute):
		return nil
	}
	return err
}

// Polls every ApprovalPollInterval until ctx ends: the poll behind ur://approval/{id} until the record's hints reach
// the inbox (RECORD-M3-07's review item).
func (self *ApprovalInbox) Run(ctx context.Context) {
	for {
		if err := self.Poll(ctx); err != nil && ctx.Err() == nil && self.log.V(1).Enabled() {
			self.log.Infof("[approval]a poll of the approval log failed: %s", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-self.args.Clock.After(self.args.Settings.ApprovalPollInterval):
		}
	}
}

// Where the approval stands now, from its ledger rows. ErrApprovalUnknown for a request this ledger never held.
func (self *ApprovalInbox) Status(approvalId Id) (*ApprovalStatus, error) {
	state, err := self.args.Ledger.State(approvalId)
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
	return approvalStatusOf(state, request, self.logCancelled(approvalId), self.args.Clock.Now()), nil
}

// The requester's router: §16.6's find-or-file, and each use's approval_use entry. One per approval state. Safe for
// concurrent use.
type ApprovalRouter struct {
	args  *ApprovalArgs
	inbox *ApprovalInbox
	log   Logger
	// one filing at a time, held across the ledger's fsync and FileRequest, so two callers of one action file once:
	// never stateLock
	fileLock sync.Mutex
}

// A router over args, indexing what it files in inbox.
func NewApprovalRouter(args *ApprovalArgs, inbox *ApprovalInbox) (*ApprovalRouter, error) {
	if err := args.check(); err != nil {
		return nil, err
	}
	if inbox == nil {
		return nil, fmt.Errorf("%w: a router needs its inbox", errInvalidSettings)
	}
	return &ApprovalRouter{args: args, inbox: inbox, log: loggerOrDefault(args.Log)}, nil
}

// §16.6's request for action, found or filed: the request for the same action, run and agent that still waits, else
// a new one, written into the ledger and filed in the approval family's log. Its taint is the run's now. Answers the
// request as stored; the caller answers *ApprovalPendingError with its id.
func (self *ApprovalRouter) FindOrFile(ctx context.Context, action *SidecarAction) (*StoredApprovalRequest, error) {
	if action == nil {
		return nil, ErrSidecarActionInvalid
	}
	stored, err := ParseStoredCanonicalAction(action.Canonical)
	if err != nil {
		return nil, err
	}
	tainted := action.RunId != nil && self.args.Runs.RunTainted(*action.RunId)
	return self.findOrFile(ctx, action, stored, tainted)
}

// FindOrFile, with the action parsed and the run's taint read.
func (self *ApprovalRouter) findOrFile(ctx context.Context, action *SidecarAction, stored *StoredCanonicalAction, tainted bool) (*StoredApprovalRequest, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := self.inbox.ensureLoaded(); err != nil {
		return nil, err
	}
	self.fileLock.Lock()
	defer self.fileLock.Unlock()
	if waiting := self.inbox.waitingFor(stored, action.RunId, action.AgentId, tainted, self.args.Clock.Now()); waiting != nil {
		if !waiting.filed {
			self.fileToLog(waiting.request)
		}
		return waiting.request, nil
	}
	request, err := self.newRequest(action, stored, tainted)
	if err != nil {
		return nil, err
	}
	if err := self.args.Ledger.Append(request.ApprovalId(), &ApprovalRequestRow{Request: request.Bytes}); err != nil {
		return nil, err
	}
	self.inbox.index(newApprovalIndexed(request, nil))
	self.fileToLog(request)
	return request, nil
}

// A new ApprovalRequest for action, as stored: §16.8's fields, the approvers P names, not_after reading 3's.
func (self *ApprovalRouter) newRequest(action *SidecarAction, stored *StoredCanonicalAction, tainted bool) (*StoredApprovalRequest, error) {
	states, err := self.args.states()
	if err != nil {
		return nil, err
	}
	now := self.args.Clock.Now()
	approvers, err := states.Approvers(stored, self.args.SidecarId, now)
	if err != nil {
		return nil, err
	}
	notAfterMillis := now.Add(self.args.Settings.ApprovalRequestTimeout).UnixMilli()
	if expiresMillis := stored.Action.GetExpiresMillis(); 0 < expiresMillis && expiresMillis < notAfterMillis {
		notAfterMillis = expiresMillis
	}
	if notAfterMillis <= now.UnixMilli() {
		return nil, errors.New("the action's own expiry has passed, so no decision could activate it")
	}
	approvalId := NewId()
	actionId := stored.ActionId(approvalId)
	payloadSha256 := stored.PayloadSha256()
	request := &protocol.ApprovalRequest{
		ApprovalId:         approvalId.Bytes(),
		ActionId:           actionId[:],
		CanonicalAction:    stored.Bytes,
		PayloadSha256:      payloadSha256[:],
		Summary:            action.Summary,
		Risk:               uint32(action.Risk),
		RequesterSidecarId: self.args.SidecarId.Bytes(),
		Tainted:            tainted,
		NotAfterMillis:     notAfterMillis,
		Version:            1,
	}
	if action.RunId != nil {
		request.RunId = action.RunId.Bytes()
	}
	if action.AgentId != nil {
		request.AgentId = action.AgentId.Bytes()
	}
	for _, approver := range approvers {
		request.Approvers = append(request.Approvers, approver.Bytes())
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return nil, err
	}
	return ParseStoredApprovalRequest(encoded)
}

// Files request in the approval family's log and notes that it took it. A refusal leaves it pending, filed again at
// the next retry: in a network with no team record, a request whose approver is not the author stays pending, failing
// closed (RECORD-M3-07).
func (self *ApprovalRouter) fileToLog(request *StoredApprovalRequest) {
	approvalId := request.ApprovalId()
	ref, err := self.args.Approvals.FileRequest(request)
	if err != nil {
		self.log.Warningf("[approval]approval %s waits for a log that takes it: %s", approvalId, err)
		return
	}
	filed := &ApprovalFiledRow{Spooled: ref.Spooled, Millis: self.args.Clock.Now().UnixMilli()}
	if !ref.Spooled {
		filed.LogId = ref.LogId
		filed.EntryId = ref.EntryId
	}
	if err := self.args.Ledger.Append(approvalId, filed); err != nil {
		// the log has it: a retry files it once more, which its approver reads as one request
		self.log.Warningf("[approval]approval %s was filed and its row was not kept: %s", approvalId, err)
		return
	}
	self.inbox.markFiled(approvalId)
}

// §16.8's approval_use for one use whose Outcome is in the ledger, in the requester's route, then the update
// callbacks. Its action_id links it to the decision entry, whose header names the channel the use spent (R-MCP-7).
func (self *ApprovalRouter) FileUse(approvalId Id, reserve *ApprovalReserve, outcome *ApprovalOutcome, runId *Id) error {
	defer self.inbox.notify(approvalId)
	use := &protocol.ApprovalUseBody{
		ApprovalId:     approvalId.Bytes(),
		UseIndex:       reserve.UseIndex,
		PayloadSha256:  bytes.Clone(reserve.PayloadSha256),
		EffectKey:      bytes.Clone(reserve.EffectKey),
		State:          approvalUseState(outcome.State),
		EffectRef:      bytes.Clone(outcome.EffectRef),
		ReservedMillis: reserve.ReservedMillis,
		OutcomeMillis:  outcome.Millis,
	}
	_, err := self.args.Approvals.FileUse(use, runId, reserve.ActionId)
	return err
}

// ApprovalUseBody.state's number for an Outcome's state: 1 done, 2 not_done, 3 uncertain.
func approvalUseState(state ApprovalOutcomeState) uint32 {
	switch state {
	case ApprovalOutcomeDone:
		return 1
	case ApprovalOutcomeNotDone:
		return 2
	}
	return 3
}

// A PresenceCounter in the network's local store: one sealed JSON file, presence/counts under the approval class,
// replaced whole and fsynced before UpdatePresenceCount returns, so a crash cannot roll a key's count back and let a
// replayed assertion pass (§16.6's per use). Safe for concurrent use.
type ApprovalPresenceCounts struct {
	store SidecarStore
	// held across the file's read and replace: the store's own lock, which UpdatePresenceCount's contract names
	countLock sync.Mutex
}

// The counts in the network's local store (Sidecar.LocalStore).
func NewApprovalPresenceCounts(localStore SidecarStore) (*ApprovalPresenceCounts, error) {
	store, err := localStore.Directory(approvalPresenceDirectoryName, approvalLedgerClass)
	if err != nil {
		return nil, err
	}
	return &ApprovalPresenceCounts{store: store}, nil
}

// See PresenceCounter.
func (self *ApprovalPresenceCounts) UpdatePresenceCount(keyId []byte, update func(storedCount uint32) (uint32, error)) error {
	self.countLock.Lock()
	defer self.countLock.Unlock()
	keyIdCounts := map[string]uint32{}
	reader, err := self.store.Open(approvalPresenceCountsName)
	switch {
	case errors.Is(err, ErrSidecarStoreAbsent):
	case err != nil:
		return err
	default:
		encoded, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return err
		}
		if err := json.Unmarshal(encoded, &keyIdCounts); err != nil {
			return fmt.Errorf("%w: presence counts that do not decode", ErrSidecarStoreFailed)
		}
	}
	name := hex.EncodeToString(keyId)
	storedCount := keyIdCounts[name]
	count, err := update(storedCount)
	if err != nil {
		return err
	}
	if count == storedCount {
		return nil
	}
	keyIdCounts[name] = count
	encoded, err := json.Marshal(keyIdCounts)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(approvalPresenceCountsName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}
