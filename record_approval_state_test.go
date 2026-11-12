//go:build !ios_extension

// MCP-M3-05: the requester's half of §16.6 on a fake approval log, the spend tests' fixture state and a real ledger
// and run store: the same action, run and agent find their waiting request, across a restart too; the request's taint
// is the run file's; a decision for an unknown request is ignored and a forged one is not kept; a presence decision's
// signCount is compared once, durably; the status walks its states; each Outcome files its approval_use; and no log
// line carries a summary or a preview.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The log every fake approval log answers as.
var testApprovalLogId = Id{0x01, 0x9a, 0x77}

// The approval family's log in memory: what was filed, the decisions and cancels the test puts in it, and the uses.
type testApprovalLog struct {
	stateLock           sync.Mutex
	filed               []*StoredApprovalRequest
	approvalIdDecisions map[Id][]byte
	approvalIdCancelled map[Id]bool
	approvalIdCancels   map[Id][]byte
	uses                []*protocol.ApprovalUseBody
	useActionIds        [][]byte
	// what FileRequest answers, nil to take the request
	refuseFile error
}

func newTestApprovalLog() *testApprovalLog {
	return &testApprovalLog{approvalIdDecisions: map[Id][]byte{}, approvalIdCancelled: map[Id]bool{}, approvalIdCancels: map[Id][]byte{}}
}

func (self *testApprovalLog) FileRequest(request *StoredApprovalRequest) (*RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.refuseFile != nil {
		return nil, self.refuseFile
	}
	self.filed = append(self.filed, request)
	return &RecordEntryRef{LogId: testApprovalLogId, EntryId: NewId(), Seq: uint64(len(self.filed))}, nil
}

func (self *testApprovalLog) Decision(ctx context.Context, approvalId Id) (*StoredApprovalDecision, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.approvalIdCancelled[approvalId] {
		return nil, ErrRecordApprovalCancelled
	}
	storedSigned, ok := self.approvalIdDecisions[approvalId]
	if !ok {
		return nil, ErrRecordApprovalPending
	}
	return ParseStoredApprovalDecision(storedSigned)
}

func (self *testApprovalLog) Cancel(ctx context.Context, approvalId Id) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if storedSigned, ok := self.approvalIdCancels[approvalId]; ok {
		return bytes.Clone(storedSigned), nil
	}
	return nil, ErrRecordApprovalPending
}

func (self *testApprovalLog) FileUse(use *protocol.ApprovalUseBody, runId *Id, actionId []byte) (*RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.uses = append(self.uses, use)
	self.useActionIds = append(self.useActionIds, bytes.Clone(actionId))
	return &RecordEntryRef{LogId: testApprovalLogId, EntryId: NewId()}, nil
}

// Puts an approver's decision in the log, as its device files it.
func (self *testApprovalLog) putDecision(approvalId Id, storedSigned []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.approvalIdDecisions[approvalId] = storedSigned
}

func (self *testApprovalLog) filedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.filed)
}

func (self *testApprovalLog) useBodies() []*protocol.ApprovalUseBody {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.uses)
}

// The spend fixture's state with who approves and whether a rule names harness.
type testApprovalStates struct {
	*testSpendFixtureState
	approvers    []Id
	namesHarness bool
}

func (self *testApprovalStates) Approvers(action *StoredCanonicalAction, requester Id, now time.Time) ([]Id, error) {
	if len(self.approvers) == 0 {
		return nil, ErrAclRequestNoMatch
	}
	return slices.Clone(self.approvers), nil
}

func (self *testApprovalStates) RuleNamesHarness(action *StoredCanonicalAction) bool {
	return self.namesHarness
}

// A run store as the record's run view.
type testApprovalRunView struct {
	runs *RunStore
}

func (self *testApprovalRunView) RunTainted(runId Id) bool {
	return self.runs.Tainted(runId)
}

// What a component does for the gate: each key's effect once, its reference, and what a test sets it to answer.
type testGateEffect struct {
	stateLock sync.Mutex
	// the effect each key made, by key
	keyRefs map[string][]byte
	// Run's calls
	runCount int
	// effects that happened: one per key, and one per keyless run
	effectCount int
	// what Run answers instead of doing the effect, nil to do it
	answer error
	// a token sent as each Run starts, and one Run waits for before it acts; nil for none
	running chan struct{}
	release chan struct{}
	// what lookup answers for a key with no effect: not_done where it can prove none, else uncertain
	lookupProvesNone bool
	// the spend the last Run saw on its context
	lastSpend *ApprovalSpend
}

func newTestGateEffect() *testGateEffect {
	return &testGateEffect{keyRefs: map[string][]byte{}}
}

func (self *testGateEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	if self.running != nil {
		self.running <- struct{}{}
	}
	if self.release != nil {
		select {
		case <-self.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.runCount += 1
	if spend, ok := ApprovalSpendFromContext(ctx); ok {
		self.lastSpend = spend
	}
	if ref, ok := self.keyRefs[string(effectKey)]; ok && len(effectKey) != 0 {
		return bytes.Clone(ref), nil
	}
	if self.answer != nil {
		return nil, self.answer
	}
	self.effectCount += 1
	ref := []byte(fmt.Sprintf("effect %d", self.effectCount))
	if len(effectKey) != 0 {
		self.keyRefs[string(effectKey)] = ref
	}
	return bytes.Clone(ref), nil
}

func (self *testGateEffect) lookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if ref, ok := self.keyRefs[string(effectKey)]; ok {
		return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: bytes.Clone(ref)}, nil
	}
	if self.lookupProvesNone {
		return &SidecarOutcome{State: ApprovalOutcomeNotDone}, nil
	}
	return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
}

// Takes an effect as a lost process would have done it, under key.
func (self *testGateEffect) doneUnder(effectKey []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.effectCount += 1
	self.keyRefs[string(effectKey)] = []byte(fmt.Sprintf("effect %d", self.effectCount))
}

func (self *testGateEffect) counts() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.runCount, self.effectCount
}

// The spend the last Run saw, false for none.
func (self *testGateEffect) spendSeen() (*ApprovalSpend, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.lastSpend, self.lastSpend != nil
}

func (self *testGateEffect) setAnswer(answer error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answer = answer
}

// Standing grants that cover every action or none.
type testStandingGrants struct {
	covers bool
}

func (self *testStandingGrants) ActiveGrant(action *StoredCanonicalAction, spender Id, now time.Time) bool {
	return self.covers
}

// A logger that keeps every line, for the test that no summary or preview reaches one.
type testApprovalLogger struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testApprovalLogger) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testApprovalLogger) Info(args ...any) { self.add(fmt.Sprint(args...)) }
func (self *testApprovalLogger) Infof(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testApprovalLogger) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testApprovalLogger) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testApprovalLogger) V(level int32) Verbose { return testApprovalVerbose{logger: self} }

func (self *testApprovalLogger) all() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return strings.Join(self.lines, "\n")
}

// Every level enabled, so a guarded line is written too.
type testApprovalVerbose struct {
	logger *testApprovalLogger
}

func (self testApprovalVerbose) Enabled() bool                    { return true }
func (self testApprovalVerbose) Info(args ...any)                 { self.logger.Info(args...) }
func (self testApprovalVerbose) Infof(format string, args ...any) { self.logger.Infof(format, args...) }

// A requester's approval state on the spend tests' world: the laptop requests and spends, its member approves from the
// phone, over a real ledger, run store and presence counts in an enrolled instance's store.
type testApprovalWorld struct {
	t       *testing.T
	spend   *testSpendWorld
	clock   *recordTestClock
	store   SidecarStore
	ledger  *ApprovalLedger
	runs    *RunStore
	log     *testApprovalLog
	states  *testApprovalStates
	grants  *testStandingGrants
	harness ApprovalHarnessEvidence
	effect  *testGateEffect
	logger  *testApprovalLogger
	lookups map[SidecarActionKind]SidecarEffectLookup
	runId   Id
	agentId Id

	args   *ApprovalArgs
	inbox  *ApprovalInbox
	router *ApprovalRouter
	gate   *ApprovalGate
}

func newTestApprovalWorld(t *testing.T) *testApprovalWorld {
	t.Helper()
	spend := newTestSpendWorld(t)
	instance, _, _ := enrolledInstance(t)
	store := instance.Store(&testNetworkId)
	clock := &recordTestClock{at: time.UnixMilli(spend.nowMs)}
	settings := defaultSidecarMcpSettings()
	ledger, err := NewApprovalLedger(store, settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := NewRunStore(store, settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	world := &testApprovalWorld{
		t:       t,
		spend:   spend,
		clock:   clock,
		store:   store,
		ledger:  ledger,
		runs:    runs,
		log:     newTestApprovalLog(),
		states:  &testApprovalStates{testSpendFixtureState: spend.state(), approvers: []Id{spend.member}},
		grants:  &testStandingGrants{},
		effect:  newTestGateEffect(),
		logger:  &testApprovalLogger{},
		lookups: map[SidecarActionKind]SidecarEffectLookup{},
		runId:   testConfigId("approval world run"),
		agentId: testConfigId("approval world agent"),
	}
	for _, kind := range []SidecarActionKind{SidecarActionMail, SidecarActionDnsSet, SidecarActionDnsDelete} {
		world.lookups[kind] = world.effect.lookup
	}
	if err := runs.Create(t.Context(), &RunFile{RunId: world.runId, Harness: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	world.open()
	return world
}

// Builds the inbox, router and gate afresh over the world's ledger and store, as a daemon's restart does.
func (self *testApprovalWorld) open() {
	self.t.Helper()
	counter, err := NewApprovalPresenceCounts(self.store)
	if err != nil {
		self.t.Fatal(err)
	}
	self.args = &ApprovalArgs{
		SidecarId: self.spend.laptop,
		Ledger:    self.ledger,
		Approvals: self.log,
		Runs:      &testApprovalRunView{runs: self.runs},
		States: func() (ApprovalStates, error) {
			return self.states, nil
		},
		Counter:  counter,
		Clock:    self.clock,
		Settings: defaultSidecarMcpSettings(),
		Spend:    DefaultSpendSettings(),
		Log:      self.logger,
	}
	if self.inbox, err = NewApprovalInbox(self.args); err != nil {
		self.t.Fatal(err)
	}
	if self.router, err = NewApprovalRouter(self.args, self.inbox); err != nil {
		self.t.Fatal(err)
	}
	self.gate, err = NewApprovalGate(self.args, self.inbox, self.router, &ApprovalGateArgs{
		Grants: self.grants,
		Harness: approvalHarnessFunc(func(ctx context.Context, action *SidecarAction, request *StoredApprovalRequest) ([]byte, error) {
			if self.harness == nil {
				return nil, nil
			}
			return self.harness.HarnessDecision(ctx, action, request)
		}),
		Lookups: func(kind SidecarActionKind) SidecarEffectLookup {
			return self.lookups[kind]
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
}

// ApprovalHarnessEvidence as a function.
type approvalHarnessFunc func(ctx context.Context, action *SidecarAction, request *StoredApprovalRequest) ([]byte, error)

func (self approvalHarnessFunc) HarnessDecision(ctx context.Context, action *SidecarAction, request *StoredApprovalRequest) ([]byte, error) {
	return self(ctx, action, request)
}

// action as the O tool hands it to Authorize, in the world's run and agent, with the world's effect.
func (self *testApprovalWorld) action(stored *StoredCanonicalAction) *SidecarAction {
	runId := self.runId
	agentId := self.agentId
	return &SidecarAction{
		Kind:      SidecarActionKind(stored.Action.GetKind()),
		Canonical: stored.Bytes,
		Risk:      SidecarRiskNormal,
		RunId:     &runId,
		AgentId:   &agentId,
		Summary:   "agent words: send the thing",
		Effect:    self.effect,
	}
}

// A mail action to recipient, a local kind.
func (self *testApprovalWorld) mailAction(recipient string) *StoredCanonicalAction {
	self.t.Helper()
	bodySha256 := sha256.Sum256([]byte("body for " + recipient))
	action, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionMail), Recipients: []string{recipient}, BodySha256: bodySha256[:], Alias: "me",
		Preview: "PREVIEW-TEXT-" + recipient,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return action
}

// The request a pending answer names, parsed from the ledger.
func (self *testApprovalWorld) pendingRequest(err error) *StoredApprovalRequest {
	self.t.Helper()
	pending := &ApprovalPendingError{}
	if !errors.As(err, &pending) {
		self.t.Fatalf("not pending: %v", err)
	}
	state, err := self.ledger.State(pending.ApprovalId)
	if err != nil || state.Request == nil {
		self.t.Fatalf("no request for %s: %v", pending.ApprovalId, err)
	}
	request, err := ParseStoredApprovalRequest(state.Request)
	if err != nil {
		self.t.Fatal(err)
	}
	return request
}

// The member's decision on request from signerId's device on channel, verdict and uses as given, as stored.
func (self *testApprovalWorld) decision(request *StoredApprovalRequest, signerId Id, channel protocol.ApprovalChannel,
	verdict protocol.ApprovalVerdict, uses uint32) []byte {
	self.t.Helper()
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	body := &protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(verdict),
		Uses:               uses,
		NotAfterMillis:     request.Request.GetNotAfterMillis(),
		ApproverMemberId:   self.spend.member.Bytes(),
		Channel:            uint32(channel),
		RequesterSidecarId: request.Request.GetRequesterSidecarId(),
		AuthPin:            self.spend.pin,
		Version:            1,
	}
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS {
		evidence := sha256.Sum256(append([]byte("approval world hook event "), request.Request.GetApprovalId()...))
		body.EvidenceSha256 = evidence[:]
	}
	signed := testSpendSignedBy(self.t, signerId, self.spend.keys[signerId], body)
	stored, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	return stored
}

// The phone's approval of request, one use.
func (self *testApprovalWorld) approve(request *StoredApprovalRequest) []byte {
	return self.decision(request, self.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, 1)
}

// Files the action's request, approves it from the phone and keeps that decision: the approval spends at the next
// Authorize.
func (self *testApprovalWorld) approved(stored *StoredCanonicalAction) *StoredApprovalRequest {
	self.t.Helper()
	request := self.pendingRequest(self.gate.Authorize(self.t.Context(), self.action(stored), nil))
	self.log.putDecision(request.ApprovalId(), self.approve(request))
	if err := self.inbox.Poll(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
	return request
}

// The ledger's rows of an approval.
func (self *testApprovalWorld) state(approvalId Id) *ApprovalLedgerState {
	self.t.Helper()
	state, err := self.ledger.State(approvalId)
	if err != nil {
		self.t.Fatal(err)
	}
	return state
}

// The approval's status, which must answer.
func (self *testApprovalWorld) status(approvalId Id) ApprovalStatusState {
	self.t.Helper()
	status, err := self.inbox.Status(approvalId)
	if err != nil {
		self.t.Fatal(err)
	}
	return status.State
}

// The same action, run and agent while their request waits answer that request, from a second call and again after a
// restart, which builds the inbox and router afresh over the ledger: one request filed in all.
func TestSameActionFindsPendingRequest(t *testing.T) {
	world := newTestApprovalWorld(t)
	stored := world.mailAction("someone@example.com")
	first := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(stored), nil))
	again := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(stored), nil))
	if again.ApprovalId() != first.ApprovalId() {
		t.Errorf("a second call filed %s beside %s", again.ApprovalId(), first.ApprovalId())
	}
	world.open()
	found, err := world.router.FindOrFile(t.Context(), world.action(stored))
	if err != nil || found.ApprovalId() != first.ApprovalId() {
		t.Errorf("after a restart: %v, %v", found, err)
	}
	if world.log.filedCount() != 1 {
		t.Errorf("%d requests filed", world.log.filedCount())
	}
	// another agent's identical action is its own request
	other := world.action(stored)
	otherAgent := testConfigId("approval world other agent")
	other.AgentId = &otherAgent
	otherRequest := world.pendingRequest(world.gate.Authorize(t.Context(), other, nil))
	if otherRequest.ApprovalId() == first.ApprovalId() {
		t.Error("another agent's action found this agent's request")
	}
	// the request is what §16.8 asks: the daemon's action as stored, its hashes, the requester, the approvers
	request := first.Request
	payloadSha256 := stored.PayloadSha256()
	actionId := stored.ActionId(first.ApprovalId())
	if !bytes.Equal(request.GetCanonicalAction(), stored.Bytes) || !bytes.Equal(request.GetPayloadSha256(), payloadSha256[:]) ||
		!bytes.Equal(request.GetActionId(), actionId[:]) || recordIdOf(request.GetRequesterSidecarId()) != world.spend.laptop ||
		len(request.GetApprovers()) != 1 || recordIdOf(request.GetApprovers()[0]) != world.spend.member ||
		recordIdOf(request.GetRunId()) != world.runId || recordIdOf(request.GetAgentId()) != world.agentId {
		t.Errorf("the request: %+v", request)
	}
	wantNotAfter := world.clock.Now().Add(defaultSidecarMcpSettings().ApprovalRequestTimeout).UnixMilli()
	if request.GetNotAfterMillis() != wantNotAfter {
		t.Errorf("not_after %d, want %d", request.GetNotAfterMillis(), wantNotAfter)
	}
}

// A request the log refuses stays pending and is filed again at the next call, never twice once the log takes it.
func TestRefusedFilingFilesAgain(t *testing.T) {
	world := newTestApprovalWorld(t)
	world.log.refuseFile = ErrRecordApprovalTeamRoute
	stored := world.mailAction("someone@example.com")
	first := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(stored), nil))
	if world.log.filedCount() != 0 {
		t.Fatal("a refused filing was kept")
	}
	world.log.refuseFile = nil
	again := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(stored), nil))
	world.pendingRequest(world.gate.Authorize(t.Context(), world.action(stored), nil))
	if again.ApprovalId() != first.ApprovalId() || world.log.filedCount() != 1 {
		t.Errorf("approval %s, %d filed", again.ApprovalId(), world.log.filedCount())
	}
}

// ApprovalRequest.tainted is the run file's at the filing: a tainted run's request says so, an untainted one's does
// not, and a run with no file reads tainted.
func TestTaintedFlagFromRunFile(t *testing.T) {
	world := newTestApprovalWorld(t)
	clean := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("a@example.com")), nil))
	if clean.Request.GetTainted() {
		t.Error("an untainted run's request reads tainted")
	}
	if err := world.runs.Taint(t.Context(), world.runId, RunTaintWebTool); err != nil {
		t.Fatal(err)
	}
	tainted := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("b@example.com")), nil))
	if !tainted.Request.GetTainted() {
		t.Error("a tainted run's request reads untainted")
	}
	unknown := world.action(world.mailAction("c@example.com"))
	unknownRun := testConfigId("a run with no file")
	unknown.RunId = &unknownRun
	if request := world.pendingRequest(world.gate.Authorize(t.Context(), unknown, nil)); !request.Request.GetTainted() {
		t.Error("a run with no file filed an untainted request")
	}
}

// A decision for a request this ledger never held is ignored: nothing is written, and no status answers for it.
func TestDecisionForUnknownRequestIgnored(t *testing.T) {
	world := newTestApprovalWorld(t)
	stored := world.mailAction("someone@example.com")
	unknown := testConfigId("an approval never filed")
	body := testSpendDecisionBody(stored, unknown, world.spend.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		world.spend.laptop, world.spend.pin, world.spend.nowMs+testConfigHourMs)
	storedSigned, err := proto.Marshal(testSpendSignedBy(t, world.spend.phone, world.spend.keys[world.spend.phone], body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.inbox.Receive(t.Context(), storedSigned); !errors.Is(err, ErrApprovalUnknown) {
		t.Errorf("an unknown request's decision answered %v", err)
	}
	if state := world.state(unknown); len(state.Rows) != 0 {
		t.Errorf("%d rows written for an unknown request", len(state.Rows))
	}
	if _, err := world.inbox.Status(unknown); !errors.Is(err, ErrApprovalUnknown) {
		t.Errorf("status of an unknown request: %v", err)
	}
	// passed straight to Authorize it is refused, never trusted
	if err := world.gate.Authorize(t.Context(), world.action(stored), testSpendSignedBy(t, world.spend.phone, world.spend.keys[world.spend.phone], body)); !errors.Is(err, ErrApprovalUnknown) {
		t.Errorf("Authorize with an unknown request's decision: %v", err)
	}
}

// A decision that does not verify under the key P names for its channel, or does not name its request's stored bytes,
// is not kept, from the poll or handed in, and the request stays pending.
func TestForgedDecisionNotKept(t *testing.T) {
	world := newTestApprovalWorld(t)
	request := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("someone@example.com")), nil))
	// the phone's body under another device's key
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(world.approve(request), signed); err != nil {
		t.Fatal(err)
	}
	signed.Signature = testSpendSignedBy(t, world.spend.phone, world.spend.keys[world.spend.otherDevice], &protocol.ApprovalDecision{}).GetSignature()
	forged, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.inbox.Receive(t.Context(), forged); err == nil {
		t.Error("a forged signature was kept")
	}
	world.log.putDecision(request.ApprovalId(), forged)
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	// a decision naming another request's bytes
	otherRequest := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("other@example.com")), nil))
	mismatched := world.approve(otherRequest)
	mismatchedSigned := &bridge.Signed{}
	if err := proto.Unmarshal(mismatched, mismatchedSigned); err != nil {
		t.Fatal(err)
	}
	body := &protocol.ApprovalDecision{}
	if err := proto.Unmarshal(mismatchedSigned.GetBody(), body); err != nil {
		t.Fatal(err)
	}
	body.ApprovalId = request.Request.GetApprovalId()
	rebound, err := proto.Marshal(testSpendSignedBy(t, world.spend.phone, world.spend.keys[world.spend.phone], body))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.inbox.Receive(t.Context(), rebound); !errors.Is(err, ErrApprovalRefused) {
		t.Errorf("a decision naming other bytes answered %v", err)
	}
	if state := world.state(request.ApprovalId()); len(state.Decisions) != 0 {
		t.Errorf("%d decisions kept", len(state.Decisions))
	}
	if got := world.status(request.ApprovalId()); got != ApprovalStatusPending {
		t.Errorf("status %s", got)
	}
	// with no state to check against, nothing is kept either
	world.args.States = nil
	if _, err := world.inbox.Receive(t.Context(), world.approve(request)); !errors.Is(err, ErrApprovalNoState) {
		t.Errorf("no state: %v", err)
	}
}

// A presence decision's signCount is the requester's to compare, durably: a second decision at the same count is
// refused, and a reopened store still holds the count.
func TestPresenceDecisionCounterStored(t *testing.T) {
	world := newTestApprovalWorld(t)
	first := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("a@example.com")), nil))
	second := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("b@example.com")), nil))
	presenceDecision := func(request *StoredApprovalRequest) []byte {
		requestSha256 := request.Sha256()
		payloadSha256 := request.Action.PayloadSha256()
		body := &protocol.ApprovalDecision{
			ApprovalId: request.Request.GetApprovalId(), RequestSha256: requestSha256[:], PayloadSha256: payloadSha256[:],
			Decision: uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE), Uses: 1,
			NotAfterMillis: request.Request.GetNotAfterMillis(), ApproverMemberId: world.spend.member.Bytes(),
			Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE),
			RequesterSidecarId: request.Request.GetRequesterSidecarId(), AuthPin: world.spend.pin, Version: 1,
		}
		stored, err := proto.Marshal(testSpendSignedByPresence(t, world.spend.presence, body))
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	if _, err := world.inbox.Receive(t.Context(), presenceDecision(first)); err != nil {
		t.Fatalf("the first presence decision: %v", err)
	}
	// the fixture's assertion reports one count, so a second decision replays it
	world.open()
	if _, err := world.inbox.Receive(t.Context(), presenceDecision(second)); !errors.Is(err, ErrPresenceCounter) {
		t.Errorf("a count regression across a reopen answered %v", err)
	}
	if got := world.status(first.ApprovalId()); got != ApprovalStatusApproved {
		t.Errorf("the first's status %s", got)
	}
}

// The status walks pending, approved, spent; a denial, a cancel and an expiry each show; an uncertain use shows until
// a retry settles it.
func TestStatusStates(t *testing.T) {
	world := newTestApprovalWorld(t)
	stored := world.mailAction("someone@example.com")
	request := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(stored), nil))
	if got := world.status(request.ApprovalId()); got != ApprovalStatusPending {
		t.Errorf("filed: %s", got)
	}
	world.log.putDecision(request.ApprovalId(), world.approve(request))
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := world.status(request.ApprovalId()); got != ApprovalStatusApproved {
		t.Errorf("approved: %s", got)
	}
	world.effect.setAnswer(errors.New("the connection dropped"))
	action := world.action(stored)
	if err := world.gate.Authorize(t.Context(), action, nil); err != nil || action.Outcome.State != ApprovalOutcomeUncertain {
		t.Fatalf("an uncertain use: %v, %+v", err, action.Outcome)
	}
	if got := world.status(request.ApprovalId()); got != ApprovalStatusUncertain {
		t.Errorf("uncertain: %s", got)
	}
	world.effect.setAnswer(nil)
	if err := world.gate.Authorize(t.Context(), world.action(stored), nil); err != nil {
		t.Fatal(err)
	}
	if got := world.status(request.ApprovalId()); got != ApprovalStatusSpent {
		t.Errorf("spent: %s", got)
	}

	denied := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("denied@example.com")), nil))
	world.log.putDecision(denied.ApprovalId(), world.decision(denied, world.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY, 0))
	cancelled := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("cancelled@example.com")), nil))
	func() {
		world.log.stateLock.Lock()
		defer world.log.stateLock.Unlock()
		world.log.approvalIdCancelled[cancelled.ApprovalId()] = true
	}()
	expired := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("expired@example.com")), nil))
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := world.status(denied.ApprovalId()); got != ApprovalStatusDenied {
		t.Errorf("denied: %s", got)
	}
	if got := world.status(cancelled.ApprovalId()); got != ApprovalStatusCancelled {
		t.Errorf("cancelled: %s", got)
	}
	world.clock.advance(defaultSidecarMcpSettings().ApprovalRequestTimeout + time.Minute)
	if got := world.status(expired.ApprovalId()); got != ApprovalStatusExpired {
		t.Errorf("expired: %s", got)
	}
}

// After each Outcome the use's approval_use entry is filed, linked by the use's action_id, with the use's index,
// hashes and state.
func TestFileUseAfterOutcome(t *testing.T) {
	world := newTestApprovalWorld(t)
	stored := world.mailAction("someone@example.com")
	request := world.approved(stored)
	if uses := world.log.useBodies(); len(uses) != 0 {
		t.Fatalf("%d uses before the spend", len(uses))
	}
	action := world.action(stored)
	if err := world.gate.Authorize(t.Context(), action, nil); err != nil {
		t.Fatal(err)
	}
	uses := world.log.useBodies()
	if len(uses) != 1 {
		t.Fatalf("%d uses", len(uses))
	}
	use := uses[0]
	actionId := stored.ActionId(request.ApprovalId())
	effectKey := ApprovalEffectKey(request.ApprovalId(), actionId)
	payloadSha256 := stored.PayloadSha256()
	if recordIdOf(use.GetApprovalId()) != request.ApprovalId() || use.GetUseIndex() != 0 || use.GetState() != 1 ||
		!bytes.Equal(use.GetEffectKey(), effectKey[:]) || !bytes.Equal(use.GetPayloadSha256(), payloadSha256[:]) ||
		!bytes.Equal(use.GetEffectRef(), action.Outcome.EffectRef) || !bytes.Equal(world.log.useActionIds[0], actionId[:]) {
		t.Errorf("the use: %+v", use)
	}
}

// No log line the requester's state writes carries an agent's summary or a preview, through a filing, a refused
// filing, a refused decision and a spend.
func TestNoSummaryOrPreviewInAnyLog(t *testing.T) {
	world := newTestApprovalWorld(t)
	world.log.refuseFile = errors.New("refused")
	stored := world.mailAction("someone@example.com")
	action := world.action(stored)
	action.Summary = "SUMMARY-TEXT-agent"
	world.pendingRequest(world.gate.Authorize(t.Context(), action, nil))
	world.log.refuseFile = nil
	request := world.pendingRequest(world.gate.Authorize(t.Context(), action, nil))
	world.log.putDecision(request.ApprovalId(), world.decision(request, world.spend.otherDevice,
		protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, 1))
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	world.log.putDecision(request.ApprovalId(), world.approve(request))
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := world.gate.Authorize(t.Context(), world.action(stored), nil); err != nil {
		t.Fatal(err)
	}
	lines := world.logger.all()
	if lines == "" {
		t.Fatal("nothing was logged, so the test proves nothing")
	}
	if strings.Contains(lines, "SUMMARY-TEXT") || strings.Contains(lines, "PREVIEW-TEXT") || strings.Contains(lines, "someone@example.com") {
		t.Errorf("a log line carries agent text or a recipient:\n%s", lines)
	}
}

// The update callbacks run for a kept decision, a cancel the log reports and a use's outcome, and a removed callback
// runs no more.
func TestUpdateCallbacksOnDecisionCancelAndUse(t *testing.T) {
	world := newTestApprovalWorld(t)
	updates := []Id{}
	var updatesLock sync.Mutex
	remove := world.inbox.AddUpdateCallback(func(approvalId Id) {
		updatesLock.Lock()
		defer updatesLock.Unlock()
		updates = append(updates, approvalId)
	})
	stored := world.mailAction("someone@example.com")
	request := world.approved(stored)
	if err := world.gate.Authorize(t.Context(), world.action(stored), nil); err != nil {
		t.Fatal(err)
	}
	cancelled := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("b@example.com")), nil))
	func() {
		world.log.stateLock.Lock()
		defer world.log.stateLock.Unlock()
		world.log.approvalIdCancelled[cancelled.ApprovalId()] = true
	}()
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	remove()
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	updatesLock.Lock()
	defer updatesLock.Unlock()
	want := []Id{request.ApprovalId(), request.ApprovalId(), cancelled.ApprovalId()}
	if !slices.Equal(updates, want) {
		t.Errorf("updates %v, want %v", updates, want)
	}
}
