//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The requester's approvals as a test steers them: one approval's status, the decisions kept, and the callbacks a
// decision wakes.
type harnessTestApprovals struct {
	stateLock  sync.Mutex
	idStatuses map[Id]*ApprovalStatus
	callbacks  map[int]ApprovalUpdateFunction
	nextId     int
}

func newHarnessTestApprovals() *harnessTestApprovals {
	return &harnessTestApprovals{idStatuses: map[Id]*ApprovalStatus{}, callbacks: map[int]ApprovalUpdateFunction{}}
}

func (self *harnessTestApprovals) AddUpdateCallback(callback ApprovalUpdateFunction) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	id := self.nextId
	self.nextId += 1
	self.callbacks[id] = callback
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.callbacks, id)
	}
}

func (self *harnessTestApprovals) Status(approvalId Id) (*ApprovalStatus, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status, ok := self.idStatuses[approvalId]
	if !ok {
		return nil, ErrApprovalUnknown
	}
	copied := *status
	copied.Channels = slices.Clone(status.Channels)
	return &copied, nil
}

func (self *harnessTestApprovals) Render(approvalId Id) (*ApprovalRender, error) {
	return &ApprovalRender{ApprovalId: approvalId, Kind: SidecarActionAliasCreate, KindName: "alias_create",
		Fields: []*ApprovalRenderField{{Name: "alias", Value: "ada"}}}, nil
}

// Files the request a gate waits on.
func (self *harnessTestApprovals) file(approvalId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.idStatuses[approvalId]; !ok {
		self.idStatuses[approvalId] = &ApprovalStatus{ApprovalId: approvalId, State: ApprovalStatusPending}
	}
}

// Keeps a decision on channel, or a denial, and wakes the callbacks as the inbox does.
func (self *harnessTestApprovals) decide(approvalId Id, channel protocol.ApprovalChannel, state ApprovalStatusState) {
	callbacks := func() []ApprovalUpdateFunction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		status := self.idStatuses[approvalId]
		status.State = state
		if state == ApprovalStatusApproved {
			status.Channels = append(status.Channels, channel)
			status.Uses = 1
		}
		callbacks := []ApprovalUpdateFunction{}
		for _, callback := range self.callbacks {
			callbacks = append(callbacks, callback)
		}
		return callbacks
	}()
	for _, callback := range callbacks {
		callback(approvalId)
	}
}

// §16.6's gate as a test models it: an action passes once a decision it counts is kept, its use reserved and its
// effect run here; until then it answers pending with one approval id. A tainted run's decision counts only from a
// device or a presence key (I-9), any other run's from any channel.
type harnessTestGate struct {
	stateLock     sync.Mutex
	approvals     *harnessTestApprovals
	runs          *RunStore
	approvalId    Id
	presentations int
	reserves      int
	// signaled after each presentation
	presented chan struct{}
}

func (self *harnessTestGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	if decision != nil {
		return errors.New("the run presented a decision of its own")
	}
	self.stateLock.Lock()
	self.presentations += 1
	approvalId := self.approvalId
	self.stateLock.Unlock()
	self.approvals.file(approvalId)
	status, _ := self.approvals.Status(approvalId)
	tainted := action.RunId != nil && self.runs.Tainted(*action.RunId)
	counted := slices.ContainsFunc(status.Channels, func(channel protocol.ApprovalChannel) bool {
		if tainted {
			return channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE || channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE
		}
		return true
	})
	defer func() {
		if self.presented != nil {
			self.presented <- struct{}{}
		}
	}()
	if status.State != ApprovalStatusApproved || !counted {
		return &ApprovalPendingError{ApprovalId: approvalId}
	}
	// the use is reserved before the effect runs
	self.stateLock.Lock()
	self.reserves += 1
	self.stateLock.Unlock()
	effectRef, err := action.Effect.Run(ctx, []byte("effect-key"))
	if err != nil {
		return err
	}
	action.Outcome = &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: effectRef}
	return nil
}

func (self *harnessTestGate) counts() (int, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.presentations, self.reserves
}

// An effect that counts its runs.
type harnessTestEffect struct {
	stateLock sync.Mutex
	runs      int
}

func (self *harnessTestEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.runs += 1
	return []byte("done"), nil
}

func (self *harnessTestEffect) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.runs
}

// A world for one run's outward actions.
type harnessApprovalWorld struct {
	runs      *RunStore
	approvals *harnessTestApprovals
	gate      *harnessTestGate
	effect    *harnessTestEffect
	emitter   *harnessUiTestEmitter
	run       *HarnessRun
}

func newHarnessApprovalWorld(t *testing.T, verdicts HarnessAutoVerdicts) *harnessApprovalWorld {
	t.Helper()
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	approvals := newHarnessTestApprovals()
	world := &harnessApprovalWorld{
		runs:      runs,
		approvals: approvals,
		gate:      &harnessTestGate{approvals: approvals, runs: runs, approvalId: NewId(), presented: make(chan struct{}, 64)},
		effect:    &harnessTestEffect{},
		emitter:   newHarnessUiTestEmitter(),
	}
	world.run = newHarnessTestRun(t, runs, &HarnessRunArgs{Gate: world.gate, Approvals: approvals, Emit: world.emitter.emit,
		AutoVerdicts: verdicts})
	return world
}

// An alias_create action's request, its effect counted.
func (self *harnessApprovalWorld) request(t *testing.T) *HarnessAuthorizeRequest {
	t.Helper()
	stored, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionAliasCreate), Alias: "ada"})
	if err != nil {
		t.Fatal(err)
	}
	return &HarnessAuthorizeRequest{Kind: SidecarActionAliasCreate, Action: stored, PolicyRisk: SidecarRiskNormal,
		AgentAskedRisk: SidecarRiskNormal, Summary: "make the alias", Effect: self.effect}
}

// Runs Authorize on its own goroutine.
func (self *harnessApprovalWorld) authorizeAsync(t *testing.T) chan error {
	request := self.request(t)
	done := make(chan error, 1)
	go func() {
		_, err := self.run.Authorize(context.Background(), request)
		done <- err
	}()
	return done
}

// Waits until the gate has seen count presentations.
func (self *harnessApprovalWorld) awaitPresentations(t *testing.T, count int) {
	t.Helper()
	guard := time.After(10 * time.Second)
	for {
		if presentations, _ := self.gate.counts(); count <= presentations {
			return
		}
		select {
		case <-self.gate.presented:
		case <-guard:
			t.Fatalf("the gate never saw %d presentations", count)
		}
	}
}

// An O action waits on approval_pending with no polling, wakes at the decision, presents the action to the gate again
// so its use is reserved before the effect runs, and emits approval_resolved; the effect runs once.
func TestHarnessAuthorizeWaitsForDecisionThenReserves(t *testing.T) {
	world := newHarnessApprovalWorld(t, nil)
	done := world.authorizeAsync(t)
	pending := world.emitter.next(t)
	if pending.Type != HarnessEventApprovalPending {
		t.Fatalf("emitted %s", pending.Type)
	}
	text := ""
	pending.Decode("text", &text)
	if !strings.Contains(text, "alias_create") || !strings.Contains(text, "alias: ada") {
		t.Fatalf("approval_pending's text: %q", text)
	}
	evidence := []string{}
	pending.Decode("evidence", &evidence)
	if !slices.Equal(evidence, []string{"device", "presence", "harness"}) {
		t.Fatalf("an untainted run's evidence: %v", evidence)
	}
	if world.effect.count() != 0 {
		t.Fatal("the effect ran before a decision")
	}
	select {
	case err := <-done:
		t.Fatalf("Authorize returned %v before a decision", err)
	default:
	}
	world.approvals.decide(world.gate.approvalId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, ApprovalStatusApproved)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Authorize did not return after the decision")
	}
	if presentations, reserves := world.gate.counts(); presentations != 2 || reserves != 1 || world.effect.count() != 1 {
		t.Fatalf("%d presentations, %d reserves, %d effects", presentations, reserves, world.effect.count())
	}
	resolved := world.emitter.next(t)
	channels := []string{}
	resolved.Decode("channels", &channels)
	if resolved.Type != HarnessEventApprovalResolved || !slices.Equal(channels, []string{"device"}) || resolved.Field("auto") != nil {
		t.Fatalf("resolved: %s %v", resolved.Type, channels)
	}

	// a denial refuses the action and runs nothing
	denied := newHarnessApprovalWorld(t, nil)
	deniedDone := denied.authorizeAsync(t)
	denied.emitter.next(t)
	denied.approvals.decide(denied.gate.approvalId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, ApprovalStatusDenied)
	if err := <-deniedDone; !errors.Is(err, ErrHarnessApprovalRefused) || denied.effect.count() != 0 {
		t.Fatalf("a denial: %v, %d effects", err, denied.effect.count())
	}
}

// The safety classifier's automatic decision, channel auto, shows as the note with its verdict, never as the person's
// approval.
func TestHarnessAutomaticDecisionShownAsNote(t *testing.T) {
	score := 0.03
	world := newHarnessApprovalWorld(t, harnessTestVerdicts{verdict: &HarnessAutoVerdict{Reason: "nothing_injected", Score: &score}})
	done := world.authorizeAsync(t)
	world.emitter.next(t)
	world.approvals.decide(world.gate.approvalId, protocol.ApprovalChannel_APPROVAL_CHANNEL_AUTO, ApprovalStatusApproved)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	resolved := world.emitter.next(t)
	note := ""
	resolved.Decode("note", &note)
	verdict := &HarnessAutoVerdict{}
	if !resolved.Decode("auto", verdict) || verdict.Reason != "nothing_injected" || note != HarnessAutomaticDecisionNote {
		t.Fatalf("an automatic decision showed %s", harnessEventJson(t, resolved))
	}
	channels := []string{}
	resolved.Decode("channels", &channels)
	if slices.Contains(channels, "device") || slices.Contains(channels, "presence") || slices.Contains(channels, "harness") {
		t.Fatalf("an automatic decision showed as a person's: %v", channels)
	}
}

// SAFE's verdict, as a test fixes it.
type harnessTestVerdicts struct {
	verdict *HarnessAutoVerdict
}

func (self harnessTestVerdicts) Verdict(approvalId Id) (*HarnessAutoVerdict, error) {
	return self.verdict, nil
}

// A tainted run's outward action waits for a person on another approval-capable device or a presence key (I-9): a
// harness prompt's decision is presented to the gate again and counts for nothing, and the action passes only at a
// device's decision, its effect once.
func TestHarnessTaintedSendWaitsForPerson(t *testing.T) {
	world := newHarnessApprovalWorld(t, nil)
	if err := world.run.Taint(context.Background(), RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	done := world.authorizeAsync(t)
	pending := world.emitter.next(t)
	evidence := []string{}
	pending.Decode("evidence", &evidence)
	if !slices.Equal(evidence, []string{"device", "presence"}) {
		t.Fatalf("a tainted run's evidence: %v", evidence)
	}
	world.approvals.decide(world.gate.approvalId, protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS, ApprovalStatusApproved)
	world.awaitPresentations(t, 2)
	select {
	case err := <-done:
		t.Fatalf("a harness prompt passed a tainted run's action: %v", err)
	default:
	}
	if world.effect.count() != 0 {
		t.Fatal("the effect ran on a harness prompt in a tainted run")
	}
	world.approvals.decide(world.gate.approvalId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, ApprovalStatusApproved)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a device's decision did not pass the action")
	}
	if presentations, reserves := world.gate.counts(); presentations != 3 || reserves != 1 || world.effect.count() != 1 {
		t.Fatalf("%d presentations, %d reserves, %d effects", presentations, reserves, world.effect.count())
	}
}

// With no gate every action is refused, and an action the gate holds for a person with no approvals wired is refused
// rather than left waiting; a request whose kind is not its action's is refused before the gate.
func TestHarnessAuthorizeFailsClosed(t *testing.T) {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	world := &harnessApprovalWorld{effect: &harnessTestEffect{}}
	ungated := newHarnessTestRun(t, runs, nil)
	if _, err := ungated.Authorize(context.Background(), world.request(t)); !errors.Is(err, ErrSidecarGateDenied) {
		t.Fatalf("no gate: %v", err)
	}
	gate := &harnessTestGate{approvals: newHarnessTestApprovals(), runs: runs, approvalId: NewId()}
	unwaited := newHarnessTestRun(t, runs, &HarnessRunArgs{Gate: gate})
	if _, err := unwaited.Authorize(context.Background(), world.request(t)); !errors.Is(err, ErrHarnessApprovalUnavailable) {
		t.Fatalf("no approvals: %v", err)
	}
	request := world.request(t)
	request.Kind = SidecarActionTaintedSend
	if _, err := unwaited.Authorize(context.Background(), request); !errors.Is(err, ErrSidecarActionInvalid) {
		t.Fatalf("a kind that is not its action's: %v", err)
	}
	if world.effect.count() != 0 {
		t.Fatal("a refused action ran its effect")
	}
}
