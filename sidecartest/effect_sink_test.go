// EffectSink through §16.6's real gate, built from the root's exported API alone, as an O tool's test builds it: one
// effect per use however often the action comes, the spend on the effect's context, and a restart's reconcile finding
// what a killed process did.

package sidecartest

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The approval family's log in memory, decisions put by the test.
type sinkTestLog struct {
	stateLock           sync.Mutex
	approvalIdDecisions map[sidecar.Id]*sidecar.StoredApprovalDecision
	uses                int
}

func (self *sinkTestLog) FileRequest(request *sidecar.StoredApprovalRequest) (*sidecar.RecordEntryRef, error) {
	return &sidecar.RecordEntryRef{LogId: sidecar.NewId(), EntryId: sidecar.NewId()}, nil
}

func (self *sinkTestLog) Decision(ctx context.Context, approvalId sidecar.Id) (*sidecar.StoredApprovalDecision, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if decision, ok := self.approvalIdDecisions[approvalId]; ok {
		return decision, nil
	}
	return nil, sidecar.ErrRecordApprovalPending
}

func (self *sinkTestLog) Cancel(ctx context.Context, approvalId sidecar.Id) ([]byte, error) {
	return nil, sidecar.ErrRecordApprovalPending
}

func (self *sinkTestLog) FileUse(use *protocol.ApprovalUseBody, runId *sidecar.Id, actionId []byte) (*sidecar.RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.uses += 1
	return &sidecar.RecordEntryRef{}, nil
}

// One member approving from one device, the requester another of the member's, at one pin.
type sinkTestStates struct {
	member, phone, laptop sidecar.Id
	phoneKey              ed25519.PublicKey
	pin                   *bridge.AuthPin
}

func (self *sinkTestStates) Pin() *bridge.AuthPin { return self.pin }
func (self *sinkTestStates) ChainAt(version uint64) ([sha256.Size]byte, bool) {
	if version != self.pin.GetVersion() {
		return [sha256.Size]byte{}, false
	}
	return [sha256.Size]byte(self.pin.GetChain()), true
}
func (self *sinkTestStates) Forked() bool { return false }
func (self *sinkTestStates) IdentityKey(sidecarId sidecar.Id) []byte {
	if sidecarId == self.phone {
		return self.phoneKey
	}
	return nil
}
func (self *sinkTestStates) ApprovalCapable(sidecarId sidecar.Id, memberId sidecar.Id) bool {
	return sidecarId == self.phone && memberId == self.member
}
func (self *sinkTestStates) PresenceKey(keyId []byte, memberId sidecar.Id) *bridge.KeyRow { return nil }
func (self *sinkTestStates) Govern(action *sidecar.StoredCanonicalAction, spender sidecar.Id, now time.Time) (sidecar.SpendRule, error) {
	return &sinkTestRule{member: self.member}, nil
}
func (self *sinkTestStates) Approvers(action *sidecar.StoredCanonicalAction, requester sidecar.Id, now time.Time) ([]sidecar.Id, error) {
	return []sidecar.Id{self.member}, nil
}
func (self *sinkTestStates) RuleNamesHarness(action *sidecar.StoredCanonicalAction) bool {
	return false
}

// The member alone approves, on any channel.
type sinkTestRule struct {
	member sidecar.Id
}

func (self *sinkTestRule) Evidence() ([]protocol.ApprovalChannel, bool) {
	return []protocol.ApprovalChannel{protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE}, true
}
func (self *sinkTestRule) ApproverCount() int                         { return 1 }
func (self *sinkTestRule) Eligible(memberId sidecar.Id) bool          { return memberId == self.member }
func (self *sinkTestRule) AdminClauseMet(memberIds []sidecar.Id) bool { return true }

// No run is tainted.
type sinkTestRuns struct{}

func (self sinkTestRuns) RunTainted(runId sidecar.Id) bool { return false }

func TestEffectSinkThroughTheGate(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	store := NewFakeStore().Root()
	settings := sidecar.DefaultSidecarSettings().Mcp
	ledger, err := sidecar.NewApprovalLedger(store, settings, clock)
	if err != nil {
		t.Fatal(err)
	}
	phonePublic, phoneKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	chain := sha256.Sum256([]byte("sink test chain"))
	states := &sinkTestStates{
		member: sidecar.NewId(), phone: sidecar.NewId(), laptop: sidecar.NewId(), phoneKey: phonePublic,
		pin: &bridge.AuthPin{Version: 1, Chain: chain[:]},
	}
	log := &sinkTestLog{approvalIdDecisions: map[sidecar.Id]*sidecar.StoredApprovalDecision{}}
	args := &sidecar.ApprovalArgs{
		SidecarId: states.laptop,
		Ledger:    ledger,
		Approvals: log,
		Runs:      sinkTestRuns{},
		States:    func() (sidecar.ApprovalStates, error) { return states, nil },
		Counter:   NewFakePresenceCounter(),
		Clock:     clock,
		Settings:  settings,
	}
	sink := NewEffectSink()
	open := func() *sidecar.ApprovalGate {
		inbox, err := sidecar.NewApprovalInbox(args)
		if err != nil {
			t.Fatal(err)
		}
		router, err := sidecar.NewApprovalRouter(args, inbox)
		if err != nil {
			t.Fatal(err)
		}
		gate, err := sidecar.NewApprovalGate(args, inbox, router, &sidecar.ApprovalGateArgs{
			Lookups: func(kind sidecar.SidecarActionKind) sidecar.SidecarEffectLookup { return sink.Lookup },
		})
		if err != nil {
			t.Fatal(err)
		}
		return gate
	}
	gate := open()
	newAction := func(value string) *sidecar.SidecarAction {
		stored, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
			Kind: uint32(sidecar.SidecarActionDnsSet), DnsName: "www", DnsType: "A", DnsValue: value, DnsTtl: 300,
		})
		if err != nil {
			t.Fatal(err)
		}
		return &sidecar.SidecarAction{Kind: sidecar.SidecarActionDnsSet, Canonical: stored.Bytes, Risk: sidecar.SidecarRiskNormal, Effect: sink}
	}
	approve := func(action *sidecar.SidecarAction) sidecar.Id {
		err := gate.Authorize(t.Context(), action, nil)
		pending := &sidecar.ApprovalPendingError{}
		if !errors.As(err, &pending) {
			t.Fatalf("not pending: %v", err)
		}
		state, err := ledger.State(pending.ApprovalId)
		if err != nil {
			t.Fatal(err)
		}
		request, err := sidecar.ParseStoredApprovalRequest(state.Request)
		if err != nil {
			t.Fatal(err)
		}
		requestSha256 := request.Sha256()
		payloadSha256 := request.Action.PayloadSha256()
		body, err := proto.Marshal(&protocol.ApprovalDecision{
			ApprovalId: request.Request.GetApprovalId(), RequestSha256: requestSha256[:], PayloadSha256: payloadSha256[:],
			Decision: uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE), Uses: 1,
			NotAfterMillis: request.Request.GetNotAfterMillis(), ApproverMemberId: states.member.Bytes(),
			Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
			RequesterSidecarId: states.laptop.Bytes(), AuthPin: states.pin, Version: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		signed := &bridge.Signed{
			Body: body, SignerId: states.phone.Bytes(), Type: uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
			Signature: ed25519.Sign(phoneKey, bridge.SignedBytes(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body)),
		}
		decision, err := sidecar.ParseSignedApprovalDecision(signed)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			log.stateLock.Lock()
			defer log.stateLock.Unlock()
			log.approvalIdDecisions[pending.ApprovalId] = decision
		}()
		if err := gate.Inbox().Poll(t.Context()); err != nil {
			t.Fatal(err)
		}
		return pending.ApprovalId
	}

	first := newAction("192.0.2.1")
	approvalId := approve(first)
	for range 3 {
		action := newAction("192.0.2.1")
		if err := gate.Authorize(t.Context(), action, nil); err != nil || action.Outcome.State != sidecar.ApprovalOutcomeDone {
			t.Fatalf("a use: %v, %+v", err, action.Outcome)
		}
	}
	if sink.EffectCount() != 1 || sink.RunCount() != 1 {
		t.Errorf("%d effects in %d runs for one use", sink.EffectCount(), sink.RunCount())
	}
	if spends := sink.Spends(); len(spends) != 1 || spends[0].ApprovalId != approvalId || len(spends[0].Decisions) != 1 {
		t.Errorf("the spend on the effect's context: %+v", spends)
	}

	// a process killed after its effect and before the Outcome: the restart's reconcile finds the effect
	second := newAction("192.0.2.2")
	secondApprovalId := approve(second)
	stored, err := sidecar.ParseStoredCanonicalAction(second.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	actionId := stored.ActionId(secondApprovalId)
	effectKey := sidecar.ApprovalEffectKey(secondApprovalId, actionId)
	payloadSha256 := stored.PayloadSha256()
	func() {
		hold := ledger.Hold(secondApprovalId)
		defer hold.Release()
		if _, _, err := hold.ReserveUse(stored.Bytes, actionId[:], payloadSha256[:], effectKey[:], 1); err != nil {
			t.Fatal(err)
		}
	}()
	sink.DoneUnder(effectKey[:])
	gate = open()
	if recordedCount, err := gate.Reconcile(t.Context()); err != nil || recordedCount != 1 {
		t.Fatalf("reconcile recorded %d, %v", recordedCount, err)
	}
	state, err := ledger.State(secondApprovalId)
	if err != nil {
		t.Fatal(err)
	}
	if outcome := state.Outcome(actionId[:]); outcome == nil || outcome.State != sidecar.ApprovalOutcomeDone {
		t.Errorf("reconciled %+v", outcome)
	}
	if sink.EffectCount() != 2 {
		t.Errorf("%d effects", sink.EffectCount())
	}
}
