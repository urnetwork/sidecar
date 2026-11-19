//go:build !sidecar_http && !js && !ios_extension

// MAIL-M9-01's approved recipients (owner decision 280, QD-1094) on the spend test network and the send world: a record
// written by a done use on a device decision approves its pair at the next use under P, and the send then goes with no
// gate; a record a harness decision made, one whose signer is no longer approval-capable, one over another action or
// another pair, and any record in a tainted run approve nothing; a removed record approves nothing.

package sidecar

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A mail_send action from alias to recipients, as the gate stores it.
func testMailApprovedAction(t *testing.T, alias string, recipients ...string) *StoredCanonicalAction {
	t.Helper()
	action, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind:       uint32(SidecarActionMail),
		Recipients: recipients,
		BodySha256: make([]byte, 32),
		Preview:    "Subject: x\n\ny",
		Alias:      alias,
	})
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// A decision on channel by signer, the approver member, over action, at the net's tip pin, its Signed as stored.
func testMailApprovedDecision(t *testing.T, net *testSpendNet, signer testConfigDevice, approver Id, channel protocol.ApprovalChannel, action *StoredCanonicalAction, requester Id) []byte {
	t.Helper()
	pin := net.spendState(false).Pin()
	body := testSpendDecisionBody(action, NewId(), approver, channel, requester, pin, net.timeMs+60_000)
	signed := testSpendSignedBy(t, signer.sidecarId, signer.key, body)
	return testConfigMarshal(t, signed)
}

// A device decision's record approves its pair under P, for any device of the member, its decision's not_after past;
// another pair's, a harness decision's, a record over another action and one whose signer is gone approve nothing.
func TestMailApprovedRecipientRecordVerifiesUnderP(t *testing.T) {
	net := newTestSpendNet(t)
	alias, recipient := "ann@acme.root.example", "someone@outside.example"
	action := testMailApprovedAction(t, alias, recipient, "other@outside.example")
	decision := testMailApprovedDecision(t, net, net.phone, net.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, action, net.laptop.sidecarId)
	record := &protocol.MailRecipientApproval{Alias: alias, Recipient: recipient, Decision: decision, Action: action.Bytes}
	state := net.spendState(false)
	later := time.UnixMilli(net.timeMs).Add(30 * 24 * time.Hour)
	if err := mailRecipientApprovalVerify(record, alias, recipient, state, net.laptop.sidecarId, later); err != nil {
		t.Fatalf("a device decision's record: %v", err)
	}
	// another of the member's devices reads it the same
	if err := mailRecipientApprovalVerify(record, alias, recipient, state, net.phone.sidecarId, later); err != nil {
		t.Fatalf("read by another device: %v", err)
	}
	if err := mailRecipientApprovalVerify(record, alias, "third@outside.example", state, net.laptop.sidecarId, later); err == nil {
		t.Fatal("a record approved another recipient")
	}
	if err := mailRecipientApprovalVerify(record, "bo@acme.root.example", recipient, state, net.laptop.sidecarId, later); err == nil {
		t.Fatal("a record approved another alias")
	}
	harness := &protocol.MailRecipientApproval{Alias: alias, Recipient: recipient, Action: action.Bytes,
		Decision: testMailApprovedDecision(t, net, net.laptop, net.member, protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS, action, net.laptop.sidecarId)}
	if err := mailRecipientApprovalVerify(harness, alias, recipient, state, net.laptop.sidecarId, later); err == nil {
		t.Fatal("a harness decision's record approved")
	}
	other := testMailApprovedAction(t, alias, recipient)
	swapped := &protocol.MailRecipientApproval{Alias: alias, Recipient: recipient, Decision: decision, Action: other.Bytes}
	if err := mailRecipientApprovalVerify(swapped, alias, recipient, state, net.laptop.sidecarId, later); err == nil {
		t.Fatal("a decision approved an action it was not over")
	}
	forged := &protocol.MailRecipientApproval{Alias: alias, Recipient: recipient, Action: action.Bytes,
		Decision: testConfigMarshal(t, &bridge.Signed{Body: []byte("not a decision"), SignerId: net.phone.sidecarId.Bytes()})}
	if err := mailRecipientApprovalVerify(forged, alias, recipient, state, net.laptop.sidecarId, later); err == nil {
		t.Fatal("a forged decision approved")
	}
}

// A record a done use wrote spares the next send to its pair the gate; a tainted run's send ignores it; a removed one
// approves nothing.
func TestMailApprovedRecipientSparesTheGate(t *testing.T) {
	world, _, _ := newMailSendTestWorld(t)
	ctx := context.Background()
	recipient := "someone@outside.example"
	approved := world.client.ApprovedRecipients()
	accepting := &testMailApprovedState{}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	copied := *binding
	copied.SpendState = func() (SpendState, error) { return accepting, nil }
	tainted := testMailId(0x7c)
	copied.RunTainted = func(runId Id) bool { return runId == tainted }
	world.client.Bind(&copied)

	if approved.ApprovedAll(ctx, testMailSendFrom, []string{recipient}) {
		t.Fatal("a pair with no record approved")
	}
	action := testMailApprovedAction(t, testMailSendFrom, recipient)
	decision := accepting.decision(t, action)
	approved.Record(ctx, testMailSendFrom, []string{recipient}, [][]byte{decision}, action.Bytes)
	if !approved.ApprovedAll(ctx, testMailSendFrom, []string{recipient}) {
		t.Fatal("a written record does not approve its pair")
	}

	testMailSubmitHold(world.gate, true)
	actionsBefore, _ := world.gate.counts()
	result, err := world.client.Send(ctx, &MailSendArgs{From: testMailSendFrom, To: []string{recipient}, Text: "x"})
	if err != nil || result.Recipients[0].Outcome != MailSendQueued {
		t.Fatalf("an approved recipient's send %+v: %v", result, err)
	}
	if actionsAfter, _ := world.gate.counts(); actionsAfter != actionsBefore {
		t.Fatal("an approved recipient's send asked the gate")
	}
	if _, err := world.client.Send(ctx, &MailSendArgs{From: testMailSendFrom, To: []string{recipient}, Text: "x", Action: MailConfigActionArgs{RunId: &tainted}}); err == nil {
		t.Fatal("a tainted run's send went on a record")
	}
	if err := approved.Remove(ctx, testMailSendFrom, recipient); err != nil {
		t.Fatal(err)
	}
	if approved.ApprovedAll(ctx, testMailSendFrom, []string{recipient}) {
		t.Fatal("a removed record approves")
	}
}

// A SpendState in which one device of the test's, its key the state's, signs approvals any rule takes.
type testMailApprovedState struct {
	signer *testMailOutboxSigner
}

// A device decision by the state's signer over action, as stored.
func (self *testMailApprovedState) decision(t *testing.T, action *StoredCanonicalAction) []byte {
	t.Helper()
	if self.signer == nil {
		self.signer = newTestMailOutboxSigner(testMailId(0x5e))
	}
	body := testSpendDecisionBody(action, NewId(), testMailId(0x5f), protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, testMailId(0x60), self.Pin(), 1)
	signed, err := self.signer.sign(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, testConfigMarshal(t, body))
	if err != nil {
		t.Fatal(err)
	}
	return testConfigMarshal(t, signed)
}

func (self *testMailApprovedState) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: 7, Chain: make([]byte, 32)}
}

func (self *testMailApprovedState) ChainAt(version uint64) ([32]byte, bool) {
	return [32]byte{}, true
}

func (self *testMailApprovedState) Forked() bool {
	return false
}

func (self *testMailApprovedState) IdentityKey(sidecarId Id) []byte {
	if self.signer != nil && sidecarId == self.signer.sidecarId {
		return self.signer.publicKey()
	}
	return nil
}

func (self *testMailApprovedState) ApprovalCapable(sidecarId Id, memberId Id) bool {
	return self.signer != nil && sidecarId == self.signer.sidecarId
}

func (self *testMailApprovedState) PresenceKey(keyId []byte, memberId Id) *bridge.KeyRow {
	return nil
}

func (self *testMailApprovedState) Govern(action *StoredCanonicalAction, spender Id, now time.Time) (SpendRule, error) {
	return testMailApprovedRule{}, nil
}

// A rule that names every approver and takes every channel.
type testMailApprovedRule struct{}

func (self testMailApprovedRule) Evidence() []protocol.ApprovalChannel {
	return spendAllChannels
}

func (self testMailApprovedRule) ApproverCount() int {
	return 1
}

func (self testMailApprovedRule) Names(memberId Id) bool {
	return true
}

func (self testMailApprovedRule) ClauseAdmin(memberId Id) bool {
	return false
}

func (self testMailApprovedRule) AdminClauseMet(memberIds []Id) bool {
	return true
}

// A gate that passes every action and runs its effect under a spend of one decision, as Authorize does once a person's
// device decision passed it.
type testMailApprovedGate struct {
	decision []byte
}

func (self *testMailApprovedGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	spent := withApprovalSpend(ctx, &ApprovalSpend{ApprovalId: NewId(), Decisions: [][]byte{self.decision}, Action: action.Canonical})
	effectRef, err := action.Effect.Run(spent, mailConfigTestEffectKey(action.Canonical))
	if err != nil {
		action.Outcome = &SidecarOutcome{State: ApprovalOutcomeNotDone, Err: err}
		return nil
	}
	action.Outcome = &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: effectRef}
	return nil
}

func (self *testMailApprovedGate) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func() {
	return func() {}
}

// A send the gate passed on a device decision records its queued recipients, so the next send to them is W.
func TestMailApprovedRecipientRecordedByAGatedSend(t *testing.T) {
	world, _, _ := newMailSendTestWorld(t)
	ctx := context.Background()
	recipient := "someone@outside.example"
	draft := &MailSendArgs{From: testMailSendFrom, To: []string{recipient}, Subject: "Plans", Text: "Dinner at eight."}
	plan, err := world.client.planSend(draft)
	if err != nil {
		t.Fatal(err)
	}
	action, err := mailSendAction(draft, plan, DefaultMailSendSettings())
	if err != nil {
		t.Fatal(err)
	}
	accepting := &testMailApprovedState{}
	gate := &testMailApprovedGate{decision: accepting.decision(t, action)}
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	copied := *binding
	copied.Gate = gate
	copied.SpendState = func() (SpendState, error) { return accepting, nil }
	world.client.Bind(&copied)

	if world.client.ApprovedRecipients().ApprovedAll(ctx, testMailSendFrom, []string{recipient}) {
		t.Fatal("approved before any send")
	}
	result, err := world.client.Send(ctx, draft)
	if err != nil || result.Recipients[0].Outcome != MailSendQueued {
		t.Fatalf("the gated send %+v: %v", result, err)
	}
	if !world.client.ApprovedRecipients().ApprovedAll(ctx, testMailSendFrom, []string{recipient}) {
		t.Fatal("the gated send recorded no approval")
	}
}
