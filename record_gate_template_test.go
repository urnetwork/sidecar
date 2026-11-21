//go:build !ios_extension

// Owner decision 613 (QD-1071; §16.6's multi-use row) at §16.6's gate, on the approval world: an action that asks for
// a template in its place (SidecarAction.Template, mail_send's uses) files the template's request for the uses asked,
// not its own, and answers pending with the template's id, the same call again finding it; once a person approves it,
// the action sent again and each later one that falls inside it spend its uses, one each, while a mail to a recipient
// outside the set or past the count files a request of its own and spends none; a template the action does not fall
// inside, asked for fewer than 2 uses, or asked by a template is refused with nothing filed; a denied or cancelled
// template refuses rather than filing again; in a run tainted since, the stale rule files the template afresh,
// tainted; a template presented as the action spends nothing, its decision in hand or not, and takes no standing grant;
// and an action asking 1 use or none files its own single-use request, as before.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A mail from the world's alias me to recipients, its body text: a full action, which a template may cover.
func (self *testApprovalWorld) mailTo(text string, recipients ...string) *StoredCanonicalAction {
	self.t.Helper()
	bodySha256 := sha256.Sum256([]byte(text))
	action, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionMail), Recipients: recipients, BodySha256: bodySha256[:], Alias: "me", Preview: text,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return action
}

// The template mail_send's uses builds of the world's alias and recipients (NewMailTemplateAction).
func (self *testApprovalWorld) sendTemplate(recipients ...string) *StoredCanonicalAction {
	self.t.Helper()
	template, err := NewMailTemplateAction("me", recipients)
	if err != nil {
		self.t.Fatal(err)
	}
	return template
}

// stored as an agent's mail_send hands it to the gate asking uses of template in its place.
func (self *testApprovalWorld) askingTemplate(stored *StoredCanonicalAction, template []byte, uses uint32) *SidecarAction {
	action := self.action(stored)
	action.Template = template
	action.Uses = uses
	return action
}

// The phone's approval of request for uses, kept through the inbox's intake.
func (self *testApprovalWorld) approveUses(request *StoredApprovalRequest, uses uint32) {
	self.t.Helper()
	decision := self.decision(request, self.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, uses)
	if _, err := self.inbox.Receive(self.t.Context(), decision); err != nil {
		self.t.Fatal(err)
	}
}

// A mail asking for a template files the template's request for the uses asked, in the run and agent the mail binds,
// and answers pending with its id; the same call again finds it waiting, so one request is filed and nothing runs.
func TestTemplateFiledInTheActionsPlace(t *testing.T) {
	world := newTestApprovalWorld(t)
	first := world.mailTo("the first", "a@example.com", "b@example.com")
	template := world.sendTemplate("a@example.com", "b@example.com", "c@example.com")
	request := world.pendingRequest(world.gate.Authorize(t.Context(), world.askingTemplate(first, template.Bytes, 3), nil))
	if !bytes.Equal(request.Action.Bytes, template.Bytes) || request.Request.GetUses() != 3 || request.Request.GetTainted() ||
		recordIdOf(request.Request.GetRunId()) != world.runId || recordIdOf(request.Request.GetAgentId()) != world.agentId {
		t.Fatalf("the request filed: %+v", request.Request)
	}
	again := world.pendingRequest(world.gate.Authorize(t.Context(), world.askingTemplate(first, template.Bytes, 3), nil))
	if again.ApprovalId() != request.ApprovalId() {
		t.Errorf("the call again answered %s, not the template's waiting request", again.ApprovalId())
	}
	if world.log.filedCount() != 1 {
		t.Errorf("%d requests filed", world.log.filedCount())
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("the effect ran %d times with no decision", runCount)
	}
}

// Once a person approves the template for 3 uses, the first mail sent again spends the first, and each later mail from
// the alias to a subset spends one more, asking uses again or not; a mail naming a recipient outside the set files a
// request of its own while uses remain, and one past the count does too, neither taking a use or running the effect.
func TestTemplateApprovalLetsSubsetsThroughToItsCount(t *testing.T) {
	world := newTestApprovalWorld(t)
	template := world.sendTemplate("a@example.com", "b@example.com", "c@example.com")
	first := world.mailTo("the first", "a@example.com", "b@example.com")
	request := world.pendingRequest(world.gate.Authorize(t.Context(), world.askingTemplate(first, template.Bytes, 3), nil))
	world.approveUses(request, 3)

	retried := world.askingTemplate(first, template.Bytes, 3)
	testGateExpectOutcome(t, "the first mail sent again", world.gate.Authorize(t.Context(), retried, nil), retried, ApprovalOutcomeDone)

	expectOwn := func(name string, err error) {
		t.Helper()
		own := world.pendingRequest(err)
		if own.ApprovalId() == request.ApprovalId() || own.Action.Action.GetScope() || own.Request.GetUses() != 1 {
			t.Errorf("%s answered %s, uses %d, not a single-use request of its own", name, own.ApprovalId(), own.Request.GetUses())
		}
	}
	outside := world.mailTo("the outside", "a@example.com", "mallory@example.com")
	expectOwn("a mail naming a recipient outside the set", world.gate.Authorize(t.Context(), world.action(outside), nil))
	// asking uses for it asks a template of its own set, never the approved one
	other := world.pendingRequest(world.gate.Authorize(t.Context(), world.askingTemplate(outside,
		world.sendTemplate("a@example.com", "mallory@example.com").Bytes, 3), nil))
	if other.ApprovalId() == request.ApprovalId() || !other.Action.Action.GetScope() {
		t.Errorf("the outside mail asking uses answered %s", other.ApprovalId())
	}
	if reserveCount := len(world.state(request.ApprovalId()).Reserves); reserveCount != 1 {
		t.Fatalf("%d uses reserved after the outside mails", reserveCount)
	}

	second := world.action(world.mailTo("the second", "c@example.com"))
	testGateExpectOutcome(t, "a later mail to a subset", world.gate.Authorize(t.Context(), second, nil), second, ApprovalOutcomeDone)
	third := world.askingTemplate(world.mailTo("the third", "b@example.com", "c@example.com"), template.Bytes, 3)
	testGateExpectOutcome(t, "a later mail asking uses again", world.gate.Authorize(t.Context(), third, nil), third, ApprovalOutcomeDone)
	if got := world.status(request.ApprovalId()); got != ApprovalStatusSpent {
		t.Errorf("the template's status after its 3 uses: %s", got)
	}

	expectOwn("a mail past the count", world.gate.Authorize(t.Context(), world.action(world.mailTo("the fourth", "a@example.com")), nil))
	if runCount, effectCount := world.effect.counts(); runCount != 3 || effectCount != 3 {
		t.Errorf("%d runs and %d effects for 3 uses", runCount, effectCount)
	}
	if reserveCount := len(world.state(request.ApprovalId()).Reserves); reserveCount != 3 {
		t.Errorf("%d uses reserved", reserveCount)
	}
}

// A template the action does not fall inside, one of another alias, a full action in a template's place, bytes that
// are no action, a template asked for fewer than 2 uses and a template asking a template are each refused before any
// decision is looked for, with nothing filed.
func TestTemplateTheActionDoesNotFallInsideRefused(t *testing.T) {
	world := newTestApprovalWorld(t)
	mail := world.mailTo("a mail", "a@example.com", "d@example.com")
	otherAlias, err := NewMailTemplateAction("you", []string{"a@example.com", "d@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	covering := world.sendTemplate("a@example.com", "d@example.com")
	cases := []struct {
		name     string
		action   *SidecarAction
		wantUses bool
	}{
		{name: "a set without one of its recipients", action: world.askingTemplate(mail, world.sendTemplate("a@example.com", "b@example.com").Bytes, 3)},
		{name: "another alias's template", action: world.askingTemplate(mail, otherAlias.Bytes, 3)},
		{name: "a full mail in a template's place", action: world.askingTemplate(mail, world.mailTo("another", "a@example.com").Bytes, 3)},
		{name: "bytes that are no action", action: world.askingTemplate(mail, []byte{0xff, 0x01}, 3)},
		{name: "a template asked by a template", action: world.askingTemplate(world.sendTemplate("a@example.com"), covering.Bytes, 3)},
		{name: "a template for 1 use", action: world.askingTemplate(mail, covering.Bytes, 1), wantUses: true},
		{name: "a template for no count", action: world.askingTemplate(mail, covering.Bytes, 0), wantUses: true},
	}
	for _, c := range cases {
		err := world.gate.Authorize(t.Context(), c.action, nil)
		if !errors.Is(err, ErrSidecarActionInvalid) || c.wantUses != errors.Is(err, ErrApprovalUses) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if world.log.filedCount() != 0 {
		t.Errorf("%d requests filed", world.log.filedCount())
	}
}

// A person's no on the template stops the agent asking it again: a denied template, and an approved one cancelled,
// each refuses the mail that asks it rather than filing it anew.
func TestDeniedOrCancelledTemplateRefusesAgain(t *testing.T) {
	world := newTestApprovalWorld(t)
	deniedMail := world.mailTo("a denied mail", "a@example.com")
	deniedTemplate := world.sendTemplate("a@example.com", "b@example.com")
	denied := world.pendingRequest(world.gate.Authorize(t.Context(), world.askingTemplate(deniedMail, deniedTemplate.Bytes, 2), nil))
	world.log.putDecision(denied.ApprovalId(), world.decision(denied, world.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY, 0))
	if err := world.inbox.Poll(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := world.gate.Authorize(t.Context(), world.askingTemplate(deniedMail, deniedTemplate.Bytes, 2), nil); !errors.Is(err, ErrApprovalDenied) {
		t.Errorf("a mail asking a denied template: %v", err)
	}

	cancelledMail := world.mailTo("a cancelled mail", "c@example.com")
	cancelledTemplate := world.sendTemplate("c@example.com", "d@example.com")
	cancelled := world.pendingRequest(world.gate.Authorize(t.Context(), world.askingTemplate(cancelledMail, cancelledTemplate.Bytes, 2), nil))
	world.approveUses(cancelled, 2)
	cancel, err := proto.Marshal(world.signedCancel(world.spend.phone, cancelled.ApprovalId()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.inbox.ReceiveCancel(t.Context(), cancel); err != nil {
		t.Fatal(err)
	}
	if err := world.gate.Authorize(t.Context(), world.askingTemplate(cancelledMail, cancelledTemplate.Bytes, 2), nil); !errors.Is(err, ErrApprovalCancelled) {
		t.Errorf("a mail asking a cancelled template: %v", err)
	}
	if world.log.filedCount() != 2 {
		t.Errorf("%d requests filed", world.log.filedCount())
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("the effect ran %d times", runCount)
	}
}

// TS1 with a template: a run tainted after its template was approved untainted spends nothing on it, and the mail
// asking it files the template afresh, tainted, for the same uses, whose approval then spends in the tainted run.
func TestStaleTemplateFiledAfreshTainted(t *testing.T) {
	world := newTestApprovalWorld(t)
	template := world.sendTemplate("a@example.com", "b@example.com")
	mail := world.mailTo("a mail", "a@example.com")
	clean := world.pendingRequest(world.gate.Authorize(t.Context(), world.askingTemplate(mail, template.Bytes, 2), nil))
	world.approveUses(clean, 2)
	if err := world.runs.Taint(t.Context(), world.runId, RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	fresh := world.pendingRequest(world.gate.Authorize(t.Context(), world.askingTemplate(mail, template.Bytes, 2), nil))
	if fresh.ApprovalId() == clean.ApprovalId() || !fresh.Request.GetTainted() || !bytes.Equal(fresh.Action.Bytes, template.Bytes) ||
		fresh.Request.GetUses() != 2 {
		t.Fatalf("the stale answer %s: %+v", fresh.ApprovalId(), fresh.Request)
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("the effect ran %d times on a stale decision", runCount)
	}
	world.approveUses(fresh, 2)
	action := world.askingTemplate(mail, template.Bytes, 2)
	testGateExpectOutcome(t, "the tainted template's approval", world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
}

// A template is filed, never spent: presented as the action once approved, with its decision in hand or not, it is
// refused with no use reserved and nothing run, and its uses still serve the mails inside it; with a standing grant
// that would cover anything, a template takes none and is filed.
func TestTemplatePresentedItselfSpendsNothing(t *testing.T) {
	world := newTestApprovalWorld(t)
	template := world.sendTemplate("a@example.com", "b@example.com")
	request, decision := world.approvedTemplate(template, 2)
	itself := func() *SidecarAction {
		action := world.action(template)
		action.Uses = 2
		return action
	}
	if err := world.gate.Authorize(t.Context(), itself(), nil); !errors.Is(err, ErrApprovalTemplateUse) {
		t.Errorf("the approved template itself: %v", err)
	}
	if err := world.gate.Authorize(t.Context(), itself(), testGateSigned(t, decision)); !errors.Is(err, ErrApprovalTemplateUse) {
		t.Errorf("the approved template itself, its decision in hand: %v", err)
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("the effect ran %d times", runCount)
	}
	if reserveCount := len(world.state(request.ApprovalId()).Reserves); reserveCount != 0 {
		t.Errorf("%d uses reserved by the template itself", reserveCount)
	}
	for _, recipient := range []string{"a@example.com", "b@example.com"} {
		action := world.action(world.mailAction(recipient))
		testGateExpectOutcome(t, recipient, world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
	}

	world.grants.covers = true
	other := world.sendTemplate("c@example.com", "d@example.com")
	asking := world.action(other)
	asking.Uses = 2
	if filed := world.pendingRequest(world.gate.Authorize(t.Context(), asking, nil)); !bytes.Equal(filed.Action.Bytes, other.Bytes) {
		t.Error("a template under a standing grant was not filed")
	}
	if runCount, _ := world.effect.counts(); runCount != 2 {
		t.Errorf("%d runs: a standing grant passed a template", runCount)
	}
}

// A mail asking 1 use, or none, files its own request for its one use, as before mail_send's uses: no template.
func TestOneUseOrNoneFilesTheMailAlone(t *testing.T) {
	world := newTestApprovalWorld(t)
	for _, uses := range []uint32{0, 1} {
		mail := world.mailTo(fmt.Sprintf("a mail asking %d", uses), "a@example.com", "b@example.com")
		action := world.action(mail)
		action.Uses = uses
		request := world.pendingRequest(world.gate.Authorize(t.Context(), action, nil))
		if !bytes.Equal(request.Action.Bytes, mail.Bytes) || request.Action.Action.GetScope() || request.Request.GetUses() != 1 {
			t.Errorf("uses %d filed %+v", uses, request.Request)
		}
	}
	if world.log.filedCount() != 2 {
		t.Errorf("%d requests filed", world.log.filedCount())
	}
}
