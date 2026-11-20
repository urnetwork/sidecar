//go:build !sidecar_http && !js && !ios_extension

// mail_send's uses (owner decision 613, QD-1071) through MailClient.Send on MAIL-M7-18's send world, its client bound
// to the approval world's real gate: a send to outside recipients asking 3 uses files a template of its From and every
// recipient, Bcc included, lowercase, with no body hash or preview, and answers pending with the template's id, nothing
// kept, deposited or queued; once a person approves it, the first draft sent again and each later one from the same
// From to a subset are queued, one use each, while a draft naming a recipient outside the set, or one past the count,
// files a single-use request of its own and sends nothing. A draft asking 1 use or none files the mail alone; uses
// asked with no run is refused before anything is planned; and a send to members alone, W, goes at once, asking for
// nothing.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The approval world's gate as a mail client binds one: its Authorize the world's, the client's Lookup the world's
// for its kind.
type testMailTemplateGate struct {
	world *testApprovalWorld
}

func (self *testMailTemplateGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	return self.world.gate.Authorize(ctx, action, decision)
}

func (self *testMailTemplateGate) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func() {
	self.world.lookups[kind] = lookup
	return func() {}
}

// The send world, its client bound to a fresh approval world's gate in place of its test gate.
func newTestMailTemplateWorld(t *testing.T) (*mailClientTestWorld, *testApprovalWorld) {
	t.Helper()
	world, _, _ := newMailSendTestWorld(t)
	approvals := newTestApprovalWorld(t)
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	copied := *binding
	copied.Gate = &testMailTemplateGate{world: approvals}
	world.client.Bind(&copied)
	return world, approvals
}

// A draft of the approval world's agent in its run, asking uses, from the world's From to the recipients given.
func testMailTemplateDraft(approvals *testApprovalWorld, uses uint32, subject string, to ...string) *MailSendArgs {
	runId, agentId := approvals.runId, approvals.agentId
	return &MailSendArgs{
		From:    testMailSendFrom,
		To:      to,
		Subject: subject,
		Text:    "The text of " + subject + ".",
		Action:  MailConfigActionArgs{RunId: &runId, AgentId: &agentId, Summary: "agent words: send the update"},
		Uses:    uses,
	}
}

// Every recipient of result queued, and the draft's sent copy kept.
func testMailTemplateQueued(t *testing.T, world *mailClientTestWorld, name string, result *MailSendResult, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(result.Recipients) == 0 || !result.SentCopy {
		t.Fatalf("%s: %+v", name, result)
	}
	for _, recipient := range result.Recipients {
		if recipient.Outcome != MailSendQueued {
			t.Fatalf("%s: a recipient %s", name, recipient.Outcome)
		}
	}
}

// The template filed for the first draft, approved for its 3 uses, lets the first draft sent again and each later
// one to a subset through, queued once each; a recipient outside the set and a draft past the count each file a
// request of their own and send nothing.
func TestMailSendUsesFilesATemplateAndSpendsIt(t *testing.T) {
	world, approvals := newTestMailTemplateWorld(t)
	ctx := context.Background()
	first := testMailTemplateDraft(approvals, 3, "First", "One@Outside.Example", "two@outside.example")
	first.Bcc = []string{"three@elsewhere.example"}
	_, err := world.client.Send(ctx, first)
	request := approvals.pendingRequest(err)
	template := request.Action.Action
	if !template.GetScope() || template.GetAlias() != testMailSendFrom || template.GetBodySha256() != nil || template.GetPreview() != "" ||
		!slices.Equal(template.GetRecipients(), []string{"one@outside.example", "three@elsewhere.example", "two@outside.example"}) {
		t.Fatalf("the template filed: %+v", template)
	}
	if request.Request.GetUses() != 3 || recordIdOf(request.Request.GetRunId()) != approvals.runId {
		t.Fatalf("the template's request: %+v", request.Request)
	}
	if len(testMailSendOutbox(t, world)) != 0 || testMailSendRead(t, world, MailFolderSent, "First") != nil {
		t.Fatal("a send waiting on its template queued or kept something")
	}
	_, err = world.client.Send(ctx, first)
	if again := approvals.pendingRequest(err); again.ApprovalId() != request.ApprovalId() {
		t.Errorf("the draft sent again before a decision answered %s", again.ApprovalId())
	}

	approvals.approveUses(request, 3)
	result, err := world.client.Send(ctx, first)
	testMailTemplateQueued(t, world, "the first draft sent again", result, err)

	expectOwn := func(name string, draft *MailSendArgs) {
		t.Helper()
		_, err := world.client.Send(ctx, draft)
		own := approvals.pendingRequest(err)
		if own.ApprovalId() == request.ApprovalId() || own.Action.Action.GetScope() || own.Request.GetUses() != 1 {
			t.Errorf("%s answered %s, not a single-use request of its own", name, own.ApprovalId())
		}
		if testMailSendRead(t, world, MailFolderSent, draft.Subject) != nil {
			t.Errorf("%s was sent", name)
		}
	}
	expectOwn("a recipient outside the set", testMailTemplateDraft(approvals, 0, "Outside", "one@outside.example", "stranger@outside.example"))

	result, err = world.client.Send(ctx, testMailTemplateDraft(approvals, 0, "Second", "TWO@outside.example"))
	testMailTemplateQueued(t, world, "a later draft to a subset", result, err)
	result, err = world.client.Send(ctx, testMailTemplateDraft(approvals, 3, "Third", "three@elsewhere.example", "one@outside.example"))
	testMailTemplateQueued(t, world, "a later draft asking uses again", result, err)
	if got := approvals.status(request.ApprovalId()); got != ApprovalStatusSpent {
		t.Errorf("the template's status after 3 uses: %s", got)
	}
	expectOwn("a draft past the count", testMailTemplateDraft(approvals, 0, "Fourth", "one@outside.example"))

	if entryCount := len(testMailSendOutbox(t, world)); entryCount != 3 {
		t.Errorf("%d outbox entries for 3 uses", entryCount)
	}
	if reserveCount := len(approvals.state(request.ApprovalId()).Reserves); reserveCount != 3 {
		t.Errorf("%d uses reserved", reserveCount)
	}
}

// A draft asking 1 use, or none, files a request for the mail alone, as before mail_send's uses.
func TestMailSendOneUseOrNoneFilesTheMailAlone(t *testing.T) {
	world, approvals := newTestMailTemplateWorld(t)
	ctx := context.Background()
	for _, uses := range []uint32{0, 1} {
		_, err := world.client.Send(ctx, testMailTemplateDraft(approvals, uses, "Single", "one@outside.example", "two@outside.example"))
		request := approvals.pendingRequest(err)
		action := request.Action.Action
		if action.GetScope() || action.GetBodySha256() == nil || request.Request.GetUses() != 1 ||
			!slices.Equal(action.GetRecipients(), []string{"one@outside.example", "two@outside.example"}) {
			t.Errorf("uses %d filed %+v", uses, request.Request)
		}
	}
}

// uses asked with no run is refused before anything is planned or asked of the gate, since a template binds its run;
// on a send to members alone, which is W, uses asks for nothing and the mail goes at once.
func TestMailSendUsesNeedsARunAndAnOutwardSend(t *testing.T) {
	world, approvals := newTestMailTemplateWorld(t)
	ctx := context.Background()
	noRun := testMailTemplateDraft(approvals, 3, "No run", "one@outside.example")
	noRun.Action = MailConfigActionArgs{}
	if _, err := world.client.Send(ctx, noRun); !errors.Is(err, ErrMailSendInvalid) {
		t.Errorf("uses with no run: %v", err)
	}
	if approvals.log.filedCount() != 0 {
		t.Fatalf("%d requests filed", approvals.log.filedCount())
	}
	result, err := world.client.Send(ctx, testMailTemplateDraft(approvals, 3, "Members", testMailIngestRecipient))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 1 || result.Recipients[0].Outcome != MailSendDelivered {
		t.Fatalf("the member send %+v", result)
	}
	if approvals.log.filedCount() != 0 {
		t.Errorf("a member send asking uses filed %d requests", approvals.log.filedCount())
	}
}

// The template a draft asks is the one NewMailTemplateAction builds of the plan's From and recipients, so a mail of
// the same plan falls inside it byte for byte.
func TestMailSendTemplateIsThePlansOwn(t *testing.T) {
	world, approvals := newTestMailTemplateWorld(t)
	draft := testMailTemplateDraft(approvals, 2, "Plan", "B@Outside.Example", "a@outside.example")
	plan, err := world.client.planSend(draft)
	if err != nil {
		t.Fatal(err)
	}
	template, err := NewMailTemplateAction(plan.fromAddress, plan.recipients)
	if err != nil {
		t.Fatal(err)
	}
	mail, err := mailSendAction(draft, plan, world.client.sendSettings())
	if err != nil {
		t.Fatal(err)
	}
	if !ActionMatchesTemplate(template, mail) {
		t.Error("the plan's mail does not fall inside the plan's template")
	}
	_, err = world.client.Send(context.Background(), draft)
	if request := approvals.pendingRequest(err); !slices.Equal(request.Action.Bytes, template.Bytes) ||
		SidecarActionKind(request.Action.Action.GetKind()) != SidecarActionMail {
		t.Error("the send filed another template than the plan's")
	}
}
