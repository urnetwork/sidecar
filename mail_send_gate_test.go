//go:build !sidecar_http && !js && !ios_extension

// A host's submitted send (QD-853, owner decision 288; §15.10's step 1, I-8) on MAIL-M7-18's send world: mail to
// members goes at once with no gate; a send naming an outside recipient waits on the gate as one mail_send action
// listing every recipient, Bcc included, and nothing is kept or deposited until the gate passes it; a gate refusal, a
// From refused first, and an effect whose Send refuses each send nothing; a retry of a done use deposits nothing
// again; and the action is the draft's, byte for byte, its preview cut at a rune within its bound.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A mixed draft: a member's address, an outside one by To, and an outside Bcc.
func testMailSubmitDraft() *MailSendArgs {
	return &MailSendArgs{
		From:    testMailSendFrom,
		To:      []string{testMailIngestRecipient, "someone@Outside.Example"},
		Bcc:     []string{"hidden@elsewhere.example"},
		Subject: "Plans",
		Text:    "Dinner at eight.",
	}
}

// Sets whether the world's gate holds every action for a person's decision.
func testMailSubmitHold(gate *mailConfigTestGate, pending bool) {
	gate.stateLock.Lock()
	defer gate.stateLock.Unlock()
	gate.pending = pending
}

// A lookup that proves nothing, so the test gate reserves uses of kind mail.
func testMailSubmitLookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
}

// Mail to the network's own addresses alone is W: it goes at once, and the gate is never asked.
func TestMailSubmitSendToMembersPassesNoGate(t *testing.T) {
	world, parts, mailboxId := newMailSendTestWorld(t)
	actionsBefore, _ := world.gate.counts()
	testMailSubmitHold(world.gate, true)
	result, err := world.client.SubmitSend(context.Background(), &MailSendArgs{
		From: testMailSendFrom, To: []string{testMailIngestRecipient}, Subject: "Lunch", Text: "At noon.",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Recipients) != 1 || result.Recipients[0].Outcome != MailSendDelivered || !result.SentCopy {
		t.Fatalf("the result %+v", result)
	}
	if deposits := parts.snapshot(); len(deposits) != 1 || deposits[0].repoId != mailboxId {
		t.Fatalf("%d deposits", len(deposits))
	}
	if actionsAfter, _ := world.gate.counts(); actionsAfter != actionsBefore {
		t.Fatalf("mail to members asked the gate %d times", actionsAfter-actionsBefore)
	}
}

// A send naming an outside recipient waits on the gate as one mail_send action, and nothing is kept or deposited,
// its member part included, until a decision passes it. Once the gate passes it, the delivery runs once: the member
// part deposits and each outside recipient is queued at o/. A retry of the done use answers its send_id and deposits
// nothing again.
func TestMailSubmitSendOutsideWaitsOnTheGate(t *testing.T) {
	world, parts, mailboxId := newMailSendTestWorld(t)
	ctx := context.Background()
	actionsBefore, runsBefore := world.gate.counts()

	testMailSubmitHold(world.gate, true)
	_, err := world.client.SubmitSend(ctx, testMailSubmitDraft())
	var pending *ApprovalPendingError
	if !errors.As(err, &pending) {
		t.Fatalf("a send to an outside recipient while the gate holds it: %v", err)
	}
	if len(parts.snapshot()) != 0 || testMailSendRead(t, world, MailFolderSent, "Plans") != nil {
		t.Fatal("a held send deposited or kept a copy")
	}
	actionsAfter, runsAfter := world.gate.counts()
	if actionsAfter != actionsBefore+1 || runsAfter != runsBefore {
		t.Fatalf("the gate took %d actions and ran %d effects", actionsAfter-actionsBefore, runsAfter-runsBefore)
	}
	held := world.gate.lastAction()
	stored, err := ParseStoredCanonicalAction(held.Canonical)
	if err != nil {
		t.Fatal(err)
	}
	bodySha256 := sha256.Sum256([]byte("Plans\r\nDinner at eight."))
	action := stored.Action
	if held.Kind != SidecarActionMail || SidecarActionKind(action.GetKind()) != SidecarActionMail || held.Risk != SidecarRiskNormal ||
		held.RunId != nil || held.AgentId != nil || held.Effect == nil {
		t.Fatalf("the held action %+v", held)
	}
	if !slices.Equal(action.GetRecipients(), []string{testMailIngestRecipient, "someone@outside.example", "hidden@elsewhere.example"}) {
		t.Fatalf("the action lists %v, not every recipient with the Bcc", action.GetRecipients())
	}
	if action.GetAlias() != testMailSendFrom || !bytes.Equal(action.GetBodySha256(), bodySha256[:]) ||
		action.GetPreview() != "Subject: Plans\n\nDinner at eight." || action.GetScope() {
		t.Fatalf("the action's from %q, body hash %x, preview %q", action.GetAlias(), action.GetBodySha256(), action.GetPreview())
	}

	// the client registered the outbox's Lookup for kind mail when it was bound, so the gate reserves its uses
	world.gate.stateLock.Lock()
	registered := world.gate.lookups[SidecarActionMail] != nil
	world.gate.stateLock.Unlock()
	if !registered {
		t.Fatal("no Lookup for kind mail on the gate")
	}

	// a decision passes it: Send once
	testMailSubmitHold(world.gate, false)
	result, err := world.client.SubmitSend(ctx, testMailSubmitDraft())
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]MailSendOutcome{}
	for _, recipient := range result.Recipients {
		outcomes[recipient.Address] = recipient.Outcome
	}
	if outcomes[testMailIngestRecipient] != MailSendDelivered || outcomes["someone@outside.example"] != MailSendQueued ||
		outcomes["hidden@elsewhere.example"] != MailSendQueued || !result.SentCopy {
		t.Fatalf("outcomes %v, sent copy %t", outcomes, result.SentCopy)
	}
	deposits := parts.snapshot()
	if len(deposits) != 1 || deposits[0].repoId != mailboxId || !slices.Equal(deposits[0].deposit.GetRecipients(), []string{testMailIngestRecipient}) {
		t.Fatalf("deposits %+v", deposits)
	}
	if sent := testMailSendRead(t, world, MailFolderSent, "Plans"); sent == nil || mailEntryId(sent.Entry) != result.SendId {
		t.Fatal("the passed send kept no sent copy")
	}
	if passed := world.gate.lastAction(); !bytes.Equal(passed.Canonical, held.Canonical) {
		t.Fatal("the same draft built another action after the approval")
	}

	// a retry of the done use: its send_id, and no second deposit (AU4)
	retried, err := world.client.SubmitSend(ctx, testMailSubmitDraft())
	if err != nil || retried.SendId != result.SendId || len(retried.Recipients) != 0 {
		t.Fatalf("the retry %+v: %v", retried, err)
	}
	if _, runs := world.gate.counts(); runs != runsBefore+1 || len(parts.snapshot()) != 1 {
		t.Fatalf("the retry ran %d effects in all, %d deposits", runs-runsBefore, len(parts.snapshot()))
	}
}

// A From this device may not send as is refused before the gate is asked, so no request is filed for a send that
// cannot go; a draft out of shape too.
func TestMailSubmitSendRefusesTheFromBeforeTheGate(t *testing.T) {
	world, parts, _ := newMailSendTestWorld(t)
	actionsBefore, _ := world.gate.counts()
	testMailSubmitHold(world.gate, true)
	draft := testMailSubmitDraft()
	draft.From = "bo@acme.root.example"
	if _, err := world.client.SubmitSend(context.Background(), draft); !errors.Is(err, ErrMailSendFromRefused) {
		t.Fatalf("a From it may not send as: %v", err)
	}
	draft = testMailSubmitDraft()
	draft.Subject = "two\r\nlines"
	if _, err := world.client.SubmitSend(context.Background(), draft); !errors.Is(err, ErrMailSendInvalid) {
		t.Fatalf("a subject with a line break: %v", err)
	}
	if _, err := world.client.SubmitSend(context.Background(), nil); !errors.Is(err, ErrMailSendInvalid) {
		t.Fatalf("no draft: %v", err)
	}
	if actionsAfter, _ := world.gate.counts(); actionsAfter != actionsBefore || len(parts.snapshot()) != 0 {
		t.Fatal("a refused send reached the gate or deposited")
	}
}

// A gate that passes every action and, before the effect runs, does what the test asks, as a policy change between a
// person's decision and the spend.
type mailSubmitTestGate struct {
	beforeEffect func()
	outcome      *SidecarOutcome
}

func (self *mailSubmitTestGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	if self.beforeEffect != nil {
		self.beforeEffect()
	}
	effectRef, err := action.Effect.Run(ctx, []byte("synthetic effect key"))
	switch {
	case err == nil:
		self.outcome = &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: effectRef}
	case errors.Is(err, ErrSidecarEffectNotDone):
		self.outcome = &SidecarOutcome{State: ApprovalOutcomeNotDone, Err: err}
	default:
		self.outcome = &SidecarOutcome{State: ApprovalOutcomeUncertain, Err: err}
	}
	action.Outcome = self.outcome
	return nil
}

func (self *mailSubmitTestGate) RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func() {
	return func() {}
}

// The client world bound again with gate in place of its own, the same engine and zone.
func testMailSubmitRebind(world *mailClientTestWorld, gate MailConfigGate) {
	binding, _, err := world.client.bound()
	if err != nil {
		world.t.Fatal(err)
	}
	world.client.Bind(&MailBinding{Engine: binding.Engine, Network: binding.Network, Gate: gate, Api: binding.Api})
}

// The effect runs Send again, so a From policy no longer grants when the gate spends refuses it there: not done, and
// nothing deposited. A client bound to no gate refuses every outside send.
func TestMailSubmitSendEffectRefusalAndNoGate(t *testing.T) {
	world, parts, _ := newMailSendTestWorld(t)
	gate := &mailSubmitTestGate{beforeEffect: func() {
		parts.stateLock.Lock()
		defer parts.stateLock.Unlock()
		parts.maySend = map[string]bool{}
	}}
	testMailSubmitRebind(world, gate)
	_, err := world.client.SubmitSend(context.Background(), testMailSubmitDraft())
	if !errors.Is(err, ErrSidecarEffectNotDone) || !errors.Is(err, ErrMailSendFromRefused) {
		t.Fatalf("a From refused at the spend: %v", err)
	}
	if gate.outcome == nil || gate.outcome.State != ApprovalOutcomeNotDone || len(parts.snapshot()) != 0 {
		t.Fatalf("the outcome %+v, %d deposits", gate.outcome, len(parts.snapshot()))
	}

	testMailSubmitRebind(world, nil)
	parts.stateLock.Lock()
	parts.maySend = map[string]bool{world.device.String() + " " + testMailSendFrom: true}
	parts.stateLock.Unlock()
	if _, err := world.client.SubmitSend(context.Background(), testMailSubmitDraft()); !errors.Is(err, ErrSidecarGateDenied) {
		t.Fatalf("no gate: %v", err)
	}
	if len(parts.snapshot()) != 0 {
		t.Fatal("a send with no gate deposited")
	}
}

// Losing a network alias can change a recipient from a case-folded local name to a case-sensitive external
// mailbox. A decision for the previous spelling cannot dispatch to the new one.
func TestMailSubmitSendRefusesAChangedDeliveryAddressAtTheSpend(t *testing.T) {
	world, parts, _ := newMailSendTestWorld(t)
	binding, _, err := world.client.bound()
	if err != nil {
		t.Fatal(err)
	}
	row := binding.Network()
	row.Alias = "former"
	updated := *binding
	updated.Network = func() NetworkLabelRow { return row }
	updated.Gate = &mailSubmitTestGate{beforeEffect: func() { row.Alias = "" }}
	world.client.Bind(&updated)
	draft := testMailSubmitDraft()
	draft.To = append(draft.To, "Bo@former.root.example")
	if _, err := world.client.SubmitSend(context.Background(), draft); !errors.Is(err, ErrSidecarEffectNotDone) {
		t.Fatalf("an address changed while awaiting approval: %v", err)
	}
	if len(parts.snapshot()) != 0 {
		t.Fatal("a send with changed recipients deposited mail")
	}
}

// The action is the draft's: the same draft builds the same bytes, and a subject, a text, a recipient or a From that
// differs builds another; distinct external local parts remain in To, Cc and Bcc order.
func TestMailSubmitSendActionIsTheDrafts(t *testing.T) {
	world, _, _ := newMailSendTestWorld(t)
	plan := func(args *MailSendArgs) *StoredCanonicalAction {
		t.Helper()
		planned, err := world.client.planSend(t.Context(), args)
		if err != nil {
			t.Fatal(err)
		}
		stored, err := mailSendAction(args, planned, DefaultMailSendSettings())
		if err != nil {
			t.Fatal(err)
		}
		return stored
	}
	first := plan(testMailSubmitDraft())
	if again := plan(testMailSubmitDraft()); !bytes.Equal(first.Bytes, again.Bytes) {
		t.Fatal("one draft built two actions")
	}
	changes := []func(args *MailSendArgs){
		func(args *MailSendArgs) { args.Subject = "Plan" },
		func(args *MailSendArgs) { args.Text = "Dinner at nine." },
		func(args *MailSendArgs) { args.Cc = []string{"third@outside.example"} },
		// the subject's end moved into the text: the CRLF keeps them apart
		func(args *MailSendArgs) { args.Subject, args.Text = "Plans Dinner", " at eight." },
	}
	for i, change := range changes {
		args := testMailSubmitDraft()
		change(args)
		if changed := plan(args); bytes.Equal(changed.Bytes, first.Bytes) {
			t.Errorf("change %d built the same action", i)
		}
	}
	args := testMailSubmitDraft()
	args.To = append(args.To, "SOMEONE@outside.example", "SOMEONE@Outside.Example", strings.ToUpper(testMailIngestRecipient))
	args.Cc = []string{"cc@outside.example"}
	if recipients := plan(args).Action.GetRecipients(); !slices.Equal(recipients, []string{
		testMailIngestRecipient, "someone@outside.example", "SOMEONE@outside.example", "cc@outside.example", "hidden@elsewhere.example",
	}) {
		t.Fatalf("recipients %v", recipients)
	}
}

// A preview past its bound is cut at a rune, never inside one, and ends with the mark where it fits; a long draft's
// action still builds.
func TestMailSubmitSendPreviewCutsAtARune(t *testing.T) {
	args := &MailSendArgs{Subject: "Grüße", Text: strings.Repeat("日本", 1000)}
	for _, maxByteCount := range []int{1, 2, 3, 4, 17, 18, 19, 20, 64, 2 * 1024} {
		preview := mailSendPreview(args, maxByteCount)
		if maxByteCount < len(preview) || !utf8.ValidString(preview) {
			t.Errorf("a preview within %d bytes is %d bytes, valid %t", maxByteCount, len(preview), utf8.ValidString(preview))
		}
		if len(mailSendPreviewCutMark) <= maxByteCount && !strings.HasSuffix(preview, mailSendPreviewCutMark) {
			t.Errorf("a preview cut at %d bytes has no mark: %q", maxByteCount, preview)
		}
	}
	if whole := mailSendPreview(&MailSendArgs{Subject: "s", Text: "t"}, 64); whole != "Subject: s\n\nt" {
		t.Errorf("a short preview reads %q", whole)
	}

	world, _, _ := newMailSendTestWorld(t)
	long := testMailSubmitDraft()
	long.Text = strings.Repeat("ü", 4096)
	planned, err := world.client.planSend(t.Context(), long)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := mailSendAction(long, planned, DefaultMailSendSettings())
	if err != nil {
		t.Fatal(err)
	}
	if preview := stored.Action.GetPreview(); DefaultCanonicalActionSettings().PreviewMaxByteCount < len(preview) || !utf8.ValidString(preview) {
		t.Fatalf("a long draft's preview is %d bytes", len(preview))
	}
}
