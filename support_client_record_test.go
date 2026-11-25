//go:build !ios_extension && !sidecar_http && !js

package sidecar

// DESIGN-COMPUTE §28.12's kind 30 as the support client writes it, and QD-1398's decider beside the body: a message's
// vault entry as it first leaves, its entry none and its seq 0, once across retries; the service's acknowledgment as a
// received entry its client_ref joins, once whether the post's answer or the member's events brought it; kind 27's
// tier and approver from the decision its use spent, posted beside a body that names neither; a decision spending only
// on the body its action hashes; and RecordBodyValidate's rules for SupportMessageBody. Synthetic values only.

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The vault's support_message bodies the host took, in order.
func (self *testSupportWorld) supportDrafts() []*protocol.SupportMessageBody {
	self.host.stateLock.Lock()
	defer self.host.stateLock.Unlock()
	bodies := []*protocol.SupportMessageBody{}
	for _, draft := range self.host.drafts {
		if draft.Kind != RecordKindSupportMessage {
			self.t.Fatalf("a draft of kind %s", draft.Kind)
		}
		body := draft.Body.(*protocol.SupportMessageBody)
		if err := RecordBodyValidate(RecordKindSupportMessage, body); err != nil {
			self.t.Fatalf("the client wrote a body the record refuses: %v", err)
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// The bodies of direction.
func testSupportDraftsOf(bodies []*protocol.SupportMessageBody, direction uint32) []*protocol.SupportMessageBody {
	kept := []*protocol.SupportMessageBody{}
	for _, body := range bodies {
		if body.GetDirection() == direction {
			kept = append(kept, body)
		}
	}
	return kept
}

func TestSupportMessageIsRecordedOnceAsItFirstLeaves(t *testing.T) {
	world := newTestSupportWorld(t)
	// no verified policy names the host: the message has not left, and nothing is recorded
	world.sources.host = ""
	result, err := world.send(world.harnessArgs("the daemon restarts", testSupportCleanRun("call-r")))
	if err != nil {
		t.Fatal(err)
	}
	world.pass()
	if drafts := world.supportDrafts(); len(drafts) != 0 {
		t.Fatalf("%d entries before the message left", len(drafts))
	}
	// it leaves, and the service fails twice: one entry as it first left, none at the retries
	world.sources.host = testSupportServiceHost
	world.service.failNext = 2
	world.clock.advance(world.client.settings.RetryFirstInterval)
	world.pass()
	world.clock.advance(2 * world.client.settings.RetryFirstInterval)
	world.pass()
	drafts := world.supportDrafts()
	if len(drafts) != 1 || drafts[0].GetDirection() != supportDirectionSent || drafts[0].GetEntry() != "" || drafts[0].GetSeq() != 0 ||
		drafts[0].GetType() != supportEventTypeNumber("submitted") || supportClientRefText(drafts[0].GetClientRef()) != result.ClientRef {
		t.Fatalf("as it left: %v", drafts)
	}
	world.clock.advance(4 * world.client.settings.RetryFirstInterval)
	world.pass()
	drafts = world.supportDrafts()
	if len(drafts) != 2 || drafts[1].GetDirection() != supportDirectionReceived || drafts[1].GetEntry() != "100171" ||
		!bytes.Equal(drafts[1].GetClientRef(), drafts[0].GetClientRef()) {
		t.Fatalf("after the acknowledgment: %v", drafts)
	}
	// the member's events bring the same message: the view holds it, and nothing more is recorded
	world.service.addEvent(&SupportServiceEvent{
		Entry: "100171", Seq: 1, Type: "submitted", Body: "the daemon restarts", Agent: "release-bot", Tier: SupportTierAgent,
		ClientRef: result.ClientRef, At: world.clock.Now(),
	})
	world.pass()
	if drafts := world.supportDrafts(); len(drafts) != 2 {
		t.Fatalf("%d entries after the event stream's copy", len(drafts))
	}

	// a follow-up names the item it continues as it leaves
	args := world.harnessArgs("it happened again after the update", testSupportCleanRun("call-f"))
	args.Entry = "100171"
	if _, err := world.send(args); err != nil {
		t.Fatal(err)
	}
	world.pass()
	drafts = world.supportDrafts()
	if len(drafts) != 4 {
		t.Fatalf("%d entries after the follow-up", len(drafts))
	}
	followup, acknowledged := drafts[2], drafts[3]
	if followup.GetDirection() != supportDirectionSent || followup.GetEntry() != "100171" || followup.GetSeq() != 0 ||
		followup.GetType() != supportEventTypeNumber("followup") {
		t.Fatalf("the follow-up as it left: %v", followup)
	}
	if acknowledged.GetDirection() != supportDirectionReceived || acknowledged.GetSeq() != 4 || acknowledged.GetType() != supportEventTypeNumber("followup") {
		t.Fatalf("the follow-up's acknowledgment: %v", acknowledged)
	}
}

// A post's answer lost after the service took it: the member's events bring the message first, recorded once as
// received, and the repeat's replayed answer records no second acknowledgment.
func TestSupportAcknowledgmentIsRecordedOnceWhenTheEventsComeFirst(t *testing.T) {
	world := newTestSupportWorld(t)
	world.service.loseAnswerNext = 1
	result, err := world.send(world.harnessArgs("the bridge drops after sleep", testSupportCleanRun("call-l")))
	if err != nil {
		t.Fatal(err)
	}
	world.pass()
	world.service.addEvent(&SupportServiceEvent{
		Entry: "100171", Seq: 1, Type: "submitted", Body: "the bridge drops after sleep", Agent: "release-bot", Tier: SupportTierAgent,
		ClientRef: result.ClientRef, At: world.clock.Now(),
	})
	world.pass()
	world.clock.advance(world.client.settings.RetryFirstInterval)
	world.pass()
	posts := world.service.snapshot()
	if len(posts) != 2 || posts[0].idempotencyKey != posts[1].idempotencyKey {
		t.Fatalf("posts %+v", posts)
	}
	drafts := world.supportDrafts()
	sent, received := testSupportDraftsOf(drafts, supportDirectionSent), testSupportDraftsOf(drafts, supportDirectionReceived)
	if len(sent) != 1 || len(received) != 1 || received[0].GetSeq() != 1 || received[0].GetText() != "the bridge drops after sleep" {
		t.Fatalf("sent %v, received %v", sent, received)
	}
}

// A decision signed on channel channel for a test request, as stored.
func testSupportDecision(t *testing.T, channel protocol.ApprovalChannel) []byte {
	t.Helper()
	request := testComputeCalendarRequest(t)
	decision := testRecordDecisionBody(request, channel)
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_AUTO {
		decision = testComputeAutoDecision(request)
	}
	stored, err := proto.Marshal(testRecordSignDecision(t, decision))
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// Kind 27's tier and approver come from the decision its use spent: the classifier's, channel 4, sends it as agent; a
// person's released; a decision that does not parse claims no person. Each is posted beside a body naming neither, and
// the view and the vault take it.
func TestSupportKind27DeciderIsPostedBesideTheBody(t *testing.T) {
	cases := []struct {
		name      string
		decisions func(t *testing.T) [][]byte
		tier      SupportTier
		approved  string
	}{
		{
			name: "the classifier's",
			decisions: func(t *testing.T) [][]byte {
				return [][]byte{testSupportDecision(t, protocol.ApprovalChannel_APPROVAL_CHANNEL_AUTO)}
			},
			tier: SupportTierAgent, approved: SupportApprovedClassifier,
		},
		{
			name: "a person's on another device",
			decisions: func(t *testing.T) [][]byte {
				return [][]byte{testSupportDecision(t, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)}
			},
			tier: SupportTierReleased, approved: SupportApprovedPerson,
		},
		{
			name:      "one that does not parse",
			decisions: func(t *testing.T) [][]byte { return [][]byte{[]byte("not a decision")} },
			tier:      SupportTierAgent, approved: SupportApprovedClassifier,
		},
	}
	for _, c := range cases {
		world := newTestSupportWorld(t)
		world.host.spendDecisions = c.decisions(t)
		run := &SupportRun{RunId: Id{9}, ToolCallId: "t", Tainted: true, TaintReasons: []string{"web_tool"}, MarksKnown: true}
		result, err := world.send(world.harnessArgs("the fetch tool fails on redirects", run))
		if err != nil || result.Outcome != SupportOutcomeApprovalPending {
			t.Fatalf("%s: %+v, %v", c.name, result, err)
		}
		world.host.approved = true
		world.pass()
		world.pass()
		posts := world.service.snapshot()
		if len(posts) != 1 {
			t.Fatalf("%s: %d posts", c.name, len(posts))
		}
		if posts[0].body.Tier != "" || posts[0].body.Sender.Approved != "" || posts[0].tier != string(c.tier) || posts[0].approved != c.approved {
			t.Fatalf("%s: the body's tier %q and approver %q; beside it %q and %q", c.name, posts[0].body.Tier,
				posts[0].body.Sender.Approved, posts[0].tier, posts[0].approved)
		}
		sent := testSupportDraftsOf(world.supportDrafts(), supportDirectionSent)
		if len(sent) != 1 || sent[0].GetTier() != supportTierNumber(c.tier) {
			t.Fatalf("%s: the vault's entry %v", c.name, sent)
		}
		read, err := world.client.Read(t.Context(), &SupportReadArgs{Entry: "100171"})
		if err != nil || len(read.Messages) != 1 || read.Messages[0].Tier != c.tier {
			t.Fatalf("%s: the view %+v, %v", c.name, read, err)
		}
	}
}

// A decision spends only on the message its approver saw: a body changed in the outbox after its action was filed, or
// a decision on another message's action, moves nothing, and nothing is posted.
func TestSupportEffectSpendsOnlyOnTheBodyItsActionHashes(t *testing.T) {
	tainted := func() *SupportRun {
		return &SupportRun{RunId: Id{9}, ToolCallId: "t", Tainted: true, TaintReasons: []string{"web_tool"}, MarksKnown: true}
	}

	world := newTestSupportWorld(t)
	result, err := world.send(world.harnessArgs("the fetch tool fails", tainted()))
	if err != nil {
		t.Fatal(err)
	}
	if err := world.client.changeOutboxItem(result.ClientRef, func(item *supportOutboxItem) {
		item.Body = bytes.Replace(item.Body, []byte("fails"), []byte("leaks"), 1)
	}); err != nil {
		t.Fatal(err)
	}
	world.host.approved = true
	world.pass()
	world.pass()
	if posts := world.service.snapshot(); len(posts) != 0 {
		t.Fatalf("a changed body went: %d posts", len(posts))
	}
	item, err := world.client.outboxItem(result.ClientRef)
	if err != nil || item.State != supportOutboxAwaiting {
		t.Fatalf("the item: %+v, %v", item, err)
	}

	world = newTestSupportWorld(t)
	other, err := NewSupportSendAction(&SupportSendActionArgs{
		Body:         []byte(`{"v":1,"text":"another message"}`),
		Support:      &protocol.SupportFields{Product: SupportProductUrnetwork, Text: "another message", ClientRef: bytes.Repeat([]byte{7}, 16)},
		TaintReasons: []string{"web_tool"},
	})
	if err != nil {
		t.Fatal(err)
	}
	world.host.spendDecisions = [][]byte{testSupportDecision(t, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE)}
	world.host.spendAction = other.Bytes
	if _, err := world.send(world.harnessArgs("the fetch tool fails", tainted())); err != nil {
		t.Fatal(err)
	}
	world.host.approved = true
	world.pass()
	world.pass()
	if posts := world.service.snapshot(); len(posts) != 0 {
		t.Fatalf("a decision on another message's action spent: %d posts", len(posts))
	}
}

// A support_message body valid as the client writes one, sent.
func testSupportMessageBody() *protocol.SupportMessageBody {
	return &protocol.SupportMessageBody{
		Direction:  supportDirectionSent,
		Product:    SupportProductUrnetwork,
		Type:       supportEventTypeNumber("submitted"),
		Tier:       supportTierNumberAgent,
		ClientRef:  bytes.Repeat([]byte{1}, supportClientRefByteCount),
		Text:       "ur git push fails with an index error",
		AgentLabel: "release-bot this device",
		Bundle: &protocol.BundleManifest{
			Events: 3, First: 100, Last: 200, Bytes: 1024, Sha256: bytes.Repeat([]byte{2}, recordHashByteCount),
			Codes: []*protocol.BundleCodeCount{{Component: "support", Code: "message_queued", Count: 3}},
		},
		Files:             []*protocol.FileFields{{Name: "build.log", Type: supportFileTypeText, Size: 14, Sha256: bytes.Repeat([]byte{3}, recordHashByteCount)}},
		BodySha256:        bytes.Repeat([]byte{4}, recordHashByteCount),
		BodyBytes:         412,
		ApprovalId:        bytes.Repeat([]byte{5}, recordIdByteCount),
		DisclosureVersion: 1,
	}
}

func TestRecordSupportMessageBodyRules(t *testing.T) {
	settings := DefaultRecordBodySettings()
	if err := RecordBodyValidate(RecordKindSupportMessage, testSupportMessageBody()); err != nil {
		t.Fatal(err)
	}
	received := &protocol.SupportMessageBody{
		Direction: supportDirectionReceived, Product: SupportProductUrnetwork, Entry: "100171", Seq: 6, Type: supportEventTypeNumber("status"),
		Status: supportStatusNumber("fixed"), FixedIn: "2026.11.24-1234",
	}
	if err := RecordBodyValidate(RecordKindSupportMessage, received); err != nil {
		t.Fatal(err)
	}
	stored, err := proto.Marshal(testSupportMessageBody())
	if err != nil {
		t.Fatal(err)
	}
	if err := RecordBodyValidateStored(RecordKindSupportMessage, stored); err != nil {
		t.Fatal(err)
	}
	refused := map[string]func(body *protocol.SupportMessageBody){
		"no direction":               func(body *protocol.SupportMessageBody) { body.Direction = 0 },
		"a third direction":          func(body *protocol.SupportMessageBody) { body.Direction = 3 },
		"another product":            func(body *protocol.SupportMessageBody) { body.Product = "billing" },
		"an entry outside FB's form": func(body *protocol.SupportMessageBody) { body.Entry = "0171" },
		"a seq with no entry":        func(body *protocol.SupportMessageBody) { body.Seq = 2 },
		"an event type past FB's":    func(body *protocol.SupportMessageBody) { body.Type = supportEventTypeLast + 1 },
		"a tier past agent":          func(body *protocol.SupportMessageBody) { body.Tier = supportTierNumberLast + 1 },
		"a short client_ref":         func(body *protocol.SupportMessageBody) { body.ClientRef = body.ClientRef[:15] },
		"text past its cap": func(body *protocol.SupportMessageBody) {
			body.Text = strings.Repeat("a", settings.SupportTextByteCount+1)
		},
		"text that is no UTF-8": func(body *protocol.SupportMessageBody) { body.Text = "\xff\xfe" },
		"a label past its cap": func(body *protocol.SupportMessageBody) {
			body.AgentLabel = strings.Repeat("a", settings.SupportAgentLabelByteCount+1)
		},
		"a fourth file": func(body *protocol.SupportMessageBody) {
			for len(body.Files) <= settings.SupportFileCount {
				body.Files = append(body.Files, proto.Clone(body.Files[0]).(*protocol.FileFields))
			}
		},
		"a file with no name":     func(body *protocol.SupportMessageBody) { body.Files[0].Name = "" },
		"a file of no type":       func(body *protocol.SupportMessageBody) { body.Files[0].Type = 0 },
		"a file of a fourth type": func(body *protocol.SupportMessageBody) { body.Files[0].Type = supportFileTypeJpeg + 1 },
		"a file past its cap":     func(body *protocol.SupportMessageBody) { body.Files[0].Size = settings.SupportFileByteCount + 1 },
		"a file with no hash":     func(body *protocol.SupportMessageBody) { body.Files[0].Sha256 = nil },
		"a short body hash":       func(body *protocol.SupportMessageBody) { body.BodySha256 = body.BodySha256[:31] },
		"a body past its cap":     func(body *protocol.SupportMessageBody) { body.BodyBytes = settings.SupportBodyByteCount + 1 },
		"a status past closed":    func(body *protocol.SupportMessageBody) { body.Status = supportStatusLast + 1 },
		"a fixed_in past its cap": func(body *protocol.SupportMessageBody) {
			body.FixedIn = strings.Repeat("9", settings.SupportFixedInByteCount+1)
		},
		"a short approval id":        func(body *protocol.SupportMessageBody) { body.ApprovalId = body.ApprovalId[:15] },
		"a sent one with no version": func(body *protocol.SupportMessageBody) { body.DisclosureVersion = 0 },
		"a received one naming an approval": func(body *protocol.SupportMessageBody) {
			body.Direction = supportDirectionReceived
		},
		"a bundle ending before it starts": func(body *protocol.SupportMessageBody) { body.Bundle.First = 300 },
		"a bundle past its cap":            func(body *protocol.SupportMessageBody) { body.Bundle.Bytes = settings.SupportBundleByteCount + 1 },
		"a bundle's short hash":            func(body *protocol.SupportMessageBody) { body.Bundle.Sha256 = body.Bundle.Sha256[:8] },
		"a bundle code with no name":       func(body *protocol.SupportMessageBody) { body.Bundle.Codes[0].Code = "" },
		"a bundle code's long component": func(body *protocol.SupportMessageBody) {
			body.Bundle.Codes[0].Component = strings.Repeat("c", settings.SupportCodeNameByteCount+1)
		},
		"too many bundle codes": func(body *protocol.SupportMessageBody) {
			for len(body.Bundle.Codes) <= settings.SupportBundleCodeCount {
				body.Bundle.Codes = append(body.Bundle.Codes, proto.Clone(body.Bundle.Codes[0]).(*protocol.BundleCodeCount))
			}
		},
	}
	for name, change := range refused {
		body := testSupportMessageBody()
		change(body)
		if err := RecordBodyValidate(RecordKindSupportMessage, body); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the team's projection holds no text, label, bundle or files, and keeps the rest
	projection, err := RecordProjectForTeam(RecordKindSupportMessage, testSupportMessageBody(), false)
	if err != nil {
		t.Fatal(err)
	}
	projected := projection.(*protocol.SupportMessageBody)
	if projected.GetText() != "" || projected.GetAgentLabel() != "" || projected.GetBundle() != nil || len(projected.GetFiles()) != 0 ||
		projected.GetTier() != supportTierNumberAgent || projected.GetBodyBytes() != 412 || projected.GetDisclosureVersion() != 1 {
		t.Fatalf("the projection reads %v", projected)
	}
}

// The numbered values the record checks on every leg agree with the lists the client names them by.
func TestSupportMessageNumbersAgreeWithTheirNames(t *testing.T) {
	if len(supportEventTypes) != int(supportEventTypeLast) || len(supportStatuses) != int(supportStatusLast) {
		t.Fatalf("%d event types, %d statuses", len(supportEventTypes), len(supportStatuses))
	}
	if supportTierNumber(SupportTierHuman) != 1 || supportTierNumber(SupportTierReleased) != 2 || supportTierNumber(SupportTierAgent) != 3 ||
		supportTierNumber(SupportTierAuto) != 0 {
		t.Fatal("the tiers' numbers")
	}
	if supportCut("ab€", 4) != "ab" || supportCut("abc", 3) != "abc" {
		t.Fatal("a cut at a character's edge")
	}
}
