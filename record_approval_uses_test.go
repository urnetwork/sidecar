//go:build !ios_extension

// QD-1010 (owner decision 574; §16.6's multi-use row, §18.5's Decide): an ApprovalRequest names, at its version 2, the
// uses its agent asks for a template and 1 for any other action, which approvers render and sign as
// ApprovalDecision.uses. Each a top-level test: the parse holding uses to its version and its action, and Uses reading
// a version-1 request as before the field; a request filed at version 2 naming 1 for an action that is no template,
// an agent's ask for more refused, a template's request carrying its count, a template asking fewer than 2 refused with
// nothing filed, and the same template asked for another count filed anew; a decision for more uses than its request
// names refused at intake, its twin kept and spent; an approval on the daemon signing the requested count, a smaller
// one narrowing it and a larger one refused; a version-1 request still approving 1, and its template only with the
// person's count; an app host approving a template for 3 as shown; and the render showing the count.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A request at version 2 for uses, as a requester files it (QD-1010): the member its approver, waiting in the vault.
func (self *testApproverWorld) putUses(requester Id, action *StoredCanonicalAction, uses uint32) *StoredApprovalRequest {
	self.t.Helper()
	approvalId := NewId()
	actionId := action.ActionId(approvalId)
	payloadSha256 := action.PayloadSha256()
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalRequest{
		ApprovalId: approvalId.Bytes(), ActionId: actionId[:], RunId: NewId().Bytes(), CanonicalAction: action.Bytes,
		PayloadSha256: payloadSha256[:], Risk: uint32(SidecarRiskNormal), RequesterSidecarId: requester.Bytes(),
		Approvers: [][]byte{self.memberId.Bytes()}, NotAfterMillis: self.sidecar.clock.Now().Add(time.Hour).UnixMilli(),
		Version: approvalRequestVersion2, Uses: uses,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	request, err := ParseStoredApprovalRequest(stored)
	if err != nil {
		self.t.Fatal(err)
	}
	self.log.stateLock.Lock()
	defer self.log.stateLock.Unlock()
	self.log.pending = append(self.log.pending, &RecordPendingApproval{LogId: self.vaultId, EntryId: NewId(), Request: request})
	return request
}

// A dns_set template: each use an A record of app.example.
func testApproverDnsTemplate(t *testing.T) *StoredCanonicalAction {
	t.Helper()
	template, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionDnsSet), Scope: true, DnsName: "app.example", DnsType: "A"})
	if err != nil {
		t.Fatal(err)
	}
	return template
}

// The item of approvalId as host lists it.
func (self *testApproverWorld) hostItem(host ApprovalHost, approvalId Id) *SidecarRequestItem {
	self.t.Helper()
	items, err := self.approver.ForHost(host).Pending(self.t.Context())
	if err != nil {
		self.t.Fatal(err)
	}
	for _, item := range items {
		if item.ApprovalId == approvalId {
			return item
		}
	}
	self.t.Fatalf("host %d lists no item of %s", host, approvalId)
	return nil
}

// The parse holds uses to the request's version and its action: version 2 names 1 for an action that is no template
// and 2 or more for a template, never 0; version 1 names none. Uses reads a version-1 request as before the field: 1
// for an action that is no template, no count for a template.
func TestParseStoredApprovalRequestHoldsUsesToItsVersion(t *testing.T) {
	single := testRecordStored(t, testRecordDnsAction())
	template := testApproverDnsTemplate(t).Bytes
	parse := func(action []byte, version uint32, uses uint32) (*StoredApprovalRequest, error) {
		approvalId := NewId()
		actionId := ApprovalActionId(approvalId, action)
		payloadSha256 := ApprovalPayloadSha256(action)
		return ParseStoredApprovalRequest(testRecordStored(t, &protocol.ApprovalRequest{
			ApprovalId: approvalId.Bytes(), ActionId: actionId[:], CanonicalAction: action, PayloadSha256: payloadSha256[:],
			Risk: uint32(SidecarRiskNormal), RequesterSidecarId: NewId().Bytes(), Approvers: [][]byte{NewId().Bytes()},
			NotAfterMillis: 1762387200000, Version: version, Uses: uses,
		}))
	}
	cases := []struct {
		name      string
		action    []byte
		version   uint32
		uses      uint32
		wantUses  uint32
		wantNamed bool
	}{
		{name: "one action at version 2", action: single, version: 2, uses: 1, wantUses: 1, wantNamed: true},
		{name: "a template for 3 at version 2", action: template, version: 2, uses: 3, wantUses: 3, wantNamed: true},
		{name: "a template for 2 at version 2", action: template, version: 2, uses: 2, wantUses: 2, wantNamed: true},
		{name: "one action at version 1", action: single, version: 1, uses: 0, wantUses: 1, wantNamed: true},
		{name: "a template at version 1", action: template, version: 1, uses: 0, wantUses: 0, wantNamed: false},
	}
	for _, c := range cases {
		request, err := parse(c.action, c.version, c.uses)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if uses, named := request.Uses(); uses != c.wantUses || named != c.wantNamed {
			t.Errorf("%s: uses %d, named %t", c.name, uses, named)
		}
	}
	refused := []struct {
		name    string
		action  []byte
		version uint32
		uses    uint32
	}{
		{name: "version 2 naming no count", action: single, version: 2, uses: 0},
		{name: "version 2, a template naming none", action: template, version: 2, uses: 0},
		{name: "version 2, two uses of one action", action: single, version: 2, uses: 2},
		{name: "version 2, a template for 1", action: template, version: 2, uses: 1},
		{name: "version 1 naming a count", action: single, version: 1, uses: 1},
		{name: "version 1, a template naming a count", action: template, version: 1, uses: 3},
	}
	for _, c := range refused {
		if _, err := parse(c.action, c.version, c.uses); !errors.Is(err, ErrRecordStoredInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if _, err := parse(single, 3, 1); !errors.Is(err, ErrApprovalVersionUnknown) {
		t.Errorf("version 3: %v", err)
	}
}

// The requester files every request at version 2 naming its uses: 1 for an action that is no template, which an
// agent's ask for more cannot raise, and a template's own count, which a template asking fewer than 2 cannot leave
// unnamed; a template asked again for its count finds its request, and for another count files anew.
func TestRequestNamesTheUsesItsAgentAsks(t *testing.T) {
	world := newTestApprovalWorld(t)
	single := world.pendingRequest(world.gate.Authorize(t.Context(), world.action(world.mailAction("someone@example.com")), nil))
	if single.Request.GetVersion() != approvalRequestVersion2 || single.Request.GetUses() != 1 {
		t.Errorf("one action's request: version %d, uses %d", single.Request.GetVersion(), single.Request.GetUses())
	}
	more := world.action(world.mailAction("another@example.com"))
	more.Uses = 2
	if err := world.gate.Authorize(t.Context(), more, nil); !errors.Is(err, ErrApprovalUses) || !errors.Is(err, ErrSidecarActionInvalid) {
		t.Errorf("an agent's ask for two uses of one action: %v", err)
	}
	if _, err := world.router.FindOrFile(t.Context(), more); !errors.Is(err, ErrApprovalUses) {
		t.Errorf("two uses of one action, filed directly: %v", err)
	}
	// twin: 1 asked outright is the action's one use
	one := world.action(world.mailAction("another@example.com"))
	one.Uses = 1
	if request := world.pendingRequest(world.gate.Authorize(t.Context(), one, nil)); request.Request.GetUses() != 1 {
		t.Errorf("one use asked: %d", request.Request.GetUses())
	}
	if world.log.filedCount() != 2 {
		t.Fatalf("%d requests filed", world.log.filedCount())
	}

	template := world.mailTemplate("a@example.com", "b@example.com", "c@example.com")
	asking := func(uses uint32) *SidecarAction {
		action := world.action(template)
		action.Uses = uses
		return action
	}
	for _, uses := range []uint32{0, 1} {
		if err := world.gate.Authorize(t.Context(), asking(uses), nil); !errors.Is(err, ErrApprovalUses) {
			t.Errorf("a template asking %d uses: %v", uses, err)
		}
	}
	if world.log.filedCount() != 2 {
		t.Fatalf("%d requests filed after a template asked too few uses", world.log.filedCount())
	}
	templated := world.pendingRequest(world.gate.Authorize(t.Context(), asking(3), nil))
	if templated.Request.GetVersion() != approvalRequestVersion2 || templated.Request.GetUses() != 3 || !templated.Action.Action.GetScope() {
		t.Errorf("the template's request: %+v", templated.Request)
	}
	if again := world.pendingRequest(world.gate.Authorize(t.Context(), asking(3), nil)); again.ApprovalId() != templated.ApprovalId() {
		t.Error("the template asked again for 3 uses filed another request")
	}
	other := world.pendingRequest(world.gate.Authorize(t.Context(), asking(4), nil))
	if other.ApprovalId() == templated.ApprovalId() || other.Request.GetUses() != 4 {
		t.Errorf("the template asked for 4 uses: %+v", other.Request)
	}
	if world.log.filedCount() != 4 {
		t.Errorf("%d requests filed", world.log.filedCount())
	}
	if runCount, _ := world.effect.counts(); runCount != 0 {
		t.Errorf("an effect ran %d times", runCount)
	}
}

// An approver signs the count a request names or a smaller one, so the requester keeps no decision for more uses than
// it asked: one for 3 on a request for 2 is refused at intake and kept nowhere; its twin, for 2, is kept and spends
// on two of the template's uses.
func TestDecisionAboveTheRequestsUsesRefusedAtIntake(t *testing.T) {
	world := newTestApprovalWorld(t)
	template := world.mailTemplate("a@example.com", "b@example.com", "c@example.com")
	asked := world.action(template)
	asked.Uses = 2
	request := world.pendingRequest(world.gate.Authorize(t.Context(), asked, nil))
	over := world.decision(request, world.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, 3)
	if _, err := world.inbox.Receive(t.Context(), over); !errors.Is(err, ErrApprovalRefused) {
		t.Errorf("a decision for 3 uses on a request for 2: %v", err)
	}
	use := world.action(world.mailAction("a@example.com"))
	if err := world.gate.Authorize(t.Context(), use, testGateSigned(t, over)); !errors.Is(err, ErrApprovalRefused) {
		t.Errorf("the decision for 3 handed to a use: %v", err)
	}
	if decisions := world.state(request.ApprovalId()).Decisions; len(decisions) != 0 {
		t.Fatalf("%d decisions kept", len(decisions))
	}

	asIs := world.decision(request, world.spend.phone, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE,
		protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE, 2)
	if _, err := world.inbox.Receive(t.Context(), asIs); err != nil {
		t.Fatal(err)
	}
	for _, recipient := range []string{"a@example.com", "b@example.com"} {
		action := world.action(world.mailAction(recipient))
		testGateExpectOutcome(t, recipient, world.gate.Authorize(t.Context(), action, nil), action, ApprovalOutcomeDone)
	}
	if _, effectCount := world.effect.counts(); effectCount != 2 {
		t.Errorf("%d effects for two uses", effectCount)
	}
}

// On the daemon, an approval with no count signs the count the request names, as ur approve does without --uses; a
// smaller count of 2 or more narrows a template's; a larger one, or 1 on a template, is refused with nothing filed; an
// action that is no template signs its 1, and 2 of it is refused; a denial signs no uses.
func TestApproveSignsTheRequestedUses(t *testing.T) {
	world := newTestApproverWorld(t)
	request := world.putUses(world.requesterId, testApproverDnsTemplate(t), 3)
	decide := func(request *StoredApprovalRequest, decision string, uses uint32) error {
		return world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: decision, Uses: uses}, SidecarActConfirmed, nil)
	}
	for _, c := range []struct {
		asked uint32
		want  uint32
	}{{asked: 0, want: 3}, {asked: 3, want: 3}, {asked: 2, want: 2}} {
		if err := decide(request, SidecarDecisionApprove, c.asked); err != nil {
			t.Fatalf("uses %d asked: %v", c.asked, err)
		}
		decision := world.lastDecision()
		if decision.Decision.GetUses() != c.want || !decision.Binds(request) {
			t.Errorf("uses %d asked: signed %d", c.asked, decision.Decision.GetUses())
		}
	}
	filed := world.decisionCount()
	for _, asked := range []uint32{4, 1} {
		if err := decide(request, SidecarDecisionApprove, asked); !errors.Is(err, ErrApprovalUses) {
			t.Errorf("uses %d of a request for 3: %v", asked, err)
		}
	}
	if world.decisionCount() != filed {
		t.Fatalf("%d decisions filed by refused counts", world.decisionCount()-filed)
	}
	if err := decide(request, SidecarDecisionDeny, 0); err != nil {
		t.Fatal(err)
	}
	if uses := world.lastDecision().Decision.GetUses(); uses != 0 {
		t.Errorf("a denial signed %d uses", uses)
	}

	single := world.putUses(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), 1)
	if err := decide(single, SidecarDecisionApprove, 0); err != nil {
		t.Fatal(err)
	}
	if uses := world.lastDecision().Decision.GetUses(); uses != 1 {
		t.Errorf("one action approved as shown: %d uses", uses)
	}
	if err := decide(single, SidecarDecisionApprove, 2); !errors.Is(err, ErrApprovalUses) {
		t.Errorf("two uses of one action: %v", err)
	}
}

// A version-1 request, from a requester before the field, still decodes and approves: an action that is no template
// signs 1 and renders no count, and a template, whose request names none, takes the person's count of 2 or more, none
// refused on the daemon, as before the field.
func TestVersionOneRequestStillApprovesOne(t *testing.T) {
	world := newTestApproverWorld(t)
	single := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	render := world.item(single.ApprovalId()).Render
	if render.Uses != 1 || slices.ContainsFunc(render.Fields, func(field *ApprovalRenderField) bool { return field.Name == "uses" }) {
		t.Errorf("a version-1 request's render: uses %d, fields %v", render.Uses, render.Fields)
	}
	if err := world.approver.Decide(t.Context(), single.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if uses := world.lastDecision().Decision.GetUses(); uses != 1 {
		t.Errorf("a version-1 request approved with %d uses", uses)
	}

	template := world.put(world.requesterId, testApproverDnsTemplate(t), "")
	if render := world.item(template.ApprovalId()).Render; render.Uses != 0 || !render.Template {
		t.Errorf("a version-1 template's render: uses %d", render.Uses)
	}
	if err := world.approver.Decide(t.Context(), template.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); !errors.Is(err, ErrApprovalUses) {
		t.Errorf("a version-1 template approved with no count: %v", err)
	}
	if err := world.approver.Decide(t.Context(), template.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove, Uses: 5}, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if uses := world.lastDecision().Decision.GetUses(); uses != 5 {
		t.Errorf("a version-1 template approved with %d uses", uses)
	}
}

// §18.5's Decide carries no count, so an app host approves a template as its request names it: a template request for
// 3 lists approve and deny on a local-mode and a remote-mode app host, and each one's approval signs 3 uses by device.
func TestAppHostApprovesATemplateAsRequested(t *testing.T) {
	world := newTestApproverWorld(t)
	for _, host := range []ApprovalHost{ApprovalHostAppLocal, ApprovalHostAppRemote} {
		request := world.putUses(world.requesterId, testApproverDnsTemplate(t), 3)
		item := world.hostItem(host, request.ApprovalId())
		if !slices.Equal(item.Decisions, []string{SidecarDecisionApprove, SidecarDecisionDeny}) || item.Render.Uses != 3 || !item.Render.Template {
			t.Fatalf("host %d lists %+v, uses %d", host, item.Decisions, item.Render.Uses)
		}
		if err := world.approver.ForHost(host).Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove},
			SidecarActConfirmed, nil); err != nil {
			t.Fatalf("host %d: %v", host, err)
		}
		decision := world.lastDecision()
		if decision.Decision.GetUses() != 3 || decision.Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE) || !decision.Binds(request) {
			t.Errorf("host %d signed %+v", host, decision.Decision)
		}
	}
}

// The render shows the count among the daemon-built fields, after the action's: a template's 3 by name, with its
// heading saying the approval covers up to 3 uses; an action that is no template its 1; and a version-1 request none.
func TestRenderShowsTheRequestedUses(t *testing.T) {
	world := newTestApproverWorld(t)
	usesOf := func(render *ApprovalRender) string {
		values := []string{}
		for _, field := range render.Fields {
			if field.Name == "uses" {
				values = append(values, field.Value)
			}
		}
		return strings.Join(values, ",")
	}

	templated := world.render(world.putUses(world.requesterId, testApproverDnsTemplate(t), 3))
	text := templated.Text()
	if usesOf(templated) != "3" || templated.Fields[len(templated.Fields)-1].Name != "uses" || templated.Uses != 3 ||
		!strings.Contains(text, "dns_set, a template for up to 3 uses, each of which must match it") || !strings.Contains(text, "\n  uses: 3\n") {
		t.Errorf("a template for 3:\n%s", text)
	}
	single := world.render(world.putUses(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), 1))
	if usesOf(single) != "1" || single.Uses != 1 || strings.Contains(single.Text(), "template") || !strings.Contains(single.Text(), "\n  uses: 1\n") {
		t.Errorf("one action:\n%s", single.Text())
	}
	old := world.render(world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), ""))
	if usesOf(old) != "" || strings.Contains(old.Text(), "uses") {
		t.Errorf("a version-1 request:\n%s", old.Text())
	}
	oldTemplate := world.render(world.put(world.requesterId, testApproverDnsTemplate(t), ""))
	if usesOf(oldTemplate) != "" || !strings.Contains(oldTemplate.Text(), "dns_set, a template each use must match") {
		t.Errorf("a version-1 template:\n%s", oldTemplate.Text())
	}
}

// The render of request as the daemon's host lists it.
func (self *testApproverWorld) render(request *StoredApprovalRequest) *ApprovalRender {
	self.t.Helper()
	render := self.item(request.ApprovalId()).Render
	if render == nil || !bytes.Equal(render.ApprovalId.Bytes(), request.Request.GetApprovalId()) {
		self.t.Fatalf("no render of %s", request.ApprovalId())
	}
	return render
}
