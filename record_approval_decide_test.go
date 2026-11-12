//go:build !ios_extension

// MCP-M3-07: the approver's device on the act tests' sidecar and authority and a fake approval log: a request it
// renders by the daemon-built fields, its summary apart and controls dropped; a device decision signed by the identity
// key over the stored bytes and filed in the request's log; its own request refused as device and signed by a presence
// key instead; nothing from mcp, a hook or an unconfirmed call; a read_only device showing and signing nothing; uses
// above one for a template alone; a request of an unknown version shown refused; and a cancel filed in its request's log.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The approval family's log as an approver's device sees it, requests put by the test.
type testApproverLog struct {
	stateLock    sync.Mutex
	pending      []*RecordPendingApproval
	decisions    [][]byte
	decisionLogs []Id
	cancels      [][]byte
	logIds       []Id
}

func (self *testApproverLog) Pending(ctx context.Context) ([]*RecordPendingApproval, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*RecordPendingApproval{}, self.pending...), nil
}

func (self *testApproverLog) FileDecision(ctx context.Context, logId Id, storedSigned []byte, runId *Id) (*RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.decisions = append(self.decisions, bytes.Clone(storedSigned))
	self.decisionLogs = append(self.decisionLogs, logId)
	return &RecordEntryRef{LogId: logId, EntryId: NewId()}, nil
}

func (self *testApproverLog) FileCancel(ctx context.Context, logId Id, storedSigned []byte) (*RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, waiting := range self.pending {
		if waiting.LogId == logId {
			self.cancels = append(self.cancels, bytes.Clone(storedSigned))
			return &RecordEntryRef{LogId: logId, EntryId: NewId()}, nil
		}
	}
	return nil, ErrRecordApprovalUnknown
}

func (self *testApproverLog) approvalLogs() ([]Id, error) {
	return self.logIds, nil
}

// An approving device and what it decides on: the act tests' sidecar, consented for its member, and the log.
type testApproverWorld struct {
	t         *testing.T
	sidecar   *Sidecar
	authority *testActAuthority
	log       *testApproverLog
	approver  *ApprovalApprover
	memberId  Id
	// another device of the member, which files the requests
	requesterId Id
	vaultId     Id
}

func newTestApproverWorld(t *testing.T) *testApproverWorld {
	t.Helper()
	sidecar, authority, _ := newActTestSidecar(t)
	world := &testApproverWorld{
		t:           t,
		sidecar:     sidecar,
		authority:   authority,
		memberId:    NewId(),
		requesterId: NewId(),
		vaultId:     NewId(),
	}
	world.log = &testApproverLog{logIds: []Id{NewId(), world.vaultId}}
	identity := sidecar.currentIdentity()
	authority.stateLock.Lock()
	authority.sidecars[identity.SidecarId] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: identity.SidecarId.Bytes(), MemberId: world.memberId.Bytes()}, MemberId: world.memberId}
	authority.consents[[2]Id{identity.SidecarId, world.memberId}] = true
	authority.stateLock.Unlock()
	world.approver = NewApprovalApprover(sidecar, world.log)
	return world
}

// A request by requester for action, the member its approver, waiting in the vault.
func (self *testApproverWorld) put(requester Id, action *StoredCanonicalAction, summary string) *StoredApprovalRequest {
	self.t.Helper()
	approvalId := NewId()
	actionId := action.ActionId(approvalId)
	payloadSha256 := action.PayloadSha256()
	runId := NewId()
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalRequest{
		ApprovalId: approvalId.Bytes(), ActionId: actionId[:], RunId: runId.Bytes(), CanonicalAction: action.Bytes,
		PayloadSha256: payloadSha256[:], Summary: summary, Risk: uint32(SidecarRiskNormal),
		RequesterSidecarId: requester.Bytes(), Approvers: [][]byte{self.memberId.Bytes()},
		NotAfterMillis: self.sidecar.clock.Now().Add(time.Hour).UnixMilli(), Version: 1,
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

// The world's one item of approvalId.
func (self *testApproverWorld) item(approvalId Id) *SidecarRequestItem {
	self.t.Helper()
	items, err := self.approver.Pending(self.t.Context())
	if err != nil {
		self.t.Fatal(err)
	}
	for _, item := range items {
		if item.ApprovalId == approvalId {
			return item
		}
	}
	self.t.Fatalf("no item of %s", approvalId)
	return nil
}

// The decision filed last, parsed.
func (self *testApproverWorld) lastDecision() *StoredApprovalDecision {
	self.t.Helper()
	self.log.stateLock.Lock()
	defer self.log.stateLock.Unlock()
	if len(self.log.decisions) == 0 {
		self.t.Fatal("no decision filed")
	}
	decision, err := ParseStoredApprovalDecision(self.log.decisions[len(self.log.decisions)-1])
	if err != nil {
		self.t.Fatal(err)
	}
	return decision
}

func (self *testApproverWorld) decisionCount() int {
	self.log.stateLock.Lock()
	defer self.log.stateLock.Unlock()
	return len(self.log.decisions)
}

// A dns_set of value.
func testApproverDnsSet(t *testing.T, value string) *StoredCanonicalAction {
	t.Helper()
	action, err := NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(SidecarActionDnsSet), DnsName: "app.example", DnsType: "A", DnsValue: value, DnsTtl: 300,
	})
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// Another sidecar's request: the device signs a device decision by its identity key over the stored bytes, at the
// state's pin, in the request's log; a denial is signed too.
func TestDeviceDecisionSignedAndFiled(t *testing.T) {
	world := newTestApproverWorld(t)
	request := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	item := world.item(request.ApprovalId())
	if item.Channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE || len(item.Decisions) != 2 {
		t.Fatalf("the item: %+v", item)
	}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	decision := world.lastDecision()
	identity := world.sidecar.currentIdentity()
	if err := decision.Verify(bridge.SignedKeyAlgEd25519, identity.IdentityPublicKey); err != nil {
		t.Fatalf("the decision does not verify under the identity key: %v", err)
	}
	if !decision.Binds(request) || recordIdOf(decision.Decision.GetApproverMemberId()) != world.memberId ||
		decision.Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE) ||
		decision.Decision.GetUses() != 1 || decision.Decision.GetNotAfterMillis() != request.Request.GetNotAfterMillis() ||
		!proto.Equal(decision.Decision.GetAuthPin(), world.authority.Pin()) || len(decision.Decision.GetEvidenceSha256()) != 0 {
		t.Errorf("the decision: %+v", decision.Decision)
	}
	if world.log.decisionLogs[0] != world.vaultId {
		t.Error("filed in another log than its request's")
	}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionDeny}, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if denial := world.lastDecision(); denial.Decision.GetDecision() != uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY) {
		t.Errorf("the denial: %+v", denial.Decision)
	}
}

// §16.6's host table: this sidecar's own request is never signed as device. With no presence check it is refused and
// nothing is filed; with one it is signed by the member's live presence key, which a check that fails signs nothing.
func TestOwnRequestRefusedAsDevice(t *testing.T) {
	world := newTestApproverWorld(t)
	identity := world.sidecar.currentIdentity()
	request := world.put(identity.SidecarId, testApproverDnsSet(t, "198.51.100.7"), "")
	if item := world.item(request.ApprovalId()); item.Channel != protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE {
		t.Errorf("the own request's channel %d", item.Channel)
	}
	approve := &SidecarRequestDecision{Decision: SidecarDecisionApprove}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), approve, SidecarActConfirmed, nil); !errors.Is(err, ErrApprovalOwnRequest) {
		t.Errorf("the own request without presence: %v", err)
	}
	refused := func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		return nil, errors.New("the person said no")
	}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), approve, SidecarActConfirmed, refused); !errors.Is(err, ErrSidecarActPresence) {
		t.Errorf("a refused prompt: %v", err)
	}
	if world.decisionCount() != 0 {
		t.Fatalf("%d decisions filed", world.decisionCount())
	}
	key, keyId := addTestPresenceKey(t, world.authority)
	world.authority.stateLock.Lock()
	world.authority.liveKeys[len(world.authority.liveKeys)-1].MemberId = world.memberId.Bytes()
	row := proto.Clone(world.authority.liveKeys[len(world.authority.liveKeys)-1]).(*bridge.KeyRow)
	world.authority.stateLock.Unlock()
	seen := []byte{}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), approve, SidecarActConfirmed, testPresenceCheck(t, key, keyId, &seen)); err != nil {
		t.Fatal(err)
	}
	decision := world.lastDecision()
	if decision.Decision.GetChannel() != uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE) {
		t.Errorf("channel %d", decision.Decision.GetChannel())
	}
	if err := VerifyPresenceUse(decision.Signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, row, nil); err != nil {
		t.Errorf("the presence decision does not verify: %v", err)
	}
	if !bytes.Equal(seen, bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, decision.Bytes)) {
		t.Error("the prompt was asked over other bytes than the decision's")
	}
}

// D-CORE-13: a decision or a cancel from mcp, a hook or an unconfirmed control call is refused, nothing signed.
func TestConfirmMethodRefusedFromMcpAndHook(t *testing.T) {
	world := newTestApproverWorld(t)
	request := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	for _, origin := range []SidecarActOrigin{SidecarActMcp, SidecarActHook, SidecarActUnconfirmed} {
		if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, origin, nil); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("decide from origin %d: %v", origin, err)
		}
		if err := world.approver.Cancel(t.Context(), request.ApprovalId(), origin); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("cancel from origin %d: %v", origin, err)
		}
	}
	if world.decisionCount() != 0 || len(world.log.cancels) != 0 {
		t.Error("something was filed")
	}
}

// D-MCP-14: a read_only device is no approval-capable device: it shows nothing to sign and signs nothing; so is an
// unconsented one.
func TestReadOnlyHostSignsNothing(t *testing.T) {
	world := newTestApproverWorld(t)
	request := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	identity := world.sidecar.currentIdentity()
	world.authority.stateLock.Lock()
	world.authority.sidecars[identity.SidecarId].Row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	world.authority.stateLock.Unlock()
	if items, err := world.approver.Pending(t.Context()); err != nil || len(items) != 0 {
		t.Errorf("a read_only device lists %d, %v", len(items), err)
	}
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalNotEligible) {
		t.Errorf("a read_only device decided: %v", err)
	}
	world.authority.stateLock.Lock()
	world.authority.sidecars[identity.SidecarId].Row.Capabilities = 0
	delete(world.authority.consents, [2]Id{identity.SidecarId, world.memberId})
	world.authority.stateLock.Unlock()
	if err := world.approver.Decide(t.Context(), request.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); !errors.Is(err, ErrSidecarApprovalNotEligible) {
		t.Errorf("an unconsented device decided: %v", err)
	}
	if world.decisionCount() != 0 {
		t.Error("a decision was filed")
	}
}

// A decision covers more than one action only on a template, and a template takes 2 or more.
func TestUsesAboveOneNeedsTemplate(t *testing.T) {
	world := newTestApproverWorld(t)
	single := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	if err := world.approver.Decide(t.Context(), single.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove, Uses: 2}, SidecarActConfirmed, nil); !errors.Is(err, ErrApprovalUses) {
		t.Errorf("two uses of one action: %v", err)
	}
	template, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionDnsSet), Scope: true, DnsName: "app.example", DnsType: "A"})
	if err != nil {
		t.Fatal(err)
	}
	templated := world.put(world.requesterId, template, "")
	if world.item(templated.ApprovalId()).Render.Template != true {
		t.Error("the template is not shown as one")
	}
	if err := world.approver.Decide(t.Context(), templated.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove}, SidecarActConfirmed, nil); !errors.Is(err, ErrApprovalUses) {
		t.Errorf("one use of a template: %v", err)
	}
	if err := world.approver.Decide(t.Context(), templated.ApprovalId(), &SidecarRequestDecision{Decision: SidecarDecisionApprove, Uses: 3}, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	if decision := world.lastDecision(); decision.Decision.GetUses() != 3 {
		t.Errorf("uses %d", decision.Decision.GetUses())
	}
}

// §22.5's M3 row on the device: a request whose action is of a version this build does not know shows refused, and
// no decision reaches it.
func TestApproverListsUnknownVersionRefused(t *testing.T) {
	world := newTestApproverWorld(t)
	world.log.stateLock.Lock()
	world.log.pending = append(world.log.pending, &RecordPendingApproval{
		LogId: world.vaultId, EntryId: NewId(), Refused: errors.New("canonical action version 9 \x1b[31mred"),
	})
	world.log.stateLock.Unlock()
	items, err := world.approver.Pending(t.Context())
	if err != nil || len(items) != 1 {
		t.Fatalf("%d items, %v", len(items), err)
	}
	if items[0].Render != nil || items[0].Refused == "" || len(items[0].Decisions) != 0 || strings.ContainsRune(items[0].Refused, 0x1b) {
		t.Errorf("the refused item: %+v", items[0])
	}
}

// §22.7's actions row: a dns_set whose agent text claims other rdata shows the action's own dns_value as the action,
// and the claim only as untrusted text, every control character dropped.
func TestPreviewClaimingOtherRdataShowsDnsValue(t *testing.T) {
	world := newTestApproverWorld(t)
	request := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "set app.example A 192.0.2.10\x1b[2J‮\r\nok")
	text := world.item(request.ApprovalId()).Render.Text()
	action, untrusted, found := strings.Cut(text, "untrusted text")
	if !found {
		t.Fatalf("no untrusted heading:\n%s", text)
	}
	if !strings.Contains(action, "dns_value: 198.51.100.7") || strings.Contains(action, "192.0.2.10") {
		t.Errorf("the action block:\n%s", action)
	}
	if !strings.Contains(untrusted, "set app.example A 192.0.2.10") {
		t.Errorf("the untrusted block:\n%s", untrusted)
	}
	for _, control := range []string{"\x1b", "‮", "\r"} {
		if strings.Contains(text, control) {
			t.Errorf("the text carries %q", control)
		}
	}
	if strings.Count(text, "\n") != strings.Count(text, "\n") || strings.Contains(untrusted, "10\n") {
		t.Errorf("the summary's own line break survived:\n%s", text)
	}
}

// ApprovalPrintable drops C0, DEL, C1 and the bidi controls and keeps the rest, ill-formed bytes shown as U+FFFD.
func TestApprovalPrintableDropsControls(t *testing.T) {
	cases := []struct {
		text string
		want string
	}{
		{text: "plain", want: "plain"},
		{text: "a\tb\nc\x00d\x7f", want: "abcd"},
		{text: "c1\u0085\u009b[0m", want: "c1[0m"},
		{text: "bidi‮hidden⁦⁩‎‏؜", want: "bidihidden"},
		{text: "kept: é 日本", want: "kept: é 日本"},
		{text: "bad\xffbyte", want: "bad�byte"},
	}
	for _, c := range cases {
		if got := ApprovalPrintable(c.text); got != c.want {
			t.Errorf("%q: %q, want %q", c.text, got, c.want)
		}
	}
}

// A cancel is signed by the identity key and filed in whichever of the device's logs holds the request.
func TestCancelFiledInTheRequestsLog(t *testing.T) {
	world := newTestApproverWorld(t)
	request := world.put(world.requesterId, testApproverDnsSet(t, "198.51.100.7"), "")
	if err := world.approver.Cancel(t.Context(), request.ApprovalId(), SidecarActConfirmed); err != nil {
		t.Fatal(err)
	}
	if len(world.log.cancels) != 1 {
		t.Fatalf("%d cancels", len(world.log.cancels))
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(world.log.cancels[0], signed); err != nil {
		t.Fatal(err)
	}
	identity := world.sidecar.currentIdentity()
	if err := bridge.VerifySigned(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_CANCEL, bridge.SignedKeyAlgEd25519, ed25519.PublicKey(identity.IdentityPublicKey)); err != nil {
		t.Errorf("the cancel does not verify: %v", err)
	}
	cancel := &protocol.ApprovalCancel{}
	if err := proto.Unmarshal(signed.GetBody(), cancel); err != nil || recordIdOf(cancel.GetApprovalId()) != request.ApprovalId() {
		t.Errorf("the cancel names %x, %v", cancel.GetApprovalId(), err)
	}
}
