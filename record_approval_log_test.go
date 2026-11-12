//go:build !sidecar_http

// record_approval_log.go on sidecartest's streams: a personal network's request, a decision by the member's other
// device, and the requester reading it back; a stored action tampered after its payload_sha256 and an action version
// this build does not know, each refused by the approver's device; §22.7's dns_set whose agent text claims other rdata
// shown by its daemon-built dns_value; a request for an approver who is not the author refused; and a tagged
// requester's non-grant action staying pending, since it reads no vault. External, as record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A dns_set action as the daemon builds it.
func testRecordDnsSet(t *testing.T, value string) *sidecar.StoredCanonicalAction {
	t.Helper()
	action, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind:     uint32(sidecar.SidecarActionDnsSet),
		DnsName:  "app.example",
		DnsType:  "A",
		DnsValue: value,
	})
	if err != nil {
		t.Fatal(err)
	}
	return action
}

// requester's ApprovalRequest for an action's stored bytes, approvers the world's member, its summary the agent's text,
// as stored.
func (self *testRecordWorld) approvalRequest(requester *testRecordDevice, actionBytes []byte, summary string, approvers [][]byte) []byte {
	self.t.Helper()
	approvalId := sidecar.NewId()
	actionId := sidecar.ApprovalActionId(approvalId, actionBytes)
	payload := sidecar.ApprovalPayloadSha256(actionBytes)
	if approvers == nil {
		approvers = [][]byte{self.memberId.Bytes()}
	}
	request := &protocol.ApprovalRequest{
		ApprovalId:         approvalId.Bytes(),
		ActionId:           actionId[:],
		CanonicalAction:    actionBytes,
		PayloadSha256:      payload[:],
		Summary:            summary,
		Risk:               uint32(protocol.SidecarRisk_SIDECAR_RISK_NORMAL),
		RequesterSidecarId: requester.sidecarId.Bytes(),
		Approvers:          approvers,
		NotAfterMillis:     self.clock.Now().Add(time.Hour).UnixMilli(),
		Version:            1,
	}
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		self.t.Fatal(err)
	}
	return stored
}

// approver's device decision on request, channel device, as stored.
func (self *testRecordDevice) decide(request *sidecar.StoredApprovalRequest) []byte {
	self.t.Helper()
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	decision := &protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     request.Request.GetNotAfterMillis(),
		ApproverMemberId:   self.world.memberId.Bytes(),
		Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		RequesterSidecarId: request.Request.GetRequesterSidecarId(),
		AuthPin:            self.world.auth.Tip().Pin(),
		Version:            1,
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(decision)
	if err != nil {
		self.t.Fatal(err)
	}
	signed := &bridge.Signed{
		Body:      body,
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	}
	stored, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	return stored
}

// Parses a stored request, which must parse.
func testRecordParsedRequest(t *testing.T, stored []byte) *sidecar.StoredApprovalRequest {
	t.Helper()
	request, err := sidecar.ParseStoredApprovalRequest(stored)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// A personal network: a request in the member's vault, the member's other device shown it by its daemon-built fields
// and deciding it, and the requester reading the decision back, bound to its request's stored bytes; once decided,
// the request is no longer pending.
func TestRecordApprovalsRoundTripInAPersonalNetwork(t *testing.T) {
	world := newTestRecordWorld(t)
	requester := world.device(true)
	approver := world.device(true)
	requesterRecord := requester.open()
	approverRecord := approver.open()
	action := testRecordDnsSet(t, "198.51.100.7")
	// §22.7: the agent's text claims other rdata than the action carries
	request := testRecordParsedRequest(t, world.approvalRequest(requester, action.Bytes, "set app.example A 192.0.2.10", nil))
	ref, err := requesterRecord.Approvals().FileRequest(request)
	if err != nil || ref.LogId != world.vaultId {
		t.Fatalf("filing: %+v, %v", ref, err)
	}
	if err := requesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending, err := approverRecord.Approvals().Pending(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Refused != nil || pending[0].Request == nil {
		t.Fatalf("pending: %d", len(pending))
	}
	shown := pending[0].Request
	if shown.Action.Action.GetDnsValue() != "198.51.100.7" || shown.Request.GetSummary() != "set app.example A 192.0.2.10" {
		t.Errorf("the approver is shown %q, with summary %q", shown.Action.Action.GetDnsValue(), shown.Request.GetSummary())
	}
	if _, err := approverRecord.Approvals().FileDecision(t.Context(), world.vaultId, approver.decide(shown), nil); err != nil {
		t.Fatal(err)
	}
	if err := approverRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	decision, err := requesterRecord.Approvals().Decision(t.Context(), request.ApprovalId())
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Binds(request) || decision.Verify(bridge.SignedKeyAlgEd25519, approver.key.Public().(ed25519.PublicKey)) != nil {
		t.Error("the decision does not bind or verify")
	}
	if pending, err := approverRecord.Approvals().Pending(t.Context()); err != nil || len(pending) != 0 {
		t.Errorf("still pending after its decision: %d, %v", len(pending), err)
	}
}

// A request whose stored action changed after its payload_sha256 was taken, which only a writer outside the daemon's
// own path could file, is shown refused by the approver's device, never rendered.
func TestRecordApprovalsRefusesATamperedAction(t *testing.T) {
	world := newTestRecordWorld(t)
	requester := world.device(true)
	approver := world.device(true)
	requesterRecord := requester.open()
	honest := testRecordDnsSet(t, "198.51.100.7")
	stored := world.approvalRequest(requester, honest.Bytes, "set it", nil)
	request := &protocol.ApprovalRequest{}
	if err := proto.Unmarshal(stored, request); err != nil {
		t.Fatal(err)
	}
	request.CanonicalAction = testRecordDnsSet(t, "203.0.113.66").Bytes
	tampered, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	draft := &sidecar.RecordDraft{Kind: sidecar.RecordKindApproval, Source: sidecar.RecordSourceObserved, NoSession: true, ActionId: request.GetActionId(), StoredBody: tampered}
	testRecordAppend(t, requesterRecord, draft)
	if err := requesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending, err := approver.open().Approvals().Pending(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Request != nil || !errors.Is(pending[0].Refused, sidecar.ErrRecordStoredInvalid) {
		t.Fatalf("a tampered action: %d pending", len(pending))
	}
}

// An action of a version this build's approvers do not know is refused, never rendered (§22.5's §16 row).
func TestRecordApprovalsRefusesAnUnknownActionVersion(t *testing.T) {
	world := newTestRecordWorld(t)
	requester := world.device(true)
	approver := world.device(true)
	requesterRecord := requester.open()
	later, err := proto.Marshal(&protocol.CanonicalAction{
		Kind:     uint32(sidecar.SidecarActionDnsSet),
		Version:  2,
		DnsName:  "app.example",
		DnsType:  "A",
		DnsValue: "198.51.100.7",
	})
	if err != nil {
		t.Fatal(err)
	}
	stored := world.approvalRequest(requester, later, "a later action", nil)
	request := &protocol.ApprovalRequest{}
	if err := proto.Unmarshal(stored, request); err != nil {
		t.Fatal(err)
	}
	draft := &sidecar.RecordDraft{Kind: sidecar.RecordKindApproval, Source: sidecar.RecordSourceObserved, NoSession: true, ActionId: request.GetActionId(), StoredBody: stored}
	testRecordAppend(t, requesterRecord, draft)
	if err := requesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending, err := approver.open().Approvals().Pending(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || !errors.Is(pending[0].Refused, sidecar.ErrCanonicalActionVersionUnknown) {
		t.Fatalf("an unknown version: %d pending, %v", len(pending), pending)
	}
}

// A request naming an approver who is not the requester's author goes to the team record, RECORD-M6-01's: refused
// here, so it stays pending.
func TestRecordApprovalsRefusesAnotherMembersApprover(t *testing.T) {
	world := newTestRecordWorld(t)
	requester := world.device(true)
	action := testRecordDnsSet(t, "198.51.100.7")
	request := testRecordParsedRequest(t, world.approvalRequest(requester, action.Bytes, "set it", [][]byte{sidecar.NewId().Bytes()}))
	if _, err := requester.open().Approvals().FileRequest(request); !errors.Is(err, sidecar.ErrRecordApprovalTeamRoute) {
		t.Fatalf("another member's approver: %v", err)
	}
}

// A tagged sidecar files to its sponsor's vault by deposit, and its sponsor decides there; but the tagged sidecar
// reads no vault, so a decision on a non-grant action never reaches it here and stays pending, failing closed
// (plan-RECORD-deposit-only-decisions).
func TestRecordApprovalsTaggedRequestersNonGrantActionStaysPending(t *testing.T) {
	world := newTestRecordWorld(t)
	approver := world.device(true)
	tagged := world.device(false)
	delete(world.fixture.Members, tagged.sidecarId)
	world.fixture.Sponsors[tagged.sidecarId] = world.memberId
	world.publish()
	taggedRecord := tagged.open()
	action := testRecordDnsSet(t, "198.51.100.7")
	request := testRecordParsedRequest(t, world.approvalRequest(tagged, action.Bytes, "set it", nil))
	if _, err := taggedRecord.Approvals().FileRequest(request); err != nil {
		t.Fatal(err)
	}
	if err := taggedRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	approverRecord := approver.open()
	testRecordIngest(t, approverRecord, world)
	if err := approverRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	pending, err := approverRecord.Approvals().Pending(t.Context())
	if err != nil || len(pending) != 1 || pending[0].Request == nil {
		t.Fatalf("the sponsor's pending: %d, %v", len(pending), err)
	}
	if _, err := approverRecord.Approvals().FileDecision(t.Context(), world.vaultId, approver.decide(pending[0].Request), nil); err != nil {
		t.Fatal(err)
	}
	if err := approverRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := taggedRecord.Approvals().Decision(t.Context(), request.ApprovalId()); !errors.Is(err, sidecar.ErrRecordApprovalUndeliverable) {
		t.Fatalf("the tagged requester's decision: %v", err)
	}
}

// RECORD-M3-07's cancel reader, for the requester's inbox: a cancel the approver filed after its decision is found by
// Cancel, its Signed as stored, while Decision still answers the decision before it.
func TestRecordApprovalsCancelAfterDecision(t *testing.T) {
	world := newTestRecordWorld(t)
	requester := world.device(true)
	approver := world.device(true)
	requesterRecord := requester.open()
	approverRecord := approver.open()
	request := testRecordParsedRequest(t, world.approvalRequest(requester, testRecordDnsSet(t, "198.51.100.7").Bytes, "", nil))
	if _, err := requesterRecord.Approvals().FileRequest(request); err != nil {
		t.Fatal(err)
	}
	if err := requesterRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := requesterRecord.Approvals().Cancel(t.Context(), request.ApprovalId()); !errors.Is(err, sidecar.ErrRecordApprovalPending) {
		t.Errorf("no cancel yet: %v", err)
	}
	if _, err := approverRecord.Approvals().FileDecision(t.Context(), world.vaultId, approver.decide(request), nil); err != nil {
		t.Fatal(err)
	}
	cancelBody, err := proto.Marshal(&protocol.ApprovalCancel{ApprovalId: request.ApprovalId().Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	cancel, err := proto.Marshal(&bridge.Signed{
		Body:      cancelBody,
		SignerId:  approver.sidecarId.Bytes(),
		Signature: ed25519.Sign(approver.key, bridge.SignedBytes(sidecar.ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_CANCEL, cancelBody)),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_CANCEL),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := approverRecord.Approvals().FileCancel(t.Context(), world.vaultId, cancel); err != nil {
		t.Fatal(err)
	}
	if err := approverRecord.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := requesterRecord.Approvals().Decision(t.Context(), request.ApprovalId()); err != nil {
		t.Errorf("the decision before the cancel: %v", err)
	}
	found, err := requesterRecord.Approvals().Cancel(t.Context(), request.ApprovalId())
	if err != nil || !bytes.Equal(found, cancel) {
		t.Errorf("the cancel: %v", err)
	}
}
