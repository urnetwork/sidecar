// RECORD.md section 5.1's hashed bytes and §16.6's ids, with parsers that keep each message's stored bytes, on every
// leg: ACL-M2-07's GrantActivate check, MCP's spend check and gate, the record's own readers and §17 share them.
//
// Every value covers bytes as stored, never a re-encoding (§16.8's what freezes). protobuf's encoding is not
// canonical, so each parser here returns its message with the bytes it came from, every later hash takes those bytes,
// and nothing here calls proto.Marshal. A reader keeps a field it cannot name by keeping the bytes. grant_id stays
// ACL's AclGrantId (§8.8).
//
// The approval parsers are the approver's, spender's and gate's: they refuse what such a verifier cannot judge, a
// version or field it does not know among them (record_action_rules.go). A reader that only shows an entry parses
// its body as its kind's message instead (record_kind.go), and keeps what it does not know.
//
// Package-level functions are safe for concurrent use, and so are the Stored values, which nothing changes once
// parsed.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §6.9's purposes in the record (§16.8): a RecordHeader's and a RetentionPolicy's, and an ApprovalDecision's and an
// ApprovalCancel's. identity_sign.go signs each type under its purpose.
const (
	RecordEntryPurpose = "record-entry"
	ApprovalPurpose    = "approval"
)

// RECORD.md section 5.1's and §16.6's sizes and domains, which are format values.
const (
	// A body's salt, 32 random bytes drawn per entry (owner decision 61).
	RecordSaltByteCount = 32
	// An entry_id, and every other id the record's messages carry: an Id's bytes.
	recordIdByteCount = 16
	// action_id, a leaf, a commitment and each other hash here.
	recordHashByteCount = sha256.Size

	// RFC 9162's leaf prefix.
	recordLeafPrefix           = 0x00
	recordBodyCommitmentDomain = "urnetwork-sidecar-v1/record-body"
	approvalActionIdDomain     = "urnetwork-sidecar-v1/action"
	approvalEffectKeyDomain    = "urnetwork-sidecar-v1/effect"
	recordToolActionIdDomain   = "urnetwork-sidecar-v1/action-tool"
)

var (
	// Stored bytes that do not parse as their message, or break a length, a value or a binding this file checks:
	// RECORD.md section 5.4's "does not parse", and what a verifier refuses outright.
	ErrRecordStoredInvalid = errors.New("record stored bytes invalid")
	// An ApprovalRequest or ApprovalDecision of a version this build does not know, which a verifier refuses (§16.8).
	ErrApprovalVersionUnknown = errors.New("approval version unknown")
)

// RFC 9162's leaf hash of an entry, SHA-256(0x00 || body), over its Signed.body as stored. prev_sha256 chains these,
// and M6's verifiable log takes them as leaves (§16.8).
func RecordLeafHash(signedBody []byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte{recordLeafPrefix})
	hash.Write(signedBody)
	var leaf [sha256.Size]byte
	hash.Sum(leaf[:0])
	return leaf
}

// body_commitment, SHA-256("urnetwork-sidecar-v1/record-body" || salt || body), over the body as marshaled once at
// sealing (§16.8, RECORD.md section 5.1). A salt that is not 32 bytes is refused, so a short or missing slot row can
// never stand in for one.
func RecordBodyCommitment(salt []byte, body []byte) ([sha256.Size]byte, error) {
	if len(salt) != RecordSaltByteCount {
		return [sha256.Size]byte{}, fmt.Errorf("%w: a salt of %d bytes", ErrRecordStoredInvalid, len(salt))
	}
	hash := sha256.New()
	hash.Write([]byte(recordBodyCommitmentDomain))
	hash.Write(salt)
	hash.Write(body)
	var commitment [sha256.Size]byte
	hash.Sum(commitment[:0])
	return commitment, nil
}

// payload_sha256: SHA-256 of a CanonicalAction as stored (§16.8), never a re-encoding.
func ApprovalPayloadSha256(storedAction []byte) [sha256.Size]byte {
	return sha256.Sum256(storedAction)
}

// request_sha256: SHA-256 of an ApprovalRequest as stored (§16.8), which binds run_id, agent_id, approvers and
// expiry into a decision that holds none of them.
func ApprovalRequestSha256(storedRequest []byte) [sha256.Size]byte {
	return sha256.Sum256(storedRequest)
}

// §16.6's action_id: SHA-256("urnetwork-sidecar-v1/action" || approval_id || this use's CanonicalAction bytes). For
// uses = 1 it is ApprovalRequest.action_id, computed at proposal (R-MCP-6). approval_id is an Id's 16 bytes, so the
// concatenation is unambiguous.
func ApprovalActionId(approvalId Id, storedAction []byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(approvalActionIdDomain))
	hash.Write(approvalId[:])
	hash.Write(storedAction)
	var actionId [sha256.Size]byte
	hash.Sum(actionId[:0])
	return actionId
}

// §16.6's effect_key: SHA-256("urnetwork-sidecar-v1/effect" || approval_id || action_id), under which each component
// is idempotent and a restart finds its effect (D-MCP-11).
func ApprovalEffectKey(approvalId Id, actionId [sha256.Size]byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write([]byte(approvalEffectKeyDomain))
	hash.Write(approvalId[:])
	hash.Write(actionId[:])
	var effectKey [sha256.Size]byte
	hash.Sum(effectKey[:0])
	return effectKey
}

// A tool call's action_id (RECORD.md section 4.4): SHA-256("urnetwork-sidecar-v1/action-tool" || run_id ||
// u16be(len(tool_use_id)) || tool_use_id), the id the harness gives the call. A harness or event with no id takes 32
// random bytes instead, linking nothing, so an empty id is refused here, as is one too long for its length prefix.
func RecordToolActionId(runId Id, toolUseId string) ([sha256.Size]byte, error) {
	if toolUseId == "" || math.MaxUint16 < len(toolUseId) {
		return [sha256.Size]byte{}, fmt.Errorf("%w: a tool_use_id of %d bytes", ErrRecordStoredInvalid, len(toolUseId))
	}
	hash := sha256.New()
	hash.Write([]byte(recordToolActionIdDomain))
	hash.Write(runId[:])
	hash.Write(binary.BigEndian.AppendUint16(nil, uint16(len(toolUseId))))
	hash.Write([]byte(toolUseId))
	var actionId [sha256.Size]byte
	hash.Sum(actionId[:0])
	return actionId, nil
}

// Refuses a field whose length is not want, or, where optional, not empty either.
func recordCheckLength(name string, value []byte, want int, optional bool) error {
	if len(value) == want || (optional && len(value) == 0) {
		return nil
	}
	return fmt.Errorf("%w: %s of %d bytes", ErrRecordStoredInvalid, name, len(value))
}

// The Id a checked 16-byte field holds.
func recordIdOf(value []byte) Id {
	var id Id
	copy(id[:], value)
	return id
}

// A RecordHeader with the bytes it was parsed from: an entry's Signed.body, which its signature and leaf cover.
type StoredRecordHeader struct {
	Header *protocol.RecordHeader
	// as received, never re-encoded
	Bytes []byte
}

// Parses an entry's Signed.body as a RecordHeader, keeping the bytes. A header of a kind, source or field this build
// does not know parses, since a reader keeps it, verifies it and shows it generically (§16.8); one whose ids, chain,
// commitment or content refs are not their lengths, or whose seq is 0, does not, which RECORD.md section 5.4 consumes
// unrecorded and section 5.5 ignores, each with an alarm. The chain itself is the reader's to judge (section 5.5).
func ParseStoredRecordHeader(signedBody []byte) (*StoredRecordHeader, error) {
	header := &protocol.RecordHeader{}
	if err := proto.Unmarshal(signedBody, header); err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrRecordStoredInvalid, err)
	}
	checks := []error{
		recordCheckLength("entry_id", header.GetEntryId(), recordIdByteCount, false),
		recordCheckLength("log_id", header.GetLogId(), recordIdByteCount, false),
		recordCheckLength("writer_sidecar_id", header.GetWriterSidecarId(), recordIdByteCount, false),
		recordCheckLength("prev_sha256", header.GetPrevSha256(), recordHashByteCount, false),
		recordCheckLength("agent_id", header.GetAgentId(), recordIdByteCount, true),
		recordCheckLength("run_id", header.GetRunId(), recordIdByteCount, true),
		recordCheckLength("action_id", header.GetActionId(), recordHashByteCount, true),
		recordCheckLength("body_commitment", header.GetBodyCommitment(), recordHashByteCount, false),
		recordCheckLength("grant_id", header.GetGrantId(), recordHashByteCount, true),
	}
	for _, content := range header.GetContent() {
		checks = append(checks,
			recordCheckLength("content repo_id", content.GetRepoId(), recordIdByteCount, false),
			recordCheckLength("content object_id", content.GetObjectId(), recordIdByteCount, false),
			recordCheckLength("content commitment", content.GetCommitment(), recordHashByteCount, false),
		)
	}
	if err := errors.Join(checks...); err != nil {
		return nil, err
	}
	if header.GetSeq() == 0 {
		return nil, fmt.Errorf("%w: seq 0", ErrRecordStoredInvalid)
	}
	return &StoredRecordHeader{Header: header, Bytes: bytes.Clone(signedBody)}, nil
}

// The entry's leaf, over its stored header.
func (self *StoredRecordHeader) LeafHash() [sha256.Size]byte {
	return RecordLeafHash(self.Bytes)
}

// The entry's kind, as a RecordKind.
func (self *StoredRecordHeader) Kind() RecordKind {
	return RecordKind(self.Header.GetKind())
}

// A CanonicalAction with the bytes it was parsed from, which payload_sha256 and action_id cover.
type StoredCanonicalAction struct {
	Action *protocol.CanonicalAction
	// as stored, never re-encoded
	Bytes []byte
}

// Parses a CanonicalAction as stored and holds it to record_action_rules.go's rules: a version this build knows, a
// kind it knows, only the fields that version may set, and no field it cannot name. Approvers, spenders and gates
// take an action only through here, so one they could not render is refused, never approved unseen (D-MCP-17).
func ParseStoredCanonicalAction(stored []byte) (*StoredCanonicalAction, error) {
	action := &protocol.CanonicalAction{}
	if err := proto.Unmarshal(stored, action); err != nil {
		return nil, fmt.Errorf("%w: canonical action: %v", ErrRecordStoredInvalid, err)
	}
	if err := canonicalActionCheck(action, CanonicalActionVersionKnown); err != nil {
		return nil, err
	}
	return &StoredCanonicalAction{Action: action, Bytes: bytes.Clone(stored)}, nil
}

// payload_sha256 over the stored bytes.
func (self *StoredCanonicalAction) PayloadSha256() [sha256.Size]byte {
	return ApprovalPayloadSha256(self.Bytes)
}

// §16.6's action_id of this action under approvalId.
func (self *StoredCanonicalAction) ActionId(approvalId Id) [sha256.Size]byte {
	return ApprovalActionId(approvalId, self.Bytes)
}

// An ApprovalRequest with the bytes it was parsed from, which request_sha256 covers, and its action, parsed from the
// bytes the request carries.
type StoredApprovalRequest struct {
	Request *protocol.ApprovalRequest
	// as stored, never re-encoded
	Bytes  []byte
	Action *StoredCanonicalAction
}

// ApprovalRequest versions this build knows.
func approvalRequestVersionKnown(version uint32) bool {
	return version == 1
}

// Parses an ApprovalRequest as stored, for the approver's device and the spender: a version this build knows and no
// field it cannot name; ids at their lengths; a risk SidecarRisk names; an expiry; payload_sha256 equal to SHA-256 of
// the canonical_action bytes it carries and action_id equal to §16.6's formula over them (R-MCP-6); and that action
// passing ParseStoredCanonicalAction. summary and preview stay untrusted text for the approver to show as such.
func ParseStoredApprovalRequest(stored []byte) (*StoredApprovalRequest, error) {
	request := &protocol.ApprovalRequest{}
	if err := proto.Unmarshal(stored, request); err != nil {
		return nil, fmt.Errorf("%w: approval request: %v", ErrRecordStoredInvalid, err)
	}
	if len(request.ProtoReflect().GetUnknown()) != 0 {
		return nil, fmt.Errorf("%w: approval request carries a field this build cannot name", ErrRecordStoredInvalid)
	}
	if !approvalRequestVersionKnown(request.GetVersion()) {
		return nil, fmt.Errorf("%w: approval request version %d", ErrApprovalVersionUnknown, request.GetVersion())
	}
	checks := []error{
		recordCheckLength("approval_id", request.GetApprovalId(), recordIdByteCount, false),
		recordCheckLength("action_id", request.GetActionId(), recordHashByteCount, false),
		recordCheckLength("run_id", request.GetRunId(), recordIdByteCount, true),
		recordCheckLength("agent_id", request.GetAgentId(), recordIdByteCount, true),
		recordCheckLength("payload_sha256", request.GetPayloadSha256(), recordHashByteCount, false),
		recordCheckLength("requester_sidecar_id", request.GetRequesterSidecarId(), recordIdByteCount, false),
	}
	for _, approver := range request.GetApprovers() {
		checks = append(checks, recordCheckLength("approver", approver, recordIdByteCount, false))
	}
	if err := errors.Join(checks...); err != nil {
		return nil, err
	}
	switch protocol.SidecarRisk(request.GetRisk()) {
	case protocol.SidecarRisk_SIDECAR_RISK_NORMAL, protocol.SidecarRisk_SIDECAR_RISK_HIGH:
	default:
		return nil, fmt.Errorf("%w: risk %d", ErrRecordStoredInvalid, request.GetRisk())
	}
	if request.GetNotAfterMillis() <= 0 {
		return nil, fmt.Errorf("%w: no expiry", ErrRecordStoredInvalid)
	}
	action, err := ParseStoredCanonicalAction(request.GetCanonicalAction())
	if err != nil {
		return nil, err
	}
	payloadSha256 := action.PayloadSha256()
	if !bytes.Equal(request.GetPayloadSha256(), payloadSha256[:]) {
		return nil, fmt.Errorf("%w: payload_sha256 is not its action's", ErrRecordStoredInvalid)
	}
	actionId := action.ActionId(recordIdOf(request.GetApprovalId()))
	if !bytes.Equal(request.GetActionId(), actionId[:]) {
		return nil, fmt.Errorf("%w: action_id is not its action's", ErrRecordStoredInvalid)
	}
	return &StoredApprovalRequest{Request: request, Bytes: bytes.Clone(stored), Action: action}, nil
}

// request_sha256 over the stored bytes.
func (self *StoredApprovalRequest) Sha256() [sha256.Size]byte {
	return ApprovalRequestSha256(self.Bytes)
}

// The request's approval_id.
func (self *StoredApprovalRequest) ApprovalId() Id {
	return recordIdOf(self.Request.GetApprovalId())
}

// An ApprovalDecision with its Signed: a decision entry's body (RECORD.md section 6.4) and each of a GrantActivate's
// decisions (§8.8). The decision's stored bytes are Signed.body, which the signature covers whatever encodes the
// Signed around it.
type StoredApprovalDecision struct {
	Decision *protocol.ApprovalDecision
	Signed   *bridge.Signed
	// Signed.body, as signed
	Bytes []byte
}

// ApprovalDecision versions this build knows.
func approvalDecisionVersionKnown(version uint32) bool {
	return version == 1
}

// Parses a Signed ApprovalDecision as stored, as ParseSignedApprovalDecision does.
func ParseStoredApprovalDecision(storedSigned []byte) (*StoredApprovalDecision, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(storedSigned, signed); err != nil {
		return nil, fmt.Errorf("%w: approval decision's Signed: %v", ErrRecordStoredInvalid, err)
	}
	return ParseSignedApprovalDecision(signed)
}

// Parses an ApprovalDecision from its Signed, for the spender and every gate: type SIGNED_APPROVAL_DECISION; a
// version this build knows and no field it cannot name; ids and hashes at their lengths; a verdict and channel
// record.proto names; an expiry; uses of at least 1 on an approval; and evidence_sha256 a hook event's leaf on channel
// harness and empty on device and presence (record-md-presence-evidence-sha256). sshsig is ignored and never trusted,
// since no decision needs one (plan-MCP-risk-classifier#1). The signature is Verify's, given the signer's key, and the
// rest of §16.6's spend check is the spender's.
func ParseSignedApprovalDecision(signed *bridge.Signed) (*StoredApprovalDecision, error) {
	if signed == nil {
		return nil, fmt.Errorf("%w: no Signed", ErrRecordStoredInvalid)
	}
	if signed.GetType() != uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION) {
		return nil, fmt.Errorf("%w: a Signed of type %#x", ErrRecordStoredInvalid, signed.GetType())
	}
	decision := &protocol.ApprovalDecision{}
	if err := proto.Unmarshal(signed.GetBody(), decision); err != nil {
		return nil, fmt.Errorf("%w: approval decision: %v", ErrRecordStoredInvalid, err)
	}
	if len(decision.ProtoReflect().GetUnknown()) != 0 {
		return nil, fmt.Errorf("%w: approval decision carries a field this build cannot name", ErrRecordStoredInvalid)
	}
	if !approvalDecisionVersionKnown(decision.GetVersion()) {
		return nil, fmt.Errorf("%w: approval decision version %d", ErrApprovalVersionUnknown, decision.GetVersion())
	}
	checks := []error{
		recordCheckLength("approval_id", decision.GetApprovalId(), recordIdByteCount, false),
		recordCheckLength("request_sha256", decision.GetRequestSha256(), recordHashByteCount, false),
		recordCheckLength("payload_sha256", decision.GetPayloadSha256(), recordHashByteCount, false),
		recordCheckLength("approver_member_id", decision.GetApproverMemberId(), recordIdByteCount, false),
		recordCheckLength("requester_sidecar_id", decision.GetRequesterSidecarId(), recordIdByteCount, false),
	}
	if err := errors.Join(checks...); err != nil {
		return nil, err
	}
	verdict := protocol.ApprovalVerdict(decision.GetDecision())
	if verdict != protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE && verdict != protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY {
		return nil, fmt.Errorf("%w: verdict %d", ErrRecordStoredInvalid, decision.GetDecision())
	}
	switch protocol.ApprovalChannel(decision.GetChannel()) {
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE:
		if len(decision.GetEvidenceSha256()) != 0 {
			return nil, fmt.Errorf("%w: evidence_sha256 on channel %d", ErrRecordStoredInvalid, decision.GetChannel())
		}
	case protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
		if err := recordCheckLength("evidence_sha256", decision.GetEvidenceSha256(), recordHashByteCount, false); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: channel %d", ErrRecordStoredInvalid, decision.GetChannel())
	}
	if verdict == protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE && decision.GetUses() == 0 {
		return nil, fmt.Errorf("%w: an approval of no uses", ErrRecordStoredInvalid)
	}
	if decision.GetNotAfterMillis() <= 0 {
		return nil, fmt.Errorf("%w: no expiry", ErrRecordStoredInvalid)
	}
	if decision.GetAuthPin() == nil {
		return nil, fmt.Errorf("%w: no auth pin", ErrRecordStoredInvalid)
	}
	return &StoredApprovalDecision{Decision: decision, Signed: signed, Bytes: bytes.Clone(signed.GetBody())}, nil
}

// Whether the decision verifies under its signer's key: §6.9's Signed, purpose approval, SIGNED_APPROVAL_DECISION.
// The caller resolves Signed.key_id to the key and checks it fits the channel (§16.6's spendable).
func (self *StoredApprovalDecision) Verify(keyAlg bridge.SignedKeyAlg, publicKey []byte) error {
	return bridge.VerifySigned(self.Signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, keyAlg, publicKey)
}

// Whether the decision names this request and its action by their stored bytes: approval_id, request_sha256,
// payload_sha256 and requester_sidecar_id, the hash half of §16.6's spendable. Signer, channel, expiry, pin and
// eligibility are the spender's (ACL-M2-07, MCP-M3-03).
func (self *StoredApprovalDecision) Binds(request *StoredApprovalRequest) bool {
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	return bytes.Equal(self.Decision.GetApprovalId(), request.Request.GetApprovalId()) &&
		bytes.Equal(self.Decision.GetRequestSha256(), requestSha256[:]) &&
		bytes.Equal(self.Decision.GetPayloadSha256(), payloadSha256[:]) &&
		bytes.Equal(self.Decision.GetRequesterSidecarId(), request.Request.GetRequesterSidecarId())
}
