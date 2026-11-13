//go:build !ios_extension

// §16.6's approver side for requests (MCP-M3-07; R-MCP-7, D-MCP-6, D-MCP-14, D-MCP-17, Q-MCP-5, I-8), for a daemon
// approving another host's request through ur approve <id> and, from M8, an app: the request kind beside CORE-M2-04's
// authority kinds, whose path ur approve keeps for them, dispatching by kind.
//
//	list     RecordApprovals.Pending's requests, each rendered (ApprovalRender) or shown refused where its stored bytes
//	         do not check; on a device that is no consented, approval-capable device, nothing: a read_only, ephemeral,
//	         tagged or unconsented device gives no device evidence and shows nothing to sign (D-MCP-14)
//	decide   after the person's confirmation alone (SidecarActConfirmed: a Confirm method answered on /dev/tty, never
//	         mcp or hook), an ApprovalDecision under purpose approval, a denial too, so the requester stops waiting:
//	         channel device by the identity key, for another sidecar's request whose approvers name this device's
//	         member; for this sidecar's own request channel presence by the presence check the caller passes (the
//	         daemon's prompt, MCP-M3-09), never device, since §16.6's host table gives a daemon its own agents'
//	         requests by presence or harness alone; then FileDecision in the request's log
//	fields   requester_sidecar_id the request's, auth_pin the pin the device's state stands at, request_sha256 and
//	         payload_sha256 over the stored bytes, not_after the request's, uses 1, or for a template the person's
//	         choice of 2 or more, evidence_sha256 empty (QD-261)
//	cancel   ApprovalCancel{approval_id} by the identity key, after the same confirmation, filed in the request's log
//	sealed   a request whose action carries a sealed_detail, a dial or route grant's prefixes and ports (QD-740), is
//	         rendered with what the detail opens to on this device (WithDetailOpener); where no opener is given or
//	         the detail does not open, the render says so, the request lists deny alone, and an approval is refused,
//	         so no prefix or port is approved unseen (D-MCP-17)
//
// The pass approves nothing (§5.9): only a confirmed call reaches here. A presence check that fails, is refused or does
// not verify against a live presence key this device registered for its member signs nothing.
//
// Nothing here creates, derives or unwraps a key: Sidecar.Sign holds the identity key, and a presence key never leaves
// its authenticator. Safe for concurrent use. On every leg but the ios_extension legs.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The approval item kind of §16's requests, beside CORE-M2-04's authority kinds.
const SidecarApprovalRequest = "request"

var (
	// This sidecar's own request takes presence evidence, never device (§16.6's host table), and no presence check
	// was given.
	ErrApprovalOwnRequest = errors.New("this sidecar's own request takes a presence key's evidence, never device")
	// uses above 1 is for a template alone, and a template takes 2 or more.
	ErrApprovalUses = errors.New("uses above 1 only for a template, and a template takes 2 or more")
	// The action's sealed_detail did not open on this device, so it approves nothing it could not show (D-MCP-17).
	ErrApprovalDetailSealed = errors.New("the action's sealed detail does not open on this device, so it is not approved here")
)

// The approval family's log as an approver's device uses it: RecordApprovals (RECORD-M3-07), or a test's.
type ApproverLog interface {
	// Each request waiting in the logs this device reads, parsed and checked, or refused.
	Pending(ctx context.Context) ([]*RecordPendingApproval, error)
	// Files a decision, its Signed as stored, beside its request in logId.
	FileDecision(ctx context.Context, logId Id, storedSigned []byte, runId *Id) (*RecordEntryRef, error)
	// Files a cancel, its Signed as stored, beside its request in logId.
	FileCancel(ctx context.Context, logId Id, storedSigned []byte) (*RecordEntryRef, error)
	// The logs this device reads approvals in.
	approvalLogs() ([]Id, error)
}

var _ ApproverLog = (*RecordApprovals)(nil)

// One request as an approver's device lists it.
type SidecarRequestItem struct {
	// The zero Id for a request shown refused, whose bytes did not check.
	ApprovalId Id
	LogId      Id
	EntryId    Id
	// Nil when Refused is set.
	Render *ApprovalRender
	// Why this device will not render it, printable; empty for none. Shown refused, never approved unseen (D-MCP-17).
	Refused string
	// The channel this device signs it on: device, or presence for its own request; unspecified where it signs none.
	Channel protocol.ApprovalChannel
	// approve and deny where this device may answer, empty where it may not.
	Decisions []string
}

// What a person decided on a request.
type SidecarRequestDecision struct {
	// SidecarDecisionApprove or SidecarDecisionDeny.
	Decision string
	// How many distinct actions an approval covers (D-MCP-11): 0 and 1 mean one; 2 or more only for a template.
	Uses uint32
}

// An approver's device's side of §16.6's requests: its sidecar, for its standing and keys, its approval log, and what
// opens an action's sealed_detail, nil where the device opens none.
type ApprovalApprover struct {
	sidecar *Sidecar
	log     ApproverLog
	details CanonicalActionDetailOpener
}

// The approver side of sidecar over log.
func NewApprovalApprover(sidecar *Sidecar, log ApproverLog) *ApprovalApprover {
	return &ApprovalApprover{sidecar: sidecar, log: log}
}

// The same approver side, opening each action's sealed_detail with opener before it renders or approves it. The
// receiver is not changed.
func (self *ApprovalApprover) WithDetailOpener(opener CanonicalActionDetailOpener) *ApprovalApprover {
	return &ApprovalApprover{sidecar: self.sidecar, log: self.log, details: opener}
}

// What request's action's sealed_detail opens to on this device: nil with no error for an action that carries none,
// and ErrApprovalDetailSealed for one this device has no opener for or cannot open.
func (self *ApprovalApprover) openDetail(request *StoredApprovalRequest) (*protocol.CanonicalActionDetail, error) {
	if len(request.Action.Action.GetSealedDetail()) == 0 {
		return nil, nil
	}
	if self.details == nil {
		return nil, ErrApprovalDetailSealed
	}
	detail, err := self.details.OpenActionDetail(request.Action)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrApprovalDetailSealed, err)
	}
	if detail == nil {
		return nil, ErrApprovalDetailSealed
	}
	return detail, nil
}

// The approver side over this sidecar's record (Sidecar.Record's approvals).
func (self *Sidecar) ApprovalApprover() (*ApprovalApprover, error) {
	record, err := self.Record()
	if err != nil {
		return nil, err
	}
	return NewApprovalApprover(self, record.Approvals()), nil
}

// This device's standing to approve: the verified state, its identity and its admission, which must be a consented,
// approval-capable device of its member (§16.6's approval_capable). False where it is not.
func (self *ApprovalApprover) standing() (SidecarAuthority, *SidecarIdentity, *AclSidecar, error) {
	authority := self.sidecar.authority()
	if authority == nil {
		return nil, nil, nil, ErrSidecarActNoAuthority
	}
	identity := self.sidecar.currentIdentity()
	if identity == nil {
		return nil, nil, nil, ErrSidecarNoIdentity
	}
	own, ok := self.sidecar.approvalCapableAdmission(authority)
	if !ok || !authority.Consented(identity.SidecarId, own.MemberId) {
		return authority, identity, nil, ErrSidecarApprovalNotEligible
	}
	return authority, identity, own, nil
}

// The channel this device signs request on, and what it may answer: none where its approvers do not name this
// device's member; presence for this sidecar's own request; else device.
func approverChannel(request *StoredApprovalRequest, identity *SidecarIdentity, own *AclSidecar) (protocol.ApprovalChannel, []string) {
	named := slices.ContainsFunc(request.Request.GetApprovers(), func(approver []byte) bool {
		return bytes.Equal(approver, own.MemberId.Bytes())
	})
	if !named {
		return protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED, []string{}
	}
	decisions := []string{SidecarDecisionApprove, SidecarDecisionDeny}
	if recordIdOf(request.Request.GetRequesterSidecarId()) == identity.SidecarId {
		return protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE, decisions
	}
	return protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, decisions
}

// The requests waiting for this device's decision, each rendered, or shown refused. Empty on a device that is no
// consented, approval-capable device of its member, which shows nothing to sign (D-MCP-14).
func (self *ApprovalApprover) Pending(ctx context.Context) ([]*SidecarRequestItem, error) {
	_, identity, own, err := self.standing()
	if errors.Is(err, ErrSidecarApprovalNotEligible) {
		return []*SidecarRequestItem{}, nil
	}
	if err != nil {
		return nil, err
	}
	pending, err := self.log.Pending(ctx)
	if err != nil {
		return nil, err
	}
	items := []*SidecarRequestItem{}
	for _, waiting := range pending {
		item := &SidecarRequestItem{LogId: waiting.LogId, EntryId: waiting.EntryId, Decisions: []string{}}
		if waiting.Refused != nil || waiting.Request == nil {
			item.Refused = "this device will not render it"
			if waiting.Refused != nil {
				item.Refused = ApprovalPrintable(waiting.Refused.Error())
			}
			items = append(items, item)
			continue
		}
		item.ApprovalId = waiting.Request.ApprovalId()
		detail, detailErr := self.openDetail(waiting.Request)
		item.Render = RenderApprovalRequestDetail(waiting.Request, detail)
		item.Render.Flagged = waiting.Flagged
		item.Channel, item.Decisions = approverChannel(waiting.Request, identity, own)
		if detailErr != nil && 0 < len(item.Decisions) {
			// what it could not show it may only refuse
			item.Decisions = []string{SidecarDecisionDeny}
		}
		items = append(items, item)
	}
	return items, nil
}

// The waiting request of approvalId, with the log it is in.
func (self *ApprovalApprover) find(ctx context.Context, approvalId Id) (*RecordPendingApproval, error) {
	pending, err := self.log.Pending(ctx)
	if err != nil {
		return nil, err
	}
	for _, waiting := range pending {
		if waiting.Request != nil && waiting.Request.ApprovalId() == approvalId {
			return waiting, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrSidecarApprovalUnknown, approvalId)
}

// Signs and files a person's decision on the request approvalId, as the file header says. origin must be the
// person's confirmation; check is the presence check this sidecar's own request takes, nil where the host holds no
// presence key, which refuses an own request.
func (self *ApprovalApprover) Decide(ctx context.Context, approvalId Id, decision *SidecarRequestDecision, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if origin != SidecarActConfirmed {
		return ErrSidecarActMode
	}
	if decision == nil || (decision.Decision != SidecarDecisionApprove && decision.Decision != SidecarDecisionDeny) {
		return ErrSidecarApprovalDecision
	}
	authority, identity, own, err := self.standing()
	if err != nil {
		return err
	}
	waiting, err := self.find(ctx, approvalId)
	if err != nil {
		return err
	}
	request := waiting.Request
	channel, _ := approverChannel(request, identity, own)
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_UNSPECIFIED {
		return fmt.Errorf("%w: the request's approvers do not name this device's member", ErrSidecarApprovalNotEligible)
	}
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE && check == nil {
		return ErrApprovalOwnRequest
	}

	verdict := protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE
	uses := max(1, decision.Uses)
	if decision.Decision == SidecarDecisionDeny {
		verdict = protocol.ApprovalVerdict_APPROVAL_VERDICT_DENY
		uses = 0
	} else if (1 < uses) != request.Action.Action.GetScope() {
		return ErrApprovalUses
	} else if _, err := self.openDetail(request); err != nil {
		// an approval signs only what this device opened and showed
		return err
	}
	pin := authority.Pin()
	if pin == nil {
		return ErrSidecarActNoAuthority
	}
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(verdict),
		Uses:               uses,
		NotAfterMillis:     request.Request.GetNotAfterMillis(),
		ApproverMemberId:   own.MemberId.Bytes(),
		Channel:            uint32(channel),
		RequesterSidecarId: bytes.Clone(request.Request.GetRequesterSidecarId()),
		AuthPin:            &bridge.AuthPin{Version: pin.GetVersion(), Chain: bytes.Clone(pin.GetChain())},
		Version:            1,
	})
	if err != nil {
		return err
	}
	var signed *bridge.Signed
	if channel == protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE {
		signed, err = approverPresenceSigned(authority, identity, own, body, check)
	} else {
		signed, err = self.sidecar.Sign(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body, nil)
	}
	if err != nil {
		return err
	}
	storedSigned, err := proto.Marshal(signed)
	if err != nil {
		return err
	}
	_, err = self.log.FileDecision(ctx, waiting.LogId, storedSigned, nil)
	return err
}

// A presence decision over body: the check's evidence over §6.9's signed bytes, its key one this device registered
// for its member and live at the state, verified by §16.6's per-use profile before anything is filed. Signs nothing
// where the check fails, is refused or does not verify.
func approverPresenceSigned(authority SidecarAuthority, identity *SidecarIdentity, own *AclSidecar, body []byte, check SidecarPresenceCheck) (*bridge.Signed, error) {
	evidence, err := check(bridge.SignedBytes(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarActPresence, err)
	}
	if evidence == nil || len(evidence.GetKeyId()) == 0 || len(evidence.GetSignature()) == 0 {
		return nil, fmt.Errorf("%w: no evidence", ErrSidecarActPresence)
	}
	var key *bridge.KeyRow
	for _, liveKey := range authority.LiveKeys(identity.SidecarId) {
		if bytes.Equal(liveKey.GetKeyId(), evidence.GetKeyId()) && bytes.Equal(liveKey.GetMemberId(), own.MemberId.Bytes()) {
			key = liveKey
		}
	}
	if key == nil {
		return nil, fmt.Errorf("%w: no live presence key of this device's member has that key_id", ErrSidecarActPresence)
	}
	signed := &bridge.Signed{
		Body:      bytes.Clone(body),
		KeyId:     bytes.Clone(evidence.GetKeyId()),
		Signature: bytes.Clone(evidence.GetSignature()),
		Type:      uint32(bridge.SignedType_SIGNED_APPROVAL_DECISION),
	}
	if len(evidence.GetAuthenticatorData()) != 0 || len(evidence.GetClientDataJson()) != 0 {
		signed.Webauthn = &bridge.WebAuthnEvidence{
			AuthenticatorData: bytes.Clone(evidence.GetAuthenticatorData()),
			ClientDataJson:    bytes.Clone(evidence.GetClientDataJson()),
		}
	}
	if err := VerifyPresenceUse(signed, ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, key, nil); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSidecarActPresence, err)
	}
	return signed, nil
}

// Signs ApprovalCancel{approvalId} by the identity key and files it beside its request, in whichever of this device's
// approval logs holds it, after the person's confirmation alone. A use reserved before it still completes (§16.6's
// cancel row).
func (self *ApprovalApprover) Cancel(ctx context.Context, approvalId Id, origin SidecarActOrigin) error {
	if origin != SidecarActConfirmed {
		return ErrSidecarActMode
	}
	if _, _, _, err := self.standing(); err != nil {
		return err
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalCancel{ApprovalId: approvalId.Bytes()})
	if err != nil {
		return err
	}
	signed, err := self.sidecar.Sign(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_CANCEL, body, nil)
	if err != nil {
		return err
	}
	storedSigned, err := proto.Marshal(signed)
	if err != nil {
		return err
	}
	logIds, err := self.log.approvalLogs()
	if err != nil {
		return err
	}
	for _, logId := range logIds {
		_, err := self.log.FileCancel(ctx, logId, storedSigned)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, ErrRecordApprovalUnknown), errors.Is(err, ErrRecordApprovalTeamRoute):
			continue
		}
		return err
	}
	return fmt.Errorf("%w: %s", ErrSidecarApprovalUnknown, approvalId)
}
