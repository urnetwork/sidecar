//go:build !ios_extension

// §16.6's harness_ok, its state half, and the harness decision it lets this daemon sign (D-MCP-9, D-MCP-14, Q-MCP-3,
// Q-MCP-6, I-8, I-9, FS-28; MCP-M3-10): whether this sidecar may approve its own request on the evidence of the
// harness's prompt, read at P from the config alone. The event half, the hook event or the /dev/tty confirmation that
// asked about the call, is mcp/harness_evidence.go's, since only ur links the hooks.
//
//	requester  s is an untagged sidecar of member M, consented and approval-capable: consented(d, M), not tagged,
//	           ephemeral, read_only or suspended, since a read_only device signs no decision (D-MCP-14)
//	approver   M is an approver §8 requires of the action, and the request names M among its approvers
//	alone      M has no approval-capable device other than s and no presence key live at P: a Worker or any other
//	           read_only device keeps harness_ok, a second CLI clears it (D-MCP-14), and a presence key prompts instead
//	evidence   the governing evidence list, the matching requests rule's, else evidenceDefault, holds harness
//	taint      the request is untainted and so is its run now; in a tainted one only a requests rule whose own list
//	           names harness lets it count, never evidenceDefault (owner decision 142, Q-MCP-6)
//	kinds      an O tool's own kind alone, and never a template, whose uses a person sets: so a harness decision never
//	           authorizes a KeyRegister, KeyRevoke, RecoveryBind, RecoveryRebind, OwnerConfirm, admission, authority
//	           statement or revocation of another of the member's devices, which are signed directly, for a
//	           /dev/tty-confirmed command or in an app's UI (D-CORE-13)
//
// The decision: approve, one use, channel harness, not after the event's time plus Ingest.HarnessEvidenceTimeout or
// the request's own not_after, whichever is sooner (MCP.md's reading 4), evidence_sha256 the leaf of the hook_event
// entry that asked (RECORD.md section 5.1), the pin P it was judged at, signed with this sidecar's identity key. No
// gate sees harness_ok's conditions, taint above all, so spendable takes a harness decision's signer as s itself and
// nothing more (record_spend.go): the conditions are the signing daemon's alone, which is why this file is the place
// they hold.
//
// Nothing here creates, derives or unwraps a key. Package-level functions are safe for concurrent use, and so is a
// ConfigApprovalStates, which is immutable. On every leg but the ios_extension legs.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// harness_ok does not hold: the error says which condition failed, ids only.
var ErrHarnessNotOk = errors.New("harness evidence does not count")

// The kinds a harness decision may approve: §16.5's outward tools' own, a closed list. Everything else a person signs
// directly (D-MCP-9).
var harnessDecisionKinds = []SidecarActionKind{
	SidecarActionPublish,
	SidecarActionListen,
	SidecarActionForward,
	SidecarActionExpose,
	SidecarActionAliasCreate,
	SidecarActionAliasDelete,
	SidecarActionAgentConfigWrite,
	SidecarActionAgentConfigDelete,
	SidecarActionDnsSet,
	SidecarActionDnsDelete,
	SidecarActionMail,
	SidecarActionAccessRequest,
	SidecarActionRestore,
}

// Whether a harness decision may approve an action of kind.
func HarnessDecisionKind(kind SidecarActionKind) bool {
	return slices.Contains(harnessDecisionKinds, kind)
}

// What harness_ok reads of P beyond the approval states: the member a device is, and the member's other approval
// channels.
type HarnessStates interface {
	ApprovalStates
	// The member whose untagged, consented device the sidecar is at P, false for none.
	DeviceMember(sidecarId Id) (Id, bool)
	// Whether the member has an approval-capable device at P other than except.
	OtherApprovalCapable(memberId Id, except Id) bool
	// Whether a presence key of the member is live at P.
	HoldsPresenceKey(memberId Id) bool
}

var _ HarnessStates = (*ConfigApprovalStates)(nil)

// The member an untagged row names, when the device is consented for it.
func (self *ConfigApprovalStates) DeviceMember(sidecarId Id) (Id, bool) {
	memberId, ok := configRowMember(self.config.sidecars[sidecarId])
	if !ok || !self.acl.ConsentedFor(sidecarId, memberId) {
		return Id{}, false
	}
	return memberId, true
}

// Any sidecar of the state but except that is an approval-capable device of the member.
func (self *ConfigApprovalStates) OtherApprovalCapable(memberId Id, except Id) bool {
	for sidecarId := range self.config.sidecars {
		if sidecarId != except && self.ApprovalCapable(sidecarId, memberId) {
			return true
		}
	}
	return false
}

// Any registered key the spend check would take as the member's presence key at P.
func (self *ConfigApprovalStates) HoldsPresenceKey(memberId Id) bool {
	for _, key := range self.config.keys {
		if self.PresenceKey(key.GetKeyId(), memberId) != nil {
			return true
		}
	}
	return false
}

// What harness_ok judges: this daemon's own request, as stored, and its run's taint now.
type HarnessOkArgs struct {
	Request *StoredApprovalRequest
	// s: this sidecar, which filed the request and would sign and spend the decision.
	Requester Id
	// The request's run reads tainted now: a run tainted since its filing counts as tainted (TS1).
	RunTainted bool
	Now        time.Time
}

// §16.6's harness_ok, its state half (see the file header): the member a harness decision would approve for, or
// ErrHarnessNotOk naming the condition that failed.
func HarnessOk(states HarnessStates, args *HarnessOkArgs) (Id, error) {
	refuse := func(condition string) (Id, error) {
		return Id{}, fmt.Errorf("%w: %s", ErrHarnessNotOk, condition)
	}
	if states == nil || args == nil || args.Request == nil || args.Request.Request == nil || args.Request.Action == nil {
		return refuse("nothing to judge")
	}
	request := args.Request
	action := request.Action
	if !bytes.Equal(request.Request.GetRequesterSidecarId(), args.Requester.Bytes()) {
		return refuse("another sidecar's request")
	}
	if !HarnessDecisionKind(SidecarActionKind(action.Action.GetKind())) {
		return refuse("a kind a person signs directly")
	}
	if action.Action.GetScope() {
		return refuse("a template, whose uses a person sets")
	}
	memberId, ok := states.DeviceMember(args.Requester)
	if !ok || !states.ApprovalCapable(args.Requester, memberId) {
		return refuse("the requester is no approval-capable device of a member")
	}
	approvers, err := states.Approvers(action, args.Requester, args.Now)
	if err != nil || !slices.Contains(approvers, memberId) {
		return refuse("the member is not an approver the action requires")
	}
	named := false
	for _, approver := range request.Request.GetApprovers() {
		named = named || bytes.Equal(approver, memberId.Bytes())
	}
	if !named {
		return refuse("the request names another approver")
	}
	if states.OtherApprovalCapable(memberId, args.Requester) {
		return refuse("the member has another approval-capable device")
	}
	if states.HoldsPresenceKey(memberId) {
		return refuse("the member holds a presence key")
	}
	rule, err := states.Govern(action, args.Requester, args.Now)
	if err != nil || !slices.Contains(rule.Evidence(), protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS) {
		return refuse("the governing evidence list does not hold harness")
	}
	if (request.Request.GetTainted() || args.RunTainted) && !states.RuleNamesHarness(action) {
		return refuse("a tainted run, and no requests rule of its own names harness")
	}
	return memberId, nil
}

// A harness decision's body on request: approve, one use, channel harness, approver memberId, evidence_sha256 the
// leaf of the hook_event entry that asked, notAfter the sooner of the evidence's bound and the request's, and pin
// the P it was judged at. Deterministic bytes.
func HarnessDecisionBody(request *StoredApprovalRequest, memberId Id, pin *bridge.AuthPin, evidenceSha256 []byte, notAfter time.Time) ([]byte, error) {
	if request == nil || request.Request == nil || request.Action == nil || pin == nil {
		return nil, fmt.Errorf("%w: a decision on nothing", ErrHarnessNotOk)
	}
	if len(evidenceSha256) != sha256.Size {
		return nil, fmt.Errorf("%w: no hook event's leaf to cite", ErrHarnessNotOk)
	}
	notAfterMillis := min(notAfter.UnixMilli(), request.Request.GetNotAfterMillis())
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	return proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.ApprovalDecision{
		ApprovalId:         bytes.Clone(request.Request.GetApprovalId()),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     notAfterMillis,
		ApproverMemberId:   memberId.Bytes(),
		Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS),
		EvidenceSha256:     bytes.Clone(evidenceSha256),
		RequesterSidecarId: bytes.Clone(request.Request.GetRequesterSidecarId()),
		AuthPin:            &bridge.AuthPin{Version: pin.GetVersion(), Chain: bytes.Clone(pin.GetChain())},
		Version:            1,
	})
}

// Signs a harness decision on this sidecar's own request with its identity key: the Signed as stored, which the gate's
// inbox takes and spends. The caller has held the request to HarnessOk and found the event it cites.
func (self *Sidecar) SignHarnessDecision(request *StoredApprovalRequest, memberId Id, pin *bridge.AuthPin, evidenceSha256 []byte, notAfter time.Time) ([]byte, error) {
	identity := self.Identity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	if !bytes.Equal(request.Request.GetRequesterSidecarId(), identity.SidecarId.Bytes()) {
		return nil, fmt.Errorf("%w: another sidecar's request", ErrHarnessNotOk)
	}
	body, err := HarnessDecisionBody(request, memberId, pin, evidenceSha256, notAfter)
	if err != nil {
		return nil, err
	}
	signed, err := self.Sign(ApprovalPurpose, bridge.SignedType_SIGNED_APPROVAL_DECISION, body, nil)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(signed)
}
