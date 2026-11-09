// Authority approvals (CORE-M2-04, R-CORE-17, D-CORE-13): the core behind §18.5's GetPending and Decide and `ur
// approve <id>`, for the kinds §5.6's alarms and admissions open, dispatched by kind in one table that §16's track
// (the request kind, MCP-M3-07) and CORE-M6-04 (cleanup) join:
//
//	admission         approve signs this device's member's new device's SidecarAdmit, after the safety number;
//	                  deny dismisses
//	admission_alarm   approve signs OwnerConfirm{sidecar_id}, after the safety number; revoke hands the device to
//	                  RevokeDevice (CORE-M3-03); deny dismisses it, and a parked device stays parked
//	recovery_window   deny signs RecoveryVeto{proposal_id} on an AdminSet member's device; approve dismisses it, the
//	                  window running its course
//	recovery_rebind   revoke offers a compromise revocation of the rebind's signer (CORE-M3-03); deny dismisses it
//	recovery_unseen   revoke offers the recovered device's revocation (CORE-M3-03); deny dismisses it
//
// Every decision runs as a sidecarAct of the person's confirmation, on /dev/tty or in an app's UI, never MCP, a hook
// or an unconfirmed control call (D-CORE-13), and a covered act takes its one presence check (identity_act.go).
// Whether this device may sign is read from the verified state, never decided here: a read_only, ephemeral or tagged
// device signs none of these (§7.9), only the member's consented device signs its OwnerConfirm and scoped admission
// (§8.5), and only an AdminSet member's device vetoes. What needs k of n, an admin's admission of another member's
// device or a cosign, refuses until the verified state exposes §7.9's counted rule (TEAM-M2-10).
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The decisions an item takes.
const (
	SidecarDecisionApprove = "approve"
	SidecarDecisionDeny    = "deny"
	SidecarDecisionRevoke  = "revoke"
)

var (
	// No open item has that id, or it was decided.
	ErrSidecarApprovalUnknown = errors.New("no such approval is pending")
	// The decision is not one the item's kind takes.
	ErrSidecarApprovalDecision = errors.New("the item does not take that decision")
	// This device may not sign it: read_only, ephemeral or tagged, not consented for the member, or not an AdminSet
	// member's device.
	ErrSidecarApprovalNotEligible = errors.New("this device may not sign it")
	// The signature needs k of n, which the verified state does not yet say how to count (TEAM-M2-10).
	ErrSidecarApprovalAuthority = errors.New("this needs more than one counted signer, which this device cannot gather yet")
	// The decision's effect is another task's, not built yet: a revocation through RevokeDevice (CORE-M3-03).
	ErrSidecarApprovalUnbuilt = errors.New("that decision's effect is not built yet")
)

// One item a person decides (§18.5's SidecarApprovalItem).
type SidecarApprovalItem struct {
	ApprovalId Id
	// admission, admission_alarm, recovery_window, recovery_rebind, recovery_unseen; §16's track adds request.
	Kind string
	// The device it is about: the admitted, the alarmed, the rebind's signer or the recovered device. Nil for none.
	SidecarId *Id
	// The member it is about.
	MemberId *Id
	// A window's or a proposal's 32-byte id.
	ProposalId []byte
	// The entry that opened it, where a compromise revocation's since_n starts.
	Position uint64
	RaisedAt time.Time
	// The safety number the person compares before approving an admission or an OwnerConfirm (§5.6's genesis row),
	// 60 digits; empty where none applies or none is known.
	SafetyNumber string
	// What this device may answer it: approve, deny, revoke.
	Decisions []string
}

// A request to admit a new device of this device's member, which the device's enrollment surfaced (a `ur login`
// device's safety number shown beside it, or an invite's): opened with OpenAdmission.
type SidecarAdmissionRequest struct {
	SidecarId         Id
	MemberId          Id
	IdentityPublicKey []byte
	// SidecarCapability bits the admission carries: read_only for a page Worker, invited for an invite's first device.
	Capabilities uint32
}

// What one kind does.
type sidecarApprovalKind struct {
	// the decisions the kind takes
	decisions []string
	// the decisions this device may make on item now, from the verified state: a subset of decisions
	eligible func(self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord) []string
	// runs decision, which eligible allowed: signs what it signs as an act of origin's
	decide func(ctx context.Context, self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord, decision string, origin SidecarActOrigin, check SidecarPresenceCheck) error
}

// The kinds, by name. A track adds its kind with registerSidecarApprovalKind, at init.
var sidecarApprovalKinds = map[string]*sidecarApprovalKind{}

// Adds a kind. A second kind of one name is a programming error, found at start.
func registerSidecarApprovalKind(name string, kind *sidecarApprovalKind) {
	if kind == nil || kind.eligible == nil || kind.decide == nil || sidecarApprovalKinds[name] != nil {
		panic(fmt.Sprintf("approval kind %q registered twice or incomplete", name))
	}
	sidecarApprovalKinds[name] = kind
}

// The kinds §5.6's alarms and admissions open.
func init() {
	registerSidecarApprovalKind(SidecarApprovalAdmission, &sidecarApprovalKind{
		decisions: []string{SidecarDecisionApprove, SidecarDecisionDeny},
		eligible:  sidecarAdmissionEligible,
		decide:    sidecarDecideAdmission,
	})
	registerSidecarApprovalKind(SidecarApprovalAdmissionAlarm, &sidecarApprovalKind{
		decisions: []string{SidecarDecisionApprove, SidecarDecisionRevoke, SidecarDecisionDeny},
		eligible:  sidecarAdmissionAlarmEligible,
		decide:    sidecarDecideAdmissionAlarm,
	})
	registerSidecarApprovalKind(SidecarApprovalRecoveryWindow, &sidecarApprovalKind{
		decisions: []string{SidecarDecisionApprove, SidecarDecisionDeny},
		eligible:  sidecarRecoveryWindowEligible,
		decide:    sidecarDecideRecoveryWindow,
	})
	for _, kind := range []string{SidecarApprovalRecoveryRebind, SidecarApprovalRecoveryUnseen} {
		registerSidecarApprovalKind(kind, &sidecarApprovalKind{
			decisions: []string{SidecarDecisionRevoke, SidecarDecisionDeny},
			eligible:  sidecarRevokeOfferEligible,
			decide:    sidecarDecideRevokeOffer,
		})
	}
}

// This device's admission, if it may sign authority approvals for its member at all: admitted and not revoked,
// untagged, not ephemeral, not read_only (§7.9's signers row, §16.6's approval-capable).
func (self *Sidecar) approvalCapableAdmission(authority SidecarAuthority) (*AclSidecar, bool) {
	identity := self.currentIdentity()
	if identity == nil {
		return nil, false
	}
	own := authority.Admission(identity.SidecarId)
	if own == nil || own.Row == nil || own.Row.GetRevokedAt() != 0 || 0 < len(own.TagIds) || own.Ephemeral ||
		own.Row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0 {
		return nil, false
	}
	return own, true
}

// Whether this device is its member's consented, approval-capable device, the one that signs that member's
// OwnerConfirm and scoped admission (§8.5).
func (self *Sidecar) consentedFor(authority SidecarAuthority, memberId Id) bool {
	own, ok := self.approvalCapableAdmission(authority)
	if !ok || own.MemberId != memberId {
		return false
	}
	identity := self.currentIdentity()
	return identity != nil && authority.Consented(identity.SidecarId, memberId)
}

// An admission: only the member's consented device approves it; anyone may dismiss.
func sidecarAdmissionEligible(self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord) []string {
	if item.MemberId == nil || !self.consentedFor(authority, *item.MemberId) {
		return []string{SidecarDecisionDeny}
	}
	return []string{SidecarDecisionApprove, SidecarDecisionDeny}
}

// An admission alarm: the member's consented device approves or revokes; anyone may dismiss.
func sidecarAdmissionAlarmEligible(self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord) []string {
	decisions := []string{SidecarDecisionDeny}
	if item.MemberId != nil && self.consentedFor(authority, *item.MemberId) {
		decisions = append([]string{SidecarDecisionApprove, SidecarDecisionRevoke}, decisions...)
	}
	return decisions
}

// A recovery window: an AdminSet member's approval-capable device vetoes, never the proposed device; anyone lets it
// run.
func sidecarRecoveryWindowEligible(self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord) []string {
	own, ok := self.approvalCapableAdmission(authority)
	identity := self.currentIdentity()
	adminSet := false
	if record, err := self.loadAlarmRecord(); err == nil && ok {
		adminSet = slices.Contains(record.AdminMemberIds, own.MemberId)
	}
	// never the proposed device itself
	proposed := item.SidecarId != nil && identity != nil && *item.SidecarId == identity.SidecarId
	if !ok || !adminSet || proposed {
		return []string{SidecarDecisionApprove}
	}
	return []string{SidecarDecisionApprove, SidecarDecisionDeny}
}

// A rebind or an unseen recovery: an approval-capable device revokes; anyone may dismiss.
func sidecarRevokeOfferEligible(self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord) []string {
	if _, ok := self.approvalCapableAdmission(authority); !ok {
		return []string{SidecarDecisionDeny}
	}
	return []string{SidecarDecisionRevoke, SidecarDecisionDeny}
}

// The admission request an item carries, from its record.
func (self *sidecarApprovalRecord) admissionRequest() (*SidecarAdmissionRequest, error) {
	if self.SidecarId == nil || self.MemberId == nil || len(self.IdentityPublicKey) == 0 {
		return nil, ErrSidecarApprovalUnknown
	}
	return &SidecarAdmissionRequest{
		SidecarId:         *self.SidecarId,
		MemberId:          *self.MemberId,
		IdentityPublicKey: bytes.Clone(self.IdentityPublicKey),
		Capabilities:      self.Capabilities,
	}, nil
}

// Signs an admission's or an OwnerConfirm's statement as an act of origin's, the presence check where the log covers it.
// When it admits or confirms a page Worker, workerId, the act also carries §7.10's stale revocations of that member's
// other Workers this device sees as stale, posted first (identity_act_stale.go). A group view that cannot answer
// revokes nothing, and the admission goes on: no revocation is signed without the evidence.
func (self *Sidecar) runAdmissionAct(ctx context.Context, origin SidecarActOrigin, check SidecarPresenceCheck, memberId Id,
	workerId *Id, signedType bridge.SignedType, statement proto.Message) error {
	act, err := self.newAct(origin)
	if err != nil {
		return err
	}
	if err := act.Add(signedType, statement); err != nil {
		return err
	}
	if workerId != nil {
		revocations, err := act.AddStaleRevocations(ctx, memberId, workerId)
		switch {
		case err != nil:
			self.log.Infof("[identity]no stale Worker revoked with this admission: %s", err)
		case self.log.V(1).Enabled():
			self.log.Infof("[identity]%d stale Workers revoked with this admission, %d offered", len(revocations.Revoked), len(revocations.Offered))
		}
	}
	_, err = act.Run(ctx, check)
	return err
}

// Whether the device is a page Worker: admitted, or to be admitted, read_only (§18.8).
func sidecarIsPageWorker(capabilities uint32) bool {
	return capabilities&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0
}

// Signs one statement as an act of origin's, the presence check where the log covers it.
func (self *Sidecar) runOneStatement(ctx context.Context, origin SidecarActOrigin, check SidecarPresenceCheck, signedType bridge.SignedType, statement proto.Message) error {
	act, err := self.newAct(origin)
	if err != nil {
		return err
	}
	if err := act.Add(signedType, statement); err != nil {
		return err
	}
	_, err = act.Run(ctx, check)
	return err
}

// approve: the member's consented device admits its member's new device alone, the scoped case (§7.9's signers row).
// Every other admission needs counted signers, which the verified state does not yet expose.
func sidecarDecideAdmission(ctx context.Context, self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord, decision string, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if decision != SidecarDecisionApprove {
		return nil
	}
	request, err := item.admissionRequest()
	if err != nil {
		return err
	}
	identity := self.currentIdentity()
	if identity == nil {
		return ErrSidecarNoIdentity
	}
	if !self.consentedFor(authority, request.MemberId) {
		return ErrSidecarApprovalAuthority
	}
	// a page Worker's admission carries §7.10's stale revocations of its member's other Workers (D-TEAM-29)
	var workerId *Id
	if sidecarIsPageWorker(request.Capabilities) {
		workerId = &request.SidecarId
	}
	// after an admission the signer commits the device's Add or first wrap in the config group (§5.6's reads row),
	// which GkmClient's config-group commit does once KEYS lands it: any writer leaf commits it meanwhile
	return self.runAdmissionAct(ctx, origin, check, request.MemberId, workerId, bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		NetworkId:         identity.NetworkId.Bytes(),
		SidecarId:         request.SidecarId.Bytes(),
		IdentityPublicKey: request.IdentityPublicKey,
		IdentityAlg:       configIdentityAlgEd25519,
		MemberId:          request.MemberId.Bytes(),
		Capabilities:      request.Capabilities,
	})
}

// approve signs OwnerConfirm{sidecar_id}; revoke is RevokeDevice's (CORE-M3-03); deny dismisses, signing nothing,
// so a parked device stays parked.
func sidecarDecideAdmissionAlarm(ctx context.Context, self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord, decision string, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	switch decision {
	case SidecarDecisionApprove:
		if item.SidecarId == nil {
			return ErrSidecarApprovalUnknown
		}
		// the member's OwnerConfirm of an admin-admitted page Worker carries §7.10's stale revocations its groups show
		var workerId *Id
		if admission := authority.Admission(*item.SidecarId); item.MemberId != nil && admission != nil && admission.Row != nil &&
			sidecarIsPageWorker(admission.Row.GetCapabilities()) {
			workerId = item.SidecarId
		}
		memberId := Id{}
		if item.MemberId != nil {
			memberId = *item.MemberId
		}
		return self.runAdmissionAct(ctx, origin, check, memberId, workerId, bridge.SignedType_SIGNED_OWNER_CONFIRM,
			&protocol.OwnerConfirm{SidecarId: item.SidecarId.Bytes()})
	case SidecarDecisionRevoke:
		return fmt.Errorf("%w: RevokeDevice is CORE-M3-03's", ErrSidecarApprovalUnbuilt)
	}
	return nil
}

// deny signs RecoveryVeto{proposal_id}; approve dismisses, the window running its course.
func sidecarDecideRecoveryWindow(ctx context.Context, self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord, decision string, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if decision != SidecarDecisionDeny {
		return nil
	}
	proposalId, err := hex.DecodeString(item.ProposalId)
	if err != nil || len(proposalId) != 32 {
		return ErrSidecarApprovalUnknown
	}
	return self.runOneStatement(ctx, origin, check, bridge.SignedType_SIGNED_RECOVERY_VETO, &protocol.RecoveryVeto{ProposalId: proposalId})
}

// revoke offers a compromise revocation, RevokeDevice's (CORE-M3-03); deny dismisses.
func sidecarDecideRevokeOffer(ctx context.Context, self *Sidecar, authority SidecarAuthority, item *sidecarApprovalRecord, decision string, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if decision == SidecarDecisionRevoke {
		return fmt.Errorf("%w: a compromise revocation is CORE-M3-03's RevokeDevice", ErrSidecarApprovalUnbuilt)
	}
	return nil
}

// The safety number of item's device, over this sidecar's anchored genesis and the device's identity key; empty where
// either is unknown.
func (self *Sidecar) itemSafetyNumber(authority SidecarAuthority, item *sidecarApprovalRecord) string {
	if item.Kind != SidecarApprovalAdmission && item.Kind != SidecarApprovalAdmissionAlarm {
		return ""
	}
	anchor, err := self.Anchor()
	if err != nil {
		return ""
	}
	identityPublicKey := item.IdentityPublicKey
	if len(identityPublicKey) == 0 && item.SidecarId != nil {
		if admission := authority.Admission(*item.SidecarId); admission != nil && admission.Row != nil {
			identityPublicKey = admission.Row.GetIdentityPublicKey()
		}
	}
	number, err := SafetyNumber(anchor.GenesisSha256, identityPublicKey)
	if err != nil {
		return ""
	}
	return number
}

// What waits for this device's decision: every open item, with the decisions this device may make on it now, the
// safety number where an approval needs it. ErrSidecarActNoAuthority with no verified state installed.
func (self *Sidecar) PendingApprovals() ([]*SidecarApprovalItem, error) {
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	record, err := func() (*sidecarAlarmRecord, error) {
		self.alarms.stateLock.Lock()
		defer self.alarms.stateLock.Unlock()
		return self.loadAlarmRecord()
	}()
	if err != nil {
		return nil, err
	}
	items := []*SidecarApprovalItem{}
	for _, item := range record.Items {
		kind := sidecarApprovalKinds[item.Kind]
		if item.Decided || kind == nil {
			continue
		}
		approvalItem := &SidecarApprovalItem{
			ApprovalId:   item.ItemId,
			Kind:         item.Kind,
			SidecarId:    item.SidecarId,
			MemberId:     item.MemberId,
			Position:     item.Position,
			RaisedAt:     time.UnixMilli(item.RaisedAtMs),
			SafetyNumber: self.itemSafetyNumber(authority, item),
			Decisions:    kind.eligible(self, authority, item),
		}
		if item.ProposalId != "" {
			approvalItem.ProposalId, _ = hex.DecodeString(item.ProposalId)
		}
		items = append(items, approvalItem)
	}
	return items, nil
}

// Decides one open item: decision is one the item's kind takes and this device may make, origin a person's
// confirmation, never MCP, a hook or an unconfirmed control call (D-CORE-13), and check the presence check a covered
// act runs. The item closes once its decision's statement is signed and kept, or at once for a dismissal; a post whose
// answer was lost answers ErrSidecarActPending, its statement going again with the same bytes (identity_pending.go).
func (self *Sidecar) DecideApproval(ctx context.Context, approvalId Id, decision string, origin SidecarActOrigin, check SidecarPresenceCheck) error {
	if origin != SidecarActConfirmed {
		return ErrSidecarActMode
	}
	authority := self.authority()
	if authority == nil {
		return ErrSidecarActNoAuthority
	}
	item, err := func() (*sidecarApprovalRecord, error) {
		self.alarms.stateLock.Lock()
		defer self.alarms.stateLock.Unlock()
		record, err := self.loadAlarmRecord()
		if err != nil {
			return nil, err
		}
		for _, item := range record.Items {
			if item.ItemId == approvalId && !item.Decided {
				copied := *item
				return &copied, nil
			}
		}
		return nil, ErrSidecarApprovalUnknown
	}()
	if err != nil {
		return err
	}
	kind := sidecarApprovalKinds[item.Kind]
	if kind == nil || !slices.Contains(kind.decisions, decision) {
		return ErrSidecarApprovalDecision
	}
	if !slices.Contains(kind.eligible(self, authority, item), decision) {
		return ErrSidecarApprovalNotEligible
	}
	// a statement signed and pending is a decision made: the item closes, and its post goes again on its own
	decideErr := kind.decide(ctx, self, authority, item, decision, origin, check)
	if decideErr != nil && !errors.Is(decideErr, ErrSidecarActPending) {
		return decideErr
	}
	self.alarms.stateLock.Lock()
	defer self.alarms.stateLock.Unlock()
	record, err := self.loadAlarmRecord()
	if err != nil {
		return err
	}
	for _, held := range record.Items {
		if held.ItemId == approvalId {
			held.Decided = true
			held.Decision = decision
		}
	}
	if err := self.persistAlarmRecord(record); err != nil {
		return err
	}
	return decideErr
}

// Opens an admission item for a new device of this device's member, which PendingApprovals lists with its safety
// number until a person decides it. Answers its id.
func (self *Sidecar) OpenAdmission(request *SidecarAdmissionRequest) (Id, error) {
	if request == nil || len(request.IdentityPublicKey) == 0 {
		return Id{}, ErrSidecarApprovalUnknown
	}
	self.alarms.stateLock.Lock()
	defer self.alarms.stateLock.Unlock()
	record, err := self.loadAlarmRecord()
	if err != nil {
		return Id{}, err
	}
	itemId := sidecarApprovalItemId(SidecarApprovalAdmission, append(request.SidecarId.Bytes(), request.IdentityPublicKey...), 0)
	sidecarId := request.SidecarId
	memberId := request.MemberId
	record.open(&sidecarApprovalRecord{
		ItemId:            itemId,
		Kind:              SidecarApprovalAdmission,
		SidecarId:         &sidecarId,
		MemberId:          &memberId,
		IdentityPublicKey: bytes.Clone(request.IdentityPublicKey),
		Capabilities:      request.Capabilities,
		RaisedAtMs:        self.clock.Now().UnixMilli(),
	})
	return itemId, self.persistAlarmRecord(record)
}
