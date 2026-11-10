// PreviewDeviceRevoke (CORE-M3-02, D-CORE-20, I-4, I-15, FS-98; DESIGN-DETAILS 5.7): the plan of §5.6's revocation of
// another of this member's devices, derived at the tip from §7.9's verified state alone, which a person reads before
// confirming and RevokeDevice re-derives before it signs (identity_revoke_device.go).
//
//	caller   this sidecar, approval-capable for its member M and not suspended, as the log says
//	         (SidecarRevokeAuthority.ApprovalCapable): else REVOKE_NOT_CAPABLE, a read_only page Worker, a quick burner,
//	         a tagged sidecar and an unconsented device included
//	scope    a sidecar whose untagged admission names M, parked, stale, revoked and admin-admitted ones included: never
//	         this sidecar (REVOKE_SELF), nor another member's, a tagged one M sponsors or an unknown id (REVOKE_NOT_OWN)
//	reasons  lost: no cascade, and lostAt and sinceN are ignored; compromise: since_n is the first entry timed at or
//	         after the loss time (SidecarAuthority.ProposedSince), which a person may move earlier, never later, never
//	         past the tip, and never from a loss time in the future (REVOKE_SINCE)
//	plan     §7.9's cascade from since_n as the authority derives it (SidecarAuthority.Cascade): what P parks and
//	         voids, what stands, and who sealed keychain.wrap to a binding it voids; each confirmation a sidecar of P
//	         gave from the position P held it, with its position (rows keep every one, DESIGN-DETAILS 5.2.2); each
//	         presence or SSH key the target registered that the cascade does not void, offered for KeyRevoke; the counted
//	         signatures, 1 or k for an AdminSet member's device; and Presence, set from the log
//	         (SidecarAuthority.PresenceRequired), never by the caller. REVOKE_PARKS_SELF names the entry that puts this
//	         sidecar in P.
//
// A target already revoked answers that entry as a stands row, with its key items still registered, and signs no
// second SidecarRevoke, except a compromise revocation after a lost or removed one, or from an earlier since_n than
// its standing compromise one, which signs anew.
//
// PlanId is fixed here, with vectors in testdata/revoke_plan/: the first 16 bytes of
//
//	SHA-256("urnetwork-sidecar-v1/revoke-plan" || 0x00 || sidecar_id, 16 B || u64be(revoked_at) ||
//	        u64be(standing_since_n) || u8(reason) || u64be(since_n) || u32be(signatures) || u8(presence) ||
//	        u32be(key count) || each key item's u16be(length) || key_id, in key_id byte order)
//
// where revoked_at is the entry that revoked the target, 0 while it stands; standing_since_n the since_n of its
// standing compromise revocation, 0 for none; and reason SidecarRevokeReason's value, 1 lost or 4 compromise. It names
// no statement header, so it survives a header signed again, and no cascade item, so park and void items that entered
// after a preview are no reason for REVOKE_STALE (§5.6's sign row).
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// DeviceRevokePlan.Reason's values, SidecarRevoke's reasons a member gives (§7.9).
const (
	DeviceRevokeLost       = "lost"
	DeviceRevokeCompromise = "compromise"
)

// §5.6's REVOKE_ codes, DeviceRevokeError.Code's values.
const (
	DeviceRevokeCodeSelf       = "REVOKE_SELF"
	DeviceRevokeCodeNotOwn     = "REVOKE_NOT_OWN"
	DeviceRevokeCodeNotCapable = "REVOKE_NOT_CAPABLE"
	DeviceRevokeCodeCancelled  = "REVOKE_CANCELLED"
	DeviceRevokeCodeSince      = "REVOKE_SINCE"
	DeviceRevokeCodeParksSelf  = "REVOKE_PARKS_SELF"
	DeviceRevokeCodeStale      = "REVOKE_STALE"
	DeviceRevokeCodeRefused    = "REVOKE_REFUSED"
)

// DeviceRevokeItem's effects and the kinds this file adds to the cascade's.
const (
	DeviceRevokeEffectPark   = "park"
	DeviceRevokeEffectVoid   = "void"
	DeviceRevokeEffectStands = "stands"
	DeviceRevokeEffectReseal = "reseal"
	DeviceRevokeEffectKey    = "key"

	DeviceRevokeKindDevice       = "device"
	DeviceRevokeKindKey          = "key"
	DeviceRevokeKindConfirmation = "confirmation"
	DeviceRevokeKindRevocation   = "revocation"
)

const (
	deviceRevokePlanIdLabel = "urnetwork-sidecar-v1/revoke-plan"
	// the previews a Sidecar keeps for RevokeDevice, the oldest going first
	deviceRevokePreviewMaxCount = 32
)

// A reason that is neither lost nor compromise.
var ErrSidecarRevokeReason = errors.New("a device revocation's reason is lost or compromise")

// What a PlanId covers.
type deviceRevokePlanIdFields struct {
	sidecarId Id
	// the entry that revoked the target, 0 while it stands
	revokedAt uint64
	// the since_n of its standing compromise revocation, 0 for none
	standingSinceN uint64
	reason         bridge.SidecarRevokeReason
	sinceN         uint64
	signatures     int
	presence       bool
	keyIds         [][]byte
}

// The PlanId of fields, in the encoding this file's head fixes.
func deviceRevokePlanId(fields *deviceRevokePlanIdFields) Id {
	keyIds := slices.Clone(fields.keyIds)
	slices.SortFunc(keyIds, bytes.Compare)
	encoded := make([]byte, 0, 128)
	encoded = append(encoded, deviceRevokePlanIdLabel...)
	encoded = append(encoded, 0)
	encoded = append(encoded, fields.sidecarId[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, fields.revokedAt)
	encoded = binary.BigEndian.AppendUint64(encoded, fields.standingSinceN)
	encoded = append(encoded, byte(fields.reason))
	encoded = binary.BigEndian.AppendUint64(encoded, fields.sinceN)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(fields.signatures))
	if fields.presence {
		encoded = append(encoded, 1)
	} else {
		encoded = append(encoded, 0)
	}
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(keyIds)))
	for _, keyId := range keyIds {
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(keyId)))
		encoded = append(encoded, keyId...)
	}
	digest := sha256.Sum256(encoded)
	return Id(digest[:len(Id{})])
}

// A plan as derived at one state, with what RevokeDevice signs from it.
type deviceRevokeDerivation struct {
	plan   *DeviceRevokePlan
	reason bridge.SidecarRevokeReason
	// whether a SidecarRevoke is signed: false for a target whose standing revocation already covers the plan
	signsRevoke bool
	// the entry that revoked the target, 0 while it stands
	revokedAt uint64
	// the pin the plan was derived at
	at *bridge.AuthPin
}

// The plan's key item ids.
func (self *deviceRevokeDerivation) keyIds() [][]byte {
	keyIds := [][]byte{}
	for _, item := range self.plan.Items {
		if item.Effect == DeviceRevokeEffectKey {
			keyIds = append(keyIds, item.Id)
		}
	}
	return keyIds
}

// One previewed plan, kept for RevokeDevice.
type sidecarRevokePreview struct {
	derivation *deviceRevokeDerivation
}

// The previews a Sidecar holds, in memory only, under their own lock.
type sidecarRevokePlans struct {
	stateLock sync.Mutex
	// oldest first
	previews []*sidecarRevokePreview
}

// Keeps a derived plan for RevokeDevice, replacing one of the same PlanId.
func (self *Sidecar) keepRevokePreview(derivation *deviceRevokeDerivation) {
	self.revokePlans.stateLock.Lock()
	defer self.revokePlans.stateLock.Unlock()
	self.revokePlans.previews = slices.DeleteFunc(self.revokePlans.previews, func(preview *sidecarRevokePreview) bool {
		return preview.derivation.plan.PlanId == derivation.plan.PlanId
	})
	self.revokePlans.previews = append(self.revokePlans.previews, &sidecarRevokePreview{derivation: derivation})
	if deviceRevokePreviewMaxCount < len(self.revokePlans.previews) {
		self.revokePlans.previews = self.revokePlans.previews[len(self.revokePlans.previews)-deviceRevokePreviewMaxCount:]
	}
}

// The preview of planId, nil for one never previewed here or since dropped.
func (self *Sidecar) revokePreview(planId Id) *deviceRevokeDerivation {
	self.revokePlans.stateLock.Lock()
	defer self.revokePlans.stateLock.Unlock()
	for _, preview := range self.revokePlans.previews {
		if preview.derivation.plan.PlanId == planId {
			return preview.derivation
		}
	}
	return nil
}

// Drops the preview of planId, once it is signed.
func (self *Sidecar) dropRevokePreview(planId Id) {
	self.revokePlans.stateLock.Lock()
	defer self.revokePlans.stateLock.Unlock()
	self.revokePlans.previews = slices.DeleteFunc(self.revokePlans.previews, func(preview *sidecarRevokePreview) bool {
		return preview.derivation.plan.PlanId == planId
	})
}

// A SidecarRevoke's bytes with no header, as PresenceRequired and ProposalRequired read a statement to be signed.
func deviceRevokeStatement(signerId Id, signedType bridge.SignedType, statement proto.Message) *SidecarStatement {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(statement)
	if err != nil {
		body = nil
	}
	return &SidecarStatement{SignerId: signerId, Type: signedType, Body: body}
}

// The since_n of the target's standing compromise revocation, 0 for none: its cascade span that ends at the entry
// that revoked it (SidecarRow.cascades). A later compromise revocation of a device already revoked leaves a span rows
// cannot tell from another cascade's hold, so it is not read here, and a plan from no earlier a since_n then signs
// again, which is idempotent.
func deviceRevokeStandingSince(row *bridge.SidecarRow) uint64 {
	standing := uint64(0)
	for _, span := range row.GetCascades() {
		if span.GetUntil() == row.GetRevokedAt() && (standing == 0 || span.GetFrom() < standing) {
			standing = span.GetFrom()
		}
	}
	return standing
}

// Derives the plan of revoking sidecarId at authority's newest state. sinceFixed is a since_n already settled, by an
// earlier preview or an alarm; else lostAt and sinceN are the person's, as PreviewDeviceRevoke takes them.
func (self *Sidecar) deriveDeviceRevoke(authority SidecarAuthority, identity *SidecarIdentity, sidecarId Id, reason string, lostAt time.Time, sinceN uint64, sinceFixed bool) (*deviceRevokeDerivation, error) {
	refuse := func(code string) (*deviceRevokeDerivation, error) {
		return nil, &DeviceRevokeError{Code: code}
	}
	revokes, ok := authority.(SidecarRevokeAuthority)
	if !ok {
		// whether this device is approval-capable and unsuspended is unknown: it revokes nothing
		return refuse(DeviceRevokeCodeNotCapable)
	}
	own, capable := self.approvalCapableAdmission(authority)
	if !capable || !revokes.ApprovalCapable(identity.SidecarId) || revokes.Suspended(identity.SidecarId) {
		return refuse(DeviceRevokeCodeNotCapable)
	}
	var revokeReason bridge.SidecarRevokeReason
	switch reason {
	case DeviceRevokeLost:
		revokeReason = bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST
	case DeviceRevokeCompromise:
		revokeReason = bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE
	default:
		return nil, ErrSidecarRevokeReason
	}
	if sidecarId == identity.SidecarId {
		return refuse(DeviceRevokeCodeSelf)
	}
	target := authority.Admission(sidecarId)
	if target == nil || target.Row == nil || 0 < len(target.TagIds) || target.MemberId != own.MemberId {
		return refuse(DeviceRevokeCodeNotOwn)
	}
	pin := authority.Pin()
	if pin == nil {
		return nil, ErrSidecarActNoAuthority
	}
	tip := pin.GetVersion()

	plan := &DeviceRevokePlan{SidecarId: sidecarId, Reason: reason, Items: []DeviceRevokeItem{}}
	derivation := &deviceRevokeDerivation{
		plan:        plan,
		reason:      revokeReason,
		signsRevoke: true,
		revokedAt:   target.Row.GetRevokedAt(),
		at:          pin,
	}
	standingSinceN := uint64(0)
	if derivation.revokedAt != 0 {
		standingSinceN = deviceRevokeStandingSince(target.Row)
	}

	voidedKeyIds := [][]byte{}
	if revokeReason == bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_COMPROMISE {
		if sinceFixed {
			if sinceN == 0 || tip < sinceN {
				return refuse(DeviceRevokeCodeSince)
			}
		} else {
			proposed := uint64(0)
			if !lostAt.IsZero() {
				if self.clock.Now().Before(lostAt) {
					return refuse(DeviceRevokeCodeSince)
				}
				proposed = tip
				if n, _, found := authority.ProposedSince(lostAt); found && n < tip {
					proposed = n
				}
			}
			switch {
			case sinceN == 0 && proposed == 0:
				// no loss time and no position: nothing says where P starts
				return refuse(DeviceRevokeCodeSince)
			case sinceN == 0:
				sinceN = proposed
			case tip < sinceN || (proposed != 0 && proposed < sinceN):
				return refuse(DeviceRevokeCodeSince)
			}
		}
		plan.SinceN = sinceN
		if sinceTime, found := revokes.EntryTime(sinceN); found {
			plan.SinceTime = sinceTime
		}
		items, err := authority.Cascade(sidecarId, sinceN)
		if err != nil {
			return nil, err
		}
		held := map[Id]uint64{sidecarId: sinceN}
		for _, item := range items {
			if item.Effect == DeviceRevokeEffectPark && item.Kind == DeviceRevokeKindDevice {
				if parkedId, err := IdFromBytes(item.Id); err == nil {
					if parkedId == identity.SidecarId {
						return nil, &DeviceRevokeError{Code: DeviceRevokeCodeParksSelf, Position: item.Position}
					}
					held[parkedId] = item.Position
				}
			}
			if item.Effect == DeviceRevokeEffectVoid && item.Kind == DeviceRevokeKindKey {
				voidedKeyIds = append(voidedKeyIds, item.Id)
			}
		}
		plan.Items = append(plan.Items, items...)
		plan.Items = append(plan.Items, deviceRevokeConfirmationItems(authority, own.MemberId, held)...)
		// a standing compromise revocation from no later a since_n already covers this one
		if derivation.revokedAt != 0 && standingSinceN != 0 && standingSinceN <= sinceN {
			derivation.signsRevoke = false
		}
	} else if derivation.revokedAt != 0 {
		// lost adds nothing to a revocation that stands
		derivation.signsRevoke = false
	}
	if derivation.revokedAt != 0 {
		plan.Items = append(plan.Items, DeviceRevokeItem{
			Effect: DeviceRevokeEffectStands, Kind: DeviceRevokeKindRevocation, Id: sidecarId.Bytes(), Position: derivation.revokedAt,
		})
	}

	// each presence or SSH key the target registered that the cascade does not void, offered for KeyRevoke
	for _, key := range revokes.RegisteredKeys(sidecarId) {
		if key.GetRevokedAt() != 0 || slices.ContainsFunc(voidedKeyIds, func(voided []byte) bool { return bytes.Equal(voided, key.GetKeyId()) }) {
			continue
		}
		name := ""
		switch key.GetPurpose() {
		case bridge.KeyPurpose_KEY_PURPOSE_PRESENCE:
			name = "presence"
		case bridge.KeyPurpose_KEY_PURPOSE_SSHSIG:
			name = "ssh"
		}
		plan.Items = append(plan.Items, DeviceRevokeItem{
			Effect: DeviceRevokeEffectKey, Kind: DeviceRevokeKindKey, Id: bytes.Clone(key.GetKeyId()), Name: name, Position: key.GetAt(),
		})
	}

	plan.Signatures = 1
	if derivation.signsRevoke {
		plan.Signatures = max(1, revokes.RevokeSignatures(sidecarId))
	}
	// Presence comes from the log's rule over what the act would sign, never from the caller
	revoke := &bridge.SidecarRevoke{SidecarId: sidecarId.Bytes(), Reason: revokeReason, SinceN: plan.SinceN}
	switch {
	case derivation.signsRevoke:
		plan.Presence = authority.PresenceRequired(deviceRevokeStatement(identity.SidecarId, bridge.SignedType_SIGNED_SIDECAR_REVOKE, revoke))
		if 1 < plan.Signatures && !plan.Presence {
			plan.Presence = authority.PresenceRequired(deviceRevokeStatement(identity.SidecarId, bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Subject: sidecarId.Bytes()}))
		}
	default:
		plan.Presence = authority.PresenceRequired(deviceRevokeStatement(identity.SidecarId, bridge.SignedType_SIGNED_KEY_REVOKE, &protocol.KeyRevoke{}))
	}
	plan.PlanId = deviceRevokePlanId(&deviceRevokePlanIdFields{
		sidecarId:      sidecarId,
		revokedAt:      derivation.revokedAt,
		standingSinceN: standingSinceN,
		reason:         revokeReason,
		sinceN:         plan.SinceN,
		signatures:     plan.Signatures,
		presence:       plan.Presence,
		keyIds:         derivation.keyIds(),
	})
	return derivation, nil
}

// The confirmations a sidecar of P gave from the position P held it, on the member's devices and the devices P parks,
// each as a void row naming the confirmed device and the confirmation's entry, in position order: what DESIGN-DETAILS
// 5.2.2's confirmation history shows a person of who lifted or confirmed what.
func deviceRevokeConfirmationItems(authority SidecarAuthority, memberId Id, held map[Id]uint64) []DeviceRevokeItem {
	admissions := map[Id]*AclSidecar{}
	for _, admission := range authority.MemberDevices(memberId) {
		if admission != nil && admission.Row != nil {
			if sidecarId, err := IdFromBytes(admission.Row.GetSidecarId()); err == nil {
				admissions[sidecarId] = admission
			}
		}
	}
	for sidecarId := range held {
		if admissions[sidecarId] == nil {
			if admission := authority.Admission(sidecarId); admission != nil && admission.Row != nil {
				admissions[sidecarId] = admission
			}
		}
	}
	items := []DeviceRevokeItem{}
	for sidecarId, admission := range admissions {
		for _, confirmation := range admission.Row.GetConfirmations() {
			signerId, err := IdFromBytes(confirmation.GetSigner())
			if err != nil {
				continue
			}
			if from, inP := held[signerId]; inP && from <= confirmation.GetAt() {
				name := "admission_confirm"
				if confirmation.GetKind() == 2 {
					name = "owner_confirm"
				}
				items = append(items, DeviceRevokeItem{
					Effect: DeviceRevokeEffectVoid, Kind: DeviceRevokeKindConfirmation, Id: sidecarId.Bytes(), Name: name, Position: confirmation.GetAt(),
				})
			}
		}
	}
	slices.SortFunc(items, func(a DeviceRevokeItem, b DeviceRevokeItem) int {
		if a.Position != b.Position {
			if a.Position < b.Position {
				return -1
			}
			return 1
		}
		return bytes.Compare(a.Id, b.Id)
	})
	return items
}

// The plan of revoking sidecarId, another of this member's devices, as reason, "lost" or "compromise". For
// compromise, lostAt is the loss time the person gives, whose first entry at or after it is the proposed since_n, and
// sinceN a position the person moved it to, 0 for the proposed one; lost ignores both. Answers a *DeviceRevokeError
// with §5.6's code for every refusal, ErrSidecarDevicesPrecondition while Locked or Unenrolled, and
// ErrSidecarActNoAuthority while no verified state is installed. Signs nothing; the plan is kept for RevokeDevice.
func (self *Sidecar) PreviewDeviceRevoke(ctx context.Context, sidecarId Id, reason string, lostAt time.Time, sinceN uint64) (*DeviceRevokePlan, error) {
	identity, err := self.devicesReady()
	if err != nil {
		return nil, err
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	derivation, err := self.deriveDeviceRevoke(authority, identity, sidecarId, reason, lostAt, sinceN, false)
	if err != nil {
		return nil, err
	}
	self.keepRevokePreview(derivation)
	plan := *derivation.plan
	plan.Items = slices.Clone(derivation.plan.Items)
	return &plan, nil
}
