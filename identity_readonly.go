// §7.9's read_only row on the signing side (D-TEAM-24, CORE-M4-01): a read_only sidecar's Sign refuses at once what
// every verifier refuses from it, so a page Worker learns locally, before it builds or posts anything, that it may
// not sign an admission, a wrap or a head. It may sign its own SidecarRevoke (sign-out), its own ReaderKeys, its
// KeyPackages' MLS credentials, `read` record entries and their receipt deposits; HeadCheck replies and its leaf's
// path-only commits, resyncs and acks are signed outside Sign. Each act is judged by ReadOnlyAllows, the one list every
// verifier asks (config_read_only.go), so this side never allows what a verifier refuses.
//
// This is a courtesy, never the control: verifiers still check every statement (§7.9), so a modified Worker that
// signs anyway gains nothing.
//
// A sidecar signs as read_only once the installed authority's admission of it carries read_only, as a page Worker's
// does (§18.8): before then it has no admission to act under, and an act refuses with no authority. On every leg, the
// sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Whether this sidecar signs as a read_only device: the installed verified state admits it read_only.
func (self *Sidecar) signsReadOnly() bool {
	authority := self.authority()
	identity := self.currentIdentity()
	if authority == nil || identity == nil {
		return false
	}
	admission := authority.Admission(identity.SidecarId)
	if admission == nil || admission.Row == nil {
		return false
	}
	return admission.Row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0
}

// The act a statement of signedType with body is, signed by sidecarId as a read_only device, as verifiers judge it
// (§7.9's read_only row). A body that does not decode is judged by its type alone, so it is never more allowed than a
// well-formed one.
func sidecarReadOnlySignAct(sidecarId Id, signedType bridge.SignedType, body []byte) ReadOnlyAct {
	switch signedType {
	case bridge.SignedType_SIGNED_SIDECAR_REVOKE:
		revoke := &bridge.SidecarRevoke{}
		if proto.Unmarshal(body, revoke) == nil && bytes.Equal(revoke.GetSidecarId(), sidecarId.Bytes()) {
			return ReadOnlyActSignOut
		}
		return ReadOnlyActStatement
	case bridge.SignedType_SIGNED_READER_KEY:
		return ReadOnlyActReaderKey
	case bridge.SignedType_SIGNED_UR_MLS_CREDENTIAL:
		// the credentials of its own KeyPackages
		return ReadOnlyActKeyPackage
	case bridge.SignedType_SIGNED_RECORD_HEADER:
		header := &protocol.RecordHeader{}
		if proto.Unmarshal(body, header) == nil && RecordKind(header.GetKind()) == RecordKindRead &&
			bytes.Equal(header.GetWriterSidecarId(), sidecarId.Bytes()) {
			return ReadOnlyActReadEntry
		}
		return ReadOnlyActStatement
	case bridge.SignedType_SIGNED_EVS_PUSH:
		push := &protocol.EvsPush{}
		if proto.Unmarshal(body, push) == nil && push.GetRefKind() == uint32(protocol.EvsRefKind_EVS_REF_DEPOSIT) &&
			bytes.Equal(push.GetOwnerSidecarId(), sidecarId.Bytes()) && bytes.Equal(push.GetSignerSidecarId(), sidecarId.Bytes()) {
			// a push to its own deposit ref: the receipt deposit its read entries ride
			return ReadOnlyActReceiptDeposit
		}
		return ReadOnlyActEvsHead
	case bridge.SignedType_SIGNED_EVS_RESEED, bridge.SignedType_SIGNED_EVS_PATH_MAP, bridge.SignedType_SIGNED_EVS_IMPORT:
		return ReadOnlyActEvsHead
	case bridge.SignedType_SIGNED_GEN_ROTATE:
		return ReadOnlyActGenRotate
	case bridge.SignedType_SIGNED_READER_WRAP, bridge.SignedType_SIGNED_DELEGATION_WRAP:
		return ReadOnlyActWrap
	case bridge.SignedType_SIGNED_GROUP_FORM:
		return ReadOnlyActGroupInfoWrite
	case bridge.SignedType_SIGNED_APPROVAL_DECISION, bridge.SignedType_SIGNED_APPROVAL_CANCEL:
		return ReadOnlyActApprovalDecision
	case bridge.SignedType_SIGNED_SOCKET_REGISTRATION:
		return ReadOnlyActSocketRegistration
	case bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION:
		return ReadOnlyActServiceWrite
	}
	// every other statement: admissions of every kind, OwnerConfirm, EvsShare, keys, indexers, recovery bindings, and
	// every authority, acl and bridge statement, the directory's writes and retention policies included
	return ReadOnlyActStatement
}

// A read_only device's refusal: what verifiers refuse from it, refused before any key is read. It is an
// ErrSidecarSignRefused too.
var ErrSidecarSignReadOnly = fmt.Errorf("%w: a read_only device does not sign it", ErrSidecarSignRefused)

// Refuses, before any key is read, a statement a read_only device may not sign: nil when this sidecar does not sign
// as read_only, or the act is one ReadOnlyAllows. The error names the type's number, never the body.
func (self *Sidecar) checkReadOnlySign(signedType bridge.SignedType, body []byte) error {
	if !self.signsReadOnly() {
		return nil
	}
	identity := self.currentIdentity()
	sidecarId := Id{}
	if identity != nil {
		sidecarId = identity.SidecarId
	}
	if !ReadOnlyAllows(sidecarReadOnlySignAct(sidecarId, signedType, body)) {
		return fmt.Errorf("%w: type %#x", ErrSidecarSignReadOnly, int32(signedType))
	}
	return nil
}
