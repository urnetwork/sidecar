// §8.4's subjects and the narrow view of one state that classes them, so AclState never reads the log
// itself. A subject is a sidecar by its sidecar_id across client generations (D-ACL-14), another client of
// this network by its client_id (an app device, or a legacy client with no owner row), a subject of
// another network known only by that network (§8.11), or an anonymous tlsedge visitor. Untagged children
// such as sdk window clients act as their nearest subject ancestor (D-ACL-3), which the caller resolves
// from network_client.acl_subject_client_id before it builds a subject.
//
// Each subject is classed before it is expanded (D-ACL-19): a member device (an untagged sidecar, not
// ephemeral), an ephemeral sidecar, a tagged sidecar, or another client. An untagged sidecar takes its
// owner's user, groups and role, autogroup:member and autogroup:sidecar; a tagged one takes its tags,
// autogroup:tagged and autogroup:sidecar, and no user atom, its sponsor standing in only where a selector
// names an owner (autogroup:self, approvers). autogroup:untagged is untagged non-sidecars only, so an app
// device with an owner row takes its owner's user, groups and role and autogroup:untagged, and a legacy
// client only client:<id>, autogroup:untagged and autogroup:network (D-ACL-20,
// plan-ACL-nonsidecar-subjects).
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The bytes of an atom id: a tag's or group's random id, a derived atom's hash prefix, or an autogroup's
// fixed form (plan-ACL-atom-and-rule-ids #1, #2).
const aclAtomByteCount = 16

// The highest AclAutogroup value, autogroup:dst-owner, whose atom acl.proto fixes at M2 (D-PHASE-9).
const aclAutogroupMax = protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER

// What kind of thing a subject is.
type AclSubjectKind int

const (
	// a sidecar, by sidecar_id (D-ACL-14)
	AclSubjectSidecar AclSubjectKind = iota + 1
	// another client of this network, by client_id: an app device, or a legacy client with no owner row
	AclSubjectClient
	// a subject of another network, known here only by that network's id (§8.11)
	AclSubjectRemote
	// an anonymous tlsedge visitor, which only autogroup:public names (§8.4)
	AclSubjectPublic
)

// One subject as a gate or a client names it. A value, so a check allocates nothing.
type AclSubject struct {
	Kind AclSubjectKind
	// The sidecar_id, the client_id, or the other network's id. Unused for AclSubjectPublic.
	Id Id
	// An AclSubjectClient's owner member, network_client_owner.member_id. Zero for a legacy client.
	// A sidecar's member comes from the state, never from here.
	MemberId Id
	// An AclSubjectClient's identity roles and principal on Embed networks, as the one query
	// getProvideRelationshipDetails runs loads them (plan-ACL-nonsidecar-subjects).
	Roles     []string
	Principal string
	// What the caller refuses beside the state, §8.6's hard denies the state cannot see: an abuse halt
	// (§21), quota (§20) or an unapproved client (§7). Zero: none.
	Deny AclReason
}

// A sidecar subject.
func AclSidecarSubject(sidecarId Id) AclSubject {
	return AclSubject{Kind: AclSubjectSidecar, Id: sidecarId}
}

// Another client of this network. memberId is zero for a legacy client.
func AclClientSubject(clientId Id, memberId Id, roles []string, principal string) AclSubject {
	return AclSubject{Kind: AclSubjectClient, Id: clientId, MemberId: memberId, Roles: roles, Principal: principal}
}

// A subject of another network.
func AclRemoteSubject(networkId Id) AclSubject {
	return AclSubject{Kind: AclSubjectRemote, Id: networkId}
}

// An anonymous tlsedge visitor.
func AclPublicSubject() AclSubject {
	return AclSubject{Kind: AclSubjectPublic}
}

// What D-ACL-19 classes a subject as before expanding it.
type AclSubjectClass int

const (
	// an untagged sidecar that is not ephemeral
	AclSubjectClassMemberDevice AclSubjectClass = iota + 1
	// an ephemeral sidecar, tagged or not, whose evs access takes §8.6's ceiling
	AclSubjectClassEphemeral
	// a tagged sidecar that is not ephemeral
	AclSubjectClassTagged
	// another client of this network
	AclSubjectClassClient
	// a subject of another network, or an anonymous visitor
	AclSubjectClassOther
)

// One sidecar's admission at a state, what §8.6's evaluation and §8.5's consent read. Row is §7.9's
// SidecarRow, positions and signers included; the rest is what SidecarRow does not carry yet and the
// state reads from the SidecarAdmit (§7.9), which the view supplies either way.
type AclSidecar struct {
	Row *bridge.SidecarRow
	// The member an untagged admission names. Zero for a tagged one.
	MemberId Id
	// A tagged admission's opaque tag ids (plan-ACL-atom-and-rule-ids #1). Empty for an untagged one.
	TagIds    []Id
	Ephemeral bool
}

// Whether the admission carries a capability bit.
func (self *AclSidecar) hasCapability(capability bridge.SidecarCapability) bool {
	return self != nil && self.Row != nil && self.Row.GetCapabilities()&uint32(capability) != 0
}

// A narrow read-only view of one state S(n), which TEAM's ConfigState implements, so the acl part of S(n)
// is a function of the log alone and every task here builds against a fake of it. Suspensions are not
// asked for: they are §8.8's statements, folded into AclRows.suspensions (plan-ACL-folded-grant-state #1),
// which AclState reads itself.
//
// Answers never change for one view, and a view is safe for concurrent use.
type AclAuthView interface {
	// The state's (n, A_n).
	Pin() *bridge.AuthPin
	// The network's Genesis, whose owner_sidecar_id signed it (§8.5's genesis clause).
	Genesis() *bridge.Genesis
	// Every sidecar the state holds a row for, revoked tombstones included, in any order.
	SidecarIds() []Id
	// A sidecar's admission, or nil when the state never admitted it.
	Sidecar(sidecarId Id) *AclSidecar
	// A member's row, or nil when the id names no member of this state.
	Member(memberId Id) *bridge.MemberRow
	// Whether the sidecar writes config heads: an AdminSet member's member device that is not read_only
	// (§7.9, §8.8).
	IsConfigWriter(sidecarId Id) bool
	// Whether §7.9's compromise cascade, or a leaked bundle's DelegationRevoke, parks the sidecar now. A
	// consent park (KF2) is not this.
	Parked(sidecarId Id) bool
	// A tagged sidecar's sponsor, its admitting member or the one an admin's SponsorSet names, and false
	// once that member is removed, when autogroup:admin stands in (owner decision 83).
	Sponsor(sidecarId Id) (Id, bool)
	// Whether a record signed by signer (a sidecar_id, a recovery key's hash or a delegation_id) and
	// carried at position at rests on what a compromise cascade voids: a signer then in its set P, or a
	// recovery key whose binding one signed (§7.9's cascade, D-TEAM-26).
	CascadeVoids(signer []byte, at uint64) bool
}

// An autogroup's atom: fifteen zero bytes, then its AclAutogroup value (plan-ACL-atom-and-rule-ids #2).
func AclAutogroupAtom(autogroup protocol.AclAutogroup) Id {
	atom := Id{}
	atom[aclAtomByteCount-1] = byte(autogroup)
	return atom
}

// The autogroup an atom's fixed form names, or false for any other atom.
func aclAtomAutogroup(atom Id) (protocol.AclAutogroup, bool) {
	for i := 0; i < aclAtomByteCount-1; i += 1 {
		if atom[i] != 0 {
			return protocol.AclAutogroup_ACL_AUTOGROUP_UNSPECIFIED, false
		}
	}
	value := protocol.AclAutogroup(atom[aclAtomByteCount-1])
	if value < protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER || aclAutogroupMax < value {
		return protocol.AclAutogroup_ACL_AUTOGROUP_UNSPECIFIED, false
	}
	return value, true
}

// Whether bytes have the fixed autogroup form, a valid value or not: fifteen zero bytes. No tag, group or
// derived atom takes it, since a writer redraws one that would (plan-ACL-atom-and-rule-ids #1).
func aclAtomHasAutogroupForm(atom Id) bool {
	for i := 0; i < aclAtomByteCount-1; i += 1 {
		if atom[i] != 0 {
			return false
		}
	}
	return true
}

// The autogroups a member's role puts its untagged subjects in. autogroup:admin is the two roles that
// count toward k of n, Owner and Admin, since a personal network's one member is its Owner and an
// admin-approved rule must have an approver there (acl-m2-02-state-readings #1).
func aclRoleAutogroups(role bridge.MemberRole) uint32 {
	switch role {
	case bridge.MemberRole_MEMBER_ROLE_OWNER:
		return aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_OWNER) |
			aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN)
	case bridge.MemberRole_MEMBER_ROLE_ADMIN:
		return aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN)
	case bridge.MemberRole_MEMBER_ROLE_AUDITOR:
		return aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR)
	}
	return 0
}

// One autogroup as a bit of a mask.
func aclAutogroupBit(autogroup protocol.AclAutogroup) uint32 {
	return 1 << uint32(autogroup)
}
