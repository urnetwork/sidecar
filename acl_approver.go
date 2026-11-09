// §8.6's approvers of a requested grant, resolved at the statement's position from a requests rule's approver
// atoms (D-ACL-23, owner decisions 74, 83, 180):
//
//	user:, group:          the members their atoms list
//	autogroup:member|owner|admin|auditor
//	                       members by role, autogroup:admin being Owners and Admins
//	autogroup:self         the requester's owner, or a tagged requester's sponsor
//	autogroup:sponsor      the requester's sponsor
//	autogroup:dst-owner    from the grant's destinations: a subject's owner or a tagged sidecar's sponsor, and
//	                       for a socket the one owner or sponsor of the subjects that hold listen on it in this
//	                       state, never live registrations (plan-ACL-small-readings #5)
//
// Each of the last three falls back to autogroup:admin where it finds no one member: a sponsor gone, an
// untagged requester with no sponsor, or destinations of several owners. The quorum, the count and §8.6's
// admin clause are ACL-M2-07's; this only says who is eligible.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The autogroups that name members as approvers.
const aclApproverAutogroups = 1<<uint32(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER) |
	1<<uint32(protocol.AclAutogroup_ACL_AUTOGROUP_OWNER) |
	1<<uint32(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN) |
	1<<uint32(protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR)

// Who may approve under one requests rule: members named outright, and members by role.
type AclApprovers struct {
	// Sorted, without repeats.
	MemberIds []Id
	// Bits of the role autogroups that approve: member, owner, admin, auditor.
	Autogroups uint32
}

// Whether the set names an autogroup.
func (self *AclApprovers) HasAutogroup(autogroup protocol.AclAutogroup) bool {
	return self.Autogroups&aclAutogroupBit(autogroup) != 0
}

// Who the owner slot of a subject names: its member, or a tagged sidecar's live sponsor, and false when
// there is none, where autogroup:admin stands in.
func (self *AclState) subjectOwner(subject AclSubject) (Id, bool) {
	switch subject.Kind {
	case AclSubjectSidecar:
		if sidecar := self.sidecarState(subject.Id); sidecar != nil && sidecar.valid {
			return sidecar.owner, sidecar.hasOwner
		}
	case AclSubjectClient:
		if subject.MemberId != (Id{}) && self.view.Member(subject.MemberId) != nil {
			return subject.MemberId, true
		}
	}
	return Id{}, false
}

// Resolves a requests rule's approver atoms for one requester and the grant's destinations, as the rows
// carry targets, at the statement's time now.
func (self *AclState) ResolveApprovers(approverAtoms [][]byte, requester AclSubject, grantDst []*protocol.AclTarget, now time.Time) *AclApprovers {
	approvers := &AclApprovers{}
	addAdmin := func() {
		approvers.Autogroups |= aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN)
	}
	addOwner := func(owner Id, hasOwner bool) {
		if hasOwner {
			approvers.MemberIds = append(approvers.MemberIds, owner)
		} else {
			addAdmin()
		}
	}
	for _, atomBytes := range approverAtoms {
		atom, err := IdFromBytes(atomBytes)
		if err != nil {
			continue
		}
		if autogroup, isAutogroup := aclAtomAutogroup(atom); isAutogroup {
			switch autogroup {
			case protocol.AclAutogroup_ACL_AUTOGROUP_SELF:
				addOwner(self.subjectOwner(requester))
			case protocol.AclAutogroup_ACL_AUTOGROUP_SPONSOR:
				owner, hasOwner := Id{}, false
				if requester.Kind == AclSubjectSidecar {
					if sidecar := self.sidecarState(requester.Id); sidecar != nil && sidecar.valid && sidecar.tagged {
						owner, hasOwner = sidecar.owner, sidecar.hasOwner
					}
				}
				addOwner(owner, hasOwner)
			case protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER:
				addOwner(self.destinationOwner(grantDst, now))
			default:
				if aclAutogroupBit(autogroup)&aclApproverAutogroups != 0 {
					approvers.Autogroups |= aclAutogroupBit(autogroup)
				}
			}
			continue
		}
		atomIndex, found := self.atomIndexes[atom]
		if !found {
			continue
		}
		if atomRow := self.atomRow(atomIndex); atomRow != nil {
			for _, memberBytes := range atomRow.GetMemberIds() {
				approvers.MemberIds = append(approvers.MemberIds, Id(memberBytes))
			}
		}
	}
	slices.SortFunc(approvers.MemberIds, Id.Cmp)
	approvers.MemberIds = slices.Compact(approvers.MemberIds)
	return approvers
}

// autogroup:dst-owner: the one owner or sponsor across the grant's destinations, or false where there is
// none or more than one (owner decision 180).
func (self *AclState) destinationOwner(grantDst []*protocol.AclTarget, now time.Time) (Id, bool) {
	nowMs := now.UnixMilli()
	owner := Id{}
	ownerCount := 0
	alone := true
	addSidecar := func(sidecar *aclSidecarState) {
		if !sidecar.hasOwner {
			alone = false
			return
		}
		if ownerCount == 0 || owner != sidecar.owner {
			ownerCount += 1
			owner = sidecar.owner
		}
	}
	for _, target := range grantDst {
		switch {
		case len(target.GetSidecarId()) != 0:
			// grantDst is the caller's, so an id of another size names no one
			sidecarId, err := IdFromBytes(target.GetSidecarId())
			sidecar := self.sidecarState(sidecarId)
			if err != nil || sidecar == nil || sidecar.hardDeny(nowMs) != 0 {
				alone = false
				continue
			}
			addSidecar(sidecar)
		case len(target.GetAtom()) != 0:
			atom, err := IdFromBytes(target.GetAtom())
			atomIndex, found := self.atomIndexes[atom]
			if err != nil || !found {
				alone = false
				continue
			}
			holders := 0
			for i := range self.sidecars {
				sidecar := &self.sidecars[i]
				if _, holds := slices.BinarySearch(sidecar.atoms, atomIndex); holds && sidecar.hardDeny(nowMs) == 0 {
					holders += 1
					addSidecar(sidecar)
				}
			}
			if holders == 0 {
				alone = false
			}
		case len(target.GetSocketTokens()) != 0 || target.GetSocketPrefix():
			socket := aclSocketTarget{tokenPaths: target.GetSocketTokens(), prefix: target.GetSocketPrefix()}
			listeners := 0
			for i := range self.sidecars {
				sidecar := &self.sidecars[i]
				if sidecar.hardDeny(nowMs) == 0 && self.sidecarListensOnTarget(sidecar, &socket, nowMs) {
					listeners += 1
					addSidecar(sidecar)
				}
			}
			if listeners == 0 {
				alone = false
			}
		default:
			// a client, network, repo, address or name has no subject owner in the rows
			alone = false
		}
	}
	if !alone || ownerCount != 1 {
		return Id{}, false
	}
	return owner, true
}

// Whether the sidecar holds, at nowMs, a listen grant overlapping one socket target.
func (self *AclState) sidecarListensOnTarget(sidecar *aclSidecarState, socket *aclSocketTarget, nowMs int64) bool {
	for i := range self.rules {
		rule := &self.rules[i]
		if !sidecar.listenRules.has(rule.index) || !rule.activeAt(nowMs) {
			continue
		}
		if aclSocketTargetsOverlap(rule.sockets, []aclSocketTarget{*socket}) {
			return true
		}
	}
	return false
}

// Whether a member may approve under the set at this state: named outright, or holding a role autogroup
// the set names, every member holding autogroup:member.
func (self *AclState) Approves(approvers *AclApprovers, memberId Id) bool {
	if _, found := slices.BinarySearchFunc(approvers.MemberIds, memberId, Id.Cmp); found {
		return self.view.Member(memberId) != nil
	}
	member := self.view.Member(memberId)
	if member == nil {
		return false
	}
	held := aclRoleAutogroups(member.GetRole()) | aclAutogroupBit(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER)
	return approvers.Autogroups&held != 0
}
