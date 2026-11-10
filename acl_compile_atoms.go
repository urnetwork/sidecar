// CompileAcl's atoms: what each §8.4 selector compiles to, and the AclAtom row behind it.
//
//	autogroup:<name>     its fixed atom, fifteen zero bytes then its value, with no row (plan-ACL-atom-and-rule-ids #2)
//	tag:<name>           the tags file's id; its row lists the standing sidecars carrying it and, in
//	                     tag_owner_member_ids, its tagOwners expanded to members (#4), which only CanApplyTag reads
//	group:<name>         the groups file's id; its row lists its members, each email through resolve
//	user:<email>         the member resolve names, as a derived atom of kind 1 over the member_id
//	sidecar:<id>         a derived atom of kind 2 over the id, listing it
//	client:<id>          a derived atom of kind 3, listing the sidecar resolve's binding names, or with none the client
//	network:<net>        a derived atom of kind 4 over the network resolve names; network:* a derived atom over "*"
//	                     with no row, which names no network until §8.11's shares give it one (ACL-M6-03)
//	role:, principal:    derived atoms of kinds 5 and 6 over the name, carrying it
//
// Derived atoms are the first 16 bytes of SHA-256("urnetwork-sidecar-v1/acl-atom" || 0x00 || kind || 0x00 || value)
// (plan-ACL-nonsidecar-subjects), unkeyed because each value is already server-visible. A member a selector resolves
// to that the log's rows no longer hold expands to nothing, so the selector grants nothing until a save drops it; a
// name, email, network or client with no table row refuses the head, which no writer could have saved.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// network:*'s atom: no network id is one byte, so no network's atom takes it.
func aclNetworkWildcardAtom() Id {
	return AclDerivedAtom(AclDerivedAtomNetwork, []byte("*"))
}

// The atom a subject selector compiles to, its row added to the compile's atoms.
func (self *aclCompiler) atom(selector AclSelector) (Id, error) {
	switch selector.Kind {
	case AclSelectorAutogroup:
		return AclAutogroupAtom(selector.Autogroup), nil
	case AclSelectorTag:
		atomId, found := self.tagIds[selector.Name]
		if !found {
			return Id{}, aclCompileRefusal("a tag the tags file does not hold")
		}
		if _, built := self.atoms[atomId]; !built {
			row := &protocol.AclAtom{Atom: atomId.Bytes(), TagOwnerMemberIds: self.tagOwners(selector)}
			for _, sidecar := range self.input.Sidecars {
				if sidecar.GetRevokedAt() != 0 {
					continue
				}
				if slices.ContainsFunc(sidecar.GetTagIds(), func(tagId []byte) bool { return bytes.Equal(tagId, atomId.Bytes()) }) {
					row.SidecarIds = append(row.SidecarIds, bytes.Clone(sidecar.GetSidecarId()))
				}
			}
			self.mergeAtom(row)
		}
		return atomId, nil
	case AclSelectorGroup:
		atomId, found := self.groupIds[selector.Name]
		if !found {
			return Id{}, aclCompileRefusal("a group the groups file does not hold")
		}
		if _, built := self.atoms[atomId]; !built {
			row := &protocol.AclAtom{Atom: atomId.Bytes()}
			memberIds, err := self.groupMembers(selector)
			if err != nil {
				return Id{}, err
			}
			for _, memberId := range memberIds {
				row.MemberIds = append(row.MemberIds, memberId.Bytes())
			}
			self.mergeAtom(row)
		}
		return atomId, nil
	case AclSelectorUser:
		memberId, err := self.userMember(selector)
		if err != nil {
			return Id{}, err
		}
		atomId := AclDerivedAtom(AclDerivedAtomMember, memberId.Bytes())
		row := &protocol.AclAtom{Atom: atomId.Bytes()}
		if self.members[memberId] != nil {
			row.MemberIds = [][]byte{memberId.Bytes()}
		}
		self.mergeAtom(row)
		return atomId, nil
	case AclSelectorSidecar:
		atomId := AclDerivedAtom(AclDerivedAtomSidecar, selector.Id.Bytes())
		self.mergeAtom(&protocol.AclAtom{Atom: atomId.Bytes(), SidecarIds: [][]byte{selector.Id.Bytes()}})
		return atomId, nil
	case AclSelectorClient:
		sidecarId, found := self.clientIds[selector.Id]
		if !found {
			return Id{}, aclCompileRefusal("a client resolve does not hold")
		}
		atomId := AclDerivedAtom(AclDerivedAtomClient, selector.Id.Bytes())
		row := &protocol.AclAtom{Atom: atomId.Bytes()}
		if sidecarId != (Id{}) {
			row.SidecarIds = [][]byte{sidecarId.Bytes()}
		} else {
			row.ClientIds = [][]byte{selector.Id.Bytes()}
		}
		self.mergeAtom(row)
		return atomId, nil
	case AclSelectorNetwork:
		if selector.Name == "*" {
			return aclNetworkWildcardAtom(), nil
		}
		networkId, found := self.networkIds[selector.Name]
		if !found {
			return Id{}, aclCompileRefusal("a network resolve does not hold")
		}
		atomId := AclDerivedAtom(AclDerivedAtomNetwork, networkId.Bytes())
		self.mergeAtom(&protocol.AclAtom{Atom: atomId.Bytes(), NetworkIds: [][]byte{networkId.Bytes()}})
		return atomId, nil
	case AclSelectorRole:
		atomId := AclDerivedAtom(AclDerivedAtomRole, []byte(selector.Name))
		self.mergeAtom(&protocol.AclAtom{Atom: atomId.Bytes(), Role: selector.Name})
		return atomId, nil
	case AclSelectorPrincipal:
		atomId := AclDerivedAtom(AclDerivedAtomPrincipal, []byte(selector.Name))
		self.mergeAtom(&protocol.AclAtom{Atom: atomId.Bytes(), Principal: selector.Name})
		return atomId, nil
	}
	return Id{}, aclCompileRefusal("a selector of no kind")
}

// The atoms of a selector list, sorted, without repeats.
func (self *aclCompiler) atomList(selectors []AclSelector) ([][]byte, error) {
	atoms := [][]byte{}
	for _, selector := range selectors {
		atomId, err := self.atom(selector)
		if err != nil {
			return nil, err
		}
		atoms = append(atoms, atomId.Bytes())
	}
	return aclSortBytesList(atoms), nil
}

// The target a subject selector compiles to as a destination or a via: an id where the selector names one subject
// outright, else its atom.
func (self *aclCompiler) subjectTarget(selector AclSelector) (*protocol.AclTarget, error) {
	switch selector.Kind {
	case AclSelectorSidecar:
		return &protocol.AclTarget{SidecarId: selector.Id.Bytes()}, nil
	case AclSelectorClient:
		sidecarId, found := self.clientIds[selector.Id]
		if !found {
			return nil, aclCompileRefusal("a client resolve does not hold")
		}
		if sidecarId != (Id{}) {
			return &protocol.AclTarget{SidecarId: sidecarId.Bytes()}, nil
		}
		// D-ACL-5's naming of a legacy client (plan-ACL-nonsidecar-subjects)
		return &protocol.AclTarget{ClientId: selector.Id.Bytes()}, nil
	case AclSelectorNetwork:
		networkId, found := self.networkIds[selector.Name]
		if !found {
			return nil, aclCompileRefusal("a network resolve does not hold")
		}
		return &protocol.AclTarget{NetworkId: networkId.Bytes()}, nil
	}
	atomId, err := self.atom(selector)
	if err != nil {
		return nil, err
	}
	return &protocol.AclTarget{Atom: atomId.Bytes()}, nil
}

// Adds an atom row, merging its lists into a row of the same atom already there.
func (self *aclCompiler) mergeAtom(row *protocol.AclAtom) {
	atomId := Id(row.GetAtom())
	existing, found := self.atoms[atomId]
	if !found {
		self.atoms[atomId] = row
		return
	}
	existing.MemberIds = append(existing.MemberIds, row.GetMemberIds()...)
	existing.SidecarIds = append(existing.SidecarIds, row.GetSidecarIds()...)
	existing.TagOwnerMemberIds = append(existing.TagOwnerMemberIds, row.GetTagOwnerMemberIds()...)
	existing.ClientIds = append(existing.ClientIds, row.GetClientIds()...)
	existing.NetworkIds = append(existing.NetworkIds, row.GetNetworkIds()...)
	if existing.Role == "" {
		existing.Role = row.GetRole()
	}
	if existing.Principal == "" {
		existing.Principal = row.GetPrincipal()
	}
}

// The member an email resolves to.
func (self *aclCompiler) userMember(selector AclSelector) (Id, error) {
	memberId, found := self.memberIds[selector.Name]
	if !found {
		return Id{}, aclCompileRefusal("a user resolve does not hold")
	}
	return memberId, nil
}

// A group's members the log's rows still hold, sorted: the groups block's emails through resolve. A group the block
// does not list, such as one SCIM keeps, holds none here.
func (self *aclCompiler) groupMembers(group AclSelector) ([]Id, error) {
	memberIds := []Id{}
	for _, entry := range self.policy.Groups {
		if entry.Group != group {
			continue
		}
		for _, user := range entry.Members {
			memberId, err := self.userMember(user)
			if err != nil {
				return nil, err
			}
			if self.members[memberId] != nil {
				memberIds = append(memberIds, memberId)
			}
		}
	}
	slices.SortFunc(memberIds, Id.Cmp)
	return slices.Compact(memberIds), nil
}

// A tag's tagOwners as member_ids, for CanApplyTag (plan-ACL-atom-and-rule-ids #4): users and groups through resolve
// and the groups block, and autogroups by the roles they name. A tag no entry lists has no owner.
func (self *aclCompiler) tagOwners(tag AclSelector) [][]byte {
	memberIds := []Id{}
	for _, entry := range self.policy.TagOwners {
		if entry.Tag != tag {
			continue
		}
		for _, owner := range entry.Owners {
			switch owner.Kind {
			case AclSelectorUser:
				if memberId, err := self.userMember(owner); err == nil && self.members[memberId] != nil {
					memberIds = append(memberIds, memberId)
				}
			case AclSelectorGroup:
				groupMemberIds, err := self.groupMembers(owner)
				if err == nil {
					memberIds = append(memberIds, groupMemberIds...)
				}
			case AclSelectorAutogroup:
				memberIds = append(memberIds, self.autogroupMembers(owner.Autogroup)...)
			}
		}
	}
	slices.SortFunc(memberIds, Id.Cmp)
	memberIds = slices.Compact(memberIds)
	owners := [][]byte{}
	for _, memberId := range memberIds {
		owners = append(owners, memberId.Bytes())
	}
	return owners
}

// The members an autogroup names as people: every member for autogroup:member, else those of its roles
// (acl-m2-02-state-readings #1).
func (self *aclCompiler) autogroupMembers(autogroup protocol.AclAutogroup) []Id {
	memberIds := []Id{}
	for memberId, member := range self.members {
		if autogroup == protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER || aclRoleAutogroups(member.GetRole())&aclAutogroupBit(autogroup) != 0 {
			memberIds = append(memberIds, memberId)
		}
	}
	return memberIds
}
