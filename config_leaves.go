// §7.9's leaves and commit rows (owner decisions 113, 114, 128, 144, 182; D-KEYS-2, D-KEYS-23):
//
//	leaves  member devices (untagged, not ephemeral) admitted and not revoked, nor their member, parked or suspended,
//	          ranked by (live_since, sidecar_id), live_since the position at which one last became so: its admission,
//	          its recovery activation, or the AdmissionConfirm, OwnerConfirm or Unsuspend that restored it; the first
//	          1,000 are leaf-entitled in the config group and in the team directory's, the rest read each by wraps
//	move    a newly live device ranks last, so one that stays live never loses entitlement, and when an entitled one
//	          stops being live the first wrapped one by rank becomes entitled at that position
//	commit  the signer of an admission or revocation commits what it requires even if it is no config writer: a
//	          leaf-entitled device's Add and a leaf's Remove from its own leaf, or a wrapped reader's first wrap or a
//	          rotation; a wrapped signer only wraps and rotates
//
// Rank depends on the log alone, which is why a member device's admission carrying a not_after is refused
// (config_admit.go). A state computes its ranks once, on first use, from its rows and its acl part's suspensions.
//
// Nothing here creates, derives or unwraps a key, so nothing calls testHookSecret. On every leg.

package sidecar

import (
	"bytes"
	"cmp"
	"slices"
)

// How many member devices are leaf-entitled in the config group and the team directory's: MLS's 1,000 leaves
// (D-KEYS-2), a protocol constant every reader holds alike.
const configLeafEntitledCount = 1000

// §7.9's leaves rank of this state: every live member device by (live_since, sidecar_id).
type configLeaves struct {
	order []Id
	ranks map[Id]int
}

// Whether a row is §7.9's live member device at this state: untagged and not ephemeral, admitted and not revoked, its
// member a member, neither parked nor suspended.
func (self *ConfigState) leafLive(sidecarId Id, acl *AclState) bool {
	row := self.sidecars[sidecarId]
	if row == nil || !configRowMemberDevice(row) || row.GetRevokedAt() != 0 || row.GetParkedAt() != 0 {
		return false
	}
	if memberId, _ := configRowMember(row); self.members[memberId] == nil {
		return false
	}
	return acl == nil || !acl.Suspended(sidecarId)
}

// The rank, built once.
func (self *ConfigState) leaves() *configLeaves {
	self.leavesOnce.Do(func() {
		acl, _ := self.Acl()
		leaves := &configLeaves{ranks: map[Id]int{}}
		for _, sidecarId := range self.SidecarIds() {
			if self.leafLive(sidecarId, acl) {
				leaves.order = append(leaves.order, sidecarId)
			}
		}
		slices.SortFunc(leaves.order, func(a Id, b Id) int {
			if c := cmp.Compare(self.sidecars[a].GetLiveSince(), self.sidecars[b].GetLiveSince()); c != 0 {
				return c
			}
			return a.Cmp(b)
		})
		for rank, sidecarId := range leaves.order {
			leaves.ranks[sidecarId] = rank
		}
		self.leavesCache = leaves
	})
	return self.leavesCache
}

// The device's place in §7.9's leaves rank, 0 the first, false for one that is no live member device.
func (self *ConfigState) LeafRank(sidecarId Id) (int, bool) {
	rank, live := self.leaves().ranks[sidecarId]
	return rank, live
}

// Whether the device is leaf-entitled in the config group and the team directory's: among the first 1,000 by rank.
func (self *ConfigState) LeafEntitled(sidecarId Id) bool {
	rank, live := self.LeafRank(sidecarId)
	return live && rank < configLeafEntitledCount
}

// The live member devices past the first 1,000, by rank: they read the config and the team directory by per-generation
// wraps, as agents do (owner decisions 144, 182).
func (self *ConfigState) WrappedMembers() []Id {
	order := self.leaves().order
	if len(order) <= configLeafEntitledCount {
		return []Id{}
	}
	return slices.Clone(order[configLeafEntitledCount:])
}

// What §7.9's commit row lets a device commit in the config group and the team directory's for one target device.
type ConfigCommits struct {
	// An Add of the target from the signer's leaf: both leaf-entitled.
	Add bool
	// A Remove of the target from the signer's leaf, with its rotation.
	Remove bool
	// A rotation alone: a wrapped signer's for a revocation, or an admission signer's after a reap.
	Rotate bool
	// The target's first wrap: a wrapped signer's admission, or a wrapped target's.
	FirstWrap bool
}

// §7.9's commit row for §10.9: what signerId may commit for targetId at this state, as the signer of the target's
// admission or revocation, even if it is no config writer. The signer stands and is no read_only device. A live target
// takes, only from a signer its admission names, an Add from the signer's leaf when both are leaf-entitled member
// devices, else its first wrap; a target that stopped being live takes a rotation, and a member device a Remove from a
// leaf-entitled signer. Rows keep no revocation's signer, so for a revocation the caller vouches that signerId signed
// it; a promotion the revocation made, the first wrapped device becoming entitled, is the signer's to Add by the same
// reading.
func (self *ConfigState) MayCommit(signerId Id, targetId Id) ConfigCommits {
	commits := ConfigCommits{}
	signer, standing := self.standingSidecar(signerId, self.timeMs)
	target := self.sidecars[targetId]
	if !standing || configRowReadOnly(signer) || target == nil || signerId == targetId {
		return commits
	}
	acl, _ := self.Acl()
	memberDevice := configRowMemberDevice(target)
	live := target.GetRevokedAt() == 0 && target.GetParkedAt() == 0
	if memberDevice {
		live = self.leafLive(targetId, acl)
	}
	signerLeaf := self.LeafEntitled(signerId)
	if live {
		if !slices.ContainsFunc(target.GetAdmissionSigners(), func(admissionSigner []byte) bool {
			return bytes.Equal(admissionSigner, signerId.Bytes())
		}) {
			return commits
		}
		if memberDevice && signerLeaf && self.LeafEntitled(targetId) {
			commits.Add = true
		} else {
			commits.FirstWrap = true
		}
		return commits
	}
	commits.Remove = memberDevice && signerLeaf
	commits.Rotate = true
	return commits
}
