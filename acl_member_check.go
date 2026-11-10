// §10.9's check on who a group change adds, and §8.12's invariant's list of who must not hold a key: what makes
// R-ACL-7 hold, a breached server neither admitting a ghost nor granting a reader. gkm sees no proposal, so members
// judge every Add, external commit and ReaderWrap they read against the state at its own auth pin (§7.9's admissions,
// §8.5's consent and the repo's access log), and a writer judges every holder of the epoch and generation it is about
// to seal to, committing the Remove or rotation before sealing to one this names (D-ACL-18).
//
// A sidecar passes when the state admits it, nothing hard denies it (revoked, past its not_after, parked, suspended,
// its member gone) and §8.6 gives it read on the repo at now: kind defaults, rules, the access log's admins and
// unexpired RepoGrants no config writer's RepoRevoke stands against, and in an owner-bound repo only the owner's
// consented devices, their EvsShares' subjects and, from M6, the audit reader (owner decisions 63, 126). Deposit is
// no read, so a depositor takes neither a leaf nor a ReaderWrap. A leaf further needs a member device, untagged and
// not ephemeral, since tagged, ephemeral, CI and cloud sidecars read by wraps and never take a seat (D-KEYS-11); in
// the config group and a team directory's, a device §7.9's leaves rule entitles (owner decisions 144, 182), the
// rest reading there by wraps; and no group past 1,000 leaves (D-KEYS-2). Which waiting device a data repo seats is
// the committer's choice (acl_seats.go), which members do not check: they check only that a seated device reads and
// the bound.
//
// The leaves rule is TEAM's, one function of the log (config_leaves.go), which the state's view answers through
// AclLeafRankView. That stays apart from AclAuthView, which views outside this package implement too: a view without
// it entitles no device, so the config group and a team directory's take no leaf through it, the closed direction.
//
// A Delegation's key and a member's recovery key are held under their own identities, which §10.5's KeyHolders
// judges (gkm_holders.go), so NonReaders reads only the sidecars that hold a leaf or a ReaderWrap: an agent a live
// Delegation covers reads through that Delegation's wrap and is no such holder, which is §10.5's Residual, the live
// Delegation's key aside. Covered agents hold no ReaderWrap where their Delegation reaches, which KeyHolders checks
// on a delivery beside this.
//
// Pure functions of the state and the time: no clock, no I/O, and a check allocates nothing. On every leg, the
// sidecar_http page Worker's included: root Id, no connect type. Nothing here creates, derives or unwraps a key, so
// nothing calls testHookSecret.

package sidecar

import (
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What a group change makes of a sidecar.
type AclRepoMemberForm int

const (
	// a leaf of the group's tree: an Add in a commit, or an external commit's join, a resync's or a recovery
	// self-join's
	AclRepoMemberLeaf AclRepoMemberForm = iota + 1
	// the recipient of a ReaderWrap of a generation, staged or late
	AclRepoMemberWrap
)

// One sidecar a commit or a delivery adds to a repo's key holders, as the members that judge it see it (§10.9).
type AclRepoMember struct {
	SidecarId Id
	Form      AclRepoMemberForm
	// For a leaf: how many leaves the group's tree holds once the commit applies, its Removes first and the new leaf
	// counted, which no group takes past 1,000 (D-KEYS-2). A count below 1 is no tree and refuses. Unused for a wrap.
	LeafCount int
}

// One holder of a repo's key that §8.12's invariant names: it holds a leaf of the group's epoch or a ReaderWrap of
// its generation and does not read the repo at the state and time.
type AclNonReader struct {
	SidecarId Id
	// A hard deny the state shows (unadmitted, revoked, expired, parked, suspended), a lost consent in an owner-bound
	// repo, or no right in force there, such as an expired or revoked grant, or a repo deleted or unknown.
	Reason AclReason
}

// What a state's view answers of §7.9's leaves rule, which TEAM's ConfigState implements: whether the device is
// leaf-entitled in the config group and a team directory's, among the first 1,000 live member devices by
// (live_since, sidecar_id) (owner decisions 144, 182). AclState asks it only in a check, never while it builds, so a
// view may answer it from its own AclState.
type AclLeafRankView interface {
	LeafEntitled(sidecarId Id) bool
}

// The view every reader's AclState is built over answers the leaves rule.
var _ AclLeafRankView = (*ConfigState)(nil)

// Whether a group's leaves follow §7.9's leaves rule rather than data seats: the config's and a team directory's
// (owner decision 182).
func aclRepoKindLeafRanked(kind protocol.RepoKind) bool {
	return kind == protocol.RepoKind_REPO_KIND_CONFIG || kind == protocol.RepoKind_REPO_KIND_DIRECTORY
}

// §10.9's Add and delivery check on the sidecar a commit or a ReaderWrap adds, at this state, which must be the
// state at the commit's or delivery's own auth pin, never the tip, and at its time: allowed with what lets it read
// (a kind default, a rule, a repo admin, a RepoGrant or EvsShare with its position, or the audit block), else the
// reason. A member refuses the commit or the wrap on any refusal.
func (self *AclState) CheckRepoMember(repoId Id, member AclRepoMember, now time.Time) AclDecision {
	nowMs := now.UnixMilli()
	sidecar := self.sidecarState(member.SidecarId)
	if sidecar == nil {
		return aclDeny(AclReasonUnadmitted)
	}
	decision := self.repoMemberDecision(sidecar, repoId, member.Form, nowMs)
	if !decision.Allowed || member.Form != AclRepoMemberLeaf {
		return decision
	}
	if member.LeafCount < 1 || aclRepoSeatCount < member.LeafCount {
		return aclDeny(AclReasonSeatsFull)
	}
	return decision
}

// The holders given that do not read the repo at now, sorted by sidecar_id, each once, and none when every holder
// reads: the sidecars §8.12's invariant forbids a writer to seal to, so EnsureWritable commits their Removes or
// rotates before it returns a key (§10.5, §10.9's Remove row). holders are the sidecars holding a leaf of the epoch's
// tree or a ReaderWrap of the generation; a holder this state never admitted is a non-reader. A leaf that only lost
// §7.9's leaf entitlement still reads, by wraps, so it is not named: its Remove is a move (§7.9), not this.
func (self *AclState) NonReaders(repoId Id, holders []Id, now time.Time) []AclNonReader {
	nowMs := now.UnixMilli()
	nonReaders := []AclNonReader{}
	for _, holderId := range holders {
		sidecar := self.sidecarState(holderId)
		if sidecar == nil {
			nonReaders = append(nonReaders, AclNonReader{SidecarId: holderId, Reason: AclReasonUnadmitted})
			continue
		}
		if decision := self.repoMemberDecision(sidecar, repoId, AclRepoMemberWrap, nowMs); !decision.Allowed {
			nonReaders = append(nonReaders, AclNonReader{SidecarId: holderId, Reason: decision.Reason})
		}
	}
	slices.SortFunc(nonReaders, func(a AclNonReader, b AclNonReader) int {
		return a.SidecarId.Cmp(b.SidecarId)
	})
	return slices.CompactFunc(nonReaders, func(a AclNonReader, b AclNonReader) bool {
		return a.SidecarId == b.SidecarId
	})
}

// CheckRepoMember for an indexed sidecar, but for the leaf count, which a commit bounds as a whole.
func (self *AclState) repoMemberDecision(sidecar *aclSidecarState, repoId Id, form AclRepoMemberForm, nowMs int64) AclDecision {
	if form != AclRepoMemberLeaf && form != AclRepoMemberWrap {
		// a form this code does not know adds no one
		return aclDeny(AclReasonNoGrant)
	}
	if reason := sidecar.hardDeny(nowMs); reason != 0 {
		return aclDeny(reason)
	}
	access := self.sidecarEvsAccess(sidecar, repoId, AclTokenAudienceEvs, nowMs)
	if !access.Rights.Has(AclEvsRead) {
		repo := self.repos[repoId]
		if repo != nil && !repo.deleted && aclRepoKindOwnerBound(repo.kind) &&
			sidecar.class == AclSubjectClassMemberDevice && sidecar.memberId == repo.ownerId {
			return aclDeny(AclReasonUnconsented)
		}
		if access.Allowed {
			// deposit alone: no read, subscription, key or place among the readers
			return aclDeny(AclReasonNoGrant)
		}
		return access.AclDecision
	}
	if form == AclRepoMemberLeaf {
		if sidecar.class != AclSubjectClassMemberDevice {
			return aclDeny(AclReasonNotMemberDevice)
		}
		if aclRepoKindLeafRanked(self.repos[repoId].kind) {
			// a view that does not answer the leaves rule entitles no one
			leafView, ranks := self.view.(AclLeafRankView)
			if !ranks || !leafView.LeafEntitled(sidecar.id) {
				return aclDeny(AclReasonNotLeafEntitled)
			}
		}
	}
	return access.AclDecision
}
