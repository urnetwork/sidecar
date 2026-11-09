// §8.8's access logs folded into AclRows' repos (owner decision 8): each statement with its signer's sidecar_id and
// the log position of the entry that carried it, so a reader judges a signer's repo admin right at a position, and
// §7.9's cascade finds what P signed. The rows keep:
//
//	admins       RepoCreate's signer, then RepoAdmin's adds and removes
//	grants       the newest RepoGrant per subject; a later RepoRevoke of the subject takes it out
//	shares       the newest EvsShare per subject; a RepoRevoke of the subject takes it out too
//	revokes      config writers' standing RepoRevokes, one per subject, until a config writer's RepoGrant of that
//	             subject, or in an owner-bound repo its owner's EvsShare to it, lifts it
//	             (plan-ACL-owner-bound-standing-revoke)
//	deletion     the newest RepoDelete, restored_at set by the RepoRestore of its deletion_id
//	lock         the newest RepoVersioning's; format 1 folds it and enforces nothing (D-PHASE-9)
//	consented    an owner-bound repo's owner's devices consented at its RepoCreate, and each its owner's
//	             OwnerConfirm adds; a device consented any other way between bases waits for the next base's compile
//
// FoldAclRepos is one pure fold, which ApplyStatement runs per entry and a writer's compile may run over the
// statements a base folds; it judges nothing, so it takes only statements that took effect, each with its verdict.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type.

package sidecar

import (
	"bytes"
	"cmp"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Why a fold could not take a statement over the repos it was given: its repo is not there, or a RepoCreate's
// already is. Over a new base this ends the statement's effect there (§7.9's base row).
var ErrAclAccessLogFold = errors.New("access log statement does not fold here")

// One statement that took effect, with what its check found.
type AclAccessLogEntry struct {
	Statement *AclStatement
	Verdict   *AclStatementVerdict
}

// The repos after folding entries in order onto repos, which are not changed: only the rows a statement touches are
// copied. A statement that is no access-log statement, EvsShare or OwnerConfirm folds nothing.
func FoldAclRepos(repos []*protocol.AclRepo, entries []AclAccessLogEntry) ([]*protocol.AclRepo, error) {
	next := repos
	cloned := false
	// a repo row to change: copied once per fold, the list with it
	repoForWrite := func(repoIdBytes []byte) (*protocol.AclRepo, error) {
		for i, repo := range next {
			if !bytes.Equal(repo.GetRepoId(), repoIdBytes) {
				continue
			}
			if !cloned {
				next = slices.Clone(next)
				cloned = true
			}
			copied := proto.Clone(repo).(*protocol.AclRepo)
			next[i] = copied
			return copied, nil
		}
		return nil, ErrAclAccessLogFold
	}
	for _, entry := range entries {
		statement, verdict := entry.Statement, entry.Verdict
		if statement == nil || verdict == nil {
			return nil, ErrAclAccessLogFold
		}
		at := statement.N
		signer := verdict.Signer.Bytes()
		switch body := statement.Body.(type) {
		case *protocol.RepoCreate:
			if slices.ContainsFunc(next, func(repo *protocol.AclRepo) bool { return bytes.Equal(repo.GetRepoId(), body.GetRepoId()) }) {
				return nil, ErrAclAccessLogFold
			}
			repo := &protocol.AclRepo{
				RepoId: bytes.Clone(body.GetRepoId()),
				Kind:   body.GetKind(),
				Admins: []*protocol.AclRepoAdminRow{{SidecarId: signer, Signer: signer, At: at}},
			}
			if aclRepoKindOwnerBound(body.GetKind()) {
				repo.OwnerMemberId = verdict.MemberId.Bytes()
				for _, sidecarId := range verdict.ConsentedSidecarIds {
					repo.ConsentedSidecarIds = append(repo.ConsentedSidecarIds, sidecarId.Bytes())
				}
			}
			next = append(slices.Clone(next), repo)
			cloned = true
		case *protocol.RepoAdmin:
			repo, err := repoForWrite(body.GetRepoId())
			if err != nil {
				return nil, err
			}
			repo.Admins = slices.DeleteFunc(repo.Admins, func(admin *protocol.AclRepoAdminRow) bool {
				return bytes.Equal(admin.GetSidecarId(), body.GetSidecarId())
			})
			if body.GetChange() == protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD {
				repo.Admins = append(repo.Admins, &protocol.AclRepoAdminRow{SidecarId: bytes.Clone(body.GetSidecarId()), Signer: signer, At: at})
			}
		case *protocol.RepoGrant:
			repo, err := repoForWrite(body.GetRepoId())
			if err != nil {
				return nil, err
			}
			repo.Grants = slices.DeleteFunc(repo.Grants, func(grant *protocol.AclRepoGrantRow) bool {
				return bytes.Equal(grant.GetSubject(), body.GetSubject())
			})
			repo.Grants = append(repo.Grants, &protocol.AclRepoGrantRow{
				Subject: bytes.Clone(body.GetSubject()), Role: body.GetRole(), Expires: body.GetExpires(), Signer: signer, At: at,
			})
			if verdict.ConfigWriter {
				repo.Revokes = aclDropRevokes(repo.Revokes, body.GetSubject())
			}
		case *protocol.RepoRevoke:
			repo, err := repoForWrite(body.GetRepoId())
			if err != nil {
				return nil, err
			}
			repo.Grants = slices.DeleteFunc(repo.Grants, func(grant *protocol.AclRepoGrantRow) bool {
				return bytes.Equal(grant.GetSubject(), body.GetSubject())
			})
			repo.Shares = slices.DeleteFunc(repo.Shares, func(share *protocol.AclRepoShareRow) bool {
				return bytes.Equal(share.GetSubject(), body.GetSubject())
			})
			if verdict.ConfigWriter {
				repo.Revokes = append(aclDropRevokes(repo.Revokes, body.GetSubject()), &protocol.AclRepoRevokeRow{
					Subject: bytes.Clone(body.GetSubject()), Signer: signer, At: at,
				})
			}
		case *protocol.EvsShare:
			repo, err := repoForWrite(body.GetRepoId())
			if err != nil {
				return nil, err
			}
			repo.Shares = slices.DeleteFunc(repo.Shares, func(share *protocol.AclRepoShareRow) bool {
				return bytes.Equal(share.GetSubject(), body.GetSubject())
			})
			repo.Shares = append(repo.Shares, &protocol.AclRepoShareRow{
				Subject: bytes.Clone(body.GetSubject()), Expires: body.GetExpires(), Signer: signer, At: at,
			})
			repo.Revokes = aclDropRevokes(repo.Revokes, body.GetSubject())
		case *protocol.RepoDelete:
			repo, err := repoForWrite(body.GetRepoId())
			if err != nil {
				return nil, err
			}
			repo.Deletion = &protocol.AclRepoDeletionRow{DeletionId: bytes.Clone(body.GetDeletionId()), Now: body.GetNow(), DeletedAt: at}
		case *protocol.RepoRestore:
			repo, err := repoForWrite(body.GetRepoId())
			if err != nil {
				return nil, err
			}
			deletion := repo.GetDeletion()
			if deletion == nil || !bytes.Equal(deletion.GetDeletionId(), body.GetDeletionId()) || deletion.GetNow() || deletion.GetRestoredAt() != 0 {
				return nil, ErrAclAccessLogFold
			}
			deletion.RestoredAt = at
		case *protocol.RepoVersioning:
			repo, err := repoForWrite(body.GetRepoId())
			if err != nil {
				return nil, err
			}
			repo.Lock = body.GetLock()
		case *protocol.OwnerConfirm:
			for _, repo := range next {
				if !aclRepoKindOwnerBound(repo.GetKind()) || Id(repo.GetOwnerMemberId()) != verdict.MemberId ||
					slices.ContainsFunc(repo.GetConsentedSidecarIds(), func(listed []byte) bool { return bytes.Equal(listed, body.GetSidecarId()) }) {
					continue
				}
				copied, _ := repoForWrite(repo.GetRepoId())
				copied.ConsentedSidecarIds = append(copied.ConsentedSidecarIds, bytes.Clone(body.GetSidecarId()))
			}
		}
	}
	return next, nil
}

// The revokes without the subject's.
func aclDropRevokes(revokes []*protocol.AclRepoRevokeRow, subject []byte) []*protocol.AclRepoRevokeRow {
	return slices.DeleteFunc(revokes, func(revoke *protocol.AclRepoRevokeRow) bool {
		return bytes.Equal(revoke.GetSubject(), subject)
	})
}

// Whether the rows hold the sidecar as the repo's admin at position: an admin row added at or before it, while it
// stands (§8.8's access logs). The directory's config writers and an owner-bound repo's consent are the caller's, as
// the check at that position reads them. A removed admin's row is gone, so its right before the removal is not told
// (question acl-m2-06-access-log-positions).
func (self *AclState) RepoAdminAt(repoId Id, sidecarId Id, position uint64) bool {
	repo := self.repos[repoId]
	if repo == nil {
		return false
	}
	for _, admin := range repo.row.GetAdmins() {
		if Id(admin.GetSidecarId()) == sidecarId && admin.GetAt() <= position {
			return true
		}
	}
	return false
}

// One EvsShare a compromise cascade voids.
type AclVoidedShare struct {
	RepoId  Id
	Subject Id
	Signer  Id
	// The position of the entry that carried it.
	At uint64
}

// The EvsShares §7.9's cascade voids, in repo then position order: each whose signer is in P at the share's position,
// parkedFrom giving each sidecar of P the position from which it is in P. A share stays void until a signer outside
// P shares again, a newer row replacing it. TEAM-M2-04's CascadePlan lists them; the state judges each share itself
// through AclAuthView.CascadeVoids.
func (self *AclState) VoidEvsShares(parkedFrom map[Id]uint64) []AclVoidedShare {
	voided := []AclVoidedShare{}
	for _, row := range self.rows.GetRepos() {
		for _, share := range row.GetShares() {
			signerId, err := IdFromBytes(share.GetSigner())
			if err != nil {
				continue
			}
			from, inP := parkedFrom[signerId]
			if !inP || share.GetAt() < from {
				continue
			}
			voided = append(voided, AclVoidedShare{RepoId: Id(row.GetRepoId()), Subject: Id(share.GetSubject()), Signer: signerId, At: share.GetAt()})
		}
	}
	slices.SortStableFunc(voided, func(a AclVoidedShare, b AclVoidedShare) int {
		if c := a.RepoId.Cmp(b.RepoId); c != 0 {
			return c
		}
		return cmp.Compare(a.At, b.At)
	})
	return voided
}
