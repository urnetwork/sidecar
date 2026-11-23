// §8.8's access logs folded into AclRows' repos (owner decision 8): each statement with its signer's sidecar_id and
// the log position of the entry that carried it, so a reader judges a signer's repo admin right at a position, and
// §7.9's cascade finds what P signed. The rows keep:
//
//	admins       RepoCreate's signer, then RepoAdmin's adds; a remove stamps the standing row's removed_at and keeps
//	             it, so the admin's right before the removal is still told (QD-743), and an add of a sidecar that
//	             stands replaces its standing row
//	grants       the newest RepoGrant per subject; a later RepoRevoke of the subject takes it out
//	shares       the newest EvsShare per subject; a RepoRevoke of the subject takes it out too
//	revokes      config writers' standing RepoRevokes, one per subject, until a config writer's RepoGrant of that
//	             subject, or in an owner-bound repo its owner's EvsShare to it, lifts it
//	             (plan-ACL-owner-bound-standing-revoke)
//	deletion     the newest RepoDelete with its entry's time_ms (QD-743) and its signer (QD-798), restored_at set by
//	             the RepoRestore of its deletion_id, so §11.12's deleted{deletion_id, time, signer} is told from the
//	             row on any day, the log keeping the entry or not
//	lock         the newest RepoVersioning's; format 1 folds it and enforces nothing (D-PHASE-9)
//	prefix_rules each RepoPrefixRules' {signer, at}, appended and never removed or reordered, so in position order
//	             for the repo's life: a set stays after a later one replaces it, since pushes pinned in its span are
//	             judged by it, and a compromise cascade voids none. Nothing else moves: no right, holder or key
//	             changes, so holders_shrunk_at stays and no generation is asked for. M2 folds it and enforces
//	             nothing (D-PHASE-9; DESIGN-DETAILS 16.2.3). At launch none is folded: the rules moved to Later
//	             (QD-1032), and the log refuses every RepoPrefixRules before it reaches this fold
//	             (acl_statement.go's configAclPrefixRulesDark), so the list stays empty unless a log runs the rules
//	owner        RepoCreate's signer's member for an owner-bound kind (vault, mailbox, secret), and for a mailcfg
//	             that is a Team scope's own, its creator's member's, as a mailbox is its member's: one whose signer
//	             is a member device that writes no config heads (QD-1093), or a config writer's while a network
//	             mailcfg stands (QD-1108). A config writer's mailcfg while none stands names no owner and is the
//	             network's, so the first standing unowned mailcfg is the network's, and once the network's is deleted
//	             the next config writer's creation is the network's again (aclNetworkMailcfgStands reads the rows the
//	             fold holds at the entry, which every reader holds alike). Every other mailcfg is owned, a member's
//	             second too, so none of them ever reads as the network's; which of a member's is its scope's, the
//	             first in log order, is the reader's (MailRepos.ScopeMailConfigRepo)
//	consented    exactly the owner's consented devices now (§8.5's consented(d, M); §8.8's "the owner's consented
//	             sidecar_ids"; QD-1191) of an owner-bound repo, an owned mailcfg's too: those consented at its
//	             RepoCreate, each its owner's OwnerConfirm adds, and each device consented after the RepoCreate any
//	             other way, by its admission's signers (the scoped clause), an AdmissionConfirm from the owner's
//	             consented device or the invited clause, which TEAM's configAdvanceConsents lists at the entry that
//	             consents it (AclState.listConsentedOwnerDevices), so a member's second device reads its vault from
//	             its admission on, between bases included (owner decision 355), at every reader, gate and api alike.
//	             The same step drops a listed device at the entry that ends its consent, revoked, parked, its consent
//	             voided by a compromise cascade, its member gone or ephemeral, an OwnerConfirm's listing of a device
//	             that entry leaves unconsented among them, and lists it again at the entry whose confirmation by the
//	             owner's consented device, or whose lift of its park, consents it again. So gkm's rows-only form and
//	             members checks and evs's client-side drop check, which read the list beside the device's row, refuse
//	             what AclState's readers refuse, which judge consented(d, M) beside it too, and a reader judging a
//	             past act, a GroupForm, a commit or a DROP, reads the list at the act's own pin
//	shrunk time  RepoCreate's entry time_ms as holders_shrunk_time_ms, the repo's t_s while holders_shrunk_at is 0,
//	             which §7.9's shrink row compares its holders at (QD-883); TEAM's configSetShrunkAt writes both
//	             fields at each shrink after, and bases carry them, so a verifier that starts at a base reads the
//	             time however old the making is (QD-1015)
//
// FoldAclRepos is one pure fold, which ApplyStatement runs per entry and a writer's compile may run over the
// statements a base folds; it judges nothing, so it takes only statements that took effect, each with its verdict.
// A removed admin's row stays until a base's compile (config_base.go's foldRows) finds its removal before the base's
// retention point, where aclRowsKeptAt drops it: from that point on no position finds the admin standing, so every
// answer the rows give at a position the log can still name is unchanged, and every reader drops it at the same base.
//
// Readers of the admins other than RepoAdminAt take the standing rows alone, as AclRepoAdminStands says.
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
			if !aclRepoInboxFits(body.GetKind(), body.GetInbox()) || (body.GetInbox() == protocol.RepoInbox_REPO_INBOX_ADMIN &&
				slices.ContainsFunc(next, func(repo *protocol.AclRepo) bool { return repo.GetInbox() == protocol.RepoInbox_REPO_INBOX_ADMIN })) {
				return nil, ErrAclAccessLogFold
			}
			if slices.ContainsFunc(next, func(repo *protocol.AclRepo) bool { return bytes.Equal(repo.GetRepoId(), body.GetRepoId()) }) {
				return nil, ErrAclAccessLogFold
			}
			repo := &protocol.AclRepo{
				RepoId: bytes.Clone(body.GetRepoId()),
				Kind:   body.GetKind(),
				Inbox:  body.GetInbox(),
				Admins: []*protocol.AclRepoAdminRow{{SidecarId: signer, Signer: signer, At: at}},
				// the making is the repo's t_s until its first shrink (QD-1015)
				HoldersShrunkTimeMs: statement.TimeMs,
			}
			ownerBound := aclRepoKindOwnerBound(body.GetKind())
			if body.GetKind() == protocol.RepoKind_REPO_KIND_MAILCFG && (!verdict.ConfigWriter || aclNetworkMailcfgStands(next)) {
				// a Team scope's own, its creator's member's: a member device's that writes no config heads (QD-1093),
				// or a config writer's while the network's stands (QD-1108). A verdict naming no member here is one no
				// check gives, and folds to nothing: read as unowned it would stand as the network's, or beside it
				if verdict.MemberId == (Id{}) {
					return nil, ErrAclAccessLogFold
				}
				ownerBound = true
			}
			if ownerBound {
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
			standingRow := func(admin *protocol.AclRepoAdminRow) bool {
				return AclRepoAdminStands(admin) && bytes.Equal(admin.GetSidecarId(), body.GetSidecarId())
			}
			if body.GetChange() == protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD {
				// a removed row keeps its own span; a standing one gives way to the newest add's signer and position
				repo.Admins = slices.DeleteFunc(repo.Admins, standingRow)
				repo.Admins = append(repo.Admins, &protocol.AclRepoAdminRow{SidecarId: bytes.Clone(body.GetSidecarId()), Signer: signer, At: at})
			} else {
				// the row is the repo's copy (repoForWrite), so it is stamped in place; a sidecar with no standing row
				// stamps nothing, as a remove of a non-admin always folded to nothing
				for _, admin := range repo.Admins {
					if standingRow(admin) {
						admin.RemovedAt = at
					}
				}
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
			repo.Deletion = &protocol.AclRepoDeletionRow{
				DeletionId: bytes.Clone(body.GetDeletionId()), Now: body.GetNow(), DeletedAt: at, DeletedTimeMs: statement.TimeMs,
				Signer: signer,
			}
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
		case *protocol.RepoPrefixRules:
			// the row is the repo's copy (repoForWrite), its list with it; the pair is the body's and the position's,
			// so ApplyStatement, a base's tail re-applied and a writer's compile append the same row (DESIGN-DETAILS
			// 5.2.2)
			repo, err := repoForWrite(body.GetRepoId())
			if err != nil {
				return nil, err
			}
			repo.PrefixRules = append(repo.PrefixRules, &protocol.AclRepoPrefixRulesRow{Signer: signer, At: at})
		case *protocol.OwnerConfirm:
			for _, repo := range next {
				if !aclRepoRowOwnerBound(repo) || !bytes.Equal(repo.GetOwnerMemberId(), verdict.MemberId.Bytes()) ||
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

// repos with each owner-bound row, an owned mailcfg's included, listing exactly the devices this state consents for
// the row's owner now (§8.5's consented(d, M); QD-1191): a listed device this state does not consent for the owner
// leaves the list, as does a repeat of one it keeps, the ids that stay keep their order, and each consented device the
// row does not list is appended after them in sidecar_id order. The file header's consented row, which TEAM's
// configAdvanceConsents runs on the state an entry built. A pure function of the rows and the state's consent replay,
// so every reader lists and drops the same ids at the same entry. repos is not changed: a row whose list changes is
// copied, the list with it, and false is returned with repos itself when none does. A row naming no valid owner keeps
// its list, which no rows a state can index hold.
func (self *AclState) listConsentedOwnerDevices(repos []*protocol.AclRepo) ([]*protocol.AclRepo, bool) {
	// each member's consented devices, in sidecar_id order, built only for the owners the rows name
	var memberConsentedIds map[Id][]Id
	consentedIds := func(memberId Id) []Id {
		if memberConsentedIds == nil {
			memberConsentedIds = map[Id][]Id{}
			for i := range self.sidecars {
				sidecar := &self.sidecars[i]
				if self.sidecarConsented(sidecar) {
					memberConsentedIds[sidecar.memberId] = append(memberConsentedIds[sidecar.memberId], sidecar.id)
				}
			}
		}
		return memberConsentedIds[memberId]
	}
	holds := func(sidecarIds [][]byte, sidecarId []byte) bool {
		return slices.ContainsFunc(sidecarIds, func(heldId []byte) bool { return bytes.Equal(heldId, sidecarId) })
	}
	var next []*protocol.AclRepo
	for i, repo := range repos {
		if !aclRepoRowOwnerBound(repo) {
			continue
		}
		ownerId, err := IdFromBytes(repo.GetOwnerMemberId())
		if err != nil || ownerId == (Id{}) {
			continue
		}
		ownerConsentedIds := consentedIds(ownerId)
		listedIds := repo.GetConsentedSidecarIds()
		consentedIdBytes := make([][]byte, 0, len(ownerConsentedIds))
		for _, sidecarId := range ownerConsentedIds {
			consentedIdBytes = append(consentedIdBytes, sidecarId.Bytes())
		}
		keptIds := make([][]byte, 0, len(consentedIdBytes))
		for _, listedId := range listedIds {
			if holds(consentedIdBytes, listedId) && !holds(keptIds, listedId) {
				keptIds = append(keptIds, bytes.Clone(listedId))
			}
		}
		for _, consentedId := range consentedIdBytes {
			if !holds(keptIds, consentedId) {
				keptIds = append(keptIds, consentedId)
			}
		}
		if slices.EqualFunc(keptIds, listedIds, bytes.Equal) {
			continue
		}
		if next == nil {
			next = slices.Clone(repos)
		}
		copied := proto.Clone(repo).(*protocol.AclRepo)
		copied.ConsentedSidecarIds = keptIds
		next[i] = copied
	}
	if next == nil {
		return repos, false
	}
	return next, true
}

// Whether a repo row stands: no RepoDelete, or its newest one restored.
func aclRepoRowStands(repo *protocol.AclRepo) bool {
	deletion := repo.GetDeletion()
	return deletion == nil || deletion.GetDeletedAt() == 0 || deletion.GetRestoredAt() != 0
}

// Whether the network's mailcfg stands among repos: a standing mailcfg whose row names no owner. The first such in log
// order is the network's (QD-1093), and while one stands every mailcfg RepoCreate is its signer's member's Team scope's
// own, a config writer's included (QD-1108). checkRepoCreate, its re-application over a base and the fold all ask it of
// the rows at the entry's position, which every reader holds alike, so each reads the same creation the same way.
func aclNetworkMailcfgStands(repos []*protocol.AclRepo) bool {
	return slices.ContainsFunc(repos, func(repo *protocol.AclRepo) bool {
		return repo.GetKind() == protocol.RepoKind_REPO_KIND_MAILCFG && len(repo.GetOwnerMemberId()) == 0 && aclRepoRowStands(repo)
	})
}

// The revokes without the subject's.
func aclDropRevokes(revokes []*protocol.AclRepoRevokeRow, subject []byte) []*protocol.AclRepoRevokeRow {
	return slices.DeleteFunc(revokes, func(revoke *protocol.AclRepoRevokeRow) bool {
		return bytes.Equal(revoke.GetSubject(), subject)
	})
}

// Whether an admin row stands: no RepoAdmin{remove} has stamped it. Every reader that asks who administers a repo now
// reads these rows alone; only RepoAdminAt reads a removed one, for a position before its removal.
func AclRepoAdminStands(admin *protocol.AclRepoAdminRow) bool {
	return admin.GetRemovedAt() == 0
}

// Whether the rows hold the sidecar as the repo's admin at position: an admin row added at or before it and not removed
// by then, the removal's own position included (§8.8's access logs; QD-743), so an admin removed later is told an admin
// before its removal. The directory's config writers and an owner-bound repo's consent are the caller's, as the check
// at that position reads them. A removed admin's row leaves at the first base whose retention point passed its removal
// (aclRowsKeptAt), after which a position before that point is not told for it.
func (self *AclState) RepoAdminAt(repoId Id, sidecarId Id, position uint64) bool {
	repo := self.repos[repoId]
	if repo == nil {
		return false
	}
	for _, admin := range repo.row.GetAdmins() {
		if Id(admin.GetSidecarId()) != sidecarId || position < admin.GetAt() {
			continue
		}
		if AclRepoAdminStands(admin) || position < admin.GetRemovedAt() {
			return true
		}
	}
	return false
}

// The acl rows a base's compile carries, its retention point retentionPoint (§7.9's retention row): rows less each
// removed admin row whose removal lies before the point (QD-743). From the point on, the log names no position at which
// such an admin stands, so the rows answer RepoAdminAt as before at every position a statement or pin there can name.
// A function of rows and positions alone, as QD-648's forwarding rows are, so every reader drops a row at the same base.
// rows is not changed; it is returned itself when nothing leaves.
func aclRowsKeptAt(rows *protocol.AclRows, retentionPoint uint64) *protocol.AclRows {
	leaves := func(admin *protocol.AclRepoAdminRow) bool {
		return !AclRepoAdminStands(admin) && admin.GetRemovedAt() < retentionPoint
	}
	var kept *protocol.AclRows
	for i, repo := range rows.GetRepos() {
		if !slices.ContainsFunc(repo.GetAdmins(), leaves) {
			continue
		}
		if kept == nil {
			kept = aclRowsCopy(rows)
			kept.Repos = slices.Clone(rows.GetRepos())
		}
		copied := proto.Clone(repo).(*protocol.AclRepo)
		copied.Admins = slices.DeleteFunc(copied.Admins, leaves)
		kept.Repos[i] = copied
	}
	if kept == nil {
		return rows
	}
	return kept
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
