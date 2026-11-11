//go:build !sidecar_http && !ios_extension

// §7.9's tokens row at a gate (D-ACL-21, QD-070): evs and gkm honor a repo:<id>:<role> capability only while its
// subject holds that right on the repo in their newest verified state, beside the rev/ objects RevocationChecker reads.
// A token states what the exchange saw, up to 15 minutes ago, so a capability in hand means nothing without this
// check: a subject a group edit, a Suspend, a revocation, a cascade park or an expiry drops loses the scope as soon as
// the gate's state moves, within §8.9's 5 s, not at the token's end.
//
// The four rights are AclState.EvsAccess's for the token's audience, which intersects the per-repo rule bitsets the
// state built once at its position and reads each candidate rule's expiry against now, so a check allocates nothing:
//
//	r        while the subject reads the repo
//	rw       while it writes it (write implies read)
//	admin    while it administers it (admin implies write), as the repo's admins and, in the directory, its consented,
//	         not-read-only admins alone hold it (§8.10)
//	deposit  while §8 gives it deposit there, or it reads an owner-bound repo it does not write (§16.8's receipts);
//	         deposit implies no read, so a deposit-only subject is never counted a reader
//
// The audience matters only on the config: member devices but read_only ones commit its group at gkm, while evs rw
// stays with config writers (§7.9's commit row, §10.6).
//
// Cold state is no pass: a network the cache holds nothing of, or holds with nothing loaded, answers AclScopeUnknown,
// which every gate answers 503, and a network the cache had never heard of is told to it so its load starts.
//
// Safe for concurrent use. Nothing here creates, derives or unwraps a key.

package sidecar

import (
	"time"
)

// What HonorScope answers.
type AclScopeAnswer int

const (
	// The network's state is not loaded, or the cache holds nothing of it yet: the gate answers 503, retryable, and
	// allows nothing.
	AclScopeUnknown AclScopeAnswer = iota
	// The newest verified state gives the subject the right.
	AclScopeHonored
	// It does not: 403.
	AclScopeRefused
)

// Every right a scope may carry.
const aclEvsAllRights = AclEvsDeposit | AclEvsRead | AclEvsWrite | AclEvsAdmin

// Whether the newest verified state of networkId gives the sidecar subjectId every right of scope on repoId at now,
// for a token of audience: one map read and one EvsAccess, no lock, no I/O and no allocation once the network is
// loaded.
func (self *AclGateCache) HonorScope(networkId Id, subjectId Id, repoId Id, scope AclEvsRights, audience AclTokenAudience, now time.Time) AclScopeAnswer {
	snapshot, status := self.State(networkId)
	switch status {
	case AclGateUnknown:
		// evs's and gkm's networks all have logs: ask for one, and refuse meanwhile
		self.Changed(networkId)
		return AclScopeUnknown
	case AclGateNotLoaded:
		return AclScopeUnknown
	}
	return AclHonorScope(snapshot.Acl, subjectId, repoId, scope, audience, now)
}

// HonorScope's answer from one state: honored only when the sidecar holds every right of scope there at now. A scope
// naming no right, or a right no role carries, is refused.
func AclHonorScope(state *AclState, subjectId Id, repoId Id, scope AclEvsRights, audience AclTokenAudience, now time.Time) AclScopeAnswer {
	if state == nil {
		return AclScopeUnknown
	}
	if scope == 0 || scope&^aclEvsAllRights != 0 {
		return AclScopeRefused
	}
	switch audience {
	case AclTokenAudienceEvs, AclTokenAudienceGkm:
	default:
		return AclScopeRefused
	}
	access := state.EvsAccess(AclSidecarSubject(subjectId), repoId, audience, now)
	if access.Rights.Has(scope) {
		return AclScopeHonored
	}
	return AclScopeRefused
}

// Whether the state holds an admission of the sidecar that is not revoked: what a gate needs before it believes a
// token names a sidecar of this network at all. A suspended, parked or expired admission still stands here; the
// rights checks refuse those.
func (self *AclState) Admitted(sidecarId Id) bool {
	sidecar := self.sidecarState(sidecarId)
	return sidecar != nil && sidecar.valid && !sidecar.revoked && !sidecar.memberGone
}

// A repo's newest RepoDelete as a gate holds it (§8.8's AclRepo deletion row), with what §11.12's DELETE writes into
// repo/: the RepoDelete entry's time and its signer, known only while the gate's log keeps that entry. The row itself
// carries positions alone (question acl-m2-06-access-log-positions), so past the log's window the deletion is undated.
type AclRepoDeletion struct {
	DeletionId Id
	// RepoDelete{now}: straight to shredding, never restorable.
	Now bool
	// The position of the entry that carried the RepoDelete.
	DeletedAt uint64
	// A RepoRestore of DeletionId stands.
	Restored bool
	// Whether the log keeps the RepoDelete's entry, so TimeMs and SignerSidecarId are known.
	Dated bool
	// The entry's time_ms, api's clock when it sequenced it.
	TimeMs int64
	// The sidecar that signed the RepoDelete.
	SignerSidecarId Id
}

// The repo's newest RepoDelete in the snapshot, nil when its rows hold no such repo or no RepoDelete of it.
func (self *AclGateSnapshot) RepoDeletion(repoId Id) *AclRepoDeletion {
	if self == nil || self.Acl == nil {
		return nil
	}
	row := self.Acl.Repo(repoId).GetDeletion()
	if row == nil || row.GetDeletedAt() == 0 {
		return nil
	}
	deletionId, err := IdFromBytes(row.GetDeletionId())
	if err != nil || deletionId == (Id{}) {
		return nil
	}
	deletion := &AclRepoDeletion{
		DeletionId: deletionId,
		Now:        row.GetNow(),
		DeletedAt:  row.GetDeletedAt(),
		Restored:   row.GetRestoredAt() != 0,
	}
	if kept := self.Config.keptEntryAt(row.GetDeletedAt()); kept != nil && kept.statement != nil {
		for _, signer := range kept.statement.signers {
			if signer.Kind == ConfigSignerSidecar {
				deletion.Dated = true
				deletion.TimeMs = kept.entry.GetTimeMs()
				deletion.SignerSidecarId = signer.SidecarId
				break
			}
		}
	}
	return deletion
}

// The entry the state's log keeps at position n, nil when its window holds none there or holds an entry of another
// chain. The window is the log's immutable view, so this reads with no lock.
func (self *ConfigState) keptEntryAt(n uint64) *configKeptEntry {
	if self == nil || self.history == nil || n == 0 || self.n < n {
		return nil
	}
	view := self.history.view.Load()
	if view == nil || n < view.from || view.from+uint64(len(view.entries)) <= n {
		return nil
	}
	kept := view.entries[n-view.from]
	if kept == nil {
		return nil
	}
	if chain, ok := self.chainAt(n); !ok || chain != kept.chain {
		return nil
	}
	return kept
}
