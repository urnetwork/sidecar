// The real EvsAuthState (ACL-M2-14): evs's newest verified authorization state is §8.9's one per-process gate cache,
// sidecar.AclGateCache (C-09), and §7.8's rev/ objects are TEAM-M1-07's sidecar.RevocationChecker, so evs judges a
// token by the log alone and api stays a carrier:
//
//	CheckRevocation  rev/ for the token's client, sidecar and member, each answer kept at most 5 s (§7.8's check row)
//	MatchBinding     the token's ur_sidecar_id an admitted, unrevoked sidecar of the token's network in the newest
//	                 verified state. The token's (ur_sidecar_id, ur_client_id) pair is §5's binding as the exchange
//	                 bound it at the mint (QD-717): the log carries no client ids and evs keeps no Postgres, so evs
//	                 looks no binding up, and a looked-up one would be api's assertion just as the token is
//	HonorScope       AclGateCache.HonorScope for the evs audience (D-ACL-21, QD-070), so a subject a group edit, a
//	                 Suspend or an expiry drops loses the scope within §8.9's 5 s, not at the token's 15 minutes
//	Repo             the repo's AclRepo row in the token's network's state: its kind, owner and newest RepoDelete, with
//	                 the RepoDelete's time from its row (QD-743) and its signer only while the gate's log keeps that
//	                 entry
//	RepoDeletion     the same RepoDelete by network rather than by token, so the state is also taskworker's
//	                 EvsRepoDeletionSource: §11.12's shred start and reconciler judge from rows alone
//
// A sidecar rebound to a new client leaves its old client's tokens reading for at most a token's life (15 minutes);
// the old client's writes are voided by the rev/ object every write reads (CheckRevocation).
//
// Every doubt answers EvsAuthUnknown, which evs answers 503: a network not loaded and no rev/ reader. D-EVS-18's
// head-CAS check is §11's and reads the same cache through EvsGateViews.
//
// Safe for concurrent use. CheckRevocation does I/O under ctx; the rest answer from memory and allocate nothing on a
// loaded network.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// §8.9's gate cache as the real EvsAuthState reads it: sidecar.AclGateCache's methods, or a test's stand-in.
type EvsAclGate interface {
	// The network's verified state and what the cache says of it, with no I/O.
	State(networkId sidecar.Id) (*sidecar.AclGateSnapshot, sidecar.AclGateStatus)
	// Tells the cache a gate needs the network, which starts its load.
	Changed(networkId sidecar.Id)
}

// The rev/ reader the real EvsAuthState uses: sidecar.RevocationChecker's Check, or a test's stand-in.
type EvsRevocationReader interface {
	Check(ctx context.Context, principal *sidecar.Principal) error
}

// The real EvsAuthState. See the file header.
type AclEvsAuthState struct {
	gate        EvsAclGate
	revocations EvsRevocationReader
}

// The state over gate, reading rev/ through revocations. A nil gate or revocations answers every check that needs
// it 503.
func NewAclEvsAuthState(gate EvsAclGate, revocations EvsRevocationReader) *AclEvsAuthState {
	return &AclEvsAuthState{gate: gate, revocations: revocations}
}

var (
	_ EvsAuthState          = (*AclEvsAuthState)(nil)
	_ EvsRepoDeletionSource = (*AclEvsAuthState)(nil)
)

// The snapshot of the token's network, Unknown while it is not loaded; a network the cache has not heard of is told
// to it.
func (self *AclEvsAuthState) snapshot(principal *sidecar.Principal) (*sidecar.AclGateSnapshot, EvsAuthAnswer) {
	if principal == nil {
		return nil, EvsAuthUnknown
	}
	return self.networkSnapshot(sidecar.Id(principal.NetworkId))
}

// The snapshot of a network, Unknown while it is not loaded; a network the cache has not heard of is told to it.
func (self *AclEvsAuthState) networkSnapshot(networkId sidecar.Id) (*sidecar.AclGateSnapshot, EvsAuthAnswer) {
	if self.gate == nil {
		return nil, EvsAuthUnknown
	}
	snapshot, status := self.gate.State(networkId)
	switch status {
	case sidecar.AclGateLoaded:
	case sidecar.AclGateUnknown:
		self.gate.Changed(networkId)
		return nil, EvsAuthUnknown
	default:
		return nil, EvsAuthUnknown
	}
	if snapshot == nil || snapshot.Acl == nil {
		return nil, EvsAuthUnknown
	}
	return snapshot, EvsAuthAllowed
}

// See EvsAuthState: ErrEvsTokenRevoked when an object voids a subject, any other error when evs cannot tell.
func (self *AclEvsAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	if self.revocations == nil {
		return errors.New("this evs reads no revocations")
	}
	err := self.revocations.Check(ctx, principal)
	if errors.Is(err, sidecar.ErrRevocationVoidsToken) {
		return fmt.Errorf("%w: %w", ErrEvsTokenRevoked, err)
	}
	return err
}

// See EvsAuthState and the file header: the snapshot is the token's network's, so a sidecar that network never
// admitted, one it revoked and one another network admitted are all denied, and the token's client is taken as the
// exchange bound it.
func (self *AclEvsAuthState) MatchBinding(principal *sidecar.Principal) EvsAuthAnswer {
	snapshot, answer := self.snapshot(principal)
	if answer != EvsAuthAllowed {
		return answer
	}
	if principal.SidecarId == nil {
		return EvsAuthDenied
	}
	if !snapshot.Acl.Admitted(sidecar.Id(*principal.SidecarId)) {
		return EvsAuthDenied
	}
	return EvsAuthAllowed
}

// See EvsAuthState: AclGateCache.HonorScope's answer for the evs audience.
func (self *AclEvsAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) EvsAuthAnswer {
	snapshot, answer := self.snapshot(principal)
	if answer != EvsAuthAllowed {
		return answer
	}
	if principal.SidecarId == nil {
		return EvsAuthDenied
	}
	switch sidecar.AclHonorScope(snapshot.Acl, sidecar.Id(*principal.SidecarId), repoId, rights, sidecar.AclTokenAudienceEvs, now) {
	case sidecar.AclScopeHonored:
		return EvsAuthAllowed
	case sidecar.AclScopeRefused:
		return EvsAuthDenied
	}
	return EvsAuthUnknown
}

// See EvsAuthState. The newest RepoDelete comes dated by its row's own time on any day of its window (QD-743), and with
// its signer only while the gate's log keeps its entry: restore needs neither, and DELETE without now refuses one whose
// signer it lacks (decideDelete), the closed direction. A RepoDelete without now that its row does not date, which no
// fold writes, is left out of the facts, so DELETE and restore answer 409 STATEMENT_MISSING for it; a RepoDelete{now}
// needs no date.
func (self *AclEvsAuthState) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*EvsRepoFacts, EvsAuthAnswer) {
	snapshot, answer := self.snapshot(principal)
	if answer != EvsAuthAllowed {
		return nil, answer
	}
	row := snapshot.Acl.Repo(repoId)
	if row == nil {
		return nil, EvsAuthDenied
	}
	facts := &EvsRepoFacts{Kind: row.GetKind(), NetworkId: sidecar.Id(principal.NetworkId)}
	if len(row.GetOwnerMemberId()) != 0 {
		ownerMemberId, err := sidecar.IdFromBytes(row.GetOwnerMemberId())
		if err != nil {
			return nil, EvsAuthUnknown
		}
		facts.OwnerMemberId = ownerMemberId
	}
	facts.Deletion = aclEvsDeletionFacts(snapshot.RepoDeletion(repoId))
	return facts, EvsAuthAllowed
}

// A RepoDelete that cannot be judged from what the state holds: one without now whose row carries no time.
var errAclEvsDeletionUndated = errors.New("the projection holds a RepoDelete it does not date")

// The facts a gate's RepoDelete gives, nil for none and for one without now its row does not date.
func aclEvsDeletionFacts(deletion *sidecar.AclRepoDeletion) *EvsRepoDeletionFacts {
	if deletion == nil || !(deletion.Dated || deletion.Now) {
		return nil
	}
	facts := &EvsRepoDeletionFacts{
		DeletionId: deletion.DeletionId,
		Now:        deletion.Now,
		Restored:   deletion.Restored,
	}
	if deletion.Dated {
		facts.Time = time.UnixMilli(deletion.TimeMs)
	}
	if deletion.Signed {
		facts.SignerSidecarId = deletion.SignerSidecarId
	}
	return facts
}

// See EvsRepoDeletionSource: the repo's newest RepoDelete in networkId's newest verified state, for §11.12's shred start
// and reconciler, judged from its rows alone, so a start 7 d 10 min after the entry finds the deletion dated and its
// RepoRestore, if any, though the gate's log no longer keeps either entry (QD-743). nil when the state holds no
// RepoDelete of the repo. An error, which leaves the repo as it is to be asked again, while the network's state is not
// loaded (a network the cache has not heard of is told to it, which starts its load), and for a RepoDelete without now
// that its row does not date, which neither a start nor the reconciler may take for no deletion.
func (self *AclEvsAuthState) RepoDeletion(ctx context.Context, networkId sidecar.Id, repoId sidecar.Id) (*EvsRepoDeletionFacts, error) {
	snapshot, answer := self.networkSnapshot(networkId)
	if answer != EvsAuthAllowed {
		return nil, fmt.Errorf("network %s's authorization state is not loaded", sidecar.EvsKeyId(networkId))
	}
	deletion := snapshot.RepoDeletion(repoId)
	if deletion == nil {
		return nil, nil
	}
	facts := aclEvsDeletionFacts(deletion)
	if facts == nil {
		return nil, errAclEvsDeletionUndated
	}
	return facts, nil
}
