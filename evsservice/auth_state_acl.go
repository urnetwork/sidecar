// The real EvsAuthState (ACL-M2-14): evs's newest verified authorization state is §8.9's one per-process gate cache,
// sidecar.AclGateCache (C-09), and §7.8's rev/ objects are TEAM-M1-07's sidecar.RevocationChecker, so evs judges a
// token by the log alone and api stays a carrier:
//
//	CheckRevocation  rev/ for the token's client, sidecar and member, each answer kept at most 5 s (§7.8's check row)
//	MatchBinding     the token's ur_sidecar_id admitted and not revoked in the newest verified state, and §5's binding
//	                 of its ur_client_id to that sidecar, which the log does not carry: an EvsBindingSource answers it
//	HonorScope       AclGateCache.HonorScope for the evs audience (D-ACL-21, QD-070), so a subject a group edit, a
//	                 Suspend or an expiry drops loses the scope within §8.9's 5 s, not at the token's 15 minutes
//	Repo             the repo's AclRepo row in the token's network's state: its kind, owner and newest RepoDelete, with
//	                 the RepoDelete's time and signer only while the gate's log keeps that entry
//
// Every doubt answers EvsAuthUnknown, which evs answers 503: a network not loaded, no rev/ reader, and no binding source.
// With no EvsBindingSource every request answers 503, the closed direction, until a host supplies one (question
// acl-m2-11-evs-binding-source). D-EVS-18's head-CAS check is §11's and reads the same cache through EvsGateViews.
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

// Where evs learns §5's binding of a client to a sidecar, which the authorization log does not carry: a host's cache
// of api's binding lookups. It answers from memory, Unknown on a miss it has asked about, and never blocks.
type EvsBindingSource interface {
	MatchBinding(networkId sidecar.Id, clientId sidecar.Id, sidecarId sidecar.Id) EvsAuthAnswer
}

// The rev/ reader the real EvsAuthState uses: sidecar.RevocationChecker's Check, or a test's stand-in.
type EvsRevocationReader interface {
	Check(ctx context.Context, principal *sidecar.Principal) error
}

// The real EvsAuthState. See the file header.
type AclEvsAuthState struct {
	gate        EvsAclGate
	revocations EvsRevocationReader
	bindings    EvsBindingSource
}

// The state over gate, reading rev/ through revocations and bindings through bindings. A nil gate or revocations
// answers every check that needs it 503; a nil bindings answers every MatchBinding 503.
func NewAclEvsAuthState(gate EvsAclGate, revocations EvsRevocationReader, bindings EvsBindingSource) *AclEvsAuthState {
	return &AclEvsAuthState{gate: gate, revocations: revocations, bindings: bindings}
}

var _ EvsAuthState = (*AclEvsAuthState)(nil)

// The snapshot of the token's network, Unknown while it is not loaded; a network the cache has not heard of is told
// to it.
func (self *AclEvsAuthState) snapshot(principal *sidecar.Principal) (*sidecar.AclGateSnapshot, EvsAuthAnswer) {
	if self.gate == nil || principal == nil {
		return nil, EvsAuthUnknown
	}
	networkId := sidecar.Id(principal.NetworkId)
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

// See EvsAuthState and the file header.
func (self *AclEvsAuthState) MatchBinding(principal *sidecar.Principal) EvsAuthAnswer {
	snapshot, answer := self.snapshot(principal)
	if answer != EvsAuthAllowed {
		return answer
	}
	if principal.SidecarId == nil {
		return EvsAuthDenied
	}
	sidecarId := sidecar.Id(*principal.SidecarId)
	if !snapshot.Acl.Admitted(sidecarId) {
		return EvsAuthDenied
	}
	if self.bindings == nil {
		return EvsAuthUnknown
	}
	return self.bindings.MatchBinding(sidecar.Id(principal.NetworkId), sidecar.Id(principal.ClientId), sidecarId)
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

// See EvsAuthState. A RepoDelete the gate's log no longer dates is left out of the facts, so DELETE and restore answer
// 409 STATEMENT_MISSING for it, the closed direction, until the row carries its time (question
// acl-m2-06-access-log-positions); a RepoDelete{now} needs no date.
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
	if deletion := snapshot.RepoDeletion(repoId); deletion != nil && (deletion.Dated || deletion.Now) {
		facts.Deletion = &EvsRepoDeletionFacts{
			DeletionId: deletion.DeletionId,
			Now:        deletion.Now,
			Restored:   deletion.Restored,
		}
		if deletion.Dated {
			facts.Deletion.Time = time.UnixMilli(deletion.TimeMs)
			facts.Deletion.SignerSidecarId = deletion.SignerSidecarId
		}
	}
	return facts, EvsAuthAllowed
}
