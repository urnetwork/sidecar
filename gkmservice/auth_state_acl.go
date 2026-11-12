// The real GkmAuthState (QD-718, question keys-m2-17-gkm-auth-state-owner): gkm's newest verified authorization
// state is §8.9's one per-process gate cache, sidecar.AclGateCache (C-09), and §7.8's rev/ objects are TEAM-M1-07's
// sidecar.RevocationChecker, so gkm judges a token by the log alone:
//
//	CheckRevocation  rev/ for the token's client, sidecar and member, each answer kept at most 5 s (§7.8's check row)
//	HonorScope       AclGateCache.HonorScope for the gkm audience (D-ACL-21, QD-070): the one scope check, ACL's, in
//	                 which the config gives member devices but read_only ones gkm's rw. No copy of it lives here
//	Reads            the same check for r of another sidecar: a KeyPackage claim's target, a late delivery's recipient
//	Sidecar          the row's standing as members read it (sidecar.GkmSidecarStandingAt), and the acl part's Suspend
//	RepoReaders      §8.12's RepoReaders at now
//	RepoWriters      the repo's writers at now, or in the directory group the config's (§10.9's directory row)
//	PendingTargets   each repo the sidecar reads at now with those writers (§10.6's KeyPackages row)
//	CheckPin         the pin on the state's chain within what it retains; above the state, not reached yet
//	DelegationReads  sidecar.GkmDelegationHolds: a live Delegation whose reach holds the repo, or in the config a
//	                 sidecar's live forwarding Delegation (owner decision 197)
//	DelegationKey    the row's reader key digest (sidecar.GkmDelegationKeySha256), a forwarding row's sidecar, and
//	                 the Genesis's config repo
//	LateHolders      sidecar.GkmLateHolders: who may sign a LATE delivery, the recipient's member's devices first
//	HoldersDropped   sidecar.GkmRemoveDue at the newest state, through now
//
// The gkm-only answers are KEYS's own functions over the snapshot's ConfigState, which is the GkmAuthView every
// member reads, so gkm and the members apply one rule to one state.
//
// Every doubt answers GkmAuthUnknown, which gkm answers 503: a network the cache holds nothing of or holds with
// nothing loaded, no gate, and a state whose holders cannot be computed. Only a loaded state allows or denies. A
// network with no loaded state is asked for at each request's standing check, the first a guard makes: that starts
// the load of one the cache had not heard of, and of one whose first load failed or whose state the cache's byte
// budget evicted, which no event or poll would load again; while a load runs it costs one more, of nothing new, and
// a source that keeps failing is read once a FailureBackoff. CheckRevocation with no rev/ reader is an error that is
// not ErrGkmTokenRevoked, 503.
//
// Safe for concurrent use. CheckRevocation does I/O under ctx; the rest answer from memory. HonorScope and Reads
// allocate nothing on a loaded network; the lists and the holder answers walk the network's sidecars, on routes that
// hint or stage, never on a read's path.

package gkmservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §8.9's gate cache as the real GkmAuthState reads it: sidecar.AclGateCache's methods, or a test's stand-in.
type GkmAclGate interface {
	// The network's verified state and what the cache says of it, with no I/O.
	State(networkId sidecar.Id) (*sidecar.AclGateSnapshot, sidecar.AclGateStatus)
	// Tells the cache a gate needs the network, which starts its load.
	Changed(networkId sidecar.Id)
	// ACL-M2-14's scope check at the newest verified state, which also asks for a network the cache has not heard of.
	HonorScope(networkId sidecar.Id, subjectId sidecar.Id, repoId sidecar.Id, scope sidecar.AclEvsRights, audience sidecar.AclTokenAudience, now time.Time) sidecar.AclScopeAnswer
}

// The rev/ reader the real GkmAuthState uses: sidecar.RevocationChecker's Check, or a test's stand-in.
type GkmRevocationReader interface {
	Check(ctx context.Context, principal *sidecar.Principal) error
}

// The real GkmAuthState. See the file header.
type AclGkmAuthState struct {
	gate        GkmAclGate
	revocations GkmRevocationReader
	clock       sidecar.Clock
}

// The state over gate, reading rev/ through revocations. clock is what a sidecar's covering Delegation is judged
// live at, the engine's; nil is real time. A nil gate answers every check that needs it 503, and a nil revocations
// every CheckRevocation.
func NewAclGkmAuthState(gate GkmAclGate, revocations GkmRevocationReader, clock sidecar.Clock) *AclGkmAuthState {
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	return &AclGkmAuthState{gate: gate, revocations: revocations, clock: clock}
}

var _ GkmAuthState = (*AclGkmAuthState)(nil)

// The snapshot of the token's network, Unknown while it is not loaded, when the cache is asked for it (the file
// header).
func (self *AclGkmAuthState) snapshot(principal *sidecar.Principal) (*sidecar.AclGateSnapshot, GkmAuthAnswer) {
	if self.gate == nil || principal == nil {
		return nil, GkmAuthUnknown
	}
	networkId := sidecar.Id(principal.NetworkId)
	snapshot, status := self.gate.State(networkId)
	if status != sidecar.AclGateLoaded {
		self.gate.Changed(networkId)
		return nil, GkmAuthUnknown
	}
	if snapshot == nil || snapshot.Acl == nil || snapshot.Config == nil {
		return nil, GkmAuthUnknown
	}
	return snapshot, GkmAuthAllowed
}

// Allowed or Denied, for a test the loaded state decides.
func gkmAclAnswer(allowed bool) GkmAuthAnswer {
	if allowed {
		return GkmAuthAllowed
	}
	return GkmAuthDenied
}

// ACL's answer as gkm's.
func gkmAclScopeAnswer(answer sidecar.AclScopeAnswer) GkmAuthAnswer {
	switch answer {
	case sidecar.AclScopeHonored:
		return GkmAuthAllowed
	case sidecar.AclScopeRefused:
		return GkmAuthDenied
	}
	return GkmAuthUnknown
}

// See GkmAuthState: ErrGkmTokenRevoked when an object voids a subject, any other error when gkm cannot tell.
func (self *AclGkmAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	if self.revocations == nil {
		return errors.New("this gkm reads no revocations")
	}
	err := self.revocations.Check(ctx, principal)
	if errors.Is(err, sidecar.ErrRevocationVoidsToken) {
		return fmt.Errorf("%w: %w", ErrGkmTokenRevoked, err)
	}
	return err
}

// See GkmAuthState and the file header.
func (self *AclGkmAuthState) Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*GkmSidecarFacts, GkmAuthAnswer) {
	snapshot, answer := self.snapshot(principal)
	if answer != GkmAuthAllowed {
		return nil, answer
	}
	standing := sidecar.GkmSidecarStandingAt(snapshot.Config, sidecarId, self.clock.Now())
	if standing == nil {
		return nil, GkmAuthDenied
	}
	return &GkmSidecarFacts{
		IdentityPublicKey:    standing.IdentityPublicKey,
		Revoked:              standing.Revoked,
		Parked:               standing.Parked,
		Suspended:            snapshot.Acl.Suspended(sidecarId),
		ReadOnly:             standing.ReadOnly,
		MemberDevice:         standing.MemberDevice,
		MemberId:             standing.MemberId,
		RecoveryAdmitted:     standing.RecoveryAdmitted,
		CoveringDelegationId: standing.CoveringDelegationId,
	}, GkmAuthAllowed
}

// See GkmAuthState: AclGateCache.HonorScope's answer for the gkm audience.
func (self *AclGkmAuthState) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, right sidecar.AclEvsRights, now time.Time) GkmAuthAnswer {
	if self.gate == nil || principal == nil {
		return GkmAuthUnknown
	}
	if principal.SidecarId == nil {
		return GkmAuthDenied
	}
	return gkmAclScopeAnswer(self.gate.HonorScope(sidecar.Id(principal.NetworkId), sidecar.Id(*principal.SidecarId), repoId, right, sidecar.AclTokenAudienceGkm, now))
}

// See GkmAuthState: the gate's r for sidecarId in the token's network.
func (self *AclGkmAuthState) Reads(principal *sidecar.Principal, repoId sidecar.Id, sidecarId sidecar.Id, now time.Time) GkmAuthAnswer {
	if self.gate == nil || principal == nil {
		return GkmAuthUnknown
	}
	return gkmAclScopeAnswer(self.gate.HonorScope(sidecar.Id(principal.NetworkId), sidecarId, repoId, sidecar.AclEvsRead, sidecar.AclTokenAudienceGkm, now))
}

// Who a pending or wrap-pending hint about repoId goes to at now: its writers, or in the directory group the
// config's. Empty for a repo the state does not hold.
func gkmAclHintWriters(snapshot *sidecar.AclGateSnapshot, repoId sidecar.Id, now time.Time) []sidecar.Id {
	if snapshot.Acl.Repo(repoId).GetKind() == protocol.RepoKind_REPO_KIND_DIRECTORY {
		configRepoId, ok := snapshot.Acl.ConfigRepoId()
		if !ok {
			return []sidecar.Id{}
		}
		repoId = configRepoId
	}
	return snapshot.Acl.RepoWriters(repoId, now)
}

// See GkmAuthState. A first KeyPackage upload's hint asks this once, so it walks the network's repos.
func (self *AclGkmAuthState) PendingTargets(principal *sidecar.Principal, sidecarId sidecar.Id, now time.Time) ([]*GkmPendingTarget, GkmAuthAnswer) {
	snapshot, answer := self.snapshot(principal)
	if answer != GkmAuthAllowed {
		return nil, answer
	}
	targets := []*GkmPendingTarget{}
	for _, repoId := range snapshot.Acl.RepoIds() {
		if sidecar.AclHonorScope(snapshot.Acl, sidecarId, repoId, sidecar.AclEvsRead, sidecar.AclTokenAudienceGkm, now) != sidecar.AclScopeHonored {
			continue
		}
		targets = append(targets, &GkmPendingTarget{RepoId: repoId, SidecarIds: gkmAclHintWriters(snapshot, repoId, now)})
	}
	return targets, GkmAuthAllowed
}

// See GkmAuthState. Empty for a repo the state does not hold.
func (self *AclGkmAuthState) RepoReaders(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, GkmAuthAnswer) {
	snapshot, answer := self.snapshot(principal)
	if answer != GkmAuthAllowed {
		return nil, answer
	}
	return snapshot.Acl.RepoReaders(repoId, now), GkmAuthAllowed
}

// See GkmAuthState. Empty for a repo the state does not hold.
func (self *AclGkmAuthState) RepoWriters(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, GkmAuthAnswer) {
	snapshot, answer := self.snapshot(principal)
	if answer != GkmAuthAllowed {
		return nil, answer
	}
	return gkmAclHintWriters(snapshot, repoId, now), GkmAuthAllowed
}

// See GkmAuthState: the state retains A_k from its retention point, the previous base or just past the newest base's
// fold, so a pin before it is Denied as one off the chain is.
func (self *AclGkmAuthState) CheckPin(principal *sidecar.Principal, pin *bridge.AuthPin) GkmAuthAnswer {
	snapshot, answer := self.snapshot(principal)
	if answer != GkmAuthAllowed {
		return answer
	}
	if pin == nil {
		return GkmAuthDenied
	}
	if snapshot.Pin.GetVersion() < pin.GetVersion() {
		return GkmAuthUnknown
	}
	return gkmAclAnswer(snapshot.Config.OnChain(pin))
}

// See GkmAuthState. Denied for a repo the state does not hold; Unknown for a state whose holders do not compute.
func (self *AclGkmAuthState) DelegationReads(principal *sidecar.Principal, repoId sidecar.Id, delegationId []byte, now time.Time) GkmAuthAnswer {
	snapshot, answer := self.snapshot(principal)
	if answer != GkmAuthAllowed {
		return answer
	}
	holds, err := sidecar.GkmDelegationHolds(snapshot.Config, repoId, delegationId, now)
	switch {
	case err == nil:
		return gkmAclAnswer(holds)
	case errors.Is(err, sidecar.ErrGkmNoRepo):
		return GkmAuthDenied
	}
	return GkmAuthUnknown
}

// See GkmAuthState. Denied for a row that holds no key or digest of its size, or a forwarding row whose sidecar does
// not parse, which a row TEAM wrote never is.
func (self *AclGkmAuthState) DelegationKey(principal *sidecar.Principal, delegationId []byte) (*GkmDelegationKeyFacts, GkmAuthAnswer) {
	snapshot, answer := self.snapshot(principal)
	if answer != GkmAuthAllowed {
		return nil, answer
	}
	row := snapshot.Config.Delegation(delegationId)
	if row == nil {
		return nil, GkmAuthDenied
	}
	readerKeySha256, ok := sidecar.GkmDelegationKeySha256(row)
	if !ok {
		return nil, GkmAuthDenied
	}
	facts := &GkmDelegationKeyFacts{ReaderKeySha256: readerKeySha256}
	if configRepoId, ok := snapshot.Acl.ConfigRepoId(); ok {
		facts.ConfigRepoId = configRepoId
	}
	if sidecar.ConfigDelegationRowForwards(row) {
		forwardSidecarId, err := sidecar.IdFromBytes(row.GetForwardSidecarId())
		if err != nil || forwardSidecarId == (sidecar.Id{}) {
			return nil, GkmAuthDenied
		}
		facts.ForwardSidecarId = &forwardSidecarId
	}
	return facts, GkmAuthAllowed
}

// See GkmAuthState. Denied for a repo the state does not hold or a recipient that names nothing.
func (self *AclGkmAuthState) LateHolders(principal *sidecar.Principal, repoId sidecar.Id, recipient string, now time.Time) ([]sidecar.Id, GkmAuthAnswer) {
	snapshot, answer := self.snapshot(principal)
	if answer != GkmAuthAllowed {
		return nil, answer
	}
	holderIds, err := sidecar.GkmLateHolders(snapshot.Config, repoId, recipient, now)
	switch {
	case err == nil:
		return holderIds, GkmAuthAllowed
	case errors.Is(err, sidecar.ErrGkmNoRepo), errors.Is(err, sidecar.ErrGkmMalformed):
		return nil, GkmAuthDenied
	}
	return nil, GkmAuthUnknown
}

// See GkmAuthState: Unknown wherever the state cannot tell, a repo it does not hold among them, which the budget
// then classes P1.
func (self *AclGkmAuthState) HoldersDropped(principal *sidecar.Principal, repoId sidecar.Id, pin *bridge.AuthPin, since time.Time, now time.Time) GkmAuthAnswer {
	snapshot, answer := self.snapshot(principal)
	if answer != GkmAuthAllowed {
		return answer
	}
	if pin == nil {
		return GkmAuthUnknown
	}
	dropped, err := sidecar.GkmRemoveDue(snapshot.Config, repoId, pin, since, now)
	if err != nil {
		return GkmAuthUnknown
	}
	return gkmAclAnswer(dropped)
}
