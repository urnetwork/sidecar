// §10.6's tokens and scopes: who may do what at gkm. A daemon's service token (aud gkm, 15 minutes, §7.8) verifies
// offline through ServiceHost.Authenticate, and carries repo:<id>:r|rw|admin|deposit scopes, or, for an unadmitted
// client of member M, recovery:<M>. The rest of every check asks gkm's newest verified state, behind GkmAuthState,
// so T2 runs on a fake and the host supplies the real one, AclGkmAuthState (auth_state_acl.go; QD-718), over §8.9's
// gate cache (ACL-M2-13's AclGateCache, whose HonorScope answers for the gkm audience) and §7.8's rev/ reader:
//
//   - a scope is honored only while the newest verified state gives its subject that right on the repo (D-ACL-21):
//     r while it reads R, rw and admin while it writes R, deposit while it may deposit there (QD-070, decided), so a
//     subject a group edit or a Suspend drops loses it within §8.9's 5 s and not at the token's 15 minutes;
//   - rev/ for the token's three subjects is read on every write (§7.8), and voids a token issued before its
//     not_before;
//   - a token whose only repo scopes are deposit reaches GET drop-key and nothing else, and every other route needs
//     an r, rw or admin scope on some repo (QD-177, decided); a recovery:<member_id> scope reaches that member's own
//     recovery wraps and no other route.
//
// Every answer of the state is three-valued, and only an answer of the state allows: a network whose state is not
// loaded answers 503, never an allow (ACL-M2-13's cold state).

package gkmservice

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The audience gkm's tokens carry (§7.8).
const GkmAudience = "gkm"

// What the newest verified state says to one question.
type GkmAuthAnswer int

const (
	// The state for the token's network is not loaded, or could not be read: 503, retryable, and nothing allowed.
	GkmAuthUnknown GkmAuthAnswer = 0
	// The state agrees.
	GkmAuthAllowed GkmAuthAnswer = 1
	// The state disagrees: 403.
	GkmAuthDenied GkmAuthAnswer = 2
)

// A token one of whose subjects a rev/ object voids (§7.8): 401, so the daemon mints no new one for that subject.
var ErrGkmTokenRevoked = errors.New("gkm token revoked")

// What gkm's newest verified state holds of one sidecar, as §10.6's rows ask it.
type GkmSidecarFacts struct {
	// The identity key its admission names, a SidecarAdmit's or, for a network's first device, the Genesis's: what
	// a ReaderKey's or a credential's signature is checked under.
	IdentityPublicKey []byte
	// Revoked, which a tombstone keeps.
	Revoked bool
	// Parked by a compromise cascade, until its lift (§7.9).
	Parked bool
	// Under a Suspend (§8.8).
	Suspended bool
	// The read_only capability (D-TEAM-24): it keeps key upkeep under r, and loses wraps, claims, Welcomes and
	// GroupInfo (§10.6's scopes).
	ReadOnly bool
	// Untagged and not ephemeral: a member device, which alone uploads KeyPackages and commits as a leaf.
	MemberDevice bool
	// The member an untagged admission names; nil for a tagged one.
	MemberId *sidecar.Id
	// Admitted by its member's recovery key (§10.8): the one device whose external commit may say generation 0 and
	// carry no GenWrap (§10.6's epoch PUT check). False refuses that exception.
	RecoveryAdmitted bool
	// The live Delegation that admitted and covers it, whose d: deliveries it reads (§10.6's read row); nil for none.
	CoveringDelegationId []byte
}

// What gkm's newest verified state holds of one Delegation's reader key (§10.5; DESIGN-DETAILS 4.2.2), as the
// delegation-key routes and the wrap checks ask it.
type GkmDelegationKeyFacts struct {
	// SHA-256 of the X-Wing key a DelegationWrap to the Delegation seals to, sidecar.GkmDelegationKeySha256's: a
	// forwarding Delegation's row's reader_key_sha256, any other's that of its row's reader_xwing_public_key. What
	// the key object's bytes must hash to, and what a DelegationWrap's recipient_key_sha256 must be.
	ReaderKeySha256 []byte
	// The sidecar a forwarding Delegation is of, its signer and the one sidecar that uploads its key object; nil for
	// a Delegation that does not forward, whose key its row holds and which takes no object.
	ForwardSidecarId *sidecar.Id
	// The network's config repo, a forwarding Delegation's whole reach (owner decision 197): a token that reads it
	// may read the key object.
	ConfigRepoId sidecar.Id
}

// One repo a sidecar reads, and who a pending hint about it goes to (§10.6's pending changes): the repo's writers,
// or in the directory group only the signer of the statement it answers and the config writers (§10.9).
type GkmPendingTarget struct {
	RepoId     sidecar.Id
	SidecarIds []sidecar.Id
}

// gkm's newest verified authorization state (§7.9, §8.9), per network, and §7.8's rev/ objects. Safe for
// concurrent use. CheckRevocation may do I/O, under ctx; the rest answer from memory, so they may run on every
// request.
type GkmAuthState interface {
	// nil when no rev/ object voids the token's client, sidecar or member; ErrGkmTokenRevoked when one does; any
	// other error when gkm cannot tell, which answers 503.
	CheckRevocation(ctx context.Context, principal *sidecar.Principal) error
	// What the token's network's state holds of a sidecar: Denied when it never admitted it.
	Sidecar(principal *sidecar.Principal, sidecarId sidecar.Id) (*GkmSidecarFacts, GkmAuthAnswer)
	// Whether the newest verified state gives the token's sidecar right on repoId at now for the gkm audience
	// (D-ACL-21): AclState.EvsAccess's rights, in which the config gives member devices but read_only ones gkm rw.
	HonorScope(principal *sidecar.Principal, repoId sidecar.Id, right sidecar.AclEvsRights, now time.Time) GkmAuthAnswer
	// Whether sidecarId reads repoId at now in the newest verified state (§8.12's RepoReaders): a KeyPackage claim's
	// target and a late delivery's recipient must.
	Reads(principal *sidecar.Principal, repoId sidecar.Id, sidecarId sidecar.Id, now time.Time) GkmAuthAnswer
	// Each repo sidecarId reads at now, with who a pending hint about it goes to (§10.6's KeyPackages and pending
	// changes rows).
	PendingTargets(principal *sidecar.Principal, sidecarId sidecar.Id, now time.Time) ([]*GkmPendingTarget, GkmAuthAnswer)
	// Every sidecar that reads repoId at now (§8.12's RepoReaders), sorted: who a commit hint on gkm:<group_id> goes
	// to, so a rotation without a commit is seen (D-KEYS-19).
	RepoReaders(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, GkmAuthAnswer)
	// Who a pending or wrap-pending hint about repoId goes to, sorted: its writers, or in the directory group the
	// config writers (§10.6's late wraps and GroupInfo rows, §10.9's directory row).
	RepoWriters(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) ([]sidecar.Id, GkmAuthAnswer)
	// Whether pin names a position of the token's network's log the newest verified state judges and agrees with: at
	// or past its previous base's position, at or below its own, and A_n there equal to pin's chain (§7.9's retain
	// row; §10.6's "auth matches proj/ at that version"). Unknown for a pin past the newest state, which gkm has not
	// reached yet; Denied for one before the previous base or off the chain.
	CheckPin(principal *sidecar.Principal, pin *bridge.AuthPin) GkmAuthAnswer
	// Whether a Delegation is live at now and its reach holds repoId (§10.5's live and reach): a late DelegationWrap's
	// recipient must, as a ReaderWrap's must read R (§10.6's late row). A forwarding Delegation is live while §7.9's
	// forwarding row keeps it, neither ended nor superseded and its sidecar holding keys, and reaches the config alone
	// (owner decision 197): sidecar.GkmDelegationHolds answers both kinds from the state.
	DelegationReads(principal *sidecar.Principal, repoId sidecar.Id, delegationId []byte, now time.Time) GkmAuthAnswer
	// What the newest verified state holds of a Delegation's reader key: Denied when it holds no row of that id,
	// ended and superseded rows answering as any other.
	DelegationKey(principal *sidecar.Principal, delegationId []byte) (*GkmDelegationKeyFacts, GkmAuthAnswer)
	// The holders a late delivery's ask widens its hint to once its since is 15 minutes old (§10.6's late wraps):
	// sidecars that hold repoId's key at now and may deliver, so none read_only, the recipient's member's devices
	// first (an agent's or a Delegation's sponsor's), then by identity bytes. recipient is the ask's, as its wrap
	// path writes it: s:<sidecar_id> or d:<delegation_id>.
	LateHolders(principal *sidecar.Principal, repoId sidecar.Id, recipient string, now time.Time) ([]sidecar.Id, GkmAuthAnswer)
	// Whether the newest verified state shows a key holder of repoId dropped since pin and since: a shrink after pin's
	// position, a compromise retirement among them, or a holder's authorization expiry in (since, now]
	// (sidecar.GkmRemoveDue at the newest state, through now). Allowed when one did, Denied when none did, Unknown
	// when the state cannot tell. §11.13's write budget reads it alone to class a commit as a Remove and a staged
	// delivery or claim as a REMOVE rotation's (§10.6's checks row, budget.go), never a statement's stated cause.
	HoldersDropped(principal *sidecar.Principal, repoId sidecar.Id, pin *bridge.AuthPin, since time.Time, now time.Time) GkmAuthAnswer
}

// A scope's role, as §7.8 spells it after repo:<id>:.
const (
	gkmScopeRoleDeposit = "deposit"
	gkmScopeRoleRead    = "r"
	gkmScopeRoleWrite   = "rw"
	gkmScopeRoleAdmin   = "admin"
)

// The scope prefixes a gkm token carries (§7.8).
const (
	gkmRepoScopePrefix     = "repo:"
	gkmRecoveryScopePrefix = "recovery:"
)

// The rights one role's scope carries: admin implies write and read, write read, and deposit nothing else
// (plan-ACL-small-readings #3).
func gkmScopeRoleRights(role string) sidecar.AclEvsRights {
	switch role {
	case gkmScopeRoleDeposit:
		return sidecar.AclEvsDeposit
	case gkmScopeRoleRead:
		return sidecar.AclEvsRead
	case gkmScopeRoleWrite:
		return sidecar.AclEvsWrite | sidecar.AclEvsRead
	case gkmScopeRoleAdmin:
		return sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead
	}
	return 0
}

// The rights that let a token reach the routes that need "r, rw or admin on some repo".
const gkmRepoAccessRights = sidecar.AclEvsRead | sidecar.AclEvsWrite | sidecar.AclEvsAdmin

// A token's scopes, parsed once per request. A scope that does not parse names nothing, so a malformed one grants
// nothing.
type gkmTokenScopes struct {
	repoIdRights      map[sidecar.Id]sidecar.AclEvsRights
	recoveryMemberIds map[sidecar.Id]bool
}

// The scopes of principal.
func parseGkmTokenScopes(principal *sidecar.Principal) *gkmTokenScopes {
	scopes := &gkmTokenScopes{
		repoIdRights:      map[sidecar.Id]sidecar.AclEvsRights{},
		recoveryMemberIds: map[sidecar.Id]bool{},
	}
	for _, scope := range principal.Scopes {
		if rest, ok := strings.CutPrefix(scope, gkmRepoScopePrefix); ok {
			idText, role, ok := strings.Cut(rest, ":")
			if !ok {
				continue
			}
			repoId, err := sidecar.ParseId(idText)
			rights := gkmScopeRoleRights(role)
			if err != nil || rights == 0 || repoId == (sidecar.Id{}) {
				continue
			}
			scopes.repoIdRights[repoId] |= rights
			continue
		}
		if idText, ok := strings.CutPrefix(scope, gkmRecoveryScopePrefix); ok {
			memberId, err := sidecar.ParseId(idText)
			if err != nil || memberId == (sidecar.Id{}) {
				continue
			}
			scopes.recoveryMemberIds[memberId] = true
		}
	}
	return scopes
}

// Whether the token holds r, rw or admin on some repo, the reach of every route but drop-key's and the recovery
// read's (QD-177).
func (self *gkmTokenScopes) holdsRepoAccess() bool {
	for _, rights := range self.repoIdRights {
		if rights&gkmRepoAccessRights != 0 {
			return true
		}
	}
	return false
}

// Whether the token holds any repo scope at all, deposit included.
func (self *gkmTokenScopes) holdsRepoScope() bool {
	return len(self.repoIdRights) != 0
}

// The repos whose scopes carry any of rights, sorted, so a group's resolution examines them in one order.
func (self *gkmTokenScopes) reposWith(rights sidecar.AclEvsRights) []sidecar.Id {
	repoIds := []sidecar.Id{}
	for repoId, held := range self.repoIdRights {
		if held&rights != 0 {
			repoIds = append(repoIds, repoId)
		}
	}
	slices.SortFunc(repoIds, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
	return repoIds
}

// The one right a check honors: the strongest that both the token holds and the route takes, so a token holding
// admin on a route taking r, rw or admin is held to admin. Zero when they share none.
func gkmStrongestRight(rights sidecar.AclEvsRights) sidecar.AclEvsRights {
	for _, right := range []sidecar.AclEvsRights{sidecar.AclEvsAdmin, sidecar.AclEvsWrite, sidecar.AclEvsRead, sidecar.AclEvsDeposit} {
		if rights.Has(right) {
			return right
		}
	}
	return 0
}

// What a right implies within its role: the rights recorded as honored once the state agrees.
func gkmImpliedRights(right sidecar.AclEvsRights) sidecar.AclEvsRights {
	switch right {
	case sidecar.AclEvsAdmin:
		return sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead
	case sidecar.AclEvsWrite:
		return sidecar.AclEvsWrite | sidecar.AclEvsRead
	}
	return right
}
