// §11.8's authorization row: who may do what on a repo. The daemon's service token (aud evs, scopes
// repo:<id>:deposit|r|rw|admin, 15 min, §7.8) verifies offline through ServiceHost.Authenticate; the rest of the
// check asks the newest verified state, behind EvsAuthState, so T2 runs on a fake and ACL-M2-14 supplies the real
// one over AclGateCache:
//
//   - rev/ for the token's three subjects (client, sidecar, member) on every write and on streams over 60 s, cached
//     at most 5 s by TEAM-M1-07's RevocationChecker: a token issued before a subject's not_before is void;
//   - the scope honored only while the newest verified state gives the sidecar that right on the repo (D-ACL-21,
//     §7.9's tokens row), deposit included (g0-recheck-0-deposit-scope#1, decided), so a subject a group edit or a
//     Suspend drops loses it within §8.9's 5 s and not at the token's 15 minutes;
//   - ur_sidecar_id an admitted, unrevoked sidecar of the token's network. The token's (ur_sidecar_id, ur_client_id)
//     pair is §5's binding as the exchange bound it at the mint, and evs looks no binding up (QD-717).
//
// Every answer is three-valued, and only an answer of the state allows: a network whose state is not loaded
// answers 503, never an allow (ACL-M2-13's cold state).

package evsservice

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What the newest verified state says to one question.
type EvsAuthAnswer int

const (
	// The state for the token's network is not loaded, or could not be read: evs answers 503, retryable, and
	// allows nothing.
	EvsAuthUnknown EvsAuthAnswer = 0
	// The state agrees.
	EvsAuthAllowed EvsAuthAnswer = 1
	// The state disagrees: 403.
	EvsAuthDenied EvsAuthAnswer = 2
)

// A token one of whose subjects a rev/ object voids (§7.8): 401, so the daemon mints no new one for that subject.
var ErrEvsTokenRevoked = errors.New("evs token revoked")

// What the projection holds of a repo, which PUT .../repos/<id> writes into repo/ (§11.12's naming row).
type EvsRepoFacts struct {
	// Its kind, fixed at creation.
	Kind protocol.RepoKind
	// An owner-bound kind's owner, else the zero id.
	OwnerMemberId sidecar.Id
	// The network whose authorization log filed its RepoCreate (plan-EVSB-repo-network): repo/'s network_id,
	// which the creating token's network must equal.
	NetworkId sidecar.Id
	// The repo's newest RepoDelete (§8.8's AclRepo deletion row), nil when the log holds none: what DELETE and
	// restore require and take (§11.12's log first row), and what the reconciler applies.
	Deletion *EvsRepoDeletionFacts
}

// A repo's newest RepoDelete as the projection holds it, with its entry's time and its signer, which its row carries
// (AclRepoDeletionRow.deleted_time_ms, QD-743, and AclRepoDeletionRow.signer, QD-798), the signer also named by the
// entry at the row's position (AclRepoDeletionRow.deleted_at) while the projection's log keeps it.
type EvsRepoDeletionFacts struct {
	DeletionId sidecar.Id
	// RepoDelete{now}: straight to shredding, never restorable.
	Now bool
	// The RepoDelete entry's time: repo/'s state_ms while deleted, and what the 7-day start counts from. Zero where the
	// projection does not date it.
	Time time.Time
	// The entry's signer: repo/'s state_signer while deleted. The zero id only where neither the projection's log nor
	// the row names it, a row no fold writes, which DELETE without now refuses (decideDelete).
	SignerSidecarId sidecar.Id
	// A RepoRestore of DeletionId is projected, which api takes only within 7 d (§8.8).
	Restored bool
}

// The newest verified authorization state evs holds (§7.9, §8.9), per network. ACL-M2-14 implements it over
// AclGateCache and TEAM-M1-07's RevocationChecker; sidecartest's fake in this package's tests stands in until
// then. Safe for concurrent use. CheckRevocation may do I/O, under ctx; the others answer from memory, so they
// may run on every request.
type EvsAuthState interface {
	// nil when no rev/ object voids the token's client, sidecar or member; ErrEvsTokenRevoked when one does; any
	// other error when evs cannot tell, which answers 503.
	CheckRevocation(ctx context.Context, principal *sidecar.Principal) error
	// Whether the newest verified state holds the token's ur_sidecar_id as an admitted, unrevoked sidecar of the
	// token's network. The token's ur_client_id is §5's binding as the exchange bound it at the mint (QD-717).
	MatchBinding(principal *sidecar.Principal) EvsAuthAnswer
	// Whether the newest verified state gives the token's sidecar every right in rights on repoId at now
	// (D-ACL-21): AclState.EvsAccess's rights for the evs audience, read from the per-repo bitsets.
	HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) EvsAuthAnswer
	// What the token's network's projection holds of repoId: Denied when it holds no RepoCreate for it.
	Repo(principal *sidecar.Principal, repoId sidecar.Id) (*EvsRepoFacts, EvsAuthAnswer)
}

// A scope's role, as §7.8 spells it after repo:<id>:.
const (
	evsScopeRoleDeposit = "deposit"
	evsScopeRoleRead    = "r"
	evsScopeRoleWrite   = "rw"
	evsScopeRoleAdmin   = "admin"
)

// The scope prefix every repo capability starts with.
const evsRepoScopePrefix = "repo:"

// The rights one role's scope carries: admin implies write and read, write read, and deposit nothing else
// (acl_evs.go's ceiling rules).
func evsScopeRoleRights(role string) sidecar.AclEvsRights {
	switch role {
	case evsScopeRoleDeposit:
		return sidecar.AclEvsDeposit
	case evsScopeRoleRead:
		return sidecar.AclEvsRead
	case evsScopeRoleWrite:
		return sidecar.AclEvsWrite | sidecar.AclEvsRead
	case evsScopeRoleAdmin:
		return sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead
	}
	return 0
}

// The rights the token's scopes carry on repoId, from every repo:<id>:<role> naming it. A scope that does not
// parse names nothing, so a malformed one grants nothing.
func TokenRepoRights(principal *sidecar.Principal, repoId sidecar.Id) sidecar.AclEvsRights {
	rights := sidecar.AclEvsRights(0)
	for _, scope := range principal.Scopes {
		rest, ok := strings.CutPrefix(scope, evsRepoScopePrefix)
		if !ok {
			continue
		}
		idText, role, ok := strings.Cut(rest, ":")
		if !ok {
			continue
		}
		scopeRepoId, err := sidecar.ParseId(idText)
		if err != nil || scopeRepoId != repoId {
			continue
		}
		rights |= evsScopeRoleRights(role)
	}
	return rights
}

// The one right a route's check honors: the strongest that both the token holds and the route takes, so a
// token holding rw on a route taking rw or deposit is held to rw. Zero when they share none.
func strongestRight(rights sidecar.AclEvsRights) sidecar.AclEvsRights {
	for _, right := range []sidecar.AclEvsRights{sidecar.AclEvsAdmin, sidecar.AclEvsWrite, sidecar.AclEvsRead, sidecar.AclEvsDeposit} {
		if rights.Has(right) {
			return right
		}
	}
	return 0
}

// What a right implies within its role: the rights the guard records as honored once the state agrees.
func impliedRights(right sidecar.AclEvsRights) sidecar.AclEvsRights {
	switch right {
	case sidecar.AclEvsAdmin:
		return sidecar.AclEvsAdmin | sidecar.AclEvsWrite | sidecar.AclEvsRead
	case sidecar.AclEvsWrite:
		return sidecar.AclEvsWrite | sidecar.AclEvsRead
	}
	return right
}
