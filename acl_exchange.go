//go:build !ios_extension

// The token exchange's repo scopes (§7.8, owner decision 2): which repo:<id>:deposit|r|rw|admin capabilities api's
// exchange grants a sidecar for an evs or gkm token, from §8's rows in the newest verified projection. TEAM's exchange
// (TEAM-M2-15, TEAM-M6-10) calls this as its ExchangeScopeSource, adds §7.8's own refusals and its recovery: scope,
// stamps proj_v, and mints. The table is AclState.EvsAccess's, so the exchange grants exactly what evs and gkm then
// honor (D-ACL-21):
//
//	r        the sidecar reads the repo
//	rw       it writes it; on the config, evs rw only for config writers, gkm rw for every member device but a
//	         read_only one (§7.9's commit row, §10.6), so an ephemeral sidecar gets no config rw at either (FS-19)
//	admin    it administers the repo; in the team directory only its consented, not-read-only admins, its creator and
//	         the config writers (§8.10, §16.11); on the config only §7.9's bootstrap sidecar, the Genesis's
//	         owner_sidecar_id while it stands as a config writer
//
// The config repo's row is the state's own, from the Genesis (acl_state.go, QD-719): no rows hold one, and its scopes
// answer in every state.
//	deposit  §8 gives it deposit, or it reads an owner-bound repo it does not write (§16.8's receipts)
//
// A read_only sidecar gets only r and the receipt deposit, whatever else it is (D-TEAM-24); in a team network every
// admitted sidecar but a read_only one gets the directory's rw. A forward_only client (§7.4), which acts as its
// sidecar, gets only repo:<config_repo_id>:r, and only while that sidecar's forwarding Delegation is live (§7.9's
// forwarding row, owner decision 197), whatever its sidecar reads.
//
// One token carries at most 64 repo: scopes (§7.8), keeping its bearer under the lb's 8 KiB header line, and a request
// for more is refused whole. A scope that is not repo:<id>:<role> is not this table's: it is refused here, and the
// exchange judges §7.8's other scopes before it asks. A subject that is no sidecar holds no repo scope. A scope's id may
// be in either of ParseId's forms; a granted scope is returned as it was asked.
//
// Not on the ios_extension leg, whose forwarding role mints no token. Pure: nothing here does I/O or reads a clock.

package sidecar

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// The most repo: scopes one token carries (§7.8).
const AclExchangeMaxRepoScopeCount = 64

// The scope prefix every repo capability starts with (§7.8).
const aclExchangeRepoScopePrefix = "repo:"

// A request the table cannot judge as a whole: more repo scopes than one token carries, or no state.
var ErrAclExchangeScope = errors.New("acl exchange: invalid scope request")

// One exchange's ask of the rows.
type AclExchangeRequest struct {
	// The sidecar the client is bound to, whose rights the rows hold. Zero for a client bound to none, which gets no
	// repo scope.
	SidecarId Id
	// Which service the token is for. Only evs and gkm take repo scopes.
	Audience AclTokenAudience
	// The scopes as asked, each once.
	Scopes []string
	// The client is forward_only (§7.4).
	ForwardOnly bool
	// The time the exchange judges at, api's clock.
	Now time.Time
}

// What the table grants.
type AclExchangeGrant struct {
	// The granted scopes, a subset of the request's, in its order.
	Scopes []string
	// The scopes asked and not granted, in the request's order.
	Refused []string
	// The log position the scopes came from: the token's proj_v.
	ProjVersion uint64
}

// The scope a role names, as §7.8 spells it after repo:<id>:.
func aclExchangeRoleRight(role string) AclEvsRights {
	switch role {
	case "deposit":
		return AclEvsDeposit
	case "r":
		return AclEvsRead
	case "rw":
		return AclEvsWrite
	case "admin":
		return AclEvsAdmin
	}
	return 0
}

// One repo scope parsed, false for a scope that is not repo:<id>:<role> with a role §7.8 names.
func parseAclExchangeRepoScope(scope string) (Id, AclEvsRights, bool) {
	rest, ok := strings.CutPrefix(scope, aclExchangeRepoScopePrefix)
	if !ok {
		return Id{}, 0, false
	}
	idText, role, ok := strings.Cut(rest, ":")
	if !ok {
		return Id{}, 0, false
	}
	right := aclExchangeRoleRight(role)
	if right == 0 {
		return Id{}, 0, false
	}
	repoId, err := ParseId(idText)
	if err != nil || repoId == (Id{}) {
		return Id{}, 0, false
	}
	return repoId, right, true
}

// The scopes the newest verified state grants the request: the table above, each scope judged alone, so one refused
// scope refuses only itself. ErrAclExchangeScope for a request over the 64 repo scopes, or with no state.
func AclExchangeScopes(state *ConfigState, request *AclExchangeRequest) (*AclExchangeGrant, error) {
	if state == nil || request == nil {
		return nil, fmt.Errorf("%w: no state or no request", ErrAclExchangeScope)
	}
	acl, err := state.Acl()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAclExchangeScope, err)
	}
	repoScopeCount := 0
	for _, scope := range request.Scopes {
		if strings.HasPrefix(scope, aclExchangeRepoScopePrefix) {
			repoScopeCount += 1
		}
	}
	if AclExchangeMaxRepoScopeCount < repoScopeCount {
		return nil, fmt.Errorf("%w: %d repo scopes, over %d", ErrAclExchangeScope, repoScopeCount, AclExchangeMaxRepoScopeCount)
	}

	grant := &AclExchangeGrant{Scopes: []string{}, Refused: []string{}, ProjVersion: state.Pin().GetVersion()}
	audienceTakesRepos := request.Audience == AclTokenAudienceEvs || request.Audience == AclTokenAudienceGkm
	configRepoId, _ := IdFromBytes(state.Genesis().GetConfigRepoId())
	forwardingLive := request.ForwardOnly && request.SidecarId != (Id{}) && state.ForwardingDelegation(request.SidecarId) != nil
	for _, scope := range request.Scopes {
		repoId, right, ok := parseAclExchangeRepoScope(scope)
		granted := ok && audienceTakesRepos && request.SidecarId != (Id{})
		if granted && request.ForwardOnly {
			// a forwarding client reads the config alone, while its sidecar's forwarding Delegation is live
			granted = forwardingLive && repoId == configRepoId && right == AclEvsRead
		}
		if granted {
			access := acl.EvsAccess(AclSidecarSubject(request.SidecarId), repoId, request.Audience, request.Now)
			granted = access.Rights.Has(right)
		}
		if granted {
			grant.Scopes = append(grant.Scopes, scope)
		} else {
			grant.Refused = append(grant.Refused, scope)
		}
	}
	return grant, nil
}
