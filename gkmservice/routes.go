// §10.14's routes and §10.6's scopes block, as one table, so a route cannot exist without a scope: the guard
// (service.go) holds every request to its route's row before any handler runs, and a handler that names its repo in
// its body cannot answer a success before it has authorized that repo (GkmRequest.authorized).
//
// Each pattern is one string literal, method and path, as net/http's mux takes it and as connect's
// api/check-routes.sh reads this file against bringyour.yml's /gkm/ operations (connect-m1-c11-route-scope). A route
// whose handler has not landed has a nil Serve and answers 501 once the guard passes it.
//
// The rows, with the decided readings folded in (QD-177: own and read need r, rw or admin on some repo, and a
// deposit-only token reaches drop-key alone; QD-066: the batched wraps, recovery-wraps and reader-keys routes;
// QD-156: the repo-keyed drop-key and the forms read; QD-074: the ladder):
//
//	own       POST reader-key, key-packages: the token's own sidecar's record, admitted and not revoked, parked or
//	          suspended; KeyPackages only from member devices (the handler)
//	public    GET reader-key/<sidecar_id>, POST reader-keys: a public record, under an admitted sidecar's token
//	read      GET a group, its epochs, gen/, wraps (the caller's own), group-info, Welcomes, and POST ack: r, rw or
//	          admin
//	leaf      POST epochs/<n>: r, rw or admin, from a member device; members refuse what gkm cannot see (§10.9)
//	info      POST group-info: r, rw or admin, from a member device that is not read_only
//	deliver   POST wraps/<g>/<c8>: r, rw or admin, from a sidecar that is not read_only, under the wrap checks
//	stage     POST recovery-wraps/<g>/<c8>: a rotator's RecoveryWraps, r, rw or admin, not read_only
//	write     POST gen/<g>, key-packages/claim, welcome/<n>: rw, which §7.8 gives member devices in the config group
//	          and every sidecar but read_only ones in the directory, so HonorScope's gkm audience decides
//	admin     POST /gkm/groups, POST repos/<id>/forms, POST ladder: admin
//	deposit   GET repos/<id>/drop-key: deposit, r, rw or admin
//	recovery  GET recovery/<member_id>/wraps: a device of that member, or its unadmitted client under
//	          recovery:<member_id>; POST (a rebind's re-wrap) and DELETE: that member's own device, not read_only

package gkmservice

import (
	"github.com/urnetwork/sidecar"
)

// A row of §10.6's scopes block.
type gkmScope int

const (
	gkmScopeOwn gkmScope = iota + 1
	gkmScopePublic
	gkmScopeRead
	gkmScopeLeaf
	gkmScopeInfo
	gkmScopeDeliver
	gkmScopeStage
	gkmScopeWrite
	gkmScopeAdmin
	gkmScopeDeposit
	gkmScopeRecoveryRead
	gkmScopeRecoveryOwn
)

// The rights a scope row's routes take on their repo, any one of them; the strongest the token holds is the one
// honored. Zero for a row on no one repo.
func (self gkmScope) rights() sidecar.AclEvsRights {
	switch self {
	case gkmScopeRead, gkmScopeLeaf, gkmScopeInfo, gkmScopeDeliver, gkmScopeStage, gkmScopeRecoveryOwn:
		return gkmRepoAccessRights
	case gkmScopeWrite:
		return sidecar.AclEvsWrite | sidecar.AclEvsAdmin
	case gkmScopeAdmin:
		return sidecar.AclEvsAdmin
	case gkmScopeDeposit:
		return sidecar.AclEvsDeposit | gkmRepoAccessRights
	}
	return 0
}

// How a route names the repo its scope is checked on.
type gkmTarget int

const (
	// A per-sidecar route: no repo, only the token's reach and the sidecar's standing.
	gkmTargetNone gkmTarget = iota
	// {repo_id} in the path.
	gkmTargetPathRepo
	// {group_id} in the path, whose repo the token's scopes and the repo's GroupForms give.
	gkmTargetPathGroup
	// The body names it: the handler calls AuthorizeRepo or AuthorizeGroup before it answers a success. A recovery
	// row's {member_id} is checked by the guard first.
	gkmTargetBody
	// {member_id} in the path and no repo: a recovery read, or a delete of a retired binding's wraps.
	gkmTargetPathMember
)

// Which repo/ states a write takes (§10.6's checks row), reread before the write, cached at most 5 s.
type gkmRepoState int

const (
	// No repo/ check: a read, or a write to a per-sidecar object or to Redis.
	gkmRepoStateAny gkmRepoState = iota
	// active only.
	gkmRepoStateActive
	// active, or keying for the group's creation or re-forming: the GroupForm, epoch 0, the ladder and the first
	// wraps (KF1, §10.8).
	gkmRepoStateKeying
	// as keying, or deleted while §19.10's re-seed mode is on, which admits only a re-seed's GroupForm and ladder.
	gkmRepoStateReseed
)

// One route of §10.14.
type GkmRoute struct {
	// net/http's pattern, method and path, which is also the route's template for metrics and the service log: it
	// holds no id (I-13).
	Pattern string
	Scope   gkmScope
	Target  gkmTarget
	// The route writes: §19.11's `writes: false` closes it, and rev/ is read before it runs (§7.8).
	Write bool
	// The repo/ states a write to the repo takes.
	RepoState gkmRepoState
	// Answers the request; nil until the route's task lands, which answers 501 after the guard.
	Serve func(engine *GkmEngine, request *GkmRequest)
}

// Every route gkm serves, each under its §10.6 row. A later task fills its routes' Serve here.
var gkmRoutes = []*GkmRoute{
	// KEYS-M2-13: per-sidecar objects on the first cluster
	{Pattern: "POST /gkm/key-packages", Scope: gkmScopeOwn, Target: gkmTargetNone, Write: true, Serve: (*GkmEngine).serveKeyPackagesUpload},
	{Pattern: "POST /gkm/key-packages/claim", Scope: gkmScopeWrite, Target: gkmTargetBody, Write: true, RepoState: gkmRepoStateActive, Serve: (*GkmEngine).serveKeyPackageClaim},
	{Pattern: "POST /gkm/reader-key", Scope: gkmScopeOwn, Target: gkmTargetNone, Write: true, Serve: (*GkmEngine).serveReaderKeyUpload},
	{Pattern: "GET /gkm/reader-key/{sidecar_id}", Scope: gkmScopePublic, Target: gkmTargetNone, Serve: (*GkmEngine).serveReaderKeyRead},
	{Pattern: "POST /gkm/reader-keys", Scope: gkmScopePublic, Target: gkmTargetNone, Serve: (*GkmEngine).serveReaderKeysRead},
	{Pattern: "GET /gkm/welcomes", Scope: gkmScopeRead, Target: gkmTargetNone, Serve: (*GkmEngine).serveWelcomes},

	// KEYS-M2-14: groups, epochs, Welcomes, GroupInfo and acks
	{Pattern: "POST /gkm/groups", Scope: gkmScopeAdmin, Target: gkmTargetBody, Write: true, RepoState: gkmRepoStateKeying, Serve: (*GkmEngine).serveGroupCreate},
	{Pattern: "GET /gkm/groups/{group_id}", Scope: gkmScopeRead, Target: gkmTargetPathGroup, Serve: (*GkmEngine).serveGroupRead},
	{Pattern: "GET /gkm/repos/{repo_id}/forms", Scope: gkmScopeRead, Target: gkmTargetPathRepo, Serve: (*GkmEngine).serveFormsRead},
	{Pattern: "POST /gkm/repos/{repo_id}/forms", Scope: gkmScopeAdmin, Target: gkmTargetPathRepo, Write: true, RepoState: gkmRepoStateReseed, Serve: (*GkmEngine).serveReform},
	{Pattern: "GET /gkm/groups/{group_id}/epochs", Scope: gkmScopeRead, Target: gkmTargetPathGroup, Serve: (*GkmEngine).serveEpochsRead},
	{Pattern: "POST /gkm/groups/{group_id}/epochs/{n}", Scope: gkmScopeLeaf, Target: gkmTargetPathGroup, Write: true, RepoState: gkmRepoStateActive, Serve: (*GkmEngine).serveEpochCommit},
	{Pattern: "POST /gkm/groups/{group_id}/welcome/{n}", Scope: gkmScopeWrite, Target: gkmTargetPathGroup, Write: true, RepoState: gkmRepoStateActive, Serve: (*GkmEngine).serveWelcomeWrite},
	{Pattern: "GET /gkm/groups/{group_id}/group-info", Scope: gkmScopeRead, Target: gkmTargetPathGroup, Serve: (*GkmEngine).serveGroupInfoRead},
	{Pattern: "POST /gkm/groups/{group_id}/group-info", Scope: gkmScopeInfo, Target: gkmTargetPathGroup, Write: true, RepoState: gkmRepoStateActive, Serve: (*GkmEngine).serveGroupInfoWrite},
	{Pattern: "POST /gkm/groups/{group_id}/ack", Scope: gkmScopeRead, Target: gkmTargetPathGroup, Write: true, Serve: (*GkmEngine).serveAck},

	// KEYS-M2-15: generations, wraps, drop keys and recovery wraps; KEYS-M2-25: the ladder
	{Pattern: "GET /gkm/groups/{group_id}/gen", Scope: gkmScopeRead, Target: gkmTargetPathGroup},
	{Pattern: "POST /gkm/groups/{group_id}/gen/{g}", Scope: gkmScopeWrite, Target: gkmTargetPathGroup, Write: true, RepoState: gkmRepoStateActive},
	{Pattern: "GET /gkm/groups/{group_id}/wraps/{g}", Scope: gkmScopeRead, Target: gkmTargetPathGroup},
	{Pattern: "POST /gkm/groups/{group_id}/wraps/{g}/{c8}", Scope: gkmScopeDeliver, Target: gkmTargetPathGroup, Write: true, RepoState: gkmRepoStateKeying},
	{Pattern: "POST /gkm/groups/{group_id}/recovery-wraps/{g}/{c8}", Scope: gkmScopeStage, Target: gkmTargetPathGroup, Write: true, RepoState: gkmRepoStateKeying},
	{Pattern: "POST /gkm/groups/{group_id}/ladder", Scope: gkmScopeAdmin, Target: gkmTargetPathGroup, Write: true, RepoState: gkmRepoStateReseed},
	{Pattern: "GET /gkm/repos/{repo_id}/drop-key", Scope: gkmScopeDeposit, Target: gkmTargetPathRepo},
	{Pattern: "GET /gkm/recovery/{member_id}/wraps", Scope: gkmScopeRecoveryRead, Target: gkmTargetPathMember},
	{Pattern: "POST /gkm/recovery/{member_id}/wraps", Scope: gkmScopeRecoveryOwn, Target: gkmTargetBody, Write: true, RepoState: gkmRepoStateActive},
	{Pattern: "DELETE /gkm/recovery/{member_id}/wraps", Scope: gkmScopeRecoveryOwn, Target: gkmTargetPathMember, Write: true},
}

// The path values the patterns name.
const (
	gkmPathValueSidecarId  = "sidecar_id"
	gkmPathValueRepoId     = "repo_id"
	gkmPathValueGroupId    = "group_id"
	gkmPathValueMemberId   = "member_id"
	gkmPathValueEpoch      = "n"
	gkmPathValueGeneration = "g"
)
