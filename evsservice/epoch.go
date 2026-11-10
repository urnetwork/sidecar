// POST /evs/v1/repos/<id>/path-epoch and POST .../path-epoch/block (§11.6's map and block rows, §11.20; EVS1-M2-16).
//
//	map    one Signed EvsPathMap part with its map's path_map_sha256 (rw), stored at pmap/<repo>/<ref>/<p>/<map>/<part>/_
//	       If-None-Match, equal bytes on a 412 being success: the part held to its shape, this repo, and a signature by
//	       the token's sidecar under the identity key the newest state admits; repo/ active. This plan's reading of
//	       §11.20's route list, which §11.6 implies: the route stores parts and nothing else, and a PATH_EPOCH push
//	       through .../push checks them at its commit (epoch_commit.go)
//	block  {ref_id, ms <= 120,000} (rw): 10 min past due_by_ms a mapper may stop creation on the ref for at most 2 min,
//	       at most once each 10 min, by one head CAS raising only the fence and setting block_until_ms; until it passes
//	       a push creating a path gets 412 PATH_EPOCH_DUE (check_cas.go). A ref with nothing due answers 412 PATH_EPOCH,
//	       a block before its time 429 WAIT with retry_after_ms, a batched epoch while two sources stand 412
//	       EPOCH_SOURCES_FULL, since the commit row defers it, and a CAS lost PushRefusalRetryCount times 429 BUSY.
//	       "At most once each 10 min" reads block_until_ms alone, the head keeping no block's start: a block may begin
//	       once 8 min have passed since the last one's end, as if that one had lasted its whole 2 min
//
// Both writes are P1 (§11.13's classes: path maps; the block a head overwrite), paid before they are issued.

package evsservice

import (
	"errors"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.6's block row's bounds.
const (
	evsPathEpochBlockMaxDuration = 2 * time.Minute
	// a block only 10 min past due_by_ms, and at most once each 10 min
	evsPathEpochBlockAfterDue = 10 * time.Minute
	evsPathEpochBlockInterval = 10 * time.Minute
)

// The route templates.
const (
	evsPathEpochMapTemplate   = "POST /evs/v1/repos/{repo_id}/path-epoch"
	evsPathEpochBlockTemplate = "POST /evs/v1/repos/{repo_id}/path-epoch/block"
)

// The path-epoch routes.
func (self *EvsEngine) pathEpochRoutes() []*EvsRoute {
	return []*EvsRoute{
		{
			Method:  http.MethodPost,
			Pattern: evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}/path-epoch",
			Name:    evsPathEpochMapTemplate,
			Rights:  sidecar.AclEvsWrite,
			Write:   true,
			Placed:  true,
			Serve:   self.servePathMapPart,
		},
		{
			Method:         http.MethodPost,
			Pattern:        evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}/path-epoch/block",
			Name:           evsPathEpochBlockTemplate,
			Rights:         sidecar.AclEvsWrite,
			Write:          true,
			NeedsSureClock: true,
			Placed:         true,
			Serve:          self.servePathEpochBlock,
		},
	}
}

// The repo's state, refused unless active: its refusal answered, false.
func (self *EvsEngine) requireActiveRepo(request *EvsRequest) bool {
	read, err := self.repos.Read(request.Ctx, request.Cluster, request.RepoId)
	switch {
	case errors.Is(err, ErrEvsRepoNotFound):
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
		return false
	case err != nil:
		request.Unavailable(nil)
		return false
	}
	if refusal := checkRepoState(read.Object); refusal != nil {
		request.Refuse(refusal.Reply(sidecar.Id{}))
		return false
	}
	return true
}

// P1 for one write of objectByteCount, in the token network's queue, with its grant; false once answered.
func (self *EvsEngine) admitOne(request *EvsRequest, kind WriteOperationKind, objectByteCount int64) (sidecar.WriteGrant, bool) {
	cost, err := PricePush(self.priceTable, &PushOperations{
		Immediate: []WriteOperation{{Kind: kind, ObjectByteCount: objectByteCount, Count: 1}},
	})
	if err != nil {
		request.Unavailable(nil)
		return nil, false
	}
	grant, err := self.budget.AdmitP1(request.Ctx, request.Cluster.ClusterId(), connect.Id(networkIdOf(request.Principal)), cost)
	var refusal *sidecar.WriteRefusal
	switch {
	case errors.As(err, &refusal):
		request.Refuse(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED, RetryAfterMs: max(1, refusal.RetryAfterMs())})
		return nil, false
	case err != nil:
		request.Unavailable(nil)
		return nil, false
	}
	return grant, true
}

// POST .../path-epoch: see the file header.
func (self *EvsEngine) servePathMapPart(request *EvsRequest) {
	body := &protocol.EvsPathMapRequest{}
	if !request.ReadMessage(body, sidecar.EvsPathMapMaxByteCount+evsPathMapRequestOverhead) {
		return
	}
	if len(body.GetPathMapSha256()) != 32 {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	signed, pathMap, err := sidecar.ParseEvsPathMap(body.GetPart())
	if err != nil || sidecar.Id(pathMap.GetRepoId()) != request.RepoId || sidecar.Id(signed.GetSignerId()) != request.SidecarId {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	refId := sidecar.Id(pathMap.GetRefId())
	request.NoteRefIds(refId)
	if self.deps.GateViews == nil {
		request.Unavailable(nil)
		return
	}
	view, answer := self.deps.GateViews.View(networkIdOf(request.Principal))
	if answer != EvsAuthAllowed || view == nil {
		request.Unavailable(nil)
		return
	}
	identityKey := view.IdentityKey(request.SidecarId)
	if len(identityKey) == 0 || verifyEvsPathMapPart(signed, identityKey) != nil {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	if !self.requireActiveRepo(request) {
		return
	}
	grant, ok := self.admitOne(request, WriteOperationCreate, int64(len(body.GetPart())))
	if !ok {
		return
	}
	defer grant.Close()
	key := PathMapKey(request.RepoId, refId, pathMap.GetPathEpoch(), body.GetPathMapSha256(), pathMap.GetPart())
	_, err = sidecar.PutImmutable(grant.Context(), request.Cluster, key, body.GetPart(), nil)
	switch {
	case err == nil:
		request.Reply(nil)
	case errors.Is(err, sidecar.ErrBlobImmutableMismatch):
		// another part already stands under this map's key: the mapper maps again under a new hash
		request.Refuse(newEvsCheckRefusal(EvsCheckReasonMapSource, "another part under this map's key").Reply(sidecar.Id{}))
	default:
		request.Unavailable(nil)
	}
}

// A map part request's bytes beyond the part: the hash and the framing.
const evsPathMapRequestOverhead = 1024

// POST .../path-epoch/block: see the file header.
func (self *EvsEngine) servePathEpochBlock(request *EvsRequest) {
	body := &protocol.EvsPathEpochBlockRequest{}
	if !request.ReadMessage(body, 1024) {
		return
	}
	refId, err := sidecar.IdFromBytes(body.GetRefId())
	duration := time.Duration(body.GetMs()) * time.Millisecond
	if err != nil || duration <= 0 || evsPathEpochBlockMaxDuration < duration {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	request.NoteRefIds(refId)
	if !self.requireActiveRepo(request) {
		return
	}
	head, err := self.heads.ReadCluster(request.Ctx, request.Cluster, request.RepoId, refId)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	grant, ok := self.admitOne(request, WriteOperationOverwrite, int64(len(head.Bytes)))
	if !ok {
		return
	}
	defer grant.Close()
	for attempt := 0; attempt <= self.settings.PushRefusalRetryCount; attempt += 1 {
		now := request.Now()
		pathEpoch := head.Head.GetPathEpoch()
		if head.Absent() || pathEpoch.GetDueGeneration() == 0 {
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH)
			return
		}
		if !pathEpoch.GetDueBlocksCreation() && evsPathEpochBatchedMaxSourceCount <= len(pathEpoch.GetSources()) {
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_EPOCH_SOURCES_FULL)
			return
		}
		wait := time.UnixMilli(pathEpoch.GetDueByMs()).Add(evsPathEpochBlockAfterDue).Sub(now)
		if blockUntil := pathEpoch.GetBlockUntilMs(); blockUntil != 0 {
			wait = max(wait, time.UnixMilli(blockUntil).Add(evsPathEpochBlockInterval-evsPathEpochBlockMaxDuration).Sub(now))
		}
		if 0 < wait {
			request.Refuse(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_WAIT, RetryAfterMs: uint32(max(1, wait.Milliseconds()))})
			return
		}
		next := CloneEvsHead(head.Head)
		next.Fence = head.Head.GetFence() + 1
		next.PathEpoch = CloneEvsPathEpoch(pathEpoch)
		next.PathEpoch.BlockUntilMs = now.Add(duration).UnixMilli()
		_, err := self.heads.Commit(grant.Context(), request.Cluster, request.RepoId, refId, head, next)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			request.Reply(nil)
			return
		case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
		default:
			request.Unavailable(nil)
			return
		}
		reread, readErr := self.heads.ReadCluster(request.Ctx, request.Cluster, request.RepoId, refId)
		if readErr != nil {
			request.Unavailable(nil)
			return
		}
		if unknown != nil && reread.Head.GetPathEpoch().GetBlockUntilMs() == next.PathEpoch.GetBlockUntilMs() &&
			reread.Head.GetFence() == next.GetFence() {
			// the lost write landed
			request.Reply(nil)
			return
		}
		head = reread
	}
	request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_BUSY)
}

// A copy of a path epoch, an absent one reading as epoch 1.
func CloneEvsPathEpoch(pathEpoch *protocol.EvsPathEpoch) *protocol.EvsPathEpoch {
	if pathEpoch == nil {
		return &protocol.EvsPathEpoch{Current: 1}
	}
	return proto.Clone(pathEpoch).(*protocol.EvsPathEpoch)
}
