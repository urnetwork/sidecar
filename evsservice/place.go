// PUT /evs/v1/repos/<id> (§11.8's placement row, §11.12's naming row, owner decision 145): places a repo, then
// writes its repo/ there. A sidecar files §8.8's RepoCreate first, becoming the repo's admin, so the route takes
// admin, and the projection gives repo/ its kind and owner.
//
//  1. place/<repo_id> on the first metadata cluster, If-None-Match, naming the cluster that takes new repos
//     (BlobStore.NewRepoClusterId, sidecar.yml's place_new) and this sidecar as creator. A place_new this process
//     cannot reach answers a new repo 503 before anything is written, so no place/ ever names it; a repo already
//     placed goes on to step 2's rule.
//  2. On 412, or an unknown outcome, it reads place/: the same creator continues on the cluster place/ names,
//     whatever place_new says now, and any other gets 409, so of two racing creates exactly one places the repo and
//     a retry never moves it. An unknown outcome whose read finds no place/ never landed and never will (§19.6's
//     settle rule), and the same bytes go once more.
//  3. Only then repo/<id> there, If-None-Match, `keying` until §10's KF1, format 1, with the creating token's
//     network (plan-EVSB-repo-network). A 412 whose repo/ is this repo, network, kind and owner is a retry, and
//     answers 200 as the first did; any other is a fault that alarms.
//
// Both writes are P1 for the creating network (plan-EVSB-write-classes). The projection's kind must be one of §11.12's
// nine, with an owner exactly for vault, mailbox and secret, else 400 INVALID with an alarm. The rest of the route's
// family, GET, DELETE, restore and activate, is repo.go's.

package evsservice

import (
	"bytes"
	"errors"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The placement route.
func (self *EvsEngine) placeRoutes() []*EvsRoute {
	return []*EvsRoute{
		{
			Method:  http.MethodPut,
			Pattern: evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}",
			Name:    "PUT /evs/v1/repos/{repo_id}",
			Rights:  sidecar.AclEvsAdmin,
			Write:   true,
			Placed:  false,
			Serve:   self.servePutRepo,
		},
	}
}

// How many times a create of place/ or repo/ is sent: once, and once more after a read shows an unknown outcome
// never landed. A protocol step, as PutImmutable's.
const evsCreateWriteCount = 2

// PUT /evs/v1/repos/<id>.
func (self *EvsEngine) servePutRepo(request *EvsRequest) {
	facts, answer := self.deps.AuthState.Repo(request.Principal, request.RepoId)
	switch answer {
	case EvsAuthAllowed:
	case EvsAuthDenied:
		// the projection holds no RepoCreate for this id: the sidecar files it first (§11.12)
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
		return
	default:
		request.Unavailable(nil)
		return
	}
	if facts.NetworkId != networkIdOf(request.Principal) {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return
	}
	if !sidecar.EvsRepoKindKnown(facts.Kind) || sidecar.EvsRepoKindOwnerBound(facts.Kind) != (facts.OwnerMemberId != sidecar.Id{}) {
		// §11.12's kinds table: a kind this build does not know, or an owner exactly for the owner-bound kinds, is a
		// projection this build cannot keep, never a repo it creates
		self.alarm("repo_kind", "repo %s: the projection holds kind %d with owner %t", sidecar.EvsKeyId(request.RepoId), facts.Kind, facts.OwnerMemberId != sidecar.Id{})
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	place, ok := self.placeRepo(request)
	if !ok {
		return
	}
	cluster, err := self.blobs.Cluster(place.ClusterId)
	if err != nil {
		// placed on a cluster this process holds no credentials for: a retry on another process continues there
		self.log.Warningf("[evs] repo %s placed on cluster %s, which this process cannot reach", sidecar.EvsKeyId(request.RepoId), place.ClusterId)
		request.Unavailable(nil)
		return
	}
	if !self.createRepoObject(request, cluster, facts) {
		return
	}
	request.Reply(nil)
}

// Steps 1 and 2: the placement this create continues on. false once it has answered the refusal.
func (self *EvsEngine) placeRepo(request *EvsRequest) (*sidecar.EvsRepoPlace, bool) {
	repoId := request.RepoId
	newClusterId := self.blobs.NewRepoClusterId()
	if _, err := self.blobs.Cluster(newClusterId); err != nil {
		// a repo already placed continues where place/ names, and a new one waits, so no place/ names this cluster
		if held, err := self.places.Resolve(request.Ctx, repoId); err == nil {
			return self.continuePlace(request, held)
		}
		self.log.Warningf("[evs] place_new names cluster %s, which this process cannot reach", newClusterId)
		request.Unavailable(nil)
		return nil, false
	}
	firstCluster, err := self.blobs.FirstCluster()
	if err != nil {
		request.Unavailable(nil)
		return nil, false
	}
	place := &sidecar.EvsRepoPlace{ClusterId: newClusterId, CreatorSidecarId: request.SidecarId}
	placeBytes, err := place.Marshal()
	if err != nil {
		request.Unavailable(nil)
		return nil, false
	}
	grant, ok := self.admitCreate(request, firstCluster.ClusterId(), len(placeBytes))
	if !ok {
		return nil, false
	}
	defer grant.Close()
	barrierKey := barrierRepoKey(repoId)
	// what place/ holds after a write that did not land as this one
	continueOn := func() (*sidecar.EvsRepoPlace, bool) {
		held, err := sidecar.ReadEvsRepoPlace(request.Ctx, firstCluster, repoId)
		switch {
		case err == nil:
			return self.continuePlace(request, held)
		case errors.Is(err, sidecar.ErrEvsRepoPlaceInvalid):
			self.alarm("place_invalid", "repo %s: place/ holds no placement", sidecar.EvsKeyId(repoId))
		}
		request.Unavailable(nil)
		return nil, false
	}
	for writeCount := 1; ; writeCount += 1 {
		testHookBarrier(BarrierPlacePutBefore, barrierKey)
		_, err := firstCluster.PutIfNoneMatch(grant.Context(), sidecar.EvsPlaceKey(repoId), placeBytes, nil)
		testHookBarrier(BarrierPlacePutAfter, barrierKey)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			self.places.Remember(repoId, place)
			return place, true
		case errors.Is(err, sidecar.ErrBlobPrecondition):
			return continueOn()
		case errors.As(err, &unknown):
			held, readErr := sidecar.ReadEvsRepoPlace(request.Ctx, firstCluster, repoId)
			switch {
			case readErr == nil:
				return self.continuePlace(request, held)
			case errors.Is(readErr, sidecar.ErrEvsRepoNotPlaced) && writeCount < evsCreateWriteCount:
				// it never landed, and by the settle rule it never will: the same bytes again
				continue
			case errors.Is(readErr, sidecar.ErrEvsRepoPlaceInvalid):
				self.alarm("place_invalid", "repo %s: place/ holds no placement", sidecar.EvsKeyId(repoId))
			}
			request.Unavailable(&protocol.EvsRefusalReply{Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN})
			return nil, false
		}
		request.Unavailable(nil)
		return nil, false
	}
}

// Step 2's rule for a placement that stands: its creator continues on its cluster, any other gets 409.
func (self *EvsEngine) continuePlace(request *EvsRequest, held *sidecar.EvsRepoPlace) (*sidecar.EvsRepoPlace, bool) {
	if held.CreatorSidecarId != request.SidecarId {
		// §11.8 names no code for this 409, and questions/evs1-m2-07-placement-refusal-code asks for one: until it
		// is answered the route and status say it, and the code is left unset
		request.refuseStatus(http.StatusConflict, &protocol.EvsRefusalReply{})
		return nil, false
	}
	self.places.Remember(request.RepoId, held)
	return held, true
}

// Step 3: repo/ on the placed cluster. false once it has answered the refusal.
func (self *EvsEngine) createRepoObject(request *EvsRequest, cluster sidecar.BlobCluster, facts *EvsRepoFacts) bool {
	repoId := request.RepoId
	object := &protocol.EvsRepoObject{
		RepoId:    repoId.Bytes(),
		Kind:      facts.Kind,
		State:     protocol.EvsRepoState_EVS_REPO_KEYING,
		StateMs:   request.Now().UnixMilli(),
		Format:    sidecar.EvsRepoFormat1,
		NetworkId: facts.NetworkId.Bytes(),
	}
	if facts.OwnerMemberId != (sidecar.Id{}) {
		object.OwnerMemberId = facts.OwnerMemberId.Bytes()
	}
	objectBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(object)
	if err != nil {
		request.Unavailable(nil)
		return false
	}
	grant, ok := self.admitCreate(request, cluster.ClusterId(), len(objectBytes))
	if !ok {
		return false
	}
	defer grant.Close()
	barrierKey := barrierRepoKey(repoId)
	// whether the repo/ that stands is this create's repo, so a retry answers as the first did
	sameRepo := func() (same bool, found bool, err error) {
		read, err := self.repos.ReadFresh(request.Ctx, cluster, repoId)
		switch {
		case errors.Is(err, sidecar.ErrEvsRepoNotFound):
			return false, false, nil
		case err != nil:
			return false, false, err
		}
		held := read.Object
		same = held.GetKind() == object.GetKind() && bytes.Equal(held.GetOwnerMemberId(), object.GetOwnerMemberId()) &&
			(len(held.GetNetworkId()) == 0 || bytes.Equal(held.GetNetworkId(), object.GetNetworkId()))
		return same, true, nil
	}
	settle := func() bool {
		same, found, err := sameRepo()
		switch {
		case err != nil && errors.Is(err, sidecar.ErrEvsRepoInvalid):
			self.alarm("repo_invalid", "repo %s: repo/ breaks its shape", sidecar.EvsKeyId(repoId))
		case err != nil:
		case same:
			return true
		case found:
			self.alarm("repo_mismatch", "repo %s: repo/ holds another kind, owner or network than the projection's", sidecar.EvsKeyId(repoId))
			request.refuseStatus(http.StatusConflict, &protocol.EvsRefusalReply{})
			return false
		}
		request.Unavailable(nil)
		return false
	}
	for writeCount := 1; ; writeCount += 1 {
		testHookBarrier(BarrierRepoPutBefore, barrierKey)
		_, err := cluster.PutIfNoneMatch(grant.Context(), RepoKey(repoId), objectBytes, nil)
		testHookBarrier(BarrierRepoPutAfter, barrierKey)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			self.repos.Forget(repoId)
			return true
		case errors.Is(err, sidecar.ErrBlobPrecondition):
			return settle()
		case errors.As(err, &unknown):
			same, found, readErr := sameRepo()
			switch {
			case readErr == nil && same:
				return true
			case readErr == nil && !found && writeCount < evsCreateWriteCount:
				continue
			case readErr == nil && found:
				self.alarm("repo_mismatch", "repo %s: repo/ holds another kind, owner or network than the projection's", sidecar.EvsKeyId(repoId))
				request.refuseStatus(http.StatusConflict, &protocol.EvsRefusalReply{})
				return false
			}
			request.Unavailable(&protocol.EvsRefusalReply{Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN})
			return false
		}
		request.Unavailable(nil)
		return false
	}
}

// The P1 admission for one small create on clusterId, for the token's network. false once it has answered the
// budget's refusal: 429 RESOURCE_EXHAUSTED with retry_after_ms, which refuses nothing.
func (self *EvsEngine) admitCreate(request *EvsRequest, clusterId string, objectByteCount int) (sidecar.WriteGrant, bool) {
	cost, err := self.createCost(objectByteCount)
	if err != nil {
		request.Unavailable(nil)
		return nil, false
	}
	grant, err := self.budget.AdmitP1(request.Ctx, clusterId, request.Principal.NetworkId, cost)
	var refusal *sidecar.WriteRefusal
	switch {
	case err == nil:
		return grant, true
	case errors.As(err, &refusal):
		request.Refuse(&protocol.EvsRefusalReply{
			Code:         protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED,
			RetryAfterMs: refusal.RetryAfterMs(),
		})
		return nil, false
	}
	request.Unavailable(nil)
	return nil, false
}

// A fault the design says alarms: logged as an error and counted by kind, opaque ids only.
func (self *EvsEngine) alarm(kind string, format string, args ...any) {
	self.metrics.alarms.Add(1, kind)
	self.log.Errorf("[evs] alarm "+kind+": "+format, args...)
}
