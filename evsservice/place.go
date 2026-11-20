// PUT /evs/v1/repos/<id> (§11.8's placement row, §11.12's naming row, owner decision 145): places a repo, then
// writes its repo/ there. A sidecar files §8.8's RepoCreate first, becoming the repo's admin, so the route takes
// admin, and the projection gives repo/ its kind and owner.
//
//  1. place/<repo_id> on the first metadata cluster, If-None-Match, naming the cluster that takes new repos
//     (BlobStore.NewRepoClusterId, sidecar.yml's place_new) and this sidecar as creator. A place_new this process
//     cannot reach answers a new repo 503 before anything is written, so no place/ ever names it; a repo already
//     placed goes on to step 2's rule.
//  2. On 412, or an unknown outcome, it reads place/: the same creator continues on the cluster place/ names,
//     whatever place_new says now. For the config kind alone, whose id the Genesis fixes, so does any sidecar whose
//     config admin the guard honored (every config writer, QD-894), place/ keeping the cluster and creator it names
//     (QD-982, owner decision 567): so another config writer places a config repo whose creator is gone with its
//     repo/ unwritten, its create stopped between place/ and repo/ or a restore having brought back place/ alone.
//     Any other gets 409 REPO_PLACED and picks another id (owner decision 411), so of two racing creates exactly one
//     writes place/, and a retry never moves it. An unknown outcome whose read finds no place/ never landed and
//     never will (§19.6's settle rule), and the same bytes go once more.
//  3. Only then repo/<id> there, If-None-Match, `keying` until §10's KF1, format 1, with the creating token's
//     network (plan-EVSB-repo-network). A 412 whose repo/ is this repo, network, kind and owner is a retry, or a
//     config writer meeting another's create of the config repo, and answers 200 as the first did, so racing config
//     writers converge on one repo/; any other is a fault that alarms, and answers 409 REPO_PLACED as well, since the
//     id holds a repo other than the one this create makes and only another id gets the creator on.
//
// In a recovery (§19.10's groups row, §11.13's re-seed row; QD-1062): while sidecar.yml's reseed is on, a repo whose
// projection ends in an unrestored, dated RepoDelete without now, inside ReseedRestoreWindow of its entry, is created
// with repo/ deleted{deletion_id, its entry's time, signer}, never keying, so access stays refused from the repo's
// first object while its history, group and slots return (reseed.go; §11.12's re-seed exception), a segment its
// admin's walk uploads before its first reseed call included (QD-977), and restore and the 7-day start resume: the
// start is queued as a transition to deleted queues it. Nothing activates such a repo, activate answering a deleted
// repo/ 409 REPO_DELETED; a RepoRestore brings it to active. One past restoring, its RepoDelete carrying now, undated
// or past the window, answers 409 SHREDDING before anything is written, place/ included, as the reseed route answers
// it; an unsure clock judges no window and answers 503; and a RepoDelete whose signer neither the projection's log
// nor its row names answers 409 STATEMENT_MISSING, no value guessed (decideDelete's rule). With reseed off every
// create is keying, as before. A retry answers by the repo/ that stands, whatever its state, as every create's does.
//
// Both writes are P1 for the creating network (plan-EVSB-write-classes). The projection's kind must be one of §11.12's
// nine, with an owner exactly for vault, mailbox and secret, else 400 INVALID with an alarm. The rest of the route's
// family, GET, DELETE, restore and activate, is repo.go's.

package evsservice

import (
	"bytes"
	"errors"
	"net/http"

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
	if !sidecar.EvsRepoKindKnown(facts.Kind) || !sidecar.AclRepoKindOwnerFits(facts.Kind, facts.OwnerMemberId != sidecar.Id{}) {
		// §11.12's kinds table: a kind this build does not know, an owner-bound kind with no owner, or an owner on a
		// kind that takes none (only a Team scope's own mailcfg names one beside them, QD-1093), is a projection this
		// build cannot keep, never a repo it creates
		self.alarm("repo_kind", "repo %s: the projection holds kind %d with owner %t", sidecar.EvsKeyId(request.RepoId), facts.Kind, facts.OwnerMemberId != sidecar.Id{})
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	deletion, ok := self.placeDeletion(request, facts)
	if !ok {
		return
	}
	place, ok := self.placeRepo(request, facts)
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
	created, ok := self.createRepoObject(request, cluster, facts, deletion)
	if !ok {
		return
	}
	if created != nil {
		// created deleted: its 7-day start, once-keyed by repo and deletion, as a transition to deleted queues it
		self.queueShred(request.Ctx, request.RepoId, created)
	}
	request.Reply(nil)
}

// The unrestored RepoDelete a repo placed in a recovery is created deleted under (see the file header; QD-1062), nil
// for one created keying: every create while reseed is off, and a live or restored repo's while it is on. false once
// it has answered the refusal of a repo past restoring, a window an unsure clock cannot judge, or a RepoDelete with
// no signer named, each before anything is written.
func (self *EvsEngine) placeDeletion(request *EvsRequest, facts *EvsRepoFacts) (*EvsRepoDeletionFacts, bool) {
	if !self.host.GatesOrClosed().Reseed() {
		return nil, true
	}
	// a window is judged only for a dated RepoDelete without now, and only by a sure clock
	if deletion := facts.Deletion; deletion != nil && deletion.DeletionId != (sidecar.Id{}) && !deletion.Restored &&
		!deletion.Now && !deletion.Time.IsZero() && !self.clockSure() {
		request.Unavailable(nil)
		return nil, false
	}
	deletion, restorable := self.reseedDeletion(facts, request.Now())
	switch {
	case deletion == nil:
		return nil, true
	case !restorable:
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING)
		return nil, false
	case deletion.SignerSidecarId == (sidecar.Id{}):
		// repo/ deleted names its RepoDelete's signer: a projection that tells none writes no guessed value
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
		return nil, false
	}
	return deletion, true
}

// Steps 1 and 2 for the repo the projection's facts describe: the placement this create continues on. false once it
// has answered the refusal.
func (self *EvsEngine) placeRepo(request *EvsRequest, facts *EvsRepoFacts) (*sidecar.EvsRepoPlace, bool) {
	repoId := request.RepoId
	newClusterId := self.blobs.NewRepoClusterId()
	if _, err := self.blobs.Cluster(newClusterId); err != nil {
		// a repo already placed continues where place/ names, and a new one waits, so no place/ names this cluster
		if held, err := self.places.Resolve(request.Ctx, repoId); err == nil {
			return self.continuePlace(request, facts, held)
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
			return self.continuePlace(request, facts, held)
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
				return self.continuePlace(request, facts, held)
			case errors.Is(readErr, sidecar.ErrEvsRepoNotPlaced) && writeCount < self.settings.CreateWriteCount:
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

// Step 2's rule for a placement that stands: its creator continues on its cluster, and for the config kind alone so
// does any sidecar whose config admin the guard honored (QD-982): the config repo's id is the Genesis's, so no other id
// can be picked, and every config writer administers it (QD-894). place/ keeps the cluster and creator it names, never
// rewritten, so a config writer continues on the creator's placement and step 3's If-None-Match leaves racing config
// writers one repo/. Any other gets 409 REPO_PLACED, final, and picks another id (QD-927), where a lifecycle 409 such
// as STATEMENT_MISSING keeps the id.
func (self *EvsEngine) continuePlace(request *EvsRequest, facts *EvsRepoFacts, held *sidecar.EvsRepoPlace) (*sidecar.EvsRepoPlace, bool) {
	creator := held.CreatorSidecarId == request.SidecarId
	// the route takes admin, so the guard honored it; held to it here all the same, as the rule's own condition
	configWriter := facts.Kind == protocol.RepoKind_REPO_KIND_CONFIG && request.Rights.Has(sidecar.AclEvsAdmin)
	if !creator && !configWriter {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED)
		return nil, false
	}
	self.places.Remember(request.RepoId, held)
	return held, true
}

// Step 3: repo/ on the placed cluster, keying, or with deletion deleted{its id, its entry's time, its signer} (see the
// file header). The answer is the repo/ this call's own write created deleted, which leaves its 7-day start due, nil
// for a keying create and for a retry that found repo/ standing; false once it has answered the refusal.
func (self *EvsEngine) createRepoObject(request *EvsRequest, cluster sidecar.BlobCluster, facts *EvsRepoFacts, deletion *EvsRepoDeletionFacts) (*protocol.EvsRepoObject, bool) {
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
	var created *protocol.EvsRepoObject
	if deletion != nil {
		// as DELETE writes an active repo's deleted state (decideDelete): the entry's time, which the 7-day start
		// counts from, so every retry sends the same bytes
		object.State = protocol.EvsRepoState_EVS_REPO_DELETED
		object.StateMs = deletion.Time.UnixMilli()
		object.DeletionId = deletion.DeletionId.Bytes()
		object.StateSigner = deletion.SignerSidecarId.Bytes()
		created = object
	}
	// held to repo/'s shape, a deleted one's deletion id and signer among it
	objectBytes, err := sidecar.MarshalEvsRepoObject(object)
	if err != nil {
		request.Unavailable(nil)
		return nil, false
	}
	grant, ok := self.admitCreate(request, cluster.ClusterId(), len(objectBytes))
	if !ok {
		return nil, false
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
			request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED)
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
			return created, true
		case errors.Is(err, sidecar.ErrBlobPrecondition):
			return nil, settle()
		case errors.As(err, &unknown):
			same, found, readErr := sameRepo()
			switch {
			case readErr == nil && same:
				// this write's or another create's: the reconciler queues a deleted repo's start either way
				return nil, true
			case readErr == nil && !found && writeCount < self.settings.CreateWriteCount:
				continue
			case readErr == nil && found:
				self.alarm("repo_mismatch", "repo %s: repo/ holds another kind, owner or network than the projection's", sidecar.EvsKeyId(repoId))
				request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_REPO_PLACED)
				return nil, false
			}
			request.Unavailable(&protocol.EvsRefusalReply{Outcome: protocol.EvsPushOutcome_EVS_PUSH_OUTCOME_UNKNOWN})
			return nil, false
		}
		request.Unavailable(nil)
		return nil, false
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
