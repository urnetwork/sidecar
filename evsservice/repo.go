// GET and DELETE /evs/v1/repos/<id>, POST .../restore and POST .../activate (§11.12, §11.20,
// plan-EVS1-repo-activate-route; EVS1-M2-19), beside PUT's placement and creation (place.go). Each is placed, and each
// write reads repo/ from the cluster and changes it by one If-Match (repo_state.go).
//
//	get       (r): repo/ as an EvsRepoObject while keying or active; a deleted repo answers 409 REPO_DELETED and one
//	          past deleted 409 SHREDDING, since §11.12's refused row closes every route but restore and DELETE with now
//	delete    (admin), [?now=1]: the projection's newest RepoDelete, unrestored and with the request's now, else 409
//	          STATEMENT_MISSING (§11.12's log first row); then active -> deleted{its id, its entry's time and signer},
//	          or with now active, or deleted under an older deletion, -> shredding, never restorable; P0 lifecycle. A
//	          deleted repo's shred start is queued for 7 d 10 min after the RepoDelete's entry, and a shredding repo's
//	          shred at once, under a once key of the repo and deletion (shred.go)
//	restore   (admin): the projection's newest RepoDelete with a projected RepoRestore of it, else 409
//	          STATEMENT_MISSING; deleted under that deletion -> active; a repo past deleted 409 SHREDDING; P0 lifecycle
//	activate  (admin), no body: keying -> active once gkm/repo/<id>/'s newest GroupForm names a group whose
//	          gkm/<group_id>/gen/1 exists, else 409 GROUP_NOT_READY; active answers 200, so a retry is harmless, and a
//	          later state its refusal; the CAS is P1 for the creating network, paid before it is issued. evs cannot see
//	          whether wraps are complete, so KF1's order on the creator stays the guarantee
//
// Not built: the hint §11.12's delete and start rows send members, which no hint shape names (EvsHeadChanged names a
// ref); members learn at their next read or lease, which a deleted repo refuses.

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"net/http"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The route templates.
const (
	evsRepoGetTemplate      = "GET /evs/v1/repos/{repo_id}"
	evsRepoDeleteTemplate   = "DELETE /evs/v1/repos/{repo_id}"
	evsRepoRestoreTemplate  = "POST /evs/v1/repos/{repo_id}/restore"
	evsRepoActivateTemplate = "POST /evs/v1/repos/{repo_id}/activate"
)

// The lifecycle routes.
func (self *EvsEngine) repoRoutes() []*EvsRoute {
	pattern := evsRoutePrefix + "repos/{" + evsRepoIdPathValue + "}"
	return []*EvsRoute{
		{Method: http.MethodGet, Pattern: pattern, Name: evsRepoGetTemplate, Rights: sidecar.AclEvsRead, Placed: true, Serve: self.serveGetRepo},
		{Method: http.MethodDelete, Pattern: pattern, Name: evsRepoDeleteTemplate, Rights: sidecar.AclEvsAdmin, Write: true, Placed: true, Serve: self.serveDeleteRepo},
		{Method: http.MethodPost, Pattern: pattern + "/restore", Name: evsRepoRestoreTemplate, Rights: sidecar.AclEvsAdmin, Write: true, Placed: true, Serve: self.serveRestoreRepo},
		{Method: http.MethodPost, Pattern: pattern + "/activate", Name: evsRepoActivateTemplate, Rights: sidecar.AclEvsAdmin, Write: true, Placed: true, Serve: self.serveActivateRepo},
	}
}

// GET: see the file header.
func (self *EvsEngine) serveGetRepo(request *EvsRequest) {
	read, err := self.repos.Read(request.Ctx, request.Cluster, request.RepoId)
	if !self.answerTransition(request, err) {
		return
	}
	switch read.Object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_KEYING, protocol.EvsRepoState_EVS_REPO_ACTIVE:
		request.Reply(read.Object)
	default:
		request.RefuseCode(repoStateRefusal(read.Object).Code)
	}
}

// The projection's newest RepoDelete of the request's repo, in the token's network. false once it has answered: 503
// while the state is not loaded, 409 STATEMENT_MISSING when the projection holds no RepoCreate or no RepoDelete, 403
// SCOPE for another network's repo.
func (self *EvsEngine) projectedDeletion(request *EvsRequest) (*EvsRepoDeletionFacts, bool) {
	facts, answer := self.deps.AuthState.Repo(request.Principal, request.RepoId)
	switch answer {
	case EvsAuthAllowed:
	case EvsAuthDenied:
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
		return nil, false
	default:
		request.Unavailable(nil)
		return nil, false
	}
	if facts.NetworkId != networkIdOf(request.Principal) {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		return nil, false
	}
	if facts.Deletion == nil || facts.Deletion.DeletionId == (sidecar.Id{}) {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
		return nil, false
	}
	return facts.Deletion, true
}

// DELETE: see the file header.
func (self *EvsEngine) serveDeleteRepo(request *EvsRequest) {
	nowText := request.Http.URL.Query().Get("now")
	if nowText != "" && nowText != "1" {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		return
	}
	deletion, ok := self.projectedDeletion(request)
	if !ok {
		return
	}
	if deletion.Restored || deletion.Now != (nowText == "1") {
		// the newest RepoDelete was restored, or is not the one this request names: the device files its own first
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
		return
	}
	read, err := transitionRepo(request.Ctx, request.Cluster, self.repos, request.RepoId, self.settings.RepoTransitionRetryCount,
		self.p0Class(request.Cluster, sidecar.WriteP0KindLifecycle), decideDelete(deletion, request.Now()))
	if !self.answerTransition(request, err) {
		return
	}
	self.queueShred(request.Ctx, request.RepoId, read.Object)
	request.Reply(nil)
}

// POST .../restore: see the file header.
func (self *EvsEngine) serveRestoreRepo(request *EvsRequest) {
	deletion, ok := self.projectedDeletion(request)
	if !ok {
		return
	}
	if !deletion.Restored || deletion.Now {
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING)
		return
	}
	_, err := transitionRepo(request.Ctx, request.Cluster, self.repos, request.RepoId, self.settings.RepoTransitionRetryCount,
		self.p0Class(request.Cluster, sidecar.WriteP0KindLifecycle), decideRestore(deletion, request.Now()))
	if !self.answerTransition(request, err) {
		return
	}
	request.Reply(nil)
}

// POST .../activate: see the file header.
func (self *EvsEngine) serveActivateRepo(request *EvsRequest) {
	read, err := self.repos.Read(request.Ctx, request.Cluster, request.RepoId)
	if !self.answerTransition(request, err) {
		return
	}
	switch read.Object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_ACTIVE:
		request.Reply(nil)
		return
	case protocol.EvsRepoState_EVS_REPO_KEYING:
	default:
		request.RefuseCode(repoStateRefusal(read.Object).Code)
		return
	}
	objectBytes, err := sidecar.MarshalEvsRepoObject(read.Object)
	if err != nil {
		request.Unavailable(nil)
		return
	}
	grant, ok := self.admitOne(request, WriteOperationOverwrite, int64(len(objectBytes)))
	if !ok {
		return
	}
	defer grant.Close()
	groupReady := func() (bool, error) {
		return evsRepoGroupReady(request.Ctx, request.Cluster, request.RepoId, self.settings.ShredListPageCount)
	}
	_, err = transitionRepo(grant.Context(), request.Cluster, self.repos, request.RepoId, self.settings.RepoTransitionRetryCount,
		func(ctx context.Context, objectByteCount int) context.Context { return ctx }, decideActivate(groupReady, request.Now()))
	if !self.answerTransition(request, err) {
		return
	}
	request.Reply(nil)
}

// gkm's GroupForms of a repo: gkm/repo/<repo_id>/<seq>, seq in 20 digits from 1 (gkmservice.GkmFormKey, which
// evs cannot import; repo_test.go pins the two together).
func evsGkmFormPrefix(repoId sidecar.Id) string {
	return "gkm/repo/" + sidecar.EvsKeyId(repoId) + "/"
}

// Whether a repo's group has formed (plan-EVS1-repo-activate-route): its newest GroupForm, the last of
// gkm/repo/<repo_id>/ by key, names a group whose gen/1 exists. A form that does not parse as a Signed GroupForm of
// this repo is a fault, ErrEvsRepoInvalid's kind, which never activates.
func evsRepoGroupReady(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, pageCount int) (bool, error) {
	prefix := evsGkmFormPrefix(repoId)
	newestKey := ""
	startAfter := ""
	for {
		infos, more, err := cluster.List(ctx, prefix, startAfter, pageCount)
		if err != nil {
			return false, err
		}
		for _, info := range infos {
			if newestKey < info.Key {
				newestKey = info.Key
			}
		}
		if !more || len(infos) == 0 {
			break
		}
		startAfter = infos[len(infos)-1].Key
	}
	if newestKey == "" {
		return false, nil
	}
	object, err := cluster.Get(ctx, newestKey)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer object.Body.Close()
	var formBytes bytes.Buffer
	if _, err := formBytes.ReadFrom(object.Body); err != nil {
		return false, err
	}
	signed := &bridge.Signed{}
	form := &protocol.GroupForm{}
	if err := proto.Unmarshal(formBytes.Bytes(), signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_GROUP_FORM) ||
		proto.Unmarshal(signed.GetBody(), form) != nil || !bytes.Equal(form.GetRepoId(), repoId.Bytes()) {
		return false, errors.Join(sidecar.ErrEvsRepoInvalid, errors.New("a GroupForm that is not this repo's"))
	}
	groupId, err := sidecar.IdFromBytes(form.GetGroupId())
	if err != nil || groupId == (sidecar.Id{}) {
		return false, errors.Join(sidecar.ErrEvsRepoInvalid, errors.New("a GroupForm naming no group"))
	}
	_, err = cluster.Head(ctx, sidecar.GkmGenerationPath(groupId, 1))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sidecar.ErrBlobNotFound):
		return false, nil
	}
	return false, err
}

// A transition's ctx, P0 of kind on cluster at an overwrite of its bytes' price, issued at once (owner decision 186).
func (self *EvsEngine) p0Class(cluster sidecar.BlobCluster, kind sidecar.WriteP0Kind) func(ctx context.Context, objectByteCount int) context.Context {
	return evsP0Class(self.budget, self.priceTable, cluster, kind)
}

// A transition's or a delete's ctx, P0 of kind on cluster.
func evsP0Class(budget sidecar.WriteBudget, priceTable *PriceTable, cluster sidecar.BlobCluster, kind sidecar.WriteP0Kind) func(ctx context.Context, objectByteCount int) context.Context {
	return func(ctx context.Context, objectByteCount int) context.Context {
		price, err := priceTable.Price(WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(objectByteCount), Count: 1})
		if err != nil {
			price = int64(objectByteCount)
		}
		return budget.IssueP0(ctx, cluster.ClusterId(), kind, price)
	}
}

// Answers a read's or transition's error; true for none.
func (self *EvsEngine) answerTransition(request *EvsRequest, err error) bool {
	var refusal *EvsRepoRefusal
	var writeRefusal *sidecar.WriteRefusal
	switch {
	case err == nil:
		return true
	case errors.As(err, &refusal):
		request.RefuseCode(refusal.Code)
	case errors.Is(err, sidecar.ErrEvsRepoNotFound):
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
	case errors.Is(err, ErrEvsRepoBusy):
		request.RefuseCode(protocol.EvsRefusalCode_EVS_REFUSAL_BUSY)
	case errors.As(err, &writeRefusal):
		request.Refuse(&protocol.EvsRefusalReply{Code: protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED, RetryAfterMs: max(1, writeRefusal.RetryAfterMs())})
	case errors.Is(err, sidecar.ErrEvsRepoInvalid), errors.Is(err, sidecar.ErrEvsRepoTransition):
		self.alarm("repo_invalid", "repo %s: %v", sidecar.EvsKeyId(request.RepoId), err)
		request.Unavailable(nil)
	default:
		request.Unavailable(nil)
	}
	return false
}

// Queues the shred a transition left due: a deleted repo's start 7 d 10 min after its RepoDelete's entry, a shredding
// repo's run at once, each once-keyed by repo and deletion so a retry queues nothing twice. A queue that does not
// answer is logged: the reconciler's walk queues every deleted and shredding repo again (reconcile.go).
func (self *EvsEngine) queueShred(ctx context.Context, repoId sidecar.Id, object *protocol.EvsRepoObject) {
	request, ok := evsShredRequest(repoId, object, self.clock.Now())
	if !ok {
		return
	}
	if self.host.Tasks == nil {
		self.log.Warningf("[evs] repo %s: no task queue, so its shred waits for the reconciler", sidecar.EvsKeyId(repoId))
		return
	}
	if err := self.host.Tasks.Schedule(ctx, request); err != nil {
		self.log.Warningf("[evs] repo %s: its shred was not queued, so it waits for the reconciler: %v", sidecar.EvsKeyId(repoId), err)
	}
}
