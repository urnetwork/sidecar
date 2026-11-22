// §10.8's recovery wraps at gkm (D-KEYS-26; QD-468, QD-066): a rotator stages them with POST
// /gkm/groups/<id>/recovery-wraps/<g>/<c8>, a member's device re-wraps after a rebind with POST
// /gkm/recovery/<member_id>/wraps and deletes a retired binding's with DELETE, and GET /gkm/recovery/<member_id>/wraps
// serves them, also to the member's unadmitted client under recovery:<member_id> (§7.8, §7.9).
//
// A RecoveryWrap lives at gkm/recovery/<member_id>/<group_id>/<g>/<c8>/<b8> on its group's repo's cluster, never the
// first (§10.6's placement row), ciphertext bare: it is unsigned (QD-468), so gkm checks its shape, 1,168 bytes, and
// where it may be written:
//
//   - staged like a delivery: only while gen/<g> is absent, or of generation 1 by gen/1's signer while the repo is
//     keying for its creation (KF1), under the STAGED bound, which counts each item (QD-066), answered per item as
//     wraps are, a 412's winner being the stored ciphertext;
//   - re-wrapped after a rebind by the member's own device, to a generation gen/ holds under the commitment the body
//     names, as one object a call, 201 or 412 with the winner;
//   - deleted by the member's own device, every wrap whose b8 names the retired binding, on each cluster, which the
//     client does only once every new one exists (§10.8).
//
// A fetch lists recovery/<member_id>/ on each metadata cluster and answers, per group and binding, the newest
// generation whose c8 is gen/<g>'s: a staged wrap of a lost claim names another commitment, so it is passed over and
// goes with staged GC (KEYS-M2-16).

package gkmservice

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A RecoveryWrap's bytes: X-Wing's 1,120 B enc, a 32 B RK_g and a 16 B tag (QD-468).
const gkmRecoveryWrapByteCount = 1120 + 32 + 16

// A binding or commitment prefix's bytes: b8 and c8 in hex.
const gkmPrefixByteCount = 8

// POST /gkm/groups/<id>/recovery-wraps/<g>/<c8>: a GkmRecoveryWrapBatch, a rotator's staged RecoveryWraps, answered by
// a GkmWrapBatchReply in order.
func (self *GkmEngine) serveRecoveryWrapBatch(request *GkmRequest) {
	generation, c8, ok := readGkmWrapPath(request)
	if !ok {
		return
	}
	batchRequest := &protocol.GkmRecoveryWrapBatch{}
	if !request.ReadMessage(batchRequest, self.settings.RequestBodyMaxByteCount) {
		return
	}
	items := batchRequest.GetItems()
	if len(items) == 0 || self.settings.WrapBatchMaxCount < len(items) {
		request.BadRequest()
		return
	}
	batch, ok := self.newWrapBatchContext(request, generation, c8)
	if !ok {
		return
	}
	groupId := batch.groupId
	reply := &protocol.GkmWrapBatchReply{Results: make([]*protocol.GkmWrapResult, len(items))}
	writes := []*gkmWrapWrite{}
	stagedStatus := batch.stagedStatus(request.SidecarId)
	// A stale creator or rotator may resume after retirement. Never recreate a retired binding's path.
	var current map[sidecar.Id][]byte
	if !self.settings.DraftMls {
		bindings, ok := self.repoRecoveryBindings(request)
		if !ok {
			return
		}
		current = bindings
	}
	afterBudget := sync.OnceValue(func() map[sidecar.Id][]byte {
		bindings, answer := self.currentRepoRecoveryBindings(request)
		if answer != GkmAuthAllowed {
			return nil
		}
		return bindings
	})
	for i, item := range items {
		reply.Results[i] = &protocol.GkmWrapResult{}
		memberId, err := sidecar.IdFromBytes(item.GetMemberId())
		if err != nil || memberId == (sidecar.Id{}) || len(item.GetBindingPrefix()) != gkmPrefixByteCount ||
			len(item.GetCiphertext()) != gkmRecoveryWrapByteCount {
			reply.Results[i].Status = 403
			continue
		}
		if current != nil {
			digest := current[memberId]
			if len(digest) != 32 || !bytes.Equal(digest[:gkmPrefixByteCount], item.GetBindingPrefix()) {
				reply.Results[i].Status = 409
				continue
			}
		}
		if stagedStatus != 0 {
			reply.Results[i].Status = uint32(stagedStatus)
			continue
		}
		rateKey := "staged:" + sidecar.EvsKeyId(request.SidecarId) + ":" + sidecar.EvsKeyId(groupId)
		if !self.rates.Allow(batch.stagedRate, rateKey, request.Now()) {
			reply.Results[i].Status = 429
			continue
		}
		key := GkmRecoveryWrapKey(memberId, groupId, generation, c8, hex.EncodeToString(item.GetBindingPrefix()))
		write := &gkmWrapWrite{key: key, body: item.GetCiphertext(), result: reply.Results[i]}
		if current != nil {
			write.beforePut = func() bool {
				bindings := afterBudget()
				if bindings == nil {
					write.result.Status = gkmWrapStatusNotTried
					return false
				}
				digest := bindings[memberId]
				if len(digest) != 32 || !bytes.Equal(digest[:gkmPrefixByteCount], item.GetBindingPrefix()) {
					write.result.Status = http.StatusConflict
					return false
				}
				return true
			}
		}
		writes = append(writes, write)
	}
	if !self.writeWrapBatch(request, groupId, generation, writes) {
		return
	}
	request.Reply(reply)
}

// POST /gkm/recovery/<member_id>/wraps: a GkmRecoveryWrap, the member's own device re-wrapping a generation gen/
// holds to its new binding after a rebind (§10.8).
func (self *GkmEngine) serveRecoveryWrapWrite(request *GkmRequest) {
	wrap := &protocol.GkmRecoveryWrap{}
	if !request.ReadMessage(wrap, self.settings.RequestBodyMaxByteCount) {
		return
	}
	groupId, err := sidecar.IdFromBytes(wrap.GetGroupId())
	if err != nil || wrap.GetGeneration() == 0 || len(wrap.GetCommitmentPrefix()) != gkmPrefixByteCount ||
		len(wrap.GetBindingPrefix()) != gkmPrefixByteCount || len(wrap.GetCiphertext()) != gkmRecoveryWrapByteCount {
		request.BadRequest()
		return
	}
	if !request.AuthorizeGroup(groupId) {
		return
	}
	facts, err := self.generationFacts(request.Ctx, request.Cluster, groupId, wrap.GetGeneration())
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		request.Conflict(nil)
		return
	}
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if !bytes.Equal(facts.commitment[:gkmPrefixByteCount], wrap.GetCommitmentPrefix()) {
		// a re-wrap names the commitment gen/<g> holds
		request.Conflict(nil)
		return
	}
	key := GkmRecoveryWrapKey(request.pathMemberId, groupId, wrap.GetGeneration(), hex.EncodeToString(wrap.GetCommitmentPrefix()), hex.EncodeToString(wrap.GetBindingPrefix()))
	// a rebind's re-wrap is no REMOVE rotation's: §11.13's P1 (budget.go)
	writeCtx, ok := request.SpendWrites(request.Cluster, "", self.settings.Prices.create(len(wrap.GetCiphertext())))
	if !ok || !request.CheckRepoWritable() {
		return
	}
	barrierKey := gkmBarrierNumberKey(groupId, wrap.GetGeneration())
	testHookBarrier(BarrierWrapPutBefore, barrierKey)
	coverage, ok := self.recoveryCoverage(request)
	if !ok {
		return
	}
	if !slices.Contains(coverage.RepoIds, request.RepoId) || !bytes.Equal(coverage.Current[:gkmPrefixByteCount], wrap.GetBindingPrefix()) {
		request.Conflict(nil)
		return
	}
	winner, err := createGkmObject(writeCtx, request.Cluster, key, wrap.GetCiphertext(), self.settings.DeliveryMaxByteCount)
	testHookBarrier(BarrierWrapPutAfter, barrierKey)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if winner != nil {
		request.PreconditionFailed(winner)
		return
	}
	request.Created()
}

// One recovery wrap a fetch found.
type gkmFoundRecoveryWrap struct {
	clusterId  string
	key        string
	groupId    sidecar.Id
	generation uint64
	c8         string
	b8         string
}

// Every recovery wrap of memberId on every metadata cluster, as their keys name them.
func (self *GkmEngine) listRecoveryWraps(request *GkmRequest, memberId sidecar.Id) ([]*gkmFoundRecoveryWrap, bool) {
	prefix := GkmRecoveryMemberPrefix(memberId)
	found := []*gkmFoundRecoveryWrap{}
	for _, clusterId := range self.blobs.MetadataClusterIds() {
		cluster, err := self.blobs.Cluster(clusterId)
		if err != nil {
			request.Unavailable()
			return nil, false
		}
		infos, err := listGkmKeys(request.Ctx, cluster, prefix, self.settings.ListPageCount, self.settings.RecoveryWrapListMaxCount)
		if err != nil {
			self.answerStoreError(request, err)
			return nil, false
		}
		ownNetwork := map[sidecar.Id]bool{}
		for _, info := range infos {
			groupId, generation, c8, b8, ok := parseGkmRecoveryWrapKey(prefix, info.Key)
			if !ok {
				continue
			}
			ours, known := ownNetwork[groupId]
			if !known {
				body, _, err := readGkmObject(request.Ctx, cluster, GkmGroupOwnerKey(groupId), self.settings.ObjectMaxByteCount)
				if err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
					self.answerStoreError(request, err)
					return nil, false
				}
				owner := &protocol.GkmGroupOwner{}
				ours = err == nil && proto.Unmarshal(body, owner) == nil && bytes.Equal(owner.GetNetworkId(), sidecar.Id(request.Principal.NetworkId).Bytes())
				ownNetwork[groupId] = ours
			}
			if !ours {
				continue
			}
			found = append(found, &gkmFoundRecoveryWrap{clusterId: clusterId, key: info.Key, groupId: groupId, generation: generation, c8: c8, b8: b8})
		}
	}
	return found, true
}

// Recovery wrap retirement is owned by the member across all of its devices. The authorization snapshot gives
// the service the entire set of eligible repos, including ones outside the requesting device's scopes.
type RecoveryWrapCoverage struct {
	Current []byte
	Retired [][]byte
	RepoIds []sidecar.Id
}

type gkmRecoveryCoverageState interface {
	RecoveryCoverage(principal *sidecar.Principal, memberId sidecar.Id, now time.Time) (*RecoveryWrapCoverage, GkmAuthAnswer)
}

type gkmRepoRecoveryState interface {
	RepoRecoveryBindings(principal *sidecar.Principal, repoId sidecar.Id, now time.Time) (map[sidecar.Id][]byte, GkmAuthAnswer)
}

func (self *GkmEngine) currentRepoRecoveryBindings(request *GkmRequest) (map[sidecar.Id][]byte, GkmAuthAnswer) {
	source, ok := self.deps.AuthState.(gkmRepoRecoveryState)
	if !ok {
		return nil, GkmAuthUnknown
	}
	bindings, answer := source.RepoRecoveryBindings(request.Principal, request.RepoId, request.Now())
	if answer == GkmAuthAllowed && bindings == nil {
		return nil, GkmAuthUnknown
	}
	return bindings, answer
}

func (self *GkmEngine) repoRecoveryBindings(request *GkmRequest) (map[sidecar.Id][]byte, bool) {
	bindings, answer := self.currentRepoRecoveryBindings(request)
	if answer != GkmAuthAllowed {
		answerGkmAuth(request, answer)
		return nil, false
	}
	return bindings, true
}

// A new winning claim and retirement both require coverage under the current bindings. A concurrent rotator
// that staged to the old binding cannot supersede the generation the rebind just verified.
func (self *GkmEngine) checkClaimRecoveryWraps(request *GkmRequest, groupId sidecar.Id, generation uint64, commitment []byte, raw []byte) bool {
	if self.settings.DraftMls {
		return true
	}
	bindings, ok := self.repoRecoveryBindings(request)
	if !ok {
		return false
	}
	c8, _ := gkmDigestPrefix(commitment)
	for memberId, binding := range bindings {
		b8, valid := gkmDigestPrefix(binding)
		if !valid {
			request.Unavailable()
			return false
		}
		key := GkmRecoveryWrapKey(memberId, groupId, generation, c8, b8)
		wrap, _, err := readGkmObject(request.Ctx, request.Cluster, key, gkmRecoveryWrapByteCount)
		if err == nil && len(wrap) == gkmRecoveryWrapByteCount {
			continue
		}
		if err != nil && !errors.Is(err, sidecar.ErrBlobNotFound) {
			self.answerStoreError(request, err)
			return false
		}
		// A retry of an earlier win must still see its original result, including after rebind, unless a re-form has
		// closed the group since (reform_fence.go): no claim there is answered as won, nor its winner judged.
		winner, err := readGkmGeneration(request.Ctx, request.Cluster, groupId, generation, self.settings.StatementMaxByteCount)
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
			request.Conflict(nil)
		case err != nil:
			self.answerStoreError(request, err)
		case !self.checkGroupOpen(request, groupId):
		case bytes.Equal(winner, raw):
			request.Created()
		default:
			request.PreconditionFailed(winner)
		}
		return false
	}
	return true
}

func (self *GkmEngine) recoveryCoverage(request *GkmRequest) (*RecoveryWrapCoverage, bool) {
	source, ok := self.deps.AuthState.(gkmRecoveryCoverageState)
	if !ok {
		request.Unavailable()
		return nil, false
	}
	coverage, answer := source.RecoveryCoverage(request.Principal, request.pathMemberId, request.Now())
	switch {
	case answer == GkmAuthDenied:
		request.Forbidden()
	case answer != GkmAuthAllowed || coverage == nil || len(coverage.Current) != 32:
		request.Unavailable()
	default:
		return coverage, true
	}
	return nil, false
}

// The latest formed group of each eligible repo must hold a replacement wrap of its current winning generation.
// A repo that has not formed a group has no key to replace. A group partway through creation or reseed waits.
func (self *GkmEngine) checkRecoveryCoverage(request *GkmRequest, coverage *RecoveryWrapCoverage) bool {
	for _, repoId := range coverage.RepoIds {
		cluster, _, err := self.places.Cluster(request.Ctx, repoId)
		if errors.Is(err, sidecar.ErrEvsRepoNotPlaced) {
			continue
		}
		if err != nil {
			self.answerStoreError(request, err)
			return false
		}
		forms, err := gkmReadForms(request.Ctx, cluster, repoId, self.settings)
		if err != nil {
			self.answerStoreError(request, err)
			return false
		}
		if len(forms) == 0 {
			continue
		}
		form := forms[len(forms)-1]
		facts, found, err := gkmNewestGenerationFacts(request.Ctx, cluster, form.GroupId, self.settings)
		if err != nil {
			self.answerStoreError(request, err)
			return false
		}
		if !found || facts.generation < form.Body.GetGeneration() {
			request.Conflict(nil)
			return false
		}
		c8, _ := gkmDigestPrefix(facts.commitment)
		b8, _ := gkmDigestPrefix(coverage.Current)
		key := GkmRecoveryWrapKey(request.pathMemberId, form.GroupId, facts.generation, c8, b8)
		ciphertext, _, err := readGkmObject(request.Ctx, cluster, key, gkmRecoveryWrapByteCount)
		if errors.Is(err, sidecar.ErrBlobNotFound) || err == nil && len(ciphertext) != gkmRecoveryWrapByteCount {
			request.Conflict(nil)
			return false
		}
		if err != nil {
			self.answerStoreError(request, err)
			return false
		}
	}
	return true
}

// GET /gkm/recovery/<member_id>/wraps: a GkmRecoveryWrapsReply, per group and binding the newest generation's wrap
// whose c8 is gen/<g>'s, at most RecoveryWrapsReplyMaxCount.
func (self *GkmEngine) serveRecoveryWrapsRead(request *GkmRequest) {
	memberId := request.pathMemberId
	if request.Http.URL.Query().Has("complete") {
		b8 := request.Http.URL.Query().Get("complete")
		if !gkmHexPrefixForm(b8) {
			request.BadRequest()
			return
		}
		if request.viaRecoveryScope {
			request.Forbidden()
			return
		}
		coverage, ok := self.recoveryCoverage(request)
		if !ok {
			return
		}
		current, _ := gkmDigestPrefix(coverage.Current)
		if current != b8 {
			request.Conflict(nil)
			return
		}
		if self.checkRecoveryCoverage(request, coverage) {
			request.Reply(nil)
		}
		return
	}
	found, ok := self.listRecoveryWraps(request, memberId)
	if !ok {
		return
	}
	// newest generation first, so the first wrap of a group and binding that gen/ confirms is its newest
	slices.SortStableFunc(found, func(a *gkmFoundRecoveryWrap, b *gkmFoundRecoveryWrap) int {
		if a.generation != b.generation {
			if b.generation < a.generation {
				return -1
			}
			return 1
		}
		return 0
	})
	answered := map[string]bool{}
	reply := &protocol.GkmRecoveryWrapsReply{}
	for _, wrap := range found {
		if self.settings.RecoveryWrapsReplyMaxCount <= len(reply.GetWraps()) {
			break
		}
		answerKey := sidecar.EvsKeyId(wrap.groupId) + ":" + wrap.b8
		if answered[answerKey] {
			continue
		}
		cluster, err := self.blobs.Cluster(wrap.clusterId)
		if err != nil {
			request.Unavailable()
			return
		}
		facts, err := self.generationFacts(request.Ctx, cluster, wrap.groupId, wrap.generation)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			// a staged wrap of a claim not made, or not yet
			continue
		}
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		if c8, _ := gkmDigestPrefix(facts.commitment); c8 != wrap.c8 {
			// a staged wrap of a lost claim
			continue
		}
		ciphertext, _, err := readGkmObject(request.Ctx, cluster, wrap.key, self.settings.DeliveryMaxByteCount)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			continue
		}
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		commitmentPrefix, _ := hex.DecodeString(wrap.c8)
		bindingPrefix, _ := hex.DecodeString(wrap.b8)
		answered[answerKey] = true
		reply.Wraps = append(reply.Wraps, &protocol.GkmRecoveryWrap{
			GroupId:          wrap.groupId.Bytes(),
			Generation:       wrap.generation,
			CommitmentPrefix: commitmentPrefix,
			BindingPrefix:    bindingPrefix,
			Ciphertext:       ciphertext,
		})
	}
	request.Reply(reply)
}

func (self *GkmEngine) canRetireRecoveryBinding(request *GkmRequest, b8 string) bool {
	coverage, ok := self.recoveryCoverage(request)
	if !ok {
		return false
	}
	current, _ := gkmDigestPrefix(coverage.Current)
	retired := slices.ContainsFunc(coverage.Retired, func(digest []byte) bool {
		prefix, ok := gkmDigestPrefix(digest)
		return ok && prefix == b8
	})
	if !retired || current == b8 {
		request.Conflict(nil)
		return false
	}
	return self.checkRecoveryCoverage(request, coverage)
}

// DELETE /gkm/recovery/<member_id>/wraps?binding=<b8>: every wrap of the member whose b8 names a retired binding, on
// each cluster, by the member's own device. A delete is a user's own, which no hold pauses (owner decision 133).
func (self *GkmEngine) serveRecoveryWrapsDelete(request *GkmRequest) {
	b8 := request.Http.URL.Query().Get("binding")
	if !gkmHexPrefixForm(b8) {
		request.BadRequest()
		return
	}
	if !self.canRetireRecoveryBinding(request, b8) {
		return
	}
	found, ok := self.listRecoveryWraps(request, request.pathMemberId)
	if !ok {
		return
	}
	// the deletes queue as P1 on each wrap's cluster, one admission a cluster (budget.go)
	clusterIds := []string{}
	clusterIdKeys := map[string][]string{}
	for _, wrap := range found {
		if wrap.b8 != b8 {
			continue
		}
		if _, ok := clusterIdKeys[wrap.clusterId]; !ok {
			clusterIds = append(clusterIds, wrap.clusterId)
		}
		clusterIdKeys[wrap.clusterId] = append(clusterIdKeys[wrap.clusterId], wrap.key)
	}
	for _, clusterId := range clusterIds {
		cluster, err := self.blobs.Cluster(clusterId)
		if err != nil {
			request.Unavailable()
			return
		}
		keys := clusterIdKeys[clusterId]
		writeCtx, ok := request.SpendWrites(cluster, "", int64(len(keys))*self.settings.Prices.delete())
		if !ok || !self.canRetireRecoveryBinding(request, b8) {
			return
		}
		for _, key := range keys {
			if err := deleteGkmObject(writeCtx, cluster, key); err != nil {
				// the client sends it again, and a key already gone is no error
				self.answerStoreError(request, err)
				return
			}
		}
	}
	request.Reply(nil)
}
