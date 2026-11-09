// §10.6's one-commit duty and epoch PUT check (D-KEYS-3, D-KEYS-5; R-KEYS-5): GET /gkm/groups/<id>/epochs?after= and
// POST /gkm/groups/<id>/epochs/<n>, over gkm/<group_id>/epoch/<n> on the repo's cluster.
//
// A commit makes epoch n once epoch/<n-1> exists, by an If-None-Match create, so the first commit wins and a loser
// gets 409 with the winner, which it processes (KF6). gkm reads only the commit's clear header (ParseMlsHeader, I-1):
// its group, epoch, content type and authenticated_data, which carries GkmCommitHeader, and for an external commit
// the joiner's credential and the old leaf it removes. It reads no proposal (owner decision 59): members refuse what a
// committer may not commit (§10.9). The check, in order:
//
//   - the commit is a commit of this group sent in epoch n-1, a member's as a PrivateMessage, an external one as a
//     PublicMessage whose credential is the uploader's own, under the identity key the log admits for it;
//   - GkmCommitHeader.generation is gen/'s newest as gkm reads it before the PUT (gen/<g+1> answers 404) and never
//     below epoch n-1's; a rotation landing between that read and the PUT is harmless, since joiners fetch a late
//     wrap. The one exception: an external commit by a device its member's recovery key admitted may say generation
//     0 and carry no GenWrap (§10.8), and the group's next commit carries gen/'s newest again;
//   - its auth pin exists, as gkm's newest state judges it, and never falls below epoch n-1's. An epoch with no pin, a
//     re-form's epoch 0 as landed, gives no floor, and question keys-wire-reform-epoch-zero asks what should; until
//     it is answered a commit onto such an epoch is refused (fail closed);
//   - repo/ is reread as the write issues, so a write in flight at a shred lands before §11.12 repeats the group's
//     deletion (§10.6's checks row), and 60 commits an hour per uploader per group.
//
// The store operations of a commit are §10.6's list: GET epoch/<n-1>, GET repo/<id> (5 s cache), GET gen/<g+1> (404)
// and the PUT, besides a HEAD of gen/<g> when the generation moved since epoch n-1, and at 16 leaves or fewer one
// group-info GET (5 s cache) and, 16 epochs past the pointer, the pointer's PUT (groupinfo.go). A retry of a lost
// answer finds its own commit standing and answers the original 200 (FI-2). A success hints commit on gkm:<group_id>
// to the repo's readers, versioned epoch × 2^24 + generation (D-KEYS-19).

package gkmservice

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// RFC 9420's ContentType commit, the only content a commit's header may carry (§10.4).
const gkmMlsContentTypeCommit = 3

// GET /gkm/groups/<id>/epochs?after=<n>: a GkmEpochsReply, the epochs after n in order, with their sizes, up to the
// settings' bounds; with no after, from epoch 0.
func (self *GkmEngine) serveEpochsRead(request *GkmRequest) {
	groupId := *request.GroupId
	prefix := GkmEpochPrefix(groupId)
	startAfter := ""
	if afterText := request.Http.URL.Query().Get("after"); afterText != "" {
		after, err := parseGkmNumber(afterText)
		if err != nil {
			request.BadRequest()
			return
		}
		startAfter = GkmEpochKey(groupId, after)
	}
	infos, more, err := request.Cluster.List(request.Ctx, prefix, startAfter, min(self.settings.EpochsReplyMaxCount, self.settings.ListPageCount))
	if err != nil {
		request.Unavailable()
		return
	}
	reply := &protocol.GkmEpochsReply{}
	byteCount := int64(0)
	complete := !more
	for _, info := range infos {
		epoch, ok := parseGkmKeyNumber(strings.TrimPrefix(info.Key, prefix))
		if !ok {
			self.alarm("epoch_key_invalid", errors.New("an epoch key out of form"))
			request.Unavailable()
			return
		}
		if 0 < len(reply.GetEpochs()) && self.settings.EpochsReplyMaxByteCount < byteCount+info.ByteCount {
			complete = false
			break
		}
		object, objectBytes, err := self.readEpoch(request.Ctx, request.Cluster, groupId, epoch)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			// retention deleted it since the LIST: the next one serves
			continue
		}
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		reply.Epochs = append(reply.Epochs, &protocol.GkmEpochEntry{Epoch: epoch, Size: uint64(len(objectBytes)), Object: object})
		byteCount += int64(len(objectBytes))
	}
	if complete && 0 < len(reply.GetEpochs()) {
		self.rememberNewestEpoch(groupId, reply.GetEpochs()[len(reply.GetEpochs())-1].GetEpoch())
	}
	request.Reply(reply)
}

// What a commit's request carries, once its clear header is checked.
type gkmCommitUpload struct {
	epoch    uint64
	request  *protocol.GkmEpochRequest
	header   *protocol.GkmCommitHeader
	external bool
}

// POST /gkm/groups/<id>/epochs/<n>: a GkmEpochRequest, a commit that makes epoch n.
func (self *GkmEngine) serveEpochCommit(request *GkmRequest) {
	upload, ok := self.readCommitUpload(request)
	if !ok {
		return
	}
	groupId := *request.GroupId
	now := request.Now()
	object := &protocol.GkmEpochObject{
		Commit:              upload.request.GetCommit(),
		Header:              upload.header,
		Uploader:            request.SidecarId.Bytes(),
		TimeMs:              now.UnixMilli(),
		GenWrap:             upload.request.GetGenWrap(),
		SealedGroupInfo:     upload.request.GetSealedGroupInfo(),
		GroupInfoGeneration: upload.request.GetGroupInfoGeneration(),
	}
	rateKey := "commit:" + sidecar.EvsKeyId(request.SidecarId) + ":" + sidecar.EvsKeyId(groupId)
	if !self.rates.Allow(self.settings.CommitRate, rateKey, now) {
		request.TooManyRequests(self.settings.CommitRate.Interval / gkmRateRetryDivisor(self.settings.CommitRate))
		return
	}
	if !self.checkPin(request, upload.header.GetAuth()) {
		return
	}
	previous, _, err := self.readEpoch(request.Ctx, request.Cluster, groupId, upload.epoch-1)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		// nothing to commit onto, or a winner retention has since passed: what stands at epoch n answers
		self.answerStandingEpoch(request, groupId, upload.epoch, object)
		return
	}
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if !self.checkCommitHeader(request, groupId, upload, previous.GetHeader()) {
		return
	}
	if !request.CheckRepoWritable() {
		return
	}
	objectBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(object)
	if err != nil {
		request.Unavailable()
		return
	}
	barrierKey := gkmBarrierNumberKey(groupId, upload.epoch)
	testHookBarrier(BarrierEpochPutBefore, barrierKey)
	winner, err := createGkmObject(request.Ctx, request.Cluster, GkmEpochKey(groupId, upload.epoch), objectBytes, self.settings.ObjectMaxByteCount)
	testHookBarrier(BarrierEpochPutAfter, barrierKey)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if winner != nil {
		held, err := parseGkmEpochObject(winner)
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		if !sameGkmEpochUpload(held, object) {
			request.Conflict(winner)
			return
		}
		// this commit's own earlier try won: the original answer stands (FI-2)
	}
	self.rememberNewestEpoch(groupId, upload.epoch)
	self.hintGroupCommit(request, groupId, upload.epoch, upload.header.GetGeneration())
	if 0 < len(object.GetSealedGroupInfo()) {
		self.healGroupInfoPointer(request.Ctx, request.Cluster, groupId, upload.epoch)
	}
	request.Reply(nil)
}

// Answers a commit whose epoch n-1 is gone: its own commit standing at n is the original 200 (FI-2), another's a 409
// with it, and nothing there a 404, since there is no epoch to commit onto.
func (self *GkmEngine) answerStandingEpoch(request *GkmRequest, groupId sidecar.Id, epoch uint64, object *protocol.GkmEpochObject) {
	held, heldBytes, err := self.readEpoch(request.Ctx, request.Cluster, groupId, epoch)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		request.NotFound()
	case err != nil:
		self.answerStoreError(request, err)
	case sameGkmEpochUpload(held, object):
		request.Reply(nil)
	default:
		request.Conflict(heldBytes)
	}
}

// The commit's clear header, held to the epoch it is sent for: a commit of this group sent in epoch n-1, its
// authenticated_data a GkmCommitHeader with an auth pin, an external commit's credential the uploader's own, and a
// GenWrap and sealed GroupInfo of the forms the header's generation takes. false once it has answered.
func (self *GkmEngine) readCommitUpload(request *GkmRequest) (*gkmCommitUpload, bool) {
	epoch, err := parseGkmNumber(request.Http.PathValue(gkmPathValueEpoch))
	if err != nil || epoch == 0 {
		request.BadRequest()
		return nil, false
	}
	commitRequest := &protocol.GkmEpochRequest{}
	if !request.ReadMessage(commitRequest, self.settings.RequestBodyMaxByteCount) {
		return nil, false
	}
	mlsHeader, err := sidecar.ParseMlsHeader(commitRequest.GetCommit())
	if err != nil {
		request.BadRequest()
		return nil, false
	}
	if !bytes.Equal(mlsHeader.GroupId, request.GroupId.Bytes()) || mlsHeader.Epoch != epoch-1 ||
		mlsHeader.ContentType != gkmMlsContentTypeCommit {
		request.BadRequest()
		return nil, false
	}
	header := &protocol.GkmCommitHeader{}
	if err := proto.Unmarshal(mlsHeader.AuthenticatedData, header); err != nil || header.GetAuth() == nil {
		request.BadRequest()
		return nil, false
	}
	upload := &gkmCommitUpload{epoch: epoch, request: commitRequest, header: header, external: mlsHeader.External != nil}
	if upload.external {
		// an external commit names its uploader (§10.6's leaf row), under the identity key the log admits for it
		credential, err := sidecar.CheckUrMlsCredential(mlsHeader.External.Credential)
		if err != nil || !bytes.Equal(credential.GetSidecarId(), request.SidecarId.Bytes()) ||
			!bytes.Equal(credential.GetIdentityPublicKey(), request.Sidecar.IdentityPublicKey) {
			request.Forbidden()
			return nil, false
		}
	}
	genWrap := commitRequest.GetGenWrap()
	if header.GetGeneration() == 0 {
		// §10.8's recovery self-join alone: an external commit by a recovery-admitted device, with no GenWrap
		if !upload.external || !request.Sidecar.RecoveryAdmitted || len(genWrap) != 0 {
			request.Forbidden()
			return nil, false
		}
	} else if len(genWrap) != gkmSealedKeyByteCount {
		request.BadRequest()
		return nil, false
	}
	sealedGroupInfo := commitRequest.GetSealedGroupInfo()
	groupInfoGeneration := commitRequest.GetGroupInfoGeneration()
	switch {
	case len(sealedGroupInfo) == 0:
		if groupInfoGeneration != 0 {
			request.BadRequest()
			return nil, false
		}
	case self.settings.EpochGroupInfoMaxByteCount < int64(len(sealedGroupInfo)) || groupInfoGeneration == 0:
		request.BadRequest()
		return nil, false
	case header.GetGeneration() != 0 && groupInfoGeneration != header.GetGeneration():
		// it seals under the epoch's own generation, which only a self-join's does not name (QD-165)
		request.BadRequest()
		return nil, false
	}
	return upload, true
}

// §10.6's epoch PUT check against epoch n-1's header and gen/. false once it has answered 403, or 503 for a store
// that did not answer.
func (self *GkmEngine) checkCommitHeader(request *GkmRequest, groupId sidecar.Id, upload *gkmCommitUpload, previous *protocol.GkmCommitHeader) bool {
	pin := upload.header.GetAuth()
	previousPin := previous.GetAuth()
	if previousPin == nil {
		// a re-form's epoch 0 as landed carries no pin: question keys-wire-reform-epoch-zero
		request.Forbidden()
		return false
	}
	if pin.GetVersion() < previousPin.GetVersion() ||
		pin.GetVersion() == previousPin.GetVersion() && !bytes.Equal(pin.GetChain(), previousPin.GetChain()) {
		request.Forbidden()
		return false
	}
	generation := upload.header.GetGeneration()
	exists := func(generation uint64) (bool, bool) {
		found, err := self.generationExists(request.Ctx, request.Cluster, groupId, generation)
		if err != nil {
			self.answerStoreError(request, err)
			return false, false
		}
		return found, true
	}
	if generation == 0 {
		// a self-join's GroupInfo seals under a generation the joiner holds, which must exist
		if groupInfoGeneration := upload.request.GetGroupInfoGeneration(); groupInfoGeneration != 0 {
			found, ok := exists(groupInfoGeneration)
			if !ok {
				return false
			}
			if !found {
				request.Forbidden()
				return false
			}
		}
		return true
	}
	if generation < previous.GetGeneration() {
		request.Forbidden()
		return false
	}
	// gen/'s newest as gkm reads it before the PUT
	next, ok := exists(generation + 1)
	if !ok {
		return false
	}
	if next {
		request.Forbidden()
		return false
	}
	if generation != previous.GetGeneration() {
		found, ok := exists(generation)
		if !ok {
			return false
		}
		if !found {
			request.Forbidden()
			return false
		}
	}
	return true
}

// Queues a commit hint on gkm:<group_id> to the repo's readers at epoch and generation. A state that cannot answer
// now loses the hint, which the readers' next fetch or hourly resync covers.
func (self *GkmEngine) hintGroupCommit(request *GkmRequest, groupId sidecar.Id, epoch uint64, generation uint64) {
	readerIds, answer := self.deps.AuthState.RepoReaders(request.Principal, request.RepoId, request.Now())
	if answer != GkmAuthAllowed {
		return
	}
	self.hintCommit(readerIds, groupId, epoch, generation)
}

// A rate's retry hint: the interval over its count, at least 1.
func gkmRateRetryDivisor(rate GkmRate) time.Duration {
	return time.Duration(max(1, rate.Count))
}

// The newest epoch each group was seen at in this process: a floor the next read lists past. Safe for concurrent
// use.
type gkmNewestEpochs struct {
	maxCount int

	stateLock     sync.Mutex
	groupIdEpochs map[sidecar.Id]uint64
}

// An empty cache of at most maxCount groups.
func newGkmNewestEpochs(maxCount int) *gkmNewestEpochs {
	return &gkmNewestEpochs{maxCount: maxCount, groupIdEpochs: map[sidecar.Id]uint64{}}
}

// Raises a group's floor to epoch, evicting another group first when full.
func (self *gkmNewestEpochs) raise(groupId sidecar.Id, epoch uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.maxCount <= 0 {
		return
	}
	held, ok := self.groupIdEpochs[groupId]
	if ok && epoch <= held {
		return
	}
	if !ok && self.maxCount <= len(self.groupIdEpochs) {
		for evictedGroupId := range self.groupIdEpochs {
			delete(self.groupIdEpochs, evictedGroupId)
			break
		}
	}
	self.groupIdEpochs[groupId] = epoch
}

// A group's floor, if seen.
func (self *gkmNewestEpochs) get(groupId sidecar.Id) (uint64, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	epoch, ok := self.groupIdEpochs[groupId]
	return epoch, ok
}

// Forgets a group: a shred's.
func (self *gkmNewestEpochs) forget(groupId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.groupIdEpochs, groupId)
}

// Notes that epoch exists for groupId.
func (self *GkmEngine) rememberNewestEpoch(groupId sidecar.Id, epoch uint64) {
	self.newestEpochs.raise(groupId, epoch)
}

// The newest epoch of a group as one LIST past this process's floor finds it, since epochs are created in order and
// retention never deletes the newest (§10.6). false for a group with no epoch object.
func (self *GkmEngine) newestEpoch(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id) (uint64, bool, error) {
	prefix := GkmEpochPrefix(groupId)
	newest, found := self.newestEpochs.get(groupId)
	startAfter := ""
	if found {
		startAfter = GkmEpochKey(groupId, newest)
	}
	for {
		infos, more, err := cluster.List(ctx, prefix, startAfter, self.settings.ListPageCount)
		if err != nil {
			return 0, false, err
		}
		for _, info := range infos {
			epoch, ok := parseGkmKeyNumber(strings.TrimPrefix(info.Key, prefix))
			if !ok {
				return 0, false, errors.Join(errGkmStoreFault, errors.New("an epoch key out of form"))
			}
			if !found || newest < epoch {
				newest = epoch
				found = true
			}
		}
		if !more || len(infos) == 0 {
			break
		}
		startAfter = infos[len(infos)-1].Key
	}
	if found {
		self.newestEpochs.raise(groupId, newest)
	}
	return newest, found, nil
}
