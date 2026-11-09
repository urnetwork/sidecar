// §10.6's GroupInfo row and group-info object (KF5, §10.8): GET and POST /gkm/groups/<id>/group-info, over
// gkm/<group_id>/group-info on the repo's cluster, and the pointer's heal at a commit.
//
// gkm cannot count leaves, so the mode follows what the client uploaded:
//
//   - at 16 leaves or fewer each epoch object carries the sealed GroupInfo, and group-info is a pointer {epoch},
//     rewritten by a leaf at each Add and by gkm when an epoch carrying a GroupInfo runs GroupInfoPointerLagCount (16)
//     or more past it, so a crash between the two PUTs heals at the next commit; a resyncing device reads the pointer
//     and probes epoch/<n+1>.. until a 404;
//   - above 16 leaves group-info holds the sealed GroupInfo itself, which a leaf writes on demand, at most once per
//     epoch, since each write must name a newer epoch than the one it replaces.
//
// A write rises: If-Match on the etag read, or If-None-Match when none stands, and only to a newer epoch, which must
// exist and, for a pointer, carry a sealed GroupInfo; a sealed one names a generation gen/ holds. A read that wants an
// epoch newer than the one gkm holds (?want=) hints wrap-pending to the repo's writers, at most once per
// GroupInfoWantHintInterval per group and process (KF5).

package gkmservice

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A stored group-info object, parsed: errGkmStoreFault for bytes that do not parse.
func parseGkmGroupInfoObject(objectBytes []byte) (*protocol.GkmGroupInfoObject, error) {
	object := &protocol.GkmGroupInfoObject{}
	if err := proto.Unmarshal(objectBytes, object); err != nil {
		return nil, errors.Join(errGkmStoreFault, err)
	}
	return object, nil
}

// One group-info read: the object and its etag, or none, good until expiresAt.
type gkmGroupInfoEntry struct {
	object    *protocol.GkmGroupInfoObject
	etag      string
	expiresAt time.Time
}

// group-info as an epoch PUT's pointer check reads it, each answer good for GroupInfoCacheTtl (§10.6's store
// operations: a 5 s cache). Safe for concurrent use.
type gkmGroupInfoCache struct {
	clock    sidecar.Clock
	settings *GkmServiceSettings

	stateLock    sync.Mutex
	groupEntries map[sidecar.Id]*gkmGroupInfoEntry
}

// An empty cache on clock.
func newGkmGroupInfoCache(clock sidecar.Clock, settings *GkmServiceSettings) *gkmGroupInfoCache {
	return &gkmGroupInfoCache{clock: clock, settings: settings, groupEntries: map[sidecar.Id]*gkmGroupInfoEntry{}}
}

// A group's group-info and etag from this cache while fresh, else one GET; nil and "" for none.
func (self *gkmGroupInfoCache) read(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id) (*protocol.GkmGroupInfoObject, string, error) {
	var cached *gkmGroupInfoEntry
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry, ok := self.groupEntries[groupId]
		if ok && self.clock.Now().Before(entry.expiresAt) {
			cached = entry
		} else if ok {
			delete(self.groupEntries, groupId)
		}
	}()
	if cached != nil {
		return cached.object, cached.etag, nil
	}
	readAt := self.clock.Now()
	objectBytes, info, err := readGkmObject(ctx, cluster, GkmGroupInfoKey(groupId), self.settings.ObjectMaxByteCount)
	var object *protocol.GkmGroupInfoObject
	etag := ""
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
	case err != nil:
		return nil, "", err
	default:
		object, err = parseGkmGroupInfoObject(objectBytes)
		if err != nil {
			return nil, "", err
		}
		etag = info.Etag
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.settings.GroupInfoCacheTtl <= 0 || self.settings.GroupInfoCacheCount <= 0 {
			return
		}
		if self.settings.GroupInfoCacheCount <= len(self.groupEntries) {
			for evictedGroupId := range self.groupEntries {
				delete(self.groupEntries, evictedGroupId)
				break
			}
		}
		self.groupEntries[groupId] = &gkmGroupInfoEntry{object: object, etag: etag, expiresAt: readAt.Add(self.settings.GroupInfoCacheTtl)}
	}()
	return object, etag, nil
}

// Drops a group's entry: what a write calls, so the next read sees it.
func (self *gkmGroupInfoCache) forget(groupId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.groupEntries, groupId)
}

// Rewrites the pointer to epoch when the commit just stored there carries a sealed GroupInfo and runs
// GroupInfoPointerLagCount or more past the epoch group-info names. A failure is passed over: the next such commit
// heals it, which is the row's point.
func (self *GkmEngine) healGroupInfoPointer(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, epoch uint64) {
	held, etag, err := self.groupInfos.read(ctx, cluster, groupId)
	if err != nil {
		return
	}
	floor := uint64(0)
	if held != nil {
		floor = held.GetEpoch()
	}
	if epoch < floor+self.settings.GroupInfoPointerLagCount {
		return
	}
	pointerBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmGroupInfoObject{Epoch: epoch})
	if err != nil {
		return
	}
	barrierKey := gkmBarrierGroupKey(groupId)
	testHookBarrier(BarrierPointerPutBefore, barrierKey)
	err = replaceGkmObject(ctx, cluster, GkmGroupInfoKey(groupId), etag, pointerBytes)
	testHookBarrier(BarrierPointerPutAfter, barrierKey)
	self.groupInfos.forget(groupId)
	if err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[gkm] a group-info pointer's heal failed: %v", err)
	}
}

// GET /gkm/groups/<id>/group-info?want=<epoch>: the stored GkmGroupInfoObject, byte for byte. One older than want, or
// none, hints wrap-pending to the repo's writers.
func (self *GkmEngine) serveGroupInfoRead(request *GkmRequest) {
	groupId := *request.GroupId
	var want *uint64
	if wantText := request.Http.URL.Query().Get("want"); wantText != "" {
		wantEpoch, err := parseGkmNumber(wantText)
		if err != nil {
			request.BadRequest()
			return
		}
		want = &wantEpoch
	}
	objectBytes, _, err := readGkmObject(request.Ctx, request.Cluster, GkmGroupInfoKey(groupId), self.settings.ObjectMaxByteCount)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		if want != nil {
			self.hintWantGroupInfo(request, groupId, *want)
		}
		request.NotFound()
		return
	}
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	object, err := parseGkmGroupInfoObject(objectBytes)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if want != nil && object.GetEpoch() < *want {
		self.hintWantGroupInfo(request, groupId, *want)
	}
	request.ReplyBytes(200, objectBytes)
}

// wrap-pending to the repo's writers for a GroupInfo of epoch want, at most once per GroupInfoWantHintInterval per
// group in this process.
func (self *GkmEngine) hintWantGroupInfo(request *GkmRequest, groupId sidecar.Id, want uint64) {
	rate := GkmRate{Count: 1, Interval: self.settings.GroupInfoWantHintInterval}
	if !rate.valid() || !self.rates.Allow(rate, "gi_want:"+sidecar.EvsKeyId(groupId), request.Now()) {
		return
	}
	writerIds, answer := self.deps.AuthState.RepoWriters(request.Principal, request.RepoId, request.Now())
	if answer != GkmAuthAllowed {
		return
	}
	self.hintWork(writerIds, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING, &groupId, want, nil)
}

// POST /gkm/groups/<id>/group-info: a GkmGroupInfoObject, the pointer or above 16 leaves the sealed GroupInfo, for a
// newer epoch than the one standing.
func (self *GkmEngine) serveGroupInfoWrite(request *GkmRequest) {
	groupId := *request.GroupId
	body, ok := request.ReadBody(self.settings.RequestBodyMaxByteCount)
	if !ok {
		return
	}
	object := &protocol.GkmGroupInfoObject{}
	if err := proto.Unmarshal(body, object); err != nil {
		request.BadRequest()
		return
	}
	pointer := len(object.GetSealedGroupInfo()) == 0
	if pointer != (object.GetGeneration() == 0) {
		// a pointer names no generation, and a sealed GroupInfo the one that seals it
		request.BadRequest()
		return
	}
	objectBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(object)
	if err != nil {
		request.BadRequest()
		return
	}
	epochObject, _, err := self.readEpoch(request.Ctx, request.Cluster, groupId, object.GetEpoch())
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		request.NotFound()
		return
	}
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if pointer && len(epochObject.GetSealedGroupInfo()) == 0 {
		// a pointer to an epoch that carries no GroupInfo points at nothing
		request.Forbidden()
		return
	}
	if !pointer {
		found, err := self.generationExists(request.Ctx, request.Cluster, groupId, object.GetGeneration())
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		if !found {
			request.Forbidden()
			return
		}
	}
	key := GkmGroupInfoKey(groupId)
	// what stands: this write's own bytes are its retry, an epoch at or past it the newer write that won
	judge := func() (done bool, etag string) {
		heldBytes, info, err := readGkmObject(request.Ctx, request.Cluster, key, self.settings.ObjectMaxByteCount)
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
			return false, ""
		case err != nil:
			self.answerStoreError(request, err)
			return true, ""
		case bytes.Equal(heldBytes, objectBytes):
			request.Reply(nil)
			return true, ""
		}
		held, err := parseGkmGroupInfoObject(heldBytes)
		if err != nil {
			self.answerStoreError(request, err)
			return true, ""
		}
		if object.GetEpoch() <= held.GetEpoch() {
			request.Conflict(heldBytes)
			return true, ""
		}
		return false, info.Etag
	}
	done, etag := judge()
	if done || !request.CheckRepoWritable() {
		return
	}
	barrierKey := gkmBarrierGroupKey(groupId)
	testHookBarrier(BarrierPointerPutBefore, barrierKey)
	err = replaceGkmObject(request.Ctx, request.Cluster, key, etag, objectBytes)
	testHookBarrier(BarrierPointerPutAfter, barrierKey)
	self.groupInfos.forget(groupId)
	var unknown *sidecar.BlobUnknownError
	switch {
	case err == nil:
		request.Reply(nil)
	case errors.Is(err, sidecar.ErrBlobPrecondition), errors.As(err, &unknown):
		// another write moved it, or this one's answer was lost: what stands now decides
		if done, _ := judge(); !done {
			request.Unavailable()
		}
	default:
		request.Unavailable()
	}
}
