// gen/<g>, where alone a generation is created (D-KEYS-15): every gen/ read and write gkm makes goes through this
// file's accessor, so §10.16's gen packs, a Later item, add their fallback in one place (KEYS.md's reading 8).
//
// gen/ is create-only for the repo's life (gkm-7), so what a process reads of one generation never goes stale: its
// commitment, auth pin and time are cached, bounded, and an evicted entry costs one GET.

package gkmservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What gkm's checks read of one stored generation. A ladder's re-formed generations name their old group (QD-074),
// so these are read from the body as stored and never held to the path's group.
type gkmGenerationFacts struct {
	generation uint64
	repoId     []byte
	commitment []byte
	auth       *bridge.AuthPin
	timeMs     int64
	signerId   []byte
	// Present for a kind that takes deposits (D-KEYS-17).
	dropNotAfterMs int64
	hasDropKey     bool
}

// A stored gen/<g>'s facts: errGkmStoreFault for bytes that are no Signed GenRotate.
func parseGkmGenerationFacts(objectBytes []byte) (*gkmGenerationFacts, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(objectBytes, signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_GEN_ROTATE) {
		return nil, errors.Join(errGkmStoreFault, errors.New("a gen object that is no Signed GenRotate"))
	}
	rotate := &protocol.GenRotate{}
	if err := proto.Unmarshal(signed.GetBody(), rotate); err != nil || len(rotate.GetCommitment()) != 32 {
		return nil, errors.Join(errGkmStoreFault, errors.New("a gen object's GenRotate"))
	}
	return &gkmGenerationFacts{
		generation:     rotate.GetGeneration(),
		repoId:         rotate.GetRepoId(),
		commitment:     rotate.GetCommitment(),
		auth:           rotate.GetAuth(),
		timeMs:         rotate.GetTimeMs(),
		signerId:       signed.GetSignerId(),
		dropNotAfterMs: rotate.GetDropNotAfterMs(),
		hasDropKey:     0 < len(rotate.GetDropPublicKey()),
	}, nil
}

// The key of one cached generation.
type gkmGenerationCacheKey struct {
	groupId    sidecar.Id
	generation uint64
}

// Facts of generations this process has read. Safe for concurrent use.
type gkmGenerationCache struct {
	maxCount int

	stateLock sync.Mutex
	keyFacts  map[gkmGenerationCacheKey]*gkmGenerationFacts
}

// An empty cache of at most maxCount generations.
func newGkmGenerationCache(maxCount int) *gkmGenerationCache {
	return &gkmGenerationCache{maxCount: maxCount, keyFacts: map[gkmGenerationCacheKey]*gkmGenerationFacts{}}
}

func (self *gkmGenerationCache) get(groupId sidecar.Id, generation uint64) (*gkmGenerationFacts, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	facts, ok := self.keyFacts[gkmGenerationCacheKey{groupId: groupId, generation: generation}]
	return facts, ok
}

func (self *gkmGenerationCache) put(groupId sidecar.Id, generation uint64, facts *gkmGenerationFacts) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.maxCount <= 0 {
		return
	}
	key := gkmGenerationCacheKey{groupId: groupId, generation: generation}
	if _, ok := self.keyFacts[key]; !ok && self.maxCount <= len(self.keyFacts) {
		for evicted := range self.keyFacts {
			delete(self.keyFacts, evicted)
			break
		}
	}
	self.keyFacts[key] = facts
}

// Forgets a group's generations: a shred's.
func (self *gkmGenerationCache) forgetGroup(groupId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for key := range self.keyFacts {
		if key.groupId == groupId {
			delete(self.keyFacts, key)
		}
	}
}

// gen/<g>'s bytes as stored: sidecar.ErrBlobNotFound for none. The one read of gen/ the engine and the reconciler
// make, where a gen pack's fallback goes (§10.16).
func readGkmGeneration(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generation uint64) ([]byte, error) {
	objectBytes, _, err := readGkmObject(ctx, cluster, GkmGenerationKey(groupId, generation), gkmStatementMaxByteCount)
	return objectBytes, err
}

// The generations a group holds after since, ascending: the one listing of gen/, where a gen pack's fallback lists
// its packs too (§10.16).
func listGkmGenerations(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, since uint64, pageCount int) ([]uint64, error) {
	prefix := GkmGenerationPrefix(groupId)
	startAfter := ""
	if 0 < since {
		startAfter = GkmGenerationKey(groupId, since)
	}
	infos, err := listGkmKeysAfter(ctx, cluster, prefix, startAfter, pageCount, gkmGenerationListMaxCount)
	if err != nil {
		return nil, err
	}
	generations := make([]uint64, 0, len(infos))
	for _, info := range infos {
		generation, ok := parseGkmKeyNumber(strings.TrimPrefix(info.Key, prefix))
		if !ok {
			return nil, errors.Join(errGkmStoreFault, errors.New("a gen key out of form"))
		}
		generations = append(generations, generation)
	}
	return generations, nil
}

// gen/<g>'s bytes as stored, through the accessor.
func (self *GkmEngine) readGeneration(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generation uint64) ([]byte, error) {
	return readGkmGeneration(ctx, cluster, groupId, generation)
}

// gen/<g>'s facts, from this process's cache or one GET: sidecar.ErrBlobNotFound for none.
func (self *GkmEngine) generationFacts(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generation uint64) (*gkmGenerationFacts, error) {
	if facts, ok := self.generations.get(groupId, generation); ok {
		return facts, nil
	}
	objectBytes, err := self.readGeneration(ctx, cluster, groupId, generation)
	if err != nil {
		return nil, err
	}
	facts, err := parseGkmGenerationFacts(objectBytes)
	if err != nil {
		return nil, err
	}
	self.generations.put(groupId, generation, facts)
	return facts, nil
}

// Whether gen/<g> exists: the cache, else one HEAD.
func (self *GkmEngine) generationExists(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generation uint64) (bool, error) {
	if _, ok := self.generations.get(groupId, generation); ok {
		return true, nil
	}
	_, err := cluster.Head(ctx, GkmGenerationKey(groupId, generation))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sidecar.ErrBlobNotFound):
		return false, nil
	}
	return false, err
}

// Creates gen/<g> If-None-Match, as createGkmObject does: winner nil when objectBytes stand there.
func (self *GkmEngine) createGeneration(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generation uint64, objectBytes []byte) ([]byte, error) {
	winner, err := createGkmObject(ctx, cluster, GkmGenerationKey(groupId, generation), objectBytes, gkmStatementMaxByteCount)
	if err != nil {
		return nil, err
	}
	held := objectBytes
	if winner != nil {
		held = winner
	}
	if facts, err := parseGkmGenerationFacts(held); err == nil {
		self.generations.put(groupId, generation, facts)
	}
	return winner, nil
}

// The most generation keys one listing of a group's gen/ reads before it alarms: years of monthly and REMOVE
// rotations stay far below it.
const gkmGenerationListMaxCount = 64 * 1024

// The generations a group holds after since, ascending, through the accessor.
func (self *GkmEngine) generationNumbers(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, since uint64) ([]uint64, error) {
	return listGkmGenerations(ctx, cluster, groupId, since, self.settings.ListPageCount)
}

// The Signed GenRotates of generations, in order, each read through the accessor. One deleted since its LIST, which
// only a shred does, ends the list there.
func (self *GkmEngine) readGenerations(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generations []uint64) ([]*bridge.Signed, error) {
	signeds := make([]*bridge.Signed, 0, len(generations))
	for _, generation := range generations {
		objectBytes, err := self.readGeneration(ctx, cluster, groupId, generation)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			break
		}
		if err != nil {
			return nil, err
		}
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(objectBytes, signed); err != nil {
			return nil, errors.Join(errGkmStoreFault, err)
		}
		signeds = append(signeds, signed)
	}
	return signeds, nil
}

// The since of a gen or drop-key read: decimal, 0 when absent. false once it has answered 400.
func (self *GkmEngine) readSince(request *GkmRequest) (uint64, bool) {
	sinceText := request.Http.URL.Query().Get("since")
	if sinceText == "" {
		return 0, true
	}
	since, err := parseGkmNumber(sinceText)
	if err != nil {
		request.BadRequest()
		return 0, false
	}
	return since, true
}

// GET /gkm/groups/<id>/gen?since=<g>: a GkmGenerationsReply, the GenRotates after g in order, up to
// GenerationsReplyMaxCount; the client asks again after its last (QD-526 row 7).
func (self *GkmEngine) serveGenerationsRead(request *GkmRequest) {
	since, ok := self.readSince(request)
	if !ok {
		return
	}
	groupId := *request.GroupId
	generations, err := self.generationNumbers(request.Ctx, request.Cluster, groupId, since)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if self.settings.GenerationsReplyMaxCount < len(generations) {
		generations = generations[:self.settings.GenerationsReplyMaxCount]
	}
	signeds, err := self.readGenerations(request.Ctx, request.Cluster, groupId, generations)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	request.Reply(&protocol.GkmGenerationsReply{Generations: signeds})
}

// POST /gkm/groups/<id>/gen/<g>: a Signed GenRotate, the claim of generation g, where alone it is created (D-KEYS-15),
// under §10.6's claim checks:
//
//	scope   rw (the guard), and the group the repo's newest form names
//	chain   generation = g; gen/<g-1> exists and parent_commitment is its commitment; in a re-formed group no g at or
//	        below the form's generation, which the ladder carries (QD-074(5))
//	auth    auth.version >= gen/<g-1>'s, at or past the previous base and matching proj/ there (CheckPin)
//	time    time_ms within 10 minutes of gkm's clock
//	signer  admitted, not read_only, and not revoked, parked or suspended in gkm's newest state
//	leaf    a leaf wrap's epoch exists
//	rate    60 an hour per uploader per group
//
// The first claim wins: a 412 carries the winner, which the rotator judges (§10.5's Rotate, step 4), and the same
// bytes again answer 201, so a lost answer's retry succeeds once. A success hints commit on gkm:<group_id> at the
// newest epoch and g, so a rotation with no commit is seen (D-KEYS-19).
func (self *GkmEngine) serveGenerationClaim(request *GkmRequest) {
	groupId := *request.GroupId
	generation, err := parseGkmNumber(request.Http.PathValue(gkmPathValueGeneration))
	if err != nil || generation < 2 {
		// gen/1 comes with epoch 0, and a re-form's generations by the ladder
		request.BadRequest()
		return
	}
	body, ok := request.ReadBody(gkmStatementMaxByteCount)
	if !ok {
		return
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(body, signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_GEN_ROTATE) {
		request.BadRequest()
		return
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
	if err != nil {
		request.BadRequest()
		return
	}
	lookup := self.newSignerLookup(request.Principal)
	parsed, err := sidecar.ParseGenRotate(raw, groupId, generation, lookup.identityKey)
	switch {
	case err == nil:
	case lookup.answer != GkmAuthAllowed:
		answerGkmAuth(request, lookup.answer)
		return
	case errors.Is(err, sidecar.ErrGkmAuthentication):
		request.Forbidden()
		return
	default:
		request.BadRequest()
		return
	}
	if answer := lookup.signerStanding(); answer != GkmAuthAllowed {
		answerGkmAuth(request, answer)
		return
	}
	rotate := parsed.Rotate
	if !bytes.Equal(rotate.GetRepoId(), request.RepoId.Bytes()) {
		request.BadRequest()
		return
	}
	forms, err := self.forms.forms(request.Ctx, request.Cluster, request.RepoId)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if 0 < len(forms) {
		form := forms[len(forms)-1]
		if 0 < len(form.Body.GetPreviousGroupId()) && generation <= form.Body.GetGeneration() {
			request.Forbidden()
			return
		}
	}
	now := request.Now()
	rateKey := "claim:" + sidecar.EvsKeyId(request.SidecarId) + ":" + sidecar.EvsKeyId(groupId)
	if !self.rates.Allow(self.settings.ClaimRate, rateKey, now) {
		request.TooManyRequests(self.settings.ClaimRate.Interval / gkmRateRetryDivisor(self.settings.ClaimRate))
		return
	}
	if !self.checkStatementTime(request, rotate.GetTimeMs()) {
		return
	}
	parent, err := self.generationFacts(request.Ctx, request.Cluster, groupId, generation-1)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		request.Forbidden()
		return
	}
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if !bytes.Equal(rotate.GetParentCommitment(), parent.commitment) ||
		rotate.GetAuth().GetVersion() < parent.auth.GetVersion() {
		request.Forbidden()
		return
	}
	if !self.checkPin(request, rotate.GetAuth()) {
		return
	}
	if leafWrap := rotate.GetLeafWrap(); leafWrap != nil {
		_, err := request.Cluster.Head(request.Ctx, GkmEpochKey(groupId, leafWrap.GetEpoch()))
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			request.Forbidden()
			return
		}
		if err != nil {
			request.Unavailable()
			return
		}
	}
	// a REMOVE rotation's claim, which the write budget never refuses, only while gkm's newest state shows a drop since
	// gen/<g-1>'s pin and time, whatever cause the claim states (§10.6's checks row, budget.go)
	writeCtx, ok := request.SpendWrites(request.Cluster, self.rotationWriteKind(request, parent), self.settings.Prices.create(len(raw)))
	if !ok || !request.CheckRepoWritable() {
		return
	}
	barrierKey := gkmBarrierNumberKey(groupId, generation)
	testHookBarrier(BarrierGenClaimBefore, barrierKey)
	winner, err := self.createGeneration(writeCtx, request.Cluster, groupId, generation, raw)
	testHookBarrier(BarrierGenClaimAfter, barrierKey)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	if winner != nil {
		request.PreconditionFailed(winner)
		return
	}
	if epoch, found, err := self.newestEpoch(request.Ctx, request.Cluster, groupId); err == nil && found {
		self.hintGroupCommit(request, groupId, epoch, generation)
	}
	request.Created()
}

// SHA-256 of b.
func sha256Of(b []byte) []byte {
	digest := sha256.Sum256(b)
	return digest[:]
}
