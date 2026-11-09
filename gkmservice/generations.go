// gen/<g>, where alone a generation is created (D-KEYS-15): every gen/ read and write gkm makes goes through this
// file's accessor, so §10.16's gen packs, a Later item, add their fallback in one place (KEYS.md's reading 8).
//
// gen/ is create-only for the repo's life (gkm-7), so what a process reads of one generation never goes stale: its
// commitment, auth pin and time are cached, bounded, and an evicted entry costs one GET.

package gkmservice

import (
	"context"
	"errors"
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

// gen/<g>'s bytes as stored: sidecar.ErrBlobNotFound for none.
func (self *GkmEngine) readGeneration(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generation uint64) ([]byte, error) {
	objectBytes, _, err := readGkmObject(ctx, cluster, GkmGenerationKey(groupId, generation), gkmStatementMaxByteCount)
	return objectBytes, err
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
