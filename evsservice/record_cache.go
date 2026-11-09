// Batch records by place (§11.8's read and cache rows): evs reads a record by range at the place its window entry
// or log page names, and each process keeps the records it wrote or read, since they never change. A record is
// committed only at the place its version's entry names, so a cache keyed by place never serves another copy.
//
// A batch that 404s has been evacuated: its records are in a pack or parcel that pidx/ names (§11.13), which
// EVSB-M2-10's RecordLocator finds. Until it lands ReadRecord answers ErrEvsRecordEvacuated, and its caller answers
// 503 rather than guess.
//
// Safe for concurrent use.

package evsservice

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The batch a place names was evacuated: the record is in pidx/'s container (EVSB-M2-10).
var ErrEvsRecordEvacuated = errors.New("evs record evacuated")

// A place's batch key.
func PlaceBatchKey(place *protocol.EvsPlace) string {
	return BatchKey(place.GetMinute(), place.GetInstance(), place.GetSeq())
}

// One cached record's key: its cluster and place.
type recordCacheKey struct {
	clusterId string
	minute    uint32
	instance  uint32
	seq       uint32
	offset    uint32
	length    uint32
}

// The key of place on clusterId.
func recordCacheKeyOf(clusterId string, place *protocol.EvsPlace) recordCacheKey {
	return recordCacheKey{
		clusterId: clusterId,
		minute:    place.GetMinute(),
		instance:  place.GetInstance(),
		seq:       place.GetSeq(),
		offset:    place.GetOffset(),
		length:    place.GetLength(),
	}
}

// One record in the cache's recency list.
type recordCacheItem struct {
	key         recordCacheKey
	recordBytes []byte
}

// Records by place, least recently used out past RecordCacheByteCount.
type RecordCache struct {
	settings *EvsSettings

	stateLock  sync.Mutex
	keyItems   map[recordCacheKey]*list.Element
	recency    *list.List
	byteCount  int64
	hitCount   int
	readCount  int
	evictCount int
}

// An empty cache.
func NewRecordCache(settings *EvsSettings) *RecordCache {
	return &RecordCache{settings: settings, keyItems: map[recordCacheKey]*list.Element{}, recency: list.New()}
}

// The record's bytes at place, if this process holds them.
func (self *RecordCache) Get(clusterId string, place *protocol.EvsPlace) ([]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	element, ok := self.keyItems[recordCacheKeyOf(clusterId, place)]
	if !ok {
		return nil, false
	}
	self.recency.MoveToFront(element)
	self.hitCount += 1
	return element.Value.(*recordCacheItem).recordBytes, true
}

// Keeps a record's bytes at place. Callers hand over bytes no one changes afterwards.
func (self *RecordCache) Put(clusterId string, place *protocol.EvsPlace, recordBytes []byte) {
	if self.settings.RecordCacheByteCount < int64(len(recordBytes)) {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	key := recordCacheKeyOf(clusterId, place)
	if element, ok := self.keyItems[key]; ok {
		self.recency.MoveToFront(element)
		return
	}
	self.keyItems[key] = self.recency.PushFront(&recordCacheItem{key: key, recordBytes: recordBytes})
	self.byteCount += int64(len(recordBytes))
	for self.settings.RecordCacheByteCount < self.byteCount {
		oldest := self.recency.Back()
		item := oldest.Value.(*recordCacheItem)
		self.recency.Remove(oldest)
		delete(self.keyItems, item.key)
		self.byteCount -= int64(len(item.recordBytes))
		self.evictCount += 1
	}
}

// Hits, store reads and evictions, for tests and §19.8's gauges.
func (self *RecordCache) Counts() (hitCount int, readCount int, evictCount int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.hitCount, self.readCount, self.evictCount
}

// Counts one store read.
func (self *RecordCache) countRead() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.readCount += 1
}

// The record at place on cluster (§11.8's read row): this process's cache, else one range GET of its batch, parsed
// whole. ErrEvsRecordEvacuated when the batch is gone; sidecar.ErrEvsPushInvalid for bytes there that are no
// record, which only a wrong place can produce and which breaks the chain a reader checks.
func ReadRecord(ctx context.Context, cache *RecordCache, cluster sidecar.BlobCluster, place *protocol.EvsPlace) (*sidecar.EvsBatchRecord, error) {
	clusterId := cluster.ClusterId()
	if recordBytes, ok := cache.Get(clusterId, place); ok {
		return sidecar.ParseEvsBatchRecord(recordBytes)
	}
	if place.GetLength() < sidecar.EvsBatchRecordHeaderByteCount || sidecar.EvsBatchMaxRecordByteCount < place.GetLength() {
		return nil, fmt.Errorf("%w: a place of %d bytes", sidecar.ErrEvsPushInvalid, place.GetLength())
	}
	cache.countRead()
	object, err := cluster.GetRange(ctx, PlaceBatchKey(place), int64(place.GetOffset()), int64(place.GetLength()))
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		return nil, ErrEvsRecordEvacuated
	case errors.Is(err, sidecar.ErrBlobRange):
		return nil, fmt.Errorf("%w: a place past its batch's end", sidecar.ErrEvsPushInvalid)
	case err != nil:
		return nil, err
	}
	defer object.Body.Close()
	recordBytes, err := io.ReadAll(io.LimitReader(object.Body, int64(place.GetLength())+1))
	if err != nil {
		return nil, err
	}
	record, err := sidecar.ParseEvsBatchRecord(recordBytes)
	if err != nil {
		return nil, err
	}
	cache.Put(clusterId, place, recordBytes)
	return record, nil
}
