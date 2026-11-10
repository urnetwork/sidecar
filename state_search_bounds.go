// §5.9's bounds row for the index cache (CORE-M10-01), and the retained buckets of its holds row (D-EVS-51).
//
// Bound: Search.CacheByteCount, 4 GiB on a desktop, 16 GiB on a daemon designated for search, §18.4's caps on phones
// (256 MiB and 10% of free space, which sdk's host passes in settings) and in the page Worker (128 MiB), the version
// table's pages included. Past it, all partitions go first, least recently searched, then buckets the same way, so a
// search stays complete for the latest window the longest; a designated daemon evicts the all of a repo it serves only
// once every other all has gone (D-CORE-17). Phones and browsers also drop all shards unused for 30 days, which their
// policy asks for through EvictUnused. When a partition was last searched is kept in memory only (MarkSearched), so
// after a start the order falls back to when each file was kept: nothing on the medium says that a search ran.
//
// Retained buckets (§11.14's retained row): a device holding a stale all keeps the files of a bucket a roll-up dropped,
// masked as usual, until its all copy shows the bucket rolled up (a/m's rolled_through_day at or past the bucket's start
// day), an ERASE occurs in the repo, or two bucket lengths pass after the roll-up, so search stays complete between a
// roll-up and its download. The sync engine, SEARCH-M10-19's, says when a bucket is retained and when its all moves;
// this file keeps the record and drops the files.
//
// On every leg: root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"cmp"
	"encoding/hex"
	"slices"
	"time"
)

// A bucket a roll-up dropped, kept while a stale all is cached.
type SearchCacheRetained struct {
	StartDay uint32
	// W, the bucket's length in days.
	WindowDays uint32
	// When this device applied the roll-up that dropped it: never kept past two bucket lengths after.
	RolledUpAt time.Time
}

// One retained bucket in the holdings record.
type searchCacheRetainedWire struct {
	StartDay   uint32 `json:"start_day"`
	WindowDays uint32 `json:"window_days"`
	RolledUpMs int64  `json:"rolled_up_ms"`
}

// A retained bucket as the holdings record keeps it.
func retainedWireOf(retained SearchCacheRetained) searchCacheRetainedWire {
	return searchCacheRetainedWire{StartDay: retained.StartDay, WindowDays: retained.WindowDays, RolledUpMs: retained.RolledUpAt.UnixMilli()}
}

// The retained bucket the holdings record kept.
func (self searchCacheRetainedWire) retained() SearchCacheRetained {
	return SearchCacheRetained{StartDay: self.StartDay, WindowDays: self.WindowDays, RolledUpAt: time.UnixMilli(self.RolledUpMs)}
}

// Records that a ref's partition was searched now: eviction's order, in memory only. Takes no query (§5.9's never row).
func (self *SearchCache) MarkSearched(repoId Id, refId Id, partition SearchCachePartition) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.searched[searchCacheSearchedKey{repoId: repoId, refId: refId, all: partition.All}] = self.clock.Now()
}

// The bound of a daemon designated for search (§5.4's Search settings, owner decision 175).
const SearchDesignatedCacheByteCount int64 = 16 * 1024 * 1024 * 1024

// Sets whether this daemon is designated for search (§7.9's IndexerSet), and the repos it serves (D-CORE-17): while
// designated its bound is at least 16 GiB, and it keeps the all of each served repo until every other all has gone.
func (self *SearchCache) SetDesignated(designated bool, servedRepoIds []Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.designated = designated
	clear(self.served)
	if !designated {
		return
	}
	for _, repoId := range servedRepoIds {
		self.served[repoId] = true
	}
}

// The bound eviction holds the cache to: Search.CacheByteCount, at least 16 GiB while designated, and, in memory,
// Search.MemoryByteCount.
func (self *SearchCache) bound() int64 {
	if self.memory {
		return self.settings.MemoryByteCount
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.designated {
		return max(self.settings.CacheByteCount, SearchDesignatedCacheByteCount)
	}
	return self.settings.CacheByteCount
}

// One partition of one ref, as eviction weighs it.
type searchCacheEvictable struct {
	repoId Id
	refId  Id
	all    bool
	served bool
	// when it was last searched, or else when its newest file was kept
	usedAt time.Time
	files  []SearchCacheKey
	bytes  int64
}

// Every ref the store holds a record of, from the medium, so a ref not loaded yet counts too.
func (self *SearchCache) refKeysWithLock() ([][2]Id, error) {
	entries, err := self.store.List("")
	if err != nil {
		return nil, err
	}
	refKeys := [][2]Id{}
	for _, entry := range entries {
		// <repo hex>/<ref hex>/holdings
		if len(entry.Name) != 32+1+32+1+len(searchCacheHoldingsName) || entry.Name[65:] != "/"+searchCacheHoldingsName {
			continue
		}
		repoId, repoErr := searchCacheIdOfHex(entry.Name[:32])
		refId, refErr := searchCacheIdOfHex(entry.Name[33:65])
		if repoErr != nil || refErr != nil {
			continue
		}
		refKeys = append(refKeys, [2]Id{repoId, refId})
	}
	return refKeys, nil
}

// Every partition the cache holds, in eviction's order: alls before buckets, a served repo's all after every other all,
// least recently used first.
func (self *SearchCache) evictablesWithLock() ([]*searchCacheEvictable, error) {
	refKeys, err := self.refKeysWithLock()
	if err != nil {
		return nil, err
	}
	evictables := []*searchCacheEvictable{}
	for _, refKey := range refKeys {
		ref, err := self.loadRefWithLock(refKey[0], refKey[1])
		if err != nil {
			return nil, err
		}
		self.stateLock.Lock()
		byKind := map[bool]*searchCacheEvictable{}
		for _, file := range ref.Files {
			evictable := byKind[file.Partition.All]
			if evictable == nil {
				evictable = &searchCacheEvictable{
					repoId: refKey[0],
					refId:  refKey[1],
					all:    file.Partition.All,
					served: file.Partition.All && self.served[refKey[0]],
				}
				byKind[file.Partition.All] = evictable
			}
			evictable.files = append(evictable.files, file.Key)
			evictable.bytes += file.ByteCount
			if evictable.usedAt.Before(file.KeptAt) {
				evictable.usedAt = file.KeptAt
			}
		}
		for all, evictable := range byKind {
			if searchedAt, ok := self.searched[searchCacheSearchedKey{repoId: refKey[0], refId: refKey[1], all: all}]; ok {
				evictable.usedAt = searchedAt
			}
			evictables = append(evictables, evictable)
		}
		self.stateLock.Unlock()
	}
	slices.SortStableFunc(evictables, func(a *searchCacheEvictable, b *searchCacheEvictable) int {
		rank := func(evictable *searchCacheEvictable) int {
			switch {
			case evictable.all && !evictable.served:
				return 0
			case evictable.all:
				return 1
			}
			return 2
		}
		if c := cmp.Compare(rank(a), rank(b)); c != 0 {
			return c
		}
		return a.usedAt.Compare(b.usedAt)
	})
	return evictables, nil
}

// An id from its 32 hex digits.
func searchCacheIdOfHex(text string) (Id, error) {
	var id Id
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != len(id) {
		return id, ErrSearchCacheArgs
	}
	copy(id[:], decoded)
	return id, nil
}

// Brings the cache under its bound (§5.9's bounds row): whole partitions go, all partitions first, least recently
// searched, a served repo's all last among them, then buckets. Answers the bytes freed. A cache in memory is held to
// Search.MemoryByteCount, inside MemoryBudgetByteCount, a reading of "in memory inside MemoryBudgetByteCount".
func (self *SearchCache) Evict() (int64, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	bound := self.bound()
	if self.ByteCount() <= bound {
		return 0, nil
	}
	evictables, err := self.evictablesWithLock()
	if err != nil {
		return 0, err
	}
	before := self.ByteCount()
	yield := newSidecarYield(self.clock)
	for _, evictable := range evictables {
		if self.ByteCount() <= bound {
			break
		}
		for _, key := range evictable.files {
			if err := self.removeFileWithLock(key); err != nil {
				return before - self.ByteCount(), err
			}
			yield.step()
		}
	}
	return before - self.ByteCount(), nil
}

// Drops every all partition not searched since unusedSince (§18.4's caps row: phones and browsers drop all shards unused
// for 30 days). A served repo's all is kept. Answers the bytes freed.
func (self *SearchCache) EvictUnused(unusedSince time.Time) (int64, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	evictables, err := self.evictablesWithLock()
	if err != nil {
		return 0, err
	}
	before := self.ByteCount()
	for _, evictable := range evictables {
		if !evictable.all || evictable.served || !evictable.usedAt.Before(unusedSince) {
			continue
		}
		for _, key := range evictable.files {
			if err := self.removeFileWithLock(key); err != nil {
				return before - self.ByteCount(), err
			}
		}
	}
	return before - self.ByteCount(), nil
}

// Keeps the files of a bucket a roll-up dropped while this device's all is stale: until ApplyRolledThrough shows it
// rolled up, DropRetained ends it at an ERASE, or SweepRetained finds two bucket lengths past rolledUpAt.
func (self *SearchCache) RetainBucket(repoId Id, refId Id, startDay uint32, windowDays uint32, rolledUpAt time.Time) error {
	if windowDays == 0 {
		return ErrSearchCacheArgs
	}
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	ref, err := self.loadRefWithLock(repoId, refId)
	if err != nil {
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ref.Retained = slices.DeleteFunc(ref.Retained, func(retained SearchCacheRetained) bool { return retained.StartDay == startDay })
		ref.Retained = append(ref.Retained, SearchCacheRetained{StartDay: startDay, WindowDays: windowDays, RolledUpAt: rolledUpAt})
	}()
	return self.storeRefWithLock(ref)
}

// Drops the retained buckets matching drop, with their files.
func (self *SearchCache) dropRetainedWithLock(ref *SearchCacheRef, drop func(retained SearchCacheRetained) bool) error {
	dropped := []uint32{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ref.Retained = slices.DeleteFunc(ref.Retained, func(retained SearchCacheRetained) bool {
			if drop(retained) {
				dropped = append(dropped, retained.StartDay)
				return true
			}
			return false
		})
	}()
	if len(dropped) == 0 {
		return nil
	}
	keys := []SearchCacheKey{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, file := range ref.Files {
			if !file.Partition.All && slices.Contains(dropped, file.Partition.StartDay) {
				keys = append(keys, file.Key)
			}
		}
	}()
	for _, key := range keys {
		if err := self.removeFileWithLock(key); err != nil {
			return err
		}
	}
	return self.storeRefWithLock(ref)
}

// The ref's all copy now shows every bucket through rolledThroughDay rolled up (a/m's rolled_through_day): the retained
// buckets it covers go.
func (self *SearchCache) ApplyRolledThrough(repoId Id, refId Id, rolledThroughDay uint32) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	ref, err := self.loadRefWithLock(repoId, refId)
	if err != nil {
		return err
	}
	return self.dropRetainedWithLock(ref, func(retained SearchCacheRetained) bool {
		return retained.StartDay <= rolledThroughDay
	})
}

// An ERASE in the repo ends every retained bucket of its refs (§11.14's retained row).
func (self *SearchCache) DropRetained(repoId Id) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	refKeys, err := self.refKeysWithLock()
	if err != nil {
		return err
	}
	for _, refKey := range refKeys {
		if refKey[0] != repoId {
			continue
		}
		ref, err := self.loadRefWithLock(refKey[0], refKey[1])
		if err != nil {
			return err
		}
		if err := self.dropRetainedWithLock(ref, func(SearchCacheRetained) bool { return true }); err != nil {
			return err
		}
	}
	return nil
}

// Drops every retained bucket two bucket lengths past its roll-up, now on the cache's clock.
func (self *SearchCache) SweepRetained() error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	now := self.clock.Now()
	refKeys, err := self.refKeysWithLock()
	if err != nil {
		return err
	}
	for _, refKey := range refKeys {
		ref, err := self.loadRefWithLock(refKey[0], refKey[1])
		if err != nil {
			return err
		}
		err = self.dropRetainedWithLock(ref, func(retained SearchCacheRetained) bool {
			return !now.Before(retained.RolledUpAt.Add(2 * time.Duration(retained.WindowDays) * 24 * time.Hour))
		})
		if err != nil {
			return err
		}
	}
	return nil
}
