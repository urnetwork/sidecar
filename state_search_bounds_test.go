package sidecar

// CORE-M10-01: §5.9's bounds row, all partitions first, least recently searched, a served repo's all last among them,
// and the retained buckets of its holds row, kept until all covers them and never past two bucket lengths.

import (
	"testing"
	"time"
)

// Puts one file of a ref's partition, answering the bytes it takes.
func (self *testSearchCacheWorld) putPartition(t *testing.T, repoId Id, refId Id, partition SearchCachePartition, path string) int64 {
	t.Helper()
	key := SearchCacheKey{RepoId: repoId, RefId: refId, Path: path, Version: 1}
	kept := newTestSearchRecord(t, key, partition, testSearchPlaintext(path+repoId.String(), 6000))
	if err := self.cache.PutRecord(t.Context(), kept.record); err != nil {
		t.Fatal(err)
	}
	ref, err := self.cache.Ref(repoId, refId)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range ref.Files {
		if file.Key == key {
			return file.ByteCount
		}
	}
	t.Fatalf("%s not held", path)
	return 0
}

// Whether the cache holds a ref's partition.
func (self *testSearchCacheWorld) holds(t *testing.T, repoId Id, refId Id, all bool) bool {
	t.Helper()
	ref, err := self.cache.Ref(repoId, refId)
	if err != nil {
		t.Fatal(err)
	}
	if ref == nil {
		return false
	}
	for _, file := range ref.Files {
		if file.Partition.All == all {
			return true
		}
	}
	return false
}

// Past its bound the cache drops all partitions first, least recently searched, a served repo's all after the rest,
// and only then buckets, least recently searched.
func TestEvictionOrder(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	repoA, refA := NewId(), NewId()
	repoB, refB := NewId(), NewId()
	repoC, refC := NewId(), NewId()
	world.putPartition(t, repoA, refA, SearchCachePartition{StartDay: 20000}, ".ur-index/i1/b/20000/0")
	allA := world.putPartition(t, repoA, refA, SearchCachePartition{All: true}, ".ur-index/i1/a/0")
	world.putPartition(t, repoB, refB, SearchCachePartition{StartDay: 20000}, ".ur-index/i1/b/20000/0")
	allB := world.putPartition(t, repoB, refB, SearchCachePartition{All: true}, ".ur-index/i1/a/0")
	world.putPartition(t, repoC, refC, SearchCachePartition{All: true}, ".ur-index/i1/a/0")
	world.cache.SetDesignated(true, []Id{repoC})

	// B's all was searched longest ago, then A's; the buckets the other way round
	world.cache.MarkSearched(repoB, refB, SearchCachePartition{All: true})
	world.clock.advance(time.Minute)
	world.cache.MarkSearched(repoA, refA, SearchCachePartition{All: true})
	world.cache.MarkSearched(repoA, refA, SearchCachePartition{StartDay: 20000})
	world.clock.advance(time.Minute)
	world.cache.MarkSearched(repoB, refB, SearchCachePartition{StartDay: 20000})

	// a designated daemon's bound is at least 16 GiB, so these bounds are an undesignated one's, the served repo kept
	world.cache.stateLock.Lock()
	world.cache.designated = false
	world.cache.stateLock.Unlock()
	total := world.cache.ByteCount()
	world.settings.CacheByteCount = total - allB
	if _, err := world.cache.Evict(); err != nil {
		t.Fatal(err)
	}
	if world.holds(t, repoB, refB, true) || !world.holds(t, repoA, refA, true) || !world.holds(t, repoC, refC, true) {
		t.Fatal("not B's all first")
	}
	world.settings.CacheByteCount = total - allB - allA
	if _, err := world.cache.Evict(); err != nil {
		t.Fatal(err)
	}
	if world.holds(t, repoA, refA, true) || !world.holds(t, repoC, refC, true) {
		t.Fatal("not A's all next, before the served repo's")
	}
	if !world.holds(t, repoA, refA, false) || !world.holds(t, repoB, refB, false) {
		t.Fatal("a bucket went while an all was held")
	}
	world.settings.CacheByteCount = world.cache.ByteCount() - 1
	if _, err := world.cache.Evict(); err != nil {
		t.Fatal(err)
	}
	if world.holds(t, repoC, refC, true) || !world.holds(t, repoA, refA, false) || !world.holds(t, repoB, refB, false) {
		t.Fatal("not the served repo's all, before any bucket")
	}
	world.settings.CacheByteCount = world.cache.ByteCount() - 1
	if _, err := world.cache.Evict(); err != nil {
		t.Fatal(err)
	}
	if world.holds(t, repoA, refA, false) || !world.holds(t, repoB, refB, false) {
		t.Error("not the least recently searched bucket first")
	}
	if bound := world.settings.CacheByteCount; bound < world.cache.ByteCount() {
		t.Errorf("%d bytes over a bound of %d", world.cache.ByteCount(), bound)
	}
}

// Phones and browsers drop all shards unused for 30 days; a served repo's all stays, and buckets stay.
func TestEvictUnusedDropsOnlyStaleAlls(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	repoA, refA := NewId(), NewId()
	repoB, refB := NewId(), NewId()
	world.putPartition(t, repoA, refA, SearchCachePartition{All: true}, ".ur-index/i1/a/0")
	world.putPartition(t, repoA, refA, SearchCachePartition{StartDay: 20000}, ".ur-index/i1/b/20000/0")
	world.putPartition(t, repoB, refB, SearchCachePartition{All: true}, ".ur-index/i1/a/0")
	world.cache.SetDesignated(true, []Id{repoB})
	world.clock.advance(31 * 24 * time.Hour)
	if _, err := world.cache.EvictUnused(world.clock.Now().Add(-30 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if world.holds(t, repoA, refA, true) || !world.holds(t, repoA, refA, false) || !world.holds(t, repoB, refB, true) {
		t.Error("not exactly the unused, unserved all dropped")
	}
}

// §11.14's retained row: a bucket a roll-up dropped stays while this device's all is stale, until all's
// rolled_through_day covers it, an ERASE in the repo, or two bucket lengths after the roll-up.
func TestDroppedBucketKeptUntilCovered(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<30)
	repoId, refId := NewId(), NewId()
	world.putPartition(t, repoId, refId, SearchCachePartition{StartDay: 100}, ".ur-index/i1/b/100/0")
	world.putPartition(t, repoId, refId, SearchCachePartition{StartDay: 107}, ".ur-index/i1/b/107/0")
	world.putPartition(t, repoId, refId, SearchCachePartition{All: true}, ".ur-index/i1/a/0")
	if err := world.cache.RetainBucket(repoId, refId, 100, 7, world.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := world.cache.RetainBucket(repoId, refId, 107, 7, world.clock.Now()); err != nil {
		t.Fatal(err)
	}
	bucketHeld := func(startDay uint32) bool {
		ref, err := world.cache.Ref(repoId, refId)
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range ref.Files {
			if !file.Partition.All && file.Partition.StartDay == startDay {
				return true
			}
		}
		return false
	}

	// all's copy still shows day 99 rolled through: both stay
	if err := world.cache.ApplyRolledThrough(repoId, refId, 99); err != nil {
		t.Fatal(err)
	}
	if !bucketHeld(100) || !bucketHeld(107) {
		t.Fatal("a retained bucket went before all covered it")
	}
	if err := world.cache.ApplyRolledThrough(repoId, refId, 100); err != nil {
		t.Fatal(err)
	}
	if bucketHeld(100) || !bucketHeld(107) {
		t.Fatal("not exactly the covered bucket dropped")
	}

	// a day short of two bucket lengths it stays; at two it goes, all's copy stale or not
	world.clock.advance(14*24*time.Hour - time.Second)
	if err := world.cache.SweepRetained(); err != nil {
		t.Fatal(err)
	}
	if !bucketHeld(107) {
		t.Fatal("dropped before two bucket lengths")
	}
	world.clock.advance(time.Second)
	if err := world.cache.SweepRetained(); err != nil {
		t.Fatal(err)
	}
	if bucketHeld(107) {
		t.Error("kept past two bucket lengths")
	}
	ref, err := world.cache.Ref(repoId, refId)
	if err != nil || ref == nil || len(ref.Retained) != 0 || !world.holds(t, repoId, refId, true) {
		t.Errorf("after the sweep: %+v, %v", ref, err)
	}

	// an ERASE in the repo ends retention at once
	world.putPartition(t, repoId, refId, SearchCachePartition{StartDay: 114}, ".ur-index/i1/b/114/0")
	if err := world.cache.RetainBucket(repoId, refId, 114, 7, world.clock.Now()); err != nil {
		t.Fatal(err)
	}
	if err := world.cache.DropRetained(repoId); err != nil {
		t.Fatal(err)
	}
	if bucketHeld(114) {
		t.Error("an ERASE left a retained bucket")
	}
}

// A daemon designated for search holds at least 16 GiB, whatever its settings say.
func TestDesignatedDaemonHolds16GiB(t *testing.T) {
	world := newTestSearchCacheWorld(t, 1<<20)
	if bound := world.cache.bound(); bound != 1<<20 {
		t.Errorf("bound %d", bound)
	}
	world.cache.SetDesignated(true, nil)
	if bound := world.cache.bound(); bound != SearchDesignatedCacheByteCount {
		t.Errorf("designated bound %d", bound)
	}
	world.cache.SetDesignated(false, []Id{NewId()})
	if bound := world.cache.bound(); bound != 1<<20 || len(world.cache.served) != 0 {
		t.Errorf("undesignated bound %d, %d served", bound, len(world.cache.served))
	}
}
