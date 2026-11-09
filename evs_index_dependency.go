// The dependency row (§11.14's commit path; D-EVS-46): whether a writer's entry for a document version is a diff on a
// base, read literally, as a pure function of the bucket at the push's base. A diff for version v names its base by
// version and is written only where the index at the push's base keeps that base while the diff is current, in the
// current bucket: the document's newest entry is at the version v replaces and is no tombstone, and either
//
//	(a) an entry of it at that version lies outside every writer's head in this bucket, in a shard or in a sealed
//	    slot or large entry its manifest has not absorbed, and is the base, while no writer's head holds a diff at
//	    that version, whose base a merge built before this push may keep instead; or
//	(b) it is this writer's own head entry, a diff whose base is the document's newest entry outside every head of
//	    this bucket: the new entry takes that base, its delta composed, and replaces the entry.
//
// Anything else is full, so no entry rests on the entry it replaces or on any head. The base's chain plus one stays
// under 16 diffs and the delta under half the base's set, and an entry late into the previous or an expired bucket is
// full. Bases resolve exactly here, whole key sets composed, since a writer's delta must apply to what the index holds:
// a base that does not resolve makes the entry full, never a diff on a guess.

package sidecar

import (
	"context"
	"slices"
)

// The most diffs a chain holds below a self-contained entry: a new diff's base's chain plus one stays under 16.
const indexChainMaxDiffCount = 15

// Where one entry of a document sits in its bucket.
type indexEntryPlace int

const (
	// A shard's doc table row or tombstone.
	indexPlaceShard indexEntryPlace = iota + 1
	// A writer's slot other than its head.
	indexPlaceSealed
	// A large entry.
	indexPlaceLarge
	// A writer's head.
	indexPlaceHead
)

// One entry of a document in a bucket. A shard row reads as a full entry, a shard tombstone as a tombstone.
type indexBucketEntry struct {
	place indexEntryPlace
	kind  indexEntryKind
	// The doc_key, or a ref tombstone's ref_id.
	key         [indexIdByteCount]byte
	version     uint64
	baseVersion uint64
	// Slots, large entries and heads: whose, and their seq.
	writer Id
	seq    uint32
	// A sealed slot or large entry the bucket's manifest shows absorbed.
	absorbed bool
	// Slots, large entries and heads: the entry. Shard rows: the document, its keys inverted from the postings.
	entry    *indexEntry
	document *indexShardDocument
}

// Whether the entry is a version kept outside every head where no writer may reuse its file: a shard's row, or a
// sealed slot or large entry no merge has absorbed (the dependency row's case a).
func (self *indexBucketEntry) keptOutsideHeads() bool {
	switch self.place {
	case indexPlaceShard:
		return true
	case indexPlaceSealed, indexPlaceLarge:
		return !self.absorbed
	}
	return false
}

// Whether the entry is a live version, full or diff.
func (self *indexBucketEntry) live() bool {
	return self.kind == indexEntryFull || self.kind == indexEntryDiff
}

// A bucket's entries by document key, as a push's base holds them.
type indexBucketDocuments struct {
	bucket *indexViewBucket
	// By doc_key, and by ref_id for ref tombstones.
	entries map[[indexIdByteCount]byte][]*indexBucketEntry
}

// Every entry the bucket holds, by key: each shard's rows and tombstones, its shards decoded, and each writer's slots
// and large entries. A shard that breaks its format is left out, as the view alarms it.
func (self *indexView) bucketDocuments(ctx context.Context, bucket *indexViewBucket) (*indexBucketDocuments, error) {
	documents := &indexBucketDocuments{bucket: bucket, entries: map[[indexIdByteCount]byte][]*indexBucketEntry{}}
	add := func(entry *indexBucketEntry) {
		documents.entries[entry.key] = append(documents.entries[entry.key], entry)
	}
	for _, shard := range bucket.shards {
		decoded, err := self.shard(ctx, shard)
		if err != nil {
			return nil, err
		}
		if decoded == nil {
			continue
		}
		for _, document := range decoded.documents {
			add(&indexBucketEntry{place: indexPlaceShard, kind: indexEntryFull, key: document.key, version: document.version, document: document})
		}
		for _, tombstone := range decoded.tombstones {
			add(&indexBucketEntry{place: indexPlaceShard, kind: tombstone.kind, key: tombstone.key, version: tombstone.version})
		}
	}
	for _, writer := range bucket.writers {
		absorbed := bucket.absorbedSeq(writer.sidecarId)
		head := writer.head()
		for _, slot := range writer.slots {
			place := indexPlaceSealed
			if slot == head {
				place = indexPlaceHead
			}
			for _, entry := range slot.slot.entries {
				add(&indexBucketEntry{
					place: place, kind: entry.kind, key: entry.key, version: entry.version, baseVersion: entry.baseVersion,
					writer: writer.sidecarId, seq: slot.seq(), absorbed: place == indexPlaceSealed && slot.seq() <= absorbed, entry: entry,
				})
			}
		}
		for _, large := range writer.large {
			for _, entry := range large.slot.entries {
				add(&indexBucketEntry{
					place: indexPlaceLarge, kind: entry.kind, key: entry.key, version: entry.version, baseVersion: entry.baseVersion,
					writer: writer.sidecarId, seq: large.seq(), absorbed: large.seq() <= absorbed, entry: entry,
				})
			}
		}
	}
	return documents, nil
}

// The document's entries, nil where the bucket holds none.
func (self *indexBucketDocuments) of(key [indexIdByteCount]byte) []*indexBucketEntry {
	if self == nil {
		return nil
	}
	return self.entries[key]
}

// The entry with the highest version among entries that pass keep, tombstones included; nil for none. Of equal
// versions the first wins, which leaves the choice to the caller's order.
func indexNewestEntry(entries []*indexBucketEntry, keep func(entry *indexBucketEntry) bool) *indexBucketEntry {
	var newest *indexBucketEntry
	for _, entry := range entries {
		if keep(entry) && (newest == nil || newest.version < entry.version) {
			newest = entry
		}
	}
	return newest
}

// The key set of key's version in the bucket, from its shards, sealed slots and large entries, never a head, copies of
// one version being one and a self-contained copy answering first; and how many diffs its chain holds. A version that
// does not resolve, whose chain passes 15 diffs, or whose composed set's size is not its row's trigram count, answers
// an error.
func (self *indexBucketDocuments) resolve(key [indexIdByteCount]byte, version uint64) (indexKeySet, int, error) {
	return self.resolveDepth(key, version, 0)
}

// resolve, depth diffs above the version asked for.
func (self *indexBucketDocuments) resolveDepth(key [indexIdByteCount]byte, version uint64, depth int) (indexKeySet, int, error) {
	if indexChainMaxDiffCount < depth {
		return nil, 0, indexMalformed("a chain past 15 diffs")
	}
	copies := []*indexBucketEntry{}
	for _, entry := range self.of(key) {
		if entry.place != indexPlaceHead && entry.version == version && entry.live() {
			copies = append(copies, entry)
		}
	}
	// A self-contained copy first, then diffs, each in the order the bucket was read.
	slices.SortStableFunc(copies, func(a *indexBucketEntry, b *indexBucketEntry) int {
		return int(a.kind) - int(b.kind)
	})
	var lastErr error = indexMalformed("a base no file holds")
	for _, copy := range copies {
		if copy.kind == indexEntryFull {
			if copy.document != nil {
				return copy.document.keys, 0, nil
			}
			return copy.entry.keys, 0, nil
		}
		base, chain, err := self.resolveDepth(key, copy.baseVersion, depth+1)
		if err != nil {
			lastErr = err
			continue
		}
		keys, err := copy.entry.delta.applyTo(base)
		if err == nil && uint64(len(keys)) != copy.entry.row.trigramCount {
			err = indexMalformed("a composed set whose size is not its row's trigram count")
		}
		if err != nil {
			lastErr = err
			continue
		}
		return keys, chain + 1, nil
	}
	return nil, 0, lastErr
}

// One document version a writer's push carries, before the dependency row chooses its entry.
type indexPendingDocument struct {
	// indexEntryFull for a live version, whatever entry it becomes; indexEntryTombstone for a removal, a dropped chunk
	// or a turn to binary or skipped; indexEntryRefTombstone for a ref DELETE on ur/index.
	kind indexEntryKind
	// The doc_key, or a ref tombstone's ref_id.
	key     [indexIdByteCount]byte
	version uint64
	// The version this one replaces: a path's v - 1, a derived document's previous sequence. 0 for a creation, which
	// is always full.
	replaces uint64
	// A live version's key set and row.
	keys indexKeySet
	row  *indexRow
}

// What the dependency row chose for one live version: full, or a diff on a base version with its delta.
type indexEntryChoice struct {
	diff        bool
	baseVersion uint64
	delta       indexDelta
}

// The dependency row for one live version this writer pushes into the bucket documents holds at the push's base,
// current saying whether that bucket is the root's newest. erased says whether the ref's erasure set lists a version,
// whose documents no diff may rest on. A version no case allows, or whose base does not resolve, is full.
func indexChooseEntry(documents *indexBucketDocuments, current bool, writer Id, pending *indexPendingDocument, erased func(key [indexIdByteCount]byte, version uint64) bool) *indexEntryChoice {
	full := &indexEntryChoice{}
	if !current || pending.replaces == 0 || pending.replaces >= pending.version || erased(pending.key, pending.replaces) {
		return full
	}
	entries := documents.of(pending.key)
	newest := indexNewestEntry(entries, func(entry *indexBucketEntry) bool {
		return true
	})
	if newest == nil || newest.version != pending.replaces || !newest.live() {
		return full
	}
	// A ref tombstone of the document's ref above the base deletes it.
	if pending.row != nil && len(pending.row.refId) == indexIdByteCount {
		for _, refTombstone := range documents.of([indexIdByteCount]byte(pending.row.refId)) {
			if refTombstone.kind == indexEntryRefTombstone && pending.replaces < refTombstone.version {
				return full
			}
		}
	}

	choose := func(baseVersion uint64) *indexEntryChoice {
		if erased(pending.key, baseVersion) {
			return nil
		}
		base, chain, err := documents.resolve(pending.key, baseVersion)
		if err != nil || indexChainMaxDiffCount < chain+1 {
			return nil
		}
		delta := indexDeltaBetween(base, pending.keys)
		if len(base) <= 2*(len(delta.added)+len(delta.removed)) {
			return nil
		}
		return &indexEntryChoice{diff: true, baseVersion: baseVersion, delta: delta}
	}

	// Case a: a copy of the replaced version kept outside every head, and no head holding a diff of that version.
	keptCopy := slices.ContainsFunc(entries, func(entry *indexBucketEntry) bool {
		return entry.version == pending.replaces && entry.live() && entry.keptOutsideHeads()
	})
	headDiff := slices.ContainsFunc(entries, func(entry *indexBucketEntry) bool {
		return entry.place == indexPlaceHead && entry.version == pending.replaces && entry.kind == indexEntryDiff
	})
	if keptCopy && !headDiff {
		if choice := choose(pending.replaces); choice != nil {
			return choice
		}
		return full
	}

	// Case b: this writer's head holds the replaced version as a diff whose base is the document's newest entry outside
	// every head, kept where no writer reuses it.
	own := slices.IndexFunc(entries, func(entry *indexBucketEntry) bool {
		return entry.place == indexPlaceHead && entry.writer == writer && entry.version == pending.replaces && entry.kind == indexEntryDiff
	})
	if own < 0 {
		return full
	}
	baseVersion := entries[own].baseVersion
	outside := indexNewestEntry(entries, func(entry *indexBucketEntry) bool {
		return entry.place != indexPlaceHead
	})
	if outside == nil || outside.version != baseVersion || !outside.live() || !slices.ContainsFunc(entries, func(entry *indexBucketEntry) bool {
		return entry.version == baseVersion && entry.live() && entry.keptOutsideHeads()
	}) {
		return full
	}
	if choice := choose(baseVersion); choice != nil {
		return choice
	}
	return full
}
