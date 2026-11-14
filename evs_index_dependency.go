//go:build !ios_extension

// The dependency row (§11.14's commit path as DESIGN-DETAILS 1.2.3 rewrites it; D-EVS-46; R1, own bases; QD-685): a
// writer's entry for a document version is a diff only on a full entry of its document in another file of its own
// writer in its own bucket, a slot that is not the head, absorbed or not, or a large entry, as the push's base shows
// them. The newest such entry below the version is the base and the delta is taken against it, so no diff rests on a
// diff, on a head, on a shard or on any file another device writes. A diff is written only where the delta is under
// half the base's set, the entry within SlotEntryMaxByteCount, the document no creation, and the base's slot kept
// already or fewer than KeepSlotCount kept; anything else is full, in a slot within SlotEntryMaxByteCount, else as a
// large entry.
//
// The writer keeps every file a diff of its unabsorbed slots rests on: it does not reuse such a slot nor remove such a
// large entry (evs_index_head.go), and no merge writes or removes a writer's file, so nothing a diff needs is in reach
// of another device's push without a CAS on a file the diff's writer also writes (R2). A base resolves in one step,
// here and on the read side (search_chains.go).
//
// choose reads no other writer's file and no shard, so a writer's push is a function of its own files in the bucket,
// the bucket's manifest row for it, the erasure set, the push's signed time and the documents it carries (1.2.8).

package sidecar

import (
	"context"
	"slices"
)

// The base of a diff (1.2.1): the full entry of key at version in a large entry of writer's, or in a slot of writer's
// other than diffSlot and the writer's head; of two such, the one in the file with the higher seq. Nil when no file of
// writer's holds one, which breaks the format where diffSlot is unabsorbed.
func indexResolveBase(writer *indexViewWriter, key [indexIdByteCount]byte, version uint64, diffSlot *indexViewSlot) (*indexViewSlot, *indexEntry) {
	if writer == nil {
		return nil, nil
	}
	head := writer.head()
	var baseFile *indexViewSlot
	var base *indexEntry
	consider := func(file *indexViewSlot) {
		for _, entry := range file.slot.entries {
			if entry.key == key && entry.version == version && entry.kind == indexEntryFull && (baseFile == nil || baseFile.seq() < file.seq()) {
				baseFile, base = file, entry
			}
		}
	}
	for _, slot := range writer.slots {
		if slot != head && slot != diffSlot {
			consider(slot)
		}
	}
	for _, large := range writer.large {
		consider(large)
	}
	return baseFile, base
}

// One document version a writer's push carries, before choose decides its entry.
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

// What choose gave one live version: full, or a diff on a base version with its delta, and the base's file, which
// joins the push's keep set.
type indexEntryChoice struct {
	diff        bool
	baseVersion uint64
	delta       indexDelta
	baseFile    *indexViewSlot
}

// The slots of keep, which KeepSlotCount bounds; its large entries are not counted.
func indexKeptSlotCount(keep map[*indexViewSlot]bool) int {
	count := 0
	for file := range keep {
		if file.path.kind == indexPathSlot {
			count += 1
		}
	}
	return count
}

// 1.2.3's choose for one live version pending, over writer's own files in its bucket at the push's base (nil for a
// writer that has none there) and the push's keep set: B is the full entries of the key below pending's version that
// erased does not list, in writer's large entries and its slots other than the head; the base is B's highest version,
// then the file with the higher seq; and the entry is a diff on it when the delta is under half the base's set, the
// diff within SlotEntryMaxByteCount when encoded at timeSeconds, the document no creation, and the base's file a large
// entry, already kept, or one more slot than keep holds within KeepSlotCount. Anything else is full.
func indexChooseEntry(writer *indexViewWriter, keep map[*indexViewSlot]bool, pending *indexPendingDocument, timeSeconds uint64, companion bool, erased func(key [indexIdByteCount]byte, version uint64) bool, settings *IndexFormatSettings) (*indexEntryChoice, error) {
	full := &indexEntryChoice{}
	if writer == nil || pending.replaces == 0 || pending.replaces >= pending.version {
		return full, nil
	}
	head := writer.head()
	var baseFile *indexViewSlot
	var base *indexEntry
	consider := func(file *indexViewSlot) {
		for _, entry := range file.slot.entries {
			if entry.key != pending.key || entry.kind != indexEntryFull || pending.version <= entry.version || erased(entry.key, entry.version) {
				continue
			}
			if base == nil || base.version < entry.version || (base.version == entry.version && baseFile.seq() < file.seq()) {
				baseFile, base = file, entry
			}
		}
	}
	for _, slot := range writer.slots {
		if slot != head {
			consider(slot)
		}
	}
	for _, large := range writer.large {
		consider(large)
	}
	if base == nil {
		return full, nil
	}
	delta := indexDeltaBetween(base.keys, pending.keys)
	if len(base.keys) <= 2*(len(delta.added)+len(delta.removed)) {
		return full, nil
	}
	diff := &indexEntry{kind: indexEntryDiff, key: pending.key, version: pending.version, baseVersion: base.version, timeSeconds: timeSeconds, row: pending.row, delta: delta}
	encoded, err := diff.appendEncoded(nil, companion, settings)
	if err != nil {
		return nil, err
	}
	if settings.SlotEntryMaxByteCount < len(encoded) {
		return full, nil
	}
	if baseFile.path.kind == indexPathSlot && !keep[baseFile] && settings.KeepSlotCount <= indexKeptSlotCount(keep) {
		return full, nil
	}
	return &indexEntryChoice{diff: true, baseVersion: base.version, delta: delta, baseFile: baseFile}, nil
}

// One entry of a document in a bucket, a shard's row reading as a full entry and its tombstone as a tombstone: what
// D-EVS-45's move asks of a newer bucket, and what a reader's tests look at.
type indexBucketEntry struct {
	kind indexEntryKind
	// The doc_key, or a ref tombstone's ref_id.
	key         [indexIdByteCount]byte
	version     uint64
	baseVersion uint64
	// A shard's row or tombstone; else a writer's slot or large entry, with whose it is, its seq, whether it is the
	// writer's head, and whether the bucket's manifest shows it absorbed.
	shard    bool
	writer   Id
	seq      uint32
	head     bool
	large    bool
	absorbed bool
	// Slots and large entries: the entry. Shard rows: the document, its keys inverted from the postings.
	entry    *indexEntry
	document *indexShardDocument
}

// A bucket's entries by document key, as a view holds them.
type indexBucketDocuments struct {
	bucket *indexViewBucket
	// By doc_key, and by ref_id for ref tombstones.
	entries map[[indexIdByteCount]byte][]*indexBucketEntry
}

// Every entry the bucket holds, by key: each shard's rows and tombstones, its shards decoded, and each writer's slots
// and large entries. A shard that breaks its format is left out, as the view alarms it. A writer's push reads this of
// newer buckets alone, for D-EVS-45's move, never of a bucket it writes.
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
			add(&indexBucketEntry{shard: true, kind: indexEntryFull, key: document.key, version: document.version, document: document})
		}
		for _, tombstone := range decoded.tombstones {
			add(&indexBucketEntry{shard: true, kind: tombstone.kind, key: tombstone.key, version: tombstone.version})
		}
	}
	for _, writer := range bucket.writers {
		absorbed := bucket.absorbedSeq(writer.sidecarId)
		head := writer.head()
		for _, file := range slices.Concat(writer.slots, writer.large) {
			isLarge := file.path.kind == indexPathLargeEntry
			for _, entry := range file.slot.entries {
				add(&indexBucketEntry{
					kind: entry.kind, key: entry.key, version: entry.version, baseVersion: entry.baseVersion,
					writer: writer.sidecarId, seq: file.seq(), head: file == head, large: isLarge,
					absorbed: file != head && file.seq() <= absorbed, entry: entry,
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
