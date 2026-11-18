//go:build !ios_extension

// A bucket's entries by document (§11.14's window row; D-EVS-45): every entry a bucket holds of each key, its shards'
// rows and tombstones and each writer's slots and large entries, as a push's move to a newer bucket, a backfill's
// held keys and the tests read them. Every entry is full or a tombstone (owner decision 584), so each is read as it
// stands.

package sidecar

import (
	"context"
	"slices"
)

// One entry of a document in a bucket, a shard's row reading as a full entry and its tombstone as a tombstone: what
// D-EVS-45's move asks of a newer bucket, and what a reader's tests look at.
type indexBucketEntry struct {
	kind indexEntryKind
	// The doc_key, or a ref tombstone's ref_id.
	key     [indexIdByteCount]byte
	version uint64
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
					kind: entry.kind, key: entry.key, version: entry.version,
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
