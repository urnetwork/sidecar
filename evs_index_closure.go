//go:build !ios_extension

// A CLOSURE's rewrite of one index file (§11.14's erase, pad and shrink rows; §11.12's rekey row; DESIGN-DETAILS
// 15.2.5's clean, as owner decision 584 leaves it with full entries only; plan-SEARCH-shrink-claim; SEARCH-M10-17): the
// replaced version without every entry, row and tombstone of a document the ref's erasure set lists at or below its
// listed version, L(k), padded with zero bytes to the replaced version's exact length, so the size shows nothing and
// 11.12's rekey bound holds.
//
//	slot   the slot without each such entry, the rest in key order as before, its header's count and body_length set,
//	       its coverage, seq and window kept; zero entries is a slot an erasure emptied
//	large  its one entry gone: no entry and all pad, which a decoder takes as a large entry an erasure emptied
//	       (protocol/INDEX-FORMAT.md's Erasure); its writer removes it once a merge absorbs it, as any large entry
//	shard  indexShardBuilder.rewriteWithout: built by blocks of 64 if that fits the replaced length, else on the
//	       replaced partition, the replaced header's pad_generation kept
//
// A file holding nothing the set lists is its replaced bytes as they stand: a path the eraser rewrites only to take
// its key, whose retained version held the document (§11.14's erase row's history), gets the same plaintext under a
// fresh key. A ref tombstone names a ref_id, never a document, so no rewrite takes one. A rewrite is a function of the
// replaced file and the erasure set at the CLOSURE's base, which a reproducer rebuilds and compares
// (evs_index_reproduce.go). One that would come out longer than the replaced version is refused, never padded short.
//
// No key is created, derived or unwrapped here: the CLOSURE's fresh key is its push's (EvsRepo.Closure). Package-level
// functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
)

// L(k) of what a rewrite takes out: the highest version at which the ref's erasure set lists each doc_key, over every
// erasure the set lists, as the epoch guard reads it (DESIGN-DETAILS 15.2.5's clean takes the set, not one erasure's
// documents).
type indexEraseListed map[[indexIdByteCount]byte]uint64

// Whether a rewrite takes an entry, row or tombstone of kind for key at version out.
func (self indexEraseListed) takes(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
	listed, ok := self[key]
	return ok && kind != indexEntryRefTombstone && version <= listed
}

// The replaced version of an index file at path, plaintext, without what listed takes, padded to its exact length; and
// whether anything was taken. A file a rewrite cannot read, or one of a kind that holds no document, is refused.
func indexClean(path indexPath, plaintext []byte, listed indexEraseListed, settings *IndexFormatSettings) ([]byte, bool, error) {
	contentSha256 := sha256.Sum256(plaintext)
	switch path.kind {
	case indexPathSlot, indexPathLargeEntry:
		slot, err := indexDecodeSlot(plaintext, contentSha256[:], path.companion, settings)
		if err != nil {
			return nil, false, err
		}
		kept := []*indexEntry{}
		for _, entry := range slot.entries {
			if !listed.takes(entry.kind, entry.key, entry.version) {
				kept = append(kept, entry)
			}
		}
		if len(kept) == len(slot.entries) {
			return bytes.Clone(plaintext), false, nil
		}
		rewritten := &indexSlot{header: slot.header, entries: kept}
		// the length with no pad, read through a pad of one byte, since an empty large entry is refused without one
		rewritten.padByteCount = 1
		probe, err := indexEncodeSlot(rewritten, path.companion, settings)
		if err != nil {
			return nil, false, err
		}
		unpaddedByteCount := len(probe) - 1
		if len(plaintext) < unpaddedByteCount {
			return nil, false, indexMalformed("a rewrite longer than what it replaces")
		}
		// an empty large entry with no pad left is refused by the encoder, as no honest replaced version gives one
		rewritten.padByteCount = len(plaintext) - unpaddedByteCount
		file, err := indexEncodeSlot(rewritten, path.companion, settings)
		if err != nil {
			return nil, false, err
		}
		return file, true, nil
	case indexPathBucketShard, indexPathAllShard:
		shard, err := indexDecodeShard(plaintext, contentSha256[:], path.companion)
		if err != nil {
			return nil, false, err
		}
		taken := false
		drop := func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
			takes := listed.takes(kind, key, version)
			taken = taken || takes
			return takes
		}
		file, _, err := indexNewShardBuilder(path.companion).rewriteWithout(shard, drop, len(plaintext))
		if err != nil {
			return nil, false, err
		}
		if !taken {
			// nothing listed: the replaced bytes as they stand, not a re-encoding that might block them otherwise
			return bytes.Clone(plaintext), false, nil
		}
		return file, true, nil
	}
	return nil, false, indexMalformed("a CLOSURE of an index file that holds no document")
}

// Whether the replaced version of an index file at path, plaintext, holds anything listed takes.
func indexHolds(path indexPath, plaintext []byte, listed indexEraseListed, settings *IndexFormatSettings) (bool, error) {
	if len(listed) == 0 {
		return false, nil
	}
	contentSha256 := sha256.Sum256(plaintext)
	switch path.kind {
	case indexPathSlot, indexPathLargeEntry:
		slot, err := indexDecodeSlot(plaintext, contentSha256[:], path.companion, settings)
		if err != nil {
			return false, err
		}
		return indexSlotHolds(slot, listed), nil
	case indexPathBucketShard, indexPathAllShard:
		shard, err := indexDecodeShard(plaintext, contentSha256[:], path.companion)
		if err != nil {
			return false, err
		}
		return indexShardHolds(shard, listed), nil
	}
	return false, nil
}

// Whether a decoded slot or large entry holds anything listed takes.
func indexSlotHolds(slot *indexSlot, listed indexEraseListed) bool {
	for _, entry := range slot.entries {
		if listed.takes(entry.kind, entry.key, entry.version) {
			return true
		}
	}
	return false
}

// Whether a decoded shard holds a row or tombstone listed takes.
func indexShardHolds(shard *indexShard, listed indexEraseListed) bool {
	for _, document := range shard.documents {
		if listed.takes(indexEntryFull, document.key, document.version) {
			return true
		}
	}
	for _, tombstone := range shard.tombstones {
		if listed.takes(tombstone.kind, tombstone.key, tombstone.version) {
			return true
		}
	}
	return false
}
