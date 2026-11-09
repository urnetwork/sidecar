// A bucket shard's tombstone table (§11.14's tombstones row; protocol/INDEX-FORMAT.md's Shards): the deletions a
// bucket keeps for older partitions until its roll-up, since an empty posting set cannot say a document went
// (D-EVS-44). Each is a kind, a key, a version and a time, with no postings. A ref tombstone sits only on ur/index, and
// an all shard holds none, because a roll-up drops what a tombstone supersedes there (§11.14's roll-up one row).

package sidecar

import (
	"bytes"
	"cmp"
)

// A tombstone's encoded length past its two VBytes: the kind and the key.
const indexTombstoneFixedByteCount = 1 + indexIdByteCount

// The longest tombstone.
const indexTombstoneMaxByteCount = indexTombstoneFixedByteCount + 2*indexVByteMaxByteCount

// One deletion: a document's at its version (kind 3), or a ref's, below which every row of that ref goes (kind 4).
type indexShardTombstone struct {
	kind indexEntryKind
	// A doc_key, or a ref tombstone's ref_id.
	key         [indexIdByteCount]byte
	version     uint64
	timeSeconds uint64
}

// The table's order: by kind, then key.
func indexCompareTombstones(a *indexShardTombstone, b *indexShardTombstone) int {
	return cmp.Or(cmp.Compare(a.kind, b.kind), bytes.Compare(a.key[:], b.key[:]))
}

// Refuses a tombstone this shard cannot hold.
func (self *indexShardTombstone) check(companion bool) error {
	switch self.kind {
	case indexEntryTombstone:
	case indexEntryRefTombstone:
		if !companion {
			return indexMalformed("a ref tombstone outside ur/index")
		}
	default:
		return indexMalformed("a tombstone of no tombstone kind")
	}
	return nil
}

// Appends one tombstone.
func (self *indexShardTombstone) appendEncoded(dst []byte) []byte {
	dst = append(dst, byte(self.kind))
	dst = append(dst, self.key[:]...)
	dst = indexAppendVByte(dst, self.version)
	return indexAppendVByte(dst, self.timeSeconds)
}

// Reads one tombstone.
func (self *indexDecoder) tombstone(companion bool) *indexShardTombstone {
	tombstone := &indexShardTombstone{kind: indexEntryKind(self.oneByte())}
	copy(tombstone.key[:], self.take(indexIdByteCount))
	tombstone.version = self.vbyte()
	tombstone.timeSeconds = self.vbyte()
	if self.err != nil {
		return nil
	}
	if err := tombstone.check(companion); err != nil {
		self.err = err
		return nil
	}
	return tombstone
}

// Appends a whole table, refusing one out of order, a key twice under either kind, or a kind this shard cannot hold.
// tombstones must already be in the table's order.
func indexAppendTombstones(dst []byte, tombstones []*indexShardTombstone, companion bool) ([]byte, error) {
	if err := indexCheckTombstoneOrder(tombstones, companion); err != nil {
		return nil, err
	}
	for _, tombstone := range tombstones {
		dst = tombstone.appendEncoded(dst)
	}
	return dst, nil
}

// Refuses a table out of order, with a key twice under one kind or both, or with a kind its root does not take.
func indexCheckTombstoneOrder(tombstones []*indexShardTombstone, companion bool) error {
	documentTombstoneCount := 0
	for index, tombstone := range tombstones {
		if err := tombstone.check(companion); err != nil {
			return err
		}
		if 0 < index && 0 <= indexCompareTombstones(tombstones[index-1], tombstone) {
			return indexMalformed("tombstones out of order or repeated")
		}
		if tombstone.kind == indexEntryTombstone {
			documentTombstoneCount += 1
		}
	}
	// Kind 3 sorts first, and both kinds ascend by key, so one walk finds a key under both.
	if indexTombstoneKeysMeet(tombstones[:documentTombstoneCount], tombstones[documentTombstoneCount:]) {
		return indexMalformed("a key under both tombstone kinds")
	}
	return nil
}

// Whether two key-ordered runs of tombstones share a key.
func indexTombstoneKeysMeet(a []*indexShardTombstone, b []*indexShardTombstone) bool {
	bIndex := 0
	for _, tombstone := range a {
		for bIndex < len(b) && bytes.Compare(b[bIndex].key[:], tombstone.key[:]) < 0 {
			bIndex += 1
		}
		if bIndex < len(b) && b[bIndex].key == tombstone.key {
			return true
		}
	}
	return false
}
