// D6's shard test (DESIGN-DETAILS 11.2.3 as QD-760 amends it; protocol/INDEX-FORMAT.md's Documents): a document is
// skipped when its key set would encode past KeySetMax, or when it alone would not fit a shard, lone(d) past
// ShardBody, with
//
//	lone(d) = ShardLone + len(row) + dict(K) + n
//
// the encoded length, before its pad, of a shard holding d alone with one part made a constant. The doc table's row,
// the dictionary in blocks of 64 and the n postings are counted byte for byte: a key's entry is its flag byte, the
// 3 - p bytes its block's previous key does not share and one byte each for a document count of 1 and a list length of
// 1; a block's index row is its first key, its entries offset and its list offset 64 x j; each list is the one byte
// 0x01. The magic, the header and its length, the doc_key, the version and the time move with the bucket's day, the
// pad generation and the version, which the device that extracts and a later merger do not share, so they count as
// ShardLone. Format 1 needs at most 95 B of its 128 there, so a kept document's lone shard encodes at least 33 B under
// the cap, in a bucket and in all, whoever writes it and when: what a merge's take needs of a new shard (1.2.4).
//
// The test reads the key set and the row's bytes as its entry holds them and nothing else, so the device that extracts,
// a reproducer, a decoder and a merger or reader composing a diff all compute it alike. It calls no encoder: it is one
// pass over the keys, an addition and two comparisons a key, and allocates nothing. ShardBody is the shard encoder's
// own cap, so the test and the encoder cannot part. It links on every leg, since the entry codec does.

package sidecar

// lone(d) for a document whose row encodes to rowByteCount bytes and whose keys, ascending and distinct as the
// collector gives them, are keys.
func indexLoneShardByteCount(rowByteCount int, keys indexKeySet, settings *IndexFormatSettings) int {
	blockCount := (len(keys) + indexBlockMaxKeyCount - 1) / indexBlockMaxKeyCount
	dictionaryByteCount := indexVByteLength(uint64(blockCount))
	entriesOffset := 0
	for index, key := range keys {
		prefix := 0
		if index%indexBlockMaxKeyCount == 0 {
			// the block's index row: its first key, its entries offset, and its list offset, which is index, since
			// every list before it is one byte
			dictionaryByteCount += indexTrigramByteCount + indexVByteLength(uint64(entriesOffset)) + indexVByteLength(uint64(index))
		} else {
			prefix = indexSharedPrefix(keys[index-1], key)
		}
		// the flag byte, the key's unshared bytes, a document count of 1 and a list length of 1
		entryByteCount := 1 + indexTrigramByteCount - prefix + 2
		dictionaryByteCount += entryByteCount
		entriesOffset += entryByteCount
	}
	return settings.ShardLoneByteCount + rowByteCount + dictionaryByteCount + len(keys)
}

// Whether lone(d) passes ShardBody: the document would not fit a shard of its own.
func indexDocumentPastAShard(keys indexKeySet, row *indexRow, settings *IndexFormatSettings) bool {
	return indexShardMaxByteCount < indexLoneShardByteCount(row.encodedByteCount(), keys, settings)
}

// D6: whether a document with these keys and this row is skipped, its key set's encoding against KeySetMax first,
// which a set of millions of keys answers with no pass, and then lone(d) against ShardBody. row is the row as the
// document's entry carries it, ref_id included on ur/index, never one built again from fields.
func indexDocumentSkipped(keys indexKeySet, row *indexRow, settings *IndexFormatSettings) bool {
	// every key takes a byte at least, so more keys than KeySetMax's bytes are past it before any pass
	if indexKeySetMaxByteCount < len(keys) || indexKeySetMaxByteCount < keys.encodedByteCount() {
		return true
	}
	return indexDocumentPastAShard(keys, row, settings)
}
