// A shard's dictionary (§11.14's dictionary row; protocol/INDEX-FORMAT.md's Shards): its keys ascending in blocks of
// up to 64, front-coded within a block, with a block index of each block's first key and the offsets of its entries
// and of its first list, so a phone finds a key's list by frame without reading the rest. A fresh shard blocks by 64; a
// rewrite padded to its replaced length may keep the replaced shard's partition instead (plan-SEARCH-shrink-claim),
// so a decoder takes any block of 1 to 64 keys and re-encodes from the file's own partition.

package sidecar

// A block's most keys, and how a fresh shard blocks.
const indexBlockMaxKeyCount = 64

// A trigram key's bytes, most significant first.
const indexTrigramByteCount = 3

// The key entry's flag byte: bits 0-1 the shared prefix, bit 2 a bitset, bits 3-7 zero.
const (
	indexKeyEntryPrefixMask byte = 0x03
	indexKeyEntryBitset     byte = 0x04
)

// The longest key entry: the flag, the key whole, and two VBytes.
const indexKeyEntryMaxByteCount = 1 + indexTrigramByteCount + 2*indexVByteMaxByteCount

// The longest block index entry: the first key and two VBytes.
const indexBlockEntryMaxByteCount = indexTrigramByteCount + 2*indexVByteMaxByteCount

// One key of a dictionary: its list's document count and length, and its form.
type indexDictionaryKey struct {
	key           uint32
	documentCount uint64
	listByteCount uint64
	bitset        bool
}

// One block of the block index. Offsets count from the first byte after the block index, and from the first byte of
// the postings.
type indexDictionaryBlock struct {
	firstKey      uint32
	entriesOffset uint64
	listOffset    uint64
}

// The bytes of key, most significant first.
func indexTrigramBytes(key uint32) [indexTrigramByteCount]byte {
	return [indexTrigramByteCount]byte{byte(key >> 16), byte(key >> 8), byte(key)}
}

// The leading bytes key shares with previous: 0, 1 or 2, since keys in a block are distinct.
func indexSharedPrefix(previous uint32, key uint32) int {
	a, b := indexTrigramBytes(previous), indexTrigramBytes(key)
	prefix := 0
	for prefix < indexTrigramByteCount-1 && a[prefix] == b[prefix] {
		prefix += 1
	}
	return prefix
}

// The keys in each block: blockKeyCounts as it stands, or blocks of 64 when nil.
func indexBlockPartition(keyCount int, blockKeyCounts []int) ([]int, error) {
	if blockKeyCounts == nil {
		partition := []int{}
		for remaining := keyCount; 0 < remaining; remaining -= indexBlockMaxKeyCount {
			partition = append(partition, min(remaining, indexBlockMaxKeyCount))
		}
		return partition, nil
	}
	total := 0
	for _, count := range blockKeyCounts {
		if count < 1 || indexBlockMaxKeyCount < count {
			return nil, indexMalformed("a block of no keys or more than 64")
		}
		total += count
	}
	if total != keyCount {
		return nil, indexMalformed("a partition that is not its keys'")
	}
	return blockKeyCounts, nil
}

// Appends the dictionary: VByte block count, the block index, then the key entries. keys ascend, and partition says
// how many each block holds.
func indexAppendDictionary(dst []byte, keys []indexDictionaryKey, partition []int) []byte {
	blocks := make([]indexDictionaryBlock, 0, len(partition))
	entries := []byte{}
	listOffset := uint64(0)
	next := 0
	for _, count := range partition {
		blocks = append(blocks, indexDictionaryBlock{
			firstKey:      keys[next].key,
			entriesOffset: uint64(len(entries)),
			listOffset:    listOffset,
		})
		for index := next; index < next+count; index += 1 {
			key := keys[index]
			prefix := 0
			if index != next {
				prefix = indexSharedPrefix(keys[index-1].key, key.key)
			}
			flag := byte(prefix)
			if key.bitset {
				flag |= indexKeyEntryBitset
			}
			keyBytes := indexTrigramBytes(key.key)
			entries = append(entries, flag)
			entries = append(entries, keyBytes[prefix:]...)
			entries = indexAppendVByte(entries, key.documentCount)
			entries = indexAppendVByte(entries, key.listByteCount)
			listOffset += key.listByteCount
		}
		next += count
	}
	dst = indexAppendVByte(dst, uint64(len(blocks)))
	for _, block := range blocks {
		keyBytes := indexTrigramBytes(block.firstKey)
		dst = append(dst, keyBytes[:]...)
		dst = indexAppendVByte(dst, block.entriesOffset)
		dst = indexAppendVByte(dst, block.listOffset)
	}
	return append(dst, entries...)
}

// Reads one block index entry.
func (self *indexDecoder) dictionaryBlock() indexDictionaryBlock {
	keyBytes := self.take(indexTrigramByteCount)
	block := indexDictionaryBlock{}
	if keyBytes != nil {
		block.firstKey = uint32(keyBytes[0])<<16 | uint32(keyBytes[1])<<8 | uint32(keyBytes[2])
	}
	block.entriesOffset = self.vbyte()
	block.listOffset = self.vbyte()
	return block
}

// Reads one key entry after previous, the key before it in its block, or with first set for a block's first key. The
// prefix must be the longest the two share, the flag's other bits zero, and the key above previous.
func (self *indexDecoder) keyEntry(previous uint32, first bool) indexDictionaryKey {
	flag := self.oneByte()
	if self.err != nil {
		return indexDictionaryKey{}
	}
	if flag&^(indexKeyEntryPrefixMask|indexKeyEntryBitset) != 0 {
		self.refuse("a key entry's flag with a spare bit set")
		return indexDictionaryKey{}
	}
	prefix := int(flag & indexKeyEntryPrefixMask)
	if first && prefix != 0 {
		self.refuse("a block's first key sharing a prefix")
		return indexDictionaryKey{}
	}
	if prefix == indexTrigramByteCount {
		self.refuse("a key repeated in its block")
		return indexDictionaryKey{}
	}
	keyBytes := indexTrigramBytes(previous)
	copy(keyBytes[prefix:], self.take(uint64(indexTrigramByteCount-prefix)))
	entry := indexDictionaryKey{
		key:    uint32(keyBytes[0])<<16 | uint32(keyBytes[1])<<8 | uint32(keyBytes[2]),
		bitset: flag&indexKeyEntryBitset != 0,
	}
	entry.documentCount = self.vbyte()
	entry.listByteCount = self.vbyte()
	if self.err != nil {
		return indexDictionaryKey{}
	}
	if !first {
		if entry.key <= previous {
			self.refuse("keys out of order")
			return indexDictionaryKey{}
		}
		if indexSharedPrefix(previous, entry.key) != prefix {
			self.refuse("a prefix that is not the longest")
			return indexDictionaryKey{}
		}
	}
	if entry.documentCount == 0 || entry.listByteCount == 0 {
		self.refuse("a key with no documents")
		return indexDictionaryKey{}
	}
	return entry
}
