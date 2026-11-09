// Posting lists (§11.14's postings row; protocol/INDEX-FORMAT.md's Shards): for one trigram key, the docids of a
// shard's live documents holding it, document-level and with no positions. A list is VByte gaps between ascending
// docids, the first gap docid + 1, or a bitset of ⌈N/8⌉ bytes over the shard's N documents, whichever is shorter,
// gaps on a tie. Lists are shared across a shard's documents, so they sit under the keyed pad, and nothing in one is
// compressed with another (§11.14's codes row).
//
// A list is never longer than its bitset would be, and N is bounded by the shard's 1 MiB, so every list is a few KiB
// and a reader may hold one whole even when it spans frames.

package sidecar

import (
	"math/bits"
)

// The bytes a bitset over documentCount documents takes.
func indexBitsetByteCount(documentCount int) int {
	return (documentCount + 7) / 8
}

// The bytes docIds take as gaps. They ascend, distinct.
func indexGapListByteCount(docIds []uint32) int {
	byteCount := 0
	last := -1
	for _, docId := range docIds {
		byteCount += indexVByteLength(uint64(int(docId) - last))
		last = int(docId)
	}
	return byteCount
}

// Appends docIds, ascending and below documentCount, in the shorter of the two forms, and says which it took.
func indexAppendList(dst []byte, docIds []uint32, documentCount int) ([]byte, bool) {
	if indexBitsetByteCount(documentCount) < indexGapListByteCount(docIds) {
		bitset := make([]byte, indexBitsetByteCount(documentCount))
		for _, docId := range docIds {
			bitset[docId/8] |= 1 << (docId % 8)
		}
		return append(dst, bitset...), true
	}
	last := -1
	for _, docId := range docIds {
		dst = indexAppendVByte(dst, uint64(int(docId)-last))
		last = int(docId)
	}
	return dst, false
}

// One key's list as read: a bitset as it stands, or its docids. A bitset stays a bitset, since it is the dense case
// and ANDs as bytes (§11.14's plan row).
type indexPostingList struct {
	// The documents it holds.
	count int
	// Docid d is bit d mod 8 of byte d / 8. Nil for a gap list.
	bitset []byte
	// Ascending. Nil for a bitset.
	docIds []uint32
}

// Whether docId is in the list.
func (self *indexPostingList) contains(docId uint32) bool {
	if self.bitset != nil {
		return int(docId/8) < len(self.bitset) && self.bitset[docId/8]&(1<<(docId%8)) != 0
	}
	low, high := 0, len(self.docIds)
	for low < high {
		middle := int(uint(low+high) >> 1)
		if self.docIds[middle] < docId {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return low < len(self.docIds) && self.docIds[low] == docId
}

// Every docid, ascending.
func (self *indexPostingList) all() []uint32 {
	if self.bitset == nil {
		return self.docIds
	}
	docIds := make([]uint32, 0, self.count)
	for index, b := range self.bitset {
		for ; b != 0; b &= b - 1 {
			docIds = append(docIds, uint32(index*8+bits.TrailingZeros8(b)))
		}
	}
	return docIds
}

// Reads one list of listCount documents from encoded, which is exactly its list bytes, in a shard of documentCount
// documents. Only the one encoding the shorter-list rule picks is taken: a bitset of exactly ⌈N/8⌉ bytes with no
// spare bit set, strictly shorter than its gaps would be; or listCount minimal, non-zero gaps filling encoded, every
// docid below N, no longer than the bitset.
func indexDecodeList(encoded []byte, bitset bool, listCount uint64, documentCount int) (*indexPostingList, error) {
	if listCount == 0 || uint64(documentCount) < listCount {
		return nil, indexMalformed("a list's document count out of range")
	}
	bitsetByteCount := indexBitsetByteCount(documentCount)
	if bitset {
		if len(encoded) != bitsetByteCount {
			return nil, indexMalformed("a bitset that is not the shard's length")
		}
		if spare := documentCount % 8; spare != 0 && encoded[len(encoded)-1]>>spare != 0 {
			return nil, indexMalformed("a bitset's spare bit set")
		}
		count := 0
		gapByteCount := 0
		last := -1
		for index, b := range encoded {
			count += bits.OnesCount8(b)
			for ; b != 0; b &= b - 1 {
				docId := index*8 + bits.TrailingZeros8(b)
				gapByteCount += indexVByteLength(uint64(docId - last))
				last = docId
			}
		}
		if uint64(count) != listCount {
			return nil, indexMalformed("a bitset that does not hold its document count")
		}
		if gapByteCount <= bitsetByteCount {
			return nil, indexMalformed("a bitset where gaps are no longer")
		}
		return &indexPostingList{count: count, bitset: encoded}, nil
	}
	if bitsetByteCount < len(encoded) {
		return nil, indexMalformed("gaps longer than a bitset")
	}
	// Every gap takes at least a byte, so a count past the bytes is refused before it sizes anything.
	if uint64(len(encoded)) < listCount {
		return nil, indexMalformed("a list's document count past its bytes")
	}
	decoder := indexDecoder{src: encoded}
	docIds := make([]uint32, 0, listCount)
	last := -1
	for range listCount {
		gap := decoder.vbyte()
		if decoder.err != nil {
			return nil, decoder.err
		}
		if gap == 0 || uint64(documentCount-1-last) < gap {
			return nil, indexMalformed("a docid out of range")
		}
		last += int(gap)
		docIds = append(docIds, uint32(last))
	}
	if decoder.remaining() != 0 {
		return nil, indexMalformed("bytes past a list's last gap")
	}
	return &indexPostingList{count: len(docIds), docIds: docIds}, nil
}
