//go:build !ios_extension

// Posting intersection (§11.14's plan row; SEARCH-M10-23): a shard's candidates for a query, from the lists of the
// query's trigrams alone. Lists come rarest first, so the candidate set only shrinks: a sparse candidate set gallops
// into a gap list and tests a bitset bit by bit, and a dense one ANDs a bitset byte by byte. Alternatives of a group
// (a OR b) are unions. Nothing here reads a list the query did not name, so what a search touches is a function of the
// query's trigrams and the shard's dictionary.

package sidecar

import (
	"math/bits"
)

// A shard's candidate docids: ascending docids, or a bitset over its documents where that is denser.
type searchDocSet struct {
	documentCount int
	// Ascending. Nil for a bitset.
	docIds []uint32
	// Docid d is bit d mod 8 of byte d / 8. Nil for docids.
	bitset []byte
}

// A set holding what list holds. A bitset is copied, since an intersection writes into it.
func searchDocSetOf(list *indexPostingList, documentCount int) *searchDocSet {
	if list.bitset != nil {
		return &searchDocSet{documentCount: documentCount, bitset: append([]byte{}, list.bitset...)}
	}
	return &searchDocSet{documentCount: documentCount, docIds: append([]uint32{}, list.docIds...)}
}

// How many documents the set holds.
func (self *searchDocSet) count() int {
	if self.bitset == nil {
		return len(self.docIds)
	}
	count := 0
	for _, b := range self.bitset {
		count += bits.OnesCount8(b)
	}
	return count
}

// Every docid, ascending.
func (self *searchDocSet) all() []uint32 {
	if self.bitset == nil {
		return self.docIds
	}
	docIds := []uint32{}
	for index, b := range self.bitset {
		for ; b != 0; b &= b - 1 {
			docIds = append(docIds, uint32(index*8+bits.TrailingZeros8(b)))
		}
	}
	return docIds
}

// The first index at or after from whose docid is at least target, by galloping: doubling steps, then a binary search
// inside the last step, so a sparse probe into a long list reads a few of its entries.
func searchGallop(docIds []uint32, from int, target uint32) int {
	if len(docIds) <= from || target <= docIds[from] {
		return from
	}
	low, step := from, 1
	high := from + step
	for high < len(docIds) && docIds[high] < target {
		low = high
		step *= 2
		high = from + step
	}
	high = min(high, len(docIds))
	for low+1 < high {
		middle := int(uint(low+high) >> 1)
		if docIds[middle] < target {
			low = middle
		} else {
			high = middle
		}
	}
	return high
}

// Keeps only the documents list holds as well.
func (self *searchDocSet) intersect(list *indexPostingList) {
	switch {
	case self.bitset != nil && list.bitset != nil:
		for index := range self.bitset {
			self.bitset[index] &= list.bitset[index]
		}
	case self.bitset != nil:
		// A gap list is no denser than its bitset, so its docids become the set.
		docIds := []uint32{}
		for _, docId := range list.docIds {
			if self.bitset[docId/8]&(1<<(docId%8)) != 0 {
				docIds = append(docIds, docId)
			}
		}
		self.bitset, self.docIds = nil, docIds
	case list.bitset != nil:
		kept := self.docIds[:0]
		for _, docId := range self.docIds {
			if list.bitset[docId/8]&(1<<(docId%8)) != 0 {
				kept = append(kept, docId)
			}
		}
		self.docIds = kept
	default:
		kept := self.docIds[:0]
		position := 0
		for _, docId := range self.docIds {
			position = searchGallop(list.docIds, position, docId)
			if position == len(list.docIds) {
				break
			}
			if list.docIds[position] == docId {
				kept = append(kept, docId)
			}
		}
		self.docIds = kept
	}
}

// Keeps only the documents other holds as well.
func (self *searchDocSet) intersectSet(other *searchDocSet) {
	if other.bitset != nil {
		self.intersect(&indexPostingList{bitset: other.bitset})
		return
	}
	self.intersect(&indexPostingList{docIds: other.docIds})
}

// Adds every document other holds, as a bitset where either is one.
func (self *searchDocSet) union(other *searchDocSet) {
	if self.bitset == nil && other.bitset == nil {
		merged := make([]uint32, 0, len(self.docIds)+len(other.docIds))
		left, right := self.docIds, other.docIds
		for 0 < len(left) || 0 < len(right) {
			switch {
			case len(right) == 0 || (0 < len(left) && left[0] < right[0]):
				merged, left = append(merged, left[0]), left[1:]
			case len(left) == 0 || right[0] < left[0]:
				merged, right = append(merged, right[0]), right[1:]
			default:
				merged, left, right = append(merged, left[0]), left[1:], right[1:]
			}
		}
		self.docIds = merged
		return
	}
	bitset := make([]byte, indexBitsetByteCount(self.documentCount))
	for _, set := range []*searchDocSet{self, other} {
		if set.bitset != nil {
			for index, b := range set.bitset {
				bitset[index] |= b
			}
			continue
		}
		for _, docId := range set.docIds {
			bitset[docId/8] |= 1 << (docId % 8)
		}
	}
	self.bitset, self.docIds = bitset, nil
}
