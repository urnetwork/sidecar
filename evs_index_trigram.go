// The trigram extractor (§11.14's trigrams row): every 3-byte window of normalized text, a document's set of distinct
// 24-bit keys. A key's bytes read in text order, so an aligned CJK character is one trigram and one- and two-character
// queries resolve.

package sidecar

import (
	"math/bits"
	"slices"
)

// One bit for every key there can be.
const indexTrigramWordCount = (indexKeyMax + 1) / 64

// The window ending at text[index], which must have two bytes before it.
func indexTrigramAt(text []byte, index int) uint32 {
	return uint32(text[index-2])<<16 | uint32(text[index-1])<<8 | uint32(text[index])
}

// The key set of a text held whole, as a query's term is. A document's goes through indexTrigramCollector, which
// holds no more for a long text than for a short one.
func indexTrigrams(text []byte) indexKeySet {
	keys := make(indexKeySet, 0, max(len(text)-2, 0))
	for index := 2; index < len(text); index += 1 {
		keys = append(keys, indexTrigramAt(text, index))
	}
	slices.Sort(keys)
	return slices.Compact(keys)
}

// Takes a document's text as it streams past, carrying a window across writes. Its memory is fixed at 2 MiB of bits,
// and at most 1 MiB saying which words a document touched, so the next document clears only those. Not safe for
// concurrent use.
type indexTrigramCollector struct {
	wordBits     []uint64
	touchedWords []uint32
	window       uint32
	byteCount    int
}

// Holds nothing yet.
func indexNewTrigramCollector() *indexTrigramCollector {
	return &indexTrigramCollector{wordBits: make([]uint64, indexTrigramWordCount)}
}

// Adds every window that ends in text. It never fails, which makes it a sink for a document's text.
func (self *indexTrigramCollector) Write(text []byte) (int, error) {
	for _, b := range text {
		self.window = (self.window<<8 | uint32(b)) & indexKeyMax
		self.byteCount += 1
		if self.byteCount < 3 {
			continue
		}
		word := self.window / 64
		if self.wordBits[word] == 0 {
			self.touchedWords = append(self.touchedWords, word)
		}
		self.wordBits[word] |= 1 << (self.window % 64)
	}
	return len(text), nil
}

// Every key so far, ascending.
func (self *indexTrigramCollector) keys() indexKeySet {
	slices.Sort(self.touchedWords)
	keys := indexKeySet{}
	for _, word := range self.touchedWords {
		for wordBits := self.wordBits[word]; wordBits != 0; wordBits &= wordBits - 1 {
			keys = append(keys, word*64+uint32(bits.TrailingZeros64(wordBits)))
		}
	}
	return keys
}

// Forgets the document, clearing only what it touched.
func (self *indexTrigramCollector) reset() {
	for _, word := range self.touchedWords {
		self.wordBits[word] = 0
	}
	self.touchedWords = self.touchedWords[:0]
	self.window = 0
	self.byteCount = 0
}
