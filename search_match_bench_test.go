// Posting lookups against §16.10's median (SEARCH-M10-23): a median query touches 374-73,000 postings, about a
// millisecond in wasm with frame decryption dominating. These match one full shard of mail-like documents natively;
// the wasm leg's run and the decrypting frame source are SEARCH-M10-40's benchmark rows.

package sidecar

import (
	"math/rand"
	"testing"
)

// A shard near its cap: documents of 120 words' worth of trigrams over a vocabulary, a few keys common to many.
func benchmarkMatchSource(b *testing.B) *searchPartitionSource {
	random := rand.New(rand.NewSource(1))
	documents := []*indexShardDocument{}
	for index := range 2500 {
		keys := testRandomKeys(random, 120, 0x616100, 6000)
		if index%3 == 0 {
			keys = indexSortedKeys(append(keys, 0x7a7a7a))
		}
		documents = append(documents, testShardDocument("bench", index, indexDocMail, keys))
	}
	reader, _ := testOpenShard(b, documents)
	return &searchPartitionSource{partition: searchPartitionCurrent, shards: []*searchShardSource{{n: 0, reader: reader}}}
}

// One rare word of three trigrams.
func BenchmarkSearchMatchRareWord(b *testing.B) {
	source := benchmarkMatchSource(b)
	query := testQueryOf([]indexKeySet{{0x616200, 0x616a00, 0x617000}})
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := searchMatch(&searchMatchArgs{query: query, source: source, maxCandidateCount: 20000}); err != nil {
			b.Fatal(err)
		}
	}
}

// Two words, one common, ANDed.
func BenchmarkSearchMatchCommonAndRare(b *testing.B) {
	source := benchmarkMatchSource(b)
	query := testQueryOf([]indexKeySet{{0x7a7a7a}}, []indexKeySet{{0x616300, 0x616400}})
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := searchMatch(&searchMatchArgs{query: query, source: source, maxCandidateCount: 20000}); err != nil {
			b.Fatal(err)
		}
	}
}
