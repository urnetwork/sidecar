//go:build !js && !ios_extension

// The fuzz targets of D6's shard test and of a layout that always writes (DESIGN-DETAILS 11.6 and 1.6; QD-760,
// QD-775). Their seeds are f.Add calls and run in every go test, but not on js, where testing.F cannot open its corpus
// directory.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"slices"
	"testing"
)

// 11.6's FuzzIndexLoneShard: for any key set and row the codec accepts, under any header a decoder accepts and any
// version and time, lone(d) is at least 33 B above the length of the shard holding the document alone, and a document
// D6 keeps is never refused.
func FuzzIndexLoneShard(f *testing.F) {
	f.Add([]byte("abcdefghi"), uint16(36), uint32(20340), uint32(30), uint64(2), uint64(1), uint64(1800000000), false)
	f.Add(bytes.Repeat([]byte{0, 1, 0, 0, 1, 1, 0, 2, 0}, 30), uint16(2048), uint32(math.MaxUint32), uint32(math.MaxUint32), uint64(math.MaxUint64), uint64(math.MaxUint64), uint64(math.MaxUint64), false)
	f.Add([]byte{}, uint16(0), uint32(0), uint32(0), uint64(1), uint64(0), uint64(0), true)
	f.Fuzz(func(t *testing.T, keyBytes []byte, rowByteCount uint16, startDay uint32, days uint32, generation uint64, version uint64, timeSeconds uint64, all bool) {
		settings := DefaultIndexFormatSettings()
		keys := indexKeySet{}
		for index := 0; index+indexTrigramByteCount <= len(keyBytes); index += indexTrigramByteCount {
			keys = append(keys, uint32(keyBytes[index])<<16|uint32(keyBytes[index+1])<<8|uint32(keyBytes[index+2]))
		}
		slices.Sort(keys)
		keys = slices.Compact(keys)
		minimal := (&indexRow{docKind: indexDocRecord, trigramCount: uint64(len(keys))}).encodedByteCount()
		row := testRowOfByteCount(t, len(keys), max(minimal, min(int(rowByteCount), indexRowMaxByteCount)))
		header := indexNewFileHeader(indexFileBucketShard, testHeadTables)
		header.BucketStartDay, header.BucketDays = startDay, max(days, 1)
		if all {
			header = indexNewFileHeader(indexFileAllShard, testHeadTables)
		}
		header.PadGeneration = max(generation, 1)
		lone := indexLoneShardByteCount(row.encodedByteCount(), keys, settings)
		file, err := testLoneShard(t, header, keys, row, version, timeSeconds)
		switch {
		case errors.Is(err, errIndexShardFull):
			if lone <= indexShardMaxByteCount {
				t.Fatalf("a document of lone %d refused", lone)
			}
		case err != nil:
			t.Fatal(err)
		case lone-33 < len(file):
			t.Fatalf("a lone shard of %d B, lone %d", len(file), lone)
		}
	})
}

// 1.6's FuzzIndexLayoutWrites (QD-775), in FuzzIndexLayoutTakes's place: any shards a decoder accepts and any winners
// D6 kept, a seed choosing their shapes, small ones, random sets of up to 40,000 keys, and dense runs of up to 199,000
// keys near lone = ShardBody, with removals and newer versions of held documents among the winners: a layout returns no
// error, every shard it writes is within ShardBody before its pad, and each key stands once.
func FuzzIndexLayoutWrites(f *testing.F) {
	f.Add(int64(1), uint8(2), uint8(12), uint8(0))
	f.Add(int64(2), uint8(3), uint8(40), uint8(1))
	f.Add(int64(3), uint8(1), uint8(6), uint8(2))
	f.Fuzz(func(t *testing.T, seed int64, shardCount uint8, winnerCount uint8, shape uint8) {
		settings := DefaultIndexFormatSettings()
		window, root := testLayoutGround()
		random := rand.New(rand.NewSource(seed))
		documentOf := func(label string, index int) *indexShardDocument {
			var keys indexKeySet
			switch shape % 4 {
			case 1:
				keys = testRandomKeys(random, 1+random.Intn(40000), 0, indexKeyMax+1)
			case 2:
				keys = testIndexKeys(random.Intn(0x10000), 1+random.Intn(199000), 1)
			default:
				keys = testRandomKeys(random, 1+random.Intn(300), random.Intn(0x100000), 4096)
			}
			document := testLayoutDocument(testIndexId(label, index), keys)
			if indexDocumentSkipped(keys, document.row, settings) {
				return testLayoutDocument(testIndexId(label, index), keys[:1])
			}
			return document
		}
		layoutArgs := &indexLayoutArgs{root: root, fileType: indexFileBucketShard, window: window, padKey: testPadKey(t, 2), tables: testHeadTables, settings: settings}
		files := [][]byte{}
		held := []*indexShardDocument{}
		for n := range int(shardCount % 4) {
			entries := []*indexLayoutEntry{}
			for index := range 1 + random.Intn(8) {
				entries = append(entries, &indexLayoutEntry{document: documentOf(fmt.Sprintf("held %d", n), index)})
			}
			// a shard a decoder accepts: as much of what was drawn as fits the cap, by take's own search
			count, err := indexTake(layoutArgs, indexNewShardBuilder(false), &indexLayoutShard{}, entries)
			if err != nil || count == 0 {
				t.Fatal(count, err)
			}
			documents := []*indexShardDocument{}
			for _, entry := range entries[:count] {
				documents = append(documents, entry.document)
			}
			held = append(held, documents...)
			files = append(files, testBuildShard(t, &indexShard{header: testShardHeader(indexFileBucketShard), documents: documents}, false, testPadKey(t, 2)))
		}
		bucket, shards := testBucketOfShards(t, root, window, files...)
		extra := []*indexEntry{}
		taken := map[[indexIdByteCount]byte]bool{}
		for index := range int(winnerCount % 48) {
			if 0 < len(held) && random.Intn(3) == 0 {
				document := held[random.Intn(len(held))]
				if taken[document.key] {
					continue
				}
				taken[document.key] = true
				if random.Intn(2) == 0 {
					extra = append(extra, &indexEntry{kind: indexEntryTombstone, key: document.key, version: 2, timeSeconds: 1757400100})
				} else {
					newer := documentOf("newer", index)
					extra = append(extra, &indexEntry{kind: indexEntryFull, key: document.key, version: 2, timeSeconds: 1757400100, row: newer.row, keys: newer.keys})
				}
				continue
			}
			extra = append(extra, testLayoutEntries([]*indexShardDocument{documentOf("winner", index)})...)
		}
		result, err := testMergeShards(t, root, bucket, shards, extra...)
		if err != nil {
			t.Fatalf("a layout of %d shards and %d winners: %v", len(files), len(extra), err)
		}
		testShardsAfter(t, root, bucket, shards, result)
	})
}
