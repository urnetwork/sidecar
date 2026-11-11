//go:build !js

// §22.6's Index files target for shards, their doc and tombstone tables, and the small files: decoding is total and
// bounded, the streaming walk a phone runs and the whole decode a writer runs agree on every input, and whatever
// decodes re-encodes to the bytes it came from. Non-minimal VByte, unsorted or repeated keys and docids, bitsets off
// their threshold, a key in both of a shard's tables and a tombstone in an all shard sit in the seeds in
// testdata/fuzz/, which run in every go test.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Seeds this target must hold: the vectors' shards under their own root and the other, and every hand-built bad
// shard but the two a megabyte long, which TestShardRefusals keeps.
func testShardSeeds(t testing.TB) map[string][]byte {
	seeds := map[string][]byte{}
	for _, c := range testShardCases(t) {
		if c.name != "probe-rewrite" {
			seeds["good-"+c.name] = c.file
		}
	}
	for name, file := range testBadShards(t) {
		if len(file) < 64*1024 {
			seeds["bad-"+name] = file
		}
	}
	return seeds
}

// Seeds for the small files: each kind's good bytes, and ones close to canonical.
func testSmallFileSeeds(t testing.TB) map[string][]byte {
	marshal := func(message proto.Message) []byte {
		encoded, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	writer := testIndexIdBytes("writer", 1)
	return map[string][]byte{
		"settings":        marshal(&protocol.IndexSettings{Off: true, WindowDays: 90}),
		"lock":            marshal(&protocol.IndexLock{HolderSidecarId: writer, BucketStartDay: 20310, UntilMs: 1800000000000}),
		"bucket-manifest": marshal(&protocol.IndexManifest{StartDay: 20340, Days: 30, Shards: []*protocol.IndexShard{{N: 0, Docs: 4}, {N: 2, Docs: 9}}, Absorbed: []*protocol.IndexWatermark{{WriterSidecarId: writer, Seq: 3}}}),
		"all-manifest":    marshal(&protocol.IndexManifest{Shards: []*protocol.IndexShard{{N: 0, Docs: 4, FirstDay: 20000, LastDay: 20100}}, RolledThroughDay: 20310}),
		"erasure-set":     marshal(&protocol.IndexErasureSet{ListedSince: 2, Erasures: []*protocol.IndexErasure{{ErasureId: writer, EraserSidecarId: writer, Epoch: 3, Docs: []*protocol.IndexErased{{DocKey: writer, Version: 4}}}}}),
		"shards-unsorted": marshal(&protocol.IndexManifest{Shards: []*protocol.IndexShard{{N: 2}, {N: 0}}}),
		"unknown-field":   testWithUnknownField(marshal(&protocol.IndexSettings{WindowDays: 90})),
	}
}

func TestShardSeedFilesAreCurrent(t *testing.T) {
	for name, file := range testShardSeeds(t) {
		for _, companion := range []bool{false, true} {
			testCheckCorpusFile(t, "FuzzIndexShard", fmt.Sprintf("%s-%t", name, companion), fmt.Sprintf("[]byte(%q)", file), fmt.Sprintf("bool(%t)", companion))
		}
	}
	for name, file := range testSmallFileSeeds(t) {
		testCheckCorpusFile(t, "FuzzIndexSmallFile", name, fmt.Sprintf("[]byte(%q)", file))
	}
}

func FuzzIndexShard(f *testing.F) {
	f.Fuzz(func(t *testing.T, file []byte, companion bool) {
		reader, walkErr := indexOpenShard(indexBytesFrames(file), companion)
		if walkErr == nil {
			walkErr = reader.walk(indexShardVisitor{})
		}
		sum := sha256.Sum256(file)
		shard, err := indexDecodeShard(file, sum[:], companion)
		if (walkErr == nil) != (err == nil) {
			t.Fatalf("the walk answered %v and the whole decode %v", walkErr, err)
		}
		if err != nil {
			if !errors.Is(err, errIndexMalformed) && !errors.Is(err, errIndexNewerFormat) {
				t.Fatalf("a refusal that is no index refusal: %v", err)
			}
			return
		}
		again, err := indexNewShardBuilder(companion).encode(shard)
		if err != nil {
			t.Fatalf("what decoded does not encode: %v", err)
		}
		if !bytes.Equal(again, file) {
			t.Fatalf("re-encoding changed the bytes")
		}
		// Every key the documents hold is found by its block and lists them.
		for docId, document := range shard.documents {
			for _, key := range document.keys {
				location, ok, err := reader.lookup(key)
				if err != nil || !ok {
					t.Fatalf("key %06x of docid %d not found: %v", key, docId, err)
				}
				list, err := reader.list(location)
				if err != nil || !list.contains(uint32(docId)) {
					t.Fatalf("key %06x's list lacks docid %d: %v", key, docId, err)
				}
			}
		}
	})
}

func FuzzIndexSmallFile(f *testing.F) {
	f.Fuzz(func(t *testing.T, file []byte) {
		decoders := []func() (proto.Message, error){
			func() (proto.Message, error) { return indexDecodeSettings(file) },
			func() (proto.Message, error) { return indexDecodeLock(file) },
			func() (proto.Message, error) { return indexDecodeManifest(file, false) },
			func() (proto.Message, error) { return indexDecodeManifest(file, true) },
			func() (proto.Message, error) { return indexDecodeErasureSet(file, DefaultIndexFormatSettings()) },
		}
		for _, decode := range decoders {
			message, err := decode()
			if err != nil {
				if !errors.Is(err, errIndexMalformed) {
					t.Fatalf("a refusal that is no index refusal: %v", err)
				}
				continue
			}
			again, err := indexMarshalSmall(message)
			if err != nil || !bytes.Equal(again, file) {
				t.Fatalf("re-marshaling changed the bytes: %v", err)
			}
		}
	})
}
