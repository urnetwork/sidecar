//go:build !sidecar_http

// The ?closure=1 bound a full shard must fit (§11.12), which host_quota_keys.go holds off the browser Worker's leg.

package sidecar

import (
	"bytes"
	"errors"
	"math/rand"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Shards near their cap: the largest a builder writes pads within 1 MiB, past the cap it answers errIndexShardFull,
// and a 1 MiB file in one record of one padded segment fits one ?closure=1 upload (§11.12's 1,088 KiB).
func TestFullShardFitsOneClosureUpload(t *testing.T) {
	random := rand.New(rand.NewSource(9))
	documents := []*indexShardDocument{}
	for index := range 120 {
		documents = append(documents, testShardDocument("full", index, indexDocFile, testRandomKeys(random, 2000, 0, indexKeyMax+1)))
	}
	builder := indexNewShardBuilder(false)
	keyCountFits := func(keyCount int) bool {
		trimmed := []*indexShardDocument{}
		for _, document := range documents {
			keys := document.keys[:min(keyCount, len(document.keys))]
			row := *document.row
			row.trigramCount = uint64(len(keys))
			trimmed = append(trimmed, &indexShardDocument{key: document.key, version: document.version, timeSeconds: document.timeSeconds, row: &row, keys: keys})
		}
		_, _, err := builder.encodeUnpadded(&indexShard{header: testShardHeader(indexFileAllShard), documents: trimmed})
		if err != nil && !errors.Is(err, errIndexShardFull) {
			t.Fatal(err)
		}
		return err == nil
	}
	low, high := 1, 2000
	if keyCountFits(high) {
		t.Fatal("the documents fit whole; give them more keys")
	}
	for low+1 < high {
		middle := (low + high) / 2
		if keyCountFits(middle) {
			low = middle
		} else {
			high = middle
		}
	}
	largest := []*indexShardDocument{}
	for _, document := range documents {
		keys := document.keys[:min(low, len(document.keys))]
		row := *document.row
		row.trigramCount = uint64(len(keys))
		largest = append(largest, &indexShardDocument{key: document.key, version: document.version, timeSeconds: document.timeSeconds, row: &row, keys: keys})
	}
	file := testBuildShard(t, &indexShard{header: testShardHeader(indexFileAllShard), documents: largest}, false, testPadKey(t, 2))
	if len(file) < indexShardMaxByteCount-64*1024 || indexShardPaddedMaxByteCount < len(file) {
		t.Fatalf("the largest shard is %d B", len(file))
	}
	if _, err := testDecodeShard(file, false); err != nil {
		t.Fatal(err)
	}

	keys := evsTestKeys(t, evsTestId("index repo"), 2)
	segment := &bytes.Buffer{}
	segmentBuilder, err := NewEvsSegmentBuilder(segment, keys.manifest, keys.fek)
	if err != nil {
		t.Fatal(err)
	}
	record, err := segmentBuilder.BeginRecord(evsTestId("shard"), evsTestHeader("shard", protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, indexShardPaddedMaxByteCount))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := record.Write(make([]byte, indexShardPaddedMaxByteCount)); err != nil {
		t.Fatal(err)
	}
	if err := record.Close(); err != nil {
		t.Fatal(err)
	}
	summary, err := segmentBuilder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	if QuotaClosureUploadMaxByteCount < summary.PaddedSize {
		t.Errorf("a 1 MiB index file's segment is %d B", summary.PaddedSize)
	}
}
