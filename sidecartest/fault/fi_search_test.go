package fault

// FI-18's index clauses, FI-19, FI-20, FI-22, FI-23 and FI-24 (TEST-M10-02) on hand-built index histories and recorded
// searches, as fault.FI(n) after every step: a healthy history of writers, a merge, a roll-up, a CUT, its CLOSURE and
// its completion reads clean, and each mutant fails the invariant that names it, a posting left under a current key, a
// double roll-up, a re-encode that differs, a fetch that depends on the query, an early short reply and a sync before
// answering among them, with DESIGN-DETAILS 1.7's roll-up that drops a tombstone above a newer bucket's older entry and
// its companion push built from a pin read before the index. The oracle's codec is held first to testdata/index/'s
// vectors, the index's own bytes, which it reads and writes without the index's code. FI-18's search clauses and
// FI-21 run on the search world (fi_search_world_test.go), whose repo key a ledger needs.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A file vector's path, from its own header: what its bytes say they are, under a file-mode root or ur/index's.
func fiSearchVectorPath(t *testing.T, plaintext []byte, companion bool) string {
	t.Helper()
	reader := &oracleIndexReader{src: plaintext}
	reader.take(uint64(len(oracleIndexMagic)))
	headerBytes := reader.take(reader.vbyte())
	if reader.err != nil {
		t.Fatal(reader.err)
	}
	header := &protocol.IndexFileHeader{}
	if err := proto.Unmarshal(headerBytes, header); err != nil {
		t.Fatal(err)
	}
	root := ".ur-index/i1"
	if companion {
		root = "i1"
	}
	writer := hex.EncodeToString(header.WriterSidecarId)
	switch header.Type {
	case oracleIndexTypeSlot:
		return fmt.Sprintf("%s/b/%d/w/%s/%s/0", root, header.BucketStartDay, writer[:2], writer)
	case oracleIndexTypeLargeEntry:
		return fmt.Sprintf("%s/b/%d/w/%s/%s/L%d", root, header.BucketStartDay, writer[:2], writer, header.Seq)
	case oracleIndexTypeBucketShard:
		return fmt.Sprintf("%s/b/%d/s/0", root, header.BucketStartDay)
	}
	return root + "/a/0"
}

// Every whole slot, large entry, shard and head file testdata/index/ holds decodes by the oracle's own codec and
// encodes again to its bytes: the index's writers and the oracle read format 1 alike, with no code in common.
func TestFi22CodecReadsAndWritesTheIndexVectorsByteForByte(t *testing.T) {
	type vector struct {
		Name      string `json:"name"`
		Companion bool   `json:"companion"`
		Hex       string `json:"hex"`
		Sha256    string `json:"sha256"`
	}
	settings := DefaultOracleIndexFormatSettings()
	read := func(name string, path string, plaintext []byte) {
		file, err := oracleIndexDecode(path, plaintext, settings)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			return
		}
		again, err := oracleIndexEncode(file, settings)
		if err != nil || !bytes.Equal(again, plaintext) {
			t.Errorf("%s encodes again to other bytes: %v", name, err)
		}
	}
	whole := 0
	for _, name := range []string{"slot", "shard"} {
		encoded, err := os.ReadFile("../../testdata/index/" + name + "/vectors.json")
		if err != nil {
			t.Fatal(err)
		}
		vectors := []vector{}
		if err := json.Unmarshal(encoded, &vectors); err != nil {
			t.Fatal(err)
		}
		for _, vector := range vectors {
			plaintext, err := hex.DecodeString(vector.Hex)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(plaintext, []byte(oracleIndexMagic)) {
				// a table cut out of a shard, no file of its own
				continue
			}
			whole += 1
			read(name+"/"+vector.Name, fiSearchVectorPath(t, plaintext, vector.Companion), plaintext)
		}
	}
	encoded, err := os.ReadFile("../../testdata/index/head/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	heads := []struct {
		Name  string `json:"name"`
		Files []struct {
			Path string `json:"path"`
			Hex  string `json:"hex"`
		} `json:"files"`
	}{}
	if err := json.Unmarshal(encoded, &heads); err != nil {
		t.Fatal(err)
	}
	for _, head := range heads {
		for _, file := range head.Files {
			plaintext, err := hex.DecodeString(file.Hex)
			if err != nil {
				t.Fatal(err)
			}
			whole += 1
			read("head/"+head.Name+" "+file.Path, file.Path, plaintext)
		}
	}
	if whole < 20 {
		t.Errorf("%d whole files read", whole)
	}
}

// --- hand-built histories ---

// The writers and buckets of the hand-built histories.
var (
	fiSearchWriterA = [16]byte{0xa1, 1}
	fiSearchWriterB = [16]byte{0xb2, 2}
)

const (
	fiSearchBucket1 = 20340
	fiSearchBucket2 = 20370
)

func fiSearchDocKey(label string) [16]byte {
	digest := sha256.Sum256([]byte("fi search doc " + label))
	return [16]byte(digest[:16])
}

// A full entry of label's document at version: its row a file's, its keys its text's distinct 3-byte windows.
func fiSearchFull(label string, version uint64, text string) *oracleIndexEntry {
	keySet := map[uint32]bool{}
	for index := 0; index+3 <= len(text); index += 1 {
		keySet[uint32(text[index])<<16|uint32(text[index+1])<<8|uint32(text[index+2])] = true
	}
	keys := []uint32{}
	for key := range keySet {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	row := &oracleIndexRow{docKind: oracleIndexDocFile, size: uint64(len(text)), trigrams: uint64(len(keys)), locator: label}
	row.fields[4] = label
	return &oracleIndexEntry{kind: oracleIndexEntryFull, key: fiSearchDocKey(label), version: version, timeSeconds: 1_757_000_000 + version, row: row, keys: keys}
}

func fiSearchTombstone(label string, version uint64) *oracleIndexEntry {
	return &oracleIndexEntry{kind: oracleIndexEntryTombstone, key: fiSearchDocKey(label), version: version, timeSeconds: 1_757_000_000 + version}
}

func fiSearchFileHeader(fileType uint32, bucket uint32, writer [16]byte, seq uint32) *protocol.IndexFileHeader {
	header := &protocol.IndexFileHeader{
		Format: oracleIndexFormatVersion, Type: fileType, Normalizer: oracleIndexNormalizer, Extractor: oracleIndexExtractor,
		UnicodeVersion: "17.0.0", TextModuleVersion: "v0.43.0",
	}
	switch fileType {
	case oracleIndexTypeSlot, oracleIndexTypeLargeEntry:
		header.BucketStartDay = bucket
		header.BucketDays = 30
		header.WriterSidecarId = writer[:]
		header.Seq = seq
	case oracleIndexTypeBucketShard:
		header.BucketStartDay = bucket
		header.BucketDays = 30
		header.PadGeneration = 1
	case oracleIndexTypeAllShard:
		header.PadGeneration = 1
	}
	return header
}

func fiSearchSlotPath(bucket uint32, writer [16]byte, slot uint32) string {
	text := hex.EncodeToString(writer[:])
	return fmt.Sprintf(".ur-index/i1/b/%d/w/%s/%s/%d", bucket, text[:2], text, slot)
}

func fiSearchShardPath(bucket uint32, n uint32) string {
	return fmt.Sprintf(".ur-index/i1/b/%d/s/%d", bucket, n)
}

func fiSearchManifestPath(bucket uint32) string {
	return fmt.Sprintf(".ur-index/i1/b/%d/m", bucket)
}

const (
	fiSearchAllShard    = ".ur-index/i1/a/0"
	fiSearchAllManifest = ".ur-index/i1/a/m"
	fiSearchErasureSet  = ".ur-index/x"
)

// A hand-built index ref: its pushes, each at the next ref version, each file at its path's next version.
type fiSearchIndex struct {
	t *testing.T

	stateLock    sync.Mutex
	pushes       []*SearchIndexPush
	refVersion   uint64
	pathVersions map[string]uint64
	plaintexts   map[string][]byte
}

func newFiSearchIndex(t *testing.T) *fiSearchIndex {
	return &fiSearchIndex{t: t, pathVersions: map[string]uint64{}, plaintexts: map[string][]byte{}}
}

func (self *fiSearchIndex) Name() string {
	return "the hand-built ref"
}

func (self *fiSearchIndex) IndexPushes(ctx context.Context) ([]*SearchIndexPush, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.pushes), nil
}

// One file to write: its path and what it holds.
type fiSearchWrite struct {
	path string
	file *oracleIndexFile
	// the bytes as given, in place of the file's canonical encoding
	plaintext []byte
}

func fiSearchSlot(bucket uint32, writer [16]byte, slot uint32, seq uint32, entries ...*oracleIndexEntry) *fiSearchWrite {
	path := fiSearchSlotPath(bucket, writer, slot)
	parsed, _ := oracleIndexParsePath(path, DefaultOracleIndexFormatSettings())
	return &fiSearchWrite{path: path, file: &oracleIndexFile{path: parsed, header: fiSearchFileHeader(oracleIndexTypeSlot, bucket, writer, seq), entries: entries}}
}

func fiSearchShard(path string, entries ...*oracleIndexEntry) *fiSearchWrite {
	parsed, _ := oracleIndexParsePath(path, DefaultOracleIndexFormatSettings())
	fileType := uint32(oracleIndexTypeBucketShard)
	if parsed.kind == oracleIndexPathAllShard {
		fileType = oracleIndexTypeAllShard
	}
	file := &oracleIndexFile{path: parsed, header: fiSearchFileHeader(fileType, parsed.bucket, [16]byte{}, 0)}
	for _, entry := range entries {
		if entry.live() {
			file.documents = append(file.documents, entry)
		} else {
			file.tombstones = append(file.tombstones, entry)
		}
	}
	slices.SortFunc(file.documents, func(a *oracleIndexEntry, b *oracleIndexEntry) int { return bytes.Compare(a.key[:], b.key[:]) })
	slices.SortFunc(file.tombstones, oracleIndexCompareTombstones)
	return &fiSearchWrite{path: path, file: file}
}

func fiSearchManifest(bucket uint32, shards ...uint32) *fiSearchWrite {
	manifest := &protocol.IndexManifest{StartDay: bucket, Days: 30}
	for _, n := range shards {
		manifest.Shards = append(manifest.Shards, &protocol.IndexShard{N: n})
	}
	path := fiSearchManifestPath(bucket)
	parsed, _ := oracleIndexParsePath(path, DefaultOracleIndexFormatSettings())
	return &fiSearchWrite{path: path, file: &oracleIndexFile{path: parsed, manifest: manifest}}
}

func fiSearchAll(rolledThroughDay uint32, shards ...uint32) *fiSearchWrite {
	manifest := &protocol.IndexManifest{RolledThroughDay: rolledThroughDay}
	for _, n := range shards {
		manifest.Shards = append(manifest.Shards, &protocol.IndexShard{N: n})
	}
	parsed, _ := oracleIndexParsePath(fiSearchAllManifest, DefaultOracleIndexFormatSettings())
	return &fiSearchWrite{path: fiSearchAllManifest, file: &oracleIndexFile{path: parsed, manifest: manifest}}
}

// The erasure set listing each erasure id's documents through their versions.
func fiSearchErasures(erasures map[string]map[string]uint64) *fiSearchWrite {
	set := &protocol.IndexErasureSet{}
	for _, id := range slices.Sorted(func(yield func(string) bool) {
		for id := range erasures {
			if !yield(id) {
				return
			}
		}
	}) {
		erasureId := sha256.Sum256([]byte("fi search erasure " + id))
		erasure := &protocol.IndexErasure{ErasureId: erasureId[:16], EraserSidecarId: fiSearchWriterA[:], Epoch: 1}
		for label, version := range erasures[id] {
			docKey := fiSearchDocKey(label)
			erasure.Docs = append(erasure.Docs, &protocol.IndexErased{DocKey: docKey[:], Version: version})
		}
		slices.SortFunc(erasure.Docs, func(a *protocol.IndexErased, b *protocol.IndexErased) int { return bytes.Compare(a.DocKey, b.DocKey) })
		set.Erasures = append(set.Erasures, erasure)
	}
	slices.SortFunc(set.Erasures, func(a *protocol.IndexErasure, b *protocol.IndexErasure) int {
		return bytes.Compare(a.ErasureId, b.ErasureId)
	})
	parsed, _ := oracleIndexParsePath(fiSearchErasureSet, DefaultOracleIndexFormatSettings())
	return &fiSearchWrite{path: fiSearchErasureSet, file: &oracleIndexFile{path: parsed, erasureSet: set}}
}

// Commits a push of kind writing writes and removing removed, each written file encoded canonically unless its bytes
// are given, a CLOSURE's padded to the length it replaces.
func (self *fiSearchIndex) push(kind SearchIndexPushKind, writes []*fiSearchWrite, removed ...string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refVersion += 1
	push := &SearchIndexPush{RefVersion: self.refVersion, SignerId: sidecar.Id(fiSearchWriterA), SignedTime: time.Unix(1_757_000_000, 0).Add(time.Duration(self.refVersion) * time.Hour), Kind: kind, Removed: removed}
	for _, write := range writes {
		plaintext := write.plaintext
		if plaintext == nil {
			var err error
			plaintext, err = oracleIndexEncode(write.file, DefaultOracleIndexFormatSettings())
			if err != nil {
				self.t.Fatal(err)
			}
			if replaced, ok := self.plaintexts[write.path]; ok && kind == SearchIndexPushClosure && len(plaintext) < len(replaced) {
				write.file.padByteCount = len(replaced) - len(plaintext)
				plaintext = append(plaintext, make([]byte, write.file.padByteCount)...)
			}
		}
		self.pathVersions[write.path] += 1
		self.plaintexts[write.path] = plaintext
		digest := sha256.Sum256(plaintext)
		push.Written = append(push.Written, &SearchIndexFile{Path: write.path, Version: self.pathVersions[write.path], Plaintext: plaintext, ContentSha256: digest[:]})
	}
	for _, path := range removed {
		delete(self.plaintexts, path)
	}
	self.pushes = append(self.pushes, push)
}

// One step of a hand-built history.
type fiSearchStep func(index *fiSearchIndex)

// The healthy history: two writers' heads in a bucket, a merge, an edit and a removal in the next bucket, the first
// bucket's roll-up into all, a CUT erasing one document, its CLOSURE, and the CUT that drops it complete.
func fiSearchHealthy() []fiSearchStep {
	return []fiSearchStep{
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{
				fiSearchSlot(fiSearchBucket1, fiSearchWriterA, 0, 1, fiSearchFull("d1", 1, "harbor at noon"), fiSearchFull("d2", 1, "a lighthouse")),
				fiSearchManifest(fiSearchBucket1),
			})
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchSlot(fiSearchBucket1, fiSearchWriterB, 0, 1, fiSearchFull("d3", 1, "keeper's log"))})
		},
		func(index *fiSearchIndex) {
			manifest := fiSearchManifest(fiSearchBucket1, 0)
			manifest.file.manifest.Absorbed = []*protocol.IndexWatermark{{WriterSidecarId: fiSearchWriterA[:], Seq: 1}, {WriterSidecarId: fiSearchWriterB[:], Seq: 1}}
			index.push(SearchIndexPushIndex, []*fiSearchWrite{
				fiSearchShard(fiSearchShardPath(fiSearchBucket1, 0), fiSearchFull("d1", 1, "harbor at noon"), fiSearchFull("d2", 1, "a lighthouse"), fiSearchFull("d3", 1, "keeper's log")),
				manifest,
			})
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{
				fiSearchSlot(fiSearchBucket2, fiSearchWriterA, 0, 2, fiSearchFull("d1", 2, "harbor at dusk"), fiSearchTombstone("d2", 2)),
				fiSearchManifest(fiSearchBucket2),
			})
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchShard(fiSearchAllShard, fiSearchFull("d3", 1, "keeper's log")), fiSearchAll(fiSearchBucket1, 0)},
				fiSearchManifestPath(fiSearchBucket1), fiSearchShardPath(fiSearchBucket1, 0), fiSearchSlotPath(fiSearchBucket1, fiSearchWriterA, 0), fiSearchSlotPath(fiSearchBucket1, fiSearchWriterB, 0))
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushCut, []*fiSearchWrite{fiSearchErasures(map[string]map[string]uint64{"e1": {"d3": 1}})})
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushClosure, []*fiSearchWrite{fiSearchShard(fiSearchAllShard)})
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushCut, []*fiSearchWrite{fiSearchErasures(map[string]map[string]uint64{})})
		},
	}
}

// Runs steps as one schedule, each a step of its own, and checks every invariant named after each.
func fiSearchRun(t *testing.T, steps []fiSearchStep, invariants ...int) *Result {
	index := newFiSearchIndex(t)
	schedule := &Schedule{Id: "fi-search-hand"}
	schedule.Steps = append(schedule.Steps, &Step{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
		SearchRecordOf(net).AddIndex(index)
		return nil
	}})
	for _, step := range steps {
		schedule.Steps = append(schedule.Steps, &Step{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
			step(index)
			return nil
		}})
	}
	for _, n := range invariants {
		schedule.Check = append(schedule.Check, FI(n))
	}
	return runFresh(t, schedule)
}

func TestFiSearchReadsAHealthyIndexHistoryClean(t *testing.T) {
	wantPass(t, fiSearchRun(t, fiSearchHealthy(), 18, 19, 20, 22))
}

// A posting left under a current key: the erasure completes with its CLOSURE skipped, so all's shard still holds the
// erased document's postings and row.
func TestFi19CatchesAPostingLeftUnderACurrentKey(t *testing.T) {
	steps := fiSearchHealthy()
	steps = append(steps[:6], steps[7])
	result := fiSearchRun(t, steps, 19)
	wantFailure(t, result, "is complete and .ur-index/i1/a/0 still holds")
}

// An index push prepared before the CUT, landing after it, with the erased document's entry.
func TestFi19CatchesAPushAfterTheCutHoldingAnErasedDocument(t *testing.T) {
	steps := fiSearchHealthy()
	late := func(index *fiSearchIndex) {
		index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchSlot(fiSearchBucket2, fiSearchWriterB, 0, 1, fiSearchFull("d3", 1, "keeper's log"))})
	}
	steps = slices.Concat(steps[:6], []fiSearchStep{late}, steps[6:])
	wantFailure(t, fiSearchRun(t, steps, 19), "which erasure")
}

// A double roll-up: a second runner commits its roll-up of the first bucket after the first's, through the same day.
func TestFi20CatchesADoubleRollUp(t *testing.T) {
	steps := fiSearchHealthy()[:5]
	steps = append(steps, func(index *fiSearchIndex) {
		index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchShard(fiSearchAllShard, fiSearchFull("d3", 1, "keeper's log")), fiSearchAll(fiSearchBucket1, 0)})
	})
	wantFailure(t, fiSearchRun(t, steps, 20), "a second roll-up")
}

// A roll-up that leaves a file of the bucket it rolls, and one that drops a live entry no newer bucket supersedes.
func TestFi20CatchesARollUpThatKeepsABucketFileOrDropsALiveEntry(t *testing.T) {
	steps := fiSearchHealthy()[:4]
	keeps := append(slices.Clone(steps), func(index *fiSearchIndex) {
		index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchShard(fiSearchAllShard, fiSearchFull("d3", 1, "keeper's log")), fiSearchAll(fiSearchBucket1, 0)},
			fiSearchManifestPath(fiSearchBucket1), fiSearchShardPath(fiSearchBucket1, 0), fiSearchSlotPath(fiSearchBucket1, fiSearchWriterA, 0))
	})
	wantFailure(t, fiSearchRun(t, keeps, 20), "a file of bucket")
	drops := append(slices.Clone(steps), func(index *fiSearchIndex) {
		index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchShard(fiSearchAllShard), fiSearchAll(fiSearchBucket1)},
			fiSearchManifestPath(fiSearchBucket1), fiSearchShardPath(fiSearchBucket1, 0), fiSearchSlotPath(fiSearchBucket1, fiSearchWriterA, 0), fiSearchSlotPath(fiSearchBucket1, fiSearchWriterB, 0))
	})
	result := fiSearchRun(t, drops, 18, 20)
	wantFailure(t, result, "in neither all nor a newer bucket")
	wantFailure(t, result, "reads absent where its newest committed entry is live at 1")
}

// The history DESIGN-DETAILS 1.7's roll-up mutant needs: d4 deleted at 3 in the first bucket, and a late entry of its
// older version 2 in the second bucket.
func fiSearchLateEntry() []fiSearchStep {
	return []fiSearchStep{
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchSlot(fiSearchBucket1, fiSearchWriterA, 0, 1, fiSearchTombstone("d4", 3)), fiSearchManifest(fiSearchBucket1)})
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchSlot(fiSearchBucket2, fiSearchWriterB, 0, 1, fiSearchFull("d4", 2, "an older draft")), fiSearchManifest(fiSearchBucket2)})
		},
	}
}

// The roll-up promotes the tombstone into the newer bucket's shards, and the history reads clean.
func TestFiSearchReadsARollUpThatPromotesATombstoneClean(t *testing.T) {
	steps := append(fiSearchLateEntry(), func(index *fiSearchIndex) {
		index.push(SearchIndexPushIndex, []*fiSearchWrite{
			fiSearchShard(fiSearchShardPath(fiSearchBucket2, 0), fiSearchTombstone("d4", 3)), fiSearchManifest(fiSearchBucket2, 0), fiSearchAll(fiSearchBucket1),
		}, fiSearchManifestPath(fiSearchBucket1), fiSearchSlotPath(fiSearchBucket1, fiSearchWriterA, 0))
	})
	wantPass(t, fiSearchRun(t, steps, 18, 20, 22))
}

// A roll-up that drops a tombstone above an older entry of a newer bucket (DESIGN-DETAILS 1.7; IndexMerge's NoPromote):
// the deleted document comes back at its older version.
func TestFiSearchCatchesARollUpThatDropsATombstoneAboveANewerBucketsOlderEntry(t *testing.T) {
	steps := append(fiSearchLateEntry(), func(index *fiSearchIndex) {
		index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchAll(fiSearchBucket1)}, fiSearchManifestPath(fiSearchBucket1), fiSearchSlotPath(fiSearchBucket1, fiSearchWriterA, 0))
	})
	result := fiSearchRun(t, steps, 18, 20)
	wantFailure(t, result, "drops doc_key")
	wantFailure(t, result, "reads live at 2 where its newest committed entry is deleted at 3")
}

// A companion push built from a pin read before the index (DESIGN-DETAILS 1.7; I5): d5's tombstone left with its
// bucket's roll-up, and a stale entry of its older version lands after, bringing the deleted document back.
func TestFi18CatchesAnEntryLandingBelowAVersionARollUpDropped(t *testing.T) {
	steps := []fiSearchStep{
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchSlot(fiSearchBucket1, fiSearchWriterA, 0, 1, fiSearchTombstone("d5", 2)), fiSearchManifest(fiSearchBucket1)})
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchAll(fiSearchBucket1)}, fiSearchManifestPath(fiSearchBucket1), fiSearchSlotPath(fiSearchBucket1, fiSearchWriterA, 0))
		},
	}
	wantPass(t, fiSearchRun(t, steps, 18, 20))
	stale := append(slices.Clone(steps), func(index *fiSearchIndex) {
		index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchSlot(fiSearchBucket2, fiSearchWriterB, 0, 1, fiSearchFull("d5", 1, "the first draft")), fiSearchManifest(fiSearchBucket2)})
	})
	wantFailure(t, fiSearchRun(t, stale, 18), "reads live at 1 where its newest committed entry is deleted at 2")
}

// A slot reused before a merge absorbed it: the entry it held is gone from every file, and its document reads older.
func TestFi18CatchesASlotReusedUnabsorbed(t *testing.T) {
	steps := fiSearchHealthy()[:2]
	steps = append(steps, func(index *fiSearchIndex) {
		index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchSlot(fiSearchBucket1, fiSearchWriterB, 0, 2, fiSearchFull("d6", 1, "another note"))})
	})
	wantFailure(t, fiSearchRun(t, steps, 18), "reads absent where its newest committed entry is live at 1")
}

// I4: all's row of a key newer than its newest bucket entry, which a device keeping only the buckets would show older.
func TestFi18CatchesAnAllRowNewerThanItsBucketEntry(t *testing.T) {
	steps := []fiSearchStep{
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchShard(fiSearchAllShard, fiSearchFull("d7", 3, "the newest text")), fiSearchAll(fiSearchBucket1, 0)})
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchSlot(fiSearchBucket2, fiSearchWriterA, 0, 1, fiSearchFull("d7", 2, "an older text")), fiSearchManifest(fiSearchBucket2)})
		},
	}
	wantFailure(t, fiSearchRun(t, steps, 18), "(I4)")
}

// With full entries only (QD-1036) no entry rests on another, so a merge's removal of a large entry it absorbed leaves
// every document's view as it stood: DESIGN-DETAILS 1.7's mutant "a merge that removes a large entry a head rests on"
// has nothing left to break, and the oracle reads the removal clean.
func TestFi18ReadsAnAbsorbedLargeEntryRemovedClean(t *testing.T) {
	// printable bytes from a fixed generator: some 6,000 distinct windows, an entry past a slot's 8,192 B
	text := make([]byte, 6000)
	state := uint32(1)
	for index := range text {
		state = state*1664525 + 1013904223
		text[index] = byte(0x20 + (state>>24)%95)
	}
	large := fiSearchFull("d8", 1, string(text))
	largePath := strings.Replace(fiSearchSlotPath(fiSearchBucket1, fiSearchWriterA, 0), "/0", "/L1", 1)
	steps := []fiSearchStep{
		func(index *fiSearchIndex) {
			parsed, ok := oracleIndexParsePath(largePath, DefaultOracleIndexFormatSettings())
			if !ok {
				index.t.Fatal(largePath)
			}
			index.push(SearchIndexPushIndex, []*fiSearchWrite{
				{path: largePath, file: &oracleIndexFile{path: parsed, header: fiSearchFileHeader(oracleIndexTypeLargeEntry, fiSearchBucket1, fiSearchWriterA, 1), entries: []*oracleIndexEntry{large}}},
				fiSearchSlot(fiSearchBucket1, fiSearchWriterA, 0, 2),
				fiSearchManifest(fiSearchBucket1),
			})
		},
		func(index *fiSearchIndex) {
			index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchShard(fiSearchShardPath(fiSearchBucket1, 0), large), fiSearchManifest(fiSearchBucket1, 0)}, largePath)
		},
	}
	wantPass(t, fiSearchRun(t, steps, 18, 22))
}

// A re-encode that differs: a merge's shard blocked by ones, which encodes again from its own partition but is not the
// 64-key blocking a merge writes; a pad byte that is not zero; and a content_sha256 that is not the plaintext's.
func TestFi22CatchesAReEncodeThatDiffers(t *testing.T) {
	blocked := func(index *fiSearchIndex) {
		shard := fiSearchShard(fiSearchShardPath(fiSearchBucket1, 0), fiSearchFull("d1", 1, "harbor at noon"))
		shard.file.blockKeyCounts = slices.Repeat([]int{1}, len(shard.file.documents[0].keys))
		index.push(SearchIndexPushIndex, []*fiSearchWrite{shard, fiSearchManifest(fiSearchBucket1, 0)})
	}
	wantFailure(t, fiSearchRun(t, []fiSearchStep{blocked}, 22), "blocks its keys by")

	padded := func(index *fiSearchIndex) {
		slot := fiSearchSlot(fiSearchBucket1, fiSearchWriterA, 0, 1, fiSearchFull("d1", 1, "harbor at noon"))
		plaintext, err := oracleIndexEncode(slot.file, DefaultOracleIndexFormatSettings())
		if err != nil {
			index.t.Fatal(err)
		}
		slot.plaintext = append(plaintext, 0, 7)
		index.push(SearchIndexPushIndex, []*fiSearchWrite{slot})
	}
	result := fiSearchRun(t, []fiSearchStep{padded}, 18, 22)
	wantFailure(t, result, "a pad byte that is not zero")
	wantFailure(t, result, "which the oracle cannot read")

	unsorted := func(index *fiSearchIndex) {
		manifest := fiSearchManifest(fiSearchBucket1, 3, 1)
		plaintext, err := proto.MarshalOptions{Deterministic: true}.Marshal(manifest.file.manifest)
		if err != nil {
			index.t.Fatal(err)
		}
		manifest.plaintext = plaintext
		index.push(SearchIndexPushIndex, []*fiSearchWrite{manifest})
	}
	wantFailure(t, fiSearchRun(t, []fiSearchStep{unsorted}, 22), "lists shards out of order")

	misHashed := func(index *fiSearchIndex) {
		index.push(SearchIndexPushIndex, []*fiSearchWrite{fiSearchSlot(fiSearchBucket1, fiSearchWriterA, 0, 1, fiSearchFull("d1", 1, "harbor at noon"))})
		index.stateLock.Lock()
		defer index.stateLock.Unlock()
		index.pushes[len(index.pushes)-1].Written[0].ContentSha256 = bytes.Repeat([]byte{1}, 32)
	}
	wantFailure(t, fiSearchRun(t, []fiSearchStep{misHashed}, 22), "content_sha256 is not its plaintext's")
}

// An entry of the reserved kind 2, a diff's until owner decision 584, is refused as any unknown kind is (QD-1036).
func TestFi22RefusesAnEntryOfTheReservedDiffKind(t *testing.T) {
	diff := func(index *fiSearchIndex) {
		entry := fiSearchFull("d1", 1, "harbor at noon")
		slot := fiSearchSlot(fiSearchBucket1, fiSearchWriterA, 0, 1, entry)
		plaintext, err := oracleIndexEncode(slot.file, DefaultOracleIndexFormatSettings())
		if err != nil {
			index.t.Fatal(err)
		}
		at := bytes.Index(plaintext, append([]byte{oracleIndexEntryFull}, entry.key[:]...))
		if at < 0 {
			index.t.Fatal("no entry")
		}
		plaintext[at] = 2
		slot.plaintext = plaintext
		index.push(SearchIndexPushIndex, []*fiSearchWrite{slot})
	}
	wantFailure(t, fiSearchRun(t, []fiSearchStep{diff}, 22), "an entry of kind 2")
}

// A search recorded with only its fetches and requests: what FI-23 compares.
func fiSearchFetches(label string, state string, fetches []string, requests []string) *SearchRun {
	return &SearchRun{Label: label, SyncState: state, Fetches: fetches, Requests: requests}
}

func fiSearchRecordRun(t *testing.T, invariant int, record func(net *Net)) *Result {
	return runFresh(t, &Schedule{
		Id:    "fi-search-records",
		Steps: []*Step{{Actor: "device", Action: func(ctx context.Context, net *Net) error { record(net); return nil }}},
		Check: []Invariant{FI(invariant)},
	})
}

// A fetch that depends on the query: two searches from one sync state, the second reading one more all shard.
func TestFi23CatchesAFetchThatDependsOnTheQuery(t *testing.T) {
	fetches := []string{".ur-index/i1/b/20340/s/0@3", ".ur-index/i1/a/m@2"}
	healthy := func(net *Net) {
		record := SearchRecordOf(net)
		record.RecordSearch(fiSearchFetches("ios32 query a", "index@7 phone", fetches, nil))
		record.RecordSearch(fiSearchFetches("ios32 query b", "index@7 phone", fetches, nil))
		// another state compares only with itself
		record.RecordSearch(fiSearchFetches("ios32 query c", "index@8 phone", fetches[:1], nil))
	}
	wantPass(t, fiSearchRecordRun(t, 23, healthy))
	leaky := func(net *Net) {
		record := SearchRecordOf(net)
		record.RecordSearch(fiSearchFetches("ios32 query a", "index@7 phone", fetches, nil))
		record.RecordSearch(fiSearchFetches("ios32 query b", "index@7 phone", append(slices.Clone(fetches), ".ur-index/i1/a/3@1"), nil))
	}
	wantFailure(t, fiSearchRecordRun(t, 23, leaky), "differ at request 2")
	requests := func(net *Net) {
		record := SearchRecordOf(net)
		record.RecordSearch(fiSearchFetches("worker query a", "index@7 worker", nil, []string{"evs1 GET /evs/read 0"}))
		record.RecordSearch(fiSearchFetches("worker query b", "index@7 worker", nil, []string{"evs1 GET /evs/read 0", "evs1 GET /evs/read 0"}))
	}
	wantFailure(t, fiSearchRecordRun(t, 23, requests), "requests:")
	stateless := func(net *Net) {
		SearchRecordOf(net).RecordSearch(fiSearchFetches("no state", "", fetches, nil))
	}
	wantFailure(t, fiSearchRecordRun(t, 23, stateless), "names no sync state")
}

// A remote search as the rule lets it run: one step, a 4,016 B request and a 16,384 B reply, both devices quiet.
func fiSearchRemote(label string, query string) *RemoteSearchRun {
	indexerId := sidecar.Id{9}
	repoId := sidecar.Id{7}
	return &RemoteSearchRun{
		Label: label, Query: query, IndexerId: indexerId, EligibleIndexerIds: []sidecar.Id{indexerId},
		NamedRepoIds: []sidecar.Id{repoId}, RequesterRepoIds: []sidecar.Id{repoId}, IndexerRepoIds: []sidecar.Id{repoId},
		Hits:  []sidecar.SearchHit{{Repo: repoId, Path: "notes/harbor-at-noon.md", State: sidecar.SearchPossible}},
		Steps: 1, RequestByteCounts: []int{4016}, ReplyByteCounts: []int{16384},
		Frames:            &sidecartest.FrameSizeTrace{Label: label, Kind: "1 step", Requests: []int{4096}, Replies: []int{16464}},
		RequesterRequests: []string{}, IndexerRequests: []string{},
		Stored: [][]byte{[]byte("sealed bytes of no meaning")},
	}
}

func TestFi24ReadsRemoteSearchesOfOneKindClean(t *testing.T) {
	wantPass(t, fiSearchRecordRun(t, 24, func(net *Net) {
		record := SearchRecordOf(net)
		record.RecordRemoteSearch(fiSearchRemote("query a", "harbor-canary-query-a"))
		record.RecordRemoteSearch(fiSearchRemote("query b", "lighthouse-canary-query-b"))
	}))
}

// An early short reply: a failure after parsing answered in fewer bytes than its step, which the relay also sees.
func TestFi24CatchesAnEarlyShortReply(t *testing.T) {
	result := fiSearchRecordRun(t, 24, func(net *Net) {
		record := SearchRecordOf(net)
		record.RecordRemoteSearch(fiSearchRemote("query a", "harbor-canary-query-a"))
		short := fiSearchRemote("a post-parse failure", "lighthouse-canary-query-b")
		short.ReplyByteCounts = []int{80}
		short.Frames.Replies = []int{160}
		record.RecordRemoteSearch(short)
	})
	wantFailure(t, result, "a reply of 80 B for 1 steps, not 16384")
	wantFailure(t, result, "reply frames differ at frame 0")
}

// A sync before answering: the indexer reads evs while the search runs.
func TestFi24CatchesASyncBeforeAnswering(t *testing.T) {
	wantFailure(t, fiSearchRecordRun(t, 24, func(net *Net) {
		synced := fiSearchRemote("query a", "harbor-canary-query-a")
		synced.IndexerRequests = []string{"evs1 GET /evs/head?ref=r1 0"}
		SearchRecordOf(net).RecordRemoteSearch(synced)
	}), "the indexer asked \"evs1 GET")
}

// The rule's other clauses: an indexer the rule did not allow, another member's before its notice, an owner-bound repo
// to a device its owner did not consent, a hit from a repo the request did not name, and the query stored.
func TestFi24CatchesAQueryLeavingForAnIndexerTheRuleRefuses(t *testing.T) {
	for _, mutant := range []struct {
		want   string
		mutate func(run *RemoteSearchRun)
	}{
		{"which the rule did not let answer", func(run *RemoteSearchRun) { run.EligibleIndexerIds = []sidecar.Id{{8}} }},
		{"before that member's notice", func(run *RemoteSearchRun) { run.OtherMember = true }},
		{"to a device its owner did not consent", func(run *RemoteSearchRun) {
			run.OwnerBoundRepoDeviceIds = map[sidecar.Id][]sidecar.Id{{7}: {{6}}}
		}},
		{"which the request did not name", func(run *RemoteSearchRun) { run.Hits[0].Repo = sidecar.Id{5} }},
		{"stored the query or a hit", func(run *RemoteSearchRun) { run.Stored = append(run.Stored, []byte("cache: harbor-canary-query-a")) }},
		{"the served record names", func(run *RemoteSearchRun) { run.ServedRecord = []byte("served notes/harbor-at-noon.md") }},
		{"a request body of 4100 B", func(run *RemoteSearchRun) { run.RequestByteCounts = []int{4100} }},
	} {
		result := fiSearchRecordRun(t, 24, func(net *Net) {
			run := fiSearchRemote("query a", "harbor-canary-query-a")
			mutant.mutate(run)
			SearchRecordOf(net).RecordRemoteSearch(run)
		})
		if result.Err == nil || !strings.Contains(result.Err.Error(), mutant.want) {
			t.Errorf("want %q: %v", mutant.want, result.Err)
		}
	}
}

// Every search invariant is bound, and a source that cannot be read fails each that reads the index.
func TestFiSearchInvariantsAreBoundAndAnUnreadableSourceFailsClosed(t *testing.T) {
	built := BuiltInvariants()
	for n := 18; n <= 24; n += 1 {
		if !slices.Contains(built, n) {
			t.Errorf("FI-%d is not bound", n)
		}
	}
	result := runFresh(t, &Schedule{
		Id: "fi-search-unreadable",
		Steps: []*Step{{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
			SearchRecordOf(net).AddIndex(&fiSearchFailing{})
			return nil
		}}},
		Check: []Invariant{FI(18), FI(19), FI(20), FI(22)},
	})
	for _, id := range []string{"FI-18", "FI-19", "FI-20", "FI-22"} {
		if result.Err == nil || !strings.Contains(result.Err.Error(), id) || !errors.Is(result.Err, errFiSearchFailing) {
			t.Errorf("%s: %v", id, result.Err)
		}
	}
}

var errFiSearchFailing = errors.New("the source is down")

type fiSearchFailing struct{}

func (self *fiSearchFailing) Name() string {
	return "a failing ref"
}

func (self *fiSearchFailing) IndexPushes(ctx context.Context) ([]*SearchIndexPush, error) {
	return nil, errFiSearchFailing
}
