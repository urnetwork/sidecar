// Bucket merges (SEARCH-M10-10; DESIGN-DETAILS 1.2.4 and 1.6): a sealed diff composed onto its writer's kept slot and
// onto a large entry, the tie order at one version, tombstones over rows and their survival past a slot's reuse, a ref
// tombstone taking its ref's older rows, the erasure set's documents left out, take at the cap against an exhaustive
// count and the shard opened after it, a join, a manifest-only merge, a push past DirectBytes merging its own entries,
// two mergers racing, a head push landing between a merge's build and its commit, reruns after 409 and INDEX_EPOCH,
// an input collected, the expiry and due rules, a forged diff with no base, and 1.6's merge vectors with their
// plaintext hashes, all on the fake store.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

const testMergeVectorPath = "testdata/index/merge/vectors.json"

// The head world's time as a clock: each commit through the world moves it a minute.
type testIndexWorldClock struct {
	world *testHeadWorld
}

func (self *testIndexWorldClock) Now() time.Time {
	return self.world.at
}

func (self *testIndexWorldClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.world.at
	return fired
}

func (self *testIndexWorldClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// A merger of the world's ref, signing as signer, on the world's clock and settings.
func (self *testHeadWorld) merger(t testing.TB, signer Id) *IndexMerger {
	t.Helper()
	return self.mergerOf(t, self.ref.store(signer))
}

// A merger reading and writing through store.
func (self *testHeadWorld) mergerOf(t testing.TB, store indexRefStore) *IndexMerger {
	t.Helper()
	merger, err := indexNewMerger(&indexMergerArgs{
		store:    store,
		repoId:   evsTestId("view repo"),
		refId:    evsTestId("view ref"),
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL,
		format:   self.settings,
		padKey: func(ctx context.Context) (*indexPadKey, error) {
			return testPadKey(t, 2), nil
		},
		tables: testHeadTables,
		clock:  &testIndexWorldClock{world: self},
	})
	if err != nil {
		t.Fatal(err)
	}
	return merger
}

// Merges the newest bucket, failing on any error or a merge that commits nothing.
func (self *testHeadWorld) merge(t testing.TB, signer Id) *indexMergeOutcome {
	t.Helper()
	view := self.view(t, signer)
	outcome, err := self.merger(t, signer).Merge(context.Background(), indexRootNumber, view.writeRoot().newestBucket().window.startDay)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.committed == nil {
		t.Fatalf("a merge that committed nothing: skipped %d", outcome.skipped)
	}
	return outcome
}

// The newest bucket's shards' rows and tombstones by key, as a reader of the head decodes them.
type testMergedBucket struct {
	bucket     *indexViewBucket
	shards     []*indexShard
	documents  map[[indexIdByteCount]byte]*indexShardDocument
	tombstones map[[indexIdByteCount]byte]*indexShardTombstone
}

func (self *testHeadWorld) mergedBucket(t testing.TB) *testMergedBucket {
	t.Helper()
	view := self.view(t, evsTestId("reader"))
	bucket := view.writeRoot().newestBucket()
	shards, err := indexDecodeBucketShards(context.Background(), view, bucket.shards)
	if err != nil {
		t.Fatal(err)
	}
	merged := &testMergedBucket{bucket: bucket, shards: shards, documents: map[[indexIdByteCount]byte]*indexShardDocument{}, tombstones: map[[indexIdByteCount]byte]*indexShardTombstone{}}
	for _, shard := range shards {
		for _, document := range shard.documents {
			if merged.documents[document.key] != nil {
				t.Fatalf("a document in two shards of one bucket")
			}
			merged.documents[document.key] = document
		}
		for _, tombstone := range shard.tombstones {
			merged.tombstones[tombstone.key] = tombstone
		}
	}
	return merged
}

// Fails unless no file the push wrote or removed is a writer's.
func testNoWriterFile(t testing.TB, result *indexMergeResult) {
	t.Helper()
	for _, file := range result.files() {
		if path, _ := indexParsePath(file.path, false); path.kind == indexPathSlot || path.kind == indexPathLargeEntry {
			t.Fatalf("a merge wrote a writer's file")
		}
	}
	for _, removal := range result.removedShards {
		if path, _ := indexParsePath(removal.path, false); path.kind != indexPathBucketShard {
			t.Fatalf("a merge removed a file that is no shard")
		}
	}
}

// A sealed diff composes onto its writer's kept slot, and another onto a large entry: the shard rows hold the composed
// key sets, the watermark is the highest sealed seq read and never the head's, the head and every writer file stay,
// and the push names no writer's file. A merge of nothing more then commits nothing.
func TestIndexMergeComposesSealedDiffs(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	index := world.fillUntilSealed(t, a, "f", 0)
	large := testIndexKeys(0, 9000, 3)
	world.push(t, a, testLive("d", 2, 1, 0, large))
	largeEdit := slices.Clone(large)
	largeEdit[10] += 1
	plan := world.push(t, a, testLive("d", 1, 2, 1, testHeadKeys(1, 1)), testLive("d", 2, 2, 1, largeEdit))
	for _, entry := range plan.buckets[0].head.slot.entries {
		if (entry.key == testIndexId("d", 1) || entry.key == testIndexId("d", 2)) && entry.kind != indexEntryDiff {
			t.Fatalf("an edit of a sealed or large base written %d", entry.kind)
		}
	}
	world.fillUntilSealed(t, a, "g", index)
	before := world.writer(t, a)
	head := before.head()

	outcome := world.merge(t, evsTestId("merger"))
	testNoWriterFile(t, outcome.result)
	merged := world.mergedBucket(t)
	if got := merged.documents[testIndexId("d", 1)]; got == nil || got.version != 2 || !slices.Equal(got.keys, testHeadKeys(1, 1)) {
		t.Fatalf("the slot diff did not compose: %+v", got)
	}
	if got := merged.documents[testIndexId("d", 2)]; got == nil || got.version != 2 || !slices.Equal(got.keys, largeEdit) {
		t.Fatalf("the large entry's diff did not compose")
	}
	highestSealed := uint32(0)
	for _, file := range slices.Concat(before.slots, before.large) {
		if file != head {
			highestSealed = max(highestSealed, file.seq())
		}
	}
	if seq := merged.bucket.absorbedSeq(a); seq != highestSealed || head.seq() <= seq {
		t.Fatalf("watermark %d for a highest sealed seq %d under a head at %d", seq, highestSealed, head.seq())
	}
	after := world.writer(t, a)
	if len(after.slots) != len(before.slots) || len(after.large) != len(before.large) || after.head().file.version != head.file.version {
		t.Fatalf("a merge changed a writer's files")
	}

	again, err := world.merger(t, evsTestId("merger")).Merge(context.Background(), indexRootNumber, merged.bucket.window.startDay)
	if err != nil || again.committed != nil || again.skipped != indexMergeSkipNothing {
		t.Fatalf("a merge of nothing new: %+v %v", again, err)
	}
}

// At one version a tombstone wins, then the shards' own entry, then the full entry of the lowest writer_sidecar_id:
// two writers' copies of one version with different rows give the lower writer's row; a third writer's copies of what
// the shard already holds, a sealed slot of nothing else, change no shard, so the push writes the manifest alone and
// its watermark.
func TestIndexMergeTieOrder(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	if 0 < a.Cmp(b) {
		a, b = b, a
	}
	keys := testHeadKeys(4, 0)
	other := testLive("d", 4, 3, 0, keys)
	other.row = testFileRow(keys)
	other.row.locator = "notes/other.md"
	other.row.fit()
	world.push(t, b, other)
	world.fillUntilSealed(t, b, "fb", 0)
	world.push(t, a, testLive("d", 4, 3, 0, keys))
	world.fillUntilSealed(t, a, "fa", 0)
	world.merge(t, evsTestId("merger"))
	merged := world.mergedBucket(t)
	shared := merged.documents[testIndexId("d", 4)]
	if shared == nil || shared.row.locator != "notes/plan.md" {
		t.Fatalf("the tie went past the lowest writer: %+v", shared)
	}

	c := evsTestId("writer c")
	world.push(t, c, testLive("d", 4, 3, 0, keys))
	world.fillUntilSealed(t, c, "fa", 0)
	outcome := world.merge(t, evsTestId("merger"))
	if len(outcome.result.shards) != 0 || len(outcome.result.removedShards) != 0 {
		t.Fatalf("copies of the shard's own entries rewrote %d shards", len(outcome.result.shards))
	}
	merged = world.mergedBucket(t)
	if got := merged.documents[testIndexId("d", 4)]; got == nil || got.timeSeconds != shared.timeSeconds {
		t.Fatal("a writer's copy replaced the shard's own at one version")
	}
	if merged.bucket.absorbedSeq(c) == 0 {
		t.Fatal("a manifest-only merge raised no watermark")
	}
}

// FS-108's merge clauses: a tombstone over a shard row takes the row out and enters the tombstone table; the writer
// reuses the absorbed slot that held it and the tombstone stays in the shard; a newer live version over the tombstone
// replaces it in turn.
func TestIndexMergeTombstones(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 5, 1, 0, testHeadKeys(5, 0)))
	index := world.fillUntilSealed(t, a, "f", 0)
	world.merge(t, evsTestId("merger"))
	if world.mergedBucket(t).documents[testIndexId("d", 5)] == nil {
		t.Fatal("the row was not merged")
	}
	world.push(t, a, testRemoved("d", 5, 2))
	index = world.fillUntilSealed(t, a, "f", index)
	world.merge(t, evsTestId("merger"))
	merged := world.mergedBucket(t)
	if merged.documents[testIndexId("d", 5)] != nil {
		t.Fatal("a row survived its tombstone")
	}
	if got := merged.tombstones[testIndexId("d", 5)]; got == nil || got.version != 2 || got.kind != indexEntryTombstone {
		t.Fatalf("the tombstone did not enter the table: %+v", got)
	}
	// the slot holding the tombstone is absorbed: the writer's next seals reuse it, and the tombstone stays
	for range 3 {
		index = world.fillUntilSealed(t, a, "f", index)
	}
	merged = world.mergedBucket(t)
	if got := merged.tombstones[testIndexId("d", 5)]; got == nil || got.version != 2 {
		t.Fatal("the tombstone went with its slot's reuse")
	}
	world.push(t, a, testLive("d", 5, 3, 0, testHeadKeys(5, 1)))
	world.fillUntilSealed(t, a, "f", index)
	world.merge(t, evsTestId("merger"))
	merged = world.mergedBucket(t)
	if merged.tombstones[testIndexId("d", 5)] != nil || merged.documents[testIndexId("d", 5)] == nil || merged.documents[testIndexId("d", 5)].version != 3 {
		t.Fatal("a newer version did not replace the tombstone")
	}
}

// A companion row's file at one ref, keyed by label.
func testCompanionRow(keys indexKeySet, refIndex int) *indexRow {
	row := testFileRow(keys)
	row.refId = testIndexIdBytes("ref", refIndex)
	return row
}

// A view of a companion bucket built by hand: shard rows of two refs, and a writer's sealed slot holding a ref
// tombstone of the first.
func testCompanionMergeArgs(t testing.TB) *indexMergeArgs {
	t.Helper()
	window := indexBucketWindow{startDay: 20340, days: 30}
	root := &indexViewRoot{number: indexRootNumber, paths: indexNewPaths(true, indexRootNumber)}
	row := func(label string, index int, version uint64, refIndex int) *indexShardDocument {
		keys := testHeadKeys(index, 0)
		return &indexShardDocument{key: testIndexId(label, index), version: version, timeSeconds: 1757400000, row: testCompanionRow(keys, refIndex), keys: keys}
	}
	shard := &indexShard{
		header:    testShardHeader(indexFileBucketShard),
		documents: []*indexShardDocument{row("c", 1, 3, 1), row("c", 2, 8, 1), row("c", 3, 3, 2)},
	}
	file := testBuildShard(t, shard, true, testPadKey(t, 2))
	shardPath, _ := indexParsePath(root.paths.bucketShard(window.startDay, 0), true)
	decoded, err := testDecodeShard(file, true)
	if err != nil {
		t.Fatal(err)
	}
	writer := evsTestId("writer a")
	slotPath, _ := indexParsePath(func() string {
		path, _ := root.paths.slot(window.startDay, [indexIdByteCount]byte(writer), 0)
		return path
	}(), true)
	headPath, _ := indexParsePath(func() string {
		path, _ := root.paths.slot(window.startDay, [indexIdByteCount]byte(writer), 1)
		return path
	}(), true)
	refTombstone := &indexEntry{kind: indexEntryRefTombstone, key: testIndexId("ref", 1), version: 5, timeSeconds: 1757400100}
	sealed := &indexViewSlot{
		file: &indexFileVersion{path: slotPath.String(), version: 4, signerSidecarId: writer, byteCount: 100},
		path: slotPath,
		slot: &indexSlot{header: &protocol.IndexFileHeader{Seq: 1}, entries: []*indexEntry{refTombstone}},
	}
	head := &indexViewSlot{
		file: &indexFileVersion{path: headPath.String(), version: 5, signerSidecarId: writer, byteCount: 100},
		path: headPath,
		slot: &indexSlot{header: &protocol.IndexFileHeader{Seq: 2}},
	}
	manifest := &protocol.IndexManifest{StartDay: window.startDay, Days: window.days, Shards: []*protocol.IndexShard{{N: 0, Docs: 3}}}
	bucket := &indexViewBucket{
		window:       window,
		manifest:     manifest,
		manifestFile: &indexFileVersion{path: root.paths.bucketManifest(window.startDay), version: 2},
		shards:       []*indexViewShard{{file: &indexFileVersion{path: shardPath.String(), version: 3, byteCount: len(file)}, path: shardPath, decoded: decoded}},
		writers:      []*indexViewWriter{{sidecarId: writer, slots: []*indexViewSlot{sealed, head}}},
	}
	return &indexMergeArgs{
		root:      root,
		bucket:    bucket,
		shards:    []*indexShard{decoded},
		absorb:    true,
		padKey:    testPadKey(t, 2),
		tables:    testHeadTables,
		companion: true,
		settings:  DefaultIndexFormatSettings(),
	}
}

// On ur/index the newest ref tombstone stays in the tombstone table and takes every row of its ref below its version:
// the first ref's row at 3 goes, its row at 8 stays, and the second ref's row at 3 stays.
func TestIndexMergeRefTombstone(t *testing.T) {
	args := testCompanionMergeArgs(t)
	result, err := indexMerge(args)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.shards) != 1 {
		t.Fatalf("%d shards written", len(result.shards))
	}
	sum := sha256.Sum256(result.shards[0].file)
	shard, err := indexDecodeShard(result.shards[0].file, sum[:], true)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for _, document := range shard.documents {
		switch document.key {
		case testIndexId("c", 1):
			keys = append(keys, "c1")
		case testIndexId("c", 2):
			keys = append(keys, "c2")
		case testIndexId("c", 3):
			keys = append(keys, "c3")
		}
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"c2", "c3"}) {
		t.Fatalf("rows after the ref tombstone: %v", keys)
	}
	if len(shard.tombstones) != 1 || shard.tombstones[0].kind != indexEntryRefTombstone || shard.tombstones[0].version != 5 {
		t.Fatalf("the ref tombstone did not enter the table: %+v", shard.tombstones)
	}
	if result.writtenManifest.Absorbed[0].Seq != 1 {
		t.Fatalf("the watermark took the head's seq")
	}
}

// Every entry the erasure set lists at or below its version is left out first: the listed document's shard row and
// its sealed newer copy both go, a diff resting on a listed base goes with no alarm, and an unlisted document stays.
func TestIndexMergeLeavesOutErased(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("e", 1, 1, 0, testHeadKeys(1, 0)), testLive("e", 2, 1, 0, testHeadKeys(2, 0)))
	index := world.fillUntilSealed(t, a, "f", 0)
	world.merge(t, evsTestId("merger"))
	world.push(t, a, testLive("e", 1, 2, 1, testHeadKeys(1, 1)), testLive("e", 3, 1, 0, testHeadKeys(3, 0)))
	world.fillUntilSealed(t, a, "f", index)
	erasureSet := &protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{{
		ErasureId:       testIndexIdBytes("erasure", 1),
		EraserSidecarId: evsTestId("eraser").Bytes(),
		Docs:            []*protocol.IndexErased{{DocKey: testIndexIdBytes("e", 1), Version: 2}},
	}}}
	file, err := indexEncodeErasureSet(erasureSet, world.settings)
	if err != nil {
		t.Fatal(err)
	}
	eraser := world.ref.store(evsTestId("eraser"))
	eraser.testCommit(t, world.at, &indexPushFile{path: indexErasureSetPath(false), plaintext: file})
	outcome := world.merge(t, evsTestId("merger"))
	if len(outcome.events) != 0 {
		t.Fatalf("an erased document alarmed: %+v", outcome.events)
	}
	merged := world.mergedBucket(t)
	if merged.documents[testIndexId("e", 1)] != nil || merged.tombstones[testIndexId("e", 1)] != nil {
		t.Fatal("a listed document stayed in the shards")
	}
	if merged.documents[testIndexId("e", 2)] == nil || merged.documents[testIndexId("e", 3)] == nil {
		t.Fatal("an unlisted document went")
	}
}

// take at the cap (1.2.4): the youngest shard takes the count the search finds, which no larger count beats, the next
// shard opens at n + 1 with the rest, and two shards that come to fewer than ShardJoinByteCount join under the lower n.
func TestIndexMergeTakeAtTheCap(t *testing.T) {
	window := indexBucketWindow{startDay: 20340, days: 30}
	root := &indexViewRoot{number: indexRootNumber, paths: indexNewPaths(false, indexRootNumber)}
	settings := DefaultIndexFormatSettings()
	extra := []*indexEntry{}
	for index := range 400 {
		keys := testIndexKeys(index*0x2000, 700, 3)
		extra = append(extra, &indexEntry{kind: indexEntryFull, key: testIndexId("cap", index), version: 1, timeSeconds: 1757400000, row: testFileRow(keys), keys: keys})
	}
	args := &indexMergeArgs{root: root, bucket: &indexViewBucket{window: window}, extra: extra, padKey: testPadKey(t, 2), tables: testHeadTables, settings: settings}
	result, err := indexMerge(args)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.writtenManifest.Shards) < 2 {
		t.Fatalf("%d shards for past one shard's worth", len(result.writtenManifest.Shards))
	}
	first := result.writtenManifest.Shards[0]
	// the count the search found is the largest prefix that fits, as an exhaustive walk from it confirms
	builder := indexNewShardBuilder(false)
	layoutArgs := &indexLayoutArgs{root: root, fileType: indexFileBucketShard, window: window, padKey: args.padKey, tables: args.tables, settings: settings}
	sorted := slices.Clone(extra)
	slices.SortFunc(sorted, func(a *indexEntry, b *indexEntry) int { return compareIndexKeys(a.key, b.key) })
	prefix := func(count int) []*indexShardDocument {
		documents := []*indexShardDocument{}
		for _, entry := range sorted[:count] {
			documents = append(documents, &indexShardDocument{key: entry.key, version: entry.version, timeSeconds: entry.timeSeconds, row: entry.row, keys: entry.keys})
		}
		return documents
	}
	if _, err := layoutArgs.unpadded(builder, prefix(int(first.Docs)), nil); err != nil {
		t.Fatalf("the youngest shard's take does not fit: %v", err)
	}
	if _, err := layoutArgs.unpadded(builder, prefix(int(first.Docs)+1), nil); !errors.Is(err, errIndexShardFull) {
		t.Fatalf("take stopped short of the cap: %v", err)
	}
	if result.writtenManifest.Shards[1].N != 1 {
		t.Fatalf("the next shard opened at %d", result.writtenManifest.Shards[1].N)
	}

	// two small shards join: a bucket with shards 0 and 3 of a few documents each becomes one shard 0
	small := func(n uint32, label string) (*indexViewShard, *indexShard) {
		shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: testShardDocuments(int64(n), label, 4, indexDocFile)}
		file := testBuildShard(t, shard, false, testPadKey(t, 2))
		decoded, err := testDecodeShard(file, false)
		if err != nil {
			t.Fatal(err)
		}
		path, _ := indexParsePath(root.paths.bucketShard(window.startDay, n), false)
		return &indexViewShard{file: &indexFileVersion{path: path.String(), version: uint64(n) + 1, byteCount: len(file)}, path: path, decoded: decoded}, decoded
	}
	zero, zeroDecoded := small(0, "j0")
	three, threeDecoded := small(3, "j3")
	joined, err := indexMerge(&indexMergeArgs{
		root:   root,
		bucket: &indexViewBucket{window: window, manifest: &protocol.IndexManifest{StartDay: window.startDay, Days: window.days}, shards: []*indexViewShard{zero, three}},
		shards: []*indexShard{zeroDecoded, threeDecoded},
		padKey: testPadKey(t, 2), tables: testHeadTables, settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(joined.writtenManifest.Shards) != 1 || joined.writtenManifest.Shards[0].N != 0 || joined.writtenManifest.Shards[0].Docs != 8 {
		t.Fatalf("the shards did not join under the lower n: %+v", joined.writtenManifest.Shards)
	}
	if len(joined.removedShards) != 1 || joined.removedShards[0].path != three.path.String() {
		t.Fatalf("the joined shard was not removed: %+v", joined.removedShards)
	}
}

// A push past DirectBytes merges its own entries as extra without absorbing: its documents land in the shards, its
// head is written without them, every watermark stands, and the sealed slots it does not absorb stay for a merge.
func TestIndexMergeHeadPlanPastDirectBytes(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("h", 1, 1, 0, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "f", 0)
	pending := []*indexPendingDocument{testLive("h", 1, 2, 0, testHeadKeys(1, 3))}
	for bulk := range 40 {
		pending = append(pending, testLive("bulk", bulk, 1, 0, testIndexKeys(bulk*0x10000, 7000, 1)))
	}
	plan, view := world.plan(t, a, true, pending...)
	if !plan.mergeInPush {
		t.Fatal("the push did not pass DirectBytes")
	}
	root := view.writeRoot()
	files, removals, malformed, err := indexMergeHeadPlan(context.Background(), view, root, plan, testPadKey(t, 2), testHeadTables)
	if err != nil || len(malformed) != 0 {
		t.Fatal(err, malformed)
	}
	_, err = world.ref.store(a).Commit(context.Background(), &indexPush{pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: world.at.UnixMilli(), files: files, removals: removals})
	if err != nil {
		t.Fatal(err)
	}
	merged := world.mergedBucket(t)
	if len(merged.documents) != 41 || merged.documents[testIndexId("h", 1)].version != 2 {
		t.Fatalf("%d documents merged in the push", len(merged.documents))
	}
	if merged.bucket.manifest == nil || len(merged.bucket.manifest.Absorbed) != 0 {
		t.Fatal("a push merging its own entries absorbed a slot")
	}
	head := world.writer(t, a).head()
	for _, entry := range head.slot.entries {
		if entry.key == testIndexId("h", 1) {
			t.Fatal("the head kept an entry the push merged")
		}
	}
	// the sealed slot it left holds h1 at 1, below the shard's 2, and a merge drops it
	world.merge(t, evsTestId("merger"))
	if got := world.mergedBucket(t).documents[testIndexId("h", 1)]; got.version != 2 {
		t.Fatalf("a sealed older entry won over the merged one: %d", got.version)
	}
}

// FS-74's two mergers: built on one base they write equal plaintext; one commits, the other gets 409, and the
// runner's rerun on the new state finds nothing left and commits nothing.
func TestIndexMergersRace(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("r", 1, 1, 0, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "f", 0)
	build := func(signer Id) (*indexMergeResult, *indexView) {
		view := world.view(t, signer)
		root := view.writeRoot()
		bucket := root.newestBucket()
		shards, err := indexDecodeBucketShards(context.Background(), view, bucket.shards)
		if err != nil {
			t.Fatal(err)
		}
		result, err := indexMerge(&indexMergeArgs{root: root, bucket: bucket, shards: shards, absorb: true, erased: view.erased, padKey: testPadKey(t, 2), tables: testHeadTables, companion: false, settings: view.settings})
		if err != nil {
			t.Fatal(err)
		}
		return result, view
	}
	first, firstView := build(evsTestId("merger one"))
	second, secondView := build(evsTestId("merger two"))
	firstFiles, secondFiles := first.files(), second.files()
	if len(firstFiles) != len(secondFiles) {
		t.Fatal("two mergers built different pushes")
	}
	for index := range firstFiles {
		if firstFiles[index].path != secondFiles[index].path || sha256.Sum256(firstFiles[index].plaintext) != sha256.Sum256(secondFiles[index].plaintext) {
			t.Fatal("two mergers built different plaintext")
		}
	}
	commit := func(signer Id, result *indexMergeResult, view *indexView) error {
		_, err := world.ref.store(signer).Commit(context.Background(), &indexPush{pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: world.at.UnixMilli(), files: result.files(), removals: result.removedShards})
		return err
	}
	if err := commit(evsTestId("merger one"), first, firstView); err != nil {
		t.Fatal(err)
	}
	if err := commit(evsTestId("merger two"), second, secondView); !isIndexRefusal(err, indexRefusalConflict) {
		t.Fatalf("the second merger was not refused: %v", err)
	}

	// through the runner: the other merger lands inside its first attempt, and its rerun finds nothing left
	world.fillUntilSealed(t, a, "g", 100)
	other := world.merger(t, evsTestId("merger one"))
	runner := world.merger(t, evsTestId("merger two"))
	startDay := world.view(t, a).writeRoot().newestBucket().window.startDay
	raced := false
	world.ref.beforeCommit = func(push *indexPush) {
		if raced {
			return
		}
		raced = true
		if _, err := other.Merge(context.Background(), indexRootNumber, startDay); err != nil {
			t.Error(err)
		}
	}
	outcome, err := runner.Merge(context.Background(), indexRootNumber, startDay)
	world.ref.beforeCommit = nil
	if err != nil {
		t.Fatal(err)
	}
	if outcome.committed != nil || outcome.skipped != indexMergeSkipNothing || outcome.attempts != 2 {
		t.Fatalf("the beaten merger: committed %v, skipped %d, attempts %d", outcome.committed != nil, outcome.skipped, outcome.attempts)
	}
}

// A head push landing between a merge's build and its commit: both commit, the push's diff still finds its base in
// the slot the merge absorbed, which its writer now keeps, and the head the push sealed is not absorbed (FS-107's
// merge based before a composed diff's push and committing after it).
func TestIndexMergeHeadPushBetweenBuildAndCommit(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("p", 1, 1, 0, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "f", 0)
	baseSlot := world.writer(t, a).slotAt(0)
	merger := world.merger(t, evsTestId("merger"))
	startDay := world.view(t, a).writeRoot().newestBucket().window.startDay
	landed := false
	world.ref.beforeCommit = func(push *indexPush) {
		if landed || len(push.files) == 0 || !slices.ContainsFunc(push.files, func(file *indexPushFile) bool {
			path, _ := indexParsePath(file.path, false)
			return path.kind == indexPathBucketManifest
		}) {
			return
		}
		landed = true
		world.ref.beforeCommit = nil
		world.push(t, a, testLive("p", 1, 2, 1, testHeadKeys(1, 1)))
	}
	outcome, err := merger.Merge(context.Background(), indexRootNumber, startDay)
	world.ref.beforeCommit = nil
	if err != nil || outcome.committed == nil || !landed {
		t.Fatalf("committed %v, landed %v: %v", outcome != nil && outcome.committed != nil, landed, err)
	}
	writer := world.writer(t, a)
	bucket := world.mergedBucket(t).bucket
	absorbed := bucket.absorbedSeq(a)
	if writer.head().seq() <= absorbed {
		t.Fatal("the head the push wrote is absorbed")
	}
	kept := writer.kept(absorbed, nil)
	base := writer.slotAt(0)
	if base == nil || base.file.version != baseSlot.file.version || !kept[base] {
		t.Fatal("the diff's base is not kept in its slot")
	}
	if file, entry := indexResolveBase(writer, testIndexId("p", 1), 1, writer.head()); file != base || entry == nil {
		t.Fatal("the diff does not resolve from its base")
	}
}

// 409 INDEX_EPOCH reruns the merge, which then commits; a store's 429 and a quota refusal come back unsent again; an
// input collected under the build restarts it on the head.
func TestIndexMergeReruns(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("q", 1, 1, 0, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "f", 0)
	startDay := world.view(t, a).writeRoot().newestBucket().window.startDay

	world.ref.refuseNext(&indexRefusal{kind: indexRefusalRetry, retryAfter: time.Second}, false)
	if _, err := world.merger(t, evsTestId("merger")).Merge(context.Background(), indexRootNumber, startDay); !isIndexRefusal(err, indexRefusalRetry) {
		t.Fatalf("a 429 came back as %v", err)
	}
	world.ref.refuseNext(&indexRefusal{kind: indexRefusalQuota}, false)
	if _, err := world.merger(t, evsTestId("merger")).Merge(context.Background(), indexRootNumber, startDay); !isIndexRefusal(err, indexRefusalQuota) {
		t.Fatalf("a quota refusal came back as %v", err)
	}
	world.ref.refuseNext(&indexRefusal{kind: indexRefusalIndexEpoch}, false)
	outcome, err := world.merger(t, evsTestId("merger")).Merge(context.Background(), indexRootNumber, startDay)
	if err != nil || outcome.committed == nil || outcome.attempts != 2 {
		t.Fatalf("INDEX_EPOCH: %v after %d attempts", err, outcome.attempts)
	}

	world.fillUntilSealed(t, a, "g", 100)
	collecting := &testCollectingStore{indexRefStore: world.ref.store(evsTestId("merger"))}
	outcome, err = world.mergerOf(t, collecting).Merge(context.Background(), indexRootNumber, startDay)
	if err != nil || outcome.committed == nil || outcome.attempts != 2 || !collecting.collected {
		t.Fatalf("collected: %v after %d attempts", err, outcome.attempts)
	}

	// an unknown outcome that committed is settled by the same push id
	world.fillUntilSealed(t, a, "h", 200)
	world.ref.refuseNext(&indexRefusal{kind: indexRefusalOutcomeUnknown}, true)
	outcome, err = world.merger(t, evsTestId("merger")).Merge(context.Background(), indexRootNumber, startDay)
	if err != nil || outcome.committed == nil || outcome.attempts != 1 {
		t.Fatalf("an unknown outcome: %v after %d attempts", err, outcome.attempts)
	}
}

// A store whose first read answers collected, as one does when a slot is replaced between a listing and its read.
type testCollectingStore struct {
	indexRefStore
	collected bool
}

func (self *testCollectingStore) Read(ctx context.Context, file *indexFileVersion) ([]byte, error) {
	if !self.collected {
		self.collected = true
		return nil, errTestIndexCollected
	}
	return self.indexRefStore.Read(ctx, file)
}

// A bucket is expired, and never merged, at the merge's signed time: the same bucket merges a day before its expiry
// and is skipped from it. Due: by sealed bytes at MergeDueByteCount, and by a writer out of slots, never expired.
func TestIndexMergeExpiryAndDue(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("x", 1, 1, 0, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "f", 0)
	view := world.view(t, a)
	root := view.writeRoot()
	bucket := root.newestBucket()
	expiry := testDayTime(bucket.window.endDay()+bucket.window.days, 0)
	if indexBucketExpiredAt(view, root, bucket, expiry.Add(-time.Millisecond).UnixMilli()) || !indexBucketExpiredAt(view, root, bucket, expiry.UnixMilli()) {
		t.Fatal("the bucket expires elsewhere than two windows on")
	}
	if due := indexMergeDueBuckets(view, root, world.at.UnixMilli()); len(due) != 0 {
		t.Fatalf("a bucket due under MergeDueByteCount: %v", due)
	}
	world.settings.MergeDueByteCount = indexBucketSealedByteCount(bucket)
	view = world.view(t, a)
	if due := indexMergeDueBuckets(view, view.writeRoot(), world.at.UnixMilli()); !slices.Equal(due, []uint32{bucket.window.startDay}) {
		t.Fatalf("a bucket at MergeDueByteCount not due: %v", due)
	}
	if due := indexMergeDueBuckets(view, view.writeRoot(), expiry.UnixMilli()); len(due) != 0 {
		t.Fatal("an expired bucket is due")
	}
	world.settings = DefaultIndexFormatSettings()

	// a writer out of slots: a ring of 2, its sealed slot and its head, and none reusable
	world.settings.RingSlotCount = 2
	view = world.view(t, a)
	writer := view.writeRoot().newestBucket().writer(a)
	if !indexWriterOutOfSlots(view.writeRoot().newestBucket(), writer, world.settings) {
		t.Fatalf("a writer with %d slots in a ring of 2 is not out of slots", len(writer.slots))
	}
	if due := indexMergeDueBuckets(view, view.writeRoot(), world.at.UnixMilli()); len(due) != 1 {
		t.Fatal("a writer out of slots left its bucket not due")
	}
	world.settings = DefaultIndexFormatSettings()

	world.at = expiry
	outcome, err := world.merger(t, evsTestId("merger")).Merge(context.Background(), indexRootNumber, bucket.window.startDay)
	if err != nil || outcome.committed != nil || outcome.skipped != indexMergeSkipExpired {
		t.Fatalf("an expired bucket merged: %v", err)
	}
	world.at = expiry.Add(-24 * time.Hour)
	if outcome, err := world.merger(t, evsTestId("merger")).Merge(context.Background(), indexRootNumber, bucket.window.startDay); err != nil || outcome.committed == nil {
		t.Fatalf("a bucket a day before its expiry did not merge: %v", err)
	}
}

// A forged diff whose base no other file of its writer's holds is left out, and alarms index_malformed naming the
// slot's signer; the writer's other entries merge.
func TestIndexMergeMalformedDiff(t *testing.T) {
	world := testNewHeadWorld()
	forger := evsTestId("forger")
	window := indexBucketWindow{startDay: 20340, days: 30}
	forged := &indexEntry{kind: indexEntryDiff, key: testIndexId("m", 1), version: 3, baseVersion: 2, timeSeconds: 1757400000, row: testFileRow(testHeadKeys(1, 0)), delta: indexDelta{added: indexKeySet{7}}}
	honest := testViewEntry("m", 2, 1, world.at.UnixMilli(), testHeadKeys(2, 0))
	root := indexNewPaths(false, indexRootNumber)
	path0, _ := root.slot(window.startDay, [indexIdByteCount]byte(forger), 0)
	path1, _ := root.slot(window.startDay, [indexIdByteCount]byte(forger), 1)
	entries := []*indexEntry{forged, honest}
	slices.SortFunc(entries, indexCompareEntries)
	world.ref.store(forger).testCommit(t, world.at,
		&indexPushFile{path: path0, plaintext: testViewSlotFile(t, window, forger, 1, indexFileSlot, entries...)},
		&indexPushFile{path: path1, plaintext: testViewSlotFile(t, window, forger, 2, indexFileSlot)},
	)
	outcome := world.merge(t, evsTestId("merger"))
	if len(outcome.result.malformed) != 1 || outcome.result.malformed[0].signerSidecarId != forger || outcome.result.malformed[0].path != path0 {
		t.Fatalf("the forged diff: %+v", outcome.result.malformed)
	}
	alarmed := false
	for _, event := range outcome.events {
		alarmed = alarmed || event.Kind == SidecarEventIndexMalformed && *event.SidecarId == forger && event.Path == path0
	}
	if !alarmed {
		t.Fatal("no index_malformed named the forger")
	}
	merged := world.mergedBucket(t)
	if merged.documents[testIndexId("m", 1)] != nil || merged.documents[testIndexId("m", 2)] == nil {
		t.Fatal("the forged diff merged, or the honest entry did not")
	}
}

// A document whose row and postings pass a shard's cap in a shard of its own fails the merge closed, writing nothing.
func TestIndexMergeUnplaceable(t *testing.T) {
	window := indexBucketWindow{startDay: 20340, days: 30}
	root := &indexViewRoot{number: indexRootNumber, paths: indexNewPaths(false, indexRootNumber)}
	keys := testIndexKeys(0, 300000, 1)
	huge := &indexEntry{kind: indexEntryFull, key: testIndexId("huge", 1), version: 1, timeSeconds: 1757400000, row: testFileRow(keys), keys: keys}
	if keys.encodedByteCount() > indexKeySetMaxByteCount {
		t.Fatal("the probe key set is past KeySetMax")
	}
	_, err := indexMerge(&indexMergeArgs{root: root, bucket: &indexViewBucket{window: window}, extra: []*indexEntry{huge}, padKey: testPadKey(t, 2), tables: testHeadTables, settings: DefaultIndexFormatSettings()})
	if !errors.Is(err, errIndexMergeUnplaceable) {
		t.Fatalf("a document past a shard: %v", err)
	}
}

// One merge vector: a name, and each file the merge wrote with its plaintext's hash and length, and each removal.
type testMergeVector struct {
	Name     string                `json:"name"`
	Files    []testMergeVectorFile `json:"files"`
	Removals []string              `json:"removals,omitempty"`
}

type testMergeVectorFile struct {
	Path      string `json:"path"`
	Replaces  uint64 `json:"replaces"`
	Sha256    string `json:"sha256"`
	ByteCount int    `json:"byte_count"`
}

func testMergeVectorOf(name string, files []*indexPushFile, removals []*indexPushRemoval) testMergeVector {
	vector := testMergeVector{Name: name}
	for _, file := range files {
		sum := sha256.Sum256(file.plaintext)
		vector.Files = append(vector.Files, testMergeVectorFile{Path: file.path, Replaces: file.replaces, Sha256: hex.EncodeToString(sum[:]), ByteCount: len(file.plaintext)})
	}
	for _, removal := range removals {
		vector.Removals = append(vector.Removals, removal.path)
	}
	return vector
}

// Holds built vectors to the file at path, or rewrites it under SIDECAR_WRITE_VECTORS.
func testCheckMergeVectors(t *testing.T, path string, built []testMergeVector) {
	t.Helper()
	if os.Getenv(testWriteVectorsEnvironment) != "" {
		testWriteJson(t, path, built)
		return
	}
	encoded, err := testIndexFiles.ReadFile(path)
	if err != nil {
		t.Fatalf("%v; %s=1 writes it", err, testWriteVectorsEnvironment)
	}
	held := []testMergeVector{}
	if err := json.Unmarshal(encoded, &held); err != nil {
		t.Fatal(err)
	}
	if len(held) != len(built) {
		t.Fatalf("%d vectors held for %d built", len(held), len(built))
	}
	for index, vector := range built {
		heldVector := held[index]
		if heldVector.Name != vector.Name || len(heldVector.Files) != len(vector.Files) || !slices.Equal(heldVector.Removals, vector.Removals) {
			t.Errorf("vector %s: held %s with %d files", vector.Name, heldVector.Name, len(heldVector.Files))
			continue
		}
		for fileIndex, file := range vector.Files {
			if heldVector.Files[fileIndex] != file {
				t.Errorf("vector %s: file %s differs from the one held", vector.Name, file.Path)
			}
		}
	}
}

// D-TEST-15, DESIGN-DETAILS 1.6's merge/ list, pinned by each output file's plaintext hash: a sealed diff composed
// onto its writer's kept slot and onto a large entry; one version from two writers (the tie order); a tombstone over a
// row; a ref tombstone; the erasure set's document left out; take at the cap and the shard opened after it; a join; a
// merge that changes only the manifest; a merge with extra entries. SIDECAR_WRITE_VECTORS rewrites them.
func TestIndexMergeVectors(t *testing.T) {
	built := []testMergeVector{}
	record := func(name string, result *indexMergeResult) {
		built = append(built, testMergeVectorOf(name, result.files(), result.removedShards))
	}
	merger := evsTestId("merger")

	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	index := world.fillUntilSealed(t, a, "f", 0)
	large := testIndexKeys(0, 9000, 3)
	world.push(t, a, testLive("d", 2, 1, 0, large))
	largeEdit := slices.Clone(large)
	largeEdit[10] += 1
	world.push(t, a, testLive("d", 1, 2, 1, testHeadKeys(1, 1)), testLive("d", 2, 2, 1, largeEdit))
	index = world.fillUntilSealed(t, a, "f", index)
	record("composed-diffs", world.merge(t, merger).result)

	world.push(t, b, testLive("d", 9, 3, 0, testHeadKeys(9, 0)))
	world.fillUntilSealed(t, b, "fb", 0)
	world.push(t, a, testLive("d", 9, 3, 0, testHeadKeys(9, 0)))
	index = world.fillUntilSealed(t, a, "f", index)
	record("tie-order", world.merge(t, merger).result)

	world.push(t, a, testRemoved("d", 1, 3))
	index = world.fillUntilSealed(t, a, "f", index)
	record("tombstone-over-a-row", world.merge(t, merger).result)

	copies := testNewHeadWorld()
	copies.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	copies.fillUntilSealed(t, a, "f", 0)
	copies.merge(t, merger)
	copies.push(t, b, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	copies.fillUntilSealed(t, b, "f", 0)
	record("manifest-only", copies.merge(t, merger).result)

	refResult, err := indexMerge(testCompanionMergeArgs(t))
	if err != nil {
		t.Fatal(err)
	}
	record("ref-tombstone", refResult)

	erased := testNewHeadWorld()
	erased.push(t, a, testLive("e", 1, 1, 0, testHeadKeys(1, 0)), testLive("e", 2, 1, 0, testHeadKeys(2, 0)))
	erased.fillUntilSealed(t, a, "f", 0)
	erasureSet := &protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{{ErasureId: testIndexIdBytes("erasure", 1), EraserSidecarId: evsTestId("eraser").Bytes(), Docs: []*protocol.IndexErased{{DocKey: testIndexIdBytes("e", 1), Version: 1}}}}}
	file, err := indexEncodeErasureSet(erasureSet, erased.settings)
	if err != nil {
		t.Fatal(err)
	}
	erased.ref.store(evsTestId("eraser")).testCommit(t, erased.at, &indexPushFile{path: indexErasureSetPath(false), plaintext: file})
	record("erased-left-out", erased.merge(t, merger).result)

	window := indexBucketWindow{startDay: 20340, days: 30}
	root := &indexViewRoot{number: indexRootNumber, paths: indexNewPaths(false, indexRootNumber)}
	extra := []*indexEntry{}
	for entryIndex := range 400 {
		keys := testIndexKeys(entryIndex*0x2000, 700, 3)
		extra = append(extra, &indexEntry{kind: indexEntryFull, key: testIndexId("cap", entryIndex), version: 1, timeSeconds: 1757400000, row: testFileRow(keys), keys: keys})
	}
	extra = append(extra, &indexEntry{kind: indexEntryTombstone, key: testIndexId("cap gone", 1), version: 2, timeSeconds: 1757400000})
	capResult, err := indexMerge(&indexMergeArgs{root: root, bucket: &indexViewBucket{window: window}, extra: extra, padKey: testPadKey(t, 2), tables: testHeadTables, settings: DefaultIndexFormatSettings()})
	if err != nil {
		t.Fatal(err)
	}
	record("take-at-the-cap-with-extra", capResult)

	small := func(n uint32, label string) (*indexViewShard, *indexShard) {
		shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: testShardDocuments(int64(n), label, 4, indexDocFile)}
		file := testBuildShard(t, shard, false, testPadKey(t, 2))
		decoded, err := testDecodeShard(file, false)
		if err != nil {
			t.Fatal(err)
		}
		path, _ := indexParsePath(root.paths.bucketShard(window.startDay, n), false)
		return &indexViewShard{file: &indexFileVersion{path: path.String(), version: uint64(n) + 1, byteCount: len(file)}, path: path, decoded: decoded}, decoded
	}
	zero, zeroDecoded := small(0, "j0")
	three, threeDecoded := small(3, "j3")
	joined, err := indexMerge(&indexMergeArgs{
		root:   root,
		bucket: &indexViewBucket{window: window, manifest: &protocol.IndexManifest{StartDay: window.startDay, Days: window.days}, shards: []*indexViewShard{zero, three}},
		shards: []*indexShard{zeroDecoded, threeDecoded},
		padKey: testPadKey(t, 2), tables: testHeadTables, settings: DefaultIndexFormatSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	record("join", joined)

	testCheckMergeVectors(t, testMergeVectorPath, built)
}

// A merge is a function of its inputs: two devices loading one base, each its own view and decode, build equal bytes,
// whatever order the writers' files were listed in.
func TestIndexMergeIsAFunction(t *testing.T) {
	world := testNewHeadWorld()
	writers := []Id{evsTestId("writer c"), evsTestId("writer a"), evsTestId("writer b")}
	for writerIndex, writer := range writers {
		world.push(t, writer, testLive("fn", writerIndex, 1, 0, testHeadKeys(writerIndex, 0)), testLive("shared", 1, 2, 0, testHeadKeys(7, 0)))
		world.fillUntilSealed(t, writer, "f"+writer.String(), 0)
	}
	results := [][]*indexPushFile{}
	for signerIndex, signer := range []Id{evsTestId("one"), evsTestId("two")} {
		view := world.view(t, signer)
		root := view.writeRoot()
		bucket := root.newestBucket()
		if signerIndex == 1 {
			slices.Reverse(bucket.writers)
		}
		shards, err := indexDecodeBucketShards(context.Background(), view, bucket.shards)
		if err != nil {
			t.Fatal(err)
		}
		result, err := indexMerge(&indexMergeArgs{root: root, bucket: bucket, shards: shards, absorb: true, erased: view.erased, padKey: testPadKey(t, 2), tables: testHeadTables, settings: view.settings})
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, result.files())
	}
	if len(results[0]) != len(results[1]) {
		t.Fatal("two builds of one merge differ")
	}
	for index := range results[0] {
		if results[0][index].path != results[1][index].path || sha256.Sum256(results[0][index].plaintext) != sha256.Sum256(results[1][index].plaintext) {
			t.Fatal("two builds of one merge wrote different plaintext")
		}
	}
}

// A merge removes no large entry, since a diff its writer's head holds may rest on one: after a merge absorbs two, the
// writer's next push there removes the one no diff rests on and keeps the one its head's diff names (1.6; twin
// MergeRemovesLarge).
func TestIndexMergeLeavesLargeEntriesToTheirWriter(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	kept, gone := testIndexKeys(0, 9000, 3), testIndexKeys(1, 9000, 3)
	world.push(t, a, testLive("l", 1, 1, 0, kept), testLive("l", 2, 1, 0, gone))
	world.fillUntilSealed(t, a, "f", 0)
	edit := slices.Clone(kept)
	edit[10] += 1
	world.push(t, a, testLive("l", 1, 2, 1, edit))
	outcome := world.merge(t, evsTestId("merger"))
	for _, removal := range outcome.result.removedShards {
		if path, _ := indexParsePath(removal.path, false); path.kind == indexPathLargeEntry {
			t.Fatal("a merge removed a large entry")
		}
	}
	writer := world.writer(t, a)
	if len(writer.large) != 2 {
		t.Fatalf("%d large entries after the merge", len(writer.large))
	}
	plan := world.push(t, a, testLive("l", 3, 1, 0, testHeadKeys(3, 0)))
	if len(plan.buckets[0].removed) != 1 {
		t.Fatalf("the writer's next push removed %d large entries", len(plan.buckets[0].removed))
	}
	writer = world.writer(t, a)
	if len(writer.large) != 1 || writer.large[0].slot.entries[0].key != testIndexId("l", 1) {
		t.Fatal("the writer removed the large entry its head's diff rests on")
	}
	if file, entry := indexResolveBase(writer, testIndexId("l", 1), 1, writer.head()); file == nil || entry == nil {
		t.Fatal("the head's diff lost its base")
	}
}

// A seeded walk of two writers' pushes, edits, removals, seals and merges (FI-18's and I1's ground, 1.3): after every
// step each document's newest entry over the shards and every unabsorbed file, heads included, is the newest version
// written, every unabsorbed diff has its base in its own writer's files, and the shards hold one version a key.
func TestIndexMergeKeepsEveryNewestVersion(t *testing.T) {
	for seed := range int64(6) {
		random := rand.New(rand.NewSource(seed))
		world := testNewHeadWorld()
		writers := []Id{evsTestId("writer a"), evsTestId("writer b")}
		type written struct {
			version uint64
			removed bool
		}
		newest := map[int]written{}
		fill := 0
		for step := range 40 {
			writer := writers[random.Intn(len(writers))]
			switch action := random.Intn(10); {
			case action < 5:
				document := random.Intn(4)
				last := newest[document]
				version := last.version + 1
				if random.Intn(4) == 0 && last.version != 0 && !last.removed {
					world.push(t, writer, testRemoved("w", document, version))
					newest[document] = written{version: version, removed: true}
				} else {
					replaces := last.version
					if last.removed {
						replaces = 0
					}
					world.push(t, writer, testLive("w", document, version, replaces, testHeadKeys(document, int(version))))
					newest[document] = written{version: version}
				}
			case action < 8:
				fill = world.fillUntilSealed(t, writer, fmt.Sprintf("fill %d", seed), fill)
			default:
				view := world.view(t, writer)
				if bucket := view.writeRoot().newestBucket(); bucket != nil && 0 < indexBucketSealedByteCount(bucket) {
					world.merge(t, evsTestId("merger"))
				}
			}
			view := world.view(t, evsTestId("reader"))
			bucket := view.writeRoot().newestBucket()
			if bucket == nil {
				continue
			}
			shards, err := indexDecodeBucketShards(context.Background(), view, bucket.shards)
			if err != nil {
				t.Fatal(err)
			}
			winners, malformed, err := indexMergeCandidates(bucket, shards, nil, true, true, view.erased, map[Id]uint32{})
			if err != nil {
				t.Fatal(err)
			}
			if len(malformed) != 0 {
				t.Fatalf("seed %d step %d: an unabsorbed diff with no base", seed, step)
			}
			seen := map[[indexIdByteCount]byte]bool{}
			for _, shard := range shards {
				for _, document := range shard.documents {
					if seen[document.key] {
						t.Fatalf("seed %d step %d: a key twice in the shards", seed, step)
					}
					seen[document.key] = true
				}
				for _, tombstone := range shard.tombstones {
					if seen[tombstone.key] {
						t.Fatalf("seed %d step %d: a key twice in the shards", seed, step)
					}
					seen[tombstone.key] = true
				}
			}
			for document, want := range newest {
				winner := winners.documents[testIndexId("w", document)]
				if winner == nil || winner.version != want.version || (winner.kind != indexEntryFull) != want.removed {
					t.Fatalf("seed %d step %d: document %d's newest %+v, written %+v", seed, step, document, winner, want)
				}
				if !want.removed && !slices.Equal(winner.keys, testHeadKeys(document, int(want.version))) {
					t.Fatalf("seed %d step %d: document %d's keys composed wrong", seed, step, document)
				}
			}
		}
	}
}
