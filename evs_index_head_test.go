// Writer heads and the dependency row (SEARCH-M10-09): head and seal vectors with plaintext hashes (D-TEST-15), each
// branch of the dependency row as FS-107 walks it, slot reuse and the ring, the 256 KiB merge inside a push, and
// FS-74's seal only at 16,208 B and its racing pushes, all on the fake store.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

const testHeadVectorPath = "testdata/index/head/vectors.json"

// The tables every header in these tests names, fixed so a vector does not ride on the build.
var testHeadTables = indexTables{normVersion: "17.0.0", textModuleVersion: "v0.43.0"}

// One ref's index and its writers, on a file-mode ref of a general repo.
type testHeadWorld struct {
	ref *testIndexRef
	// Each push's time, moving a minute a push from inside the bucket starting on day 20,340.
	at time.Time
}

func testNewHeadWorld() *testHeadWorld {
	return &testHeadWorld{ref: testNewIndexRef(), at: testDayTime(20341, 0)}
}

// The view at the head, read by writer.
func (self *testHeadWorld) view(t testing.TB, writer Id) *indexView {
	t.Helper()
	return testLoadView(t, self.ref.store(writer))
}

// Plans writer's push of pending at the head and the world's time.
func (self *testHeadWorld) plan(t testing.TB, writer Id, mayMerge bool, pending ...*indexPendingDocument) (*indexHeadPlan, *indexView) {
	t.Helper()
	view := self.view(t, writer)
	plan, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view:         view,
		root:         view.writeRoot(),
		writer:       writer,
		signedTimeMs: self.at.UnixMilli(),
		tables:       testHeadTables,
		pending:      pending,
		mayMerge:     mayMerge,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan, view
}

// Commits a plan at the base its view was read at, moving the world's clock a minute.
func (self *testHeadWorld) commit(t testing.TB, writer Id, plan *indexHeadPlan, view *indexView) (*indexCommitted, error) {
	t.Helper()
	committed, err := self.ref.store(writer).Commit(context.Background(), &indexPush{
		pushId:       NewId(),
		baseVersion:  view.head.version,
		indexEpoch:   view.head.indexEpoch,
		signedTimeMs: self.at.UnixMilli(),
		files:        plan.files(),
	})
	self.at = self.at.Add(time.Minute)
	return committed, err
}

// Plans and commits writer's push, failing on any refusal.
func (self *testHeadWorld) push(t testing.TB, writer Id, pending ...*indexPendingDocument) *indexHeadPlan {
	t.Helper()
	plan, view := self.plan(t, writer, true, pending...)
	if plan.mergeFirst || plan.mergeInPush {
		t.Fatalf("a push that cannot commit by itself: %+v", plan)
	}
	if _, err := self.commit(t, writer, plan, view); err != nil {
		t.Fatal(err)
	}
	return plan
}

// The document's entries in the newest bucket, as a reader of the head sees them.
func (self *testHeadWorld) entries(t testing.TB, label string, index int) []*indexBucketEntry {
	t.Helper()
	view := self.view(t, evsTestId("reader"))
	documents, err := view.bucketDocuments(context.Background(), view.writeRoot().newestBucket())
	if err != nil {
		t.Fatal(err)
	}
	return documents.of(testIndexId(label, index))
}

// The keys of document index at its version n: a base range with n keys moved, so each edit is a small delta.
func testHeadKeys(index int, n int) indexKeySet {
	keys := testIndexKeys(0x200000+index*0x1000, 200, 2)
	for edit := range n {
		keys[edit] += 1
	}
	return keys
}

// A live version of document index at version, replacing replaces, with keys.
func testLive(label string, index int, version uint64, replaces uint64, keys indexKeySet) *indexPendingDocument {
	return &indexPendingDocument{
		kind:     indexEntryFull,
		key:      testIndexId(label, index),
		version:  version,
		replaces: replaces,
		keys:     keys,
		row:      testFileRow(keys),
	}
}

// A removal of document index at version.
func testRemoved(label string, index int, version uint64) *indexPendingDocument {
	return &indexPendingDocument{kind: indexEntryTombstone, key: testIndexId(label, index), version: version}
}

// The one entry of version in entries, failing unless exactly one place holds it.
func testEntryAt(t testing.TB, entries []*indexBucketEntry, version uint64) *indexBucketEntry {
	t.Helper()
	found := []*indexBucketEntry{}
	for _, entry := range entries {
		if entry.version == version {
			found = append(found, entry)
		}
	}
	if len(found) != 1 {
		t.Fatalf("version %d in %d places", version, len(found))
	}
	return found[0]
}

// A merge's effect, since merges are SEARCH-M10-10's: a manifest absorbing writer's files through seq, and one shard
// holding documents, written by a merger.
func (self *testHeadWorld) absorb(t testing.TB, writer Id, seq uint32, documents ...*indexShardDocument) {
	t.Helper()
	view := self.view(t, writer)
	root := view.writeRoot()
	bucket := root.newestBucket()
	shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: documents}
	shard.header.BucketStartDay, shard.header.BucketDays = bucket.window.startDay, bucket.window.days
	manifest := &protocol.IndexManifest{
		StartDay: bucket.window.startDay,
		Days:     bucket.window.days,
		Shards:   []*protocol.IndexShard{{N: 0, Docs: uint32(len(documents)), FirstDay: bucket.window.startDay, LastDay: bucket.window.startDay}},
		Absorbed: []*protocol.IndexWatermark{{WriterSidecarId: writer.Bytes(), Seq: seq}},
	}
	merger := self.ref.store(evsTestId("merger"))
	merger.testCommit(t, self.at,
		&indexPushFile{path: root.paths.bucketManifest(bucket.window.startDay), plaintext: testSmallFile(t, manifest), replaces: merger.testVersionOf(root.paths.bucketManifest(bucket.window.startDay))},
		&indexPushFile{path: root.paths.bucketShard(bucket.window.startDay, 0), plaintext: testBuildShard(t, shard, false, testPadKey(t, 2)), replaces: merger.testVersionOf(root.paths.bucketShard(bucket.window.startDay, 0))},
	)
	self.at = self.at.Add(time.Minute)
}

// A shard's copy of a document version.
func testShardCopy(label string, index int, version uint64, keys indexKeySet) *indexShardDocument {
	return &indexShardDocument{key: testIndexId(label, index), version: version, timeSeconds: 1757400000, row: testFileRow(keys), keys: keys}
}

// FS-107: D created and edited twice in one unsealed head, small, each full entry replacing the last, since nothing
// outside the head holds a base; and the head keeps one entry for D.
func TestIndexDependencySmallEditsInOneHeadStayFull(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	world.push(t, a, testLive("d", 1, 2, 1, testHeadKeys(1, 1)))
	world.push(t, a, testLive("d", 1, 3, 2, testHeadKeys(1, 2)))
	entries := world.entries(t, "d", 1)
	if len(entries) != 1 || entries[0].kind != indexEntryFull || entries[0].version != 3 || entries[0].place != indexPlaceHead {
		t.Fatalf("D's entries %+v", entries)
	}
}

// FS-107: D created as a large entry, then edited twice: the first edit is a diff on the large entry, outside every
// head (case a), and the second takes that base, its delta composed, and replaces the first (case b).
func TestIndexDependencyLargeThenComposedDiffs(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	base := testIndexKeys(0, 9000, 3)
	edit := func(n int) indexKeySet {
		keys := slices.Clone(base)
		for index := range n {
			keys[index*7] += 1
		}
		return keys
	}
	world.push(t, a, testLive("d", 1, 1, 0, base))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 1); entry.place != indexPlaceLarge || entry.kind != indexEntryFull {
		t.Fatalf("D's first version %+v", entry)
	}
	world.push(t, a, testLive("d", 1, 2, 1, edit(3)))
	second := testEntryAt(t, world.entries(t, "d", 1), 2)
	if second.place != indexPlaceHead || second.kind != indexEntryDiff || second.baseVersion != 1 {
		t.Fatalf("D's second version %+v", second)
	}
	world.push(t, a, testLive("d", 1, 3, 2, edit(5)))
	entries := world.entries(t, "d", 1)
	third := testEntryAt(t, entries, 3)
	if third.place != indexPlaceHead || third.kind != indexEntryDiff || third.baseVersion != 1 || 2 < len(entries) {
		t.Fatalf("D's entries %+v", entries)
	}
	view := world.view(t, a)
	documents, err := view.bucketDocuments(context.Background(), view.writeRoot().newestBucket())
	if err != nil {
		t.Fatal(err)
	}
	composed, err := third.entry.delta.applyTo(base)
	if err != nil || !slices.Equal(composed, edit(5)) {
		t.Errorf("the composed diff gives %d keys, %v", len(composed), err)
	}
	if _, chain, err := documents.resolve(testIndexId("d", 1), 1); err != nil || chain != 0 {
		t.Errorf("the base resolves with chain %d, %v", chain, err)
	}
}

// FS-107: D's base in a sealed slot, unabsorbed, then absorbed into a shard and the slot reused: each edit is a diff on
// the base kept outside every head.
func TestIndexDependencyBaseInASealedSlotThenAShard(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	// Fill A's head with other documents until it seals, leaving D's v1 in a sealed slot.
	for index := 2; ; index += 1 {
		plan := world.push(t, a, testLive("fill", index, 1, 0, testIndexKeys(0x300000+index*0x1000, 1500, 1)))
		if len(plan.buckets[0].sealedSlots) != 0 || plan.buckets[0].head.path.slotIndex != 0 {
			break
		}
	}
	if entry := testEntryAt(t, world.entries(t, "d", 1), 1); entry.place != indexPlaceSealed || entry.absorbed {
		t.Fatalf("D's v1 %+v", entry)
	}
	world.push(t, a, testLive("d", 1, 2, 1, testHeadKeys(1, 1)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 2); entry.kind != indexEntryDiff || entry.baseVersion != 1 || entry.place != indexPlaceHead {
		t.Fatalf("D's v2 on a sealed base %+v", entry)
	}

	// A merge absorbs the sealed slot, D's v1 in its shard as the head's base, and A's next head reuses slot 0.
	view := world.view(t, a)
	sealedSeq := view.writeRoot().newestBucket().writer(a).slotAt(0).seq()
	world.absorb(t, a, sealedSeq, testShardCopy("d", 1, 1, testHeadKeys(1, 0)))
	world.push(t, a, testLive("d", 1, 3, 2, testHeadKeys(1, 2)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 3); entry.kind != indexEntryDiff || entry.baseVersion != 1 {
		t.Fatalf("D's v3 over a shard base %+v", entry)
	}
	for index := 100; ; index += 1 {
		plan := world.push(t, a, testLive("fill", index, 1, 0, testIndexKeys(0x500000+index*0x1000, 1500, 1)))
		if len(plan.buckets[0].sealedSlots) != 0 {
			if plan.buckets[0].head.path.slotIndex != 0 || plan.buckets[0].head.replaces == 0 {
				t.Fatalf("A's next head took slot %d replacing %d, not the absorbed slot 0", plan.buckets[0].head.path.slotIndex, plan.buckets[0].head.replaces)
			}
			break
		}
	}
	// v3's diff is sealed now, outside every head, so v4 rests on it (case a), its chain reaching the shard's v1.
	world.push(t, a, testLive("d", 1, 4, 3, testHeadKeys(1, 3)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 4); entry.kind != indexEntryDiff || entry.baseVersion != 3 {
		t.Fatalf("D's v4 after the slot's reuse %+v", entry)
	}
	view = world.view(t, a)
	documents, err := view.bucketDocuments(context.Background(), view.writeRoot().newestBucket())
	if err != nil {
		t.Fatal(err)
	}
	if keys, chain, err := documents.resolve(testIndexId("d", 1), 3); err != nil || chain != 1 || !slices.Equal(keys, testHeadKeys(1, 2)) {
		t.Errorf("v3 resolves to %d keys with chain %d, %v", len(keys), chain, err)
	}
}

// FS-107: another writer's edit of D rests on no head: on A's head entry it is full, on A's sealed slot a diff.
func TestIndexDependencyAnotherWritersEdit(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	world.push(t, b, testLive("d", 1, 2, 1, testHeadKeys(1, 1)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 2); entry.kind != indexEntryFull || entry.writer != b {
		t.Fatalf("B's edit on A's head %+v", entry)
	}

	world = testNewHeadWorld()
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	for index := 2; ; index += 1 {
		if plan := world.push(t, a, testLive("fill", index, 1, 0, testIndexKeys(0x300000+index*0x1000, 1500, 1))); len(plan.buckets[0].sealedSlots) != 0 {
			break
		}
	}
	world.push(t, b, testLive("d", 1, 2, 1, testHeadKeys(1, 1)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 2); entry.kind != indexEntryDiff || entry.baseVersion != 1 || entry.writer != b {
		t.Fatalf("B's edit on A's sealed slot %+v", entry)
	}
}

// FS-107: with a copy of D's version sealed outside the heads while A's head holds its diff of that version, A's next
// edit is full: the newest entry outside every head is no longer the diff's base (case b), and a head holds a diff of
// the version (case a).
func TestIndexDependencyASealedCopyForcesFull(t *testing.T) {
	world := testNewHeadWorld()
	a, backfiller := evsTestId("writer a"), evsTestId("backfiller")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	for index := 2; ; index += 1 {
		if plan := world.push(t, a, testLive("fill", index, 1, 0, testIndexKeys(0x300000+index*0x1000, 1500, 1))); len(plan.buckets[0].sealedSlots) != 0 {
			break
		}
	}
	world.push(t, a, testLive("d", 1, 2, 1, testHeadKeys(1, 1)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 2); entry.kind != indexEntryDiff {
		t.Fatalf("A's v2 %+v", entry)
	}
	// The backfiller's full copy of v2, sealed by its next push.
	world.push(t, backfiller, testLive("d", 1, 2, 1, testHeadKeys(1, 1)))
	for index := 200; ; index += 1 {
		if plan := world.push(t, backfiller, testLive("fill", index, 1, 0, testIndexKeys(0x400000+index*0x1000, 1500, 1))); len(plan.buckets[0].sealedSlots) != 0 {
			break
		}
	}
	plan, _ := world.plan(t, a, true, testLive("d", 1, 3, 2, testHeadKeys(1, 2)))
	if entry := plan.buckets[0].head.slot.entries[slices.IndexFunc(plan.buckets[0].head.slot.entries, func(entry *indexEntry) bool {
		return entry.key == testIndexId("d", 1)
	})]; entry.kind != indexEntryFull || entry.version != 3 {
		t.Fatalf("A's v3 %+v", entry)
	}
}

// FS-107: an entry late into the previous bucket is full, even where its base sits outside every head there.
func TestIndexDependencyLateEntryIsFull(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	for index := 2; ; index += 1 {
		if plan := world.push(t, a, testLive("fill", index, 1, 0, testIndexKeys(0x300000+index*0x1000, 1500, 1))); len(plan.buckets[0].sealedSlots) != 0 {
			break
		}
	}
	// B, ahead of the boundary, opens the next bucket with another document.
	world.at = testDayTime(testBoundaryDay, 5*time.Minute)
	world.push(t, b, testLive("other", 1, 1, 0, testHeadKeys(9, 0)))
	// A, its clock behind, signs its edit of D in the previous window.
	world.at = testDayTime(testBoundaryDay, -5*time.Minute)
	plan, _ := world.plan(t, a, true, testLive("d", 1, 2, 1, testHeadKeys(1, 1)))
	if len(plan.buckets) != 1 || plan.buckets[0].window.startDay != 20340 {
		t.Fatalf("A's late edit went to %+v", plan.buckets)
	}
	entries := plan.buckets[0].head.slot.entries
	if entry := entries[slices.IndexFunc(entries, func(entry *indexEntry) bool { return entry.key == testIndexId("d", 1) })]; entry.kind != indexEntryFull {
		t.Errorf("a late entry is a %v", entry.kind)
	}
}

// A document held in a newer bucket takes its next entry there, whatever the push's own window.
func TestIndexHeadFollowsANewerBucketHoldingTheDocument(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("seed", 1, 1, 0, testHeadKeys(8, 0)))
	world.at = testDayTime(testBoundaryDay, 5*time.Minute)
	world.push(t, b, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	world.at = testDayTime(testBoundaryDay, -5*time.Minute)
	plan, _ := world.plan(t, a, true, testLive("d", 1, 2, 1, testHeadKeys(1, 1)), testLive("e", 1, 1, 0, testHeadKeys(2, 0)))
	if len(plan.buckets) != 2 || plan.buckets[0].window.startDay != 20340 || plan.buckets[1].window.startDay != testBoundaryDay {
		t.Fatalf("buckets %+v", plan.buckets)
	}
	if entries := plan.buckets[1].head.slot.entries; len(entries) != 1 || entries[0].key != testIndexId("d", 1) {
		t.Errorf("the newer bucket took %d entries", len(entries))
	}
}

// The chain and delta bounds: a chain at 15 diffs takes no more, and a delta of half its base's set or more is full.
func TestIndexDependencyBounds(t *testing.T) {
	base := testIndexKeys(0x200000, 200, 2)
	key := testIndexId("d", 1)
	documents := &indexBucketDocuments{entries: map[[indexIdByteCount]byte][]*indexBucketEntry{}}
	add := func(entry *indexBucketEntry) {
		documents.entries[key] = append(documents.entries[key], entry)
	}
	add(&indexBucketEntry{place: indexPlaceShard, kind: indexEntryFull, key: key, version: 1, document: &indexShardDocument{key: key, version: 1, keys: base, row: testFileRow(base)}})
	keys := base
	for version := uint64(2); version <= 16; version += 1 {
		next := slices.Clone(keys)
		next[int(version)] += 1
		delta := indexDeltaBetween(keys, next)
		add(&indexBucketEntry{place: indexPlaceSealed, kind: indexEntryDiff, key: key, version: version, baseVersion: version - 1, entry: &indexEntry{
			kind: indexEntryDiff, key: key, version: version, baseVersion: version - 1, row: testFileRow(next), delta: delta,
		}})
		keys = next
	}
	notErased := func(key [indexIdByteCount]byte, version uint64) bool { return false }
	if _, chain, err := documents.resolve(key, 16); err != nil || chain != 15 {
		t.Fatalf("v16 resolves with chain %d, %v", chain, err)
	}
	next := slices.Clone(keys)
	next[40] += 1
	if choice := indexChooseEntry(documents, true, evsTestId("a"), &indexPendingDocument{kind: indexEntryFull, key: key, version: 17, replaces: 16, keys: next}, notErased); choice.diff {
		t.Errorf("a diff on a chain of 15")
	}
	fifteen := slices.Clone(documents.entries[key][:15])
	documents.entries[key] = fifteen
	if choice := indexChooseEntry(documents, true, evsTestId("a"), &indexPendingDocument{kind: indexEntryFull, key: key, version: 16, replaces: 15, keys: next}, notErased); !choice.diff || choice.baseVersion != 15 {
		t.Errorf("no diff on a chain of 14: %+v", choice)
	}
	wide := testIndexKeys(0x200000, 200, 2)
	for index := 100; index < 160; index += 1 {
		wide[index] += 1
	}
	if choice := indexChooseEntry(documents, true, evsTestId("a"), &indexPendingDocument{kind: indexEntryFull, key: key, version: 16, replaces: 15, keys: wide}, notErased); choice.diff {
		t.Errorf("a diff whose delta is half its base's set")
	}
	erasedBase := func(key [indexIdByteCount]byte, version uint64) bool { return version <= 15 }
	if choice := indexChooseEntry(documents, true, evsTestId("a"), &indexPendingDocument{kind: indexEntryFull, key: key, version: 16, replaces: 15, keys: next}, erasedBase); choice.diff {
		t.Errorf("a diff on an erased base")
	}
	if choice := indexChooseEntry(documents, false, evsTestId("a"), &indexPendingDocument{kind: indexEntryFull, key: key, version: 16, replaces: 15, keys: next}, notErased); choice.diff {
		t.Errorf("a diff outside the current bucket")
	}
}

// A tombstone as the document's newest entry leaves the next version full, and the erasure set's documents are left
// out of the push and out of the head the push rewrites.
func TestIndexHeadTombstonesAndTheErasureSet(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)), testLive("d", 2, 1, 0, testHeadKeys(2, 0)))
	world.push(t, a, testRemoved("d", 1, 2))
	world.push(t, a, testLive("d", 1, 3, 2, testHeadKeys(1, 1)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 3); entry.kind != indexEntryFull {
		t.Fatalf("after a tombstone %+v", entry)
	}

	erasureSet := &protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{{
		ErasureId: testIndexIdBytes("erasure", 1), EraserSidecarId: a.Bytes(), Epoch: 1,
		Docs: []*protocol.IndexErased{{DocKey: testIndexIdBytes("d", 2), Version: 5}},
	}}}
	world.ref.store(a).testCommit(t, world.at, &indexPushFile{path: indexErasureSetPath(false), plaintext: testSmallFile(t, erasureSet)})
	plan, _ := world.plan(t, a, true, testLive("d", 2, 2, 1, testHeadKeys(2, 1)), testLive("d", 3, 1, 0, testHeadKeys(3, 0)))
	if len(plan.erased) != 1 || plan.erased[0] != testIndexId("d", 2) {
		t.Fatalf("erased %v", plan.erased)
	}
	for _, entry := range plan.buckets[0].head.slot.entries {
		if entry.key == testIndexId("d", 2) {
			t.Errorf("the head kept an erased document's entry")
		}
	}
	world.ref.store(a).testCommit(t, world.at, &indexPushFile{path: indexErasureSetPath(false), replaces: world.ref.store(a).testVersionOf(indexErasureSetPath(false)), plaintext: []byte{0xff}})
	view := world.view(t, a)
	if _, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{view: view, root: view.writeRoot(), writer: a, signedTimeMs: world.at.UnixMilli(), tables: testHeadTables, pending: []*indexPendingDocument{testLive("d", 4, 1, 0, testHeadKeys(4, 0))}}); !errors.Is(err, errIndexErasureSetUnreadable) {
		t.Errorf("an unreadable erasure set planned %v", err)
	}
}

// FS-74: a head seals only when the next entry would pass 16,208 B, never on idle; the sealed head is within 16,208
// B, the entry that did not fit opens the next slot as the head, and a push with nothing pending writes nothing.
func TestIndexHeadSealsOnlyAtItsCap(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	idle, _ := world.plan(t, a, true)
	if len(idle.files()) != 0 {
		t.Fatalf("an idle push writes %d files", len(idle.files()))
	}
	var sealedAt int
	for index := 1; ; index += 1 {
		before := world.view(t, a)
		document := testLive("fill", index, 1, 0, testIndexKeys(0x300000+index*0x1000, 1500, 1))
		plan := world.push(t, a, document)
		bucket := plan.buckets[0]
		if len(bucket.sealedSlots) == 0 && len(before.writeRoot().buckets) != 0 {
			if writer := before.writeRoot().newestBucket().writer(a); writer != nil && writer.head().path.slotIndex != bucket.head.path.slotIndex {
				t.Fatalf("push %d moved the head without sealing", index)
			}
		}
		if len(bucket.sealedSlots) == 0 && 1 < index && bucket.head.path.slotIndex != 0 {
			t.Fatalf("push %d opened slot %d", index, bucket.head.path.slotIndex)
		}
		if writer := before.writeRoot(); len(writer.buckets) != 0 && len(bucket.sealedSlots) != 0 && bucket.head.path.slotIndex == 1 {
			sealedAt = index
			// The head before this push could not take the entry within 16,208 B.
			old := writer.newestBucket().writer(a).head()
			entry := &indexEntry{kind: indexEntryFull, key: document.key, version: 1, timeSeconds: indexEntrySeconds(world.at.UnixMilli()), row: document.row, keys: document.keys}
			encoded, err := entry.appendEncoded(nil, false)
			if err != nil {
				t.Fatal(err)
			}
			if old.file.byteCount+len(encoded) <= indexSlotMaxByteCount {
				t.Fatalf("sealed a head of %d B that could take %d B", old.file.byteCount, len(encoded))
			}
			break
		}
		if 64 < index {
			t.Fatal("no seal in 64 pushes")
		}
	}
	view := world.view(t, a)
	writer := view.writeRoot().newestBucket().writer(a)
	sealed, head := writer.slotAt(0), writer.head()
	if sealed == nil || head.path.slotIndex != 1 || head.seq() <= sealed.seq() || indexSlotMaxByteCount < sealed.file.byteCount || len(head.slot.entries) != 1 {
		t.Fatalf("after the seal at push %d: sealed %+v, head %+v", sealedAt, sealed, head)
	}
}

// The ring: a writer reuses its lowest absorbed slot; with none, new slots up to 8; past 8 it merges first, or, unable
// to, takes up to 16 and alarms; with all 16 held, it writes nothing.
func TestIndexHeadSlotRing(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	fill := func(index int) *indexPendingDocument {
		return testLive("fill", index, 1, 0, testIndexKeys(0x300000+index*0x400, 7000, 1))
	}
	index := 1
	for k := 0; k < indexWriterRingSlotCount; k += 1 {
		plan := world.push(t, a, fill(index), fill(index+1))
		index += 2
		if plan.buckets[0].head.path.slotIndex != uint32(k) && plan.buckets[0].head.path.slotIndex != uint32(k+1) {
			t.Fatalf("push %d's head at slot %d", k, plan.buckets[0].head.path.slotIndex)
		}
		if plan.buckets[0].head.path.slotIndex == indexWriterRingSlotCount-1 {
			break
		}
	}
	// Slot 7 is the head and holds what fits: the next seal finds no free slot.
	plan, _ := world.plan(t, a, true, fill(index), fill(index+1), fill(index+2))
	if !plan.mergeFirst || len(plan.files()) != 0 {
		t.Fatalf("a full ring that may merge planned %+v", plan)
	}
	plan, view := world.plan(t, a, false, fill(index), fill(index+1), fill(index+2))
	if plan.mergeFirst || !plan.pastRing || plan.buckets[0].head.path.slotIndex < indexWriterRingSlotCount {
		t.Fatalf("a full ring that may not merge planned %+v", plan)
	}
	if _, err := world.commit(t, a, plan, view); err != nil {
		t.Fatal(err)
	}

	// A merge absorbs slots 0 and 1: the next seal reuses slot 0.
	view = world.view(t, a)
	writer := view.writeRoot().newestBucket().writer(a)
	world.absorb(t, a, writer.slotAt(1).seq(), testShardCopy("fill", 1, 1, testIndexKeys(0x300000+1*0x400, 7000, 1)))
	plan, _ = world.plan(t, a, true, fill(index+3), fill(index+4), fill(index+5))
	if plan.mergeFirst {
		t.Fatalf("an absorbed slot did not free the ring")
	}
	reused := false
	for _, file := range plan.files() {
		if path, _ := indexParsePath(file.path, false); path.kind == indexPathSlot && path.slotIndex == 0 && file.replaces != 0 {
			reused = true
		}
	}
	if !reused {
		t.Errorf("the absorbed slot 0 was not reused")
	}

	// Every one of the 16 slots held and none absorbed, the head full to its cap.
	full := &indexViewWriter{sidecarId: a}
	for k := range uint32(indexWriterSlotCount) {
		slot := &indexSlot{header: &protocol.IndexFileHeader{Seq: k + 1}}
		if k == indexWriterSlotCount-1 {
			slot = testSlotOfLength(t, indexSlotMaxByteCount)
			slot.header.Seq = k + 1
		}
		full.slots = append(full.slots, &indexViewSlot{path: indexPath{kind: indexPathSlot, slotIndex: k}, slot: slot, file: &indexFileVersion{version: 1}})
	}
	bucket := &indexViewBucket{window: indexBucketWindow{startDay: 20340, days: 30}, writers: []*indexViewWriter{full}}
	args := &indexHeadPlanArgs{view: world.view(t, a), writer: a, tables: testHeadTables}
	err := indexPlaceEntries(args, args.view.writeRoot(), bucket, full, &indexHeadPlanBucket{window: bucket.window}, []*indexEntry{{kind: indexEntryTombstone, key: testIndexId("x", 1), version: 1}}, &indexHeadPlan{})
	if !errors.Is(err, errIndexNoFreeSlot) {
		t.Errorf("a writer holding all 16 slots answered %v", err)
	}
}

// A large entry takes the next seq, and the head is renumbered above it, so the head always holds its writer's highest
// seq and no merge's watermark covers it.
func TestIndexHeadStaysAboveItsLargeEntries(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	plan := world.push(t, a, testLive("big", 1, 1, 0, testIndexKeys(0, 9000, 3)))
	if len(plan.buckets[0].large) != 1 || plan.buckets[0].head == nil {
		t.Fatalf("plan %+v", plan.buckets[0])
	}
	view := world.view(t, a)
	writer := view.writeRoot().newestBucket().writer(a)
	if writer.head().seq() != 3 || writer.large[0].seq() != 2 || writer.highestSeq() != writer.head().seq() {
		t.Errorf("head seq %d, large seq %d", writer.head().seq(), writer.large[0].seq())
	}
}

// A push whose entries pass 256 KiB goes straight into the bucket's shards, a merge inside the push, writing no slot.
func TestIndexHeadPastTwoHundredFiftySixKibMergesInThePush(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	pending := []*indexPendingDocument{}
	for index := range 40 {
		pending = append(pending, testLive("bulk", index, 1, 0, testIndexKeys(index*0x10000, 7000, 1)))
	}
	plan, _ := world.plan(t, a, true, pending...)
	if !plan.mergeInPush || len(plan.files()) != 0 || len(plan.buckets) != 1 || len(plan.buckets[0].direct) != 40 {
		t.Errorf("plan %+v", plan)
	}
}

// FS-74 at unit level: two writers' pushes from one base, each changing only its own head, both commit; one writer's
// two pushes from one base race on its head, the second gets 409 naming it, and replanned at the new base it commits
// with nothing lost and nothing doubled.
func TestIndexHeadRacingPushes(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	planA, viewA := world.plan(t, a, true, testLive("d", 2, 1, 0, testHeadKeys(2, 0)))
	planB, viewB := world.plan(t, b, true, testLive("d", 3, 1, 0, testHeadKeys(3, 0)))
	first, err := world.commit(t, a, planA, viewA)
	if err != nil {
		t.Fatal(err)
	}
	second, err := world.commit(t, b, planB, viewB)
	if err != nil || second.version != first.version+1 {
		t.Fatalf("B's push at %+v, %v", second, err)
	}

	planOne, viewOne := world.plan(t, a, true, testLive("d", 4, 1, 0, testHeadKeys(4, 0)))
	planTwo, viewTwo := world.plan(t, a, true, testLive("d", 5, 1, 0, testHeadKeys(5, 0)))
	if _, err := world.commit(t, a, planOne, viewOne); err != nil {
		t.Fatal(err)
	}
	_, err = world.commit(t, a, planTwo, viewTwo)
	refusal, ok := indexRefusalOf(err)
	if !ok || refusal.kind != indexRefusalConflict || len(refusal.paths) != 1 || refusal.paths[0] != planTwo.files()[0].path {
		t.Fatalf("the racing push answered %v", err)
	}
	world.push(t, a, testLive("d", 5, 1, 0, testHeadKeys(5, 0)))
	view := world.view(t, a)
	head := view.writeRoot().newestBucket().writer(a).head()
	keys := []string{}
	for _, entry := range head.slot.entries {
		keys = append(keys, hex.EncodeToString(entry.key[:4]))
	}
	for _, index := range []int{1, 2, 4, 5} {
		key := testIndexId("d", index)
		if !slices.ContainsFunc(head.slot.entries, func(entry *indexEntry) bool { return entry.key == key }) {
			t.Errorf("A's head lost d%d: %v", index, keys)
		}
	}
	if len(head.slot.entries) != 4 {
		t.Errorf("A's head holds %d entries", len(head.slot.entries))
	}
}

// One head vector: a scenario's files, each with its plaintext hash.
type testHeadVector struct {
	Name  string               `json:"name"`
	Files []testHeadVectorFile `json:"files"`
}

// One file a plan writes.
type testHeadVectorFile struct {
	Path     string `json:"path"`
	Replaces uint64 `json:"replaces"`
	Sha256   string `json:"sha256"`
	Hex      string `json:"hex"`
}

// The vector of a plan's files.
func testHeadVectorOf(name string, plan *indexHeadPlan) testHeadVector {
	vector := testHeadVector{Name: name}
	for _, file := range plan.files() {
		sum := sha256.Sum256(file.plaintext)
		vector.Files = append(vector.Files, testHeadVectorFile{Path: file.path, Replaces: file.replaces, Sha256: hex.EncodeToString(sum[:]), Hex: hex.EncodeToString(file.plaintext)})
	}
	return vector
}

// D-TEST-15: heads and seals as plaintext, pinned with their hashes: a first head, a head rewritten with an entry
// replacing its older one, a large entry renumbering the head, a diff on a large entry, a seal at the cap opening the
// next slot, and a seal in the middle of a push rewriting the head it fills. SIDECAR_WRITE_VECTORS rewrites them.
func TestIndexHeadVectors(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	built := []testHeadVector{}
	record := func(name string, pending ...*indexPendingDocument) {
		plan, view := world.plan(t, a, true, pending...)
		built = append(built, testHeadVectorOf(name, plan))
		if _, err := world.commit(t, a, plan, view); err != nil {
			t.Fatal(err)
		}
	}
	record("first-head", testLive("v", 1, 1, 0, testHeadKeys(1, 0)), testLive("v", 2, 1, 0, testHeadKeys(2, 0)), testRemoved("v", 3, 4))
	record("head-entry-replaced", testLive("v", 1, 2, 1, testHeadKeys(1, 1)))
	record("large-entry", testLive("v", 4, 1, 0, testIndexKeys(0, 9000, 3)))
	large := testIndexKeys(0, 9000, 3)
	large[10] += 1
	record("diff-on-large", testLive("v", 4, 2, 1, large))
	for index := 10; ; index += 1 {
		plan, _ := world.plan(t, a, true, testLive("v", index, 1, 0, testIndexKeys(0x300000+index*0x1000, 1500, 1)))
		if len(plan.buckets[0].sealedSlots) != 0 || plan.buckets[0].head.path.slotIndex != 0 {
			record("seal-at-cap", testLive("v", index, 1, 0, testIndexKeys(0x300000+index*0x1000, 1500, 1)))
			break
		}
		record("", testLive("v", index, 1, 0, testIndexKeys(0x300000+index*0x1000, 1500, 1)))
	}
	// Two entries a push, until the head takes the first and seals before the second: the seal rewrites it.
	for index := 100; ; index += 2 {
		pair := func() []*indexPendingDocument {
			return []*indexPendingDocument{
				testLive("v", index, 1, 0, testIndexKeys(0x300000+index*0x1000, 1500, 1)),
				testLive("v", index+1, 1, 0, testIndexKeys(0x300000+(index+1)*0x1000, 1500, 1)),
			}
		}
		plan, _ := world.plan(t, a, true, pair()...)
		if len(plan.buckets[0].sealed) != 0 {
			record("seal-mid-push", pair()...)
			break
		}
		record("", pair()[0])
	}
	named := []testHeadVector{}
	for _, vector := range built {
		if vector.Name != "" {
			named = append(named, vector)
		}
	}

	if os.Getenv(testWriteVectorsEnvironment) != "" {
		testWriteJson(t, testHeadVectorPath, named)
		return
	}
	encoded, err := testIndexFiles.ReadFile(testHeadVectorPath)
	if err != nil {
		t.Fatalf("%v; %s=1 writes it", err, testWriteVectorsEnvironment)
	}
	held := []testHeadVector{}
	if err := json.Unmarshal(encoded, &held); err != nil {
		t.Fatal(err)
	}
	if len(held) != len(named) {
		t.Fatalf("%d vectors held for %d built", len(held), len(named))
	}
	for index, vector := range named {
		if held[index].Name != vector.Name || len(held[index].Files) != len(vector.Files) {
			t.Errorf("vector %d: %s holds %d files, built %s %d", index, held[index].Name, len(held[index].Files), vector.Name, len(vector.Files))
			continue
		}
		for fileIndex, file := range vector.Files {
			heldFile := held[index].Files[fileIndex]
			plaintext, err := hex.DecodeString(heldFile.Hex)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(plaintext)
			if heldFile.Path != file.Path || heldFile.Replaces != file.Replaces || heldFile.Sha256 != file.Sha256 || hex.EncodeToString(sum[:]) != heldFile.Sha256 || !bytes.Equal(plaintext, mustHex(t, file.Hex)) {
				t.Errorf("%s: file %d (%s) differs from its vector", vector.Name, fileIndex, file.Path)
			}
		}
	}
}

// hex's bytes, failing the test on bad input.
func mustHex(t testing.TB, text string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
