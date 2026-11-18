// Writer heads (SEARCH-M10-09 and SEARCH-M10-45; §11.14's dependency, seal and large rows; owner decision 584): every
// entry full or a tombstone, an edit's full entry replacing its writer's older one in the head and standing beside it
// once the head sealed, the head rule's two pushes of one writer on one base, an absorbed slot reused and absorbed
// large entries removed, a plan run twice giving equal bytes, seals, the ring and the push past DirectBytes, and the
// head vectors with plaintext hashes (D-TEST-15), all on the fake store.

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

	"google.golang.org/protobuf/proto"

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
	// What every view is loaded with.
	settings *IndexFormatSettings
	// The repo's admins, whose settings and erasure set versions count: the eraser.
	admins []Id
}

func testNewHeadWorld() *testHeadWorld {
	return &testHeadWorld{ref: testNewIndexRef(), at: testDayTime(20341, 0), settings: DefaultIndexFormatSettings(), admins: []Id{evsTestId("eraser")}}
}

// Whether file's signer is one of the world's admins.
func (self *testHeadWorld) isAdmin(file *indexFileVersion) bool {
	return slices.Contains(self.admins, file.signerSidecarId)
}

// The view at the head, read by writer.
func (self *testHeadWorld) view(t testing.TB, writer Id) *indexView {
	t.Helper()
	return testLoadViewWith(t, self.ref.store(writer), self.settings, self.admins...)
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

// Commits a plan at the base its view was read at, its files and removals, moving the world's clock a minute.
func (self *testHeadWorld) commit(t testing.TB, writer Id, plan *indexHeadPlan, view *indexView) (*indexCommitted, error) {
	t.Helper()
	committed, err := self.ref.store(writer).Commit(context.Background(), &indexPush{
		pushId:       NewId(),
		baseVersion:  view.head.version,
		indexEpoch:   view.head.indexEpoch,
		signedTimeMs: self.at.UnixMilli(),
		files:        plan.files(),
		removals:     plan.removals(),
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

// The newest bucket's view of writer's files.
func (self *testHeadWorld) writer(t testing.TB, writer Id) *indexViewWriter {
	t.Helper()
	view := self.view(t, writer)
	return view.writeRoot().newestBucket().writer(writer)
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

// Fills writer's head with documents of label from index on, one a push, until a push seals it; the index after the
// last.
func (self *testHeadWorld) fillUntilSealed(t testing.TB, writer Id, label string, index int) int {
	t.Helper()
	for ; ; index += 1 {
		plan := self.push(t, writer, testLive(label, index, 1, testIndexKeys(0x300000+index*0x1000, 1500, 1)))
		if len(plan.buckets[0].sealedSlots) != 0 {
			return index + 1
		}
		if 4096 < index {
			t.Fatal("no seal")
		}
	}
}

// The keys of document index at its version n: a base range with n keys moved, so each edit changes little.
func testHeadKeys(index int, n int) indexKeySet {
	keys := testIndexKeys(0x200000+index*0x1000, 200, 2)
	for edit := range n {
		keys[edit] += 1
	}
	return keys
}

// A live version of document index at version, with keys.
func testLive(label string, index int, version uint64, keys indexKeySet) *indexPendingDocument {
	return &indexPendingDocument{
		kind:    indexEntryFull,
		key:     testIndexId(label, index),
		version: version,
		keys:    keys,
		row:     testFileRow(keys),
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

// FS-107 (owner decision 584): D created and edited twice in one unsealed head, each full entry replacing the last;
// once the head seals, the next edit is full again in the new head, the sealed slot keeping the older version as it
// stood, and the edit after it replaces that one in the head. Every entry holds its version's whole key set.
func TestIndexHeadEditsAreFullEntries(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, testHeadKeys(1, 0)))
	world.push(t, a, testLive("d", 1, 2, testHeadKeys(1, 1)))
	if entries := world.entries(t, "d", 1); len(entries) != 1 || entries[0].kind != indexEntryFull || entries[0].version != 2 || !entries[0].head {
		t.Fatalf("D's entries %+v", entries)
	}
	world.fillUntilSealed(t, a, "fill", 2)
	world.push(t, a, testLive("d", 1, 3, testHeadKeys(1, 2)))
	world.push(t, a, testLive("d", 1, 4, testHeadKeys(1, 3)))
	entries := world.entries(t, "d", 1)
	if sealed := testEntryAt(t, entries, 2); sealed.kind != indexEntryFull || sealed.head || !slices.Equal(sealed.entry.keys, testHeadKeys(1, 1)) {
		t.Fatalf("D's v2 %+v", sealed)
	}
	if fourth := testEntryAt(t, entries, 4); fourth.kind != indexEntryFull || !fourth.head || !slices.Equal(fourth.entry.keys, testHeadKeys(1, 3)) {
		t.Fatalf("D's v4 %+v", fourth)
	}
	// the head's newer entry replaced v3's
	if len(entries) != 2 {
		t.Errorf("D in %d places", len(entries))
	}
}

// FS-107's large case: a big document's edit is a large entry of its own with its whole key set, beside the one it
// replaces until that one is absorbed and removed.
func TestIndexHeadLargeEditsAreLargeEntries(t *testing.T) {
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
	world.push(t, a, testLive("d", 1, 1, base))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 1); !entry.large || entry.kind != indexEntryFull {
		t.Fatalf("D's first version %+v", entry)
	}
	world.push(t, a, testLive("d", 1, 2, edit(3)))
	second := testEntryAt(t, world.entries(t, "d", 1), 2)
	if !second.large || second.kind != indexEntryFull || !slices.Equal(second.entry.keys, edit(3)) {
		t.Fatalf("D's second version %+v", second)
	}
	// the first, absorbed, goes at the writer's next push; the second stays
	first := testEntryAt(t, world.entries(t, "d", 1), 1)
	world.absorb(t, a, first.seq, testShardCopy("d", 1, 1, base))
	plan := world.push(t, a, testLive("d", 1, 3, edit(5)))
	if removals := plan.removals(); len(removals) != 1 {
		t.Fatalf("%d removals", len(removals))
	}
	writer := world.writer(t, a)
	if len(writer.large) != 2 || !slices.ContainsFunc(writer.large, func(file *indexViewSlot) bool { return file.slot.entries[0].version == 2 }) || !slices.ContainsFunc(writer.large, func(file *indexViewSlot) bool { return file.slot.entries[0].version == 3 }) {
		t.Errorf("after the third version: %d large entries", len(writer.large))
	}
}

// FS-107: another writer's edit is full, as every entry is, whether the first writer's version sits in its head or in
// a sealed slot, and so is the first writer's own next edit.
func TestIndexHeadAnotherWritersEditIsFull(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 1, 1, testHeadKeys(1, 0)))
	world.push(t, b, testLive("d", 1, 2, testHeadKeys(1, 1)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 2); entry.kind != indexEntryFull || entry.writer != b {
		t.Fatalf("B's edit on A's head %+v", entry)
	}
	world.fillUntilSealed(t, a, "fill", 2)
	world.push(t, b, testLive("d", 1, 3, testHeadKeys(1, 2)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 3); entry.kind != indexEntryFull || entry.writer != b {
		t.Fatalf("B's edit on A's sealed slot %+v", entry)
	}
	world.push(t, a, testLive("d", 1, 4, testHeadKeys(1, 3)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 4); entry.kind != indexEntryFull || entry.writer != a || !slices.Equal(entry.entry.keys, testHeadKeys(1, 3)) {
		t.Fatalf("A's edit %+v", entry)
	}
}

// R2, FS-74: one writer's two pushes from one base, one appending and one sealing its head, in both orders: the second
// to commit gets 409 on the head both write, and replanned at the new base it commits, nothing lost or doubled.
func TestIndexHeadTwoPushesOfOneWriterOnOneBase(t *testing.T) {
	for _, sealFirst := range []bool{false, true} {
		world := testNewHeadWorld()
		a := evsTestId("writer a")
		// the head holds what fits but one more entry of this size
		index := 1
		for ; ; index += 1 {
			plan, _ := world.plan(t, a, true, testLive("fill", index, 1, testIndexKeys(0x300000+index*0x1000, 1500, 1)))
			if 0 < len(world.view(t, a).writeRoot().buckets) && len(plan.buckets[0].sealedSlots) != 0 {
				break
			}
			world.push(t, a, testLive("fill", index, 1, testIndexKeys(0x300000+index*0x1000, 1500, 1)))
		}
		appending := testLive("small", 1, 1, testIndexKeys(0x700000, 3, 1))
		sealing := testLive("fill", index, 1, testIndexKeys(0x300000+index*0x1000, 1500, 1))
		planAppend, viewAppend := world.plan(t, a, true, appending)
		planSeal, viewSeal := world.plan(t, a, true, sealing)
		if len(planSeal.buckets[0].sealed) != 1 || planSeal.buckets[0].sealed[0].replaces == 0 || len(planAppend.buckets[0].sealedSlots) != 0 {
			t.Fatalf("the seal does not write the head it seals: %+v", planSeal.buckets[0])
		}
		first, firstView, second, secondView := planAppend, viewAppend, planSeal, viewSeal
		if sealFirst {
			first, firstView, second, secondView = planSeal, viewSeal, planAppend, viewAppend
		}
		if _, err := world.commit(t, a, first, firstView); err != nil {
			t.Fatal(err)
		}
		_, err := world.commit(t, a, second, secondView)
		if refusal, ok := indexRefusalOf(err); !ok || refusal.kind != indexRefusalConflict {
			t.Fatalf("seal first %v: the second push answered %v", sealFirst, err)
		}
		if sealFirst {
			world.push(t, a, appending)
		} else {
			world.push(t, a, sealing)
		}
		if entries := world.entries(t, "small", 1); len(entries) != 1 {
			t.Errorf("seal first %v: the appended document in %d places", sealFirst, len(entries))
		}
		if entries := world.entries(t, "fill", index); len(entries) != 1 {
			t.Errorf("seal first %v: the sealing document in %d places", sealFirst, len(entries))
		}
	}
}

// FS-107: a merge absorbs the slot holding D's older version and the writer reuses it at its next seal, whatever its
// head holds of D: no entry rests on the slot, so nothing keeps it, and D's newer version reads on from the slot that
// holds it.
func TestIndexHeadReusesItsAbsorbedSlot(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, testHeadKeys(1, 0)))
	next := world.fillUntilSealed(t, a, "fill", 2)
	// D's v2 is full in the head, slot 1, beside v1 in sealed slot 0
	world.push(t, a, testLive("d", 1, 2, testHeadKeys(1, 1)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 2); entry.kind != indexEntryFull || !entry.head {
		t.Fatalf("D's v2 %+v", entry)
	}
	before := world.writer(t, a)
	world.absorb(t, a, before.slotAt(0).seq(), testShardCopy("d", 1, 1, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "more", next)
	after := world.writer(t, a)
	if head := after.head(); head.path.slotIndex != 0 || after.slotAt(0).file.version == before.slotAt(0).file.version {
		t.Fatalf("the seal took slot %d, not the absorbed slot 0", head.path.slotIndex)
	}
	entries := world.entries(t, "d", 1)
	if first := testEntryAt(t, entries, 1); !first.shard {
		t.Errorf("D's v1 %+v", first)
	}
	if second := testEntryAt(t, entries, 2); second.kind != indexEntryFull || second.shard || second.head || !slices.Equal(second.entry.keys, testHeadKeys(1, 1)) {
		t.Errorf("D's v2 %+v", second)
	}
}

// A writer's absorbed large entries are removed at its next push in the bucket, and one above the watermark is left.
func TestIndexHeadRemovesAbsorbedLargeEntries(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	first, second, third := testIndexKeys(0, 9000, 3), testIndexKeys(1, 9000, 3), testIndexKeys(2, 9000, 3)
	world.push(t, a, testLive("big", 1, 1, first), testLive("big", 2, 1, second))
	writer := world.writer(t, a)
	if len(writer.large) != 2 {
		t.Fatalf("%d large entries", len(writer.large))
	}
	highest := max(writer.large[0].seq(), writer.large[1].seq())
	world.push(t, a, testLive("big", 3, 1, third))
	world.absorb(t, a, highest, testShardCopy("big", 1, 1, first), testShardCopy("big", 2, 1, second))
	plan := world.push(t, a, testLive("d", 9, 1, testHeadKeys(9, 0)))
	removals := plan.removals()
	if len(removals) != 2 {
		t.Fatalf("%d removals", len(removals))
	}
	for _, removal := range removals {
		if removed, _ := indexParsePath(removal.path, false); removed.kind != indexPathLargeEntry || highest < removed.seq {
			t.Errorf("removed %s", removal.path)
		}
	}
	if after := world.writer(t, a); len(after.large) != 1 || after.large[0].slot.entries[0].key != testIndexId("big", 3) {
		t.Errorf("after the push: %d large entries", len(after.large))
	}
}

// I8: a plan is a function of its inputs: run twice on one base and one document set, in two orders, it writes equal
// bytes and removes the same files.
func TestIndexHeadPlanIsAFunction(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, testHeadKeys(1, 0)), testLive("d", 2, 1, testHeadKeys(2, 0)))
	world.fillUntilSealed(t, a, "fill", 3)
	documents := []*indexPendingDocument{
		testLive("d", 1, 2, testHeadKeys(1, 1)), testLive("d", 2, 2, testHeadKeys(2, 1)),
		testRemoved("fill", 3, 2), testLive("big", 1, 1, testIndexKeys(0, 9000, 3)),
	}
	reversed := slices.Clone(documents)
	slices.Reverse(reversed)
	one, _ := world.plan(t, a, true, documents...)
	two, _ := world.plan(t, a, true, reversed...)
	oneFiles, twoFiles := one.files(), two.files()
	if len(oneFiles) == 0 || len(oneFiles) != len(twoFiles) || len(one.removals()) != len(two.removals()) {
		t.Fatalf("%d and %d files", len(oneFiles), len(twoFiles))
	}
	for index := range oneFiles {
		if oneFiles[index].path != twoFiles[index].path || oneFiles[index].replaces != twoFiles[index].replaces || !bytes.Equal(oneFiles[index].plaintext, twoFiles[index].plaintext) {
			t.Errorf("file %d differs", index)
		}
	}
}

// A version after a tombstone is a full entry replacing it in the head, and the erasure set's documents are left out
// of the push and out of the head the push rewrites.
func TestIndexHeadTombstonesAndTheErasureSet(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	// a signs the erasure set below, as an admin's CUT
	world.admins = append(world.admins, a)
	world.push(t, a, testLive("d", 1, 1, testHeadKeys(1, 0)), testLive("d", 2, 1, testHeadKeys(2, 0)))
	world.push(t, a, testRemoved("d", 1, 2))
	world.push(t, a, testLive("d", 1, 3, testHeadKeys(1, 1)))
	if entry := testEntryAt(t, world.entries(t, "d", 1), 3); entry.kind != indexEntryFull {
		t.Fatalf("after a tombstone %+v", entry)
	}

	erasureSet := &protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{{
		ErasureId: testIndexIdBytes("erasure", 1), EraserSidecarId: a.Bytes(), Epoch: 1,
		Docs: []*protocol.IndexErased{{DocKey: testIndexIdBytes("d", 2), Version: 5}},
	}}}
	world.ref.store(a).testCommit(t, world.at, &indexPushFile{path: indexErasureSetPath(false), plaintext: testSmallFile(t, erasureSet)})
	plan, _ := world.plan(t, a, true, testLive("d", 2, 2, testHeadKeys(2, 1)), testLive("d", 3, 1, testHeadKeys(3, 0)))
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
	if _, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{view: view, root: view.writeRoot(), writer: a, signedTimeMs: world.at.UnixMilli(), tables: testHeadTables, pending: []*indexPendingDocument{testLive("d", 4, 1, testHeadKeys(4, 0))}}); !errors.Is(err, errIndexErasureSetUnreadable) {
		t.Errorf("an unreadable erasure set planned %v", err)
	}
}

// FS-74: a head seals only when the next entry would pass SlotMax, never on idle; the sealed head is written again with
// its own bytes under its CAS (R2), the entry that did not fit opens the next slot as the head, and a push with nothing
// pending writes nothing.
func TestIndexHeadSealsOnlyAtItsCap(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	idle, _ := world.plan(t, a, true)
	if len(idle.files()) != 0 {
		t.Fatalf("an idle push writes %d files", len(idle.files()))
	}
	settings := world.settings
	for index := 1; ; index += 1 {
		before := world.view(t, a)
		var headBytes []byte
		if 0 < len(before.writeRoot().buckets) {
			stored, err := world.ref.store(a).Read(context.Background(), before.writeRoot().newestBucket().writer(a).head().file)
			if err != nil {
				t.Fatal(err)
			}
			headBytes = stored
		}
		document := testLive("fill", index, 1, testIndexKeys(0x300000+index*0x1000, 1500, 1))
		plan := world.push(t, a, document)
		bucket := plan.buckets[0]
		if len(bucket.sealedSlots) == 0 {
			if 1 < index && bucket.head.path.slotIndex != 0 {
				t.Fatalf("push %d opened slot %d", index, bucket.head.path.slotIndex)
			}
			continue
		}
		old := before.writeRoot().newestBucket().writer(a).head()
		entry := &indexEntry{kind: indexEntryFull, key: document.key, version: 1, timeSeconds: indexEntrySeconds(world.at.UnixMilli()), row: document.row, keys: document.keys}
		encoded, err := entry.appendEncoded(nil, false, DefaultIndexFormatSettings())
		if err != nil {
			t.Fatal(err)
		}
		if old.file.byteCount+len(encoded) <= settings.SlotMaxByteCount {
			t.Fatalf("sealed a head of %d B that could take %d B", old.file.byteCount, len(encoded))
		}
		// the sealed head written again as it stood
		if len(bucket.sealed) != 1 || bucket.sealed[0].replaces != old.file.version || bucket.sealed[0].path.slotIndex != old.path.slotIndex {
			t.Fatalf("the seal wrote %+v", bucket.sealed)
		}
		if !bytes.Equal(headBytes, bucket.sealed[0].file) {
			t.Errorf("the sealed head's bytes changed")
		}
		break
	}
	writer := world.writer(t, a)
	sealed, head := writer.slotAt(0), writer.head()
	if sealed == nil || head.path.slotIndex != 1 || head.seq() <= sealed.seq() || settings.SlotMaxByteCount < sealed.file.byteCount || len(head.slot.entries) != 1 {
		t.Fatalf("after the seal: sealed %+v, head %+v", sealed, head)
	}
}

// The ring: a writer reuses its lowest absorbed slot; with none, new slots while it holds fewer than RingSlots; at a
// ninth it merges first, or, unable to, takes it and alarms; with every slot held, it writes nothing.
func TestIndexHeadSlotRing(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	settings := world.settings
	fill := func(index int) *indexPendingDocument {
		return testLive("fill", index, 1, testIndexKeys(0x300000+index*0x400, 7000, 1))
	}
	index := 1
	for k := 0; k < settings.RingSlotCount; k += 1 {
		plan := world.push(t, a, fill(index), fill(index+1))
		index += 2
		if plan.buckets[0].head.path.slotIndex == uint32(settings.RingSlotCount-1) {
			break
		}
	}
	// slot 7 is the head and holds what fits: the next seal would hold a ninth slot
	plan, _ := world.plan(t, a, true, fill(index), fill(index+1), fill(index+2))
	if !plan.mergeFirst || len(plan.files()) != 0 {
		t.Fatalf("a full ring that may merge planned %+v", plan)
	}
	plan, view := world.plan(t, a, false, fill(index), fill(index+1), fill(index+2))
	if plan.mergeFirst || !plan.pastRing || plan.buckets[0].head.path.slotIndex < uint32(settings.RingSlotCount) {
		t.Fatalf("a full ring that may not merge planned %+v", plan)
	}
	if _, err := world.commit(t, a, plan, view); err != nil {
		t.Fatal(err)
	}

	// a merge absorbs slots 0 and 1: the next seal reuses slot 0
	writer := world.writer(t, a)
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

	// every slot held and none absorbed, the head full to its cap
	full := &indexViewWriter{sidecarId: a}
	for k := range uint32(indexWriterSlotCount) {
		slot := &indexSlot{header: &protocol.IndexFileHeader{Seq: k + 1}}
		if k == indexWriterSlotCount-1 {
			slot = testSlotOfLength(t, settings.SlotMaxByteCount)
			slot.header.Seq = k + 1
		}
		full.slots = append(full.slots, &indexViewSlot{path: indexPath{kind: indexPathSlot, slotIndex: k}, slot: slot, file: &indexFileVersion{version: 1}})
	}
	bucket := &indexViewBucket{window: indexBucketWindow{startDay: 20340, days: 30}, writers: []*indexViewWriter{full}}
	args := &indexHeadPlanArgs{view: world.view(t, a), writer: a, tables: testHeadTables}
	work := &indexHeadBucketWork{window: bucket.window, bucket: bucket, writer: full, entries: []*indexEntry{{kind: indexEntryTombstone, key: testIndexId("x", 1), version: 1}}}
	err := indexPlaceEntries(args, args.view.writeRoot(), work, &indexHeadPlanBucket{window: bucket.window}, &indexHeadPlan{})
	if !errors.Is(err, errIndexNoFreeSlot) {
		t.Errorf("a writer holding every slot answered %v", err)
	}
}

// A large entry takes the next seq, and the head is renumbered above it, so the head always holds its writer's highest
// seq and no merge's watermark covers it; a writer with no slot in the bucket gets slot 0 beside its large entry.
func TestIndexHeadStaysAboveItsLargeEntries(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 1, 1, testHeadKeys(1, 0)))
	plan := world.push(t, a, testLive("big", 1, 1, testIndexKeys(0, 9000, 3)))
	if len(plan.buckets[0].large) != 1 || plan.buckets[0].head == nil {
		t.Fatalf("plan %+v", plan.buckets[0])
	}
	writer := world.writer(t, a)
	if writer.head().seq() != 3 || writer.large[0].seq() != 2 || writer.highestSeq() != writer.head().seq() {
		t.Errorf("head seq %d, large seq %d", writer.head().seq(), writer.large[0].seq())
	}
	only := world.push(t, b, testLive("big", 2, 1, testIndexKeys(1, 9000, 3)))
	if head := only.buckets[0].head; head == nil || head.path.slotIndex != 0 || head.replaces != 0 || len(head.slot.entries) != 0 || head.slot.header.Seq != 2 {
		t.Errorf("a writer's first push of a large entry alone wrote head %+v", head)
	}
}

// A push whose entries pass DirectBytes goes straight into the bucket's shards, a merge inside the push, and writes
// the writer's head there without the keys it carried.
func TestIndexHeadPastDirectBytesWritesItsHead(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("bulk", 0, 1, testIndexKeys(0, 7000, 1)), testLive("d", 1, 1, testHeadKeys(1, 0)))
	pending := []*indexPendingDocument{}
	for index := range 40 {
		pending = append(pending, testLive("bulk", index, 2, testIndexKeys(index*0x10000, 7000, 1)))
	}
	plan, _ := world.plan(t, a, true, pending...)
	if !plan.mergeInPush || len(plan.buckets) != 1 || len(plan.buckets[0].direct) != 40 {
		t.Fatalf("plan %+v", plan)
	}
	for _, entry := range plan.buckets[0].direct {
		if entry.kind != indexEntryFull {
			t.Fatalf("a direct entry of kind %d", entry.kind)
		}
	}
	head := plan.buckets[0].head
	if files := plan.files(); len(files) != 1 || head == nil || head.replaces == 0 || len(head.slot.entries) != 1 || head.slot.entries[0].key != testIndexId("d", 1) {
		t.Errorf("the head past DirectBytes: %+v", head)
	}
}

// A document held in a newer bucket takes its next entry there, whatever the push's own window; the writer, holding no
// slot there, gets slot 0 for it.
func TestIndexHeadFollowsANewerBucketHoldingTheDocument(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("seed", 1, 1, testHeadKeys(8, 0)))
	world.at = testDayTime(testBoundaryDay, 5*time.Minute)
	world.push(t, b, testLive("d", 1, 1, testHeadKeys(1, 0)))
	world.at = testDayTime(testBoundaryDay, -5*time.Minute)
	plan, _ := world.plan(t, a, true, testLive("d", 1, 2, testHeadKeys(1, 1)), testLive("e", 1, 1, testHeadKeys(2, 0)))
	if len(plan.buckets) != 2 || plan.buckets[0].window.startDay != 20340 || plan.buckets[1].window.startDay != testBoundaryDay {
		t.Fatalf("buckets %+v", plan.buckets)
	}
	if head := plan.buckets[1].head; head.path.slotIndex != 0 || len(head.slot.entries) != 1 || head.slot.entries[0].key != testIndexId("d", 1) {
		t.Errorf("the newer bucket took %d entries", len(head.slot.entries))
	}
}

// An entry late into the previous bucket is full there, as in the current one: the bucket need not be the newest.
func TestIndexHeadLateEntryIsFull(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 1, 1, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "fill", 2)
	// B, ahead of the boundary, opens the next bucket with another document
	world.at = testDayTime(testBoundaryDay, 5*time.Minute)
	world.push(t, b, testLive("other", 1, 1, testHeadKeys(9, 0)))
	// A, its clock behind, signs its edit of D in the previous window
	world.at = testDayTime(testBoundaryDay, -5*time.Minute)
	plan, _ := world.plan(t, a, true, testLive("d", 1, 2, testHeadKeys(1, 1)))
	if len(plan.buckets) != 1 || plan.buckets[0].window.startDay != 20340 {
		t.Fatalf("A's late edit went to %+v", plan.buckets)
	}
	entries := plan.buckets[0].head.slot.entries
	if entry := entries[slices.IndexFunc(entries, func(entry *indexEntry) bool { return entry.key == testIndexId("d", 1) })]; entry.kind != indexEntryFull || !slices.Equal(entry.keys, testHeadKeys(1, 1)) {
		t.Errorf("a late entry is a %v", entry.kind)
	}
}

// FS-74 at unit level: two writers' pushes from one base, each changing only its own head, both commit; one writer's
// two pushes from one base race on its head, the second gets 409 naming it, and replanned at the new base it commits
// with nothing lost and nothing doubled.
func TestIndexHeadRacingPushes(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 1, 1, testHeadKeys(1, 0)))
	planA, viewA := world.plan(t, a, true, testLive("d", 2, 1, testHeadKeys(2, 0)))
	planB, viewB := world.plan(t, b, true, testLive("d", 3, 1, testHeadKeys(3, 0)))
	first, err := world.commit(t, a, planA, viewA)
	if err != nil {
		t.Fatal(err)
	}
	second, err := world.commit(t, b, planB, viewB)
	if err != nil || second.version != first.version+1 {
		t.Fatalf("B's push at %+v, %v", second, err)
	}

	planOne, viewOne := world.plan(t, a, true, testLive("d", 4, 1, testHeadKeys(4, 0)))
	planTwo, viewTwo := world.plan(t, a, true, testLive("d", 5, 1, testHeadKeys(5, 0)))
	if _, err := world.commit(t, a, planOne, viewOne); err != nil {
		t.Fatal(err)
	}
	_, err = world.commit(t, a, planTwo, viewTwo)
	refusal, ok := indexRefusalOf(err)
	if !ok || refusal.kind != indexRefusalConflict || len(refusal.paths) != 1 || refusal.paths[0] != planTwo.files()[0].path {
		t.Fatalf("the racing push answered %v", err)
	}
	world.push(t, a, testLive("d", 5, 1, testHeadKeys(5, 0)))
	head := world.writer(t, a).head()
	for _, index := range []int{1, 2, 4, 5} {
		key := testIndexId("d", index)
		if !slices.ContainsFunc(head.slot.entries, func(entry *indexEntry) bool { return entry.key == key }) {
			t.Errorf("A's head lost d%d", index)
		}
	}
	if len(head.slot.entries) != 4 {
		t.Errorf("A's head holds %d entries", len(head.slot.entries))
	}
}

// One head vector: a scenario's files, each with its plaintext hash, and its removals.
type testHeadVector struct {
	Name     string               `json:"name"`
	Files    []testHeadVectorFile `json:"files"`
	Removals []string             `json:"removals,omitempty"`
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
	for _, removal := range plan.removals() {
		vector.Removals = append(vector.Removals, removal.path)
	}
	return vector
}

// D-TEST-15, the head/ list as plaintext, pinned with their hashes, every entry full or a tombstone (owner decision
// 584): a first entry; a second edit while the first is in the head, replacing it; a seal as the head stood, its bytes
// written again; an edit after the seal, full in the new head; a seal that reuses an absorbed slot; a big document, a
// large entry, and its edit, another; a removal's tombstone and a creation after it; an absorbed large entry removed
// and an unabsorbed one left; a push past DirectBytes. SIDECAR_WRITE_VECTORS rewrites them.
func TestIndexHeadVectors(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	built := []testHeadVector{}
	record := func(name string, pending ...*indexPendingDocument) *indexHeadPlan {
		plan, view := world.plan(t, a, true, pending...)
		built = append(built, testHeadVectorOf(name, plan))
		if !plan.mergeInPush {
			if _, err := world.commit(t, a, plan, view); err != nil {
				t.Fatal(err)
			}
		}
		return plan
	}
	fill := func(index int) *indexPendingDocument {
		return testLive("v", index, 1, testIndexKeys(0x300000+index*0x1000, 1500, 1))
	}
	// fills from index until one seals the head, recorded as name; the index after it
	sealWith := func(name string, index int) int {
		for ; ; index += 1 {
			plan, _ := world.plan(t, a, true, fill(index))
			if len(plan.buckets[0].sealedSlots) != 0 {
				record(name, fill(index))
				return index
			}
			record("", fill(index))
		}
	}
	record("first-entry-full", testLive("v", 1, 1, testHeadKeys(1, 0)))
	record("edit-in-the-head-full", testLive("v", 1, 2, testHeadKeys(1, 1)))
	// slot 0 sealed as it stood, v1's v2 in it; the fill that sealed it opens slot 1
	sealIndex := sealWith("seal-as-it-stood", 10)
	record("edit-after-a-seal-full", testLive("v", 1, 3, testHeadKeys(1, 2)))
	// slot 0 absorbed, v1's v3 full in the head: the next seal reuses slot 0
	world.absorb(t, a, world.writer(t, a).slotAt(0).seq(), testShardCopy("v", 1, 2, testHeadKeys(1, 1)))
	sealWith("seal-reuses-an-absorbed-slot", sealIndex+1)
	large := testIndexKeys(0, 9000, 3)
	record("large-entry", testLive("v", 2, 1, large))
	largeEdit := slices.Clone(large)
	largeEdit[10] += 1
	// the first large entry absorbed, the edit's not: the edit's push leaves both, the first not yet absorbed at its base
	record("large-entry-edit", testLive("v", 2, 2, largeEdit))
	record("", testLive("v", 3, 1, testHeadKeys(3, 1)))
	record("removal-tombstone", testRemoved("v", 3, 2))
	record("creation-after-a-removal-full", testLive("v", 3, 3, testHeadKeys(3, 2)))
	// the first large entry absorbed and removed at the next push, the edit's, above the watermark, left
	lowest := uint32(0)
	for _, file := range world.writer(t, a).large {
		if lowest == 0 || file.seq() < lowest {
			lowest = file.seq()
		}
	}
	world.absorb(t, a, lowest, testShardCopy("v", 2, 1, large))
	record("absorbed-large-entry-removed", testLive("v", 5, 1, testHeadKeys(5, 0)))
	pending := []*indexPendingDocument{}
	for bulk := range 40 {
		pending = append(pending, testLive("bulk", bulk, 1, testIndexKeys(bulk*0x10000, 7000, 1)))
	}
	record("past-direct-bytes", pending...)

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
		if held[index].Name != vector.Name || len(held[index].Files) != len(vector.Files) || !slices.Equal(held[index].Removals, vector.Removals) {
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
	// what each vector shows, read from the files it pins
	byName := map[string]testHeadVector{}
	for _, vector := range named {
		byName[vector.Name] = vector
	}
	entryOf := func(name string, key [indexIdByteCount]byte) *indexEntry {
		for _, file := range byName[name].Files {
			plaintext := mustHex(t, file.Hex)
			sum := sha256.Sum256(plaintext)
			slot, err := indexDecodeSlot(plaintext, sum[:], false, DefaultIndexFormatSettings())
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			for _, entry := range slot.entries {
				if entry.key == key {
					return entry
				}
			}
		}
		return nil
	}
	for _, c := range []struct {
		name    string
		key     [indexIdByteCount]byte
		kind    indexEntryKind
		version uint64
		keys    indexKeySet
	}{
		{name: "first-entry-full", key: testIndexId("v", 1), kind: indexEntryFull, version: 1, keys: testHeadKeys(1, 0)},
		{name: "edit-in-the-head-full", key: testIndexId("v", 1), kind: indexEntryFull, version: 2, keys: testHeadKeys(1, 1)},
		{name: "edit-after-a-seal-full", key: testIndexId("v", 1), kind: indexEntryFull, version: 3, keys: testHeadKeys(1, 2)},
		{name: "large-entry", key: testIndexId("v", 2), kind: indexEntryFull, version: 1, keys: large},
		{name: "large-entry-edit", key: testIndexId("v", 2), kind: indexEntryFull, version: 2, keys: largeEdit},
		{name: "removal-tombstone", key: testIndexId("v", 3), kind: indexEntryTombstone, version: 2},
		{name: "creation-after-a-removal-full", key: testIndexId("v", 3), kind: indexEntryFull, version: 3, keys: testHeadKeys(3, 2)},
	} {
		entry := entryOf(c.name, c.key)
		if entry == nil || entry.kind != c.kind || entry.version != c.version || !slices.Equal(entry.keys, c.keys) {
			t.Errorf("%s: %+v", c.name, entry)
		}
	}
	// no vector holds the reserved kind 2: every entry of every file is full or a tombstone
	for _, vector := range named {
		for _, file := range vector.Files {
			plaintext := mustHex(t, file.Hex)
			sum := sha256.Sum256(plaintext)
			slot, err := indexDecodeSlot(plaintext, sum[:], false, DefaultIndexFormatSettings())
			if err != nil {
				t.Fatalf("%s: %v", vector.Name, err)
			}
			for _, entry := range slot.entries {
				if entry.kind != indexEntryFull && entry.kind != indexEntryTombstone {
					t.Errorf("%s: %s holds an entry of kind %d", vector.Name, file.Path, entry.kind)
				}
			}
		}
	}
	if stood := byName["seal-as-it-stood"]; len(stood.Files) != 2 || stood.Files[0].Replaces == 0 {
		t.Errorf("seal-as-it-stood writes %d files", len(stood.Files))
	}
	if removed := byName["absorbed-large-entry-removed"]; len(removed.Removals) != 1 {
		t.Errorf("absorbed-large-entry-removed removes %v", removed.Removals)
	}
	if edit := byName["large-entry-edit"]; len(edit.Removals) != 0 {
		t.Errorf("large-entry-edit removes %v", edit.Removals)
	}
	reused := false
	for _, file := range byName["seal-reuses-an-absorbed-slot"].Files {
		if path, _ := indexParsePath(file.Path, false); path.kind == indexPathSlot && path.slotIndex == 0 && file.Replaces != 0 {
			reused = true
		}
	}
	if !reused {
		t.Errorf("seal-reuses-an-absorbed-slot does not write the absorbed slot 0")
	}
	if direct := byName["past-direct-bytes"]; len(direct.Files) != 1 {
		t.Errorf("past-direct-bytes writes %d files, not its head alone", len(direct.Files))
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

// A push carries one entry a document: two of one key are refused before anything is planned.
func TestIndexHeadRefusesADocumentTwice(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	view := world.view(t, a)
	_, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: a, signedTimeMs: world.at.UnixMilli(), tables: testHeadTables,
		pending: []*indexPendingDocument{testLive("d", 1, 2, testHeadKeys(1, 1)), testRemoved("d", 1, 3)},
	})
	if !errors.Is(err, errIndexMalformed) {
		t.Errorf("a document twice planned %v", err)
	}
}

// A slot's raw bytes from its header and entries, bypassing the encoder's own checks, for a decoder to judge.
func testRawSlot(t testing.TB, header *protocol.IndexFileHeader, entries ...*indexEntry) []byte {
	t.Helper()
	body := []byte{}
	for _, entry := range entries {
		var err error
		if body, err = entry.appendEncoded(body, false, DefaultIndexFormatSettings()); err != nil {
			t.Fatal(err)
		}
	}
	header = proto.CloneOf(header)
	header.Count = uint32(len(entries))
	header.BodyLength = uint32(len(body))
	encoded, err := indexMarshalHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	file := indexAppendVByte([]byte(indexFileMagic), uint64(len(encoded)))
	return append(append(file, encoded...), body...)
}

// DESIGN-DETAILS 1.2.2's coverage (QD-689, reading 4): rows ascend by ref_id, then horizon false before true, at most
// one of each kind a ref. The encoder sorts them so; a decoder refuses another order and a kind twice.
func TestIndexSlotCoverageHoldsTwoRowsARef(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	refA, refB := testIndexIdBytes("ref", 1), testIndexIdBytes("ref", 2)
	if 0 < bytes.Compare(refA, refB) {
		refA, refB = refB, refA
	}
	header := func(coverage ...*protocol.IndexCoverage) *protocol.IndexFileHeader {
		header := indexNewFileHeader(indexFileSlot, testHeadTables)
		header.BucketStartDay, header.BucketDays, header.WriterSidecarId, header.Seq = 20340, 30, evsTestId("writer a").Bytes(), 1
		header.Coverage = coverage
		return header
	}
	both := []*protocol.IndexCoverage{{RefId: refB, Version: 9}, {RefId: refA, Version: 4, Horizon: true}, {RefId: refA, Version: 7}}
	file, err := indexEncodeSlot(&indexSlot{header: header(both...)}, false, settings)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(file)
	slot, err := indexDecodeSlot(file, sum[:], false, settings)
	if err != nil {
		t.Fatal(err)
	}
	if coverage := slot.header.Coverage; len(coverage) != 3 || !bytes.Equal(coverage[0].RefId, refA) || coverage[0].Horizon || !coverage[1].Horizon || !bytes.Equal(coverage[2].RefId, refB) {
		t.Errorf("coverage encoded as %v", coverage)
	}
	for _, coverage := range [][]*protocol.IndexCoverage{
		{{RefId: refA, Horizon: true}, {RefId: refA}},
		{{RefId: refA}, {RefId: refA, Version: 3}},
		{{RefId: refB}, {RefId: refA}},
	} {
		raw := testRawSlot(t, header(coverage...))
		sum := sha256.Sum256(raw)
		if _, err := indexDecodeSlot(raw, sum[:], false, settings); !errors.Is(err, errIndexMalformed) {
			t.Errorf("coverage %v decoded, %v", coverage, err)
		}
	}
}

// A large entry's one entry is full: the encoder refuses a large entry holding a tombstone, and so does the decoder.
func TestIndexLargeEntryHoldsOneFullEntry(t *testing.T) {
	settings := DefaultIndexFormatSettings()
	base := testIndexKeys(0, 30000, 3)
	tombstone := &indexEntry{kind: indexEntryTombstone, key: testIndexId("d", 1), version: 2, timeSeconds: 1}
	header := indexNewFileHeader(indexFileLargeEntry, testHeadTables)
	header.BucketStartDay, header.BucketDays, header.WriterSidecarId, header.Seq = 20340, 30, evsTestId("writer a").Bytes(), 1
	if _, err := indexEncodeSlot(&indexSlot{header: header, entries: []*indexEntry{tombstone}}, false, settings); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a large entry holding a tombstone encoded, %v", err)
	}
	raw := testRawSlot(t, header, tombstone)
	sum := sha256.Sum256(raw)
	if _, err := indexDecodeSlot(raw, sum[:], false, settings); !errors.Is(err, errIndexMalformed) {
		t.Errorf("a large entry holding a tombstone decoded, %v", err)
	}
	full := &indexEntry{kind: indexEntryFull, key: testIndexId("d", 1), version: 1, timeSeconds: 1, row: testFileRow(base), keys: base}
	if _, err := indexEncodeSlot(&indexSlot{header: header, entries: []*indexEntry{full}}, false, settings); err != nil {
		t.Errorf("a large entry holding a full entry: %v", err)
	}
}
