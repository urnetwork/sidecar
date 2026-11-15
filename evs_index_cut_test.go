//go:build !ios_extension

package sidecar

// SEARCH-M10-16 (§11.12's cut row; §11.14's cut and epoch rows; FS-111 at unit level on the fake): a CUT writes the
// erasure set and moves the epoch, joins an erasure listed again, lists a card through the epoch it names and again
// through a rebuilt one, drops complete erasures only by raising listed_since, and waits on a full set; the epoch guard
// refuses what the set lists; each kind of prepared push built before a CUT (a companion push to a fresh head path, a
// large entry, a merge's shard, a backfill's head, a reused old slot) gets 409 INDEX_EPOCH and rebuilds without the
// document; a journal begun below listed_since is extracted again from the text, where the erased document no longer
// opens; and builders and readers ignore and alarm an erasure set from a signer who may not erase.

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// The tests' admin judge: the eraser's versions count, settings and erasure set alike.
func testIndexEraserAdmin(file *indexFileVersion) bool {
	return file.signerSidecarId == evsTestId("eraser")
}

// An eraser of a ref through store, signing as the eraser, complete answering from complete.
func testNewEraser(t testing.TB, store indexRefStore, companion bool, clock Clock, complete map[Id]bool) *IndexEraser {
	t.Helper()
	eraser, err := indexNewEraser(&indexEraserArgs{
		store:     store,
		repoId:    evsTestId("view repo"),
		refId:     evsTestId("view ref"),
		repoKind:  protocol.RepoKind_REPO_KIND_GENERAL,
		companion: companion,
		isAdmin:   testIndexEraserAdmin,
		format:    DefaultIndexFormatSettings(),
		eraser:    evsTestId("eraser"),
		complete: func(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
			answer := map[Id]bool{}
			for _, erasureId := range erasureIds {
				answer[erasureId] = complete[erasureId]
			}
			return answer, nil
		},
		clock: clock,
		log:   NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return eraser
}

// Commits a CUT listing documents under erasure label, failing on any error.
func testCut(t testing.TB, eraser *IndexEraser, label string, documents ...*IndexCutDocument) *IndexCutResult {
	t.Helper()
	result, err := eraser.Cut(context.Background(), &IndexCutArgs{ErasureId: evsTestId(label), Documents: documents})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// The erasure set at the head, as a reader whose eraser counts reads it.
func testErasureSetOf(t testing.TB, view *indexView) *protocol.IndexErasureSet {
	t.Helper()
	if view.erasureSetUnreadable || view.erasureSet == nil {
		t.Fatal("no erasure set reads")
	}
	return view.erasureSet
}

// §11.12's cut row: the CUT changes the erasure set alone, names the head's epoch and moves it to its own version;
// asked again with nothing new it pushes nothing; called for an erasure the set lists, the documents join that entry,
// whose epoch and cut_ms stay.
func TestIndexCutWritesTheErasureSetAndMovesTheEpoch(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, nil)
	before := world.view(t, a)
	result := testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: testIndexId("d", 2), Version: 3}, &IndexCutDocument{Key: testIndexId("d", 1), Version: 1})
	if !result.Pushed || result.Epoch != before.head.indexEpoch || result.Version != before.head.version+1 {
		t.Fatalf("the CUT: %+v", result)
	}
	view := world.view(t, a)
	if view.head.indexEpoch != result.Version {
		t.Fatalf("the epoch is %d, not the CUT's version %d", view.head.indexEpoch, result.Version)
	}
	set := testErasureSetOf(t, view)
	if len(set.Erasures) != 1 {
		t.Fatalf("%d erasures", len(set.Erasures))
	}
	erasure := set.Erasures[0]
	if Id(erasure.ErasureId) != evsTestId("erasure 1") || Id(erasure.EraserSidecarId) != evsTestId("eraser") || erasure.Epoch != before.head.indexEpoch || erasure.CutMs != world.at.UnixMilli() {
		t.Fatalf("the erasure %+v", erasure)
	}
	listedVersions := map[[indexIdByteCount]byte]uint64{}
	for index, erased := range erasure.Docs {
		listedVersions[[indexIdByteCount]byte(erased.DocKey)] = erased.Version
		if 0 < index && string(erasure.Docs[index-1].DocKey) >= string(erased.DocKey) {
			t.Fatal("the documents are not sorted by doc_key")
		}
	}
	if len(erasure.Docs) != 2 || listedVersions[testIndexId("d", 1)] != 1 || listedVersions[testIndexId("d", 2)] != 3 {
		t.Fatalf("the documents %+v", erasure.Docs)
	}
	if !view.erased(testIndexId("d", 1), 1) || view.erased(testIndexId("d", 1), 2) || !view.erased(testIndexId("d", 2), 3) {
		t.Fatal("the view reads the set wrong")
	}

	// nothing new: nothing pushed
	again := testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: testIndexId("d", 1), Version: 1})
	if again.Pushed || world.view(t, a).head.version != view.head.version {
		t.Fatalf("a CUT of nothing new pushed: %+v", again)
	}

	// a late copy: the documents join the entry, its epoch and cut_ms kept
	cutMs := erasure.CutMs
	world.at = world.at.Add(5 * 60 * 1e9)
	joined := testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: testIndexId("d", 3), Version: 2}, &IndexCutDocument{Key: testIndexId("d", 1), Version: 2})
	if !joined.Pushed || joined.Epoch != view.head.indexEpoch {
		t.Fatalf("the joining CUT: %+v", joined)
	}
	set = testErasureSetOf(t, world.view(t, a))
	if len(set.Erasures) != 1 || set.Erasures[0].Epoch != before.head.indexEpoch || set.Erasures[0].CutMs != cutMs || len(set.Erasures[0].Docs) != 3 {
		t.Fatalf("the joined erasure %+v", set.Erasures)
	}
	for _, erased := range set.Erasures[0].Docs {
		if [indexIdByteCount]byte(erased.DocKey) == testIndexId("d", 1) && erased.Version != 2 {
			t.Fatal("a document listed again kept its lower version")
		}
	}
}

// DESIGN-DETAILS 15.2.10's step 4: a card is listed through the epoch the CUT names; when another CUT lands first,
// the CUT is refused 409 INDEX_EPOCH and built again, listing the card through the new epoch.
func TestIndexCutListsACardThroughTheEpochItNames(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, nil)
	testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: testIndexId("d", 1), Version: 1})
	other := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, nil)
	world.ref.beforeCommit = func(push *indexPush) {
		world.ref.beforeCommit = nil
		testCut(t, other, "erasure 3", &IndexCutDocument{Key: testIndexId("d", 9), Version: 1})
	}
	card := testIndexId("card", 1)
	result := testCut(t, eraser, "erasure 2", &IndexCutDocument{Key: card, ThroughEpoch: true})
	view := world.view(t, a)
	if result.Attempts != 2 || result.Epoch != view.head.indexEpoch-1 || result.Version != view.head.indexEpoch {
		t.Fatalf("the rebuilt CUT: %+v at epoch %d", result, view.head.indexEpoch)
	}
	through := result.Epoch<<32 | 0xffffffff
	set := testErasureSetOf(t, view)
	found := false
	for _, erasure := range set.Erasures {
		if Id(erasure.ErasureId) == evsTestId("erasure 2") {
			found = true
			if erasure.Epoch != result.Epoch || len(erasure.Docs) != 1 || erasure.Docs[0].Version != through {
				t.Fatalf("the card's listing %+v, want through %d", erasure, through)
			}
		}
	}
	if !found || len(set.Erasures) != 3 {
		t.Fatalf("the set %+v", set.Erasures)
	}
	if !view.erased(card, result.Epoch<<32) || view.erased(card, (result.Epoch+1)<<32) {
		t.Fatal("the card is not listed exactly through its epoch")
	}
	if got := indexCardVersionThrough(1<<40, 32); got != 1<<64-1 {
		t.Fatalf("an epoch past 2^32 lists through %d", got)
	}
}

// §11.12's cut row: a complete erasure goes only by raising listed_since past its epoch; a pending one stays whatever
// its epoch.
func TestIndexCutDropsCompleteErasuresByListedSince(t *testing.T) {
	world := testNewHeadWorld()
	clock := &testIndexWorldClock{world: world}
	complete := map[Id]bool{}
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, clock, complete)
	x := testCut(t, eraser, "erasure x", &IndexCutDocument{Key: testIndexId("x", 1), Version: 1})
	y := testCut(t, eraser, "erasure y", &IndexCutDocument{Key: testIndexId("y", 1), Version: 1})
	z := testCut(t, eraser, "erasure z", &IndexCutDocument{Key: testIndexId("z", 1), Version: 1})
	complete[evsTestId("erasure x")] = true
	complete[evsTestId("erasure z")] = true
	w := testCut(t, eraser, "erasure w", &IndexCutDocument{Key: testIndexId("w", 1), Version: 1})
	if w.DroppedCount != 2 {
		t.Fatalf("dropped %d", w.DroppedCount)
	}
	set := testErasureSetOf(t, world.view(t, evsTestId("reader")))
	if set.ListedSince != z.Epoch+1 {
		t.Fatalf("listed_since %d, want past z's epoch %d", set.ListedSince, z.Epoch)
	}
	ids := []Id{}
	for _, erasure := range set.Erasures {
		ids = append(ids, Id(erasure.ErasureId))
		if erasure.Epoch < set.ListedSince && Id(erasure.ErasureId) != evsTestId("erasure y") {
			t.Errorf("an erasure below listed_since that is not pending stayed")
		}
	}
	if len(ids) != 2 || !slices.Contains(ids, evsTestId("erasure y")) || !slices.Contains(ids, evsTestId("erasure w")) {
		t.Fatalf("the erasures left %v", ids)
	}
	if x.Epoch >= y.Epoch || y.Epoch >= z.Epoch {
		t.Fatal("the epochs do not rise")
	}
}

// §11.12's cut row: a set that cannot hold the erasure beside the pending ones makes the CUT wait; once a pending one
// completes, the CUT drops it and lands.
func TestIndexCutWaitsOnAFullSet(t *testing.T) {
	world := testNewHeadWorld()
	complete := map[Id]bool{}
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, complete)
	documents := func(label string, count int) []*IndexCutDocument {
		listed := []*IndexCutDocument{}
		for index := range count {
			listed = append(listed, &IndexCutDocument{Key: testIndexId(label, index), Version: 1})
		}
		return listed
	}
	testCut(t, eraser, "erasure 1", documents("big", 550)...)
	head := world.view(t, evsTestId("reader")).head.version
	_, err := eraser.Cut(context.Background(), &IndexCutArgs{ErasureId: evsTestId("erasure 2"), Documents: documents("more", 200)})
	if !errors.Is(err, ErrIndexErasureSetFull) {
		t.Fatalf("a full set answered %v", err)
	}
	if world.view(t, evsTestId("reader")).head.version != head {
		t.Fatal("a CUT on a full set pushed")
	}
	complete[evsTestId("erasure 1")] = true
	result := testCut(t, eraser, "erasure 2", documents("more", 200)...)
	if result.DroppedCount != 1 || len(result.Set.Erasures) != 1 {
		t.Fatalf("after the pending erasure completed: %+v", result)
	}
}

// The epoch guard: a push names its view's base and epoch; a file holding a listed document at or below its version, a
// shard row of one, or a diff written anew on a listed base is refused; a resting diff a head carries forward at its
// own path passes; only a CUT writes the set, and a CLOSURE never goes through the guard.
func TestIndexEpochGuardRefusesWhatTheSetLists(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "fill", 2)
	world.push(t, a, testLive("d", 1, 2, 1, testHeadKeys(1, 1)))
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, nil)
	testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: testIndexId("d", 1), Version: 1})
	view := world.view(t, a)
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		t.Fatal(err)
	}
	head := view.writeRoot().newestBucket().writer(a).head()
	if diff := head.slot.entries; !slices.ContainsFunc(diff, func(entry *indexEntry) bool { return entry.kind == indexEntryDiff && entry.baseVersion == 1 }) {
		t.Fatal("no resting diff in the head")
	}
	plaintext, err := view.store.Read(context.Background(), head.file)
	if err != nil {
		t.Fatal(err)
	}
	// carried at its own path, the head written again with its own bytes: passes
	if err := guard.checkFiles([]*indexPushFile{{path: head.file.path, plaintext: plaintext, replaces: head.file.version}}, false); err != nil {
		t.Fatalf("a carried resting diff refused: %v", err)
	}
	// the same diff written at a new path: refused
	paths := view.writeRoot().paths
	fresh, _ := paths.slot(view.writeRoot().newestBucket().window.startDay, [indexIdByteCount]byte(a), 15)
	if err := guard.checkFiles([]*indexPushFile{{path: fresh, plaintext: plaintext}}, false); !errors.Is(err, errIndexEpochListed) {
		t.Fatalf("a new diff on a listed base: %v", err)
	}
	// a listed version's full entry: refused
	window := view.writeRoot().newestBucket().window
	listed := testViewSlotFile(t, window, a, 9, indexFileSlot, testViewEntry("d", 1, 1, world.at.UnixMilli(), testHeadKeys(1, 0)))
	if err := guard.checkFiles([]*indexPushFile{{path: fresh, plaintext: listed}}, false); !errors.Is(err, errIndexEpochListed) {
		t.Fatalf("a listed version's entry: %v", err)
	}
	// a shard row of it: refused
	shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: []*indexShardDocument{testShardCopy("d", 1, 1, testHeadKeys(1, 0))}}
	shard.header.BucketStartDay, shard.header.BucketDays = window.startDay, window.days
	if err := guard.checkFiles([]*indexPushFile{{path: paths.bucketShard(window.startDay, 7), plaintext: testBuildShard(t, shard, false, testPadKey(t, 2))}}, false); !errors.Is(err, errIndexEpochListed) {
		t.Fatalf("a listed shard row: %v", err)
	}
	// the set from a push that is not a CUT, and a CLOSURE
	set := testSmallFile(t, &protocol.IndexErasureSet{})
	if err := guard.checkFiles([]*indexPushFile{{path: indexErasureSetPath(false), plaintext: set}}, false); !errors.Is(err, errIndexEpochErasureSet) {
		t.Fatalf("the set from an index push: %v", err)
	}
	if _, err := guard.push(indexPushClosure, 0, nil, nil); !errors.Is(err, errIndexEpochClosure) {
		t.Fatalf("a CLOSURE through the guard: %v", err)
	}
	push, err := guard.push(indexPushIndex, 7, nil, nil)
	if err != nil || push.indexEpoch != view.head.indexEpoch || push.baseVersion != view.head.version || push.pushId == (Id{}) {
		t.Fatalf("the guard's push %+v, %v", push, err)
	}
}

// A large pseudo-random lowercase text: many distinct trigrams, so one document's entry is a large entry.
func testLargeText(byteCount int) []byte {
	text := make([]byte, 0, byteCount)
	state := uint32(2463534242)
	for len(text) < byteCount {
		for range 7 {
			state ^= state << 13
			state ^= state >> 17
			state ^= state << 5
			text = append(text, byte('a'+state%26))
		}
		text = append(text, ' ')
	}
	return text
}

// FS-111's companion clauses: a companion push holding D, built and paused before its head CAS, then an eraser's CUT
// listing D, hints dropped: the push gets 409 INDEX_EPOCH, rebuilds from the set and commits without D, its unit
// leaving. Once to a fresh head path, once with D past EntryMax as a large entry.
func TestIndexCutRefusesCompanionPushesBuiltBeforeIt(t *testing.T) {
	for _, large := range []bool{false, true} {
		world := newTestCompanionWorld(t)
		content := []byte("words of the document that is erased\n")
		if large {
			content = testLargeText(48 * 1024)
		}
		_, unit := world.commit(t, world.writer, "d.txt", content, false)
		world.companion.Committed(unit)
		_, kept := world.commit(t, world.writer, "kept.txt", []byte("words that stay\n"), false)
		world.companion.Committed(kept)
		document := unit.documents[0]
		eraser := testNewEraser(t, world.index.store(evsTestId("eraser")), true, world.cache.clock, nil)
		commits := 0
		world.index.beforeCommit = func(push *indexPush) {
			commits += 1
			if commits != 1 {
				return
			}
			if large && !slices.ContainsFunc(push.files, func(file *indexPushFile) bool {
				parsed, _ := indexParsePath(file.path, true)
				return parsed.kind == indexPathLargeEntry
			}) {
				t.Error("the prepared push holds no large entry")
			}
			world.index.beforeCommit = nil
			testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: document.key, Version: document.version})
		}
		if err := world.companion.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		view := testCompanionView(t, world, nil)
		for _, bucket := range view.writeRoot().buckets {
			for _, writer := range bucket.writers {
				for _, file := range slices.Concat(writer.slots, writer.large) {
					for _, entry := range file.slot.entries {
						if entry.key == document.key {
							t.Fatalf("large %v: D was published after the CUT", large)
						}
					}
				}
			}
		}
		entries, _ := world.head(t)
		if entries[kept.documents[0].key] == nil || world.unitCount(t) != 0 {
			t.Fatalf("large %v: the rebuilt push lost the kept document or its units", large)
		}
	}
}

// FS-111's merge clause: a merge's new shard holding D, built before the CUT, rebuilds without D.
func TestIndexCutRefusesAMergeBuiltBeforeIt(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "fill", 2)
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, nil)
	world.ref.beforeCommit = func(push *indexPush) {
		world.ref.beforeCommit = nil
		testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: testIndexId("d", 1), Version: 1})
	}
	outcome := world.merge(t, evsTestId("merger"))
	if outcome.attempts != 2 {
		t.Fatalf("the merge committed after %d attempts", outcome.attempts)
	}
	merged := world.mergedBucket(t)
	if merged.documents[testIndexId("d", 1)] != nil {
		t.Fatal("the merge's shard holds D after the CUT")
	}
	if len(merged.documents) == 0 {
		t.Fatal("the merge left nothing")
	}
}

// FS-111's backfill clause: a backfill's head holding D, built before the CUT, rebuilds without D.
func TestIndexCutRefusesABackfillBuiltBeforeIt(t *testing.T) {
	world := testNewBackfillWorld(true)
	writer, indexer := evsTestId("writer a"), evsTestId("indexer")
	world.commit(t, writer, nil, testContentChange{path: "notes/d.md", content: []byte("erased words")})
	world.commit(t, writer, nil, testContentChange{path: "notes/kept.md", content: []byte("kept words")})
	world.now = world.now.Add(11 * 60 * 1e9)
	key := world.key(t, "notes/d.md", 0)
	eraser := testNewEraser(t, world.index.store(evsTestId("eraser")), true, world, nil)
	world.index.beforeCommit = func(push *indexPush) {
		world.index.beforeCommit = nil
		testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: key, Version: 1})
	}
	outcome := world.backfill(t, world.backfiller(t, indexer, nil))
	if outcome.committed == nil || outcome.attempts != 2 {
		t.Fatalf("committed %v after %d attempts", outcome.committed != nil, outcome.attempts)
	}
	if entries := world.entriesOf(t, indexer, "notes/d.md", 0); len(entries) != 0 {
		t.Fatal("the backfill entered D after the CUT")
	}
	if entries := world.entriesOf(t, indexer, "notes/kept.md", 0); len(entries) != 1 {
		t.Fatal("the rebuilt backfill lost the kept document")
	}
}

// FS-111's reused-slot clause: a writer's push into an absorbed slot it reuses, holding D, built before the CUT, is
// refused 409 INDEX_EPOCH and planned again at the new head without D, as every builder through the guard is.
func TestIndexCutRefusesAReusedSlotBuiltBeforeIt(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	index := world.fillUntilSealed(t, a, "fill", 0)
	index = world.fillUntilSealed(t, a, "fill", index)
	world.merge(t, evsTestId("merger"))
	plan, view := world.plan(t, a, true, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	reused := false
	for _, file := range plan.files() {
		parsed, _ := indexParsePath(file.path, false)
		if parsed.kind == indexPathSlot && file.replaces != 0 && slices.ContainsFunc(plan.buckets[0].head.slot.entries, func(entry *indexEntry) bool { return entry.key == testIndexId("d", 1) }) {
			reused = reused || plan.buckets[0].head.replaces == file.replaces
		}
	}
	if !reused {
		t.Fatal("the plan does not reuse an absorbed slot for D")
	}
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		t.Fatal(err)
	}
	push, err := guard.push(indexPushIndex, world.at.UnixMilli(), plan.files(), plan.removals())
	if err != nil {
		t.Fatal(err)
	}
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, nil)
	testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: testIndexId("d", 1), Version: 1})
	if _, err := world.ref.store(a).Commit(context.Background(), push); !isIndexRefusal(err, indexRefusalIndexEpoch) {
		t.Fatalf("the push built before the CUT answered %v", err)
	}
	again, view := world.plan(t, a, true, testLive("d", 1, 1, 0, testHeadKeys(1, 0)), testLive("e", 1, 1, 0, testHeadKeys(2, 0)))
	if len(again.erased) != 1 || again.erased[0] != testIndexId("d", 1) {
		t.Fatalf("the rebuilt plan erased %v", again.erased)
	}
	if _, err := world.commit(t, a, again, view); err != nil {
		t.Fatal(err)
	}
	for _, entry := range world.entries(t, "d", 1) {
		if entry.version <= 1 {
			t.Fatal("D was written after the CUT")
		}
	}
}

// §11.14's epoch row: a journal's unit begun below the set's listed_since is extracted again from the text at its pin;
// one whose text no longer opens (the ERASE destroyed its keys) is dropped, so a complete erasure the set dropped is not
// published from key sets journaled before it.
func TestIndexJournalBegunBelowListedSinceRebuilds(t *testing.T) {
	world := newTestCompanionWorld(t)
	_, kept := world.commit(t, world.writer, "kept.txt", []byte("words that stay\n"), false)
	world.companion.Committed(kept)
	_, gone := world.commit(t, world.writer, "gone.txt", []byte("words that are erased\n"), false)
	world.companion.Committed(gone)
	units, _ := world.journal.units()
	if len(units) != 2 || units[0].epoch != 0 || units[0].stripped {
		t.Fatalf("the units %+v", units)
	}
	// gone.txt's version is erased and complete: its text no longer opens, and a CUT dropped that erasure
	world.content.stateLock.Lock()
	versions := world.content.pathVersions["gone.txt"]
	versions[len(versions)-1].unopenable = true
	world.content.stateLock.Unlock()
	complete := map[Id]bool{}
	eraser := testNewEraser(t, world.index.store(evsTestId("eraser")), true, world.cache.clock, complete)
	testCut(t, eraser, "erasure x", &IndexCutDocument{Key: gone.documents[0].key, Version: gone.documents[0].version})
	complete[evsTestId("erasure x")] = true
	other := testCut(t, eraser, "erasure y", &IndexCutDocument{Key: testIndexId("other", 1), Version: 1})
	if other.Set.ListedSince == 0 || other.DroppedCount != 1 {
		t.Fatalf("the second CUT: %+v", other)
	}
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, _ := world.head(t)
	if entry := entries[kept.documents[0].key]; entry == nil || len(entry.keys) == 0 {
		t.Fatal("a stale unit whose text opens was not extracted again")
	}
	if entries[gone.documents[0].key] != nil {
		t.Fatal("a stale unit whose text no longer opens was published")
	}
	if world.unitCount(t) != 0 {
		t.Fatal("the units stayed")
	}
	// units journaled from now are stamped with the epoch the build read
	_, later := world.commit(t, world.writer, "later.txt", []byte("later words\n"), false)
	world.companion.Committed(later)
	units, _ = world.journal.units()
	if len(units) != 1 || units[0].epoch < other.Set.ListedSince {
		t.Fatalf("a unit journaled after the build is stamped %+v", units)
	}
}

// §11.14's cut row, for builders: an erasure set version from a signer who may not erase is ignored and alarmed, and
// every builder then writes nothing, a CUT included (fail closed).
func TestIndexViewIgnoresAnErasureSetFromANonAdmin(t *testing.T) {
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	world.push(t, a, testLive("d", 1, 1, 0, testHeadKeys(1, 0)))
	forged := world.ref.store(b)
	push := forged.testPush(t, world.at, []*indexPushFile{{path: indexErasureSetPath(false), plaintext: testSmallFile(t, &protocol.IndexErasureSet{})}}, nil)
	push.kind = indexPushCut
	if _, err := forged.Commit(context.Background(), push); err != nil {
		t.Fatal(err)
	}
	view := world.view(t, a)
	if !view.erasureSetUnreadable || view.erasureSet != nil {
		t.Fatal("a forged set was read")
	}
	alarmed := false
	for _, alarm := range view.alarms {
		alarmed = alarmed || alarm.reason == indexViewAlarmErasureSet && alarm.signerSidecarId == b
	}
	if !alarmed {
		t.Fatal("a forged set was not alarmed naming its signer")
	}
	if _, err := indexNewEpochGuard(view); !errors.Is(err, errIndexErasureSetUnreadable) {
		t.Fatalf("a guard over a forged set: %v", err)
	}
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, nil)
	if _, err := eraser.Cut(context.Background(), &IndexCutArgs{ErasureId: evsTestId("erasure 1"), Documents: []*IndexCutDocument{{Key: testIndexId("d", 1), Version: 1}}}); !errors.Is(err, errIndexErasureSetUnreadable) {
		t.Fatalf("a CUT over a forged set: %v", err)
	}
}

// §11.14's cut row, for readers: a round lists a set version from a signer who may not erase bad, alarms naming that
// signer, and the last set one who may erase signed keeps masking its documents, so a forged set unmasks nothing.
func TestSearchSyncIgnoresAForgedErasureSet(t *testing.T) {
	world := newTestSyncWorld(t, false)
	writer := evsTestId("writer")
	world.push(t, writer, "doc", 2)
	eraser := testNewEraser(t, world.head.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world.head}, nil)
	testCut(t, eraser, "erasure 1", &IndexCutDocument{Key: testIndexId("doc", 0), Version: 1})
	world.round(t)
	probe := func() uint64 {
		snapshot := world.snapshot(t)
		if snapshot.Versions() == nil {
			t.Fatal("no version table")
		}
		probed, err := snapshot.Versions().Probe(testIndexId("doc", 0), nil)
		if err != nil {
			t.Fatal(err)
		}
		return probed.ErasedThrough
	}
	if probe() != 1 {
		t.Fatal("the genuine set does not mask its document")
	}
	forger := evsTestId("forger")
	world.stateLock.Lock()
	world.forgers = map[Id]bool{forger: true}
	world.stateLock.Unlock()
	forged := world.head.ref.store(forger)
	push := forged.testPush(t, world.head.at, []*indexPushFile{{path: indexErasureSetPath(false), replaces: forged.testVersionOf(indexErasureSetPath(false)), plaintext: testSmallFile(t, &protocol.IndexErasureSet{})}}, nil)
	push.kind = indexPushCut
	if _, err := forged.Commit(context.Background(), push); err != nil {
		t.Fatal(err)
	}
	world.round(t)
	if signer, ok := world.malformed()[indexErasureSetPath(false)]; !ok || signer != forger {
		t.Fatalf("the forged set alarmed %v naming %s", ok, signer)
	}
	if probe() != 1 {
		t.Fatal("a forged set unmasked the erased document")
	}
}
