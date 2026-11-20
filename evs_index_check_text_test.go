//go:build !ios_extension

// QD-1098's omitted-document check by a host with the text (§11.14's reads coverage row; FS-76; D-EVS-56; owner
// decision 621), the cases beside its main path in evs_index_reproduce_test.go, on the fake stores: a document the
// erasure set at the push's epoch lists, which the push commits with no entry, and one it lists only below the version
// the push commits; a path under the never row in a general ref, a mailbox and a group inbox; a chunk D6 skips beside
// the chunk after it; and a push past DirectBytes, whose entries the check finds in the bucket's shards and whose
// document left out it names against the head the push wrote. Each case is also run with a document left out, so a
// check that holds nothing to an entry cannot pass it. Beside them, the rows and tombstones a push past DirectBytes
// merges into the shards are judged against the text as a head's entries are, and the rows its merge carried over
// are not; and an entry above the effective ref version at the pin, which no path version exceeds, enters nothing
// and, as a tombstone over a live chunk, hides a document (QD-1153).

package sidecar

import (
	"context"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Marks a content push as one that wrote its signer's head in the ref's own index in the same statement.
func testInRefPush(push *indexContentPush) {
	push.changesHead = true
}

// Every full entry a writer extracts of path at refVersion, as it extracts it before planning its head: erased or
// not, since the planner leaves out what the erasure set lists. A path under the never row is the caller's to leave
// out, as the writer leaves it out before extracting.
func testExtractedEntries(t testing.TB, world *testBackfillWorld, groupInbox bool, path string, refVersion uint64) []*indexEntry {
	t.Helper()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	state, err := world.content.State(context.Background(), path, refVersion)
	if err != nil {
		t.Fatal(err)
	}
	extractor := &indexBuildExtractor{
		view: world.view(t), normalizer: normalizer, refId: world.content.refId, refKey: world.refKey,
		groupInbox: groupInbox, keepErased: true,
	}
	if err := extractor.extract(path, state, world.now.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	return extractor.entries
}

// One writer's index push beside its in-ref content push, as a host with the text checked it.
type testInRefCheck struct {
	plan    *indexHeadPlan
	landed  *indexCommitted
	outcome *indexTextCheckOutcome
	raised  []SidecarEvent
}

// signer's head at the index's head planned with entries, merged into the bucket's shards in the push where they pass
// DirectBytes, committed, and checked by a host with the text as the index push that rode with committed, pinned at
// its version, holding every shard at the push's base.
func testCheckInRef(t testing.TB, world *testBackfillWorld, signer Id, committed *indexContentPush, groupInbox bool, entries ...*indexEntry) *testInRefCheck {
	t.Helper()
	return testCheckInRefOf(t, world, world.content, signer, committed, groupInbox, entries...)
}

// As testCheckInRef, the host reading content as the push's content ref.
func testCheckInRefOf(t testing.TB, world *testBackfillWorld, content indexContentRef, signer Id, committed *indexContentPush, groupInbox bool, entries ...*indexEntry) *testInRefCheck {
	t.Helper()
	view := world.view(t)
	baseShards := map[string]*indexShard{}
	for _, root := range view.roots {
		shards := slices.Clone(root.allShards)
		for _, bucket := range root.buckets {
			shards = append(shards, bucket.shards...)
		}
		for _, shard := range shards {
			decoded, err := view.shard(context.Background(), shard)
			if err != nil || decoded == nil {
				t.Fatalf("shard %s does not read: %v", shard.file.path, err)
			}
			baseShards[shard.file.path] = decoded
		}
	}
	pending := []*indexPendingDocument{}
	for _, entry := range entries {
		pending = append(pending, &indexPendingDocument{kind: entry.kind, key: entry.key, version: entry.version, keys: entry.keys, row: entry.row})
	}
	plan, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: signer, signedTimeMs: world.now.UnixMilli(), tables: testHeadTables,
		pending: pending, mayMerge: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.mergeFirst {
		t.Fatal("the writer must merge before its push")
	}
	files, removals, err := indexMergeHeadPlan(context.Background(), view, view.writeRoot(), plan, testPadKey(t, 2), testHeadTables)
	if err != nil {
		t.Fatal(err)
	}
	push := &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: world.now.UnixMilli(),
		files: files, removals: removals,
	}
	landed, err := world.index.store(signer).Commit(context.Background(), push)
	if err != nil {
		t.Fatal(err)
	}
	// the index push is the one that rode with the content push at its version
	replay := testReproducePush(push, landed, signer, 2)
	replay.version = committed.version
	check := &testInRefCheck{plan: plan, landed: landed}
	check.outcome, err = indexCheckWithText(context.Background(), &indexTextCheckArgs{
		view: world.view(t), push: replay, baseShards: baseShards, content: content, pin: committed.version,
		refKey: world.refKey, groupInbox: groupInbox, events: func(event SidecarEvent) { check.raised = append(check.raised, event) },
	})
	if err != nil {
		t.Fatal(err)
	}
	return check
}

// The doc_keys the check mismatched, with their versions.
func (self *testInRefCheck) mismatched() map[[indexIdByteCount]byte]uint64 {
	mismatched := map[[indexIdByteCount]byte]uint64{}
	for _, mismatch := range self.outcome.mismatches {
		mismatched[mismatch.key] = mismatch.version
	}
	return mismatched
}

// Fails unless the check found nothing: no mismatch, no event, no repair.
func (self *testInRefCheck) clean(t testing.TB, label string) {
	t.Helper()
	if len(self.outcome.mismatches) != 0 || len(self.raised) != 0 || len(self.outcome.repairs) != 0 || len(self.outcome.own) != 0 {
		t.Fatalf("%s: %d mismatched, %d raised, repairs %v", label, len(self.outcome.mismatches), len(self.raised), self.outcome.repairs)
	}
}

// Fails unless the check found the one document path left out, as omitted's own entry gives it: its key at its version
// mismatched against the head the push wrote, the host's own entry standing for it, its path going to a backfill, and
// one index_mismatch naming signer and that head.
func (self *testInRefCheck) leftOut(t testing.TB, world *testBackfillWorld, signer Id, path string, omitted *indexEntry) {
	t.Helper()
	if len(self.outcome.mismatches) != 1 || self.outcome.mismatches[0].key != omitted.key || self.outcome.mismatches[0].version != omitted.version {
		t.Fatalf("%s left out: mismatched %v", path, self.mismatched())
	}
	if len(self.outcome.own) != 1 || self.outcome.own[0].key != omitted.key || !slices.Equal(self.outcome.own[0].keys, omitted.keys) {
		t.Fatalf("%s left out: %d own entries", path, len(self.outcome.own))
	}
	if !slices.Equal(self.outcome.repairs, []string{path}) {
		t.Fatalf("%s left out: repairs %v", path, self.outcome.repairs)
	}
	head := ""
	for _, bucket := range world.view(t).writeRoot().buckets {
		if writer := bucket.writer(signer); writer != nil && writer.head() != nil {
			head = writer.head().file.path
		}
	}
	written := false
	for _, file := range self.landed.files {
		written = written || file.path == head
	}
	if head == "" || !written {
		t.Fatalf("%s left out: the push wrote no head of its signer's", path)
	}
	if len(self.raised) != 1 || self.raised[0].Kind != SidecarEventIndexMismatch || self.raised[0].SidecarId == nil ||
		*self.raised[0].SidecarId != signer || self.raised[0].Path != head || self.outcome.mismatches[0].path != head {
		t.Fatalf("%s left out: raised %+v, not one index_mismatch naming the signer and the head %s", path, self.raised, head)
	}
}

// A document the erasure set at the push's epoch lists at or above the version the push commits is no omission: the
// writer's planner leaves it out, as §11.14's epoch row orders, and the check leaves it out as the writer does. A
// document the set lists only below the version the push commits is not covered by the listing: left out, it is
// flagged.
func TestIndexCheckWithTextHoldsNoErasedDocumentToAnEntry(t *testing.T) {
	alice, mallory := evsTestId("writer a"), evsTestId("writer m")
	// alice's in-ref push of again.txt, then mallory's content push, and a CUT that lands before mallory's index push:
	// erased.txt listed at the version mallory's push commits, again.txt at alice's version below it; mallory's writer,
	// refused 409 INDEX_EPOCH, builds again at the CUT's epoch
	setup := func() (*testBackfillWorld, *indexContentPush) {
		world := testNewBackfillWorld(false)
		older := world.commit(t, alice, testInRefPush, testContentChange{path: "again.txt", content: []byte("an older page about plums")})
		testCheckInRef(t, world, alice, older, false, testExtractedEntries(t, world, false, "again.txt", older.version)...).clean(t, "alice's push")
		committed := world.commit(t, mallory, testInRefPush,
			testContentChange{path: "kept.txt", content: []byte("honest ledger of turnips")},
			testContentChange{path: "erased.txt", content: []byte("a page about radishes someone erased")},
			testContentChange{path: "again.txt", content: []byte("a page about parsnips written after the erasure")},
		)
		erasedState, err := world.content.State(context.Background(), "erased.txt", committed.version)
		if err != nil {
			t.Fatal(err)
		}
		againState, err := world.content.State(context.Background(), "again.txt", older.version)
		if err != nil {
			t.Fatal(err)
		}
		if nextState, err := world.content.State(context.Background(), "again.txt", committed.version); err != nil || nextState.version <= againState.version {
			t.Fatal("mallory's push did not commit again.txt above alice's version")
		}
		eraser := testNewEraser(t, world.index.store(evsTestId("eraser")), false, world, nil)
		cut := testCut(t, eraser, "erasure",
			&IndexCutDocument{Key: world.key(t, "erased.txt", 0), Version: erasedState.version},
			&IndexCutDocument{Key: world.key(t, "again.txt", 0), Version: againState.version},
		)
		view := world.view(t)
		if !cut.Pushed || view.head.indexEpoch != cut.Version || !view.erased(world.key(t, "erased.txt", 0), erasedState.version) {
			t.Fatalf("the CUT: %+v", cut)
		}
		return world, committed
	}
	entriesOf := func(world *testBackfillWorld, committed *indexContentPush, paths ...string) []*indexEntry {
		entries := []*indexEntry{}
		for _, path := range paths {
			entries = append(entries, testExtractedEntries(t, world, false, path, committed.version)...)
		}
		return entries
	}

	// the writer extracts every document it committed; its planner leaves erased.txt out, and nothing is flagged
	world, committed := setup()
	check := testCheckInRef(t, world, mallory, committed, false, entriesOf(world, committed, "kept.txt", "erased.txt", "again.txt")...)
	erasedKey := world.key(t, "erased.txt", 0)
	if !slices.Equal(check.plan.erased, [][indexIdByteCount]byte{erasedKey}) {
		t.Fatalf("the planner left out %d documents, not erased.txt alone", len(check.plan.erased))
	}
	if entries := world.entriesOf(t, mallory, "erased.txt", 0); len(entries) != 0 {
		t.Fatalf("the push committed erased.txt with %d entries", len(entries))
	}
	if len(world.entriesOf(t, mallory, "again.txt", 0)) != 1 || len(world.entriesOf(t, mallory, "kept.txt", 0)) != 1 {
		t.Fatal("the push did not enter the documents the set does not list")
	}
	check.clean(t, "a push leaving out the erased document")
	if check.outcome.checked != 2 {
		t.Fatalf("%d entries judged", check.outcome.checked)
	}

	// again.txt left out too: listed below the version the push commits, it is a document left out
	world, committed = setup()
	again := entriesOf(world, committed, "again.txt")[0]
	check = testCheckInRef(t, world, mallory, committed, false, entriesOf(world, committed, "kept.txt", "erased.txt")...)
	check.leftOut(t, world, mallory, "again.txt", again)
}

// A path under the never row gives no doc_key, so a push that changed one and enters it nowhere is no omission: a
// general ref's .ur-index/ path, a mailbox's paths but m/, and a group inbox's, each with text an extractor would
// otherwise index. In each place a document left out beside them is flagged, so the check ran there.
func TestIndexCheckWithTextHoldsNoNeverPathToAnEntry(t *testing.T) {
	mallory := evsTestId("writer m")
	message := func(subject string, body string) []byte {
		return []byte("From: a@example.com\r\nTo: b@example.com\r\nSubject: " + subject + "\r\n\r\n" + body + "\r\n")
	}
	type place struct {
		label      string
		repoKind   protocol.RepoKind
		groupInbox bool
		// two documents the push commits, each the writer must enter
		documents []testContentChange
		// paths under the never row the push commits beside them, as text
		never []testContentChange
	}
	places := []*place{
		{
			label:    "a general ref",
			repoKind: protocol.RepoKind_REPO_KIND_GENERAL,
			documents: []testContentChange{
				{path: "notes/a.md", content: []byte("honest ledger of turnips")},
				{path: "notes/b.md", content: []byte("radishes and parsnips")},
			},
			never: []testContentChange{
				{path: ".ur-index/notes.txt", content: []byte("words kept out of every index")},
			},
		},
		{
			label:    "a mailbox",
			repoKind: protocol.RepoKind_REPO_KIND_MAILBOX,
			documents: []testContentChange{
				{path: "m/2026/11/000001", content: message("turnips", "an honest ledger of turnips")},
				{path: "m/2026/11/000002", content: message("radishes", "radishes and parsnips")},
			},
			never: []testContentChange{
				{path: "i/000001", content: []byte("turnips an honest ledger of turnips")},
				{path: "vault/k", content: []byte("words only the owner reads")},
				{path: "forward", content: []byte("forward to someone else")},
			},
		},
		{
			label:      "a group inbox",
			repoKind:   protocol.RepoKind_REPO_KIND_GENERAL,
			groupInbox: true,
			documents: []testContentChange{
				{path: "m/2026/11/000001", content: message("turnips", "an honest ledger of turnips")},
				{path: "m/2026/11/000002", content: message("radishes", "radishes and parsnips")},
			},
			never: []testContentChange{
				{path: "r/000001", content: []byte("a receipt of turnips")},
				{path: "vault/k", content: []byte("words only the owner reads")},
			},
		},
	}
	for _, place := range places {
		setup := func() (*testBackfillWorld, *indexContentPush) {
			world := testNewBackfillWorld(false)
			world.repoKind = place.repoKind
			committed := world.commit(t, mallory, testInRefPush, slices.Concat(place.documents, place.never)...)
			for _, never := range place.never {
				if !indexCoverageExcluded(world.view(t), place.groupInbox, &indexContentChange{path: never.path}) {
					t.Fatalf("%s: %s is not under the never row", place.label, never.path)
				}
				// the premise: but for the never row, its text would give a doc_key
				if len(testExtractedEntries(t, world, place.groupInbox, never.path, committed.version)) == 0 {
					t.Fatalf("%s: %s gives no entry of itself", place.label, never.path)
				}
			}
			return world, committed
		}
		entriesOf := func(world *testBackfillWorld, committed *indexContentPush, documents ...testContentChange) []*indexEntry {
			entries := []*indexEntry{}
			for _, document := range documents {
				extracted := testExtractedEntries(t, world, place.groupInbox, document.path, committed.version)
				if len(extracted) != 1 {
					t.Fatalf("%s: %s extracts as %d entries", place.label, document.path, len(extracted))
				}
				entries = append(entries, extracted...)
			}
			return entries
		}

		world, committed := setup()
		check := testCheckInRef(t, world, mallory, committed, place.groupInbox, entriesOf(world, committed, place.documents...)...)
		check.clean(t, place.label+", every document entered")
		if check.outcome.checked != len(place.documents) {
			t.Fatalf("%s: %d entries judged", place.label, check.outcome.checked)
		}

		world, committed = setup()
		omitted := entriesOf(world, committed, place.documents[1])[0]
		check = testCheckInRef(t, world, mallory, committed, place.groupInbox, entriesOf(world, committed, place.documents[0])...)
		check.leftOut(t, world, mallory, place.documents[1].path, omitted)
	}
}

// A chunk D6 skips gives no doc_key, so a push that commits it with no entry is no omission, while the chunk after it,
// which D6 keeps, is held to its entry: 1 MiB of mixed-script letters that alone would not fit a shard (11.6's
// TestADocumentPastAShardIsSkipped), then a line of plain words past the first chunk.
func TestIndexCheckWithTextHoldsNoSkippedChunkToAnEntry(t *testing.T) {
	mallory := evsTestId("writer m")
	settings := DefaultIndexFormatSettings()
	noise := slices.Concat(testMixedScriptLetters(5, settings.ChunkByteCount), []byte(" then a quiet line about turnips"))
	setup := func() (*testBackfillWorld, *indexContentPush) {
		world := testNewBackfillWorld(false)
		committed := world.commit(t, mallory, testInRefPush,
			testContentChange{path: "notes/a.md", content: []byte("honest ledger of turnips")},
			testContentChange{path: "notes/noise.txt", content: noise},
		)
		return world, committed
	}

	world, committed := setup()
	entries := testExtractedEntries(t, world, false, "notes/noise.txt", committed.version)
	// the premise: D6 skips chunk 0 and keeps chunk 1
	if len(entries) != 1 || entries[0].key != world.key(t, "notes/noise.txt", 1) {
		t.Fatalf("noise.txt extracts as %d entries, not its chunk 1 alone", len(entries))
	}
	tail := entries[0]
	check := testCheckInRef(t, world, mallory, committed, false, slices.Concat(testExtractedEntries(t, world, false, "notes/a.md", committed.version), entries)...)
	check.clean(t, "a push entering every chunk D6 keeps")
	if check.outcome.checked != 2 {
		t.Fatalf("%d entries judged", check.outcome.checked)
	}

	// the chunk D6 keeps left out is flagged, and the skipped chunk still is not
	world, committed = setup()
	check = testCheckInRef(t, world, mallory, committed, false, testExtractedEntries(t, world, false, "notes/a.md", committed.version)...)
	check.leftOut(t, world, mallory, "notes/noise.txt", tail)
	if _, ok := check.mismatched()[world.key(t, "notes/noise.txt", 0)]; ok {
		t.Fatal("the chunk D6 skips was flagged")
	}
}

// Texts of mixed-script letters, 128 KiB each, at bulk-<label>.txt, from the seed first on: an entry of about 106 KiB
// each, which fits a shard alone, so three pass DirectBytes together.
func testBulkChanges(first int64, labels ...string) ([]testContentChange, []string) {
	changes, paths := []testContentChange{}, []string{}
	for index, label := range labels {
		path := "bulk-" + label + ".txt"
		changes = append(changes, testContentChange{path: path, content: testMixedScriptLetters(first+int64(index), 128*1024)})
		paths = append(paths, path)
	}
	return changes, paths
}

// A world in which mallory holds a head in the bucket and then commits three bulk texts and b.txt in one content
// push, which the caller enters in a push past DirectBytes. Returns the world, that content push and the bulk texts'
// paths.
func testPastDirectBytesWorld(t testing.TB, mallory Id) (*testBackfillWorld, *indexContentPush, []string) {
	t.Helper()
	world := testNewBackfillWorld(false)
	seeded := world.commit(t, mallory, testInRefPush, testContentChange{path: "seed.txt", content: []byte("a first page of plums")})
	testCheckInRef(t, world, mallory, seeded, false, testExtractedEntries(t, world, false, "seed.txt", seeded.version)...).clean(t, "the seed push")
	changes, paths := testBulkChanges(7, "a", "b", "c")
	committed := world.commit(t, mallory, testInRefPush, append(changes, testContentChange{path: "b.txt", content: []byte("radishes and parsnips")})...)
	return world, committed, paths
}

// The one entry each path extracts as, at committed's version.
func testOneEntryEach(t testing.TB, world *testBackfillWorld, committed *indexContentPush, paths ...string) []*indexEntry {
	t.Helper()
	entries := []*indexEntry{}
	for _, path := range paths {
		extracted := testExtractedEntries(t, world, false, path, committed.version)
		if len(extracted) != 1 {
			t.Fatalf("%s extracts as %d entries", path, len(extracted))
		}
		entries = append(entries, extracted...)
	}
	return entries
}

// The entries of path's chunk 0 the newest bucket holds: in its shards, and in signer's files.
func testHeldOf(t testing.TB, world *testBackfillWorld, signer Id, path string) (int, int) {
	t.Helper()
	view := world.view(t)
	documents, err := view.bucketDocuments(context.Background(), view.writeRoot().newestBucket())
	if err != nil {
		t.Fatal(err)
	}
	shardCount, ownCount := 0, 0
	for _, entry := range documents.of(world.key(t, path, 0)) {
		switch {
		case entry.shard:
			shardCount += 1
		case entry.writer == signer:
			ownCount += 1
		}
	}
	return shardCount, ownCount
}

// The shard of the newest bucket holding a row or tombstone of key, and whether the push wrote it.
func (self *testInRefCheck) shardHolding(t testing.TB, world *testBackfillWorld, key [indexIdByteCount]byte) (string, bool) {
	t.Helper()
	view := world.view(t)
	for _, shard := range view.writeRoot().newestBucket().shards {
		decoded, err := view.shard(context.Background(), shard)
		if err != nil || decoded == nil {
			t.Fatalf("shard %s does not read: %v", shard.file.path, err)
		}
		for _, entry := range indexShardEntries(decoded) {
			if entry.key != key {
				continue
			}
			written := false
			for _, file := range self.landed.files {
				written = written || file.path == shard.file.path
			}
			return shard.file.path, written
		}
	}
	return "", false
}

// A push past DirectBytes merges its entries into the bucket's shards in the same push and writes its signer's head
// without them: the check finds the document's doc_key in a shard and flags nothing. With the document's shard entry
// left out of the merge, it is flagged, and index_mismatch names the signer and the head the push wrote.
func TestIndexCheckWithTextFindsAnEntryMergedPastDirectBytes(t *testing.T) {
	mallory := evsTestId("writer m")

	world, committed, bulkPaths := testPastDirectBytesWorld(t, mallory)
	check := testCheckInRef(t, world, mallory, committed, false, testOneEntryEach(t, world, committed, append(slices.Clone(bulkPaths), "b.txt")...)...)
	if !check.plan.mergeInPush {
		t.Fatal("the push did not pass DirectBytes")
	}
	if shardCount, ownCount := testHeldOf(t, world, mallory, "b.txt"); shardCount != 1 || ownCount != 0 {
		t.Fatalf("b.txt held in %d shard entries and %d of the writer's", shardCount, ownCount)
	}
	check.clean(t, "a push past DirectBytes entering every document")
	// the head the push wrote again without what it merged, and the four rows it merged
	if check.outcome.checked != 5 {
		t.Fatalf("%d entries judged", check.outcome.checked)
	}

	world, committed, bulkPaths = testPastDirectBytesWorld(t, mallory)
	omitted := testOneEntryEach(t, world, committed, "b.txt")[0]
	check = testCheckInRef(t, world, mallory, committed, false, testOneEntryEach(t, world, committed, bulkPaths...)...)
	if !check.plan.mergeInPush {
		t.Fatal("the push without b.txt did not pass DirectBytes")
	}
	if shardCount, ownCount := testHeldOf(t, world, mallory, "b.txt"); shardCount != 0 || ownCount != 0 {
		t.Fatalf("b.txt held in %d shard entries and %d of the writer's", shardCount, ownCount)
	}
	for _, path := range bulkPaths {
		if shardCount, _ := testHeldOf(t, world, mallory, path); shardCount != 1 {
			t.Fatalf("%s did not merge into the shards", path)
		}
	}
	check.leftOut(t, world, mallory, "b.txt", omitted)
}

// A push past DirectBytes merges its entries into the bucket's shards, where its signer's head holds none of them, so a
// host with the text judges each row and tombstone the push added to a shard against the text, as it judges a head's
// entries (D-EVS-56's "re-extract each document version a delta adds"; DESIGN-DETAILS 1.2.8). A tombstone the push
// merged over a document its content keeps live is a document hidden, and a row of trigrams the document never held a
// planted one: each is a mismatch against the shard holding it, naming the signer, the host's own entry standing for
// it. The rows the merge carried over from the shards at the push's base are not judged again, a stale one among them
// included, which the push did not write.
func TestIndexCheckWithTextJudgesEntriesMergedPastDirectBytes(t *testing.T) {
	mallory, alice := evsTestId("writer m"), evsTestId("writer a")
	// mallory's push past DirectBytes of the bulk texts as extracted and b.txt's entry as change makes it
	push := func(change func(world *testBackfillWorld, b *indexEntry) *indexEntry) (*testBackfillWorld, *testInRefCheck, *indexEntry) {
		world, committed, bulkPaths := testPastDirectBytesWorld(t, mallory)
		b := testOneEntryEach(t, world, committed, "b.txt")[0]
		check := testCheckInRef(t, world, mallory, committed, false, append(testOneEntryEach(t, world, committed, bulkPaths...), change(world, b))...)
		if !check.plan.mergeInPush {
			t.Fatal("the push did not pass DirectBytes")
		}
		return world, check, b
	}
	honest := func(world *testBackfillWorld, b *indexEntry) *indexEntry {
		return b
	}
	// the one mismatch of b.txt's key, against the shard the push wrote holding it, the host's own entry b in its place
	forged := func(world *testBackfillWorld, check *testInRefCheck, b *indexEntry, label string) {
		shard, written := check.shardHolding(t, world, b.key)
		if !written {
			t.Fatalf("%s: no shard the push wrote holds b.txt", label)
		}
		if len(check.outcome.mismatches) != 1 || check.outcome.mismatches[0].key != b.key || check.outcome.mismatches[0].version != b.version || check.outcome.mismatches[0].path != shard {
			t.Fatalf("%s: mismatched %v", label, check.mismatched())
		}
		if len(check.outcome.own) != 1 || check.outcome.own[0].key != b.key || !slices.Equal(check.outcome.own[0].keys, b.keys) {
			t.Fatalf("%s: %d own entries", label, len(check.outcome.own))
		}
		if len(check.raised) != 1 || check.raised[0].Kind != SidecarEventIndexMismatch || check.raised[0].SidecarId == nil ||
			*check.raised[0].SidecarId != mallory || check.raised[0].Path != shard {
			t.Fatalf("%s: raised %+v, not one index_mismatch naming the signer and %s", label, check.raised, shard)
		}
	}

	// honest: the head's seed entry and the four rows the push merged are judged, and bear out
	_, check, _ := push(honest)
	check.clean(t, "an honest push past DirectBytes")
	if check.outcome.checked != 5 {
		t.Fatalf("%d entries judged, not the head's one and the four merged", check.outcome.checked)
	}

	// a tombstone over b.txt, which the push's content keeps live
	world, check, b := push(func(world *testBackfillWorld, b *indexEntry) *indexEntry {
		return &indexEntry{kind: indexEntryTombstone, key: b.key, version: b.version, timeSeconds: b.timeSeconds}
	})
	forged(world, check, b, "a tombstone merged over a live document")

	// b.txt's row holding seed.txt's trigrams in place of its own
	world, check, b = push(func(world *testBackfillWorld, b *indexEntry) *indexEntry {
		seed := testExtractedEntries(t, world, false, "seed.txt", 1)[0]
		planted := *b
		planted.keys, planted.row = slices.Clone(seed.keys), seed.row
		return &planted
	})
	forged(world, check, b, "a row of trigrams b.txt never held")

	// on an honest world, an old client's push leaves stale the row of a bulk text beside b.txt's in a shard; mallory's
	// next push past DirectBytes changes b.txt, whose older row it drops from that shard, writing the shard again with
	// the rows beside it carried over: only the rows the push added are judged, and the stale row it carried is not its
	// to answer for
	world, check, _ = push(honest)
	beside, _ := check.shardHolding(t, world, world.key(t, "b.txt", 0))
	stalePath := ""
	for _, path := range []string{"bulk-a.txt", "bulk-b.txt", "bulk-c.txt"} {
		if shard, _ := check.shardHolding(t, world, world.key(t, path, 0)); shard == beside {
			stalePath = path
		}
	}
	if stalePath == "" {
		t.Fatal("no bulk text's row shares a shard with b.txt's")
	}
	stale := world.key(t, stalePath, 0)
	world.commit(t, alice, nil, testContentChange{path: stalePath, content: []byte("a bulk text rewritten with no index")})
	changes, paths := testBulkChanges(10, "d", "e", "f")
	committed := world.commit(t, mallory, testInRefPush, append(changes, testContentChange{path: "b.txt", content: []byte("radishes, parsnips and leeks")})...)
	check = testCheckInRef(t, world, mallory, committed, false, testOneEntryEach(t, world, committed, append(paths, "b.txt")...)...)
	if !check.plan.mergeInPush {
		t.Fatal("the next push did not pass DirectBytes")
	}
	if _, written := check.shardHolding(t, world, stale); !written {
		t.Fatal("the next push did not write the shard holding the stale row again")
	}
	check.clean(t, "a push past DirectBytes carrying a stale row over")
	if check.outcome.checked != 5 {
		t.Fatalf("%d entries judged, not the head's one and the four the push added", check.outcome.checked)
	}
}

// A content ref on an overlay: its effective ref version at a pin adds its chain's base versions (§11.7), which the
// fake gives as baseVersions.
type testOverlayContent struct {
	*testIndexContent
	baseVersions uint64
}

func (self *testOverlayContent) EffectiveVersion(ctx context.Context, refVersion uint64) (uint64, error) {
	return refVersion + self.baseVersions, nil
}

// QD-1153: no path version exceeds the effective ref version it commits at (§11.7), so a tombstone of a path's chunk
// above that bound at the pin, over a chunk the text keeps live, is a document hidden until the path's version passes
// it: a mismatch, the host's own entry standing for it. The omitted row counts no entry above the bound, so a push
// whose one entry of a document it commits is such a tombstone also leaves it out. On an overlay, whose bound adds
// its chain's base versions, the same tombstones fall at or below the bound, versions the device cannot place, and
// pass as they did.
func TestIndexCheckWithTextBoundsEntriesByTheEffectiveRefVersion(t *testing.T) {
	mallory := evsTestId("writer m")
	overlay := func(world *testBackfillWorld) indexContentRef {
		return &testOverlayContent{testIndexContent: world.content, baseVersions: 1000}
	}
	// mallory enters a.txt and b.txt honestly, then its push changing a.txt alone carries a tombstone over b.txt at a
	// version far above any b.txt can hold
	hiding := func(content func(world *testBackfillWorld) indexContentRef) (*testBackfillWorld, *testInRefCheck, *indexEntry) {
		world := testNewBackfillWorld(false)
		first := world.commit(t, mallory, testInRefPush,
			testContentChange{path: "a.txt", content: []byte("honest ledger of turnips")},
			testContentChange{path: "b.txt", content: []byte("radishes and parsnips")},
		)
		testCheckInRef(t, world, mallory, first, false, testOneEntryEach(t, world, first, "a.txt", "b.txt")...).clean(t, "the honest push")
		next := world.commit(t, mallory, testInRefPush, testContentChange{path: "a.txt", content: []byte("honest ledger of turnips, kept")})
		b := testOneEntryEach(t, world, next, "b.txt")[0]
		hidden := &indexEntry{kind: indexEntryTombstone, key: b.key, version: next.version + 100, timeSeconds: b.timeSeconds}
		check := testCheckInRefOf(t, world, content(world), mallory, next, false, append(testOneEntryEach(t, world, next, "a.txt"), hidden)...)
		return world, check, b
	}
	world, check, b := hiding(func(world *testBackfillWorld) indexContentRef { return world.content })
	if len(check.outcome.mismatches) != 1 || check.outcome.mismatches[0].key != b.key || check.outcome.mismatches[0].version <= b.version {
		t.Fatalf("a tombstone above the bound: mismatched %v", check.mismatched())
	}
	if len(check.outcome.own) != 1 || check.outcome.own[0].key != b.key || !slices.Equal(check.outcome.own[0].keys, b.keys) {
		t.Fatalf("a tombstone above the bound: %d own entries", len(check.outcome.own))
	}
	head := world.view(t).writeRoot().newestBucket().writer(mallory).head()
	if len(check.raised) != 1 || *check.raised[0].SidecarId != mallory || check.raised[0].Path != head.file.path || len(check.outcome.repairs) != 0 {
		t.Fatalf("a tombstone above the bound: raised %+v, repairs %v", check.raised, check.outcome.repairs)
	}
	_, check, _ = hiding(overlay)
	check.clean(t, "the tombstone at or below an overlay's bound")

	// mallory's push commits c.txt and enters it only as a tombstone above the bound: left out, and hidden
	leaving := func(content func(world *testBackfillWorld) indexContentRef) (*testBackfillWorld, *testInRefCheck, *indexEntry) {
		world := testNewBackfillWorld(false)
		committed := world.commit(t, mallory, testInRefPush,
			testContentChange{path: "a.txt", content: []byte("honest ledger of turnips")},
			testContentChange{path: "c.txt", content: []byte("celery and chard")},
		)
		c := testOneEntryEach(t, world, committed, "c.txt")[0]
		hidden := &indexEntry{kind: indexEntryTombstone, key: c.key, version: committed.version + 100, timeSeconds: c.timeSeconds}
		check := testCheckInRefOf(t, world, content(world), mallory, committed, false, append(testOneEntryEach(t, world, committed, "a.txt"), hidden)...)
		return world, check, c
	}
	world, check, c := leaving(func(world *testBackfillWorld) indexContentRef { return world.content })
	mismatched := check.mismatched()
	if _, ok := mismatched[c.key]; !ok || len(mismatched) != 1 || len(check.outcome.mismatches) != 2 {
		t.Fatalf("c.txt left out behind a tombstone above the bound: mismatched %v, %d mismatches", mismatched, len(check.outcome.mismatches))
	}
	if len(check.outcome.own) != 1 || check.outcome.own[0].key != c.key || !slices.Equal(check.outcome.repairs, []string{"c.txt"}) {
		t.Fatalf("c.txt left out: %d own entries, repairs %v", len(check.outcome.own), check.outcome.repairs)
	}
	head = world.view(t).writeRoot().newestBucket().writer(mallory).head()
	if len(check.raised) != 1 || *check.raised[0].SidecarId != mallory || check.raised[0].Path != head.file.path {
		t.Fatalf("c.txt left out: raised %+v", check.raised)
	}
	_, check, _ = leaving(overlay)
	check.clean(t, "the tombstone at or below an overlay's bound, entering c.txt")
}
