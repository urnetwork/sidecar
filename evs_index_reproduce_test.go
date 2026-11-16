//go:build !ios_extension

// SEARCH-M10-21's tests (§11.14's reproduce and coverage rows; FS-75's reproduce clause, FS-76; DESIGN-DETAILS 1.2.8
// and 1.5), on the fake stores: a merge reproduced from the inputs the device holds, matching every output so nothing
// is fetched; a merge whose shard bytes differ caught, fetched and alarmed against its signer; a CLOSURE's shard
// rewrite reproduced and its replaced version handed back for deletion; a lacking input, a missing pad key and a
// phone outside its windows each fetching everything and raising nothing; a head derived from a card, matched, and a
// forged head fetched and alarmed; and a host with the text catching a planted entry, a hidden document and a deleted
// document indexed, using its own result.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// What the device holds at the head of ref: the listing and every file's plaintext, as a sync round leaves them.
func testHeldBase(t testing.TB, ref *testIndexRef) *indexReproduceBase {
	t.Helper()
	store := ref.store(evsTestId("reader"))
	listing, err := store.List(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	type held struct {
		path    string
		version uint64
	}
	plaintexts := map[held][]byte{}
	for _, file := range listing.files {
		plaintext, err := store.Read(context.Background(), file)
		if err != nil {
			t.Fatal(err)
		}
		plaintexts[held{path: file.path, version: file.version}] = plaintext
	}
	return &indexReproduceBase{listing: listing, held: func(ctx context.Context, file *indexFileVersion) ([]byte, bool, error) {
		plaintext, ok := plaintexts[held{path: file.path, version: file.version}]
		return plaintext, ok, nil
	}}
}

// The replayed form of a committed push.
func testReproducePush(push *indexPush, committed *indexCommitted, signer Id, generation uint64) *indexReproducePush {
	replaced := map[string]uint64{}
	for _, file := range push.files {
		replaced[file.path] = file.replaces
	}
	replay := &indexReproducePush{
		version: committed.version, baseVersion: push.baseVersion, signer: signer, signedTimeMs: push.signedTimeMs,
		generation: generation, removals: push.removals,
	}
	for _, file := range committed.files {
		replay.files = append(replay.files, &indexReproduceFile{file: file, replaces: replaced[file.path]})
	}
	return replay
}

// A reproducer of the head world's ref holding K_index_g of generation 2 alone.
func (self *testHeadWorld) reproducer(t testing.TB, may func() bool, events func(SidecarEvent)) *IndexReproducer {
	t.Helper()
	reproducer, err := indexNewReproducer(&indexReproducerArgs{
		repoId:   evsTestId("view repo"),
		refId:    evsTestId("view ref"),
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL,
		isAdmin:  self.isAdmin,
		format:   self.settings,
		tables:   testHeadTables,
		padKeyOf: func(ctx context.Context, generation uint64) (*indexPadKey, error) {
			if generation != 2 {
				return nil, errIndexReproduceLacking
			}
			return testPadKey(t, 2), nil
		},
		mayReproduce: may,
		events:       events,
	})
	if err != nil {
		t.Fatal(err)
	}
	return reproducer
}

// A head world with two sealed slots of one writer, and the base the device holds before a merge of them, the merge
// committed through a hook that may change its files.
func testMergeToReproduce(t testing.TB, change func(push *indexPush)) (*testHeadWorld, *indexReproduceBase, *indexReproducePush) {
	t.Helper()
	world := testNewHeadWorld()
	writer := evsTestId("writer a")
	next := world.fillUntilSealed(t, writer, "doc", 0)
	world.fillUntilSealed(t, writer, "doc", next)
	base := testHeldBase(t, world.ref)
	var merged *indexPush
	world.ref.beforeCommit = func(push *indexPush) {
		if change != nil {
			change(push)
		}
		merged = push
	}
	outcome := world.merge(t, evsTestId("merger"))
	world.ref.beforeCommit = nil
	return world, base, testReproducePush(merged, outcome.committed, evsTestId("merger"), 2)
}

// FS-75's reproduce clause: with every input held, a merge's outputs are rebuilt and match, nothing fetched or raised.
func TestIndexReproduceAMergeFetchesNothing(t *testing.T) {
	world, base, push := testMergeToReproduce(t, nil)
	outcome, err := world.reproducer(t, nil, nil).Reproduce(context.Background(), push, base)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.kind != indexReproduceMerge || len(outcome.fetch) != 0 || len(outcome.events) != 0 || len(outcome.matched) != len(push.files) || len(outcome.matched) == 0 {
		t.Fatalf("a merge reproduced: kind %d, %d fetched, %d events, %d of %d matched", outcome.kind, len(outcome.fetch), len(outcome.events), len(outcome.matched), len(push.files))
	}
	for _, matched := range outcome.matched {
		if sum := sha256.Sum256(matched.plaintext); sum != matched.file.contentSha256 {
			t.Fatalf("%s: the device keeps bytes that are not the entry version's", matched.file.path)
		}
	}
}

// FS-76: a merge whose shard bytes differ from the rebuild (a document left out) is caught: that shard is fetched and
// index_mismatch names the merger; the rest match.
func TestIndexReproduceCatchesAForgedMerge(t *testing.T) {
	forged := ""
	world, base, push := testMergeToReproduce(t, func(push *indexPush) {
		for _, file := range push.files {
			path, _ := indexParsePath(file.path, false)
			if path.kind != indexPathBucketShard {
				continue
			}
			sum := sha256.Sum256(file.plaintext)
			shard, err := indexDecodeShard(file.plaintext, sum[:], false)
			if err != nil {
				t.Fatal(err)
			}
			shard.documents = shard.documents[1:]
			rebuilt, err := indexNewShardBuilder(false).build(shard, testPadKey(t, 2))
			if err != nil {
				t.Fatal(err)
			}
			file.plaintext, forged = rebuilt, file.path
			return
		}
	})
	raised := []SidecarEvent{}
	outcome, err := world.reproducer(t, nil, func(event SidecarEvent) { raised = append(raised, event) }).Reproduce(context.Background(), push, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(outcome.fetch) != 1 || outcome.fetch[0].path != forged || len(outcome.matched) != len(push.files)-1 {
		t.Fatalf("a forged shard: %d fetched, %d matched", len(outcome.fetch), len(outcome.matched))
	}
	if len(raised) != 1 || raised[0].Kind != SidecarEventIndexMismatch || raised[0].Path != forged || *raised[0].SidecarId != evsTestId("merger") ||
		*raised[0].RepoId != evsTestId("view repo") || *raised[0].RefId != evsTestId("view ref") {
		t.Fatalf("the mismatch raised: %+v", raised)
	}
}

// A device lacking an input, or the pad key of the push's generation, downloads and raises nothing, as does a phone
// outside the foreground and its windows.
func TestIndexReproduceLackingAnInputDownloads(t *testing.T) {
	world, base, push := testMergeToReproduce(t, nil)
	lacking := &indexReproduceBase{listing: base.listing, held: func(ctx context.Context, file *indexFileVersion) ([]byte, bool, error) {
		if path, _ := indexParsePath(file.path, false); path.kind == indexPathSlot {
			return nil, false, nil
		}
		return base.held(ctx, file)
	}}
	otherGeneration := *push
	otherGeneration.generation = 3
	for _, reproduce := range []func() (*indexReproduceOutcome, error){
		func() (*indexReproduceOutcome, error) {
			return world.reproducer(t, nil, nil).Reproduce(context.Background(), push, lacking)
		},
		func() (*indexReproduceOutcome, error) {
			return world.reproducer(t, nil, nil).Reproduce(context.Background(), &otherGeneration, base)
		},
		func() (*indexReproduceOutcome, error) {
			return world.reproducer(t, func() bool { return false }, nil).Reproduce(context.Background(), push, base)
		},
	} {
		outcome, err := reproduce()
		if err != nil {
			t.Fatal(err)
		}
		if len(outcome.fetch) != len(push.files) || len(outcome.matched) != 0 || len(outcome.events) != 0 {
			t.Fatalf("%d fetched of %d, %d matched, %d events", len(outcome.fetch), len(push.files), len(outcome.matched), len(outcome.events))
		}
	}
}

// A CLOSURE's shard rewrite, without the erasure's document and padded to the replaced length, is reproduced, and the
// replaced version comes back for the cache to delete.
func TestIndexReproduceAClosure(t *testing.T) {
	world, _, _ := testMergeToReproduce(t, nil)
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: testIndexId("doc", 0), Version: 1})
	base := testHeldBase(t, world.ref)
	view := world.view(t, evsTestId("reader"))
	bucket := view.writeRoot().newestBucket()
	var shardFile *indexFileVersion
	var rewritten []byte
	for _, viewShard := range bucket.shards {
		shard, err := view.shard(context.Background(), viewShard)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(shard.documents, func(document *indexShardDocument) bool { return document.key == testIndexId("doc", 0) }) {
			continue
		}
		rewritten, _, err = indexNewShardBuilder(false).rewriteWithout(shard, func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
			return key == testIndexId("doc", 0) && version <= 1
		}, viewShard.file.byteCount)
		if err != nil {
			t.Fatal(err)
		}
		shardFile = viewShard.file
	}
	if shardFile == nil {
		t.Fatal("no shard holds the document")
	}
	closure := &indexPush{
		pushId: NewId(), kind: indexPushClosure, baseVersion: view.head.version, signedTimeMs: world.at.UnixMilli(),
		files: []*indexPushFile{{path: shardFile.path, plaintext: rewritten, replaces: shardFile.version}},
	}
	committed, err := world.ref.store(evsTestId("eraser")).Commit(context.Background(), closure)
	if err != nil {
		t.Fatal(err)
	}
	push := testReproducePush(closure, committed, evsTestId("eraser"), 2)
	push.closure, push.erasureId = true, evsTestId("erasure")
	outcome, err := world.reproducer(t, nil, nil).Reproduce(context.Background(), push, base)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.kind != indexReproduceClosure || len(outcome.matched) != 1 || len(outcome.fetch) != 0 || len(outcome.events) != 0 {
		t.Fatalf("a CLOSURE reproduced: kind %d, %d matched, %d fetched, %d events", outcome.kind, len(outcome.matched), len(outcome.fetch), len(outcome.events))
	}
	if len(outcome.replaced) != 1 || outcome.replaced[0].path != shardFile.path || outcome.replaced[0].version != shardFile.version {
		t.Fatalf("the replaced versions: %+v", outcome.replaced)
	}
}

// A card writer's head derived from its previous head and the card the reader folds matches the push's, nothing
// fetched; a head whose bytes differ is fetched and alarmed against its writer.
func TestIndexDeriveHeadFromACard(t *testing.T) {
	world := testNewHeadWorld()
	writer := evsTestId("card writer")
	refKey := bytes.Repeat([]byte{0x6b}, 32)
	refId := evsTestId("view ref")
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	card := func(title string, version uint64) *IndexDocument {
		document := &IndexDocument{Kind: IndexDocDerived, Name: []byte("run/0123"), Version: version}
		document.Fields[indexFieldTitle] = []byte(title)
		return document
	}
	pending := func(document *IndexDocument, replaces uint64) *indexPendingDocument {
		key, err := indexDocKey(refKey, refId, document.Name, document.Chunk)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := document.prepare(normalizer, false, refId, world.settings)
		if err != nil {
			t.Fatal(err)
		}
		return &indexPendingDocument{kind: indexEntryFull, key: key, version: document.Version, replaces: replaces, keys: prepared.keys, row: prepared.row}
	}
	world.push(t, writer, pending(card("limiter fix", 1), 0))

	derive := func(pushed *IndexDocument, folded *IndexDocument) (*indexReproduceOutcome, []SidecarEvent) {
		base := testHeldBase(t, world.ref)
		plan, view := world.plan(t, writer, false, pending(pushed, 1))
		signedTime := world.at
		committed, err := world.commit(t, writer, plan, view)
		if err != nil {
			t.Fatal(err)
		}
		push := testReproducePush(&indexPush{baseVersion: view.head.version, signedTimeMs: signedTime.UnixMilli(), files: plan.files(), removals: plan.removals()}, committed, writer, 2)
		raised := []SidecarEvent{}
		outcome, err := world.reproducer(t, nil, func(event SidecarEvent) { raised = append(raised, event) }).DeriveHead(context.Background(), &indexDeriveHeadArgs{
			push: push, base: base, documents: []*indexDeriveDocument{{document: folded, replaces: 1}}, refId: refId, refKey: refKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		return outcome, raised
	}
	outcome, raised := derive(card("limiter fix, round two", 2), card("limiter fix, round two", 2))
	if len(outcome.matched) == 0 || len(outcome.fetch) != 0 || len(raised) != 0 {
		t.Fatalf("an honest card head: %d matched, %d fetched, %d raised", len(outcome.matched), len(outcome.fetch), len(raised))
	}
	outcome, raised = derive(card("a title the log never held", 3), card("limiter fix, round three", 3))
	if len(outcome.fetch) == 0 || len(raised) == 0 || *raised[0].SidecarId != writer || raised[0].Kind != SidecarEventIndexMismatch {
		t.Fatalf("a forged card head: %d fetched, %+v raised", len(outcome.fetch), raised)
	}
}

// FS-76 by a host with the text: an honest entry passes; a planted key set, a tombstone hiding a standing document and
// a live entry of a removed path with nothing above it each alarm against the writer, the host's own entry standing
// for the first two and the removed path going to a backfill.
func TestIndexCheckWithTextCatchesForgedEntries(t *testing.T) {
	world := testNewBackfillWorld(false)
	alice := evsTestId("writer a")
	world.commit(t, alice, nil,
		testContentChange{path: "a.txt", content: []byte("honest ledger of turnips")},
		testContentChange{path: "b.txt", content: []byte("radishes and parsnips")},
		testContentChange{path: "c.txt", content: []byte("a page later removed")},
		testContentChange{path: "d.txt", content: []byte("a page someone wants hidden")},
	)
	world.commit(t, alice, nil, testContentChange{path: "c.txt"})
	pin := uint64(2)
	view := world.view(t)
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	honest := func(path string, refVersion uint64, text []byte) *indexEntry {
		state, err := world.content.State(context.Background(), path, refVersion)
		if err != nil {
			t.Fatal(err)
		}
		if text != nil {
			state.content, state.byteCount = bytes.NewReader(text), uint64(len(text))
		}
		extractor := &indexBuildExtractor{view: view, normalizer: normalizer, refId: world.content.refId, refKey: world.refKey, keepErased: true}
		if err := extractor.extract(path, state, world.now.UnixMilli()); err != nil {
			t.Fatal(err)
		}
		return extractor.entries[0]
	}
	asPending := func(entry *indexEntry) *indexPendingDocument {
		return &indexPendingDocument{kind: indexEntryFull, key: entry.key, version: entry.version, keys: entry.keys, row: entry.row}
	}
	a := honest("a.txt", pin, nil)
	planted := honest("b.txt", pin, []byte("words the text never held"))
	planted.key = world.key(t, "b.txt", 0)
	removed := honest("c.txt", 1, nil)
	hidden := &indexPendingDocument{kind: indexEntryTombstone, key: world.key(t, "d.txt", 0), version: 1}

	mallory := evsTestId("writer m")
	plan, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: mallory, signedTimeMs: world.now.UnixMilli(), tables: testHeadTables,
		pending: []*indexPendingDocument{asPending(a), asPending(planted), asPending(removed), hidden},
	})
	if err != nil {
		t.Fatal(err)
	}
	push := &indexPush{pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: world.now.UnixMilli(), files: plan.files()}
	committed, err := world.index.store(mallory).Commit(context.Background(), push)
	if err != nil {
		t.Fatal(err)
	}
	raised := []SidecarEvent{}
	outcome, err := indexCheckWithText(context.Background(), &indexTextCheckArgs{
		view: world.view(t), push: testReproducePush(push, committed, mallory, 2), content: world.content, pin: pin,
		refKey: world.refKey, events: func(event SidecarEvent) { raised = append(raised, event) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome.checked != 4 || len(outcome.mismatches) != 3 {
		t.Fatalf("%d checked, %d mismatched", outcome.checked, len(outcome.mismatches))
	}
	mismatched := map[[indexIdByteCount]byte]bool{}
	for _, mismatch := range outcome.mismatches {
		mismatched[mismatch.key] = true
	}
	if mismatched[a.key] || !mismatched[planted.key] || !mismatched[removed.key] || !mismatched[hidden.key] {
		t.Fatal("the wrong entries mismatched")
	}
	ownKeys := map[[indexIdByteCount]byte]bool{}
	for _, own := range outcome.own {
		ownKeys[own.key] = true
	}
	if !ownKeys[planted.key] || !ownKeys[hidden.key] || len(outcome.own) != 2 {
		t.Fatalf("the host's own results: %d", len(outcome.own))
	}
	if !slices.Equal(outcome.repairs, []string{"c.txt"}) {
		t.Fatalf("repairs: %v", outcome.repairs)
	}
	if len(raised) == 0 || *raised[0].SidecarId != mallory || !strings.HasPrefix(raised[0].Path, indexFileModePrefix) {
		t.Fatalf("the mismatch raised: %+v", raised)
	}
}

// FS-75's reproduce clause for a roll-up: its runner's push rebuilt at the head after its lock, all's shards, a/m, the
// runner's head and the freed lock matching, nothing fetched; the same push replayed as signed before the bucket's
// expiry is a runner rolling early, every output fetched and alarmed (1.5).
func TestIndexReproduceARollup(t *testing.T) {
	world, a := testRollupWorld(t)
	before := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(before.window.endDay()+before.window.days, time.Hour)
	var base *indexReproduceBase
	var rolled *indexPush
	world.ref.beforeCommit = func(push *indexPush) {
		if slices.ContainsFunc(push.files, func(file *indexPushFile) bool { return strings.HasSuffix(file.path, "/a/m") }) {
			base, rolled = testHeldBase(t, world.ref), push
		}
	}
	outcome := world.rollUp(t, evsTestId("runner"))
	world.ref.beforeCommit = nil
	push := testReproducePush(rolled, outcome.committed, evsTestId("runner"), 2)
	reproduced, err := world.reproducer(t, nil, nil).Reproduce(context.Background(), push, base)
	if err != nil {
		t.Fatal(err)
	}
	if reproduced.kind != indexReproduceRollup || len(reproduced.fetch) != 0 || len(reproduced.events) != 0 || len(reproduced.matched) != len(push.files) {
		t.Fatalf("a roll-up reproduced: kind %d, %d fetched, %d events, %d of %d matched", reproduced.kind, len(reproduced.fetch), len(reproduced.events), len(reproduced.matched), len(push.files))
	}
	early := *push
	early.signedTimeMs = testDayTime(before.window.endDay(), time.Hour).UnixMilli()
	reproduced, err = world.reproducer(t, nil, nil).Reproduce(context.Background(), &early, base)
	if err != nil {
		t.Fatal(err)
	}
	if len(reproduced.fetch) != len(push.files) || len(reproduced.events) == 0 || *reproduced.events[0].SidecarId != evsTestId("runner") {
		t.Fatalf("a roll-up signed early: %d fetched of %d, %d events", len(reproduced.fetch), len(push.files), len(reproduced.events))
	}
}
