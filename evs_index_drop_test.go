//go:build !ios_extension

package sidecar

// SEARCH-M10-18 (§11.14's drop, holds, limit and writers rows; FS-96's index clause and FS-76's hold clauses on fake
// holds; QD-1036's full entries, under which FS-107's DROP case is the kept version's full entry staying where it is;
// QD-1078): a DROP's rewrites leave no listed version's entry, row or tombstone in any partition, each file at its
// replaced length, the kept version's entry where it was, each touched writer's head and bucket's manifest written
// again, an indexer's build byte-equal and every search equal; a removed boundary's tombstone stays; a rewrite past the
// replaced length is refused and nothing is padded short; a signer without the index leaves the rewrite to the backfill,
// searches masking the listed versions meanwhile, and the backfill mends a racing merge's first shard too; a hold keeps
// what the rewrite replaced and pauses no ERASE; and on the evs stand-in the hook's rewrites ride the DROP push,
// rebuilt once when another push moves a file they replace.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// K_ref of the fake ref's index, fixed.
func testIndexDropRefKey() []byte {
	sum := sha256.Sum256([]byte("drop test ref key"))
	return sum[:]
}

// The doc_key of path's chunk on the head world's ref.
func testIndexDropKey(t testing.TB, refKey []byte, path string, chunk uint32) [indexIdByteCount]byte {
	t.Helper()
	key, err := indexDocKey(refKey, evsTestId("view ref"), []byte(path), chunk)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The key only version's content holds.
func testIndexDropVersionKey(version uint64) uint32 {
	return uint32(0x7f0000 + version)
}

// A version's key set: a base every version shares, and its own key.
func testIndexDropKeys(version uint64) indexKeySet {
	return append(testIndexKeys(0x500000, 120, 3), testIndexDropVersionKey(version))
}

// A version's key set past what an entry in a slot holds: a large entry.
func testIndexDropLargeKeys(version uint64) indexKeySet {
	return append(testLargeKeys(0, 6000), testIndexDropVersionKey(version))
}

// A live version of key.
func testIndexDropLive(key [indexIdByteCount]byte, version uint64, keys indexKeySet) *indexPendingDocument {
	return &indexPendingDocument{kind: indexEntryFull, key: key, version: version, keys: keys, row: testFileRow(keys)}
}

// A lineage a DROP drops: its listed versions, and the kept one, 0 at a removed boundary.
func testIndexDroppedPath(path string, kept uint64, listed ...uint64) *indexDroppedPath {
	return &indexDroppedPath{path: path, kept: kept, listed: listed}
}

// The rewrite of paths at view, failing on any error.
func testIndexDropRewrite(t testing.TB, view *indexView, refKey []byte, paths ...*indexDroppedPath) *indexDropRewriteResult {
	t.Helper()
	result, err := indexDropRewrite(context.Background(), &indexDropRewriteArgs{view: view, refKey: refKey, paths: paths, settings: DefaultIndexDropSettings()})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Commits a rewrite as the index part of a push built at view, signed by signer.
func testIndexDropCommit(t testing.TB, store indexRefStore, view *indexView, signedTime time.Time, result *indexDropRewriteResult) *indexCommitted {
	t.Helper()
	committed, err := store.Commit(context.Background(), &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: signedTime.UnixMilli(),
		files: result.files,
	})
	if err != nil {
		t.Fatal(err)
	}
	return committed
}

// One entry, row or tombstone of a key in a live file.
type testIndexDropHeld struct {
	path    string
	kind    indexEntryKind
	version uint64
}

// Every entry, row and tombstone of key in the view's live files: each writer's slots and large entries, absorbed or
// not, each bucket shard and each all shard, under every root.
func testIndexDropHolding(t testing.TB, view *indexView, key [indexIdByteCount]byte) []testIndexDropHeld {
	t.Helper()
	held := []testIndexDropHeld{}
	shards := func(viewShards []*indexViewShard) {
		for _, shard := range viewShards {
			decoded, err := view.shard(context.Background(), shard)
			if err != nil || decoded == nil {
				t.Fatalf("a shard that does not read: %v", err)
			}
			for _, document := range decoded.documents {
				if document.key == key {
					held = append(held, testIndexDropHeld{path: shard.file.path, kind: indexEntryFull, version: document.version})
				}
			}
			for _, tombstone := range decoded.tombstones {
				if tombstone.key == key {
					held = append(held, testIndexDropHeld{path: shard.file.path, kind: tombstone.kind, version: tombstone.version})
				}
			}
		}
	}
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			for _, writer := range bucket.writers {
				for _, file := range slices.Concat(writer.slots, writer.large) {
					for _, entry := range file.slot.entries {
						if entry.key == key {
							held = append(held, testIndexDropHeld{path: file.file.path, kind: entry.kind, version: entry.version})
						}
					}
				}
			}
			shards(bucket.shards)
		}
		shards(root.allShards)
	}
	return held
}

// Fails unless no live file holds key at any of versions.
func testIndexDropNoneHeld(t testing.TB, view *indexView, key [indexIdByteCount]byte, versions ...uint64) {
	t.Helper()
	for _, held := range testIndexDropHolding(t, view, key) {
		if slices.Contains(versions, held.version) {
			t.Fatalf("a listed version %d still held, kind %d", held.version, held.kind)
		}
	}
}

// Fails unless some live file holds key live at version.
func testIndexDropHeldLive(t testing.TB, view *indexView, key [indexIdByteCount]byte, version uint64) {
	t.Helper()
	for _, held := range testIndexDropHolding(t, view, key) {
		if held.kind == indexEntryFull && held.version == version {
			return
		}
	}
	t.Fatalf("version %d no longer held", version)
}

// What a search of the view finds for query, as a reader searches: the newest version of each key wins over every
// partition (each bucket's shards and unabsorbed writer files, and all's shards), a tombstone winning its tie; a hit is a
// key whose newest entry is live and holds every query key, at that version.
func testIndexDropSearch(t testing.TB, view *indexView, query ...uint32) map[[indexIdByteCount]byte]uint64 {
	t.Helper()
	type newest struct {
		version uint64
		live    bool
		keys    indexKeySet
	}
	newests := map[[indexIdByteCount]byte]newest{}
	consider := func(key [indexIdByteCount]byte, version uint64, live bool, keys indexKeySet) {
		held, ok := newests[key]
		if !ok || held.version < version || held.version == version && !live {
			newests[key] = newest{version: version, live: live, keys: keys}
		}
	}
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			documents, err := view.bucketDocuments(context.Background(), bucket)
			if err != nil {
				t.Fatal(err)
			}
			for key, entries := range documents.entries {
				for _, entry := range entries {
					switch {
					case entry.absorbed || entry.kind == indexEntryRefTombstone:
					case entry.kind == indexEntryTombstone:
						consider(key, entry.version, false, nil)
					case entry.shard:
						consider(key, entry.version, true, entry.document.keys)
					default:
						consider(key, entry.version, true, entry.entry.keys)
					}
				}
			}
		}
		shards, err := indexDecodeBucketShards(context.Background(), view, root.allShards)
		if err != nil {
			t.Fatal(err)
		}
		for _, shard := range shards {
			for _, document := range shard.documents {
				consider(document.key, document.version, true, document.keys)
			}
		}
	}
	hits := map[[indexIdByteCount]byte]uint64{}
	for key, held := range newests {
		if !held.live {
			continue
		}
		all := true
		for _, want := range query {
			_, found := slices.BinarySearch(held.keys, want)
			all = all && found
		}
		if all {
			hits[key] = held.version
		}
	}
	return hits
}

// The searches every drop test runs: each version's own key, another document's, and a key every version holds.
func testIndexDropQueries() [][]uint32 {
	return [][]uint32{
		{testIndexDropVersionKey(1)}, {testIndexDropVersionKey(2)}, {testIndexDropVersionKey(3)}, {testIndexDropVersionKey(4)},
		{testIndexDropVersionKey(100)}, {0x500000, testIndexDropVersionKey(4)}, {0x500000},
	}
}

// Every query's hits at view.
func testIndexDropSearches(t testing.TB, view *indexView) []map[[indexIdByteCount]byte]uint64 {
	t.Helper()
	hits := []map[[indexIdByteCount]byte]uint64{}
	for _, query := range testIndexDropQueries() {
		hits = append(hits, testIndexDropSearch(t, view, query...))
	}
	return hits
}

// Fails unless two runs of the queries found the same hits.
func testIndexDropSearchesEqual(t testing.TB, before []map[[indexIdByteCount]byte]uint64, after []map[[indexIdByteCount]byte]uint64) {
	t.Helper()
	for index := range before {
		if len(before[index]) != len(after[index]) {
			t.Fatalf("query %d found %d before the rewrite and %d after", index, len(before[index]), len(after[index]))
		}
		for key, version := range before[index] {
			if after[index][key] != version {
				t.Fatalf("query %d found a key at %d before and at %d after", index, version, after[index][key])
			}
		}
	}
}

// The files of a listing by path.
func testIndexDropListed(t testing.TB, store indexRefStore, refVersion uint64) map[string]*indexFileVersion {
	t.Helper()
	listing, err := store.List(context.Background(), refVersion)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]*indexFileVersion{}
	for _, file := range listing.files {
		files[file.path] = file
	}
	return files
}

// A world whose dropped path, notes/plan.md, has four versions over every partition: version 1 rolled up into all
// beside another document, version 2 in writer a's sealed slot and version 3 in writer b's large entry, both merged
// into the newer bucket's shard, which shows version 3, and version 4, the head, in a's head.
func testIndexDropWorld(t testing.TB) (*testHeadWorld, []byte, [indexIdByteCount]byte, [indexIdByteCount]byte) {
	t.Helper()
	world := testNewHeadWorld()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	refKey := testIndexDropRefKey()
	plan := testIndexDropKey(t, refKey, "notes/plan.md", 0)
	other := testIndexDropKey(t, refKey, "notes/other.md", 0)
	world.push(t, a, testIndexDropLive(plan, 1, testIndexDropKeys(1)), testIndexDropLive(other, 1, testIndexDropKeys(100)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.merge(t, evsTestId("merger"))
	first := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	world.rollUp(t, evsTestId("runner"))
	world.push(t, a, testIndexDropLive(plan, 2, testIndexDropKeys(2)))
	world.fillUntilSealed(t, a, "more", 0)
	world.push(t, b, testIndexDropLive(plan, 3, testIndexDropLargeKeys(3)))
	world.merge(t, evsTestId("merger"))
	world.push(t, a, testIndexDropLive(plan, 4, testIndexDropKeys(4)))
	return world, refKey, plan, other
}

// FS-96's index clause: a DROP listing versions 1 to 4 and keeping 4 rewrites the all shard, the bucket shard, a's
// sealed slot and b's large entry without them, each at its replaced length, writes a's and b's heads and the bucket's
// manifest again as they stood, and leaves the kept version's full entry in a's head and the other document in all; an
// indexer building it from the same base writes the same bytes; every search finds what it found before; and a push a
// built on the DROP's base gets 409 on its head and re-applies.
func TestIndexDropRewriteLeavesNoListedVersion(t *testing.T) {
	world, refKey, plan, other := testIndexDropWorld(t)
	a := evsTestId("writer a")
	base := world.view(t, evsTestId("dropper"))
	if held := testIndexDropHolding(t, base, plan); len(held) < 5 {
		t.Fatalf("the world holds the path in %d places", len(held))
	}
	dropped := testIndexDroppedPath("notes/plan.md", 4, 1, 2, 3, 4)
	result := testIndexDropRewrite(t, base, refKey, dropped)
	if result.rewrittenCount != 4 || result.takenCount != 4 || result.headCount != 2 || result.manifestCount != 1 || len(result.files) != 7 {
		t.Fatalf("rewritten %d, taken %d, heads %d, manifests %d, files %d", result.rewrittenCount, result.takenCount, result.headCount, result.manifestCount, len(result.files))
	}
	// an indexer reproducing it at the same base
	reproduced := testIndexDropRewrite(t, world.view(t, evsTestId("indexer")), refKey, dropped)
	if len(reproduced.files) != len(result.files) {
		t.Fatalf("%d files reproduced of %d", len(reproduced.files), len(result.files))
	}
	for index, file := range result.files {
		again := reproduced.files[index]
		if again.path != file.path || again.replaces != file.replaces || !bytes.Equal(again.plaintext, file.plaintext) {
			t.Fatalf("a reproduction that differs at a file")
		}
	}
	replaced := testIndexDropListed(t, world.ref.store(evsTestId("reader")), 0)
	for _, file := range result.files {
		if standing := replaced[file.path]; standing == nil || standing.version != file.replaces || standing.byteCount != len(file.plaintext) {
			t.Fatalf("a rewrite that does not replace its file at its length")
		}
	}
	before := testIndexDropSearches(t, base)
	// a's push built on the DROP's base, sent after it
	pending, pendingView := world.plan(t, a, false, testIndexDropLive(testIndexDropKey(t, refKey, "notes/late.md", 0), 1, testIndexDropKeys(200)))

	committed := testIndexDropCommit(t, world.ref.store(evsTestId("dropper")), base, world.at, result)
	after := world.view(t, evsTestId("reader"))
	testIndexDropNoneHeld(t, after, plan, 1, 2, 3)
	testIndexDropHeldLive(t, after, plan, 4)
	testIndexDropHeldLive(t, after, other, 1)
	testIndexDropSearchesEqual(t, before, testIndexDropSearches(t, after))
	if hits := testIndexDropSearch(t, after, testIndexDropVersionKey(4)); hits[plan] != 4 {
		t.Fatalf("the kept version not found: %v", hits)
	}
	written := map[string]bool{}
	for _, file := range committed.files {
		written[file.path] = true
	}
	for _, writer := range after.writeRoot().newestBucket().writers {
		if head := writer.head(); head == nil || !written[head.file.path] {
			t.Fatalf("a writer whose file the DROP rewrote kept its head as it was")
		}
	}
	if manifest := after.writeRoot().newestBucket().manifestFile; manifest == nil || !written[manifest.path] {
		t.Fatal("the bucket's manifest was not written again")
	}
	if _, err := world.commit(t, a, pending, pendingView); !isIndexRefusal(err, indexRefusalConflict) {
		t.Fatalf("a's push built before the DROP: %v", err)
	}
	world.push(t, a, testIndexDropLive(testIndexDropKey(t, refKey, "notes/late.md", 0), 1, testIndexDropKeys(200)))
	testIndexDropNoneHeld(t, world.view(t, evsTestId("reader")), plan, 1, 2, 3)
}

// A removed boundary keeps nothing: versions 1 and 2 go from the shard, the absorbed slot and the head, and the
// removal's tombstone at 3, which no DROP lists, stays; the path reads removed before and after.
func TestIndexDropRewriteAtARemovedBoundary(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	refKey := testIndexDropRefKey()
	plan := testIndexDropKey(t, refKey, "notes/plan.md", 0)
	world.push(t, a, testIndexDropLive(plan, 1, testIndexDropKeys(1)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.merge(t, evsTestId("merger"))
	world.push(t, a, testIndexDropLive(plan, 2, testIndexDropKeys(2)))
	world.push(t, a, &indexPendingDocument{kind: indexEntryTombstone, key: plan, version: 3})
	base := world.view(t, evsTestId("dropper"))
	before := testIndexDropSearches(t, base)
	result := testIndexDropRewrite(t, base, refKey, testIndexDroppedPath("notes/plan.md", 0, 1, 2))
	if result.takenCount == 0 || result.manifestCount != 1 {
		t.Fatalf("taken %d, manifests %d", result.takenCount, result.manifestCount)
	}
	testIndexDropCommit(t, world.ref.store(evsTestId("dropper")), base, world.at, result)
	after := world.view(t, evsTestId("reader"))
	testIndexDropNoneHeld(t, after, plan, 1, 2)
	tombstone := false
	for _, held := range testIndexDropHolding(t, after, plan) {
		tombstone = tombstone || held.kind == indexEntryTombstone && held.version == 3
	}
	if !tombstone {
		t.Fatal("the standing removal's tombstone went")
	}
	testIndexDropSearchesEqual(t, before, testIndexDropSearches(t, after))
}

// The rewrite is an index push naming the head's epoch, so a file it writes leaves out what the erasure set lists as
// well (§11.14's epoch row): a document a CUT listed, in the sealed slot beside the dropped version, goes with it, and
// the push commits at the CUT's epoch.
func TestIndexDropRewriteLeavesOutTheErasureSet(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	refKey := testIndexDropRefKey()
	plan := testIndexDropKey(t, refKey, "notes/plan.md", 0)
	erased := testIndexDropKey(t, refKey, "notes/erased.md", 0)
	world.push(t, a, testIndexDropLive(plan, 1, testIndexDropKeys(1)), testIndexDropLive(erased, 1, testIndexDropKeys(100)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.push(t, a, testIndexDropLive(plan, 2, testIndexDropKeys(2)))
	eraser := testNewEraser(t, world.ref.store(evsTestId("eraser")), false, &testIndexWorldClock{world: world}, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: erased, Version: 1})
	base := world.view(t, evsTestId("dropper"))
	if base.head.indexEpoch == 0 {
		t.Fatal("no CUT moved the epoch")
	}
	result := testIndexDropRewrite(t, base, refKey, testIndexDroppedPath("notes/plan.md", 2, 1, 2))
	testIndexDropCommit(t, world.ref.store(evsTestId("dropper")), base, world.at, result)
	after := world.view(t, evsTestId("reader"))
	testIndexDropNoneHeld(t, after, plan, 1)
	testIndexDropNoneHeld(t, after, erased, 1)
	testIndexDropHeldLive(t, after, plan, 2)
}

// A lineage's listed versions are what its walk found below through_version, counted as its body counts them: a
// written boundary keeps its head, a removed one nothing, and a walk that counts otherwise builds no rewrite.
func TestIndexDroppedPathOfALineage(t *testing.T) {
	versions := []*EvsHistoryVersion{
		{Version: 4, EntrySha256: []byte{4}}, {Version: 3, Removed: true}, {Version: 2, EntrySha256: []byte{2}}, {Version: 1, EntrySha256: []byte{1}},
	}
	written, err := indexDroppedPathOf(&EvsDropLineage{Path: "a.txt", Versions: versions, DropPath: &protocol.EvsDropPath{
		ThroughVersion: 5, Boundary: EvsDropBoundaryWritten, Count: 3,
	}})
	if err != nil || written.kept != 4 || !slices.Equal(written.listed, []uint64{1, 2, 4}) || written.takes(4) || !written.takes(2) || written.takes(3) {
		t.Fatalf("a written lineage: %+v, %v", written, err)
	}
	removed, err := indexDroppedPathOf(&EvsDropLineage{Path: "a.txt", Versions: versions[1:], DropPath: &protocol.EvsDropPath{
		ThroughVersion: 3, Boundary: EvsDropBoundaryRemoved, Count: 2,
	}})
	if err != nil || removed.kept != 0 || !slices.Equal(removed.listed, []uint64{1, 2}) {
		t.Fatalf("a removed lineage: %+v, %v", removed, err)
	}
	if _, err := indexDroppedPathOf(&EvsDropLineage{Path: "a.txt", Versions: versions, DropPath: &protocol.EvsDropPath{
		ThroughVersion: 5, Boundary: EvsDropBoundaryWritten, Count: 4,
	}}); !errors.Is(err, errIndexDropLineage) {
		t.Fatalf("a walk that counts otherwise: %v", err)
	}
}

// A store whose listing names one path one byte shorter than its plaintext, as a forged size would.
type testIndexDropShortStore struct {
	indexRefStore
	path string
}

func (self *testIndexDropShortStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	listing, err := self.indexRefStore.List(ctx, refVersion)
	if err != nil {
		return nil, err
	}
	for _, file := range listing.files {
		if file.path == self.path {
			file.byteCount -= 1
		}
	}
	return listing, nil
}

// A rewrite past the replaced length is refused, never padded short: a slot's and a shard's into one byte less than
// they encode to, and every rewrite where the listing names a length the file does not have, so nothing is written.
func TestIndexDropRewritePastTheReplacedLengthIsRefused(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	refKey := testIndexDropRefKey()
	plan := testIndexDropKey(t, refKey, "notes/plan.md", 0)
	other := testIndexDropKey(t, refKey, "notes/other.md", 0)
	world.push(t, a, testIndexDropLive(plan, 1, testIndexDropKeys(1)), testIndexDropLive(other, 1, testIndexDropKeys(100)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.merge(t, evsTestId("merger"))
	view := world.view(t, evsTestId("reader"))
	bucket := view.writeRoot().newestBucket()
	slot := bucket.writer(a).slotAt(0)
	kept := slices.DeleteFunc(slices.Clone(slot.slot.entries), func(entry *indexEntry) bool { return entry.key == plan })
	unpadded, err := indexEncodeSlot(&indexSlot{header: slot.slot.header, entries: kept}, false, view.settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := indexDropSlotTo(&indexSlot{header: slot.slot.header, entries: kept}, len(unpadded)-1, false, view.settings); !errors.Is(err, errIndexMalformed) {
		t.Fatalf("a slot's rewrite past its target: %v", err)
	}
	fits, err := indexDropSlotTo(&indexSlot{header: slot.slot.header, entries: kept}, slot.file.byteCount, false, view.settings)
	if err != nil || len(fits) != slot.file.byteCount {
		t.Fatalf("a slot's rewrite at its own length: %d B, %v", len(fits), err)
	}
	shard, err := view.shard(context.Background(), bucket.shards[0])
	if err != nil || shard == nil {
		t.Fatalf("the shard: %v", err)
	}
	takes := func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool { return key == plan }
	builder := indexNewShardBuilder(false)
	smallest, _, err := builder.rewriteWithout(shard, takes, bucket.shards[0].file.byteCount)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := len(bytes.TrimRight(smallest, "\x00"))
	if _, _, err := builder.rewriteWithout(shard, takes, trimmed-1); !errors.Is(err, errIndexMalformed) {
		t.Fatalf("a shard's rewrite past its target: %v", err)
	}
	for _, path := range []string{slot.file.path, bucket.shards[0].file.path} {
		short := testLoadViewWith(t, &testIndexDropShortStore{indexRefStore: world.ref.store(evsTestId("reader")), path: path}, world.settings, world.admins...)
		if _, err := indexDropRewrite(context.Background(), &indexDropRewriteArgs{
			view: short, refKey: refKey, paths: []*indexDroppedPath{testIndexDroppedPath("notes/plan.md", 0, 1)}, settings: DefaultIndexDropSettings(),
		}); !errors.Is(err, errIndexMalformed) {
			t.Fatalf("a rewrite over a listing that names another length: %v", err)
		}
	}
}

// A fake file-mode content ref for a DROP backfill: its head and its DROPs, no push of which a coverage reading counts.
type testIndexDropContent struct {
	refId Id
	head  uint64
	drops []*indexContentDrop
}

func (self *testIndexDropContent) RefId() Id {
	return self.refId
}

func (self *testIndexDropContent) Head(ctx context.Context) (*indexContentHead, error) {
	return &indexContentHead{version: self.head}, nil
}

func (self *testIndexDropContent) Pushes(ctx context.Context, afterVersion uint64, throughVersion uint64) ([]*indexContentPush, error) {
	return nil, nil
}

func (self *testIndexDropContent) State(ctx context.Context, path string, refVersion uint64) (*indexContentState, error) {
	return &indexContentState{}, nil
}

func (self *testIndexDropContent) Paths(ctx context.Context, refVersion uint64, visit func(path string, byteCount uint64) error) error {
	return nil
}

func (self *testIndexDropContent) Drops(ctx context.Context, afterVersion uint64, throughVersion uint64) ([]*indexContentDrop, error) {
	drops := []*indexContentDrop{}
	for _, drop := range self.drops {
		if afterVersion < drop.version && drop.version <= throughVersion {
			drops = append(drops, drop)
		}
	}
	return drops, nil
}

// A backfiller of the world's ref on the world's clock, as indexer, reading its DROPs from content.
func testIndexDropBackfiller(t testing.TB, world *testHeadWorld, refKey []byte, indexer Id, content *testIndexDropContent) *IndexBackfiller {
	t.Helper()
	backfiller, err := indexNewBackfiller(&indexBackfillArgs{
		store: world.ref.store(indexer), repoId: evsTestId("view repo"), refId: evsTestId("view ref"),
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL, isAdmin: world.isAdmin, format: world.settings, tables: testHeadTables,
		clock: &testIndexWorldClock{world: world}, writer: indexer, refKey: refKey,
		contents: []indexContentRef{content}, drops: indexNewDropBackfill(nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	return backfiller
}

// A signer not holding the index sends the DROP without rewrites: the listed versions stay in the files, masked by the
// kept version's newer entry, until the backfill's look BackfillAge after the DROP rewrites them, the kept version
// staying; a look before that leaves them, and a look after it has nothing more to do.
func TestIndexDropLeftToTheBackfill(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	refKey := testIndexDropRefKey()
	plan := testIndexDropKey(t, refKey, "notes/plan.md", 0)
	world.push(t, a, testIndexDropLive(plan, 1, testIndexDropKeys(1)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.merge(t, evsTestId("merger"))
	world.push(t, a, testIndexDropLive(plan, 2, testIndexDropKeys(2)))
	dropTime := world.at
	head, err := world.ref.store(a).Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	content := &testIndexDropContent{refId: evsTestId("view ref"), head: head.version, drops: []*indexContentDrop{{
		version: head.version, signedTimeMs: dropTime.UnixMilli(), paths: []*indexDroppedPath{testIndexDroppedPath("notes/plan.md", 2, 1, 2)},
	}}}
	backfiller := testIndexDropBackfiller(t, world, refKey, evsTestId("indexer"), content)
	masked := world.view(t, evsTestId("reader"))
	if len(testIndexDropHolding(t, masked, plan)) < 3 {
		t.Fatal("the listed version is not in the files")
	}
	if hits := testIndexDropSearch(t, masked, testIndexDropVersionKey(1)); len(hits) != 0 {
		t.Fatalf("a search found a listed version: %v", hits)
	}
	if hits := testIndexDropSearch(t, masked, testIndexDropVersionKey(2)); hits[plan] != 2 {
		t.Fatalf("a search missed the kept version: %v", hits)
	}
	world.at = dropTime.Add(5 * time.Minute)
	outcome, err := backfiller.backfillDrops(context.Background())
	if err != nil || outcome.dropCount != 0 || outcome.committedCount != 0 {
		t.Fatalf("a look before BackfillAge: %+v, %v", outcome, err)
	}
	testIndexDropHeldLive(t, world.view(t, evsTestId("reader")), plan, 1)
	world.at = dropTime.Add(DefaultIndexBackfillSettings().BackfillAge)
	if err := backfiller.Backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := world.view(t, evsTestId("reader"))
	testIndexDropNoneHeld(t, after, plan, 1)
	testIndexDropHeldLive(t, after, plan, 2)
	again, err := backfiller.backfillDrops(context.Background())
	if err != nil || again.dropCount != 0 {
		t.Fatalf("a second look: %+v, %v", again, err)
	}
}

// §11.14's limit row: at the storage limit the backfill's rewrite is refused as payload, comes back to the schedule
// unsent, the floor where it was and search answering from the files as they stand, and the next look after the limit
// lifts rewrites them.
func TestIndexDropBackfillWaitsAtTheLimit(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	refKey := testIndexDropRefKey()
	plan := testIndexDropKey(t, refKey, "notes/plan.md", 0)
	world.push(t, a, testIndexDropLive(plan, 1, testIndexDropKeys(1)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.push(t, a, testIndexDropLive(plan, 2, testIndexDropKeys(2)))
	head, err := world.ref.store(a).Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	content := &testIndexDropContent{refId: evsTestId("view ref"), head: head.version, drops: []*indexContentDrop{{
		version: head.version, signedTimeMs: world.at.UnixMilli(), paths: []*indexDroppedPath{testIndexDroppedPath("notes/plan.md", 2, 1, 2)},
	}}}
	backfiller := testIndexDropBackfiller(t, world, refKey, evsTestId("indexer"), content)
	world.at = world.at.Add(DefaultIndexBackfillSettings().BackfillAge)
	world.ref.refuseNext(&indexRefusal{kind: indexRefusalQuota, quota: &QuotaRefusal{LimitKey: "evs_storage_bytes"}}, false)
	if _, err := backfiller.backfillDrops(context.Background()); !isIndexRefusal(err, indexRefusalQuota) {
		t.Fatalf("a rewrite at the limit: %v", err)
	}
	held := world.view(t, evsTestId("reader"))
	testIndexDropHeldLive(t, held, plan, 1)
	if hits := testIndexDropSearch(t, held, testIndexDropVersionKey(2)); hits[plan] != 2 {
		t.Fatalf("search at the limit: %v", hits)
	}
	outcome, err := backfiller.backfillDrops(context.Background())
	if err != nil || outcome.committedCount != 1 {
		t.Fatalf("the look after the limit: %+v, %v", outcome, err)
	}
	testIndexDropNoneHeld(t, world.view(t, evsTestId("reader")), plan, 1)
}

// R3 has no manifest to fence a bucket's first merge with: a merge built before the DROP from a's sealed slot commits
// after it, creating the manifest and a shard holding the listed version again. The backfill's look takes it out.
func TestIndexDropBackfillMendsARacingMerge(t *testing.T) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	refKey := testIndexDropRefKey()
	plan := testIndexDropKey(t, refKey, "notes/plan.md", 0)
	world.push(t, a, testIndexDropLive(plan, 1, testIndexDropKeys(1)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.push(t, a, testIndexDropLive(plan, 2, testIndexDropKeys(2)))
	dropper := world.ref.store(evsTestId("dropper"))
	raced := false
	world.ref.beforeCommit = func(push *indexPush) {
		if raced {
			return
		}
		raced = true
		// the DROP commits between the merge's build and its push
		base := world.view(t, evsTestId("dropper"))
		testIndexDropCommit(t, dropper, base, world.at, testIndexDropRewrite(t, base, refKey, testIndexDroppedPath("notes/plan.md", 2, 1, 2)))
	}
	world.merge(t, evsTestId("merger"))
	world.ref.beforeCommit = nil
	if !raced {
		t.Fatal("no race")
	}
	head, err := dropper.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if held := testIndexDropHolding(t, world.view(t, evsTestId("reader")), plan); !slices.ContainsFunc(held, func(held testIndexDropHeld) bool { return held.version == 1 }) {
		t.Fatal("the merge did not carry the listed version into its shard")
	}
	content := &testIndexDropContent{refId: evsTestId("view ref"), head: head.version, drops: []*indexContentDrop{{
		version: head.version - 1, signedTimeMs: world.at.UnixMilli(), paths: []*indexDroppedPath{testIndexDroppedPath("notes/plan.md", 2, 1, 2)},
	}}}
	world.at = world.at.Add(DefaultIndexBackfillSettings().BackfillAge)
	outcome, err := testIndexDropBackfiller(t, world, refKey, evsTestId("indexer"), content).backfillDrops(context.Background())
	if err != nil || outcome.committedCount != 1 {
		t.Fatalf("the backfill's look: %+v, %v", outcome, err)
	}
	after := world.view(t, evsTestId("reader"))
	testIndexDropNoneHeld(t, after, plan, 1)
	testIndexDropHeldLive(t, after, plan, 2)
}

// FS-76's hold clauses on fake holds: under a hold the DROP's rewrite commits, the live files hold no listed version
// and the hold keeps the replaced versions that do, readable; an erasure of the path's versions then takes every live
// file and destroys the key of every stored version holding them, the bucket a roll-up removed and the all shard the
// DROP rewrote among them, the hold pausing nothing, so no openable stored version holds them.
func TestIndexDropUnderAHold(t *testing.T) {
	world := testNewEraseWorld()
	world.evs.hold = true
	a := evsTestId("writer a")
	refKey := testIndexDropRefKey()
	plan := testIndexDropKey(t, refKey, "notes/plan.md", 0)
	other := testIndexDropKey(t, refKey, "notes/other.md", 0)
	world.push(t, a, testIndexDropLive(plan, 1, testIndexDropKeys(1)), testIndexDropLive(other, 1, testIndexDropKeys(100)))
	world.fillUntilSealed(t, a, "fill", 0)
	world.merge(t, evsTestId("merger"))
	first := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	world.rollUp(t, evsTestId("runner"))
	world.push(t, a, testIndexDropLive(plan, 2, testIndexDropKeys(2)))

	base := world.view(t, evsTestId("dropper"))
	result := testIndexDropRewrite(t, base, refKey, testIndexDroppedPath("notes/plan.md", 2, 1, 2))
	if result.rewrittenCount == 0 {
		t.Fatal("nothing rewritten")
	}
	testIndexDropCommit(t, world.evs.as(evsTestId("dropper")), base, world.at, result)
	testIndexDropNoneHeld(t, world.view(t, evsTestId("reader")), plan, 1)
	dropListed := indexEraseListed{plan: 1}
	heldListed := false
	reader := world.evs.as(evsTestId("reader"))
	for path, versions := range world.evs.versions() {
		parsed, ok := indexParsePath(path, false)
		if !ok || !indexPathHoldsDocuments(parsed.kind) {
			continue
		}
		for _, version := range versions {
			if version.endedAt == 0 {
				continue
			}
			plaintext, err := reader.Read(context.Background(), version.file)
			if err != nil {
				t.Fatalf("a held version that does not read: %v", err)
			}
			holds, err := indexHolds(parsed, plaintext, dropListed, world.settings)
			if err != nil {
				t.Fatal(err)
			}
			heldListed = heldListed || holds
		}
	}
	if !heldListed {
		t.Fatal("the hold kept no version holding the listed one")
	}

	eraser := world.eraser(t, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: plan, Version: 2})
	listed := world.listed(t)
	if rewritten := world.rewrite(t, eraser, "erasure", true); !rewritten.Completed {
		t.Fatalf("the erasure under the hold: %+v", rewritten)
	}
	world.evs.sweep(t, listed)
}

// K_ref of the stand-in writer's repo.
func testIndexDropEvsRefKey(t testing.TB, writer *evsTestWriter) []byte {
	t.Helper()
	repoKey, err := writer.gkm.EnsureWritable(context.Background(), writer.world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		t.Fatal(err)
	}
	return refKey
}

// The stand-in's DROP world: a.txt written three times and another writer's slot holding a.txt's first version beside
// b.txt's, committed to the main ref's index, every planned path registered with the stand-in; and the slot's path.
func testIndexDropEvsWorld(t *testing.T) (*evsTestWriter, *evsTestDropServer, *evsTestDropCapture, string) {
	t.Helper()
	writer, server, capture := newEvsTestDropPusher(t)
	writer.server.indexEpochs = true
	writer.test.client.SetWritePlanHook(func(ctx context.Context, plan *EvsWritePlan) error {
		for _, planned := range plan.Paths {
			writer.server.know(planned.Path)
		}
		return nil
	})
	t.Cleanup(func() { writer.test.client.SetWritePlanHook(nil) })
	evsTestDropHistory(t, writer, server, "a.txt", 500, 3)
	refKey := testIndexDropEvsRefKey(t, writer)
	keyOf := func(path string) [indexIdByteCount]byte {
		key, err := indexDocKey(refKey, writer.world.refId, []byte(path), 0)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	other := evsTestId("other writer")
	header := indexNewFileHeader(indexFileSlot, indexLinkedTables())
	header.BucketStartDay, header.BucketDays, header.WriterSidecarId, header.Seq = 20340, 30, other.Bytes(), 1
	slot, err := indexEncodeSlot(&indexSlot{header: header, entries: []*indexEntry{
		{kind: indexEntryFull, key: keyOf("a.txt"), version: 1, timeSeconds: 1757400000, row: testFileRow(testIndexDropKeys(1)), keys: testIndexDropKeys(1)},
		{kind: indexEntryFull, key: keyOf("b.txt"), version: 1, timeSeconds: 1757400000, row: testFileRow(testIndexDropKeys(100)), keys: testIndexDropKeys(100)},
	}}, false, DefaultIndexFormatSettings())
	if err != nil {
		t.Fatal(err)
	}
	path, err := indexNewPaths(false, indexRootNumber).slot(20340, [indexIdByteCount]byte(other.Bytes()), 0)
	if err != nil {
		t.Fatal(err)
	}
	testIndexDropEvsCommitSlot(t, writer, path, slot, 0)
	return writer, server, capture, path
}

// Commits slot at path on the stand-in's main ref index, replacing replaces.
func testIndexDropEvsCommitSlot(t testing.TB, writer *evsTestWriter, path string, slot []byte, replaces uint64) {
	t.Helper()
	store := newIndexEvsStore(writer.repo, nil, false)
	head, err := store.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(context.Background(), &indexPush{
		pushId: NewId(), baseVersion: head.version, indexEpoch: head.indexEpoch, signedTimeMs: writer.test.clock.Now().UnixMilli(),
		files: []*indexPushFile{{path: path, plaintext: slot, replaces: replaces}},
	}); err != nil {
		t.Fatal(err)
	}
}

// The stand-in's main ref index slot at path, read through the verifying reader.
func testIndexDropEvsSlot(t testing.TB, writer *evsTestWriter, path string) *indexViewSlot {
	t.Helper()
	view, err := indexLoadView(context.Background(), &indexViewArgs{
		store: newIndexEvsStore(writer.repo, nil, false), repoId: writer.world.repoId, refId: writer.world.refId,
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL, isAdmin: func(*indexFileVersion) bool { return true }, settings: DefaultIndexFormatSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			for _, held := range bucket.writers {
				for _, slot := range held.slots {
					if slot.file.path == path {
						return slot
					}
				}
			}
		}
	}
	t.Fatal("no slot at the path")
	return nil
}

// The rewriter on the stand-in writer's client, holdsIndex its answer.
func testIndexDropEvsRewriter(t testing.TB, writer *evsTestWriter, holdsIndex bool) *IndexDropRewriter {
	t.Helper()
	rewriter, err := newIndexDropRewriter(&indexDropRewriterArgs{
		client: writer.test.client,
		store: func(repo *EvsRepo, refName []byte) indexRefStore {
			return newIndexEvsStore(repo, refName, false)
		},
		isAdmin: func(repoId Id) func(file *indexFileVersion) bool {
			return func(*indexFileVersion) bool { return true }
		},
		holdsIndex: func(repoId Id, refName []byte) bool { return holdsIndex },
		format:     DefaultIndexFormatSettings(),
		settings:   &IndexDropSettings{ChunkScanCount: 4, AttemptCount: 2},
		log:        NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return rewriter
}

// Drops a.txt's history, failing on any error.
func testIndexDropEvsDrop(t testing.TB, writer *evsTestWriter) *EvsDropHistoryResult {
	t.Helper()
	preview, err := writer.repo.DropHistoryPreview(context.Background(), &EvsDropPreviewArgs{Paths: []string{"a.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := writer.repo.DropHistory(context.Background(), &EvsDropHistoryArgs{PreviewId: preview.PreviewId, ConfirmPath: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// The hook on the real write path: the DROP push carries the other writer's slot written again without a.txt's listed
// version at its length, b.txt's entry kept, and the push reads rewritten.
func TestIndexDropHookRidesTheDropPush(t *testing.T) {
	writer, _, capture, path := testIndexDropEvsWorld(t)
	before := testIndexDropEvsSlot(t, writer, path)
	t.Cleanup(testIndexDropEvsRewriter(t, writer, true).Install())
	result := testIndexDropEvsDrop(t, writer)
	if len(result.Pushes) != 1 || !result.Pushes[0].IndexRewritten {
		t.Fatalf("the DROP's pushes %+v", result.Pushes)
	}
	drops := capture.drops(t)
	if len(drops) != 1 || len(drops[0].Changes) != 2 {
		t.Fatalf("%d DROP pushes", len(drops))
	}
	after := testIndexDropEvsSlot(t, writer, path)
	if after.file.byteCount != before.file.byteCount || after.file.version == before.file.version || len(after.slot.entries) != 1 ||
		after.slot.entries[0].key != before.slot.entries[slices.IndexFunc(before.slot.entries, func(entry *indexEntry) bool { return entry.key != testIndexDropEvsKey(t, writer, "a.txt") })].key {
		t.Fatalf("the slot after the DROP: %d B at %d, %d entries", after.file.byteCount, after.file.version, len(after.slot.entries))
	}
}

// a.txt's doc_key on the stand-in's main ref.
func testIndexDropEvsKey(t testing.TB, writer *evsTestWriter, path string) [indexIdByteCount]byte {
	t.Helper()
	key, err := indexDocKey(testIndexDropEvsRefKey(t, writer), writer.world.refId, []byte(path), 0)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A device that does not hold the index sends the DROP without rewrites, left to the backfill: the slot stands as it
// was.
func TestIndexDropHookLeavesItToTheBackfill(t *testing.T) {
	writer, _, capture, path := testIndexDropEvsWorld(t)
	before := testIndexDropEvsSlot(t, writer, path)
	t.Cleanup(testIndexDropEvsRewriter(t, writer, false).Install())
	result := testIndexDropEvsDrop(t, writer)
	if len(result.Pushes) != 1 || result.Pushes[0].IndexRewritten {
		t.Fatalf("the DROP's pushes %+v", result.Pushes)
	}
	if drops := capture.drops(t); len(drops) != 1 || len(drops[0].Changes) != 1 {
		t.Fatal("a DROP carrying index changes")
	}
	if after := testIndexDropEvsSlot(t, writer, path); after.file.version != before.file.version {
		t.Fatal("the slot moved with a DROP sent without rewrites")
	}
}

// Another push writes the slot between the hook's read and the DROP's plan: the DROP is refused for its rewrite alone,
// which is built again under the same confirmation on the slot's new version, and rides the DROP.
func TestIndexDropRewritesRebuiltWhenTheirFileMoves(t *testing.T) {
	writer, _, capture, path := testIndexDropEvsWorld(t)
	rewriter := testIndexDropEvsRewriter(t, writer, true)
	calls := []bool{}
	writer.test.client.SetDropIndexHook(func(ctx context.Context, repo *EvsRepo, args *EvsDropIndexArgs) (*EvsDropIndexRewrites, error) {
		calls = append(calls, args.Rebuild)
		rewrites, err := rewriter.Hook(ctx, repo, args)
		if err != nil || args.Rebuild {
			return rewrites, err
		}
		// the slot moves: the same entries, written again by another push
		standing := testIndexDropEvsSlot(t, writer, path)
		slot, err := indexEncodeSlot(standing.slot, false, DefaultIndexFormatSettings())
		if err != nil {
			t.Fatal(err)
		}
		testIndexDropEvsCommitSlot(t, writer, path, slot, standing.file.version)
		return rewrites, nil
	})
	t.Cleanup(func() { writer.test.client.SetDropIndexHook(nil) })
	result := testIndexDropEvsDrop(t, writer)
	if !slices.Equal(calls, []bool{false, true}) || !result.Pushes[0].IndexRewritten {
		t.Fatalf("hook calls %v, rewritten %v", calls, result.Pushes[0].IndexRewritten)
	}
	if drops := capture.drops(t); len(drops) != 1 || len(drops[0].Changes) != 2 {
		t.Fatal("the DROP that committed does not carry its rewrite")
	}
	after := testIndexDropEvsSlot(t, writer, path)
	if len(after.slot.entries) != 1 || after.slot.entries[0].key == testIndexDropEvsKey(t, writer, "a.txt") {
		t.Fatal("the rebuilt rewrite left a.txt's listed version")
	}
}

// An index store whose first listing finds the head moved under it, as a push landing during the walk leaves it.
type testIndexDropMovingStore struct {
	indexRefStore
	moves *int
}

func (self *testIndexDropMovingStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	if 0 < *self.moves {
		*self.moves -= 1
		return nil, indexEvsMoved(1, 2)
	}
	return self.indexRefStore.List(ctx, refVersion)
}

// A push moving the head while the hook reads the index sends it to read again, not to leave the rewrite to the
// backfill: the rewrite built on the second read rides the DROP.
func TestIndexDropHookReadsTheIndexAgainWhenItMoves(t *testing.T) {
	writer, _, capture, path := testIndexDropEvsWorld(t)
	rewriter := testIndexDropEvsRewriter(t, writer, true)
	moves := 1
	rewriter.args.store = func(repo *EvsRepo, refName []byte) indexRefStore {
		return &testIndexDropMovingStore{indexRefStore: newIndexEvsStore(repo, refName, false), moves: &moves}
	}
	t.Cleanup(rewriter.Install())
	result := testIndexDropEvsDrop(t, writer)
	if moves != 0 || !result.Pushes[0].IndexRewritten {
		t.Fatalf("moves left %d, rewritten %v", moves, result.Pushes[0].IndexRewritten)
	}
	if drops := capture.drops(t); len(drops) != 1 || len(drops[0].Changes) != 2 {
		t.Fatal("the DROP does not carry its rewrite")
	}
	if after := testIndexDropEvsSlot(t, writer, path); len(after.slot.entries) != 1 {
		t.Fatalf("the slot holds %d entries", len(after.slot.entries))
	}
}
