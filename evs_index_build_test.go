//go:build !ios_extension

// SEARCH-M10-15's tests (§11.14's settings, on, off, limit and rebuild rows; FS-72's first build, FS-79 at unit level,
// on the fake stores): one full build lands, each document in the window of its content push's time or in all, every
// push reading not yet searchable until it does and indexed after; two builders of one pin write equal shards and
// manifests, and the lock lets one build at a time; a build replaces every writer's file but the settings, and a
// writer's push planned before it is refused; the erasure set's documents are left out; config repos build nothing;
// the migration's first build on a file-mode ref; settings by an admin count and another's do not, the directory
// refusing off and long windows; off removes every file and takes no delta from honest writers; off at the storage
// limit in its steps, waiting while the off version is refused.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A builder of the world's index ref, signing as builder, on the world's clock and content.
func (self *testBackfillWorld) builderOf(t testing.TB, builder Id) *IndexBuilder {
	t.Helper()
	indexBuilder, err := indexNewBuilder(&indexBuilderArgs{
		store:     self.index.store(builder),
		repoId:    evsTestId("view repo"),
		refId:     evsTestId("view ref"),
		repoKind:  self.repoKind,
		companion: self.companion,
		isAdmin:   testIndexEraserAdmin,
		format:    self.settings,
		tables:    testHeadTables,
		clock:     self,
		builder:   builder,
		refKey:    self.refKey,
		contents:  []indexContentRef{self.content},
		padKey: func(ctx context.Context) (*indexPadKey, error) {
			return testPadKey(t, 2), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return indexBuilder
}

// The settings write's args for the world's index ref through store.
func (self *testBackfillWorld) settingsArgs(store indexRefStore) *indexSettingsArgs {
	return &indexSettingsArgs{
		store:        store,
		repoId:       evsTestId("view repo"),
		refId:        evsTestId("view ref"),
		repoKind:     self.repoKind,
		companion:    self.companion,
		isAdmin:      testIndexEraserAdmin,
		format:       self.settings,
		attemptCount: 8,
		clock:        self,
	}
}

// Whether a bucket's shards hold key, and all's.
func testShardsHold(t testing.TB, view *indexView, shards []*indexViewShard, key [indexIdByteCount]byte) bool {
	t.Helper()
	decoded, err := indexDecodeBucketShards(context.Background(), view, shards)
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range decoded {
		for _, document := range shard.documents {
			if document.key == key {
				return true
			}
		}
	}
	return false
}

// The paths the head lists under the world's root.
func testRootPaths(t testing.TB, world *testBackfillWorld) []string {
	t.Helper()
	listing, err := world.index.store(evsTestId("reader")).List(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	prefix := indexNewPaths(world.companion, indexRootNumber).root + "/"
	paths := []string{}
	for _, file := range listing.files {
		if strings.HasPrefix(file.path, prefix) {
			paths = append(paths, file.path)
		}
	}
	return paths
}

// Commits three files: one long before the latest windows, one in the window before today's, one in today's.
func testBuildContent(t testing.TB, world *testBackfillWorld, signer Id) {
	t.Helper()
	world.now = testDayTime(20200, 0)
	world.commit(t, signer, nil, testContentChange{path: "old.txt", content: []byte("an old ledger of turnips")})
	world.now = testDayTime(20320, 0)
	world.commit(t, signer, nil, testContentChange{path: "mid.txt", content: []byte("radishes in the window before")})
	world.now = testDayTime(20341, 0)
	world.commit(t, signer, nil, testContentChange{path: "new.txt", content: []byte("parsnips in today's window")})
}

// FS-79 at unit level: before the build every push reads not yet searchable; one build lands, today's document in
// today's bucket, the one before in the previous window's, the old one in all; every push then reads indexed, the
// builder's head carrying the horizon and the lock freed.
func TestIndexBuildWritesTheRootWholeFromTheText(t *testing.T) {
	world := testNewBackfillWorld(true)
	testBuildContent(t, world, evsTestId("writer a"))
	if coverage := world.coverage(t, false); coverage.indexedThrough != 0 || coverage.unindexedCount != 3 {
		t.Fatalf("before the build: through %d, %d not yet searchable", coverage.indexedThrough, coverage.unindexedCount)
	}
	builder := evsTestId("builder")
	outcome, err := world.builderOf(t, builder).Build(context.Background())
	if err != nil || outcome.committed == nil || outcome.skipped != indexBuildNotSkipped {
		t.Fatalf("the build: %v, skipped %d", err, outcome.skipped)
	}
	if len(outcome.refs) != 1 || outcome.refs[0].pin != 3 || outcome.refs[0].horizon != 3 || outcome.refs[0].entryCount != 3 {
		t.Fatalf("the build's ref: %+v", outcome.refs[0])
	}
	if coverage := world.coverage(t, false); coverage.indexedThrough != 3 || coverage.unindexedCount != 0 {
		t.Fatalf("after the build: through %d, %d not yet searchable", coverage.indexedThrough, coverage.unindexedCount)
	}
	view := world.view(t)
	root := view.writeRoot()
	if len(root.buckets) != 2 || root.buckets[0].window.startDay != 20310 || root.buckets[1].window.startDay != 20340 {
		t.Fatalf("buckets: %v", root.bucketWindows())
	}
	if !testShardsHold(t, view, root.buckets[0].shards, world.key(t, "mid.txt", 0)) || !testShardsHold(t, view, root.buckets[1].shards, world.key(t, "new.txt", 0)) {
		t.Fatal("a latest document is not in its window's shards")
	}
	if !testShardsHold(t, view, root.allShards, world.key(t, "old.txt", 0)) || testShardsHold(t, view, root.allShards, world.key(t, "new.txt", 0)) {
		t.Fatal("all holds the wrong documents")
	}
	if root.allManifest == nil || root.allManifest.RolledThroughDay != 20280 {
		t.Fatalf("a/m: %v", root.allManifest)
	}
	rows := world.headRows(t, builder)
	if len(rows) != 1 || !rows[0].Horizon || rows[0].Version != 3 || !bytes.Equal(rows[0].RefId, world.content.refId.Bytes()) {
		t.Fatalf("the builder's rows: %v", rows)
	}
	if root.lock == nil || len(root.lock.HolderSidecarId) != 0 {
		t.Fatal("the build left its lock held")
	}
}

// Two devices racing build equal plaintext: the plans of two builders at one pin write the same shards and manifests,
// only each one's own head differing; and through the lock only one builds, the other finding it held.
func TestIndexBuildTwoBuildersWriteEqualPlaintext(t *testing.T) {
	world := testNewBackfillWorld(true)
	testBuildContent(t, world, evsTestId("writer a"))
	a, b := evsTestId("builder a"), evsTestId("builder b")
	view := world.view(t)
	listing, err := world.index.store(a).List(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	plans := []*indexBuildPlan{}
	for _, builder := range []Id{a, b} {
		ref, entries, err := world.builderOf(t, builder).collect(context.Background(), view, normalizer, world.content, world.now)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := indexPlanBuild(context.Background(), &indexBuildPlanArgs{
			view: view, root: view.writeRoot(), listing: listing, entries: entries,
			rows:    []*protocol.IndexCoverage{{RefId: ref.refId.Bytes(), Version: ref.horizon, Horizon: true}},
			builder: builder, signedTimeMs: world.now.UnixMilli(), padKey: testPadKey(t, 2), tables: testHeadTables,
		})
		if err != nil {
			t.Fatal(err)
		}
		plans = append(plans, plan)
	}
	filesA, filesB := plans[0].contentFiles(a, true), plans[1].contentFiles(b, true)
	if len(filesA) == 0 || len(filesA) != len(filesB) {
		t.Fatalf("the plans write %d and %d files", len(filesA), len(filesB))
	}
	for index := range filesA {
		if filesA[index].path != filesB[index].path || !bytes.Equal(filesA[index].plaintext, filesB[index].plaintext) {
			t.Fatalf("%s differs between the builders", filesA[index].path)
		}
	}
	if len(plans[0].files) != len(filesA)+1 {
		t.Fatal("a plan writes more than the content and its own head")
	}

	// a holds the lock: b's build finds it held and writes nothing
	root := view.writeRoot()
	if _, err := indexTakeLock(context.Background(), world.index.store(a), view, root, a, 0, world.now, world); err != nil {
		t.Fatal(err)
	}
	outcome, err := world.builderOf(t, b).Build(context.Background())
	if err != nil || outcome.skipped != indexBuildSkipLocked || outcome.committed != nil {
		t.Fatalf("b's build beside a's lock: %v, skipped %d", err, outcome.skipped)
	}
}

// A build replaces every writer's file but the settings: a writer's head goes, the admin's settings version stays, and
// the writer's next push planned at the old base is refused on its head and plans again.
func TestIndexBuildReplacesEveryWriterFileButTheSettings(t *testing.T) {
	world := testNewBackfillWorld(true)
	testBuildContent(t, world, evsTestId("writer a"))
	writer, admin := evsTestId("writer w"), evsTestId("eraser")
	world.carry(t, writer, world.row(2, false))
	if _, err := indexApplySettings(context.Background(), world.settingsArgs(world.index.store(admin)), func(current *protocol.IndexSettings) *protocol.IndexSettings {
		return &protocol.IndexSettings{WindowDays: 30}
	}); err != nil {
		t.Fatal(err)
	}
	stale := world.view(t)
	settingsPath := stale.writeRoot().paths.settings()
	settingsVersion := world.index.store(admin).testVersionOf(settingsPath)
	stalePlan, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: stale, root: stale.writeRoot(), writer: writer, signedTimeMs: world.now.UnixMilli(), tables: testHeadTables,
		coverage: indexRaiseCoverage(indexWriterNewestRows(stale.writeRoot(), writer), []*protocol.IndexCoverage{world.row(3, false)}),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := world.builderOf(t, evsTestId("builder")).Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	view := world.view(t)
	for _, bucket := range view.writeRoot().buckets {
		if bucket.writer(writer) != nil {
			t.Fatal("the writer's head outlived the build")
		}
	}
	if world.index.store(admin).testVersionOf(settingsPath) != settingsVersion || view.writeRoot().settings.GetWindowDays() != 30 {
		t.Fatal("the build changed the settings")
	}
	_, err = world.index.store(writer).Commit(context.Background(), &indexPush{
		pushId: NewId(), baseVersion: stale.head.version, indexEpoch: stale.head.indexEpoch, signedTimeMs: world.now.UnixMilli(),
		files: stalePlan.files(), removals: stalePlan.removals(),
	})
	if !isIndexRefusal(err, indexRefusalConflict) {
		t.Fatalf("a push planned before the build: %v", err)
	}
}

// The erasure set's documents are left out of a build; a config repo builds nothing.
func TestIndexBuildLeavesOutTheErasureSetAndConfigRepos(t *testing.T) {
	world := testNewBackfillWorld(true)
	testBuildContent(t, world, evsTestId("writer a"))
	eraser := testNewEraser(t, world.index.store(evsTestId("eraser")), true, world, nil)
	// new.txt's first version is its push's, 3
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: world.key(t, "new.txt", 0), Version: 3})
	outcome, err := world.builderOf(t, evsTestId("builder")).Build(context.Background())
	if err != nil || outcome.committed == nil {
		t.Fatalf("the build after a CUT: %v", err)
	}
	view := world.view(t)
	for _, bucket := range view.writeRoot().buckets {
		if testShardsHold(t, view, bucket.shards, world.key(t, "new.txt", 0)) {
			t.Fatal("the build wrote an erased document")
		}
	}
	if outcome.refs[0].entryCount != 2 {
		t.Fatalf("the build wrote %d documents", outcome.refs[0].entryCount)
	}

	config := testNewBackfillWorld(true)
	config.repoKind = protocol.RepoKind_REPO_KIND_CONFIG
	testBuildContent(t, config, evsTestId("writer a"))
	if _, err := config.builderOf(t, evsTestId("builder")).Build(context.Background()); !errors.Is(err, errIndexBuildExcluded) {
		t.Fatalf("a build in a config repo: %v", err)
	}
	if paths := testRootPaths(t, config); len(paths) != 0 {
		t.Fatalf("a config repo holds index files: %v", paths)
	}
}

// FS-72's migration ending in a first build: a file-mode ref a format-1 client wrote holds no index; the first build
// writes it from the ref's own text at its base, and every push then reads indexed.
func TestIndexFirstBuildEndsAMigration(t *testing.T) {
	world := testNewBackfillWorld(false)
	testBuildContent(t, world, evsTestId("format-1 writer"))
	if coverage := world.coverage(t, false); coverage.unindexedCount != 3 {
		t.Fatalf("the migrated ref: %d not yet searchable", coverage.unindexedCount)
	}
	outcome, err := world.builderOf(t, evsTestId("builder")).FirstBuild(context.Background())
	if err != nil || outcome.committed == nil {
		t.Fatalf("the first build: %v", err)
	}
	// the ref is its own index's: the lock's and the build's pushes touch only .ur-index/, so every version reads indexed
	view := world.view(t)
	if coverage := world.coverage(t, false); coverage.indexedThrough != view.head.version || coverage.unindexedCount != 0 {
		t.Fatalf("after the first build: through %d of %d, %d not yet searchable", coverage.indexedThrough, view.head.version, coverage.unindexedCount)
	}
	if !testShardsHold(t, view, view.writeRoot().allShards, world.key(t, "old.txt", 0)) {
		t.Fatal("the first build left the old document out of all")
	}
}

// A version counts only if a repo admin signed it: an admin's window counts; another's is passed over and alarmed;
// windows outside 7-365 are refused, and the team directory refuses off and a window past 90.
func TestIndexSettingsCountAnAdminsVersionAndRefuseWhatTheKindDoesNot(t *testing.T) {
	world := testNewBackfillWorld(true)
	window := func(days uint32) indexSettingsChange {
		change, err := indexSettingsChangeOf(EvsIndexWindow, days)
		if err != nil {
			t.Fatal(err)
		}
		return change
	}
	if _, err := indexApplySettings(context.Background(), world.settingsArgs(world.index.store(evsTestId("eraser"))), window(14)); err != nil {
		t.Fatal(err)
	}
	if root := world.view(t).writeRoot(); root.windowDays(world.repoKind) != 14 {
		t.Fatalf("an admin's window: %d", root.windowDays(world.repoKind))
	}
	if _, err := indexApplySettings(context.Background(), world.settingsArgs(world.index.store(evsTestId("member"))), window(60)); err != nil {
		t.Fatal(err)
	}
	view := world.view(t)
	if view.writeRoot().windowDays(world.repoKind) != 14 || !slices.ContainsFunc(view.alarms, func(alarm *indexViewAlarm) bool {
		return alarm.reason == indexViewAlarmSettings && alarm.signerSidecarId == evsTestId("member")
	}) {
		t.Fatal("a member's settings version counted, or raised no alarm")
	}
	if _, err := indexApplySettings(context.Background(), world.settingsArgs(world.index.store(evsTestId("eraser"))), window(5)); !errors.Is(err, ErrEvsIndexSettings) {
		t.Fatalf("a 5-day window: %v", err)
	}

	directory := testNewBackfillWorld(true)
	directory.repoKind = protocol.RepoKind_REPO_KIND_DIRECTORY
	off, _ := indexSettingsChangeOf(EvsIndexOff, 0)
	for _, change := range []indexSettingsChange{off, window(120)} {
		if _, err := indexApplySettings(context.Background(), directory.settingsArgs(directory.index.store(evsTestId("eraser"))), change); !errors.Is(err, ErrEvsIndexSettings) {
			t.Fatalf("the directory took settings it refuses: %v", err)
		}
	}
	if _, err := indexApplySettings(context.Background(), directory.settingsArgs(directory.index.store(evsTestId("eraser"))), window(60)); err != nil {
		t.Fatalf("the directory's 60-day window: %v", err)
	}
}

// Off removes every file of the root but its settings in the push that turns it off, the erasure set staying; honest
// writers then write nothing, and a build finds it off.
func TestIndexOffRemovesEveryFileAndTakesNoDelta(t *testing.T) {
	world := testNewBackfillWorld(true)
	testBuildContent(t, world, evsTestId("writer a"))
	eraser := testNewEraser(t, world.index.store(evsTestId("eraser")), true, world, nil)
	testCut(t, eraser, "erasure", &IndexCutDocument{Key: world.key(t, "mid.txt", 0), Version: 1})
	if _, err := world.builderOf(t, evsTestId("builder")).Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	built := len(testRootPaths(t, world))
	off, _ := indexSettingsChangeOf(EvsIndexOff, 0)
	outcomes, err := indexApplySettings(context.Background(), world.settingsArgs(world.index.store(evsTestId("eraser"))), off)
	if err != nil || len(outcomes) != 1 || outcomes[0].waiting || outcomes[0].removedCount != built || outcomes[0].version == 0 {
		t.Fatalf("off: %v, %+v", err, outcomes)
	}
	view := world.view(t)
	root := view.writeRoot()
	if paths := testRootPaths(t, world); len(paths) != 1 || paths[0] != root.paths.settings() || !root.off() {
		t.Fatalf("after off the root holds %v", paths)
	}
	if view.erasureSet == nil || len(view.erasureSet.Erasures) != 1 {
		t.Fatal("off took the erasure set")
	}
	plan, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: view, root: root, writer: evsTestId("writer a"), signedTimeMs: world.now.UnixMilli(), tables: testHeadTables,
		pending: []*indexPendingDocument{{kind: indexEntryTombstone, key: world.key(t, "old.txt", 0), version: 2}},
	})
	if err != nil || len(plan.files()) != 0 {
		t.Fatalf("an honest writer's push with the index off writes %d files: %v", len(plan.files()), err)
	}
	if outcome, err := world.builderOf(t, evsTestId("builder")).Build(context.Background()); err != nil || outcome.skipped != indexBuildSkipOff {
		t.Fatalf("a build with the index off: %v, skipped %d", err, outcome.skipped)
	}
}

// A store whose commits a test refuses or races: before runs ahead of each commit, and an error it answers is the
// commit's.
type testIndexHookedStore struct {
	indexRefStore
	before func(push *indexPush) error
}

func (self *testIndexHookedStore) Commit(ctx context.Context, push *indexPush) (*indexCommitted, error) {
	if self.before != nil {
		if err := self.before(push); err != nil {
			return nil, err
		}
	}
	return self.indexRefStore.Commit(ctx, push)
}

// Off at the storage limit, in its steps: the settings version is refused while removals pass, so the files go first
// and the off version waits; called again once the limit clears, the off version lands, and the head a writer
// re-created meanwhile goes after it.
func TestIndexOffAtTheLimitInItsSteps(t *testing.T) {
	world := testNewBackfillWorld(true)
	testBuildContent(t, world, evsTestId("writer a"))
	if _, err := world.builderOf(t, evsTestId("builder")).Build(context.Background()); err != nil {
		t.Fatal(err)
	}
	built := len(testRootPaths(t, world))
	writer := evsTestId("writer w")
	atLimit, recreate := true, false
	holdsSettings := func(push *indexPush) bool {
		return slices.ContainsFunc(push.files, func(file *indexPushFile) bool {
			return strings.HasSuffix(file.path, "/settings")
		})
	}
	store := &testIndexHookedStore{indexRefStore: world.index.store(evsTestId("eraser")), before: func(push *indexPush) error {
		if holdsSettings(push) && len(push.removals) == 0 && recreate {
			// a writer re-creates its head before the off version lands, and the limit clears
			recreate, atLimit = false, false
			world.carry(t, writer, world.row(3, false))
		}
		if holdsSettings(push) && atLimit {
			return &indexRefusal{kind: indexRefusalQuota}
		}
		return nil
	}}
	off, _ := indexSettingsChangeOf(EvsIndexOff, 0)
	outcomes, err := indexApplySettings(context.Background(), world.settingsArgs(store), off)
	if err != nil || len(outcomes) != 1 || !outcomes[0].waiting || outcomes[0].removedCount != built || outcomes[0].version != 0 {
		t.Fatalf("off at the limit: %v, %+v", err, outcomes)
	}
	view := world.view(t)
	if paths := testRootPaths(t, world); len(paths) != 0 || view.writeRoot().off() {
		t.Fatalf("the files went first: %v, off %v", paths, view.writeRoot().off())
	}

	// a writer writes while the off version waits; called again, the off version lands and that head goes after it
	world.carry(t, writer, world.row(2, false))
	recreate = true
	outcomes, err = indexApplySettings(context.Background(), world.settingsArgs(store), off)
	if err != nil || len(outcomes) != 1 || outcomes[0].waiting || outcomes[0].version == 0 {
		t.Fatalf("off once the limit clears: %v, %+v", err, outcomes)
	}
	view = world.view(t)
	if paths := testRootPaths(t, world); len(paths) != 1 || paths[0] != view.writeRoot().paths.settings() || !view.writeRoot().off() {
		t.Fatalf("after the steps the root holds %v", paths)
	}
}
