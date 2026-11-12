// Roll-ups and the index lock (SEARCH-M10-11; DESIGN-DETAILS 1.2.5, 1.5 and 1.6): a bucket into an empty all and over
// an older all row, a tombstone taking all's row, the promotion of a tombstone and of a live version into a newer
// bucket that holds only older entries, with that bucket's shard and manifest, a ref tombstone on ur/index, the
// erasure set's documents left out, the removed bucket's coverage carried forward as a horizon row in the runner's
// head, the lock taken, held against a second runner, lapsed and taken over, renewed at half its term, and its fence
// stopping a lapsed runner, a rerun's plaintext equal to the first, the storage limit, the schedule's runner rules,
// and 1.6's roll-up vectors with their plaintext hashes, all on the fake store.

package sidecar

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

const testRollupVectorPath = "testdata/index/rollup/vectors.json"

// A roller of the world's ref, running as runner on the world's clock and settings.
func (self *testHeadWorld) roller(t testing.TB, runner Id) *IndexRoller {
	t.Helper()
	return self.rollerWith(t, runner, nil)
}

// A roller whose coverage reading is indexedThrough.
func (self *testHeadWorld) rollerWith(t testing.TB, runner Id, indexedThrough func(view *indexView, refId []byte) (uint64, bool)) *IndexRoller {
	t.Helper()
	roller, err := indexNewRoller(&indexRollerArgs{
		store:    self.ref.store(runner),
		repoId:   evsTestId("view repo"),
		refId:    evsTestId("view ref"),
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL,
		format:   self.settings,
		padKey: func(ctx context.Context) (*indexPadKey, error) {
			return testPadKey(t, 2), nil
		},
		tables:         testHeadTables,
		clock:          &testIndexWorldClock{world: self},
		runner:         runner,
		indexedThrough: indexedThrough,
	})
	if err != nil {
		t.Fatal(err)
	}
	return roller
}

// Rolls the oldest expired bucket, failing on an error or a roll-up that commits nothing.
func (self *testHeadWorld) rollUp(t testing.TB, runner Id) *indexRollupOutcome {
	t.Helper()
	outcome, err := self.roller(t, runner).Roll(context.Background(), indexRootNumber)
	if err != nil {
		t.Fatal(err)
	}
	if outcome.committed == nil {
		t.Fatalf("a roll-up that committed nothing: skipped %d", outcome.skipped)
	}
	return outcome
}

// all's rows by key, as a reader of the head decodes them.
func (self *testHeadWorld) allRows(t testing.TB) (map[[indexIdByteCount]byte]*indexShardDocument, *indexViewRoot) {
	t.Helper()
	view := self.view(t, evsTestId("reader"))
	root := view.writeRoot()
	shards, err := indexDecodeBucketShards(context.Background(), view, root.allShards)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[[indexIdByteCount]byte]*indexShardDocument{}
	for _, shard := range shards {
		if len(shard.tombstones) != 0 {
			t.Fatal("a tombstone in all")
		}
		for _, document := range shard.documents {
			if rows[document.key] != nil {
				t.Fatal("a document twice in all")
			}
			rows[document.key] = document
		}
	}
	return rows, root
}

// The world after a first bucket of documents, its clock moved to day, and that bucket's start day.
func testRollupWorld(t testing.TB) (*testHeadWorld, Id) {
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("u", 1, 1, 0, testHeadKeys(1, 0)), testLive("u", 2, 1, 0, testHeadKeys(2, 0)))
	world.fillUntilSealed(t, a, "f", 0)
	world.merge(t, evsTestId("merger"))
	world.push(t, a, testLive("u", 3, 1, 0, testHeadKeys(3, 0)))
	return world, a
}

// A bucket into an empty all: every live document of it, its heads' included, becomes an all row; a/m names S as
// rolled through; every file under b/<S>/ goes, the lock is free again, and a rerun finds nothing expired.
func TestIndexRollupIntoEmptyAll(t *testing.T) {
	world, a := testRollupWorld(t)
	before := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(before.window.endDay()+before.window.days, time.Hour)
	outcome := world.rollUp(t, evsTestId("runner"))
	if outcome.startDay != before.window.startDay {
		t.Fatalf("rolled %d", outcome.startDay)
	}
	rows, root := world.allRows(t)
	for _, key := range [][indexIdByteCount]byte{testIndexId("u", 1), testIndexId("u", 2), testIndexId("u", 3), testIndexId("f", 0)} {
		if rows[key] == nil {
			t.Fatal("a document of the rolled bucket is not in all")
		}
	}
	if root.allManifest == nil || root.allManifest.RolledThroughDay != before.window.startDay {
		t.Fatal("a/m does not name the bucket rolled through")
	}
	if root.bucket(before.window.startDay) != nil {
		t.Fatal("the rolled bucket stayed")
	}
	for _, file := range before.files() {
		if world.ref.store(a).testVersionOf(file.path) != 0 {
			t.Fatalf("a file of the rolled bucket stayed")
		}
	}
	if root.lock == nil || len(root.lock.HolderSidecarId) != 0 {
		t.Fatal("the lock is not free after the roll-up")
	}
	again, err := world.roller(t, evsTestId("runner")).Roll(context.Background(), indexRootNumber)
	if err != nil || again.skipped != indexRollupSkipNone {
		t.Fatalf("a second roll-up: %+v %v", again, err)
	}
}

// Over an older all row the bucket's newer version replaces it; a tombstone takes all's row and then goes, nothing
// older remaining (FS-108's roll-up clause); a version the erasure set lists does not reach all.
func TestIndexRollupOverAllRows(t *testing.T) {
	world, a := testRollupWorld(t)
	first := world.view(t, a).writeRoot().newestBucket()
	// the next window: u1 edited, u2 removed, u4 created and erased
	world.at = testDayTime(first.window.endDay(), time.Hour)
	world.push(t, a, testLive("u", 1, 2, 0, testHeadKeys(1, 1)), testRemoved("u", 2, 2), testLive("u", 4, 1, 0, testHeadKeys(4, 0)))
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	world.rollUp(t, evsTestId("runner"))
	rows, _ := world.allRows(t)
	if rows[testIndexId("u", 1)] == nil || rows[testIndexId("u", 1)].version != 1 || rows[testIndexId("u", 2)] == nil {
		t.Fatal("the first roll-up's rows")
	}
	erasureSet := &protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{{ErasureId: testIndexIdBytes("erasure", 1), EraserSidecarId: evsTestId("eraser").Bytes(), Docs: []*protocol.IndexErased{{DocKey: testIndexIdBytes("u", 4), Version: 1}}}}}
	file, err := indexEncodeErasureSet(erasureSet, world.settings)
	if err != nil {
		t.Fatal(err)
	}
	world.ref.store(evsTestId("eraser")).testCommit(t, world.at, &indexPushFile{path: indexErasureSetPath(false), plaintext: file})
	world.at = testDayTime(first.window.endDay()+2*first.window.days, time.Hour)
	world.rollUp(t, evsTestId("runner"))
	rows, root := world.allRows(t)
	if got := rows[testIndexId("u", 1)]; got == nil || got.version != 2 {
		t.Fatal("the newer version did not replace all's row")
	}
	if rows[testIndexId("u", 2)] != nil {
		t.Fatal("a tombstone left all's row")
	}
	if rows[testIndexId("u", 4)] != nil {
		t.Fatal("an erased document reached all")
	}
	if len(root.buckets) != 0 {
		t.Fatalf("%d buckets left", len(root.buckets))
	}
}

// Two writers' clocks apart at a window boundary leave a newer version, and then a tombstone, in the older bucket
// while the newer bucket holds an older entry (FS-108's skew clause): the roll-up promotes each into the newer bucket's
// shards with its manifest, created there, the tombstone taking all's row, and readers find the newer bucket's entry
// masked; that bucket's own merge keeps the promoted entries above its older ones.
func TestIndexRollupPromotes(t *testing.T) {
	world, a := testRollupWorld(t)
	b := evsTestId("writer b")
	first := world.view(t, a).writeRoot().newestBucket()
	boundary := first.window.endDay()
	// b plans at a base before the next window opens, signed a minute before the boundary
	world.at = testDayTime(boundary, -time.Minute)
	planB, viewB := world.plan(t, b, true, testLive("s", 1, 3, 0, testHeadKeys(11, 1)), testRemoved("s", 2, 3))
	// a's older versions land first, past the boundary, opening the next bucket
	world.at = testDayTime(boundary, time.Minute)
	world.push(t, a, testLive("s", 1, 2, 0, testHeadKeys(11, 0)), testLive("s", 2, 2, 0, testHeadKeys(12, 0)))
	if _, err := world.commit(t, b, planB, viewB); err != nil {
		t.Fatal(err)
	}
	if planB.buckets[0].window.startDay != first.window.startDay {
		t.Fatal("b's entries did not land in the older bucket")
	}
	world.at = testDayTime(boundary+first.window.days, time.Hour)
	outcome := world.rollUp(t, evsTestId("runner"))
	promoted := outcome.result.promoted[boundary]
	if len(promoted) != 2 {
		t.Fatalf("%d entries promoted", len(promoted))
	}
	merged := world.mergedBucket(t)
	if merged.bucket.window.startDay != boundary || merged.bucket.manifest == nil {
		t.Fatal("the promotion wrote no manifest in the newer bucket")
	}
	if got := merged.documents[testIndexId("s", 1)]; got == nil || got.version != 3 {
		t.Fatal("the live version was not promoted")
	}
	if got := merged.tombstones[testIndexId("s", 2)]; got == nil || got.version != 3 {
		t.Fatal("the tombstone was not promoted")
	}
	if len(merged.bucket.manifest.Absorbed) != 0 {
		t.Fatal("a promotion absorbed a slot")
	}
	rows, _ := world.allRows(t)
	if rows[testIndexId("s", 1)] != nil || rows[testIndexId("s", 2)] != nil {
		t.Fatal("a promoted document also went to all")
	}
	// the newer bucket's own merge keeps the promoted entries over a's older ones: a, its clock an hour behind the
	// next window, seals its head there
	world.at = testDayTime(boundary+first.window.days, -time.Hour)
	world.fillUntilSealed(t, a, "g", 0)
	world.merge(t, evsTestId("merger"))
	merged = world.mergedBucket(t)
	if merged.documents[testIndexId("s", 1)].version != 3 || merged.tombstones[testIndexId("s", 2)] == nil || merged.documents[testIndexId("s", 2)] != nil {
		t.Fatal("a merge of the target put an older entry back")
	}
}

// The skew world of FS-108: b's newer versions of s1 and s2 sit in the older bucket while a's older ones sit in the
// next, a's head there sealed once, and the clock where the older bucket has expired; the next bucket's start day.
func testRollupSkewWorld(t testing.TB) (*testHeadWorld, Id, uint32) {
	world, a := testRollupWorld(t)
	b := evsTestId("writer b")
	boundary := world.view(t, a).writeRoot().newestBucket().window.endDay()
	world.at = testDayTime(boundary, -time.Minute)
	planB, viewB := world.plan(t, b, true, testLive("s", 1, 3, 0, testHeadKeys(11, 1)), testRemoved("s", 2, 3))
	world.at = testDayTime(boundary, time.Minute)
	world.push(t, a, testLive("s", 1, 2, 0, testHeadKeys(11, 0)), testLive("s", 2, 2, 0, testHeadKeys(12, 0)))
	world.fillUntilSealed(t, a, "g", 0)
	if _, err := world.commit(t, b, planB, viewB); err != nil {
		t.Fatal(err)
	}
	world.at = testDayTime(boundary+30, time.Hour)
	return world, a, boundary
}

// Whether a push is a roll-up's: it removes files.
func testIsRollupPush(push *indexPush) bool {
	return 0 < len(push.removals) && slices.ContainsFunc(push.files, func(file *indexPushFile) bool {
		path, _ := indexParsePath(file.path, false)
		return path.kind == indexPathAllManifest
	})
}

// 1.6's promotion races: a merge of the target landing between the roll-up's build and its commit makes the roll-up
// rerun, lock held, and promote over the merged shards; a roll-up landing between a merge's build and its commit
// makes the merge rerun, and keep the promoted entries over the older sealed ones. Either way the target's shards hold
// the promoted versions, and its manifest fenced the loser.
func TestIndexRollupPromotionRacesAMerge(t *testing.T) {
	for _, mergeFirst := range []bool{true, false} {
		world, _, boundary := testRollupSkewWorld(t)
		merger := world.merger(t, evsTestId("merger"))
		roller := world.roller(t, evsTestId("runner"))
		raced := false
		var rollup *indexRollupOutcome
		var merge *indexMergeOutcome
		var err error
		if mergeFirst {
			world.ref.beforeCommit = func(push *indexPush) {
				if raced || !testIsRollupPush(push) {
					return
				}
				raced = true
				if merge, err = merger.Merge(context.Background(), indexRootNumber, boundary); err != nil || merge.committed == nil {
					t.Errorf("the racing merge: %v", err)
				}
			}
			rollup, err = roller.Roll(context.Background(), indexRootNumber)
			if err != nil || rollup.committed == nil || rollup.attempts != 2 {
				t.Fatalf("the beaten roll-up: %v after %d attempts", err, rollup.attempts)
			}
		} else {
			world.ref.beforeCommit = func(push *indexPush) {
				if raced || testIsRollupPush(push) || 0 < len(push.removals) || !slices.ContainsFunc(push.files, func(file *indexPushFile) bool {
					path, _ := indexParsePath(file.path, false)
					return path.kind == indexPathBucketManifest
				}) {
					return
				}
				raced = true
				if rollup, err = roller.Roll(context.Background(), indexRootNumber); err != nil || rollup.committed == nil {
					t.Errorf("the racing roll-up: %v", err)
				}
			}
			merge, err = merger.Merge(context.Background(), indexRootNumber, boundary)
			if err != nil || merge.committed == nil || merge.attempts != 2 {
				t.Fatalf("the beaten merge: %v after %d attempts", err, merge.attempts)
			}
		}
		world.ref.beforeCommit = nil
		if !raced {
			t.Fatal("no race")
		}
		merged := world.mergedBucket(t)
		if got := merged.documents[testIndexId("s", 1)]; got == nil || got.version != 3 {
			t.Fatalf("merge first %v: the target holds s1 at %v", mergeFirst, got)
		}
		if merged.tombstones[testIndexId("s", 2)] == nil || merged.documents[testIndexId("s", 2)] != nil {
			t.Fatalf("merge first %v: the promoted tombstone is not the target's entry", mergeFirst)
		}
	}
}

// A newer entry landing in the target between the roll-up's read and its commit: both commit, the promoted entry sits
// below it and is masked, and the target's next merge drops the promoted one for it (1.5's promotion target row).
func TestIndexRollupNewerEntryLandsInTarget(t *testing.T) {
	world, a, boundary := testRollupSkewWorld(t)
	landed := false
	world.ref.beforeCommit = func(push *indexPush) {
		if landed || !testIsRollupPush(push) {
			return
		}
		landed = true
		at := world.at
		// a's clock an hour behind, inside the target's window
		world.at = testDayTime(boundary+30, -time.Hour)
		world.push(t, a, testLive("s", 1, 4, 0, testHeadKeys(11, 2)))
		world.at = at
	}
	outcome := world.rollUp(t, evsTestId("runner"))
	world.ref.beforeCommit = nil
	if !landed || outcome.attempts != 1 {
		t.Fatalf("landed %v, attempts %d", landed, outcome.attempts)
	}
	world.at = testDayTime(boundary+30, -time.Hour)
	world.fillUntilSealed(t, a, "h", 0)
	world.merge(t, evsTestId("merger"))
	if got := world.mergedBucket(t).documents[testIndexId("s", 1)]; got == nil || got.version != 4 {
		t.Fatalf("the target's merge kept %v", got)
	}
}

// The lock: a second runner finds it held and leaves it; a holder that dies loses it once its until_ms is LockGrace
// past, a second runner takes it and rolls, and the first runner's late push fails on the lock and stops.
func TestIndexRollupLock(t *testing.T) {
	world, a := testRollupWorld(t)
	first := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	runnerOne, runnerTwo := evsTestId("runner one"), evsTestId("runner two")
	view := world.view(t, runnerOne)
	held, err := indexTakeLock(context.Background(), world.ref.store(runnerOne), view, view.writeRoot(), runnerOne, first.window.startDay, world.at, &testIndexWorldClock{world: world})
	if err != nil {
		t.Fatal(err)
	}
	outcome, err := world.roller(t, runnerTwo).Roll(context.Background(), indexRootNumber)
	if err != nil || outcome.skipped != indexRollupSkipLocked {
		t.Fatalf("a held lock: %+v %v", outcome, err)
	}
	// a minute short of LockTerm plus LockGrace, still held
	world.at = time.UnixMilli(held.untilMs).Add(world.settings.LockGrace - time.Minute)
	if outcome, _ := world.roller(t, runnerTwo).Roll(context.Background(), indexRootNumber); outcome.skipped != indexRollupSkipLocked {
		t.Fatal("a lock taken before its grace passed")
	}
	world.at = time.UnixMilli(held.untilMs).Add(world.settings.LockGrace)
	world.rollUp(t, runnerTwo)

	// runner one wakes and pushes as it had built: the lock's CAS refuses it
	stale := &IndexRoller{args: world.roller(t, runnerOne).args, settings: DefaultIndexRollerSettings(), clock: &testIndexWorldClock{world: world}}
	late := &indexRollupOutcome{startDay: first.window.startDay, lock: held}
	if _, err := stale.attempt(context.Background(), indexRootNumber, late); !errors.Is(err, errIndexLockLost) {
		t.Fatalf("a lapsed runner went on: %v", err)
	}
}

// A runner whose build is refused for a change under it reruns with the lock held: a 409 that is not the lock's, and
// 409 INDEX_EPOCH; at the storage limit the roll-up is refused, unsent again, and its bucket stays; an unknown outcome
// is settled by the same push id.
func TestIndexRollupReruns(t *testing.T) {
	world, a := testRollupWorld(t)
	first := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	runner := evsTestId("runner")

	world.ref.refuseNext(&indexRefusal{kind: indexRefusalQuota}, false)
	if _, err := world.roller(t, runner).Roll(context.Background(), indexRootNumber); !isIndexRefusal(err, indexRefusalQuota) {
		t.Fatalf("the lock at the storage limit: %v", err)
	}
	if world.view(t, a).writeRoot().bucket(first.window.startDay) == nil {
		t.Fatal("a refused roll-up removed its bucket")
	}

	pushes := 0
	world.ref.beforeCommit = func(push *indexPush) {
		pushes += 1
		switch pushes {
		case 2:
			world.ref.refuseNext(&indexRefusal{kind: indexRefusalConflict, paths: []string{"elsewhere"}}, false)
		case 3:
			world.ref.refuseNext(&indexRefusal{kind: indexRefusalIndexEpoch}, false)
		case 4:
			world.ref.refuseNext(&indexRefusal{kind: indexRefusalOutcomeUnknown}, true)
		}
	}
	outcome, err := world.roller(t, runner).Roll(context.Background(), indexRootNumber)
	world.ref.beforeCommit = nil
	if err != nil || outcome.committed == nil || outcome.attempts != 3 {
		t.Fatalf("reruns: %v after %d attempts", err, outcome.attempts)
	}
}

// A roll-up's output is a function of its inputs: built twice at one base, by two runners whose leases differ, the
// files but the lock and each runner's own head are equal, and the build the second time equals the committed one.
func TestIndexRollupIsAFunction(t *testing.T) {
	world, a := testRollupWorld(t)
	first := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	build := func(runner Id) []*indexPushFile {
		view := world.view(t, runner)
		root := view.writeRoot()
		expired := root.bucket(first.window.startDay)
		shards, err := indexDecodeBucketShards(context.Background(), view, expired.shards)
		if err != nil {
			t.Fatal(err)
		}
		result, err := indexRollup(context.Background(), &indexRollupArgs{
			view: view, root: root, expired: &indexRollupBucket{bucket: expired, shards: shards},
			runner: runner, signedTimeMs: world.at.UnixMilli(), padKey: testPadKey(t, 2), tables: testHeadTables,
		})
		if err != nil {
			t.Fatal(err)
		}
		return result.files
	}
	one, two := build(evsTestId("runner one")), build(evsTestId("runner two"))
	if len(one) != len(two) {
		t.Fatal("two builds of one roll-up differ")
	}
	for index := range one {
		if one[index].path != two[index].path || !bytes.Equal(one[index].plaintext, two[index].plaintext) {
			t.Fatal("two builds of one roll-up wrote different plaintext")
		}
	}
	outcome := world.rollUp(t, evsTestId("runner one"))
	committed := map[string][sha256.Size]byte{}
	for _, file := range outcome.result.files {
		committed[file.path] = sha256.Sum256(file.plaintext)
	}
	for _, file := range one {
		if committed[file.path] != sha256.Sum256(file.plaintext) {
			t.Fatal("the committed roll-up differs from the build at its base")
		}
	}
}

// S's coverage outlives S: a horizon row its slots held is carried into the runner's own head in the bucket of the
// push, beside that head's own rows; with a coverage reading it carries indexed_through instead; and nothing is
// carried for a ref a slot outside S already covers at or past it.
func TestIndexRollupCarriesCoverage(t *testing.T) {
	world := testNewHeadWorld()
	a, runner := evsTestId("writer a"), evsTestId("runner")
	refId := testIndexIdBytes("content ref", 1)
	other := testIndexIdBytes("content ref", 2)
	view := world.view(t, a)
	plan, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: a, signedTimeMs: world.at.UnixMilli(), tables: testHeadTables,
		pending:  []*indexPendingDocument{testLive("c", 1, 1, 0, testHeadKeys(1, 0))},
		coverage: []*protocol.IndexCoverage{{RefId: refId, Version: 5, Horizon: true}, {RefId: other, Version: 9, Horizon: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.commit(t, a, plan, view); err != nil {
		t.Fatal(err)
	}
	first := world.view(t, a).writeRoot().newestBucket()
	// a later slot outside S covers the other ref past S's row
	world.at = testDayTime(first.window.endDay(), time.Hour)
	view = world.view(t, a)
	plan, err = indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: a, signedTimeMs: world.at.UnixMilli(), tables: testHeadTables,
		pending:  []*indexPendingDocument{testLive("c", 2, 1, 0, testHeadKeys(2, 0))},
		coverage: []*protocol.IndexCoverage{{RefId: other, Version: 12, Horizon: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.commit(t, a, plan, view); err != nil {
		t.Fatal(err)
	}
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	outcome := world.rollUp(t, runner)
	if len(outcome.result.carriedCoverage) != 1 || !bytes.Equal(outcome.result.carriedCoverage[0].RefId, refId) || outcome.result.carriedCoverage[0].Version != 5 {
		t.Fatalf("carried %+v", outcome.result.carriedCoverage)
	}
	head := world.view(t, runner).writeRoot().newestBucket().writer(runner).head()
	if len(head.slot.header.Coverage) != 1 || head.slot.header.Coverage[0].Version != 5 || !head.slot.header.Coverage[0].Horizon {
		t.Fatalf("the runner's head holds %+v", head.slot.header.Coverage)
	}

	// with a coverage reading, I_R is what it answers
	world2 := testNewHeadWorld()
	view = world2.view(t, a)
	plan, err = indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: a, signedTimeMs: world2.at.UnixMilli(), tables: testHeadTables,
		pending:  []*indexPendingDocument{testLive("c", 1, 1, 0, testHeadKeys(1, 0))},
		coverage: []*protocol.IndexCoverage{{RefId: refId, Version: 3}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world2.commit(t, a, plan, view); err != nil {
		t.Fatal(err)
	}
	expiredDay := world2.view(t, a).writeRoot().newestBucket().window
	world2.at = testDayTime(expiredDay.endDay()+expiredDay.days, time.Hour)
	reading := func(view *indexView, ref []byte) (uint64, bool) {
		return 7, bytes.Equal(ref, refId)
	}
	rolled, err := world2.rollerWith(t, runner, reading).Roll(context.Background(), indexRootNumber)
	if err != nil || rolled.committed == nil {
		t.Fatal(err)
	}
	if len(rolled.result.carriedCoverage) != 1 || rolled.result.carriedCoverage[0].Version != 7 {
		t.Fatalf("carried %+v with a reading of 7", rolled.result.carriedCoverage)
	}
}

// A runner renews its lock at LockRenewAfter while it works, by the same CAS, and then rolls.
func TestIndexRollupRenewsItsLock(t *testing.T) {
	world, a := testRollupWorld(t)
	first := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	runner := evsTestId("runner")
	roller := world.roller(t, runner)
	takes := 0
	world.ref.beforeCommit = func(push *indexPush) {
		takes += 1
		if takes == 1 {
			// past LockRenewAfter before the build
			world.at = world.at.Add(roller.settings.LockRenewAfter)
		}
	}
	outcome, err := roller.Roll(context.Background(), indexRootNumber)
	world.ref.beforeCommit = nil
	if err != nil || outcome.committed == nil || takes != 3 {
		t.Fatalf("a renewed roll-up: %v, %d pushes", err, takes)
	}
	if outcome.lock.signedTimeMs != world.at.UnixMilli() {
		t.Fatal("the lock was not renewed at the later time")
	}
}

// The schedule's runner rules: an indexer rolls an expired bucket at once; with an indexer serving the repo another
// desktop rolls only once it has committed a day past the expiry; with none, the first desktop that commits after the
// expiry rolls it, and a phone only while it may run. Merges: a desktop leaves a due bucket to the indexer unless it is
// out of slots there.
func TestIndexScheduleRunnerRules(t *testing.T) {
	type row struct {
		name          string
		device        indexSearchDevice
		indexerServes bool
		mayRun        bool
		committedAt   time.Duration
		rolls         bool
	}
	rows := []row{
		{name: "an indexer at once", device: indexSearchDeviceIndexer, rolls: true},
		{name: "a desktop beside an indexer, a commit just past expiry", device: indexSearchDeviceDesktop, indexerServes: true, committedAt: time.Hour},
		{name: "a desktop beside an indexer, a commit a day past expiry", device: indexSearchDeviceDesktop, indexerServes: true, committedAt: 25 * time.Hour, rolls: true},
		{name: "a desktop with no indexer, no commit since", device: indexSearchDeviceDesktop, committedAt: -time.Hour},
		{name: "a desktop with no indexer, a commit after expiry", device: indexSearchDeviceDesktop, committedAt: time.Hour, rolls: true},
		{name: "a phone off Wi-Fi", device: indexSearchDevicePhone, committedAt: time.Hour},
		{name: "a phone that may run", device: indexSearchDevicePhone, mayRun: true, committedAt: time.Hour, rolls: true},
	}
	for _, c := range rows {
		world, a := testRollupWorld(t)
		first := world.view(t, a).writeRoot().newestBucket()
		view := world.view(t, a)
		expiry := time.UnixMilli(indexBucketExpiryMs(view, view.writeRoot(), first))
		if indexBucketExpiredAt(view, view.writeRoot(), first, expiry.Add(-time.Millisecond).UnixMilli()) || !indexBucketExpiredAt(view, view.writeRoot(), first, expiry.UnixMilli()) {
			t.Fatalf("%s: the expiry instant is not the ages' boundary", c.name)
		}
		world.at = expiry.Add(26 * time.Hour)
		schedule := indexNewSchedule(nil, &testIndexWorldClock{world: world})
		ref := schedule.add(&indexScheduleRefArgs{
			merger:        world.merger(t, evsTestId("device")),
			roller:        world.roller(t, evsTestId("device")),
			device:        c.device,
			self:          evsTestId("device"),
			indexerServes: func() bool { return c.indexerServes },
			mayRun:        func() bool { return c.mayRun },
		})
		ref.Committed(expiry.Add(c.committedAt).UnixMilli())
		ticks := schedule.tick(context.Background())
		if len(ticks) != 1 || len(ticks[0].errs) != 0 {
			t.Fatalf("%s: %+v", c.name, ticks)
		}
		rolled := ticks[0].rollup != nil && ticks[0].rollup.committed != nil
		if rolled != c.rolls {
			t.Errorf("%s: rolled %v", c.name, rolled)
		}
	}

	// merges: a due bucket the indexer serves is left by a desktop that is not out of slots
	world := testNewHeadWorld()
	a := evsTestId("writer a")
	world.push(t, a, testLive("m", 1, 1, 0, testHeadKeys(1, 0)))
	world.fillUntilSealed(t, a, "f", 0)
	world.settings.MergeDueByteCount = 1
	for _, c := range []struct {
		device        indexSearchDevice
		indexerServes bool
		merges        int
	}{
		{device: indexSearchDeviceDesktop, indexerServes: true, merges: 0},
		{device: indexSearchDevicePhone, merges: 0},
		{device: indexSearchDeviceDesktop, merges: 1},
	} {
		schedule := indexNewSchedule(nil, &testIndexWorldClock{world: world})
		schedule.add(&indexScheduleRefArgs{merger: world.merger(t, evsTestId("device")), device: c.device, self: evsTestId("device"), indexerServes: func() bool { return c.indexerServes }})
		ticks := schedule.tick(context.Background())
		if len(ticks[0].merges) != c.merges {
			t.Errorf("device %d beside an indexer %v merged %d", c.device, c.indexerServes, len(ticks[0].merges))
		}
	}
}

// D-TEST-15, DESIGN-DETAILS 1.6's rollup/ list, pinned by each output file's plaintext hash: a bucket into an empty
// all; over an older all row with a tombstone taking another; a promotion of a tombstone and of a live version, with
// the target bucket's shard and manifest; a ref tombstone; and a second run's plaintext equal to the first, since a
// rerun builds the vector's files again. SIDECAR_WRITE_VECTORS rewrites them.
func TestIndexRollupVectors(t *testing.T) {
	built := []testMergeVector{}
	record := func(name string, outcome *indexRollupOutcome) {
		built = append(built, testMergeVectorOf(name, outcome.result.files, outcome.result.removals))
	}
	runner := evsTestId("runner")

	world, a := testRollupWorld(t)
	first := world.view(t, a).writeRoot().newestBucket()
	world.at = testDayTime(first.window.endDay(), time.Hour)
	world.push(t, a, testLive("u", 1, 2, 0, testHeadKeys(1, 1)), testRemoved("u", 2, 2))
	world.at = testDayTime(first.window.endDay()+first.window.days, time.Hour)
	record("into-an-empty-all", world.rollUp(t, runner))
	world.at = testDayTime(first.window.endDay()+2*first.window.days, time.Hour)
	record("over-all-rows-and-a-tombstone", world.rollUp(t, runner))

	skew, a := testRollupWorld(t)
	b := evsTestId("writer b")
	boundary := skew.view(t, a).writeRoot().newestBucket().window.endDay()
	skew.at = testDayTime(boundary, -time.Minute)
	planB, viewB := skew.plan(t, b, true, testLive("s", 1, 3, 0, testHeadKeys(11, 1)), testRemoved("s", 2, 3))
	skew.at = testDayTime(boundary, time.Minute)
	skew.push(t, a, testLive("s", 1, 2, 0, testHeadKeys(11, 0)), testLive("s", 2, 2, 0, testHeadKeys(12, 0)))
	if _, err := skew.commit(t, b, planB, viewB); err != nil {
		t.Fatal(err)
	}
	skew.at = testDayTime(boundary+30, time.Hour)
	record("promotions", skew.rollUp(t, runner))

	refResult := testCompanionRollup(t)
	built = append(built, testMergeVectorOf("ref-tombstone", refResult.files, refResult.removals))
	again := testCompanionRollup(t)
	if len(again.files) != len(refResult.files) {
		t.Fatal("a rerun of the ref tombstone's roll-up differs")
	}
	for index := range again.files {
		if !bytes.Equal(again.files[index].plaintext, refResult.files[index].plaintext) {
			t.Fatal("a rerun of the ref tombstone's roll-up wrote other plaintext")
		}
	}
	testCheckMergeVectors(t, testRollupVectorPath, built)
}

// A ur/index roll-up built by hand: S holds a writer's head with a ref tombstone of one ref at 5 and a row of another,
// and all holds that ref's rows at 2 and 9 and the other ref's at 2. all keeps the row at 9 and the other ref's, and the
// ref tombstone, which no newer bucket needs, goes.
func testCompanionRollup(t testing.TB) *indexRollupResult {
	t.Helper()
	ref := testNewIndexRef()
	writer := evsTestId("writer a")
	store := ref.store(writer)
	settings := DefaultIndexFormatSettings()
	paths := indexNewPaths(true, indexRootNumber)
	window := indexBucketWindow{startDay: 20340, days: 30}
	at := testDayTime(20341, 0)
	head := indexNewFileHeader(indexFileSlot, testHeadTables)
	head.BucketStartDay, head.BucketDays, head.WriterSidecarId, head.Seq = window.startDay, window.days, writer.Bytes(), 1
	liveKeys := testHeadKeys(3, 0)
	entries := []*indexEntry{
		{kind: indexEntryRefTombstone, key: testIndexId("ref", 1), version: 5, timeSeconds: 1757400100},
		{kind: indexEntryFull, key: testIndexId("cr", 3), version: 4, timeSeconds: 1757400100, row: testCompanionRow(liveKeys, 2), keys: liveKeys},
	}
	slices.SortFunc(entries, indexCompareEntries)
	slot, err := indexEncodeSlot(&indexSlot{header: head, entries: entries}, true, settings)
	if err != nil {
		t.Fatal(err)
	}
	slotPath, _ := paths.slot(window.startDay, [indexIdByteCount]byte(writer), 0)
	row := func(index int, version uint64, refIndex int) *indexShardDocument {
		keys := testHeadKeys(index, 1)
		return &indexShardDocument{key: testIndexId("cr", index), version: version, timeSeconds: 1754000000, row: testCompanionRow(keys, refIndex), keys: keys}
	}
	all := testBuildShard(t, &indexShard{header: testShardHeader(indexFileAllShard), documents: []*indexShardDocument{row(1, 2, 1), row(2, 9, 1), row(4, 2, 2)}}, true, testPadKey(t, 2))
	allManifest, err := indexEncodeManifest(&protocol.IndexManifest{Shards: []*protocol.IndexShard{{N: 0, Docs: 3}}, RolledThroughDay: 20310}, true)
	if err != nil {
		t.Fatal(err)
	}
	store.testCommit(t, at,
		&indexPushFile{path: slotPath, plaintext: slot},
		&indexPushFile{path: paths.allShard(0), plaintext: all},
		&indexPushFile{path: paths.allManifest(), plaintext: allManifest},
	)
	view, err := indexLoadView(context.Background(), &indexViewArgs{store: store, repoId: evsTestId("view repo"), refId: evsTestId("view ref"), repoKind: protocol.RepoKind_REPO_KIND_GENERAL, companion: true, settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	root := view.writeRoot()
	expired := root.bucket(window.startDay)
	allShards, err := indexDecodeBucketShards(context.Background(), view, root.allShards)
	if err != nil {
		t.Fatal(err)
	}
	result, err := indexRollup(context.Background(), &indexRollupArgs{
		view: view, root: root, expired: &indexRollupBucket{bucket: expired, shards: []*indexShard{}},
		expiredFiles: expired.files(), allShards: allShards,
		runner: evsTestId("runner"), signedTimeMs: testDayMs(20401, 0), padKey: testPadKey(t, 2), tables: testHeadTables,
	})
	if err != nil {
		t.Fatal(err)
	}
	var shardFile *indexPushFile
	for _, file := range result.files {
		if file.path == paths.allShard(0) {
			shardFile = file
		}
	}
	if shardFile == nil {
		t.Fatal("all's shard was not rewritten")
	}
	shard, err := testDecodeShard(shardFile.plaintext, true)
	if err != nil {
		t.Fatal(err)
	}
	kept := map[[indexIdByteCount]byte]uint64{}
	for _, document := range shard.documents {
		kept[document.key] = document.version
	}
	if _, ok := kept[testIndexId("cr", 1)]; ok || kept[testIndexId("cr", 2)] != 9 || kept[testIndexId("cr", 4)] != 2 || kept[testIndexId("cr", 3)] != 4 {
		t.Fatalf("all after the ref tombstone: %v", kept)
	}
	if len(result.promoted) != 0 {
		t.Fatal("a ref tombstone no newer bucket needs was promoted")
	}
	return result
}
