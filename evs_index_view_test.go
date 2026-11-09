// The store seam, the index view and buckets (SEARCH-M10-08): bucket vectors at boundaries and across a window change,
// a skewed reader's buckets, FS-74's commit just past a boundary, settings signers, and the fake's path CAS, index
// epoch, versionless replacement and unknown outcomes, which the index's other tasks rest on.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A bucket boundary the tests sit on: day 20,370, a multiple of 30 and of nothing smaller that matters here.
const testBoundaryDay = 20370

// The time ms at day plus offset.
func testDayMs(day uint32, offset time.Duration) int64 {
	return int64(day)*indexDayMs + offset.Milliseconds()
}

// The time at day plus offset.
func testDayTime(day uint32, offset time.Duration) time.Time {
	return time.UnixMilli(testDayMs(day, offset))
}

// One bucket vector.
type testBucketCase struct {
	name       string
	buckets    []indexBucketWindow
	windowDays uint32
	signedMs   int64
	want       indexBucketWindow
	created    bool
}

func TestIndexBucketForBoundaries(t *testing.T) {
	first := indexBucketWindow{startDay: 20340, days: 30}
	later := indexBucketWindow{startDay: 20430, days: 30}
	cases := []testBucketCase{
		{name: "first bucket at its own start", windowDays: 30, signedMs: testDayMs(20340, 0), want: first, created: true},
		{name: "first bucket from its last second", windowDays: 30, signedMs: testDayMs(testBoundaryDay, -time.Second), want: first, created: true},
		{name: "first bucket from the boundary", windowDays: 30, signedMs: testDayMs(testBoundaryDay, 0), want: indexBucketWindow{startDay: testBoundaryDay, days: 30}, created: true},
		{name: "a second before the boundary", buckets: []indexBucketWindow{first}, windowDays: 30, signedMs: testDayMs(testBoundaryDay, -time.Second), want: first},
		{name: "at the boundary", buckets: []indexBucketWindow{first}, windowDays: 30, signedMs: testDayMs(testBoundaryDay, 0), want: indexBucketWindow{startDay: testBoundaryDay, days: 30}, created: true},
		{name: "a second past the boundary", buckets: []indexBucketWindow{first}, windowDays: 30, signedMs: testDayMs(testBoundaryDay, time.Second), want: indexBucketWindow{startDay: testBoundaryDay, days: 30}, created: true},
		{name: "whole empty windows skipped", buckets: []indexBucketWindow{first}, windowDays: 30, signedMs: testDayMs(20431, time.Hour), want: later, created: true},
		{name: "a new window after a change", buckets: []indexBucketWindow{first}, windowDays: 7, signedMs: testDayMs(testBoundaryDay, time.Second), want: indexBucketWindow{startDay: testBoundaryDay, days: 7}, created: true},
		{name: "the old window kept after a change", buckets: []indexBucketWindow{first}, windowDays: 7, signedMs: testDayMs(testBoundaryDay, -time.Second), want: first},
		{name: "a skip in the new window", buckets: []indexBucketWindow{first}, windowDays: 7, signedMs: testDayMs(20390, 0), want: indexBucketWindow{startDay: 20384, days: 7}, created: true},
		{name: "a skewed day in a skipped window", buckets: []indexBucketWindow{first, later}, windowDays: 30, signedMs: testDayMs(20430, -time.Second), want: first},
		{name: "a skewed day before the first", buckets: []indexBucketWindow{first}, windowDays: 30, signedMs: testDayMs(20340, -time.Second), want: first},
		{name: "a day in the newest", buckets: []indexBucketWindow{first, later}, windowDays: 30, signedMs: testDayMs(20459, 23*time.Hour), want: later},
	}
	for _, c := range cases {
		got, created := indexBucketFor(c.buckets, c.windowDays, c.signedMs)
		if got != c.want || created != c.created {
			t.Errorf("%s: got %+v created %v, want %+v created %v", c.name, got, created, c.want, c.created)
		}
	}
}

func TestIndexBucketForEntryKeepsANewerBucket(t *testing.T) {
	older := indexBucketWindow{startDay: 20340, days: 30}
	newer := indexBucketWindow{startDay: testBoundaryDay, days: 30}
	if got := indexBucketForEntry(older, &newer); got != newer {
		t.Errorf("a document held in a newer bucket went to %+v", got)
	}
	if got := indexBucketForEntry(newer, &older); got != newer {
		t.Errorf("a document held in an older bucket went to %+v", got)
	}
	if got := indexBucketForEntry(newer, nil); got != newer {
		t.Errorf("a new document went to %+v", got)
	}
}

func TestIndexBucketAges(t *testing.T) {
	buckets := []indexBucketWindow{{startDay: 20340, days: 30}, {startDay: testBoundaryDay, days: 30}}
	current, previous, expired := indexBucketCurrent, indexBucketPrevious, indexBucketExpired
	cases := []struct {
		name  string
		nowMs int64
		want  []indexBucketAge
	}{
		{name: "inside the newest", nowMs: testDayMs(20375, 0), want: []indexBucketAge{previous, current}},
		{name: "a second before the newest ends", nowMs: testDayMs(20400, -time.Second), want: []indexBucketAge{previous, current}},
		{name: "a second after the newest ends", nowMs: testDayMs(20400, time.Second), want: []indexBucketAge{expired, previous}},
		{name: "a window past the newest", nowMs: testDayMs(20431, 0), want: []indexBucketAge{expired, expired}},
		{name: "a clock behind the newest's start", nowMs: testDayMs(testBoundaryDay, -10*time.Minute), want: []indexBucketAge{current, current}},
	}
	for _, c := range cases {
		if got := indexBucketAges(buckets, 30, c.nowMs); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	// A shorter window from a settings change ages by the window it would open.
	if got := indexBucketAges(buckets, 7, testDayMs(20401, 0)); !slices.Equal(got, []indexBucketAge{expired, previous}) {
		t.Errorf("after a change to 7 days: got %v", got)
	}
	if got := indexBucketAges(buckets, 7, testDayMs(20408, 0)); !slices.Equal(got, []indexBucketAge{expired, expired}) {
		t.Errorf("a 7-day window past the newest: got %v", got)
	}
}

// FS-76's clause: buckets follow the commits' signed time, so readers whose clocks are 10 minutes apart place every
// entry alike, and both search every bucket present, an expired one until its roll-up, so their results agree even
// where they age a bucket differently at a boundary.
func TestIndexBucketsIgnoreAReadersSkew(t *testing.T) {
	// Writers within 10 minutes of evs, either side of the boundary, in commit order.
	signed := []time.Duration{-2 * time.Hour, -9 * time.Minute, 4 * time.Minute, -6 * time.Minute, 11 * time.Minute, 3 * time.Hour}
	place := func() []indexBucketWindow {
		buckets := []indexBucketWindow{{startDay: 20340, days: 30}}
		placed := []indexBucketWindow{}
		for _, offset := range signed {
			window, created := indexBucketFor(buckets, 30, testDayMs(testBoundaryDay, offset))
			if created {
				buckets = append(buckets, window)
			}
			placed = append(placed, window)
		}
		return placed
	}
	first, second := place(), place()
	if !slices.Equal(first, second) {
		t.Fatalf("placement changed between runs: %v, %v", first, second)
	}
	want := []indexBucketWindow{{20340, 30}, {20340, 30}, {testBoundaryDay, 30}, {20340, 30}, {testBoundaryDay, 30}, {testBoundaryDay, 30}}
	if !slices.Equal(first, want) {
		t.Errorf("placement %v, want %v", first, want)
	}

	buckets := []indexBucketWindow{{startDay: 20310, days: 30}, {startDay: 20340, days: 30}}
	for _, skew := range []time.Duration{-10 * time.Minute, -time.Second, time.Second, 10 * time.Minute} {
		ages := indexBucketAges(buckets, 30, testDayMs(testBoundaryDay, skew))
		exact := indexBucketAges(buckets, 30, testDayMs(testBoundaryDay, 0))
		for index := range ages {
			if diff := int(ages[index]) - int(exact[index]); diff < -1 || 1 < diff {
				t.Errorf("skew %s: bucket %d aged %v against %v", skew, index, ages[index], exact[index])
			}
		}
	}
}

func TestIndexDirectoryWindows(t *testing.T) {
	directory := protocol.RepoKind_REPO_KIND_DIRECTORY
	general := protocol.RepoKind_REPO_KIND_GENERAL
	if days := indexEffectiveWindowDays(nil, directory); days != 7 {
		t.Errorf("directory with no settings: %d days", days)
	}
	if days := indexEffectiveWindowDays(&protocol.IndexSettings{}, directory); days != 7 {
		t.Errorf("directory with window 0: %d days", days)
	}
	if days := indexEffectiveWindowDays(nil, general); days != 30 {
		t.Errorf("general with no settings: %d days", days)
	}
	if days := indexEffectiveWindowDays(&protocol.IndexSettings{WindowDays: 90}, directory); days != 90 {
		t.Errorf("directory at 90: %d days", days)
	}
	for _, refused := range []*protocol.IndexSettings{{WindowDays: 91}, {Off: true}, {WindowDays: 6}} {
		if err := indexCheckSettingsForKind(refused, directory); err == nil {
			t.Errorf("the directory took %v", refused)
		}
	}
	if err := indexCheckSettingsForKind(&protocol.IndexSettings{Off: true, WindowDays: 365}, general); err != nil {
		t.Errorf("a general repo refused off at 365 days: %v", err)
	}
}

// A slot file for a writer in a bucket, entries as given.
func testViewSlotFile(t testing.TB, window indexBucketWindow, writer Id, seq uint32, fileType uint32, entries ...*indexEntry) []byte {
	t.Helper()
	header := indexNewFileHeader(fileType, indexTables{normVersion: "17.0.0", textModuleVersion: "v0.43.0"})
	header.BucketStartDay = window.startDay
	header.BucketDays = window.days
	header.WriterSidecarId = writer.Bytes()
	header.Seq = seq
	file, err := indexEncodeSlot(&indexSlot{header: header, entries: entries}, false)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// A full entry of a file document with keys, at version, signed at timeMs.
func testViewEntry(label string, index int, version uint64, timeMs int64, keys indexKeySet) *indexEntry {
	return &indexEntry{
		kind:        indexEntryFull,
		key:         testIndexId(label, index),
		version:     version,
		timeSeconds: indexEntrySeconds(timeMs),
		row:         testFileRow(keys),
		keys:        keys,
	}
}

// A small file's bytes.
func testSmallFile(t testing.TB, message proto.Message) []byte {
	t.Helper()
	file, err := indexMarshalSmall(message)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// A view of ref's file-mode index at its head, admins counted by admins.
func testLoadView(t testing.TB, store indexRefStore, admins ...Id) *indexView {
	t.Helper()
	view, err := indexLoadView(context.Background(), &indexViewArgs{
		store:    store,
		repoId:   evsTestId("view repo"),
		refId:    evsTestId("view ref"),
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL,
		isAdmin: func(file *indexFileVersion) bool {
			return slices.Contains(admins, file.signerSidecarId)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// FS-74's clause: a commit just past a bucket boundary by its signed time writes its first slot in the new current
// bucket, and every reader then sees two buckets, the new one current.
func TestIndexCommitPastABoundaryOpensTheNextBucket(t *testing.T) {
	ref := testNewIndexRef()
	writer := evsTestId("writer a")
	store := ref.store(writer)
	paths := indexNewPaths(false, indexRootNumber)
	keys := testIndexKeys(0x616263, 4, 1)

	before := testDayTime(testBoundaryDay, -time.Second)
	window, created := indexBucketFor(nil, 30, before.UnixMilli())
	if !created {
		t.Fatal("the first push created no bucket")
	}
	slotPath, _ := paths.slot(window.startDay, [indexIdByteCount]byte(writer), 0)
	store.testCommit(t, before, &indexPushFile{path: slotPath, plaintext: testViewSlotFile(t, window, writer, 1, indexFileSlot, testViewEntry("doc", 1, 1, before.UnixMilli(), keys))})

	view := testLoadView(t, store)
	root := view.root(indexRootNumber)
	after := testDayTime(testBoundaryDay, time.Second)
	next, created := indexBucketFor(root.bucketWindows(), root.windowDays(view.repoKind), after.UnixMilli())
	if !created || next.startDay != testBoundaryDay {
		t.Fatalf("a push a second past the boundary went to %+v, created %v", next, created)
	}
	nextPath, _ := paths.slot(next.startDay, [indexIdByteCount]byte(writer), 0)
	store.testCommit(t, after, &indexPushFile{path: nextPath, plaintext: testViewSlotFile(t, next, writer, 1, indexFileSlot, testViewEntry("doc", 2, 1, after.UnixMilli(), keys))})

	view = testLoadView(t, store)
	root = view.root(indexRootNumber)
	if got := root.bucketWindows(); !slices.Equal(got, []indexBucketWindow{window, next}) {
		t.Fatalf("buckets %v", got)
	}
	ages := indexBucketAges(root.bucketWindows(), 30, after.UnixMilli())
	if !slices.Equal(ages, []indexBucketAge{indexBucketPrevious, indexBucketCurrent}) {
		t.Errorf("ages %v", ages)
	}
	head := root.newestBucket().writer(writer).head()
	if head == nil || head.path.slotIndex != 0 || head.seq() != 1 || len(head.slot.entries) != 1 {
		t.Errorf("the new bucket's first slot is %+v", head)
	}
	if len(view.alarms) != 0 {
		t.Errorf("alarms %v", view.alarms)
	}
}

// A settings version a repo admin did not sign is ignored and alarmed, naming its signer; the newest an admin signed
// counts, and with none the defaults hold.
func TestIndexSettingsFromANonAdminIgnoredAndAlarmed(t *testing.T) {
	ref := testNewIndexRef()
	admin, member := evsTestId("admin"), evsTestId("member")
	path := indexNewPaths(false, indexRootNumber).settings()

	empty := testLoadView(t, ref.store(admin), admin)
	if root := empty.writeRoot(); root.settings != nil || root.off() || root.windowDays(empty.repoKind) != 30 {
		t.Fatalf("no settings read as %v", root.settings)
	}

	ref.store(admin).testCommit(t, testDayTime(20340, 0), &indexPushFile{path: path, plaintext: testSmallFile(t, &protocol.IndexSettings{WindowDays: 14})})
	adminVersion := ref.store(admin).testVersionOf(path)
	ref.store(member).testCommit(t, testDayTime(20341, 0), &indexPushFile{path: path, replaces: adminVersion, plaintext: testSmallFile(t, &protocol.IndexSettings{Off: true})})

	view := testLoadView(t, ref.store(admin), admin)
	root := view.root(indexRootNumber)
	if root.settings == nil || root.settings.WindowDays != 14 || root.off() {
		t.Fatalf("settings %v, want the admin's 14 days", root.settings)
	}
	if root.settingsFile.signerSidecarId != admin || root.windowDays(view.repoKind) != 14 {
		t.Errorf("counted %+v", root.settingsFile)
	}
	if len(view.alarms) != 1 || view.alarms[0].reason != indexViewAlarmSettings || view.alarms[0].signerSidecarId != member || view.alarms[0].path != path {
		t.Fatalf("alarms %+v", view.alarms)
	}
	events := view.events()
	if len(events) != 1 || events[0].Kind != SidecarEventIndexMalformed || *events[0].SidecarId != member || events[0].Path != path || *events[0].RepoId != view.repoId {
		t.Errorf("events %+v", events)
	}

	// With no admin counted at all, the index is on at the default window.
	none := testLoadView(t, ref.store(admin))
	if root := none.root(indexRootNumber); root.settings != nil || root.windowDays(none.repoKind) != 30 || len(none.alarms) != 2 {
		t.Errorf("no admin: settings %v, %d alarms", root.settings, len(none.alarms))
	}
}

// The view reads a root's lock, erasure set, buckets with and without a manifest, writers' heads and large entries,
// and drops and alarms what breaks the format.
func TestIndexViewReadsAnIndex(t *testing.T) {
	ref := testNewIndexRef()
	a, b := evsTestId("writer a"), evsTestId("writer b")
	paths := indexNewPaths(false, indexRootNumber)
	window := indexBucketWindow{startDay: 20340, days: 30}
	at := testDayTime(20341, 0)
	keys := testIndexKeys(0x616263, 4, 1)
	slot := func(writer Id, k uint32) string {
		path, _ := paths.slot(window.startDay, [indexIdByteCount]byte(writer), k)
		return path
	}
	large, _ := paths.largeEntry(window.startDay, [indexIdByteCount]byte(a), 3)
	bigKeys := testIndexKeys(0, 9000, 3)

	ref.store(a).testCommit(t, at,
		&indexPushFile{path: slot(a, 0), plaintext: testViewSlotFile(t, window, a, 1, indexFileSlot, testViewEntry("doc", 1, 2, at.UnixMilli(), keys))},
		&indexPushFile{path: slot(a, 1), plaintext: testViewSlotFile(t, window, a, 2, indexFileSlot, testViewEntry("doc", 2, 2, at.UnixMilli(), keys))},
		&indexPushFile{path: large, plaintext: testViewSlotFile(t, window, a, 3, indexFileLargeEntry, testViewEntry("doc", 3, 5, at.UnixMilli(), bigKeys))},
		&indexPushFile{path: paths.lock(), plaintext: testSmallFile(t, &protocol.IndexLock{HolderSidecarId: a.Bytes(), BucketStartDay: 20310, UntilMs: at.UnixMilli()})},
		&indexPushFile{path: indexErasureSetPath(false), plaintext: testSmallFile(t, &protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{{
			ErasureId: testIndexIdBytes("erasure", 1), EraserSidecarId: a.Bytes(), Epoch: 1,
			Docs: []*protocol.IndexErased{{DocKey: testIndexIdBytes("doc", 9), Version: 4}},
		}}})},
	)
	// Writer b's slot names another window for the bucket, and a path under the root is none of §11.14's own.
	ref.store(b).testCommit(t, at,
		&indexPushFile{path: slot(b, 0), plaintext: testViewSlotFile(t, indexBucketWindow{startDay: 20340, days: 7}, b, 1, indexFileSlot, testViewEntry("doc", 4, 1, at.UnixMilli(), keys))},
		&indexPushFile{path: paths.root + "/b/20340/w/zz", plaintext: []byte("x")},
	)

	view := testLoadView(t, ref.store(a))
	root := view.root(indexRootNumber)
	if root == nil || len(root.buckets) != 1 || root.buckets[0].window != window {
		t.Fatalf("buckets %+v", root)
	}
	bucket := root.buckets[0]
	writerA := bucket.writer(a)
	if writerA == nil || len(writerA.slots) != 2 || len(writerA.large) != 1 || writerA.head().path.slotIndex != 1 || writerA.highestSeq() != 3 {
		t.Fatalf("writer a %+v", writerA)
	}
	if bucket.writer(b) != nil {
		t.Errorf("writer b's slot of another window was kept")
	}
	if root.lock == nil || !bytes.Equal(root.lock.HolderSidecarId, a.Bytes()) {
		t.Errorf("lock %v", root.lock)
	}
	if !view.erased(testIndexId("doc", 9), 4) || !view.erased(testIndexId("doc", 9), 1) || view.erased(testIndexId("doc", 9), 5) || view.erased(testIndexId("doc", 1), 1) {
		t.Errorf("the erasure set reads wrong")
	}
	reasons := map[indexViewAlarmReason]int{}
	for _, alarm := range view.alarms {
		reasons[alarm.reason] += 1
		if alarm.signerSidecarId != b {
			t.Errorf("an alarm names %s, not b", alarm.signerSidecarId)
		}
	}
	if reasons[indexViewAlarmMalformed] != 1 || reasons[indexViewAlarmUnknownPath] != 1 {
		t.Errorf("alarms %v", reasons)
	}
}

// A bucket's manifest gives its window and shards, the shards decode on first use, and a shard the manifest names that
// is not listed is alarmed against the manifest.
func TestIndexViewReadsManifestsAndShards(t *testing.T) {
	ref := testNewIndexRef()
	merger := evsTestId("merger")
	paths := indexNewPaths(false, indexRootNumber)
	window := indexBucketWindow{startDay: 20340, days: 30}
	at := testDayTime(20341, 0)

	shard := &indexShard{header: testShardHeader(indexFileBucketShard), documents: testShardDocuments(7, "doc", 20, indexDocFile)}
	shardFile := testBuildShard(t, shard, false, testPadKey(t, 2))
	manifest := &protocol.IndexManifest{StartDay: window.startDay, Days: window.days, Shards: []*protocol.IndexShard{{N: 0, Docs: 20, FirstDay: 20340, LastDay: 20341}}}
	all := &protocol.IndexManifest{RolledThroughDay: 20310, Shards: []*protocol.IndexShard{{N: 0, Docs: 1, FirstDay: 20310, LastDay: 20339}}}
	ref.store(merger).testCommit(t, at,
		&indexPushFile{path: paths.bucketManifest(window.startDay), plaintext: testSmallFile(t, manifest)},
		&indexPushFile{path: paths.bucketShard(window.startDay, 0), plaintext: shardFile},
		&indexPushFile{path: paths.allManifest(), plaintext: testSmallFile(t, all)},
	)

	view := testLoadView(t, ref.store(merger))
	root := view.root(indexRootNumber)
	if len(root.buckets) != 1 || root.buckets[0].window != window || len(root.buckets[0].shards) != 1 {
		t.Fatalf("buckets %+v", root.buckets)
	}
	decoded, err := view.shard(context.Background(), root.buckets[0].shards[0])
	if err != nil || decoded == nil || len(decoded.documents) != 20 {
		t.Fatalf("shard %v, %v", decoded, err)
	}
	if root.allManifest == nil || root.allManifest.RolledThroughDay != 20310 || len(root.allShards) != 0 {
		t.Errorf("all %+v", root.allManifest)
	}
	if len(view.alarms) != 1 || view.alarms[0].path != paths.allManifest() {
		t.Errorf("alarms %+v", view.alarms)
	}
}

// A file whose header names a newer format is no malformation: the view says so and alarms nothing.
func TestIndexViewSaysANewerFormat(t *testing.T) {
	ref := testNewIndexRef()
	writer := evsTestId("writer")
	window := indexBucketWindow{startDay: 20340, days: 30}
	header := indexNewFileHeader(indexFileSlot, indexTables{normVersion: "17.0.0", textModuleVersion: "v0.43.0"})
	header.Format = 2
	header.BucketStartDay, header.BucketDays, header.WriterSidecarId, header.Seq = window.startDay, window.days, writer.Bytes(), 1
	encoded, err := indexMarshalHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	file := indexAppendVByte([]byte(indexFileMagic), uint64(len(encoded)))
	file = append(file, encoded...)
	path, _ := indexNewPaths(false, indexRootNumber).slot(window.startDay, [indexIdByteCount]byte(writer), 0)
	ref.store(writer).testCommit(t, testDayTime(20341, 0), &indexPushFile{path: path, plaintext: file})

	view := testLoadView(t, ref.store(writer))
	if !view.newerFormat || len(view.alarms) != 0 {
		t.Errorf("newer format %v, alarms %v", view.newerFormat, view.alarms)
	}
}

// The fake's path CAS: a write names the version it replaces, a creation names none, and every path another push
// changed is named in the 409; a write's version is its base's plus one, a creation's past the push's base.
func TestIndexStoreFakeCasNamesEveryConflict(t *testing.T) {
	ref := testNewIndexRef()
	a, b := ref.store(evsTestId("a")), ref.store(evsTestId("b"))
	at := testDayTime(20341, 0)
	first := a.testCommit(t, at, &indexPushFile{path: "x/1", plaintext: []byte("one")}, &indexPushFile{path: "x/2", plaintext: []byte("two")})
	if first.version != 1 || first.files[0].version != 1 || first.files[1].version != 1 {
		t.Fatalf("first push %+v", first)
	}
	stale := b.testPush(t, at, []*indexPushFile{{path: "x/1", replaces: 1, plaintext: []byte("b1")}, {path: "x/2", replaces: 1, plaintext: []byte("b2")}}, nil)
	a.testCommit(t, at, &indexPushFile{path: "x/1", replaces: 1, plaintext: []byte("a1")}, &indexPushFile{path: "x/2", replaces: 1, plaintext: []byte("a2")})

	_, err := b.Commit(context.Background(), stale)
	refusal, ok := indexRefusalOf(err)
	if !ok || refusal.kind != indexRefusalConflict || !slices.Equal(refusal.paths, []string{"x/1", "x/2"}) {
		t.Fatalf("stale push answered %v", err)
	}
	if bytes.Contains([]byte(err.Error()), []byte("x/1")) {
		t.Errorf("a refusal names a path: %s", err)
	}
	created := a.testCommit(t, at, &indexPushFile{path: "x/3", plaintext: []byte("three")})
	if created.files[0].version != 3 {
		t.Errorf("a creation at base 2 took version %d", created.files[0].version)
	}
	if _, err := a.Commit(context.Background(), a.testPush(t, at, []*indexPushFile{{path: "x/3", plaintext: []byte("again")}}, nil)); !isIndexRefusal(err, indexRefusalConflict) {
		t.Errorf("a second creation answered %v", err)
	}
}

// The fake's epoch: every push but a CLOSURE names the head's index_epoch, a CUT moves it to its own version, and a
// push built before the CUT gets 409 INDEX_EPOCH.
func TestIndexStoreFakeIndexEpoch(t *testing.T) {
	ref := testNewIndexRef()
	store := ref.store(evsTestId("a"))
	at := testDayTime(20341, 0)
	before := store.testPush(t, at, []*indexPushFile{{path: "h", plaintext: []byte("head")}}, nil)
	cut := store.testPush(t, at, []*indexPushFile{{path: indexErasureSetPath(false), plaintext: []byte{}}}, nil)
	cut.kind = indexPushCut
	committed, err := store.Commit(context.Background(), cut)
	if err != nil {
		t.Fatal(err)
	}
	if head, _ := store.Head(context.Background()); head.indexEpoch != committed.version {
		t.Fatalf("the CUT left the epoch at %d", head.indexEpoch)
	}
	if _, err := store.Commit(context.Background(), before); !isIndexRefusal(err, indexRefusalIndexEpoch) {
		t.Fatalf("a push built before the CUT answered %v", err)
	}
	closure := store.testPush(t, at, []*indexPushFile{{path: "h", plaintext: []byte("closure")}}, nil)
	closure.kind, closure.indexEpoch = indexPushClosure, 0
	if _, err := store.Commit(context.Background(), closure); err != nil {
		t.Errorf("a CLOSURE naming no epoch answered %v", err)
	}
}

// The fake's versionless replacement: a replaced version reads collected and leaves the listing, while settings keep
// every version; a listing at an older ref version still shows what it held.
func TestIndexStoreFakeVersionlessReplacement(t *testing.T) {
	ref := testNewIndexRef()
	store := ref.store(evsTestId("a"))
	at := testDayTime(20341, 0)
	settings := indexNewPaths(false, 1).settings()
	store.testCommit(t, at, &indexPushFile{path: "h", plaintext: []byte("one")}, &indexPushFile{path: settings, plaintext: []byte{}})
	old, _ := store.History(context.Background(), "h", 0)
	store.testCommit(t, at, &indexPushFile{path: "h", replaces: 1, plaintext: []byte("two")}, &indexPushFile{path: settings, replaces: 1, plaintext: []byte{0x10, 0x07}})

	if _, err := store.Read(context.Background(), old[0]); err != errTestIndexCollected {
		t.Errorf("a replaced version read %v", err)
	}
	if history, _ := store.History(context.Background(), "h", 0); len(history) != 1 || history[0].version != 2 {
		t.Errorf("a versionless path keeps %d versions", len(history))
	}
	if history, _ := store.History(context.Background(), settings, 0); len(history) != 2 || history[0].version != 2 {
		t.Errorf("settings keep %d versions", len(history))
	}
	listing, err := store.List(context.Background(), 1)
	if err != nil || listing.head.version != 1 || len(listing.files) != 2 {
		t.Fatalf("listing at 1: %+v, %v", listing, err)
	}
	index := slices.IndexFunc(listing.files, func(file *indexFileVersion) bool { return file.path == "h" })
	if sum := sha256.Sum256([]byte("one")); index < 0 || listing.files[index].version != 1 || listing.files[index].contentSha256 != sum {
		t.Errorf("listing at 1 holds another version of h")
	}
}

// The fake's queued refusals: a 429 commits nothing and the same push goes again; an unknown outcome that committed
// answers its commit to a retry of the same push id, and one that did not commits on the retry.
func TestIndexStoreFakeRefusalsAndUnknownOutcomes(t *testing.T) {
	ref := testNewIndexRef()
	store := ref.store(evsTestId("a"))
	at := testDayTime(20341, 0)
	push := store.testPush(t, at, []*indexPushFile{{path: "h", plaintext: []byte("one")}}, nil)

	ref.refuseNext(&indexRefusal{kind: indexRefusalRetry, retryAfter: time.Second}, false)
	if _, err := store.Commit(context.Background(), push); !isIndexRefusal(err, indexRefusalRetry) {
		t.Fatalf("answered %v", err)
	}
	ref.refuseNext(&indexRefusal{kind: indexRefusalQuota, quota: &QuotaRefusal{LimitKey: "storage", Limit: 1, Used: 1}}, false)
	if _, err := store.Commit(context.Background(), push); !isIndexRefusal(err, indexRefusalQuota) {
		t.Fatalf("answered %v", err)
	}
	ref.refuseNext(&indexRefusal{kind: indexRefusalOutcomeUnknown}, true)
	_, err := store.Commit(context.Background(), push)
	refusal, ok := indexRefusalOf(err)
	if !ok || refusal.kind != indexRefusalOutcomeUnknown || refusal.pushId != push.pushId {
		t.Fatalf("answered %v", err)
	}
	committed, err := store.Commit(context.Background(), push)
	if err != nil || committed.version != 1 {
		t.Fatalf("the retry answered %+v, %v", committed, err)
	}
	if head, _ := store.Head(context.Background()); head.version != 1 {
		t.Errorf("the retry committed twice: head %d", head.version)
	}

	second := store.testPush(t, at, []*indexPushFile{{path: "h", replaces: 1, plaintext: []byte("two")}}, nil)
	ref.refuseNext(&indexRefusal{kind: indexRefusalOutcomeUnknown}, false)
	if _, err := store.Commit(context.Background(), second); !isIndexRefusal(err, indexRefusalOutcomeUnknown) {
		t.Fatalf("answered %v", err)
	}
	if committed, err := store.Commit(context.Background(), second); err != nil || committed.version != 2 {
		t.Errorf("the retry of a push that never landed answered %+v, %v", committed, err)
	}
}
