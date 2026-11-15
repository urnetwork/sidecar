// SEARCH-M10-12's tests (§11.14's coverage row; DESIGN-DETAILS 1.2.6, 15.2.9, 16.2.5): indexed_through across two
// writers, a horizon and a gap; what changes no document; an ignored push counted as indexed; FS-74's killed writer
// and skipped index reported not yet searchable until a backfill covers them; a backfill dropping a superseded entry,
// leaving what changed after h, skipping an erased and an unopenable document, indexing no ignored version, stopping
// below a push it cannot judge, rebuilding on the epoch, writing tombstones for a removal, dropped chunks and a ref
// DELETE, entering a document whose diff has no base, and carrying a record log's run cards; all on the fake stores.

package sidecar

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One version of a path in the fake content ref.
type testContentVersion struct {
	commitVersion uint64
	version       uint64
	removed       bool
	unopenable    bool
	content       []byte
	// The device ignores this version under the prefix rules: its effective state skips it.
	ignored bool
}

// One change a test commits: content at path, nil removing it.
type testContentChange struct {
	path       string
	content    []byte
	ignored    bool
	unopenable bool
}

// A fake content ref: its pushes and each path's versions, read as coverage and a backfill read them. Safe for
// concurrent use.
type testIndexContent struct {
	refId Id

	stateLock    sync.Mutex
	pushes       []*indexContentPush
	pathVersions map[string][]*testContentVersion
	// Pushes the device cannot judge: a set it does not hold.
	unjudged map[uint64]bool
	// The ref version of the next push, where an in-ref test aligns it with the index's.
	nextVersion uint64
}

func testNewIndexContent(refId Id) *testIndexContent {
	return &testIndexContent{refId: refId, pathVersions: map[string][]*testContentVersion{}, unjudged: map[uint64]bool{}, nextVersion: 1}
}

func (self *testIndexContent) RefId() Id {
	return self.refId
}

func (self *testIndexContent) Head(ctx context.Context) (*indexContentHead, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	head := &indexContentHead{}
	if 0 < len(self.pushes) {
		last := self.pushes[len(self.pushes)-1]
		head.version, head.signedTimeMs = last.version, last.signedTimeMs
	}
	return head, nil
}

func (self *testIndexContent) Pushes(ctx context.Context, afterVersion uint64, throughVersion uint64) ([]*indexContentPush, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pushes := []*indexContentPush{}
	for _, push := range self.pushes {
		if afterVersion < push.version && push.version <= throughVersion {
			pushes = append(pushes, push)
		}
	}
	return pushes, nil
}

func (self *testIndexContent) State(ctx context.Context, path string, refVersion uint64) (*indexContentState, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	var effective *testContentVersion
	for _, version := range self.pathVersions[path] {
		if version.commitVersion <= refVersion && !version.ignored {
			effective = version
		}
	}
	if effective == nil {
		return &indexContentState{}, nil
	}
	state := &indexContentState{version: effective.version, commitVersion: effective.commitVersion, removed: effective.removed, unopenable: effective.unopenable}
	if !effective.removed && !effective.unopenable {
		state.content = bytes.NewReader(effective.content)
		state.byteCount = uint64(len(effective.content))
	}
	return state, nil
}

func (self *testIndexContent) Paths(ctx context.Context, refVersion uint64, visit func(path string, byteCount uint64) error) error {
	paths := func() []string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		paths := []string{}
		for path := range self.pathVersions {
			paths = append(paths, path)
		}
		slices.Sort(paths)
		return paths
	}()
	for _, path := range paths {
		state, _ := self.State(ctx, path, refVersion)
		if state.version == 0 || state.removed {
			continue
		}
		if err := visit(path, state.byteCount); err != nil {
			return err
		}
	}
	return nil
}

// Commits a push by signer at signedTime of changes, mark set on the push before it is kept.
func (self *testIndexContent) commit(signer Id, signedTime time.Time, mark func(push *indexContentPush), changes ...testContentChange) *indexContentPush {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	push := &indexContentPush{version: self.nextVersion, signedTimeMs: signedTime.UnixMilli(), signer: signer}
	self.nextVersion += 1
	for _, change := range changes {
		versions := self.pathVersions[change.path]
		next := &testContentVersion{commitVersion: push.version, version: push.version, removed: change.content == nil, unopenable: change.unopenable, content: change.content, ignored: change.ignored}
		if 0 < len(versions) {
			last := versions[len(versions)-1]
			if !last.removed {
				next.version = last.version + 1
			}
		}
		self.pathVersions[change.path] = append(versions, next)
		push.changes = append(push.changes, &indexContentChange{path: change.path})
	}
	if mark != nil {
		mark(push)
	}
	if push.deletesRef {
		for path, versions := range self.pathVersions {
			if last := versions[len(versions)-1]; !last.removed {
				self.pathVersions[path] = append(versions, &testContentVersion{commitVersion: push.version, version: last.version + 1, removed: true})
			}
		}
	}
	self.pushes = append(self.pushes, push)
	return push
}

// The device's verdict on a change: wait for an unjudged push, ignored for an ignored version, else allowed.
func (self *testIndexContent) verdict(ctx context.Context, push *indexContentPush, change *indexContentChange) (AclPrefixVerdict, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.unjudged[push.version] {
		return AclPrefixVerdict{Outcome: AclPrefixWait, Reason: AclPrefixReasonPending}, nil
	}
	for _, version := range self.pathVersions[change.path] {
		if version.commitVersion == push.version && version.ignored {
			return AclPrefixVerdict{Outcome: AclPrefixIgnored, Reason: AclPrefixReasonNotUnder}, nil
		}
	}
	return AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonUnder}, nil
}

// An index ref and one content ref, on a clock the test moves: ur/index over a git-mode ref when companion, else a
// file-mode ref's own index, whose content is the index's ref.
type testBackfillWorld struct {
	index     *testIndexRef
	content   *testIndexContent
	companion bool
	repoKind  protocol.RepoKind
	settings  *IndexFormatSettings
	refKey    []byte
	now       time.Time
}

func testNewBackfillWorld(companion bool) *testBackfillWorld {
	contentRefId := evsTestId("view ref")
	if companion {
		contentRefId = evsTestId("content ref")
	}
	return &testBackfillWorld{
		index:     testNewIndexRef(),
		content:   testNewIndexContent(contentRefId),
		companion: companion,
		repoKind:  protocol.RepoKind_REPO_KIND_GENERAL,
		settings:  DefaultIndexFormatSettings(),
		refKey:    bytes.Repeat([]byte{0x6b}, 32),
		now:       testDayTime(20341, 0),
	}
}

func (self *testBackfillWorld) Now() time.Time {
	return self.now
}

func (self *testBackfillWorld) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.now
	return fired
}

func (self *testBackfillWorld) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}

// The index at its head.
func (self *testBackfillWorld) view(t testing.TB) *indexView {
	t.Helper()
	view, err := indexLoadView(context.Background(), &indexViewArgs{
		store:     self.index.store(evsTestId("reader")),
		repoId:    evsTestId("view repo"),
		refId:     evsTestId("view ref"),
		repoKind:  self.repoKind,
		companion: self.companion,
		settings:  self.settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// Commits a content push a minute after the last. In a file-mode test the content is the index's own ref, so the push
// takes the index's next version and an empty push on the index's fake stands for it there.
func (self *testBackfillWorld) commit(t testing.TB, signer Id, mark func(push *indexContentPush), changes ...testContentChange) *indexContentPush {
	t.Helper()
	self.now = self.now.Add(time.Minute)
	if self.companion {
		return self.content.commit(signer, self.now, mark, changes...)
	}
	store := self.index.store(signer)
	head, err := store.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	self.content.nextVersion = head.version + 1
	push := self.content.commit(signer, self.now, mark, changes...)
	store.testCommit(t, self.now)
	return push
}

// A writer's head in the bucket of now carrying rows alone, as a companion push that only raises coverage does.
func (self *testBackfillWorld) carry(t testing.TB, writer Id, rows ...*protocol.IndexCoverage) {
	t.Helper()
	view := self.view(t)
	root := view.writeRoot()
	plan, err := indexPlanHead(context.Background(), &indexHeadPlanArgs{
		view: view, root: root, writer: writer, signedTimeMs: self.now.UnixMilli(), tables: testHeadTables,
		coverage: indexRaiseCoverage(indexWriterNewestRows(root, writer), rows),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := self.index.store(writer).Commit(context.Background(), &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: self.now.UnixMilli(),
		files: plan.files(), removals: plan.removals(),
	}); err != nil {
		t.Fatal(err)
	}
}

// A row for the content ref.
func (self *testBackfillWorld) row(version uint64, horizon bool) *protocol.IndexCoverage {
	return &protocol.IndexCoverage{RefId: self.content.refId.Bytes(), Version: version, Horizon: horizon}
}

// Coverage at the index's head, on the device's verdicts when judged.
func (self *testBackfillWorld) coverage(t testing.TB, judged bool) *indexCoverage {
	t.Helper()
	view := self.view(t)
	args := &indexCoverageArgs{view: view, root: view.writeRoot(), content: self.content}
	if judged {
		args.verdict = self.content.verdict
	}
	coverage, err := indexCoverageOf(context.Background(), args)
	if err != nil {
		t.Fatal(err)
	}
	return coverage
}

// A backfiller signing as writer, on the world's clock, the device's verdicts and cards.
func (self *testBackfillWorld) backfiller(t testing.TB, writer Id, cards indexBackfillCards) *IndexBackfiller {
	t.Helper()
	backfiller, err := indexNewBackfiller(&indexBackfillArgs{
		store:     self.index.store(writer),
		repoId:    evsTestId("view repo"),
		refId:     evsTestId("view ref"),
		repoKind:  self.repoKind,
		companion: self.companion,
		format:    self.settings,
		tables:    testHeadTables,
		clock:     self,
		writer:    writer,
		refKey:    self.refKey,
		contents:  []indexContentRef{self.content},
		verdictOf: func(refId Id) indexPrefixVerdict { return self.content.verdict },
		mayMerge:  true,
		padKey: func(ctx context.Context) (*indexPadKey, error) {
			return testPadKey(t, 2), nil
		},
		cards: cards,
	})
	if err != nil {
		t.Fatal(err)
	}
	return backfiller
}

// One backfill, failing on any error.
func (self *testBackfillWorld) backfill(t testing.TB, backfiller *IndexBackfiller) *indexBackfillOutcome {
	t.Helper()
	outcome, err := backfiller.backfill(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return outcome
}

// The doc_key of path's chunk in the content ref.
func (self *testBackfillWorld) key(t testing.TB, path string, chunk uint32) [indexIdByteCount]byte {
	t.Helper()
	key, err := indexDocKey(self.refKey, self.content.refId, []byte(path), chunk)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The entries of path's chunk in the newest bucket that writer's files hold.
func (self *testBackfillWorld) entriesOf(t testing.TB, writer Id, path string, chunk uint32) []*indexBucketEntry {
	t.Helper()
	view := self.view(t)
	bucket := view.writeRoot().newestBucket()
	if bucket == nil {
		return nil
	}
	documents, err := view.bucketDocuments(context.Background(), bucket)
	if err != nil {
		t.Fatal(err)
	}
	entries := []*indexBucketEntry{}
	for _, entry := range documents.of(self.key(t, path, chunk)) {
		if entry.writer == writer {
			entries = append(entries, entry)
		}
	}
	return entries
}

// writer's head rows in the newest bucket.
func (self *testBackfillWorld) headRows(t testing.TB, writer Id) []*protocol.IndexCoverage {
	t.Helper()
	return indexWriterNewestRows(self.view(t).writeRoot(), writer)
}

func TestIndexCoverageAcrossWritersAHorizonAndAGap(t *testing.T) {
	world := testNewBackfillWorld(true)
	a, b, c := evsTestId("writer a"), evsTestId("writer b"), evsTestId("backfiller c")
	for index, signer := range []Id{a, b, a, b, a} {
		world.commit(t, signer, nil, testContentChange{path: "notes/" + string(rune('a'+index)) + ".md", content: []byte("text")})
	}
	// nothing covers anything yet: every push reads not yet searchable
	if coverage := world.coverage(t, true); coverage.indexedThrough != 0 || coverage.unindexedCount != 5 {
		t.Fatalf("an empty index: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
	// a's companion holds its own pushes through 3, and a backfiller's horizon every writer's through 1
	world.carry(t, a, world.row(3, false))
	world.carry(t, c, world.row(1, true))
	coverage := world.coverage(t, true)
	if coverage.indexedThrough != 1 || coverage.unindexedCount != 3 || coverage.horizon != 1 || coverage.writerRows[a] != 3 {
		t.Fatalf("a gap at b's push 2: through %d, %d unindexed, horizon %d, a's row %d", coverage.indexedThrough, coverage.unindexedCount, coverage.horizon, coverage.writerRows[a])
	}
	counts := []indexPushCount{}
	for _, counted := range coverage.pushes {
		counts = append(counts, counted.count)
	}
	if !slices.Equal(counts, []indexPushCount{indexPushUnindexed, indexPushCovered, indexPushUnindexed, indexPushUnindexed}) {
		t.Fatalf("pushes above the horizon counted %v", counts)
	}
	// b's companion closes the gap: a's push 5 is the oldest left
	world.carry(t, b, world.row(4, false))
	if coverage := world.coverage(t, true); coverage.indexedThrough != 4 || coverage.unindexedCount != 1 {
		t.Fatalf("b's row: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
	// rows never fall: a row carried forward, and a lower row beside a higher one, read the highest
	world.carry(t, a, world.row(2, false))
	world.carry(t, c, world.row(5, true))
	if coverage := world.coverage(t, true); coverage.indexedThrough != 5 || coverage.unindexedCount != 0 || coverage.writerRows[a] != 3 {
		t.Fatalf("a horizon at the head: through %d, %d unindexed, a's row %d", coverage.indexedThrough, coverage.unindexedCount, coverage.writerRows[a])
	}
	if rows := world.headRows(t, a); len(rows) != 1 || rows[0].Version != 3 {
		t.Fatalf("a's head lowered its row: %v", rows)
	}
}

func TestIndexCoverageCountsWhatChangesNoDocument(t *testing.T) {
	world := testNewBackfillWorld(false)
	writer := evsTestId("writer a")
	world.commit(t, writer, func(push *indexContentPush) { push.changesHead = true }, testContentChange{path: "notes/a.md", content: []byte("in ref")})
	world.commit(t, writer, func(push *indexContentPush) { push.indexNone = true }, testContentChange{path: "notes/b.bin", content: []byte{0, 1, 2}})
	world.commit(t, writer, nil, testContentChange{path: ".ur-index/i1/lock", content: []byte("lock")})
	world.commit(t, writer, nil)
	world.commit(t, writer, nil, testContentChange{path: "notes/c.md", content: []byte("old client")})
	coverage := world.coverage(t, true)
	if coverage.indexedThrough != 4 || coverage.unindexedCount != 1 {
		t.Fatalf("through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
	want := []indexPushCount{indexPushInRef, indexPushNoDocument, indexPushNoDocument, indexPushNoDocument, indexPushUnindexed}
	for index, counted := range coverage.pushes {
		if counted.count != want[index] {
			t.Errorf("push %d counted %d, want %d", counted.push.version, counted.count, want[index])
		}
	}

	// a mailbox's paths but m/ change no document, and a reader classifies them with no fetch
	mailbox := testNewBackfillWorld(false)
	mailbox.repoKind = protocol.RepoKind_REPO_KIND_MAILBOX
	mailbox.commit(t, writer, nil, testContentChange{path: "i/000001", content: []byte("snippet")}, testContentChange{path: "vault/k", content: []byte("secret")})
	mailbox.commit(t, writer, nil, testContentChange{path: "m/2026/11/000001", content: []byte("Subject: s\r\n\r\nbody")})
	if coverage := mailbox.coverage(t, true); coverage.indexedThrough != 1 || coverage.unindexedCount != 1 {
		t.Fatalf("a mailbox: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}

	// on ur/index a ref DELETE changes no path and still needs its ref tombstone
	companion := testNewBackfillWorld(true)
	companion.commit(t, writer, func(push *indexContentPush) { push.deletesRef = true })
	if coverage := companion.coverage(t, true); coverage.indexedThrough != 0 || coverage.unindexedCount != 1 {
		t.Fatalf("a ref DELETE: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
}

func TestIndexCoverageCountsAnIgnoredPushAsIndexed(t *testing.T) {
	world := testNewBackfillWorld(true)
	a, breacher := evsTestId("writer a"), evsTestId("breacher")
	world.commit(t, a, nil, testContentChange{path: "notes/a.md", content: []byte("first")})
	world.commit(t, breacher, nil, testContentChange{path: "notes/a.md", content: []byte("breach"), ignored: true})
	world.commit(t, a, nil, testContentChange{path: "notes/b.md", content: []byte("next")})
	world.carry(t, a, world.row(3, false))
	// the breach's push is no change to this device: indexed_through does not stall on it
	coverage := world.coverage(t, true)
	if coverage.indexedThrough != 3 || coverage.unindexedCount != 0 || coverage.pushes[1].count != indexPushIgnored {
		t.Fatalf("a breach: through %d, %d unindexed, counted %d", coverage.indexedThrough, coverage.unindexedCount, coverage.pushes[1].count)
	}
	// a device holding no rule set judges nothing ignored
	if coverage := world.coverage(t, false); coverage.indexedThrough != 1 || coverage.unindexedCount != 1 {
		t.Fatalf("no rules: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
	// a push one of whose changes is allowed is not ignored, and one under a set the device cannot read is unjudged
	world.commit(t, breacher, nil, testContentChange{path: "notes/c.md", content: []byte("ignored"), ignored: true}, testContentChange{path: "agents/c.md", content: []byte("allowed")})
	unjudged := world.commit(t, breacher, nil, testContentChange{path: "notes/d.md", content: []byte("pending")})
	world.content.unjudged[unjudged.version] = true
	coverage = world.coverage(t, true)
	if coverage.indexedThrough != 3 || coverage.unindexedCount != 2 {
		t.Fatalf("partly ignored and unjudged: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
	if last := coverage.pushes[len(coverage.pushes)-1]; !last.unjudged || last.count != indexPushUnindexed {
		t.Fatalf("an unjudged push counted %d, unjudged %v", last.count, last.unjudged)
	}
}

// FS-74's killed writer: its content committed and its companion push never sent, so its push reads not yet
// searchable, and a backfill BackfillAge later indexes it into the backfiller's own head and raises the horizon.
func TestIndexBackfillCoversAKilledWriter(t *testing.T) {
	world := testNewBackfillWorld(true)
	killed, backfillerId := evsTestId("killed writer"), evsTestId("indexer")
	world.commit(t, killed, nil, testContentChange{path: "notes/plan.md", content: []byte("# Plan\nquarterly budget review\n")})
	if coverage := world.coverage(t, true); coverage.indexedThrough != 0 || coverage.unindexedCount != 1 {
		t.Fatalf("the killed writer's push: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
	backfiller := world.backfiller(t, backfillerId, nil)
	// younger than BackfillAge: nothing is due, and nothing is written
	world.now = world.now.Add(9 * time.Minute)
	if outcome := world.backfill(t, backfiller); outcome.committed != nil || outcome.skipped != indexBackfillSkipNone {
		t.Fatalf("a young push backfilled: skipped %d", outcome.skipped)
	}
	world.now = world.now.Add(time.Minute)
	outcome := world.backfill(t, backfiller)
	if outcome.committed == nil || len(outcome.refs) != 1 || outcome.refs[0].h != 1 || outcome.refs[0].entryCount != 1 {
		t.Fatalf("the backfill: %+v", outcome)
	}
	if coverage := world.coverage(t, true); coverage.indexedThrough != 1 || coverage.unindexedCount != 0 {
		t.Fatalf("after the backfill: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
	entries := world.entriesOf(t, backfillerId, "notes/plan.md", 0)
	if len(entries) != 1 || entries[0].kind != indexEntryFull || entries[0].version != 1 || !entries[0].head {
		t.Fatalf("the backfiller's head holds %+v", entries)
	}
	if rows := world.headRows(t, backfillerId); len(rows) != 2 || rows[0].Horizon || rows[0].Version != 1 || !rows[1].Horizon || rows[1].Version != 1 {
		t.Fatalf("the backfiller's rows: %v", rows)
	}
	// a second pass finds nothing due
	if outcome := world.backfill(t, backfiller); outcome.committed != nil {
		t.Fatal("a covered push backfilled again")
	}
}

// FS-74's skipped index on a file-mode ref: an old client's push changes no head, reads not yet searchable, and a
// backfill covers it in the ref's own index with a horizon row and no own row.
func TestIndexBackfillCoversASkippedIndexInRef(t *testing.T) {
	world := testNewBackfillWorld(false)
	oldClient, backfillerId := evsTestId("old client"), evsTestId("desktop")
	world.commit(t, oldClient, nil, testContentChange{path: "notes/old.md", content: []byte("written without the index")})
	if coverage := world.coverage(t, true); coverage.unindexedCount != 1 {
		t.Fatalf("an old client's push: %d unindexed", coverage.unindexedCount)
	}
	world.now = world.now.Add(11 * time.Minute)
	outcome := world.backfill(t, world.backfiller(t, backfillerId, nil))
	if outcome.committed == nil || outcome.refs[0].entryCount != 1 {
		t.Fatalf("the backfill: %+v", outcome)
	}
	if coverage := world.coverage(t, true); coverage.unindexedCount != 0 {
		t.Fatalf("after the backfill: %d unindexed", coverage.unindexedCount)
	}
	if rows := world.headRows(t, backfillerId); len(rows) != 1 || !rows[0].Horizon {
		t.Fatalf("an in-ref backfill's rows: %v", rows)
	}
	if entries := world.entriesOf(t, backfillerId, "notes/old.md", 0); len(entries) != 1 {
		t.Fatalf("the backfiller's head holds %d entries", len(entries))
	}
}

// A path whose newest change is indexed by its committer is superseded, and one changed again after h, or by a push
// younger than BackfillAge, is left to that change's own entry; h stops below the young push.
func TestIndexBackfillLeavesSupersededAndLaterChanges(t *testing.T) {
	world := testNewBackfillWorld(true)
	a, b, backfillerId := evsTestId("writer a"), evsTestId("writer b"), evsTestId("indexer")
	world.commit(t, a, nil, testContentChange{path: "notes/one.md", content: []byte("one, first")})
	world.commit(t, a, nil, testContentChange{path: "notes/two.md", content: []byte("two")}, testContentChange{path: "notes/four.md", content: []byte("four, first")})
	world.commit(t, b, nil, testContentChange{path: "notes/one.md", content: []byte("one, by b")})
	world.carry(t, b, world.row(3, false))
	world.now = world.now.Add(11 * time.Minute)
	young := world.commit(t, a, nil, testContentChange{path: "notes/four.md", content: []byte("four, young")})
	outcome := world.backfill(t, world.backfiller(t, backfillerId, nil))
	if outcome.committed == nil || outcome.refs[0].h != young.version-1 {
		t.Fatalf("h %d, want %d", outcome.refs[0].h, young.version-1)
	}
	if entries := world.entriesOf(t, backfillerId, "notes/two.md", 0); len(entries) != 1 || entries[0].version != 2 {
		t.Fatalf("two: %+v", entries)
	}
	if entries := world.entriesOf(t, backfillerId, "notes/one.md", 0); len(entries) != 0 {
		t.Fatal("a superseded version of one entered")
	}
	if entries := world.entriesOf(t, backfillerId, "notes/four.md", 0); len(entries) != 0 {
		t.Fatal("four, changed again after h, entered")
	}
	coverage := world.coverage(t, true)
	if coverage.indexedThrough != young.version-1 || coverage.unindexedCount != 1 {
		t.Fatalf("after: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
	// the push above h is a's, so the backfiller vouches for its own row at the pin beside the horizon at h
	if rows := world.headRows(t, backfillerId); len(rows) != 2 || rows[0].Version != young.version || rows[1].Version != young.version-1 {
		t.Fatalf("rows %v", rows)
	}
}

// On ur/index the backfiller raises its own row to the pin only where it signed no push above h that is still
// unindexed: its own young push keeps its row where it was, and once that push is due the row moves to the pin.
func TestIndexBackfillRaisesNoOwnRowItCannotVouchFor(t *testing.T) {
	world := testNewBackfillWorld(true)
	writer, desktop := evsTestId("writer a"), evsTestId("desktop")
	world.commit(t, writer, nil, testContentChange{path: "notes/one.md", content: []byte("one")})
	world.now = world.now.Add(11 * time.Minute)
	own := world.commit(t, desktop, nil, testContentChange{path: "notes/mine.md", content: []byte("mine, not yet journaled")})
	backfiller := world.backfiller(t, desktop, nil)
	outcome := world.backfill(t, backfiller)
	if outcome.committed == nil || outcome.refs[0].h != own.version-1 {
		t.Fatalf("h %d, want %d", outcome.refs[0].h, own.version-1)
	}
	if rows := world.headRows(t, desktop); len(rows) != 1 || !rows[0].Horizon || rows[0].Version != own.version-1 {
		t.Fatalf("an own row past an own unindexed push: %v", rows)
	}
	world.now = world.now.Add(11 * time.Minute)
	world.backfill(t, backfiller)
	if rows := world.headRows(t, desktop); len(rows) != 2 || rows[0].Horizon || rows[0].Version != own.version || rows[1].Version != own.version {
		t.Fatalf("rows once the own push is due: %v", rows)
	}
}

// The erasure set's documents and one whose content an ERASE left unopenable are skipped, and their pushes still
// read indexed under the raised horizon.
func TestIndexBackfillSkipsErasedAndUnopenable(t *testing.T) {
	world := testNewBackfillWorld(true)
	writer, backfillerId := evsTestId("writer a"), evsTestId("indexer")
	world.commit(t, writer, nil, testContentChange{path: "notes/erased.md", content: []byte("erased words")})
	world.commit(t, writer, nil, testContentChange{path: "notes/gone.md", content: []byte("unopenable"), unopenable: true})
	world.commit(t, writer, nil, testContentChange{path: "notes/kept.md", content: []byte("kept words")})
	// an eraser's CUT lists erased.md's chunk 0 through version 1
	erasedKey := world.key(t, "notes/erased.md", 0)
	set := &protocol.IndexErasureSet{ListedSince: 1, Erasures: []*protocol.IndexErasure{{
		ErasureId: testIndexIdBytes("erasure", 1), EraserSidecarId: evsTestId("eraser").Bytes(), Epoch: 0, CutMs: world.now.UnixMilli(),
		Docs: []*protocol.IndexErased{{DocKey: erasedKey[:], Version: 1}},
	}}}
	eraser := world.index.store(evsTestId("eraser"))
	push := eraser.testPush(t, world.now, []*indexPushFile{{path: indexErasureSetPath(true), plaintext: testSmallFile(t, set)}}, nil)
	push.kind = indexPushCut
	if _, err := eraser.Commit(context.Background(), push); err != nil {
		t.Fatal(err)
	}
	world.now = world.now.Add(11 * time.Minute)
	outcome := world.backfill(t, world.backfiller(t, backfillerId, nil))
	if outcome.committed == nil || outcome.refs[0].entryCount != 2 {
		t.Fatalf("the backfill: %+v", outcome.refs[0])
	}
	if entries := world.entriesOf(t, backfillerId, "notes/erased.md", 0); len(entries) != 0 {
		t.Fatal("an erased document entered")
	}
	if entries := world.entriesOf(t, backfillerId, "notes/gone.md", 0); len(entries) != 0 {
		t.Fatal("an unopenable document entered")
	}
	if entries := world.entriesOf(t, backfillerId, "notes/kept.md", 0); len(entries) != 1 {
		t.Fatal("kept.md not entered")
	}
	if coverage := world.coverage(t, true); coverage.indexedThrough != 3 {
		t.Fatalf("through %d", coverage.indexedThrough)
	}
}

// DESIGN-DETAILS 16.2.5: a backfill indexes no version its device ignores. The breach's version is never entered,
// the path's effective version is, and a push that only breached is counted indexed with nothing entered.
func TestIndexBackfillIndexesNoIgnoredVersion(t *testing.T) {
	world := testNewBackfillWorld(true)
	a, breacher, backfillerId := evsTestId("writer a"), evsTestId("breacher"), evsTestId("indexer")
	world.commit(t, a, nil, testContentChange{path: "notes/a.md", content: []byte("allowed words")})
	world.commit(t, breacher, nil, testContentChange{path: "notes/a.md", content: []byte("breach words"), ignored: true})
	world.commit(t, breacher, nil, testContentChange{path: "notes/breach.md", content: []byte("created in breach"), ignored: true})
	world.now = world.now.Add(11 * time.Minute)
	outcome := world.backfill(t, world.backfiller(t, backfillerId, nil))
	if outcome.committed == nil || outcome.refs[0].entryCount != 1 || outcome.refs[0].h != 3 {
		t.Fatalf("the backfill: %+v", outcome.refs[0])
	}
	if entries := world.entriesOf(t, backfillerId, "notes/a.md", 0); len(entries) != 1 || entries[0].version != 1 {
		t.Fatalf("a.md entered at %+v, want its effective version 1", entries)
	}
	if entries := world.entriesOf(t, backfillerId, "notes/breach.md", 0); len(entries) != 0 {
		t.Fatal("a version written in breach entered")
	}
	if coverage := world.coverage(t, true); coverage.indexedThrough != 3 || coverage.unindexedCount != 0 {
		t.Fatalf("after: through %d, %d unindexed", coverage.indexedThrough, coverage.unindexedCount)
	}
}

// A push under a rule set the device cannot read stops h below it: the device cannot say it would show the change.
func TestIndexBackfillStopsBelowAnUnjudgedPush(t *testing.T) {
	world := testNewBackfillWorld(true)
	writer, backfillerId := evsTestId("writer a"), evsTestId("indexer")
	world.commit(t, writer, nil, testContentChange{path: "notes/one.md", content: []byte("one")})
	pending := world.commit(t, writer, nil, testContentChange{path: "notes/two.md", content: []byte("two")})
	world.commit(t, writer, nil, testContentChange{path: "notes/three.md", content: []byte("three")})
	world.content.unjudged[pending.version] = true
	world.now = world.now.Add(11 * time.Minute)
	outcome := world.backfill(t, world.backfiller(t, backfillerId, nil))
	if outcome.committed == nil || outcome.refs[0].h != 1 || outcome.refs[0].entryCount != 1 {
		t.Fatalf("the backfill: %+v", outcome.refs[0])
	}
	if entries := world.entriesOf(t, backfillerId, "notes/three.md", 0); len(entries) != 0 {
		t.Fatal("a version above the unjudged push entered")
	}
}

// A backfill is an index push: a CUT landing between its build and its commit refuses it 409 INDEX_EPOCH, and it
// rebuilds from t at the new epoch.
func TestIndexBackfillRebuildsOnTheEpoch(t *testing.T) {
	world := testNewBackfillWorld(true)
	writer, backfillerId := evsTestId("writer a"), evsTestId("indexer")
	world.commit(t, writer, nil, testContentChange{path: "notes/one.md", content: []byte("one")})
	world.now = world.now.Add(11 * time.Minute)
	eraser := world.index.store(evsTestId("eraser"))
	cut := false
	world.index.beforeCommit = func(push *indexPush) {
		if cut {
			return
		}
		cut = true
		set := &protocol.IndexErasureSet{ListedSince: 1}
		cutPush := eraser.testPush(t, world.now, []*indexPushFile{{path: indexErasureSetPath(true), plaintext: testSmallFile(t, set)}}, nil)
		cutPush.kind = indexPushCut
		world.index.beforeCommit = nil
		if _, err := eraser.Commit(context.Background(), cutPush); err != nil {
			t.Error(err)
		}
	}
	outcome := world.backfill(t, world.backfiller(t, backfillerId, nil))
	if outcome.committed == nil || outcome.attempts != 2 {
		t.Fatalf("committed %v after %d attempts", outcome.committed != nil, outcome.attempts)
	}
	if view := world.view(t); view.head.indexEpoch == 0 {
		t.Fatal("the CUT did not move the epoch")
	}
	if coverage := world.coverage(t, true); coverage.indexedThrough != 1 {
		t.Fatalf("through %d", coverage.indexedThrough)
	}
}

// A removal gives a tombstone where the index holds the path live, a version with fewer chunks tombstones the chunks
// past its count, and a ref DELETE gives a ref tombstone on ur/index.
func TestIndexBackfillTombstones(t *testing.T) {
	world := testNewBackfillWorld(true)
	world.settings.ChunkByteCount = 64
	world.settings.OverlapByteCount = 8
	writer, backfillerId := evsTestId("writer a"), evsTestId("indexer")
	backfiller := world.backfiller(t, backfillerId, nil)
	long := bytes.Repeat([]byte("alpha beta gamma delta "), 10)
	world.commit(t, writer, nil, testContentChange{path: "notes/long.md", content: long}, testContentChange{path: "notes/gone.md", content: []byte("soon removed")})
	world.now = world.now.Add(11 * time.Minute)
	world.backfill(t, backfiller)
	if entries := world.entriesOf(t, backfillerId, "notes/long.md", 3); len(entries) != 1 || entries[0].kind != indexEntryFull {
		t.Fatalf("chunk 3 of the long version: %+v", entries)
	}
	world.commit(t, writer, nil, testContentChange{path: "notes/long.md", content: long[:70]}, testContentChange{path: "notes/gone.md"})
	world.now = world.now.Add(11 * time.Minute)
	world.backfill(t, backfiller)
	for chunk, want := range []indexEntryKind{indexEntryFull, indexEntryFull, indexEntryTombstone, indexEntryTombstone} {
		entries := world.entriesOf(t, backfillerId, "notes/long.md", uint32(chunk))
		if len(entries) != 1 || entries[0].kind != want || entries[0].version != 2 {
			t.Fatalf("chunk %d after the shorter version: %+v", chunk, entries)
		}
	}
	if entries := world.entriesOf(t, backfillerId, "notes/long.md", 4); len(entries) != 0 {
		t.Fatal("a chunk the index never held tombstoned")
	}
	if entries := world.entriesOf(t, backfillerId, "notes/gone.md", 0); len(entries) != 1 || entries[0].kind != indexEntryTombstone || entries[0].version != 2 {
		t.Fatalf("the removed path: %+v", entries)
	}
	deleted := world.commit(t, writer, func(push *indexContentPush) { push.deletesRef = true })
	world.now = world.now.Add(11 * time.Minute)
	world.backfill(t, backfiller)
	view := world.view(t)
	documents, err := view.bucketDocuments(context.Background(), view.writeRoot().newestBucket())
	if err != nil {
		t.Fatal(err)
	}
	var refKey [indexIdByteCount]byte
	copy(refKey[:], world.content.refId.Bytes())
	refTombstones := documents.of(refKey)
	if len(refTombstones) != 1 || refTombstones[0].kind != indexEntryRefTombstone || refTombstones[0].version != deleted.version {
		t.Fatalf("the ref DELETE: %+v", refTombstones)
	}
}

// A host with the text enters again a document whose unabsorbed diff has no base: a forged slot's diff, matched to
// its path by the doc_keys the host computes, is entered full in the backfiller's head, with nothing else due.
func TestIndexBackfillReentersADiffWithNoBase(t *testing.T) {
	world := testNewBackfillWorld(false)
	writer, forger, backfillerId := evsTestId("writer a"), evsTestId("forger"), evsTestId("desktop")
	world.commit(t, writer, func(push *indexContentPush) { push.changesHead = true }, testContentChange{path: "notes/forged.md", content: []byte("the first words")})
	world.commit(t, writer, func(push *indexContentPush) { push.changesHead = true }, testContentChange{path: "notes/forged.md", content: []byte("the real words")})
	view := world.view(t)
	root := view.writeRoot()
	window, _ := indexBucketFor(root.bucketWindows(), root.windowDays(view.repoKind), world.now.UnixMilli())
	keys := testIndexKeys(0x616100, 20, 1)
	// version 2 as a diff on a version 1 that no other file of the forger's holds
	diff := &indexEntry{
		kind: indexEntryDiff, key: world.key(t, "notes/forged.md", 0), version: 2, baseVersion: 1,
		timeSeconds: indexEntrySeconds(world.now.UnixMilli()), row: testFileRow(keys), delta: indexDelta{added: keys[:2]},
	}
	path, err := root.paths.slot(window.startDay, [indexIdByteCount]byte(forger.Bytes()), 0)
	if err != nil {
		t.Fatal(err)
	}
	world.index.store(forger).testCommit(t, world.now, &indexPushFile{path: path, plaintext: testViewSlotFile(t, window, forger, 1, indexFileSlot, diff)})
	head, _ := world.index.store(writer).Head(context.Background())
	world.carry(t, writer, world.row(head.version, true))
	world.now = world.now.Add(time.Minute)
	if coverage := world.coverage(t, true); coverage.unindexedCount != 0 {
		t.Fatalf("%d unindexed: the re-entry would ride a backfill", coverage.unindexedCount)
	}
	outcome := world.backfill(t, world.backfiller(t, backfillerId, nil))
	if outcome.committed == nil || len(outcome.reentered) != 1 || outcome.reentered[0] != world.key(t, "notes/forged.md", 0) {
		t.Fatalf("re-entered %d, committed %v", len(outcome.reentered), outcome.committed != nil)
	}
	entries := world.entriesOf(t, backfillerId, "notes/forged.md", 0)
	if len(entries) != 1 || entries[0].kind != indexEntryFull || entries[0].version != 2 {
		t.Fatalf("the re-entry: %+v", entries)
	}
}

// A fake of a record log's cards: a blocked version, the runs' cards, and how often the erasure ref was read.
type testBackfillCards struct {
	blocked      uint64
	erasureReads int
	asked        [][]uint64
}

func (self *testBackfillCards) ReadErasures(ctx context.Context) error {
	self.erasureReads += 1
	return nil
}

func (self *testBackfillCards) BlockedFrom(ctx context.Context, refId Id, afterVersion uint64, pin uint64, epoch uint64) (uint64, error) {
	if afterVersion < self.blocked && self.blocked <= pin {
		return self.blocked, nil
	}
	return 0, nil
}

func (self *testBackfillCards) Cards(ctx context.Context, refId Id, versions []uint64, pin uint64, epoch uint64) ([]*IndexDocument, error) {
	self.asked = append(self.asked, slices.Clone(versions))
	card := &IndexDocument{Kind: IndexDocDerived, Name: []byte("run/r1"), Version: epoch<<32 + versions[len(versions)-1]}
	card.Fields[indexFieldBody] = []byte("deployment checklist run")
	return []*IndexDocument{card}, nil
}

// 15.2.9's backfill row on a record log: h stays below the first version whose card is blocked, the erasure ref is
// read before the first card folded at an epoch and not again at it, and the cards of the runs the due versions
// touched ride the push.
func TestIndexBackfillCarriesRunCards(t *testing.T) {
	world := testNewBackfillWorld(true)
	writer, backfillerId := evsTestId("stream writer"), evsTestId("indexer")
	for index := range 4 {
		world.commit(t, writer, nil, testContentChange{path: "e/" + string(rune('1'+index)), content: []byte("entry")})
	}
	cards := &testBackfillCards{blocked: 4}
	backfiller := world.backfiller(t, backfillerId, cards)
	world.now = world.now.Add(11 * time.Minute)
	outcome := world.backfill(t, backfiller)
	if outcome.committed == nil || outcome.refs[0].h != 3 {
		t.Fatalf("h %d, want 3, below the blocked card", outcome.refs[0].h)
	}
	if cards.erasureReads != 1 || len(cards.asked) != 1 || !slices.Equal(cards.asked[0], []uint64{1, 2, 3}) {
		t.Fatalf("erasure reads %d, cards asked for %v", cards.erasureReads, cards.asked)
	}
	if entries := world.entriesOf(t, backfillerId, "run/r1", 0); len(entries) != 1 || entries[0].version != 3 {
		t.Fatalf("the run card: %+v", entries)
	}
	// unblocked at the same epoch: no second read of the erasure ref
	cards.blocked = 0
	world.now = world.now.Add(time.Minute)
	world.backfill(t, backfiller)
	if cards.erasureReads != 1 || len(cards.asked) != 2 || !slices.Equal(cards.asked[1], []uint64{4}) {
		t.Fatalf("erasure reads %d, cards asked for %v", cards.erasureReads, cards.asked)
	}
	// after a CUT moves the epoch, the next card folded reads the erasure ref first
	eraser := world.index.store(evsTestId("eraser"))
	cutPush := eraser.testPush(t, world.now, []*indexPushFile{{path: indexErasureSetPath(true), plaintext: testSmallFile(t, &protocol.IndexErasureSet{ListedSince: 1})}}, nil)
	cutPush.kind = indexPushCut
	if _, err := eraser.Commit(context.Background(), cutPush); err != nil {
		t.Fatal(err)
	}
	world.commit(t, writer, nil, testContentChange{path: "e/5", content: []byte("entry")})
	world.now = world.now.Add(11 * time.Minute)
	world.backfill(t, backfiller)
	if cards.erasureReads != 2 {
		t.Fatalf("erasure reads %d after the epoch moved", cards.erasureReads)
	}
}

// The schedule runs a desktop's backfill when no indexer serves the repo, and a roll-up's I_R reads coverage.
func TestIndexScheduleRunsTheBackfillAndRollupsReadCoverage(t *testing.T) {
	world := testNewBackfillWorld(true)
	writer, desktop := evsTestId("writer a"), evsTestId("desktop")
	world.commit(t, writer, nil, testContentChange{path: "notes/one.md", content: []byte("one")})
	world.now = world.now.Add(11 * time.Minute)
	merger, err := indexNewMerger(&indexMergerArgs{
		store: world.index.store(desktop), repoId: evsTestId("view repo"), refId: evsTestId("view ref"),
		repoKind: world.repoKind, companion: true, format: world.settings, tables: testHeadTables, clock: world,
		padKey: func(ctx context.Context) (*indexPadKey, error) { return testPadKey(t, 2), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	schedule := indexNewSchedule(nil, world)
	schedule.add(&indexScheduleRefArgs{merger: merger, device: indexSearchDeviceDesktop, self: desktop, backfill: world.backfiller(t, desktop, nil)})
	for _, tick := range schedule.tick(context.Background()) {
		if len(tick.errs) != 0 {
			t.Fatal(tick.errs)
		}
	}
	if coverage := world.coverage(t, true); coverage.indexedThrough != 1 {
		t.Fatalf("the schedule's backfill: through %d", coverage.indexedThrough)
	}
	world.commit(t, writer, nil, testContentChange{path: "notes/two.md", content: []byte("two")})
	indexedThrough := indexCoverageIndexedThrough(context.Background(), func(refId Id) indexContentRef {
		if refId == world.content.refId {
			return world.content
		}
		return nil
	}, nil, false)
	if through, ok := indexedThrough(world.view(t), world.content.refId.Bytes()); !ok || through != 1 {
		t.Fatalf("a roll-up's I_R: %d %v", through, ok)
	}
	if _, ok := indexedThrough(world.view(t), evsTestId("unread ref").Bytes()); ok {
		t.Fatal("a ref the device cannot read gave an I_R")
	}
}

// The judge's adapter reads a push it holds no statement of as no change, allowed, as the judge reads a change it
// cannot see, and asks nothing of the repo for it.
func TestIndexEvsPrefixVerdictAllowsWhatItCannotSee(t *testing.T) {
	verdict, err := indexEvsPrefixVerdict(nil, evsTestId("content ref"))(context.Background(), &indexContentPush{version: 1}, &indexContentChange{path: "notes/a.md"})
	if err != nil || verdict.Outcome != AclPrefixAllowed || verdict.Reason != AclPrefixReasonNoChange {
		t.Fatalf("%+v %v", verdict, err)
	}
}
