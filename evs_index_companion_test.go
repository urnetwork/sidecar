//go:build !ios_extension

package sidecar

// SEARCH-M10-14 (DESIGN-DETAILS 1.6's journal list; §22.5's companion row): a committer's units published by a
// companion push with its coverage row; the build's read order, the index before each content head before the push; a
// unit superseded at the pin; a 409 returning units to committed; a 429 followed by a new build and never a resend; a
// push not sent past its life; the journal surviving a restart (FS-74's writer killed between its git push and its
// companion push); the bound and a stripped unit extracted again; an erased document left out with no hint; a ref
// DELETE's tombstone and a late entry dropped (FS-108); an ignored version's unit dropped with the row raised past it;
// and the cadence at its interval, at a full head and at a flush.

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// ur/index and one git-mode content ref, a writer's journal and companion on a clock the test moves.
type testCompanionWorld struct {
	cache     *testSearchCacheWorld
	index     *testIndexRef
	content   *testIndexContent
	writer    Id
	refKey    []byte
	settings  *SidecarSearchSettings
	format    *IndexFormatSettings
	journal   *IndexJournal
	companion *IndexCompanion
	// what the companion reads, in order
	stateLock sync.Mutex
	reads     []string
	// runs once at the next content head read
	onHead func()
	// ignored versions are judged
	judge bool
}

func newTestCompanionWorld(t *testing.T) *testCompanionWorld {
	t.Helper()
	cache := newTestSearchCacheWorld(t, 1<<30)
	world := &testCompanionWorld{
		cache:    cache,
		index:    testNewIndexRef(),
		content:  testNewIndexContent(evsTestId("content ref")),
		writer:   evsTestId("writer"),
		refKey:   bytes.Repeat([]byte{0x6b}, 32),
		settings: DefaultSidecarSettings().Search,
		format:   DefaultIndexFormatSettings(),
	}
	cache.clock.advance(testDayTime(20341, 0).Sub(cache.clock.Now()))
	world.restart(t)
	return world
}

// A journal and companion afresh over the world's store, as a process start makes them.
func (self *testCompanionWorld) restart(t *testing.T) {
	t.Helper()
	journal, err := newIndexJournal(self.cache.instance.Store(&self.cache.networkId), evsTestId("view repo"), self.settings, self.format)
	if err != nil {
		t.Fatal(err)
	}
	companion, err := newIndexCompanion(&indexCompanionArgs{
		journal: journal,
		store:   &testCompanionStore{world: self, store: self.index.store(self.writer)},
		contents: func(refId Id) indexContentRef {
			if refId != self.content.refId {
				return nil
			}
			return &testCompanionContent{world: self, testIndexContent: self.content}
		},
		prefixVerdict: func(refId Id) indexPrefixVerdict {
			if !self.judge {
				return nil
			}
			return self.content.verdict
		},
		repoId:     evsTestId("view repo"),
		indexRefId: evsTestId("view ref"),
		repoKind:   protocol.RepoKind_REPO_KIND_GENERAL,
		writer:     self.writer,
		isAdmin:    testIndexEraserAdmin,
		tables:     testHeadTables,
		refKey:     self.refKey,
		settings:   self.settings,
		format:     self.format,
		clock:      self.cache.clock,
		log:        NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	self.journal, self.companion = journal, companion
}

func (self *testCompanionWorld) read(label string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reads = append(self.reads, label)
}

// ur/index's store, its reads and commits logged.
type testCompanionStore struct {
	world *testCompanionWorld
	store *testIndexStore
}

func (self *testCompanionStore) Head(ctx context.Context) (*indexRefHead, error) {
	self.world.read("index head")
	return self.store.Head(ctx)
}

func (self *testCompanionStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	self.world.read("index list")
	return self.store.List(ctx, refVersion)
}

func (self *testCompanionStore) History(ctx context.Context, path string, refVersion uint64) ([]*indexFileVersion, error) {
	return self.store.History(ctx, path, refVersion)
}

func (self *testCompanionStore) Read(ctx context.Context, file *indexFileVersion) ([]byte, error) {
	return self.store.Read(ctx, file)
}

func (self *testCompanionStore) Commit(ctx context.Context, push *indexPush) (*indexCommitted, error) {
	self.world.read("commit")
	return self.store.Commit(ctx, push)
}

// The content ref, its head reads logged.
type testCompanionContent struct {
	world *testCompanionWorld
	*testIndexContent
}

func (self *testCompanionContent) Head(ctx context.Context) (*indexContentHead, error) {
	self.world.read("content head")
	self.world.stateLock.Lock()
	onHead := self.world.onHead
	self.world.onHead = nil
	self.world.stateLock.Unlock()
	if onHead != nil {
		onHead()
	}
	return self.testIndexContent.Head(ctx)
}

// Commits content at path to the content ref as signer, and the unit its committer journals: path's documents
// extracted as the push gave them.
func (self *testCompanionWorld) commit(t *testing.T, signer Id, path string, content []byte, ignored bool) (*indexContentPush, *indexJournalUnit) {
	t.Helper()
	push := self.content.commit(signer, self.cache.clock.Now(), nil, testContentChange{path: path, content: content, ignored: ignored})
	state, err := self.content.State(context.Background(), path, push.version)
	if err != nil {
		t.Fatal(err)
	}
	if ignored {
		self.content.stateLock.Lock()
		versions := self.content.pathVersions[path]
		state.version = versions[len(versions)-1].version
		self.content.stateLock.Unlock()
	}
	unit := &indexJournalUnit{refId: self.content.refId, version: push.version, signedTimeMs: push.signedTimeMs}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		t.Fatal(err)
	}
	streamArgs := &indexStreamArgs{
		template:   &IndexDocument{Kind: IndexDocFile, Name: []byte(path), Version: state.version},
		byteCount:  uint64(len(content)),
		normalizer: normalizer,
		companion:  true,
		refId:      self.content.refId,
		settings:   self.format,
		emit: func(document *indexStreamDocument) error {
			key, err := indexDocKey(self.refKey, self.content.refId, []byte(path), document.chunk)
			if err != nil {
				return err
			}
			unit.documents = append(unit.documents, &indexJournalDocument{key: key, name: path, chunk: document.chunk, version: state.version, keys: document.keys, row: document.row})
			return nil
		},
	}
	if _, err := indexExtractFileStream(streamArgs, bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	return push, unit
}

// The writer's head on ur/index at the head: its entries by doc_key and its coverage.
func (self *testCompanionWorld) head(t *testing.T) (map[[indexIdByteCount]byte]*indexEntry, []*protocol.IndexCoverage) {
	t.Helper()
	view := testLoadViewWith(t, self.index.store(evsTestId("reader")), self.format)
	view = testCompanionView(t, self, view)
	entries := map[[indexIdByteCount]byte]*indexEntry{}
	root := view.writeRoot()
	for _, bucket := range root.buckets {
		if writer := bucket.writer(self.writer); writer != nil {
			for _, slot := range writer.slots {
				for _, entry := range slot.slot.entries {
					entries[entry.key] = entry
				}
			}
		}
	}
	return entries, indexWriterNewestRows(root, self.writer)
}

// The view of ur/index, a companion one.
func testCompanionView(t *testing.T, world *testCompanionWorld, _ *indexView) *indexView {
	t.Helper()
	view, err := indexLoadView(context.Background(), &indexViewArgs{
		store: world.index.store(evsTestId("reader")), repoId: evsTestId("view repo"), refId: evsTestId("view ref"),
		repoKind: protocol.RepoKind_REPO_KIND_GENERAL, companion: true, isAdmin: testIndexEraserAdmin,
		settings: world.format,
	})
	if err != nil {
		t.Fatal(err)
	}
	return view
}

// The journal's unit count.
func (self *testCompanionWorld) unitCount(t *testing.T) int {
	t.Helper()
	units, err := self.journal.units()
	if err != nil {
		t.Fatal(err)
	}
	return len(units)
}

// The coverage row of the content ref in rows, 0 for none.
func testCompanionOwnRow(rows []*protocol.IndexCoverage, refId Id) uint64 {
	for _, row := range rows {
		if bytes.Equal(row.RefId, refId.Bytes()) && !row.Horizon {
			return row.Version
		}
	}
	return 0
}

// §22.5's companion row: a git-mode push's documents, journaled at its commit, are published in the writer's head on
// ur/index with the row {R, p_R, false}, and the journal empties.
func TestCompanionPublishesItsUnitsWithItsCoverage(t *testing.T) {
	world := newTestCompanionWorld(t)
	push, unit := world.commit(t, world.writer, "src/harbor.go", []byte("package harbor\n\nfunc Lights() string { return \"evening ferry\" }\n"), false)
	if err := world.companion.Committed(unit); err != nil {
		t.Fatal(err)
	}
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, rows := world.head(t)
	if entries[unit.documents[0].key] == nil || entries[unit.documents[0].key].version != unit.documents[0].version {
		t.Fatal("the unit's document is not in the writer's head")
	}
	if testCompanionOwnRow(rows, world.content.refId) != push.version {
		t.Fatalf("coverage %v", rows)
	}
	if world.unitCount(t) != 0 {
		t.Fatal("a published unit stayed in the journal")
	}
}

// 1.2.6's fence (R5): the build reads ur/index, then each content head, then commits: never content before the index.
func TestCompanionReadsTheIndexBeforeTheContent(t *testing.T) {
	world := newTestCompanionWorld(t)
	_, unit := world.commit(t, world.writer, "a.txt", []byte("first words of the file\n"), false)
	world.companion.Committed(unit)
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	world.stateLock.Lock()
	reads := slices.Clone(world.reads)
	world.stateLock.Unlock()
	list, head, commit := slices.Index(reads, "index list"), slices.Index(reads, "content head"), slices.Index(reads, "commit")
	if list < 0 || head < 0 || commit < 0 || !(list < head && head < commit) {
		t.Fatalf("read order %v", reads)
	}
}

// Step 4's superseded: a unit whose path R holds at a higher version at the pin publishes nothing, and the row still
// rises to the pin.
func TestCompanionDropsASupersededUnit(t *testing.T) {
	world := newTestCompanionWorld(t)
	_, unit := world.commit(t, world.writer, "a.txt", []byte("an older text of the file\n"), false)
	world.companion.Committed(unit)
	newer, _ := world.commit(t, evsTestId("other writer"), "a.txt", []byte("a newer text another wrote\n"), false)
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, rows := world.head(t)
	if entries[unit.documents[0].key] != nil {
		t.Fatal("a superseded unit was published")
	}
	if testCompanionOwnRow(rows, world.content.refId) != newer.version || world.unitCount(t) != 0 {
		t.Fatalf("row %v, %d units", rows, world.unitCount(t))
	}
}

// Step 6: a 409 returns the units to committed and the build starts over; the second build publishes them once.
func TestCompanionReturnsUnitsOnConflict(t *testing.T) {
	world := newTestCompanionWorld(t)
	_, unit := world.commit(t, world.writer, "a.txt", []byte("words of the file\n"), false)
	world.companion.Committed(unit)
	world.index.refuseNext(&indexRefusal{kind: indexRefusalConflict}, false)
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, _ := world.head(t)
	if entries[unit.documents[0].key] == nil || world.unitCount(t) != 0 {
		t.Fatal("the units were not published after the 409")
	}
}

// R5: a push refused 429 is built again, under a new push id and a new signed time, never sent again as built.
func TestCompanionNeverResendsAfterARetry(t *testing.T) {
	world := newTestCompanionWorld(t)
	_, unit := world.commit(t, world.writer, "a.txt", []byte("words of the file\n"), false)
	world.companion.Committed(unit)
	world.index.refuseNext(&indexRefusal{kind: indexRefusalRetry, retryAfter: time.Second}, false)
	pushes := []*indexPush{}
	world.index.beforeCommit = func(push *indexPush) {
		pushes = append(pushes, push)
		world.cache.clock.advance(time.Second)
	}
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pushes) != 2 || pushes[0].pushId == pushes[1].pushId || pushes[0].signedTimeMs == pushes[1].signedTimeMs {
		t.Fatalf("%d pushes after a 429", len(pushes))
	}
}

// IndexPushLife: a build whose life passes before its send sends nothing, and the next build publishes.
func TestCompanionSendsNothingPastItsLife(t *testing.T) {
	world := newTestCompanionWorld(t)
	_, unit := world.commit(t, world.writer, "a.txt", []byte("words of the file\n"), false)
	world.companion.Committed(unit)
	world.onHead = func() { world.cache.clock.advance(world.format.PushLife + time.Second) }
	committed := 0
	world.index.beforeCommit = func(push *indexPush) { committed += 1 }
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if committed != 1 {
		t.Fatalf("%d commits: a push past its life was sent", committed)
	}
}

// FS-74's killed writer: units on disk outlive the process; a new journal reads them and its companion publishes them.
func TestCompanionJournalSurvivesARestart(t *testing.T) {
	world := newTestCompanionWorld(t)
	_, unit := world.commit(t, world.writer, "a.txt", []byte("words written before the crash\n"), false)
	world.companion.Committed(unit)
	world.restart(t)
	if world.unitCount(t) != 1 {
		t.Fatal("the unit did not survive the restart")
	}
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, _ := world.head(t)
	if entries[unit.documents[0].key] == nil {
		t.Fatal("the restarted companion did not publish the unit")
	}
}

// The bound: past JournalByteCount the oldest unit loses its key sets; a build extracts it again from R's text at the
// pin, and publishes it.
func TestCompanionJournalBound(t *testing.T) {
	world := newTestCompanionWorld(t)
	world.settings.JournalByteCount = 1
	_, unit := world.commit(t, world.writer, "a.txt", []byte("words of the stripped file\n"), false)
	world.companion.Committed(unit)
	units, _ := world.journal.units()
	if len(units) != 1 || !units[0].stripped || units[0].documents[0].keys != nil {
		t.Fatal("the bound kept a unit's key sets")
	}
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, _ := world.head(t)
	entry := entries[unit.documents[0].key]
	if entry == nil || len(entry.keys) == 0 {
		t.Fatal("a stripped unit was not extracted again")
	}
}

// FS-111's dropped hint: the erasure set lists the document, no hint reached the journal, and the build leaves it
// out; the unit leaves.
func TestCompanionLeavesAnErasedDocumentOut(t *testing.T) {
	world := newTestCompanionWorld(t)
	_, unit := world.commit(t, world.writer, "a.txt", []byte("words that are erased\n"), false)
	world.companion.Committed(unit)
	document := unit.documents[0]
	erasureSet, err := indexEncodeErasureSet(&protocol.IndexErasureSet{Erasures: []*protocol.IndexErasure{{
		ErasureId: evsTestId("erasure").Bytes(), EraserSidecarId: evsTestId("eraser").Bytes(), CutMs: 1,
		Docs: []*protocol.IndexErased{{DocKey: document.key[:], Version: document.version}},
	}}}, world.format)
	if err != nil {
		t.Fatal(err)
	}
	eraser := world.index.store(evsTestId("eraser"))
	push := eraser.testPush(t, world.cache.clock.Now(), []*indexPushFile{{path: indexErasureSetPath(true), plaintext: erasureSet}}, nil)
	push.kind = indexPushCut
	if _, err := eraser.Commit(context.Background(), push); err != nil {
		t.Fatal(err)
	}
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, _ := world.head(t)
	if entries[document.key] != nil || world.unitCount(t) != 0 {
		t.Fatal("an erased document was published")
	}
}

// FS-108: a ref DELETE this sidecar signed publishes its ref tombstone, and a late unit of the deleted ref's document
// is superseded at the pin and dropped.
func TestCompanionRefDeleteDropsALateEntry(t *testing.T) {
	world := newTestCompanionWorld(t)
	_, late := world.commit(t, world.writer, "a.txt", []byte("words before the delete\n"), false)
	world.companion.Committed(late)
	deleted := world.content.commit(world.writer, world.cache.clock.Now(), func(push *indexContentPush) { push.deletesRef = true })
	tombstone := &indexJournalUnit{refId: world.content.refId, version: deleted.version, signedTimeMs: deleted.signedTimeMs,
		documents: []*indexJournalDocument{{key: [indexIdByteCount]byte(world.content.refId), version: deleted.version, refTombstone: true}}}
	world.companion.Committed(tombstone)
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, _ := world.head(t)
	if entries[late.documents[0].key] != nil {
		t.Fatal("a late entry of a deleted ref was published")
	}
	refEntry := entries[[indexIdByteCount]byte(world.content.refId)]
	if refEntry == nil || refEntry.kind != indexEntryRefTombstone || refEntry.version != deleted.version {
		t.Fatalf("the ref tombstone: %+v", refEntry)
	}
}

// DESIGN-DETAILS 16.7's scope note: a unit of a version this device ignores is dropped at the build, and the row
// rises past its push.
func TestCompanionDropsAnIgnoredVersion(t *testing.T) {
	world := newTestCompanionWorld(t)
	world.judge = true
	push, unit := world.commit(t, world.writer, "a.txt", []byte("words under a breached prefix\n"), true)
	world.companion.Committed(unit)
	if err := world.companion.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	entries, rows := world.head(t)
	if entries[unit.documents[0].key] != nil {
		t.Fatal("an ignored version was published")
	}
	if testCompanionOwnRow(rows, world.content.refId) < push.version {
		t.Fatalf("the row did not rise past the ignored push: %v", rows)
	}
}

// QD-511's cadence: a build at once for the first unit; then none before CompanionInterval, one after it; and one at
// once when the head would fill.
func TestCompanionCadence(t *testing.T) {
	world := newTestCompanionWorld(t)
	ctx := context.Background()
	_, first := world.commit(t, world.writer, "a.txt", []byte("first words\n"), false)
	world.companion.Committed(first)
	if built, err := world.companion.Tick(ctx); err != nil || !built {
		t.Fatalf("the first unit waited: %v", err)
	}
	_, second := world.commit(t, world.writer, "b.txt", []byte("second words\n"), false)
	world.companion.Committed(second)
	world.cache.clock.advance(world.settings.CompanionInterval / 2)
	if built, _ := world.companion.Tick(ctx); built {
		t.Fatal("a build inside the interval")
	}
	world.cache.clock.advance(world.settings.CompanionInterval / 2)
	if built, err := world.companion.Tick(ctx); err != nil || !built {
		t.Fatalf("no build at the interval: %v", err)
	}
	// a unit whose entries alone fill a head is due at once
	world.format.SlotMaxByteCount = 64
	_, third := world.commit(t, world.writer, "c.txt", []byte("third words in a file large enough\n"), false)
	world.format.SlotMaxByteCount = DefaultIndexFormatSettings().SlotMaxByteCount
	world.companion.args.format.SlotMaxByteCount = 64
	world.companion.Committed(third)
	world.companion.args.format.SlotMaxByteCount = DefaultIndexFormatSettings().SlotMaxByteCount
	if next, _ := world.companion.NextDue(); next.After(world.cache.clock.Now()) {
		t.Fatal("a full head waited for the interval")
	}
}

// The journal is the local layer's overlay (searchLocalJournal), and an erasure reaches it with no build: ApplyErase
// takes an erased key's documents at every version, ApplyCut a listed document at or below its version, and a unit
// left with nothing goes.
func TestIndexJournalErasesAndServesTheLocalLayer(t *testing.T) {
	var _ searchLocalJournal = (*IndexJournal)(nil)
	world := newTestCompanionWorld(t)
	_, erased := world.commit(t, world.writer, "a.txt", []byte("words an erasure takes\n"), false)
	_, cut := world.commit(t, world.writer, "b.txt", []byte("words a cut lists\n"), false)
	_, kept := world.commit(t, world.writer, "c.txt", []byte("words that stay\n"), false)
	for _, unit := range []*indexJournalUnit{erased, cut, kept} {
		if err := world.journal.Committed(unit); err != nil {
			t.Fatal(err)
		}
	}
	visible := func() map[[indexIdByteCount]byte]bool {
		keys := map[[indexIdByteCount]byte]bool{}
		err := world.journal.searchJournalEntries(func(entry *indexEntry) error {
			if entry.kind != indexEntryFull || len(entry.keys) == 0 {
				t.Fatalf("an overlay entry without its keys: %+v", entry)
			}
			keys[entry.key] = true
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return keys
	}
	if len(visible()) != 3 {
		t.Fatalf("the overlay holds %d documents", len(visible()))
	}
	if err := world.journal.ApplyErase([][indexIdByteCount]byte{erased.documents[0].key}); err != nil {
		t.Fatal(err)
	}
	cutKey, cutVersion := cut.documents[0].key, cut.documents[0].version
	err := world.journal.ApplyCut(func(key [indexIdByteCount]byte, version uint64) bool {
		return key == cutKey && version <= cutVersion
	})
	if err != nil {
		t.Fatal(err)
	}
	left := visible()
	if len(left) != 1 || !left[kept.documents[0].key] || world.unitCount(t) != 1 {
		t.Fatalf("after the erasure: %d documents, %d units", len(left), world.unitCount(t))
	}
}
