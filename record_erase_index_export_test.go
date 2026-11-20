//go:build !sidecar_http && !ios_extension

// A bridge for RECORD-M10-01's external tests (record_erase_index_test.go): a record log's ur/index on the index's
// in-memory fake (evs_index_fake_test.go and evs_index_erase_test.go's fake evs), the index's real eraser behind
// SidecarRecord.SetEraseIndex through recordNewEraseIndex, and what the tests read back: the erasure set, a document's
// entries and their keys, the index side's ERASEs and FI-19's sweep. Beside it, a stream writer's push of one run card,
// built at one moment and sent at another, as a companion push carries a card (SEARCH-M10-14's card markers are not on
// sidecar yet). The record's own ERASEs go to the record streams' fake: a test's tap tells the index's fake of each,
// so one ordered list holds every ERASE of an erasure, as evs's erasure ref does.

package sidecar

import (
	"bytes"
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A record log's ur/index on the fake, its writers and erasers signing as the sidecars they name.
type RecordEraseTestIndex struct {
	t       testing.TB
	world   *testHeadWorld
	evs     *testEraseEvs
	logKind protocol.RepoKind
	refKey  []byte

	stateLock sync.Mutex
	// the methods its index handles were called with, in order
	calls []string
	// failures the next calls of a method answer before reaching the index: a kill there
	methodFailures map[string][]error
	// run at each call, before a failure
	onCall func(method string)
}

// The ur/index of a log of logKind, an erasure set or settings version counting where admins signed it.
func NewRecordEraseTestIndex(t testing.TB, logKind protocol.RepoKind, admins ...Id) *RecordEraseTestIndex {
	world := testNewHeadWorld()
	world.admins = slices.Clone(admins)
	return &RecordEraseTestIndex{
		t: t, world: world, evs: testNewEraseEvs(world), logKind: logKind, refKey: bytes.Repeat([]byte{0x3d}, 32),
		methodFailures: map[string][]error{},
	}
}

// A RecordEraseIndexOpen for SetEraseIndex: a fresh eraser of the log's ur/index at each open, signing as eraserId, as
// a device starting holds none of its memory.
func (self *RecordEraseTestIndex) Open(eraserId Id) RecordEraseIndexOpen {
	return func(ctx context.Context, logId Id) (RecordEraseIndex, error) {
		store := self.evs.as(eraserId)
		index, err := recordNewEraseIndex(&recordEraseIndexArgs{
			store: store, eraseStore: store, repoId: logId, refId: evsTestId("record index ref"), logKind: self.logKind,
			isAdmin: self.world.isAdmin, format: self.world.settings, eraser: eraserId, complete: self.complete,
			refKey: self.refKey, clock: &testIndexWorldClock{world: self.world}, log: NewNoopLogger(),
		})
		if err != nil {
			return nil, err
		}
		return &recordEraseTestIndexHandle{RecordEraseIndex: index, bridge: self}, nil
	}
}

// Which erasures are complete by their newest ERASE, the record's and the index side's in one order.
func (self *RecordEraseTestIndex) complete(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	return recordEraseCompleteByNewest(self.evs.erases, func(erase *testEraseErase) (Id, bool) {
		return erase.erasureId, erase.erased.complete
	}), nil
}

// Tells the index's fake of an ERASE the record streams committed, in its place among the erasure's ERASEs.
func (self *RecordEraseTestIndex) NoteStreamErase(erasureId Id, complete bool) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	self.evs.erases = append(self.evs.erases, &testEraseErase{
		erasureId: erasureId, erased: &indexEraseErased{complete: complete, timeMs: self.world.at.UnixMilli()},
	})
}

// Fails the next call of method, "cut", "reenter", "rewrite" or "resume", with err before it reaches the index.
func (self *RecordEraseTestIndex) FailNext(method string, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.methodFailures[method] = append(self.methodFailures[method], err)
}

// Runs hook at each call, with the method's name, before anything else.
func (self *RecordEraseTestIndex) OnCall(hook func(method string)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.onCall = hook
}

// The methods called, in order.
func (self *RecordEraseTestIndex) Calls() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls)
}

// One call's bookkeeping: its hook, then its failure, if one is queued.
func (self *RecordEraseTestIndex) call(method string) error {
	hook, failure := func() (func(method string), error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls = append(self.calls, method)
		var failure error
		if failures := self.methodFailures[method]; 0 < len(failures) {
			failure = failures[0]
			self.methodFailures[method] = failures[1:]
		}
		return self.onCall, failure
	}()
	if hook != nil {
		hook(method)
	}
	return failure
}

// The index handle a record erasure holds: each call booked, then the eraser's.
type recordEraseTestIndexHandle struct {
	RecordEraseIndex
	bridge *RecordEraseTestIndex
}

func (self *recordEraseTestIndexHandle) Cut(ctx context.Context, args *IndexCutArgs) (*IndexCutResult, error) {
	if err := self.bridge.call("cut"); err != nil {
		return nil, err
	}
	return self.RecordEraseIndex.Cut(ctx, args)
}

func (self *recordEraseTestIndexHandle) Reenter(ctx context.Context, args *IndexReenterArgs) (*IndexReenterResult, error) {
	if err := self.bridge.call("reenter"); err != nil {
		return nil, err
	}
	return self.RecordEraseIndex.Reenter(ctx, args)
}

func (self *recordEraseTestIndexHandle) Rewrite(ctx context.Context, args *IndexRewriteArgs) (*IndexRewriteResult, error) {
	if err := self.bridge.call("rewrite"); err != nil {
		return nil, err
	}
	return self.RecordEraseIndex.Rewrite(ctx, args)
}

func (self *recordEraseTestIndexHandle) Resume(ctx context.Context, args *IndexResumeArgs) (*IndexResumeResult, error) {
	if err := self.bridge.call("resume"); err != nil {
		return nil, err
	}
	return self.RecordEraseIndex.Resume(ctx, args)
}

// Moves the index's clock, which its erasers read, on by duration.
func (self *RecordEraseTestIndex) Advance(duration time.Duration) {
	self.world.at = self.world.at.Add(duration)
}

// The doc_key of name in the stream whose ref is refId.
func (self *RecordEraseTestIndex) DocKey(refId Id, name []byte) [16]byte {
	self.t.Helper()
	key, err := indexDocKey(self.refKey, refId, name, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	return key
}

// The doc_key of runId's card in the stream whose ref is refId.
func (self *RecordEraseTestIndex) CardKey(refId Id, runId Id) [16]byte {
	self.t.Helper()
	return self.DocKey(refId, indexRunCardName(runId))
}

// The index at its head as a reader of it sees it.
func (self *RecordEraseTestIndex) view() *indexView {
	self.t.Helper()
	view, err := indexLoadView(context.Background(), &indexViewArgs{
		store: self.world.ref.store(evsTestId("record index reader")), repoId: evsTestId("record log"),
		refId: evsTestId("record index ref"), repoKind: self.logKind, companion: true, isAdmin: self.world.isAdmin,
		settings: self.world.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return view
}

// The head's index_epoch.
func (self *RecordEraseTestIndex) Epoch() uint64 {
	self.t.Helper()
	return self.view().head.indexEpoch
}

// L(k) at the head, over every erasure the set lists.
func (self *RecordEraseTestIndex) Listed() map[[16]byte]uint64 {
	self.t.Helper()
	return indexErasureSetListed(self.view().erasureSet)
}

// The documents the set lists for erasureId, nil where it lists no such erasure.
func (self *RecordEraseTestIndex) ErasureDocs(erasureId Id) map[[16]byte]uint64 {
	self.t.Helper()
	erasure := indexErasureOf(self.view().erasureSet, erasureId)
	if erasure == nil {
		return nil
	}
	docs := map[[16]byte]uint64{}
	for _, erased := range erasure.GetDocs() {
		docs[[16]byte(erased.GetDocKey())] = erased.GetVersion()
	}
	return docs
}

// One entry of a document in the index at its head.
type RecordEraseTestEntry struct {
	Version uint64
	Writer  Id
	Head    bool
	Shard   bool
	Keys    []uint32
}

// Every entry of key in every bucket of the index at its head, a shard's row's keys inverted from its postings.
func (self *RecordEraseTestIndex) Entries(key [16]byte) []*RecordEraseTestEntry {
	self.t.Helper()
	view := self.view()
	entries := []*RecordEraseTestEntry{}
	for _, bucket := range view.writeRoot().buckets {
		documents, err := view.bucketDocuments(context.Background(), bucket)
		if err != nil {
			self.t.Fatal(err)
		}
		for _, entry := range documents.of(key) {
			held := &RecordEraseTestEntry{Version: entry.version, Writer: entry.writer, Head: entry.head, Shard: entry.shard}
			switch {
			case entry.entry != nil:
				held.Keys = slices.Clone([]uint32(entry.entry.keys))
			case entry.document != nil:
				held.Keys = slices.Clone([]uint32(entry.document.keys))
			}
			entries = append(entries, held)
		}
	}
	return entries
}

// The keys extractor 1 gives text in a card's text field.
func (self *RecordEraseTestIndex) TextKeys(text string) []uint32 {
	self.t.Helper()
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		self.t.Fatal(err)
	}
	keys, err := normalizer.documentKeys([]indexTextField{{number: indexFieldBody, text: strings.NewReader(text)}})
	if err != nil {
		self.t.Fatal(err)
	}
	return slices.Clone([]uint32(keys))
}

// The index side's ERASEs of erasureId, beside the record's the tap told of: their count, and whether the newest says
// complete.
func (self *RecordEraseTestIndex) Erases(erasureId Id) (int, bool) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	count, complete := 0, false
	for _, erase := range self.evs.erases {
		if erase.erasureId == erasureId {
			count += 1
			complete = erase.erased.complete
		}
	}
	return count, complete
}

// The CLOSUREs of erasureId committed on the index.
func (self *RecordEraseTestIndex) Closures(erasureId Id) int {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	count := 0
	for _, closure := range self.evs.closures {
		if closure.erasureId == erasureId {
			count += 1
		}
	}
	return count
}

// FI-19's sweep: no stored version of an index file under a key a reader can still obtain holds an entry the set
// lists, at or below its listed version.
func (self *RecordEraseTestIndex) Sweep() {
	self.t.Helper()
	listed := indexEraseListed(self.Listed())
	self.evs.stateLock.Lock()
	hold := self.evs.hold
	destroyed := map[Id]bool{}
	for slotId := range self.evs.destroyed {
		destroyed[slotId] = true
	}
	self.evs.stateLock.Unlock()
	for path, versions := range self.evs.versions() {
		parsed, ok := indexParsePath(path, true)
		if !ok || !indexPathHoldsDocuments(parsed.kind) {
			continue
		}
		for _, version := range versions {
			if (version.endedAt != 0 && !hold) || destroyed[version.slotId] {
				continue
			}
			holds, err := indexHolds(parsed, version.plaintext, listed, self.world.settings)
			if err != nil {
				self.t.Fatal(err)
			}
			if holds {
				self.t.Fatalf("an openable stored version of %s at %d holds a listed entry", path, version.file.version)
			}
		}
	}
}

// A stream writer's push of one run card, built at the head as it stood then.
type RecordEraseTestCardPush struct {
	bridge *RecordEraseTestIndex
	store  *testIndexStore
	push   *indexPush
	// The card's version and keys, as built.
	Version uint64
	Keys    []uint32
}

// Builds writerId's push of runId's card in the stream of streamSidecarId, whose ref is refId, as reader reads the
// stream now: folded at the head's epoch with the erasure test erasures and the set give, as a companion push of that
// stream folds it. Nil where the fold gives no card.
func (self *RecordEraseTestIndex) PrepareCard(reader *RecordReader, logId Id, streamSidecarId Id, refId Id, runId Id, writerId Id, erasures []*RecordStreamErasure) *RecordEraseTestCardPush {
	self.t.Helper()
	ctx := context.Background()
	store := self.world.ref.store(writerId)
	view, err := indexLoadView(ctx, &indexViewArgs{
		store: store, repoId: logId, refId: evsTestId("record index ref"), repoKind: self.logKind, companion: true,
		isAdmin: self.world.isAdmin, settings: self.world.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		self.t.Fatal(err)
	}
	head := uint64(0)
	streams, _ := reader.Streams(logId)
	for _, stream := range streams {
		if stream.StreamSidecarId == streamSidecarId && 0 < len(stream.Pushes) {
			head = stream.Pushes[len(stream.Pushes)-1].Version
		}
	}
	stream := newIndexRecordReaderStream(reader, logId, self.logKind, streamSidecarId, refId)
	document, _, err := searchRunCard(ctx, stream, runId, head, guard.epoch(), newIndexRecordErasures(erasures, view.erasureSet).erasedAtEpoch, DefaultIndexRecordSettings(), self.world.settings)
	if err != nil {
		self.t.Fatal(err)
	}
	if document == nil {
		return nil
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		self.t.Fatal(err)
	}
	prepared, err := document.prepare(normalizer, true, refId, self.world.settings)
	if err != nil {
		self.t.Fatal(err)
	}
	key := self.CardKey(refId, runId)
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: writerId, signedTimeMs: self.world.at.UnixMilli(),
		tables: indexLinkedTables(), mayMerge: false,
		pending: []*indexPendingDocument{{kind: indexEntryFull, key: key, version: document.Version, keys: prepared.keys, row: prepared.row}},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if plan.mergeFirst || plan.mergeInPush {
		self.t.Fatalf("a card push that cannot commit by itself: %+v", plan)
	}
	push, err := guard.push(indexPushIndex, self.world.at.UnixMilli(), plan.files(), plan.removals())
	if err != nil {
		self.t.Fatal(err)
	}
	return &RecordEraseTestCardPush{
		bridge: self, store: store, push: push, Version: document.Version, Keys: slices.Clone([]uint32(prepared.keys)),
	}
}

// Sends the push as it was built: nil once committed, else evs's refusal.
func (self *RecordEraseTestCardPush) Send() error {
	_, err := self.store.Commit(context.Background(), self.push)
	return err
}

// Whether err is 409 INDEX_EPOCH: a CUT landed after the push was built.
func RecordEraseTestIndexEpochRefused(err error) bool {
	return isIndexRefusal(err, indexRefusalIndexEpoch)
}

// Sets settings on the eraser, for a test of one of its bounds.
func (self *RecordEraser) SetSettingsForTest(settings *RecordEraserSettings) {
	self.settings = settings
}

// The rule both index sides judge complete by (record_erase.go's complete row): an erasure is complete while its newest
// ERASE says so, so a late copy's ERASE after a complete one opens it again, and a completion ERASE after that ends it.
func TestRecordEraseCompleteByNewest(t *testing.T) {
	type erase struct {
		erasureId Id
		complete  bool
	}
	first, second := evsTestId("first erasure"), evsTestId("second erasure")
	cases := []struct {
		erases []erase
		want   map[Id]bool
	}{
		{erases: []erase{{erasureId: first}, {erasureId: first, complete: true}}, want: map[Id]bool{first: true}},
		{erases: []erase{{erasureId: first, complete: true}, {erasureId: first}}, want: map[Id]bool{}},
		{
			erases: []erase{{erasureId: first, complete: true}, {erasureId: second}, {erasureId: first}, {erasureId: first, complete: true}},
			want:   map[Id]bool{first: true},
		},
	}
	for index, c := range cases {
		got := recordEraseCompleteByNewest(c.erases, func(erase erase) (Id, bool) { return erase.erasureId, erase.complete })
		if !maps.Equal(got, c.want) {
			t.Errorf("case %d: complete %v, want %v", index, got, c.want)
		}
	}
}
