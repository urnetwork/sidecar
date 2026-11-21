//go:build !sidecar_http && !ios_extension

// A bridge for the directory erasure's tests of QD-1158 (directory_erasure_after_cut_test.go): both index refs of the
// team directory on the index's in-memory fake, the cards ref's own index (.ur-index/ under it) and the streams'
// ur/index, each a ref with its own files and history, and one erasure ref between them, as the directory's repo has
// on evs. Every ERASE of an erasure goes to that one ref, the record's of its announce entries and the cards' keys
// a tap tells of among them, in one order: each ref's eraser reads its progress there, and its CUTs judge which
// erasures are complete there. Each ref's eraser is built by the binding's own constructor (directoryNewErasureIndex),
// so it reads an erasure's progress by its newest ERASE. Both refs keep every version, as under a preservation hold, so
// FI-19's sweep reads each one.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The two index refs' names, as the tests name them.
const (
	DirectoryErasureTestCardsRef   = "cards"
	DirectoryErasureTestStreamsRef = "ur/index"
)

// One CUT a ref's eraser committed: its ref, its erasure, and how many ERASEs the erasure ref held when it committed.
type DirectoryErasureTestCut struct {
	Ref        string
	ErasureId  Id
	EraseCount int
}

// One index ref of the directory on the fake.
type directoryErasureTestRef struct {
	name      string
	world     *testHeadWorld
	evs       *testEraseEvs
	refKey    []byte
	refId     Id
	companion bool
}

// See the file header.
type DirectoryErasureTestRefs struct {
	t testing.TB
	// the cards ref's index; its fake evs holds the erasure ref, every ERASE and every destroyed key
	cards   *directoryErasureTestRef
	streams *directoryErasureTestRef

	stateLock sync.Mutex
	cuts      []*DirectoryErasureTestCut
	// the record streams' ERASEs told so far
	streamErasureCount int
}

// Both refs, a set version counting where one of admins signed it.
func NewDirectoryErasureTestRefs(t testing.TB, admins ...Id) *DirectoryErasureTestRefs {
	newRef := func(name string, companion bool, refKeyByte byte) *directoryErasureTestRef {
		world := testNewHeadWorld()
		world.admins = slices.Clone(admins)
		evs := testNewEraseEvs(world)
		evs.hold = true
		return &directoryErasureTestRef{
			name: name, world: world, evs: evs, refKey: bytes.Repeat([]byte{refKeyByte}, 32),
			refId: evsTestId("directory index ref " + name), companion: companion,
		}
	}
	return &DirectoryErasureTestRefs{
		t:       t,
		cards:   newRef(DirectoryErasureTestCardsRef, false, 0x6c),
		streams: newRef(DirectoryErasureTestStreamsRef, true, 0x7d),
	}
}

// The ref named name.
func (self *DirectoryErasureTestRefs) ref(name string) *directoryErasureTestRef {
	switch name {
	case DirectoryErasureTestCardsRef:
		return self.cards
	case DirectoryErasureTestStreamsRef:
		return self.streams
	}
	self.t.Fatalf("no index ref %s", name)
	return nil
}

// An eraser's store on a ref other than the cards ref: its own files, history, keys and CLOSUREs, and the erasure ref's
// ERASEs.
type directoryErasureTestSharedStore struct {
	*testEraseStore
	erasureRef *testEraseStore
}

// See indexEraseStore: on the erasure ref.
func (self *directoryErasureTestSharedStore) Erase(ctx context.Context, erase *indexErasePush) error {
	return self.erasureRef.Erase(ctx, erase)
}

// See indexEraseStore: this ref's CLOSUREs of the erasure, and its ERASEs on the erasure ref.
func (self *directoryErasureTestSharedStore) Progress(ctx context.Context, erasureId Id) (*indexEraseProgress, error) {
	own, err := self.testEraseStore.Progress(ctx, erasureId)
	if err != nil {
		return nil, err
	}
	shared, err := self.erasureRef.Progress(ctx, erasureId)
	if err != nil {
		return nil, err
	}
	return &indexEraseProgress{closures: own.closures, erases: shared.erases, completionKey: shared.completionKey}, nil
}

// One ref's eraser as a device's pass holds it, its CUTs noted.
type directoryErasureTestRefIndex struct {
	*directoryEvsErasureIndex
	refs *DirectoryErasureTestRefs
	ref  *directoryErasureTestRef
}

func (self *directoryErasureTestRefIndex) Cut(ctx context.Context, args *IndexCutArgs) (*IndexCutResult, error) {
	result, err := self.directoryEvsErasureIndex.Cut(ctx, args)
	if err == nil && result.Pushed {
		erasures := self.refs.cards.evs
		erasures.stateLock.Lock()
		eraseCount := len(erasures.erases)
		erasures.stateLock.Unlock()
		self.refs.stateLock.Lock()
		defer self.refs.stateLock.Unlock()
		self.refs.cuts = append(self.refs.cuts, &DirectoryErasureTestCut{Ref: self.ref.name, ErasureId: args.ErasureId, EraseCount: eraseCount})
	}
	return result, err
}

// The eraser of the ref named name signing as eraserId, built afresh at each call as each pass of a device builds one.
func (self *DirectoryErasureTestRefs) Open(name string, eraserId Id) DirectoryErasureIndex {
	self.t.Helper()
	ref := self.ref(name)
	store := ref.evs.as(eraserId)
	var eraseStore indexEraseStore = store
	if ref != self.cards {
		eraseStore = &directoryErasureTestSharedStore{testEraseStore: store, erasureRef: self.cards.evs.as(eraserId)}
	}
	index, err := directoryNewErasureIndex(&indexEraserArgs{
		store: store, eraseStore: eraseStore, repoId: evsTestId("directory repo"), refId: ref.refId,
		repoKind: protocol.RepoKind_REPO_KIND_DIRECTORY, companion: ref.companion, isAdmin: ref.world.isAdmin,
		format: ref.world.settings, eraser: eraserId, complete: self.complete, refKey: ref.refKey, tables: testHeadTables,
		mayMerge: func() bool { return true }, clock: &testIndexWorldClock{world: ref.world}, log: NewNoopLogger(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return &directoryErasureTestRefIndex{directoryEvsErasureIndex: index, refs: self, ref: ref}
}

// Which erasures are complete while their newest ERASE on the erasure ref says so as readers read it: the binding's
// judge ((*EvsErasure).completionState).
func (self *DirectoryErasureTestRefs) complete(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
	erasures := self.cards.evs
	erasures.stateLock.Lock()
	defer erasures.stateLock.Unlock()
	indexes := make([]int, 0, len(erasures.erases))
	for index := range erasures.erases {
		indexes = append(indexes, index)
	}
	return recordEraseCompleteByNewest(indexes, func(index int) (Id, bool, bool) {
		erase, read := erasures.erases[index], erasures.readErasedWithLock(index)
		return erase.erasureId, read.complete, !erase.completion || read.complete
	}), nil
}

// Enters writerId's document name at version in the ref named name, in a push of its own as the push carrying the card,
// repo file or announce entry did, naming the head's epoch.
func (self *DirectoryErasureTestRefs) Enter(name string, writerId Id, document []byte, version uint64) {
	self.t.Helper()
	ctx := context.Background()
	ref := self.ref(name)
	key, err := indexDocKey(ref.refKey, ref.refId, document, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	store := ref.world.ref.store(writerId)
	view, err := indexLoadView(ctx, &indexViewArgs{
		store: store, repoId: evsTestId("directory repo"), refId: ref.refId, repoKind: protocol.RepoKind_REPO_KIND_DIRECTORY,
		companion: ref.companion, isAdmin: ref.world.isAdmin, settings: ref.world.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		self.t.Fatal(err)
	}
	keys := testHeadKeys(len(document)+int(version), 0)
	row := testFileRow(keys)
	if ref.companion {
		// ur/index's rows name the stream the entry came from
		row.refId = evsTestId("directory stream of " + writerId.String()).Bytes()
	}
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: writerId, signedTimeMs: ref.world.at.UnixMilli(), tables: testHeadTables,
		pending: []*indexPendingDocument{{kind: indexEntryFull, key: key, version: version, keys: keys, row: row}},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	if plan.mergeFirst || plan.mergeInPush {
		self.t.Fatalf("a document's push that cannot commit by itself: %+v", plan)
	}
	push, err := guard.push(indexPushIndex, ref.world.at.UnixMilli(), plan.files(), plan.removals())
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := store.Commit(ctx, push); err != nil {
		self.t.Fatal(err)
	}
	ref.world.at = ref.world.at.Add(time.Minute)
}

// Tells the erasure ref of each ERASE the record streams committed since the last call, in order: erasures is every
// ERASE of the directory the streams hold, oldest first.
func (self *DirectoryErasureTestRefs) NoteStreamErasures(erasures []*RecordStreamErasure) {
	self.stateLock.Lock()
	from := self.streamErasureCount
	self.streamErasureCount = max(from, len(erasures))
	self.stateLock.Unlock()
	if len(erasures) <= from {
		return
	}
	evs := self.cards.evs
	evs.stateLock.Lock()
	defer evs.stateLock.Unlock()
	for _, erasure := range erasures[from:] {
		keys := []*EvsErasedKey{}
		for _, key := range erasure.Keys {
			keys = append(keys, &EvsErasedKey{SlotId: key.SlotId, KeyIndex: uint16(key.KeyIndex)})
		}
		for _, key := range erasure.destroyedKeys() {
			evs.destroyed[key.SlotId] = true
		}
		evs.erases = append(evs.erases, &testEraseErase{
			erasureId:  erasure.ErasureId,
			erased:     &indexEraseErased{keys: keys, complete: erasure.Complete, timeMs: erasure.TimeMillis},
			completion: erasure.Completion,
			note:       bytes.Clone(erasure.SealedNote),
		})
		evs.eraseTimes = append(evs.eraseTimes, time.UnixMilli(erasure.TimeMillis))
	}
}

// Tells the erasure ref of an ERASE of the cards' keys that committed under args.ErasureId, in its place: its keys
// gone, and whether it said complete. One whose keys were all gone committed nothing.
func (self *DirectoryErasureTestRefs) NoteErase(args *EvsEraseArgs) {
	evs := self.cards.evs
	evs.stateLock.Lock()
	defer evs.stateLock.Unlock()
	keys := []*EvsErasedKey{}
	for _, key := range args.Keys {
		if !evs.destroyed[key.SlotId] {
			keys = append(keys, &EvsErasedKey{SlotId: key.SlotId, KeyIndex: key.KeyIndex})
		}
	}
	if len(keys) == 0 {
		return
	}
	for _, key := range keys {
		evs.destroyed[key.SlotId] = true
	}
	evs.erases = append(evs.erases, &testEraseErase{
		erasureId: args.ErasureId,
		erased:    &indexEraseErased{keys: keys, complete: args.Complete, timeMs: self.cards.world.at.UnixMilli()},
		note:      bytes.Clone(args.Note),
	})
	evs.eraseTimes = append(evs.eraseTimes, self.cards.world.at)
}

// The erasure's ERASEs on the erasure ref: how many committed, how many of them completion ERASEs, and whether the
// newest says complete as readers read it.
func (self *DirectoryErasureTestRefs) Erases(erasureId Id) (int, int, bool) {
	evs := self.cards.evs
	evs.stateLock.Lock()
	defer evs.stateLock.Unlock()
	count, completions, complete := 0, 0, false
	for index, erase := range evs.erases {
		if erase.erasureId != erasureId {
			continue
		}
		count += 1
		if erase.completion {
			completions += 1
		}
		complete = evs.readErasedWithLock(index).complete
	}
	return count, completions, complete
}

// Whether an ERASE of the erasure that says complete committed before its first CUT on either ref, or with no CUT of
// it at all: what DESIGN-DETAILS 15.2.10's step 2 forbids.
func (self *DirectoryErasureTestRefs) CompleteBeforeCut(erasureId Id) bool {
	before := math.MaxInt
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, cut := range self.cuts {
			if cut.ErasureId == erasureId {
				before = min(before, cut.EraseCount)
			}
		}
	}()
	evs := self.cards.evs
	evs.stateLock.Lock()
	defer evs.stateLock.Unlock()
	for index, erase := range evs.erases {
		if before <= index {
			break
		}
		if erase.erasureId == erasureId && evs.readErasedWithLock(index).complete {
			return true
		}
	}
	return false
}

// The CUTs committed, in order.
func (self *DirectoryErasureTestRefs) Cuts() []*DirectoryErasureTestCut {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.cuts)
}

// The index at the ref's head as a reader of it sees it.
func (self *DirectoryErasureTestRefs) view(ref *directoryErasureTestRef) *indexView {
	self.t.Helper()
	view, err := indexLoadView(context.Background(), &indexViewArgs{
		store: ref.world.ref.store(evsTestId("directory index reader")), repoId: evsTestId("directory repo"), refId: ref.refId,
		repoKind: protocol.RepoKind_REPO_KIND_DIRECTORY, companion: ref.companion, isAdmin: ref.world.isAdmin,
		settings: ref.world.settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return view
}

// Whether the set at the ref's head lists erasureId.
func (self *DirectoryErasureTestRefs) Lists(name string, erasureId Id) bool {
	self.t.Helper()
	return indexErasureOf(self.view(self.ref(name)).erasureSet, erasureId) != nil
}

// The version the set at the ref's head lists document at for erasureId, 0 for none.
func (self *DirectoryErasureTestRefs) ListedVersion(name string, erasureId Id, document []byte) uint64 {
	self.t.Helper()
	ref := self.ref(name)
	key, err := indexDocKey(ref.refKey, ref.refId, document, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	erasure := indexErasureOf(self.view(ref).erasureSet, erasureId)
	for _, erased := range erasure.GetDocs() {
		if bytes.Equal(erased.GetDocKey(), key[:]) {
			return erased.GetVersion()
		}
	}
	return 0
}

// Every stored version of an index file of the ref named name that holds an entry of document, at any version, under
// a key no ERASE destroyed, as path@version: what a current reader's keys still open.
func (self *DirectoryErasureTestRefs) Readable(name string, document []byte) []string {
	self.t.Helper()
	ref := self.ref(name)
	key, err := indexDocKey(ref.refKey, ref.refId, document, 0)
	if err != nil {
		self.t.Fatal(err)
	}
	return self.readable(ref, indexEraseListed{key: math.MaxUint64})
}

// The stored versions of ref's index files holding an entry listed takes under a key no ERASE destroyed.
func (self *DirectoryErasureTestRefs) readable(ref *directoryErasureTestRef, listed indexEraseListed) []string {
	self.t.Helper()
	erasures := self.cards.evs
	erasures.stateLock.Lock()
	destroyed := map[Id]bool{}
	for slotId := range erasures.destroyed {
		destroyed[slotId] = true
	}
	erasures.stateLock.Unlock()
	readable := []string{}
	for path, versions := range ref.evs.versions() {
		parsed, ok := indexParsePath(path, ref.companion)
		if !ok || !indexPathHoldsDocuments(parsed.kind) {
			continue
		}
		for _, version := range versions {
			if destroyed[version.slotId] {
				continue
			}
			holds, err := indexHolds(parsed, version.plaintext, listed, ref.world.settings)
			if err != nil {
				self.t.Fatal(err)
			}
			if holds {
				readable = append(readable, fmt.Sprintf("%s@%d", path, version.file.version))
			}
		}
	}
	slices.Sort(readable)
	return readable
}

// FI-19's index and keys clauses on both refs: no stored version of an index file, every version being kept, holds an
// entry the set at its ref's head lists, at or below its listed version, under a key a current reader can obtain.
func (self *DirectoryErasureTestRefs) Sweep() {
	self.t.Helper()
	for _, ref := range []*directoryErasureTestRef{self.cards, self.streams} {
		listed := indexEraseListed(indexErasureSetListed(self.view(ref).erasureSet))
		if readable := self.readable(ref, listed); len(readable) != 0 {
			self.t.Fatalf("on %s stored index versions holding a listed entry still open: %v", ref.name, readable)
		}
	}
}
