//go:build !sidecar_http && !ios_extension

// A bridge for the directory erasure's completion tests (directory_erasure_completion_test.go; QD-1132, QD-1137): one
// index ref of the team directory on the index's in-memory fake (evs_index_fake_test.go and evs_index_erase_test.go's
// fake evs), the index's real eraser behind DirectoryErasureIndex as DirectoryEvsErasure.index builds it, its CUTs
// reading an erasure complete while its newest ERASE says so, as that binding's do, and what the tests read back: whether
// the set lists an erasure, and its ERASEs. The directory's other ERASEs, of its cards' keys, go to the tests' model of
// the cards ref: a tap tells the fake of each, so one ordered list holds every ERASE of an erasure, as evs's erasure ref
// does. Beside it, format 2's half of an erasure as a device takes it up where another device began it.

package sidecar

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// One index ref of the directory on the fake, its erasers signing as the sidecars they name.
type DirectoryErasureTestIndex struct {
	t      testing.TB
	world  *testHeadWorld
	evs    *testEraseEvs
	refKey []byte
	refId  Id
}

// The ref, a set version counting where one of admins signed it.
func NewDirectoryErasureTestIndex(t testing.TB, admins ...Id) *DirectoryErasureTestIndex {
	world := testNewHeadWorld()
	world.admins = slices.Clone(admins)
	return &DirectoryErasureTestIndex{
		t: t, world: world, evs: testNewEraseEvs(world), refKey: bytes.Repeat([]byte{0x5e}, 32),
		refId: evsTestId("directory index ref"),
	}
}

// The ref's eraser signing as eraserId, built afresh at each call as each pass of a device builds one, by the
// binding's own constructor (directoryNewErasureIndex), so it reads an erasure's progress by its newest ERASE.
func (self *DirectoryErasureTestIndex) Open(eraserId Id) DirectoryErasureIndex {
	self.t.Helper()
	store := self.evs.as(eraserId)
	index, err := directoryNewErasureIndex(&indexEraserArgs{
		store: store, eraseStore: store, repoId: evsTestId("directory repo"), refId: self.refId,
		repoKind: protocol.RepoKind_REPO_KIND_DIRECTORY, isAdmin: self.world.isAdmin, format: self.world.settings,
		eraser: eraserId, complete: self.complete, refKey: self.refKey, tables: testHeadTables,
		mayMerge: func() bool { return true }, clock: &testIndexWorldClock{world: self.world}, log: NewNoopLogger(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return index
}

// Which erasures are complete while their newest ERASE says so as readers read it, a completion that completes
// nothing changing nothing: the directory's binding's judge ((*EvsErasure).completionState).
func (self *DirectoryErasureTestIndex) complete(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	indexes := make([]int, 0, len(self.evs.erases))
	for index := range self.evs.erases {
		indexes = append(indexes, index)
	}
	return recordEraseCompleteByNewest(indexes, func(index int) (Id, bool, bool) {
		erase, read := self.evs.erases[index], self.evs.readErasedWithLock(index)
		return erase.erasureId, read.complete, !erase.completion || read.complete
	}), nil
}

// Tells the fake of an ERASE of the cards' keys that committed under args.ErasureId, in its place among the erasure's
// ERASEs: its keys gone, and whether it said complete. One whose keys were all gone committed nothing.
func (self *DirectoryErasureTestIndex) NoteErase(args *EvsEraseArgs) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	keys := []*EvsErasedKey{}
	for _, key := range args.Keys {
		if !self.evs.destroyed[key.SlotId] {
			keys = append(keys, &EvsErasedKey{SlotId: key.SlotId, KeyIndex: key.KeyIndex})
		}
	}
	if len(keys) == 0 {
		return
	}
	for _, key := range keys {
		self.evs.destroyed[key.SlotId] = true
	}
	self.evs.erases = append(self.evs.erases, &testEraseErase{
		erasureId: args.ErasureId,
		erased:    &indexEraseErased{keys: keys, complete: args.Complete, timeMs: self.world.at.UnixMilli()},
		note:      bytes.Clone(args.Note),
	})
	self.evs.eraseTimes = append(self.evs.eraseTimes, self.world.at)
}

// Whether the history the ref's eraser walks reads whole from now: false leaves every rewrite unproven, as where the
// store could not walk it.
func (self *DirectoryErasureTestIndex) SetHistoryWhole(whole bool) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	self.evs.retainedIncomplete = !whole
}

// Whether the set at the ref's head lists erasureId.
func (self *DirectoryErasureTestIndex) Lists(erasureId Id) bool {
	self.t.Helper()
	return indexErasureOf(self.world.view(self.t, evsTestId("directory index reader")).erasureSet, erasureId) != nil
}

// The erasure's ERASEs on the fake, the tap's among them: how many committed, how many of them completion ERASEs, and
// whether the newest says complete as readers read it.
func (self *DirectoryErasureTestIndex) Erases(erasureId Id) (int, int, bool) {
	self.evs.stateLock.Lock()
	defer self.evs.stateLock.Unlock()
	count, completions, complete := 0, 0, false
	for index, erase := range self.evs.erases {
		if erase.erasureId != erasureId {
			continue
		}
		count += 1
		if erase.completion {
			completions += 1
		}
		complete = self.evs.readErasedWithLock(index).complete
	}
	return count, completions, complete
}

// Format 2's half of erasureId as this device takes it up where another device began it, as the runner's work for a
// request whose ERASE it reads (directoryErasureWork.began): nothing found at this sync, and every ref's rewrite read
// owed, its own progress read from evs's state.
func (self *DirectoryClient) EraseBegunFilesForTest(ctx context.Context, erasureId Id, reason RecordErasureReason) (*DirectoryErasureFilesResult, error) {
	work := newDirectoryErasureWork()
	work.erasureId, work.reason, work.began = erasureId, reason, true
	return self.eraseFiles(ctx, work)
}
