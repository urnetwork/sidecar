// MAIL-M10-02's erasure in a format-2 mailbox, on MAIL-M7-16's store stand-in with the search index's eraser faked at
// mail's seam (mailIndexEraser): the CUT before the first ERASE; a batch's one CUT; the documents a CUT lists and the
// note that carries them; a full erasure set, an allowance and an unproven rewrite; who resumes when; the journal
// between a CUT and its first ERASE; and the refusals that destroy nothing. The index's own eraser takes mail's CUT in
// mail_erase_index_evs_test.go.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A sealed directory in memory: the journal's.
type mailEraseTestJournalStore struct {
	stateLock sync.Mutex
	files     map[string][]byte
}

func newMailEraseTestJournalStore() *mailEraseTestJournalStore {
	return &mailEraseTestJournalStore{files: map[string][]byte{}}
}

func (self *mailEraseTestJournalStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	data, ok := self.files[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (self *mailEraseTestJournalStore) Create(name string) (SidecarStoreWriter, error) {
	return &mailEraseTestJournalWriter{store: self, name: name}, nil
}

func (self *mailEraseTestJournalStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.files, name)
	return nil
}

func (self *mailEraseTestJournalStore) List(prefix string) ([]SidecarStoreEntry, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := []SidecarStoreEntry{}
	for name, data := range self.files {
		if strings.HasPrefix(name, prefix) {
			entries = append(entries, SidecarStoreEntry{Name: name, ByteCount: int64(len(data))})
		}
	}
	slices.SortFunc(entries, func(a SidecarStoreEntry, b SidecarStoreEntry) int { return strings.Compare(a.Name, b.Name) })
	return entries, nil
}

func (self *mailEraseTestJournalStore) Directory(name string, class string) (SidecarStore, error) {
	return self, nil
}

func (self *mailEraseTestJournalStore) count() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.files)
}

type mailEraseTestJournalWriter struct {
	store  *mailEraseTestJournalStore
	name   string
	buffer bytes.Buffer
}

func (self *mailEraseTestJournalWriter) Write(data []byte) (int, error) {
	return self.buffer.Write(data)
}

func (self *mailEraseTestJournalWriter) Commit() error {
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	self.store.files[self.name] = bytes.Clone(self.buffer.Bytes())
	return nil
}

func (self *mailEraseTestJournalWriter) Close() error {
	return nil
}

// One device's view of the erase store: its ERASEs carry its sidecar and the world's time, and each ERASE and CLOSURE
// is logged in the world's order.
type mailEraseIndexTestStore struct {
	*mailEraseTestStore
	world  *mailEraseIndexTestWorld
	signer Id
}

func (self *mailEraseIndexTestStore) Erase(ctx context.Context, args *EvsEraseArgs) error {
	if err := self.world.takeEraseFailure(); err != nil {
		return err
	}
	before := len(self.committedErasures())
	if err := self.mailEraseTestStore.Erase(ctx, args); err != nil {
		return err
	}
	func() {
		self.vaultLock.Lock()
		defer self.vaultLock.Unlock()
		if before < len(self.erasures) {
			committed := self.erasures[len(self.erasures)-1]
			committed.EraserSidecarId, committed.Time = self.signer, self.world.clock.Now()
		}
	}()
	if before < len(self.committedErasures()) {
		self.world.note("erase")
	}
	return nil
}

func (self *mailEraseIndexTestStore) Closure(ctx context.Context, erasureId Id, path string, content []byte, ifVersion uint64, erased []*EvsErasedKey) error {
	if err := self.mailEraseTestStore.Closure(ctx, erasureId, path, content, ifVersion, erased); err != nil {
		return err
	}
	self.world.note("closure")
	return nil
}

// The search index's eraser as mail's seam sees it: an erasure set, the index files' keys as slots of the erase store,
// and whatever the test says the rewrite meets.
type mailEraseIndexTestEraser struct {
	world *mailEraseIndexTestWorld
	// the device this eraser signs as
	store *mailEraseIndexTestStore

	cuts    []*IndexCutArgs
	resumes []*IndexResumeArgs
}

func (self *mailEraseIndexTestEraser) Cut(ctx context.Context, args *IndexCutArgs) (*IndexCutResult, error) {
	world := self.world
	self.cuts = append(self.cuts, args)
	if world.cutErr != nil {
		return nil, world.cutErr
	}
	if world.setFull {
		return &IndexCutResult{}, ErrIndexErasureSetFull
	}
	if _, listed := world.listed[args.ErasureId]; !listed {
		world.listed[args.ErasureId] = args.Documents
		world.cutTimes[args.ErasureId] = world.clock.Now()
		world.note("cut")
		return &IndexCutResult{Pushed: true, Version: uint64(len(world.listed))}, nil
	}
	return &IndexCutResult{}, nil
}

func (self *mailEraseIndexTestEraser) Resume(ctx context.Context, args *IndexResumeArgs) (*IndexResumeResult, error) {
	world := self.world
	self.resumes = append(self.resumes, args)
	world.note("index")
	result := &IndexResumeResult{}
	if args.Role == IndexResumeMember {
		if notBefore := world.cutTimes[args.ErasureId].Add(DefaultIndexEraseSettings().ResumeAfter); world.clock.Now().Before(notBefore) {
			result.NotBefore = notBefore
			return result, nil
		}
	}
	if _, listed := world.listed[args.ErasureId]; !listed {
		if len(args.Documents) == 0 {
			return result, ErrIndexEraseNotCut
		}
		cut, err := self.Cut(ctx, &IndexCutArgs{ErasureId: args.ErasureId, Documents: args.Documents})
		result.Cut = cut
		if err != nil {
			return result, err
		}
	}
	if world.waiting != nil {
		waiting := *world.waiting
		waiting.ErasureId = args.ErasureId
		result.Rewrite = &IndexRewriteResult{Erasure: &waiting}
		return result, nil
	}
	result.Rewrite = &IndexRewriteResult{Unproven: world.unproven, Erasure: &SidecarErasure{ErasureId: args.ErasureId, State: SidecarErasureRewriting}}
	if slotId := world.indexSlotId; slotId != (Id{}) && self.store.slotHeld(slotId) {
		// one index file holds the documents: its pair's ERASE destroys its old key
		complete := args.Complete && !world.unproven
		err := self.store.Erase(ctx, &EvsEraseArgs{
			ErasureId: args.ErasureId, Keys: []*EvsErasedKey{{SlotId: slotId}}, Complete: complete, Note: args.Note,
		})
		if err != nil {
			return result, err
		}
		result.Rewrite.PairCount, result.Rewrite.FileCount, result.Rewrite.KeyCount, result.Rewrite.Completed = 1, 1, 1, complete
		if complete {
			result.Rewrite.Erasure.State = SidecarErasureDone
		}
	}
	return result, nil
}

// A format-2 mailbox: MAIL-M7-16's world with the index's eraser faked and a journal.
type mailEraseIndexTestWorld struct {
	*mailEraseTestWorld
	journal *mailEraseTestJournalStore

	stateLock sync.Mutex
	// each CUT, index step, ERASE and CLOSURE, in order
	steps []string
	// the next ERASE fails with this before it commits, once
	eraseFailure error

	// the erasure set: each listed erasure's documents and its CUT's time
	listed   map[Id][]*IndexCutDocument
	cutTimes map[Id]time.Time
	// what the index's eraser meets
	setFull  bool
	cutErr   error
	waiting  *SidecarErasure
	unproven bool
	// the slot of the one index file holding the messages, zero for an index that holds none
	indexSlotId Id
}

func newMailEraseIndexTestWorld(t *testing.T) *mailEraseIndexTestWorld {
	return &mailEraseIndexTestWorld{
		mailEraseTestWorld: newMailEraseTestWorld(t), journal: newMailEraseTestJournalStore(),
		listed: map[Id][]*IndexCutDocument{}, cutTimes: map[Id]time.Time{},
	}
}

func (self *mailEraseIndexTestWorld) note(step string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.steps = append(self.steps, step)
}

func (self *mailEraseIndexTestWorld) taken() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	steps := self.steps
	self.steps = nil
	return steps
}

func (self *mailEraseIndexTestWorld) takeEraseFailure() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	err := self.eraseFailure
	self.eraseFailure = nil
	return err
}

// The doc_key the stand-in gives a chunk of a path.
func testMailEraseDocKey(path string, chunk uint32) ([indexIdByteCount]byte, error) {
	digest := sha256.Sum256(binary.BigEndian.AppendUint32([]byte(path), chunk))
	return [indexIdByteCount]byte(digest[:indexIdByteCount]), nil
}

// An index file's slot holding the messages' postings, its key standing.
func (self *mailEraseIndexTestWorld) holdIndexFile() {
	self.indexSlotId = NewEvsSlotId()
	self.eraseStore.holdSlot(self.indexSlotId)
}

// A format-2 eraser as a device makes one, signing as sidecarId, with or without the device's journal, and the index's
// eraser it reaches.
func (self *mailEraseIndexTestWorld) format2Eraser(sidecarId Id, journal SidecarStore, settings *MailEraseSettings) (*MailEraser, *mailEraseIndexTestEraser) {
	store := &mailEraseIndexTestStore{mailEraseTestStore: self.eraseStore, world: self, signer: sidecarId}
	eraser := newMailEraser(self.repoId, store, self.repo, &MailEraserArgs{
		SidecarId: sidecarId, Authority: self.authority, Purge: self.purge, Clock: self.clock, Journal: journal, Settings: settings,
		Progress: func(erasure *SidecarErasure) { self.events = append(self.events, erasure) },
	})
	index := &mailEraseIndexTestEraser{world: self, store: store}
	eraser.indexOpen = func(ctx context.Context) (*mailEraseIndex, error) {
		return &mailEraseIndex{eraser: index, docKey: testMailEraseDocKey, format: DefaultIndexFormatSettings()}, nil
	}
	return eraser, index
}

// The committed ERASEs that say complete.
func (self *mailEraseIndexTestWorld) completeCount() int {
	count := 0
	for _, erasure := range self.eraseStore.committedErasures() {
		if erasure.Complete {
			count += 1
		}
	}
	return count
}

// §15.7's order in a format-2 mailbox: the CUT listing the messages' documents, the first ERASE of their bodies' keys,
// the index's files, then the i/ segment's CLOSURE and the ERASE that completes the erasure. The first ERASE's note
// carries each message's version and chunk count, and the event says fenced then done.
func TestMailEraseFormat2CutsBeforeTheFirstEraseAndCompletesLast(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One", "Two", "Kept")
	world.holdIndexFile()
	world.taken()
	eraser, index := world.format2Eraser(NewId(), world.journal, nil)
	erasure, err := eraser.Erase(ctx, world.month, ids[:2])
	if err != nil || erasure.State != MailErasureDone || !erasure.Fenced || erasure.Unproven {
		t.Fatalf("erase: %+v, %v", erasure, err)
	}
	if steps := world.taken(); !slices.Equal(steps, []string{"cut", "erase", "index", "erase", "closure", "erase"}) {
		t.Fatalf("the steps %v", steps)
	}
	if len(index.cuts) != 1 || index.cuts[0].ErasureId != erasure.ErasureId || len(index.cuts[0].Documents) != 2 {
		t.Fatalf("the CUT: %+v", index.cuts)
	}
	for position, id := range ids[:2] {
		path := MailMessagePath(world.month, id)
		key, _ := testMailEraseDocKey(path, 0)
		versions, err := world.eraseStore.Versions(ctx, path)
		if err != nil {
			t.Fatal(err)
		}
		if document := index.cuts[0].Documents[position]; document.Key != key || document.Version != versions[0].Version || document.ThroughEpoch {
			t.Errorf("document %d: %+v, want the path's chunk 0 at version %d", position, document, versions[0].Version)
		}
	}
	// the index's step ends nothing while an i/ segment is left to carry complete
	if len(index.resumes) != 1 || index.resumes[0].Complete || index.resumes[0].Role != IndexResumeEraser || len(index.resumes[0].Documents) != 2 {
		t.Fatalf("the index's step: %+v", index.resumes[0])
	}
	erasures := world.eraseStore.committedErasures()
	if len(erasures) != 3 || erasures[0].Complete || erasures[1].Complete || !erasures[2].Complete {
		t.Fatalf("the ERASEs: %d", len(erasures))
	}
	messages, _, ok := parseMailErasureNote(erasures[0].Note)
	if !ok || len(messages) != 2 || messages[0].ChunkCount != 1 || messages[0].Version == 0 || messages[0].MessageId != ids[0] {
		t.Fatalf("the first ERASE's note: %+v", messages)
	}
	if world.eraseStore.slotHeld(world.indexSlotId) {
		t.Error("the index file's old key stands")
	}
	if rows := world.rowIds(); !slices.Equal(rows, ids[2:]) {
		t.Errorf("rows after the erasure: %d", len(rows))
	}
	if world.journal.count() != 0 {
		t.Error("the journal keeps an erasure whose first ERASE committed")
	}
	if len(world.events) != 1 || world.events[0].State != MailErasureDone {
		t.Errorf("events %+v", world.events)
	}
}

// A format-1 mailbox has no CUT: the eraser reaches no index, and its ERASE's note names paths alone.
func TestMailEraseFormat1HasNoCut(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One")
	eraser, index := world.format2Eraser(NewId(), world.journal, nil)
	eraser.indexOpen = func(ctx context.Context) (*mailEraseIndex, error) { return nil, nil }
	erasure, err := eraser.Erase(ctx, world.month, ids)
	if err != nil || erasure.State != MailErasureDone || erasure.Fenced {
		t.Fatalf("erase: %+v, %v", erasure, err)
	}
	if len(index.cuts) != 0 || len(index.resumes) != 0 || world.journal.count() != 0 {
		t.Fatal("a format-1 erasure reached the index's eraser")
	}
	messages, _, ok := parseMailErasureNote(world.eraseStore.committedErasures()[0].Note)
	if !ok || len(messages) != 1 || messages[0].ChunkCount != 0 || messages[0].Version != 0 {
		t.Fatalf("the note: %+v", messages)
	}
}

// A CUT with the index off: the index holds no file of the messages, so the CUT still commits first, the index's step
// rewrites nothing, and the i/ part's ERASE completes the erasure.
func TestMailEraseFormat2CutsWithTheIndexOff(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One")
	world.taken()
	eraser, index := world.format2Eraser(NewId(), world.journal, nil)
	erasure, err := eraser.Erase(ctx, world.month, ids)
	if err != nil || erasure.State != MailErasureDone || !erasure.Fenced {
		t.Fatalf("erase: %+v, %v", erasure, err)
	}
	if steps := world.taken(); !slices.Equal(steps, []string{"cut", "erase", "index", "closure", "erase"}) {
		t.Fatalf("the steps %v", steps)
	}
	if len(index.cuts) != 1 || world.completeCount() != 1 {
		t.Fatalf("%d CUTs, %d complete ERASEs", len(index.cuts), world.completeCount())
	}
}

// A batch trash shred is one CUT: a month's due messages go in one erasure whose CUT lists all of them, and past
// ShredBatchMessageCount in one erasure a batch.
func TestMailShredTrashFormat2IsOneCutABatch(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One", "Two", "Three", "Kept")
	writer := NewMailFlagWriter(world.eraseStore, NewMailHlc(world.clock), NewId(), DefaultMailStoreSettings())
	for _, id := range ids[:3] {
		if _, err := writer.Apply(ctx, []*MailFlagChange{{Month: world.month, MessageId: id, Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true}}); err != nil {
			t.Fatal(err)
		}
	}
	func() {
		world.eraseStore.eraseLock.Lock()
		defer world.eraseStore.eraseLock.Unlock()
		world.eraseStore.pushTimes[MailFlagPath(world.month, 0)] = world.clock.Now()
	}()
	world.clock.now = world.clock.now.Add(31 * 24 * time.Hour)
	eraser, index := world.format2Eraser(NewId(), world.journal, nil)
	shred, err := eraser.ShredTrash(ctx)
	if err != nil || len(shred.Erasures) != 1 || shred.Erasures[0].State != MailErasureDone {
		t.Fatalf("shred: %+v, %v", shred, err)
	}
	if len(index.cuts) != 1 || len(index.cuts[0].Documents) != 3 || len(world.listed) != 1 {
		t.Fatalf("%d CUTs listing %d erasures", len(index.cuts), len(world.listed))
	}
	if rows := world.rowIds(); !slices.Equal(rows, ids[3:]) {
		t.Errorf("rows after the shred: %d", len(rows))
	}

	// two a batch: three due messages are two erasures, each with its one CUT
	batched := newMailEraseIndexTestWorld(t)
	batchedIds := batched.ingestMessages("One", "Two", "Three")
	batchedWriter := NewMailFlagWriter(batched.eraseStore, NewMailHlc(batched.clock), NewId(), DefaultMailStoreSettings())
	for _, id := range batchedIds {
		if _, err := batchedWriter.Apply(ctx, []*MailFlagChange{{Month: batched.month, MessageId: id, Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: true}}); err != nil {
			t.Fatal(err)
		}
	}
	func() {
		batched.eraseStore.eraseLock.Lock()
		defer batched.eraseStore.eraseLock.Unlock()
		batched.eraseStore.pushTimes[MailFlagPath(batched.month, 0)] = batched.clock.Now()
	}()
	batched.clock.now = batched.clock.now.Add(31 * 24 * time.Hour)
	settings := DefaultMailEraseSettings()
	settings.ShredBatchMessageCount = 2
	batchedEraser, batchedIndex := batched.format2Eraser(NewId(), batched.journal, settings)
	shred, err = batchedEraser.ShredTrash(ctx)
	if err != nil || len(shred.Erasures) != 2 || len(batchedIndex.cuts) != 2 || len(batched.rowIds()) != 0 {
		t.Fatalf("the batched shred: %+v, %v, %d CUTs", shred, err, len(batchedIndex.cuts))
	}
}

// A full erasure set makes the CUT wait and holds back no ERASE: the bodies' keys go at once, the erasure waits with
// its rows still listed, and a later resume, on any admin's device after the eraser's 25 h, commits the CUT from the
// documents the first ERASE's note carries and finishes.
func TestMailEraseFormat2AFullSetWaitsWithoutHoldingTheFirstErase(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One", "Kept")
	world.holdIndexFile()
	world.setFull = true
	eraser, index := world.format2Eraser(NewId(), world.journal, nil)
	erasure, err := eraser.Erase(ctx, world.month, ids[:1])
	if err != nil || erasure.State != MailErasureWaiting || erasure.Fenced || erasure.SegmentsLeft != 1 {
		t.Fatalf("erase: %+v, %v", erasure, err)
	}
	if want := world.clock.Now().Add(DefaultMailEraseSettings().CutRetryInterval); !erasure.NextTry.Equal(want) {
		t.Errorf("the next try %s, want %s", erasure.NextTry, want)
	}
	if len(world.eraseStore.openableVersions(MailMessagePath(world.month, ids[0]))) != 0 {
		t.Fatal("the body kept its key while the CUT waited")
	}
	if len(world.listed) != 0 || len(world.rowIds()) != 2 || world.completeCount() != 0 {
		t.Fatal("the waiting erasure went past its first ERASE")
	}
	// still full: the resume waits again
	if resumed, err := eraser.Resume(ctx); err != nil || len(resumed) != 1 || resumed[0].State != MailErasureWaiting {
		t.Fatalf("the resume at a full set: %+v, %v", resumed, err)
	}
	world.setFull = false
	// another admin's device, whose only source of the documents is the note
	other, otherIndex := world.format2Eraser(NewId(), newMailEraseTestJournalStore(), nil)
	resumed, err := other.Resume(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].State != MailErasureDone || resumed[0].ErasureId != erasure.ErasureId {
		t.Fatalf("the resume: %+v, %v", resumed, err)
	}
	key, _ := testMailEraseDocKey(MailMessagePath(world.month, ids[0]), 0)
	documents := world.listed[erasure.ErasureId]
	if len(documents) != 1 || documents[0].Key != key || documents[0].Version != index.cuts[0].Documents[0].Version {
		t.Fatalf("the CUT the resume committed: %+v", documents)
	}
	if len(otherIndex.resumes) != 1 || len(otherIndex.resumes[0].Documents) != 1 {
		t.Fatalf("the resume's documents: %+v", otherIndex.resumes)
	}
	if rows := world.rowIds(); !slices.Equal(rows, ids[1:]) || world.completeCount() != 1 || world.eraseStore.slotHeld(world.indexSlotId) {
		t.Error("the resumed erasure left a row, a key or no complete")
	}
}

// The index's wait is the erasure's: its objects, bytes, next try and finish show in the event, the i/ segment's
// bytes pushing the finish out at the floor, and no i/ part runs until the index's pairs do. The resume then finishes.
func TestMailEraseFormat2WaitsOnTheIndexesAllowance(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One")
	world.holdIndexFile()
	now := world.clock.Now()
	nextTry := indexNextUtcMidnight(now)
	world.waiting = &SidecarErasure{State: SidecarErasureWaiting, ObjectsLeft: 2, BytesLeft: 9000, NextTry: nextTry, Finish: nextTry.Add(time.Second)}
	eraser, _ := world.format2Eraser(NewId(), world.journal, nil)
	erasure, err := eraser.Erase(ctx, world.month, ids)
	if err != nil || erasure.State != MailErasureWaiting || !erasure.Fenced {
		t.Fatalf("erase: %+v, %v", erasure, err)
	}
	if erasure.IndexObjectsLeft != 2 || erasure.IndexBytesLeft != 9000 || erasure.SegmentsLeft != 1 || !erasure.NextTry.Equal(nextTry) {
		t.Fatalf("the wait: %+v", erasure)
	}
	// the i/ segment follows the index's last pair: one more 00:00 UTC at the floor
	if want := nextTry.Add(24 * time.Hour); !erasure.Finish.Equal(want) {
		t.Errorf("the finish %s, want %s", erasure.Finish, want)
	}
	event := world.events[len(world.events)-1]
	if event.State != SidecarErasureWaiting || event.ObjectsLeft != 3 || event.BytesLeft != 9000+erasure.BytesLeft || !event.NextTry.Equal(nextTry) {
		t.Errorf("the event: %+v", event)
	}
	if len(world.eraseStore.closedPaths) != 0 || len(world.rowIds()) != 1 || len(world.eraseStore.openableVersions(MailMessagePath(world.month, ids[0]))) != 0 {
		t.Fatal("the waiting erasure kept its body or ran an i/ part")
	}
	world.waiting = nil
	world.clock.now = nextTry
	resumed, err := eraser.Resume(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].State != MailErasureDone || len(world.rowIds()) != 0 || world.completeCount() != 1 {
		t.Fatalf("the resume: %+v, %v", resumed, err)
	}
}

// An unproven index rewrite fails closed: every key found is destroyed, the row is gone, and no ERASE says complete,
// so the erasure stays rewriting.
func TestMailEraseFormat2UnprovenNeverSaysComplete(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One")
	world.holdIndexFile()
	world.unproven = true
	eraser, _ := world.format2Eraser(NewId(), world.journal, nil)
	erasure, err := eraser.Erase(ctx, world.month, ids)
	if err != nil || erasure.State != MailErasureRewriting || !erasure.Unproven {
		t.Fatalf("erase: %+v, %v", erasure, err)
	}
	if world.completeCount() != 0 || len(world.rowIds()) != 0 || world.eraseStore.slotHeld(world.indexSlotId) {
		t.Fatal("an unproven erasure said complete, or left a row or a key")
	}
	if len(world.eraseStore.openableVersions(MailIndexPath(world.month, 0))) != 1 {
		t.Error("the segment's replaced chain kept a key")
	}
}

// An erasure with no i/ segment left ends with the index's rewrite, whose last ERASE completes it: here a message
// whose row an earlier part already took out while the index waited.
func TestMailEraseFormat2EndsWithTheIndexWhereNoSegmentIsLeft(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One")
	world.holdIndexFile()
	// the index waits, so the erasure stops after its first ERASE
	world.waiting = &SidecarErasure{State: SidecarErasureWaiting, ObjectsLeft: 1, BytesLeft: 100, NextTry: world.clock.Now().Add(time.Hour)}
	eraser, _ := world.format2Eraser(NewId(), world.journal, nil)
	erasure, err := eraser.Erase(ctx, world.month, ids)
	if err != nil || erasure.State != MailErasureWaiting {
		t.Fatalf("erase: %+v, %v", erasure, err)
	}
	// the row goes by another erasure step's CLOSURE and ERASE, which leaves this erasure no segment
	segmentPath := MailIndexPath(world.month, 0)
	content, version, err := world.eraseStore.Read(ctx, segmentPath, mailIndexSegmentReadMaxByteCount)
	if err != nil {
		t.Fatal(err)
	}
	without, removedCount := mailSegmentWithout(content, world.month, []mailErasedMessage{{Month: world.month, MessageId: ids[0]}})
	keys, err := eraser.pathKeys(ctx, segmentPath)
	if err != nil || removedCount != 1 {
		t.Fatal(err)
	}
	if err := world.eraseStore.Closure(ctx, erasure.ErasureId, segmentPath, without, version, keys); err != nil {
		t.Fatal(err)
	}
	if err := world.eraseStore.mailVaultTestStore.Erase(ctx, &EvsEraseArgs{ErasureId: erasure.ErasureId, Keys: keys}); err != nil {
		t.Fatal(err)
	}
	world.waiting = nil
	fresh, index := world.format2Eraser(eraser.sidecarId, world.journal, nil)
	resumed, err := fresh.Resume(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].State != MailErasureDone {
		t.Fatalf("the resume: %+v, %v", resumed, err)
	}
	if len(index.resumes) != 1 || !index.resumes[0].Complete || world.completeCount() != 1 {
		t.Fatalf("the index's step: %+v, %d complete", index.resumes[0], world.completeCount())
	}
}

// Who resumes when (§11.12's reconcile row): the eraser's own device at once; another admin's device only 25 h after
// the CUT, left rewriting with that time until then; any admin's at once when the eraser no longer administers.
func TestMailEraseFormat2AnotherDeviceTakesOverAfter25Hours(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One")
	world.holdIndexFile()
	eraserId := NewId()
	killed := errors.New("killed between the closure and its erase")
	eraser, _ := world.format2Eraser(eraserId, world.journal, nil)
	// the index's pairs run, then the device dies between the i/ CLOSURE and its ERASE
	world.eraseStore.failErase = killed
	world.eraseStore.eraseCount = 0
	begun, err := eraser.Erase(ctx, world.month, ids)
	if !errors.Is(err, killed) || begun == nil || begun.State != MailErasureRewriting {
		t.Fatalf("the kill: %+v, %v", begun, err)
	}
	cutTime := world.cutTimes[begun.ErasureId]
	other, otherIndex := world.format2Eraser(NewId(), newMailEraseTestJournalStore(), nil)
	resumed, err := other.Resume(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].State != MailErasureRewriting || !resumed[0].NextTry.Equal(cutTime.Add(25*time.Hour)) {
		t.Fatalf("another device before 25 h: %+v, %v", resumed, err)
	}
	if otherIndex.resumes[0].Role != IndexResumeMember || world.completeCount() != 0 {
		t.Fatalf("its role %d", otherIndex.resumes[0].Role)
	}
	world.clock.now = cutTime.Add(25 * time.Hour)
	resumed, err = other.Resume(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].State != MailErasureDone || world.completeCount() != 1 {
		t.Fatalf("another device after 25 h: %+v, %v", resumed, err)
	}

	// the eraser's own device resumes at its start, with no wait
	own := newMailEraseIndexTestWorld(t)
	ownIds := own.ingestMessages("One")
	own.holdIndexFile()
	ownEraser, _ := own.format2Eraser(eraserId, own.journal, nil)
	own.eraseStore.failErase = killed
	if _, err := ownEraser.Erase(ctx, own.month, ownIds); !errors.Is(err, killed) {
		t.Fatalf("the kill: %v", err)
	}
	restarted, restartedIndex := own.format2Eraser(eraserId, own.journal, nil)
	resumed, err = restarted.Resume(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].State != MailErasureDone || restartedIndex.resumes[0].Role != IndexResumeEraser {
		t.Fatalf("the eraser's restart: %+v, %v", resumed, err)
	}

	// an eraser that no longer administers the repo: any admin's device takes its erasure at once
	gone := newMailEraseIndexTestWorld(t)
	goneIds := gone.ingestMessages("One")
	gone.holdIndexFile()
	goneEraser, _ := gone.format2Eraser(eraserId, gone.journal, nil)
	gone.eraseStore.failErase = killed
	if _, err := goneEraser.Erase(ctx, gone.month, goneIds); !errors.Is(err, killed) {
		t.Fatalf("the kill: %v", err)
	}
	survivorId := NewId()
	survivor, survivorIndex := gone.format2Eraser(survivorId, newMailEraseTestJournalStore(), nil)
	survivor.authority = &mailEraseIndexTestAuthority{adminIds: []Id{survivorId}}
	resumed, err = survivor.Resume(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].State != MailErasureDone || survivorIndex.resumes[0].Role != IndexResumeAny {
		t.Fatalf("the survivor: %+v, %v", resumed, err)
	}
}

// Only the listed sidecars administer.
type mailEraseIndexTestAuthority struct {
	adminIds []Id
}

func (self *mailEraseIndexTestAuthority) Erases(repoId Id, sidecarId Id) bool {
	return slices.Contains(self.adminIds, sidecarId)
}

// The journal: a device killed between its CUT and its first ERASE destroyed nothing and left nothing in evs a resume
// reads as mail's. Its next step, a restart's Resume here, runs the erasure again under the same id, so the CUT that
// stands is the one the ERASEs name. A device with no journal resumes nothing.
func TestMailEraseFormat2JournalRetriesAnErasureKilledAfterItsCut(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One", "Kept")
	world.holdIndexFile()
	eraserId := NewId()
	eraser, _ := world.format2Eraser(eraserId, world.journal, nil)
	killed := errors.New("killed after the CUT")
	world.eraseFailure = killed
	if erasure, err := eraser.Erase(ctx, world.month, ids[:1]); !errors.Is(err, killed) || erasure != nil {
		t.Fatalf("the kill: %+v, %v", erasure, err)
	}
	if len(world.listed) != 1 || world.journal.count() != 1 || len(world.eraseStore.committedErasures()) != 0 {
		t.Fatalf("after the kill: %d CUTs, %d journaled", len(world.listed), world.journal.count())
	}
	if len(world.eraseStore.openableVersions(MailMessagePath(world.month, ids[0]))) != 1 {
		t.Fatal("the kill destroyed the body")
	}
	// a device without that journal finds nothing to resume
	other, _ := world.format2Eraser(NewId(), newMailEraseTestJournalStore(), nil)
	if resumed, err := other.Resume(ctx); err != nil || len(resumed) != 0 {
		t.Fatalf("a device without the journal: %+v, %v", resumed, err)
	}
	var cutId Id
	for erasureId := range world.listed {
		cutId = erasureId
	}
	restarted, index := world.format2Eraser(eraserId, world.journal, nil)
	resumed, err := restarted.Resume(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].State != MailErasureDone || resumed[0].ErasureId != cutId {
		t.Fatalf("the restart: %+v, %v", resumed, err)
	}
	if len(world.listed) != 1 || len(index.cuts) != 1 || world.journal.count() != 0 || world.completeCount() != 1 {
		t.Fatalf("after the restart: %d CUTs, %d journaled, %d complete", len(world.listed), world.journal.count(), world.completeCount())
	}
	if rows := world.rowIds(); !slices.Equal(rows, ids[1:]) {
		t.Errorf("rows after the restart: %d", len(rows))
	}
	// a second erase of the same message finds it erased
	if again, err := restarted.Erase(ctx, world.month, ids[:1]); err != nil || len(again.MessageIds) != 0 {
		t.Errorf("a second erase: %+v, %v", again, err)
	}
}

// What destroys nothing: a CUT evs refused, after which the journal holds nothing; a batch past one CUT's documents;
// and an index the eraser cannot reach.
func TestMailEraseFormat2RefusalsDestroyNothing(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One", "Two")
	intact := func(label string) {
		t.Helper()
		for _, id := range ids {
			if len(world.eraseStore.openableVersions(MailMessagePath(world.month, id))) != 1 {
				t.Fatalf("%s: a body lost its key", label)
			}
		}
		if len(world.eraseStore.committedErasures()) != 0 || len(world.rowIds()) != 2 {
			t.Fatalf("%s: something was erased", label)
		}
	}
	eraser, index := world.format2Eraser(NewId(), world.journal, nil)
	world.cutErr = &indexRefusal{kind: indexRefusalRetry, retryAfter: time.Minute}
	if erasure, err := eraser.Erase(ctx, world.month, ids); err == nil || erasure != nil || !isIndexRefusal(err, indexRefusalRetry) {
		t.Fatalf("a refused CUT: %+v, %v", erasure, err)
	}
	intact("a refused CUT")
	if world.journal.count() != 0 {
		t.Fatal("a refused CUT stayed journaled")
	}
	// an outcome evs did not settle may have committed: the erasure stays journaled for the resume
	world.cutErr = &indexRefusal{kind: indexRefusalOutcomeUnknown}
	if _, err := eraser.Erase(ctx, world.month, ids); err == nil {
		t.Fatal("an unsettled CUT erased")
	}
	intact("an unsettled CUT")
	if world.journal.count() != 1 {
		t.Fatal("an unsettled CUT left the journal")
	}
	world.cutErr = nil
	for _, entry := range func() []SidecarStoreEntry { entries, _ := world.journal.List(""); return entries }() {
		world.journal.Remove(entry.Name)
	}

	settings := DefaultMailEraseSettings()
	settings.CutDocumentMaxCount = 1
	small, smallIndex := world.format2Eraser(NewId(), world.journal, settings)
	if erasure, err := small.Erase(ctx, world.month, ids); !errors.Is(err, ErrMailEraseBatchTooLarge) || erasure != nil {
		t.Fatalf("a batch past the CUT's bound: %+v, %v", erasure, err)
	}
	intact("a batch past the CUT's bound")
	if len(smallIndex.cuts) != 0 || world.journal.count() != 0 {
		t.Fatal("a refused batch reached the index or the journal")
	}

	unreachable := errors.New("no repo key")
	eraser.index = nil
	eraser.indexOpen = func(ctx context.Context) (*mailEraseIndex, error) { return nil, unreachable }
	if erasure, err := eraser.Erase(ctx, world.month, ids); !errors.Is(err, ErrMailEraseIndexUnavailable) || !errors.Is(err, unreachable) || erasure != nil {
		t.Fatalf("an unreachable index: %+v, %v", erasure, err)
	}
	intact("an unreachable index")
	if len(index.cuts) != 2 {
		t.Fatalf("%d CUTs asked", len(index.cuts))
	}
}

// A deposit no reader took yet has no m/ file and no document in any index: its erasure lists the documents an ingest
// would write, at version 1, to the bound the deposit's size gives, and its first ERASE completes it.
func TestMailEraseFormat2AnUnconsumedDepositCompletesAtItsFirstErase(t *testing.T) {
	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	unread := world.depositMessage(testMailIngestMessage("Unread", "body"))
	world.taken()
	eraser, index := world.format2Eraser(NewId(), world.journal, nil)
	erasure, err := eraser.Erase(ctx, world.month, []Id{unread.id})
	if err != nil || erasure.State != MailErasureDone || !erasure.Fenced {
		t.Fatalf("erase: %+v, %v", erasure, err)
	}
	if steps := world.taken(); !slices.Equal(steps, []string{"cut", "erase"}) {
		t.Fatalf("the steps %v", steps)
	}
	if len(index.cuts[0].Documents) != 1 || index.cuts[0].Documents[0].Version != 1 || world.completeCount() != 1 {
		t.Fatalf("the CUT: %+v", index.cuts[0].Documents[0])
	}
}

// A message's documents are one a 1 MiB chunk of its extracted text: a message that cannot outgrow a chunk is one
// without being read as text, a large one is counted as the index's writer counts it, and one past the read's bound
// is listed to the bound.
func TestMailEraseFormat2ListsEveryChunkOfALargeMessage(t *testing.T) {
	format := DefaultIndexFormatSettings()
	line := "the quick brown fox jumps over the lazy dog and keeps running\r\n"
	body := strings.Repeat(line, 2*format.ChunkByteCount/len(line)+16)
	message := []byte("From: a@example.test\r\nTo: b@example.test\r\nSubject: Large\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + body)
	path := MailMessagePath(MailYearMonthOf(testMailIngestReceiveMillis), NewId())
	count, err := mailIndexChunkCount(path, message, format)
	if err != nil || count != uint32(len(indexExtractMail([]byte(path), message, format))) || count != 3 {
		t.Fatalf("%d chunks, %v", count, err)
	}
	if bound := mailIndexChunkBound(uint64(len(message)), 4, format); bound < count {
		t.Fatalf("the bound %d is under the count %d", bound, count)
	}
	if mailIndexChunkBound(0, 4, format) != 1 || mailIndexChunkBound(uint64(format.ChunkByteCount/4), 4, format) != 1 ||
		mailIndexChunkBound(uint64(format.ChunkByteCount/4+1), 4, format) != 2 {
		t.Fatal("the bound's edges")
	}

	world := newMailEraseIndexTestWorld(t)
	ctx := context.Background()
	eraser, _ := world.format2Eraser(NewId(), world.journal, nil)
	largePath := MailMessagePath(world.month, NewId())
	if _, err := world.eraseStore.Write(ctx, []*mailStoreWrite{{Path: largePath, Content: message}}); err != nil {
		t.Fatal(err)
	}
	mailIndex, err := eraser.indexOf(ctx)
	if err != nil {
		t.Fatal(err)
	}
	version, chunkCount, err := eraser.documentOf(ctx, mailIndex, largePath, 1, 0)
	if err != nil || version != 1 || chunkCount != 3 {
		t.Fatalf("the large message: version %d, %d chunks, %v", version, chunkCount, err)
	}
	documents, err := mailIndex.documents([]mailErasedMessage{{Month: world.month, MessageId: NewId(), Version: 7, ChunkCount: 3}})
	if err != nil || len(documents) != 3 || documents[0].Key == documents[1].Key || documents[2].Version != 7 {
		t.Fatalf("the documents: %+v, %v", documents, err)
	}
	// past the read's bound: every chunk a message at the bound could have
	eraser.settings.MessageMaxByteCount = 1024
	if _, chunkCount, err := eraser.documentOf(ctx, mailIndex, largePath, 1, 0); err != nil || chunkCount != 1 {
		t.Fatalf("past the bound: %d chunks, %v", chunkCount, err)
	}
	eraser.settings.MessageMaxByteCount = 2 * format.ChunkByteCount
	if _, chunkCount, err := eraser.documentOf(ctx, mailIndex, largePath, 1, 0); err != nil || chunkCount != 8 {
		t.Fatalf("past a larger bound: %d chunks, %v", chunkCount, err)
	}
}

// The note's message line: a path alone in format 1, a path with its version and chunk count in format 2, and nothing
// else reads as one.
func TestMailErasureNoteCarriesAMessagesDocuments(t *testing.T) {
	month := MailYearMonthOf(testMailIngestReceiveMillis)
	plain := mailErasedMessage{Month: month, MessageId: NewId()}
	documented := mailErasedMessage{Month: month, MessageId: NewId(), Version: 3, ChunkCount: 5}
	note := mailErasureNote([]mailErasedMessage{plain, documented}, []mailErasedSegment{{Month: month, N: 2}})
	messages, segments, ok := parseMailErasureNote(note)
	if !ok || !slices.Equal(messages, []mailErasedMessage{plain, documented}) || len(segments) != 1 {
		t.Fatalf("the note read back: %+v %+v %t", messages, segments, ok)
	}
	path := MailMessagePath(month, plain.MessageId)
	for _, line := range []string{path + " 3", path + " 0 1", path + " 1 0", path + " 03 1", path + " 3 1 ", path + "  3 1", path + " 3 x", path + " -1 1"} {
		if _, _, ok := parseMailErasureNote([]byte(line)); ok {
			t.Errorf("%q read as a mail note", strings.TrimPrefix(line, path))
		}
	}
	if !mailErasureDocumented(messages) || mailErasureDocumented(messages[:1]) {
		t.Error("which notes name documents")
	}
}
