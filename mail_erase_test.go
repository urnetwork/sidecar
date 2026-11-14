// MAIL-M7-16's erasure on the vault's store stand-in, which keeps a slot per chain and loses a version with its
// slot's key: FS-13's erased message, row and deposit; a 429 that waits and resumes (FS-47's mail case); restarts
// between the erasure's steps; a writer racing a CLOSURE; the refusals; the trash shred and its clock guard.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The erase store in memory: the vault's stand-in with CLOSUREs, each a checkpoint of its path in a new slot, and
// the push time of a path's newest version.
type mailEraseTestStore struct {
	*mailVaultTestStore

	eraseLock sync.Mutex
	closures  []*EvsClosure
	// the next CLOSURE fails with this before it writes, once
	failClosure error
	// the next ERASE after the first fails with this before it commits, once: a crash between a CLOSURE and its ERASE
	failErase   error
	eraseCount  int
	pushTimes   map[string]time.Time
	closedPaths []string
}

func newMailEraseTestStore() *mailEraseTestStore {
	return &mailEraseTestStore{mailVaultTestStore: newMailVaultTestStore(), pushTimes: map[string]time.Time{}}
}

func (self *mailEraseTestStore) Versions(ctx context.Context, path string) ([]*EvsHistoryVersion, error) {
	versions, err := self.mailVaultTestStore.Versions(ctx, path)
	if err == nil && 0 < len(versions) {
		self.eraseLock.Lock()
		defer self.eraseLock.Unlock()
		versions[0].Time = self.pushTimes[path]
	}
	return versions, err
}

func (self *mailEraseTestStore) Erase(ctx context.Context, args *EvsEraseArgs) error {
	fail := func() error {
		self.eraseLock.Lock()
		defer self.eraseLock.Unlock()
		self.eraseCount += 1
		if err := self.failErase; err != nil && 1 < self.eraseCount {
			self.failErase = nil
			return err
		}
		return nil
	}()
	if fail != nil {
		return fail
	}
	return self.mailVaultTestStore.Erase(ctx, args)
}

func (self *mailEraseTestStore) Closure(ctx context.Context, erasureId Id, path string, content []byte, ifVersion uint64, erased []*EvsErasedKey) error {
	fail := func() error {
		self.eraseLock.Lock()
		defer self.eraseLock.Unlock()
		err := self.failClosure
		self.failClosure = nil
		return err
	}()
	if fail != nil {
		return fail
	}
	func() {
		// a whole checkpoint under a fresh key
		self.vaultLock.Lock()
		defer self.vaultLock.Unlock()
		self.chainCounts[path] = self.chainLength
	}()
	versions, err := self.mailVaultTestStore.Write(ctx, []*mailStoreWrite{{Path: path, Content: content, IfVersion: ifVersion}})
	if err != nil {
		return err
	}
	self.eraseLock.Lock()
	defer self.eraseLock.Unlock()
	self.closures = append(self.closures, &EvsClosure{Version: versions[0], ErasureId: erasureId, Keys: slices.Clone(erased)})
	self.closedPaths = append(self.closedPaths, path)
	return nil
}

func (self *mailEraseTestStore) Closures(ctx context.Context) ([]*EvsClosure, error) {
	self.eraseLock.Lock()
	defer self.eraseLock.Unlock()
	return slices.Clone(self.closures), nil
}

func (self *mailEraseTestStore) slotHeld(slotId Id) bool {
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	return self.heldSlotIds[slotId]
}

// A deposit's slot, which holds its key until an ERASE or a CONSUME takes it.
func (self *mailEraseTestStore) holdSlot(slotId Id) {
	self.vaultLock.Lock()
	defer self.vaultLock.Unlock()
	self.heldSlotIds[slotId] = true
}

// Whether the admin answer is yes.
type mailEraseTestAuthority struct {
	admin bool
}

func (self *mailEraseTestAuthority) Erases(repoId Id, sidecarId Id) bool {
	return self.admin
}

// What a device's local purge was handed.
type mailEraseTestPurge struct {
	messageIds []Id
}

func (self *mailEraseTestPurge) PurgeMail(ctx context.Context, repoId Id, messageIds []Id) error {
	self.messageIds = append(self.messageIds, messageIds...)
	return nil
}

// A mailbox with ingest and an eraser over one erase store.
type mailEraseTestWorld struct {
	*mailIngestTestWorld
	eraseStore *mailEraseTestStore
	authority  *mailEraseTestAuthority
	purge      *mailEraseTestPurge
	clock      *mailTestClock
	events     []*SidecarErasure
	month      MailYearMonth
}

func newMailEraseTestWorld(t *testing.T) *mailEraseTestWorld {
	world := &mailEraseTestWorld{
		mailIngestTestWorld: newMailIngestTestWorld(t), eraseStore: newMailEraseTestStore(),
		authority: &mailEraseTestAuthority{admin: true}, purge: &mailEraseTestPurge{},
		clock: &mailTestClock{now: time.UnixMilli(int64(testMailIngestPushMillis))},
		month: MailYearMonthOf(testMailIngestReceiveMillis),
	}
	world.store = world.eraseStore.mailTestStore
	world.repo.slotHeld = world.eraseStore.slotHeld
	world.repo.onDeposit = world.eraseStore.holdSlot
	world.repo.erasureSource = world.eraseStore.Erasures
	return world
}

// An ingestor writing through the erase store, so each write takes a slot.
func (self *mailEraseTestWorld) slotIngestor() *MailIngestor {
	args := &MailIngestArgs{SidecarId: NewId(), Root: testMailIngestRoot, Authority: self.mailIngestTestWorld.authority}
	return newMailIngestor(self.repoId, self.repo, self.eraseStore, args)
}

// An eraser as a device makes one: a restart, or another admin's device.
func (self *mailEraseTestWorld) eraser() *MailEraser {
	return newMailEraser(self.repoId, self.eraseStore, self.repo, &MailEraserArgs{
		SidecarId: NewId(), Authority: self.authority, Purge: self.purge, Clock: self.clock,
		Progress: func(erasure *SidecarErasure) { self.events = append(self.events, erasure) },
	})
}

// Deposits and ingests one message a subject, and gives their ids.
func (self *mailEraseTestWorld) ingestMessages(subjects ...string) []Id {
	self.t.Helper()
	ids := []Id{}
	for _, subject := range subjects {
		ids = append(ids, self.depositMessage(testMailIngestMessage(subject, "body")).id)
	}
	if pass, err := self.slotIngestor().Ingest(context.Background()); err != nil || pass.Ingested != len(subjects) {
		self.t.Fatalf("ingest: %+v, %v", pass, err)
	}
	return ids
}

// The ids of the month's i/ rows, as stored, whether or not a key opens them.
func (self *mailEraseTestWorld) rowIds() []Id {
	self.t.Helper()
	ids := []Id{}
	for _, entry := range self.entries(self.month) {
		ids = append(ids, Id(entry.GetId()))
	}
	return ids
}

// FS-13: an erased message's body, its row and its unconsumed deposit are gone, and nothing brings it back. The
// first ERASE names the messages and takes the bodies' and the deposit's keys; the segment is written again without
// their rows and every older version of it loses its key; this device's copies are purged; and a later ingest
// consumes the deposits with no message.
func TestMailEraseDestroysTheBodyTheRowAndTheDeposit(t *testing.T) {
	world := newMailEraseTestWorld(t)
	ctx := context.Background()
	kept := world.ingestMessages("Kept", "Also kept")
	// a message whose CONSUME was lost, so its deposit stands beside its m/
	leftover := world.depositMessage(testMailIngestMessage("Leftover", "body"))
	world.repo.failConsumeBefore = errors.New("killed before the CONSUME")
	if _, err := world.slotIngestor().Ingest(ctx); err == nil {
		t.Fatal("the kill did not stop the pass")
	}
	// a deposit no reader took yet
	unread := world.depositMessage(testMailIngestMessage("Unread", "body"))
	if world.repo.standingCount(world.receiverId) != 2 || world.store.file(MailMessagePath(world.month, leftover.id)) == nil {
		t.Fatal("the leftover deposit should stand beside its message")
	}

	segmentPath := MailIndexPath(world.month, 0)
	olderVersions := world.eraseStore.openableVersions(segmentPath)
	erasure, err := world.eraser().Erase(ctx, world.month, []Id{leftover.id, unread.id})
	if err != nil || erasure.State != MailErasureDone || erasure.SegmentsLeft != 0 {
		t.Fatalf("erase: %+v, %v", erasure, err)
	}
	if _, _, err := world.eraseStore.Read(ctx, MailMessagePath(world.month, leftover.id), 1024*1024); !errors.Is(err, ErrEvsEntryRefused) {
		t.Errorf("the erased body still opens: %v", err)
	}
	if len(world.eraseStore.openableVersions(MailMessagePath(world.month, leftover.id))) != 0 {
		t.Error("a version of the erased body keeps its key")
	}
	if ids := world.rowIds(); !slices.Equal(ids, kept) {
		t.Errorf("rows after the erasure: %d, want the 2 kept", len(ids))
	}
	if openable := world.eraseStore.openableVersions(segmentPath); len(openable) != 1 || slices.Contains(olderVersions, openable[0]) {
		t.Errorf("the segment's versions with a key: %v, before %v", openable, olderVersions)
	}
	for _, id := range kept {
		if _, _, err := world.eraseStore.Read(ctx, MailMessagePath(world.month, id), 1024*1024); err != nil {
			t.Errorf("a kept body does not open: %v", err)
		}
	}
	erasures, _ := world.eraseStore.Erasures(ctx, 0)
	if len(erasures) != 2 || erasures[0].Complete || !erasures[1].Complete || erasures[0].ErasureId != erasure.ErasureId || erasures[1].ErasureId != erasure.ErasureId {
		t.Fatalf("erases %+v", erasures)
	}
	messages, segments, ok := parseMailErasureNote(erasures[0].Note)
	if !ok || len(messages) != 2 || len(segments) != 0 || len(erasures[0].Keys) != 3 {
		t.Errorf("the first ERASE names %d messages and %d keys", len(messages), len(erasures[0].Keys))
	}
	if _, segments, ok := parseMailErasureNote(erasures[1].Note); !ok || !slices.Equal(segments, []mailErasedSegment{{Month: world.month, N: 0}}) {
		t.Errorf("the part's ERASE names %v", segments)
	}
	if !slices.Equal(world.purge.messageIds, []Id{leftover.id, unread.id}) {
		t.Errorf("purged %d messages", len(world.purge.messageIds))
	}
	if len(world.events) != 1 || world.events[0].State != MailErasureDone || world.events[0].ErasureId != erasure.ErasureId {
		t.Errorf("events %+v", world.events)
	}

	// neither deposit opens, and ingest consumes both with no message
	pass, err := world.slotIngestor().Ingest(ctx)
	if err != nil || pass.Erased != 2 || pass.Ingested != 0 || pass.Consumed != 2 || world.repo.standingCount(world.receiverId) != 0 {
		t.Fatalf("ingest after the erasure: %+v, %v", pass, err)
	}
	if ids := world.rowIds(); !slices.Equal(ids, kept) || world.store.file(MailMessagePath(world.month, unread.id)) != nil {
		t.Error("an erased deposit came back")
	}
	// erasing them again destroys nothing more
	again, err := world.eraser().Erase(ctx, world.month, []Id{leftover.id, unread.id})
	if erasures, _ := world.eraseStore.Erasures(ctx, 0); err != nil || again.State != MailErasureDone || len(erasures) != 2 {
		t.Errorf("erasing again: %+v, %v", again, err)
	}
}

// FS-47's mail case: a part evs refuses 429 leaves the erasure waiting, its bodies gone and its rows still listed,
// with the time to try again and the estimate at the floor; Resume after the wait finishes it from evs alone.
func TestMailEraseRefused429WaitsAndResumes(t *testing.T) {
	world := newMailEraseTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One", "Two", "Three")
	world.eraseStore.failClosure = &EvsError{Status: http.StatusTooManyRequests, RetryAfter: 90 * time.Second}
	erasure, err := world.eraser().Erase(ctx, world.month, ids[:2])
	if err != nil || erasure.State != MailErasureWaiting || erasure.SegmentsLeft != 1 || erasure.BytesLeft <= 0 {
		t.Fatalf("a refused part: %+v, %v", erasure, err)
	}
	if !erasure.NextTry.Equal(world.clock.Now().Add(90 * time.Second)) {
		t.Errorf("next try %s", erasure.NextTry)
	}
	// under the floor's bytes a day: the next 00:00 UTC
	if want := world.clock.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour); !erasure.Finish.Equal(want) {
		t.Errorf("finish %s, want %s", erasure.Finish, want)
	}
	event := world.events[len(world.events)-1]
	if event.State != MailErasureWaiting || event.ObjectsLeft != 1 || !event.NextTry.Equal(erasure.NextTry) {
		t.Errorf("event %+v", event)
	}
	if len(world.eraseStore.openableVersions(MailMessagePath(world.month, ids[0]))) != 0 || len(world.rowIds()) != 3 {
		t.Error("while waiting: the bodies should be gone and the rows still listed")
	}

	// another admin's device resumes with nothing but evs
	resumed, err := world.eraser().Resume(ctx)
	if err != nil || len(resumed) != 1 || resumed[0].ErasureId != erasure.ErasureId || resumed[0].State != MailErasureDone {
		t.Fatalf("resume: %+v, %v", resumed, err)
	}
	if rows := world.rowIds(); !slices.Equal(rows, ids[2:]) {
		t.Errorf("rows after the resume: %d", len(rows))
	}
	erasures, _ := world.eraseStore.Erasures(ctx, 0)
	if len(erasures) != 2 || !erasures[1].Complete {
		t.Errorf("erases after the resume: %d", len(erasures))
	}
	if resumed, err := world.eraser().Resume(ctx); err != nil || len(resumed) != 0 {
		t.Errorf("a resume with nothing left: %+v, %v", resumed, err)
	}
}

// A restart mid-erasure resumes: killed after the first ERASE, the restarted device re-keys the segment; killed
// between a CLOSURE and its ERASE, it finds the CLOSURE and destroys the keys it lists, completing the erasure.
func TestMailEraseResumesAfterARestartAtEachStep(t *testing.T) {
	for _, step := range []string{"before the closure", "between the closure and its erase"} {
		world := newMailEraseTestWorld(t)
		ctx := context.Background()
		ids := world.ingestMessages("One", "Two")
		segmentPath := MailIndexPath(world.month, 0)
		killed := errors.New("killed " + step)
		if step == "before the closure" {
			world.eraseStore.failClosure = killed
		} else {
			world.eraseStore.failErase = killed
		}
		erasure, err := world.eraser().Erase(ctx, world.month, ids[:1])
		if !errors.Is(err, killed) || erasure == nil || erasure.State != MailErasureRewriting {
			t.Fatalf("%s: %+v, %v", step, erasure, err)
		}
		if step != "before the closure" && len(world.eraseStore.openableVersions(segmentPath)) < 2 {
			t.Fatalf("%s: the replaced chain's keys should still stand", step)
		}
		resumed, err := world.eraser().Resume(ctx)
		if err != nil || len(resumed) != 1 || resumed[0].State != MailErasureDone || resumed[0].ErasureId != erasure.ErasureId {
			t.Fatalf("%s: resume %+v, %v", step, resumed, err)
		}
		if rows := world.rowIds(); !slices.Equal(rows, ids[1:]) {
			t.Errorf("%s: rows %d", step, len(rows))
		}
		if openable := world.eraseStore.openableVersions(segmentPath); len(openable) != 1 {
			t.Errorf("%s: %d versions of the segment keep a key", step, len(openable))
		}
		erasures, _ := world.eraseStore.Erasures(ctx, 0)
		if len(erasures) != 2 || !erasures[1].Complete || len(world.eraseStore.closedPaths) != 1 {
			t.Errorf("%s: %d erases, %d closures", step, len(erasures), len(world.eraseStore.closedPaths))
		}
	}
}

// A device whose i/ write meets the CLOSURE's 409 re-applies without the erased rows: an ingest's append that lost
// to an erasure lands on the segment the CLOSURE left.
func TestMailIndexWriterLosingToAClosureWritesNoErasedRowBack(t *testing.T) {
	world := newMailEraseTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One", "Two")
	later := world.depositMessage(testMailIngestMessage("Later", "body"))
	// the erasure lands between the ingest's read of the segment and its push
	world.store.beforeWrite = func() {
		if erasure, err := world.eraser().Erase(ctx, world.month, ids[:1]); err != nil || erasure.State != MailErasureDone {
			t.Errorf("the racing erasure: %+v, %v", erasure, err)
		}
	}
	if pass, err := world.slotIngestor().Ingest(ctx); err != nil || pass.Ingested != 1 {
		t.Fatalf("the ingest that lost: %+v, %v", pass, err)
	}
	if rows := world.rowIds(); !slices.Equal(rows, []Id{ids[1], later.id}) {
		t.Errorf("rows after the race: %d", len(rows))
	}
}

// The refusals: a sidecar that does not administer the repo, a message that never stood, and a general repo's
// versions, which name no slot, each with nothing destroyed.
func TestMailEraseRefusals(t *testing.T) {
	world := newMailEraseTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One")
	world.authority.admin = false
	eraser := world.eraser()
	if _, err := eraser.Erase(ctx, world.month, ids); !errors.Is(err, ErrMailNotEraser) {
		t.Errorf("a non-admin erase: %v", err)
	}
	if _, err := eraser.Resume(ctx); !errors.Is(err, ErrMailNotEraser) {
		t.Errorf("a non-admin resume: %v", err)
	}
	if _, err := eraser.ShredTrash(ctx); !errors.Is(err, ErrMailNotEraser) {
		t.Errorf("a non-admin shred: %v", err)
	}
	unbound := newMailEraser(world.repoId, world.eraseStore, world.repo, &MailEraserArgs{SidecarId: NewId()})
	if _, err := unbound.Erase(ctx, world.month, ids); !errors.Is(err, ErrMailNotEraser) {
		t.Errorf("an erase with no authority: %v", err)
	}
	world.authority.admin = true
	if _, err := world.eraser().Erase(ctx, world.month, []Id{ids[0], NewId()}); !errors.Is(err, ErrMailMessageAbsent) {
		t.Errorf("a message that never stood: %v", err)
	}
	if erasures, _ := world.eraseStore.Erasures(ctx, 0); len(erasures) != 0 {
		t.Fatalf("a refused erase destroyed keys: %d", len(erasures))
	}

	group := newMailEraseTestWorld(t)
	group.eraseStore.slotless = true
	groupIds := group.ingestMessages("To the group")
	if _, err := group.eraser().Erase(ctx, group.month, groupIds); !errors.Is(err, ErrMailNotShreddable) {
		t.Errorf("a general repo's message: %v", err)
	}
	if erasures, _ := group.eraseStore.Erasures(ctx, 0); len(erasures) != 0 || len(group.purge.messageIds) != 0 {
		t.Error("a message that cannot be shredded was claimed erased")
	}
}

// A reader's Refresh purges this device's copies of what another device erased, once.
func TestMailEraseRefreshPurgesWhatAnotherDeviceErased(t *testing.T) {
	world := newMailEraseTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("One", "Two")
	readerPurge := &mailEraseTestPurge{}
	reader := newMailEraser(world.repoId, world.eraseStore, world.repo, &MailEraserArgs{SidecarId: NewId(), Purge: readerPurge})
	if erased, err := reader.Refresh(ctx); err != nil || len(erased) != 0 {
		t.Fatalf("a refresh with no erasure: %v, %v", erased, err)
	}
	if _, err := world.eraser().Erase(ctx, world.month, ids[:1]); err != nil {
		t.Fatal(err)
	}
	if erased, err := reader.Refresh(ctx); err != nil || !slices.Equal(erased, ids[:1]) || !slices.Equal(readerPurge.messageIds, ids[:1]) {
		t.Fatalf("the reader's refresh: %v, %v, purged %d", erased, err, len(readerPurge.messageIds))
	}
	if erased, err := reader.Refresh(ctx); err != nil || len(erased) != 0 || len(readerPurge.messageIds) != 1 {
		t.Errorf("a second refresh: %v, %v", erased, err)
	}
}

// The trash shred: a message in trash for 30 days is erased, one in trash for less waits, and one taken out of
// trash stays. A trash a slow clock dated in the past is not shredded before 30 days from its flags' push.
func TestMailShredTrashErasesAfterRetentionAndGuardsASlowClock(t *testing.T) {
	world := newMailEraseTestWorld(t)
	ctx := context.Background()
	ids := world.ingestMessages("Old trash", "New trash", "Restored", "Slow clock", "Kept")
	start := world.clock.Now()
	flagPath := MailFlagPath(world.month, 0)
	trash := func(clock Clock, messageId Id, set bool) {
		t.Helper()
		writer := NewMailFlagWriter(world.eraseStore, NewMailHlc(clock), NewId(), DefaultMailStoreSettings())
		if _, err := writer.Apply(ctx, []*MailFlagChange{{Month: world.month, MessageId: messageId, Kind: protocol.MailFlagKind_MAIL_FLAG_TRASH, Set: set}}); err != nil {
			t.Fatal(err)
		}
		world.eraseStore.eraseLock.Lock()
		defer world.eraseStore.eraseLock.Unlock()
		world.eraseStore.pushTimes[flagPath] = world.clock.Now()
	}
	trash(world.clock, ids[0], true)
	trash(world.clock, ids[2], true)
	// a device whose clock is 60 days slow trashes a message
	trash(&mailTestClock{now: start.Add(-60 * 24 * time.Hour)}, ids[3], true)
	world.clock.now = start.Add(10 * 24 * time.Hour)
	trash(world.clock, ids[2], false)

	// 30 days after the first trash, its flags last pushed 20 days ago: nothing is dated before that push
	world.clock.now = start.Add(30 * 24 * time.Hour)
	shred, err := world.eraser().ShredTrash(ctx)
	if err != nil || len(shred.Erasures) != 0 || shred.Waiting != 2 {
		t.Fatalf("before the guard's time: %+v, %v", shred, err)
	}
	trash(world.clock, ids[1], true)
	world.clock.now = start.Add(59 * 24 * time.Hour)
	if shred, err := world.eraser().ShredTrash(ctx); err != nil || len(shred.Erasures) != 0 || shred.Waiting != 3 {
		t.Fatalf("29 days after the flags' last push: %+v, %v", shred, err)
	}
	world.clock.now = start.Add(60 * 24 * time.Hour)
	shred, err = world.eraser().ShredTrash(ctx)
	if err != nil || len(shred.Erasures) != 1 || shred.Erasures[0].State != MailErasureDone || shred.Waiting != 0 {
		t.Fatalf("at the retention: %+v, %v", shred, err)
	}
	erased := slices.Clone(shred.Erasures[0].MessageIds)
	want := []Id{ids[0], ids[1], ids[3]}
	slices.SortFunc(erased, mailIdCompare)
	slices.SortFunc(want, mailIdCompare)
	if !slices.Equal(erased, want) {
		t.Errorf("shredded %d messages, want the 3 in trash", len(erased))
	}
	rows := world.rowIds()
	slices.SortFunc(rows, mailIdCompare)
	kept := []Id{ids[2], ids[4]}
	slices.SortFunc(kept, mailIdCompare)
	if !slices.Equal(rows, kept) {
		t.Errorf("rows after the shred: %d, want the restored and the kept", len(rows))
	}
	if shred, err := world.eraser().ShredTrash(ctx); err != nil || len(shred.Erasures) != 0 {
		t.Errorf("a second shred: %+v, %v", shred, err)
	}
}

// §11.13's bound at the floor: the ⌈bytes / floor⌉-th 00:00 UTC after the time to try again.
func TestMailEraseFinishIsTheFloorsBound(t *testing.T) {
	nextTry := time.Date(2026, time.November, 14, 9, 30, 0, 0, time.UTC)
	floor := int64(3008 * 1024)
	for bytesLeft, want := range map[int64]time.Time{
		1:          time.Date(2026, time.November, 15, 0, 0, 0, 0, time.UTC),
		floor:      time.Date(2026, time.November, 15, 0, 0, 0, 0, time.UTC),
		floor + 1:  time.Date(2026, time.November, 16, 0, 0, 0, 0, time.UTC),
		10 * floor: time.Date(2026, time.November, 24, 0, 0, 0, 0, time.UTC),
	} {
		if finish := mailEraseFinish(nextTry, bytesLeft, floor); !finish.Equal(want) {
			t.Errorf("%d bytes left: %s, want %s", bytesLeft, finish, want)
		}
	}
	if !mailEraseFinish(nextTry, 0, floor).IsZero() || !mailEraseFinish(nextTry, 1, 0).IsZero() {
		t.Error("no bytes or no floor gives an estimate")
	}
}
