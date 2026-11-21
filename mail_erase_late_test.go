// Interrupted mail publication and erasure on separate devices. All stores are private to the test.

package sidecar

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// Interrupts a normal ingest at the last store write and optionally loses its result.
type mailLateIngestTestStore struct {
	mailEraseStore
	before func()
	after  error
}

func (self *mailLateIngestTestStore) Write(ctx context.Context, writes []*mailStoreWrite) ([]uint64, error) {
	if self.before != nil {
		before := self.before
		self.before = nil
		before()
	}
	versions, err := self.mailEraseStore.Write(ctx, writes)
	if err == nil && self.after != nil {
		return nil, self.after
	}
	return versions, err
}

// The original ERASE completed on a deposit alone. Ingest then commits the body and row
// and dies before learning either that the write landed or that the message is erased.
func TestMailEraseResumesLateIngestAfterTerminalDepositErase(t *testing.T) {
	world := newMailEraseTestWorld(t)
	ctx := t.Context()
	kept := world.ingestMessages("keep")
	message := testMailIngestMessage("late", "private body")
	trailer := testMailIngestTrailer(world.receiverId, message)
	trailer.Evidence.ReceiveTimeMillis++
	deposit := world.repo.deposit(world.receiverId, world.receiverId, testMailIngestPlaintext(t, message, trailer))
	messagePath := MailMessagePath(world.month, deposit.id)
	segmentPath := MailIndexPath(world.month, 0)
	view := NewMailView(&MailViewArgs{MailboxId: world.repoId, Mailbox: world.eraseStore, Settings: DefaultMailStoreSettings()})
	join, err := NewMailSearchJoin(&MailSearchJoinArgs{View: view.args, Clock: world.clock})
	if err != nil {
		t.Fatal(err)
	}
	if err := join.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("lost the ingest result")
	ingestor := world.slotIngestor()
	var original Id
	ingestor.index.store = &mailLateIngestTestStore{mailEraseStore: world.eraseStore, after: crash, before: func() {
		erasure, err := world.eraser().Erase(ctx, world.month, []Id{deposit.id})
		if err != nil || erasure.State != MailErasureDone {
			t.Fatalf("deposit-only erasure: %+v, %v", erasure, err)
		}
		original = erasure.ErasureId
	}}
	if _, err := ingestor.Ingest(ctx); !errors.Is(err, crash) {
		t.Fatalf("ingest did not stop after commit: %v", err)
	}
	bodySlots := world.eraseStore.slotIdsOf(messagePath)
	segmentSlots := world.eraseStore.slotIdsOf(segmentPath)
	if len(bodySlots) == 0 || len(segmentSlots) == 0 || !slices.Contains(world.rowIds(), deposit.id) {
		t.Fatal("fixture did not leave a late publication")
	}
	if err := join.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	show, _, err := searchJoinMailHit(ctx, join, SearchJoinAsk{Spam: true, Trash: true}, world.repoId, &indexRow{docKind: indexDocMail, locator: messagePath})
	if err != nil || show {
		t.Fatalf("a cached search released the erased row: %t, %v", show, err)
	}
	if _, err := view.Entry(ctx, world.month, deposit.id); !errors.Is(err, ErrMailViewEntryAbsent) {
		t.Fatalf("an interim mail read released the erased row: %v", err)
	}
	page, err := view.List(ctx, &MailListArgs{Limit: 1})
	if err != nil || len(page.Entries) != 1 || mailEntryId(page.Entries[0].Entry) != kept[0] || page.Next != nil {
		t.Fatalf("interim list: %+v, %v", page, err)
	}
	// A new admin with neither process's state discovers the completed erasure on its regular ingest pass.
	restarted := world.slotIngestor()
	restarted.eraser = world.eraser()
	if pass, err := restarted.Ingest(ctx); err != nil || pass.Erased != 1 || pass.Consumed != 1 || pass.Ingested != 0 {
		t.Fatalf("admin restart: %+v, %v", pass, err)
	}
	for _, slot := range append(bodySlots, segmentSlots...) {
		if world.eraseStore.slotHeld(slot) {
			t.Fatal("a late body or old segment slot still has its key")
		}
	}
	if !slices.Equal(world.rowIds(), kept) || len(world.eraseStore.openableVersions(segmentPath)) != 1 {
		t.Fatal("the re-checkpoint lost the neighbor or retained the erased row")
	}
	rows, err := world.eraseStore.Erasures(ctx, 0)
	if err != nil || len(rows) != 3 || rows[1].ErasureId != original || rows[1].Complete || !mailErasureComplete(rows, original) {
		t.Fatalf("reopening and completing the same erasure: %+v, %v", rows, err)
	}
	if resumed, err := world.eraser().Resume(ctx); err != nil || len(resumed) != 0 {
		t.Fatalf("repeat restart: %+v, %v", resumed, err)
	}
}

// A writer that survives checks the erasure before announcing the message or forwarding it.
func TestMailIngestWithholdsCallbacksAfterConcurrentErase(t *testing.T) {
	world := newMailEraseTestWorld(t)
	ctx := t.Context()
	deposit := world.depositMessage(testMailIngestMessage("late", "body"))
	ingestor := world.slotIngestor()
	ingestor.args.Message = func(*MailMessage) { t.Fatal("announced a message after its ERASE committed") }
	ingestor.index.store = &mailLateIngestTestStore{mailEraseStore: world.eraseStore, before: func() {
		if _, err := world.eraser().Erase(ctx, world.month, []Id{deposit.id}); err != nil {
			t.Fatal(err)
		}
	}}
	ingestor.eraser = world.eraser()
	pass, err := ingestor.Ingest(ctx)
	if err != nil || pass.Erased != 1 || pass.Ingested != 0 || pass.Consumed != 1 || len(world.rowIds()) != 0 {
		t.Fatalf("ingest: %+v, %v", pass, err)
	}
}

// Runs an ingest between the eraser's authenticated inventory and its initial slot deletion.
type mailConsumeBeforeEraseTestStore struct {
	mailEraseStore
	before func()
}

func (self *mailConsumeBeforeEraseTestStore) Erase(ctx context.Context, args *EvsEraseArgs) error {
	if self.before != nil {
		before := self.before
		self.before = nil
		before()
	}
	return self.mailEraseStore.Erase(ctx, args)
}

// A consumed deposit can answer NOTHING_TO_ERASE. The body and its row were
// published first, and an ERASE of just the missing slot left no signed tombstone.
func TestMailEraseReinventoriesWhenConsumeWinsItsFirstErase(t *testing.T) {
	world := newMailEraseTestWorld(t)
	ctx := t.Context()
	deposit := world.depositMessage(testMailIngestMessage("consume", "body"))
	eraser := world.eraser()
	eraser.store = &mailConsumeBeforeEraseTestStore{mailEraseStore: world.eraseStore, before: func() {
		if pass, err := world.slotIngestor().Ingest(ctx); err != nil || pass.Ingested != 1 || pass.Consumed != 1 {
			t.Fatalf("concurrent consume: %+v, %v", pass, err)
		}
		world.eraseStore.vaultLock.Lock()
		delete(world.eraseStore.heldSlotIds, deposit.slotId)
		world.eraseStore.vaultLock.Unlock()
	}}
	result, err := eraser.Erase(ctx, world.month, []Id{deposit.id})
	if err != nil || result.State != MailErasureDone || len(world.rowIds()) != 0 {
		t.Fatalf("erase: %+v, %v", result, err)
	}
	if versions := world.eraseStore.openableVersions(MailMessagePath(world.month, deposit.id)); len(versions) != 0 {
		t.Fatalf("body still opens at %v", versions)
	}
	rows, err := world.eraseStore.Erasures(ctx, 0)
	if err != nil || len(rows) != 2 || !mailErasureComplete(rows, result.ErasureId) {
		t.Fatalf("signed erasures: %+v, %v", rows, err)
	}
}
