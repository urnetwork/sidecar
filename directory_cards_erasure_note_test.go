//go:build !sidecar_http && !ios_extension

// QD-1148's backstop on sidecartest's fakes (directory_cards_erasure.go's note row): a directory admin's moderation of a
// card names the announcements it took in its ERASE's sealed note, and the card's writer journals each its last card
// held at the first sync that reads the ERASE, so another erasure's CUT that drops the moderation from the cards ref's
// erasure set before the writer's card returns brings nothing back, however long the writer was off. The fake keeps no
// card keys, so a test commits the moderation's ERASE on the erasure ref itself (FakeDirectoryCards.EraseCardKeys) and
// drops a listing as a later CUT does (DropErased); the eraser's own notes run on directory_erasure_index_test.go's
// model, and the whole order on the real engines in FS-87's index case in the dropped-listing order
// (sidecartest/fault/fs87_index_dropped_evs.go).

package sidecar_test

import (
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An ERASE by eraserId of a card's keys, a fresh slot's, complete, whose sealed note is body.
func (self *testDirectoryWorld) eraseCardKeys(eraserId sidecar.Id, erasureId sidecar.Id, body *protocol.ErasureBody) {
	self.t.Helper()
	note, err := proto.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.cards.EraseCardKeys(self.t.Context(), self.directoryId, eraserId, &sidecar.EvsEraseArgs{
		ErasureId: erasureId, Keys: []*sidecar.EvsErasedKey{{SlotId: sidecar.NewId()}}, Complete: true, Note: note,
	}); err != nil {
		self.t.Fatal(err)
	}
}

// A directory admin's moderation of announcementId, which writerId's card holds at version, as evs takes it
// (directory_erasure.go's order and note rows): the CUT lists its document, moderation's removal takes the card whole,
// and the ERASE of its keys says the erasure complete, its note naming the announcement, or naming none where noted is
// false, as before QD-1148. The world's reader is the admin, which evs mints admin. Answers the erasure's id.
func (self *testDirectoryWorld) moderateCard(writerId sidecar.Id, announcementId sidecar.Id, version uint64, noted bool) sidecar.Id {
	self.t.Helper()
	self.grant(self.readerId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true})
	erasureId := sidecar.NewId()
	self.cards.ListErased(self.directoryId, self.readerId, testAnnouncementDocumentName(&writerId, announcementId), version)
	self.removeFile(self.readerId, sidecar.DirectoryCardPath(writerId))
	body := &protocol.ErasureBody{ErasureId: erasureId.Bytes(), Reason: uint32(sidecar.RecordErasureReasonModeration)}
	if noted {
		body.AnnouncementIds = [][]byte{announcementId.Bytes()}
	}
	self.eraseCardKeys(self.readerId, erasureId, body)
	return erasureId
}

// The card writer's journal of client, failing the test where it does not read.
func testCardJournal(t *testing.T, client *sidecar.DirectoryClient) []*sidecar.DirectoryCardJournaledForTest {
	t.Helper()
	journal, err := client.CardJournalForTest()
	if err != nil {
		t.Fatal(err)
	}
	return journal
}

// Whether journal is exactly announcementId, named by erasureId's note.
func testJournalNoted(journal []*sidecar.DirectoryCardJournaledForTest, announcementId sidecar.Id, erasureId sidecar.Id) bool {
	return len(journal) == 1 && journal[0].AnnouncementId == announcementId && journal[0].NotedBy != nil && *journal[0].NotedBy == erasureId
}

// A directory admin's erasure of a run another member's card holds names the run in its notes (QD-1148): the ERASE of
// the removed card's keys, the erasure's last and complete one, carries the run's id alone in announcement_ids, reason
// moderation, no entry and no request. Its erasure of a run on its own card, a person's, names none.
func TestDirectoryFormat2ModerationNotesNameTheRun(t *testing.T) {
	world, evs := newTestErasureWorld(t)
	world.cards.RaiseFormat(world.directoryId)
	admin := evs.adminDevice(t)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	daemon := world.device(writer)
	now := world.clock.Now().UnixMilli()
	runId, keptId := sidecar.NewId(), sidecar.NewId()
	daemon.writeCard(t, testRunItem(writer.sidecarId, &memberId, runId, 1, now), testRunItem(writer.sidecarId, &memberId, keptId, 1, now))

	admin.mustSync(t)
	result, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: runId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != sidecar.RecordErasureReasonModeration || result.Files == nil || !result.Files.Complete ||
		!slices.Equal(result.Files.RemovedPaths, []string{sidecar.DirectoryCardPath(writer.sidecarId)}) {
		t.Fatalf("the moderation: %+v, files %+v", result, result.Files)
	}
	notes := testErasureNotes(t, evs.allErases())
	if len(notes) == 0 {
		t.Fatal("the moderation's ERASEs carry no note")
	}
	for _, note := range notes {
		if sidecar.RecordErasureReason(note.GetReason()) != sidecar.RecordErasureReasonModeration || len(note.GetEntryIds()) != 0 || len(note.GetRequestId()) != 0 ||
			len(note.GetAnnouncementIds()) != 1 || sidecar.Id(note.GetAnnouncementIds()[0]) != runId {
			t.Fatalf("a moderation's note: reason %d, %d entries, request %x, announcements %x", note.GetReason(), len(note.GetEntryIds()), note.GetRequestId(), note.GetAnnouncementIds())
		}
	}

	adminMemberId := *world.directoryFixture.Sidecars[admin.writer.sidecarId].MemberId
	ownId := sidecar.NewId()
	admin.writeCard(t, testRunItem(admin.writer.sidecarId, &adminMemberId, ownId, 1, world.clock.Now().UnixMilli()))
	erased := len(evs.allErases())
	admin.mustSync(t)
	result, err = admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: ownId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != sidecar.RecordErasureReasonPerson {
		t.Fatalf("the erasure of the admin's own run: reason %d", result.Reason)
	}
	notes = testErasureNotes(t, evs.allErases()[erased:])
	if len(notes) == 0 {
		t.Fatal("the person's erasure sent no note")
	}
	for _, note := range notes {
		if sidecar.RecordErasureReason(note.GetReason()) != sidecar.RecordErasureReasonPerson || len(note.GetAnnouncementIds()) != 0 {
			t.Fatalf("a person's note: reason %d, announcements %x", note.GetReason(), note.GetAnnouncementIds())
		}
	}
}

// A directory admin moderates a run A's card holds while A's daemon still runs it, and another erasure's CUT drops the
// moderation from the cards ref's erasure set before A's card returns (QD-1148): the return reads the set, which lists
// nothing of A's, and still leaves the run out, A's sync having journaled what the moderation's note named; the run it
// kept and its worker item come back two above, and a reader shows those two. B's run, moderated in the same order by
// an ERASE whose note names nothing, as before the note, comes back two above: what no note names, only the set's
// read finds.
func TestDirectoryCardReturnLeavesOutWhatANoteNamedOnceItsListingDropped(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	aMember, bMember := sidecar.NewId(), sidecar.NewId()
	a := world.memberWriter(aMember)
	b := world.memberWriter(bMember)
	world.publish()
	aDevice, bDevice := world.device(a), world.device(b)
	now := world.clock.Now().UnixMilli()
	erasedId, keptId, workerId, unnotedId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	erased := testRunItem(a.sidecarId, &aMember, erasedId, 2, now)
	kept := testRunItem(a.sidecarId, &aMember, keptId, 1, now)
	worker := testWorkerItem(a.sidecarId, &aMember, workerId, 1, now)
	unnoted := testRunItem(b.sidecarId, &bMember, unnotedId, 1, now)
	aDevice.writeCard(t, erased, kept, worker)
	bDevice.writeCard(t, unnoted)

	world.moderateCard(a.sidecarId, erasedId, 2, true)
	world.moderateCard(b.sidecarId, unnotedId, 1, false)
	// a later erasure's CUT, which lists its own document and drops both, complete, from the set
	otherId := sidecar.NewId()
	world.cards.DropErased(world.directoryId, world.readerId,
		testAnnouncementDocumentName(&a.sidecarId, erasedId), testAnnouncementDocumentName(&b.sidecarId, unnotedId))
	world.cards.ListErased(world.directoryId, world.readerId, testAnnouncementDocumentName(&otherId, sidecar.NewId()), 1)
	world.clock.Advance(time.Minute)
	world.publish()

	reads := world.counts().ErasedReads
	returned := aDevice.writeCard(t, erased, kept, worker)
	if versions := testCardWrittenVersions(returned); len(versions) != 2 || versions[keptId] != 3 || versions[workerId] != 3 {
		t.Fatalf("A's card back after the moderation carries %v", versions)
	}
	if !slices.Equal(returned.Moderated, []sidecar.Id{erasedId}) {
		t.Fatalf("A's return left out %v", returned.Moderated)
	}
	if count := world.counts().ErasedReads - reads; count != 1 {
		t.Fatalf("A's return read the erasure set %d times", count)
	}
	again := bDevice.writeCard(t, unnoted)
	if versions := testCardWrittenVersions(again); len(versions) != 1 || versions[unnotedId] != 3 || len(again.Moderated) != 0 {
		t.Fatalf("B's card back after a moderation no note named carries %v, left out %v", versions, again.Moderated)
	}

	reader := world.reader(nil)
	reader.mustSync(t)
	if shown := testItemsOf(t, reader, a.sidecarId); len(shown) != 2 || shown[erasedId] != nil ||
		shown[keptId].Announcement.GetVersion() != 3 || shown[workerId].Announcement.GetVersion() != 3 {
		t.Fatalf("a reader after A's return: %v", shown)
	}
	if shown := testItemsOf(t, reader, b.sidecarId); len(shown) != 1 || shown[unnotedId] == nil {
		t.Fatalf("a reader after B's return: %v", shown)
	}
}

// A writer idle after a moderation journals the note's announcement at its next sync, with no card written (QD-1148):
// another erasure's CUT has dropped the moderation's listing first, and A's sync, reading the ERASE, journals the run
// under the moderation's erasure. A's daemon then restarts: its new client reads no ERASE again, the erasure ref having
// moved no further, and holds the run journaled, and its return leaves it out from the journal alone, the set listing
// nothing of A's, the kept run coming back two above.
func TestDirectoryModerationNoteJournalsAtTheNextSyncWhileIdle(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	now := world.clock.Now().UnixMilli()
	erasedId, keptId := sidecar.NewId(), sidecar.NewId()
	erased := testRunItem(writer.sidecarId, &memberId, erasedId, 1, now)
	kept := testRunItem(writer.sidecarId, &memberId, keptId, 1, now)
	device.writeCard(t, erased, kept)

	erasureId := world.moderateCard(writer.sidecarId, erasedId, 1, true)
	world.cards.DropErased(world.directoryId, world.readerId, testAnnouncementDocumentName(&writer.sidecarId, erasedId))
	if journal := testCardJournal(t, device.client); len(journal) != 0 {
		t.Fatalf("the journal before A's sync: %v", journal)
	}
	writes := world.counts().CardWrites
	device.mustSync(t)
	if journal := testCardJournal(t, device.client); !testJournalNoted(journal, erasedId, erasureId) {
		t.Fatalf("the journal after A's idle sync: %+v", journal)
	}
	if world.counts().CardWrites != writes {
		t.Fatal("A's idle sync wrote a card")
	}

	world.clock.Advance(time.Minute)
	world.publish()
	restarted := world.restartClient(device)
	if journal := testCardJournal(t, restarted); !testJournalNoted(journal, erasedId, erasureId) {
		t.Fatalf("the journal after A's restart: %+v", journal)
	}
	returned, err := restarted.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: []*protocol.Announcement{erased, kept}})
	if err != nil {
		t.Fatal(err)
	}
	if versions := testCardWrittenVersions(returned); len(versions) != 1 || versions[keptId] != 3 || !slices.Equal(returned.Moderated, []sidecar.Id{erasedId}) {
		t.Fatalf("A's return after its restart carries %v, left out %v", versions, returned.Moderated)
	}
	restarted.Runs().Close()
}

// A daemon off past several erasures still leaves its moderated run out (QD-1148): while A's daemon is stopped, a
// directory admin moderates one of its runs, then B's run, then erases twice more, each CUT dropping every complete
// erasure before it from the set. A's daemon starts again: its first sync reads each ERASE since it stopped and
// journals its own run from the moderation's note, and not B's; its next run's card, its return, reads the set listing
// nothing of A's and leaves the moderated run out though the run writer still holds it open, the kept run and the new
// one at their raised versions, and a claim on the moderated run is refused.
func TestDirectoryModerationNoteHoldsAWriterOffPastSeveralCuts(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	device := world.format2Device(sidecar.NewId())
	writerId := device.writer.sidecarId
	erasedRunId := world.startRun(device.client, "ship the launch plan")
	keptRunId := world.startRun(device.client, "tidy the changelog")
	shown := world.shownRuns(writerId)
	if shown[erasedRunId] == nil || shown[keptRunId] == nil {
		t.Fatalf("A's runs before the moderation: %v", shown)
	}
	erasedId := sidecar.Id(shown[erasedRunId].GetAnnouncementId())
	// A's daemon stops
	device.client.Runs().Close()

	bMember := sidecar.NewId()
	b := world.memberWriter(bMember)
	world.publish()
	bRunId := sidecar.NewId()
	world.device(b).writeCard(t, testRunItem(b.sidecarId, &bMember, bRunId, 1, world.clock.Now().UnixMilli()))
	erasedDocument := testAnnouncementDocumentName(&writerId, erasedId)
	bDocument := testAnnouncementDocumentName(&b.sidecarId, bRunId)
	moderationId := world.moderateCard(writerId, erasedId, 1, true)
	world.cards.DropErased(world.directoryId, world.readerId, erasedDocument)
	world.moderateCard(b.sidecarId, bRunId, 1, true)
	dropped := [][]byte{erasedDocument, bDocument}
	for range 2 {
		world.clock.Advance(time.Hour)
		otherId := sidecar.NewId()
		otherDocument := testAnnouncementDocumentName(&otherId, sidecar.NewId())
		world.cards.DropErased(world.directoryId, world.readerId, dropped...)
		world.cards.ListErased(world.directoryId, world.readerId, otherDocument, 1)
		dropped = append(dropped, otherDocument)
		erasureId := sidecar.NewId()
		world.eraseCardKeys(world.readerId, erasureId, &protocol.ErasureBody{ErasureId: erasureId.Bytes(), Reason: uint32(sidecar.RecordErasureReasonPerson)})
	}
	world.publish()

	restarted := world.restartClient(device)
	runs := restarted.Runs()
	if err := runs.Resume(func(runId sidecar.Id) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if journal := testCardJournal(t, restarted); !testJournalNoted(journal, erasedId, moderationId) {
		t.Fatalf("A's journal after its first sync back: %+v", journal)
	}
	reads := world.counts().ErasedReads
	startedRunId := world.startRun(restarted, "review the loader")
	shown = world.shownRuns(writerId)
	if len(shown) != 2 || shown[erasedRunId] != nil || shown[keptRunId].GetVersion() != 3 || shown[startedRunId].GetVersion() != 3 {
		t.Fatalf("A's runs after its return: %v", shown)
	}
	if count := world.counts().ErasedReads - reads; count != 1 {
		t.Fatalf("A's return read the erasure set %d times", count)
	}
	if _, err := testRunsClaim(t, runs, erasedRunId, []string{"src/launch"}, 0); !errors.Is(err, sidecar.ErrDirectoryRunModerated) {
		t.Fatalf("a claim on the moderated run: %v", err)
	}
	runs.Close()
}

// Only a directory admin's moderation note journals, and only what this sidecar's card held (QD-1148). ERASEs whose
// notes name A's kept run journal nothing: one a sidecar the state names no directory admin committed, which a server
// breaching the scope rule lets erase and which alarms bad_erasure once; a directory admin's under a person's or a
// revocation's reason; one whose note names another erasure than its own. Nor does a directory admin's moderation
// note naming a run A's card never held, or B's. The moderation note naming A's other run journals it alone, and A's
// return leaves that run out and carries the kept one two above.
func TestDirectoryModerationNoteJournalsOnlyAnAdminsModerationOfItsCard(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId, otherMember := sidecar.NewId(), sidecar.NewId()
	writer := world.memberWriter(memberId)
	rogue := world.memberWriter(sidecar.NewId())
	other := world.memberWriter(otherMember)
	world.publish()
	world.grant(world.readerId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true})
	world.grant(rogue.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true})
	device := world.device(writer)
	now := world.clock.Now().UnixMilli()
	erasedId, keptId, otherRunId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	erased := testRunItem(writer.sidecarId, &memberId, erasedId, 1, now)
	kept := testRunItem(writer.sidecarId, &memberId, keptId, 1, now)
	device.writeCard(t, erased, kept)
	world.device(other).writeCard(t, testRunItem(other.sidecarId, &otherMember, otherRunId, 1, now))

	naming := func(reason sidecar.RecordErasureReason, erasureId sidecar.Id, announcementIds ...sidecar.Id) *protocol.ErasureBody {
		body := &protocol.ErasureBody{ErasureId: erasureId.Bytes(), Reason: uint32(reason)}
		if reason == sidecar.RecordErasureReasonRevocation {
			body.RequestId = erasureId.Bytes()
		}
		for _, announcementId := range announcementIds {
			body.AnnouncementIds = append(body.AnnouncementIds, announcementId.Bytes())
		}
		return body
	}
	rogueErasureId := sidecar.NewId()
	world.eraseCardKeys(rogue.sidecarId, rogueErasureId, naming(sidecar.RecordErasureReasonModeration, rogueErasureId, keptId))
	for _, reason := range []sidecar.RecordErasureReason{sidecar.RecordErasureReasonPerson, sidecar.RecordErasureReasonRevocation} {
		erasureId := sidecar.NewId()
		world.eraseCardKeys(world.readerId, erasureId, naming(reason, erasureId, keptId))
	}
	mismatchedId := sidecar.NewId()
	world.eraseCardKeys(world.readerId, mismatchedId, naming(sidecar.RecordErasureReasonModeration, sidecar.NewId(), keptId))
	strangerId := sidecar.NewId()
	world.eraseCardKeys(world.readerId, strangerId, naming(sidecar.RecordErasureReasonModeration, strangerId, sidecar.NewId(), otherRunId))
	device.mustSync(t)
	if journal := testCardJournal(t, device.client); len(journal) != 0 {
		t.Fatalf("the journal after ERASEs no moderation of A's card sent: %+v", journal)
	}
	if count := device.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, rogue.sidecarId); count != 1 {
		t.Fatalf("%d bad_erasure alarms naming the rogue eraser", count)
	}

	moderationId := world.moderateCard(writer.sidecarId, erasedId, 1, true)
	world.cards.DropErased(world.directoryId, world.readerId, testAnnouncementDocumentName(&writer.sidecarId, erasedId))
	device.mustSync(t)
	if journal := testCardJournal(t, device.client); !testJournalNoted(journal, erasedId, moderationId) {
		t.Fatalf("the journal after the moderation: %+v", journal)
	}
	world.clock.Advance(time.Minute)
	world.publish()
	returned := device.writeCard(t, erased, kept)
	if versions := testCardWrittenVersions(returned); len(versions) != 1 || versions[keptId] != 3 || !slices.Equal(returned.Moderated, []sidecar.Id{erasedId}) {
		t.Fatalf("A's return carries %v, left out %v", versions, returned.Moderated)
	}
}
