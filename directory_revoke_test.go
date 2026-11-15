//go:build !sidecar_http

// RECORD-M6-20's revocation on sidecartest's fakes, FS-99's M6 cases at the revoker and at readers: a revoke with no
// admin daemon running hides the name at once and reads pending with its age; its marker and its erasure_request
// leave in one push; a second revoke, and a revoke resumed after a failed append, file one request id; a person's
// act alone revokes; and a reader takes a directory ERASE only from a directory admin, alarming on any other.

package sidecar_test

import (
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A device of a new member that the state names a directory admin and evs mints admin to.
func (self *testDirectoryWorld) adminDevice() *testDirectoryDevice {
	self.t.Helper()
	writer := self.memberWriter(sidecar.NewId())
	at := self.directoryAuth.Tip().Pin().GetVersion() + 1
	directory := self.directoryFixture.Repos[self.directoryId]
	directory.Admins = append(directory.Admins, sidecartest.FakeDirectoryRepoAdmin{SidecarId: writer.sidecarId, At: at})
	repo := self.recordFixture.Repos[self.directoryId]
	repo.Admins = append(repo.Admins, writer.sidecarId)
	if err := self.streams.Grant(self.directoryId, writer.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true}); err != nil {
		self.t.Fatal(err)
	}
	self.publish()
	return self.device(writer)
}

// A repo P of kind general whose admin is a new member's device, announced as title and pushed.
func (self *testDirectoryWorld) announcedRepo(title string) (*testDirectoryDevice, sidecar.Id) {
	self.t.Helper()
	writer := self.memberWriter(sidecar.NewId())
	self.publish()
	repoId := self.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, writer)
	owner := self.device(writer)
	if _, err := owner.client.AnnounceRepo(self.t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: title, Confirmed: true}); err != nil {
		self.t.Fatal(err)
	}
	owner.flush(self.t)
	return owner, repoId
}

// The directory's entries of kind as a device's own record reads them at evs now.
func (self *testDirectoryDevice) entriesAtEvs(t *testing.T, kind sidecar.RecordKind) []*sidecar.RecordReadEntry {
	t.Helper()
	reader := self.record.Reader()
	if err := reader.Sync(t.Context(), self.writer.world.directoryId); err != nil {
		t.Fatal(err)
	}
	entries, _ := reader.EntriesOfKinds(self.writer.world.directoryId, 0, kind)
	return entries
}

// A record writer that fails each append past the first failAfter, appending through next otherwise.
type testFailingWriter struct {
	next sidecar.RecordWriter

	stateLock sync.Mutex
	failAfter int
	appended  int
}

func (self *testFailingWriter) Append(draft *sidecar.RecordDraft) ([]*sidecar.RecordEntryRef, error) {
	fail := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.appended += 1
		return 0 <= self.failAfter && self.failAfter < self.appended
	}()
	if fail {
		return nil, errors.New("the writer stopped")
	}
	return self.next.Append(draft)
}

func TestDirectoryRevokeHidesAtOnceAndWaitsForARunner(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	reader := world.reader(nil)
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, repoId); item == nil || item.Announcement.GetWhat().GetTitle() != "design notes" {
		t.Fatalf("the announced item: %v", item)
	}
	owner.mustSync(t)

	// a person's act alone
	for _, args := range []*sidecar.DirectoryRevokeArgs{
		{RepoId: repoId},
		{RepoId: repoId, Confirmed: true, HarnessAncestor: true},
	} {
		if _, err := owner.client.RevokeRepo(t.Context(), args); !errors.Is(err, sidecar.ErrDirectoryRevokeUnconfirmed) {
			t.Fatalf("an unconfirmed revoke: %v", err)
		}
	}
	// and its repo's admin's alone
	stranger := world.device(world.memberWriter(sidecar.NewId()))
	world.publish()
	if _, err := stranger.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryRepoRight) {
		t.Fatalf("a revoke by a device with no right on the repo: %v", err)
	}

	revocation, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if revocation.State != sidecar.DirectoryRevocationPending || revocation.MarkerVersion != 2 || revocation.MarkerEntryId == nil || revocation.RequestEntryId == nil ||
		!slices.Equal(revocation.Warnings, []string{sidecar.DirectoryRepoLabelWarning}) {
		t.Fatalf("the revocation: %+v", revocation)
	}
	owner.flush(t)

	// the marker and the request left in one push
	versions, err := world.streams.For(world.readerId).ReadStream(t.Context(), world.directoryId, owner.writer.sidecarId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 2 || len(versions[1].Entries) != 2 {
		t.Fatalf("the owner's stream: %d pushes, the last of %d entries", len(versions), len(versions[len(versions)-1].Entries))
	}
	requests := owner.entriesAtEvs(t, sidecar.RecordKindErasureRequest)
	if len(requests) != 1 {
		t.Fatalf("%d erasure_request entries", len(requests))
	}
	request, err := sidecar.DirectoryDecodeErasureRequest(requests[0].Body)
	if err != nil || sidecar.Id(request.GetRequestId()) != revocation.RequestId || sidecar.Id(request.GetRepoId()) != repoId || request.GetMarkerVersion() != 2 {
		t.Fatalf("the request: %v, %v", request, err)
	}

	// every honest reader stops showing the name at once, with nothing erased
	reader.mustSync(t)
	marker := testRepoItemShown(t, reader, repoId)
	if marker == nil || marker.Display != sidecar.DirectoryItemPrivate || marker.Announcement.GetWhat().GetTitle() != "" ||
		proto.Size(marker.Announcement) != sidecar.DirectoryRepoEntryStepByteCount {
		t.Fatalf("the marker: %v", marker)
	}
	if views := reader.client.ErasureRequests(); len(views) != 1 || views[0].Erased || views[0].RequestId != revocation.RequestId || views[0].SignerSidecarId != owner.writer.sidecarId {
		t.Fatalf("the request as a reader holds it: %+v", views)
	}

	// a second revoke files nothing and answers the first, pending with its age
	world.clock.Advance(3 * time.Hour)
	owner.mustSync(t)
	again, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || again.RequestId != revocation.RequestId || again.State != sidecar.DirectoryRevocationPending || again.Age != 3*time.Hour {
		t.Fatalf("a second revoke: %+v, %v", again, err)
	}
	owner.flush(t)
	if requests := owner.entriesAtEvs(t, sidecar.RecordKindErasureRequest); len(requests) != 1 {
		t.Fatalf("%d erasure_request entries after a second revoke", len(requests))
	}
	lines := owner.client.RevocationStatusLines()
	if len(lines) != 1 || !strings.Contains(lines[0], "pending for 3h") || !strings.Contains(lines[0], repoId.String()) {
		t.Errorf("the revoker's status lines: %v", lines)
	}
	if erasures, err := world.streams.For(world.readerId).ReadErasures(t.Context(), world.directoryId, 0); err != nil || len(erasures) != 0 {
		t.Errorf("ERASEs with no admin daemon running: %d, %v", len(erasures), err)
	}
}

func TestDirectoryRevokeResumedFilesOneRequest(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	owner.mustSync(t)
	// a client of the same device whose writer stops after the marker
	failing := &testFailingWriter{next: owner.record.Writer(), failAfter: 1}
	client := world.clientFor(owner.writer.sidecarId, failing, false)
	client.mustSync(t)
	if _, err := client.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true}); err == nil {
		t.Fatal("a revoke whose request was not appended answered")
	}
	if revocations, err := client.client.Revocations(); err != nil || len(revocations) != 1 || revocations[0].RequestEntryId != nil {
		t.Fatalf("the journal after the stop: %+v, %v", revocations, err)
	}
	requestId := func() sidecar.Id {
		revocations, _ := client.client.Revocations()
		return revocations[0].RequestId
	}()
	failing.stateLock.Lock()
	failing.failAfter = -1
	failing.stateLock.Unlock()
	revocation, err := client.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || revocation.RequestId != requestId || revocation.MarkerVersion != 2 || revocation.RequestEntryId == nil {
		t.Fatalf("the resumed revoke: %+v, %v", revocation, err)
	}
	owner.flush(t)
	requests := owner.entriesAtEvs(t, sidecar.RecordKindErasureRequest)
	if len(requests) != 1 {
		t.Fatalf("%d erasure_request entries", len(requests))
	}
	// the marker written twice is one version of the item
	markers := 0
	for _, entry := range owner.entriesAtEvs(t, sidecar.RecordKindAnnounce) {
		item, err := sidecar.DirectoryDecodeAnnouncement(entry.Body)
		if err != nil {
			t.Fatal(err)
		}
		if item.GetWhere().GetPrivate() {
			markers += 1
			if item.GetVersion() != 2 {
				t.Errorf("a marker at version %d", item.GetVersion())
			}
		}
	}
	if markers != 2 {
		t.Errorf("%d markers", markers)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if views := reader.client.ErasureRequests(); len(views) != 1 || views[0].RequestId != requestId {
		t.Errorf("the request as a reader holds it: %+v", views)
	}
	if marker := testRepoItemShown(t, reader, repoId); marker == nil || marker.Display != sidecar.DirectoryItemPrivate {
		t.Errorf("the marker: %v", marker)
	}
}

func TestDirectoryRevokeLapsesWhenTheRepoIsAnnouncedAgain(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	owner.mustSync(t)
	first, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: "design notes, again", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	owner.flush(t)
	owner.mustSync(t)
	revocations, err := owner.client.Revocations()
	if err != nil || len(revocations) != 1 || revocations[0].State != sidecar.DirectoryRevocationLapsed {
		t.Fatalf("the revocation after a new announcement: %+v, %v", revocations, err)
	}
	if lines := owner.client.RevocationStatusLines(); len(lines) != 0 {
		t.Errorf("a lapsed revocation's status lines: %v", lines)
	}
	// a revoke of the item announced again is a new request above it
	second, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || second.RequestId == first.RequestId || second.MarkerVersion != 4 || second.State != sidecar.DirectoryRevocationPending {
		t.Fatalf("the second revocation: %+v, %v", second, err)
	}
}

func TestDirectoryReaderRefusesAnEraseFromANonAdmin(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	reader := world.reader(nil)
	reader.mustSync(t)
	// a sidecar the state names no admin, which a server breaching the scope rule lets erase
	rogue := world.memberWriter(sidecar.NewId())
	world.publish()
	if err := world.streams.Grant(world.directoryId, rogue.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true, Admin: true}); err != nil {
		t.Fatal(err)
	}
	entries := owner.entriesAtEvs(t, sidecar.RecordKindAnnounce)
	if len(entries) != 1 || len(entries[0].Copies) != 1 {
		t.Fatalf("%d announce entries", len(entries))
	}
	erasureId := sidecar.NewId()
	note, err := proto.Marshal(&protocol.ErasureBody{ErasureId: erasureId.Bytes(), EntryIds: [][]byte{entries[0].EntryId.Bytes()}, Reason: uint32(sidecar.RecordErasureReasonModeration)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.streams.For(rogue.sidecarId).Erase(t.Context(), world.directoryId, &sidecar.RecordStreamErase{
		PushId: sidecar.NewId(), ErasureId: erasureId, Complete: true, SealedNote: note,
		Keys: []*sidecar.RecordSlotKey{{SlotId: entries[0].Copies[0].SlotId, KeyIndex: entries[0].Copies[0].KeyIndex}},
	}); err != nil {
		t.Fatal(err)
	}
	reader.mustSync(t)
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, repoId); item == nil || item.Announcement.GetWhat().GetTitle() != "design notes" {
		t.Errorf("the item after a non-admin's ERASE: %v", item)
	}
	if count := reader.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, rogue.sidecarId); count != 1 {
		t.Errorf("%d bad_erasure alarms naming the signer", count)
	}
	if _, ok := reader.client.ErasureOf(entries[0].EntryId); ok {
		t.Error("a non-admin's ERASE reads as an erasure")
	}
}
