//go:build !sidecar_http

// RECORD-M6-20's erasure runner and the directory admin's erasure on sidecartest's fakes, FS-99's M6 cases: an
// admin's ERASE of another writer's entry; a runner that starts after 24 h raising directory_erasure, waiting its
// delay and erasing exactly the copies naming the repo, each ERASE naming the request; later copies swept while the
// marker stands; a non-admin's request, and one after the repo is announced again, erasing nothing and alarming; a
// request lapsed that way staying lapsed when the repo is revoked again, through the erasure of the entries that
// showed it and a restart (owner decision 472); the superseded rule (QD-1061), on a directory admin's device admitted
// after the later request's ERASEs, and for a request whose marker a later request erased before it was worked, never
// for a revocation its revoker has not read back, with expiry keeping the marker of a request inside its delay; two runners racing, one ERASE committing; the indexer rule;
// and expiry holding an item's newest copy.

package sidecar_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Randomness that answers every 8-byte draw with delay, so a runner's wait is delay.
type testErasureDelay struct {
	delay time.Duration
}

func (self *testErasureDelay) Read(p []byte) (int, error) {
	clear(p)
	if 8 <= len(p) {
		binary.BigEndian.PutUint64(p, uint64(self.delay))
	}
	return len(p), nil
}

// The directory_erasure events a runner raised.
type testErasureRaises struct {
	stateLock sync.Mutex
	outcomes  []string
}

func (self *testErasureRaises) raise(repoId sidecar.Id, requestId sidecar.Id, outcome string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.outcomes = append(self.outcomes, outcome)
	return nil
}

func (self *testErasureRaises) raised() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.outcomes)
}

// A runner on the device, its eraser the device's record's, waiting delay, with the indexers given.
func (self *testDirectoryDevice) runner(t *testing.T, delay time.Duration, indexers func() []sidecar.Id) (*sidecar.DirectoryErasureRunner, *testErasureRaises) {
	t.Helper()
	raises := &testErasureRaises{}
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
		Client:   self.client,
		Erase:    self.record.Eraser().Erase,
		Indexers: indexers,
		Raise:    raises.raise,
		Random:   &testErasureDelay{delay: delay},
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner, raises
}

// The device after a restart: a new directory client over its own copy's store and its record, raising its own
// alarms.
func (self *testDirectoryWorld) restarted(device *testDirectoryDevice) *testDirectoryDevice {
	self.t.Helper()
	reader := &testDirectoryReader{files: device.files, store: device.store, synced: make(chan struct{}, 64)}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  device.writer.sidecarId,
		Store:      device.store,
		Cards:      self.cards.For(device.writer.sidecarId),
		Streams:    func() sidecar.RecordStreams { return self.streams.For(device.writer.sidecarId) },
		Auth:       func() sidecar.DirectoryAuthView { return self.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			reader.stateLock.Lock()
			defer reader.stateLock.Unlock()
			reader.alarms = append(reader.alarms, alarm)
		},
		Clock:     self.clock,
		Settings:  sidecar.DefaultSidecarSettings().Directory,
		Writer:    device.record.Writer(),
		NetworkId: self.networkId,
		Sign:      device.writer.sign,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	reader.client = client
	return &testDirectoryDevice{writer: device.writer, record: device.record, testDirectoryReader: reader}
}

// Each erasure_request's LapsedVersion as client holds it, by request id.
func testLapsedVersions(client *sidecar.DirectoryClient) map[sidecar.Id]uint64 {
	versions := map[sidecar.Id]uint64{}
	for _, view := range client.ErasureRequests() {
		versions[view.RequestId] = view.LapsedVersion
	}
	return versions
}

// The request ids the directory's ERASEs name at evs, one an ERASE, failing the test unless each is a revocation's whose
// erasure id is the request its note names.
func (self *testDirectoryWorld) erasureRequestIds(t *testing.T) []sidecar.Id {
	t.Helper()
	erasures, err := self.streams.For(self.readerId).ReadErasures(t.Context(), self.directoryId, 0)
	if err != nil {
		t.Fatal(err)
	}
	requestIds := []sidecar.Id{}
	for _, erasure := range erasures {
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(erasure.SealedNote, body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body.GetRequestId(), erasure.ErasureId.Bytes()) {
			t.Fatalf("an ERASE whose id %s is not the request its note names, %x", erasure.ErasureId, body.GetRequestId())
		}
		requestIds = append(requestIds, erasure.ErasureId)
	}
	return requestIds
}

// One sync and one pass, which must both succeed.
func (self *testDirectoryDevice) pass(t *testing.T, runner *sidecar.DirectoryErasureRunner) *sidecar.DirectoryErasurePass {
	t.Helper()
	self.mustSync(t)
	pass, err := runner.Pass(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return pass
}

// A run item of writer's that names repoId, pushed in its own stream.
func (self *testDirectoryWriter) announceRunIn(repoId sidecar.Id, memberId sidecar.Id) sidecar.Id {
	announcementId := sidecar.NewId()
	item := testRunItem(self.sidecarId, &memberId, announcementId, 1, self.world.clock.Now().UnixMilli())
	item.Where.RepoId = repoId.Bytes()
	self.announce(item)
	return announcementId
}

// The ids of the directory's announce entries at evs whose key is still held, with each one's item.
func (self *testDirectoryDevice) liveAnnouncements(t *testing.T) map[sidecar.Id]*protocol.Announcement {
	t.Helper()
	live := map[sidecar.Id]*protocol.Announcement{}
	for _, entry := range self.entriesAtEvs(t, sidecar.RecordKindAnnounce) {
		if entry.State != sidecar.RecordEntryLive {
			continue
		}
		item, err := sidecar.DirectoryDecodeAnnouncement(entry.Body)
		if err != nil {
			t.Fatal(err)
		}
		live[entry.EntryId] = item
	}
	return live
}

func TestDirectoryAdminErasesAnEntry(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	_, repoId := world.announcedRepo("design notes")
	admin := world.adminDevice()
	admin.client.BindEraser(admin.record.Eraser().Erase)
	admin.mustSync(t)
	item := testRepoItemShown(t, admin.testDirectoryReader, repoId)
	if item == nil {
		t.Fatal("no item")
	}
	announcementId := sidecar.Id(item.Announcement.GetAnnouncementId())
	// a person's act alone, and a directory admin's alone
	if _, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: announcementId}); !errors.Is(err, sidecar.ErrDirectoryEraseUnconfirmed) {
		t.Fatalf("an unconfirmed erase: %v", err)
	}
	member := world.device(world.memberWriter(sidecar.NewId()))
	world.publish()
	member.client.BindEraser(member.record.Eraser().Erase)
	member.mustSync(t)
	if _, err := member.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: announcementId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryEraseNotAdmin) {
		t.Fatalf("an erase by a device that is no directory admin: %v", err)
	}
	unbound := world.adminDevice()
	unbound.mustSync(t)
	if _, err := unbound.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: announcementId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryEraserUnbound) {
		t.Fatalf("an erase with no eraser bound: %v", err)
	}

	admin.mustSync(t)
	result, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: announcementId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != sidecar.RecordErasureReasonModeration || !slices.Equal(result.EntryIds, []sidecar.Id{item.EntryId}) {
		t.Fatalf("the erasure: %+v", result)
	}
	admin.flush(t)
	reader := world.reader(nil)
	reader.mustSync(t)
	if shown := testRepoItemShown(t, reader, repoId); shown != nil {
		t.Errorf("the erased item still shows: %v", shown)
	}
	erasure, ok := reader.client.ErasureOf(item.EntryId)
	if !ok || erasure.EraserSidecarId != admin.writer.sidecarId || erasure.Reason != sidecar.RecordErasureReasonModeration || erasure.RequestId != nil {
		t.Errorf("the erasure as a reader shows it: %+v, %v", erasure, ok)
	}
	if count := len(reader.alarmReasons()); count != 0 {
		t.Errorf("%d alarms on an admin's ERASE: %v", count, reader.alarmReasons())
	}
	if _, err := admin.client.Erase(t.Context(), &sidecar.DirectoryEraseArgs{Id: sidecar.NewId(), Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryItemNone) {
		t.Errorf("an erase of an id nothing holds: %v", err)
	}
}

func TestDirectoryRunnerErasesExactlyTheCopiesNamingTheRepo(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	_, otherRepoId := world.announcedRepo("billing")
	owner.mustSync(t)
	// a second version of the item, and two members' runs, one in each repo
	if _, err := owner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: "design notes", Description: "the redesign", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	owner.flush(t)
	memberId := sidecar.NewId()
	runWriter := world.memberWriter(memberId)
	world.publish()
	runWriter.announceRunIn(repoId, memberId)
	otherRunId := runWriter.announceRunIn(otherRepoId, memberId)

	owner.mustSync(t)
	revocation, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || revocation.MarkerVersion != 3 {
		t.Fatalf("the revocation: %+v, %v", revocation, err)
	}
	owner.flush(t)

	// no admin daemon runs for a day and an hour: nothing is erased, and the revoker reads pending
	world.clock.Advance(25 * time.Hour)
	world.publish()
	admin := world.adminDevice()
	runner, raises := admin.runner(t, 4*time.Minute, nil)
	pass := admin.pass(t, runner)
	if !pass.Runs || len(pass.Erased) != 0 || !slices.Equal(pass.Delayed, []sidecar.Id{revocation.RequestId}) || len(pass.Pending) != 1 || pass.Pending[0].Age != 25*time.Hour {
		t.Fatalf("the pass that first shows the work: %+v", pass)
	}
	if raised := raises.raised(); !slices.Equal(raised, []string{sidecar.SidecarDirectoryErasurePending}) {
		t.Fatalf("raised past 24 h: %v", raised)
	}
	lines := runner.StatusLines()
	if len(lines) != 2 || !strings.Contains(lines[0], "1 erasure request(s) wait") || !strings.Contains(lines[1], "pending for 25h, past 24h") || !strings.Contains(lines[1], repoId.String()) {
		t.Errorf("an admin's status lines: %v", lines)
	}
	// what ur status reads, with no runner of its own: the admin's lines, and the revoker's own pending one
	if read := admin.client.ErasureStatusLines(nil); !slices.Equal(read, lines) {
		t.Errorf("ur status on the admin's device: %v", read)
	}
	if read := owner.client.ErasureStatusLines(nil); len(read) == 0 || !strings.Contains(read[0], "is pending for 25h") {
		t.Errorf("ur status on the revoker's device: %v", read)
	}
	// before the delay ends nothing goes
	world.clock.Advance(3 * time.Minute)
	if pass := admin.pass(t, runner); len(pass.Erased) != 0 {
		t.Fatalf("a pass inside the delay erased %v", pass.Erased)
	}
	world.clock.Advance(time.Minute)
	pass = admin.pass(t, runner)
	if len(pass.Erased[revocation.RequestId]) != 3 || len(pass.Erased) != 1 {
		t.Fatalf("the pass after the delay erased %v", pass.Erased)
	}
	admin.flush(t)

	// exactly the copies naming the repo: its two earlier versions and the run in it
	live := admin.liveAnnouncements(t)
	names := []string{}
	for _, item := range live {
		switch {
		case item.GetWhere().GetPrivate():
			names = append(names, "marker")
		case sidecar.DirectoryAnnouncementKind(item.GetKind()) == sidecar.DirectoryAnnouncementKindRun:
			if sidecar.Id(item.GetAnnouncementId()) != otherRunId || sidecar.Id(item.GetWhere().GetRepoId()) != otherRepoId {
				t.Errorf("a run naming the revoked repo is still held")
			}
			names = append(names, "other run")
		default:
			names = append(names, item.GetWhat().GetTitle())
		}
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"billing", "marker", "other run"}) {
		t.Fatalf("the announce entries still held: %v", names)
	}
	// each ERASE names the request as its erasure id and in its note
	erasures, err := world.streams.For(world.readerId).ReadErasures(t.Context(), world.directoryId, 0)
	if err != nil || len(erasures) == 0 {
		t.Fatalf("%d ERASEs, %v", len(erasures), err)
	}
	for _, erasure := range erasures {
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(erasure.SealedNote, body); err != nil || erasure.ErasureId != revocation.RequestId || erasure.EraserSidecarId != admin.writer.sidecarId ||
			!bytes.Equal(body.GetRequestId(), revocation.RequestId.Bytes()) || body.GetReason() != uint32(sidecar.RecordErasureReasonRevocation) {
			t.Errorf("an ERASE: id %s, note %v, %v", erasure.ErasureId, body, err)
		}
	}

	// the admin's device raises done, the revoker reads done, and a reader shows a repo owner's revocation
	pass = admin.pass(t, runner)
	if len(pass.Erased) != 0 || len(pass.Pending) != 0 {
		t.Fatalf("the pass after the erasure: %+v", pass)
	}
	if raised := raises.raised(); !slices.Equal(raised, []string{sidecar.SidecarDirectoryErasurePending, sidecar.SidecarDirectoryErasureDone}) {
		t.Errorf("raised: %v", raised)
	}
	if lines := runner.StatusLines(); len(lines) != 0 {
		t.Errorf("status lines once erased: %v", lines)
	}
	owner.mustSync(t)
	revocations, err := owner.client.Revocations()
	if err != nil || len(revocations) != 1 || revocations[0].State != sidecar.DirectoryRevocationDone || revocations[0].EraserSidecarId == nil || *revocations[0].EraserSidecarId != admin.writer.sidecarId {
		t.Fatalf("the revocation at its revoker: %+v, %v", revocations, err)
	}
	if lines := owner.client.RevocationStatusLines(); len(lines) != 0 {
		t.Errorf("the revoker's status lines once erased: %v", lines)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if marker := testRepoItemShown(t, reader, repoId); marker == nil || marker.Display != sidecar.DirectoryItemPrivate {
		t.Errorf("the marker: %v", marker)
	}
	if other := testRepoItemShown(t, reader, otherRepoId); other == nil || other.Announcement.GetWhat().GetTitle() != "billing" {
		t.Errorf("the other repo's item: %v", other)
	}
	if count := len(reader.alarmReasons()); count != 0 {
		t.Errorf("alarms at a reader: %v", reader.alarmReasons())
	}

	// a copy a daemon wrote after the request goes at a later sync while the marker stands, for 30 days
	world.clock.Advance(24 * time.Hour)
	world.publish()
	runWriter.announceRunIn(repoId, memberId)
	pass = admin.pass(t, runner)
	if len(pass.Delayed) != 1 || len(pass.Erased) != 0 {
		t.Fatalf("the pass that first shows a later copy: %+v", pass)
	}
	world.clock.Advance(4 * time.Minute)
	if pass = admin.pass(t, runner); len(pass.Erased[revocation.RequestId]) != 1 {
		t.Fatalf("the sweep erased %v", pass.Erased)
	}
	admin.flush(t)
	world.clock.Advance(30 * 24 * time.Hour)
	world.publish()
	runWriter.announceRunIn(repoId, memberId)
	world.clock.Advance(10 * time.Minute)
	if pass = admin.pass(t, runner); len(pass.Erased) != 0 || len(pass.Delayed) != 0 {
		t.Fatalf("a pass past the 30 days: %+v", pass)
	}
}

func TestDirectoryRunnerRefusesARequestThatFailsItsCheck(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	owner.mustSync(t)
	// a member with no right on the repo files a request for it
	strangerWriter := world.memberWriter(sidecar.NewId())
	world.publish()
	stranger := world.device(strangerWriter)
	forgedId := sidecar.NewId()
	if _, err := stranger.record.Writer().Append(&sidecar.RecordDraft{
		Kind: sidecar.RecordKindErasureRequest, Source: sidecar.RecordSourceApprover, NoSession: true,
		Body: &protocol.DirectoryErasureRequest{RequestId: forgedId.Bytes(), RepoId: repoId.Bytes(), MarkerVersion: 2},
	}); err != nil {
		t.Fatal(err)
	}
	stranger.flush(t)
	// and the owner revokes, then announces the repo again before any runner ran
	revocation, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: "design notes", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	owner.flush(t)

	admin := world.adminDevice()
	runner, raises := admin.runner(t, 0, nil)
	pass := admin.pass(t, runner)
	refused := slices.Clone(pass.Refused)
	slices.SortFunc(refused, sidecar.Id.Cmp)
	want := []sidecar.Id{forgedId, revocation.RequestId}
	slices.SortFunc(want, sidecar.Id.Cmp)
	if !slices.Equal(refused, want) || len(pass.Erased) != 0 || len(pass.Pending) != 0 {
		t.Fatalf("the pass: %+v", pass)
	}
	if count := admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, stranger.writer.sidecarId); count != 1 {
		t.Errorf("%d bad_erasure alarms naming the signer with no right", count)
	}
	if count := admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, owner.writer.sidecarId); count != 1 {
		t.Errorf("%d bad_erasure alarms naming the signer of the lapsed request", count)
	}
	// once
	world.clock.Advance(48 * time.Hour)
	world.publish()
	if pass = admin.pass(t, runner); len(pass.Refused) != 0 || len(pass.Erased) != 0 {
		t.Fatalf("a second pass: %+v", pass)
	}
	if count := admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, stranger.writer.sidecarId); count != 1 {
		t.Errorf("%d bad_erasure alarms after a second pass", count)
	}
	if erasures, err := world.streams.For(world.readerId).ReadErasures(t.Context(), world.directoryId, 0); err != nil || len(erasures) != 0 {
		t.Errorf("ERASEs for refused requests: %d, %v", len(erasures), err)
	}
	if raised := raises.raised(); len(raised) != 0 {
		t.Errorf("directory_erasure raised for refused requests: %v", raised)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, repoId); item == nil || item.Announcement.GetWhat().GetTitle() != "design notes" {
		t.Errorf("the item announced again: %v", item)
	}
}

// QD-984's sequence in one repo (owner decision 472): revoke P (request 1, marker version 2), announce P again (version
// 3: request 1 lapses, refused with bad_erasure naming its signer), revoke P again (request 2, marker version 4). The
// next pass holds request 2 alone as work, every ERASE names request 2 and the second revocation reads done at its
// revoker. Request 1 stays lapsed after the ERASEs took the entries that showed its lapse, through a later copy's
// sweep, which goes under request 2, and through a restart of the runner's client over its own copy.
func TestDirectoryRunnerKeepsALapsedRequestLapsed(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	memberId := sidecar.NewId()
	runWriter := world.memberWriter(memberId)
	world.publish()
	runWriter.announceRunIn(repoId, memberId)
	admin := world.adminDevice()
	runner, raises := admin.runner(t, 4*time.Minute, nil)

	owner.mustSync(t)
	first, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || first.MarkerVersion != 2 {
		t.Fatalf("the first revocation: %+v, %v", first, err)
	}
	if _, err := owner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: "design notes", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	owner.flush(t)
	pass := admin.pass(t, runner)
	if !slices.Equal(pass.Refused, []sidecar.Id{first.RequestId}) || len(pass.Delayed) != 0 || len(pass.Pending) != 0 || len(pass.Erased) != 0 {
		t.Fatalf("the pass over the lapsed request: %+v", pass)
	}
	if count := admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, owner.writer.sidecarId); count != 1 {
		t.Fatalf("%d bad_erasure alarms naming the lapsed request's signer", count)
	}

	// the second revocation's marker, a higher version, revives nothing: request 2 alone is work
	owner.mustSync(t)
	second, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || second.RequestId == first.RequestId || second.MarkerVersion != 4 || second.State != sidecar.DirectoryRevocationPending {
		t.Fatalf("the second revocation: %+v, %v", second, err)
	}
	owner.flush(t)
	pass = admin.pass(t, runner)
	if !slices.Equal(pass.Delayed, []sidecar.Id{second.RequestId}) || len(pass.Refused) != 0 || len(pass.Erased) != 0 ||
		len(pass.Pending) != 1 || pass.Pending[0].Request.RequestId != second.RequestId {
		t.Fatalf("the pass after the second revocation: %+v", pass)
	}
	if versions := testLapsedVersions(admin.client); len(versions) != 2 || versions[first.RequestId] != 3 || versions[second.RequestId] != 0 {
		t.Fatalf("the requests' lapses: %v", versions)
	}
	world.clock.Advance(4 * time.Minute)
	pass = admin.pass(t, runner)
	// the first announcement, the first marker, the item announced again and the run in P
	if len(pass.Erased) != 1 || len(pass.Erased[second.RequestId]) != 4 {
		t.Fatalf("the pass after the delay erased %v", pass.Erased)
	}
	admin.flush(t)
	if requestIds := world.erasureRequestIds(t); len(requestIds) == 0 || slices.ContainsFunc(requestIds, func(id sidecar.Id) bool { return id != second.RequestId }) {
		t.Fatalf("the ERASEs name %v, not request 2 alone", requestIds)
	}

	// the entries that showed the lapse are erased now, and request 1 stays lapsed, alarmed once
	pass = admin.pass(t, runner)
	if len(pass.Erased) != 0 || len(pass.Delayed) != 0 || len(pass.Pending) != 0 || len(pass.Refused) != 0 {
		t.Fatalf("the pass once the copies are erased: %+v", pass)
	}
	if versions := testLapsedVersions(admin.client); versions[first.RequestId] != 3 {
		t.Fatalf("the requests' lapses once the copies are erased: %v", versions)
	}
	if count := admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, owner.writer.sidecarId); count != 1 {
		t.Errorf("%d bad_erasure alarms naming the lapsed request's signer", count)
	}
	if lines := runner.StatusLines(); len(lines) != 0 {
		t.Errorf("an admin's status lines: %v", lines)
	}
	owner.mustSync(t)
	revocations, err := owner.client.Revocations()
	if err != nil || len(revocations) != 1 || revocations[0].RequestId != second.RequestId || revocations[0].State != sidecar.DirectoryRevocationDone ||
		revocations[0].EraserSidecarId == nil || *revocations[0].EraserSidecarId != admin.writer.sidecarId {
		t.Fatalf("the second revocation at its revoker: %+v, %v", revocations, err)
	}

	// a copy a daemon wrote since goes under request 2
	world.clock.Advance(time.Hour)
	world.publish()
	runWriter.announceRunIn(repoId, memberId)
	if pass = admin.pass(t, runner); !slices.Equal(pass.Delayed, []sidecar.Id{second.RequestId}) || len(pass.Refused) != 0 {
		t.Fatalf("the pass that first shows a later copy: %+v", pass)
	}
	world.clock.Advance(4 * time.Minute)
	if pass = admin.pass(t, runner); len(pass.Erased) != 1 || len(pass.Erased[second.RequestId]) != 1 {
		t.Fatalf("the sweep erased %v", pass.Erased)
	}
	admin.flush(t)

	// a restart: the copy holds none of the entries that showed the lapse, and the store keeps it
	restarted := world.restarted(admin)
	restartedRunner, restartedRaises := restarted.runner(t, 0, nil)
	world.clock.Advance(25 * time.Hour)
	world.publish()
	pass = restarted.pass(t, restartedRunner)
	for _, entry := range restarted.client.Entries() {
		if entry.Kind() != sidecar.RecordKindAnnounce || entry.Body == nil {
			continue
		}
		if item, err := sidecar.DirectoryDecodeAnnouncement(entry.Body); err == nil && sidecar.Id(item.GetWhere().GetRepoId()) == repoId && item.GetVersion() == 3 {
			t.Fatalf("the restarted copy still opens the item announced again")
		}
	}
	if slices.ContainsFunc(pass.Refused, func(id sidecar.Id) bool { return id != first.RequestId }) || len(pass.Delayed) != 0 || len(pass.Pending) != 0 || len(pass.Erased) != 0 {
		t.Fatalf("the restarted runner's pass: %+v", pass)
	}
	if versions := testLapsedVersions(restarted.client); versions[first.RequestId] != 3 || versions[second.RequestId] != 0 {
		t.Fatalf("the requests' lapses after a restart: %v", versions)
	}
	if raised := slices.Concat(raises.raised(), restartedRaises.raised()); len(raised) != 0 {
		t.Errorf("directory_erasure raised: %v", raised)
	}
	if requestIds := world.erasureRequestIds(t); slices.Contains(requestIds, first.RequestId) {
		t.Errorf("an ERASE names the lapsed request: %v", requestIds)
	}
}

// QD-1061's sequence at a copy that never opened what lapsed request 1: revoke P (request 1, marker version 2),
// announce P again (version 3), revoke P again (request 2, marker version 4), and request 2's ERASEs take every
// version below 4. A directory admin's device admitted after them cannot open version 3, so it finds no lapse; it
// reads request 1 superseded, its own marker gone under marker 4: not pending, though its push is past 24 h, nothing
// raised and no bad_erasure, and a copy a daemon writes since goes under request 2, this runner reaching the older
// request first.
func TestDirectoryRunnerReadsARequestSupersededOnACopyAdmittedAfterTheErasure(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	memberId := sidecar.NewId()
	runWriter := world.memberWriter(memberId)
	world.publish()
	runWriter.announceRunIn(repoId, memberId)
	admin := world.adminDevice()
	runner, _ := admin.runner(t, 0, nil)

	owner.mustSync(t)
	first, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || first.MarkerVersion != 2 {
		t.Fatalf("the first revocation: %+v, %v", first, err)
	}
	if _, err := owner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: "design notes", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	owner.flush(t)
	owner.mustSync(t)
	second, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || second.RequestId == first.RequestId || second.MarkerVersion != 4 {
		t.Fatalf("the second revocation: %+v, %v", second, err)
	}
	owner.flush(t)
	// the first announcement, the first marker, the item announced again and the run in P, all under request 2
	pass := admin.pass(t, runner)
	if !slices.Equal(pass.Refused, []sidecar.Id{first.RequestId}) || len(pass.Erased) != 1 || len(pass.Erased[second.RequestId]) != 4 {
		t.Fatalf("the pass of the runner that read the lapse: %+v", pass)
	}
	admin.flush(t)

	// a directory admin's device admitted a day later, past the 24 h a pending request alarms at
	world.clock.Advance(25 * time.Hour)
	world.publish()
	late := world.adminDevice()
	lateRunner, lateRaises := late.runner(t, 0, nil)
	pass = late.pass(t, lateRunner)
	for _, entry := range late.client.Entries() {
		if entry.Kind() != sidecar.RecordKindAnnounce || entry.Body == nil {
			continue
		}
		if item, err := sidecar.DirectoryDecodeAnnouncement(entry.Body); err == nil && sidecar.Id(item.GetWhere().GetRepoId()) == repoId && item.GetVersion() < 4 {
			t.Fatalf("the late copy opens version %d of the repo's item", item.GetVersion())
		}
	}
	if versions := testLapsedVersions(late.client); len(versions) != 2 || versions[first.RequestId] != 0 {
		t.Fatalf("the late copy found a lapse it holds nothing of: %v", versions)
	}
	if !slices.Equal(pass.Superseded, []sidecar.Id{first.RequestId}) || len(pass.Pending) != 0 || len(pass.Refused) != 0 || len(pass.Delayed) != 0 || len(pass.Erased) != 0 {
		t.Fatalf("the late runner's pass: %+v", pass)
	}
	if lines := lateRunner.StatusLines(); len(lines) != 0 {
		t.Errorf("the late admin's status lines: %v", lines)
	}
	if lines := late.client.ErasureStatusLines(nil); len(lines) != 0 {
		t.Errorf("ur status on the late admin's device: %v", lines)
	}
	if pending := lateRunner.Pending(); len(pending) != 0 {
		t.Errorf("%d requests pending on the late admin's device", len(pending))
	}

	// a copy a daemon wrote since goes under request 2, on the runner that holds no lapse
	runWriter.announceRunIn(repoId, memberId)
	pass = late.pass(t, lateRunner)
	if !slices.Equal(pass.Superseded, []sidecar.Id{first.RequestId}) || len(pass.Erased) != 1 || len(pass.Erased[second.RequestId]) != 1 || len(pass.Pending) != 0 {
		t.Fatalf("the late runner's sweep: %+v", pass)
	}
	late.flush(t)
	if requestIds := world.erasureRequestIds(t); len(requestIds) == 0 || slices.ContainsFunc(requestIds, func(id sidecar.Id) bool { return id != second.RequestId }) {
		t.Errorf("the ERASEs name %v, not request 2 alone", requestIds)
	}
	if raised := lateRaises.raised(); len(raised) != 0 {
		t.Errorf("directory_erasure raised on the late admin's device: %v", raised)
	}
	if count := late.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, owner.writer.sidecarId); count != 0 {
		t.Errorf("%d bad_erasure alarms for a superseded request", count)
	}
}

// A request whose marker a later request erased before the older one was worked (QD-1061): a repo that nothing in the
// directory names yet is revoked by one of its admins (request 1, marker version 1), which has no copy to erase, so no
// ERASE names it and it waits, alarming past 24 h. Its other admin revokes it too (request 2, marker version 2), and
// request 2's ERASE takes the first marker. Request 1 then reads superseded on the runner and lapsed at its revoker,
// whose next revoke files a new request above the marker that stands.
func TestDirectoryRunnerSupersedesARequestWhoseMarkerALaterRequestErased(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	firstWriter := world.memberWriter(sidecar.NewId())
	secondWriter := world.memberWriter(sidecar.NewId())
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, firstWriter, secondWriter)
	firstOwner := world.device(firstWriter)
	secondOwner := world.device(secondWriter)
	admin := world.adminDevice()
	runner, raises := admin.runner(t, 0, nil)

	firstOwner.mustSync(t)
	first, err := firstOwner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || first.MarkerVersion != 1 {
		t.Fatalf("the first revocation: %+v, %v", first, err)
	}
	firstOwner.flush(t)
	world.clock.Advance(25 * time.Hour)
	world.publish()
	pass := admin.pass(t, runner)
	if len(pass.Pending) != 1 || pass.Pending[0].Request.RequestId != first.RequestId || len(pass.Erased) != 0 || len(pass.Superseded) != 0 {
		t.Fatalf("the pass over a request with nothing to erase: %+v", pass)
	}
	if raised := raises.raised(); !slices.Equal(raised, []string{sidecar.SidecarDirectoryErasurePending}) {
		t.Fatalf("raised past 24 h: %v", raised)
	}

	secondOwner.mustSync(t)
	second, err := secondOwner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || second.RequestId == first.RequestId || second.MarkerVersion != 2 {
		t.Fatalf("the second revocation: %+v, %v", second, err)
	}
	secondOwner.flush(t)
	// request 1 is read first and still opens its marker; request 2 erases that marker
	pass = admin.pass(t, runner)
	if len(pass.Erased) != 1 || len(pass.Erased[second.RequestId]) != 1 || len(pass.Pending) != 1 || pass.Pending[0].Request.RequestId != first.RequestId {
		t.Fatalf("the pass that works the later request: %+v", pass)
	}
	admin.flush(t)

	pass = admin.pass(t, runner)
	if !slices.Equal(pass.Superseded, []sidecar.Id{first.RequestId}) || len(pass.Pending) != 0 || len(pass.Refused) != 0 || len(pass.Delayed) != 0 || len(pass.Erased) != 0 {
		t.Fatalf("the pass once the first marker is erased: %+v", pass)
	}
	if lines := runner.StatusLines(); len(lines) != 0 {
		t.Errorf("an admin's status lines: %v", lines)
	}
	// nothing more is raised for it: the pending raised while it waited is the last
	if raised := raises.raised(); !slices.Equal(raised, []string{sidecar.SidecarDirectoryErasurePending}) {
		t.Errorf("raised: %v", raised)
	}
	if count := admin.alarmsNaming(sidecar.SidecarRecordAlarmBadErasure, firstWriter.sidecarId); count != 0 {
		t.Errorf("%d bad_erasure alarms for a superseded request", count)
	}
	if requestIds := world.erasureRequestIds(t); len(requestIds) != 1 || requestIds[0] != second.RequestId {
		t.Errorf("the ERASEs name %v, not request 2 alone", requestIds)
	}

	// its revoker reads it lapsed, the later revoker reads done
	firstOwner.mustSync(t)
	revocations, err := firstOwner.client.Revocations()
	if err != nil || len(revocations) != 1 || revocations[0].RequestId != first.RequestId || revocations[0].State != sidecar.DirectoryRevocationLapsed || !revocations[0].Superseded {
		t.Fatalf("the superseded revocation at its revoker: %+v, %v", revocations, err)
	}
	if lines := firstOwner.client.RevocationStatusLines(); len(lines) != 0 {
		t.Errorf("the superseded revocation's status lines: %v", lines)
	}
	secondOwner.mustSync(t)
	revocations, err = secondOwner.client.Revocations()
	if err != nil || len(revocations) != 1 || revocations[0].RequestId != second.RequestId || revocations[0].State != sidecar.DirectoryRevocationDone {
		t.Fatalf("the later revocation at its revoker: %+v, %v", revocations, err)
	}
	// a person's revoke on the first device is a new request above the marker that stands
	third, err := firstOwner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || third.RequestId == first.RequestId || third.MarkerVersion != 3 || third.State != sidecar.DirectoryRevocationPending || third.Superseded {
		t.Fatalf("a revoke over a superseded revocation: %+v, %v", third, err)
	}
}

// A revocation this copy has not read back is not superseded by a marker another device wrote above it meanwhile: its
// own marker is not gone, it has not arrived. P's other admin announces it again (version 2) and revokes it (marker
// version 3) while the first admin's revocation (marker version 2) waits unpushed. The first reads pending under
// marker 3 before its push and after it, and its request is worked.
func TestDirectoryRevokeNotReadBackIsNotSuperseded(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	firstWriter := world.memberWriter(sidecar.NewId())
	secondWriter := world.memberWriter(sidecar.NewId())
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, firstWriter, secondWriter)
	firstOwner := world.device(firstWriter)
	secondOwner := world.device(secondWriter)
	if _, err := firstOwner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: "design notes", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	firstOwner.flush(t)
	firstOwner.mustSync(t)
	secondOwner.mustSync(t)
	if _, err := secondOwner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: "design notes", Description: "the redesign", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	secondOwner.flush(t)
	secondOwner.mustSync(t)
	second, err := secondOwner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || second.MarkerVersion != 3 {
		t.Fatalf("the second admin's revocation: %+v, %v", second, err)
	}
	secondOwner.flush(t)

	// the first admin's copy still shows version 1: its marker is version 2, and waits unpushed
	first, err := firstOwner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || first.MarkerVersion != 2 || first.RequestId == second.RequestId {
		t.Fatalf("the first admin's revocation: %+v, %v", first, err)
	}
	firstOwner.mustSync(t)
	if marker := testRepoItemShown(t, firstOwner.testDirectoryReader, repoId); marker == nil || marker.Display != sidecar.DirectoryItemPrivate || marker.Announcement.GetVersion() != 3 {
		t.Fatalf("the item the first admin's copy shows: %v", marker)
	}
	revocations, err := firstOwner.client.Revocations()
	if err != nil || len(revocations) != 1 || revocations[0].RequestId != first.RequestId || revocations[0].State != sidecar.DirectoryRevocationPending || revocations[0].Superseded {
		t.Fatalf("the revocation before its push: %+v, %v", revocations, err)
	}
	world.clock.Advance(time.Minute)
	world.publish()
	firstOwner.flush(t)
	firstOwner.mustSync(t)
	revocations, err = firstOwner.client.Revocations()
	if err != nil || len(revocations) != 1 || revocations[0].State != sidecar.DirectoryRevocationPending || revocations[0].Superseded {
		t.Fatalf("the revocation once pushed: %+v, %v", revocations, err)
	}
	// both requests are worked in push order: the second admin's takes every version below 3, the first marker among
	// them, and the first admin's, whose marker this copy still opens under marker 3, the version below 2
	admin := world.adminDevice()
	runner, _ := admin.runner(t, 0, nil)
	pass := admin.pass(t, runner)
	if len(pass.Superseded) != 0 || len(pass.Erased) != 2 || len(pass.Erased[second.RequestId]) != 3 || len(pass.Erased[first.RequestId]) != 1 {
		t.Fatalf("the runner's pass: %+v", pass)
	}
}

// Expiry keeps the marker of a request inside its delay. P is revoked (request 1, marker version 2) and marked private
// again (version 3, a marker that files no request), and no directory admin's daemon runs for 31 days, so the first
// marker is past its 30 days under the newer one when a runner starts. Expired in the pass that first showed the
// request's work, it would read the request superseded with a copy a daemon wrote still unerased. The runner holds it
// through the delay, erases the copy under the request, and only then lets the marker go.
func TestDirectoryRunnerExpiryKeepsTheMarkerOfARequestInsideItsDelay(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	memberId := sidecar.NewId()
	runWriter := world.memberWriter(memberId)
	world.publish()
	owner.mustSync(t)
	first, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil || first.MarkerVersion != 2 {
		t.Fatalf("the revocation: %+v, %v", first, err)
	}
	owner.flush(t)
	owner.mustSync(t)
	if _, err := owner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, Private: true, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	owner.flush(t)
	world.clock.Advance(31 * 24 * time.Hour)
	world.publish()
	// a daemon that has not read the marker yet writes a copy naming the repo
	runWriter.announceRunIn(repoId, memberId)

	admin := world.adminDevice()
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
		Client: admin.client,
		Erase:  admin.record.Eraser().Erase,
		Expire: func(ctx context.Context, directoryId sidecar.Id, hold func(entry *sidecar.RecordReadEntry) bool) error {
			_, err := admin.record.Retention().Expire(ctx, &sidecar.RecordRetentionExpireArgs{LogId: directoryId, Hold: hold})
			return err
		},
		Random: &testErasureDelay{delay: 4 * time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	markerVersions := func() []uint64 {
		versions := []uint64{}
		for _, item := range admin.liveAnnouncements(t) {
			if sidecar.DirectoryAnnouncementKind(item.GetKind()) == sidecar.DirectoryAnnouncementKindRepo && item.GetWhere().GetPrivate() {
				versions = append(versions, item.GetVersion())
			}
		}
		slices.Sort(versions)
		return versions
	}
	// the pass that first shows the work expires the first announcement, 31 days replaced, and keeps the first marker
	pass := admin.pass(t, runner)
	if !slices.Equal(pass.Delayed, []sidecar.Id{first.RequestId}) || len(pass.Erased) != 0 || len(pass.Superseded) != 0 {
		t.Fatalf("the pass that first shows the work: %+v", pass)
	}
	admin.flush(t)
	if versions := markerVersions(); !slices.Equal(versions, []uint64{2, 3}) {
		t.Fatalf("the markers held inside the delay: %v", versions)
	}
	if live := admin.liveAnnouncements(t); len(live) != 3 {
		t.Fatalf("%d announce entries held inside the delay, not the two markers and the run", len(live))
	}
	world.clock.Advance(4 * time.Minute)
	pass = admin.pass(t, runner)
	if len(pass.Erased) != 1 || len(pass.Erased[first.RequestId]) != 1 || len(pass.Superseded) != 0 {
		t.Fatalf("the pass after the delay: %+v", pass)
	}
	admin.flush(t)
	// one ERASE names the request, the run its only entry; the others are expiry's
	erasures, err := world.streams.For(world.readerId).ReadErasures(t.Context(), world.directoryId, 0)
	if err != nil {
		t.Fatal(err)
	}
	named := 0
	for _, erasure := range erasures {
		body := &protocol.ErasureBody{}
		if err := proto.Unmarshal(erasure.SealedNote, body); err != nil {
			t.Fatal(err)
		}
		if sidecar.RecordErasureReason(body.GetReason()) != sidecar.RecordErasureReasonRevocation {
			continue
		}
		if erasure.ErasureId != first.RequestId || !bytes.Equal(body.GetRequestId(), first.RequestId.Bytes()) || len(body.GetEntryIds()) != 1 {
			t.Fatalf("a revocation's ERASE: id %s, note %v", erasure.ErasureId, body)
		}
		named += 1
	}
	if named != 1 {
		t.Fatalf("%d ERASEs name the request", named)
	}
	// its work done, the first marker expires, and the request, an ERASE naming it, reads superseded and is not swept
	if versions := markerVersions(); !slices.Equal(versions, []uint64{3}) {
		t.Fatalf("the markers held once the request is erased: %v", versions)
	}
	pass = admin.pass(t, runner)
	if !slices.Equal(pass.Superseded, []sidecar.Id{first.RequestId}) || len(pass.Pending) != 0 || len(pass.Erased) != 0 {
		t.Fatalf("the pass once the first marker expired: %+v", pass)
	}
}

func TestDirectoryRunnersRacingCommitOneErase(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	owner.mustSync(t)
	revocation, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	owner.flush(t)
	first := world.adminDevice()
	second := world.adminDevice()
	firstRunner, _ := first.runner(t, 0, nil)
	secondRunner, _ := second.runner(t, 0, nil)
	// both have synced the work before either's ERASE commits
	first.mustSync(t)
	second.mustSync(t)
	firstPass, err := firstRunner.Pass(t.Context())
	if err != nil || len(firstPass.Erased[revocation.RequestId]) != 1 {
		t.Fatalf("the first runner: %+v, %v", firstPass, err)
	}
	if _, err := secondRunner.Pass(t.Context()); err != nil {
		t.Fatalf("the second runner: %v", err)
	}
	erasures, err := world.streams.For(world.readerId).ReadErasures(t.Context(), world.directoryId, 0)
	if err != nil || len(erasures) != 1 || erasures[0].EraserSidecarId != first.writer.sidecarId || erasures[0].ErasureId != revocation.RequestId {
		t.Fatalf("the committed ERASEs: %d, %v", len(erasures), err)
	}
	// a runner that syncs the ERASE finds nothing left
	third := world.adminDevice()
	thirdRunner, _ := third.runner(t, 0, nil)
	if pass := third.pass(t, thirdRunner); len(pass.Erased) != 0 || len(pass.Pending) != 0 {
		t.Fatalf("a later runner: %+v", pass)
	}
	if violations := world.streams.Violations(); len(violations) != 0 {
		t.Errorf("violations: %v", violations)
	}
}

func TestDirectoryRunnerIsTheIndexerAdminElseEveryAdmin(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	owner.mustSync(t)
	if _, err := owner.client.RevokeRepo(t.Context(), &sidecar.DirectoryRevokeArgs{RepoId: repoId, Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	owner.flush(t)
	admin := world.adminDevice()
	indexer := world.adminDevice()
	indexers := []sidecar.Id{indexer.writer.sidecarId}
	// a network-scope indexer that is a directory admin is the runner: another admin's daemon only names what waits
	runner, _ := admin.runner(t, 0, func() []sidecar.Id { return indexers })
	if pass := admin.pass(t, runner); pass.Runs || len(pass.Erased) != 0 || len(pass.Pending) != 1 {
		t.Fatalf("an admin beside an indexer admin: %+v", pass)
	}
	// a device that is no directory admin does nothing
	member := world.device(world.memberWriter(sidecar.NewId()))
	world.publish()
	memberRunner, _ := member.runner(t, 0, nil)
	if pass := member.pass(t, memberRunner); pass.Runs || len(pass.Pending) != 0 || len(memberRunner.StatusLines()) != 0 {
		t.Fatalf("a member's device: %+v", pass)
	}
	// an indexer that is no directory admin leaves every admin's daemon the runner
	indexers = []sidecar.Id{member.writer.sidecarId}
	if pass := admin.pass(t, runner); !pass.Runs || len(pass.Erased) != 1 {
		t.Fatalf("an admin beside an indexer that is no admin: %+v", pass)
	}
	// and the indexer admin runs when it is one
	indexers = []sidecar.Id{indexer.writer.sidecarId}
	indexerRunner, _ := indexer.runner(t, 0, func() []sidecar.Id { return indexers })
	if pass := indexer.pass(t, indexerRunner); !pass.Runs {
		t.Fatalf("the indexer admin: %+v", pass)
	}
}

func TestDirectoryRunnerExpiryHoldsAnItemsNewestCopy(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	memberId := sidecar.NewId()
	runWriter := world.memberWriter(memberId)
	world.publish()
	runWriter.announceRunIn(repoId, memberId)
	world.clock.Advance(10 * 24 * time.Hour)
	world.publish()
	owner.mustSync(t)
	if _, err := owner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: "design notes", Description: "ten days on", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	owner.flush(t)

	admin := world.adminDevice()
	holds := 0
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
		Client: admin.client,
		Erase:  admin.record.Eraser().Erase,
		Expire: func(ctx context.Context, directoryId sidecar.Id, hold func(entry *sidecar.RecordReadEntry) bool) error {
			holds += 1
			_, err := admin.record.Retention().Expire(ctx, &sidecar.RecordRetentionExpireArgs{LogId: directoryId, Hold: hold})
			return err
		},
		Random: &testErasureDelay{},
	})
	if err != nil {
		t.Fatal(err)
	}
	// at day 35 the first version, replaced at day 10, is still within its 30 days; the run's item expired at day 0
	world.clock.Advance(25 * 24 * time.Hour)
	world.publish()
	admin.pass(t, runner)
	admin.flush(t)
	titles := func() []string {
		titles := []string{}
		for _, item := range admin.liveAnnouncements(t) {
			if sidecar.DirectoryAnnouncementKind(item.GetKind()) == sidecar.DirectoryAnnouncementKindRun {
				titles = append(titles, "run")
				continue
			}
			titles = append(titles, item.GetWhat().GetDescription())
		}
		slices.Sort(titles)
		return titles
	}
	if got := titles(); !slices.Equal(got, []string{"", "ten days on"}) || holds != 1 {
		t.Fatalf("held at day 35: %v after %d expiry passes", got, holds)
	}
	// at day 45 the first version is 35 days replaced and goes; the newest copy stays however old
	world.clock.Advance(10 * 24 * time.Hour)
	world.publish()
	admin.pass(t, runner)
	admin.flush(t)
	if got := titles(); !slices.Equal(got, []string{"ten days on"}) {
		t.Fatalf("held at day 45: %v", got)
	}
	world.clock.Advance(400 * 24 * time.Hour)
	world.publish()
	admin.pass(t, runner)
	admin.flush(t)
	if got := titles(); !slices.Equal(got, []string{"ten days on"}) {
		t.Fatalf("held at day 445: %v", got)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, repoId); item == nil || item.Announcement.GetWhat().GetDescription() != "ten days on" {
		t.Errorf("the item after expiry: %v", item)
	}
}
