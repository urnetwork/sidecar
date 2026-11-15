//go:build !sidecar_http

// RECORD-M6-20's erasure runner and the directory admin's erasure on sidecartest's fakes, FS-99's M6 cases: an
// admin's ERASE of another writer's entry; a runner that starts after 24 h raising directory_erasure, waiting its
// delay and erasing exactly the copies naming the repo, each ERASE naming the request; later copies swept while the
// marker stands; a non-admin's request, and one after the repo is announced again, erasing nothing and alarming; two
// runners racing, one ERASE committing; the indexer rule; and expiry holding an item's newest copy.

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
	stranger := world.device(world.memberWriter(sidecar.NewId()))
	world.publish()
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
