//go:build !sidecar_http

// RECORD-M6-14's fold on sidecartest's fakes, its entries sealed and signed for real so each reader verifies them as
// any log's: a run and its renewal, a withdrawal, a reused announcement_id, the fold reaching one state whatever order
// the streams arrive in, and List and Get over it. The card rules' FS-84 cases are directory_rules_test.go's.

package sidecar_test

import (
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A writer admitted in both states as a member device of memberId, consented and standing, writing its own stream and
// reading the directory, as every admitted sidecar of a team does (§16.11's readers row).
func (self *testDirectoryWorld) memberWriter(memberId sidecar.Id) *testDirectoryWriter {
	writer := self.writer()
	self.directoryFixture.Sidecars[writer.sidecarId] = &sidecartest.FakeDirectorySidecar{MemberId: &memberId}
	self.recordFixture.Members[writer.sidecarId] = memberId
	repo := self.recordFixture.Repos[self.directoryId]
	repo.Readers = append(repo.Readers, writer.sidecarId)
	return writer
}

// Appends count positions to both states, the clock moving step between them.
func (self *testDirectoryWorld) advance(count int, step time.Duration) {
	for i := 0; i < count; i += 1 {
		self.clock.Advance(step)
		self.publish()
	}
}

// Seals item as the writer's announce entry and pushes it in stream's own stream, the writer's when stream is nil, at
// pin, the world's tip when pin is nil. Answers the pin.
func (self *testDirectoryWriter) announceIn(item *protocol.Announcement, stream *testDirectoryWriter, pin *bridge.AuthPin) *bridge.AuthPin {
	t := self.world.t
	t.Helper()
	if stream == nil {
		stream = self
	}
	if pin == nil {
		pin = self.world.recordAuth.Tip().Pin()
	}
	sealed, err := sidecar.RecordSeal(self.env, &sidecar.RecordSealArgs{
		LogId:         self.world.directoryId,
		Kind:          sidecar.RecordKindAnnounce,
		Source:        sidecar.RecordSourceObserved,
		TimeMillis:    self.world.clock.Now().UnixMilli(),
		PolicyVersion: pin.GetVersion(),
		Body:          item,
	})
	if err != nil {
		t.Fatal(err)
	}
	stream.counter += 1
	path, err := sidecar.RecordStreamPath(stream.counter)
	if err != nil {
		t.Fatal(err)
	}
	push := &sidecar.RecordStreamPush{
		PushId:          sidecar.NewId(),
		WriterSidecarId: stream.sidecarId,
		SlotId:          sidecar.NewId(),
		AuthPin:         pin,
		SlotRows:        []*sidecar.RecordSlotRow{sealed.SlotRow(0)},
	}
	push.Entries = []*sidecar.RecordStreamEntry{{Path: path, Entry: sealed.EntryBytes(&push.SlotId, 0)}}
	if _, err := self.world.streams.For(stream.sidecarId).Append(t.Context(), self.world.directoryId, push); err != nil {
		t.Fatal(err)
	}
	return pin
}

// Seals item as the writer's announce entry in its own stream at the world's tip.
func (self *testDirectoryWriter) announce(item *protocol.Announcement) {
	self.world.t.Helper()
	self.announceIn(item, nil, nil)
}

// A run item of writerId's for memberId (nil for none): version, renewed at renewedMillis and expiring 90 min on.
func testRunItem(writerId sidecar.Id, memberId *sidecar.Id, announcementId sidecar.Id, version uint64, renewedMillis int64) *protocol.Announcement {
	expiresMillis, _ := sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, renewedMillis)
	item := &protocol.Announcement{
		AnnouncementId: announcementId.Bytes(),
		Kind:           uint32(sidecar.DirectoryAnnouncementKindRun),
		Version:        version,
		StartedMillis:  renewedMillis,
		RenewedMillis:  renewedMillis,
		ExpiresMillis:  expiresMillis,
		State:          uint32(sidecar.DirectoryAnnouncementStateActive),
		Who: &protocol.AnnounceWho{
			SidecarId:  writerId.Bytes(),
			AgentId:    sidecar.NewId().Bytes(),
			AgentLabel: "builder",
			Harness:    "claude-code",
		},
		What:  &protocol.AnnounceWhat{Title: "refactor the settings loader", RunId: sidecar.NewId().Bytes()},
		Where: &protocol.AnnounceWhere{Project: "example.org/team/app", Branch: "main"},
	}
	if memberId != nil {
		item.Who.MemberId = memberId.Bytes()
	}
	return item
}

// A worker item of writerId's for memberId.
func testWorkerItem(writerId sidecar.Id, memberId *sidecar.Id, announcementId sidecar.Id, version uint64, renewedMillis int64) *protocol.Announcement {
	expiresMillis, _ := sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindWorker, renewedMillis)
	item := &protocol.Announcement{
		AnnouncementId: announcementId.Bytes(),
		Kind:           uint32(sidecar.DirectoryAnnouncementKindWorker),
		Version:        version,
		StartedMillis:  renewedMillis,
		RenewedMillis:  renewedMillis,
		ExpiresMillis:  expiresMillis,
		State:          uint32(sidecar.DirectoryAnnouncementStateActive),
		Who:            &protocol.AnnounceWho{SidecarId: writerId.Bytes()},
		What: &protocol.AnnounceWhat{
			Description: "a build host",
			Harnesses:   []string{"codex"},
			Services:    []*protocol.Service{{Kind: uint32(sidecar.DirectoryServiceKindBridgePort), Name: "tcp:8080", Description: "a preview server"}},
			Requests:    uint32(sidecar.DirectoryRequestsOpen),
		},
		Where: &protocol.AnnounceWhere{HostLabel: "build-host"},
	}
	if memberId != nil {
		item.Who.MemberId = memberId.Bytes()
	}
	return item
}

// A withdrawal of a run item: its id, kind and who at version, renewed at renewedMillis.
func testWithdrawal(writerId sidecar.Id, memberId *sidecar.Id, announcementId sidecar.Id, version uint64, renewedMillis int64) *protocol.Announcement {
	expiresMillis, _ := sidecar.DirectoryAnnouncementExpiresMillis(sidecar.DirectoryAnnouncementKindRun, renewedMillis)
	item := &protocol.Announcement{
		AnnouncementId: announcementId.Bytes(),
		Kind:           uint32(sidecar.DirectoryAnnouncementKindRun),
		Version:        version,
		RenewedMillis:  renewedMillis,
		ExpiresMillis:  expiresMillis,
		State:          uint32(sidecar.DirectoryAnnouncementStateWithdrawn),
		Who:            &protocol.AnnounceWho{SidecarId: writerId.Bytes()},
	}
	if memberId != nil {
		item.Who.MemberId = memberId.Bytes()
	}
	return item
}

// A repo item of writerId's for repoId of kind, or its private marker, offering reader and writer with requests open,
// padded to its 2,048 B steps.
func testRepoItem(t *testing.T, writerId sidecar.Id, memberId *sidecar.Id, repoId sidecar.Id, kind protocol.RepoKind, version uint64, renewedMillis int64, title string, private bool) *protocol.Announcement {
	t.Helper()
	announcementId := sidecar.DirectoryRepoAnnouncementId(repoId)
	item := &protocol.Announcement{
		AnnouncementId: announcementId.Bytes(),
		Kind:           uint32(sidecar.DirectoryAnnouncementKindRepo),
		Version:        version,
		StartedMillis:  renewedMillis,
		RenewedMillis:  renewedMillis,
		State:          uint32(sidecar.DirectoryAnnouncementStateActive),
		Who:            &protocol.AnnounceWho{SidecarId: writerId.Bytes()},
		What:           &protocol.AnnounceWhat{RepoKind: uint32(kind), Requests: uint32(sidecar.DirectoryRequestsOpen)},
		Where:          &protocol.AnnounceWhere{RepoId: repoId.Bytes()},
	}
	if private {
		item.Where.Private = true
	} else {
		item.What.Title = title
		item.What.Roles = []uint32{uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_READER), uint32(protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER)}
	}
	if memberId != nil {
		item.Who.MemberId = memberId.Bytes()
	}
	if _, err := sidecar.DirectoryPadRepoAnnouncement(item); err != nil {
		t.Fatal(err)
	}
	return item
}

// The alarms raised for reason naming sidecarId.
func (self *testDirectoryReader) alarmsNaming(reason sidecar.SidecarRecordAlarm, sidecarId sidecar.Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	count := 0
	for _, alarm := range self.alarms {
		if alarm.Reason == reason && alarm.SidecarId != nil && *alarm.SidecarId == sidecarId {
			count += 1
		}
	}
	return count
}

// Every item List answers, private markers included.
func (self *testDirectoryReader) items(t *testing.T) []*sidecar.DirectoryItem {
	t.Helper()
	items, err := self.client.List(&sidecar.DirectoryFilter{IncludePrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// The one item of writerId's, failing the test unless exactly one shows.
func testOnlyItemOf(t *testing.T, items []*sidecar.DirectoryItem, writerId sidecar.Id) *sidecar.DirectoryItem {
	t.Helper()
	found := []*sidecar.DirectoryItem{}
	for _, item := range items {
		if item.SignerSidecarId == writerId {
			found = append(found, item)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d items signed by %s", len(found), writerId)
	}
	return found[0]
}

// A run shows active with its who from the reader's state, and a renewal, a new entry at the same version with a later
// renewed_millis, replaces it rather than adding a second.
func TestDirectoryFoldShowsARunAndItsRenewal(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	runId := sidecar.NewId()
	started := world.clock.Now().UnixMilli()
	writer.announce(testRunItem(writer.sidecarId, &memberId, runId, 1, started))
	world.clock.Advance(time.Hour)
	renewed := testRunItem(writer.sidecarId, &memberId, runId, 1, world.clock.Now().UnixMilli())
	renewed.StartedMillis = started
	writer.announce(renewed)

	reader := world.reader(nil)
	reader.mustSync(t)
	items := reader.items(t)
	if len(items) != 1 {
		t.Fatalf("%d items", len(items))
	}
	item := items[0]
	if item.Display != sidecar.DirectoryItemActive || item.Announcement.GetRenewedMillis() != renewed.GetRenewedMillis() ||
		item.Announcement.GetStartedMillis() != started {
		t.Errorf("shown %s, renewed %d, started %d", item.Display, item.Announcement.GetRenewedMillis(), item.Announcement.GetStartedMillis())
	}
	if item.MemberId == nil || *item.MemberId != memberId || !item.MemberDevice || item.AutogroupAdmin {
		t.Errorf("who %v, member device %v", item.MemberId, item.MemberDevice)
	}
	if item.Key != (sidecar.DirectoryItemKey{Kind: sidecar.DirectoryAnnouncementKindRun, WriterSidecarId: writer.sidecarId, AnnouncementId: runId}) {
		t.Errorf("key %+v", item.Key)
	}
	if len(reader.alarmReasons()) != 0 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}
}

// A withdrawal hides its item at once, never as stale or ended, and a version above it counts for nothing: state 4 is
// terminal (plan-RECORD-m6-carrier #1).
func TestDirectoryFoldWithdrawalHidesTheItem(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	runId := sidecar.NewId()
	writer.announce(testRunItem(writer.sidecarId, &memberId, runId, 1, world.clock.Now().UnixMilli()))
	reader := world.reader(nil)
	reader.mustSync(t)
	if len(reader.items(t)) != 1 {
		t.Fatal("the run before its withdrawal")
	}
	world.clock.Advance(time.Minute)
	writer.announce(testWithdrawal(writer.sidecarId, &memberId, runId, 2, world.clock.Now().UnixMilli()))
	reader.mustSync(t)
	if items := reader.items(t); len(items) != 0 {
		t.Fatalf("%d items after the withdrawal, the first %s", len(items), items[0].Display)
	}
	world.clock.Advance(time.Minute)
	writer.announce(testRunItem(writer.sidecarId, &memberId, runId, 3, world.clock.Now().UnixMilli()))
	reader.mustSync(t)
	if items := reader.items(t); len(items) != 0 {
		t.Errorf("a version above a withdrawal shows %d items", len(items))
	}
}

// Two writers on one run id are two items, each under its own writer, neither voiding the other, and readers raise
// id_reuse naming each (plan-RECORD-small-readings #2); Get asks which writer's.
func TestDirectoryFoldReusedAnnouncementIdIsTwoItems(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	firstMember, secondMember := sidecar.NewId(), sidecar.NewId()
	first := world.memberWriter(firstMember)
	second := world.memberWriter(secondMember)
	world.publish()
	runId := sidecar.NewId()
	nowMillis := world.clock.Now().UnixMilli()
	first.announce(testRunItem(first.sidecarId, &firstMember, runId, 1, nowMillis))
	// the copy names a higher version, which would win a fold across writers
	second.announce(testRunItem(second.sidecarId, &secondMember, runId, 9, nowMillis+1))

	reader := world.reader(nil)
	reader.mustSync(t)
	items := reader.items(t)
	if len(items) != 2 {
		t.Fatalf("%d items", len(items))
	}
	firstItem := testOnlyItemOf(t, items, first.sidecarId)
	secondItem := testOnlyItemOf(t, items, second.sidecarId)
	if firstItem.Announcement.GetVersion() != 1 || secondItem.Announcement.GetVersion() != 9 ||
		*firstItem.MemberId != firstMember || *secondItem.MemberId != secondMember {
		t.Errorf("versions %d and %d", firstItem.Announcement.GetVersion(), secondItem.Announcement.GetVersion())
	}
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmIdReuse, first.sidecarId) != 1 ||
		reader.alarmsNaming(sidecar.SidecarRecordAlarmIdReuse, second.sidecarId) != 1 {
		t.Errorf("alarms %v", reader.alarmReasons())
	}
	// a later view raises nothing again
	reader.items(t)
	if reader.alarmsNaming(sidecar.SidecarRecordAlarmIdReuse, first.sidecarId) != 1 {
		t.Error("id_reuse raised twice")
	}
	if _, err := reader.client.Get(runId, nil); !errors.Is(err, sidecar.ErrDirectoryItemAmbiguous) {
		t.Errorf("an ambiguous Get: %v", err)
	}
	item, err := reader.client.Get(runId, &first.sidecarId)
	if err != nil || item.SignerSidecarId != first.sidecarId {
		t.Errorf("the first writer's: %v", err)
	}
	if _, err := reader.client.Get(sidecar.NewId(), nil); !errors.Is(err, sidecar.ErrDirectoryItemNone) {
		t.Errorf("a missing item: %v", err)
	}
}

// What a view shows, comparable across folds.
func testDirectoryViewOf(t *testing.T, items []*sidecar.DirectoryItem) []string {
	t.Helper()
	view := []string{}
	for _, item := range items {
		body, err := proto.MarshalOptions{Deterministic: true}.Marshal(item.Announcement)
		if err != nil {
			t.Fatal(err)
		}
		view = append(view, string(item.Display)+" "+item.SignerSidecarId.String()+" "+item.EntryId.String()+" "+string(body))
	}
	return view
}

// The fold reaches one state whatever order its entries and streams arrive in (FS-84's last clause): every seeded
// shuffle of a reader's entries folds to the same view, and a reader that synced after each writer's push shows what
// one that synced once at the end shows.
func TestDirectoryFoldIsOneStateWhateverTheOrder(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	members := []sidecar.Id{sidecar.NewId(), sidecar.NewId(), sidecar.NewId()}
	writers := []*testDirectoryWriter{}
	for _, memberId := range members {
		writers = append(writers, world.memberWriter(memberId))
	}
	repoId := sidecar.NewId()
	world.directoryFixture.Repos[repoId] = &sidecartest.FakeDirectoryRepo{
		Kind: protocol.RepoKind_REPO_KIND_GENERAL,
		Admins: []sidecartest.FakeDirectoryRepoAdmin{
			{SidecarId: writers[0].sidecarId, At: 1}, {SidecarId: writers[1].sidecarId, At: 1},
		},
	}
	world.publish()
	early := world.reader(nil)
	sharedRunId := sidecar.NewId()
	for round := 0; round < 3; round += 1 {
		for index, writer := range writers {
			memberId := members[index]
			nowMillis := world.clock.Now().UnixMilli()
			writer.announce(testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, nowMillis))
			// a renewal of one shared id per writer, and a reuse of it across writers
			writer.announce(testRunItem(writer.sidecarId, &memberId, sharedRunId, 1, nowMillis+int64(round)))
			if round == 2 && index == 2 {
				writer.announce(testWithdrawal(writer.sidecarId, &memberId, sharedRunId, 2, nowMillis+10))
			}
			if index < 2 {
				// two admins of one repo, the tie going to the higher writer id
				writer.announce(testRepoItem(t, writer.sidecarId, &memberId, repoId, protocol.RepoKind_REPO_KIND_GENERAL, uint64(round+1), nowMillis, "the shared repo", false))
			}
			world.clock.Advance(time.Second)
			early.mustSync(t)
		}
		writers[round].announce(testWorkerItem(writers[round].sidecarId, &members[round], sidecar.NewId(), 1, world.clock.Now().UnixMilli()))
	}
	late := world.reader(nil)
	late.mustSync(t)
	early.mustSync(t)

	want := testDirectoryViewOf(t, late.items(t))
	if len(want) == 0 {
		t.Fatal("nothing shows")
	}
	if got := testDirectoryViewOf(t, early.items(t)); !slices.Equal(got, want) {
		t.Errorf("a reader syncing after each push shows %d items, one syncing once %d", len(got), len(want))
	}
	entries := late.client.Entries()
	random := rand.New(rand.NewPCG(84, 16))
	for shuffle := 0; shuffle < 32; shuffle += 1 {
		random.Shuffle(len(entries), func(i int, j int) { entries[i], entries[j] = entries[j], entries[i] })
		fold := sidecar.NewDirectoryFold(world.directoryId, nil)
		fold.Update(entries)
		if got := testDirectoryViewOf(t, fold.View(world.directoryAuth.Tip(), world.clock.Now().UnixMilli())); !slices.Equal(got, want) {
			t.Fatalf("shuffle %d folds to %d items, not %d", shuffle, len(got), len(want))
		}
	}
}

// List filters the folded state locally by kind, member, repo, active_only and query, naming the fields a query
// matched; private markers show only when asked; and nothing of a filter reaches evs (I-19): two filters cost the same
// requests.
func TestDirectoryListFilters(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	alice, bob := sidecar.NewId(), sidecar.NewId()
	aliceWriter := world.memberWriter(alice)
	bobWriter := world.memberWriter(bob)
	repoId, privateRepoId := sidecar.NewId(), sidecar.NewId()
	for _, id := range []sidecar.Id{repoId, privateRepoId} {
		world.directoryFixture.Repos[id] = &sidecartest.FakeDirectoryRepo{
			Kind: protocol.RepoKind_REPO_KIND_GENERAL, Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: aliceWriter.sidecarId, At: 1}},
		}
	}
	world.publish()
	nowMillis := world.clock.Now().UnixMilli()
	run := testRunItem(aliceWriter.sidecarId, &alice, sidecar.NewId(), 1, nowMillis)
	run.Where.RepoId = repoId.Bytes()
	aliceWriter.announce(run)
	stale := testRunItem(bobWriter.sidecarId, &bob, sidecar.NewId(), 1, nowMillis-sidecar.DirectoryRunExpiry.Milliseconds()-time.Minute.Milliseconds())
	stale.What.Title = "an older task"
	bobWriter.announce(stale)
	bobWriter.announce(testWorkerItem(bobWriter.sidecarId, &bob, sidecar.NewId(), 1, nowMillis))
	aliceWriter.announce(testRepoItem(t, aliceWriter.sidecarId, &alice, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, nowMillis, "settings service", false))
	aliceWriter.announce(testRepoItem(t, aliceWriter.sidecarId, &alice, privateRepoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, nowMillis, "", true))

	reader := world.reader(nil)
	reader.mustSync(t)
	list := func(filter *sidecar.DirectoryFilter) []*sidecar.DirectoryItem {
		t.Helper()
		items, err := reader.client.List(filter)
		if err != nil {
			t.Fatal(err)
		}
		return items
	}
	before := world.cards.Counts()
	if items := list(nil); len(items) != 4 {
		t.Errorf("the zero filter lists %d items, the private marker apart", len(items))
	}
	if items := list(&sidecar.DirectoryFilter{IncludePrivate: true}); len(items) != 5 {
		t.Errorf("%d items with the private marker", len(items))
	}
	if items := list(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun}); len(items) != 2 || items[0].Display != sidecar.DirectoryItemActive || items[1].Display != sidecar.DirectoryItemStale {
		t.Errorf("runs: %d, active first", len(items))
	}
	if items := list(&sidecar.DirectoryFilter{ActiveOnly: true, Kind: sidecar.DirectoryAnnouncementKindRun}); len(items) != 1 || items[0].SignerSidecarId != aliceWriter.sidecarId {
		t.Errorf("active runs: %d", len(items))
	}
	if items := list(&sidecar.DirectoryFilter{MemberId: &bob}); len(items) != 2 {
		t.Errorf("bob's: %d", len(items))
	}
	if items := list(&sidecar.DirectoryFilter{RepoId: &repoId}); len(items) != 2 {
		t.Errorf("the repo's run and item: %d", len(items))
	}
	items := list(&sidecar.DirectoryFilter{Query: "SETTINGS"})
	if len(items) != 2 {
		t.Fatalf("a query matching two titles answers %d", len(items))
	}
	for _, item := range items {
		if !slices.Equal(item.Matches, []string{"title"}) {
			t.Errorf("matches %v", item.Matches)
		}
	}
	if items := list(&sidecar.DirectoryFilter{Query: "preview tcp:8080"}); len(items) != 1 ||
		!slices.Equal(items[0].Matches, []string{"services.description", "services.name"}) {
		t.Errorf("a two-word query over a worker's services: %d", len(items))
	}
	if items := list(&sidecar.DirectoryFilter{Query: "settings absent-word"}); len(items) != 0 {
		t.Errorf("a query with a word nothing holds answers %d", len(items))
	}
	after := world.cards.Counts()
	if after.StreamReads != before.StreamReads || after.StreamsNamed != before.StreamsNamed || after.CardsReads != before.CardsReads {
		t.Errorf("a filter reached evs: %+v, then %+v", before, after)
	}
}

// Nothing shows while no state is bound, and a personal network's client answers ErrDirectoryNone.
func TestDirectoryListWithoutADirectory(t *testing.T) {
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("directory", "search")
	if err != nil {
		t.Fatal(err)
	}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId: sidecar.NewId(), Store: store, Settings: sidecar.DefaultSidecarSettings().Directory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.List(nil); !errors.Is(err, sidecar.ErrDirectoryNone) {
		t.Errorf("List with no directory: %v", err)
	}
	if _, err := client.Get(sidecar.NewId(), nil); !errors.Is(err, sidecar.ErrDirectoryNone) {
		t.Errorf("Get with no directory: %v", err)
	}
	fold := sidecar.NewDirectoryFold(sidecar.NewId(), nil)
	if items := fold.View(sidecar.DirectoryAuthUnavailable{}, time.Now().UnixMilli()); len(items) != 0 {
		t.Errorf("an unbound state shows %d", len(items))
	}
}
