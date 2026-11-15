//go:build !sidecar_http && !ios_extension

// RECORD-M6-21's removal, moderation and retention on sidecartest's fakes, FS-87's M6 directory legs: a removal masks
// the member's items, notices and pending requests at its position in every reader, and not before it; with no indexer
// a member device's cleanup 24 h later removes their notices and cards in one push, and the indexer's at once; a
// departing member's tagged agents announce under autogroup:admin until a SponsorSet; a directory admin's moderation
// alarms the moderated member's devices alone, once; retention erases past keep_days and announce entries 30 days on,
// waiting with no admin daemon while ur status names the oldest, and the runner's weekly BASE follows its expiry.

package sidecar_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Revokes sidecarId in the next position of both states, as a SidecarRevoke, a reap or its member's MemberRevoke does
// to each of its devices.
func (self *testDirectoryWorld) revoke(sidecarIds ...sidecar.Id) {
	at := self.directoryAuth.Tip().Pin().GetVersion() + 1
	for _, sidecarId := range sidecarIds {
		self.directoryFixture.Sidecars[sidecarId].RevokedAt = at
	}
	self.publish()
}

// A tagged sidecar sponsored by sponsorId, admitted and reading the directory, writing its own stream.
func (self *testDirectoryWorld) taggedWriter(sponsorId sidecar.Id) *testDirectoryWriter {
	writer := self.writer()
	self.directoryFixture.Sidecars[writer.sidecarId] = &sidecartest.FakeDirectorySidecar{SponsorId: &sponsorId}
	repo := self.recordFixture.Repos[self.directoryId]
	repo.Readers = append(repo.Readers, writer.sidecarId)
	return writer
}

// A cleanup over device's client, with indexers as the network-scope indexers, nil for none.
func testDirectoryRemoval(t *testing.T, reader *testDirectoryReader, indexers []sidecar.Id) *sidecar.DirectoryRemoval {
	t.Helper()
	removal, err := sidecar.NewDirectoryRemoval(&sidecar.DirectoryRemovalArgs{
		Client:   reader.client,
		Indexers: func() []sidecar.Id { return indexers },
	})
	if err != nil {
		t.Fatal(err)
	}
	return removal
}

// One sync and one cleanup, which must both succeed.
func testCleanup(t *testing.T, reader *testDirectoryReader, removal *sidecar.DirectoryRemoval) *sidecar.DirectoryCleanupPass {
	t.Helper()
	reader.mustSync(t)
	pass, err := removal.Cleanup(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return pass
}

// Whether reader's fold shows an item signed by writerId.
func testShowsItemOf(t *testing.T, reader *testDirectoryReader, writerId sidecar.Id) bool {
	t.Helper()
	return slices.ContainsFunc(reader.items(t), func(item *sidecar.DirectoryItem) bool { return item.SignerSidecarId == writerId })
}

// FS-87's mask: a removed member's device's run and worker items, its pending request and that request's notice in the
// approver's view are masked at the revocation's position in every reader, with no alarm, while a reader whose state
// has not reached it still shows them; the notice file stays on the cards ref until a cleanup, which masking does not
// wait for.
func TestDirectoryRemovalMasksAtThePosition(t *testing.T) {
	env := newTestRequestsEnv(t)
	world := env.world
	requester := env.requester
	// the member's other device, whose run and worker items its own chain pushes
	items := world.memberWriter(env.requesterMember)
	world.publish()
	nowMillis := world.clock.Now().UnixMilli()
	items.announce(testRunItem(items.sidecarId, &env.requesterMember, sidecar.NewId(), 1, nowMillis))
	items.announce(testWorkerItem(items.sidecarId, &env.requesterMember, sidecar.NewId(), 1, nowMillis))
	filed := env.mustFile(requester, env.ask())
	before := world.directoryAuth.Tip()
	readers := []*testDirectoryReader{env.approver.testDirectoryReader, world.reader(nil)}
	for _, reader := range readers {
		reader.mustSync(t)
		if count := len(slices.DeleteFunc(reader.items(t), func(item *sidecar.DirectoryItem) bool { return item.SignerSidecarId != items.sidecarId })); count != 2 {
			t.Fatalf("%d items of the member's before its removal", count)
		}
	}
	if view := env.request(env.approver, filed.RequestId); view.State != sidecar.DirectoryRequestPending || !view.Decidable {
		t.Fatalf("the request before the removal: %+v", view)
	}

	world.revoke(requester.writer.sidecarId, items.sidecarId)
	for index, reader := range readers {
		reader.mustSync(t)
		if testShowsItemOf(t, reader, items.sidecarId) {
			t.Fatalf("reader %d shows a removed member's item", index)
		}
		for _, reason := range reader.alarmReasons() {
			if reason == sidecar.SidecarRecordAlarmBadEntry || reason == sidecar.SidecarRecordAlarmParkedWriter {
				t.Fatalf("reader %d alarmed %s over a mask", index, reason)
			}
		}
	}
	if views := env.requests(env.approver, &sidecar.DirectoryRequestFilter{RequestId: &filed.RequestId}); len(views) != 0 {
		t.Fatalf("the approver still shows the removed member's request: %+v", views[0])
	}
	if decidable := env.requests(env.approver, &sidecar.DirectoryRequestFilter{Decidable: true}); len(decidable) != 0 {
		t.Fatalf("the approver decides %d requests of a removed member's", len(decidable))
	}
	if testNoticeAt(t, env.approver, filed.NoticePath) == nil {
		t.Fatal("the notice went before any cleanup")
	}
	// a reader whose state is still before the revocation shows what it masks at the position
	late := world.clientWith(world.readerId, nil, true, &testDirectoryClientOptions{auth: func() sidecar.DirectoryAuthView { return before }})
	late.mustSync(t)
	if !testShowsItemOf(t, late, items.sidecarId) {
		t.Fatal("a reader before the revocation's position masks the item")
	}
}

// FS-87's cleanup with no indexer designated (owner decision 177): a member device removes nothing before 24 h from
// the revocation and then the revoked sidecars' notices and cards in one push that lists each; a second member device
// finds nothing left; a read_only client and a tagged sidecar that is no indexer clean nothing.
func TestDirectoryRemovalMemberDeviceCleansUp24HoursLater(t *testing.T) {
	env := newTestRequestsEnv(t)
	world := env.world
	requester := env.requester
	filed := env.mustFile(requester, env.ask())
	second := world.memberWriter(env.requesterMember)
	world.publish()
	secondDevice := env.device(second)
	secondFiled := env.mustFile(secondDevice, env.ask())
	// from format 2 a card of the second device's, which the same push takes
	cardPath := sidecar.DirectoryCardPath(second.sidecarId)
	world.putFile(second.sidecarId, cardPath, []byte("a card"), world.directoryAuth.Tip().Pin())
	other := env.device(world.memberWriter(sidecar.NewId()))
	tagged := world.taggedWriter(env.approverMember)
	world.publish()
	taggedDevice := world.device(tagged)

	world.revoke(requester.writer.sidecarId, second.sidecarId)
	removal := testDirectoryRemoval(t, env.approver.testDirectoryReader, nil)
	pass := testCleanup(t, env.approver.testDirectoryReader, removal)
	if !pass.Cleans || pass.Indexer || len(pass.Removed) != 0 || len(pass.Waiting) != 2 {
		t.Fatalf("a member device's cleanup at once: %+v", pass)
	}
	readOnly := world.clientFor(env.approver.writer.sidecarId, env.approver.record.Writer(), true)
	if pass := testCleanup(t, readOnly, testDirectoryRemoval(t, readOnly, nil)); pass.Cleans {
		t.Fatalf("a read_only client cleans: %+v", pass)
	}
	if pass := testCleanup(t, taggedDevice.testDirectoryReader, testDirectoryRemoval(t, taggedDevice.testDirectoryReader, nil)); pass.Cleans {
		t.Fatalf("a tagged sidecar that is no indexer cleans: %+v", pass)
	}

	world.clock.Advance(24*time.Hour - time.Minute)
	world.publish()
	if pass := testCleanup(t, env.approver.testDirectoryReader, removal); len(pass.Removed) != 0 {
		t.Fatalf("a cleanup a minute before 24 h: %+v", pass)
	}
	world.clock.Advance(time.Minute)
	world.publish()
	pushes := world.cards.Counts().RemovalPushes
	pass = testCleanup(t, env.approver.testDirectoryReader, removal)
	want := []string{cardPath, filed.NoticePath, secondFiled.NoticePath}
	slices.Sort(want)
	if !slices.Equal(pass.Removed, want) || len(pass.Waiting) != 0 || world.cards.Counts().RemovalPushes != pushes+1 {
		t.Fatalf("the cleanup at 24 h: %+v after %d pushes", pass, world.cards.Counts().RemovalPushes-pushes)
	}
	for _, reader := range []*testDirectoryReader{other.testDirectoryReader, world.reader(nil)} {
		reader.mustSync(t)
		for _, path := range want {
			for _, file := range reader.client.Cards() {
				if file.Path == path && !file.Removed {
					t.Fatalf("%s still holds a file after the cleanup", path)
				}
			}
		}
	}
	if pass := testCleanup(t, other.testDirectoryReader, testDirectoryRemoval(t, other.testDirectoryReader, nil)); len(pass.Removed) != 0 || pass.Conflict {
		t.Fatalf("a second member device's cleanup: %+v", pass)
	}
}

// The network-scope indexer cleans at its first sync after the revocation, while a member device still waits; a
// binding with no push of several removals cleans nothing and says so.
func TestDirectoryRemovalIndexerCleansAtOnce(t *testing.T) {
	env := newTestRequestsEnv(t)
	world := env.world
	filed := env.mustFile(env.requester, env.ask())
	indexer := env.device(world.memberWriter(sidecar.NewId()))
	world.revoke(env.requester.writer.sidecarId)
	member := testCleanup(t, env.approver.testDirectoryReader, testDirectoryRemoval(t, env.approver.testDirectoryReader, []sidecar.Id{indexer.writer.sidecarId}))
	if len(member.Removed) != 0 || len(member.Waiting) != 1 {
		t.Fatalf("a member device beside a designated indexer: %+v", member)
	}
	unbound := world.clientWith(indexer.writer.sidecarId, indexer.record.Writer(), false, nil)
	unbound.client.Bind(testCardsWithoutRemover{DirectoryCards: world.cards.For(indexer.writer.sidecarId)}, nil)
	unbound.mustSync(t)
	if _, err := testDirectoryRemoval(t, unbound, []sidecar.Id{indexer.writer.sidecarId}).Cleanup(t.Context()); !errors.Is(err, sidecar.ErrDirectoryCleanupUnbound) {
		t.Fatalf("a cleanup over a binding with no multi-file removal: %v", err)
	}
	pass := testCleanup(t, indexer.testDirectoryReader, testDirectoryRemoval(t, indexer.testDirectoryReader, []sidecar.Id{indexer.writer.sidecarId}))
	if !pass.Indexer || !slices.Equal(pass.Removed, []string{filed.NoticePath}) {
		t.Fatalf("the indexer's cleanup: %+v", pass)
	}
}

// A DirectoryCards with no RemoveCards.
type testCardsWithoutRemover struct {
	sidecar.DirectoryCards
}

// FS-87's departing member: its devices are masked, while its tagged agent keeps announcing, its item showing
// autogroup:admin and no member until a SponsorSet names another, whose member it then shows.
func TestDirectoryRemovalDepartingMembersAgentsUnderAutogroupAdmin(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	departing := sidecar.NewId()
	device := world.memberWriter(departing)
	agent := world.taggedWriter(departing)
	world.publish()
	nowMillis := world.clock.Now().UnixMilli()
	device.announce(testRunItem(device.sidecarId, &departing, sidecar.NewId(), 1, nowMillis))
	runId := sidecar.NewId()
	agent.announce(testRunItem(agent.sidecarId, &departing, runId, 1, nowMillis))
	reader := world.reader(nil)
	reader.mustSync(t)
	if item := testOnlyItemOf(t, reader.items(t), agent.sidecarId); item.MemberId == nil || *item.MemberId != departing || item.AutogroupAdmin {
		t.Fatalf("the agent's item before the removal: %+v", item)
	}

	// the MemberRevoke: its device revoked, its agent's sponsor gone
	world.directoryFixture.Sidecars[agent.sidecarId].SponsorId = nil
	world.revoke(device.sidecarId)
	reader.mustSync(t)
	if testShowsItemOf(t, reader, device.sidecarId) {
		t.Fatal("the departing member's device still shows")
	}
	item := testOnlyItemOf(t, reader.items(t), agent.sidecarId)
	if item.MemberId != nil || !item.AutogroupAdmin || item.Display != sidecar.DirectoryItemActive {
		t.Fatalf("the agent's item after the removal: %+v", item)
	}
	// it renews with no member, as its daemon writes once its sponsor is gone
	world.clock.Advance(time.Hour)
	world.publish()
	agent.announce(testRunItem(agent.sidecarId, nil, runId, 1, world.clock.Now().UnixMilli()))
	reader.mustSync(t)
	if item := testOnlyItemOf(t, reader.items(t), agent.sidecarId); item.MemberId != nil || !item.AutogroupAdmin ||
		item.Announcement.GetRenewedMillis() != world.clock.Now().UnixMilli() {
		t.Fatalf("the agent's renewal under autogroup:admin: %+v", item)
	}
	sponsor := sidecar.NewId()
	world.directoryFixture.Sidecars[agent.sidecarId].SponsorId = &sponsor
	world.publish()
	reader.mustSync(t)
	if item := testOnlyItemOf(t, reader.items(t), agent.sidecarId); item.MemberId == nil || *item.MemberId != sponsor || item.AutogroupAdmin {
		t.Fatalf("the agent's item after a SponsorSet: %+v", item)
	}
	if count := reader.alarmsNaming(sidecar.SidecarRecordAlarmBadEntry, agent.sidecarId); count != 0 {
		t.Fatalf("%d bad_entry alarms over the agent", count)
	}
}

// §16.11's moderation row: a directory admin's Moderate erases another member's run item, a person's act and an
// admin's alone, never its own entries; the moderated member's devices and the writer raise moderation naming the
// writer, once, a restart raising none again, and another member's device raises none.
func TestDirectoryModerationAlarmsTheMembersDevices(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	admin := world.adminDevice()
	admin.client.BindEraser(admin.record.Eraser().Erase)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	sibling := world.memberWriter(memberId)
	world.publish()
	writerDevice := world.device(writer)
	siblingDevice := world.device(sibling)
	otherDevice := world.device(world.memberWriter(sidecar.NewId()))
	world.publish()
	announcementId := sidecar.NewId()
	nowMillis := world.clock.Now().UnixMilli()
	writer.announce(testRunItem(writer.sidecarId, &memberId, announcementId, 1, nowMillis))
	writer.announce(testRunItem(writer.sidecarId, &memberId, announcementId, 1, nowMillis+60_000))
	admin.mustSync(t)

	if _, err := admin.client.Moderate(t.Context(), &sidecar.DirectoryEraseArgs{Id: announcementId}); !errors.Is(err, sidecar.ErrDirectoryEraseUnconfirmed) {
		t.Fatalf("an unconfirmed moderation: %v", err)
	}
	siblingDevice.client.BindEraser(siblingDevice.record.Eraser().Erase)
	siblingDevice.mustSync(t)
	if _, err := siblingDevice.client.Moderate(t.Context(), &sidecar.DirectoryEraseArgs{Id: announcementId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryEraseNotAdmin) {
		t.Fatalf("a moderation by no directory admin: %v", err)
	}
	ownId := sidecar.NewId()
	admin.writer.announce(testRunItem(admin.writer.sidecarId, nil, ownId, 1, nowMillis))
	admin.mustSync(t)
	if _, err := admin.client.Moderate(t.Context(), &sidecar.DirectoryEraseArgs{Id: ownId, Confirmed: true}); !errors.Is(err, sidecar.ErrDirectoryModerateOwn) {
		t.Fatalf("an admin moderating its own item: %v", err)
	}
	result, err := admin.client.Moderate(t.Context(), &sidecar.DirectoryEraseArgs{Id: announcementId, Confirmed: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.Reason != sidecar.RecordErasureReasonModeration || len(result.EntryIds) != 2 {
		t.Fatalf("the moderation: %+v", result)
	}
	for _, device := range []*testDirectoryDevice{siblingDevice, writerDevice} {
		device.mustSync(t)
		device.mustSync(t)
		if count := device.alarmsNaming(sidecar.SidecarRecordAlarmModeration, writer.sidecarId); count != 1 {
			t.Fatalf("%d moderation alarms on a device of the moderated member", count)
		}
		if testShowsItemOf(t, device.testDirectoryReader, writer.sidecarId) {
			t.Fatal("the moderated item still shows")
		}
	}
	otherDevice.mustSync(t)
	if count := otherDevice.alarmsNaming(sidecar.SidecarRecordAlarmModeration, writer.sidecarId); count != 0 {
		t.Fatalf("%d moderation alarms on another member's device", count)
	}
	// a restart over the same copy raises none again
	restarted := testReopenedClient(t, world, siblingDevice.testDirectoryReader, sibling.sidecarId)
	restarted.mustSync(t)
	if count := restarted.alarmsNaming(sidecar.SidecarRecordAlarmModeration, writer.sidecarId); count != 0 {
		t.Fatalf("%d moderation alarms after a restart", count)
	}
}

// A new client over reader's own store, as a restart makes it.
func testReopenedClient(t *testing.T, world *testDirectoryWorld, reader *testDirectoryReader, sidecarId sidecar.Id) *testDirectoryReader {
	t.Helper()
	reopened := &testDirectoryReader{files: reader.files, store: reader.store, synced: make(chan struct{}, 64)}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  sidecarId,
		Store:      reader.store,
		Cards:      world.cards.For(sidecarId),
		Streams:    func() sidecar.RecordStreams { return world.streams.For(sidecarId) },
		Auth:       func() sidecar.DirectoryAuthView { return world.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return world.recordAuth.Tip() },
		Alarm: func(alarm *sidecar.RecordAlarm) {
			reopened.stateLock.Lock()
			defer reopened.stateLock.Unlock()
			reopened.alarms = append(reopened.alarms, alarm)
		},
		Clock:     world.clock,
		Settings:  sidecar.DefaultSidecarSettings().Directory,
		NetworkId: world.networkId,
	})
	if err != nil {
		t.Fatal(err)
	}
	reopened.client = client
	return reopened
}

// The BASE calls a record's retention made, by stream.
type testBaseCalls struct {
	stateLock sync.Mutex
	paths     map[sidecar.Id][]string
	calls     int
}

func (self *testBaseCalls) base(ctx context.Context, logId sidecar.Id, streamSidecarId sidecar.Id, paths []string) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls += 1
	self.paths[streamSidecarId] = append(self.paths[streamSidecarId], paths...)
	return len(paths), nil
}

// FS-87's retention: with no runner the expired announce entry and, at 400 days, the coordination notes wait, a
// directory admin's ur status naming the oldest and no other device's; the runner's pass erases them, a live repo item's
// newest copy kept, and its weekly BASE then removes their files once a week.
func TestDirectoryRetentionErasesPastKeepDays(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	admin := world.adminDevice()
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	writer.push(2)
	writer.announce(testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, world.clock.Now().UnixMilli()))
	admin.mustSync(t)
	if waiting := admin.client.RetentionWaiting(nil); len(waiting) != 0 {
		t.Fatalf("%d entries wait at day 0", len(waiting))
	}

	// day 31: the run's entry is 30 days past its item's expiry; no runner runs, so it waits and is named
	world.clock.Advance(31 * 24 * time.Hour)
	world.publish()
	admin.mustSync(t)
	waiting := admin.client.RetentionWaiting(nil)
	if len(waiting) != 1 || waiting[0].Kind != sidecar.RecordKindAnnounce {
		t.Fatalf("waiting at day 31: %+v", waiting)
	}
	lines := admin.client.ErasureStatusLines(nil)
	if len(lines) != 1 || !strings.Contains(lines[0], "1 entries past retention") || !strings.Contains(lines[0], waiting[0].EntryId.String()) {
		t.Fatalf("an admin's status lines: %q", lines)
	}
	owner.mustSync(t)
	if lines := owner.client.ErasureStatusLines(nil); len(lines) != 0 {
		t.Fatalf("a device that is no directory admin names %q", lines)
	}

	bases := &testBaseCalls{paths: map[sidecar.Id][]string{}}
	admin.record.Retention().SetBase(bases.base)
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
		Client: admin.client,
		Erase:  admin.record.Eraser().Erase,
		Expire: func(ctx context.Context, directoryId sidecar.Id, hold func(entry *sidecar.RecordReadEntry) bool) error {
			_, err := admin.record.Retention().Expire(ctx, &sidecar.RecordRetentionExpireArgs{LogId: directoryId, Hold: hold})
			return err
		},
		Base:   admin.record.Retention().DirectoryBase,
		Random: &testErasureDelay{},
	})
	if err != nil {
		t.Fatal(err)
	}
	admin.pass(t, runner)
	admin.flush(t)
	admin.mustSync(t)
	if waiting := admin.client.RetentionWaiting(nil); len(waiting) != 0 {
		t.Fatalf("waiting after the runner's pass: %+v", waiting)
	}
	if lines := admin.client.ErasureStatusLines(nil); len(lines) != 0 {
		t.Fatalf("status lines after the pass: %q", lines)
	}
	if bases.calls != 1 || len(bases.paths[writer.sidecarId]) != 1 {
		t.Fatalf("the BASE after the first expiry: %d calls, %v", bases.calls, bases.paths)
	}
	admin.pass(t, runner)
	if bases.calls != 1 {
		t.Fatalf("a second BASE inside the week: %d calls", bases.calls)
	}

	// day 401: the notes are past keep_days 400; the repo's newest copy, 401 days old, stays
	world.clock.Advance(370 * 24 * time.Hour)
	world.publish()
	admin.mustSync(t)
	if waiting := admin.client.RetentionWaiting(nil); len(waiting) != 2 || waiting[0].Kind != sidecar.RecordKindNote {
		t.Fatalf("waiting at day 401: %+v", waiting)
	}
	admin.pass(t, runner)
	admin.flush(t)
	admin.mustSync(t)
	if waiting := admin.client.RetentionWaiting(nil); len(waiting) != 0 {
		t.Fatalf("waiting after the day 401 pass: %+v", waiting)
	}
	// the second BASE lists the notes' files beside the run entry's, which a real BASE took last week and finds gone
	if paths := bases.paths[writer.sidecarId]; bases.calls != 2 || !slices.Contains(paths[1:], "e/0/0/1") || !slices.Contains(paths[1:], "e/0/0/2") {
		t.Fatalf("the BASE after the notes' expiry: %d calls, %v", bases.calls, bases.paths)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, repoId); item == nil || item.Announcement.GetWhat().GetTitle() != "design notes" {
		t.Fatalf("the repo's item after 401 days: %v", item)
	}
}

// The mask time each view answers: the revocation's position and that entry's time, nothing for a standing sidecar,
// and a position with no time once the state no longer holds it.
func TestDirectoryAuthMaskedSince(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	writer := world.memberWriter(sidecar.NewId())
	world.publish()
	if _, _, masked := world.directoryAuth.Tip().MaskedSince(writer.sidecarId); masked {
		t.Fatal("a standing sidecar reads masked")
	}
	world.clock.Advance(time.Hour)
	world.revoke(writer.sidecarId)
	at := world.directoryAuth.Tip().Pin().GetVersion()
	position, timeMillis, masked := world.directoryAuth.Tip().MaskedSince(writer.sidecarId)
	if !masked || position != at || timeMillis != world.clock.Now().UnixMilli() {
		t.Fatalf("masked since %d at %d (%v)", position, timeMillis, masked)
	}
	world.advance(3, time.Hour)
	world.directoryAuth.RetainFrom(at + 1)
	if position, timeMillis, masked := world.directoryAuth.Tip().MaskedSince(writer.sidecarId); !masked || position != at || timeMillis != 0 {
		t.Fatalf("past retention: masked since %d at %d (%v)", position, timeMillis, masked)
	}
	if _, _, masked := (sidecar.DirectoryAuthUnavailable{}).MaskedSince(writer.sidecarId); masked {
		t.Fatal("no state reads a mask")
	}
}
