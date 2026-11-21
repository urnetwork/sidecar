//go:build !sidecar_http && !ios_extension

// RECORD-M10-03's move to format 2 on sidecartest's fakes: a daemon the format2 gate admits writes its run onto its card
// and its repo's item onto the r/ file in place of entries; announce entries and files of one announcement fold to one
// state, counted once (FS-84); a reader across the switch shows the item throughout, a daemon outside the gate follows
// once the repo reads format 2 and moves a repo item off its entry, whose expiry then ends reading both; a
// versionless notice's replaced content purged a minute on still brings the requester its decision (FS-100); and the
// carrier seeding no item an erasure took after a return whose put failed (QD-1144).

package sidecar_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The items reader shows for writerId, signed by it.
func testFormat2ItemsOf(t *testing.T, reader *testDirectoryReader, writerId sidecar.Id) []*sidecar.DirectoryItem {
	t.Helper()
	return slices.DeleteFunc(reader.items(t), func(item *sidecar.DirectoryItem) bool { return item.SignerSidecarId != writerId })
}

// A daemon in the format2 gate announces its run on its card and its repo's item on the r/ file, appending no announce
// entry; a reader folds both from the files.
func TestDirectoryFormat2CarriesItemsOnFiles(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	owner.mustSync(t)
	entriesBefore := len(owner.entriesAtEvs(t, sidecar.RecordKindAnnounce))
	owner.client.BindFormat2Gate(func() bool { return true })

	if _, err := owner.client.AnnounceRepo(t.Context(), &sidecar.DirectoryRepoAnnounceArgs{RepoId: repoId, DisplayName: "design notes", Description: "now on its file", Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	// evs raises the repo at that first format-2 push (§11.6's format row)
	world.cards.RaiseFormat(world.directoryId)
	runId := sidecar.NewId()
	if err := owner.client.Runs().Started(&sidecar.DirectoryRunStart{
		RunId: runId, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "example.org/team/app", AgentLabel: "builder", Harness: "codex",
		Title: "move the directory onto cards", Project: "example.org/team/app", Branch: "main",
	}); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(10 * time.Second)
	owner.flush(t)
	if entries := len(owner.entriesAtEvs(t, sidecar.RecordKindAnnounce)); entries != entriesBefore {
		t.Fatalf("%d announce entries after the switch, %d before", entries, entriesBefore)
	}
	if world.cardFileVersion(sidecar.DirectoryCardPath(owner.writer.sidecarId)) == 0 || world.cardFileVersion(sidecar.DirectoryRepoPath(repoId)) == 0 {
		t.Fatal("no card or no repo file on the cards ref")
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if !reader.client.Format2() {
		t.Fatal("the reader does not read the repo at format 2")
	}
	items := testFormat2ItemsOf(t, reader, owner.writer.sidecarId)
	if len(items) != 2 {
		t.Fatalf("%d items of the owner's", len(items))
	}
	for _, item := range items {
		if item.EntryId != (sidecar.Id{}) {
			t.Fatalf("an item from an entry after the switch: %+v", item)
		}
		switch item.Key.Kind {
		case sidecar.DirectoryAnnouncementKindRepo:
			if item.Announcement.GetWhat().GetDescription() != "now on its file" || item.Announcement.GetVersion() != 2 {
				t.Fatalf("the repo's item: %v", item.Announcement)
			}
		case sidecar.DirectoryAnnouncementKindRun:
			if item.Display != sidecar.DirectoryItemActive || item.Announcement.GetWhat().GetTitle() != "move the directory onto cards" {
				t.Fatalf("the run's item: %v", item.Announcement)
			}
		}
	}
	// a withdrawal leaves the run out of the card
	if err := owner.client.Runs().Withdraw(runId); err != nil {
		t.Fatal(err)
	}
	reader.mustSync(t)
	if items := testFormat2ItemsOf(t, reader, owner.writer.sidecarId); len(items) != 1 || items[0].Key.Kind != sidecar.DirectoryAnnouncementKindRepo {
		t.Fatalf("after the withdrawal: %d items", len(items))
	}
}

// FS-84: an announce entry and a card of one run fold to one item, the higher (version, renewed_millis) standing
// whichever carrier holds it, and a repo's entry and r/ file to one item too.
func TestDirectoryFormat2OneStateFromEitherCarrier(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	announcementId := sidecar.NewId()
	startMillis := world.clock.Now().UnixMilli()
	writer.announce(testRunItem(writer.sidecarId, &memberId, announcementId, 1, startMillis))
	world.cards.RaiseFormat(world.directoryId)
	world.clock.Advance(time.Minute)
	world.publish()
	renewed := testRunItem(writer.sidecarId, &memberId, announcementId, 1, world.clock.Now().UnixMilli())
	world.putFile(writer.sidecarId, sidecar.DirectoryCardPath(writer.sidecarId), world.cardContent(writer, writer.sidecarId, 1, world.directoryAuth.Tip().Pin(), renewed), world.directoryAuth.Tip().Pin())
	reader := world.reader(nil)
	reader.mustSync(t)
	items := testFormat2ItemsOf(t, reader, writer.sidecarId)
	if len(items) != 1 || items[0].Announcement.GetRenewedMillis() != renewed.GetRenewedMillis() || items[0].EntryId != (sidecar.Id{}) {
		t.Fatalf("an entry and a card of one run: %d items, %+v", len(items), items)
	}
	// a later entry stands over the card, still one item
	world.clock.Advance(time.Minute)
	world.publish()
	later := testRunItem(writer.sidecarId, &memberId, announcementId, 1, world.clock.Now().UnixMilli())
	writer.announce(later)
	reader.mustSync(t)
	items = testFormat2ItemsOf(t, reader, writer.sidecarId)
	if len(items) != 1 || items[0].Announcement.GetRenewedMillis() != later.GetRenewedMillis() || items[0].EntryId == (sidecar.Id{}) {
		t.Fatalf("a later entry over the card: %d items, %+v", len(items), items)
	}

	// a repo's entry and its r/ file at the same version: one item
	admin := world.memberWriter(sidecar.NewId())
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, admin)
	adminMember := world.directoryFixture.Sidecars[admin.sidecarId].MemberId
	item := testRepoItem(t, admin.sidecarId, adminMember, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, world.clock.Now().UnixMilli(), "release notes", false)
	admin.announce(item)
	world.putFile(admin.sidecarId, sidecar.DirectoryRepoPath(repoId), world.repoFileContent(admin, repoId, 1, world.directoryAuth.Tip().Pin(), item), world.directoryAuth.Tip().Pin())
	reader.mustSync(t)
	shown := 0
	for _, each := range reader.items(t) {
		if each.Key.Kind == sidecar.DirectoryAnnouncementKindRepo && sidecar.Id(each.Announcement.GetWhere().GetRepoId()) == repoId {
			shown += 1
			if each.Announcement.GetWhat().GetTitle() != "release notes" {
				t.Fatalf("the repo's item: %v", each.Announcement)
			}
		}
	}
	if shown != 1 {
		t.Fatalf("%d items of one repo from its entry and its file", shown)
	}
}

// The first format 2 write can be a withdrawal. It snapshots the other active
// runs, and a cold reader cannot resurrect the withdrawn one from retained M6 records.
func TestDirectoryFormat2FirstCardWithdrawsOneRetainedRun(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	writer := world.memberWriter(sidecar.NewId())
	world.publish()
	device := world.device(writer)
	kept := world.startRun(device.client, "keep this run")
	drop := world.startRun(device.client, "withdraw this run")
	device.flush(t)
	world.cards.RaiseFormat(world.directoryId)
	device.mustSync(t)
	if err := device.client.Runs().Withdraw(drop); err != nil {
		t.Fatal(err)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	items := testFormat2ItemsOf(t, reader, writer.sidecarId)
	if len(items) != 1 || items[0].EntryId != (sidecar.Id{}) || sidecar.Id(items[0].Announcement.GetWhat().GetRunId()) != kept {
		t.Fatalf("first card after withdrawing %s: %+v", drop, items)
	}
}

// A reader across the switch shows a repo's item throughout; a daemon outside the gate follows once the repo reads
// format 2, moving the item off its entry onto the r/ file at a higher version; 30 days on the entry is due for expiry,
// which the runner erases, and the item still shows from its file.
func TestDirectoryFormat2ReaderAcrossTheSwitch(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	owner, repoId := world.announcedRepo("design notes")
	reader := world.reader(nil)
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, repoId); item == nil || item.EntryId == (sidecar.Id{}) || reader.client.Format2() {
		t.Fatalf("before the switch: %+v", item)
	}
	world.cards.RaiseFormat(world.directoryId)
	owner.mustSync(t)
	if !owner.client.Format2() {
		t.Fatal("the owner does not read the repo at format 2")
	}
	writes, err := owner.client.MaintainRepos(t.Context())
	if err != nil || len(writes) != 1 || writes[0].Entry != nil {
		t.Fatalf("the move onto the r/ file: %+v %v", writes, err)
	}
	reader.mustSync(t)
	item := testRepoItemShown(t, reader, repoId)
	if item == nil || item.EntryId != (sidecar.Id{}) || item.Announcement.GetVersion() != 2 || item.Announcement.GetWhat().GetTitle() != "design notes" {
		t.Fatalf("after the move: %+v", item)
	}
	owner.mustSync(t)
	if writes, err := owner.client.MaintainRepos(t.Context()); err != nil || len(writes) != 0 {
		t.Fatalf("a second move: %+v %v", writes, err)
	}

	admin := world.adminDevice()
	admin.mustSync(t)
	world.clock.Advance(31 * 24 * time.Hour)
	world.publish()
	admin.mustSync(t)
	waiting := admin.client.RetentionWaiting(nil)
	if len(waiting) != 1 || waiting[0].Kind != sidecar.RecordKindAnnounce {
		t.Fatalf("waiting 31 days after the move: %+v", waiting)
	}
	runner, err := sidecar.NewDirectoryErasureRunner(&sidecar.DirectoryErasureRunnerArgs{
		Client: admin.client,
		Erase:  admin.record.Eraser().Erase,
		Expire: func(ctx context.Context, directoryId sidecar.Id, hold func(entry *sidecar.RecordReadEntry) bool) error {
			_, err := admin.record.Retention().Expire(ctx, &sidecar.RecordRetentionExpireArgs{LogId: directoryId, Hold: hold})
			return err
		},
		Random: &testErasureDelay{},
	})
	if err != nil {
		t.Fatal(err)
	}
	admin.pass(t, runner)
	admin.flush(t)
	admin.mustSync(t)
	if waiting := admin.client.RetentionWaiting(nil); len(waiting) != 0 {
		t.Fatalf("waiting after the expiry: %+v", waiting)
	}
	reader.mustSync(t)
	if item := testRepoItemShown(t, reader, repoId); item == nil || item.Announcement.GetVersion() != 2 {
		t.Fatalf("31 days on: %+v", item)
	}
}

// FS-100 on versionless notices: at format 2 a denial's rewrite replaces the pending notice, whose content the store
// purges a minute on; the requester, leasing only its notice, still reads the decided version and the one entry it
// names, and shows denied with access_decided.
func TestDirectoryFormat2VersionlessNotices(t *testing.T) {
	env := newTestDecideEnv(t)
	env.world.cards.RaiseFormat(env.world.directoryId)
	filed := env.mustFile(env.requester, env.ask())
	env.mustDecide(env.approver, filed.RequestId, false)
	env.world.clock.Advance(61 * time.Second)
	env.world.publish()
	// a reader that syncs now finds the pending version's content gone and the decided one standing
	late := env.world.reader(nil)
	late.mustSync(t)
	if notice := testNoticeAt(t, &testDirectoryDevice{testDirectoryReader: late}, filed.NoticePath); notice == nil ||
		notice.GetState() != uint32(sidecar.DirectoryNoticeStateDecided) || notice.GetOutcome() != uint32(sidecar.DirectoryOutcomeDenied) {
		t.Fatalf("the notice after the purge: %v", notice)
	}
	view := env.request(env.requester, filed.RequestId)
	if view.State != sidecar.DirectoryRequestDenied || len(view.Decisions) != 1 {
		t.Fatalf("the requester's view: %+v", view)
	}
	env.upkeep(env.requester)
	if events := env.events[env.requester.writer.sidecarId]; len(events) != 1 || events[0] != "access_decided/denied/"+filed.RequestId.String() {
		t.Fatalf("the requester's events: %v", events)
	}
}

// The return's put fails after its journal, the sidecar suspended at the state now, so the card this device put last
// still holds the run a directory admin erased (QD-1144): the restarted daemon's carrier seeds from that card less what
// the journal leaves out, and its next card, the sidecar standing again, carries the kept run and the new one two above
// with no second read of the erasure set, the erased run left out.
func TestDirectoryFormat2CarrierSeedsNoErasedItem(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	device := world.format2Device(sidecar.NewId())
	writerId := device.writer.sidecarId
	erasedRunId := world.startRun(device.client, "ship the launch plan")
	keptRunId := world.startRun(device.client, "tidy the changelog")
	world.eraseFromCard(writerId, sidecar.Id(world.shownRuns(writerId)[erasedRunId].GetAnnouncementId()), 1)
	device.mustSync(t)

	sidecarState := world.directoryFixture.Sidecars[writerId]
	sidecarState.SuspendedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	reads, writes := world.counts().ErasedReads, world.counts().CardWrites
	world.startRun(device.client, "review the loader")
	if world.counts().ErasedReads != reads+1 || world.counts().CardWrites != writes {
		t.Fatalf("the suspended return read the set %d times and put %d cards", world.counts().ErasedReads-reads, world.counts().CardWrites-writes)
	}
	sidecarState.SuspendedAt = 0
	world.publish()

	restarted := world.restartClient(device)
	nextRunId := world.startRun(restarted, "write the release notes")
	shown := world.shownRuns(writerId)
	if len(shown) != 2 || shown[erasedRunId] != nil || shown[keptRunId].GetVersion() != 3 || shown[nextRunId].GetVersion() != 3 {
		t.Fatalf("the runs after the restart: %v", shown)
	}
	if world.counts().ErasedReads != reads+1 {
		t.Fatal("the restarted daemon's card read the erasure set again")
	}
	restarted.Runs().Close()
}
