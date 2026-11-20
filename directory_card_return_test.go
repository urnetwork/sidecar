//go:build !sidecar_http && !ios_extension

// A card's return on sidecartest's fakes (§16.11's versions and closure rows, owner decision 645; QD-1106): the first
// card a sidecar writes after another signer removed its path carries every item two above the version the removal
// took, one above the tombstone the removal's push wrote for it, with no content change; a card it rewrites with no such
// removal between keeps its versions, renewals and content changes running on the raised line; the return is read
// through a put's path conflict where the copy had not read the removal, raised once though its put failed, and kept
// by the repair and by format 2's carrier across a restart. FS-87's index case holds the same return on the real engine,
// through the cards ref's index and search_agents (sidecartest/fault/fs87_index_evs.go).

package sidecar_test

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The versions a written card carries its items at, by announcement id.
func testCardWrittenVersions(written *sidecar.DirectoryCardWritten) map[sidecar.Id]uint64 {
	versions := map[sidecar.Id]uint64{}
	for _, item := range written.Items {
		versions[sidecar.Id(item.GetAnnouncementId())] = item.GetVersion()
	}
	return versions
}

// The device's card with items from its copy as it stands, with no sync first: what a daemon's write between syncs
// puts.
func (self *testDirectoryDevice) writeCardUnsynced(t *testing.T, items ...*protocol.Announcement) *sidecar.DirectoryCardWritten {
	t.Helper()
	written, err := self.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: items})
	if err != nil {
		t.Fatal(err)
	}
	return written
}

// item again at version, its content otherwise as it was: a content change where version rises.
func testItemAt(item *protocol.Announcement, version uint64) *protocol.Announcement {
	changed := proto.Clone(item).(*protocol.Announcement)
	changed.Version = version
	return changed
}

// A directory admin moderates A's card, which holds two runs and its worker item: A's device reads the removal at its
// sync, as its moderation notice shows, and its next card carries the run it kept and the worker item each two above
// the version the removal took, the moderated run left out; a reader shows them at those versions.
func TestDirectoryCardReturnRaisesEveryItemAboveTheRemoval(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	now := world.clock.Now().UnixMilli()
	erasedId, keptId, workerId := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	erased := testRunItem(writer.sidecarId, &memberId, erasedId, 2, now)
	kept := testRunItem(writer.sidecarId, &memberId, keptId, 1, now)
	worker := testWorkerItem(writer.sidecarId, &memberId, workerId, 1, now)
	before := device.writeCard(t, erased, kept, worker)
	if versions := testCardWrittenVersions(before); versions[keptId] != 1 || versions[workerId] != 1 || versions[erasedId] != 2 {
		t.Fatalf("a card before any removal carries %v", versions)
	}

	// the reader is the directory's creator, so a directory admin: its removal is a moderation
	path := sidecar.DirectoryCardPath(writer.sidecarId)
	world.removeFile(world.readerId, path)
	world.clock.Advance(time.Minute)
	world.publish()
	returned := device.writeCard(t, kept, worker)
	if count := device.alarmsNaming(sidecar.SidecarRecordAlarmModeration, writer.sidecarId); count != 1 {
		t.Fatalf("the writer's moderation notices: %d, alarms %v", count, device.alarmReasons())
	}
	versions := testCardWrittenVersions(returned)
	// the removal's tombstones: one above the version it took of each active item
	if versions[keptId] != 3 || versions[workerId] != 3 || len(versions) != 2 {
		t.Fatalf("the card back after the removal carries %v", versions)
	}
	handed := map[sidecar.Id]*protocol.Announcement{keptId: kept, workerId: worker}
	for _, item := range returned.Items {
		// no content change: the item as handed, but for its version
		if !proto.Equal(testItemAt(item, 0), testItemAt(handed[sidecar.Id(item.GetAnnouncementId())], 0)) {
			t.Fatalf("the return changed an item's content: %v", item)
		}
	}

	reader := world.reader(nil)
	reader.mustSync(t)
	shown := testItemsOf(t, reader, writer.sidecarId)
	if len(shown) != 2 || shown[erasedId] != nil || shown[keptId].Announcement.GetVersion() != 3 || shown[workerId].Announcement.GetVersion() != 3 {
		t.Fatalf("a reader after the return: %v", shown)
	}
}

// With no removal by another signer between, a card carries its items at their writers' versions; after a return it
// keeps the raised versions: a renewal keeps them, a content change raises one by one, and a second card put before the
// copy reads its own back, the removal still the copy's newest version at the path, raises nothing more.
func TestDirectoryCardRewriteKeepsItsVersions(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	keptId := sidecar.NewId()
	kept := testRunItem(writer.sidecarId, &memberId, keptId, 1, world.clock.Now().UnixMilli())
	for index, handed := range []*protocol.Announcement{kept, kept, testItemAt(kept, 2)} {
		written := device.writeCard(t, handed)
		if version := testCardWrittenVersions(written)[keptId]; version != handed.GetVersion() {
			t.Fatalf("write %d with no removal carries version %d, handed %d", index, version, handed.GetVersion())
		}
	}

	world.removeFile(world.readerId, sidecar.DirectoryCardPath(writer.sidecarId))
	changed := testItemAt(kept, 2)
	if version := testCardWrittenVersions(device.writeCard(t, changed))[keptId]; version != 4 {
		t.Fatalf("the return carries version %d", version)
	}
	// the copy still holds the removal as the path's newest version: no second rise
	if version := testCardWrittenVersions(device.writeCardUnsynced(t, changed))[keptId]; version != 4 {
		t.Fatalf("a card put before the copy read its own back carries version %d", version)
	}
	if version := testCardWrittenVersions(device.writeCard(t, changed))[keptId]; version != 4 {
		t.Fatalf("a renewal after the return carries version %d", version)
	}
	if version := testCardWrittenVersions(device.writeCard(t, testItemAt(kept, 3)))[keptId]; version != 5 {
		t.Fatalf("a content change after the return carries version %d", version)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if shown := testItemsOf(t, reader, writer.sidecarId); len(shown) != 1 || shown[keptId].Announcement.GetVersion() != 5 {
		t.Fatalf("a reader after the rewrites: %v", shown)
	}
}

// A card put from a copy that has not read the removal names the version its device put last, not the create-only 0
// that passes over any removal: the path's CAS fails it, the sync reads the removal, and the put again is the return.
// So too where the copy's newest version at the path is an earlier removal a return already answered.
func TestDirectoryCardReturnReadThroughAConflict(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	keptId := sidecar.NewId()
	kept := testRunItem(writer.sidecarId, &memberId, keptId, 1, world.clock.Now().UnixMilli())
	path := sidecar.DirectoryCardPath(writer.sidecarId)
	// the copy, synced before the put, holds nothing at the path
	device.writeCard(t, kept)
	world.removeFile(world.readerId, path)
	reads := world.counts().CardsReads
	if version := testCardWrittenVersions(device.writeCardUnsynced(t, kept))[keptId]; version != 3 {
		t.Fatalf("a card put over a removal the copy had not read carries version %d", version)
	}
	if world.counts().CardsReads == reads {
		t.Fatal("the put over the unread removal read nothing")
	}

	// the copy's newest version at the path is now the first removal, which the return answered
	world.removeFile(world.readerId, path)
	if version := testCardWrittenVersions(device.writeCardUnsynced(t, kept))[keptId]; version != 5 {
		t.Fatalf("a card put over a second removal the copy had not read carries version %d", version)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	if shown := testItemsOf(t, reader, writer.sidecarId); len(shown) != 1 || shown[keptId].Announcement.GetVersion() != 5 {
		t.Fatalf("a reader after both returns: %v", shown)
	}
}

// A return's rise is journaled with the seq before the put: a put that fails after it, its sidecar suspended at the
// state now, leaves the next card, once the sidecar stands again, carrying the rise and raising no further.
func TestDirectoryCardReturnRaiseJournaled(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	keptId := sidecar.NewId()
	kept := testRunItem(writer.sidecarId, &memberId, keptId, 1, world.clock.Now().UnixMilli())
	device.writeCard(t, kept)
	world.removeFile(world.readerId, sidecar.DirectoryCardPath(writer.sidecarId))
	device.mustSync(t)

	world.directoryFixture.Sidecars[writer.sidecarId].SuspendedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	if _, err := device.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: []*protocol.Announcement{kept}}); !errors.Is(err, sidecar.ErrDirectoryCardStanding) {
		t.Fatalf("a suspended sidecar's card: %v", err)
	}
	world.directoryFixture.Sidecars[writer.sidecarId].SuspendedAt = 0
	world.publish()
	if version := testCardWrittenVersions(device.writeCard(t, kept))[keptId]; version != 3 {
		t.Fatalf("the card after a failed return carries version %d", version)
	}
}

// The repair keeps the line: after a return, B replaces A's card and A's repair puts the items it put last again at
// the versions it carried them at, raised no further; B's removal of A's card, which readers refuse, is still another
// signer's removal, and the repair over it is a return.
func TestDirectoryCardRepairKeepsTheLine(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	aMember, bMember := sidecar.NewId(), sidecar.NewId()
	a := world.memberWriter(aMember)
	b := world.memberWriter(bMember)
	world.publish()
	device := world.device(a)
	keptId := sidecar.NewId()
	kept := testRunItem(a.sidecarId, &aMember, keptId, 1, world.clock.Now().UnixMilli())
	path := sidecar.DirectoryCardPath(a.sidecarId)
	device.writeCard(t, kept)
	world.removeFile(world.readerId, path)
	if version := testCardWrittenVersions(device.writeCard(t, kept))[keptId]; version != 3 {
		t.Fatalf("the return carries version %d", version)
	}

	device.mustSync(t)
	pin := world.directoryAuth.Tip().Pin()
	forged := testRunItem(a.sidecarId, &aMember, sidecar.NewId(), 1, world.clock.Now().UnixMilli())
	world.putFile(b.sidecarId, path, world.cardContent(b, a.sidecarId, 9, pin, forged), pin)
	device.mustSync(t)
	pass, err := device.client.Repair(t.Context())
	if err != nil || pass.Card == nil {
		t.Fatalf("the repair of B's replacement: %+v, %v", pass, err)
	}
	if version := testCardWrittenVersions(pass.Card)[keptId]; version != 3 || len(pass.Card.Items) != 1 {
		t.Fatalf("the repair carries %v", testCardWrittenVersions(pass.Card))
	}

	device.mustSync(t)
	world.removeFile(b.sidecarId, path)
	device.mustSync(t)
	if pass, err = device.client.Repair(t.Context()); err != nil || pass.Card == nil {
		t.Fatalf("the repair of B's removal: %+v, %v", pass, err)
	}
	if version := testCardWrittenVersions(pass.Card)[keptId]; version != 5 {
		t.Fatalf("the repair over B's removal carries version %d", version)
	}
}

// Format 2's carrier: a daemon's runs ride its card; once a directory admin removed it, the next run's card carries
// every run two above, the moderated card's runs among them; a restarted daemon's carrier seeds the runs from the card
// it put last at their writers' versions, so its next card keeps the raised versions, raised no further.
func TestDirectoryCardCarrierKeepsTheLineAcrossARestart(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	device := world.device(writer)
	device.client.BindFormat2Gate(func() bool { return true })
	world.cards.RaiseFormat(world.directoryId)
	device.mustSync(t)
	start := func(client *sidecar.DirectoryClient, title string) sidecar.Id {
		t.Helper()
		runId := sidecar.NewId()
		if err := client.Runs().Started(&sidecar.DirectoryRunStart{
			RunId: runId, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "example.org/team/app", AgentLabel: "builder", Harness: "codex",
			Title: title, Project: "example.org/team/app", Branch: "main",
		}); err != nil {
			t.Fatal(err)
		}
		// the start delay, the run's item joining the card as it passes
		world.clock.Advance(sidecar.DefaultDirectoryRunsSettings().StartDelay)
		return runId
	}
	shownRuns := func() map[sidecar.Id]uint64 {
		t.Helper()
		reader := world.reader(nil)
		reader.mustSync(t)
		versions := map[sidecar.Id]uint64{}
		for _, item := range testItemsOf(t, reader, writer.sidecarId) {
			versions[sidecar.Id(item.Announcement.GetWhat().GetRunId())] = item.Announcement.GetVersion()
		}
		return versions
	}
	first := start(device.client, "tidy the changelog")
	if versions := shownRuns(); versions[first] != 1 || len(versions) != 1 {
		t.Fatalf("the first run's card: %v", versions)
	}

	world.removeFile(world.readerId, sidecar.DirectoryCardPath(writer.sidecarId))
	device.mustSync(t)
	second := start(device.client, "fix the retry path")
	if versions := shownRuns(); versions[first] != 3 || versions[second] != 3 || len(versions) != 2 {
		t.Fatalf("the card back after the removal: %v", versions)
	}

	// a restart: the same stores, a new client with its carrier unseeded
	device.client.Runs().Close()
	restarted, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId: writer.sidecarId, Store: device.store, Cards: world.cards.For(writer.sidecarId),
		Streams:    func() sidecar.RecordStreams { return world.streams.For(writer.sidecarId) },
		Auth:       func() sidecar.DirectoryAuthView { return world.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return world.recordAuth.Tip() },
		Clock:      world.clock, Settings: sidecar.DefaultSidecarSettings().Directory, Writer: device.record.Writer(),
		NetworkId: world.networkId, Sign: writer.sign,
	})
	if err != nil {
		t.Fatal(err)
	}
	restarted.BindFormat2Gate(func() bool { return true })
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	third := start(restarted, "review the loader")
	if versions := shownRuns(); versions[first] != 3 || versions[second] != 3 || versions[third] != 3 || len(versions) != 3 {
		t.Fatalf("the restarted daemon's card: %v", versions)
	}
	restarted.Runs().Close()
}
