//go:build !sidecar_http && !ios_extension

// QD-1144's check at a card's return on sidecartest's fakes, its fail-closed half: a return whose binding reads no
// erasure set, whose set does not read or whose set's version no directory admin signed puts nothing, and the next
// write, once the set reads, is the return. The fake lists documents as a directory admin's CUT would
// (FakeDirectoryCards.ListErased); the evs binding's read of the real set runs in FS-87's index case
// (sidecartest/fault/fs87_index_evs.go). What a return leaves out is directory_card_return_test.go's, and the run and
// worker writers' stop directory_run_test.go's and directory_worker_test.go's.

package sidecar_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The evs binding's erasure set read through the counting seam, counted as the fake counts it.
func (self *testCountingCards) CardsErasedVersions(ctx context.Context, repoId sidecar.Id, args *sidecar.DirectoryCardsErasedArgs) ([]uint64, error) {
	self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) { counts.ErasedReads += 1 })
	reader, ok := self.inner.(sidecar.DirectoryCardsErasureSet)
	if !ok {
		return nil, sidecar.ErrDirectoryCardReturnUnchecked
	}
	return reader.CardsErasedVersions(ctx, repoId, args)
}

// A binding that reads every DirectoryCards call through and no erasure set.
type testCardsWithoutErasureSet struct {
	sidecar.DirectoryCards
}

// A directory admin's erase of announcementId while writerId's card still holds it at version: the CUT lists its
// document there, then moderation removes the card whole (§16.11's erasure and closure rows, owner decision 636).
func (self *testDirectoryWorld) eraseFromCard(writerId sidecar.Id, announcementId sidecar.Id, version uint64) {
	self.t.Helper()
	self.cards.ListErased(self.directoryId, self.readerId, testAnnouncementDocumentName(&writerId, announcementId), version)
	self.removeFile(self.readerId, sidecar.DirectoryCardPath(writerId))
}

// A member's device whose runs and worker item ride its card: the format2 gate admits its network, and the repo is at
// format 2.
func (self *testDirectoryWorld) format2Device(memberId sidecar.Id) *testDirectoryDevice {
	self.t.Helper()
	writer := self.memberWriter(memberId)
	self.publish()
	device := self.device(writer)
	device.client.BindFormat2Gate(func() bool { return true })
	self.cards.RaiseFormat(self.directoryId)
	device.mustSync(self.t)
	return device
}

// device's directory client again over its stores, as its daemon starting does: nothing of the last client's memory is
// kept. The last client's runs are closed first.
func (self *testDirectoryWorld) restartClient(device *testDirectoryDevice) *sidecar.DirectoryClient {
	self.t.Helper()
	device.client.Runs().Close()
	if worker := device.client.Worker(); worker != nil {
		worker.Close()
	}
	writerId := device.writer.sidecarId
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId: writerId, Store: device.store, Cards: self.cards.For(writerId),
		Streams:    func() sidecar.RecordStreams { return self.streams.For(writerId) },
		Auth:       func() sidecar.DirectoryAuthView { return self.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		Clock:      self.clock, Settings: sidecar.DefaultSidecarSettings().Directory, Writer: device.record.Writer(),
		NetworkId: self.networkId, Sign: device.writer.sign,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	client.BindFormat2Gate(func() bool { return true })
	if err := client.Sync(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
	return client
}

// A run started on client under claims auto, announced as its start delay passes.
func (self *testDirectoryWorld) startRun(client *sidecar.DirectoryClient, title string) sidecar.Id {
	self.t.Helper()
	runId := sidecar.NewId()
	if err := client.Runs().Started(&sidecar.DirectoryRunStart{
		RunId: runId, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "example.org/team/app", AgentLabel: "builder", Harness: "codex",
		Title: title, Project: "example.org/team/app", Branch: "main",
	}); err != nil {
		self.t.Fatal(err)
	}
	self.clock.Advance(sidecar.DefaultDirectoryRunsSettings().StartDelay)
	return runId
}

// The run items a fresh reader shows of writerId's, by run id.
func (self *testDirectoryWorld) shownRuns(writerId sidecar.Id) map[sidecar.Id]*protocol.Announcement {
	self.t.Helper()
	reader := self.reader(nil)
	reader.mustSync(self.t)
	runs := map[sidecar.Id]*protocol.Announcement{}
	for _, item := range testItemsOf(self.t, reader, writerId) {
		if item.Key.Kind == sidecar.DirectoryAnnouncementKindRun {
			runs[sidecar.Id(item.Announcement.GetWhat().GetRunId())] = item.Announcement
		}
	}
	return runs
}

// A return whose binding reads no erasure set puts nothing, so no item an erasure took comes back unread; a card put
// with no removal between reads nothing and goes through.
func TestDirectoryCardReturnNeedsABindingThatReadsTheSet(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	world.publish()
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("directory", "search")
	if err != nil {
		t.Fatal(err)
	}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId: writer.sidecarId, Store: store, Cards: &testCardsWithoutErasureSet{DirectoryCards: world.cards.For(writer.sidecarId)},
		Streams:    func() sidecar.RecordStreams { return world.streams.For(writer.sidecarId) },
		Auth:       func() sidecar.DirectoryAuthView { return world.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return world.recordAuth.Tip() },
		Clock:      world.clock, Settings: sidecar.DefaultSidecarSettings().Directory,
		NetworkId: world.networkId, Sign: writer.sign,
	})
	if err != nil {
		t.Fatal(err)
	}
	write := func() (*sidecar.DirectoryCardWritten, error) {
		t.Helper()
		if err := client.Sync(t.Context()); err != nil {
			t.Fatal(err)
		}
		kept := testRunItem(writer.sidecarId, &memberId, sidecar.NewId(), 1, world.clock.Now().UnixMilli())
		return client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: []*protocol.Announcement{kept}})
	}
	if _, err := write(); err != nil {
		t.Fatalf("a card with no removal before it: %v", err)
	}

	path := sidecar.DirectoryCardPath(writer.sidecarId)
	world.removeFile(world.readerId, path)
	writes := world.counts().CardWrites
	if _, err := write(); !errors.Is(err, sidecar.ErrDirectoryCardReturnUnchecked) {
		t.Fatalf("a return with no binding that reads the erasure set: %v", err)
	}
	if world.counts().CardWrites != writes || world.cardFileVersion(path) != 0 {
		t.Fatal("a return its binding could not check put a card")
	}
}

// A return whose erasure set does not read, or whose set's version a writer that is no directory admin signed, puts
// nothing: the moderated run stays off the cards ref with its writer's other run. Once the set reads with an admin's
// version, the next write is the return, the moderated run left out and the other run two above.
func TestDirectoryCardReturnUncheckedPutsNothing(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	memberId := sidecar.NewId()
	writer := world.memberWriter(memberId)
	other := world.memberWriter(sidecar.NewId())
	world.publish()
	device := world.device(writer)
	now := world.clock.Now().UnixMilli()
	erasedId, keptId := sidecar.NewId(), sidecar.NewId()
	erased := testRunItem(writer.sidecarId, &memberId, erasedId, 1, now)
	kept := testRunItem(writer.sidecarId, &memberId, keptId, 1, now)
	device.writeCard(t, erased, kept)
	path := sidecar.DirectoryCardPath(writer.sidecarId)
	world.eraseFromCard(writer.sidecarId, erasedId, 1)
	world.clock.Advance(time.Minute)
	world.publish()
	device.mustSync(t)

	writes := world.counts().CardWrites
	refused := func(why string) {
		t.Helper()
		if _, err := device.client.WriteCard(t.Context(), &sidecar.DirectoryCardWriteArgs{Items: []*protocol.Announcement{erased, kept}}); !errors.Is(err, sidecar.ErrDirectoryCardReturnUnchecked) {
			t.Fatalf("a return whose %s: %v", why, err)
		}
		if world.counts().CardWrites != writes || world.cardFileVersion(path) != 0 {
			t.Fatalf("a return whose %s put a card", why)
		}
	}
	world.cards.FailErasedReads(world.directoryId, 1)
	refused("erasure set does not read")
	// a later CUT's version is the set's: one by a writer that is no directory admin, which no reader takes
	world.cards.ListErased(world.directoryId, other.sidecarId, testAnnouncementDocumentName(&other.sidecarId, sidecar.NewId()), 1)
	refused("set's version no directory admin signed")

	world.cards.ListErased(world.directoryId, world.readerId, testAnnouncementDocumentName(&writer.sidecarId, erasedId), 1)
	returned := device.writeCard(t, erased, kept)
	if versions := testCardWrittenVersions(returned); len(versions) != 1 || versions[keptId] != 3 {
		t.Fatalf("the return once the set reads carries %v", versions)
	}
	if len(returned.Moderated) != 1 || returned.Moderated[0] != erasedId {
		t.Fatalf("the return left out %v", returned.Moderated)
	}
}
