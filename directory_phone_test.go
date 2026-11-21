//go:build !sidecar_http

// RECORD-M6-27's metered view, FS-86's cold phone in M6's form on sidecartest's fakes: a directory whose announce
// entries pass 8 MiB, read on a metered link, shows partial coverage naming what is left, never a complete or empty
// view, and continues from where it stopped with AllowMetered or on Wi-Fi, reading no stream twice; two filters ask
// evs the same reads (I-19); and the view leases nothing and keeps nothing once closed.

package sidecar_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A DirectoryCards that logs each call it passes on, for a request trace.
type testRecordingCards struct {
	inner sidecar.DirectoryCards

	stateLock sync.Mutex
	calls     []string
}

func (self *testRecordingCards) log(call string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, call)
}

func (self *testRecordingCards) trace() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls)
}

func (self *testRecordingCards) Refs(ctx context.Context, repoId sidecar.Id, movedAfter uint64) (*sidecar.DirectoryRefListing, error) {
	self.log(fmt.Sprintf("refs %d", movedAfter))
	return self.inner.Refs(ctx, repoId, movedAfter)
}

func (self *testRecordingCards) ReadStreams(ctx context.Context, repoId sidecar.Id, reads []*sidecar.DirectoryStreamRead) ([]*sidecar.DirectoryStreamVersions, error) {
	named := []string{}
	for _, read := range reads {
		named = append(named, fmt.Sprintf("%s@%d", read.WriterSidecarId, read.PinVersion))
	}
	self.log("read " + strings.Join(named, ","))
	return self.inner.ReadStreams(ctx, repoId, reads)
}

func (self *testRecordingCards) ReadStreamLog(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryStreamVersions, error) {
	self.log(fmt.Sprintf("log %s@%d", writerSidecarId, afterVersion))
	return self.inner.ReadStreamLog(ctx, repoId, writerSidecarId, afterVersion)
}

func (self *testRecordingCards) ReadCards(ctx context.Context, repoId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryCardsChanges, error) {
	self.log(fmt.Sprintf("cards %d", afterVersion))
	return self.inner.ReadCards(ctx, repoId, afterVersion)
}

func (self *testRecordingCards) PlanCards(ctx context.Context, repoId sidecar.Id, after uint64) (*sidecar.DirectoryCardsChanges, error) {
	self.log(fmt.Sprintf("plan %d", after))
	return self.inner.(sidecar.DirectoryViewCards).PlanCards(ctx, repoId, after)
}

func (self *testRecordingCards) ReadPlannedCard(ctx context.Context, repoId sidecar.Id, file *sidecar.DirectoryCardFile) ([]byte, error) {
	self.log(fmt.Sprintf("file %s@%d", file.Path, file.PushVersion))
	return self.inner.(sidecar.DirectoryViewCards).ReadPlannedCard(ctx, repoId, file)
}

func (self *testRecordingCards) PutCard(ctx context.Context, repoId sidecar.Id, write *sidecar.DirectoryCardWrite) (uint64, error) {
	self.log("put " + write.Path)
	return self.inner.PutCard(ctx, repoId, write)
}

func (self *testRecordingCards) RemoveCard(ctx context.Context, repoId sidecar.Id, write *sidecar.DirectoryCardWrite) error {
	self.log("remove " + write.Path)
	return self.inner.RemoveCard(ctx, repoId, write)
}

func (self *testRecordingCards) Lease(repoId sidecar.Id, prefix string, callback func(repoId sidecar.Id)) (func(), error) {
	self.log("lease " + prefix)
	return self.inner.Lease(repoId, prefix, callback)
}

// A worker item near its caps, so a few hundred renewals pass 8 MiB: 32 services each described at length.
func testLargeWorkerItem(writerId sidecar.Id, memberId *sidecar.Id, announcementId sidecar.Id, renewedMillis int64) *protocol.Announcement {
	item := testWorkerItem(writerId, memberId, announcementId, 1, renewedMillis)
	item.What.Services = nil
	for port := 0; port < sidecar.DirectoryServiceCount; port += 1 {
		item.What.Services = append(item.What.Services, &protocol.Service{
			Kind:        uint32(sidecar.DirectoryServiceKindBridgePort),
			Name:        fmt.Sprintf("tcp:%d", 8000+port),
			Description: strings.Repeat(fmt.Sprintf("service %d of the build host, ", port), 10)[:sidecar.DirectoryServiceDescriptionByteCount],
		})
	}
	return item
}

// A cold phone's world: writerCount announcing sidecars, each renewing a large worker item renewals times, about
// 10 KiB a version.
func newTestPhoneWorld(t *testing.T, writerCount int, renewals int) (*testDirectoryWorld, []*testDirectoryWriter) {
	world := newTestDirectoryWorld(t, nil)
	writers := []*testDirectoryWriter{}
	members := []sidecar.Id{}
	for i := 0; i < writerCount; i += 1 {
		members = append(members, sidecar.NewId())
		writers = append(writers, world.memberWriter(members[i]))
	}
	world.publish()
	for i, writer := range writers {
		workerId := sidecar.NewId()
		for renewal := 0; renewal < renewals; renewal += 1 {
			writer.announce(testLargeWorkerItem(writer.sidecarId, &members[i], workerId, world.clock.Now().UnixMilli()))
			world.clock.Advance(time.Second)
		}
	}
	return world, writers
}

// A phone's client of the world's, its reads logged.
func (self *testDirectoryWorld) phone() (*testDirectoryReader, *testRecordingCards) {
	self.t.Helper()
	reader := self.reader(nil)
	recording := &testRecordingCards{inner: self.cards.For(self.readerId)}
	reader.client.Bind(recording, nil)
	return reader, recording
}

// FS-86's cold phone in M6's form: past 8 MiB on a metered link the view stops before the cap, naming the announcing
// sidecars fetched, those left and the bytes left, waiting=metered, and shows what it fetched as partial, never as
// complete or empty; AllowMetered, or a move to Wi-Fi, continues from where it stopped and completes, every stream
// named once in all; and nothing reaches the view's client's own store, and no lease is taken.
func TestDirectoryPhoneColdViewPastTheMeteredCap(t *testing.T) {
	const writerCount = 40
	world, writers := newTestPhoneWorld(t, writerCount, 25)
	for _, continueBy := range []string{"allow metered", "wi-fi"} {
		phone, recording := world.phone()
		before := world.cards.Counts()
		view, err := phone.client.View(&sidecar.DirectoryViewArgs{Metered: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := view.Fetch(t.Context()); err != nil {
			t.Fatal(err)
		}
		page := view.List(nil)
		coverage := page.Coverage
		cap := sidecar.DefaultSidecarSettings().Directory.PhoneMeteredByteCount
		if coverage.Complete || coverage.Waiting != sidecar.DirectoryCoverageWaitingMetered {
			t.Fatalf("%s: complete %v, waiting %q", continueBy, coverage.Complete, coverage.Waiting)
		}
		if cap < coverage.MeteredByteCount || coverage.FetchedByteCount != coverage.MeteredByteCount {
			t.Errorf("%s: %d metered bytes against a cap of %d", continueBy, coverage.MeteredByteCount, cap)
		}
		if len(coverage.FetchedSidecarIds) == 0 || len(coverage.LeftSidecarIds) == 0 ||
			len(coverage.FetchedSidecarIds)+len(coverage.LeftSidecarIds) != writerCount || coverage.LeftByteCount <= 0 {
			t.Errorf("%s: fetched %d, left %d, %d bytes left", continueBy, len(coverage.FetchedSidecarIds), len(coverage.LeftSidecarIds), coverage.LeftByteCount)
		}
		if len(page.Items) != len(coverage.FetchedSidecarIds) {
			t.Errorf("%s: a partial view of %d items from %d sidecars", continueBy, len(page.Items), len(coverage.FetchedSidecarIds))
		}
		// newest first: the sidecars left are the ones that announced earliest
		if coverage.LeftSidecarIds[0] != writers[len(coverage.LeftSidecarIds)-1].sidecarId {
			t.Errorf("%s: the first sidecar left is not the newest of those left", continueBy)
		}
		// a second Fetch on the metered link reads nothing more
		readsBefore := world.cards.Counts().StreamReads
		if err := view.Fetch(t.Context()); err != nil {
			t.Fatal(err)
		}
		if world.cards.Counts().StreamReads != readsBefore || view.Coverage().Waiting != sidecar.DirectoryCoverageWaitingMetered {
			t.Errorf("%s: a held view fetched again", continueBy)
		}

		if continueBy == "wi-fi" {
			view.SetMetered(false)
		} else {
			view.AllowMetered()
		}
		if err := view.Fetch(t.Context()); err != nil {
			t.Fatal(err)
		}
		page = view.List(nil)
		if !page.Coverage.Complete || page.Coverage.Waiting != "" || len(page.Coverage.LeftSidecarIds) != 0 || page.Coverage.LeftByteCount != 0 ||
			len(page.Items) != writerCount {
			t.Errorf("%s: complete %v, %d items, %d left", continueBy, page.Coverage.Complete, len(page.Items), len(page.Coverage.LeftSidecarIds))
		}
		after := world.cards.Counts()
		if after.StreamsNamed-before.StreamsNamed != writerCount || after.LogPages != before.LogPages {
			t.Errorf("%s: %d streams named for %d sidecars", continueBy, after.StreamsNamed-before.StreamsNamed, writerCount)
		}
		if after.LeasesTaken != before.LeasesTaken || after.CardsReads != before.CardsReads {
			t.Errorf("%s: the view leased or read the cards ref", continueBy)
		}
		for _, call := range recording.trace() {
			if strings.HasPrefix(call, "lease") || strings.HasPrefix(call, "put") {
				t.Errorf("%s: %s", continueBy, call)
			}
		}
		if entries := phone.client.Entries(); len(entries) != 0 {
			t.Errorf("%s: the client's own copy holds %d entries", continueBy, len(entries))
		}
		if entries, err := phone.store.List(""); err != nil || len(entries) != 0 {
			t.Errorf("%s: the client's store holds %d files", continueBy, len(entries))
		}
		view.Close()
		if closed := view.List(nil); len(closed.Items) != 0 {
			t.Errorf("%s: a closed view shows %d items", continueBy, len(closed.Items))
		}
		if err := view.Fetch(t.Context()); err == nil {
			t.Errorf("%s: a closed view fetched", continueBy)
		}
	}
}

// The fetch order is the listing's alone, newest first, so two views with different filters, and a query, ask evs the
// same reads in the same order (I-19), and each shows its own filter's items.
func TestDirectoryPhoneFetchOrderIgnoresTheFilter(t *testing.T) {
	world, writers := newTestPhoneWorld(t, 70, 2)
	traces := [][]string{}
	for _, filter := range []*sidecar.DirectoryFilter{
		{Kind: sidecar.DirectoryAnnouncementKindRun, Query: "nothing-matches-this"},
		{MemberId: world.directoryFixture.Sidecars[writers[3].sidecarId].MemberId, Query: "build host"},
	} {
		phone, recording := world.phone()
		view, err := phone.client.View(&sidecar.DirectoryViewArgs{Metered: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := view.Fetch(t.Context()); err != nil {
			t.Fatal(err)
		}
		page := view.List(filter)
		if !page.Coverage.Complete {
			t.Fatal("a small directory is not complete")
		}
		if filter.MemberId != nil && (len(page.Items) != 1 || page.Items[0].SignerSidecarId != writers[3].sidecarId) {
			t.Errorf("the member's filter shows %d items", len(page.Items))
		}
		if filter.MemberId == nil && len(page.Items) != 0 {
			t.Errorf("a filter nothing matches shows %d items", len(page.Items))
		}
		traces = append(traces, recording.trace())
		view.Close()
	}
	if !slices.Equal(traces[0], traces[1]) {
		t.Errorf("the traces differ:\n%v\n%v", traces[0], traces[1])
	}
	// one listing, the newest stream alone to measure a version, then the other 69 at 64 to a request
	if len(traces[0]) != 4 || !strings.HasPrefix(traces[0][0], "refs 0") || strings.Count(traces[0][1], ",") != 0 ||
		strings.Count(traces[0][2], ",") != 63 || strings.Count(traces[0][3], ",") != 4 {
		t.Errorf("trace %v", traces[0])
	}
	if !strings.Contains(traces[0][1], writers[len(writers)-1].sidecarId.String()) {
		t.Error("the first read is not the newest stream")
	}
}

// A view left open refreshes: once it holds everything, a Fetch lists only the streams moved since its last listing and
// reads what they added, so a new announcement shows, nothing is read again, and each sidecar is named fetched once.
func TestDirectoryPhoneOpenViewRefreshes(t *testing.T) {
	world, writers := newTestPhoneWorld(t, 3, 2)
	phone, _ := world.phone()
	view, err := phone.client.View(&sidecar.DirectoryViewArgs{Metered: false})
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if page := view.List(nil); !page.Coverage.Complete || len(page.Items) != 3 {
		t.Fatalf("complete %v, %d items", page.Coverage.Complete, len(page.Items))
	}
	before := world.cards.Counts()
	memberId := world.directoryFixture.Sidecars[writers[1].sidecarId].MemberId
	writers[1].announce(testRunItem(writers[1].sidecarId, memberId, sidecar.NewId(), 1, world.clock.Now().UnixMilli()))
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	page := view.List(nil)
	after := world.cards.Counts()
	if after.MovedListings != before.MovedListings+1 || after.FullListings != before.FullListings || after.StreamsNamed != before.StreamsNamed+1 {
		t.Errorf("a refresh: %+v, then %+v", before, after)
	}
	if !page.Coverage.Complete || len(page.Items) != 4 || len(page.Coverage.FetchedSidecarIds) != 3 {
		t.Errorf("after a refresh: complete %v, %d items, %d sidecars fetched", page.Coverage.Complete, len(page.Items), len(page.Coverage.FetchedSidecarIds))
	}
	// with nothing moved, a Fetch lists and reads nothing more
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if again := world.cards.Counts(); again.StreamReads != after.StreamReads {
		t.Errorf("an idle refresh read %d streams", again.StreamReads-after.StreamReads)
	}
}

// A mixed directory on a phone. A cold view plans the latest signed version of each
// file, pauses on its exact stored cost and resumes after a queued version is replaced.
func TestDirectoryPhoneFormat2Coverage(t *testing.T) {
	settings := sidecartest.DefaultFakeDirectoryCardsSettings()
	settings.CardsPageCount = 1
	world := newTestDirectoryWorld(t, settings)
	member, other := sidecar.NewId(), sidecar.NewId()
	writer, legacy := world.memberWriter(member), world.memberWriter(other)
	world.publish()
	repoId := world.createRepo(protocol.RepoKind_REPO_KIND_GENERAL, nil, writer)
	now := world.clock.Now().UnixMilli()
	legacyId, runId := sidecar.NewId(), sidecar.NewId()
	legacy.announce(testRunItem(legacy.sidecarId, &other, legacyId, 1, now))
	run := testRunItem(writer.sidecarId, &member, runId, 1, now)
	writer.announce(run)
	repoItem := testRepoItem(t, writer.sidecarId, &member, repoId, protocol.RepoKind_REPO_KIND_GENERAL, 1, now, "field notes", false)
	delayedRepo := writer.prepareAnnouncement(repoItem, nil, nil)
	delayedRun := writer.prepareAnnouncement(run, nil, nil)
	world.cards.RaiseFormat(world.directoryId)
	cardPath, repoPath := sidecar.DirectoryCardPath(writer.sidecarId), sidecar.DirectoryRepoPath(repoId)
	pin := world.directoryAuth.Tip().Pin()
	writeCard := func(seq uint64, items ...*protocol.Announcement) {
		world.putFile(writer.sidecarId, cardPath, world.cardContent(writer, writer.sidecarId, seq, pin, items...), pin)
	}
	writeCard(1, run)
	world.putFile(writer.sidecarId, repoPath, world.repoFileContent(writer, repoId, 1, pin, repoItem), pin)
	world.clock.Advance(time.Minute)
	writeCard(2, testRunItem(writer.sidecarId, &member, runId, 2, world.clock.Now().UnixMilli()))
	budget := sidecar.DefaultSidecarSettings().Directory
	budget.PhoneMeteredByteCount = sidecar.DirectoryFileStepByteCount
	scratch := sidecartest.NewFakeStore().Root()
	phone := world.readerWithSettings(nil, budget, scratch)
	recording := &testRecordingCards{inner: world.cardsFor(world.readerId)}
	phone.client.Bind(recording, nil)
	view, err := phone.client.View(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	page := view.List(nil)
	if page.Coverage.Complete || page.Coverage.Waiting != sidecar.DirectoryCoverageWaitingMetered ||
		page.Coverage.MeteredByteCount != budget.PhoneMeteredByteCount || page.Coverage.LeftByteCount < sidecar.DirectoryFileStepByteCount ||
		len(page.Items) != 1 || page.Items[0].Announcement.GetVersion() != 2 ||
		!slices.Contains(page.Coverage.LeftSidecarIds, legacy.sidecarId) || !slices.Contains(page.Coverage.LeftSidecarIds, writer.sidecarId) {
		t.Fatalf("metered page: %+v, %d items", page.Coverage, len(page.Items))
	}
	files := func() []string {
		out := []string{}
		for _, call := range recording.trace() {
			if strings.HasPrefix(call, "file ") {
				out = append(out, call)
			}
		}
		return out
	}
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := files(); !slices.Equal(got, []string{"file " + cardPath + "@3"}) {
		t.Fatalf("metered reads: %v", got)
	}
	if kept, err := scratch.List(""); err != nil || len(kept) == 0 {
		t.Fatalf("view store: %v, %v", kept, err)
	}
	// A removal while the older body is still queued triggers a refresh instead of
	// accepting stale bytes or claiming completeness.
	world.removeFile(writer.sidecarId, repoPath)
	view.AllowMetered()
	if err := view.Fetch(t.Context()); !errors.Is(err, sidecar.ErrEvsCollected) || view.Coverage().Complete {
		t.Fatalf("replaced read: %v, %+v", err, view.Coverage())
	}
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkRuns := func(page *sidecar.DirectoryViewPage) {
		t.Helper()
		if !page.Coverage.Complete || len(page.Items) != 2 || len(page.Coverage.LeftSidecarIds) != 0 || len(page.Coverage.FetchedSidecarIds) != 2 {
			t.Fatalf("coverage after removal: %+v, %d items", page.Coverage, len(page.Items))
		}
		var fromCard, fromStream bool
		for _, item := range page.Items {
			switch item.Key.AnnouncementId {
			case runId:
				fromCard = item.Key.WriterSidecarId == writer.sidecarId && item.Announcement.GetVersion() == 2 && item.EntryId == (sidecar.Id{})
			case legacyId:
				fromStream = item.Key.WriterSidecarId == legacy.sidecarId && item.Announcement.GetVersion() == 1 && item.EntryId != (sidecar.Id{})
			}
		}
		if !fromCard || !fromStream {
			t.Fatalf("current signed card visible: %t, retained stream entry visible: %t", fromCard, fromStream)
		}
	}
	checkRuns(view.List(nil))
	// A repo announcement drafted before the removal can arrive on its stream
	// afterward. The removed file still takes precedence over that old item.
	world.clock.Advance(time.Minute)
	writer.appendAnnouncement(delayedRepo)
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkRuns(view.List(nil))
	// A cold phone verifies the removal even if it never held the former repo file.
	afterRemoval, err := phone.client.View(&sidecar.DirectoryViewArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if err := afterRemoval.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkRuns(afterRemoval.List(nil))
	afterRemoval.Close()
	// Recreating the repo file is visible from an already open view.
	world.putFile(writer.sidecarId, repoPath, world.repoFileContent(writer, repoId, 2, pin, repoItem), pin)
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if page := view.List(nil); !page.Coverage.Complete || len(page.Items) != 3 {
		t.Fatalf("refreshed page: %+v, %d items", page.Coverage, len(page.Items))
	}
	// The writer withdraws its run by omitting it from its next card. Its
	// retained record must stay hidden in both an open view and a new cold view.
	world.clock.Advance(time.Minute)
	writeCard(3)
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if page := view.List(nil); !page.Coverage.Complete || len(page.Items) != 2 {
		t.Fatalf("withdrawn run returned from its retained record: %+v, %d items", page.Coverage, len(page.Items))
	}
	// An already-signed M6 draft can drain from an offline queue after the
	// withdrawal. Its old renewal still precedes the signed snapshot.
	world.clock.Advance(time.Minute)
	writer.appendAnnouncement(delayedRun)
	if err := view.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if page := view.List(nil); !page.Coverage.Complete || len(page.Items) != 2 {
		t.Fatalf("delayed record restored the withdrawn run: %+v, %d items", page.Coverage, len(page.Items))
	}
	view.Close()
	if kept, err := scratch.List(""); err != nil || len(kept) != 0 {
		t.Fatalf("closed view store: %v, %v", kept, err)
	}
	// The process exits with another view still open. Its replacement removes the
	// abandoned scope before reading the current heads into a new one.
	abandoned, err := phone.client.View(&sidecar.DirectoryViewArgs{})
	if err != nil {
		t.Fatal(err)
	}
	if err := abandoned.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if left, err := scratch.List(""); err != nil || len(left) == 0 {
		t.Fatalf("interrupted view store: %v, %v", left, err)
	}
	restart := world.readerWithSettings(nil, budget, scratch)
	cold, err := restart.client.View(&sidecar.DirectoryViewArgs{})
	if err != nil {
		t.Fatal(err)
	}
	defer cold.Close()
	if left, err := scratch.List(""); err != nil || len(left) != 0 {
		t.Fatalf("abandoned scope after restart: %v, %v", left, err)
	}
	if err := cold.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if page := cold.List(nil); !page.Coverage.Complete || len(page.Items) != 2 {
		t.Fatalf("reopened page: %+v, %d items", page.Coverage, len(page.Items))
	}
	world.clock.Advance(26 * time.Hour)
	if page := cold.List(nil); !page.Coverage.Complete || len(page.Items) != 1 || page.Items[0].Key.Kind != sidecar.DirectoryAnnouncementKindRepo {
		t.Fatalf("past the run's stale window: %+v, %d items", page.Coverage, len(page.Items))
	}
	if err := world.streams.Grant(world.directoryId, world.readerId, sidecartest.RecordStreamsScope{}); err != nil {
		t.Fatal(err)
	}
	if err := cold.Fetch(t.Context()); err == nil {
		t.Fatal("the server withdrew directory read access")
	}
	if page := cold.List(nil); page.Coverage.Complete || len(page.Items) != 0 {
		t.Fatalf("cached after losing read: %+v, %d items", page.Coverage, len(page.Items))
	}
	if err := world.streams.Grant(world.directoryId, world.readerId, sidecartest.RecordStreamsScope{Read: true}); err != nil {
		t.Fatal(err)
	}
	if err := cold.Fetch(t.Context()); err != nil {
		t.Fatal(err)
	}
	if page := cold.List(nil); !page.Coverage.Complete || len(page.Items) != 1 {
		t.Fatalf("restored read: %+v, %d items", page.Coverage, len(page.Items))
	}

	world.directoryFixture.Sidecars[world.readerId].RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	revoked, err := restart.client.View(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer revoked.Close()
	if err := revoked.Fetch(t.Context()); !errors.Is(err, sidecar.ErrDirectoryReadLost) {
		t.Fatalf("reader lost its directory: %v", err)
	}
	if page := revoked.List(nil); page.Coverage.Complete || len(page.Items) != 0 {
		t.Fatalf("revoked phone: %+v, %d items", page.Coverage, len(page.Items))
	}

}
