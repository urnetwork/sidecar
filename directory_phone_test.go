//go:build !sidecar_http

// RECORD-M6-27's metered view, FS-86's cold phone in M6's form on sidecartest's fakes: a directory whose announce
// entries pass 8 MiB, read on a metered link, shows partial coverage naming what is left, never a complete or empty
// view, and continues from where it stopped with AllowMetered or on Wi-Fi, reading no stream twice; two filters ask
// evs the same reads (I-19); and the view leases nothing and keeps nothing once closed.

package sidecar_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
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
