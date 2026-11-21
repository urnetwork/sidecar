//go:build !sidecar_http

// Overlapping calls on one EvsClient for the streams read, record streams' read and the directory's cards read
// (evs_pin_walk.go), on T2:
// record_evs_test.go's world, every device its own EvsClient against an evsservice.EvsEngine. A read whose answer evs
// served before another call of the same client read the ref to a newer head stands as read, with no alarm, the pin
// where the other call raised it; and a head below the pin a read asked at is still a regression, alarmed. Before the
// change each read held its head to the live pin and alarmed the first case as a fork (ErrEvsHeadForked). A hold at
// the world's transport fixes the order.

package sidecar_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A reader of a repo on the world whose events are kept.
type evsWatchedReader struct {
	sidecarId sidecar.Id
	store     sidecar.SidecarStore
	client    *sidecar.EvsClient

	stateLock sync.Mutex
	events    []sidecar.SidecarEvent
}

// A new device granted scope on repoId, its client's events kept.
func newEvsWatchedReader(t *testing.T, world *recordEvsWorld, repoId sidecar.Id, scope sidecartest.RecordStreamsScope) *evsWatchedReader {
	t.Helper()
	readerId := sidecar.NewId()
	if err := world.Grant(repoId, readerId, scope); err != nil {
		t.Fatal(err)
	}
	watched := &evsWatchedReader{sidecarId: readerId, store: sidecartest.NewFakeStore().Root()}
	watched.client = world.newClient(readerId, watched.store, func(args *sidecar.EvsClientArgs) {
		args.Emit = func(event sidecar.SidecarEvent) {
			watched.stateLock.Lock()
			defer watched.stateLock.Unlock()
			watched.events = append(watched.events, event)
		}
	})
	return watched
}

// The alarms the reader raised: head_alarm's and evs_alarm's.
func (self *evsWatchedReader) alarms() []sidecar.SidecarEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	alarms := []sidecar.SidecarEvent{}
	for _, event := range self.events {
		if event.Kind == sidecar.SidecarEventHeadAlarm || event.Kind == sidecar.SidecarEventEvsAlarm {
			alarms = append(alarms, event)
		}
	}
	return alarms
}

// The reader's pin of a ref, version 0 for none.
func (self *evsWatchedReader) pinVersion(t *testing.T, repoId sidecar.Id, refId sidecar.Id) uint64 {
	t.Helper()
	pin, pinned, err := self.client.Pins().Pin(repoId, refId)
	if err != nil {
		t.Fatal(err)
	}
	if !pinned {
		return 0
	}
	return pin.Version
}

// Holds the world's answer to the next request takes names, served in full, until the test lets it go: as a slow
// link holds a reply that has left evs. Every other request passes.
type evsWorldHold struct {
	held    chan struct{}
	release chan struct{}
	once    sync.Once
}

// Arms a hold on the world's next request takes names.
func holdEvsWorldServe(t *testing.T, world *recordEvsWorld, takes func(request *http.Request) bool) *evsWorldHold {
	t.Helper()
	hold := &evsWorldHold{held: make(chan struct{}), release: make(chan struct{})}
	taken := &atomic.Bool{}
	world.stateLock.Lock()
	world.afterServe = func(request *http.Request) error {
		if !takes(request) || !taken.CompareAndSwap(false, true) {
			return nil
		}
		close(hold.held)
		<-hold.release
		return nil
	}
	world.stateLock.Unlock()
	t.Cleanup(hold.let)
	return hold
}

// Lets the held answer go on; safe to call more than once.
func (self *evsWorldHold) let() {
	self.once.Do(func() { close(self.release) })
}

// POST .../read.
func evsWorldIsRead(request *http.Request) bool {
	return request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/read")
}

// GET .../log, a walk's page of statements.
func evsWorldIsLog(request *http.Request) bool {
	return request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/log")
}

// A streams read evs answered before another streams read of the same client read the stream to a newer head stands
// as read, with no alarm: the other read's raise walked over its head while it was in flight, and the pin stays where
// it raised it.
func TestEvsReadStreamsAnsweredBeforeAnotherReadRaisedThePinStands(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	writer := world.writers[0]
	reader := newEvsWatchedReader(t, world.world, world.repoId, sidecartest.RecordStreamsScope{Read: true, Write: true})
	repo := reader.client.Repo(world.repoId)
	refId, err := repo.RefIdOf(t.Context(), sidecar.RecordStreamRefName(writer))
	if err != nil {
		t.Fatal(err)
	}
	world.append(t, writer, 1, 1)
	first, err := repo.ReadStreams(t.Context(), []*sidecar.EvsStreamRead{{RefId: refId}})
	if err != nil || len(first[0].Versions) != 1 {
		t.Fatalf("the first read: %v", err)
	}
	held := first[0].Versions[0]
	readFromFirst := func() []*sidecar.EvsStreamRead {
		return []*sidecar.EvsStreamRead{{RefId: refId, PinVersion: held.Version, PinChain: held.Statement.Chain}}
	}
	world.append(t, writer, 2, 1)
	hold := holdEvsWorldServe(t, world.world, evsWorldIsRead)
	type read struct {
		answers []*sidecar.EvsStreamVersions
		err     error
	}
	reads := make(chan read, 1)
	go func() {
		answers, err := repo.ReadStreams(context.Background(), readFromFirst())
		reads <- read{answers: answers, err: err}
	}()
	<-hold.held
	world.append(t, writer, 3, 1)
	beside, err := repo.ReadStreams(t.Context(), readFromFirst())
	if err != nil || len(beside[0].Versions) != 2 {
		t.Fatalf("the read beside it: %v", err)
	}
	hold.let()
	answer := <-reads
	if answer.err != nil {
		t.Fatalf("the held read: %v", answer.err)
	}
	if versions := answer.answers[0].Versions; len(versions) != 1 || versions[0].Version != 2 || answer.answers[0].Head.GetVersion() != 2 {
		t.Fatalf("the held read's versions %d", len(versions))
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	if pinned := reader.pinVersion(t, world.repoId, refId); pinned != 3 {
		t.Errorf("the pin %d", pinned)
	}
}

// A stream read to a head below this device's pin of its ref, as the read asked at it, is a regression: refused
// with head_alarm, whatever version the caller reads from.
func TestEvsReadStreamsBelowThePinItAskedAtIsARegression(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	writer := world.writers[0]
	reader := newEvsWatchedReader(t, world.world, world.repoId, sidecartest.RecordStreamsScope{Read: true, Write: true})
	repo := reader.client.Repo(world.repoId)
	refId, err := repo.RefIdOf(t.Context(), sidecar.RecordStreamRefName(writer))
	if err != nil {
		t.Fatal(err)
	}
	world.append(t, writer, 1, 1)
	if err := reader.client.Pins().Raise(&sidecar.EvsPin{RepoId: world.repoId, RefId: refId, Version: 9, Chain: [32]byte{9}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ReadStreams(t.Context(), []*sidecar.EvsStreamRead{{RefId: refId}}); !errors.Is(err, sidecar.ErrEvsHeadForked) {
		t.Fatalf("a head below the pin: %v", err)
	}
	if alarms := reader.alarms(); len(alarms) != 1 || alarms[0].Kind != sidecar.SidecarEventHeadAlarm || alarms[0].HeadAlarm != sidecar.SidecarHeadAlarmFork {
		t.Errorf("alarms %v", alarms)
	}
}

// A cards read evs answered before another cards read of the same client read the cards ref to a newer head stands
// as read, with no alarm, giving the file its version wrote, and the pin stays where the other read raised it.
func TestDirectoryEvsCardsReadAnsweredBeforeAnotherReadRaisedThePinStands(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 1)
	writer := directory.writers[0]
	reader := newEvsWatchedReader(t, directory.world, directory.directoryId, sidecartest.RecordStreamsScope{Read: true, Write: true})
	cards := directory.binding(t, reader.client, nil)
	notices := directoryEvsNoticePaths(t, 3)
	directory.put(t, writer, notices[0], 0, "one")
	if changes, err := cards.ReadCards(t.Context(), directory.directoryId, 0); err != nil || changes.ThroughVersion != 1 {
		t.Fatalf("the first read: %+v %v", changes, err)
	}
	directory.put(t, writer, notices[1], 0, "two")
	hold := holdEvsWorldServe(t, directory.world, evsWorldIsRead)
	type read struct {
		changes *sidecar.DirectoryCardsChanges
		err     error
	}
	reads := make(chan read, 1)
	go func() {
		changes, err := cards.ReadCards(context.Background(), directory.directoryId, 1)
		reads <- read{changes: changes, err: err}
	}()
	<-hold.held
	directory.put(t, writer, notices[2], 0, "three")
	beside := directory.binding(t, reader.client, nil)
	if changes, err := beside.ReadCards(t.Context(), directory.directoryId, 1); err != nil || changes.ThroughVersion != 3 {
		t.Fatalf("the read beside it: %+v %v", changes, err)
	}
	hold.let()
	answer := <-reads
	if answer.err != nil {
		t.Fatalf("the held read: %v", answer.err)
	}
	if changes := answer.changes; changes.HeadVersion != 2 || changes.ThroughVersion != 2 || len(changes.Files) != 1 ||
		changes.Files[0].Path != notices[1] || string(changes.Files[0].Content) != "two" {
		t.Fatalf("the held read: %+v", changes)
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	refId, err := reader.client.Repo(directory.directoryId).RefIdOf(t.Context(), sidecar.DirectoryCardsRefName())
	if err != nil {
		t.Fatal(err)
	}
	if pinned := reader.pinVersion(t, directory.directoryId, refId); pinned != 3 {
		t.Errorf("the pin %d", pinned)
	}
}

// A cards read of a head below this device's pin of the cards ref, as the read asked at it, is a regression: refused
// with head_alarm.
func TestDirectoryEvsCardsReadBelowThePinItAskedAtIsARegression(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 1)
	writer := directory.writers[0]
	reader := newEvsWatchedReader(t, directory.world, directory.directoryId, sidecartest.RecordStreamsScope{Read: true, Write: true})
	cards := directory.binding(t, reader.client, nil)
	directory.put(t, writer, directoryEvsNoticePaths(t, 1)[0], 0, "one")
	refId, err := reader.client.Repo(directory.directoryId).RefIdOf(t.Context(), sidecar.DirectoryCardsRefName())
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.client.Pins().Raise(&sidecar.EvsPin{RepoId: directory.directoryId, RefId: refId, Version: 9, Chain: [32]byte{9}}); err != nil {
		t.Fatal(err)
	}
	if _, err := cards.ReadCards(t.Context(), directory.directoryId, 0); !errors.Is(err, sidecar.ErrEvsHeadForked) {
		t.Fatalf("a head below the pin: %v", err)
	}
	if alarms := reader.alarms(); len(alarms) != 1 || alarms[0].Kind != sidecar.SidecarEventHeadAlarm || alarms[0].HeadAlarm != sidecar.SidecarHeadAlarmFork {
		t.Errorf("alarms %v", alarms)
	}
}

// A record stream's read (RecordEvsStreams.ReadStream: pinnedHead, the stream's whole history from C_0, then the pin)
// stands, with no alarm, though another read of the same client read the stream to a newer head while it walked: that
// read's raise walked over its head, and the pin stays where it raised it. Before the change the walk's raise was held
// to the live pin and refused as a regression with head_alarm.
func TestRecordEvsStreamsReadAnsweredBeforeAnotherReadRaisedThePinStands(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	writer := world.writers[0]
	reader := newEvsWatchedReader(t, world.world, world.repoId, sidecartest.RecordStreamsScope{Read: true, Write: true})
	streams := world.world.streamsOn(reader.sidecarId, reader.client, reader.store)
	refId, err := reader.client.Repo(world.repoId).RefIdOf(t.Context(), sidecar.RecordStreamRefName(writer))
	if err != nil {
		t.Fatal(err)
	}
	world.append(t, writer, 1, 1)
	if versions, err := streams.ReadStream(t.Context(), world.repoId, writer, 0); err != nil || len(versions) != 1 {
		t.Fatalf("the first read: %d %v", len(versions), err)
	}
	world.append(t, writer, 2, 1)
	hold := holdEvsWorldServe(t, world.world, evsWorldIsLog)
	type read struct {
		versions []*sidecar.RecordStreamVersion
		err      error
	}
	reads := make(chan read, 1)
	go func() {
		versions, err := streams.ReadStream(context.Background(), world.repoId, writer, 0)
		reads <- read{versions: versions, err: err}
	}()
	<-hold.held
	world.append(t, writer, 3, 1)
	beside := world.world.streamsOn(reader.sidecarId, reader.client, reader.store)
	if versions, err := beside.ReadStream(t.Context(), world.repoId, writer, 0); err != nil || len(versions) != 3 {
		t.Fatalf("the read beside it: %d %v", len(versions), err)
	}
	hold.let()
	answer := <-reads
	if answer.err != nil {
		t.Fatalf("the held read: %v", answer.err)
	}
	if len(answer.versions) != 2 || answer.versions[1].Version != 2 {
		t.Fatalf("the held read's versions %d", len(answer.versions))
	}
	if alarms := reader.alarms(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
	if pinned := reader.pinVersion(t, world.repoId, refId); pinned != 3 {
		t.Errorf("the pin %d", pinned)
	}
}
