//go:build !sidecar_http

// RECORD-M6-13's sync on sidecartest's FakeDirectoryCards over FakeRecordStreams, with FakeDirectoryAuth and
// FakeRecordAuth as the state and a fake clock: n moved streams read in ceil(n/64) requests, no lease on the cards ref,
// the daily full listing, a moved_after from before a sequence restart answering every ref, ViewCoalesce, behind paged
// through the log, and a lost read deleting the copy. Entries are sealed and signed for real, so each sync's reader
// verifies them as any log's.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A team network's directory as the sync tests drive it: the world's streams and cards, the state at each position,
// and the reading sidecar.
type testDirectoryWorld struct {
	t           *testing.T
	clock       *sidecartest.FakeClock
	streams     *sidecartest.FakeRecordStreams
	cards       *sidecartest.FakeDirectoryCards
	directoryId sidecar.Id
	readerId    sidecar.Id

	directoryAuth    *sidecartest.FakeDirectoryAuth
	directoryFixture *sidecartest.FakeDirectoryAuthFixture
	recordAuth       *sidecartest.FakeRecordAuth
	recordFixture    *sidecartest.FakeRecordAuthFixture
}

// One writer of the directory: its identity key and its own chain.
type testDirectoryWriter struct {
	world     *testDirectoryWorld
	sidecarId sidecar.Id
	key       ed25519.PrivateKey
	env       *sidecar.RecordSealEnv
	counter   uint64
}

func newTestDirectoryWorld(t *testing.T, settings *sidecartest.FakeDirectoryCardsSettings) *testDirectoryWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	streams := sidecartest.NewFakeRecordStreams(clock, nil, nil)
	directoryId, err := streams.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	readerId := sidecar.NewId()
	memberId := sidecar.NewId()
	if err := streams.Grant(directoryId, readerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	world := &testDirectoryWorld{
		t:             t,
		clock:         clock,
		streams:       streams,
		cards:         sidecartest.NewFakeDirectoryCards(streams, settings),
		directoryId:   directoryId,
		readerId:      readerId,
		directoryAuth: sidecartest.NewFakeDirectoryAuth(),
		directoryFixture: &sidecartest.FakeDirectoryAuthFixture{
			Sidecars: map[sidecar.Id]*sidecartest.FakeDirectorySidecar{readerId: {MemberId: &memberId}},
			Repos: map[sidecar.Id]*sidecartest.FakeDirectoryRepo{directoryId: {
				Kind: protocol.RepoKind_REPO_KIND_DIRECTORY, Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: readerId, At: 1}},
			}},
			DirectoryId: &directoryId,
		},
		recordAuth: sidecartest.NewFakeRecordAuth(),
		recordFixture: &sidecartest.FakeRecordAuthFixture{
			IdentityKeys: map[sidecar.Id][]byte{},
			Members:      map[sidecar.Id]sidecar.Id{readerId: memberId},
			Repos:        map[sidecar.Id]*sidecartest.FakeRecordRepoAuth{directoryId: {Readers: []sidecar.Id{readerId}}},
			Logs:         &sidecar.RecordLogIds{Team: true, DirectoryId: &directoryId},
		},
	}
	world.publish()
	return world
}

// Appends the fixtures as the next position of each state.
func (self *testDirectoryWorld) publish() {
	self.recordFixture.TimeMillis = self.clock.Now().UnixMilli()
	self.recordAuth.Append(self.recordFixture)
	self.directoryAuth.Append(self.directoryFixture)
}

// A new writer, admitted and writing its own stream.
func (self *testDirectoryWorld) writer() *testDirectoryWriter {
	self.t.Helper()
	publicKey, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		self.t.Fatal(err)
	}
	writer := &testDirectoryWriter{world: self, sidecarId: sidecar.NewId(), key: key}
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("writer", "record")
	if err != nil {
		self.t.Fatal(err)
	}
	writer.env = &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(store, writer.sidecarId), Sign: writer.sign}
	if err := self.streams.Grant(self.directoryId, writer.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		self.t.Fatal(err)
	}
	self.recordFixture.IdentityKeys[writer.sidecarId] = publicKey
	repo := self.recordFixture.Repos[self.directoryId]
	repo.Writers = append(repo.Writers, writer.sidecarId)
	return writer
}

func (self *testDirectoryWriter) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// Seals count notes and pushes them, each its own version of the writer's stream.
func (self *testDirectoryWriter) push(count int) {
	t := self.world.t
	t.Helper()
	for i := 0; i < count; i += 1 {
		sealed, err := sidecar.RecordSeal(self.env, &sidecar.RecordSealArgs{
			LogId:         self.world.directoryId,
			Kind:          sidecar.RecordKindNote,
			Source:        sidecar.RecordSourceAgent,
			TimeMillis:    self.world.clock.Now().UnixMilli(),
			Tainted:       true,
			PolicyVersion: self.world.recordAuth.Tip().Pin().GetVersion(),
			Body:          &protocol.CoordinationBody{Text: "a note in the directory"},
		})
		if err != nil {
			t.Fatal(err)
		}
		self.counter += 1
		path, err := sidecar.RecordStreamPath(self.counter)
		if err != nil {
			t.Fatal(err)
		}
		push := &sidecar.RecordStreamPush{
			PushId:          sidecar.NewId(),
			WriterSidecarId: self.sidecarId,
			SlotId:          sidecar.NewId(),
			AuthPin:         self.world.recordAuth.Tip().Pin(),
			SlotRows:        []*sidecar.RecordSlotRow{sealed.SlotRow(0)},
		}
		push.Entries = []*sidecar.RecordStreamEntry{{Path: path, Entry: sealed.EntryBytes(&push.SlotId, 0)}}
		if _, err := self.world.streams.For(self.sidecarId).Append(t.Context(), self.world.directoryId, push); err != nil {
			t.Fatal(err)
		}
	}
}

// A reading sidecar's client: its copy in a fake store, its syncs counted.
type testDirectoryReader struct {
	client *sidecar.DirectoryClient
	files  *sidecartest.FakeStore
	store  sidecar.SidecarStore

	stateLock sync.Mutex
	syncs     []error
	alarms    []*sidecar.RecordAlarm
	synced    chan struct{}
}

func (self *testDirectoryWorld) reader(sessionActive func() bool) *testDirectoryReader {
	self.t.Helper()
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("directory", "search")
	if err != nil {
		self.t.Fatal(err)
	}
	reader := &testDirectoryReader{files: files, store: store, synced: make(chan struct{}, 64)}
	client, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:     self.readerId,
		Store:         store,
		Cards:         self.cards.For(self.readerId),
		Streams:       func() sidecar.RecordStreams { return self.streams.For(self.readerId) },
		Auth:          func() sidecar.DirectoryAuthView { return self.directoryAuth.Tip() },
		RecordAuth:    func() sidecar.RecordAuthView { return self.recordAuth.Tip() },
		SessionActive: sessionActive,
		AfterSync: func(err error) {
			func() {
				reader.stateLock.Lock()
				defer reader.stateLock.Unlock()
				reader.syncs = append(reader.syncs, err)
			}()
			reader.synced <- struct{}{}
		},
		Alarm: func(alarm *sidecar.RecordAlarm) {
			reader.stateLock.Lock()
			defer reader.stateLock.Unlock()
			reader.alarms = append(reader.alarms, alarm)
		},
		Clock:    self.clock,
		Settings: sidecar.DefaultSidecarSettings().Directory,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	reader.client = client
	return reader
}

// The alarms raised so far.
func (self *testDirectoryReader) alarmReasons() []sidecar.SidecarRecordAlarm {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reasons := []sidecar.SidecarRecordAlarm{}
	for _, alarm := range self.alarms {
		reasons = append(reasons, alarm.Reason)
	}
	return reasons
}

// One sync, which must succeed.
func (self *testDirectoryReader) mustSync(t *testing.T) {
	t.Helper()
	if err := self.client.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// n moved streams are read in ceil(n/64) requests, each naming only moved streams, and every entry verifies; a later
// sync reads only what moved since.
func TestDirectorySyncReadsMovedStreamsSixtyFourToARequest(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	writers := []*testDirectoryWriter{}
	for i := 0; i < 130; i += 1 {
		writers = append(writers, world.writer())
	}
	world.publish()
	for _, writer := range writers {
		writer.push(1)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	counts := world.cards.Counts()
	if counts.StreamReads != 3 || counts.StreamsNamed != 130 {
		t.Errorf("130 moved streams in %d requests naming %d", counts.StreamReads, counts.StreamsNamed)
	}
	entries := reader.client.Entries()
	if len(entries) != 130 {
		t.Fatalf("%d entries verified", len(entries))
	}
	for _, entry := range entries {
		if entry.State != sidecar.RecordEntryLive || entry.Body == nil {
			t.Fatalf("an entry %s, body %v", entry.State, entry.Body != nil)
		}
	}
	if alarms := reader.alarmReasons(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}

	for _, writer := range writers[:5] {
		writer.push(2)
	}
	reader.mustSync(t)
	counts = world.cards.Counts()
	if counts.StreamReads != 4 || counts.StreamsNamed != 135 || counts.MovedListings != 1 {
		t.Errorf("5 moved streams: %+v", counts)
	}
	if entries := reader.client.Entries(); len(entries) != 140 {
		t.Errorf("%d entries after the second sync", len(entries))
	}
	// an idle sync reads no stream
	reader.mustSync(t)
	if counts := world.cards.Counts(); counts.StreamReads != 4 {
		t.Errorf("an idle sync read streams: %+v", counts)
	}
}

// Syncs poll the cards ref and never lease it: only a notice prefix or a notice's path takes a lease, and each hint
// on it asks for a sync.
func TestDirectorySyncLeasesNoCardsRef(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	reader := world.reader(nil)
	writer := world.writer()
	world.publish()
	writer.push(1)
	reader.mustSync(t)
	reader.mustSync(t)
	if leases := world.cards.Leases(); len(leases) != 0 {
		t.Fatalf("syncs leased %v", leases)
	}
	target := &protocol.RequestTarget{RepoId: sidecar.NewId().Bytes()}
	prefix, err := sidecar.DirectoryNoticePrefix(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, refused := range []string{"", "d/", "r/", "q/", "d/ab/" + prefix[5:37], ".ur-index/i1/"} {
		if _, err := reader.client.Lease(refused); !errors.Is(err, sidecar.ErrDirectoryLeaseRefused) {
			t.Errorf("a lease on %q: %v", refused, err)
		}
	}
	release, err := reader.client.Lease(prefix)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	leases := world.cards.Leases()
	if len(leases) != 1 || leases[0].Prefix != prefix {
		t.Fatalf("leases %v", leases)
	}
	// a notice written under the prefix hints the holder, which asks for a sync and leases nothing more
	noticePath, err := sidecar.DirectoryNoticePath(target, sidecar.NewId())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.cards.For(writer.sidecarId).PutCard(t.Context(), world.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: noticePath, Content: []byte("a notice"), AuthPin: world.recordAuth.Tip().Pin(),
	}); err != nil {
		t.Fatal(err)
	}
	reader.mustSync(t)
	cards := reader.client.Cards()
	if len(cards) != 1 || cards[0].Path != noticePath || !bytes.Equal(cards[0].Content, []byte("a notice")) {
		t.Errorf("the copy's cards %v", cards)
	}
	if leases := world.cards.Leases(); len(leases) != 1 {
		t.Errorf("leases after the hint %v", leases)
	}
}

// The first sync of each UTC day lists every ref, with no moved_after; the rest of the day lists only moved ones.
func TestDirectorySyncListsEveryRefDaily(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	world.clock.AdvanceTo(time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC))
	reader := world.reader(nil)
	reader.mustSync(t)
	reader.mustSync(t)
	world.clock.Advance(14 * time.Hour)
	reader.mustSync(t)
	if counts := world.cards.Counts(); counts.FullListings != 1 || counts.MovedListings != 2 {
		t.Fatalf("one day: %+v", counts)
	}
	world.clock.Advance(1 * time.Hour)
	reader.mustSync(t)
	reader.mustSync(t)
	if counts := world.cards.Counts(); counts.FullListings != 2 || counts.MovedListings != 3 {
		t.Errorf("the next day: %+v", counts)
	}
}

// A moved_after from before the push sequence's restart answers every ref, and the sync reads only the streams past
// what its copy holds: a commit whose raise the restart lost is not missed.
func TestDirectorySyncMovedAfterARestartAnswersEveryRef(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	writers := []*testDirectoryWriter{world.writer(), world.writer(), world.writer()}
	world.publish()
	for _, writer := range writers {
		writer.push(1)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	before := world.cards.Counts()
	world.streams.RestartSequence(world.directoryId)
	writers[1].push(1)
	listing, err := world.cards.For(world.readerId).Refs(t.Context(), world.directoryId, 1)
	if err != nil || !listing.All || len(listing.Refs) != 3 {
		t.Fatalf("a moved_after before the restart: %+v, %v", listing, err)
	}
	reader.mustSync(t)
	after := world.cards.Counts()
	if after.StreamReads-before.StreamReads != 1 || after.StreamsNamed-before.StreamsNamed != 1 {
		t.Errorf("after the restart the sync read %d requests naming %d streams", after.StreamReads-before.StreamReads, after.StreamsNamed-before.StreamsNamed)
	}
	if entries := reader.client.Entries(); len(entries) != 4 {
		t.Errorf("%d entries", len(entries))
	}
}

// A stream whose pin is older than evs's window answers behind, and the sync pages its log to the head.
func TestDirectorySyncPagesBehindThroughTheLog(t *testing.T) {
	world := newTestDirectoryWorld(t, &sidecartest.FakeDirectoryCardsSettings{
		FrameVersionCount: 64, WindowVersionCount: 4, LogPageCount: 3, CardsPageCount: 1000,
	})
	writer := world.writer()
	world.publish()
	writer.push(10)
	reader := world.reader(nil)
	reader.mustSync(t)
	counts := world.cards.Counts()
	if counts.StreamReads != 1 || counts.LogPages != 4 {
		t.Errorf("10 versions behind a window of 4: %+v", counts)
	}
	if entries := reader.client.Entries(); len(entries) != 10 {
		t.Errorf("%d entries", len(entries))
	}
	if alarms := reader.alarmReasons(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

// A stream past one read's frame answers more, and joins the next request from where it stopped.
func TestDirectorySyncFollowsMore(t *testing.T) {
	world := newTestDirectoryWorld(t, &sidecartest.FakeDirectoryCardsSettings{
		FrameVersionCount: 4, WindowVersionCount: 4096, LogPageCount: 1000, CardsPageCount: 1000,
	})
	writer := world.writer()
	world.publish()
	writer.push(9)
	reader := world.reader(nil)
	reader.mustSync(t)
	if counts := world.cards.Counts(); counts.StreamReads != 3 || counts.LogPages != 0 {
		t.Errorf("9 versions in frames of 4: %+v", counts)
	}
	if entries := reader.client.Entries(); len(entries) != 9 {
		t.Errorf("%d entries", len(entries))
	}
}

// Views coalesce over ViewCoalesce on the fake clock: the loop syncs at once, several views within the window cost one
// sync at its end, and with no view the idle interval sets the next.
func TestDirectorySyncViewCoalesce(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	reader := world.reader(nil)
	settings := sidecar.DefaultSidecarSettings().Directory
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader.client.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	awaitSync := func() {
		t.Helper()
		select {
		case <-reader.synced:
		case <-time.After(10 * time.Second):
			t.Fatal("no sync")
		}
	}
	awaitSync()
	if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	reader.client.View()
	reader.client.View()
	world.clock.Advance(settings.ViewCoalesce / 2)
	reader.client.View()
	if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reader.synced:
		t.Fatal("a view synced inside the window")
	default:
	}
	world.clock.Advance(settings.ViewCoalesce / 2)
	awaitSync()
	if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	if counts := world.cards.Counts(); counts.FullListings+counts.MovedListings != 2 {
		t.Errorf("three views: %+v", counts)
	}
	// no view: the idle interval
	world.clock.Advance(settings.IdleSyncInterval - time.Second)
	if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reader.synced:
		t.Fatal("a sync before the idle interval")
	default:
	}
	world.clock.Advance(time.Second)
	awaitSync()
}

// While a harness session is served the loop syncs every SessionSyncInterval.
func TestDirectorySyncSessionInterval(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	reader := world.reader(func() bool { return true })
	settings := sidecar.DefaultSidecarSettings().Directory
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		reader.client.Run(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()
	for i := 0; i < 3; i += 1 {
		select {
		case <-reader.synced:
		case <-time.After(10 * time.Second):
			t.Fatalf("no sync %d", i)
		}
		if err := world.clock.AwaitTimers(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
		if pending := world.clock.PendingTimers(); len(pending) != 1 || !pending[0].Equal(world.clock.Now().Add(settings.SessionSyncInterval)) {
			t.Fatalf("the next sync at %v", pending)
		}
		world.clock.Advance(settings.SessionSyncInterval)
	}
}

// A read this sidecar loses deletes its copy, and the client answers so until it reads again: by the state, a revoked
// sidecar; by evs, a refused scope.
func TestDirectorySyncLostReadDeletesTheStore(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	writer := world.writer()
	world.publish()
	writer.push(3)
	reader := world.reader(nil)
	reader.mustSync(t)
	if empty, err := sidecar.NewDirectoryStore(reader.store).Empty(); err != nil || empty {
		t.Fatalf("no copy after a sync: %v", err)
	}
	world.directoryFixture.Sidecars[world.readerId].RevokedAt = world.directoryAuth.Tip().Pin().GetVersion() + 1
	world.publish()
	if err := reader.client.Sync(t.Context()); !errors.Is(err, sidecar.ErrDirectoryReadLost) {
		t.Fatalf("a revoked reader's sync: %v", err)
	}
	if empty, err := sidecar.NewDirectoryStore(reader.store).Empty(); err != nil || !empty {
		t.Errorf("the copy outlived a lost read: %v", err)
	}
	if entries := reader.client.Entries(); len(entries) != 0 {
		t.Errorf("%d entries after a lost read", len(entries))
	}

	// evs's refusal is a lost read too
	world.directoryFixture.Sidecars[world.readerId].RevokedAt = 0
	world.publish()
	reader.mustSync(t)
	if entries := reader.client.Entries(); len(entries) != 3 {
		t.Fatalf("%d entries read again", len(entries))
	}
	if err := world.streams.Grant(world.directoryId, world.readerId, sidecartest.RecordStreamsScope{}); err != nil {
		t.Fatal(err)
	}
	if err := reader.client.Sync(t.Context()); !errors.Is(err, sidecar.ErrDirectoryReadLost) {
		t.Fatalf("a refused read: %v", err)
	}
	if empty, err := sidecar.NewDirectoryStore(reader.store).Empty(); err != nil || !empty {
		t.Errorf("the copy outlived evs's refusal: %v", err)
	}
}

// A restart reads nothing again: a new client over the same copy syncs with a moved listing and reads no stream, and its
// reader verifies what the copy holds.
func TestDirectorySyncRestartKeepsTheCopy(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	writers := []*testDirectoryWriter{world.writer(), world.writer()}
	world.publish()
	for _, writer := range writers {
		writer.push(2)
	}
	first := world.reader(nil)
	first.mustSync(t)
	before := world.cards.Counts()
	restarted, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  world.readerId,
		Store:      first.store,
		Cards:      world.cards.For(world.readerId),
		Streams:    func() sidecar.RecordStreams { return world.streams.For(world.readerId) },
		Auth:       func() sidecar.DirectoryAuthView { return world.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return world.recordAuth.Tip() },
		Clock:      world.clock,
		Settings:   sidecar.DefaultSidecarSettings().Directory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	after := world.cards.Counts()
	if after.StreamReads != before.StreamReads || after.MovedListings != before.MovedListings+1 {
		t.Errorf("a restart re-read: before %+v after %+v", before, after)
	}
	if entries := restarted.Entries(); len(entries) != 4 {
		t.Errorf("%d entries from the copy", len(entries))
	}
}

// A personal network, or a team whose directory does not exist yet, answers ErrDirectoryNone and writes nothing; a
// read_only client refuses every write.
func TestDirectoryClientNoDirectoryAndReadOnly(t *testing.T) {
	world := newTestDirectoryWorld(t, nil)
	world.directoryFixture.DirectoryId = nil
	world.publish()
	reader := world.reader(nil)
	if err := reader.client.Sync(t.Context()); !errors.Is(err, sidecar.ErrDirectoryNone) {
		t.Errorf("a sync with no directory: %v", err)
	}
	if _, err := reader.client.PutCard(t.Context(), &sidecar.DirectoryCardWrite{Path: "q/ab/x/y"}); !errors.Is(err, sidecar.ErrDirectoryNone) {
		t.Errorf("a write with no directory: %v", err)
	}
	if counts := world.cards.Counts(); counts != (sidecartest.FakeDirectoryCardsCounts{}) {
		t.Errorf("evs was asked %+v", counts)
	}

	directoryId := world.directoryId
	world.directoryFixture.DirectoryId = &directoryId
	world.publish()
	readOnly, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  world.readerId,
		Store:      sidecartest.NewFakeStore().Root(),
		Cards:      world.cards.For(world.readerId),
		Auth:       func() sidecar.DirectoryAuthView { return world.directoryAuth.Tip() },
		RecordAuth: func() sidecar.RecordAuthView { return world.recordAuth.Tip() },
		Clock:      world.clock,
		Settings:   sidecar.DefaultSidecarSettings().Directory,
		ReadOnly:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := readOnly.Sync(t.Context()); err != nil {
		t.Fatalf("a read_only client's sync: %v", err)
	}
	write := &sidecar.DirectoryCardWrite{PushId: sidecar.NewId(), Path: "q/ab/x/y", Content: []byte("x")}
	if _, err := readOnly.PutCard(t.Context(), write); !errors.Is(err, sidecar.ErrDirectoryReadOnly) {
		t.Errorf("a read_only write: %v", err)
	}
	if err := readOnly.RemoveCard(t.Context(), write); !errors.Is(err, sidecar.ErrDirectoryReadOnly) {
		t.Errorf("a read_only removal: %v", err)
	}
	if counts := world.cards.Counts(); counts.CardWrites != 0 || counts.CardRemovals != 0 {
		t.Errorf("writes reached evs: %+v", counts)
	}
}
