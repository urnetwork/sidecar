//go:build !sidecar_http

// RECORD-M6-13's sync on two evs: sidecartest's FakeDirectoryCards over FakeRecordStreams, and on T2 evsservice's
// engine through sidecar.DirectoryEvsCards (RECORD-M6-28) on record_evs_test.go's world, each with FakeDirectoryAuth
// and FakeRecordAuth as the state and a fake clock: n moved streams read in ceil(n/64) requests, no lease on the cards
// ref, the daily full listing, a moved_after from before a sequence restart answering every ref, ViewCoalesce, more
// and behind followed, a lost read deleting the copy, a wound-back stream alarming and a restart reading nothing again.
// Entries are sealed and signed for real, so each sync's reader verifies them as any log's. Every DirectoryCards call
// any sidecar makes is counted at the seam, alike on both. On T2 a push declares its client's verified pin, so the
// states' pins follow evs's chain (testEvsRecordAuthView, testEvsDirectoryAuthView).

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
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The evs a sync test's directory runs on.
type testDirectoryBackend int

const (
	// sidecartest's FakeDirectoryCards over FakeRecordStreams
	testDirectoryOnFakes testDirectoryBackend = iota
	// evsservice's engine on T2, through DirectoryEvsCards
	testDirectoryOnEvs
)

// The bounds a test's streams are read under, in versions: a stream read's frame before more, the window a pin may lag
// before behind, and a log page. On evs the window is the head's 255 entries, and a frame below 64 is one version a
// read, which a 1 B reply budget gives.
type testDirectoryBounds struct {
	frame   int
	window  int
	logPage int
}

// A 64-version frame, a 4,096-version window and a 1,000-version log page.
func defaultTestDirectoryBounds() *testDirectoryBounds {
	return &testDirectoryBounds{frame: 64, window: 4096, logPage: 1000}
}

// A team network's directory as the sync tests drive it: its evs, the state at each position, and the reading sidecar.
type testDirectoryWorld struct {
	t       *testing.T
	backend testDirectoryBackend
	// the bounds the backend reads under
	bounds *testDirectoryBounds
	// the directory client's clock, and the one pushes are timed by: on the fakes one clock, and on evs the client's
	// own, so its cadence's timers are the only ones on it, beside the evs world's
	clock       *sidecartest.FakeClock
	pushClock   *sidecartest.FakeClock
	directoryId sidecar.Id
	readerId    sidecar.Id
	// the network every card and repo file names
	networkId sidecar.Id

	// testDirectoryOnFakes
	streams *sidecartest.FakeRecordStreams
	cards   *sidecartest.FakeDirectoryCards
	// testDirectoryOnEvs
	evs              *recordEvsWorld
	evsCardsSettings *sidecar.DirectoryEvsCardsSettings

	directoryAuth    *sidecartest.FakeDirectoryAuth
	directoryFixture *sidecartest.FakeDirectoryAuthFixture
	recordAuth       *sidecartest.FakeRecordAuth
	recordFixture    *sidecartest.FakeRecordAuthFixture

	stateLock sync.Mutex
	// every DirectoryCards call made, by kind, and every lease taken
	callCounts  sidecartest.FakeDirectoryCardsCounts
	takenLeases []sidecartest.FakeDirectoryLease
	// on evs, the streams each listing names at a version below their heads, by writer: a server winding them back
	listedAt map[sidecar.Id]uint64
	// on evs, each sidecar's binding
	bindings map[sidecar.Id]*sidecar.DirectoryEvsCards
}

// One writer of the directory: its identity key and its own chain.
type testDirectoryWriter struct {
	world     *testDirectoryWorld
	sidecarId sidecar.Id
	key       ed25519.PrivateKey
	env       *sidecar.RecordSealEnv
	counter   uint64
}

// A directory on sidecartest's fakes, settings nil for the fake's defaults: what every directory test but the sync's
// builds on.
func newTestDirectoryWorld(t *testing.T, settings *sidecartest.FakeDirectoryCardsSettings) *testDirectoryWorld {
	t.Helper()
	if settings == nil {
		settings = sidecartest.DefaultFakeDirectoryCardsSettings()
	}
	world := &testDirectoryWorld{
		t:        t,
		backend:  testDirectoryOnFakes,
		bounds:   &testDirectoryBounds{frame: settings.FrameVersionCount, window: settings.WindowVersionCount, logPage: settings.LogPageCount},
		listedAt: map[sidecar.Id]uint64{},
		bindings: map[sidecar.Id]*sidecar.DirectoryEvsCards{},
	}
	world.clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	world.pushClock = world.clock
	world.streams = sidecartest.NewFakeRecordStreams(world.clock, nil, nil)
	directoryId, err := world.streams.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	world.directoryId = directoryId
	world.cards = sidecartest.NewFakeDirectoryCards(world.streams, settings)
	world.admitReader()
	return world
}

// A directory on backend, its streams read under bounds, nil for the defaults: on evs the window is the head's 255
// entries, and a frame below 64 one version a read.
func newTestDirectoryWorldOn(t *testing.T, backend testDirectoryBackend, bounds *testDirectoryBounds) *testDirectoryWorld {
	t.Helper()
	if bounds == nil {
		bounds = defaultTestDirectoryBounds()
	}
	if backend == testDirectoryOnFakes {
		settings := sidecartest.DefaultFakeDirectoryCardsSettings()
		settings.FrameVersionCount, settings.WindowVersionCount, settings.LogPageCount = bounds.frame, bounds.window, bounds.logPage
		return newTestDirectoryWorld(t, settings)
	}
	world := &testDirectoryWorld{
		t:        t,
		backend:  testDirectoryOnEvs,
		bounds:   &testDirectoryBounds{frame: bounds.frame, window: 255, logPage: bounds.logPage},
		listedAt: map[sidecar.Id]uint64{},
		bindings: map[sidecar.Id]*sidecar.DirectoryEvsCards{},
	}
	world.evs = newRecordEvsWorld(t, func(settings *evsservice.EvsSettings) {
		if bounds.frame < defaultTestDirectoryBounds().frame {
			// evs serves one version a stream at least, whatever its budget
			settings.ReadStreamMaxByteCount = 1
		}
	})
	if bounds.frame < defaultTestDirectoryBounds().frame {
		world.bounds.frame = 1
	}
	world.clock = sidecartest.NewFakeClock(world.evs.clock.Now())
	world.pushClock = world.evs.clock
	setRecordEvsWorldDirectoryLimits(world.evs)
	directoryId, err := newRecordEvsWorldDirectory(world.evs)
	if err != nil {
		t.Fatal(err)
	}
	world.directoryId = directoryId
	world.evsCardsSettings = sidecar.DefaultDirectoryEvsCardsSettings()
	world.evsCardsSettings.LogPageVersionCount = bounds.logPage
	world.admitReader()
	return world
}

// The reading sidecar admitted, a member device with rw on the directory, and the states' first positions.
func (self *testDirectoryWorld) admitReader() {
	self.readerId = sidecar.NewId()
	self.networkId = sidecar.NewId()
	self.directoryAuth = sidecartest.NewFakeDirectoryAuth()
	self.recordAuth = sidecartest.NewFakeRecordAuth()
	self.grant(self.readerId, sidecartest.RecordStreamsScope{Read: true, Write: true})
	memberId := sidecar.NewId()
	directoryId := self.directoryId
	self.directoryFixture = &sidecartest.FakeDirectoryAuthFixture{
		Sidecars: map[sidecar.Id]*sidecartest.FakeDirectorySidecar{self.readerId: {MemberId: &memberId}},
		Repos: map[sidecar.Id]*sidecartest.FakeDirectoryRepo{directoryId: {
			Kind: protocol.RepoKind_REPO_KIND_DIRECTORY, Admins: []sidecartest.FakeDirectoryRepoAdmin{{SidecarId: self.readerId, At: 1}},
		}},
		DirectoryId: &directoryId,
	}
	self.recordFixture = &sidecartest.FakeRecordAuthFixture{
		IdentityKeys: map[sidecar.Id][]byte{},
		Members:      map[sidecar.Id]sidecar.Id{self.readerId: memberId},
		Repos:        map[sidecar.Id]*sidecartest.FakeRecordRepoAuth{directoryId: {Readers: []sidecar.Id{self.readerId}}},
		Logs:         &sidecar.RecordLogIds{Team: true, DirectoryId: &directoryId},
	}
	self.publish()
}

// Appends the fixtures as the next position of each state, timed now: one pin in both, as one ConfigState gives both
// views.
func (self *testDirectoryWorld) publish() {
	self.recordFixture.TimeMillis = self.clock.Now().UnixMilli()
	self.directoryFixture.TimeMillis = self.recordFixture.TimeMillis
	self.recordAuth.Append(self.recordFixture)
	self.directoryAuth.Append(self.directoryFixture)
}

// Sets what sidecarId's token lets it do on the directory.
func (self *testDirectoryWorld) grant(sidecarId sidecar.Id, scope sidecartest.RecordStreamsScope) {
	self.t.Helper()
	var err error
	switch self.backend {
	case testDirectoryOnFakes:
		err = self.streams.Grant(self.directoryId, sidecarId, scope)
	case testDirectoryOnEvs:
		err = self.evs.Grant(self.directoryId, sidecarId, scope)
	}
	if err != nil {
		self.t.Fatal(err)
	}
}

// The pin a writer's push declares: the state's newest, on evs its devices'.
func (self *testDirectoryWorld) pin() *bridge.AuthPin {
	if self.backend == testDirectoryOnEvs {
		return self.evs.Pin()
	}
	return self.recordAuth.Tip().Pin()
}

// The record's state now, as the reader verifies by it.
func (self *testDirectoryWorld) recordView() sidecar.RecordAuthView {
	if self.backend == testDirectoryOnEvs {
		view := self.evs.view()
		return &testEvsRecordAuthView{RecordAuthView: self.recordAuth.Tip(), pin: view.Pin(), evs: view}
	}
	return self.recordAuth.Tip()
}

// The directory's state now.
func (self *testDirectoryWorld) directoryView() sidecar.DirectoryAuthView {
	if self.backend == testDirectoryOnEvs {
		view := self.evs.view()
		return &testEvsDirectoryAuthView{DirectoryAuthView: self.directoryAuth.Tip(), pin: view.Pin(), evs: view}
	}
	return self.directoryAuth.Tip()
}

// What sidecarId reaches of the directory's evs, counted: on evs its one binding.
func (self *testDirectoryWorld) cardsFor(sidecarId sidecar.Id) sidecar.DirectoryCards {
	switch self.backend {
	case testDirectoryOnEvs:
		cards := func() *sidecar.DirectoryEvsCards {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.bindings[sidecarId]
		}()
		if cards == nil {
			cards = self.newBinding(sidecarId)
			self.stateLock.Lock()
			self.bindings[sidecarId] = cards
			self.stateLock.Unlock()
		}
		return &testCountingCards{world: self, sidecarId: sidecarId, inner: cards}
	default:
		// the fake itself, which counts every call and passes on its optional parts
		return self.cards.For(sidecarId)
	}
}

// What sidecarId reaches after a restart, counted: on evs a new binding, holding nothing of the last one's.
func (self *testDirectoryWorld) restartedCardsFor(sidecarId sidecar.Id) sidecar.DirectoryCards {
	if self.backend == testDirectoryOnEvs {
		return &testCountingCards{world: self, sidecarId: sidecarId, inner: self.newBinding(sidecarId)}
	}
	return self.cards.For(sidecarId)
}

// A binding over sidecarId's evs client.
func (self *testDirectoryWorld) newBinding(sidecarId sidecar.Id) *sidecar.DirectoryEvsCards {
	self.evs.For(sidecarId)
	client := func() *sidecar.EvsClient {
		self.evs.stateLock.Lock()
		defer self.evs.stateLock.Unlock()
		return self.evs.clients[sidecarId]
	}()
	cards, err := sidecar.NewDirectoryEvsCards(&sidecar.DirectoryEvsCardsArgs{Client: client, Settings: self.evsCardsSettings})
	if err != nil {
		self.t.Fatal(err)
	}
	return cards
}

// The record's streams as sidecarId reaches them.
func (self *testDirectoryWorld) streamsFor(sidecarId sidecar.Id) sidecar.RecordStreams {
	if self.backend == testDirectoryOnEvs {
		return self.evs.For(sidecarId)
	}
	return self.streams.For(sidecarId)
}

// Restarts the directory's push sequence: on evs, Redis loses the sequence and the head cache, which a site's soft
// state does together.
func (self *testDirectoryWorld) restartSequence() {
	self.t.Helper()
	if self.backend == testDirectoryOnFakes {
		self.streams.RestartSequence(self.directoryId)
		return
	}
	// one key a call: the two families hash to two slots
	for _, key := range []string{evsservice.PushSequenceKey(self.directoryId), evsservice.HeadCacheKey(self.directoryId)} {
		if err := self.evs.host.Redis.Delete(self.t.Context(), []string{key}); err != nil {
			self.t.Fatal(err)
		}
	}
}

// Makes every later listing name writerId's stream at version, whatever its head: a server winding the stream back.
func (self *testDirectoryWorld) windBack(writerId sidecar.Id, version uint64) {
	if self.backend == testDirectoryOnFakes {
		self.cards.ListStreamAt(self.directoryId, writerId, version)
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.listedAt[writerId] = version
}

// The calls so far: the fake's own count, or on evs the seam's.
func (self *testDirectoryWorld) counts() sidecartest.FakeDirectoryCardsCounts {
	if self.backend == testDirectoryOnFakes {
		return self.cards.Counts()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.callCounts
}

// Every lease taken, in order.
func (self *testDirectoryWorld) leases() []sidecartest.FakeDirectoryLease {
	if self.backend == testDirectoryOnFakes {
		return self.cards.Leases()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]sidecartest.FakeDirectoryLease{}, self.takenLeases...)
}

// Counts f's call by kind.
func (self *testDirectoryWorld) count(f func(counts *sidecartest.FakeDirectoryCardsCounts)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	f(&self.callCounts)
}

// evs's DirectoryCards, counted at the seam as the fake counts its own: every call by kind, and each lease taken. It
// passes on the removal cleanup's and the copy's optional parts. A wound-back stream's listing is a server's, so it is
// made here.
type testCountingCards struct {
	world     *testDirectoryWorld
	sidecarId sidecar.Id
	inner     sidecar.DirectoryCards
}

func (self *testCountingCards) Refs(ctx context.Context, repoId sidecar.Id, movedAfter uint64) (*sidecar.DirectoryRefListing, error) {
	self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) {
		if movedAfter == 0 {
			counts.FullListings += 1
		} else {
			counts.MovedListings += 1
		}
	})
	listing, err := self.inner.Refs(ctx, repoId, movedAfter)
	if err != nil {
		return nil, err
	}
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	for writerId, version := range self.world.listedAt {
		listed := false
		for _, ref := range listing.Refs {
			if ref.Kind == sidecar.DirectoryRefStream && ref.WriterSidecarId == writerId {
				ref.Version, listed = version, true
			}
		}
		if !listed {
			listing.Refs = append(listing.Refs, &sidecar.DirectoryRef{
				Kind: sidecar.DirectoryRefStream, WriterSidecarId: writerId, Version: version, Sequence: listing.Sequence,
			})
		}
	}
	return listing, nil
}

func (self *testCountingCards) ReadStreams(ctx context.Context, repoId sidecar.Id, reads []*sidecar.DirectoryStreamRead) ([]*sidecar.DirectoryStreamVersions, error) {
	self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) {
		counts.StreamReads += 1
		counts.StreamsNamed += len(reads)
	})
	return self.inner.ReadStreams(ctx, repoId, reads)
}

func (self *testCountingCards) ReadStreamLog(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryStreamVersions, error) {
	self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) { counts.LogPages += 1 })
	return self.inner.ReadStreamLog(ctx, repoId, writerSidecarId, afterVersion)
}

func (self *testCountingCards) ReadCards(ctx context.Context, repoId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryCardsChanges, error) {
	self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) { counts.CardsReads += 1 })
	return self.inner.ReadCards(ctx, repoId, afterVersion)
}

func (self *testCountingCards) PutCard(ctx context.Context, repoId sidecar.Id, write *sidecar.DirectoryCardWrite) (uint64, error) {
	self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) { counts.CardWrites += 1 })
	return self.inner.PutCard(ctx, repoId, write)
}

func (self *testCountingCards) RemoveCard(ctx context.Context, repoId sidecar.Id, write *sidecar.DirectoryCardWrite) error {
	self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) { counts.CardRemovals += 1 })
	return self.inner.RemoveCard(ctx, repoId, write)
}

func (self *testCountingCards) RemoveCards(ctx context.Context, repoId sidecar.Id, writes []*sidecar.DirectoryCardWrite) error {
	remover, ok := self.inner.(sidecar.DirectoryCardsRemover)
	if !ok {
		return sidecar.ErrDirectoryCleanupUnbound
	}
	self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) {
		counts.RemovalPushes += 1
		counts.CardRemovals += len(writes)
	})
	return remover.RemoveCards(ctx, repoId, writes)
}

func (self *testCountingCards) Lease(repoId sidecar.Id, prefix string, callback func(repoId sidecar.Id)) (func(), error) {
	release, err := self.inner.Lease(repoId, prefix, callback)
	if err != nil {
		return nil, err
	}
	self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) { counts.LeasesTaken += 1 })
	self.world.stateLock.Lock()
	self.world.takenLeases = append(self.world.takenLeases, sidecartest.FakeDirectoryLease{RepoId: repoId, SidecarId: self.sidecarId, Prefix: prefix})
	self.world.stateLock.Unlock()
	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(func() {
			self.world.count(func(counts *sidecartest.FakeDirectoryCardsCounts) { counts.LeasesRelease += 1 })
			release()
		})
	}, nil
}

func (self *testCountingCards) CopyPathsKnown(repoId sidecar.Id) bool {
	copyPaths, ok := self.inner.(sidecar.DirectoryCardsCopyPaths)
	return !ok || copyPaths.CopyPathsKnown(repoId)
}

func (self *testCountingCards) KnowCopyPaths(repoId sidecar.Id, paths []string) {
	if copyPaths, ok := self.inner.(sidecar.DirectoryCardsCopyPaths); ok {
		copyPaths.KnowCopyPaths(repoId, paths)
	}
}

// A record state at a pin of evs's chain: every answer its fixture's tip's, and its pin the evs devices' state's, so
// the reader judges each push's pin on the chain the push declared it on.
type testEvsRecordAuthView struct {
	sidecar.RecordAuthView
	pin *bridge.AuthPin
	evs sidecar.GkmAuthView
}

func (self *testEvsRecordAuthView) Pin() *bridge.AuthPin {
	return self.pin
}

func (self *testEvsRecordAuthView) At(pin *bridge.AuthPin) (sidecar.RecordAuthView, error) {
	switch {
	case self.pin.GetVersion() < pin.GetVersion():
		return nil, sidecar.ErrRecordAuthAhead
	case !self.evs.OnChain(pin):
		return nil, sidecar.ErrRecordAuthOffChain
	}
	return &testEvsRecordAuthView{RecordAuthView: self.RecordAuthView, pin: pin, evs: self.evs}, nil
}

func (self *testEvsRecordAuthView) AtPosition(version uint64) (sidecar.RecordAuthView, error) {
	if self.pin.GetVersion() < version {
		return nil, sidecar.ErrRecordAuthAhead
	}
	return &testEvsRecordAuthView{RecordAuthView: self.RecordAuthView, pin: &bridge.AuthPin{Version: version}, evs: self.evs}, nil
}

// A directory state at a pin of evs's chain, as testEvsRecordAuthView: every answer at a pin its fixture's tip's.
type testEvsDirectoryAuthView struct {
	sidecar.DirectoryAuthView
	pin *bridge.AuthPin
	evs sidecar.GkmAuthView
}

func (self *testEvsDirectoryAuthView) Pin() *bridge.AuthPin {
	return self.pin
}

func (self *testEvsDirectoryAuthView) At(pin *bridge.AuthPin) (sidecar.DirectoryAuthView, error) {
	switch {
	case self.pin.GetVersion() < pin.GetVersion():
		return nil, sidecar.ErrDirectoryAuthAhead
	case !self.evs.OnChain(pin):
		return nil, sidecar.ErrDirectoryAuthOffChain
	}
	return &testEvsDirectoryAuthView{DirectoryAuthView: self.DirectoryAuthView, pin: pin, evs: self.evs}, nil
}

func (self *testEvsDirectoryAuthView) SignerStanding(sidecarId sidecar.Id, pin *bridge.AuthPin) (sidecar.DirectoryStanding, error) {
	return self.DirectoryAuthView.SignerStanding(sidecarId, self.DirectoryAuthView.Pin())
}

func (self *testEvsDirectoryAuthView) DirectoryAdmins(pin *bridge.AuthPin) ([]sidecar.Id, error) {
	return self.DirectoryAuthView.DirectoryAdmins(self.DirectoryAuthView.Pin())
}

func (self *testEvsDirectoryAuthView) EligibleApprovers(request *protocol.DirectoryRequest, requesterSidecarId sidecar.Id, pin *bridge.AuthPin) (*sidecar.DirectoryApprovers, error) {
	return self.DirectoryAuthView.EligibleApprovers(request, requesterSidecarId, self.DirectoryAuthView.Pin())
}

func (self *testEvsDirectoryAuthView) Decides(request *protocol.DirectoryRequest, requesterSidecarId sidecar.Id, deciderSidecarId sidecar.Id, pin *bridge.AuthPin) (bool, error) {
	return self.DirectoryAuthView.Decides(request, requesterSidecarId, deciderSidecarId, self.DirectoryAuthView.Pin())
}

// A new writer, admitted and writing its own stream: on evs it signs entries with its device's identity key.
func (self *testDirectoryWorld) writer() *testDirectoryWriter {
	self.t.Helper()
	writer := &testDirectoryWriter{world: self, sidecarId: sidecar.NewId()}
	self.grant(writer.sidecarId, sidecartest.RecordStreamsScope{Read: true, Write: true})
	switch self.backend {
	case testDirectoryOnEvs:
		writer.key = self.evs.signer(writer.sidecarId).PrivateKey
	default:
		_, key, err := ed25519.GenerateKey(nil)
		if err != nil {
			self.t.Fatal(err)
		}
		writer.key = key
	}
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("writer", "record")
	if err != nil {
		self.t.Fatal(err)
	}
	writer.env = &sidecar.RecordSealEnv{Chain: sidecar.NewRecordChainStore(store, writer.sidecarId), Sign: writer.sign}
	self.recordFixture.IdentityKeys[writer.sidecarId] = writer.key.Public().(ed25519.PublicKey)
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
		pin := self.world.pin()
		sealed, err := sidecar.RecordSeal(self.env, &sidecar.RecordSealArgs{
			LogId:         self.world.directoryId,
			Kind:          sidecar.RecordKindNote,
			Source:        sidecar.RecordSourceAgent,
			TimeMillis:    self.world.pushClock.Now().UnixMilli(),
			Tainted:       true,
			PolicyVersion: pin.GetVersion(),
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
			AuthPin:         pin,
			SlotRows:        []*sidecar.RecordSlotRow{sealed.SlotRow(0)},
		}
		push.Entries = []*sidecar.RecordStreamEntry{{Path: path, Entry: sealed.EntryBytes(&push.SlotId, 0)}}
		if _, err := self.world.streamsFor(self.sidecarId).Append(t.Context(), self.world.directoryId, push); err != nil {
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
		Cards:         self.cardsFor(self.readerId),
		Streams:       func() sidecar.RecordStreams { return self.streamsFor(self.readerId) },
		Auth:          self.directoryView,
		RecordAuth:    self.recordView,
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
		Clock:     self.clock,
		Settings:  sidecar.DefaultSidecarSettings().Directory,
		NetworkId: self.networkId,
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
func testDirectorySyncReadsMovedStreams(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
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
	counts := world.counts()
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
	counts = world.counts()
	if counts.StreamReads != 4 || counts.StreamsNamed != 135 || counts.MovedListings != 1 {
		t.Errorf("5 moved streams: %+v", counts)
	}
	if entries := reader.client.Entries(); len(entries) != 140 {
		t.Errorf("%d entries after the second sync", len(entries))
	}
	// an idle sync reads no stream
	reader.mustSync(t)
	if counts := world.counts(); counts.StreamReads != 4 {
		t.Errorf("an idle sync read streams: %+v", counts)
	}
}

func TestDirectorySyncReadsMovedStreamsSixtyFourToARequest(t *testing.T) {
	testDirectorySyncReadsMovedStreams(t, testDirectoryOnFakes)
}

func TestDirectorySyncReadsMovedStreamsSixtyFourToARequestOnEvs(t *testing.T) {
	testDirectorySyncReadsMovedStreams(t, testDirectoryOnEvs)
}

// Syncs poll the cards ref and never lease it: only a notice prefix or a notice's path takes a lease, and a notice a
// writer puts under the prefix reaches the copy at the next sync.
func testDirectorySyncLeasesNoCardsRef(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
	reader := world.reader(nil)
	writer := world.writer()
	world.publish()
	writer.push(1)
	reader.mustSync(t)
	reader.mustSync(t)
	if leases := world.leases(); len(leases) != 0 {
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
	leases := world.leases()
	if len(leases) != 1 || leases[0].Prefix != prefix {
		t.Fatalf("leases %v", leases)
	}
	// a notice written under the prefix reaches the copy, and nothing more is leased
	noticePath, err := sidecar.DirectoryNoticePath(target, sidecar.NewId())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.cardsFor(writer.sidecarId).PutCard(t.Context(), world.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: noticePath, Content: []byte("a notice"), AuthPin: world.pin(),
	}); err != nil {
		t.Fatal(err)
	}
	reader.mustSync(t)
	cards := reader.client.Cards()
	if len(cards) != 1 || cards[0].Path != noticePath || !bytes.Equal(cards[0].Content, []byte("a notice")) || cards[0].SignerSidecarId != writer.sidecarId {
		t.Errorf("the copy's cards %v", cards)
	}
	if leases := world.leases(); len(leases) != 1 {
		t.Errorf("leases after the notice %v", leases)
	}
}

func TestDirectorySyncLeasesNoCardsRef(t *testing.T) {
	testDirectorySyncLeasesNoCardsRef(t, testDirectoryOnFakes)
}

func TestDirectorySyncLeasesNoCardsRefOnEvs(t *testing.T) {
	testDirectorySyncLeasesNoCardsRef(t, testDirectoryOnEvs)
}

// The first sync of each UTC day lists every ref, with no moved_after; the rest of the day lists only moved ones. A
// push first, since a repo nothing committed to has no push sequence to list moves after.
func testDirectorySyncListsEveryRefDaily(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
	writer := world.writer()
	world.publish()
	writer.push(1)
	world.clock.AdvanceTo(time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC))
	reader := world.reader(nil)
	reader.mustSync(t)
	reader.mustSync(t)
	world.clock.Advance(14 * time.Hour)
	reader.mustSync(t)
	if counts := world.counts(); counts.FullListings != 1 || counts.MovedListings != 2 {
		t.Fatalf("one day: %+v", counts)
	}
	world.clock.Advance(1 * time.Hour)
	reader.mustSync(t)
	reader.mustSync(t)
	if counts := world.counts(); counts.FullListings != 2 || counts.MovedListings != 3 {
		t.Errorf("the next day: %+v", counts)
	}
}

func TestDirectorySyncListsEveryRefDaily(t *testing.T) {
	testDirectorySyncListsEveryRefDaily(t, testDirectoryOnFakes)
}

func TestDirectorySyncListsEveryRefDailyOnEvs(t *testing.T) {
	testDirectorySyncListsEveryRefDaily(t, testDirectoryOnEvs)
}

// A moved_after from before the push sequence's restart answers every ref, and the sync reads only the streams past
// what its copy holds: a commit whose raise the restart lost is not missed.
func testDirectorySyncMovedAfterARestart(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
	writers := []*testDirectoryWriter{world.writer(), world.writer(), world.writer()}
	world.publish()
	for _, writer := range writers {
		writer.push(1)
	}
	reader := world.reader(nil)
	reader.mustSync(t)
	listed, err := world.cardsFor(world.readerId).Refs(t.Context(), world.directoryId, 0)
	if err != nil {
		t.Fatal(err)
	}
	before := world.counts()
	world.restartSequence()
	writers[1].push(1)
	listing, err := world.cardsFor(world.readerId).Refs(t.Context(), world.directoryId, listed.Sequence)
	if err != nil || !listing.All || len(listing.Refs) != 3 {
		t.Fatalf("a moved_after before the restart: %+v, %v", listing, err)
	}
	reader.mustSync(t)
	after := world.counts()
	if after.StreamReads-before.StreamReads != 1 || after.StreamsNamed-before.StreamsNamed != 1 {
		t.Errorf("after the restart the sync read %d requests naming %d streams", after.StreamReads-before.StreamReads, after.StreamsNamed-before.StreamsNamed)
	}
	if entries := reader.client.Entries(); len(entries) != 4 {
		t.Errorf("%d entries", len(entries))
	}
}

func TestDirectorySyncMovedAfterARestartAnswersEveryRef(t *testing.T) {
	testDirectorySyncMovedAfterARestart(t, testDirectoryOnFakes)
}

func TestDirectorySyncMovedAfterARestartAnswersEveryRefOnEvs(t *testing.T) {
	testDirectorySyncMovedAfterARestart(t, testDirectoryOnEvs)
}

// A stream whose pin is older than evs's window answers behind, and the sync pages its log to the head.
func testDirectorySyncPagesBehind(t *testing.T, backend testDirectoryBackend, bounds *testDirectoryBounds) {
	world := newTestDirectoryWorldOn(t, backend, bounds)
	writer := world.writer()
	world.publish()
	pushCount := world.bounds.window + 5
	writer.push(pushCount)
	reader := world.reader(nil)
	reader.mustSync(t)
	logPages := (pushCount + world.bounds.logPage - 1) / world.bounds.logPage
	if counts := world.counts(); counts.StreamReads != 1 || counts.LogPages != logPages {
		t.Errorf("%d versions behind a window of %d in pages of %d: %+v", pushCount, world.bounds.window, world.bounds.logPage, counts)
	}
	if entries := reader.client.Entries(); len(entries) != pushCount {
		t.Errorf("%d entries", len(entries))
	}
	if alarms := reader.alarmReasons(); len(alarms) != 0 {
		t.Errorf("alarms %v", alarms)
	}
}

func TestDirectorySyncPagesBehindThroughTheLog(t *testing.T) {
	testDirectorySyncPagesBehind(t, testDirectoryOnFakes, &testDirectoryBounds{frame: 64, window: 4, logPage: 3})
}

func TestDirectorySyncPagesBehindThroughTheLogOnEvs(t *testing.T) {
	testDirectorySyncPagesBehind(t, testDirectoryOnEvs, &testDirectoryBounds{frame: 64, window: 255, logPage: 100})
}

// A stream past one read's frame answers more, and joins the next request from where it stopped.
func testDirectorySyncFollowsMore(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, &testDirectoryBounds{frame: 4, window: 4096, logPage: 1000})
	writer := world.writer()
	world.publish()
	writer.push(9)
	reader := world.reader(nil)
	reader.mustSync(t)
	requests := (9 + world.bounds.frame - 1) / world.bounds.frame
	if counts := world.counts(); counts.StreamReads != requests || counts.LogPages != 0 {
		t.Errorf("9 versions in frames of %d: %+v", world.bounds.frame, counts)
	}
	if entries := reader.client.Entries(); len(entries) != 9 {
		t.Errorf("%d entries", len(entries))
	}
}

func TestDirectorySyncFollowsMore(t *testing.T) {
	testDirectorySyncFollowsMore(t, testDirectoryOnFakes)
}

func TestDirectorySyncFollowsMoreOnEvs(t *testing.T) {
	testDirectorySyncFollowsMore(t, testDirectoryOnEvs)
}

// Views coalesce over ViewCoalesce on the fake clock: the loop syncs at once, several views within the window cost one
// sync at its end, and with no view the idle interval sets the next.
func testDirectorySyncViewCoalesce(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
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
	reader.client.ViewSync()
	reader.client.ViewSync()
	world.clock.Advance(settings.ViewCoalesce / 2)
	reader.client.ViewSync()
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
	if counts := world.counts(); counts.FullListings+counts.MovedListings != 2 {
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

func TestDirectorySyncViewCoalesce(t *testing.T) {
	testDirectorySyncViewCoalesce(t, testDirectoryOnFakes)
}

func TestDirectorySyncViewCoalesceOnEvs(t *testing.T) {
	testDirectorySyncViewCoalesce(t, testDirectoryOnEvs)
}

// While a harness session is served the loop syncs every SessionSyncInterval.
func testDirectorySyncSessionInterval(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
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

func TestDirectorySyncSessionInterval(t *testing.T) {
	testDirectorySyncSessionInterval(t, testDirectoryOnFakes)
}

func TestDirectorySyncSessionIntervalOnEvs(t *testing.T) {
	testDirectorySyncSessionInterval(t, testDirectoryOnEvs)
}

// A read this sidecar loses deletes its copy, and the client answers so until it reads again: by the state, a revoked
// sidecar; by evs, a refused scope.
func testDirectorySyncLostRead(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
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
	world.grant(world.readerId, sidecartest.RecordStreamsScope{})
	if err := reader.client.Sync(t.Context()); !errors.Is(err, sidecar.ErrDirectoryReadLost) {
		t.Fatalf("a refused read: %v", err)
	}
	if empty, err := sidecar.NewDirectoryStore(reader.store).Empty(); err != nil || !empty {
		t.Errorf("the copy outlived evs's refusal: %v", err)
	}
}

func TestDirectorySyncLostReadDeletesTheStore(t *testing.T) {
	testDirectorySyncLostRead(t, testDirectoryOnFakes)
}

func TestDirectorySyncLostReadDeletesTheStoreOnEvs(t *testing.T) {
	testDirectorySyncLostRead(t, testDirectoryOnEvs)
}

// A stream evs lists below what the copy holds was wound back: the sync alarms chain_fork, reads nothing of it, and
// the copy keeps every entry it verified (I-16).
func testDirectorySyncAlarmsAStreamWoundBack(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
	writer := world.writer()
	world.publish()
	writer.push(3)
	reader := world.reader(nil)
	reader.mustSync(t)
	before := world.counts()
	world.windBack(writer.sidecarId, 1)
	reader.mustSync(t)
	if alarms := reader.alarmReasons(); len(alarms) != 1 || alarms[0] != sidecar.SidecarRecordAlarmChainFork {
		t.Errorf("alarms %v", alarms)
	}
	if after := world.counts(); after.StreamReads != before.StreamReads {
		t.Errorf("a wound-back stream was read: %+v", after)
	}
	if entries := reader.client.Entries(); len(entries) != 3 {
		t.Errorf("%d entries after the wind-back", len(entries))
	}
}

func TestDirectorySyncAlarmsAStreamWoundBack(t *testing.T) {
	testDirectorySyncAlarmsAStreamWoundBack(t, testDirectoryOnFakes)
}

func TestDirectorySyncAlarmsAStreamWoundBackOnEvs(t *testing.T) {
	testDirectorySyncAlarmsAStreamWoundBack(t, testDirectoryOnEvs)
}

// A restart reads nothing again: a new client over the same copy, its evs binding new too, syncs with a moved listing
// and reads no stream, and its reader verifies what the copy holds; a notice the copy holds and a writer then rewrites
// reaches the restarted copy by its path.
func testDirectorySyncRestartKeepsTheCopy(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
	writers := []*testDirectoryWriter{world.writer(), world.writer()}
	world.publish()
	for _, writer := range writers {
		writer.push(2)
	}
	target := &protocol.RequestTarget{RepoId: sidecar.NewId().Bytes()}
	noticePath, err := sidecar.DirectoryNoticePath(target, sidecar.NewId())
	if err != nil {
		t.Fatal(err)
	}
	writerCards := world.cardsFor(writers[0].sidecarId)
	created, err := writerCards.PutCard(t.Context(), world.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: noticePath, Content: []byte("pending"), AuthPin: world.pin(),
	})
	if err != nil {
		t.Fatal(err)
	}
	first := world.reader(nil)
	first.mustSync(t)
	before := world.counts()
	restarted, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  world.readerId,
		Store:      first.store,
		Cards:      world.restartedCardsFor(world.readerId),
		Streams:    func() sidecar.RecordStreams { return world.streamsFor(world.readerId) },
		Auth:       world.directoryView,
		RecordAuth: world.recordView,
		Clock:      world.clock,
		Settings:   sidecar.DefaultSidecarSettings().Directory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	after := world.counts()
	if after.StreamReads != before.StreamReads || after.MovedListings != before.MovedListings+1 {
		t.Errorf("a restart re-read: before %+v after %+v", before, after)
	}
	if entries := restarted.Entries(); len(entries) != 4 {
		t.Errorf("%d entries from the copy", len(entries))
	}
	// a rewrite of a path created before the copy's version: no row of the restarted read names it
	if _, err := writerCards.PutCard(t.Context(), world.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: noticePath, IfVersion: created, Content: []byte("decided"), AuthPin: world.pin(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Sync(t.Context()); err != nil {
		t.Fatal(err)
	}
	cards := restarted.Cards()
	if len(cards) != 1 || cards[0].Path != noticePath || !bytes.Equal(cards[0].Content, []byte("decided")) {
		t.Errorf("the restarted copy's cards %v", cards)
	}
}

func TestDirectorySyncRestartKeepsTheCopy(t *testing.T) {
	testDirectorySyncRestartKeepsTheCopy(t, testDirectoryOnFakes)
}

func TestDirectorySyncRestartKeepsTheCopyOnEvs(t *testing.T) {
	testDirectorySyncRestartKeepsTheCopy(t, testDirectoryOnEvs)
}

// A personal network, or a team whose directory does not exist yet, answers ErrDirectoryNone and writes nothing; a
// read_only client refuses every write.
func testDirectoryClientNoDirectoryAndReadOnly(t *testing.T, backend testDirectoryBackend) {
	world := newTestDirectoryWorldOn(t, backend, nil)
	world.directoryFixture.DirectoryId = nil
	world.publish()
	reader := world.reader(nil)
	if err := reader.client.Sync(t.Context()); !errors.Is(err, sidecar.ErrDirectoryNone) {
		t.Errorf("a sync with no directory: %v", err)
	}
	if _, err := reader.client.PutCard(t.Context(), &sidecar.DirectoryCardWrite{Path: "q/ab/x/y"}); !errors.Is(err, sidecar.ErrDirectoryNone) {
		t.Errorf("a write with no directory: %v", err)
	}
	if counts := world.counts(); counts != (sidecartest.FakeDirectoryCardsCounts{}) {
		t.Errorf("evs was asked %+v", counts)
	}

	directoryId := world.directoryId
	world.directoryFixture.DirectoryId = &directoryId
	world.publish()
	readOnly, err := sidecar.NewDirectoryClient(&sidecar.DirectoryClientArgs{
		SidecarId:  world.readerId,
		Store:      sidecartest.NewFakeStore().Root(),
		Cards:      world.cardsFor(world.readerId),
		Auth:       world.directoryView,
		RecordAuth: world.recordView,
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
	if counts := world.counts(); counts.CardWrites != 0 || counts.CardRemovals != 0 {
		t.Errorf("writes reached evs: %+v", counts)
	}
}

func TestDirectoryClientNoDirectoryAndReadOnly(t *testing.T) {
	testDirectoryClientNoDirectoryAndReadOnly(t, testDirectoryOnFakes)
}

func TestDirectoryClientNoDirectoryAndReadOnlyOnEvs(t *testing.T) {
	testDirectoryClientNoDirectoryAndReadOnly(t, testDirectoryOnEvs)
}
