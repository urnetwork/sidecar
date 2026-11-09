// §23.5's fake of evs's part of the team directory behind sidecar.DirectoryCards (RECORD-M6-13), over a
// FakeRecordStreams world whose repos and scopes it shares: the directory's streams are that world's, written by the
// record writer's pushes, and this fake adds what §11.9 and §11.10 give the directory beyond them:
//
//   - the moved listing: GET .../refs?moved_after lists the refs whose last commit raised the repo's push sequence past
//     the value; no value, one from before RestartSequence, or a ref whose raise the world lost lists every ref;
//   - the stream read: POST .../read {refs} takes up to 64 streams, each answering at most FrameVersionCount versions
//     before more, standing in for its 4 MiB frame, and behind for a pin more than WindowVersionCount versions back,
//     which GET .../log pages LogPageCount at a time;
//   - the cards ref: one shared file-mode ref per repo, its statements read after a pin CardsPageCount a page, and
//     writes and removals by path CAS at rw, 409 PATH_CONFLICT otherwise, a path's versions never restarting;
//   - leases: any prefix, as evs, which sees no path, takes them; each commit under a leased prefix calls its holder
//     with no lock held; Leases lists every lease ever taken, so a test sees one on the cards ref itself.
//
// Each call is counted by kind, so a test holds a sync to its requests (FS-86). Reads take read, writes rw, by the
// world's scopes. Contents are the caller's plaintext: nothing is sealed or tokenized. Safe for concurrent use.

package sidecartest

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The cards ref's name in the world's push sequence.
const fakeDirectoryCardsRef = "cards"

type FakeDirectoryCardsSettings struct {
	// Versions of one stream a read carries before answering more: its 4 MiB frame.
	FrameVersionCount int
	// Versions back a stream's window reaches: an older pin answers behind.
	WindowVersionCount int
	// Versions a GET .../log page carries (§11.9: at most 1,000 statements).
	LogPageCount int
	// Statements of the cards ref a read carries a page.
	CardsPageCount int
}

func DefaultFakeDirectoryCardsSettings() *FakeDirectoryCardsSettings {
	return &FakeDirectoryCardsSettings{
		FrameVersionCount:  64,
		WindowVersionCount: 4096,
		LogPageCount:       1000,
		CardsPageCount:     1000,
	}
}

// What a fake's callers asked, by kind.
type FakeDirectoryCardsCounts struct {
	// GET .../refs with a moved_after, and with none.
	MovedListings int
	FullListings  int
	// POST .../read {refs} requests, and the streams they named in all.
	StreamReads   int
	StreamsNamed  int
	LogPages      int
	CardsReads    int
	CardWrites    int
	CardRemovals  int
	LeasesTaken   int
	LeasesRelease int
}

// One lease, as a holder took it.
type FakeDirectoryLease struct {
	RepoId    sidecar.Id
	SidecarId sidecar.Id
	Prefix    string
}

// The world's directory parts.
type FakeDirectoryCards struct {
	streams  *FakeRecordStreams
	settings *FakeDirectoryCardsSettings

	stateLock sync.Mutex
	repos     map[sidecar.Id]*fakeDirectoryCardsRepo
	counts    FakeDirectoryCardsCounts
	leases    []FakeDirectoryLease
	nextLease uint64
}

// One repo's cards ref and leases.
type fakeDirectoryCardsRepo struct {
	version    uint64
	files      map[string]*sidecar.DirectoryCardFile
	pathCounts map[string]uint64
	statements []*fakeDirectoryCardsStatement
	leases     map[uint64]*fakeDirectoryCardsLease
}

type fakeDirectoryCardsStatement struct {
	version uint64
	files   []*sidecar.DirectoryCardFile
}

type fakeDirectoryCardsLease struct {
	prefix   string
	callback func(repoId sidecar.Id)
}

// A fake over streams' world; settings may be nil, for the defaults.
func NewFakeDirectoryCards(streams *FakeRecordStreams, settings *FakeDirectoryCardsSettings) *FakeDirectoryCards {
	if settings == nil {
		settings = DefaultFakeDirectoryCardsSettings()
	}
	return &FakeDirectoryCards{streams: streams, settings: settings, repos: map[sidecar.Id]*fakeDirectoryCardsRepo{}}
}

// What sidecarId reaches, carrying its scope in the world.
func (self *FakeDirectoryCards) For(sidecarId sidecar.Id) sidecar.DirectoryCards {
	return &fakeDirectoryCardsClient{fake: self, sidecarId: sidecarId}
}

// The calls so far.
func (self *FakeDirectoryCards) Counts() FakeDirectoryCardsCounts {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.counts
}

// Every lease taken, in order.
func (self *FakeDirectoryCards) Leases() []FakeDirectoryLease {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.leases)
}

// The repo's cards ref, made on first use.
func (self *FakeDirectoryCards) repoWithLock(repoId sidecar.Id) *fakeDirectoryCardsRepo {
	repo, ok := self.repos[repoId]
	if !ok {
		repo = &fakeDirectoryCardsRepo{
			files:      map[string]*sidecar.DirectoryCardFile{},
			pathCounts: map[string]uint64{},
			leases:     map[uint64]*fakeDirectoryCardsLease{},
		}
		self.repos[repoId] = repo
	}
	return repo
}

// One sidecar's reach.
type fakeDirectoryCardsClient struct {
	fake      *FakeDirectoryCards
	sidecarId sidecar.Id
}

// The world's scope of this sidecar on the repo, NOT_FOUND for a repo the world does not hold.
func (self *fakeDirectoryCardsClient) scope(repoId sidecar.Id) (RecordStreamsScope, error) {
	world := self.fake.streams
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	repo, ok := world.repos[repoId]
	if !ok {
		return RecordStreamsScope{}, fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
	}
	return repo.scopes[self.sidecarId], nil
}

// The reads every read call checks.
func (self *fakeDirectoryCardsClient) checkRead(repoId sidecar.Id) error {
	scope, err := self.scope(repoId)
	if err != nil {
		return err
	}
	if !scope.Read {
		return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	}
	return nil
}

func (self *fakeDirectoryCardsClient) Refs(ctx context.Context, repoId sidecar.Id, movedAfter uint64) (*sidecar.DirectoryRefListing, error) {
	func() {
		self.fake.stateLock.Lock()
		defer self.fake.stateLock.Unlock()
		if movedAfter == 0 {
			self.fake.counts.FullListings += 1
		} else {
			self.fake.counts.MovedListings += 1
		}
	}()
	if err := self.checkRead(repoId); err != nil {
		return nil, err
	}
	sequence, err := self.fake.streams.PushSequence(repoId)
	if err != nil {
		return nil, err
	}
	reader := self.fake.streams.For(self.sidecarId)
	heads, err := reader.Streams(ctx, repoId)
	if err != nil {
		return nil, err
	}
	erasures, err := reader.ReadErasures(ctx, repoId, 0)
	if err != nil {
		return nil, err
	}
	refs := []*sidecar.DirectoryRef{}
	for _, head := range heads {
		refs = append(refs, &sidecar.DirectoryRef{
			Kind: sidecar.DirectoryRefStream, WriterSidecarId: head.SidecarId, Version: head.Version,
			Sequence: sequence.Refs[FakeRecordRef{Kind: FakeRecordRefStream, SidecarId: head.SidecarId}],
		})
	}
	if 0 < len(erasures) {
		refs = append(refs, &sidecar.DirectoryRef{
			Kind: sidecar.DirectoryRefErasure, Version: erasures[len(erasures)-1].Version,
			Sequence: sequence.Refs[FakeRecordRef{Kind: FakeRecordRefErasure}],
		})
	}
	cardsVersion := func() uint64 {
		self.fake.stateLock.Lock()
		defer self.fake.stateLock.Unlock()
		return self.fake.repoWithLock(repoId).version
	}()
	if 0 < cardsVersion {
		refs = append(refs, &sidecar.DirectoryRef{
			Kind: sidecar.DirectoryRefCards, Version: cardsVersion,
			Sequence: sequence.Refs[FakeRecordRef{Kind: FakeRecordRefNamed, Name: fakeDirectoryCardsRef}],
		})
	}
	all := movedAfter == 0 || movedAfter < sequence.RestartedAt
	for _, ref := range refs {
		// a ref the head cache lost answers every ref
		all = all || ref.Sequence == 0
	}
	listing := &sidecar.DirectoryRefListing{Sequence: sequence.Sequence, All: all}
	for _, ref := range refs {
		if all || movedAfter < ref.Sequence {
			listing.Refs = append(listing.Refs, ref)
		}
	}
	return listing, nil
}

// One stream's versions after pin with their slots, at most limit; true when more remain.
func (self *fakeDirectoryCardsClient) streamVersions(ctx context.Context, repoId sidecar.Id, writerId sidecar.Id, pin uint64, limit int) ([]*sidecar.DirectoryStreamVersion, uint64, bool, error) {
	reader := self.fake.streams.For(self.sidecarId)
	versions, err := reader.ReadStream(ctx, repoId, writerId, pin)
	if err != nil {
		return nil, 0, false, err
	}
	head := pin
	if 0 < len(versions) {
		head = versions[len(versions)-1].Version
	}
	more := limit < len(versions)
	if more {
		versions = versions[:limit]
	}
	answer := []*sidecar.DirectoryStreamVersion{}
	for _, version := range versions {
		slot, err := reader.ReadSlot(ctx, repoId, version.SlotId)
		if err != nil {
			return nil, 0, false, err
		}
		answer = append(answer, &sidecar.DirectoryStreamVersion{Version: version, Slot: slot})
	}
	return answer, head, more, nil
}

func (self *fakeDirectoryCardsClient) ReadStreams(ctx context.Context, repoId sidecar.Id, reads []*sidecar.DirectoryStreamRead) ([]*sidecar.DirectoryStreamVersions, error) {
	func() {
		self.fake.stateLock.Lock()
		defer self.fake.stateLock.Unlock()
		self.fake.counts.StreamReads += 1
		self.fake.counts.StreamsNamed += len(reads)
	}()
	if len(reads) == 0 || sidecar.DirectoryStreamReadCount < len(reads) {
		return nil, fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	}
	if err := self.checkRead(repoId); err != nil {
		return nil, err
	}
	results := []*sidecar.DirectoryStreamVersions{}
	for _, read := range reads {
		versions, head, more, err := self.streamVersions(ctx, repoId, read.WriterSidecarId, read.PinVersion, self.fake.settings.FrameVersionCount)
		if err != nil {
			return nil, err
		}
		result := &sidecar.DirectoryStreamVersions{WriterSidecarId: read.WriterSidecarId, HeadVersion: head}
		if uint64(self.fake.settings.WindowVersionCount) < head-read.PinVersion {
			result.Behind = read.PinVersion + 1
		} else {
			result.Versions, result.More = versions, more
		}
		results = append(results, result)
	}
	return results, nil
}

func (self *fakeDirectoryCardsClient) ReadStreamLog(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryStreamVersions, error) {
	func() {
		self.fake.stateLock.Lock()
		defer self.fake.stateLock.Unlock()
		self.fake.counts.LogPages += 1
	}()
	if err := self.checkRead(repoId); err != nil {
		return nil, err
	}
	versions, head, more, err := self.streamVersions(ctx, repoId, writerSidecarId, afterVersion, self.fake.settings.LogPageCount)
	if err != nil {
		return nil, err
	}
	return &sidecar.DirectoryStreamVersions{WriterSidecarId: writerSidecarId, HeadVersion: head, Versions: versions, More: more}, nil
}

// A file's copy.
func fakeDirectoryCardCopy(file *sidecar.DirectoryCardFile) *sidecar.DirectoryCardFile {
	copied := *file
	copied.Content = bytes.Clone(file.Content)
	copied.AuthPin = fakeRecordClonePin(file.AuthPin)
	return &copied
}

func (self *fakeDirectoryCardsClient) ReadCards(ctx context.Context, repoId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryCardsChanges, error) {
	func() {
		self.fake.stateLock.Lock()
		defer self.fake.stateLock.Unlock()
		self.fake.counts.CardsReads += 1
	}()
	if err := self.checkRead(repoId); err != nil {
		return nil, err
	}
	self.fake.stateLock.Lock()
	defer self.fake.stateLock.Unlock()
	repo := self.fake.repoWithLock(repoId)
	changes := &sidecar.DirectoryCardsChanges{HeadVersion: repo.version, ThroughVersion: afterVersion}
	taken := 0
	for _, statement := range repo.statements {
		if statement.version <= afterVersion {
			continue
		}
		if taken == self.fake.settings.CardsPageCount {
			changes.More = true
			break
		}
		for _, file := range statement.files {
			changes.Files = append(changes.Files, fakeDirectoryCardCopy(file))
		}
		changes.ThroughVersion = statement.version
		taken += 1
	}
	return changes, nil
}

// One path CAS commit on the cards ref, its leases called once the lock is gone.
func (self *fakeDirectoryCardsClient) commitCard(repoId sidecar.Id, write *sidecar.DirectoryCardWrite, removal bool) (uint64, error) {
	scope, err := self.scope(repoId)
	if err != nil {
		return 0, err
	}
	if !scope.Write {
		return 0, fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
	}
	if write == nil || write.Path == "" || (!removal && write.Content == nil) {
		return 0, fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
	}
	var pathVersion uint64
	var callbacks []func(repoId sidecar.Id)
	err = func() error {
		self.fake.stateLock.Lock()
		defer self.fake.stateLock.Unlock()
		repo := self.fake.repoWithLock(repoId)
		current := uint64(0)
		if file, ok := repo.files[write.Path]; ok && !file.Removed {
			current = file.Version
		}
		if current != write.IfVersion || (removal && current == 0) {
			return fakeRecordReadRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)
		}
		repo.version += 1
		repo.pathCounts[write.Path] += 1
		pathVersion = repo.pathCounts[write.Path]
		file := &sidecar.DirectoryCardFile{
			Path: write.Path, Version: pathVersion, Removed: removal, Content: bytes.Clone(write.Content),
			PushVersion: repo.version, SignerSidecarId: self.sidecarId, AuthPin: fakeRecordClonePin(write.AuthPin),
			TimeMillis: self.fake.streams.clock.Now().UnixMilli(),
		}
		repo.files[write.Path] = file
		repo.statements = append(repo.statements, &fakeDirectoryCardsStatement{version: repo.version, files: []*sidecar.DirectoryCardFile{fakeDirectoryCardCopy(file)}})
		if removal {
			self.fake.counts.CardRemovals += 1
		} else {
			self.fake.counts.CardWrites += 1
		}
		for _, lease := range repo.leases {
			if strings.HasPrefix(write.Path, lease.prefix) {
				callbacks = append(callbacks, lease.callback)
			}
		}
		return nil
	}()
	if err != nil {
		return 0, err
	}
	self.fake.streams.RaiseSequence(repoId, fakeDirectoryCardsRef)
	for _, callback := range callbacks {
		callback(repoId)
	}
	return pathVersion, nil
}

func (self *fakeDirectoryCardsClient) PutCard(ctx context.Context, repoId sidecar.Id, write *sidecar.DirectoryCardWrite) (uint64, error) {
	return self.commitCard(repoId, write, false)
}

func (self *fakeDirectoryCardsClient) RemoveCard(ctx context.Context, repoId sidecar.Id, write *sidecar.DirectoryCardWrite) error {
	_, err := self.commitCard(repoId, write, true)
	return err
}

func (self *fakeDirectoryCardsClient) Lease(repoId sidecar.Id, prefix string, callback func(repoId sidecar.Id)) (func(), error) {
	if err := self.checkRead(repoId); err != nil {
		return nil, err
	}
	self.fake.stateLock.Lock()
	defer self.fake.stateLock.Unlock()
	repo := self.fake.repoWithLock(repoId)
	self.fake.nextLease += 1
	leaseId := self.fake.nextLease
	repo.leases[leaseId] = &fakeDirectoryCardsLease{prefix: prefix, callback: callback}
	self.fake.leases = append(self.fake.leases, FakeDirectoryLease{RepoId: repoId, SidecarId: self.sidecarId, Prefix: prefix})
	self.fake.counts.LeasesTaken += 1
	return func() {
		self.fake.stateLock.Lock()
		defer self.fake.stateLock.Unlock()
		if _, ok := repo.leases[leaseId]; ok {
			delete(repo.leases, leaseId)
			self.fake.counts.LeasesRelease += 1
		}
	}, nil
}
