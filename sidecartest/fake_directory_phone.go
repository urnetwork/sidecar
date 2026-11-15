// T4's phone as the team directory's notices reach it (RECORD-M8-01; §11.9, §11.10, §18.7, D-SDK-28), until
// SDK-M8-15's surrogate cells: one phone sidecar's sidecar.DirectoryCards over a FakeDirectoryCards world, with what a
// phone's binding adds beside a sync's calls:
//
//   - leases as evs keys them, one per prefix this phone holds, each lapsing LeaseExpiry after its last renewal on the
//     world's clock (§11.10's renew row): a Lease of a prefix it holds renews it, a release drops that one callback,
//     and the lease goes with its last; Kill drops every callback, as a process's end does, and leaves each lease at
//     evs until it lapses;
//   - wakes: each commit changing a file under a live lease is one hint to this phone, however many of its leases it
//     matches (evs's one hint per client a commit, §11.10's hint row), topic evs:<repo_id> carrying the repo's push
//     sequence, and §18.7 makes the hint one wake, whose payload pushservice builds: the topic's class and that
//     version, naming nothing else (WK4);
//   - §11.9's head reads, sidecar.DirectoryHeadReader: one path's newest version, a prefix's listing, and one entry
//     of a writer's stream at the path its seq names, each from the world at this phone's read scope;
//   - counts of every call by kind, so a test holds a phone to what it read (FS-100).
//
// Safe for concurrent use.

package sidecartest

import (
	"context"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/pushservice"
)

type FakeDirectoryPhoneSettings struct {
	// A lease lapses this long after its last renewal: 7 d (§11.10's renew row).
	LeaseExpiry time.Duration
}

func DefaultFakeDirectoryPhoneSettings() *FakeDirectoryPhoneSettings {
	return &FakeDirectoryPhoneSettings{
		LeaseExpiry: 7 * 24 * time.Hour,
	}
}

// What a phone asked, by kind.
type FakeDirectoryPhoneCounts struct {
	// A sync's calls, which a phone never makes.
	Refs           int
	ReadStreams    int
	ReadStreamLogs int
	ReadCards      int
	// Writes and removals on the cards ref.
	CardWrites   int
	CardRemovals int
	// Leases taken where none stood or one had lapsed, renewed, and released.
	LeasesTaken    int
	LeasesRenewed  int
	LeasesReleased int
	// Head reads.
	NoticeReads int
	Listings    int
	EntryReads  int
}

// One wake §18.7 sent the phone.
type FakeDirectoryWake struct {
	// The payload pushservice builds: mail, team, evs or core, and the topic's version.
	Payload pushservice.WakePayload
	// APNs' body for it, which is all a vendor carries.
	Body []byte
	// On the world's clock.
	At time.Time
}

// One lease the phone holds as evs keeps it.
type FakeDirectoryPhoneLease struct {
	RepoId    sidecar.Id
	Prefix    string
	RenewedAt time.Time
	// Not lapsed at the world's clock now.
	Live bool
	// Callbacks of a live process on it.
	Holders int
}

type fakeDirectoryPhoneLeaseKey struct {
	repoId sidecar.Id
	prefix string
}

type fakeDirectoryPhoneLease struct {
	renewedAt time.Time
	callbacks map[uint64]func(repoId sidecar.Id)
	// the world's lease under it
	release func()
}

// One phone's reach. NewFakeDirectoryPhone makes one.
type FakeDirectoryPhone struct {
	cards     *FakeDirectoryCards
	sidecarId sidecar.Id
	inner     *fakeDirectoryCardsClient
	settings  *FakeDirectoryPhoneSettings

	stateLock    sync.Mutex
	leases       map[fakeDirectoryPhoneLeaseKey]*fakeDirectoryPhoneLease
	nextCallback uint64
	// the push sequence each repo's last wake carried
	wakeSequences map[sidecar.Id]uint64
	wakes         []*FakeDirectoryWake
	counts        FakeDirectoryPhoneCounts
}

var (
	_ sidecar.DirectoryCards      = (*FakeDirectoryPhone)(nil)
	_ sidecar.DirectoryHeadReader = (*FakeDirectoryPhone)(nil)
)

// sidecarId's phone over cards' world; settings may be nil, for the defaults.
func NewFakeDirectoryPhone(cards *FakeDirectoryCards, sidecarId sidecar.Id, settings *FakeDirectoryPhoneSettings) *FakeDirectoryPhone {
	if settings == nil {
		settings = DefaultFakeDirectoryPhoneSettings()
	}
	return &FakeDirectoryPhone{
		cards:         cards,
		sidecarId:     sidecarId,
		inner:         &fakeDirectoryCardsClient{fake: cards, sidecarId: sidecarId},
		settings:      settings,
		leases:        map[fakeDirectoryPhoneLeaseKey]*fakeDirectoryPhoneLease{},
		wakeSequences: map[sidecar.Id]uint64{},
	}
}

// The calls so far.
func (self *FakeDirectoryPhone) Counts() FakeDirectoryPhoneCounts {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.counts
}

// Every wake so far, in order.
func (self *FakeDirectoryPhone) Wakes() []*FakeDirectoryWake {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.wakes)
}

// The leases evs holds for this phone, lapsed ones included until a release drops them, in prefix order.
func (self *FakeDirectoryPhone) Leases() []FakeDirectoryPhoneLease {
	now := self.now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	leases := []FakeDirectoryPhoneLease{}
	for key, lease := range self.leases {
		leases = append(leases, FakeDirectoryPhoneLease{
			RepoId:    key.repoId,
			Prefix:    key.prefix,
			RenewedAt: lease.renewedAt,
			Live:      now.Before(lease.renewedAt.Add(self.settings.LeaseExpiry)),
			Holders:   len(lease.callbacks),
		})
	}
	slices.SortFunc(leases, func(a FakeDirectoryPhoneLease, b FakeDirectoryPhoneLease) int {
		return strings.Compare(a.Prefix, b.Prefix)
	})
	return leases
}

// The phone's process ends: every callback goes, and evs keeps each lease until it lapses, hinting the phone, so
// wakes still come.
func (self *FakeDirectoryPhone) Kill() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, lease := range self.leases {
		lease.callbacks = map[uint64]func(repoId sidecar.Id){}
	}
}

func (self *FakeDirectoryPhone) now() time.Time {
	return self.cards.streams.clock.Now()
}

func (self *FakeDirectoryPhone) count(add func(counts *FakeDirectoryPhoneCounts)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	add(&self.counts)
}

func (self *FakeDirectoryPhone) Refs(ctx context.Context, repoId sidecar.Id, movedAfter uint64) (*sidecar.DirectoryRefListing, error) {
	self.count(func(counts *FakeDirectoryPhoneCounts) { counts.Refs += 1 })
	return self.inner.Refs(ctx, repoId, movedAfter)
}

func (self *FakeDirectoryPhone) ReadStreams(ctx context.Context, repoId sidecar.Id, reads []*sidecar.DirectoryStreamRead) ([]*sidecar.DirectoryStreamVersions, error) {
	self.count(func(counts *FakeDirectoryPhoneCounts) { counts.ReadStreams += 1 })
	return self.inner.ReadStreams(ctx, repoId, reads)
}

func (self *FakeDirectoryPhone) ReadStreamLog(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryStreamVersions, error) {
	self.count(func(counts *FakeDirectoryPhoneCounts) { counts.ReadStreamLogs += 1 })
	return self.inner.ReadStreamLog(ctx, repoId, writerSidecarId, afterVersion)
}

func (self *FakeDirectoryPhone) ReadCards(ctx context.Context, repoId sidecar.Id, afterVersion uint64) (*sidecar.DirectoryCardsChanges, error) {
	self.count(func(counts *FakeDirectoryPhoneCounts) { counts.ReadCards += 1 })
	return self.inner.ReadCards(ctx, repoId, afterVersion)
}

func (self *FakeDirectoryPhone) PutCard(ctx context.Context, repoId sidecar.Id, write *sidecar.DirectoryCardWrite) (uint64, error) {
	self.count(func(counts *FakeDirectoryPhoneCounts) { counts.CardWrites += 1 })
	return self.inner.PutCard(ctx, repoId, write)
}

func (self *FakeDirectoryPhone) RemoveCard(ctx context.Context, repoId sidecar.Id, write *sidecar.DirectoryCardWrite) error {
	self.count(func(counts *FakeDirectoryPhoneCounts) { counts.CardRemovals += 1 })
	return self.inner.RemoveCard(ctx, repoId, write)
}

// Takes or renews the phone's lease on prefix, as one POST /evs/v1/subscriptions does, and adds callback to it.
func (self *FakeDirectoryPhone) Lease(repoId sidecar.Id, prefix string, callback func(repoId sidecar.Id)) (func(), error) {
	if err := self.inner.checkRead(repoId); err != nil {
		return nil, err
	}
	key := fakeDirectoryPhoneLeaseKey{repoId: repoId, prefix: prefix}
	now := self.now()
	held := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		_, held := self.leases[key]
		return held
	}()
	var worldRelease func()
	if !held {
		release, err := self.inner.Lease(repoId, prefix, func(repoId sidecar.Id) { self.hint(key) })
		if err != nil {
			return nil, err
		}
		worldRelease = release
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	lease, held := self.leases[key]
	switch {
	case !held:
		lease = &fakeDirectoryPhoneLease{callbacks: map[uint64]func(repoId sidecar.Id){}, release: worldRelease}
		self.leases[key] = lease
		self.counts.LeasesTaken += 1
		// the lease owns the world's now
		worldRelease = nil
	case now.Before(lease.renewedAt.Add(self.settings.LeaseExpiry)):
		self.counts.LeasesRenewed += 1
	default:
		// lapsed: evs takes it as a new lease
		self.counts.LeasesTaken += 1
	}
	if worldRelease != nil {
		// another call took the lease meanwhile
		defer worldRelease()
	}
	lease.renewedAt = now
	self.nextCallback += 1
	callbackId := self.nextCallback
	lease.callbacks[callbackId] = callback
	return func() { self.releaseCallback(key, callbackId) }, nil
}

// Drops one callback, and the lease with its last, as DELETE /evs/v1/subscriptions does once nothing shares it.
func (self *FakeDirectoryPhone) releaseCallback(key fakeDirectoryPhoneLeaseKey, callbackId uint64) {
	release := func() func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		lease, ok := self.leases[key]
		if !ok {
			return nil
		}
		if _, ok := lease.callbacks[callbackId]; !ok {
			return nil
		}
		delete(lease.callbacks, callbackId)
		if 0 < len(lease.callbacks) {
			return nil
		}
		delete(self.leases, key)
		self.counts.LeasesReleased += 1
		return lease.release
	}()
	if release != nil {
		release()
	}
}

// A commit under the world's lease of key: one hint and one wake a commit while the phone's lease is live, then its
// callbacks, with no lock held.
func (self *FakeDirectoryPhone) hint(key fakeDirectoryPhoneLeaseKey) {
	now := self.now()
	live := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		lease, ok := self.leases[key]
		return ok && now.Before(lease.renewedAt.Add(self.settings.LeaseExpiry))
	}()
	if !live {
		return
	}
	sequence, err := self.cards.streams.PushSequence(key.repoId)
	if err != nil {
		return
	}
	class, wakes := pushservice.WakeTopicClass(sidecar.PushTopicEvs(key.repoId))
	callbacks := func() []func(repoId sidecar.Id) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if wakes && self.wakeSequences[key.repoId] != sequence.Sequence {
			self.wakeSequences[key.repoId] = sequence.Sequence
			payload := pushservice.WakePayload{TopicClass: class, Version: sequence.Sequence}
			self.wakes = append(self.wakes, &FakeDirectoryWake{Payload: payload, Body: pushservice.ApnsWakeBody(&payload), At: now})
		}
		lease, ok := self.leases[key]
		if !ok {
			return nil
		}
		callbacks := []func(repoId sidecar.Id){}
		for _, callbackId := range slices.Sorted(maps.Keys(lease.callbacks)) {
			callbacks = append(callbacks, lease.callbacks[callbackId])
		}
		return callbacks
	}()
	for _, callback := range callbacks {
		callback(key.repoId)
	}
}

// The newest version of path, nil while it holds none or its newest statement removed it.
func (self *FakeDirectoryPhone) ReadCard(ctx context.Context, repoId sidecar.Id, path string) (*sidecar.DirectoryCardFile, error) {
	self.count(func(counts *FakeDirectoryPhoneCounts) { counts.NoticeReads += 1 })
	if err := self.inner.checkRead(repoId); err != nil {
		return nil, err
	}
	self.cards.stateLock.Lock()
	defer self.cards.stateLock.Unlock()
	file, ok := self.cards.repoWithLock(repoId).files[path]
	if !ok || file.Removed {
		return nil, nil
	}
	return fakeDirectoryCardCopy(file), nil
}

// The newest version of each file under prefix, in path order, removed ones left out.
func (self *FakeDirectoryPhone) ListCards(ctx context.Context, repoId sidecar.Id, prefix string) ([]*sidecar.DirectoryCardFile, error) {
	self.count(func(counts *FakeDirectoryPhoneCounts) { counts.Listings += 1 })
	if err := self.inner.checkRead(repoId); err != nil {
		return nil, err
	}
	self.cards.stateLock.Lock()
	defer self.cards.stateLock.Unlock()
	files := []*sidecar.DirectoryCardFile{}
	for path, file := range self.cards.repoWithLock(repoId).files {
		if strings.HasPrefix(path, prefix) && !file.Removed {
			files = append(files, fakeDirectoryCardCopy(file))
		}
	}
	slices.SortFunc(files, func(a *sidecar.DirectoryCardFile, b *sidecar.DirectoryCardFile) int {
		return strings.Compare(a.Path, b.Path)
	})
	return files, nil
}

// The push of writerSidecarId's stream that created the entry at seq's path, with its slot; nil while none did.
func (self *FakeDirectoryPhone) ReadStreamEntry(ctx context.Context, repoId sidecar.Id, writerSidecarId sidecar.Id, seq uint64) (*sidecar.DirectoryStreamVersion, error) {
	self.count(func(counts *FakeDirectoryPhoneCounts) { counts.EntryReads += 1 })
	path, err := sidecar.RecordStreamPath(seq)
	if err != nil {
		return nil, err
	}
	reader := self.cards.streams.For(self.sidecarId)
	versions, err := reader.ReadStream(ctx, repoId, writerSidecarId, 0)
	if err != nil {
		return nil, err
	}
	for _, version := range versions {
		for _, entry := range version.Entries {
			if entry.Path != path {
				continue
			}
			slot, err := reader.ReadSlot(ctx, repoId, version.SlotId)
			if err != nil {
				return nil, err
			}
			return &sidecar.DirectoryStreamVersion{Version: version, Slot: slot}, nil
		}
	}
	return nil, nil
}
