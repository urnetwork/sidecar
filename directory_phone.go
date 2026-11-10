// §16.11's phones row in M6's form (RECORD-M6-27): a phone keeps the directory's current announcements only while a
// view is open, in memory, and fetches them through a DirectoryView apart from any sync, up to
// Directory.PhoneMeteredByteCount a metered session. It sits in the root, not the sdk, because FS-86's M6 case runs a
// cold phone before any app host exists at M8; SDK-M6-03's SidecarDirectory.List wraps it.
//
//	order      the announcing sidecars' streams newest first, by the push sequence their last commit raised, then by
//	           id: an order no filter or query changes, since a view takes neither until it lists (I-19), so every
//	           filter at one moment asks evs the same reads
//	fetch      each stream whole from its first version, 64 to a request (§11.9), following more and paging the log for
//	           behind, each read kept in the view's memory store before the next; the reader verifies them as a
//	           sync's does, and the fold shows them as List does
//	metered    on a metered link at most PhoneMeteredByteCount of reads a session: the first request reads the newest
//	           stream alone, so a version's cost is measured before any is guessed, and each later one is planned from
//	           its streams' versions left at the costliest version read so far; fetching stops at a stream the rest of
//	           the cap would not hold, so the view reports partial coverage: the announcing sidecars fetched and those
//	           left, the bytes left, and waiting=metered (§18.4)
//	continue   on an unmetered link (SetMetered(false)) or once the person allows the metered bytes (AllowMetered),
//	           Fetch goes on from where it stopped; a stream read in part resumes at its next version, so nothing is
//	           read twice
//	never      a partial view is never shown as complete or as empty: its coverage says what is left; a phone stays off
//	           the follow, leasing nothing, and keeps no directory buckets (D-MCP-31, D-SDK-21)
//
// At M6 evs's listing names each stream's versions and not its bytes, so the cap holds to what was read and the plan
// to an estimate: a request can pass the cap by what its streams cost above the costliest version read before it, and
// the first by its one stream's frame. The bytes left are the versions left at the mean a fetched version cost, or,
// before any fetch, an entry and its push statement as §16.11's sizes row prices them. From format 2 the cards ref's
// statements name each card's size.
//
// Safe for concurrent use: one Fetch at a time, and List any time. Close drops everything the view holds.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
)

// What a version is taken to cost before a view has fetched one: an entry, about 1.5 KiB by Padmé, and its push
// statement, about 0.8 KiB (§16.11's sizes row).
const directoryPhoneVersionByteCount = 1536 + 800

// DirectoryCoverage.Waiting while the metered cap holds a view (§18.4's waiting=metered).
const DirectoryCoverageWaitingMetered = "metered"

// The view is closed: it holds and fetches nothing.
var ErrDirectoryViewClosed = errors.New("directory view closed")

// The link a view fetches over and the person's allowance, which the host reports (§18.7's conditions).
type DirectoryViewArgs struct {
	// A condition the host has not reported counts as metered (§18.4's conditions row).
	Metered bool
	// The person allowed this view's metered bytes (the filter's AllowMetered).
	AllowMetered bool
}

// How much of the directory a view holds.
type DirectoryCoverage struct {
	// Every announcing sidecar's stream is fetched to the head the view listed.
	Complete bool
	// Why fetching stopped short: DirectoryCoverageWaitingMetered while the metered cap holds it; empty otherwise.
	Waiting string
	// The announcing sidecars whose streams were fetched whole, and those left, in fetch order.
	FetchedSidecarIds []Id
	LeftSidecarIds    []Id
	// The bytes the view fetched, those of them on a metered link, and an estimate of the bytes left.
	FetchedByteCount int64
	MeteredByteCount int64
	LeftByteCount    int64
}

// One page of a view: its items now, and its coverage.
type DirectoryViewPage struct {
	Items    []*DirectoryItem
	Coverage *DirectoryCoverage
}

// One stream a view has still to fetch: its writer, the version the view holds and the head it listed.
type directoryViewStream struct {
	writerId    Id
	pinVersion  uint64
	headVersion uint64
}

// One open view of a phone's.
type DirectoryView struct {
	client      *DirectoryClient
	directoryId Id
	memory      *searchMemoryStore
	store       *DirectoryStore
	adapter     *directoryStreams
	reader      *RecordReader
	fold        *DirectoryFold

	// one Fetch at a time
	fetchLock sync.Mutex

	stateLock    sync.Mutex
	metered      bool
	allowMetered bool
	listed       bool
	erasureMoved bool
	// what is left, in fetch order, and the writers fetched whole
	queue      []*directoryViewStream
	fetchedIds []Id
	// bytes and versions read so far, and the most one version has cost
	fetchedByteCount    int64
	meteredByteCount    int64
	fetchedVersionCount int64
	maxVersionByteCount int64
	waiting             string
	closed              bool
}

// Opens a view of the directory, which fetches nothing until its first Fetch and holds what it fetches in memory
// alone until Close. ErrDirectoryNone without a directory.
func (self *DirectoryClient) View(args *DirectoryViewArgs) (*DirectoryView, error) {
	directoryId, ok := self.DirectoryId()
	if !ok {
		return nil, ErrDirectoryNone
	}
	if args == nil {
		args = &DirectoryViewArgs{Metered: true}
	}
	memory := newSearchMemoryStore()
	store := NewDirectoryStore(memory)
	if err := store.Load(directoryId); err != nil {
		return nil, err
	}
	adapter := &directoryStreams{store: store, streams: self.adapter.streams}
	view := &DirectoryView{
		client:       self,
		directoryId:  directoryId,
		memory:       memory,
		store:        store,
		adapter:      adapter,
		fold:         NewDirectoryFold(directoryId, self.alarm),
		metered:      args.Metered,
		allowMetered: args.AllowMetered,
	}
	view.reader = NewRecordReader(&RecordReaderArgs{
		SidecarId:        self.sidecarId,
		Store:            memory,
		Streams:          func() RecordStreams { return adapter },
		Auth:             self.recordAuth,
		Alarm:            self.alarm,
		Clock:            self.clock,
		Settings:         self.recordSet,
		Log:              self.log,
		UnretainedAtHead: true,
	})
	return view, nil
}

// The link changed: metered or not.
func (self *DirectoryView) SetMetered(metered bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.metered = metered
}

// The person allowed this view's metered bytes: the cap no longer holds it.
func (self *DirectoryView) AllowMetered() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.allowMetered = true
}

// The bytes the cap still allows, and whether one holds the view now.
func (self *DirectoryView) budgetWithLock() (int64, bool) {
	if !self.metered || self.allowMetered {
		return 0, false
	}
	return max(0, self.client.settings.PhoneMeteredByteCount-self.meteredByteCount), true
}

// What a version is taken to cost now: the mean of those fetched, else directoryPhoneVersionByteCount.
func (self *DirectoryView) versionByteCountWithLock() int64 {
	if self.fetchedVersionCount == 0 {
		return directoryPhoneVersionByteCount
	}
	return max(1, self.fetchedByteCount/self.fetchedVersionCount)
}

// Lists the directory's streams once, in fetch order: newest first by the push sequence their last commit raised, then
// by writer id. Nothing of a filter or query reaches this.
func (self *DirectoryView) list(ctx context.Context, cards DirectoryCards) error {
	listing, err := cards.Refs(ctx, self.directoryId, 0)
	if err != nil {
		return err
	}
	type listed struct {
		stream   *directoryViewStream
		sequence uint64
	}
	streams := []*listed{}
	erasureMoved := false
	for _, ref := range listing.Refs {
		switch ref.Kind {
		case DirectoryRefStream:
			if 0 < ref.Version {
				streams = append(streams, &listed{stream: &directoryViewStream{writerId: ref.WriterSidecarId, headVersion: ref.Version}, sequence: ref.Sequence})
			}
		case DirectoryRefErasure:
			erasureMoved = 0 < ref.Version
		}
	}
	slices.SortFunc(streams, func(a *listed, b *listed) int {
		return cmp.Or(cmp.Compare(b.sequence, a.sequence), a.stream.writerId.Cmp(b.stream.writerId))
	})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, stream := range streams {
		self.queue = append(self.queue, stream.stream)
	}
	self.erasureMoved = erasureMoved
	self.listed = true
	return nil
}

// The next request's streams from the queue's front: under the cap the newest alone until a version's cost is
// measured, then at most 64 whose versions left the cap still holds at the costliest version read; none, with
// waiting=metered, when the cap holds the first.
func (self *DirectoryView) planWithLock() []*directoryViewStream {
	if len(self.queue) == 0 {
		return nil
	}
	budget, capped := self.budgetWithLock()
	if capped && self.maxVersionByteCount == 0 {
		if budget <= 0 {
			self.waiting = DirectoryCoverageWaitingMetered
			return nil
		}
		return self.queue[:1]
	}
	batch := []*directoryViewStream{}
	estimate := int64(0)
	for _, stream := range self.queue {
		if len(batch) == DirectoryStreamReadCount {
			break
		}
		cost := int64(stream.headVersion-stream.pinVersion) * self.maxVersionByteCount
		if capped && budget < estimate+cost {
			break
		}
		batch = append(batch, stream)
		estimate += cost
	}
	if len(batch) == 0 {
		self.waiting = DirectoryCoverageWaitingMetered
	}
	return batch
}

// The bytes a stream's part of a read carried: the binding's count, else its entries' and slots' own.
func directoryStreamByteCount(result *DirectoryStreamVersions) int64 {
	if 0 < result.ByteCount {
		return result.ByteCount
	}
	byteCount := int64(0)
	for _, version := range result.Versions {
		if version == nil || version.Version == nil {
			continue
		}
		for _, entry := range version.Version.Entries {
			byteCount += int64(len(entry.Entry))
		}
		if version.Slot != nil {
			for _, row := range version.Slot.Rows {
				byteCount += int64(len(row.Row))
			}
		}
	}
	return byteCount
}

// Keeps one stream's read and counts it: its versions in the store, its bytes and versions, and where it now stands.
func (self *DirectoryView) keep(stream *directoryViewStream, result *DirectoryStreamVersions) error {
	if err := self.store.AppendStream(stream.writerId, result.Versions); err != nil {
		return err
	}
	reached := self.store.State().StreamVersions[stream.writerId]
	byteCount := directoryStreamByteCount(result)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if versionCount := int64(reached - stream.pinVersion); 0 < versionCount {
		self.fetchedVersionCount += versionCount
		self.maxVersionByteCount = max(self.maxVersionByteCount, (byteCount+versionCount-1)/versionCount)
	}
	self.fetchedByteCount += byteCount
	if self.metered {
		self.meteredByteCount += byteCount
	}
	stream.pinVersion = reached
	return nil
}

// Fetches what the view has left, in its order, until every stream is read to the head it listed or the metered cap
// holds it; then verifies what it holds and folds it. A view whose cap held it fetches nothing more until SetMetered
// or AllowMetered lets it.
func (self *DirectoryView) Fetch(ctx context.Context) error {
	self.fetchLock.Lock()
	defer self.fetchLock.Unlock()
	listed, closed := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.waiting = ""
		return self.listed, self.closed
	}()
	if closed {
		return ErrDirectoryViewClosed
	}
	cards := self.client.boundCards()
	if !listed {
		if err := self.list(ctx, cards); err != nil {
			return err
		}
	}
	for {
		batch := func() []*directoryViewStream {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return slices.Clone(self.planWithLock())
		}()
		if len(batch) == 0 {
			break
		}
		reads := make([]*DirectoryStreamRead, 0, len(batch))
		for _, stream := range batch {
			reads = append(reads, &DirectoryStreamRead{WriterSidecarId: stream.writerId, PinVersion: stream.pinVersion})
		}
		results, err := cards.ReadStreams(ctx, self.directoryId, reads)
		if err != nil {
			return err
		}
		for index, result := range results {
			if result == nil || len(batch) <= index || result.WriterSidecarId != batch[index].writerId {
				continue
			}
			stream := batch[index]
			if 0 < result.Behind {
				for {
					page, err := cards.ReadStreamLog(ctx, self.directoryId, stream.writerId, stream.pinVersion)
					if err != nil {
						return err
					}
					held := stream.pinVersion
					if err := self.keep(stream, page); err != nil {
						return err
					}
					if !page.More || stream.pinVersion <= held || stream.headVersion <= stream.pinVersion {
						break
					}
				}
			} else if err := self.keep(stream, result); err != nil {
				return err
			}
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			queue := []*directoryViewStream{}
			for _, stream := range self.queue {
				if stream.headVersion <= stream.pinVersion {
					self.fetchedIds = append(self.fetchedIds, stream.writerId)
				} else {
					queue = append(queue, stream)
				}
			}
			self.queue = queue
		}()
	}
	erasureMoved := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.erasureMoved
	}()
	self.adapter.setErasureMoved(erasureMoved)
	if err := self.reader.Sync(ctx, self.directoryId); err != nil {
		return err
	}
	self.fold.Update(self.reader.Entries(self.directoryId))
	return nil
}

// The coverage now.
func (self *DirectoryView) Coverage() *DirectoryCoverage {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	coverage := &DirectoryCoverage{
		Complete:          self.listed && len(self.queue) == 0,
		Waiting:           self.waiting,
		FetchedSidecarIds: slices.Clone(self.fetchedIds),
		LeftSidecarIds:    []Id{},
		FetchedByteCount:  self.fetchedByteCount,
		MeteredByteCount:  self.meteredByteCount,
	}
	perVersion := self.versionByteCountWithLock()
	for _, stream := range self.queue {
		coverage.LeftSidecarIds = append(coverage.LeftSidecarIds, stream.writerId)
		coverage.LeftByteCount += int64(stream.headVersion-stream.pinVersion) * perVersion
	}
	if coverage.Complete {
		coverage.Waiting = ""
	}
	return coverage
}

// The items the view holds that filter keeps, as List orders them, and its coverage: a partial view says so, and
// what is left, however few items it shows.
func (self *DirectoryView) List(filter *DirectoryFilter) *DirectoryViewPage {
	items := []*DirectoryItem{}
	closed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.closed
	}()
	if !closed {
		items = directoryFilterItems(self.fold.View(self.client.auth(), self.client.clock.Now().UnixMilli()), filter)
	}
	return &DirectoryViewPage{Items: items, Coverage: self.Coverage()}
}

// Closes the view: everything it fetched is dropped, as a phone keeps the directory only while its view is open.
func (self *DirectoryView) Close() {
	self.fetchLock.Lock()
	defer self.fetchLock.Unlock()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		self.queue = nil
	}()
	self.memory.clear()
	self.fold.Update(nil)
}
