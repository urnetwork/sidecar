//go:build !ios_extension

// An open phone view of §16.11's team directory. Format 2 files are planned by
// verified metadata, newest first, and opened within the metered allowance. Reads
// of retained announce streams resume by writer and version. Filters run locally
// over verified items and never change what the view fetches. Closing a native
// view drops its separate sealed store.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

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
	// Every listed announcement file and stream has been read and folded.
	Complete bool
	// Why fetching stopped short: DirectoryCoverageWaitingMetered while the metered cap holds it; empty otherwise.
	Waiting string
	// The announcing sidecars fetched whole, and those with files or stream versions left.
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
	files       *directoryFiles
	directoryId Id

	store   *DirectoryStore
	adapter *directoryStreams
	reader  *RecordReader
	fold    *DirectoryFold

	// one Fetch at a time
	fetchLock sync.Mutex

	stateLock    sync.Mutex
	metered      bool
	allowMetered bool
	listed       bool
	erasureMoved bool
	// the push sequence the last listing ended at: the next one's moved_after
	sequence uint64
	// what is left, in fetch order, and the writers fetched whole
	queue []*directoryViewStream
	// Metadata only, newest changed path first. File bytes are opened within budget.
	cardQueue    []*DirectoryCardFile
	cardVersion  uint64
	refreshCards bool
	pendingIds   []Id
	verified     bool
	fetchedIds   []Id
	// bytes and versions read so far, and the most one version has cost
	fetchedByteCount    int64
	meteredByteCount    int64
	streamByteCount     int64
	fetchedVersionCount int64
	maxVersionByteCount int64
	waiting             string
	closed              bool
}

// Opens a view of the directory. Fetch fills its separate store, Close clears it.
func (self *DirectoryClient) View(args *DirectoryViewArgs) (*DirectoryView, error) {
	directoryId, ok := self.DirectoryId()
	if !ok {
		return nil, ErrDirectoryNone
	}
	if args == nil {
		args = &DirectoryViewArgs{Metered: true}
	}
	var sessionStore SidecarStore = newSearchMemoryStore()
	if self.viewStore != nil {
		var err error
		if sessionStore, err = self.openViewStore(); err != nil {
			return nil, err
		}
	}
	copy, err := NewDirectoryClient(&DirectoryClientArgs{
		SidecarId: self.sidecarId, NetworkId: self.networkId, Store: sessionStore, Streams: self.adapter.streams,
		Auth: self.auth, RecordAuth: self.recordAuth, Settings: self.settings, RecordSettings: self.recordSet,
		Clock: self.clock, Alarm: self.alarm, Log: self.log, Redactor: self.redactor, ReadOnly: true,
	})
	if err != nil {
		return nil, err
	}
	copy.store.cardsOnDisk = self.viewStore != nil
	if err := copy.store.Load(directoryId); err != nil {
		return nil, err
	}
	copy.SetCardSettings(self.cardSettings())
	view := &DirectoryView{
		client: self, directoryId: directoryId, store: copy.store, adapter: copy.adapter,
		reader: copy.reader, fold: copy.currentFold(), metered: args.Metered, allowMetered: args.AllowMetered,
	}
	view.files = copy.filesOf(view.fold)
	return view, nil
}

// Opens a sealed scope for one native view. The first view after a restart reclaims interrupted scopes.
func (self *DirectoryClient) openViewStore() (SidecarStore, error) {
	self.viewStoreLock.Lock()
	defer self.viewStoreLock.Unlock()
	if !self.viewStoreReady {
		files, err := self.viewStore.List("")
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			if err := self.viewStore.Remove(file.Name); err != nil {
				return nil, err
			}
		}
		self.viewStoreReady = true
	}
	return self.viewStore.Directory(recordChainIdText(NewId()), "")
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

// What a version is taken to cost now: the mean of those fetched, else Directory.PhoneVersionByteCount.
func (self *DirectoryView) versionByteCountWithLock() int64 {
	if self.fetchedVersionCount == 0 {
		return self.client.settings.PhoneVersionByteCount
	}
	return max(1, self.streamByteCount/self.fetchedVersionCount)
}

// Lists the directory's streams that hold more than the view does, in fetch order: newest first by the push sequence
// their last commit raised, then by writer id. The first listing names every ref, a later one those moved since the
// last. Nothing of a filter or query reaches this.
func (self *DirectoryView) list(ctx context.Context, cards DirectoryCards) error {
	movedAfter := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.listed {
			return 0
		}
		return self.sequence
	}()
	listing, err := cards.Refs(ctx, self.directoryId, movedAfter)
	if err != nil {
		return err
	}
	type listed struct {
		stream   *directoryViewStream
		sequence uint64
	}
	heldVersions := self.store.State().StreamVersions
	streams := []*listed{}
	erasureMoved := false
	var cardsHead uint64
	for _, ref := range listing.Refs {
		switch ref.Kind {
		case DirectoryRefStream:
			if held := heldVersions[ref.WriterSidecarId]; held < ref.Version {
				stream := &directoryViewStream{writerId: ref.WriterSidecarId, pinVersion: held, headVersion: ref.Version}
				streams = append(streams, &listed{stream: stream, sequence: ref.Sequence})
			}
		case DirectoryRefCards:
			if listing.Format >= directoryRepoFormat2 {
				cardsHead = max(cardsHead, ref.Version)
			}
		case DirectoryRefErasure:
			erasureMoved = erasureMoved || 0 < ref.Version
		}
	}
	if err := self.store.NoteFormat(listing.Format); err != nil {
		return err
	}
	if self.cardVersion < cardsHead {
		if err := self.planCards(ctx, cards, cardsHead); err != nil {
			return err
		}
	}
	slices.SortFunc(streams, func(a *listed, b *listed) int {
		return cmp.Or(cmp.Compare(b.sequence, a.sequence), a.stream.writerId.Cmp(b.stream.writerId))
	})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	merged := make([]*directoryViewStream, 0, len(streams)+len(self.queue))
	moved := make(map[Id]bool, len(streams))
	for _, ref := range streams {
		merged = append(merged, ref.stream)
		moved[ref.stream.writerId] = true
	}
	for _, held := range self.queue {
		if !moved[held.writerId] {
			merged = append(merged, held)
		}
	}
	self.queue = merged
	self.erasureMoved = self.erasureMoved || erasureMoved
	self.sequence = listing.Sequence
	self.listed = true
	self.refreshCards = false
	return nil
}

// Reduces verified changes to the newest version of each path before opening any file.
func (self *DirectoryView) planCards(ctx context.Context, cards DirectoryCards, head uint64) error {
	source, ok := cards.(DirectoryViewCards)
	if !ok {
		return fmt.Errorf("%w: the format 2 view needs card metadata", ErrDirectoryCardsUnavailable)
	}
	files := map[string]*DirectoryCardFile{}
	for _, file := range self.cardQueue {
		files[file.Path] = file
	}
	through := self.cardVersion
	for through < head {
		page, err := source.PlanCards(ctx, self.directoryId, through)
		if err != nil {
			return err
		}
		if page == nil || page.ThroughVersion <= through {
			return fmt.Errorf("%w: card metadata stopped at %d of %d", ErrDirectoryCardsUnavailable, through, head)
		}
		for _, file := range page.Files {
			if file == nil || file.PushVersion <= through || file.PushVersion > page.ThroughVersion {
				continue
			}
			_, card := directoryCardPathSidecar(file.Path)
			_, repo := directoryRepoPathRepo(file.Path)
			if !card && !repo {
				continue
			}
			if earlier := files[file.Path]; earlier == nil || earlier.PushVersion < file.PushVersion {
				files[file.Path] = file
			}
		}
		through = page.ThroughVersion
	}
	queue := make([]*DirectoryCardFile, 0, len(files))
	for _, file := range files {
		queue = append(queue, file)
	}
	slices.SortFunc(queue, func(a, b *DirectoryCardFile) int {
		return cmp.Or(cmp.Compare(b.PushVersion, a.PushVersion), cmp.Compare(a.Path, b.Path))
	})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cardQueue, self.cardVersion = queue, through
	return nil
}

// Opens planned files in recency order and leaves the first unaffordable file on the queue.
func (self *DirectoryView) fetchCards(ctx context.Context, cards DirectoryCards) error {
	for len(self.cardQueue) > 0 {
		file := self.cardQueue[0]
		size := int64(min(file.StoredByteCount, uint64(math.MaxInt64)))
		settings := self.files.client.cardSettings()
		limit := settings.RepoFileByteCount
		if _, isCard := directoryCardPathSidecar(file.Path); isCard {
			limit = settings.CardFileByteCount
		}
		// The authenticated length already proves this file exceeds its format cap.
		// Its empty body goes through the normal refusal and alarm without a download.
		overCap := size > int64(settings.StoredByteCount(limit))
		if overCap {
			size = 0
		}
		paused := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			budget, capped := self.budgetWithLock()
			if capped && budget < size {
				self.waiting = DirectoryCoverageWaitingMetered
				return true
			}
			return false
		}()
		if paused {
			return nil
		}
		current := *file
		if !file.Removed && !overCap {
			source, ok := cards.(DirectoryViewCards)
			if !ok {
				return ErrDirectoryCardsUnavailable
			}
			body, err := source.ReadPlannedCard(ctx, self.directoryId, file)
			if err != nil {
				self.stateLock.Lock()
				self.refreshCards = true
				self.stateLock.Unlock()
				return err
			}
			if uint64(len(body)) > file.StoredByteCount {
				return fmt.Errorf("%w: card exceeds its verified size", ErrDirectoryFormatInvalid)
			}
			current.Content = body
		}
		if err := self.store.ApplyCards(&DirectoryCardsChanges{Files: []*DirectoryCardFile{&current}}); err != nil {
			return err
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.cardQueue = self.cardQueue[1:]
			self.fetchedByteCount += size
			if self.metered {
				self.meteredByteCount += size
			}
			id := directoryViewCardWriter(file)
			if !slices.Contains(self.fetchedIds, id) {
				self.fetchedIds = append(self.fetchedIds, id)
			}
		}()
	}
	return nil
}

// The announcing writer a coverage row names, including a card removed by another sidecar.
func directoryViewCardWriter(file *DirectoryCardFile) Id {
	if writer, ok := directoryCardPathSidecar(file.Path); ok {
		return writer
	}
	return file.SignerSidecarId
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
		if len(batch) == DefaultEvsFormatSettings().ReadStreamMaxRefCount {
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
	self.streamByteCount += byteCount
	if self.metered {
		self.meteredByteCount += byteCount
	}
	stream.pinVersion = reached
	return nil
}

// Fetches what the view has left, in its order, until every stream is read to the head it listed or the metered cap
// holds it; then verifies what it holds and folds it. With nothing left it lists what moved since its last listing
// first. A view whose cap held it fetches nothing more until SetMetered or AllowMetered lets it.
func (self *DirectoryView) Fetch(ctx context.Context) (err error) {
	self.fetchLock.Lock()
	defer self.fetchLock.Unlock()
	defer func() {
		code, refused := RecordStreamRefusalCode(err)
		if refused && code == protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
			// The service can know about the loss before the phone's config catches up.
			err = errors.Join(err, self.resetData())
		} else if errors.Is(err, ErrRecordNotReader) {
			// An unbound record view also answers no read. It can verify on the
			// next refresh once the record state is available.
			if state := self.client.recordAuth(); state != nil && state.Pin() != nil {
				err = errors.Join(err, self.resetData())
			}
		}
	}()
	listing, closed := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.waiting = ""
		self.verified = false
		return !self.listed || self.refreshCards || (len(self.queue) == 0 && len(self.cardQueue) == 0), self.closed
	}()
	if closed {
		return ErrDirectoryViewClosed
	}
	auth := self.client.auth()
	directoryId, exists := auth.Directory()
	if !exists || directoryId != self.directoryId {
		self.closeLocked()
		return ErrDirectoryNone
	}
	standing, err := auth.SignerStanding(self.client.sidecarId, auth.Pin())
	if err != nil {
		return err
	}
	if standing == DirectoryStandingUnadmitted || standing == DirectoryStandingRevoked || standing == DirectoryStandingExpired {
		return errors.Join(ErrDirectoryReadLost, self.resetData())
	}
	if self.fold == nil {
		// Clearing the prior view may have been interrupted by a locked store.
		if err := self.resetData(); err != nil {
			return err
		}
	}
	cards := self.client.boundCards()
	if listing {
		if err := self.list(ctx, cards); err != nil {
			return err
		}
	}
	if err := self.fetchCards(ctx, cards); err != nil {
		return err
	}
	for len(self.cardQueue) == 0 {
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
		if len(results) != len(batch) {
			return fmt.Errorf("%w: incomplete directory stream read", ErrDirectoryCardsUnavailable)
		}
		for index, result := range results {
			stream := batch[index]
			if result == nil || result.WriterSidecarId != stream.writerId {
				return fmt.Errorf("%w: the requested directory stream is missing", ErrDirectoryCardsUnavailable)
			}
			before := stream.pinVersion
			if 0 < result.Behind {
				for {
					page, err := cards.ReadStreamLog(ctx, self.directoryId, stream.writerId, stream.pinVersion)
					if err != nil {
						return err
					}
					if page == nil || page.WriterSidecarId != stream.writerId {
						return fmt.Errorf("%w: missing directory log page", ErrDirectoryCardsUnavailable)
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
			if stream.pinVersion <= before {
				return fmt.Errorf("%w: directory stream did not advance", ErrDirectoryCardsUnavailable)
			}
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			queue := []*directoryViewStream{}
			for _, stream := range self.queue {
				if stream.pinVersion < stream.headVersion {
					queue = append(queue, stream)
				} else if !slices.Contains(self.fetchedIds, stream.writerId) {
					self.fetchedIds = append(self.fetchedIds, stream.writerId)
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
	var pending []Id
	held := self.store.filesForFold()
	self.files.stateLock.Lock()
	for _, file := range held {
		if self.files.judged[file.Path] < file.PushVersion {
			id := directoryViewCardWriter(file)
			if !slices.Contains(pending, id) {
				pending = append(pending, id)
			}
		}
	}
	self.files.stateLock.Unlock()
	// RecordReader also withholds streams whose auth pin is ahead of the local
	// state. Check its verified positions without copying the stream history.
	heldStreams := self.store.State().StreamVersions
	self.reader.stateLock.Lock()
	log := self.reader.logs[self.directoryId]
	verifiedStreams := log != nil && log.complete
	if !verifiedStreams && log != nil {
		for id, head := range heldStreams {
			if log.streamVersions[id] < head && !slices.Contains(pending, id) {
				pending = append(pending, id)
			}
		}
	}
	self.reader.stateLock.Unlock()
	self.stateLock.Lock()
	self.pendingIds = pending
	self.verified = len(pending) == 0 && verifiedStreams
	self.stateLock.Unlock()
	// a phone's notice leases learn its member's workers from what the view shows (directory_notice.go)
	self.client.notePhoneView(self)
	return nil
}

// The coverage now.
func (self *DirectoryView) Coverage() *DirectoryCoverage {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	coverage := &DirectoryCoverage{
		Complete:          !self.closed && self.verified && self.listed && len(self.queue) == 0 && len(self.cardQueue) == 0,
		Waiting:           self.waiting,
		FetchedSidecarIds: slices.Clone(self.fetchedIds),
		LeftSidecarIds:    slices.Clone(self.pendingIds),
		FetchedByteCount:  self.fetchedByteCount,
		MeteredByteCount:  self.meteredByteCount,
	}
	for _, file := range self.cardQueue {
		id := directoryViewCardWriter(file)
		if !slices.Contains(coverage.LeftSidecarIds, id) {
			coverage.LeftSidecarIds = append(coverage.LeftSidecarIds, id)
		}
		coverage.LeftByteCount += int64(min(file.StoredByteCount, uint64(math.MaxInt64-coverage.LeftByteCount)))
	}
	perVersion := self.versionByteCountWithLock()
	for _, stream := range self.queue {
		if !slices.Contains(coverage.LeftSidecarIds, stream.writerId) {
			coverage.LeftSidecarIds = append(coverage.LeftSidecarIds, stream.writerId)
		}
		coverage.LeftByteCount += int64(stream.headVersion-stream.pinVersion) * perVersion
	}
	coverage.FetchedSidecarIds = slices.DeleteFunc(coverage.FetchedSidecarIds, func(id Id) bool {
		return slices.Contains(coverage.LeftSidecarIds, id)
	})
	if coverage.Complete {
		coverage.Waiting = ""
	}
	return coverage
}

// The items the view holds that filter keeps, as List orders them, and its coverage: a partial view says so, and
// what is left, however few items it shows.
func (self *DirectoryView) List(filter *DirectoryFilter) *DirectoryViewPage {
	items := []*DirectoryItem{}
	self.stateLock.Lock()
	fold := self.fold
	self.stateLock.Unlock()
	if fold != nil {
		items = directoryFilterItems(fold.View(self.client.auth(), self.client.clock.Now().UnixMilli()), filter)
	}
	return &DirectoryViewPage{Items: items, Coverage: self.Coverage()}
}

// Drops a lost read immediately. The same open subscription can try the current
// heads again when read rights return, under the remainder of its metered allowance.
func (self *DirectoryView) resetData() error {
	session := self.files.client
	self.stateLock.Lock()
	self.fold = nil
	self.listed, self.verified, self.erasureMoved, self.refreshCards = false, false, false, false
	self.sequence, self.cardVersion = 0, 0
	self.queue, self.cardQueue = nil, nil
	self.fetchedIds, self.pendingIds = nil, nil
	self.waiting = ""
	self.stateLock.Unlock()
	if err := self.store.Reset(); err != nil {
		return err
	}
	if err := self.store.Load(self.directoryId); err != nil {
		return err
	}
	session.stateLock.Lock()
	session.fold = nil
	session.stateLock.Unlock()
	session.reader = session.newReader()
	self.reader = session.reader
	self.adapter.setErasureMoved(false)
	fold := session.currentFold()
	self.files = session.filesOf(fold)
	self.stateLock.Lock()
	self.fold = fold
	self.stateLock.Unlock()
	return nil
}

// Closes the view: everything it fetched is dropped, as a phone keeps the directory only while its view is open.
func (self *DirectoryView) Close() {
	self.fetchLock.Lock()
	defer self.fetchLock.Unlock()
	self.closeLocked()
}

func (self *DirectoryView) closeLocked() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		self.fold = nil
		self.cardQueue = nil
		self.queue = nil
		self.pendingIds = nil
		self.fetchedIds = nil
	}()
	if err := self.store.Reset(); err != nil {
		self.client.log.Warningf("[directory]could not clear the closed view: %s", err)
	}
	self.files = nil
	self.reader = nil
}
