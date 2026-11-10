// Folds (§11.7's fold, stale, when, horizon, lag, epochs and removal rows; D-EVS-31, I-EVS-6, FI-6): an evs process
// writing committed versions into idx/, the cache §11.7's newest rule combines with the head's window. A fold of
// (f, u] reads those window versions' statements and entry versions (the process's record cache, else batch ranges)
// and, per path:
//
//   - a file takes its newest version or removal in (f, u], its own or a prefix's, and is skipped when a window
//     version after u changes the file itself again, unless its own removal is in (f, u]: a removal's marker is
//     always written (I-EVS-6);
//   - a directory takes every delta in (f, u] past what its entry holds, in version order, since a newer delta never
//     replaces an older one (fold_directory.go);
//   - a creation, base_entry_version 0, replaces what the entry held, carrying nothing, and an entry keeps four
//     folded versions, the newest whole and the older ones with their inline records elided;
//   - a removal at r is a marker {removing push, r, the path's version, one past its last} on the path, then, by a
//     LIST, on every current-epoch entry below it that holds a version older than r (marker.go). A fold deletes no
//     current-epoch entry, and a marker takes only a newer one, so no repeated, queued or late removal fold writes
//     over an entry a later fold wrote.
//
// Each entry is read, merged and written If-Match (If-None-Match to create), and read and merged again on a 412 or an
// unknown outcome, so folds are idempotent and any process may run one, two of one range at once included.
//
// The stale rule: every write carries a store deadline FoldStaleDeadline (15 s) after the fold issued the cluster
// read of the head it relies on, so no write planned before the horizon rose is taken past it. A fold relies only on
// a read whose folded_through is at most its f: nearing the deadline it reads the head again, and stops once that
// shows another fold past f. A fold that read a head whose collection window is open writes over no marker the
// window covers until FoldCollectMargin (150 ms) past until_ms by its own clock, and not at all on an unsure clock
// (EVSB-M2-14 opens the windows). While the head lists source epochs, each entry written carries its state in object
// metadata (carried, fresh or removed), and a path only a source still holds is carried from it, keeping that
// source's folded versions and drop mark; once the current entry holds a path's changes, the source copies they name
// are deleted, and below a removed directory every key in those sources (fold_sources.go), so a source holds only what
// still has to move (DESIGN-DETAILS 9.2.6).
//
// The horizon: folds add no head write. A finished fold's range stays with its process (Horizon), and that process's
// next commit on the ref raises folded_through over it, every write having landed before. Each write passes the write
// budget first, rereading repo/ as it issues (§11.13's skip row): a page-out's fold never waits (TryAcquireP2), and
// every other fold may (AcquireP2).
//
// When (§11.7's when row): the committing process folds the oldest FoldVersionCount (64) after a commit leaving
// FoldUnfoldedTriggerCount (96) unfolded, at most once per ref per FoldTriggerInterval (10 s), and the rest
// FoldIdleDelay (10 min) after the ref's last commit (NoteCommit); a page-out first folds what it pages (PageOut, in
// logpage.go); a PATH_EPOCH's process folds every unfolded version first (FoldAll).
//
// Safe for concurrent use. No lock is held across I/O or a barrier.

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The fold could not finish now: a page-out's budget said no or its deadline passed, or a collection window or
	// an unsure clock held a write. Nothing it wrote is wrong, and its range stays unfolded until a fold finishes it.
	ErrEvsFoldDeferred = errors.New("evs fold deferred")
	// §11.13's skip row: the repo is neither active nor deleted, so no P2 write is issued for it.
	ErrEvsFoldRepoState = errors.New("evs fold skipped: repo neither active nor deleted")
	// A version in the fold's range, or an entry it would write, breaks the fold's rules: a statement of another
	// path epoch, versions below the window left unfolded, an entry past its bound. A fault that alarms, and the
	// range stays unfolded.
	ErrEvsFoldInvalid = errors.New("evs fold invalid")
	// One entry lost FoldEntryRetryCount races in a row.
	ErrEvsFoldBusy = errors.New("evs fold busy")
)

// Another fold already passed the run's f: it stops, writing nothing more.
var errEvsFoldSuperseded = errors.New("evs fold superseded")

// What one fold is asked to do.
type EvsFoldRequest struct {
	// The ref's metadata cluster, its writes held to the budget.
	Cluster sidecar.BlobCluster
	RepoId  sidecar.Id
	RefId   sidecar.Id
	// The head the fold relies on, read from the cluster, and when that read was issued by this process's clock:
	// the stale rule's deadline runs from it. A nil Head, or a zero HeadReadAt, reads the head now.
	Head       *EvsStoredHead
	HeadReadAt time.Time
	// u: the fold's last version. Zero, or past the head, folds through the head's version.
	Through uint64
	// How its writes pay: §11.13's P2 rank, and whether a write may wait for budget, which a page-out's never does.
	Rank   sidecar.WriteP2Rank
	NoWait bool
	// Past it, by this process's clock, the fold issues nothing more and answers ErrEvsFoldDeferred: a page-out's
	// share of step 7's 5 s. Zero: none.
	Deadline time.Time
}

// What one fold did.
type EvsFoldResult struct {
	// The range it folded: (From, Through]. From equals Through when there was nothing to fold.
	From    uint64
	Through uint64
	// A head read during the fold showed another fold past From, so it stopped and its range is not this process's.
	Superseded bool
	// The entries it wrote, markers included, and the markers alone.
	EntryWriteCount  int
	MarkerWriteCount int
	// The source copies it deleted while the head listed sources: those a changed path's changes name, and the keys
	// below a removed directory in those sources (fold_sources.go).
	SourceDeleteCount int
}

// One ref of one repo.
type foldRef struct {
	repoId sidecar.Id
	refId  sidecar.Id
}

// What a process keeps of one ref's folds.
type foldRefState struct {
	clusterId string
	// This process's finished folds: every version in (foldedFrom, foldedThrough] folded in path epoch epoch,
	// relying on head reads whose folded_through was at most foldedFrom. Both zero for none.
	foldedFrom    uint64
	foldedThrough uint64
	epoch         uint64
	// The newest head this process committed, for trigger (1) and the backlog it declares.
	seenVersion       uint64
	seenFoldedThrough uint64
	// Trigger (1)'s last start, trigger (2)'s timer, and whether a background fold of the ref runs.
	lastTriggerAt time.Time
	stopIdle      func() bool
	running       bool
	// the versions it holds unfolded, as its cluster's sum counts them
	unfoldedCount uint64
	// not in the map, FoldRefStateCount keeping none, so no sum counts it
	unkept bool
}

// One process's folds. See the file header.
type Folder struct {
	ctx        context.Context
	clock      sidecar.Clock
	clockCheck sidecar.ClockCheck
	blobs      sidecar.BlobStore
	budget     sidecar.WriteBudget
	heads      *HeadStore
	records    *RecordCache
	repos      *RepoCache
	logPages   *LogPageCache
	priceTable *PriceTable
	settings   *EvsSettings
	log        sidecar.Logger
	// a test's: called before each entry write with its key, beside the write's barrier
	beforeEntryWrite func(key string)
	// a test's: deletes no source copy, as the fold did before DESIGN-DETAILS 9.2.6, for 9.1 E's twin
	keepSourceCopies bool

	stateLock sync.Mutex
	refStates map[foldRef]*foldRefState
	// by cluster, the versions its refs' states hold unfolded, which the backlog declared to the budget prices
	clusterUnfoldedCounts map[string]uint64
	// background folds finished, for a test to wait on before it reads what they wrote
	backgroundCount *sidecar.MonitorValue[int]
}

// A folder for one process until ctx ends. blobs and budget are the engine's, metadata writes held to the budget; a
// nil clockCheck reads as unsure.
func NewFolder(
	ctx context.Context,
	clock sidecar.Clock,
	clockCheck sidecar.ClockCheck,
	blobs sidecar.BlobStore,
	budget sidecar.WriteBudget,
	heads *HeadStore,
	records *RecordCache,
	repos *RepoCache,
	priceTable *PriceTable,
	settings *EvsSettings,
	log sidecar.Logger,
) *Folder {
	return &Folder{
		ctx:                   ctx,
		clock:                 clock,
		clockCheck:            clockCheck,
		blobs:                 blobs,
		budget:                budget,
		heads:                 heads,
		records:               records,
		repos:                 repos,
		logPages:              NewLogPageCache(settings),
		priceTable:            priceTable,
		settings:              settings,
		log:                   log,
		refStates:             map[foldRef]*foldRefState{},
		clusterUnfoldedCounts: map[string]uint64{},
		backgroundCount:       sidecar.NewMonitorValue(0),
	}
}

// The log pages this process read or wrote, which never change.
func (self *Folder) LogPages() *LogPageCache {
	return self.logPages
}

// How many background folds have finished, and a channel that closes at the next.
func (self *Folder) BackgroundFolds() (int, chan struct{}) {
	return self.backgroundCount.Get()
}

// Whether this process's clock is sure.
func (self *Folder) clockSure() bool {
	return self.clockCheck != nil && self.clockCheck.Sure()
}

// The folded_through a commit by this process carries over prior, the head its step 7 writes on (§11.7's horizon
// row): this process's finished folds when they reach prior's horizon in its path epoch, else prior's own. Never
// above prior's version, and never below its horizon.
func (self *Folder) Horizon(repoId sidecar.Id, refId sidecar.Id, prior *protocol.EvsHead) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.horizonWithLock(self.refStates[foldRef{repoId: repoId, refId: refId}], prior)
}

// See Horizon.
func (self *Folder) horizonWithLock(state *foldRefState, prior *protocol.EvsHead) uint64 {
	foldedThrough := prior.GetFoldedThrough()
	if state == nil || state.foldedThrough <= foldedThrough || state.epoch != EvsHeadCurrentEpoch(prior) ||
		foldedThrough < state.foldedFrom {
		return foldedThrough
	}
	return min(state.foldedThrough, prior.GetVersion())
}

// The fold state of a ref, made on first use; when the map is full one ref with no fold running is dropped first.
func (self *Folder) refStateWithLock(ref foldRef, clusterId string) *foldRefState {
	state, ok := self.refStates[ref]
	if ok {
		return state
	}
	if self.settings.FoldRefStateCount <= len(self.refStates) {
		for evictedRef, evicted := range self.refStates {
			if evicted.running {
				continue
			}
			if evicted.stopIdle != nil {
				evicted.stopIdle()
			}
			self.clusterUnfoldedCounts[evicted.clusterId] -= evicted.unfoldedCount
			delete(self.refStates, evictedRef)
			break
		}
	}
	state = &foldRefState{clusterId: clusterId, unkept: self.settings.FoldRefStateCount <= 0}
	if !state.unkept {
		self.refStates[ref] = state
	}
	return state
}

// Keeps a finished fold of (from, through] in epoch: joined to what the process held when the two touch, else
// replacing it.
func (self *Folder) finished(ref foldRef, clusterId string, epoch uint64, from uint64, through uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state := self.refStateWithLock(ref, clusterId)
	defer self.countUnfoldedWithLock(state)
	if state.epoch == epoch && from <= state.foldedThrough && state.foldedFrom <= through && state.foldedThrough != 0 {
		state.foldedFrom = min(state.foldedFrom, from)
		state.foldedThrough = max(state.foldedThrough, through)
		return
	}
	state.epoch = epoch
	state.foldedFrom = from
	state.foldedThrough = through
}

// Recounts the versions the ref's state holds unfolded into its cluster's sum: its newest committed version past
// the horizon its last commit carried, or past this process's folds where they reach it.
func (self *Folder) countUnfoldedWithLock(state *foldRefState) {
	if state.unkept {
		return
	}
	horizon := state.seenFoldedThrough
	if state.foldedFrom <= horizon && horizon < state.foldedThrough {
		horizon = state.foldedThrough
	}
	unfoldedCount := uint64(0)
	if horizon < state.seenVersion {
		unfoldedCount = state.seenVersion - horizon
	}
	self.clusterUnfoldedCounts[state.clusterId] -= state.unfoldedCount
	self.clusterUnfoldedCounts[state.clusterId] += unfoldedCount
	state.unfoldedCount = unfoldedCount
}

// Folds the request's range. See the file header. A fold with nothing to do answers at once; one another fold
// passed answers Superseded; ErrEvsFoldDeferred leaves the range to a later fold.
func (self *Folder) Fold(ctx context.Context, request *EvsFoldRequest) (*EvsFoldResult, error) {
	run, err := self.startFold(ctx, request)
	if err != nil {
		return nil, err
	}
	if run.result.Through <= run.result.From {
		return run.result, nil
	}
	err = run.planRange()
	if err == nil {
		err = run.writeRange()
	}
	switch {
	case errors.Is(err, errEvsFoldSuperseded):
		run.result.Superseded = true
		return run.result, nil
	case errors.Is(err, ErrEvsFoldInvalid):
		self.log.Errorf("[evs] alarm fold_invalid: repo %s ref %s versions (%d, %d]: %v",
			sidecar.EvsKeyId(request.RepoId), sidecar.EvsKeyId(request.RefId), run.from, run.through, err)
		return run.result, err
	case err != nil:
		return run.result, err
	}
	self.finished(foldRef{repoId: request.RepoId, refId: request.RefId}, request.Cluster.ClusterId(), run.epoch, run.from, run.through)
	return run.result, nil
}

// Every unfolded version through head's: what a PATH_EPOCH's process runs before its step 7, whose head then sets
// folded_through to head's version by Horizon (§11.7's when row (4)). As a page-out's fold, it never waits for
// budget and gives up at deadline.
func (self *Folder) FoldAll(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, head *EvsStoredHead, headReadAt time.Time, deadline time.Time) (*EvsFoldResult, error) {
	return self.Fold(ctx, &EvsFoldRequest{
		Cluster:    cluster,
		RepoId:     repoId,
		RefId:      refId,
		Head:       head,
		HeadReadAt: headReadAt,
		Through:    head.Version(),
		Rank:       sidecar.WriteP2RankPageOutFold,
		NoWait:     true,
		Deadline:   deadline,
	})
}

// One fold as it runs. Not safe for concurrent use.
type foldRun struct {
	folder     *Folder
	ctx        context.Context
	request    *EvsFoldRequest
	cluster    sidecar.BlobCluster
	barrierKey string
	startedAt  time.Time

	// the head it relies on, and the stale rule's deadline from its read
	head          *EvsStoredHead
	staleDeadline time.Time
	epoch         uint64
	sources       bool

	from    uint64
	through uint64
	pushes  *RecordPushSource
	// planned: every path a version in the range changes, and every removal, in version order
	paths     map[string]*foldPath
	removals  []*foldRemoval
	sortedIds []string

	result *EvsFoldResult
}

// One event of a path in a fold's range.
type foldEventKind int

const (
	// A version: a file's, or a directory's delta.
	foldEventWrite foldEventKind = iota + 1
	// The path's own removal.
	foldEventRemoval
	// The removal of a path holding it.
	foldEventPrefixRemoval
)

// One event, at the ref version that committed it.
type foldEvent struct {
	kind          foldEventKind
	commitVersion uint64
	pushId        sidecar.Id
	// a write's or an own removal's change
	change *EvsCommittedChange
	// a write's entry version, parsed
	entryVersion *protocol.EvsEntryVersion
	// where its change, or for a prefix's removal that removal's change, sits in its statement's list
	leaf evsLeafPlace
}

// Where a change sits in its statement's list (DESIGN-DETAILS 9.2.2's leaf row; question details-9-index-leaf): under
// changes_root, its part, 0 for a one-part push, and its index in that part's list plus 1; both 0 for an inline list,
// which the statement holds. A fold records it beside each folded version, marker and table, and a carry keeps it, so
// evs finds a change of an older path epoch, whose token it is never sent, by its place (read.go).
type evsLeafPlace struct {
	part  uint32
	index uint32
}

// A folded version's place.
func evsLeafPlaceOfVersion(version *protocol.EvsIndexVersion) evsLeafPlace {
	return evsLeafPlace{part: version.GetLeafPart(), index: version.GetLeafIndex()}
}

// A marker's place: its removing change's.
func evsLeafPlaceOfMarker(marker *protocol.EvsRemovalMarker) evsLeafPlace {
	return evsLeafPlace{part: marker.GetLeafPart(), index: marker.GetLeafIndex()}
}

// A folded table's place: its delta at names_through's.
func evsLeafPlaceOfTable(entry *protocol.EvsIndexEntry) evsLeafPlace {
	return evsLeafPlace{part: entry.GetNamesLeafPart(), index: entry.GetNamesLeafIndex()}
}

// One path a version in the range changes, or removes by a prefix.
type foldPath struct {
	tokenPath sidecar.EvsTokenPath
	// in version order, its own events before a prefix's at one version
	events []*foldEvent
	// a file whose path a window version after u changes again: left to that version's fold
	skip bool
}

// One removal in the range, whose LIST marks the entries below it.
type foldRemoval struct {
	tokenPath     sidecar.EvsTokenPath
	commitVersion uint64
	pushId        sidecar.Id
	// where its change sits in its statement's list, which each marker it writes records
	leaf evsLeafPlace
	// the path was a file just before it, so nothing lies below
	file bool
}

// The run's head, range and push source, or a run with nothing to fold.
func (self *Folder) startFold(ctx context.Context, request *EvsFoldRequest) (*foldRun, error) {
	run := &foldRun{
		folder:     self,
		ctx:        ctx,
		request:    request,
		cluster:    request.Cluster,
		barrierKey: barrierRefKey(request.RepoId, request.RefId),
		startedAt:  self.clock.Now(),
		pushes:     NewRecordPushSource(self.records, request.Cluster, request.RepoId, request.RefId),
		paths:      map[string]*foldPath{},
		result:     &EvsFoldResult{},
	}
	head, readAt := request.Head, request.HeadReadAt
	if head == nil || readAt.IsZero() {
		readAt = self.clock.Now()
		var err error
		head, err = self.heads.ReadCluster(ctx, request.Cluster, request.RepoId, request.RefId)
		if err != nil {
			return nil, err
		}
	}
	if head.Absent() {
		return run, nil
	}
	run.useHead(head, readAt)
	run.from = head.Head.GetFoldedThrough()
	// continue from this process's own finished folds where they reach the head's horizon
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.refStates[foldRef{repoId: request.RepoId, refId: request.RefId}]
		if state != nil && state.epoch == run.epoch && state.foldedFrom <= run.from && run.from < state.foldedThrough {
			run.from = min(state.foldedThrough, head.Version())
		}
	}()
	run.through = head.Version()
	if 0 < request.Through && request.Through < run.through {
		run.through = request.Through
	}
	run.through = max(run.through, run.from)
	run.result.From = run.from
	run.result.Through = run.through
	return run, nil
}

// Relies on head, read at readAt, from now on.
func (self *foldRun) useHead(head *EvsStoredHead, readAt time.Time) {
	self.head = head
	self.staleDeadline = readAt.Add(self.folder.settings.FoldStaleDeadline)
	self.epoch = EvsHeadCurrentEpoch(head.Head)
	self.sources = 0 < len(head.Head.GetPathEpoch().GetSources())
}

// Before each write and LIST: the page-out's deadline, then the stale rule, rereading the head near its deadline.
// errEvsFoldSuperseded once a read shows another fold past f, or a newer path epoch.
func (self *foldRun) ready() error {
	if err := self.ctx.Err(); err != nil {
		return err
	}
	now := self.folder.clock.Now()
	if !self.request.Deadline.IsZero() && !now.Before(self.request.Deadline) {
		return fmt.Errorf("%w: past its deadline", ErrEvsFoldDeferred)
	}
	if now.Before(self.staleDeadline.Add(-self.folder.settings.FoldHeadRereadMargin)) {
		return nil
	}
	head, err := self.folder.heads.ReadCluster(self.ctx, self.cluster, self.request.RepoId, self.request.RefId)
	if err != nil {
		return err
	}
	if head.Absent() {
		return fmt.Errorf("%w: the head is gone", ErrEvsFoldInvalid)
	}
	if self.from < head.Head.GetFoldedThrough() || EvsHeadCurrentEpoch(head.Head) != self.epoch {
		return errEvsFoldSuperseded
	}
	self.useHead(head, now)
	return nil
}

// Reads every version of (from, through], the events of each path it changes, the removals' prefix events, and
// which files a later window version changes again.
func (self *foldRun) planRange() error {
	window, err := EvsHeadWindow(self.head.Head)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	firstVersion := EvsHeadWindowFirstVersion(self.head.Head)
	if self.from+1 < firstVersion {
		// I-EVS-6: a version leaves the window only once folded
		return fmt.Errorf("%w: the window starts at %d, past the horizon %d", ErrEvsFoldInvalid, firstVersion, self.from)
	}
	for version := self.from + 1; version <= self.through; version += 1 {
		windowEntry := window[version-firstVersion]
		statement, changes, err := self.pushes.allChangesAt(self.ctx, version, windowEntry)
		if err != nil {
			return err
		}
		if len(changes) == 0 {
			continue
		}
		if statement.Push.GetPathEpoch() != self.epoch {
			return fmt.Errorf("%w: version %d in path epoch %d, the head's %d", ErrEvsFoldInvalid, version, statement.Push.GetPathEpoch(), self.epoch)
		}
		leaves, err := self.pushes.leafPlacesAt(self.ctx, version, windowEntry, changes)
		if err != nil {
			return err
		}
		for i, change := range changes {
			event := &foldEvent{commitVersion: version, pushId: windowEntry.PushId, change: change, leaf: leaves[i]}
			if change.Removes() {
				event.kind = foldEventRemoval
				self.removals = append(self.removals, &foldRemoval{
					tokenPath: change.TokenPath, commitVersion: version, pushId: windowEntry.PushId, leaf: leaves[i],
				})
			} else {
				event.kind = foldEventWrite
				event.entryVersion, err = parseEvsEntryVersion(change.EntryVersion)
				if err != nil {
					return fmt.Errorf("%w: version %d: %v", ErrEvsStatementMismatch, version, err)
				}
			}
			self.pathOf(change.TokenPath).events = append(self.pathOf(change.TokenPath).events, event)
		}
	}
	self.sortedIds = make([]string, 0, len(self.paths))
	for pathId := range self.paths {
		self.sortedIds = append(self.sortedIds, pathId)
	}
	sort.Strings(self.sortedIds)

	// each removal reaches the changed paths below it, which sort right after it
	for _, removal := range self.removals {
		removalId := string(removal.tokenPath.Bytes())
		for i := sort.SearchStrings(self.sortedIds, removalId); i < len(self.sortedIds); i += 1 {
			path := self.paths[self.sortedIds[i]]
			if !path.tokenPath.HasPrefix(removal.tokenPath) {
				break
			}
			if len(path.tokenPath) == len(removal.tokenPath) {
				continue
			}
			path.events = append(path.events, &foldEvent{kind: foldEventPrefixRemoval, commitVersion: removal.commitVersion, pushId: removal.pushId, leaf: removal.leaf})
		}
		// a path a file just before its removal holds nothing below it
		removal.file = self.paths[removalId].fileBefore(removal.commitVersion)
	}
	for _, path := range self.paths {
		sort.SliceStable(path.events, func(i int, j int) bool {
			if path.events[i].commitVersion != path.events[j].commitVersion {
				return path.events[i].commitVersion < path.events[j].commitVersion
			}
			return path.events[i].kind != foldEventPrefixRemoval && path.events[j].kind == foldEventPrefixRemoval
		})
	}
	return self.planSkips(window, firstVersion)
}

// The path's plan, made on first use.
func (self *foldRun) pathOf(tokenPath sidecar.EvsTokenPath) *foldPath {
	pathId := string(tokenPath.Bytes())
	path, ok := self.paths[pathId]
	if !ok {
		path = &foldPath{tokenPath: tokenPath}
		self.paths[pathId] = path
	}
	return path
}

// Whether the path's newest own write before version is a file's. False when no write of it in the range comes
// before version. The events need not be sorted yet.
func (self *foldPath) fileBefore(version uint64) bool {
	var newest *foldEvent
	for _, event := range self.events {
		if event.kind == foldEventWrite && event.commitVersion < version && (newest == nil || newest.commitVersion < event.commitVersion) {
			newest = event
		}
	}
	return newest != nil && newest.entryVersion.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
}

// Whether a fold must write the path whatever later versions do: a directory's deltas, which a newer delta never
// replaces, and the path's own removal, whose marker must stand before the removal leaves the window (I-EVS-6) and
// before the LIST below it, so that while sources stand no read falls back to a source under it.
func (self *foldPath) neverSkipped() bool {
	return slices.ContainsFunc(self.events, func(event *foldEvent) bool {
		return event.kind == foldEventRemoval ||
			(event.kind == foldEventWrite && event.entryVersion.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY))
	})
}

// Whether the path's first event in the range continues what an entry held, rather than creating it: what a carry
// from a source needs.
func (self *foldPath) continues() bool {
	for _, event := range self.events {
		switch event.kind {
		case foldEventWrite:
			return event.change.BaseEntryVersion != 0
		case foldEventRemoval:
			return true
		}
	}
	return false
}

// The source paths every own change of the path in the range names (§11.6's read row), in event order: what a carry
// reads from and, once the current entry holds the changes, what the fold deletes (fold_sources.go).
func (self *foldPath) sourcePaths() [][]byte {
	sourcePaths := [][]byte{}
	for _, event := range self.events {
		if event.change != nil {
			sourcePaths = append(sourcePaths, event.change.SourcePaths...)
		}
	}
	return sourcePaths
}

// Marks each file path a window version after u changes itself again, which that version's fold takes (§11.7's
// fold row), unless neverSkipped. The digest filters, and the change list decides.
func (self *foldRun) planSkips(window []*sidecar.EvsWindowEntry, firstVersion uint64) error {
	for _, pathId := range self.sortedIds {
		path := self.paths[pathId]
		if path.neverSkipped() {
			continue
		}
		for version := self.through + 1; version <= self.head.Version(); version += 1 {
			windowEntry := window[version-firstVersion]
			if !windowEntry.PathsDigest.MayChange(path.tokenPath) {
				continue
			}
			changes, err := self.pushes.ChangesAt(self.ctx, version, windowEntry, path.tokenPath)
			if err != nil {
				return err
			}
			if slices.ContainsFunc(changes, func(change *EvsCommittedChange) bool { return change.TokenPath.Equal(path.tokenPath) }) {
				path.skip = true
				break
			}
		}
	}
	return nil
}

// Writes each planned path's entry, parents before children, each followed by the deletes of the source copies its
// changes name; then each removal's markers below it in version order, the path's own marker before its LIST, and
// below it the keys of the named sources (fold_sources.go).
func (self *foldRun) writeRange() error {
	for _, pathId := range self.sortedIds {
		path := self.paths[pathId]
		if path.skip {
			continue
		}
		if err := self.writePath(path); err != nil {
			return err
		}
	}
	for _, removal := range self.removals {
		if removal.file {
			continue
		}
		if err := self.markBelow(removal); err != nil {
			return err
		}
		if err := self.emptySourcesBelow(removal); err != nil {
			return err
		}
	}
	return nil
}

// One path's entry: read, merge its events past what it holds, write, and on a 412 or an unknown outcome read and
// merge again. An entry that already holds them is not written. Once the current entry holds them, written now or
// found so, the source copies its changes name are deleted (fold_sources.go).
func (self *foldRun) writePath(path *foldPath) error {
	for attempt := 0; attempt < self.folder.settings.FoldEntryRetryCount; attempt += 1 {
		if err := self.ready(); err != nil {
			return err
		}
		read, err := ReadEntry(self.ctx, self.cluster, self.request.RepoId, self.request.RefId, self.epoch, path.tokenPath, self.head.Head.GetFoldedThrough())
		if err != nil {
			return err
		}
		held := read.Entry
		carriedEpoch := uint64(0)
		if read.Absent() && self.sources && path.continues() {
			held, carriedEpoch, err = self.sourceEntry(path)
			if err != nil {
				return err
			}
		}
		merged := mergeFoldEvents(held, path.events, self.folder.log)
		if !merged.changed {
			if read.Absent() {
				// a source copy holding them while the current epoch holds nothing: nothing stands to take over
				return nil
			}
			return self.deleteSourceCopies(path)
		}
		if names := merged.entry.GetNames(); names != nil {
			checkFoldedTableBound(names, self.folder.log)
		}
		waited, err := self.waitOverMarker(read)
		if err != nil {
			return err
		}
		if waited {
			// the wait passed the head's deadline window: read the head and the entry again
			continue
		}
		state := self.entryState(read, merged, carriedEpoch)
		err = self.put(path.tokenPath, read, merged.entry, state)
		if retryEntryWrite(err) {
			continue
		}
		if err != nil {
			return err
		}
		self.result.EntryWriteCount += 1
		if merged.removed {
			self.result.MarkerWriteCount += 1
		}
		return self.deleteSourceCopies(path)
	}
	return fmt.Errorf("%w: %d tries on one entry", ErrEvsFoldBusy, self.folder.settings.FoldEntryRetryCount)
}

// Whether a write's error leaves the entry to be read and merged again: a 412, an unknown outcome, which the read
// settles (§19.6's settle rule), or a key the store holds settling.
func retryEntryWrite(err error) bool {
	var unknown *sidecar.BlobUnknownError
	return errors.Is(err, sidecar.ErrBlobPrecondition) || errors.As(err, &unknown) || errors.Is(err, sidecar.ErrBlobHeld)
}

// The state an entry written while sources stand carries (§11.7's epochs row): removed for a marker, fresh for a path
// new to the current epoch or re-created over a marker, carried from the source it was carried from, else what it
// held. None while the head lists no source.
func (self *foldRun) entryState(read *EvsEntryRead, merged *foldMerge, carriedEpoch uint64) EvsEntryStateValue {
	if !self.sources {
		return EvsEntryStateValue{}
	}
	switch {
	case merged.removed:
		return EvsEntryStateValue{State: EvsEntryStateRemoved}
	case merged.replaced:
		return EvsEntryStateValue{State: EvsEntryStateFresh}
	case carriedEpoch != 0:
		return EvsEntryStateValue{State: EvsEntryStateCarried, Epoch: carriedEpoch}
	case !read.Absent() && read.State.State == EvsEntryStateCarried:
		return read.State
	}
	return EvsEntryStateValue{State: EvsEntryStateFresh}
}

// While sources stand: the entry of a path only a source holds, carried with its folded versions, drop mark and
// rows, untagged rows tagged with the source's epoch (§11.7's epochs row), from the newest listed source the path's
// change names that still holds it. nil when none does.
func (self *foldRun) sourceEntry(path *foldPath) (*protocol.EvsIndexEntry, uint64, error) {
	encodedSources := path.sourcePaths()
	for _, listed := range self.head.Head.GetPathEpoch().GetSources() {
		for _, encoded := range encodedSources {
			sourcePath := &protocol.EvsSourcePath{}
			if err := proto.Unmarshal(encoded, sourcePath); err != nil || sourcePath.GetEpoch() != listed.GetEpoch() {
				continue
			}
			tokenPath, err := sidecar.ParseEvsChangedTokenPath(sourcePath.GetTokenPath())
			if err != nil {
				continue
			}
			read, err := ReadEntry(self.ctx, self.cluster, self.request.RepoId, self.request.RefId, listed.GetEpoch(), tokenPath, self.head.Head.GetFoldedThrough())
			if err != nil {
				return nil, 0, err
			}
			if read.Absent() || read.Entry.GetMarker() != nil || (len(read.Entry.GetVersions()) == 0 && read.Entry.GetNames() == nil) {
				continue
			}
			return carryEvsIndexEntry(read.Entry, listed.GetEpoch()), listed.GetEpoch(), nil
		}
	}
	return nil, 0, nil
}

// One entry write, paid for: If-None-Match where the read found none, else If-Match its ETag, with the stale rule's
// deadline.
func (self *foldRun) put(tokenPath sidecar.EvsTokenPath, read *EvsEntryRead, entry *protocol.EvsIndexEntry, state EvsEntryStateValue) error {
	operation := WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(proto.Size(entry)), Count: 1}
	if read.Absent() {
		operation.Kind = WriteOperationCreate
	}
	price, err := self.folder.priceTable.Price(operation)
	if err != nil {
		return err
	}
	grant, err := self.acquire(price)
	if err != nil {
		return err
	}
	defer grant.Close()
	writeCtx := sidecar.WithBlobDeadline(grant.Context(), self.staleDeadline)
	if !self.request.Deadline.IsZero() {
		// a page-out's write that would land past step 7's window is worth nothing to it
		writeCtx = sidecar.WithBlobDeadline(writeCtx, self.request.Deadline)
	}
	if hook := self.folder.beforeEntryWrite; hook != nil {
		hook(IndexEntryKey(self.request.RepoId, self.request.RefId, self.epoch, tokenPath))
	}
	testHookBarrier(BarrierFoldEntryWriteBefore, self.barrierKey)
	_, err = PutEntry(writeCtx, self.cluster, self.request.RepoId, self.request.RefId, self.epoch, tokenPath, read, entry, state)
	testHookBarrier(BarrierFoldEntryWriteAfter, self.barrierKey)
	if errors.Is(err, ErrEvsIndexEntryInvalid) {
		return fmt.Errorf("%w: %v", ErrEvsFoldInvalid, err)
	}
	return err
}

// The P2 grant one write spends: never waiting for a page-out's fold, which then defers, and rereading repo/ as it
// issues.
func (self *foldRun) acquire(byteCount int64) (sidecar.WriteGrant, error) {
	work := &sidecar.WriteP2Work{
		Rank:      self.request.Rank,
		Due:       self.startedAt,
		ByteCount: byteCount,
		Funded:    true,
		Recheck:   self.recheckRepo,
	}
	testHookBarrier(BarrierFoldAcquireBefore, self.barrierKey)
	defer testHookBarrier(BarrierFoldAcquireAfter, self.barrierKey)
	if self.request.NoWait {
		grant, ok, err := self.folder.budget.TryAcquireP2(self.ctx, self.cluster.ClusterId(), work)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: no P2 budget now", ErrEvsFoldDeferred)
		}
		return grant, nil
	}
	return self.folder.budget.AcquireP2(self.ctx, self.cluster.ClusterId(), work)
}

// §11.13's skip row, as each write issues.
func (self *foldRun) recheckRepo(ctx context.Context) error {
	return self.folder.recheckRepo(ctx, self.cluster, self.request.RepoId)
}

// An entry's newest event: its newest folded version's commit, its marker's removal or its table's newest delta.
func evsIndexEntryNewestCommit(entry *protocol.EvsIndexEntry) uint64 {
	newest := entry.GetNamesThrough()
	if versions := entry.GetVersions(); 0 < len(versions) {
		newest = max(newest, versions[0].GetCommitVersion())
	}
	if marker := entry.GetMarker(); marker != nil {
		newest = max(newest, marker.GetRemovalVersion())
	}
	return newest
}

// The version a standing entry's path holds, whose removal is one past it, and whether it stands: a file's newest
// folded version; a directory's newest version this fold applied, else its table's names_through, the ref version
// of its newest delta, which no version of the path passes (a reading: a folded table keeps no path version, so a
// removal below a removed directory takes this bound, as directories take no path-level CAS).
func evsIndexEntryStanding(entry *protocol.EvsIndexEntry, directoryVersion uint64) (uint64, bool) {
	switch {
	case entry.GetMarker() != nil:
		return 0, false
	case 0 < len(entry.GetVersions()):
		return newestPathVersion(entry.GetVersions()), true
	case entry.GetNames() != nil && 0 < directoryVersion:
		return directoryVersion, true
	case entry.GetNames() != nil:
		return max(1, entry.GetNamesThrough()), true
	}
	return 0, false
}

// What merging a path's events into its entry gave.
type foldMerge struct {
	entry *protocol.EvsIndexEntry
	// some event was newer than what the entry held
	changed bool
	// its newest event is a removal
	removed bool
	// a creation since the last removal replaced what the entry held
	replaced bool
}

// The entry held, nil for none, with each event newer than its newest event merged in version order (§11.7's fold
// row). held is not changed.
func mergeFoldEvents(held *protocol.EvsIndexEntry, events []*foldEvent, log sidecar.Logger) *foldMerge {
	merged := &foldMerge{entry: &protocol.EvsIndexEntry{}}
	if held != nil {
		merged.entry = proto.Clone(held).(*protocol.EvsIndexEntry)
	}
	newest := evsIndexEntryNewestCommit(merged.entry)
	directoryVersion := uint64(0)
	for _, event := range events {
		if event.commitVersion <= newest {
			continue
		}
		switch event.kind {
		case foldEventWrite:
			creation := event.change.BaseEntryVersion == 0
			if event.entryVersion.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
				merged.entry = applyFoldDelta(merged.entry, event, log)
				directoryVersion = event.entryVersion.GetVersion()
			} else {
				var replaced bool
				merged.entry, replaced = applyFoldFileVersion(merged.entry, event, log)
				creation = creation || replaced
			}
			merged.removed = false
			merged.replaced = merged.replaced || creation
		case foldEventRemoval:
			pathVersion := event.change.BaseEntryVersion + 1
			if standing, ok := evsIndexEntryStanding(merged.entry, directoryVersion); ok && pathVersion <= standing &&
				0 < len(merged.entry.GetVersions()) {
				// 5g held the base to the path's newest, so this is a fault; the marker still passes every version
				log.Errorf("[evs] alarm fold_version_rule: a removal based on %d over a path at %d", event.change.BaseEntryVersion, standing)
				pathVersion = standing + 1
			}
			// a newer marker over an older one keeps the ids the older carried (format1_guard.go)
			merged.entry.Marker = inheritCarriedIds(merged.entry.GetMarker(), &protocol.EvsRemovalMarker{
				PushId:         event.pushId.Bytes(),
				RemovalVersion: event.commitVersion,
				PathVersion:    pathVersion,
				LeafPart:       event.leaf.part,
				LeafIndex:      event.leaf.index,
			})
			merged.removed = true
			merged.replaced = false
		case foldEventPrefixRemoval:
			standing, ok := evsIndexEntryStanding(merged.entry, directoryVersion)
			if !ok {
				// already absent: a prefix's removal adds no removal of its own
				continue
			}
			merged.entry.Marker = &protocol.EvsRemovalMarker{
				PushId:         event.pushId.Bytes(),
				RemovalVersion: event.commitVersion,
				PathVersion:    standing + 1,
				LeafPart:       event.leaf.part,
				LeafIndex:      event.leaf.index,
			}
			merged.removed = true
			merged.replaced = false
		}
		newest = event.commitVersion
		merged.changed = true
	}
	return merged
}

// A file's version merged into its entry: a creation replaces what the entry held, carrying no version, as does a
// write over a marker, a table or a newer path version, which 5g never commits; else it goes first, the three newest
// older ones kept with their inline records elided. Whether it replaced. The entry's drop mark stays through each,
// since a path's versions never restart and the mark says which of them a drop took; a marker's carried ids cannot
// stay on an entry that stands, so replacing one alarms and its content stays (format1_guard.go).
func applyFoldFileVersion(entry *protocol.EvsIndexEntry, event *foldEvent, log sidecar.Logger) (*protocol.EvsIndexEntry, bool) {
	version := &protocol.EvsIndexVersion{
		PushId:        event.pushId.Bytes(),
		CommitVersion: event.commitVersion,
		EntryVersion:  event.change.EntryVersion,
		LeafPart:      event.leaf.part,
		LeafIndex:     event.leaf.index,
	}
	creation := event.change.BaseEntryVersion == 0
	held := entry.GetVersions()
	if creation || entry.GetMarker() != nil || entry.GetNames() != nil || len(held) == 0 ||
		event.entryVersion.GetVersion() <= newestPathVersion(held) {
		if !creation && 0 < len(held) && event.entryVersion.GetVersion() <= newestPathVersion(held) {
			log.Errorf("[evs] alarm fold_version_rule: version %d over a path at %d", event.entryVersion.GetVersion(), newestPathVersion(held))
		}
		alarmCarriedIdsDropped(log, entry.GetMarker(), "a file's version")
		replaced := &protocol.EvsIndexEntry{Versions: []*protocol.EvsIndexVersion{version}, DropMark: entry.GetDropMark()}
		return replaced, true
	}
	kept := []*protocol.EvsIndexVersion{version}
	for _, older := range held {
		if evsIndexEntryMaxVersionCount <= len(kept) {
			break
		}
		kept = append(kept, elideEvsIndexVersion(older))
	}
	entry.Versions = kept
	return entry, false
}

// A folded version with its inline records cut, which evs restores from its push record before serving it (§11.7's
// holds row), keeping its leaf place. One with none to cut keeps its signed bytes.
func elideEvsIndexVersion(version *protocol.EvsIndexVersion) *protocol.EvsIndexVersion {
	if version.GetElided() {
		return version
	}
	entryVersion := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(version.GetEntryVersion(), entryVersion); err != nil {
		// ParseEvsIndexEntry held every version to parse
		return version
	}
	cut := false
	for _, locator := range entryVersion.GetChain() {
		if len(locator.GetInline()) != 0 {
			locator.Inline = nil
			cut = true
		}
	}
	if !cut {
		return version
	}
	elidedBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(entryVersion)
	if err != nil {
		return version
	}
	return &protocol.EvsIndexVersion{
		PushId:        version.GetPushId(),
		CommitVersion: version.GetCommitVersion(),
		EntryVersion:  elidedBytes,
		Elided:        true,
		LeafPart:      version.GetLeafPart(),
		LeafIndex:     version.GetLeafIndex(),
	}
}

// Every change of the push committed at version: a one-part push's from its record, a sealed push's from every
// part, checked whole as its seal is (EvsCheckSeal), so each change carries its source paths and each part matches
// the root the seal names for it.
func (self *RecordPushSource) allChangesAt(ctx context.Context, version uint64, entry *sidecar.EvsWindowEntry) (*sidecar.EvsStatement, []*EvsCommittedChange, error) {
	push, err := self.pushAt(ctx, version, entry)
	if err != nil {
		return nil, nil, err
	}
	if !push.sealed {
		return push.statement, push.changes, nil
	}
	if push.allChanges != nil {
		return push.statement, push.allChanges, nil
	}
	partBytes := make([][]byte, len(push.sealParts))
	for i, sealPart := range push.sealParts {
		record, err := ReadRecord(ctx, self.cache, self.cluster, sealPart.Place)
		if err != nil {
			return nil, nil, err
		}
		if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART || record.PushId != sidecar.Id(push.statement.Push.GetPushId()) {
			return nil, nil, fmt.Errorf("%w: a seal's part place holds another record", ErrEvsStatementMismatch)
		}
		statementBytes, part, _, _, err := sidecar.ParseEvsPartRecordBody(record.Body)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(statementBytes, push.statement.Bytes) {
			return nil, nil, fmt.Errorf("%w: a part of another statement", ErrEvsStatementMismatch)
		}
		partBytes[i] = part
	}
	checked, checkedParts, err := sidecar.EvsCheckSeal(push.statement, partBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrEvsStatementMismatch, err)
	}
	for i, checkedPart := range checkedParts {
		if checkedPart.Root != push.sealParts[i].ChangesRoot {
			return nil, nil, fmt.Errorf("%w: a part whose changes_root the seal does not name", ErrEvsStatementMismatch)
		}
	}
	push.allChanges = committedChanges(checked.Changes)
	return push.statement, push.allChanges, nil
}

// Where each of the changes allChangesAt gave for the push at version sits in its statement's list, in that order: see
// evsLeafPlace. A sealed push's changes are its parts' joined in part order, each part starting at the token path its
// seal names it by, which each part's changes_root was checked against.
func (self *RecordPushSource) leafPlacesAt(ctx context.Context, version uint64, entry *sidecar.EvsWindowEntry, changes []*EvsCommittedChange) ([]evsLeafPlace, error) {
	push, err := self.pushAt(ctx, version, entry)
	if err != nil {
		return nil, err
	}
	leaves := make([]evsLeafPlace, len(changes))
	if len(push.statement.Push.GetChangesRoot()) == 0 {
		return leaves, nil
	}
	if !push.sealed {
		for i := range changes {
			leaves[i] = evsLeafPlace{index: uint32(i + 1)}
		}
		return leaves, nil
	}
	part, partStart := 0, 0
	for i, change := range changes {
		if part+1 < len(push.sealParts) && change.TokenPath.Equal(push.sealParts[part+1].FirstTokenPath) {
			part, partStart = part+1, i
		}
		leaves[i] = evsLeafPlace{part: uint32(part + 1), index: uint32(i - partStart + 1)}
	}
	if part+1 != len(push.sealParts) {
		return nil, fmt.Errorf("%w: %d parts of changes for a seal of %d", ErrEvsStatementMismatch, part+1, len(push.sealParts))
	}
	return leaves, nil
}

// The statement committed at version, checked against its window entry.
func (self *RecordPushSource) statementAt(ctx context.Context, version uint64, entry *sidecar.EvsWindowEntry) (*sidecar.EvsStatement, error) {
	push, err := self.pushAt(ctx, version, entry)
	if err != nil {
		return nil, err
	}
	return push.statement, nil
}

// The push at version, read once a source.
func (self *RecordPushSource) pushAt(ctx context.Context, version uint64, entry *sidecar.EvsWindowEntry) (*recordPush, error) {
	if push, ok := self.versionPushes[version]; ok {
		return push, nil
	}
	push, err := self.readPush(ctx, entry)
	if err != nil {
		return nil, err
	}
	self.versionPushes[version] = push
	return push, nil
}

// Called after this process commits on a ref (§11.8 step 8), off the reply path: arms the idle fold of §11.7's
// when row (2), starts trigger (1)'s fold of the oldest FoldVersionCount when FoldUnfoldedTriggerCount or more
// stay unfolded, and declares the folds the cluster's refs owe to the budget. Returns at once.
func (self *Folder) NoteCommit(clusterId string, repoId sidecar.Id, refId sidecar.Id, committed *protocol.EvsHead) {
	ref := foldRef{repoId: repoId, refId: refId}
	now := self.clock.Now()
	trigger := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.refStateWithLock(ref, clusterId)
		state.seenVersion = max(state.seenVersion, committed.GetVersion())
		state.seenFoldedThrough = max(state.seenFoldedThrough, committed.GetFoldedThrough())
		self.countUnfoldedWithLock(state)
		if state.stopIdle != nil {
			state.stopIdle()
			state.stopIdle = nil
		}
		if 0 < self.settings.FoldIdleDelay {
			state.stopIdle = self.clock.AfterFunc(self.settings.FoldIdleDelay, func() {
				self.runIdleFold(ref)
			})
		}
		horizon := self.horizonWithLock(state, committed)
		if 0 < self.settings.FoldUnfoldedTriggerCount &&
			uint64(self.settings.FoldUnfoldedTriggerCount) <= committed.GetVersion()-horizon &&
			(state.lastTriggerAt.IsZero() || self.settings.FoldTriggerInterval <= now.Sub(state.lastTriggerAt)) &&
			!state.running {
			state.lastTriggerAt = now
			state.running = true
			trigger = true
		}
	}()
	if trigger {
		go self.runBackgroundFold(ref, clusterId, func(head *EvsStoredHead, horizon uint64) uint64 {
			return horizon + uint64(self.settings.FoldVersionCount)
		})
	}
	self.declareBacklog(clusterId)
}

// Trigger (2): the rest of the ref, once it has been idle FoldIdleDelay. A fold of it already running defers this
// one FoldTriggerInterval.
func (self *Folder) runIdleFold(ref foldRef) {
	if self.ctx.Err() != nil {
		return
	}
	var clusterId string
	start := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, ok := self.refStates[ref]
		if !ok {
			return
		}
		state.stopIdle = nil
		if state.running {
			state.stopIdle = self.clock.AfterFunc(self.settings.FoldTriggerInterval, func() {
				self.runIdleFold(ref)
			})
			return
		}
		state.running = true
		clusterId = state.clusterId
		start = true
	}()
	if start {
		// off the clock's goroutine, which a fold waiting on the clock must not hold
		go self.runBackgroundFold(ref, clusterId, func(head *EvsStoredHead, horizon uint64) uint64 {
			return head.Version()
		})
	}
}

// One fold off the reply path, through what through gives for the head it reads and this process's horizon over it,
// paying funded P2 at the fold rank and waiting for it. Errors are logged; the next trigger tries again.
func (self *Folder) runBackgroundFold(ref foldRef, clusterId string, through func(head *EvsStoredHead, horizon uint64) uint64) {
	defer func() {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if state, ok := self.refStates[ref]; ok {
				state.running = false
			}
		}()
		self.declareBacklog(clusterId)
		self.backgroundCount.Update(func(count int) int { return count + 1 })
	}()
	err := func() error {
		cluster, err := self.blobs.Cluster(clusterId)
		if err != nil {
			return err
		}
		readAt := self.clock.Now()
		head, err := self.heads.ReadCluster(self.ctx, cluster, ref.repoId, ref.refId)
		if err != nil || head.Absent() {
			return err
		}
		_, err = self.Fold(self.ctx, &EvsFoldRequest{
			Cluster:    cluster,
			RepoId:     ref.repoId,
			RefId:      ref.refId,
			Head:       head,
			HeadReadAt: readAt,
			Through:    through(head, self.Horizon(ref.repoId, ref.refId, head.Head)),
			Rank:       sidecar.WriteP2RankFold,
		})
		return err
	}()
	if err != nil && self.ctx.Err() == nil {
		self.log.Warningf("[evs] fold of repo %s ref %s: %v", sidecar.EvsKeyId(ref.repoId), sidecar.EvsKeyId(ref.refId), err)
	}
}

// Declares to the budget the folds the cluster's refs owe this process, in priced bytes: one entry overwrite a
// version not yet folded, an estimate the wallet clamps against (§11.13's wallet row; plan-EVSB-nvb-fields).
func (self *Folder) declareBacklog(clusterId string) {
	var unfoldedCount uint64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		unfoldedCount = self.clusterUnfoldedCounts[clusterId]
	}()
	price, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationOverwrite, Count: float64(unfoldedCount)})
	if err != nil {
		return
	}
	self.budget.DeclareP2Backlog(clusterId, "folds", sidecar.WriteP2RankFold, true, price)
}
