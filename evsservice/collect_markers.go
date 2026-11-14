// Marker collection windows (§11.7's collect row; D-EVS-31, D-EVS-40, D-OPS-20, I-EVS-6, I-EVS-8, FI-15; owner
// decision 148; EVSB-M2-14): taskworker's job evs.collect, one ref a run, which the nightly pass queues for each ref
// whose head shows removals the fold has passed by a base range. A fold never deletes an entry (marker.go); a marker
// leaves only here, in a window:
//
//	gates    nothing on an unsure clock, on a cluster whose build has not passed §19.6's settle cases (FS-114), for a
//	         repo not active or deleted, or while the head lists a source; markers stay
//	find     the removals the ref's statements name after head.collect.done, each r with folded_through >= r + 64,
//	         in the head's current path epoch, read from the head's window and log pages, at most ScanVersionCount
//	         versions a run; each removal's own entry and, by a LIST, every entry below it, the keys a window reads
//	open     one head CAS raising only the fence, setting collect {done, through: the newest r taken, until_ms: now +
//	         Window}, only ReopenMargin (150 ms) after the last window lapsed by this clock
//	wait     OpenWait (15.3 s): every fold and copy write planned on an older head has landed or never will, its 15 s
//	         deadline checked by the store host's clock and each of four clocks slewed up to 50 ms
//	delete   GET each candidate; one holding a marker of a removal at or below through has what it carries deleted
//	         (kind-5 segments and slots, from format 2; a 404 is done) unless a hold covers the repo, which leaves the
//	         marker for a later window, then is DELETEd once, unconditionally, each DELETE carrying a deadline
//	         DeleteMargin (50 ms) before until_ms by this clock and cancelled at once if the clock turns unsure; a
//	         held key or an unknown outcome leaves the marker to be read again in a later window
//	close    another fence-only CAS setting done to through, or below the oldest marker left
//
// A fold that reads a head whose window is open writes over no marker it covers until FoldCollectMargin past
// until_ms by its own clock (marker.go), and no DELETE of the window is taken by the store after until_ms in UTC,
// so no live entry a fold re-creates is deleted. Windows set no fence_ms and end no push attempt. Every write is
// unfunded P2 of rank GC: collection has no payer (§11.13's wallet row).
//
// Format 1 writes no carried ids; a marker read with them keeps them, and collection deletes what they name. A
// removal in an earlier path epoch than the head's is passed by, its markers left where the copy left them: their
// tokens in the current epoch are DESIGN-DETAILS problem 9's.
//
// Safe for concurrent use: each Collect holds its own state, and one run per ref is the job's once key.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The job's name in taskworker's registry.
const EvsCollectTaskName = "evs.collect"

// A removal's markers are collectable once the fold has passed it by one base range (§11.7's collect row), so no
// push based before it can commit (§11.8).
const evsCollectBaseRange = 64

// §11.7's floors, which no setting passes: a window reopens only 150 ms after the last lapsed, each DELETE carries a
// deadline at least 50 ms before until_ms, and the wait outlasts a fold write's deadline by four clocks' 50 ms slew
// and 100 ms to spare.
const (
	evsCollectMinReopenMargin = 150 * time.Millisecond
	evsCollectMinDeleteMargin = 50 * time.Millisecond
	evsCollectMinWaitSlack    = 300 * time.Millisecond
)

// Settings that break §11.7's floors.
var ErrMarkerCollectorSettings = errors.New("evs marker collector settings invalid")

// Tunables of marker collection.
type MarkerCollectorSettings struct {
	// How long a window stays open: 30 s.
	Window time.Duration
	// The wait between a window's open and its first DELETE: 15.3 s, and never under a fold write's deadline plus
	// 300 ms.
	OpenWait time.Duration
	// A window opens only this long after the last lapsed, by the opener's clock: 150 ms, and never less.
	ReopenMargin time.Duration
	// Each DELETE carries a deadline this long before until_ms: 50 ms, and never less.
	DeleteMargin time.Duration
	// The most versions one run reads statements of: 4,096.
	ScanVersionCount uint64
	// The most candidate entries one window reads: 1,024. The rest wait for the next window.
	WindowEntryCount int
	// With no removal found, done moves by a fence CAS only past this many versions read: 256, so a quiet ref pays
	// one head write a few hundred versions.
	DoneAdvanceVersionCount uint64
	// The nightly pass queues a ref whose head was written within this long: 7 d.
	HeadAge time.Duration
	// How long one run may take before taskworker ends it.
	RunMaxTime time.Duration
	// Keys a LIST page asks for. Must be positive.
	ListLimit int
}

// §11.7's figures.
func DefaultMarkerCollectorSettings() *MarkerCollectorSettings {
	return &MarkerCollectorSettings{
		Window:                  30 * time.Second,
		OpenWait:                15*time.Second + 300*time.Millisecond,
		ReopenMargin:            evsCollectMinReopenMargin,
		DeleteMargin:            evsCollectMinDeleteMargin,
		ScanVersionCount:        4096,
		WindowEntryCount:        1024,
		DoneAdvanceVersionCount: 256,
		HeadAge:                 7 * 24 * time.Hour,
		RunMaxTime:              10 * time.Minute,
		ListLimit:               1000,
	}
}

// ErrMarkerCollectorSettings for a value past §11.7's floors, against the fold's deadline in evsSettings.
func (self *MarkerCollectorSettings) Validate(evsSettings *EvsSettings) error {
	switch {
	case self.ReopenMargin < evsCollectMinReopenMargin || self.ReopenMargin < evsSettings.FoldCollectMargin:
		return fmt.Errorf("%w: a reopen margin of %s, under %s or the fold's %s", ErrMarkerCollectorSettings, self.ReopenMargin, evsCollectMinReopenMargin, evsSettings.FoldCollectMargin)
	case self.DeleteMargin < evsCollectMinDeleteMargin:
		return fmt.Errorf("%w: a delete margin of %s, under %s", ErrMarkerCollectorSettings, self.DeleteMargin, evsCollectMinDeleteMargin)
	case self.OpenWait < evsSettings.FoldStaleDeadline+evsCollectMinWaitSlack:
		return fmt.Errorf("%w: a wait of %s, under the fold's deadline %s and %s", ErrMarkerCollectorSettings, self.OpenWait, evsSettings.FoldStaleDeadline, evsCollectMinWaitSlack)
	case self.Window <= self.OpenWait+self.DeleteMargin:
		return fmt.Errorf("%w: a window of %s leaves no time past its wait", ErrMarkerCollectorSettings, self.Window)
	case self.ScanVersionCount == 0 || self.WindowEntryCount <= 0 || self.DoneAdvanceVersionCount == 0 ||
		self.HeadAge <= 0 || self.RunMaxTime <= 0 || self.ListLimit <= 0:
		return fmt.Errorf("%w: a bound that is not positive", ErrMarkerCollectorSettings)
	}
	return nil
}

// What a collector runs on beyond its host.
type MarkerCollectorDeps struct {
	// The holds every delete reads. nil reads hold/ through a HoldCache of its own.
	Holds *HoldCache
	// nil: the defaults.
	Settings    *MarkerCollectorSettings
	EvsSettings *EvsSettings
	// Alarms. nil discards.
	Log sidecar.Logger
	// a test's: called at each barrier, an error stopping the run there as a kill would
	atStep func(name string, key string) error
	// a test's: stands in for the wait, on a clock the test moves
	wait func(wait time.Duration)
}

// What one run did, with no id (I-13).
type MarkerCollectResult struct {
	// Versions whose statements were read, the removals found and the entries a window read.
	ScannedVersionCount int
	RemovalCount        int
	EntryCount          int
	// Markers deleted, ids they carried deleted, and markers left for a later window.
	MarkerDeletedCount  int
	CarriedDeletedCount int
	MarkerLeftCount     int
	// A window was opened, and closed with done at Done.
	Opened bool
	Closed bool
	Done   uint64
	// Why the run collected nothing, empty when it ran.
	Skipped string
}

// See the file header.
type MarkerCollector struct {
	host        *sidecar.ServiceHost
	deps        *MarkerCollectorDeps
	settings    *MarkerCollectorSettings
	evsSettings *EvsSettings
	log         sidecar.Logger
	clock       sidecar.Clock
	heads       *HeadStore
	holds       *HoldCache
	repos       *RepoCache
	records     *RecordCache
	// finds a scanned version's record once evacuation emptied its batch (QD-664)
	locator    *RecordLocator
	logPages   *LogPageCache
	priceTable *PriceTable
}

// A collector on host, which needs Blobs and a write budget. Its ClockCheck is read before every write, nil reading
// as unsure.
func NewMarkerCollector(host *sidecar.ServiceHost, deps *MarkerCollectorDeps) (*MarkerCollector, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return nil, errors.New("evs's marker collection needs a host with Blobs and a write budget")
	}
	if deps == nil {
		deps = &MarkerCollectorDeps{}
	}
	evsSettings := deps.EvsSettings
	if evsSettings == nil {
		evsSettings = DefaultEvsSettings()
	}
	if err := evsSettings.Validate(); err != nil {
		return nil, err
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultMarkerCollectorSettings()
	}
	if err := settings.Validate(evsSettings); err != nil {
		return nil, err
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	priceTable, err := DefaultPriceTable(evsSettings.PriceBlockByteCount)
	if err != nil {
		return nil, err
	}
	clock := host.ClockOrReal()
	holds := deps.Holds
	if holds == nil {
		holds = NewHoldCache(host.Blobs, clock, nil)
	}
	return &MarkerCollector{
		host:        host,
		deps:        deps,
		settings:    settings,
		evsSettings: evsSettings,
		log:         log,
		clock:       clock,
		heads:       NewHeadStore(clock, host.ClockCheck, nil, evsSettings, log),
		holds:       holds,
		repos:       NewRepoCache(clock, evsSettings),
		records:     NewRecordCache(evsSettings),
		locator:     NewRecordLocator(host.Blobs, nil),
		logPages:    NewLogPageCache(evsSettings),
		priceTable:  priceTable,
	}, nil
}

// The settings in force.
func (self *MarkerCollector) Settings() *MarkerCollectorSettings {
	return self.settings
}

func (self *MarkerCollector) clockSure() bool {
	return self.host.ClockCheck != nil && self.host.ClockCheck.Sure()
}

func (self *MarkerCollector) step(name string, key string) error {
	testHookBarrier(name, key)
	if self.deps.atStep != nil {
		return self.deps.atStep(name, key)
	}
	return nil
}

// Whether head may hold markers to collect: written, listing no source, and folded past done by more than a base
// range. What the nightly pass asks of each recently written head before it queues the ref.
func MarkerCollectionDue(head *protocol.EvsHead) bool {
	if head == nil || head.GetVersion() == 0 || 0 < len(head.GetPathEpoch().GetSources()) {
		return false
	}
	return head.GetCollect().GetDone()+evsCollectBaseRange < head.GetFoldedThrough()
}

// One removal a window may collect.
type collectRemoval struct {
	tokenPath sidecar.EvsTokenPath
	version   uint64
}

// One entry a window reads: a removal's own, or one below it, in the epoch it was listed in.
type collectCandidate struct {
	tokenPath sidecar.EvsTokenPath
	epoch     uint64
	removal   uint64
}

// repo/ or hold/, reread as a write issued, let it go no further.
var errCollectRepoStops = errors.New("evs marker collection repo stops")

// Whether repo/ shows active or deleted in a format this instance reads: why not, empty when it does.
func (self *MarkerCollector) repoWhy(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (string, *protocol.EvsRepoObject) {
	read, err := self.repos.Read(ctx, cluster, repoId)
	if err != nil {
		return "repo/ unread", nil
	}
	if !read.FormatWithin(self.evsSettings.InstanceFormat) {
		return "repo/ format", nil
	}
	switch read.Object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_ACTIVE, protocol.EvsRepoState_EVS_REPO_DELETED:
		return "", read.Object
	}
	return "repo/ state", nil
}

// A P2 grant of rank GC, unfunded, for one write on clusterId, rereading repo/ as it issues.
func (self *MarkerCollector) acquire(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, operation WriteOperation) (sidecar.WriteGrant, error) {
	byteCount, err := self.priceTable.Price(operation)
	if err != nil {
		return nil, err
	}
	return self.host.Budget.AcquireP2(ctx, cluster.ClusterId(), &sidecar.WriteP2Work{
		Rank:      sidecar.WriteP2RankGc,
		Due:       self.clock.Now(),
		ByteCount: byteCount,
		Recheck: func(ctx context.Context) error {
			if why, _ := self.repoWhy(ctx, cluster, repoId); why != "" {
				return fmt.Errorf("%w: %s", errCollectRepoStops, why)
			}
			return nil
		},
	})
}

// One run on one ref: see the file header. A nil error with Skipped set means a gate kept every marker.
func (self *MarkerCollector) Collect(ctx context.Context, clusterId string, repoId sidecar.Id, refId sidecar.Id) (*MarkerCollectResult, error) {
	result := &MarkerCollectResult{}
	cluster, err := self.host.Blobs.Cluster(clusterId)
	if err != nil {
		return result, err
	}
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		return result, err
	}
	switch {
	case !self.clockSure():
		result.Skipped = "clock unsure"
		return result, nil
	case !cluster.SettlePassed() || !segmentCluster.SettlePassed():
		// DELETE is unconditional, so no window opens on a build that has not passed FS-114
		result.Skipped = "settle not passed"
		return result, nil
	}
	if why, _ := self.repoWhy(ctx, cluster, repoId); why != "" {
		result.Skipped = why
		return result, nil
	}
	head, err := self.heads.ReadCluster(ctx, cluster, repoId, refId)
	if err != nil {
		return result, err
	}
	if !MarkerCollectionDue(head.Head) {
		result.Skipped = "nothing due"
		return result, nil
	}
	collect := head.Head.GetCollect()
	if untilMs := collect.GetUntilMs(); untilMs != 0 && self.clock.Now().Before(time.UnixMilli(untilMs).Add(self.settings.ReopenMargin)) {
		result.Skipped = "window open"
		return result, nil
	}

	removals, scannedThrough, err := self.removals(ctx, cluster, repoId, refId, head.Head, result)
	if err != nil {
		return result, err
	}
	if len(removals) == 0 {
		if self.settings.DoneAdvanceVersionCount <= scannedThrough-collect.GetDone() {
			closed, err := self.writeCollect(ctx, cluster, repoId, refId, head, func(next *protocol.EvsCollect) {
				next.Done = max(next.GetDone(), scannedThrough)
			})
			if err != nil {
				return result, err
			}
			result.Closed, result.Done = true, closed.Head.GetCollect().GetDone()
		}
		return result, nil
	}
	candidates, through, err := self.candidates(ctx, cluster, repoId, refId, EvsHeadCurrentEpoch(head.Head), removals)
	if err != nil {
		return result, err
	}
	result.EntryCount = len(candidates)

	// open
	if !self.clockSure() {
		result.Skipped = "clock unsure"
		return result, nil
	}
	if err := self.step(BarrierCollectOpenBefore, barrierRefKey(repoId, refId)); err != nil {
		return result, err
	}
	untilMs := self.clock.Now().Add(self.settings.Window).UnixMilli()
	opened, err := self.writeCollect(ctx, cluster, repoId, refId, head, func(next *protocol.EvsCollect) {
		next.Through = through
		next.UntilMs = untilMs
	})
	if err != nil {
		return result, err
	}
	if 0 < len(opened.Head.GetPathEpoch().GetSources()) || EvsHeadCurrentEpoch(opened.Head) != EvsHeadCurrentEpoch(head.Head) {
		// a path epoch began between the read and the open: the window lapses with nothing deleted
		result.Skipped = "path epoch moved"
		return result, nil
	}
	result.Opened = true
	if err := self.step(BarrierCollectOpenAfter, barrierRefKey(repoId, refId)); err != nil {
		return result, err
	}

	// wait out every fold write planned on an older head
	if self.deps.wait != nil {
		self.deps.wait(self.settings.OpenWait)
	} else {
		select {
		case <-self.clock.After(self.settings.OpenWait):
		case <-ctx.Done():
			return result, ctx.Err()
		}
	}

	oldestLeft, err := self.deleteMarkers(ctx, cluster, segmentCluster, repoId, refId, opened.Head.GetFoldedThrough(), candidates, through, untilMs, result)
	if err != nil {
		return result, err
	}

	// close: done to through, or below the oldest marker left
	done := through
	if oldestLeft != 0 {
		done = oldestLeft - 1
	}
	if !self.clockSure() {
		result.Skipped = "clock unsure"
		return result, nil
	}
	if err := self.step(BarrierCollectCloseBefore, barrierRefKey(repoId, refId)); err != nil {
		return result, err
	}
	reread, err := self.heads.ReadCluster(ctx, cluster, repoId, refId)
	if err != nil {
		return result, err
	}
	closed, err := self.writeCollect(ctx, cluster, repoId, refId, reread, func(next *protocol.EvsCollect) {
		next.Done = max(next.GetDone(), done)
	})
	if err != nil {
		return result, err
	}
	result.Closed, result.Done = true, closed.Head.GetCollect().GetDone()
	if err := self.step(BarrierCollectCloseAfter, barrierRefKey(repoId, refId)); err != nil {
		return result, err
	}
	return result, nil
}

// One fence-only head CAS changing collect as change says: the fence raised, no version, no fence_ms. A 412 rereads
// and tries again, at most FenceRetryCount times; an unknown outcome rereads and finds whether it landed.
func (self *MarkerCollector) writeCollect(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, prior *EvsStoredHead, change func(next *protocol.EvsCollect)) (*EvsStoredHead, error) {
	for attempt := 0; attempt <= self.evsSettings.FenceRetryCount; attempt += 1 {
		if !self.clockSure() {
			return nil, ErrEvsClockUnsure
		}
		if prior.Absent() || prior.Head.GetVersion() == 0 {
			return nil, fmt.Errorf("%w: the head is gone", ErrEvsHeadRule)
		}
		next := CloneEvsHead(prior.Head)
		next.Fence = prior.Head.GetFence() + 1
		collect := &protocol.EvsCollect{}
		if prior.Head.GetCollect() != nil {
			collect = &protocol.EvsCollect{Done: prior.Head.GetCollect().GetDone(), Through: prior.Head.GetCollect().GetThrough(), UntilMs: prior.Head.GetCollect().GetUntilMs()}
		}
		change(collect)
		next.Collect = collect
		grant, err := self.acquire(ctx, cluster, repoId, WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(len(prior.Bytes)), Count: 1})
		if err != nil {
			return nil, err
		}
		written, err := self.heads.Commit(grant.Context(), cluster, repoId, refId, prior, next)
		grant.Close()
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			return written, nil
		case errors.Is(err, sidecar.ErrBlobPrecondition):
		case errors.As(err, &unknown):
			reread, readErr := self.heads.ReadCluster(ctx, cluster, repoId, refId)
			if readErr != nil {
				return nil, err
			}
			if !reread.Absent() && reread.Head.GetVersion() == next.GetVersion() && reread.Head.GetFence() == next.GetFence() &&
				reread.Head.GetCollect().GetUntilMs() == collect.GetUntilMs() && reread.Head.GetCollect().GetDone() == collect.GetDone() {
				return reread, nil
			}
			prior = reread
			continue
		default:
			return nil, err
		}
		prior, err = self.heads.ReadCluster(ctx, cluster, repoId, refId)
		if err != nil {
			return nil, err
		}
	}
	return nil, ErrEvsHeadBusy
}

// The removals of versions (done, folded_through - 64] in the head's current epoch, at most ScanVersionCount
// versions read, and the last version read.
func (self *MarkerCollector) removals(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, head *protocol.EvsHead, result *MarkerCollectResult) ([]*collectRemoval, uint64, error) {
	done := head.GetCollect().GetDone()
	last := head.GetFoldedThrough() - evsCollectBaseRange
	last = min(last, done+self.settings.ScanVersionCount)
	window, err := EvsHeadWindow(head)
	if err != nil {
		return nil, done, fmt.Errorf("%w: %v", ErrEvsHeadInvalid, err)
	}
	windowFirst := EvsHeadWindowFirstVersion(head)
	epoch := EvsHeadCurrentEpoch(head)
	source := NewRecordPushSource(self.records, self.locator, cluster, repoId, refId)
	removals := []*collectRemoval{}
	for version := done + 1; version <= last; version += 1 {
		var entry *sidecar.EvsWindowEntry
		if windowFirst <= version && version-windowFirst < uint64(len(window)) {
			entry = window[version-windowFirst]
		} else {
			page, err := ReadLogPage(ctx, self.logPages, cluster, repoId, refId, EvsLogPageOf(version))
			if err != nil {
				return nil, version - 1, err
			}
			pageEntry, _, ok := page.At(version)
			if !ok {
				return nil, version - 1, fmt.Errorf("%w: log page %d lacks version %d", ErrEvsHeadInvalid, EvsLogPageOf(version), version)
			}
			entry = pageEntry
		}
		statement, changes, err := source.allChangesAt(ctx, version, entry)
		if err != nil {
			return nil, version - 1, err
		}
		result.ScannedVersionCount += 1
		if statement.Push.GetPathEpoch() != epoch {
			continue
		}
		for _, change := range changes {
			if change.Removes() {
				removals = append(removals, &collectRemoval{tokenPath: change.TokenPath, version: version})
			}
		}
	}
	result.RemovalCount = len(removals)
	return removals, last, nil
}

// The entries a window reads, oldest removal first, at most WindowEntryCount, and the newest removal they reach,
// which is the window's through: each removal's own entry, then every entry below it by a LIST.
func (self *MarkerCollector) candidates(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, epoch uint64, removals []*collectRemoval) ([]*collectCandidate, uint64, error) {
	epochPrefix := IndexEpochPrefix(repoId, refId, epoch)
	candidates := []*collectCandidate{}
	through := uint64(0)
	for _, removal := range removals {
		removalCandidates := []*collectCandidate{{tokenPath: removal.tokenPath, epoch: epoch, removal: removal.version}}
		keyPrefix := IndexChildrenPrefix(repoId, refId, epoch, removal.tokenPath)
		startAfter := ""
		for {
			objects, more, err := cluster.List(ctx, keyPrefix, startAfter, self.settings.ListLimit)
			if err != nil {
				return nil, 0, err
			}
			for _, object := range objects {
				startAfter = object.Key
				if !strings.HasSuffix(object.Key, indexEntryKeySuffix) {
					continue
				}
				tokenPath, err := IndexEntryTokenPath(epochPrefix, object.Key)
				if err != nil {
					continue
				}
				removalCandidates = append(removalCandidates, &collectCandidate{tokenPath: tokenPath, epoch: epoch, removal: removal.version})
			}
			if !more || len(objects) == 0 {
				break
			}
		}
		if self.settings.WindowEntryCount < len(candidates)+len(removalCandidates) && 0 < len(candidates) {
			// a removal is collected whole or not at all in a window, so done can pass it
			break
		}
		candidates = append(candidates, removalCandidates...)
		through = removal.version
	}
	return candidates, through, nil
}

// The window's deletes: see the file header. The removal version of the oldest marker left, zero when none was.
func (self *MarkerCollector) deleteMarkers(
	ctx context.Context,
	cluster sidecar.BlobCluster,
	segmentCluster sidecar.BlobCluster,
	repoId sidecar.Id,
	refId sidecar.Id,
	foldedThrough uint64,
	candidates []*collectCandidate,
	through uint64,
	untilMs int64,
	result *MarkerCollectResult,
) (uint64, error) {
	oldestLeft := uint64(0)
	leave := func(removal uint64) {
		result.MarkerLeftCount += 1
		if oldestLeft == 0 || removal < oldestLeft {
			oldestLeft = removal
		}
	}
	deadline := time.UnixMilli(untilMs).Add(-self.settings.DeleteMargin)
	// each DELETE is cancelled at once if the clock turns unsure
	unsure := self.host.ClockCheck.UnsureChannel()
	deleteCtx, cancel := context.WithCancel(sidecar.WithBlobDeadline(ctx, deadline))
	defer cancel()
	go func() {
		select {
		case <-unsure:
			cancel()
		case <-deleteCtx.Done():
		}
	}()
	barrierKey := barrierRefKey(repoId, refId)
	for i, candidate := range candidates {
		if !self.clockSure() || !self.clock.Now().Before(deadline) || deleteCtx.Err() != nil {
			// the window ends here: what is left waits for the next
			for _, rest := range candidates[i:] {
				leave(rest.removal)
			}
			return oldestLeft, nil
		}
		read, err := ReadEntry(ctx, cluster, repoId, refId, candidate.epoch, candidate.tokenPath, foldedThrough)
		if err != nil {
			leave(candidate.removal)
			continue
		}
		marker := read.Entry.GetMarker()
		if read.Absent() || marker == nil || through < marker.GetRemovalVersion() {
			// collected, re-created, or a newer removal's: nothing of this window
			continue
		}
		why, object := self.repoWhy(ctx, cluster, repoId)
		if why != "" {
			leave(candidate.removal)
			continue
		}
		carried := 0 < len(marker.GetSegmentIds()) || 0 < len(marker.GetSlotIds())
		if carried {
			cover, err := self.holds.CoveringRepo(ctx, repoId, object)
			if err != nil || cover.Covered() {
				// a hold keeps what it carries, and the marker with it
				leave(marker.GetRemovalVersion())
				continue
			}
		}
		if err := self.step(BarrierCollectDeleteBefore, barrierKey); err != nil {
			return oldestLeft, err
		}
		left := false
		for _, segmentId := range marker.GetSegmentIds() {
			if len(segmentId) != 32 {
				left = true
				continue
			}
			err := segmentCluster.Delete(deleteCtx, SegmentKey(repoId, [32]byte(segmentId)))
			if err != nil {
				left = true
				continue
			}
			result.CarriedDeletedCount += 1
		}
		for _, slotIdBytes := range marker.GetSlotIds() {
			slotId, err := sidecar.IdFromBytes(slotIdBytes)
			if err != nil {
				left = true
				continue
			}
			if err := self.deleteMetadata(deleteCtx, cluster, repoId, SlotKey(repoId, slotId)); err != nil {
				left = true
				continue
			}
			result.CarriedDeletedCount += 1
		}
		if left {
			leave(marker.GetRemovalVersion())
		} else if err := self.deleteMetadata(deleteCtx, cluster, repoId, IndexEntryKey(repoId, refId, read.Epoch, candidate.tokenPath)); err != nil {
			// held, unknown, past the deadline or cancelled: read again in a later window
			leave(marker.GetRemovalVersion())
		} else {
			result.MarkerDeletedCount += 1
		}
		if err := self.step(BarrierCollectDeleteAfter, barrierKey); err != nil {
			return oldestLeft, err
		}
	}
	return oldestLeft, nil
}

// One DELETE on the metadata cluster, unconditional (§11.3), unfunded P2 of rank GC. A 404 is done.
func (self *MarkerCollector) deleteMetadata(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, key string) error {
	grant, err := self.acquire(ctx, cluster, repoId, WriteOperation{Kind: WriteOperationDelete, Count: 1})
	if err != nil {
		return err
	}
	defer grant.Close()
	return cluster.Delete(grant.Context(), key)
}

// The job's args for one ref's run: the cluster and the ids, none of them content (I-13).
func EvsCollectArgs(clusterId string, repoId sidecar.Id, refId sidecar.Id) []byte {
	return []byte(clusterId + "\n" + sidecar.EvsKeyId(repoId) + "\n" + sidecar.EvsKeyId(refId))
}

// The args of one ref's run, and false for bytes of another shape.
func ParseEvsCollectArgs(args []byte) (clusterId string, repoId sidecar.Id, refId sidecar.Id, ok bool) {
	fields := strings.Split(string(args), "\n")
	if len(fields) != 3 || fields[0] == "" {
		return "", sidecar.Id{}, sidecar.Id{}, false
	}
	repoId, err := sidecar.ParseId(fields[1])
	if err != nil || sidecar.EvsKeyId(repoId) != fields[1] {
		return "", sidecar.Id{}, sidecar.Id{}, false
	}
	refId, err = sidecar.ParseId(fields[2])
	if err != nil || sidecar.EvsKeyId(refId) != fields[2] {
		return "", sidecar.Id{}, sidecar.Id{}, false
	}
	return fields[0], repoId, refId, true
}

// One ref's run in the queue, once-keyed by the ref, so the nightly pass's queueing of a ref already queued coalesces.
func EvsCollectTaskRequest(clusterId string, repoId sidecar.Id, refId sidecar.Id, runAt time.Time, settings *MarkerCollectorSettings) *sidecar.TaskRequest {
	if settings == nil {
		settings = DefaultMarkerCollectorSettings()
	}
	return &sidecar.TaskRequest{
		Name:    EvsCollectTaskName,
		OnceKey: EvsCollectTaskName + "." + clusterId + "." + barrierRefKey(repoId, refId),
		Args:    EvsCollectArgs(clusterId, repoId, refId),
		RunAt:   runAt,
		MaxTime: settings.RunMaxTime,
	}
}

// One run of evs.collect on the ref its args name.
func RunMarkerCollection(ctx context.Context, host *sidecar.ServiceHost, deps *MarkerCollectorDeps, args []byte) (*MarkerCollectResult, error) {
	clusterId, repoId, refId, ok := ParseEvsCollectArgs(args)
	if !ok {
		return nil, fmt.Errorf("%w: evs.collect args", ErrMarkerCollectorSettings)
	}
	if host == nil || host.Blobs == nil || !slices.Contains(host.Blobs.MetadataClusterIds(), clusterId) {
		return nil, fmt.Errorf("%w: evs.collect for a cluster this process does not hold", sidecar.ErrBlobClusterUnknown)
	}
	collector, err := NewMarkerCollector(host, deps)
	if err != nil {
		return nil, err
	}
	return collector.Collect(ctx, clusterId, repoId, refId)
}
