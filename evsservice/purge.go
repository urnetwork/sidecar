// The versionless purge, its committing half (§11.13's purge, who, holds and budget rows; R-EVS-20, D-EVS-37, I-EVS-9,
// FI-16; EVSB-M10-01; DESIGN-DETAILS 2.7's note). A versionless version V of path X is replaced at the first committed
// version u of X's ref that writes or removes X, and u's record lists what V leaves (PurgeCandidates, EVS2-M10-04).
// The evs process that commits u, once its step-7 PUT answers 200 or a reread shows u committed, hands that list to
// its Purger (PurgeSink, which EVS2-M10-06's step 7 calls); a refused or unknown push hands nothing (I-EVS-2), and a
// marked list is the sweep's (sweep.go). Then, in memory:
//
//	wait     60 s, the readers' allowance, on this process's clock, which must stay sure from the certainty to each
//	         DELETE: a clock unsure at any point, or a candidate not reached within 10 min, is left to the sweep
//	gates    nothing deletes while §19.11's purge mode is observe, which logs each candidate, nor on a cluster whose
//	         build has not passed §19.6's settle cases (SettlePassed)
//	reread   X's newest version from the cluster (PurgeNewestReader) and the network's hold/ objects, cached at most
//	         5 s and read again before each DELETE: a candidate the newest version names stays, and a hold covering
//	         the repo keeps each candidate that existed at its placement, an uploaded segment or a slot by its
//	         LastModified (a HEAD, only then), a staged one by its version's time_ms less the statement's lead
//	delete   kind-5 segments at seg/ on the segment cluster, which spend no NVMe budget, and slots on the repo's
//	         metadata cluster as funded P2 (rank GC), paid at u's admission through PricePush; a staged candidate
//	         whose version is under 23 h old is left to its batch's evacuation, an older one deleted at seg/; at most
//	         200 deletes a second and 1M ids queued
//	report   each kind-5 segment at seg/ it deletes, or that only a hold now keeps, as a negative stored-byte delta
//	         at its stored size; slots, outside §20.7's stored count, report nothing
//
// Its DELETEs stay unconditional, with no x-ur-if-unmodified-ms: a kind-5 segment is cited only by its own path's
// next version on its own ref (I-EVS-10), so no write on another head can make one reachable again, and FI-30, which
// the 60 s allowance leans on, holds for DELETEs (DESIGN-DETAILS 2.3). A held key or an unknown outcome leaves the
// candidate to the sweep, never counted as deleted or reported as freed. A stopping process drains its queue for up
// to 70 s; what is left is the sweep's.
//
// Safe for concurrent use: Certain only queues, and one goroutine deletes.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.13's floor, which no setting passes: the readers' allowance.
const evsPurgeMinAllowance = 60 * time.Second

// The series the purge exports, with no network or repo label (D-OPS-8; §19.8's versionless row).
const (
	versionlessPurgedBytesMetricName = "urnetwork_evs_versionless_purged_bytes_total"
	versionlessPurgeQueueMetricName  = "urnetwork_evs_versionless_purge_queue"
	versionlessPurgedByCommit        = "commit"
	versionlessPurgedBySweep         = "sweep"
)

// Settings that break §11.13's floors.
var ErrPurgerSettings = errors.New("evs purger settings invalid")

// What the committing process hands the purge once u's commit is certain.
type PurgeCommit struct {
	// The repo's metadata cluster, which holds its slots and heads.
	ClusterId string
	RepoId    sidecar.Id
	RefId     sidecar.Id
	// The repo's network, whose holds keep and whose stored bytes fall: repo/'s network_id.
	NetworkId sidecar.Id
	// u: its push, the ref version it committed at, and the path epoch its token paths are in.
	PushId    sidecar.Id
	Version   uint64
	PathEpoch uint64
	// u's record's list (PurgeCandidates). A marked list lists nothing and is the sweep's.
	List *protocol.EvsPurgeList
	// What step 4 read of each version the list names (a part's at part time): its time_ms decides a staged
	// candidate's way and a hold's keep. A candidate whose version is missing here is left to the sweep.
	Replaced []*PurgeReplaced
}

// The seam step 7 hands certain commits to (CONTRACTS.md C-14: EVS2-M10-06 calls it, EVSB-M10-01's Purger meets it).
// A nil sink queues nothing, which is safe: the sweep takes every list.
type PurgeSink interface {
	// Takes commit's candidates once u's commit is certain: its step-7 PUT answered 200, or a reread or 5a retry
	// showed u committed. Never blocks and never fails the push: what it cannot queue is the sweep's.
	Certain(commit *PurgeCommit)
}

// What X's newest committed version names, read from the cluster at the reread (§11.13's who row).
type PurgeNewestReader interface {
	// The ids X's newest committed version names (its locators' segments and its slots), empty when X stands
	// removed or was never written, at the ref's head now. An error leaves X's candidates to the sweep: the head
	// unread or held, a path epoch other than pathEpoch, or sources standing.
	NewestNames(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, pathEpoch uint64, tokenPath sidecar.EvsTokenPath) (map[string]bool, error)
}

// Tunables of the purge (§11.13's who row; §22.8 tunes the rate and the queue).
type PurgerSettings struct {
	// The readers' allowance from certainty to the first DELETE, on this process's checked clock: 60 s, and
	// never less.
	Allowance time.Duration
	// DELETEs a second this process issues at most: 200. Positive.
	DeleteRate int
	// Candidate ids queued at most: 1M. A commit past it is the sweep's. Positive.
	QueueIdCount int
	// How long a stopping process drains its queue: 70 s.
	DrainTimeout time.Duration
	// A candidate not deleted within this of its certainty is the sweep's: 10 min.
	GiveUpAge time.Duration
	// A staged candidate whose version's time_ms is under this old is left to its batch's evacuation: 23 h.
	StagedEvacuationAge time.Duration
	// How far a statement's time_ms may run ahead of evs's clock (§11.8's TIME_AHEAD), which a hold's keep of a
	// staged candidate allows for, so a batch that may predate the hold keeps its content: 10 min.
	StatementAheadBound time.Duration
}

func DefaultPurgerSettings() *PurgerSettings {
	return &PurgerSettings{
		Allowance:           evsPurgeMinAllowance,
		DeleteRate:          200,
		QueueIdCount:        1000000,
		DrainTimeout:        70 * time.Second,
		GiveUpAge:           10 * time.Minute,
		StagedEvacuationAge: 23 * time.Hour,
		StatementAheadBound: 10 * time.Minute,
	}
}

// ErrPurgerSettings for a value past §11.13's floors or one the purge cannot work with.
func (self *PurgerSettings) Validate() error {
	switch {
	case self.Allowance < evsPurgeMinAllowance:
		return fmt.Errorf("%w: an allowance of %s, under §11.13's %s", ErrPurgerSettings, self.Allowance, evsPurgeMinAllowance)
	case self.GiveUpAge <= self.Allowance:
		return fmt.Errorf("%w: a give-up age of %s, inside the allowance", ErrPurgerSettings, self.GiveUpAge)
	case self.DeleteRate <= 0 || self.QueueIdCount <= 0 || self.DrainTimeout < 0 || self.StagedEvacuationAge <= 0 || self.StatementAheadBound < 0:
		return fmt.Errorf("%w: a bound that is not positive", ErrPurgerSettings)
	}
	return nil
}

// What a Purger runs on beyond its host.
type PurgerDeps struct {
	// §19.11's purge mode. nil reads observe: nothing deletes on a gate nobody set.
	Format2 Format2Gate
	// X's newest version at the reread. nil leaves every candidate to the sweep.
	Newest PurgeNewestReader
	// The holds every DELETE reads. nil reads hold/ through a HoldCache of the purge's own.
	Holds *HoldCache
	// The process's usage producer, which takes each freed segment's negative delta. nil reports nothing and alarms,
	// the nightly count correcting the drift.
	Usage *UsageBatcher
	// nil: the defaults.
	Settings *PurgerSettings
	// Alarms, and observe mode's candidates. nil discards.
	Log sidecar.Logger
	// a test's: called at each barrier, an error stopping the item there as a kill would
	atStep func(name string, key string) error
	// a test's: stands in for the rate's wait, on a clock the test moves
	wait func(wait time.Duration)
}

// What the purge did since it started, in counts with no id (I-13).
type PurgeStats struct {
	QueuedIdCount   int
	DeletedCount    int
	AbsentCount     int
	NamedCount      int
	HeldCount       int
	EvacuationCount int
	ObservedCount   int
	// ids left to the sweep: past the queue, the clock unsure, past the give-up age, a gate closed, a reread or a
	// DELETE that failed
	SweepCount   int
	FreedByteCount int64
}

// One certain commit in the queue.
type purgeItem struct {
	commit      *PurgeCommit
	certainTime time.Time
	// closed once the clock turned unsure after the certainty
	unsure  <-chan struct{}
	idCount int
	// a test stopped it at a barrier, as a kill would: nothing more of it issues
	stopped bool
}

// See the file header.
type Purger struct {
	ctx      context.Context
	cancel   context.CancelFunc
	host     *sidecar.ServiceHost
	deps     *PurgerDeps
	settings *PurgerSettings
	clock    sidecar.Clock
	log      sidecar.Logger
	format2  Format2Gate
	holds    *HoldCache
	// the host's Blobs, its metadata writes held to the budget
	blobs      sidecar.BlobStore
	priceTable *PriceTable

	purgedCounter sidecar.MetricsCounter
	queueGauge    sidecar.MetricsGauge

	stateLock sync.Mutex
	queue     []*purgeItem
	idCount   int
	// closed and replaced on each change to the queue
	changed  chan struct{}
	draining bool
	stats    PurgeStats
	// when the last DELETE issued, for the rate
	lastDelete time.Time
	done       chan struct{}
}

// A purge on host, which needs Blobs and a write budget, started at once. Close or Drain ends it.
func NewPurger(ctx context.Context, host *sidecar.ServiceHost, deps *PurgerDeps) (*Purger, error) {
	self, err := newPurger(ctx, host, deps)
	if err != nil {
		return nil, err
	}
	go self.run()
	return self, nil
}

// NewPurger without its goroutine, which a test drives through runOnce.
func newPurger(ctx context.Context, host *sidecar.ServiceHost, deps *PurgerDeps) (*Purger, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return nil, errors.New("evs's purge needs a host with Blobs and a write budget")
	}
	if deps == nil {
		deps = &PurgerDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultPurgerSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	format2 := deps.Format2
	if format2 == nil {
		format2 = ClosedFormat2Gate{}
	}
	clock := host.ClockOrReal()
	holds := deps.Holds
	if holds == nil {
		holds = NewHoldCache(host.Blobs, clock, nil)
	}
	priceTable, err := DefaultPriceTable(DefaultEvsSettings().PriceBlockByteCount)
	if err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &Purger{
		ctx:        cancelCtx,
		cancel:     cancel,
		host:       host,
		deps:       deps,
		settings:   settings,
		clock:      clock,
		log:        log,
		format2:    format2,
		holds:      holds,
		blobs:      NewBudgetedBlobs(host.Blobs),
		priceTable: priceTable,
		changed:    make(chan struct{}),
		done:       make(chan struct{}),
	}
	if host.Metrics != nil {
		self.purgedCounter = host.Metrics.Counter(versionlessPurgedBytesMetricName, "Replaced versionless content deleted, stored bytes, by who deleted it.", "by")
		self.queueGauge = host.Metrics.Gauge(versionlessPurgeQueueMetricName, "Purge candidate ids this process holds in memory.")
	}
	return self, nil
}

// Ends the purge at once; what is queued is the sweep's.
func (self *Purger) Close() {
	self.cancel()
}

// Takes no more and deletes what falls due within DrainTimeout, then ends: what a stopping process does. The rest is
// the sweep's.
func (self *Purger) Drain() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.draining = true
		self.notifyWithLock()
	}()
	select {
	case <-self.done:
	case <-self.clock.After(self.settings.DrainTimeout):
	case <-self.ctx.Done():
	}
	self.cancel()
}

// What the purge has done.
func (self *Purger) Stats() PurgeStats {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.stats
}

// Ids queued now.
func (self *Purger) QueuedIdCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.idCount
}

func (self *Purger) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

// A barrier of item's: a test's error stops the item there, as a kill would.
func (self *Purger) step(item *purgeItem, name string, key string) bool {
	testHookBarrier(name, key)
	if self.deps.atStep != nil && self.deps.atStep(name, key) != nil {
		item.stopped = true
		return false
	}
	return true
}

// The ids a list names.
func purgeListIdCount(list *protocol.EvsPurgeList) int {
	idCount := 0
	for _, candidate := range list.GetCandidates() {
		idCount += len(candidate.GetSegmentIds()) + len(candidate.GetStagedSegmentIds()) + len(candidate.GetSlotIds())
	}
	return idCount
}

// See PurgeSink. A list that is marked, or empty, queues nothing; a clock unsure at the certainty, a draining
// process or a full queue leaves the list to the sweep.
func (self *Purger) Certain(commit *PurgeCommit) {
	if commit == nil || commit.List == nil || commit.List.GetMarked() {
		return
	}
	idCount := purgeListIdCount(commit.List)
	if idCount == 0 {
		return
	}
	clockCheck := self.host.ClockCheck
	var unsure <-chan struct{}
	sure := false
	if clockCheck != nil {
		// taken before Sure, so a turn between the two reads as unsure
		unsure = clockCheck.UnsureChannel()
		sure = clockCheck.Sure()
	}
	certainTime := self.clock.Now()
	refKey := barrierRefKey(commit.RepoId, commit.RefId)
	queued := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !sure || self.draining || self.ctx.Err() != nil || self.settings.QueueIdCount < self.idCount+idCount {
			self.stats.SweepCount += idCount
			return false
		}
		self.queue = append(self.queue, &purgeItem{commit: commit, certainTime: certainTime, unsure: unsure, idCount: idCount})
		self.idCount += idCount
		self.stats.QueuedIdCount += idCount
		self.notifyWithLock()
		return true
	}()
	if self.queueGauge != nil {
		self.queueGauge.Set(float64(self.QueuedIdCount()))
	}
	if !queued {
		if self.log.V(1).Enabled() {
			self.log.Infof("[evs] purge: %d candidate ids of %s left to the sweep at their certainty", idCount, refKey)
		}
		return
	}
	testHookBarrier(BarrierPurgeCertain, refKey)
}

// Deletes each item as it falls due, until the purge ends or, draining, its queue empties.
func (self *Purger) run() {
	defer close(self.done)
	for {
		item, wait, changed, stop := self.next()
		if stop {
			return
		}
		if item == nil {
			select {
			case <-self.ctx.Done():
				return
			case <-changed:
			case <-self.clock.After(wait):
			}
			continue
		}
		self.purge(item)
	}
}

// The front item once due, else how long until it is and a channel that closes on the next change. stop once the
// purge ends, or is draining with nothing queued.
func (self *Purger) next() (item *purgeItem, wait time.Duration, changed chan struct{}, stop bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.ctx.Err() != nil {
		return nil, 0, nil, true
	}
	if len(self.queue) == 0 {
		if self.draining {
			return nil, 0, nil, true
		}
		// nothing queued: wait for a change, the hour standing in for forever
		return nil, time.Hour, self.changed, false
	}
	front := self.queue[0]
	due := front.certainTime.Add(self.settings.Allowance)
	if now := self.clock.Now(); now.Before(due) {
		return nil, due.Sub(now), self.changed, false
	}
	self.queue = self.queue[1:]
	return front, 0, nil, false
}

// One item's candidates in turn, and its ids out of the queue's count however it ended.
func (self *Purger) purge(item *purgeItem) {
	left := self.purgeItem(item)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.idCount -= item.idCount
		self.stats.SweepCount += left
	}()
	if self.queueGauge != nil {
		self.queueGauge.Set(float64(self.QueuedIdCount()))
	}
}

// Whether the item's clock has stayed sure since its certainty, and is still.
func (self *Purger) clockSure(item *purgeItem) bool {
	select {
	case <-item.unsure:
		return false
	default:
	}
	return self.host.ClockCheck != nil && self.host.ClockCheck.Sure()
}

func (self *Purger) count(update func(stats *PurgeStats)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	update(&self.stats)
}

// The item's DELETEs: see the file header. The ids left to the sweep come back.
func (self *Purger) purgeItem(item *purgeItem) int {
	commit := item.commit
	refKey := barrierRefKey(commit.RepoId, commit.RefId)
	leftAll := func(why string) int {
		if self.log.V(1).Enabled() {
			self.log.Infof("[evs] purge: %d candidate ids of %s left to the sweep: %s", item.idCount, refKey, why)
		}
		return item.idCount
	}
	if self.settings.GiveUpAge <= self.clock.Now().Sub(item.certainTime) {
		return leftAll("past the give-up age")
	}
	if !self.clockSure(item) {
		return leftAll("the clock unsure")
	}
	if self.format2.PurgeMode() != sidecar.Format2On {
		// D-TEST-12's observe mode: each candidate logged, nothing deleted; the turn-on pass deletes what it kept
		for _, candidate := range commit.List.GetCandidates() {
			self.log.Infof("[evs] purge observe: %s version %d leaves %d segments, %d staged, %d slots", refKey,
				candidate.GetReplacedVersion(), len(candidate.GetSegmentIds()), len(candidate.GetStagedSegmentIds()), len(candidate.GetSlotIds()))
		}
		self.count(func(stats *PurgeStats) { stats.ObservedCount += item.idCount })
		return 0
	}
	cluster, err := self.blobs.Cluster(commit.ClusterId)
	if err != nil {
		return leftAll("the metadata cluster unknown")
	}
	segmentCluster, err := self.blobs.SegmentCluster()
	if err != nil {
		return leftAll("no segment cluster")
	}
	if !cluster.SettlePassed() || !segmentCluster.SettlePassed() {
		// DELETE is unconditional on a build that has not passed §19.6's settle cases: nothing deletes
		return leftAll("a build that has not passed the settle cases")
	}
	if self.deps.Newest == nil {
		return leftAll("no newest reader")
	}

	replacedTimes := map[string]time.Time{}
	for _, replaced := range commit.Replaced {
		if replaced == nil || replaced.Version == nil {
			continue
		}
		replacedTimes[purgeReplacedKey(replaced.TokenPath.Components(), replaced.Version.GetVersion())] = time.UnixMilli(replaced.Version.GetTimeMs())
	}
	left := 0
	for i, candidate := range commit.List.GetCandidates() {
		ids := len(candidate.GetSegmentIds()) + len(candidate.GetStagedSegmentIds()) + len(candidate.GetSlotIds())
		if item.stopped || self.ctx.Err() != nil || !self.clockSure(item) || self.settings.GiveUpAge <= self.clock.Now().Sub(item.certainTime) {
			left += ids
			continue
		}
		tokenPath, err := sidecar.ParseEvsTokenPath(candidate.GetTokenPath())
		if err != nil {
			left += ids
			continue
		}
		versionTime, ok := replacedTimes[purgeReplacedKey(candidate.GetTokenPath(), candidate.GetReplacedVersion())]
		if !ok {
			left += ids
			continue
		}
		names, err := self.deps.Newest.NewestNames(self.ctx, cluster, commit.RepoId, commit.RefId, commit.PathEpoch, tokenPath)
		if err != nil {
			left += ids
			continue
		}
		left += self.purgeCandidate(item, i, cluster, segmentCluster, candidate, versionTime, names)
	}
	return left
}

// A key for a replaced version: its path's components and its version.
func purgeReplacedKey(components [][]byte, version uint64) string {
	key := fmt.Sprintf("%d", version)
	for _, component := range components {
		key += "/" + string(component)
	}
	return key
}

// One candidate's ids; those left to the sweep come back.
func (self *Purger) purgeCandidate(item *purgeItem, index int, cluster sidecar.BlobCluster, segmentCluster sidecar.BlobCluster,
	candidate *protocol.EvsPurgeCandidate, versionTime time.Time, names map[string]bool) int {
	commit := item.commit
	left := 0
	type purgeId struct {
		id     []byte
		staged bool
		slot   bool
	}
	ids := []*purgeId{}
	for _, id := range candidate.GetSegmentIds() {
		ids = append(ids, &purgeId{id: id})
	}
	for _, id := range candidate.GetStagedSegmentIds() {
		ids = append(ids, &purgeId{id: id, staged: true})
	}
	for _, id := range candidate.GetSlotIds() {
		ids = append(ids, &purgeId{id: id, slot: true})
	}
	for j, purgeId := range ids {
		if names[string(purgeId.id)] {
			// the path's newest version names it: it stays (FS-64's k+2)
			self.count(func(stats *PurgeStats) { stats.NamedCount += 1 })
			continue
		}
		if purgeId.staged && self.clock.Now().Sub(versionTime) < self.settings.StagedEvacuationAge {
			// still in its batch: its evacuation decides it (sweep.go's staged decisions)
			self.count(func(stats *PurgeStats) { stats.EvacuationCount += 1 })
			continue
		}
		if item.stopped || self.ctx.Err() != nil || !self.clockSure(item) || self.pace() != nil {
			left += len(ids) - j
			break
		}
		// hold/ again as each DELETE issues, cached at most 5 s: none issues after a hold's placement is read
		barrierKey := fmt.Sprintf("%s:%d:%d", barrierRefKey(commit.RepoId, commit.RefId), index, j)
		if !self.step(item, BarrierPurgeHoldsBefore, barrierKey) {
			left += len(ids) - j
			break
		}
		cover, err := self.holds.Covering(self.ctx, commit.NetworkId, commit.RepoId)
		if err != nil {
			cover = &sidecar.HoldCover{Unknown: true}
		}
		if !self.step(item, BarrierPurgeHoldsAfter, barrierKey) {
			left += len(ids) - j
			break
		}
		var outcome purgeOutcome
		if purgeId.slot {
			outcome = self.deleteSlot(item, cluster, purgeId.id, cover, barrierKey)
		} else {
			outcome = self.deleteSegment(item, segmentCluster, purgeId.id, purgeId.staged, versionTime, cover, barrierKey)
		}
		if outcome == purgeOutcomeLeft {
			left += 1
		}
		if item.stopped {
			// what the kill left: the sweep's
			left += len(ids) - j - 1
			break
		}
	}
	return left
}

// What one candidate's DELETE came to.
type purgeOutcome int

const (
	purgeOutcomeDeleted purgeOutcome = iota + 1
	purgeOutcomeAbsent
	purgeOutcomeHeld
	purgeOutcomeLeft
)

// Waits until the next DELETE may issue: DeleteRate a second.
func (self *Purger) pace() error {
	interval := time.Second / time.Duration(self.settings.DeleteRate)
	for {
		wait := time.Duration(0)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			now := self.clock.Now()
			if next := self.lastDelete.Add(interval); now.Before(next) {
				wait = next.Sub(now)
			} else {
				self.lastDelete = now
			}
		}()
		if wait == 0 {
			return nil
		}
		if self.deps.wait != nil {
			self.deps.wait(wait)
			continue
		}
		select {
		case <-self.ctx.Done():
			return self.ctx.Err()
		case <-self.clock.After(wait):
		}
	}
}

// Deletes every item due now, in turn, with no wait: what run does at each wake, for a test on a fake clock.
func (self *Purger) runDue() {
	for {
		item, _, _, stop := self.next()
		if stop || item == nil {
			return
		}
		self.purge(item)
	}
}

// A kind-5 segment at seg/: a HEAD for its size and, under a hold, its LastModified; a staged one's creation by its
// version's time_ms less the statement's lead, so a batch that may predate a hold keeps its content.
func (self *Purger) deleteSegment(item *purgeItem, segmentCluster sidecar.BlobCluster, id []byte, staged bool, versionTime time.Time, cover *sidecar.HoldCover, barrierKey string) purgeOutcome {
	commit := item.commit
	if len(id) != 32 {
		return purgeOutcomeLeft
	}
	key := SegmentKey(commit.RepoId, [32]byte(id))
	info, err := segmentCluster.Head(self.ctx, key)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		self.count(func(stats *PurgeStats) { stats.AbsentCount += 1 })
		return purgeOutcomeAbsent
	case err != nil:
		return purgeOutcomeLeft
	}
	createTime := info.LastModified
	if staged {
		createTime = versionTime.Add(-self.settings.StatementAheadBound)
	}
	if cover.Keeps(createTime) {
		// only the hold keeps it now: it leaves the stored count (§20.7's stored row), and the hold's end deletes it
		self.count(func(stats *PurgeStats) { stats.HeldCount += 1 })
		self.reportFreed(commit, info.ByteCount, false)
		return purgeOutcomeHeld
	}
	if !self.step(item, BarrierPurgeDeleteBefore, barrierKey) {
		return purgeOutcomeLeft
	}
	deleteErr := segmentCluster.Delete(self.ctx, key)
	if deleteErr == nil {
		// it went: counted and reported whatever the barrier after it does
		self.count(func(stats *PurgeStats) { stats.DeletedCount += 1 })
		self.reportFreed(commit, info.ByteCount, true)
	}
	self.step(item, BarrierPurgeDeleteAfter, barrierKey)
	if deleteErr != nil {
		// held, or unknown: the sweep HEADs it again
		return purgeOutcomeLeft
	}
	return purgeOutcomeDeleted
}

// A slot on the repo's metadata cluster, as funded P2 of rank GC paid at u's admission; under a hold, its
// LastModified by a HEAD. Slots are outside the stored count and report nothing.
func (self *Purger) deleteSlot(item *purgeItem, cluster sidecar.BlobCluster, id []byte, cover *sidecar.HoldCover, barrierKey string) purgeOutcome {
	commit := item.commit
	slotId, err := sidecar.IdFromBytes(id)
	if err != nil {
		return purgeOutcomeLeft
	}
	key := SlotKey(commit.RepoId, slotId)
	if cover.Covered() {
		info, err := cluster.Head(self.ctx, key)
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
			self.count(func(stats *PurgeStats) { stats.AbsentCount += 1 })
			return purgeOutcomeAbsent
		case err != nil:
			return purgeOutcomeLeft
		}
		if cover.Keeps(info.LastModified) {
			self.count(func(stats *PurgeStats) { stats.HeldCount += 1 })
			return purgeOutcomeHeld
		}
	}
	byteCount, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationDelete, Count: 1})
	if err != nil {
		return purgeOutcomeLeft
	}
	grant, err := self.host.Budget.AcquireP2(self.ctx, commit.ClusterId, &sidecar.WriteP2Work{
		Rank:      sidecar.WriteP2RankGc,
		Due:       item.certainTime.Add(self.settings.Allowance),
		ByteCount: byteCount,
		Funded:    true,
	})
	if err != nil {
		return purgeOutcomeLeft
	}
	defer grant.Close()
	if !self.step(item, BarrierPurgeDeleteBefore, barrierKey) {
		return purgeOutcomeLeft
	}
	deleteErr := cluster.Delete(grant.Context(), key)
	if deleteErr == nil {
		self.count(func(stats *PurgeStats) { stats.DeletedCount += 1 })
	}
	self.step(item, BarrierPurgeDeleteAfter, barrierKey)
	if deleteErr != nil {
		return purgeOutcomeLeft
	}
	return purgeOutcomeDeleted
}

// A freed segment's stored bytes, as a negative delta to the repo's network, and, when deleted, the purge's series.
func (self *Purger) reportFreed(commit *PurgeCommit, byteCount int64, deleted bool) {
	if deleted {
		self.count(func(stats *PurgeStats) { stats.FreedByteCount += byteCount })
		if self.purgedCounter != nil {
			self.purgedCounter.Add(float64(byteCount), versionlessPurgedByCommit)
		}
	}
	if self.deps.Usage == nil {
		self.log.Errorf("[evs] alarm purge_usage: a purged segment's %d bytes reach no usage batch", byteCount)
		return
	}
	if err := self.deps.Usage.AddStored(connect.Id(commit.NetworkId), -byteCount); err != nil {
		self.log.Errorf("[evs] alarm purge_usage: %v", err)
	}
}

// X's newest version as the engine reads it (§11.7's newest row): the head from the cluster, the path's entry in
// the head's current epoch, and the window's statements through the record cache. A head in another path epoch, or
// with sources standing, is not judged here: its candidates are the sweep's.
type enginePurgeNewest struct {
	engine *EvsEngine
}

// The engine's reader of a path's newest version, for its Purger.
func (self *EvsEngine) PurgeNewest() PurgeNewestReader {
	return &enginePurgeNewest{engine: self}
}

// A path the reread cannot judge.
var errPurgeUnjudged = errors.New("evs purge: the path's newest version cannot be judged here")

func (self *enginePurgeNewest) NewestNames(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, pathEpoch uint64, tokenPath sidecar.EvsTokenPath) (map[string]bool, error) {
	head, err := self.engine.heads.ReadCluster(ctx, cluster, repoId, refId)
	if err != nil {
		return nil, err
	}
	if head.Absent() || EvsHeadCurrentEpoch(head.Head) != max(1, pathEpoch) || 0 < len(head.Head.GetPathEpoch().GetSources()) {
		return nil, errPurgeUnjudged
	}
	tokens := &EvsPathTokens{Current: tokenPath}
	read, err := ReadPathEntry(ctx, cluster, repoId, refId, head.Head, tokens)
	if err != nil {
		return nil, err
	}
	pushes := NewRecordPushSource(self.engine.records, cluster, repoId, refId)
	var newest *EvsNewest
	for attempt := 0; attempt < 2; attempt += 1 {
		newest, err = Newest(ctx, read.EvsEntryRead, head.Head, pushes)
		if errors.Is(err, ErrEvsEntryBehindWindow) && attempt == 0 {
			read, err = ReadPathEntry(ctx, cluster, repoId, refId, head.Head, tokens)
			if err != nil {
				return nil, err
			}
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	if !newest.Exists || newest.Directory {
		return names, nil
	}
	var entryVersionBytes []byte
	switch {
	case newest.IndexVersion != nil:
		entryVersionBytes = newest.IndexVersion.GetEntryVersion()
	case newest.Change != nil:
		entryVersionBytes = newest.Change.EntryVersion
	default:
		return nil, errPurgeUnjudged
	}
	entryVersion, err := parseEvsEntryVersion(entryVersionBytes)
	if err != nil {
		return nil, err
	}
	for _, locator := range entryVersion.GetChain() {
		if id := locator.GetId(); len(id) != 0 {
			names[string(id)] = true
		}
	}
	for _, slotId := range entryVersion.GetSlotIds() {
		names[string(slotId)] = true
	}
	return names, nil
}
