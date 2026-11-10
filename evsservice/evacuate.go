// Hourly evacuation (§11.13's when, resolve, move, delete, skip and resume rows; D-EVS-25, D-EVS-32, owner decision
// 136; EVSB-M2-11): taskworker's job evs.evacuate, which empties each metadata cluster's batches once they are over
// 25 h old. One run, on one cluster:
//
//	when     LIST pb/ in key order, which is minute order, and take each minute directory whose minute is over 25 h
//	         old, oldest first, up to the run's bounds; what is left waits for the next run, queued at once
//	resolve  per batch, GET it whole and check its trailer; per record, ResolvePush's rule on its ref
//	         (evacuate_resolve.go): kept, dropped, or left where it is
//	move     per repo across the run's minutes, the kept records, with its aged log pages and parcels once they
//	         reach a pack's size or age, into one pack or parcel, then its pidx/ entries, then the delete of what
//	         they replace (evacuate_move.go)
//	delete   a minute whose every batch was read, whose every record was settled and whose every repo moved: the
//	         new slots its dead records list, then each of its batches, whole (I-EVS-7)
//
// At format 2 (EvsSettings.InstanceFormat) a run reads batches of either format, and a kept format-2 record's tail is
// settled before its batch goes: each staged segment written to seg/ or dropped (evacuate_staged.go), then its purge
// list swept (sweep.go), the record moving to its container without its staged bytes. A format-1 instance leaves a
// format-2 batch, alarming (FS-72).
//
// Nothing is deleted on a doubt. A batch of a format this build does not know, a batch whose bytes fail its trailer,
// a record whose repo/ cannot be read, a pending record whose ref could not be fenced and a repo whose move failed
// each leave their whole minute where it is, alarmed, for a later run: a minute's batches go together or not at
// all. A killed run restarts the minute, and what it already moved is found through pidx/ and not moved again.
//
// Every metadata write is P2 of rank evacuation, sub-ranked by its minute, funded by the pushes that wrote the
// batches (§11.13's accounts row), and rereads repo/ and hold/ as it issues, each cached at most 5 s (the skip
// row). Packs go to the segment cluster, which spends no NVMe budget. While this process's clock is unsure no fence
// is raised, so a pending record stays and its minute waits (§19.6's clocks row). Evacuation answers no one.
//
// Safe for concurrent use: each Run holds its own state, and one run per cluster is the job's once key.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The job's name in taskworker's registry.
const EvsEvacuateTaskName = "evs.evacuate"

// §11.13's floors, which no setting passes: a batch stays 25 h, past every statement's time checks and the 24 h a
// receipt may be adopted (I-EVS-5), and a log page 24 h.
const (
	evsEvacuateMinMinuteAge  = 25 * time.Hour
	evsEvacuateMinLogPageAge = 24 * time.Hour
	evsEvacuateMaxPackAge    = 7 * 24 * time.Hour
)

// The series evacuation exports per metadata cluster, with no network or repo label (D-OPS-8).
const (
	evacuateOldestBatchMetricName = "urnetwork_evs_evacuation_oldest_batch_seconds"
	evacuateRecordsMetricName     = "urnetwork_evs_evacuation_records_total"
)

// The outcome label's values: a closed vocabulary.
const (
	evacuateOutcomeKept      = "kept"
	evacuateOutcomeDuplicate = "duplicate"
	evacuateOutcomeDead      = "dead"
	evacuateOutcomeShredded  = "shredded"
	evacuateOutcomeWaiting   = "waiting"
)

// Settings that break §11.13's floors.
var ErrEvacuatorSettings = errors.New("evs evacuator settings invalid")

// The run was stopped where a test asked: what a kill at a step leaves.
var errEvacuateStopped = errors.New("evs evacuation stopped at a step")

// Tunables of the hourly evacuation.
type EvacuatorSettings struct {
	// How often the job runs: hourly, so everything older than 24 h leaves the batches each day (owner decision
	// 136).
	RunInterval time.Duration
	// How long one run may take before taskworker ends it; the next run resumes. Under RunInterval, so runs do
	// not pile up.
	RunMaxTime time.Duration
	// A minute directory is evacuated once its minute is this old: 25 h, and never less.
	MinuteAge time.Duration
	// A log page moves once it is this old by its LastModified: 24 h, and never less.
	LogPageAge time.Duration
	// A repo's aged material packs once it reaches this size: 256 KiB. Below it the kept records go to a parcel.
	PackByteCount int64
	// A repo's aged material packs once its oldest would pass this age before the next run: 7 d, and never more.
	PackAge time.Duration
	// A pack's PUT is cancelled once it has run this long, and the next run retries it: 8 min
	// (plan-EVSB-pack-put).
	PackPutTimeout time.Duration
	// Keys a LIST page asks for. Must be positive.
	ListLimit int
	// Minute directories one run settles at most: three hours' worth, so a backlog drains at three times the rate
	// it grew. Must be positive.
	RunMinuteCount int
	// Minute directories one run reads and leaves waiting at most, before it stops looking further: a day's
	// worth. Past it the run alarms, since evacuation is then stuck behind what it cannot settle.
	RunWaitingMinuteCount int
	// The most kept records' bytes one run spools before it stops taking minutes: 1 GiB of local disk.
	SpoolByteCount int64
	// The most kept records' bytes of one repo a run takes before it stops taking minutes, since a repo's
	// container is built in memory: 64 MiB.
	RepoMoveByteCount int64
	// The most pidx/ entries of one ref a run reads to find what a container already holds: 64. An entry it does
	// not reach costs a record moved twice, never one lost.
	ResumeEntryCount int
	// Where the spool file is made. Empty: the system's temporary directory.
	SpoolDirectory string
}

// §11.13's figures.
func DefaultEvacuatorSettings() *EvacuatorSettings {
	return &EvacuatorSettings{
		RunInterval:           time.Hour,
		RunMaxTime:            50 * time.Minute,
		MinuteAge:             evsEvacuateMinMinuteAge,
		LogPageAge:            evsEvacuateMinLogPageAge,
		PackByteCount:         256 * 1024,
		PackAge:               evsEvacuateMaxPackAge,
		PackPutTimeout:        8 * time.Minute,
		ListLimit:             1000,
		RunMinuteCount:        180,
		RunWaitingMinuteCount: 1440,
		SpoolByteCount:        1024 * 1024 * 1024,
		RepoMoveByteCount:     64 * 1024 * 1024,
		ResumeEntryCount:      64,
	}
}

// ErrEvacuatorSettings for a value past §11.13's floors or one a run cannot work with.
func (self *EvacuatorSettings) Validate() error {
	switch {
	case self.MinuteAge < evsEvacuateMinMinuteAge:
		return fmt.Errorf("%w: a minute age of %s, under §11.13's %s", ErrEvacuatorSettings, self.MinuteAge, evsEvacuateMinMinuteAge)
	case self.LogPageAge < evsEvacuateMinLogPageAge:
		return fmt.Errorf("%w: a log page age of %s, under §11.13's %s", ErrEvacuatorSettings, self.LogPageAge, evsEvacuateMinLogPageAge)
	case self.PackAge <= 0 || evsEvacuateMaxPackAge < self.PackAge:
		return fmt.Errorf("%w: a pack age of %s, past §11.13's %s", ErrEvacuatorSettings, self.PackAge, evsEvacuateMaxPackAge)
	case self.RunInterval <= 0 || self.RunMaxTime <= 0 || self.PackPutTimeout <= 0:
		return fmt.Errorf("%w: a run interval, run time or pack timeout that is not positive", ErrEvacuatorSettings)
	case self.PackByteCount <= 0 || self.ListLimit <= 0 || self.RunMinuteCount <= 0 || self.RunWaitingMinuteCount <= 0 ||
		self.SpoolByteCount <= 0 || self.RepoMoveByteCount <= 0 || self.ResumeEntryCount <= 0:
		return fmt.Errorf("%w: a bound that is not positive", ErrEvacuatorSettings)
	}
	return nil
}

// What an evacuator runs on beyond its host.
type EvacuatorDeps struct {
	// The holds every delete reads. nil reads hold/ through a HoldCache of the evacuator's own.
	Holds *HoldCache
	// nil: the defaults.
	Settings *EvacuatorSettings
	// repo/'s cache age, the fence's retries, the price table's block size and the format this instance writes.
	// nil: the defaults.
	EvsSettings *EvsSettings
	// Alarms and what a run did. nil discards.
	Log sidecar.Logger
	// Format 2 (EVSB-M10-02): §19.11's purge mode the sweep reads, nil reading observe; the path's newest version,
	// nil reading it through the evacuator's own head store and record cache; and taskworker's usage producer for
	// the staged content a run drops or writes only for a hold, nil reporting nothing and alarming.
	Format2 Format2Gate
	Newest  PurgeNewestReader
	Usage   StoredDeltaSink
	// The sweep's LIST page and recompute bound. nil: the defaults.
	SweepSettings *SweepSettings
	// a test's: called at each barrier, an error stopping the run there as a kill would
	atStep func(name string, key string) error
}

// What one run did, in counts with no id (I-13).
type EvacuationResult struct {
	ClusterId string
	// Minute directories read, those whose batches were deleted, and those left waiting.
	MinuteCount        int
	MinuteDeletedCount int
	MinuteWaitingCount int
	// Batches read and deleted.
	BatchCount        int
	BatchDeletedCount int
	// Records by what Resolve and the skip row made of them.
	KeptCount      int
	DuplicateCount int
	DeadCount      int
	ShreddedCount  int
	WaitingCount   int
	// Fences raised for pending records.
	FenceCount int
	// Containers written or found already holding their bytes, parcels a pack replaced and log pages packed.
	PackCount           int
	ParcelCount         int
	ReplacedParcelCount int
	PackedLogPageCount  int
	// New slots of dead records deleted.
	SlotDeletedCount int
	// Format 2: staged segments written to seg/ and dropped, and what the sweep of kept records' lists did.
	StagedWrittenCount int
	StagedDroppedCount int
	Swept              SweepResult
	// Due minutes remain past this run's bounds: the job queues its next run at once.
	More bool
	// The age of the oldest batch still on the cluster as the run ended, and false when it holds none: §19.8's
	// liability, which pages past 26 h.
	OldestBatchAge time.Duration
	HasBatches     bool
}

// See the file header.
type Evacuator struct {
	host        *sidecar.ServiceHost
	deps        *EvacuatorDeps
	settings    *EvacuatorSettings
	evsSettings *EvsSettings
	log         sidecar.Logger
	clock       sidecar.Clock
	// the host's Blobs, its metadata writes held to the budget
	blobs      sidecar.BlobStore
	priceTable *PriceTable
	places     *sidecar.EvsRepoPlaceResolver
	repos      *RepoCache
	heads      *HeadStore
	logPages   *LogPageCache
	locator    *RecordLocator
	holds      *HoldCache
	// format 2's: §19.11's purge mode, the path's newest version for the staged decisions, and the sweep of kept
	// records' lists
	format2 Format2Gate
	newest  PurgeNewestReader
	sweep   *Sweep

	oldestBatchGauge sidecar.MetricsGauge
	recordsCounter   sidecar.MetricsCounter
	stagedCounter    sidecar.MetricsCounter
}

// An evacuator on host, which needs Blobs and a write budget, since no metadata write may go unpriced (§11.13). Its
// ClockCheck is read per fence, nil reading as unsure, and its Metrics take §19.8's series when it has them.
func NewEvacuator(host *sidecar.ServiceHost, deps *EvacuatorDeps) (*Evacuator, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return nil, errors.New("evs's evacuation needs a host with Blobs and a write budget")
	}
	if deps == nil {
		deps = &EvacuatorDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultEvacuatorSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	evsSettings := deps.EvsSettings
	if evsSettings == nil {
		evsSettings = DefaultEvsSettings()
	}
	if err := evsSettings.Validate(); err != nil {
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
	blobs := sidecar.BlobStore(NewBudgetedBlobs(host.Blobs))
	holds := deps.Holds
	if holds == nil {
		holds = NewHoldCache(host.Blobs, clock, nil)
	}
	self := &Evacuator{
		host:        host,
		deps:        deps,
		settings:    settings,
		evsSettings: evsSettings,
		log:         log,
		clock:       clock,
		blobs:       blobs,
		priceTable:  priceTable,
		places:      sidecar.NewEvsRepoPlaceResolver(blobs, clock, nil),
		repos:       NewRepoCache(clock, evsSettings),
		heads:       NewHeadStore(clock, host.ClockCheck, nil, evsSettings, log),
		logPages:    NewLogPageCache(evsSettings),
		locator:     NewRecordLocator(blobs, nil),
		holds:       holds,
	}
	self.format2 = deps.Format2
	if self.format2 == nil {
		self.format2 = ClosedFormat2Gate{}
	}
	self.newest = deps.Newest
	if self.newest == nil {
		self.newest = &headPurgeNewest{heads: self.heads, records: NewRecordCache(evsSettings)}
	}
	sweep, err := NewSweep(host, &SweepDeps{
		Format2:     deps.Format2,
		Newest:      self.newest,
		Holds:       holds,
		EvsSettings: evsSettings,
		Settings:    deps.SweepSettings,
		Log:         log,
		atStep:      deps.atStep,
	})
	if err != nil {
		return nil, err
	}
	self.sweep = sweep
	if host.Metrics != nil {
		self.oldestBatchGauge = host.Metrics.Gauge(evacuateOldestBatchMetricName, "Age of the oldest batch still on a metadata cluster, seconds.", "cluster")
		self.recordsCounter = host.Metrics.Counter(evacuateRecordsMetricName, "Batch records evacuation resolved, by outcome.", "cluster", "outcome")
		self.stagedCounter = host.Metrics.Counter(versionlessStagedMetricName, "Staged versionless segments evacuation decided, by outcome.", "outcome")
	}
	return self, nil
}

// The settings in force.
func (self *Evacuator) Settings() *EvacuatorSettings {
	return self.settings
}

// The age of the oldest batch on the cluster by its key's minute, from one LIST, and false when it holds none
// (§19.8's liabilities): evacuation keeps it under 26 h, and a P0 storm lets it pass (§11.13's when row).
func (self *Evacuator) OldestBatchAge(ctx context.Context, clusterId string) (time.Duration, bool, error) {
	cluster, err := self.blobs.Cluster(clusterId)
	if err != nil {
		return 0, false, err
	}
	startAfter := ""
	for {
		objects, more, err := cluster.List(ctx, batchKeyPrefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return 0, false, err
		}
		for _, object := range objects {
			startAfter = object.Key
			if minute, ok := batchKeyMinute(object.Key); ok {
				return self.clock.Now().Sub(batchMinuteTime(minute)), true, nil
			}
		}
		if !more {
			return 0, false, nil
		}
	}
}

// One batch of a minute directory.
type evacuateBatch struct {
	key    string
	header sidecar.EvsBatchHeader
}

// One minute directory of a run.
type evacuateMinute struct {
	minute  uint32
	batches []*evacuateBatch
	// why its batches stay this run, empty when nothing holds them
	waiting string
	// the repos whose kept records must be in a container before its batches go
	moveRepoIds map[sidecar.Id]bool
	// the repos whose records were dropped as an unheld shred's, reread before its batches go
	shredRepoIds map[sidecar.Id]bool
	// the new slots its dead records list
	deadSlots []*evacuateSlot
}

// A new slot a dead record lists.
type evacuateSlot struct {
	repoId sidecar.Id
	slotId sidecar.Id
}

// One run's state. Used by one goroutine.
type evacuateRun struct {
	evacuator *Evacuator
	ctx       context.Context
	cluster   sidecar.BlobCluster
	clusterId string
	// the run's start, which every age is measured from
	now     time.Time
	spool   *evacuateSpool
	minutes []*evacuateMinute
	repos   map[sidecar.Id]*evacuateRepo
	// each ref's head as the run last read or fenced it
	refHeads map[string]*EvsStoredHead
	// a committed seal's parts, by the seal's place
	sealParts map[string]map[string]bool
	// repos already alarmed this run, so a repo's thousand records alarm once
	alarmed map[string]bool
	result  *EvacuationResult
	// the first error a step met, which the run reports once it has done what it could
	firstErr error
	// the P2 class its metadata writes take: evacuation's, funded by the pushes that wrote the batches, or, for the
	// nightly pass's pack of an idle repo, packing's, unfunded (§11.13's order and wallet rows)
	rank   sidecar.WriteP2Rank
	funded bool
	// how far off the next run that may pack the repo is: a pack is due once its oldest would pass PackAge before
	// then (§11.13's move row)
	nextRunInterval time.Duration
}

// One run on clusterId: see the file header. The result says what it did; the error is the first a step met, or
// ctx's, and what the run could not settle waits for the next.
func (self *Evacuator) Run(ctx context.Context, clusterId string) (*EvacuationResult, error) {
	cluster, err := self.blobs.Cluster(clusterId)
	if err != nil {
		return nil, err
	}
	spool, err := newEvacuateSpool(self.settings.SpoolDirectory)
	if err != nil {
		return nil, err
	}
	defer spool.close()
	run := &evacuateRun{
		evacuator: self,
		ctx:       ctx,
		cluster:   cluster,
		clusterId: clusterId,
		now:       self.clock.Now(),
		spool:     spool,
		repos:     map[sidecar.Id]*evacuateRepo{},
		refHeads:  map[string]*EvsStoredHead{},
		sealParts: map[string]map[string]bool{},
		alarmed:   map[string]bool{},
		result:    &EvacuationResult{ClusterId: clusterId},

		rank:            sidecar.WriteP2RankEvacuation,
		funded:          true,
		nextRunInterval: self.settings.RunInterval,
	}
	run.run()
	if age, ok, err := self.OldestBatchAge(ctx, clusterId); err == nil {
		run.result.OldestBatchAge = age
		run.result.HasBatches = ok
		if self.oldestBatchGauge != nil {
			self.oldestBatchGauge.Set(age.Seconds(), clusterId)
		}
	}
	if self.recordsCounter != nil {
		for outcome, count := range map[string]int{
			evacuateOutcomeKept: run.result.KeptCount, evacuateOutcomeDuplicate: run.result.DuplicateCount,
			evacuateOutcomeDead: run.result.DeadCount, evacuateOutcomeShredded: run.result.ShreddedCount,
			evacuateOutcomeWaiting: run.result.WaitingCount,
		} {
			self.recordsCounter.Add(float64(count), clusterId, outcome)
		}
	}
	if self.log.V(1).Enabled() {
		self.log.Infof("[evs] evacuation of %s: %+v", clusterId, *run.result)
	}
	return run.result, run.firstErr
}

// Keeps the first error a step met.
func (self *evacuateRun) fail(err error) {
	if err != nil && self.firstErr == nil {
		self.firstErr = err
	}
}

// Whether the run must stop now: its ctx ended, or a test stopped it at a step.
func (self *evacuateRun) stopped() bool {
	return self.ctx.Err() != nil || errors.Is(self.firstErr, errEvacuateStopped)
}

// A test's stop at the barrier a site has just passed: an error ends the run there, as a kill would.
func (self *evacuateRun) stop(name string, key string) error {
	if self.evacuator.deps.atStep != nil {
		if err := self.evacuator.deps.atStep(name, key); err != nil {
			err = fmt.Errorf("%w: %s: %w", errEvacuateStopped, name, err)
			self.fail(err)
			return err
		}
	}
	return nil
}

// Says an alarm once a run for one subject.
func (self *evacuateRun) alarm(name string, subject string, format string, args ...any) {
	if self.alarmed[name+" "+subject] {
		return
	}
	self.alarmed[name+" "+subject] = true
	self.evacuator.log.Errorf("[evs] alarm %s: %s", name, fmt.Sprintf(format, args...))
}

// The run's steps, in the file header's order.
func (self *evacuateRun) run() {
	if err := self.ctx.Err(); err != nil {
		self.fail(err)
		return
	}
	if err := self.takeMinutes(); err != nil {
		self.fail(err)
	}
	if self.stopped() {
		self.fail(self.ctx.Err())
		return
	}
	// a repo's move is due by its oldest minute, as its batches' deletes are (§11.13's order row)
	repos := slices.SortedFunc(maps.Values(self.repos), func(a *evacuateRepo, b *evacuateRepo) int {
		if a.firstMinute != b.firstMinute {
			return int(int64(a.firstMinute) - int64(b.firstMinute))
		}
		return a.repoId.Cmp(b.repoId)
	})
	for _, repo := range repos {
		if self.stopped() {
			break
		}
		repo.moveErr = self.moveRepo(repo)
		repo.moved = repo.moveErr == nil
		if repo.moveErr != nil && !errors.Is(repo.moveErr, errEvacuateRepoWaits) {
			self.fail(repo.moveErr)
		}
	}
	for _, minute := range self.minutes {
		if self.stopped() {
			break
		}
		self.deleteMinute(minute)
	}
	if self.stopped() {
		self.fail(self.ctx.Err())
	}
	for _, minute := range self.minutes {
		if minute.waiting != "" {
			self.result.MinuteWaitingCount += 1
		}
	}
}

// Lists pb/ and resolves each due minute directory in turn, oldest first, until one is not yet due or a bound is
// met.
func (self *evacuateRun) takeMinutes() error {
	settings := self.evacuator.settings
	dueBefore := BatchMinute(self.now.Add(-settings.MinuteAge))
	var current *evacuateMinute
	settledCount := 0
	waitingCount := 0
	// resolves the minute gathered so far, and says whether the run takes another
	resolveCurrent := func() bool {
		if current == nil {
			return true
		}
		self.minutes = append(self.minutes, current)
		self.result.MinuteCount += 1
		self.resolveMinute(current)
		if current.waiting == "" {
			settledCount += 1
		} else {
			waitingCount += 1
		}
		current = nil
		switch {
		case self.stopped():
			return false
		case settings.RunMinuteCount <= settledCount, settings.SpoolByteCount <= self.spool.byteCount:
			return false
		case settings.RunWaitingMinuteCount <= waitingCount:
			self.alarm("evacuate_stuck", self.clusterId, "%d minute directories of cluster %s wait on what evacuation cannot settle", waitingCount, self.clusterId)
			return false
		}
		for _, repo := range self.repos {
			if settings.RepoMoveByteCount <= repo.keptByteCount {
				return false
			}
		}
		return true
	}
	startAfter := ""
	for {
		objects, more, err := self.cluster.List(self.ctx, batchKeyPrefix, startAfter, settings.ListLimit)
		if err != nil {
			return err
		}
		for _, object := range objects {
			startAfter = object.Key
			minute, ok := batchKeyMinute(object.Key)
			if !ok {
				// never deleted: nothing here knows what it is
				self.alarm("evacuate_batch_key", object.Key, "%s on cluster %s is no batch key", object.Key, self.clusterId)
				continue
			}
			if dueBefore <= minute {
				// keys ascend by minute, so nothing after this one is due
				resolveCurrent()
				return nil
			}
			if current != nil && current.minute != minute {
				if !resolveCurrent() {
					self.result.More = true
					return nil
				}
			}
			if current == nil {
				current = &evacuateMinute{minute: minute, moveRepoIds: map[sidecar.Id]bool{}, shredRepoIds: map[sidecar.Id]bool{}}
			}
			current.batches = append(current.batches, &evacuateBatch{key: object.Key})
		}
		if !more {
			resolveCurrent()
			return nil
		}
	}
}

// Leaves the minute's batches where they are this run, for why.
func (self *evacuateMinute) wait(why string) {
	if self.waiting == "" {
		self.waiting = why
	}
}

// Reads each batch of the minute whole and resolves its records. Anything it cannot settle leaves the minute
// waiting.
func (self *evacuateRun) resolveMinute(minute *evacuateMinute) {
	for _, batch := range minute.batches {
		if self.stopped() {
			minute.wait("stopped")
			return
		}
		batchBytes, err := self.readBatch(batch.key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			// another run deleted it, after its own moves
			continue
		}
		if err != nil {
			minute.wait("batch unread")
			self.fail(err)
			continue
		}
		self.result.BatchCount += 1
		// an instance at format 2 reads batches of either format and settles format-2 records' tails
		// (evacuate_staged.go, sweep.go); one at format 1 leaves a format-2 batch, alarming (FS-72)
		var parsed *sidecar.EvsBatch
		if sidecar.EvsRepoFormat2 <= self.evacuator.evsSettings.InstanceFormat {
			parsed, err = sidecar.ParseEvsBatchFormat2(batchBytes)
		} else {
			parsed, err = sidecar.ParseEvsBatch(batchBytes)
		}
		switch {
		case errors.Is(err, sidecar.ErrEvsFormatUnsupported):
			// §11.8's bytes row: an evacuator that does not know a batch's format leaves it, alarming
			minute.wait("batch format")
			self.alarm("evacuate_batch_format", batch.key, "batch %s on cluster %s is of a format this evacuator does not know: it stays", batch.key, self.clusterId)
			continue
		case err != nil:
			minute.wait("batch invalid")
			self.alarm("evacuate_batch_invalid", batch.key, "batch %s on cluster %s fails its checks: it stays (%v)", batch.key, self.clusterId, err)
			continue
		}
		batch.header = parsed.Header
		if BatchKey(parsed.Header.Minute, parsed.Header.Instance, parsed.Header.Seq) != batch.key {
			// its records' places would name another key than the one that holds them
			minute.wait("batch invalid")
			self.alarm("evacuate_batch_invalid", batch.key, "batch %s on cluster %s names another key in its header: it stays", batch.key, self.clusterId)
			continue
		}
		for i, record := range parsed.Records {
			place := parsed.Places[i]
			recordBytes := batchBytes[place.GetOffset() : place.GetOffset()+place.GetLength()]
			var tail *sidecar.EvsBatchRecordTail
			if i < len(parsed.Tails) {
				tail = parsed.Tails[i]
			}
			self.resolveRecord(minute, place, record, tail, recordBytes)
			if self.stopped() {
				minute.wait("stopped")
				return
			}
		}
	}
}

// A batch's bytes, whole.
func (self *evacuateRun) readBatch(key string) ([]byte, error) {
	object, err := self.cluster.Get(self.ctx, key)
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	// one byte past the largest batch, so a longer object fails its parse
	limit := int64(sidecar.EvsBatchMaxRecordByteCount + sidecar.EvsBatchHeaderByteCount + sidecar.EvsBatchTrailerByteCount + 64)
	return io.ReadAll(io.LimitReader(object.Body, limit))
}

// A P2 grant of rank evacuation for one write of the minute's work, funded by the pushes that wrote its batches.
// recheck runs as the write issues (§11.13's skip row).
func (self *evacuateRun) acquire(minute uint32, operation WriteOperation, recheck func(ctx context.Context) error) (sidecar.WriteGrant, error) {
	byteCount, err := self.evacuator.priceTable.Price(operation)
	if err != nil {
		return nil, err
	}
	return self.evacuator.host.Budget.AcquireP2(self.ctx, self.clusterId, &sidecar.WriteP2Work{
		Rank:      self.rank,
		Due:       batchMinuteTime(minute),
		ByteCount: byteCount,
		Funded:    self.funded,
		Recheck:   recheck,
	})
}

// One DELETE on the metadata cluster, paid as the minute's work.
func (self *evacuateRun) deleteKey(minute uint32, key string, recheck func(ctx context.Context) error) error {
	grant, err := self.acquire(minute, WriteOperation{Kind: WriteOperationDelete, Count: 1}, recheck)
	if err != nil {
		return err
	}
	defer grant.Close()
	return self.cluster.Delete(grant.Context(), key)
}

// Deletes the minute's batches once nothing holds them: every repo with a kept record in it moved, every repo
// dropped as a shred's still an unheld shred's, and its dead records' new slots gone (I-EVS-7, I-EVS-2).
func (self *evacuateRun) deleteMinute(minute *evacuateMinute) {
	if minute.waiting != "" {
		return
	}
	for repoId := range minute.moveRepoIds {
		if repo := self.repos[repoId]; repo == nil || !repo.moved {
			minute.wait("repo not moved")
			return
		}
	}
	for repoId := range minute.shredRepoIds {
		// a hold placed since the record was dropped keeps it: reread before its batch goes (the skip row)
		state, err := self.repoState(repoId)
		if err != nil || state.action != evacuateRepoDrop {
			minute.wait("shredded repo held")
			return
		}
	}
	for _, slot := range minute.deadSlots {
		if self.stopped() {
			minute.wait("stopped")
			return
		}
		err := self.deleteKey(minute.minute, SlotKey(slot.repoId, slot.slotId), func(ctx context.Context) error {
			return self.recheckDelete(ctx, slot.repoId)
		})
		switch {
		case errors.Is(err, errEvacuateHeld):
			// a hold keeps what a dead push left, and its batch goes without it
		case errors.Is(err, errEvacuateRepoWaits):
			minute.wait("slot not deleted")
			return
		case err != nil:
			minute.wait("slot not deleted")
			self.fail(err)
			return
		default:
			self.result.SlotDeletedCount += 1
		}
	}
	for _, batch := range minute.batches {
		barrierKey := barrierBatchKey(batch.header.Minute, batch.header.Instance, batch.header.Seq)
		testHookBarrier(BarrierEvacuateBatchDeleteBefore, barrierKey)
		if err := self.stop(BarrierEvacuateBatchDeleteBefore, barrierKey); err != nil {
			minute.wait("stopped")
			return
		}
		if err := self.deleteKey(minute.minute, batch.key, nil); err != nil {
			minute.wait("batch not deleted")
			self.fail(err)
			return
		}
		self.result.BatchDeletedCount += 1
		testHookBarrier(BarrierEvacuateBatchDeleteAfter, barrierKey)
		if err := self.stop(BarrierEvacuateBatchDeleteAfter, barrierKey); err != nil {
			minute.wait("stopped")
			return
		}
	}
	self.result.MinuteDeletedCount += 1
}

// Packs one idle repo for the nightly pass (§11.13's move row: "for an idle repo, in the nightly pass, which packs
// any whose oldest would pass 7 d before the next pass"): the move with no kept records, its metadata writes unfunded
// P2 of rank packing, due by nextPassInterval from now. Like any move it also deletes each parcel a pack already
// holds, its entries first, and each packed log page, nothing while a hold covers the repo. errEvacuateRepoWaits when
// repo/ lets no write issue. The result counts what it packed and deleted.
func (self *Evacuator) PackIdleRepo(ctx context.Context, clusterId string, repoId sidecar.Id, nextPassInterval time.Duration) (*EvacuationResult, error) {
	cluster, err := self.blobs.Cluster(clusterId)
	if err != nil {
		return nil, err
	}
	run := &evacuateRun{
		evacuator: self,
		ctx:       ctx,
		cluster:   cluster,
		clusterId: clusterId,
		now:       self.clock.Now(),
		repos:     map[sidecar.Id]*evacuateRepo{},
		refHeads:  map[string]*EvsStoredHead{},
		sealParts: map[string]map[string]bool{},
		alarmed:   map[string]bool{},
		result:    &EvacuationResult{ClusterId: clusterId},

		rank:            sidecar.WriteP2RankPack,
		funded:          false,
		nextRunInterval: nextPassInterval,
	}
	repo := &evacuateRepo{repoId: repoId, firstMinute: BatchMinute(run.now)}
	if err := run.moveRepo(repo); err != nil {
		return run.result, err
	}
	return run.result, run.firstErr
}

// The job's args for one cluster's run: its id. No args start every cluster's.
func EvsEvacuateArgs(clusterId string) []byte {
	return []byte(clusterId)
}

// One cluster's run in the queue, once-keyed by cluster, so a start and a rerun coalesce. A cluster id is a name
// from sidecar.yml, never content (I-13).
func EvsEvacuateTaskRequest(clusterId string, runAt time.Time, settings *EvacuatorSettings) *sidecar.TaskRequest {
	if settings == nil {
		settings = DefaultEvacuatorSettings()
	}
	return &sidecar.TaskRequest{
		Name:    EvsEvacuateTaskName,
		OnceKey: EvsEvacuateTaskName + "." + clusterId,
		Args:    EvsEvacuateArgs(clusterId),
		RunAt:   runAt,
		MaxTime: settings.RunMaxTime,
	}
}

// The hourly start in the queue, once-keyed by the job's name.
func EvsEvacuateStartTaskRequest(runAt time.Time) *sidecar.TaskRequest {
	return &sidecar.TaskRequest{Name: EvsEvacuateTaskName, OnceKey: EvsEvacuateTaskName, RunAt: runAt}
}

// One run of evs.evacuate. With no args it is the hourly start: it queues itself an interval on, then each metadata
// cluster's run now. With a cluster's id it is that cluster's run, which queues itself again at once while due
// minutes remain past its bounds. The result is nil for the start.
func RunEvacuation(ctx context.Context, host *sidecar.ServiceHost, deps *EvacuatorDeps, args []byte) (*EvacuationResult, error) {
	if host == nil || host.Tasks == nil {
		return nil, errors.New("evs's evacuation needs a host with a task queue")
	}
	evacuator, err := NewEvacuator(host, deps)
	if err != nil {
		return nil, err
	}
	now := evacuator.clock.Now()
	if len(args) == 0 {
		if err := host.Tasks.Schedule(ctx, EvsEvacuateStartTaskRequest(now.Add(evacuator.settings.RunInterval))); err != nil {
			return nil, err
		}
		for _, clusterId := range host.Blobs.MetadataClusterIds() {
			if err := host.Tasks.Schedule(ctx, EvsEvacuateTaskRequest(clusterId, now, evacuator.settings)); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	clusterId := string(args)
	if !slices.Contains(host.Blobs.MetadataClusterIds(), clusterId) {
		return nil, fmt.Errorf("%w: evs.evacuate for a cluster this process does not hold", sidecar.ErrBlobClusterUnknown)
	}
	result, err := evacuator.Run(ctx, clusterId)
	if result != nil && result.More {
		if scheduleErr := host.Tasks.Schedule(ctx, EvsEvacuateTaskRequest(clusterId, evacuator.clock.Now(), evacuator.settings)); scheduleErr != nil && err == nil {
			err = scheduleErr
		}
	}
	return result, err
}

// Whether a repo/ object's state lets a move's write issue: active or deleted, or shredding under a hold.
func evacuateStateMoves(state protocol.EvsRepoState, held bool) bool {
	switch state {
	case protocol.EvsRepoState_EVS_REPO_ACTIVE, protocol.EvsRepoState_EVS_REPO_DELETED:
		return true
	case protocol.EvsRepoState_EVS_REPO_SHREDDING:
		return held
	}
	return false
}
