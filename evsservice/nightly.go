// The nightly pass (§11.13's bytes, orphans and resume rows, §20.7's count row; D-EVS-16, R-EVS-13; EVSB-M2-12):
// taskworker's job evs.nightly, whose one LIST of each repo prefix a night serves the stored count, orphan GC and
// what else deletes on a listing. One run takes one shard of one metadata cluster: the repos placed there whose id
// starts with the shard's hex digits.
//
//	horizon  first, before any LIST of pidx/: the cluster's evacuation horizon, from one LIST of pb/ with limit 1
//	         (OrphanHorizon; DESIGN-DETAILS 2.2.4's step 1). An entry written before a batch's deletion is seen by
//	         any LIST issued after a horizon that the deletion moved, which is the one order orphan GC rests on
//	repos    LIST repo/<shard> on the metadata cluster in key order, at most RunRepoCount a run; a run that stops
//	         short gives the key it reached, and the job queues itself from there, so a shard resumes
//	lists    per repo: seg/ and pack/ on the segment cluster, hp/, pidx/ and pmap/ on its metadata cluster
//	count    the sizes LIST gave for seg/, pack/ and hp/, plus the record lengths the head windows of refs written
//	         in the last 26 h give for versions whose batch may still stand (nightly_count.go), by the network its
//	         repo/ names
//	orphans  OrphanGc.RunRepo on those listings (gc_orphans.go)
//	contain  a pack or parcel no pidx/ entry names, 25 h old and behind the horizon, deleted; an idle repo packed
//	         once its oldest parcel content or unpacked log page would pass 7 d before the next pass, which also
//	         deletes each parcel a pack already holds (nightly_containers.go)
//
// Every DELETE the pass issues for an object it listed names that object's LastModified
// (sidecar.WithBlobUnmodified), counts a 412 as replaced and never as deleted, and leaves a held key or an unknown
// outcome for the next night. Nothing deletes while this process's clock is unsure, or on a cluster whose build has
// not passed §19.6's settle cases; the count is read all the same.
//
// The pass keeps no cursor between nights: a missed night only delays, and a killed run's shard is listed again.
//
// Safe for concurrent use: each Run holds its own state, and one run per cluster and shard is the job's once key.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

// The job's name in taskworker's registry.
const EvsNightlyTaskName = "evs.nightly"

// §11.13's floor, which no setting passes: a container no entry names goes only once it is 25 h old.
const evsNightlyMinUnnamedContainerAge = 25 * time.Hour

// Settings a run cannot work with.
var ErrNightlyPassSettings = errors.New("evs nightly pass settings invalid")

// The clock was unsure when a horizon was asked for, or turned while it was read.
var ErrNightlyClockUnsure = errors.New("evs nightly pass clock unsure")

// Something under pb/ that is no batch's key: the horizon cannot be read from it, and nothing deletes on a guess.
var ErrNightlyBatchKey = errors.New("evs nightly pass batch key unread")

// Tunables of the nightly pass.
type NightlyPassSettings struct {
	// How often the pass starts: every 24 h.
	RunInterval time.Duration
	// How long one shard's run may take before taskworker ends it; the next run lists the shard again.
	RunMaxTime time.Duration
	// How many leading hex digits of a repo's id name its shard: 0 for one job a cluster, 1 for 16, 2 for 256.
	ShardHexDigitCount int
	// Repos one run examines at most before it stops and queues itself from the key it reached. Must be positive.
	RunRepoCount int
	// Keys a LIST page asks for. Must be positive.
	ListLimit int
	// A ref's head is read for its window when it was written within this long: 26 h, the longest a batch stays
	// (§11.13's cost row).
	HeadWindowAge time.Duration
	// A container no pidx/ entry names is deleted once it is this old by its LastModified: 25 h, and never less
	// (§11.13's resume row).
	UnnamedContainerAge time.Duration
}

// One job a cluster until a cluster's repos need more (§11.13's cost row: one LIST per repo prefix a night).
func DefaultNightlyPassSettings() *NightlyPassSettings {
	return &NightlyPassSettings{
		RunInterval:         24 * time.Hour,
		RunMaxTime:          6 * time.Hour,
		ShardHexDigitCount:  0,
		RunRepoCount:        100000,
		ListLimit:           1000,
		HeadWindowAge:       26 * time.Hour,
		UnnamedContainerAge: evsNightlyMinUnnamedContainerAge,
	}
}

// ErrNightlyPassSettings for a value a run cannot work with.
func (self *NightlyPassSettings) Validate() error {
	switch {
	case self.UnnamedContainerAge < evsNightlyMinUnnamedContainerAge:
		return fmt.Errorf("%w: an unnamed container age of %s, under §11.13's %s", ErrNightlyPassSettings, self.UnnamedContainerAge, evsNightlyMinUnnamedContainerAge)
	case self.RunInterval <= 0 || self.RunMaxTime <= 0 || self.HeadWindowAge <= 0:
		return fmt.Errorf("%w: an interval, run time or head age that is not positive", ErrNightlyPassSettings)
	case self.ShardHexDigitCount < 0 || 2 < self.ShardHexDigitCount:
		return fmt.Errorf("%w: %d shard digits", ErrNightlyPassSettings, self.ShardHexDigitCount)
	case self.RunRepoCount <= 0 || self.ListLimit <= 0:
		return fmt.Errorf("%w: a bound that is not positive", ErrNightlyPassSettings)
	}
	return nil
}

// The shards a cluster's repos fall into: every hex prefix of ShardHexDigitCount digits, in order.
func (self *NightlyPassSettings) Shards() []string {
	shards := []string{""}
	for range self.ShardHexDigitCount {
		next := make([]string, 0, 16*len(shards))
		for _, shard := range shards {
			for _, digit := range "0123456789abcdef" {
				next = append(next, shard+string(digit))
			}
		}
		shards = next
	}
	return shards
}

// What a pass runs on beyond its host.
type NightlyPassDeps struct {
	// The holds every delete reads. nil reads hold/ through a HoldCache of the pass's own.
	Holds *HoldCache
	// nil: the defaults.
	Settings    *NightlyPassSettings
	OrphanGc    *OrphanGcSettings
	EvsSettings *EvsSettings
	// The move's settings an idle repo's pack is built under (evacuate_move.go). nil: the defaults.
	Evacuator *EvacuatorSettings
	// The marker collection the pass queues (collect_markers.go). nil: the defaults.
	Collector *MarkerCollectorSettings
	// See OrphanGcDeps.
	SegmentClusterBusy func(ctx context.Context, clusterId string) bool
	// Alarms and what a run did. nil discards.
	Log sidecar.Logger
	// a test's: called at each barrier, an error stopping the run there as a kill would
	atStep func(name string, key string) error
	// a test's: stands in for orphan GC's pace, on a clock the test moves
	wait func(wait time.Duration)
}

// What one run did, in counts with no id but the networks' (I-13): a network id is what the stored count is kept
// by, and is never content.
type NightlyResult struct {
	ClusterId string
	Shard     string
	// The cluster's horizon as this run read it, and false when it read none: its clock was unsure, the LIST
	// failed, or a build had not passed the settle cases. No horizon, no deletion.
	Horizon    time.Time
	HasHorizon bool
	// Repos listed and examined, and those whose repo/ names no network: counted to no one, and kept whole.
	RepoCount               int
	UnknownNetworkRepoCount int
	// Stored bytes by network and family, for §20.7's count and §19.9's fill (EVSB-M3-02).
	NetworkBytes map[sidecar.Id]*NightlyBytes
	// Orphan GC's sums over the run's repos.
	Orphans OrphanGcResult
	// Repos orphan GC skipped, for any reason.
	OrphanSkippedRepoCount int
	// Containers no entry named, deleted by a DELETE naming their LastModified, found replaced (412), or left
	// (held, unknown); idle repos packed, and parcels a pack already held deleted with their entries.
	UnnamedDeletedCount  int
	UnnamedReplacedCount int
	UnnamedLeftCount     int
	IdlePackCount        int
	ReplacedParcelCount  int
	// Refs queued for marker collection (evs.collect).
	CollectQueuedCount int
	// The run stopped at its bound: NextStartAfter is the repo/ key it reached, and the job queues itself there.
	More           bool
	NextStartAfter string
	// Every repo of the shard was listed and counted with no read failing: only then do the run's NetworkBytes
	// stand for the shard.
	Complete bool
}

// A network's stored bytes in one run's repos, by family (§11.13's bytes row).
type NightlyBytes struct {
	// seg/ and pack/ objects, on the segment cluster.
	SegmentByteCount int64
	PackByteCount    int64
	// hp/ objects, on the metadata cluster.
	ParcelByteCount int64
	// Records still in batches, by the lengths head windows give.
	BatchRecordByteCount int64
	RepoCount            int
}

// The network's stored count: every family's bytes.
func (self *NightlyBytes) StoredByteCount() int64 {
	return self.SegmentByteCount + self.PackByteCount + self.ParcelByteCount + self.BatchRecordByteCount
}

// See the file header.
type NightlyPass struct {
	host        *sidecar.ServiceHost
	deps        *NightlyPassDeps
	settings    *NightlyPassSettings
	evsSettings *EvsSettings
	log         sidecar.Logger
	clock       sidecar.Clock
	repos       *RepoCache
	holds       *HoldCache
	orphans     *OrphanGc
	evacuator   *Evacuator
	priceTable  *PriceTable

	collectorSettings *MarkerCollectorSettings
}

// A pass on host, which needs Blobs. Its ClockCheck is read per horizon and per DELETE, nil reading as unsure.
func NewNightlyPass(host *sidecar.ServiceHost, deps *NightlyPassDeps) (*NightlyPass, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return nil, errors.New("evs's nightly pass needs a host with Blobs and a write budget")
	}
	if deps == nil {
		deps = &NightlyPassDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultNightlyPassSettings()
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
	clock := host.ClockOrReal()
	repos := NewRepoCache(clock, evsSettings)
	holds := deps.Holds
	if holds == nil {
		holds = NewHoldCache(host.Blobs, clock, nil)
	}
	priceTable, err := DefaultPriceTable(evsSettings.PriceBlockByteCount)
	if err != nil {
		return nil, err
	}
	collectorSettings := deps.Collector
	if collectorSettings == nil {
		collectorSettings = DefaultMarkerCollectorSettings()
	}
	if err := collectorSettings.Validate(evsSettings); err != nil {
		return nil, err
	}
	evacuator, err := NewEvacuator(host, &EvacuatorDeps{
		Holds:       holds,
		Settings:    deps.Evacuator,
		EvsSettings: evsSettings,
		Log:         log,
		atStep:      deps.atStep,
	})
	if err != nil {
		return nil, err
	}
	orphans, err := NewOrphanGc(host, &OrphanGcDeps{
		Holds:              holds,
		Repos:              repos,
		Settings:           deps.OrphanGc,
		EvsSettings:        evsSettings,
		SegmentClusterBusy: deps.SegmentClusterBusy,
		Log:                log,
		atStep:             deps.atStep,
		wait:               deps.wait,
	})
	if err != nil {
		return nil, err
	}
	return &NightlyPass{
		host:        host,
		deps:        deps,
		settings:    settings,
		evsSettings: evsSettings,
		log:         log,
		clock:       clock,
		repos:       repos,
		holds:       holds,
		orphans:     orphans,
		evacuator:   evacuator,
		priceTable:  priceTable,

		collectorSettings: collectorSettings,
	}, nil
}

// The settings in force.
func (self *NightlyPass) Settings() *NightlyPassSettings {
	return self.settings
}

func (self *NightlyPass) clockSure() bool {
	return self.host.ClockCheck != nil && self.host.ClockCheck.Sure()
}

func (self *NightlyPass) step(name string, key string) error {
	testHookBarrier(name, key)
	if self.deps.atStep != nil {
		return self.deps.atStep(name, key)
	}
	return nil
}

// The evacuation horizon of a metadata cluster (DESIGN-DETAILS 2.2.4): from one LIST of pb/ with limit 1 at time t
// by this process's checked clock, the start of the minute the oldest batch key names, or t - 25 h, evacuation's
// floor, if that is earlier or no batch is left. Every batch whose minute starts before it has been evacuated,
// which rests on a LIST that names every acknowledged batch (§19.6's list row). t is read before the LIST is
// issued, and the clock must be sure from before that read until the LIST has answered: an unsure clock is
// ErrNightlyClockUnsure. A key under pb/ that is no batch's is ErrNightlyBatchKey.
func (self *NightlyPass) OrphanHorizon(ctx context.Context, cluster sidecar.BlobCluster) (time.Time, error) {
	clockCheck := self.host.ClockCheck
	if clockCheck == nil {
		return time.Time{}, ErrNightlyClockUnsure
	}
	unsure := clockCheck.UnsureChannel()
	if !clockCheck.Sure() {
		return time.Time{}, ErrNightlyClockUnsure
	}
	clusterId := cluster.ClusterId()
	if err := self.step(BarrierGcHorizonBefore, clusterId); err != nil {
		return time.Time{}, err
	}
	floor := self.clock.Now().Add(-evsEvacuateMinMinuteAge)
	objects, _, err := cluster.List(ctx, batchKeyPrefix, "", 1)
	if err != nil {
		return time.Time{}, err
	}
	select {
	case <-unsure:
		return time.Time{}, ErrNightlyClockUnsure
	default:
	}
	horizon := floor
	if 0 < len(objects) {
		minute, ok := batchKeyMinute(objects[0].Key)
		if !ok {
			return time.Time{}, fmt.Errorf("%w: on cluster %s", ErrNightlyBatchKey, clusterId)
		}
		if oldest := batchMinuteTime(minute); oldest.Before(horizon) {
			horizon = oldest
		}
	}
	if err := self.step(BarrierGcHorizonAfter, clusterId); err != nil {
		return time.Time{}, err
	}
	return horizon, nil
}

// Every object under prefix, paged.
func (self *NightlyPass) listAll(ctx context.Context, cluster sidecar.BlobCluster, prefix string) ([]*sidecar.BlobInfo, error) {
	all := []*sidecar.BlobInfo{}
	startAfter := ""
	for {
		objects, more, err := cluster.List(ctx, prefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return nil, err
		}
		all = append(all, objects...)
		if !more || len(objects) == 0 {
			return all, nil
		}
		startAfter = objects[len(objects)-1].Key
	}
}

// One run: the shard of clusterId's repos whose ids start with shard, from startAfter, a repo/ key or empty. The
// result stands even beside an error, which is the first read that failed: what the run counted before it is
// in it, and Complete is false.
func (self *NightlyPass) Run(ctx context.Context, clusterId string, shard string, startAfter string) (*NightlyResult, error) {
	result := &NightlyResult{ClusterId: clusterId, Shard: shard, NetworkBytes: map[sidecar.Id]*NightlyBytes{}}
	if !slices.Contains(self.settings.Shards(), shard) {
		return result, fmt.Errorf("%w: shard %q", ErrNightlyPassSettings, shard)
	}
	cluster, err := self.host.Blobs.Cluster(clusterId)
	if err != nil {
		return result, err
	}
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		return result, err
	}

	// step 1, before any LIST of pidx/. A horizon that cannot be read stops deletion, never the count.
	if segmentCluster.SettlePassed() && cluster.SettlePassed() {
		horizon, err := self.OrphanHorizon(ctx, cluster)
		switch {
		case err == nil:
			result.Horizon, result.HasHorizon = horizon, true
		case errors.Is(err, ErrNightlyClockUnsure):
		default:
			self.log.Errorf("[evs] alarm nightly_horizon: cluster %s: %v", clusterId, err)
		}
	}

	var firstErr error
	fail := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	listPrefix := repoKeyPrefix + shard
	whole := startAfter == ""
	for {
		objects, more, err := cluster.List(ctx, listPrefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return result, err
		}
		for _, object := range objects {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			if self.settings.RunRepoCount <= result.RepoCount {
				result.More, result.NextStartAfter = true, startAfter
				return result, firstErr
			}
			startAfter = object.Key
			repoId, err := sidecar.ParseId(strings.TrimPrefix(object.Key, repoKeyPrefix))
			if err != nil || RepoKey(repoId) != object.Key {
				// not a repo's key: nothing here counts or judges it
				continue
			}
			result.RepoCount += 1
			if err := self.runRepo(ctx, cluster, segmentCluster, repoId, result); err != nil {
				fail(err)
			}
		}
		if !more || len(objects) == 0 {
			break
		}
	}
	result.Complete = whole && firstErr == nil
	return result, firstErr
}

// What the pass listed of one repo, every LIST of pidx/ and pmap/ issued after the horizon was read.
type nightlyListing struct {
	repoId sidecar.Id
	// seg/<repo>/ and pack/<repo>/ on the segment cluster
	segments []*sidecar.BlobInfo
	packs    []*sidecar.BlobInfo
	// hp/<repo>/, log/<repo>/, pidx/<repo>/ and pmap/<repo>/ on its metadata cluster
	parcels      []*sidecar.BlobInfo
	logPages     []*sidecar.BlobInfo
	pidxEntries  []*sidecar.BlobInfo
	pathMapParts []*sidecar.BlobInfo
	// the containers the pass deleted, not counted
	deletedKeys map[string]bool
}

// One repo: its listings, its containers, its count and its orphans.
func (self *NightlyPass) runRepo(ctx context.Context, cluster sidecar.BlobCluster, segmentCluster sidecar.BlobCluster, repoId sidecar.Id, result *NightlyResult) error {
	repoHex := sidecar.EvsKeyId(repoId)
	listing := &nightlyListing{repoId: repoId, deletedKeys: map[string]bool{}}
	var err error
	if listing.segments, err = self.listAll(ctx, segmentCluster, segmentKeyPrefix+repoHex+"/"); err != nil {
		return err
	}
	if listing.packs, err = self.listAll(ctx, segmentCluster, packKeyPrefix+repoHex+"/"); err != nil {
		return err
	}
	if listing.parcels, err = self.listAll(ctx, cluster, parcelKeyPrefix+repoHex+"/"); err != nil {
		return err
	}
	if listing.logPages, err = self.listAll(ctx, cluster, logKeyPrefix+repoHex+"/"); err != nil {
		return err
	}
	// issued after the horizon was taken (step 1 before step 4)
	if err := self.step(BarrierGcIndexBefore, barrierRepoKey(repoId)); err != nil {
		return err
	}
	if listing.pidxEntries, err = self.listAll(ctx, cluster, pidxKeyPrefix+repoHex+"/"); err != nil {
		return err
	}
	if listing.pathMapParts, err = self.listAll(ctx, cluster, pathMapKeyPrefix+repoHex+"/"); err != nil {
		return err
	}

	if err := self.runContainers(ctx, cluster, segmentCluster, listing, result); err != nil {
		return err
	}
	if err := self.countRepo(ctx, cluster, listing, result); err != nil {
		return err
	}

	if !result.HasHorizon {
		result.OrphanSkippedRepoCount += 1
		return nil
	}
	orphans, err := self.orphans.RunRepo(ctx, &OrphanGcRepo{
		RepoId:          repoId,
		MetadataCluster: cluster,
		Horizon:         result.Horizon,
		Segments:        listing.segments,
		PidxEntries:     listing.pidxEntries,
		PathMapParts:    listing.pathMapParts,
	})
	if orphans != nil {
		result.Orphans.CandidateCount += orphans.CandidateCount
		result.Orphans.PidxReadCount += orphans.PidxReadCount
		result.Orphans.DeletedCount += orphans.DeletedCount
		result.Orphans.ReplacedCount += orphans.ReplacedCount
		result.Orphans.HeldCount += orphans.HeldCount
		result.Orphans.FailedCount += orphans.FailedCount
		result.Orphans.MapPartDeletedCount += orphans.MapPartDeletedCount
		result.Orphans.More = result.Orphans.More || orphans.More
		if orphans.Skipped != "" {
			result.OrphanSkippedRepoCount += 1
		}
	}
	return err
}

// The job's args for one shard's run: the cluster, the shard and where to start, none of them content (I-13). No
// args start every shard's.
func EvsNightlyArgs(clusterId string, shard string, startAfter string) []byte {
	return []byte(clusterId + "\n" + shard + "\n" + startAfter)
}

// The args of one shard's run. ok is false for the start's empty args and for bytes of another shape.
func ParseEvsNightlyArgs(args []byte) (clusterId string, shard string, startAfter string, ok bool) {
	fields := strings.Split(string(args), "\n")
	if len(fields) != 3 || fields[0] == "" {
		return "", "", "", false
	}
	return fields[0], fields[1], fields[2], true
}

// One shard's run in the queue, once-keyed by cluster and shard, so a start and a rerun coalesce.
func EvsNightlyTaskRequest(clusterId string, shard string, startAfter string, runAt time.Time, settings *NightlyPassSettings) *sidecar.TaskRequest {
	if settings == nil {
		settings = DefaultNightlyPassSettings()
	}
	return &sidecar.TaskRequest{
		Name:    EvsNightlyTaskName,
		OnceKey: EvsNightlyTaskName + "." + clusterId + "." + shard,
		Args:    EvsNightlyArgs(clusterId, shard, startAfter),
		RunAt:   runAt,
		MaxTime: settings.RunMaxTime,
	}
}

// The nightly start in the queue, once-keyed by the job's name.
func EvsNightlyStartTaskRequest(runAt time.Time) *sidecar.TaskRequest {
	return &sidecar.TaskRequest{Name: EvsNightlyTaskName, OnceKey: EvsNightlyTaskName, RunAt: runAt}
}

// One run of evs.nightly. With no args it is the nightly start: it queues itself an interval on, then each shard of
// each metadata cluster now. With a shard's args it is that shard's run, which queues itself again from the key it
// reached when it stopped at its bound. The result is nil for the start.
func RunNightlyPass(ctx context.Context, host *sidecar.ServiceHost, deps *NightlyPassDeps, args []byte) (*NightlyResult, error) {
	if host == nil || host.Tasks == nil {
		return nil, errors.New("evs's nightly pass needs a host with a task queue")
	}
	pass, err := NewNightlyPass(host, deps)
	if err != nil {
		return nil, err
	}
	now := pass.clock.Now()
	if len(args) == 0 {
		if err := host.Tasks.Schedule(ctx, EvsNightlyStartTaskRequest(now.Add(pass.settings.RunInterval))); err != nil {
			return nil, err
		}
		for _, clusterId := range host.Blobs.MetadataClusterIds() {
			for _, shard := range pass.settings.Shards() {
				if err := host.Tasks.Schedule(ctx, EvsNightlyTaskRequest(clusterId, shard, "", now, pass.settings)); err != nil {
					return nil, err
				}
			}
		}
		return nil, nil
	}
	clusterId, shard, startAfter, ok := ParseEvsNightlyArgs(args)
	if !ok {
		return nil, fmt.Errorf("%w: evs.nightly args", ErrNightlyPassSettings)
	}
	if !slices.Contains(host.Blobs.MetadataClusterIds(), clusterId) {
		return nil, fmt.Errorf("%w: evs.nightly for a cluster this process does not hold", sidecar.ErrBlobClusterUnknown)
	}
	result, err := pass.Run(ctx, clusterId, shard, startAfter)
	if result != nil && result.More {
		request := EvsNightlyTaskRequest(clusterId, shard, result.NextStartAfter, pass.clock.Now(), pass.settings)
		if scheduleErr := host.Tasks.Schedule(ctx, request); scheduleErr != nil && err == nil {
			err = scheduleErr
		}
	}
	return result, err
}
