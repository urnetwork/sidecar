// Orphan GC by the evacuation horizon (§11.13's orphans and why rows as DESIGN-DETAILS 2.2.4 and 2.2.5 give them;
// D-EVS-25, D-EVS-34, I-EVS-5; EVSB-M2-13): the nightly pass's deletion of segments and path maps no committed push
// adopted. It raises no fence, waits no deadline, makes no second check and reads no batch. It waits for evacuation
// instead:
//
//	horizon  H of the repo's metadata cluster, which the pass read from one LIST of pb/ before any LIST of pidx/
//	         (nightly.go's OrphanHorizon): every batch whose minute starts before H has been evacuated, so every
//	         push whose record is older has committed, behind a pidx/ entry that names the segments it introduced,
//	         or never will
//	orphan   a seg/ object whose LastModified + AdoptionBound is at or before H and whose id no pidx/ entry of the
//	         repo lists as introduced
//	delete   one DELETE naming the object's listed LastModified (sidecar.WithBlobUnmodified), so a run that wakes
//	         late, or beside its successor, removes the object it judged or nothing: a 412 is an id uploaded again,
//	         a new object judged on a later night
//
// Per repo, on what the pass listed after it took H:
//
//	gates    nothing while this process's clock is unsure, nor while SettlePassed is false on the segment cluster
//	         or on the repo's metadata cluster (§19.6); and only while repo/ shows active or deleted and no hold
//	         covers the repo, each cached at most 5 s and read again before each DELETE
//	index    the introduced ids of every pidx/ entry whose own LastModified is at or after the oldest candidate's,
//	         less an hour, each by one GET; a listed entry that is gone (a pack replaced its parcel) lists its ref
//	         again and reads what was not read, once; over PidxReadCount entries nothing of the repo is deleted
//	         that night, alarmed
//	maps     a path map above its ref's current epoch goes the same way once H has passed its oldest part's bound,
//	         each part by a DELETE naming its LastModified; one at or below the head's epoch is §11.6's to judge
//
// A held key or an unknown outcome leaves the object for a later night and is never counted as deleted. Nothing
// here is funded or metered: the DELETEs are on the HDDs, which spend no NVMe budget, or a few a night on the
// metadata cluster for a map's parts (2.4). GC killed anywhere has nothing to undo: it holds no fence, lease or
// cursor, and the next night judges again.
//
// Safe for concurrent use: a run keeps its own state, and the pace is shared under stateLock.

package evsservice

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// DESIGN-DETAILS 2.2.4's AdoptionBound, a floor no setting passes: the last minute directory that can hold a
// record adopting a segment starts no later than its LastModified + 24 h + 2 min (a receipt's 24 h, 100 ms for its
// stamp, step 7's 5 s, 50 ms for each of two clocks and a key's minute, with 54.8 s to spare).
const evsOrphanMinAdoptionBound = 24*time.Hour + 2*time.Minute

// How far before the oldest candidate's LastModified a pidx/ entry may have been written and still be one GC must
// read: an hour (2.2.4's step 4).
const evsOrphanIndexMargin = 1 * time.Hour

// The series orphan GC exports per segment cluster, with no network or repo label (D-OPS-8).
const orphanDeletesMetricName = "urnetwork_evs_orphan_deletes_total"

// The outcome label's values: a closed vocabulary.
const (
	OrphanOutcomeDeleted  = "deleted"
	OrphanOutcomeReplaced = "replaced"
	OrphanOutcomeHeld     = "held"
	OrphanOutcomeFailed   = "failed"
)

// The alarm an index past its bound raises.
const orphanIndexBoundAlarm = "gc_orphan_index_bound"

// Settings past 2.2.4's floor, or ones a run cannot work with.
var ErrOrphanGcSettings = errors.New("evs orphan gc settings invalid")

// Tunables of orphan GC (DESIGN-DETAILS 2.2.4).
type OrphanGcSettings struct {
	// How long after its LastModified a segment, or a map's oldest part, may still be adopted by a record in a
	// batch: 24 h + 2 min, and never less.
	AdoptionBound time.Duration
	// The pass keeps no cursor, so each night judges the objects whose bound the horizon passed within this long:
	// 7 d, a segment about seven times. A pass that did not run for longer is followed by one run with it set to
	// the gap.
	Window time.Duration
	// The most segments one run deletes for one repo: 1,024.
	DeleteCount int
	// The most DELETEs a second on a segment cluster: 10, as a drop job's.
	DeleteRate int
	// The most pidx/ entries one run reads for one repo: 4,096. Past it nothing of the repo is deleted that night.
	PidxReadCount int
	// Keys a LIST page asks for. Must be positive.
	ListLimit int
	// The share of the segment cluster's measured capacity past which its DELETEs pause: half, as a drop job's.
	BusyShare float64
}

// 2.2.4's figures.
func DefaultOrphanGcSettings() *OrphanGcSettings {
	return &OrphanGcSettings{
		AdoptionBound: evsOrphanMinAdoptionBound,
		Window:        7 * 24 * time.Hour,
		DeleteCount:   1024,
		DeleteRate:    10,
		PidxReadCount: 4096,
		ListLimit:     1000,
		BusyShare:     0.5,
	}
}

// ErrOrphanGcSettings for a bound under its floor or a value a run cannot work with.
func (self *OrphanGcSettings) Validate() error {
	switch {
	case self.AdoptionBound < evsOrphanMinAdoptionBound:
		return fmt.Errorf("%w: an adoption bound of %s, under %s", ErrOrphanGcSettings, self.AdoptionBound, evsOrphanMinAdoptionBound)
	case self.Window <= 0 || self.DeleteCount <= 0 || self.DeleteRate <= 0 || self.PidxReadCount <= 0 || self.ListLimit <= 0 ||
		self.BusyShare <= 0 || 1 < self.BusyShare:
		return fmt.Errorf("%w: a bound that is not positive", ErrOrphanGcSettings)
	}
	return nil
}

// What orphan GC runs on beyond its host.
type OrphanGcDeps struct {
	// The holds every delete reads. nil reads hold/ through a HoldCache of its own.
	Holds *HoldCache
	// repo/, cached at most 5 s. nil: a cache of its own.
	Repos *RepoCache
	// nil: the defaults.
	Settings *OrphanGcSettings
	// repo/'s cache age and the format this instance reads. nil: the defaults.
	EvsSettings *EvsSettings
	// Whether the segment cluster's drive operations are past half its measured capacity, which pauses its
	// DELETEs as it pauses a drop job's ({nvb_<cluster>}, §19.6's hdd row). nil reads {nvb_<cluster>}'s figures,
	// and a cluster with no live figures or no measured capacity is busy, as a drop job stays paused while
	// hdd_capacity_ops is absent (plan-EVSB-settle-gate).
	SegmentClusterBusy func(ctx context.Context, clusterId string) bool
	// Alarms. nil discards.
	Log sidecar.Logger
	// a test's: called at each barrier, an error stopping the run there as a kill would
	atStep func(name string, key string) error
	// a test's: stands in for the pace's wait, on a clock the test moves
	wait func(wait time.Duration)
}

// One repo as the nightly pass listed it, every listing issued after Horizon was taken.
type OrphanGcRepo struct {
	RepoId sidecar.Id
	// The cluster the repo's place/ names, and the horizon read from it.
	MetadataCluster sidecar.BlobCluster
	Horizon         time.Time
	// seg/<repo>/ on the segment cluster.
	Segments []*sidecar.BlobInfo
	// pidx/<repo>/ and pmap/<repo>/ on the metadata cluster.
	PidxEntries  []*sidecar.BlobInfo
	PathMapParts []*sidecar.BlobInfo
}

// What one repo's run did, in counts with no id (I-13).
type OrphanGcResult struct {
	// Segments whose bound the horizon passed within the window, and pidx/ entries read for them.
	CandidateCount int
	PidxReadCount  int
	// Segment DELETEs by outcome.
	DeletedCount  int
	ReplacedCount int
	HeldCount     int
	FailedCount   int
	// Path map parts deleted, of maps above their ref's epoch.
	MapPartDeletedCount int
	// Why the run deleted nothing, or stopped: empty when it ran through.
	Skipped string
	// Candidates remain past DeleteCount: a later night takes them.
	More bool
}

// See the file header.
type OrphanGc struct {
	host        *sidecar.ServiceHost
	deps        *OrphanGcDeps
	settings    *OrphanGcSettings
	evsSettings *EvsSettings
	log         sidecar.Logger
	clock       sidecar.Clock
	holds       *HoldCache
	repos       *RepoCache
	heads       *HeadStore
	priceTable  *PriceTable

	deletesCounter sidecar.MetricsCounter

	stateLock sync.Mutex
	// when each segment cluster may take its next DELETE
	clusterNextDeleteTimes map[string]time.Time
}

// Orphan GC on host, which needs Blobs. Its ClockCheck is read per run and per DELETE, nil reading as unsure.
func NewOrphanGc(host *sidecar.ServiceHost, deps *OrphanGcDeps) (*OrphanGc, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return nil, errors.New("evs's orphan gc needs a host with Blobs and a write budget")
	}
	if deps == nil {
		deps = &OrphanGcDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultOrphanGcSettings()
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
	holds := deps.Holds
	if holds == nil {
		holds = NewHoldCache(host.Blobs, clock, nil)
	}
	repos := deps.Repos
	if repos == nil {
		repos = NewRepoCache(clock, evsSettings)
	}
	self := &OrphanGc{
		host:                   host,
		deps:                   deps,
		settings:               settings,
		evsSettings:            evsSettings,
		log:                    log,
		clock:                  clock,
		holds:                  holds,
		repos:                  repos,
		heads:                  NewHeadStore(clock, host.ClockCheck, nil, evsSettings, log),
		priceTable:             priceTable,
		clusterNextDeleteTimes: map[string]time.Time{},
	}
	if host.Metrics != nil {
		self.deletesCounter = host.Metrics.Counter(orphanDeletesMetricName, "DELETEs orphan gc issued for unadopted segments, by outcome.", "cluster", "outcome")
	}
	return self, nil
}

// The settings in force.
func (self *OrphanGc) Settings() *OrphanGcSettings {
	return self.settings
}

func (self *OrphanGc) clockSure() bool {
	return self.host.ClockCheck != nil && self.host.ClockCheck.Sure()
}

func (self *OrphanGc) step(name string, key string) error {
	testHookBarrier(name, key)
	if self.deps.atStep != nil {
		return self.deps.atStep(name, key)
	}
	return nil
}

func (self *OrphanGc) alarm(name string, repoId sidecar.Id, format string, args ...any) {
	self.log.Errorf("[evs] alarm %s: repo %s: %s", name, sidecar.EvsKeyId(repoId), fmt.Sprintf(format, args...))
}

// Step 2's two reads: repo/ must show active or deleted in a format this instance reads, and no hold may cover
// the repo. Anything unread, or a repo whose network is not known, stops the repo: its why is not empty.
func (self *OrphanGc) repoWhy(ctx context.Context, repo *OrphanGcRepo) string {
	read, err := self.repos.Read(ctx, repo.MetadataCluster, repo.RepoId)
	if err != nil {
		return "repo/ unread"
	}
	cover, err := self.holds.CoveringRepo(ctx, repo.RepoId, read.Object)
	if err != nil || cover.Covered() {
		return "held"
	}
	if !read.FormatWithin(self.evsSettings.InstanceFormat) {
		return "repo/ format"
	}
	switch read.Object.GetState() {
	case protocol.EvsRepoState_EVS_REPO_ACTIVE, protocol.EvsRepoState_EVS_REPO_DELETED:
		return ""
	}
	return "repo/ state"
}

// Whether an object's bound is one this run judges: passed by the horizon, within the window.
func (self *OrphanGc) due(lastModified time.Time, horizon time.Time) bool {
	bound := lastModified.Add(self.settings.AdoptionBound)
	return !bound.After(horizon) && !bound.Before(horizon.Add(-self.settings.Window))
}

// One repo's run. A nil error with Skipped set means a gate or a doubt kept everything; an error is a read that
// failed or a step a test stopped, and likewise deleted nothing more.
func (self *OrphanGc) RunRepo(ctx context.Context, repo *OrphanGcRepo) (*OrphanGcResult, error) {
	result := &OrphanGcResult{}
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		return result, err
	}
	// step 0
	switch {
	case !self.clockSure():
		result.Skipped = "clock unsure"
		return result, nil
	case !segmentCluster.SettlePassed() || !repo.MetadataCluster.SettlePassed():
		result.Skipped = "settle not passed"
		return result, nil
	case repo.Horizon.IsZero():
		result.Skipped = "no horizon"
		return result, nil
	}
	// step 2
	if why := self.repoWhy(ctx, repo); why != "" {
		result.Skipped = why
		return result, nil
	}

	// step 3, oldest first
	candidates := []*sidecar.BlobInfo{}
	for _, segment := range repo.Segments {
		if self.due(segment.LastModified, repo.Horizon) {
			candidates = append(candidates, segment)
		}
	}
	slices.SortStableFunc(candidates, func(a *sidecar.BlobInfo, b *sidecar.BlobInfo) int {
		return a.LastModified.Compare(b.LastModified)
	})
	result.CandidateCount = len(candidates)

	if 0 < len(candidates) {
		introduced, why, err := self.introduced(ctx, repo, candidates[0].LastModified, result)
		if err != nil {
			return result, err
		}
		if why != "" {
			result.Skipped = why
			return result, nil
		}
		if stop, err := self.deleteOrphans(ctx, repo, segmentCluster, candidates, introduced, result); err != nil || stop {
			return result, err
		}
	}
	return result, self.deleteMaps(ctx, repo, result)
}

// Step 4: the ids every pidx/ entry written since the oldest candidate, less an hour, lists as introduced. A why
// that is not empty means nothing of the repo may be deleted in this run.
func (self *OrphanGc) introduced(ctx context.Context, repo *OrphanGcRepo, oldest time.Time, result *OrphanGcResult) (map[string]bool, string, error) {
	repoKey := barrierRepoKey(repo.RepoId)
	since := oldest.Add(-evsOrphanIndexMargin)
	introduced := map[string]bool{}
	readKeys := map[string]bool{}
	read := func(key string) (found bool, err error) {
		if self.settings.PidxReadCount <= result.PidxReadCount {
			return false, errOrphanIndexBound
		}
		result.PidxReadCount += 1
		readKeys[key] = true
		entryBytes, err := readBlob(ctx, repo.MetadataCluster, key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		entry, err := DecodeEvsPidxEntry(entryBytes)
		if err != nil {
			return false, err
		}
		for _, segmentId := range entry.GetSegmentIds() {
			introduced[string(segmentId)] = true
		}
		return true, nil
	}
	bound := func(err error) (map[string]bool, string, error) {
		if errors.Is(err, errOrphanIndexBound) {
			self.alarm(orphanIndexBoundAlarm, repo.RepoId, "over %d pidx/ entries to read: nothing of it is deleted in this run", self.settings.PidxReadCount)
			return nil, "index bound", nil
		}
		return nil, "", err
	}

	// refs whose listed entry was gone, to list again, once
	goneRefPrefixes := []string{}
	for _, entry := range repo.PidxEntries {
		if entry.LastModified.Before(since) {
			continue
		}
		found, err := read(entry.Key)
		if err != nil {
			return bound(err)
		}
		if !found {
			refPrefix := pidxRefPrefixOf(entry.Key)
			if refPrefix == "" {
				return nil, "pidx/ key", nil
			}
			if !slices.Contains(goneRefPrefixes, refPrefix) {
				goneRefPrefixes = append(goneRefPrefixes, refPrefix)
			}
		}
	}
	for _, refPrefix := range goneRefPrefixes {
		// a pack replaced a parcel: its entries were written before the parcel's went (§11.13's index row), so
		// the ref's listing now shows them. One that shows nothing new explains nothing, and nothing goes.
		startAfter := ""
		replaced := false
		for {
			objects, more, err := repo.MetadataCluster.List(ctx, refPrefix, startAfter, self.settings.ListLimit)
			if err != nil {
				return nil, "", err
			}
			for _, object := range objects {
				startAfter = object.Key
				if readKeys[object.Key] || object.LastModified.Before(since) {
					continue
				}
				found, err := read(object.Key)
				if err != nil {
					return bound(err)
				}
				if !found {
					// still missing: nothing of the repo goes tonight (2.5)
					return nil, "pidx/ entry gone twice", nil
				}
				replaced = true
			}
			if !more {
				break
			}
		}
		if !replaced {
			return nil, "pidx/ entry gone, nothing in its place", nil
		}
	}
	if err := self.step(BarrierGcIndexAfter, repoKey); err != nil {
		return nil, "", err
	}
	return introduced, "", nil
}

// Read past PidxReadCount.
var errOrphanIndexBound = errors.New("evs orphan gc index bound")

// The segment cluster's drives are busy, or unmeasured: its deletes wait for a later night.
var errOrphanClusterBusy = errors.New("evs orphan gc segment cluster busy")

// repo/ or hold/, reread as a write issued, let it go no further.
var errOrphanRepoStops = errors.New("evs orphan gc repo stops")

// A P2 grant of rank GC for one DELETE on the repo's metadata cluster, unfunded: GC has no payer (§11.13's wallet
// row). Step 2's reads run again as the write issues.
func (self *OrphanGc) acquire(ctx context.Context, repo *OrphanGcRepo) (sidecar.WriteGrant, error) {
	byteCount, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationDelete, Count: 1})
	if err != nil {
		return nil, err
	}
	return self.host.Budget.AcquireP2(ctx, repo.MetadataCluster.ClusterId(), &sidecar.WriteP2Work{
		Rank:      sidecar.WriteP2RankGc,
		Due:       self.clock.Now(),
		ByteCount: byteCount,
		Recheck: func(ctx context.Context) error {
			if why := self.repoWhy(ctx, repo); why != "" {
				return fmt.Errorf("%w: %s", errOrphanRepoStops, why)
			}
			return nil
		},
	})
}

// pidx/<repo>/<ref>/ of an entry's key, empty for a key of another shape.
func pidxRefPrefixOf(key string) string {
	last := strings.LastIndexByte(key, '/')
	if last < 0 || !strings.HasPrefix(key, pidxKeyPrefix) {
		return ""
	}
	refPrefix := key[:last+1]
	if _, _, ok := parsePidxKey(refPrefix, key); !ok {
		return ""
	}
	return refPrefix
}

// Whether the segment cluster's drives are past half its measured capacity, or it has none measured.
func (self *OrphanGc) busy(ctx context.Context, clusterId string) bool {
	if self.deps.SegmentClusterBusy != nil {
		return self.deps.SegmentClusterBusy(ctx, clusterId)
	}
	if self.host.Redis == nil {
		return true
	}
	figures, err := readHddFigures(ctx, self.host.Redis, clusterId)
	if err != nil || figures == nil || figures.CapacityOps <= 0 {
		return true
	}
	return float64(figures.CapacityOps)*self.settings.BusyShare < figures.DriveOpsPerSecond
}

// Waits until the segment cluster may take its next DELETE: DeleteRate a second. A busy cluster ends the run's
// deletes there (errOrphanClusterBusy), as it pauses a drop job's, and the next night tries again.
func (self *OrphanGc) pace(ctx context.Context, clusterId string) error {
	if self.busy(ctx, clusterId) {
		return errOrphanClusterBusy
	}
	interval := time.Second / time.Duration(self.settings.DeleteRate)
	for {
		now := self.clock.Now()
		wait := time.Duration(0)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			next := self.clusterNextDeleteTimes[clusterId]
			if now.Before(next) {
				wait = next.Sub(now)
				return
			}
			self.clusterNextDeleteTimes[clusterId] = now.Add(interval)
		}()
		if wait == 0 {
			return nil
		}
		if self.deps.wait != nil {
			self.deps.wait(wait)
			continue
		}
		select {
		case <-self.clock.After(wait):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (self *OrphanGc) count(clusterId string, outcome string) {
	if self.deletesCounter != nil {
		self.deletesCounter.Add(1, clusterId, outcome)
	}
}

// Step 5: each candidate no entry introduces, oldest first. stop is true when a gate ended the repo's run.
func (self *OrphanGc) deleteOrphans(ctx context.Context, repo *OrphanGcRepo, segmentCluster sidecar.BlobCluster, candidates []*sidecar.BlobInfo, introduced map[string]bool, result *OrphanGcResult) (stop bool, err error) {
	clusterId := segmentCluster.ClusterId()
	segmentPrefix := segmentKeyPrefix + sidecar.EvsKeyId(repo.RepoId) + "/"
	issued := 0
	for _, segment := range candidates {
		idHex, ok := strings.CutPrefix(segment.Key, segmentPrefix)
		segmentId, hexErr := hex.DecodeString(idHex)
		if !ok || hexErr != nil || len(segmentId) != 32 {
			// not a segment's key: nothing here judges it
			continue
		}
		if introduced[string(segmentId)] {
			continue
		}
		if self.settings.DeleteCount <= issued {
			result.More = true
			return false, nil
		}
		if err := self.pace(ctx, clusterId); err != nil {
			if errors.Is(err, errOrphanClusterBusy) {
				result.Skipped = "segment cluster busy"
				return true, nil
			}
			return true, err
		}
		// step 2's two reads again, and the clock's, as the DELETE issues
		if !self.clockSure() {
			result.Skipped = "clock unsure"
			return true, nil
		}
		if why := self.repoWhy(ctx, repo); why != "" {
			result.Skipped = why
			return true, nil
		}
		barrierKey := barrierSegmentKey(repo.RepoId, segmentId)
		if err := self.step(BarrierGcDeleteBefore, barrierKey); err != nil {
			return true, err
		}
		issued += 1
		deleteErr := segmentCluster.Delete(sidecar.WithBlobUnmodified(ctx, segment.LastModified), segment.Key)
		switch {
		case deleteErr == nil:
			result.DeletedCount += 1
			self.count(clusterId, OrphanOutcomeDeleted)
		case errors.Is(deleteErr, sidecar.ErrBlobPrecondition):
			// the id was uploaded again: a new object, judged on a later night
			result.ReplacedCount += 1
			self.count(clusterId, OrphanOutcomeReplaced)
		case errors.Is(deleteErr, sidecar.ErrBlobHeld):
			result.HeldCount += 1
			self.count(clusterId, OrphanOutcomeHeld)
		default:
			// unknown: never counted as deleted, and listed again the next night
			result.FailedCount += 1
			self.count(clusterId, OrphanOutcomeFailed)
		}
		if err := self.step(BarrierGcDeleteAfter, barrierKey); err != nil {
			return true, err
		}
	}
	return false, nil
}

// One listed map: its ref, its epoch and its parts.
type orphanPathMap struct {
	refId  sidecar.Id
	epoch  uint64
	prefix string
	parts  []*sidecar.BlobInfo
	// its oldest part's LastModified
	oldest time.Time
}

// The maps of a repo's pmap/<repo>/<ref>/<p>/<map>/<part>/_ listing. A key of another shape is left alone.
func orphanPathMaps(repoId sidecar.Id, parts []*sidecar.BlobInfo) []*orphanPathMap {
	repoPrefix := pathMapKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	prefixMaps := map[string]*orphanPathMap{}
	pathMaps := []*orphanPathMap{}
	for _, part := range parts {
		rest, ok := strings.CutPrefix(part.Key, repoPrefix)
		if !ok || !strings.HasSuffix(rest, leafKeySuffix) {
			continue
		}
		fields := strings.Split(strings.TrimSuffix(rest, leafKeySuffix), "/")
		if len(fields) != 4 || len(fields[1]) != 20 || len(fields[2]) != 64 || len(fields[3]) != 20 {
			continue
		}
		refId, err := sidecar.ParseId(fields[0])
		if err != nil || sidecar.EvsKeyId(refId) != fields[0] {
			continue
		}
		epoch, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		prefix := repoPrefix + fields[0] + "/" + fields[1] + "/" + fields[2] + "/"
		pathMap, ok := prefixMaps[prefix]
		if !ok {
			pathMap = &orphanPathMap{refId: refId, epoch: epoch, prefix: prefix, oldest: part.LastModified}
			prefixMaps[prefix] = pathMap
			pathMaps = append(pathMaps, pathMap)
		}
		pathMap.parts = append(pathMap.parts, part)
		if part.LastModified.Before(pathMap.oldest) {
			pathMap.oldest = part.LastModified
		}
	}
	return pathMaps
}

// DESIGN-DETAILS 2.2.5: a map whose oldest part's bound the horizon passed, above its ref's current path epoch, is
// uncommitted and never will commit, and each of its parts goes by a DELETE naming its LastModified. The ref's
// head is read from the cluster after the horizon; a held key leaves the map for a later night.
func (self *OrphanGc) deleteMaps(ctx context.Context, repo *OrphanGcRepo, result *OrphanGcResult) error {
	for _, pathMap := range orphanPathMaps(repo.RepoId, repo.PathMapParts) {
		if !self.due(pathMap.oldest, repo.Horizon) {
			continue
		}
		head, err := self.heads.ReadCluster(ctx, repo.MetadataCluster, repo.RepoId, pathMap.refId)
		if err != nil {
			// held, or unread: the map stays
			continue
		}
		if pathMap.epoch <= head.Head.GetPathEpoch().GetCurrent() {
			// §11.6's "once p or a newer epoch commits" rule knows the committed map
			continue
		}
		for _, part := range pathMap.parts {
			if !self.clockSure() {
				result.Skipped = "clock unsure"
				return nil
			}
			if why := self.repoWhy(ctx, repo); why != "" {
				result.Skipped = why
				return nil
			}
			barrierKey := barrierRefKey(repo.RepoId, pathMap.refId)
			if err := self.step(BarrierGcDeleteBefore, barrierKey); err != nil {
				return err
			}
			// a metadata DELETE: unfunded P2 of rank GC, rereading repo/ and hold/ as it issues
			grant, err := self.acquire(ctx, repo)
			if err != nil {
				if errors.Is(err, errOrphanRepoStops) {
					result.Skipped = "repo/ or hold/ at issue"
					return nil
				}
				return err
			}
			deleteErr := repo.MetadataCluster.Delete(sidecar.WithBlobUnmodified(grant.Context(), part.LastModified), part.Key)
			grant.Close()
			if deleteErr == nil {
				result.MapPartDeletedCount += 1
			}
			if err := self.step(BarrierGcDeleteAfter, barrierKey); err != nil {
				return err
			}
		}
	}
	return nil
}
