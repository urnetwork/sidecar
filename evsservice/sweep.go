// The versionless sweep (§11.13's sweep row; R-EVS-20, D-EVS-37, D-EVS-40, I-EVS-9, FI-16; EVSB-M10-02; DESIGN-DETAILS
// 2.7's note): the backstop of the committing process's purge (purge.go). Evacuation, resolving each committed record
// that lists candidates, sweeps them before the minute's batches go, so a lost queue or a failed DELETE leaves content
// at most ~26 h:
//
//	judge    for each candidate the path's newest version does not name (read from the cluster now) and no hold
//	         keeps (an uploaded segment or a slot by its LastModified; a staged one, whose batch time a seg/ copy no
//	         longer carries, under any covering hold), one HEAD, staged ones at seg/, slots on the metadata cluster
//	delete   only a present one, naming that HEAD's LastModified (sidecar.WithBlobUnmodified), so a later upload of
//	         the same id is never taken; a 404, or a 412 for a newer object, counts absent, and only a 204 counts
//	         deleted (§19.8's urnetwork_evs_versionless_sweep_deletes_total and purged_bytes_total{by="sweep"}, whose
//	         deleted share warns past 1% a day)
//	report   nothing: the nightly pass counts what it frees
//
// A marked list names no ids, and the sweep recomputes it from the replaced versions (sweep_recompute.go); a path
// whose replaced version it cannot find keeps its content, alarming. A list with replaced set is a part's record's,
// each replaced version's ids whole with nothing subtracted (DESIGN-DETAILS 10.2.6): it is never a candidate list,
// whoever reads it, so the sweep skips it, and a push in parts is swept by its seal's list, which subtracts every
// part's versions. Nothing deletes while §19.11's purge mode is
// observe, on a build that has not passed §19.6's settle cases, or for a repo whose repo/ names no network. A clock
// unsure, a key held or a store that did not answer is a retry: the caller's minute waits.
//
// Two one-off passes reread a repo's versions flagged with window bit 4 (log pages, then records, through pidx/ once
// evacuated): at a hold's end, those whose minute falls from 26 h before its placement to its end, deleting what the
// hold kept (HoldEndPass); and when the purge turns on from observe, those since the repo's migration, deleting what
// observe mode kept (TurnOnPass). Both need SettlePassed and delete with the header, as the sweep does; taskworker
// runs them as evs.sweep jobs (sweep_task.go).
//
// Safe for concurrent use: a call keeps its own state.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The sweep's series (§19.8's versionless row), with no network or repo label.
const (
	versionlessSweepDeletesMetricName = "urnetwork_evs_versionless_sweep_deletes_total"
	versionlessSweepDeleted           = "deleted"
	versionlessSweepAbsent            = "absent"
)

// A sweep that must be tried again: a key held, a store that did not answer, a clock unsure. Nothing was decided on it.
var ErrSweepRetry = errors.New("evs sweep: try again later")

// Settings a sweep cannot work with.
var ErrSweepSettings = errors.New("evs sweep settings invalid")

// Tunables of the sweep.
type SweepSettings struct {
	// Keys a LIST page asks for in a pass. Must be positive.
	ListLimit int
	// How far back a marked list's recompute walks u's ref, in versions, for a version u replaced that neither its
	// own prev_commit_version nor the path's folded entry names: 4,096, 64 log pages. A version further back keeps
	// its content, alarming. Must be positive.
	RecomputeVersionCount int
	// §11.13's hold-end window: a hold's pass rereads versions from this long before its placement, 26 h, a
	// batch's longest life before evacuation. Must be positive.
	HoldEndLead time.Duration
}

// A LIST page of 1,000 keys, a walk of 64 log pages and §11.13's 26 h.
func DefaultSweepSettings() *SweepSettings {
	return &SweepSettings{
		ListLimit:             1000,
		RecomputeVersionCount: 4096,
		HoldEndLead:           26 * time.Hour,
	}
}

// ErrSweepSettings for a bound that is not positive.
func (self *SweepSettings) Validate() error {
	if self.ListLimit <= 0 || self.RecomputeVersionCount <= 0 || self.HoldEndLead <= 0 {
		return fmt.Errorf("%w: a bound that is not positive", ErrSweepSettings)
	}
	return nil
}

// What a Sweep runs on beyond its host.
type SweepDeps struct {
	// §19.11's purge mode. nil reads observe: nothing deletes.
	Format2 Format2Gate
	// The path's newest version. nil reads it through a head store and record cache of the sweep's own.
	Newest PurgeNewestReader
	// The holds each DELETE reads. nil reads hold/ through a HoldCache of the sweep's own.
	Holds *HoldCache
	// repo/'s cache age and the price table's block size. nil: the defaults.
	EvsSettings *EvsSettings
	// nil: the defaults.
	Settings *SweepSettings
	// Alarms. nil discards.
	Log sidecar.Logger
	// a test's: called at each barrier, an error stopping the sweep there as a kill would
	atStep func(name string, key string) error
}

// One committed record's purge list as the sweep takes it.
type SweepTarget struct {
	RepoId sidecar.Id
	RefId  sidecar.Id
	// repo/'s object, whose network's holds keep.
	Repo *protocol.EvsRepoObject
	// The path epoch the list's token paths are in: its push's.
	PathEpoch uint64
	// The record whose tail holds the list, and the ref version its push committed at, which a marked list is
	// recomputed from. A nil record leaves a marked list's content where it is, alarming.
	Record        *sidecar.EvsBatchRecord
	CommitVersion uint64
	List          *protocol.EvsPurgeList
}

// What a sweep did, in counts with no id (I-13).
type SweepResult struct {
	CandidateCount int
	DeletedCount   int
	AbsentCount    int
	NamedCount     int
	HeldCount      int
	// candidates a gate or a path it cannot judge left where they are; a marked list a gate kept or its recompute
	// could not read counts one, and each of its paths whose replaced version the recompute did not find one
	KeptCount      int
	FreedByteCount int64
	// records a pass reread
	RecordCount int
	// marked lists recomputed
	RecomputedCount int
}

func (self *SweepResult) add(other *SweepResult) {
	self.CandidateCount += other.CandidateCount
	self.DeletedCount += other.DeletedCount
	self.AbsentCount += other.AbsentCount
	self.NamedCount += other.NamedCount
	self.HeldCount += other.HeldCount
	self.KeptCount += other.KeptCount
	self.FreedByteCount += other.FreedByteCount
	self.RecordCount += other.RecordCount
	self.RecomputedCount += other.RecomputedCount
}

// See the file header.
type Sweep struct {
	host        *sidecar.ServiceHost
	deps        *SweepDeps
	settings    *SweepSettings
	evsSettings *EvsSettings
	clock       sidecar.Clock
	log         sidecar.Logger
	format2     Format2Gate
	holds       *HoldCache
	newest      PurgeNewestReader
	// the host's Blobs, its metadata writes held to the budget
	blobs      sidecar.BlobStore
	priceTable *PriceTable
	repos      *RepoCache
	heads      *HeadStore
	logPages   *LogPageCache
	locator    *RecordLocator

	deletesCounter sidecar.MetricsCounter
	purgedCounter  sidecar.MetricsCounter
}

// A sweep on host, which needs Blobs and a write budget, since a slot's DELETE is a metadata write.
func NewSweep(host *sidecar.ServiceHost, deps *SweepDeps) (*Sweep, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return nil, errors.New("evs's sweep needs a host with Blobs and a write budget")
	}
	if deps == nil {
		deps = &SweepDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultSweepSettings()
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
	format2 := deps.Format2
	if format2 == nil {
		format2 = ClosedFormat2Gate{}
	}
	clock := host.ClockOrReal()
	holds := deps.Holds
	if holds == nil {
		holds = NewHoldCache(host.Blobs, clock, nil)
	}
	priceTable, err := DefaultPriceTable(evsSettings.PriceBlockByteCount)
	if err != nil {
		return nil, err
	}
	blobs := sidecar.BlobStore(NewBudgetedBlobs(host.Blobs))
	heads := NewHeadStore(clock, host.ClockCheck, nil, evsSettings, log)
	newest := deps.Newest
	if newest == nil {
		newest = &headPurgeNewest{heads: heads, records: NewRecordCache(evsSettings), locator: NewRecordLocator(blobs, nil)}
	}
	self := &Sweep{
		host:        host,
		deps:        deps,
		settings:    settings,
		evsSettings: evsSettings,
		clock:       clock,
		log:         log,
		format2:     format2,
		holds:       holds,
		newest:      newest,
		blobs:       blobs,
		priceTable:  priceTable,
		repos:       NewRepoCache(clock, evsSettings),
		heads:       heads,
		logPages:    NewLogPageCache(evsSettings),
		locator:     NewRecordLocator(blobs, nil),
	}
	if host.Metrics != nil {
		self.deletesCounter = host.Metrics.Counter(versionlessSweepDeletesMetricName, "Sweep DELETEs of replaced versionless content, by what the HEAD before each found.", "result")
		self.purgedCounter = host.Metrics.Counter(versionlessPurgedBytesMetricName, "Replaced versionless content deleted, stored bytes, by who deleted it.", "by")
	}
	return self, nil
}

// A test's stop at the barrier a site has just passed; each site calls testHookBarrier with its own name, so the
// inventory lists it.
func (self *Sweep) step(name string, key string) error {
	if self.deps.atStep != nil {
		return self.deps.atStep(name, key)
	}
	return nil
}

func (self *Sweep) clockSure() bool {
	return self.host.ClockCheck != nil && self.host.ClockCheck.Sure()
}

// One committed record's list, as evacuation sweeps it before its batch goes and a pass after it reread the
// record: see the file header. funded says whether a slot's DELETE spends the wallet, as evacuation's does, and due
// orders it among P2. ErrSweepRetry, with what it did, when a retry is owed.
func (self *Sweep) SweepList(ctx context.Context, cluster sidecar.BlobCluster, target *SweepTarget, rank sidecar.WriteP2Rank, funded bool, due time.Time) (*SweepResult, error) {
	result := &SweepResult{}
	list := target.List
	if list == nil || list.GetReplaced() {
		// a part's list deletes nothing: its seal's lists the candidates (DESIGN-DETAILS 10.2.6)
		return result, nil
	}
	refKey := barrierRefKey(target.RepoId, target.RefId)
	if !list.GetMarked() {
		result.CandidateCount = purgeListIdCount(list)
	}
	keep := func() (*SweepResult, error) {
		if list.GetMarked() {
			result.KeptCount += 1
		} else {
			result.KeptCount = result.CandidateCount
		}
		return result, nil
	}
	if self.format2.PurgeMode() != sidecar.Format2On {
		// observe mode keeps it, and the turn-on pass deletes it
		return keep()
	}
	segmentCluster, err := self.blobs.SegmentCluster()
	if err != nil {
		return result, err
	}
	if !cluster.SettlePassed() || !segmentCluster.SettlePassed() {
		return keep()
	}
	networkId, err := sidecar.IdFromBytes(target.Repo.GetNetworkId())
	if err != nil {
		// no network to read holds by: everything is kept (plan-EVSB-repo-network)
		return keep()
	}
	candidates := list.GetCandidates()
	if list.GetMarked() {
		recomputed, unfoundCount, err := self.recompute(ctx, cluster, target)
		switch {
		case err != nil && evacuateStoreError(err):
			return result, fmt.Errorf("%w: %v", ErrSweepRetry, err)
		case err != nil:
			self.log.Errorf("[evs] alarm sweep_marked_list: a marked purge list of %s is not recomputed: its content stays (%v)", refKey, err)
			return keep()
		}
		if 0 < unfoundCount {
			self.log.Errorf("[evs] alarm sweep_marked_list: %d paths of a marked purge list of %s replaced no version the sweep finds: their content stays", unfoundCount, refKey)
			result.KeptCount += unfoundCount
		}
		result.RecomputedCount += 1
		result.CandidateCount = purgeListIdCount(recomputed)
		candidates = recomputed.GetCandidates()
	}
	err = self.sweepCandidates(ctx, cluster, segmentCluster, target, networkId, candidates, rank, funded, due, result)
	return result, err
}

// Each candidate's ids judged and, when present, deleted: see the file header.
func (self *Sweep) sweepCandidates(ctx context.Context, cluster sidecar.BlobCluster, segmentCluster sidecar.BlobCluster, target *SweepTarget,
	networkId sidecar.Id, candidates []*protocol.EvsPurgeCandidate, rank sidecar.WriteP2Rank, funded bool, due time.Time, result *SweepResult) error {
	refKey := barrierRefKey(target.RepoId, target.RefId)
	for index, candidate := range candidates {
		tokenPath, err := sidecar.ParseEvsTokenPath(candidate.GetTokenPath())
		if err != nil {
			result.KeptCount += len(candidate.GetSegmentIds()) + len(candidate.GetStagedSegmentIds()) + len(candidate.GetSlotIds())
			continue
		}
		newest, err := self.newest.NewestNames(ctx, cluster, target.RepoId, target.RefId, target.PathEpoch, tokenPath)
		switch {
		case err != nil && evacuateStoreError(err):
			return fmt.Errorf("%w: %v", ErrSweepRetry, err)
		case err != nil:
			self.log.Errorf("[evs] alarm sweep_unjudged: a candidate path of %s cannot be judged: %v", refKey, err)
			result.KeptCount += len(candidate.GetSegmentIds()) + len(candidate.GetStagedSegmentIds()) + len(candidate.GetSlotIds())
			continue
		}
		type sweepId struct {
			id     []byte
			staged bool
			slot   bool
		}
		ids := []*sweepId{}
		for _, id := range candidate.GetSegmentIds() {
			ids = append(ids, &sweepId{id: id})
		}
		for _, id := range candidate.GetStagedSegmentIds() {
			ids = append(ids, &sweepId{id: id, staged: true})
		}
		for _, id := range candidate.GetSlotIds() {
			ids = append(ids, &sweepId{id: id, slot: true})
		}
		for j, sweepId := range ids {
			if newest.Names[string(sweepId.id)] {
				result.NamedCount += 1
				continue
			}
			if !self.clockSure() {
				return fmt.Errorf("%w: the clock unsure", ErrSweepRetry)
			}
			cover, err := self.holds.Covering(ctx, networkId, target.RepoId)
			if err != nil {
				cover = &sidecar.HoldCover{Unknown: true}
			}
			barrierKey := fmt.Sprintf("%s:%d:%d", refKey, index, j)
			var outcome string
			if sweepId.slot {
				outcome, err = self.sweepSlot(ctx, cluster, target.RepoId, sweepId.id, cover, rank, funded, due, barrierKey, result)
			} else {
				outcome, err = self.sweepSegment(ctx, segmentCluster, target.RepoId, sweepId.id, sweepId.staged, cover, barrierKey, result)
			}
			if err != nil {
				return err
			}
			switch outcome {
			case versionlessSweepDeleted:
				result.DeletedCount += 1
			case versionlessSweepAbsent:
				result.AbsentCount += 1
			default:
				result.HeldCount += 1
			}
			if outcome != "" && self.deletesCounter != nil {
				self.deletesCounter.Add(1, outcome)
			}
		}
	}
	return nil
}

// One candidate segment at seg/: HEAD, then a DELETE naming its LastModified. outcome is deleted, absent, or "" for
// one a hold keeps.
func (self *Sweep) sweepSegment(ctx context.Context, segmentCluster sidecar.BlobCluster, repoId sidecar.Id, id []byte, staged bool, cover *sidecar.HoldCover, barrierKey string, result *SweepResult) (string, error) {
	if len(id) != 32 {
		return versionlessSweepAbsent, nil
	}
	key := SegmentKey(repoId, [32]byte(id))
	info, err := segmentCluster.Head(ctx, key)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		return versionlessSweepAbsent, nil
	case err != nil:
		return "", fmt.Errorf("%w: %v", ErrSweepRetry, err)
	}
	if (staged && cover.Covered()) || cover.Keeps(info.LastModified) {
		return "", nil
	}
	testHookBarrier(BarrierSweepDeleteBefore, barrierKey)
	if err := self.step(BarrierSweepDeleteBefore, barrierKey); err != nil {
		return "", err
	}
	deleteErr := segmentCluster.Delete(sidecar.WithBlobUnmodified(ctx, info.LastModified), key)
	testHookBarrier(BarrierSweepDeleteAfter, barrierKey)
	if err := self.step(BarrierSweepDeleteAfter, barrierKey); err != nil && deleteErr == nil {
		self.countFreed(info.ByteCount, result)
		return versionlessSweepDeleted, err
	}
	switch {
	case deleteErr == nil:
		self.countFreed(info.ByteCount, result)
		return versionlessSweepDeleted, nil
	case errors.Is(deleteErr, sidecar.ErrBlobPrecondition):
		// a newer object under the id: not the one judged, and it stays
		return versionlessSweepAbsent, nil
	}
	return "", fmt.Errorf("%w: %v", ErrSweepRetry, deleteErr)
}

func (self *Sweep) countFreed(byteCount int64, result *SweepResult) {
	result.FreedByteCount += byteCount
	if self.purgedCounter != nil {
		self.purgedCounter.Add(float64(byteCount), versionlessPurgedBySweep)
	}
}

// One candidate slot on the metadata cluster, as P2 of rank: HEAD, then a DELETE naming its LastModified.
func (self *Sweep) sweepSlot(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, id []byte, cover *sidecar.HoldCover, rank sidecar.WriteP2Rank, funded bool, due time.Time, barrierKey string, result *SweepResult) (string, error) {
	slotId, err := sidecar.IdFromBytes(id)
	if err != nil {
		return versionlessSweepAbsent, nil
	}
	key := SlotKey(repoId, slotId)
	info, err := cluster.Head(ctx, key)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
		return versionlessSweepAbsent, nil
	case err != nil:
		return "", fmt.Errorf("%w: %v", ErrSweepRetry, err)
	}
	if cover.Keeps(info.LastModified) {
		return "", nil
	}
	byteCount, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationDelete, Count: 1})
	if err != nil {
		return "", err
	}
	grant, err := self.host.Budget.AcquireP2(ctx, cluster.ClusterId(), &sidecar.WriteP2Work{Rank: rank, Due: due, ByteCount: byteCount, Funded: funded})
	if err != nil {
		return "", err
	}
	defer grant.Close()
	testHookBarrier(BarrierSweepDeleteBefore, barrierKey)
	if err := self.step(BarrierSweepDeleteBefore, barrierKey); err != nil {
		return "", err
	}
	deleteErr := cluster.Delete(sidecar.WithBlobUnmodified(grant.Context(), info.LastModified), key)
	testHookBarrier(BarrierSweepDeleteAfter, barrierKey)
	stepErr := self.step(BarrierSweepDeleteAfter, barrierKey)
	switch {
	case deleteErr == nil:
		return versionlessSweepDeleted, stepErr
	case errors.Is(deleteErr, sidecar.ErrBlobPrecondition):
		return versionlessSweepAbsent, stepErr
	}
	return "", fmt.Errorf("%w: %v", ErrSweepRetry, deleteErr)
}

// At a hold's end (§11.13's sweep row): the repo's versions flagged with window bit 4 whose minute falls from 26 h
// before placeTime to endTime, each record's list swept again, deleting what the hold kept.
func (self *Sweep) HoldEndPass(ctx context.Context, clusterId string, repoId sidecar.Id, placeTime time.Time, endTime time.Time) (*SweepResult, error) {
	return self.pass(ctx, clusterId, repoId, placeTime.Add(-self.settings.HoldEndLead), endTime)
}

// When §19.11's purge turns on from observe: the repo's versions flagged with window bit 4 since its migration to
// format 2, each record's list swept, deleting what observe mode kept. A zero migrationTime takes every flagged
// version, which only format 2 sets.
func (self *Sweep) TurnOnPass(ctx context.Context, clusterId string, repoId sidecar.Id, migrationTime time.Time) (*SweepResult, error) {
	return self.pass(ctx, clusterId, repoId, migrationTime, self.clock.Now())
}

// The batch minute of at, minute 0 for a time before the Unix epoch, such as the zero time.
func sweepPassMinute(at time.Time) uint32 {
	if at.Unix() < 0 {
		return 0
	}
	return BatchMinute(at)
}

// The window entry and statement bytes of the push committed at version on head's ref: from the window, else from
// its log page, which once packed is read through its pack.
func (self *Sweep) entryAt(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, head *protocol.EvsHead, version uint64) (*sidecar.EvsWindowEntry, []byte, error) {
	if entry := windowEntryAt(head, version); entry != nil {
		return entry, nil, nil
	}
	if version == 0 || head.GetVersion() < version {
		return nil, nil, fmt.Errorf("%w: version %d past the head's %d", ErrEvsStatementMismatch, version, head.GetVersion())
	}
	page := EvsLogPageOf(version)
	logPage, err := ReadLogPage(ctx, self.logPages, cluster, repoId, refId, page)
	if errors.Is(err, ErrEvsRecordEvacuated) {
		pageBytes, locateErr := self.locator.ReadLogPage(ctx, cluster, repoId, refId, page)
		if locateErr != nil {
			return nil, nil, locateErr
		}
		if logPage, err = ParseLogPage(repoId, refId, page, pageBytes); err == nil {
			self.logPages.Put(cluster.ClusterId(), repoId, refId, logPage)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	entry, statementBytes, ok := logPage.At(version)
	if !ok {
		return nil, nil, fmt.Errorf("%w: log page %d lacks version %d", ErrEvsStatementMismatch, page, version)
	}
	return entry, statementBytes, nil
}

// Every flagged version of the repo's refs whose record's minute falls in [from, to]: the heads listed, then each
// ref's versions oldest first, from its log pages and its window, each flagged record read by its place (its batch,
// else through pidx/) and its list swept. Nothing deletes while a build has not passed the settle cases or the clock
// is unsure.
func (self *Sweep) pass(ctx context.Context, clusterId string, repoId sidecar.Id, from time.Time, to time.Time) (*SweepResult, error) {
	result := &SweepResult{}
	cluster, err := self.blobs.Cluster(clusterId)
	if err != nil {
		return result, err
	}
	segmentCluster, err := self.blobs.SegmentCluster()
	if err != nil {
		return result, err
	}
	if !cluster.SettlePassed() || !segmentCluster.SettlePassed() || !self.clockSure() {
		return result, fmt.Errorf("%w: a build that has not passed the settle cases, or the clock unsure", ErrSweepRetry)
	}
	repoRead, err := self.repos.Read(ctx, cluster, repoId)
	if err != nil {
		return result, err
	}
	headPrefix := headKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	refIds := []sidecar.Id{}
	startAfter := ""
	for {
		objects, more, err := cluster.List(ctx, headPrefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return result, err
		}
		for _, object := range objects {
			startAfter = object.Key
			rest := strings.TrimPrefix(object.Key, headPrefix)
			refText, _, _ := strings.Cut(rest, "/")
			if refId, err := sidecar.ParseId(refText); err == nil && sidecar.EvsKeyId(refId) == refText {
				refIds = append(refIds, refId)
			}
		}
		if !more || len(objects) == 0 {
			break
		}
	}
	fromMinute, toMinute := sweepPassMinute(from), sweepPassMinute(to)
	for _, refId := range refIds {
		head, err := self.heads.ReadCluster(ctx, cluster, repoId, refId)
		if err != nil {
			return result, err
		}
		if head.Absent() {
			continue
		}
		for version := uint64(1); version <= head.Head.GetVersion(); version += 1 {
			entry, _, err := self.entryAt(ctx, cluster, repoId, refId, head.Head, version)
			if err != nil {
				return result, err
			}
			if !entry.ReplacesVersionless() || entry.Place == nil {
				continue
			}
			if minute := entry.Place.GetMinute(); minute < fromMinute || toMinute < minute {
				continue
			}
			// the version's push or seal record, which alone lists its candidates: a seal's over every part, a part's
			// record only what its versions replaced (DESIGN-DETAILS 10.2.6), so no part is read
			recordBytes, err := self.locator.ReadRecord(ctx, cluster, repoId, refId, entry.Place)
			if err != nil {
				return result, err
			}
			record, tail, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
			if err != nil {
				return result, err
			}
			if record.PushId != entry.PushId {
				return result, fmt.Errorf("%w: a flagged version's place holds another push's record", ErrEvsStatementMismatch)
			}
			if tail.Empty() {
				continue
			}
			list, err := tail.PurgeListValue()
			if err != nil || list == nil || list.GetReplaced() {
				continue
			}
			statement, err := EvsBatchRecordStatement(record)
			if err != nil {
				return result, err
			}
			result.RecordCount += 1
			swept, err := self.SweepList(ctx, cluster, &SweepTarget{
				RepoId: repoId, RefId: refId, Repo: repoRead.Object, PathEpoch: statement.Push.GetPathEpoch(),
				Record: record, CommitVersion: version, List: list,
			}, sidecar.WriteP2RankGc, false, self.clock.Now())
			result.add(swept)
			if err != nil {
				return result, err
			}
		}
	}
	return result, nil
}
