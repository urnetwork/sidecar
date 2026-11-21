// The drop job (§11.13's drop history rows; D-EVS-62, D-EVS-64, D-OPS-21, FI-27; DESIGN-DETAILS 10.2.8; EVSB-M10-03):
// taskworker's evs.drop runs one repo's job as P2 work, paid at the DROP's admission, through 10.2.8's transitions and
// its fences in order:
//
//	pending            -> cancelled            a cancel commits (step 8, DropSink), or the start's read finds one (F1)
//	pending            -> refused {locked}     at the start CAS, a lock standing (§8.8)
//	pending            -> executing/resolve    the start CAS (F1), once not_before_ms + DropStartDelay has passed
//	executing/resolve  -> refused {mismatch}   a link or a list off the ref's history (resolve, EVSB-M10-04); pages
//	executing/resolve  -> executing/horizon    cand and list files written, snap-0 and fence_ms in the job record (F3)
//	executing/horizon  -> executing/mark       the round's H read and past fence_ms + DropCiteBound (F4)
//	executing/mark     -> executing/verify     every ref scanned to its M_r (F5, mark, EVSB-M10-04)
//	executing/verify   -> refused {verify}     the two scans disagree below M_r (F6, verify, EVSB-M10-05); pages
//	executing/verify   -> observed             format2.drop: observe, D recorded in del files, nothing deleted
//	executing/verify   -> executing/delete     snap-r written: the round's horizon and both snapshots
//	executing/delete   -> held                 a hold covers the repo: the rest of D waits (owner decision 184), and the
//	                                           job gives up the slot, its record joining the held jobs (QD-1127)
//	executing/delete   -> executing/horizon    D answered and some id young (F7): the next round
//	executing/delete   -> done                 D answered and none young
//	held               -> done                 every covering hold ended and the slot free: the held job takes it
//	                                           back in phase horizon for a round over what it held (10.2.8's held ->
//	                                           executing/horizon is the job's), its drops reading done throughout and
//	                                           moving to done at its end
//
// F0, before every phase: ClockCheck.Sure(); SettlePassed on the repo's metadata cluster and the segment cluster; repo/
// active (deleted pauses, a restore resumes, shredding ends the job); the segment cluster's drive operations within
// HddPauseShare of a known capacity (QD-056: none known pauses); the job's lease more than LeaseMargin away. A false
// one issues nothing and the job waits. Every round reads the horizon first (F4, OrphanHorizon's one LIST of pb/), and
// mark's and verify's LISTs of head/ come after it (F5, F6): a round killed before its verify ended restarts at F4,
// reading the horizon again with marks kept; one killed in its deletes resumes at the cursor under that round's
// horizon, which its scans followed. A job that waits, for the horizon or a hold, holds no lease and sets retry_ms,
// and taskworker wakes it then and each 10 min after.
//
// One job a repo, the table's one running job record, the slot, taken by If-Match once none runs or its owner's lease
// lapsed LeaseLapse ago by this instance's checked clock; owner until now + LeaseTime, renewed at each table write; a
// lost If-Match stops the run at once. One job a segment cluster, by a Redis lease holding only the instance id. A job
// covers the pending drops whose start has passed when it is taken, except that a drop whose cite bound the horizon has
// not passed is left for the next job whenever another startable drop is past its own; if every startable drop is
// short, it covers them and waits.
//
// A job a hold stops gives up the slot (QD-1127; §11.13's table row): its record moves to the table's held jobs, with
// no lease, so a drop made during the hold starts, runs and moves to held under it as its no-hold twin starts and ends,
// listed, admitted and billed alike; an id a held job holds is left to it, whichever later drop lists it too, so no id
// counts twice (deleteSet). A held job's files keep its ids withheld (DropIndex.Withheld) and stay for tidy.
// At a held job's retry_ms a run with the slot free reads the holds: while one covers the repo, or none can tell, every
// held job due waits HorizonRetryInterval more; once none does, the oldest held job takes the slot back, whatever its
// own retry_ms, before any new job, and runs a round over what it held from its own files, its drops reading done
// throughout (owner decision 184), the rest queued behind it, each due at once, one job at a time.
//
// Resolve and mark are EVSB-M10-04's, verify EVSB-M10-05's (server injects dropverify), and the deletes EVSB-M10-06's:
// this file declares their seams (CONTRACTS.md C-16), and a job missing any of them starts nothing, so nothing is
// deleted on a step nobody built. Observe needs no deleter. A drop observed while format2.drop was observe runs again
// from its start once drop turns on, under a new job, resolve writing its files anew.
//
// Safe for concurrent use: each Run holds its own state, and the table's If-Match decides between instances.

package evsservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The job's name in taskworker's registry.
const EvsDropTaskName = "evs.drop"

// §19.8's drop history series, none with a network or repo label.
const (
	dropJobsMetricName      = "urnetwork_evs_drop_jobs"
	dropLateMarksMetricName = "urnetwork_evs_drop_late_marks_total"
	dropScanBytesMetricName = "urnetwork_evs_drop_scan_bytes_total"
)

// Why a job waits, as DropJobResult.Waiting says it.
const (
	DropWaitClock      = "clock"
	DropWaitSettle     = "settle"
	DropWaitRepo       = "repo"
	DropWaitHdd        = "hdd"
	DropWaitLease      = "lease"
	DropWaitCluster    = "cluster"
	DropWaitHorizon    = "horizon"
	DropWaitHold       = "hold"
	DropWaitStart      = "start"
	DropWaitParts      = "unbuilt"
	DropWaitAuth       = "auth"
	DropWaitUnanswered = "unanswered"
)

var (
	// Another instance took the job, or its record left: the run stops at once (§11.13's who row).
	ErrDropLeaseLost = errors.New("evs drop job lease lost")
	// A step of the job ran into something it cannot judge, so it stopped deleting nothing: a malformed file, a covered
	// drop gone from snap-0.
	ErrDropJobState = errors.New("evs drop job state invalid")
)

// Whether a version listed under a drop is not live (DESIGN-DETAILS 10.2.8's live row): the drop is covered by this job
// and not refused, or the table shows it done or held, or the table holds neither an entry nor a void record for it,
// an executed drop whose entry has left. A pending, cancelled, refused or observed drop's versions are live.
type DropLiveness struct {
	Dead  map[sidecar.Id]bool
	Known map[sidecar.Id]bool
}

// Whether versions dropId lists are not live.
func (self *DropLiveness) Executed(dropId sidecar.Id) bool {
	return self.Dead[dropId] || !self.Known[dropId]
}

// What resolve is asked: the covered drops, whose lists and links it checks and whose list and cand files it writes
// under the job's id (10.2.8's resolve, EVSB-M10-04).
type DropResolveRequest struct {
	// The repo's metadata cluster, and the segment cluster the files go to.
	Cluster        sidecar.BlobCluster
	SegmentCluster sidecar.BlobCluster
	RepoId         sidecar.Id
	JobId          sidecar.Id
	Drops          []*DropCovered
	// Waits out ReadBytesPerSecond for byteCount bytes read.
	Pace func(ctx context.Context, byteCount int64) error
	// Renews the job's lease; an error stops resolve, the lease being lost.
	Renew func(ctx context.Context) error
}

// What resolve found.
type DropResolveResult struct {
	// Drops refused {mismatch}: a link or a list off the ref's history. The rest are resolved, their list rows and the
	// candidates of all of them written, list files before cand files.
	Mismatch []sidecar.Id
	// What the resolved drops' listed versions show of the repo's history, read off their own pushes, which the job
	// records in snap-0 for D-TEST-18's soak (owner decision 513).
	Shape DropListedShape
	// Bytes it read.
	ScanByteCount int64
}

// What a dry run's resolve is asked: the request's paths at a snapshot of its ref.
type DropPreviewResolveRequest struct {
	Cluster        sidecar.BlobCluster
	SegmentCluster sidecar.BlobCluster
	RepoId         sidecar.Id
	PreviewId      sidecar.Id
	Request        *protocol.EvsDropPreviewRequest
	Pace           func(ctx context.Context, byteCount int64) error
}

// What a dry run's resolve found: per requested path, in request order, and the candidates it wrote as cand files
// under the dry run's id.
type DropPreviewResolveResult struct {
	Paths []*protocol.EvsDropPreviewPath
	// The request ref's version at the snapshot, and the listed versions' inline records' bytes.
	SnapshotVersion uint64
	InlineByteCount uint64
	// Versions read, for progress.
	VersionCount  uint64
	ScanByteCount int64
	// The entry hashes of the versions the dry run's paths would list, which its mark counts as naming nothing: a dry
	// run writes no list file, since a reader takes a list file's rows as a drop's.
	Listed map[[32]byte]bool
}

// Resolve (EVSB-M10-04).
type DropResolver interface {
	Resolve(ctx context.Context, request *DropResolveRequest) (*DropResolveResult, error)
	Preview(ctx context.Context, request *DropPreviewResolveRequest) (*DropPreviewResolveResult, error)
}

// What mark is asked: every ref of the repo, listed after the round's horizon was read, scanned to its head's version
// read from the cluster, marking the candidates live versions name and checkpointing mark files with its cursor
// (10.2.8's round, EVSB-M10-04).
type DropMarkRequest struct {
	Cluster        sidecar.BlobCluster
	SegmentCluster sidecar.BlobCluster
	RepoId         sidecar.Id
	// The job's or dry run's id, whose cand and mark files it reads and writes.
	JobId sidecar.Id
	Round uint32
	// The round's H, read before this was asked.
	Horizon time.Time
	// Each ref's M_{r-1}: a later round reads only versions after it, and a ref absent here from version 1.
	Since    map[sidecar.Id]uint64
	Liveness *DropLiveness
	// A dry run's: the entry hashes of the versions its paths would list, which mark nothing beside those the list
	// files hold under executed drops. nil for a job, whose own drops' versions its resolve's list files hold.
	Listed map[[32]byte]bool
	Pace   func(ctx context.Context, byteCount int64) error
	Renew  func(ctx context.Context) error
}

// What mark found.
type DropMarkResult struct {
	// Each ref's M_r: its head's version the scan read to.
	Snapshot      map[sidecar.Id]uint64
	ScanByteCount int64
}

// Mark (EVSB-M10-04).
type DropMarker interface {
	Mark(ctx context.Context, request *DropMarkRequest) (*DropMarkResult, error)
}

// What verify is asked: after mark, list the repo's refs and read every head again from the cluster, scan to V_r with
// the other implementation, and look every id each live version names up in D, the unmarked candidates
// (10.2.8's round, EVSB-M10-05).
type DropVerifyRequest struct {
	Cluster        sidecar.BlobCluster
	SegmentCluster sidecar.BlobCluster
	RepoId         sidecar.Id
	JobId          sidecar.Id
	Round          uint32
	// Each ref's M_r, from mark: a hit at or below it disagrees, one above it is a late mark.
	Marked map[sidecar.Id]uint64
	// Each ref's V_{r-1}: empty in round 1, which scans every ref from version 1.
	Since map[sidecar.Id]uint64
	// The covered drops not refused, whose refs verify rereads for a cancel.
	Drops    []*DropCovered
	Liveness *DropLiveness
	// Whether a lock stands on the repo, by the newest verified state; an error when it cannot tell.
	LockStanding func(ctx context.Context) (bool, error)
	Pace         func(ctx context.Context, byteCount int64) error
}

// What verify found.
type DropVerifyResult struct {
	// Each ref's V_r.
	Snapshot map[sidecar.Id]uint64
	// A hit at or below its ref's M_r: the scans disagree, the job is refused {verify} and pages.
	Disagree bool
	Detail   string
	// Hits above M_r: marked, counted, kept.
	LateMarks []DropScanId
	// Covered drops a committed cancel names.
	Cancelled []sidecar.Id
	// A lock stands: the job is refused {locked}.
	Locked        bool
	ScanByteCount int64
}

// Verify (EVSB-M10-05, injected by server since evsservice cannot import its child package).
type DropVerifier interface {
	Verify(ctx context.Context, request *DropVerifyRequest) (*DropVerifyResult, error)
}

// What the deletes are asked: D in cand order from the cursor, each judged and deleted as F7 to F9 have it, a hold
// moving the rest to held (§11.13's delete row, EVSB-M10-06).
type DropDeleteRequest struct {
	Cluster        sidecar.BlobCluster
	SegmentCluster sidecar.BlobCluster
	RepoId         sidecar.Id
	NetworkId      sidecar.Id
	JobId          sidecar.Id
	Round          uint32
	// The round's H, from the job record: F7's young rule.
	Horizon time.Time
	// D, ascending in cand order, none before the cursor, none marked, none answered for good.
	Candidates []*DropCandidate
	// The lease's end now: no DELETE issues within LeaseMargin of it, and each is cancelled DeadlineMargin before it.
	LeaseUntil     time.Time
	LeaseMargin    time.Duration
	DeadlineMargin time.Duration
	// F7's: an id is young while its LastModified + AdoptionBound is past Horizon.
	AdoptionBound time.Duration
	// At most this many DELETEs a second.
	DeletesPerSecond int
	// Writes the cursor and what was freed and held since the last checkpoint, renewing the lease, at most once a
	// CheckpointInterval: the new lease's end, or ErrDropLeaseLost, which stops the deletes.
	Checkpoint func(ctx context.Context, progress *DropDeleteProgress) (time.Time, error)
}

// One checkpoint of the deletes: every candidate before Cursor is answered. FreedByteCount is the stored bytes deleted
// since the last checkpoint that no earlier checkpoint counted as held, and HeldByteCount those moved to held, so a
// held drop's freed and held bytes sum as its done twin's would (owner decision 184).
type DropDeleteProgress struct {
	Cursor         DropCursor
	FreedByteCount uint64
	HeldByteCount  uint64
}

// What the deletes did.
type DropDeleteResult struct {
	// A covering hold moved the rest of D to held.
	Held bool
	// The least LastModified + AdoptionBound of the young ids, zero when none was young.
	YoungBound time.Time
	// Ids left unanswered: a held key, an unknown outcome. The cursor stops before the first.
	Unanswered int
	// The last checkpoint's.
	Progress *DropDeleteProgress
}

// The deletes (EVSB-M10-06).
type DropDeleter interface {
	Delete(ctx context.Context, request *DropDeleteRequest) (*DropDeleteResult, error)
}

// Whether a lock stands on a repo in its network's newest verified state (§8.8): what the start CAS reads.
type DropLockView interface {
	// standing, and Allowed when the state is loaded; Unknown while it is not, which starts nothing.
	LockStanding(networkId sidecar.Id, repoId sidecar.Id) (standing bool, answer EvsAuthAnswer)
}

// The lock over the process's gate cache (C-09): the repo's AclRepo row's lock.
type aclDropLocks struct {
	gate EvsAclGate
}

// The lock view over gate, the process's one gate cache.
func NewAclDropLocks(gate EvsAclGate) DropLockView {
	return &aclDropLocks{gate: gate}
}

func (self *aclDropLocks) LockStanding(networkId sidecar.Id, repoId sidecar.Id) (bool, EvsAuthAnswer) {
	snapshot := sidecar.RequestAclGateSnapshot(self.gate, networkId)
	if snapshot == nil || snapshot.Acl == nil {
		return false, EvsAuthUnknown
	}
	row := snapshot.Acl.Repo(repoId)
	return row.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED, EvsAuthAllowed
}

// The evacuation horizon of a metadata cluster (DESIGN-DETAILS 2.2.4): NightlyPass.OrphanHorizon.
type DropHorizonSource interface {
	OrphanHorizon(ctx context.Context, cluster sidecar.BlobCluster) (time.Time, error)
}

// What a job runs on beyond its host.
type DropJobDeps struct {
	Resolver DropResolver
	Marker   DropMarker
	Verifier DropVerifier
	Deleter  DropDeleter
	// The lock the start CAS and verify read. nil starts nothing.
	Locks DropLockView
	// The horizon each round reads first. nil reads it through a NightlyPass of the job's own.
	Horizon DropHorizonSource
	// §19.11's drop mode. nil reads observe.
	Format2 Format2Gate
	// The holds a resumed held job reads. nil reads hold/ through a HoldCache of the job's own.
	Holds *HoldCache
	// nil: the defaults.
	Settings    *DropSettings
	EvsSettings *EvsSettings
	// This instance's id, which its leases hold. Zero: a random one.
	Instance sidecar.Id
	// Pages and what a run did. nil discards.
	Log sidecar.Logger
	// a test's: called at each barrier, an error stopping the run there as a kill would
	atStep func(name string, key string) error
}

// What one run did, in counts with no id but the repo's.
type DropJobResult struct {
	RepoId sidecar.Id
	// When the repo asks to run again: zero for nothing waiting.
	Next time.Time
	// Why it stopped short, one of the DropWait values; empty when it did all it could.
	Waiting string
	// Drops moved, by the state they reached.
	Moved map[DropState]int
	// The round it reached, and whether the job ended this run.
	Round uint32
	Ended bool
}

// One repo's drop job. See the file header.
type DropJob struct {
	host     *sidecar.ServiceHost
	deps     *DropJobDeps
	settings *DropSettings
	clock    sidecar.Clock
	log      sidecar.Logger
	// the host's Blobs, its metadata writes held to the budget
	blobs      sidecar.BlobStore
	table      *DropTable
	repos      *RepoCache
	holds      *HoldCache
	format2    Format2Gate
	horizon    DropHorizonSource
	priceTable *PriceTable
	instance   sidecar.Id
	records    *RecordCache
	locator    *RecordLocator
	logPages   *LogPageCache

	lateMarks sidecar.MetricsCounter
	scanBytes sidecar.MetricsCounter
}

// A job on host, which needs Blobs and a write budget.
func NewDropJob(host *sidecar.ServiceHost, deps *DropJobDeps) (*DropJob, error) {
	if host == nil || host.Blobs == nil || host.Budget == nil {
		return nil, errors.New("evs's drop job needs a host with Blobs and a write budget")
	}
	if deps == nil {
		deps = &DropJobDeps{}
	}
	settings := deps.Settings
	if settings == nil {
		settings = DefaultDropSettings()
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	evsSettings := deps.EvsSettings
	if evsSettings == nil {
		evsSettings = DefaultEvsSettings()
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	clock := host.ClockOrReal()
	blobs := NewBudgetedBlobs(host.Blobs)
	table, err := NewDropTable(host, blobs, settings, log)
	if err != nil {
		return nil, err
	}
	holds := deps.Holds
	if holds == nil {
		holds = NewHoldCache(host.Blobs, clock, nil)
	}
	format2 := deps.Format2
	if format2 == nil {
		format2 = ClosedFormat2Gate{}
	}
	horizon := deps.Horizon
	if horizon == nil {
		pass, err := NewNightlyPass(host, &NightlyPassDeps{Log: log, Holds: holds, EvsSettings: evsSettings})
		if err != nil {
			return nil, err
		}
		horizon = pass
	}
	priceTable, err := DefaultPriceTable(evsSettings.PriceBlockByteCount)
	if err != nil {
		return nil, err
	}
	instance := deps.Instance
	if instance == (sidecar.Id{}) {
		if _, err := rand.Read(instance[:]); err != nil {
			return nil, err
		}
	}
	self := &DropJob{
		host:       host,
		deps:       deps,
		settings:   settings,
		clock:      clock,
		log:        log,
		blobs:      blobs,
		table:      table,
		repos:      NewRepoCache(clock, evsSettings),
		holds:      holds,
		format2:    format2,
		horizon:    horizon,
		priceTable: priceTable,
		instance:   instance,
		records:    NewRecordCache(evsSettings),
		locator:    NewRecordLocator(host.Blobs, nil),
		logPages:   NewLogPageCache(evsSettings),
	}
	if host.Metrics != nil {
		self.lateMarks = host.Metrics.Counter(dropLateMarksMetricName, "Candidates verify found named above mark's snapshot, marked and kept (§19.8's drop_late_mark).")
		self.scanBytes = host.Metrics.Counter(dropScanBytesMetricName, "Bytes the drop jobs and dry runs read, by pass.", "pass")
	}
	return self, nil
}

// The table the job writes.
func (self *DropJob) Table() *DropTable {
	return self.table
}

// The settings in force.
func (self *DropJob) Settings() *DropSettings {
	return self.settings
}

// A test's stop at the barrier a site has just passed, each site calling testHookBarrier with its own name so the
// inventory lists it: an error stops the run there, as a kill would.
func (self *DropJob) step(name string, key string) error {
	if self.deps.atStep != nil {
		return self.deps.atStep(name, key)
	}
	return nil
}

// A random job or dry run id.
func newDropId() (sidecar.Id, error) {
	var id sidecar.Id
	_, err := rand.Read(id[:])
	return id, err
}

// Waits so a pass reads at most ReadBytesPerSecond.
func (self *DropJob) pace(ctx context.Context, byteCount int64) error {
	return dropPace(ctx, self.clock, self.settings, byteCount)
}

// Waits on clock as long as byteCount bytes take at settings' ReadBytesPerSecond (§11.13's bound row: 32 MB/s a job).
func dropPace(ctx context.Context, clock sidecar.Clock, settings *DropSettings, byteCount int64) error {
	if byteCount <= 0 {
		return nil
	}
	wait := time.Duration(float64(byteCount) / float64(settings.ReadBytesPerSecond) * float64(time.Second))
	if wait <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-clock.After(wait):
		return nil
	}
}

// One table write as funded P2 work of rank drop (§11.13: paid at the DROP's admission), rereading nothing: the table
// write itself decides.
func (self *DropJob) update(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, decide func(state *DropTableState, now time.Time) (bool, error)) (*DropTableRead, error) {
	byteCount, err := self.priceTable.Price(WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(self.settings.TableByteCount), Count: 1})
	if err != nil {
		return nil, err
	}
	grant, err := self.host.Budget.AcquireP2(ctx, cluster.ClusterId(), &sidecar.WriteP2Work{
		Rank: sidecar.WriteP2RankDrop, Due: self.clock.Now(), ByteCount: byteCount, Funded: true,
	})
	if err != nil {
		return nil, err
	}
	defer grant.Close()
	return self.table.Update(grant.Context(), cluster, repoId, decide)
}

// The job record this instance holds, or ErrDropLeaseLost.
func (self *DropJob) ownJob(state *DropTableState, jobId sidecar.Id) (*DropJobRecord, error) {
	job := state.Job
	if job == nil || job.JobId != jobId || job.Owner != self.instance {
		return nil, ErrDropLeaseLost
	}
	return job, nil
}

// One run of repoId's job on its metadata cluster clusterId: see the file header. An error leaves the job where its
// last table write put it, for the next run.
func (self *DropJob) Run(ctx context.Context, clusterId string, repoId sidecar.Id) (*DropJobResult, error) {
	result := &DropJobResult{RepoId: repoId, Moved: map[DropState]int{}}
	cluster, err := self.blobs.Cluster(clusterId)
	if err != nil {
		return result, err
	}
	segmentCluster, err := self.host.Blobs.SegmentCluster()
	if err != nil {
		return result, err
	}
	read, err := self.table.Read(ctx, cluster, repoId)
	if err != nil {
		return result, err
	}
	if read.Etag == "" {
		return result, nil
	}
	if err := checkHeldCoverage(ctx, segmentCluster, repoId, read.State, self.settings, nil); err != nil {
		var missing missingHeldOwners
		if !errors.As(err, &missing) {
			return result, err
		}
		read, err = self.restoreHeldOwners(ctx, cluster, segmentCluster, repoId, read.State, missing)
		if err != nil {
			return result, err
		}
	}
	now := self.clock.Now()
	if err := self.tidy(ctx, cluster, segmentCluster, repoId, read.State, now); err != nil {
		return result, err
	}
	job := read.State.Job
	switch {
	case job != nil && job.Owner != (sidecar.Id{}) && job.Owner != self.instance && now.Before(time.UnixMilli(job.UntilMs).Add(self.settings.LeaseLapse)):
		result.Waiting, result.Next = DropWaitLease, time.UnixMilli(job.UntilMs).Add(self.settings.LeaseLapse)
		return result, nil
	case job != nil && job.RetryMs != 0 && now.Before(time.UnixMilli(job.RetryMs)):
		result.Waiting, result.Next = DropWaitHorizon, time.UnixMilli(job.RetryMs)
		return result, nil
	case job == nil && len(dueHeldJobs(read.State, now)) == 0 && !self.anyStartable(read.State, now):
		// the slot free and nothing to run in it yet
		result.Next = self.nextStart(read.State)
		if !result.Next.IsZero() {
			result.Waiting = DropWaitStart
		}
		if wake := heldWake(read.State); !wake.IsZero() && (result.Next.IsZero() || wake.Before(result.Next)) {
			result.Waiting, result.Next = DropWaitHold, wake
		}
		return result, nil
	}
	repoObject, why, err := self.gate(ctx, cluster, segmentCluster, repoId)
	if err != nil {
		return result, err
	}
	if why != "" {
		result.Waiting = why
		if why != DropWaitRepo || repoObject.GetState() == protocol.EvsRepoState_EVS_REPO_DELETED {
			result.Next = now.Add(self.settings.PauseRetryInterval)
		}
		return result, nil
	}
	if !self.partsBuilt() {
		// nothing starts on a step nobody built, so nothing is deleted on one
		result.Waiting, result.Next = DropWaitParts, now.Add(self.settings.HorizonRetryInterval)
		return result, nil
	}
	held, err := self.takeClusterLease(ctx, segmentCluster)
	if err != nil {
		return result, err
	}
	if !held {
		result.Waiting, result.Next = DropWaitCluster, now.Add(self.settings.PauseRetryInterval)
		return result, nil
	}
	defer self.releaseClusterLease(segmentCluster)
	run := &dropJobRun{
		job: self, ctx: ctx, cluster: cluster, segmentCluster: segmentCluster, repoId: repoId, repoObject: repoObject, result: result,
		last: read.State,
	}
	if job == nil {
		err = run.next(read.State)
	} else {
		err = run.resume(job.JobId)
	}
	if errors.Is(err, ErrDropLeaseLost) {
		// another instance holds it now: it is that instance's to finish
		return result, nil
	}
	if err == nil {
		run.wake()
	}
	return result, err
}

// The held jobs whose retry_ms has come, oldest first: each reads the holds again.
func dueHeldJobs(state *DropTableState, now time.Time) []*DropJobRecord {
	due := []*DropJobRecord{}
	for _, job := range state.HeldJobs {
		if !now.Before(time.UnixMilli(job.RetryMs)) {
			due = append(due, job)
		}
	}
	return due
}

// The earliest retry_ms of the held jobs, zero for none.
func heldWake(state *DropTableState) time.Time {
	var wake time.Time
	for _, job := range state.HeldJobs {
		if at := time.UnixMilli(job.RetryMs); wake.IsZero() || at.Before(wake) {
			wake = at
		}
	}
	return wake
}

// Whether every seam the current mode needs is built: resolve, mark and verify, and the deletes when drop is on.
func (self *DropJob) partsBuilt() bool {
	if self.deps.Resolver == nil || self.deps.Marker == nil || self.deps.Verifier == nil || self.deps.Locks == nil {
		return false
	}
	return self.format2.DropMode() != sidecar.Format2On || self.deps.Deleter != nil
}

// Whether a drop may start: pending past not_before_ms + StartDelay, or observed once drop is on.
func (self *DropJob) startable(entry *DropTableEntry, now time.Time) bool {
	switch entry.State {
	case DropStatePending:
	case DropStateObserved:
		if self.format2.DropMode() != sidecar.Format2On {
			return false
		}
	default:
		return false
	}
	return !now.Before(time.UnixMilli(entry.NotBeforeMs).Add(self.settings.StartDelay))
}

// Whether any drop of state may start now.
func (self *DropJob) anyStartable(state *DropTableState, now time.Time) bool {
	for _, entry := range state.Drops {
		if self.startable(entry, now) {
			return true
		}
	}
	return false
}

// The earliest start of a pending drop, zero when none waits.
func (self *DropJob) nextStart(state *DropTableState) time.Time {
	var next time.Time
	for _, entry := range state.Drops {
		if entry.State != DropStatePending {
			continue
		}
		start := time.UnixMilli(entry.NotBeforeMs).Add(self.settings.StartDelay)
		if next.IsZero() || start.Before(next) {
			next = start
		}
	}
	return next
}

// F0's checks that need no job record: the clock, both clusters' settle, repo/ active and the HDDs' load. Returns
// repo/ and why the job waits, "" for none.
func (self *DropJob) gate(ctx context.Context, cluster sidecar.BlobCluster, segmentCluster sidecar.BlobCluster, repoId sidecar.Id) (*protocol.EvsRepoObject, string, error) {
	if self.host.ClockCheck == nil || !self.host.ClockCheck.Sure() {
		return nil, DropWaitClock, nil
	}
	if !cluster.SettlePassed() || !segmentCluster.SettlePassed() {
		return nil, DropWaitSettle, nil
	}
	read, err := self.repos.Read(ctx, cluster, repoId)
	if errors.Is(err, sidecar.ErrEvsRepoNotFound) {
		return nil, DropWaitRepo, nil
	}
	if err != nil {
		return nil, "", err
	}
	if read.Object.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		// deleted pauses and a restore resumes; shredding ends the job, its shred taking drops/ and dropscan/
		return read.Object, DropWaitRepo, nil
	}
	if self.host.Redis == nil {
		return read.Object, DropWaitHdd, nil
	}
	figures, err := readHddFigures(ctx, self.host.Redis, segmentCluster.ClusterId())
	if err != nil || figures == nil || figures.CapacityOps <= 0 ||
		self.settings.HddPauseShare*float64(figures.CapacityOps) < figures.DriveOpsPerSecond {
		return read.Object, DropWaitHdd, nil
	}
	return read.Object, "", nil
}

// Takes or renews the segment cluster's lease for this instance. No Redis: the bound is soft state, so the job runs.
func (self *DropJob) takeClusterLease(ctx context.Context, segmentCluster sidecar.BlobCluster) (bool, error) {
	if self.host.Redis == nil {
		return true, nil
	}
	key := dropClusterLeaseKey(segmentCluster.ClusterId())
	set, err := self.host.Redis.SetIfAbsent(ctx, key, self.instance[:], self.settings.LeaseTime)
	if err != nil || set {
		return set, err
	}
	return self.host.Redis.CompareAndSet(ctx, key, self.instance[:], self.instance[:], self.settings.LeaseTime)
}

// Releases the segment cluster's lease if this instance holds it.
func (self *DropJob) releaseClusterLease(segmentCluster sidecar.BlobCluster) {
	if self.host.Redis == nil {
		return
	}
	// the run's ctx may have ended; the release is the lease's own
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stop := self.clock.AfterFunc(self.settings.LeaseMargin, cancel)
	defer stop()
	self.host.Redis.CompareAndDelete(ctx, dropClusterLeaseKey(segmentCluster.ClusterId()), self.instance[:])
}

// The covered drops' liveness and refused set from state.
func dropLiveness(state *DropTableState, covered map[sidecar.Id]bool) *DropLiveness {
	liveness := &DropLiveness{Dead: map[sidecar.Id]bool{}, Known: map[sidecar.Id]bool{}}
	for _, entry := range state.Drops {
		liveness.Known[entry.DropId] = true
		if entry.State.Executed() || (covered[entry.DropId] && !entry.State.Void()) {
			liveness.Dead[entry.DropId] = true
		}
	}
	for _, void := range state.Voids {
		liveness.Known[void.DropId] = true
		delete(liveness.Dead, void.DropId)
	}
	return liveness
}

// One run's state: the job it holds, its clusters and repo.
type dropJobRun struct {
	job            *DropJob
	ctx            context.Context
	cluster        sidecar.BlobCluster
	segmentCluster sidecar.BlobCluster
	repoId         sidecar.Id
	repoObject     *protocol.EvsRepoObject
	result         *DropJobResult
	jobId          sidecar.Id
	leaseUntil     time.Time
	lastWrite      time.Time
	files          *DropFiles
	// the table as the run's last read or write left it
	last *DropTableState
}

// One table write of the run's, as the job's update makes it, keeping what it left.
func (self *dropJobRun) update(decide func(state *DropTableState, now time.Time) (bool, error)) (*DropTableRead, error) {
	read, err := self.job.update(self.ctx, self.cluster, self.repoId, decide)
	if err == nil {
		self.last = read.State
	}
	return read, err
}

// Binds the run to jobId and its files.
func (self *dropJobRun) bind(jobId sidecar.Id) {
	self.jobId = jobId
	self.files = NewDropFiles(self.segmentCluster, self.repoId, jobId, self.job.settings)
}

// The repo's barrier key.
func (self *dropJobRun) key() string {
	return barrierRepoKey(self.repoId)
}

// The repo's network, which locks and holds are read by.
func (self *dropJobRun) networkId() sidecar.Id {
	networkId, err := sidecar.IdFromBytes(self.repoObject.GetNetworkId())
	if err != nil {
		return sidecar.Id{}
	}
	return networkId
}

// Counts drops moved into a state.
func (self *dropJobRun) moved(state DropState, count int) {
	if count == 0 {
		return
	}
	self.result.Moved[state] += count
	for range count {
		self.job.table.countState(state)
	}
}

// A table write that holds this run's job: decide sees the record, and the write renews the lease. ErrDropLeaseLost
// once another instance holds it or it left.
func (self *dropJobRun) write(decide func(state *DropTableState, job *DropJobRecord, now time.Time) error) (*DropTableState, error) {
	read, err := self.update(func(state *DropTableState, now time.Time) (bool, error) {
		job, err := self.job.ownJob(state, self.jobId)
		if err != nil {
			return false, err
		}
		if err := decide(state, job, now); err != nil {
			return false, err
		}
		if state.Job != nil && state.Job.Owner == self.job.instance {
			state.Job.UntilMs = now.Add(self.job.settings.LeaseTime).UnixMilli()
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	self.lastWrite = self.job.clock.Now()
	if job := read.State.Job; job != nil && job.Owner == self.job.instance {
		self.leaseUntil = time.UnixMilli(job.UntilMs)
	}
	return read.State, nil
}

// Renews the lease once CheckpointInterval has passed since the last write.
func (self *dropJobRun) renew(ctx context.Context) error {
	if self.job.clock.Now().Sub(self.lastWrite) < self.job.settings.CheckpointInterval {
		return nil
	}
	_, err := self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error {
		return nil
	})
	return err
}

// F0 before a phase: the clock and both clusters' settle, and the lease more than LeaseMargin away, renewed when
// it is not. Why it must wait, "" for none.
func (self *dropJobRun) gate() (string, error) {
	if self.job.host.ClockCheck == nil || !self.job.host.ClockCheck.Sure() {
		return DropWaitClock, nil
	}
	if !self.cluster.SettlePassed() || !self.segmentCluster.SettlePassed() {
		return DropWaitSettle, nil
	}
	if !self.job.clock.Now().Add(self.job.settings.LeaseMargin).Before(self.leaseUntil) {
		if _, err := self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error { return nil }); err != nil {
			return "", err
		}
	}
	return "", nil
}

// Waits: the job record keeps its phase, its lease released, woken at retry.
func (self *dropJobRun) wait(why string, phase protocol.EvsDropPhase, retry time.Time) error {
	_, err := self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error {
		job.Phase = phase
		job.Owner = sidecar.Id{}
		job.UntilMs = 0
		job.RetryMs = retry.UnixMilli()
		setDropPhase(state, job, phase)
		return nil
	})
	if err != nil {
		return err
	}
	self.result.Waiting, self.result.Next = why, retry
	return nil
}

// Sets each executing drop the job covers to phase. The covered drops are those in state executing: one job a repo.
func setDropPhase(state *DropTableState, job *DropJobRecord, phase protocol.EvsDropPhase) {
	for _, entry := range state.Drops {
		if entry.State == DropStateExecuting {
			entry.Phase = phase
		}
	}
}

// Ends the job: its record leaves, its files stay for tidy. Each executing drop ends in state, and each held one of
// this job's, a held job resumed after its holds (snap-0 names them), done: the held entries of the jobs still held
// stay theirs (QD-1127).
func (self *dropJobRun) end(state DropState) error {
	ownDropIds := map[sidecar.Id]bool{}
	if self.last.Job.Resumed {
		if state != DropStateDone {
			// A refusal cannot release objects this job already withheld.
			return self.hold()
		}
		file, err := self.files.Read(self.ctx, DropFileSnap, 0)
		if err != nil {
			return err
		}
		if file == nil {
			return fmt.Errorf("%w: no snap-0 for resumed job", ErrDropJobState)
		}
		for _, drop := range file.Covered {
			ownDropIds[drop.DropId] = true
		}
	}
	movedCount := 0
	_, err := self.write(func(table *DropTableState, job *DropJobRecord, now time.Time) error {
		movedCount = 0
		for _, entry := range table.Drops {
			// an executing entry is the running job's, one job a repo; a held one ends done once its held ids are deleted
			if entry.State == DropStateExecuting || (entry.State == DropStateHeld && ownDropIds[entry.DropId]) {
				entry.FreedByteCount, entry.HeldByteCount = job.FreedByteCount, job.HeldByteCount
				table.setState(entry, state, dropDay(now))
				movedCount += 1
			}
		}
		table.Job = nil
		return nil
	})
	if err != nil {
		return err
	}
	self.moved(state, movedCount)
	self.result.Ended = true
	return nil
}

// Takes a new job over the startable drops and starts each (F1): see the file header.
func (self *dropJobRun) start(state *DropTableState) error {
	now := self.job.clock.Now()
	startable := []*DropTableEntry{}
	for _, entry := range state.Drops {
		if self.job.startable(entry, now) {
			startable = append(startable, entry)
		}
	}
	if len(startable) == 0 {
		return nil
	}
	horizon, err := self.job.horizon.OrphanHorizon(self.ctx, self.cluster)
	if err != nil {
		return err
	}
	past := []*DropTableEntry{}
	for _, entry := range startable {
		if !horizon.Before(time.UnixMilli(entry.SeenMs).Add(self.job.settings.CiteBound)) {
			past = append(past, entry)
		}
	}
	covered := startable
	if 0 < len(past) {
		covered = past
	}
	// F1's reads, before the CAS: a cancel in the ref's history after the drop, and the lock
	locked, answer := self.job.deps.Locks.LockStanding(self.networkId(), self.repoId)
	if answer != EvsAuthAllowed {
		self.result.Waiting, self.result.Next = DropWaitAuth, now.Add(self.job.settings.PauseRetryInterval)
		return nil
	}
	cancelled := map[sidecar.Id]bool{}
	for _, entry := range covered {
		found, err := self.job.cancelAfter(self.ctx, self.cluster, self.repoId, entry)
		if err != nil {
			return err
		}
		cancelled[entry.DropId] = found
	}
	jobId, err := newDropId()
	if err != nil {
		return err
	}
	testHookBarrier(BarrierDropStartBefore, self.key())
	if err := self.job.step(BarrierDropStartBefore, self.key()); err != nil {
		return err
	}
	starts := map[DropState]int{}
	read, err := self.update(func(table *DropTableState, now time.Time) (bool, error) {
		clear(starts)
		if table.Job != nil {
			// another instance started first, or a held job took the slot back
			return false, ErrDropLeaseLost
		}
		executing := 0
		for _, chosen := range covered {
			entry := table.Drop(chosen.DropId)
			if entry == nil || !self.job.startable(entry, now) {
				continue
			}
			switch {
			case cancelled[entry.DropId]:
				table.setState(entry, DropStateCancelled, dropDay(now))
				starts[DropStateCancelled] += 1
			case locked:
				table.setState(entry, DropStateRefusedLocked, dropDay(now))
				starts[DropStateRefusedLocked] += 1
			default:
				// an observed drop that runs again keeps no void record and no end
				entry.EndedDay = 0
				entry.State, entry.Phase = DropStateExecuting, protocol.EvsDropPhase_EVS_DROP_RESOLVE
				entry.FreedByteCount, entry.HeldByteCount = 0, 0
				starts[DropStateExecuting] += 1
				executing += 1
			}
		}
		if 0 < executing {
			table.Job = &DropJobRecord{
				JobId: jobId, Owner: self.job.instance, UntilMs: now.Add(self.job.settings.LeaseTime).UnixMilli(),
				Phase: protocol.EvsDropPhase_EVS_DROP_RESOLVE, CoveredCount: uint16(executing), StartedMs: now.UnixMilli(),
			}
		}
		return 0 < len(starts), nil
	})
	if err != nil {
		return err
	}
	testHookBarrier(BarrierDropStartAfter, self.key())
	if err := self.job.step(BarrierDropStartAfter, self.key()); err != nil {
		return err
	}
	for state, count := range starts {
		self.moved(state, count)
	}
	if read.State.Job == nil || read.State.Job.JobId != jobId {
		return nil
	}
	self.jobId = jobId
	self.leaseUntil = time.UnixMilli(read.State.Job.UntilMs)
	self.lastWrite = self.job.clock.Now()
	return self.resume(jobId)
}

// Runs the running job from where its record stands: resolve, a round or the deletes.
func (self *dropJobRun) resume(jobId sidecar.Id) error {
	self.bind(jobId)
	// take the lease: a lapsed one, a waiting job's, or this instance's own
	read, err := self.update(func(table *DropTableState, now time.Time) (bool, error) {
		job := table.Job
		if job == nil || job.JobId != jobId {
			return false, ErrDropLeaseLost
		}
		if job.Owner != (sidecar.Id{}) && job.Owner != self.job.instance && now.Before(time.UnixMilli(job.UntilMs).Add(self.job.settings.LeaseLapse)) {
			return false, ErrDropLeaseLost
		}
		job.Owner = self.job.instance
		job.UntilMs = now.Add(self.job.settings.LeaseTime).UnixMilli()
		job.RetryMs = 0
		return true, nil
	})
	if err != nil {
		return err
	}
	return self.loop(read.State)
}

// With the slot free: once a held job's retry_ms has come the holds are read, and once none covers the repo the oldest
// held job takes the slot back, whatever its own retry_ms; while one does, or none can tell, every held job due waits
// again. Then, unless a held job took it, a new job over the startable drops.
func (self *dropJobRun) next(table *DropTableState) error {
	now := self.job.clock.Now()
	if 0 < len(dueHeldJobs(table, now)) {
		cover, err := self.job.holds.CoveringRepo(self.ctx, self.repoId, self.repoObject)
		if err == nil && cover != nil && !cover.Unknown && len(cover.Holds) == 0 {
			for _, job := range table.HeldJobs {
				// Wake the oldest job on hold release. A previously resumed job that
				// still cannot delete keeps its retry time while others take their turn.
				if !job.Resumed || !now.Before(time.UnixMilli(job.RetryMs)) {
					return self.resumeHeld(job.JobId)
				}
			}
		}
		if err := self.waitHeld(); err != nil {
			return err
		}
		self.result.Waiting = DropWaitHold
	}
	if !self.job.anyStartable(table, now) {
		return nil
	}
	return self.start(table)
}

// Every held job whose retry_ms has come waits HorizonRetryInterval more: a hold still covers the repo, or no reader can
// tell. The write also evicts what has aged, as each wake of a held job does.
func (self *dropJobRun) waitHeld() error {
	_, err := self.update(func(table *DropTableState, now time.Time) (bool, error) {
		changed := false
		for _, job := range dueHeldJobs(table, now) {
			job.RetryMs = now.Add(self.job.settings.HorizonRetryInterval).UnixMilli()
			changed = true
		}
		return changed, nil
	})
	return err
}

// Held job jobId, whose holds have all ended, takes the slot back (QD-1127): its record leaves the held jobs for the
// slot, resumed, its lease this instance's, in phase horizon for a round over what it held, which its own files name;
// its drops keep reading done (owner decision 184). The held jobs behind it are due at once, so each takes the slot in
// turn as soon as it is free. ErrDropLeaseLost when the slot is taken or the held job is gone.
func (self *dropJobRun) resumeHeld(jobId sidecar.Id) error {
	self.bind(jobId)
	testHookBarrier(BarrierDropTakeBefore, self.key())
	if err := self.job.step(BarrierDropTakeBefore, self.key()); err != nil {
		return err
	}
	read, err := self.update(func(table *DropTableState, now time.Time) (bool, error) {
		index := table.heldJobIndex(jobId)
		if table.Job != nil || index < 0 {
			return false, ErrDropLeaseLost
		}
		job := table.HeldJobs[index]
		table.HeldJobs = slices.Delete(table.HeldJobs, index, index+1)
		for _, queued := range table.HeldJobs {
			if !queued.Resumed {
				queued.RetryMs = 0
			}
		}
		job.Held, job.Resumed = false, true
		job.Phase = protocol.EvsDropPhase_EVS_DROP_HORIZON
		job.Owner = self.job.instance
		job.UntilMs = now.Add(self.job.settings.LeaseTime).UnixMilli()
		job.RetryMs = 0
		table.Job = job
		return true, nil
	})
	if err != nil {
		return err
	}
	testHookBarrier(BarrierDropTakeAfter, self.key())
	if err := self.job.step(BarrierDropTakeAfter, self.key()); err != nil {
		return err
	}
	return self.loop(read.State)
}

// Runs the job this run holds the lease of, from table, phase by phase until it ends, waits or leaves this instance.
func (self *dropJobRun) loop(table *DropTableState) error {
	self.lastWrite = self.job.clock.Now()
	self.leaseUntil = time.UnixMilli(table.Job.UntilMs)
	for {
		if why, err := self.gate(); err != nil || why != "" {
			if err != nil {
				return err
			}
			return self.wait(why, table.Job.Phase, self.job.clock.Now().Add(self.job.settings.PauseRetryInterval))
		}
		job := table.Job
		var next *DropTableState
		var err error
		switch {
		case job.Phase == protocol.EvsDropPhase_EVS_DROP_RESOLVE:
			next, err = self.resolve(table)
		case job.Phase == protocol.EvsDropPhase_EVS_DROP_DELETE:
			next, err = self.deletes(table)
		default:
			next, err = self.round(table)
		}
		if err != nil || next == nil || next.Job == nil || next.Job.JobId != self.jobId || next.Job.Owner != self.job.instance {
			return err
		}
		table = next
	}
}

// Once the run is over with the slot free, the repo asks to run again no later than a held job's retry_ms and the
// next pending drop's start, now for one already past: a drop made during a hold starts when its twin's would, and a
// held job meets its hold's end.
func (self *dropJobRun) wake() {
	if self.last == nil || self.last.Job != nil {
		return
	}
	now := self.job.clock.Now()
	for _, next := range []time.Time{self.job.nextStart(self.last), heldWake(self.last)} {
		if next.IsZero() {
			continue
		}
		if next.Before(now) {
			next = now
		}
		if self.result.Next.IsZero() || next.Before(self.result.Next) {
			self.result.Next = next
		}
	}
}

// The covered drops from snap-0, each still executing or held in table.
func (self *dropJobRun) covered(table *DropTableState) ([]*DropCovered, map[sidecar.Id]bool, error) {
	file, err := self.files.Read(self.ctx, DropFileSnap, 0)
	if err != nil {
		return nil, nil, err
	}
	if file == nil {
		return nil, nil, fmt.Errorf("%w: no snap-0", ErrDropJobState)
	}
	covered := []*DropCovered{}
	coveredIds := map[sidecar.Id]bool{}
	for _, drop := range file.Covered {
		entry := table.Drop(drop.DropId)
		if entry == nil || (entry.State != DropStateExecuting && entry.State != DropStateHeld) {
			continue
		}
		covered = append(covered, drop)
		coveredIds[drop.DropId] = true
	}
	return covered, coveredIds, nil
}

// Resolve: the covered drops' lists and links, list files then cand files (EVSB-M10-04), then snap-0 and
// executing/horizon with fence_ms (F2, F3). Each refused drop is refused alone, and a job left with none ends.
func (self *dropJobRun) resolve(table *DropTableState) (*DropTableState, error) {
	drops := []*DropCovered{}
	for _, entry := range table.Drops {
		if entry.State == DropStateExecuting {
			drops = append(drops, &DropCovered{
				DropId: entry.DropId, RefId: entry.RefId, Version: entry.Version, PushId: entry.PushId, Place: entry.Place, SeenMs: entry.SeenMs,
			})
		}
	}
	if len(drops) == 0 {
		return nil, self.end(DropStateDone)
	}
	testHookBarrier(BarrierDropResolveBefore, self.key())
	if err := self.job.step(BarrierDropResolveBefore, self.key()); err != nil {
		return nil, err
	}
	resolved, err := self.job.deps.Resolver.Resolve(self.ctx, &DropResolveRequest{
		Cluster: self.cluster, SegmentCluster: self.segmentCluster, RepoId: self.repoId, JobId: self.jobId, Drops: drops,
		Pace: self.job.pace, Renew: self.renew,
	})
	if err != nil {
		return nil, err
	}
	self.job.countScan("resolve", resolved.ScanByteCount)
	testHookBarrier(BarrierDropResolveAfter, self.key())
	if err := self.job.step(BarrierDropResolveAfter, self.key()); err != nil {
		return nil, err
	}
	mismatch := map[sidecar.Id]bool{}
	for _, dropId := range resolved.Mismatch {
		mismatch[dropId] = true
	}
	kept := []*DropCovered{}
	fenceMs := int64(0)
	for _, drop := range drops {
		if mismatch[drop.DropId] {
			self.job.log.Errorf("[evs] page drop_refused_mismatch: repo %s drop %s: its list or lineage is off the ref's history", sidecar.EvsKeyId(self.repoId), sidecar.EvsKeyId(drop.DropId))
			continue
		}
		kept = append(kept, drop)
		fenceMs = max(fenceMs, drop.SeenMs)
	}
	if err := self.putCovered(kept, resolved.Shape); err != nil {
		return nil, err
	}
	refusedCount := 0
	next, err := self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error {
		refusedCount = 0
		for _, entry := range state.Drops {
			if entry.State == DropStateExecuting && mismatch[entry.DropId] {
				state.setState(entry, DropStateRefusedMismatch, dropDay(now))
				refusedCount += 1
			}
		}
		job.FenceMs = fenceMs
		job.CoveredCount = uint16(len(kept))
		job.Phase = protocol.EvsDropPhase_EVS_DROP_HORIZON
		setDropPhase(state, job, protocol.EvsDropPhase_EVS_DROP_HORIZON)
		return nil
	})
	if err != nil {
		return nil, err
	}
	self.moved(DropStateRefusedMismatch, refusedCount)
	if len(kept) == 0 {
		return nil, self.end(DropStateDone)
	}
	return next, nil
}

// Writes snap-0: the drops resolve kept and what their listed versions show of the repo's history (owner decision
// 513). A snap-0 that already stands with other bytes stays when it covers the same drops, its shape as it was first
// written: a resolve killed after its snap-0 and run again by a build that reads the shape, or reads it otherwise,
// must not strand the job on two bits the soak alone counts. One covering other drops is the store's
// ErrBlobImmutableMismatch, as before.
func (self *dropJobRun) putCovered(kept []*DropCovered, shape DropListedShape) error {
	err := self.files.Put(self.ctx, DropFileSnap, 0, EncodeDropCoveredFile(self.repoId, self.jobId, kept, shape))
	if !errors.Is(err, sidecar.ErrBlobImmutableMismatch) {
		return err
	}
	standing, readErr := self.files.Read(self.ctx, DropFileSnap, 0)
	if readErr != nil {
		return readErr
	}
	if standing == nil || !bytes.Equal(EncodeDropCoveredFile(self.repoId, self.jobId, standing.Covered, shape), EncodeDropCoveredFile(self.repoId, self.jobId, kept, shape)) {
		return err
	}
	if self.job.log.V(1).Enabled() {
		self.job.log.Infof("[evs] drop snap-0 stands: repo %s job %s: it covers the drops resolved and keeps the shape it was written with", sidecar.EvsKeyId(self.repoId), sidecar.EvsKeyId(self.jobId))
	}
	return nil
}

// The snapshot of round r, nil for round 0 or one not written.
func (self *dropJobRun) roundSnapshot(round uint32) (*DropRoundSnapshot, error) {
	if round == 0 {
		return nil, nil
	}
	file, err := self.files.Read(self.ctx, DropFileSnap, round)
	if err != nil || file == nil {
		return nil, err
	}
	return file.Round, nil
}

// A round, from F4: the horizon, mark, verify, snap-r, then observe's end or the deletes.
func (self *dropJobRun) round(table *DropTableState) (*DropTableState, error) {
	job := table.Job
	round := job.Round + 1
	if job.Phase == protocol.EvsDropPhase_EVS_DROP_MARK || job.Phase == protocol.EvsDropPhase_EVS_DROP_VERIFY {
		// a round killed before its verify ended restarts at its F4
		round = job.Round
	}
	settings := self.job.settings
	// F4: the horizon first, before any LIST of head/
	testHookBarrier(BarrierDropHorizonBefore, self.key())
	if err := self.job.step(BarrierDropHorizonBefore, self.key()); err != nil {
		return nil, err
	}
	horizon, err := self.job.horizon.OrphanHorizon(self.ctx, self.cluster)
	if err != nil {
		return nil, err
	}
	testHookBarrier(BarrierDropHorizonAfter, self.key())
	if err := self.job.step(BarrierDropHorizonAfter, self.key()); err != nil {
		return nil, err
	}
	bound := time.UnixMilli(job.FenceMs).Add(settings.CiteBound)
	if horizon.Before(bound) {
		retry := self.job.clock.Now().Add(settings.HorizonRetryInterval)
		if wake := bound.Add(settings.HorizonRetryLag); retry.Before(wake) {
			retry = wake
		}
		return nil, self.wait(DropWaitHorizon, protocol.EvsDropPhase_EVS_DROP_HORIZON, retry)
	}
	table, err = self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error {
		job.Round = round
		job.HorizonMs = horizon.UnixMilli()
		job.Phase = protocol.EvsDropPhase_EVS_DROP_MARK
		job.Cursor = DropCursor{}
		setDropPhase(state, job, protocol.EvsDropPhase_EVS_DROP_MARK)
		return nil
	})
	if err != nil {
		return nil, err
	}
	self.result.Round = round
	covered, coveredIds, err := self.covered(table)
	if err != nil {
		return nil, err
	}
	previous, err := self.roundSnapshot(round - 1)
	if err != nil {
		return nil, err
	}
	markedSince, checkedSince := map[sidecar.Id]uint64{}, map[sidecar.Id]uint64{}
	if previous != nil {
		for _, ref := range previous.Refs {
			markedSince[ref.RefId], checkedSince[ref.RefId] = ref.Marked, ref.Checked
		}
	}
	liveness := dropLiveness(table, coveredIds)
	// F5: mark, after the horizon
	if why, err := self.gate(); err != nil || why != "" {
		if err != nil {
			return nil, err
		}
		return nil, self.wait(why, protocol.EvsDropPhase_EVS_DROP_MARK, self.job.clock.Now().Add(settings.PauseRetryInterval))
	}
	testHookBarrier(BarrierDropMarkBefore, self.key())
	if err := self.job.step(BarrierDropMarkBefore, self.key()); err != nil {
		return nil, err
	}
	marked, err := self.job.deps.Marker.Mark(self.ctx, &DropMarkRequest{
		Cluster: self.cluster, SegmentCluster: self.segmentCluster, RepoId: self.repoId, JobId: self.jobId, Round: round,
		Horizon: horizon, Since: markedSince, Liveness: liveness, Pace: self.job.pace, Renew: self.renew,
	})
	if err != nil {
		return nil, err
	}
	self.job.countScan("mark", marked.ScanByteCount)
	testHookBarrier(BarrierDropMarkAfter, self.key())
	if err := self.job.step(BarrierDropMarkAfter, self.key()); err != nil {
		return nil, err
	}
	table, err = self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error {
		job.Phase = protocol.EvsDropPhase_EVS_DROP_VERIFY
		setDropPhase(state, job, protocol.EvsDropPhase_EVS_DROP_VERIFY)
		return nil
	})
	if err != nil {
		return nil, err
	}
	// F6: verify, by the other implementation, after mark
	if why, err := self.gate(); err != nil || why != "" {
		if err != nil {
			return nil, err
		}
		return nil, self.wait(why, protocol.EvsDropPhase_EVS_DROP_VERIFY, self.job.clock.Now().Add(settings.PauseRetryInterval))
	}
	testHookBarrier(BarrierDropVerifyBefore, self.key())
	if err := self.job.step(BarrierDropVerifyBefore, self.key()); err != nil {
		return nil, err
	}
	networkId := self.networkId()
	verified, err := self.job.deps.Verifier.Verify(self.ctx, &DropVerifyRequest{
		Cluster: self.cluster, SegmentCluster: self.segmentCluster, RepoId: self.repoId, JobId: self.jobId, Round: round,
		Marked: marked.Snapshot, Since: checkedSince, Drops: covered, Liveness: liveness,
		LockStanding: func(ctx context.Context) (bool, error) {
			standing, answer := self.job.deps.Locks.LockStanding(networkId, self.repoId)
			if answer != EvsAuthAllowed {
				return false, fmt.Errorf("network %s's authorization state is not loaded", sidecar.EvsKeyId(networkId))
			}
			return standing, nil
		},
		Pace: self.job.pace,
	})
	if err != nil {
		return nil, err
	}
	self.job.countScan("verify", verified.ScanByteCount)
	testHookBarrier(BarrierDropVerifyAfter, self.key())
	if err := self.job.step(BarrierDropVerifyAfter, self.key()); err != nil {
		return nil, err
	}
	switch {
	case verified.Disagree:
		self.job.log.Errorf("[evs] page drop_refused_verify: repo %s job %s round %d: the scans disagree: %s", sidecar.EvsKeyId(self.repoId), sidecar.EvsKeyId(self.jobId), round, verified.Detail)
		return nil, self.end(DropStateRefusedVerify)
	case verified.Locked:
		return nil, self.end(DropStateRefusedLocked)
	}
	if 0 < len(verified.Cancelled) {
		cancelled := map[sidecar.Id]bool{}
		for _, dropId := range verified.Cancelled {
			cancelled[dropId] = true
		}
		cancelledCount := 0
		table, err = self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error {
			cancelledCount = 0
			for _, entry := range state.Drops {
				if entry.State == DropStateExecuting && cancelled[entry.DropId] {
					state.setState(entry, DropStateCancelled, dropDay(now))
					cancelledCount += 1
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		self.moved(DropStateCancelled, cancelledCount)
		// what this job still covers: its executing drops, or the held ones snap-0 names, not another held job's
		stillCovered := false
		for _, entry := range table.Drops {
			stillCovered = stillCovered || entry.State == DropStateExecuting || (entry.State == DropStateHeld && coveredIds[entry.DropId])
		}
		if !stillCovered {
			return nil, self.end(DropStateDone)
		}
	}
	if 0 < len(verified.LateMarks) {
		if self.job.lateMarks != nil {
			self.job.lateMarks.Add(float64(len(verified.LateMarks)))
		}
		if err := self.writeLateMarks(verified.LateMarks); err != nil {
			return nil, err
		}
	}
	snapshot := &DropRoundSnapshot{Horizon: horizon}
	for refId, version := range marked.Snapshot {
		snapshot.Refs = append(snapshot.Refs, &DropRefSnapshot{RefId: refId, Marked: version, Checked: verified.Snapshot[refId]})
	}
	for refId, version := range verified.Snapshot {
		if _, ok := marked.Snapshot[refId]; !ok {
			snapshot.Refs = append(snapshot.Refs, &DropRefSnapshot{RefId: refId, Checked: version})
		}
	}
	if err := self.files.Put(self.ctx, DropFileSnap, round, EncodeDropRoundFile(self.repoId, self.jobId, round, snapshot)); err != nil {
		return nil, err
	}
	if self.job.format2.DropMode() != sidecar.Format2On {
		return nil, self.observe()
	}
	return self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error {
		job.Phase = protocol.EvsDropPhase_EVS_DROP_DELETE
		job.Cursor = DropCursor{}
		setDropPhase(state, job, protocol.EvsDropPhase_EVS_DROP_DELETE)
		return nil
	})
}

// Writes verify's late marks as the next mark file, repeating the newest file's cursor.
func (self *dropJobRun) writeLateMarks(lateMarks []DropScanId) error {
	_, cursorRefId, cursorVersion, err := self.files.Marks(self.ctx)
	if err != nil {
		return err
	}
	sequence, err := self.files.NextSequence(self.ctx, DropFileMark)
	if err != nil {
		return err
	}
	return self.files.Put(self.ctx, DropFileMark, sequence, EncodeDropMarkFile(self.repoId, self.jobId, sequence, cursorRefId, cursorVersion, lateMarks))
}

// D: the candidates neither marked nor answered for good, from cursor on, in cand order, less every id a held job
// other than this one holds, its newest answer held (QD-1127). Two drops can list one segment or slot: the held job's
// bytes for the id left the stored count when it moved it to held, and it deletes the id once its holds end, as its
// no-hold twin deleted it at once and a later job found it absent, so no id moves to held twice or counts twice.
func (self *dropJobRun) deleteSet(cursor DropCursor) ([]*DropCandidate, error) {
	candidates, err := self.files.Candidates(self.ctx)
	if err != nil {
		return nil, err
	}
	marks, _, _, err := self.files.Marks(self.ctx)
	if err != nil {
		return nil, err
	}
	answers, err := self.files.Answers(self.ctx)
	if err != nil {
		return nil, err
	}
	heldElsewhere := map[DropScanId]bool{}
	if self.last != nil {
		for _, held := range self.last.HeldJobs {
			if held.JobId == self.jobId {
				continue
			}
			heldAnswers, err := NewDropFiles(self.segmentCluster, self.repoId, held.JobId, self.job.settings).Answers(self.ctx)
			if err != nil {
				return nil, err
			}
			for scanId, outcome := range heldAnswers {
				if outcome == DropOutcomeHeld {
					heldElsewhere[scanId] = true
				}
			}
		}
	}
	set := []*DropCandidate{}
	for _, candidate := range candidates {
		answer := answers[candidate.DropScanId]
		// The deleter checkpoints its cursor before the job parks. A crash
		// between them must not turn those retained answers into completion.
		if marks[candidate.DropScanId] || heldElsewhere[candidate.DropScanId] || answer.Final() ||
			(candidate.Cursor.before(cursor) && answer != DropOutcomeHeld) {
			continue
		}
		set = append(set, candidate)
	}
	return set, nil
}

// format2.drop: observe: D recorded as del files, every outcome observed, nothing deleted; each covered drop observed.
func (self *dropJobRun) observe() error {
	if self.last.Job.Resumed {
		// Observed is a final per-object answer. These held objects still need
		// physical deletion when the gate permits it.
		return self.hold()
	}
	set, err := self.deleteSet(DropCursor{})
	if err != nil {
		return err
	}
	sequence, err := self.files.NextSequence(self.ctx, DropFileDel)
	if err != nil {
		return err
	}
	for chunk := range slices.Chunk(set, self.job.settings.FileRowCount) {
		answers := make([]*DropAnswer, 0, len(chunk))
		for _, candidate := range chunk {
			answers = append(answers, &DropAnswer{DropScanId: candidate.DropScanId, Outcome: DropOutcomeObserved})
		}
		if err := self.files.Put(self.ctx, DropFileDel, sequence, EncodeDropDelFile(self.repoId, self.jobId, sequence, answers)); err != nil {
			return err
		}
		sequence += 1
	}
	if self.job.log.V(1).Enabled() {
		self.job.log.Infof("[evs] drop observed: repo %s job %s: %d ids would be deleted", sidecar.EvsKeyId(self.repoId), sidecar.EvsKeyId(self.jobId), len(set))
	}
	return self.end(DropStateObserved)
}

// The deletes of the round the record names, from its cursor, under its horizon (EVSB-M10-06's): done, held, the
// next round for young ids, or a wait for unanswered ones.
func (self *dropJobRun) deletes(table *DropTableState) (*DropTableState, error) {
	job := table.Job
	if self.job.format2.DropMode() != sidecar.Format2On {
		if job.Resumed {
			return nil, self.hold()
		}
		// Physical work may already be checkpointed. Its owner stays in the
		// table until deletion can run again, even on an observe-only worker.
		return nil, self.wait(DropWaitUnanswered, job.Phase, self.job.clock.Now().Add(self.job.settings.PauseRetryInterval))
	}
	set, err := self.deleteSet(job.Cursor)
	if err != nil {
		return nil, err
	}
	settings := self.job.settings
	deleted, err := self.job.deps.Deleter.Delete(self.ctx, &DropDeleteRequest{
		Cluster: self.cluster, SegmentCluster: self.segmentCluster, RepoId: self.repoId, NetworkId: self.networkId(),
		JobId: self.jobId, Round: job.Round, Horizon: time.UnixMilli(job.HorizonMs), Candidates: set, LeaseUntil: self.leaseUntil,
		LeaseMargin: settings.LeaseMargin, DeadlineMargin: settings.DeleteDeadlineMargin, AdoptionBound: settings.AdoptionBound,
		DeletesPerSecond: settings.DeletesPerSecond,
		Checkpoint: func(ctx context.Context, progress *DropDeleteProgress) (time.Time, error) {
			_, err := self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error {
				job.Cursor = progress.Cursor
				job.FreedByteCount += progress.FreedByteCount
				job.HeldByteCount += progress.HeldByteCount
				return nil
			})
			return self.leaseUntil, err
		},
	})
	if err != nil {
		return nil, err
	}
	now := self.job.clock.Now()
	switch {
	case deleted.Held:
		return nil, self.hold()
	case 0 < deleted.Unanswered:
		return nil, self.wait(DropWaitUnanswered, protocol.EvsDropPhase_EVS_DROP_DELETE, now.Add(settings.PauseRetryInterval))
	case !deleted.YoungBound.IsZero():
		retry := now.Add(settings.HorizonRetryInterval)
		if wake := deleted.YoungBound.Add(settings.HorizonRetryLag); retry.Before(wake) {
			retry = wake
		}
		return nil, self.wait(DropWaitHorizon, protocol.EvsDropPhase_EVS_DROP_HORIZON, retry)
	}
	return nil, self.end(DropStateDone)
}

// A hold covers the repo, so the rest of D waits (owner decision 184): each executing drop moves to held with the job's
// freed and held bytes, reading done, and the job gives up the slot (QD-1127), its record joining the held jobs with no
// lease, to read the holds again at retry_ms. A later drop then runs in the slot as its no-hold twin's would.
func (self *dropJobRun) hold() error {
	testHookBarrier(BarrierDropHeldBefore, self.key())
	if err := self.job.step(BarrierDropHeldBefore, self.key()); err != nil {
		return err
	}
	heldCount := 0
	retry := time.Time{}
	_, err := self.write(func(state *DropTableState, job *DropJobRecord, now time.Time) error {
		heldCount = 0
		for _, entry := range state.Drops {
			if entry.State == DropStateExecuting {
				entry.FreedByteCount, entry.HeldByteCount = job.FreedByteCount, job.HeldByteCount
				state.setState(entry, DropStateHeld, dropDay(now))
				heldCount += 1
			}
		}
		retry = now.Add(self.job.settings.HorizonRetryInterval)
		job.Held = true
		job.Owner = sidecar.Id{}
		job.UntilMs = 0
		job.RetryMs = retry.UnixMilli()
		state.HeldJobs = append(state.HeldJobs, job)
		state.Job = nil
		return nil
	})
	if err != nil {
		return err
	}
	self.moved(DropStateHeld, heldCount)
	self.result.Waiting, self.result.Next = DropWaitHold, time.UnixMilli(retry.UnixMilli())
	testHookBarrier(BarrierDropHeldAfter, self.key())
	return self.job.step(BarrierDropHeldAfter, self.key())
}

// Counts bytes a pass read.
func (self *DropJob) countScan(pass string, byteCount int64) {
	if self.scanBytes != nil && 0 < byteCount {
		self.scanBytes.Add(float64(byteCount), pass)
	}
}

// Whether a committed cancel of entry stands on its ref after it (F1): every version from u_d + 1 to the head's, read
// from the cluster, whose window entry has bit 5, its DROP body read from its record.
func (self *DropJob) cancelAfter(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, entry *DropTableEntry) (bool, error) {
	object, err := cluster.Get(ctx, HeadKey(repoId, entry.RefId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return false, fmt.Errorf("%w: drop %s's ref has no head", ErrDropJobState, sidecar.EvsKeyId(entry.DropId))
	}
	if err != nil {
		return false, err
	}
	defer object.Body.Close()
	headBytes, err := io.ReadAll(io.LimitReader(object.Body, EvsHeadMaxByteCount+1))
	if err != nil {
		return false, err
	}
	head, err := ParseEvsHead(headBytes)
	if err != nil {
		return false, err
	}
	window, err := EvsHeadWindow(head)
	if err != nil {
		return false, err
	}
	windowFirst := EvsHeadWindowFirstVersion(head)
	for version := entry.Version + 1; version <= head.GetVersion(); version += 1 {
		var windowEntry *sidecar.EvsWindowEntry
		if windowFirst <= version {
			windowEntry = window[version-windowFirst]
		} else {
			page, err := self.readLogPage(ctx, cluster, repoId, entry.RefId, EvsLogPageOf(version))
			if err != nil {
				return false, err
			}
			found := false
			if windowEntry, _, found = page.At(version); !found {
				return false, fmt.Errorf("%w: log page %d lacks version %d", ErrDropJobState, EvsLogPageOf(version), version)
			}
		}
		if !windowEntry.Drop() {
			continue
		}
		history, err := self.dropBodyAt(ctx, cluster, repoId, entry.RefId, windowEntry.Place)
		if err != nil {
			return false, err
		}
		cancelsDropId, err := sidecar.IdFromBytes(history.GetCancelsDropId())
		if history.GetAction() == 2 && err == nil && cancelsDropId == entry.DropId && history.GetCancelsVersion() == entry.Version {
			return true, nil
		}
	}
	return false, nil
}

// A log page of a ref, from log/ or, once packed, its container.
func (self *DropJob) readLogPage(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, page uint64) (*LogPage, error) {
	logPage, err := ReadLogPage(ctx, self.logPages, cluster, repoId, refId, page)
	if !errors.Is(err, ErrEvsRecordEvacuated) {
		return logPage, err
	}
	pageBytes, err := self.locator.ReadLogPage(ctx, cluster, repoId, refId, page)
	if err != nil {
		return nil, err
	}
	return ParseLogPage(repoId, refId, page, pageBytes)
}

// The DROP body of the push whose record is at place: a one-part push's from its payload, a seal's from its parts.
func (self *DropJob) dropBodyAt(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, place *protocol.EvsPlace) (*protocol.EvsDropHistory, error) {
	record, err := ReadRecordLocated(ctx, self.records, self.locator, cluster, repoId, refId, place)
	if err != nil {
		return nil, err
	}
	return dropBodyOfRecord(ctx, self.records, self.locator, cluster, record)
}

// The DROP body of a committed push's record, a one-part push's from its payload and a seal's from its parts, read
// through records and locator; ErrDropJobState for a record that holds none.
func dropBodyOfRecord(ctx context.Context, records *RecordCache, locator *RecordLocator, cluster sidecar.BlobCluster, record *sidecar.EvsBatchRecord) (*protocol.EvsDropHistory, error) {
	repoId, refId := record.RepoId, record.RefId
	statement, err := EvsBatchRecordStatement(record)
	if err != nil {
		return nil, err
	}
	var checked *sidecar.EvsCheckedPayload
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH:
		_, payload, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		if checked, err = sidecar.EvsCheckStoredPayload(statement, payload); err != nil {
			return nil, err
		}
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		_, parts, err := sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		partBytes := make([][]byte, 0, len(parts))
		for _, part := range parts {
			partRecord, err := ReadRecordLocated(ctx, records, locator, cluster, repoId, refId, part.Place)
			if err != nil {
				return nil, err
			}
			_, onePart, _, _, err := sidecar.ParseEvsPartRecordBody(partRecord.Body)
			if err != nil {
				return nil, err
			}
			partBytes = append(partBytes, onePart)
		}
		if checked, _, err = sidecar.EvsCheckStoredSeal(statement, partBytes); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: a bit-5 version at a record of type %d", ErrDropJobState, record.Type)
	}
	if checked.Drop == nil {
		return nil, fmt.Errorf("%w: a bit-5 version with no DROP body", ErrDropJobState)
	}
	return checked.Drop.History, nil
}

// Evacuation's append of a committed DROP the table lacks (§11.13's who row): once its record is settled committed at
// version, before its batch goes, its body read from the record (a seal's from its parts) and seen_ms the clock after
// the head read that showed it committed. "" once there is nothing to append or the append landed; else why the minute
// waits, so a batch never goes with the append lost (DESIGN-DETAILS 10.5's lost-append row).
func (self *evacuateRun) appendDrop(minute uint32, place *protocol.EvsPlace, record *sidecar.EvsBatchRecord, version uint64) (string, error) {
	drops := self.evacuator.deps.Drops
	if drops == nil || (record.Type != protocol.EvsBatchRecordType_EVS_BATCH_PUSH && record.Type != protocol.EvsBatchRecordType_EVS_BATCH_SEAL) {
		return "", nil
	}
	statement, err := EvsBatchRecordStatement(record)
	if err != nil {
		return "drop statement", err
	}
	if statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 {
		return "", nil
	}
	history, err := dropBodyOfRecord(self.ctx, NewRecordCache(self.evacuator.evsSettings), self.evacuator.locator, self.cluster, record)
	if err != nil {
		return "drop body", err
	}
	grant, err := self.acquire(minute, WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: int64(self.evacuator.evsSettings.Drop.TableByteCount), Count: 1}, nil)
	if err != nil {
		return "drop append grant", err
	}
	defer grant.Close()
	err = drops.Append(grant.Context(), &DropCommit{
		ClusterId: self.clusterId, RepoId: record.RepoId, RefId: record.RefId, PushId: record.PushId, Version: version, Place: place, Body: history,
	}, self.evacuator.clock.Now().UnixMilli())
	switch {
	case errors.Is(err, ErrDropClockUnsure):
		return "drop append clock", nil
	case err != nil:
		return "drop append", err
	}
	return "", nil
}

// What tidy deletes and evicts: ended entries and dry runs past their retention, by a table write, and each ended job's
// and dry run's files, 30 d after the newest of them was written, but a job's list files and its snap-0, which stay
// for the repo's life: snap-0 names the drops the list files hold, so `sidecarctl evs drop-reindex` can write an older
// job's corrupt list file again (owner decisions 398, 570; QD-1021). Later rounds' snap files go with the rest.
// Nothing deletes on an unsure clock or a cluster that has not passed the settle cases.
func (self *DropJob) tidy(ctx context.Context, cluster sidecar.BlobCluster, segmentCluster sidecar.BlobCluster, repoId sidecar.Id, state *DropTableState, now time.Time) error {
	if self.host.ClockCheck == nil || !self.host.ClockCheck.Sure() || !cluster.SettlePassed() || !segmentCluster.SettlePassed() {
		return nil
	}
	if state.expiring(now, self.settings) {
		// the write evicts what has expired
		if _, err := self.update(ctx, cluster, repoId, func(table *DropTableState, now time.Time) (bool, error) {
			return table.expiring(now, self.settings), nil
		}); err != nil {
			return err
		}
	}
	live := map[sidecar.Id]bool{}
	// the running job's files and every held job's, which its round after the holds reads (QD-1127)
	for _, jobId := range state.JobIds() {
		live[jobId] = true
	}
	for _, preview := range state.Previews {
		live[preview.PreviewId] = true
	}
	prefix := dropscanKeyPrefix + sidecar.EvsKeyId(repoId) + "/"
	jobObjects := map[sidecar.Id][]*sidecar.BlobInfo{}
	startAfter := ""
	for {
		objects, more, err := segmentCluster.List(ctx, prefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return err
		}
		for _, object := range objects {
			rest := object.Key[len(prefix):]
			if len(rest) < 33 || rest[32] != '/' {
				continue
			}
			jobId, err := parseEvsHexId(rest[:32])
			if err != nil || live[jobId] {
				continue
			}
			jobObjects[jobId] = append(jobObjects[jobId], object)
		}
		if !more || len(objects) == 0 {
			break
		}
		startAfter = objects[len(objects)-1].Key
	}
	for jobId, objects := range jobObjects {
		newest := time.Time{}
		for _, object := range objects {
			if newest.Before(object.LastModified) {
				newest = object.LastModified
			}
		}
		if now.Before(newest.Add(self.settings.EndedRetention)) {
			continue
		}
		listPrefix := dropFileKindPrefix(repoId, jobId, DropFileList)
		coveredKey := DropFileKey(repoId, jobId, DropFileSnap, 0)
		for _, object := range objects {
			if strings.HasPrefix(object.Key, listPrefix) {
				// the listed index stays for the repo's life (DESIGN-DETAILS 10.2.9)
				continue
			}
			if object.Key == coveredKey {
				// so does snap-0, the drops the listed index was resolved from (owner decision 570)
				continue
			}
			if err := segmentCluster.Delete(sidecar.WithBlobUnmodified(ctx, object.LastModified), object.Key); err != nil && !errors.Is(err, sidecar.ErrBlobPrecondition) {
				return err
			}
		}
	}
	return nil
}
