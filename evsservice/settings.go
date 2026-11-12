// What tunes the evs engine (connect/CODESTYLE.md's settings rule): every timing, count and size that is policy
// rather than format. A bound the design's argument needs, such as repo/'s 5 s cache inside step 7's window, is a
// ceiling Validate holds, so a setting can shorten it and never stretch it. Format values (a batch's 256 KiB, a
// head's 255 window entries, 8 refusal records) stay constants beside their codecs.

package evsservice

import (
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// A settings value outside what the design allows.
var ErrEvsSettings = errors.New("evs settings invalid")

// §11.8's step-4 bound on a cached repo/: what linearization reads a repo's state through (§11.8's
// linearizability), and the most RepoCacheTtl may be.
const evsRepoCacheMaxTtl = 5 * time.Second

// §11.9's cache row: a cached head is served only within 10 min of its cache time, which evs-24 publishes.
const evsHeadCacheMaxServeAge = 10 * time.Minute

// §11.7's stale row: a fold write's store deadline, 15 s after its head read, which the collection window's 15.3 s
// wait counts on, so a setting may shorten it and never stretch it.
const evsFoldMaxStaleDeadline = 15 * time.Second

// §11.7's collect row: a fold writes over a covered marker only 150 ms past until_ms by its clock, so a setting may
// lengthen the margin and never shorten it.
const evsFoldMinCollectMargin = 150 * time.Millisecond

// §11.8 step 7: the head If-Match is issued only within 5 s of step 4's reads, the bound linearization rests on
// (repo/ and the authorization state read at most 5 s before the commit), so a setting may shorten it and never
// stretch it.
const evsPushMaxStepSevenWindow = 5 * time.Second

// §11.8's fence row: an attempt ends 503 unknown on a fence_ms later than its arrival less 100 ms, the margin the
// clocks' 50 ms bound needs, so a setting may widen it and never narrow it.
const evsPushMinFenceMargin = 100 * time.Millisecond

// §11.6's copy row: a copy rereads its head at least every 5 s (§11.7's stale rule), so a setting may shorten it and
// never stretch it.
const evsCopyMaxHeadRereadInterval = 5 * time.Second

// The engine's settings. Every field is read where it is used, from one instance.
type EvsSettings struct {
	// place/'s resolution: a 404 cached 5 s, the placements a process keeps (§11.8's resolve row).
	Place *sidecar.EvsRepoPlaceSettings

	// The storage format this instance runs as (§11.6's format row, EVS-FORMAT.md; format1_guard.go): 2, which
	// takes format-2 values from networks in §19.11's format2 gate and raises their repos, refusing them 409
	// VERSIONING outside it; or 1, a format-1 instance as a rolled-back binary is (FS-72), which refuses every
	// format-2 construct 409 FORMAT_UNSUPPORTED {needs_format: 2}, answers a format-2 repo's pushes 503 and writes
	// nothing to it. Validate holds it to 1 or 2; it is a fact of the binary a test stands in for, not a knob.
	InstanceFormat uint32

	// How long a repo/ read stays cached in a process: §11.8 step 4's "cached at most 5 s". At most 5 s;
	// non-positive caches nothing, every read going to the cluster.
	RepoCacheTtl time.Duration
	// The most repo/ objects one process caches; past it one is evicted. Non-positive caches none.
	RepoCacheCount int

	// The metadata clusters' XFS block size, choosing §11.13's price table: 4 KiB until §22.8's nvme run
	// decides (D-TEST-11).
	PriceBlockByteCount int64

	// The most bytes of a request body a route reads: the lb's client_max_body_size, 16 MiB (§11.3). A
	// streamed segment upload is EVSB-M2-09's and takes its own bound. Non-positive refuses every body.
	RequestBodyMaxByteCount int64
	// How long Drain waits for requests in flight before it returns. Non-positive returns at once.
	DrainTimeout time.Duration
	// Retry-After on a 503 from a store or state that did not answer, which a retry may soon find answering: 1 s.
	// A closed gate answers its own reread interval instead (§19.11). Non-positive sends 1 s.
	UnavailableRetryAfter time.Duration
	// How often the readiness probe reads the first metadata cluster. Non-positive probes once, at start.
	StoreProbeInterval time.Duration
	// How long one probe read may take before the cluster reads as unreachable.
	StoreProbeTimeout time.Duration
	// §11.8's authorization row: a stream longer than this reads rev/ again before it goes on, 60 s.
	// Non-positive rereads at every check.
	RevocationStreamInterval time.Duration

	// §11.9's cache row: a cached head is served only within this of its cache time, 10 min. At most 10 min;
	// non-positive serves no cached head.
	HeadCacheServeAge time.Duration
	// {evsh_<repo_id>}'s ttl, which any ref's commit extends and which only bounds memory (§11.9; evs-24's
	// ttl row): 10 min. Positive.
	HeadCacheTtl time.Duration
	// How many times RaiseFence rereads the head and tries again after a 412, a fence racing a commit. §11.8's
	// refuse row's bound for its own CAS is 8, which this follows.
	FenceRetryCount int

	// §11.8's flush row: an open batch is written once its oldest record has waited this long, 20 ms.
	// Non-positive writes each batch at once.
	BatchFlushDelay time.Duration
	// §11.8's flush row's light load: a batch is written at once when nothing is in flight on its cluster
	// and the process took fewer than this many records there in the last BatchLightLoadWindow, 50.
	// Non-positive never counts as light.
	BatchLightLoadRecordCount int
	// The window BatchLightLoadRecordCount counts over, 1 s. Positive.
	BatchLightLoadWindow time.Duration
	// §11.8's flush row: at most this many batch writes in flight per process and cluster, 2. Positive.
	BatchWriteInFlightCount int

	// The bytes of batch records a process keeps by place (§11.8's cache row), records being immutable.
	// Non-positive keeps none.
	RecordCacheByteCount int64
	// The overlay chains a process keeps (§11.7's versions row: read at the ref's creation and cached).
	// Non-positive keeps none, every creation rereading the chain's heads.
	OverlayCacheCount int

	// §11.7's stale row: every fold write carries a store deadline this long after the fold issued the cluster read
	// of the head it relies on, 15 s, which a collection window's 15.3 s wait rests on. At most 15 s; positive.
	FoldStaleDeadline time.Duration
	// How long before that deadline a fold reads the head again rather than issue a write the store may refuse past
	// it, 1 s. At least zero and below FoldStaleDeadline.
	FoldHeadRereadMargin time.Duration
	// §11.7's when row (1): a commit leaving this many versions unfolded has its process fold the oldest
	// FoldVersionCount, off the reply path, 96. Non-positive never triggers it.
	FoldUnfoldedTriggerCount int
	// How many versions trigger (1) folds, 64. Positive.
	FoldVersionCount int
	// Trigger (1) runs at most once per ref per this, 10 s, and an idle fold that finds a fold of its ref running
	// tries again this long later. Positive.
	FoldTriggerInterval time.Duration
	// §11.7's when row (2): this long after a ref's last commit by this process, the process folds the rest, 10 min.
	// Non-positive never.
	FoldIdleDelay time.Duration
	// §11.7's collect row: a fold that read a head whose collection window is open writes over no marker the window
	// covers until this long past until_ms by its own clock, 150 ms, which keeps it 100 ms past in UTC on a clock
	// within 50 ms. At least 150 ms.
	FoldCollectMargin time.Duration
	// retry_after_ms of §11.7's lag row's 429 FOLD_BEHIND, 1 s. Positive.
	FoldBehindRetryAfter time.Duration
	// How many times a fold reads one entry again after a 412 or an unknown outcome before it gives the fold up, 16.
	// Positive.
	FoldEntryRetryCount int
	// The keys one LIST returns below a removed path, 1,000. Positive.
	FoldListPageCount int
	// How many refs a process keeps fold state for: its horizon, its triggers, its idle timer. Past it one idle
	// ref's is dropped, costing only a horizon raise. Non-positive keeps none.
	FoldRefStateCount int
	// The bytes of log pages a process keeps, which never change (§11.8's Resolve row), 16 MiB. Non-positive keeps
	// none.
	LogPageCacheByteCount int64

	// §11.8 step 7: the head If-Match is issued only within this of step 4's reads, else steps 4 and 5 run again,
	// 5 s. At most 5 s; positive.
	PushStepSevenWindow time.Duration
	// What a page-out at step 6 leaves step 7 of that window: its deadline is this long before the window ends, 1 s.
	// At least zero and below PushStepSevenWindow.
	PushPageOutReserve time.Duration
	// §11.8's 412 row: how many times a push reruns 5 (b-h) on a reread head and issues step 7 again before 429
	// BUSY, 8. Positive.
	PushConflictRetryCount int
	// How many times a push runs step 4 again from the cluster, after a refusal on a cached head, a passed 5 s
	// window or a stale read, before it answers 429 BUSY, 8. Positive.
	PushRerunCount int
	// §11.8's refuse row: how many times the recording CAS rereads and tries again after a 412 before the push
	// answers 503 unknown, 8. Positive.
	PushRefusalRetryCount int
	// §11.8's unknown row: rereads of the head after a step 7 whose outcome is unknown, before the push answers 503
	// unknown, 3, and the wait between them, 200 ms. Positive count; the wait at least zero.
	PushUnknownRereadCount    int
	PushUnknownRereadInterval time.Duration
	// §11.8's fence row: an attempt reading a fence_ms later than its arrival less this ends 503 unknown, 100 ms. At
	// least 100 ms.
	PushFenceMargin time.Duration
	// §11.8's refuse row: a refusal meeting a refusal fence younger than this, by refused_ms, answers 429 instead
	// of recording, 1 s. Positive.
	RefusalFenceInterval time.Duration
	// How long one attempt of a push may run once the client's request has arrived, its writes going on if the
	// client leaves: past it, 503 unknown. Within the lb's 30 s silence, 25 s. Positive.
	PushAttemptTimeout time.Duration
	// The body a one-part push or a seal may carry: its statement, a payload of at most 1 MiB and its receipts, 2
	// MiB. Positive.
	PushBodyMaxByteCount int64
	// The gen/<g> records a process keeps, which never change while their repo lives (§10's gen row). Non-positive
	// keeps none.
	GenerationCacheCount int
	// §11.8's lease row: the longest seal lease a push may ask for, 120 s. At most 120 s; positive.
	LeaseMaxDuration time.Duration

	// §11.9's request bounds (EVS1-M2-14): the paths one read names, 64; its ranges, 64, and their bytes in all, 32
	// MiB; and the slots, maps, log pages and push records it names, each 64. Positive.
	ReadPathMaxCount      int
	ReadRangeMaxCount     int
	ReadRangeMaxByteCount int64
	ReadObjectMaxCount    int
	// The body of a stored object one read frame carries, 1 MiB: an object past it spans frames. Positive and under
	// the frame bound.
	ReadFrameByteCount int
	// §11.9's rounds row: a segment up to this is read whole and a larger one in ReadSegmentRangeAlign-aligned
	// ranges, 256 KiB and 64 KiB. Positive.
	ReadSegmentWholeByteCount int64
	ReadSegmentRangeAlign     int64
	// How many times a read goes to a newer head from the cluster when an entry holds a version past the head it
	// read (§11.9's newest row), 2. Positive.
	ReadHeadRetryCount int
	// GET .../log's page: at most this many statements an answer, 1,000. Positive, at most 1,000.
	LogReplyStatementCount int
	// GET .../refs: the keys one LIST of head/<repo>/ returns, 1,000. Positive.
	RefsListPageCount int

	// §11.10's lease row (EVS1-M2-15): the token prefixes one lease request names, 16, the protocol's value, which
	// the client's Subscribe holds its paths to as well (evs_subscribe.go). Positive.
	LeaseMaxPrefixCount int
	// A lease's life after its last write, which a renewal repeats, 7 d; and {evsl_<repo_id>}'s own ttl, past every
	// lease's life so that a repo nobody renews leaves nothing, 8 d. Both positive, the hash's the longer.
	LeaseLife   time.Duration
	LeaseKeyTtl time.Duration
	// A lease request's body: 16 prefixes of at most 32 tokens, and the ids, 16 KiB. Positive.
	SubscriptionRequestMaxByteCount int64
	// The repo/ keys one LIST of the daily lease sweep returns, 1,000. Positive.
	LeaseSweepListPageCount int

	// §11.12's lifecycle: how many times a transition reads repo/ from the cluster again after another write came
	// first or an answer was lost, before a route answers 429 BUSY or a job fails to be retried, 8. Positive.
	RepoTransitionRetryCount int
	// The keys one LIST of a shred's delete pass or a reconciliation's walk returns, 1,000. Positive.
	ShredListPageCount int
	// How long a shred a preservation hold stopped at its step 4 waits before it reads the holds again, when no
	// hold covering the repo names an end: 24 h. Positive.
	ShredHoldRecheckInterval time.Duration

	// §11.6's copy row (EVS1-M2-17): a path-epoch copy's operations a second on one repo, 50, and while two or more
	// sources stand, 150; the cluster's share comes from the write budget (WriteBudget.CopyOpsPerSecond). Positive.
	CopyRepoOpsPerSecond        int
	CopyRepoSourcesOpsPerSecond int
	// §11.6's copy row: a copy rereads its ref's head at least this often, 5 s, the stale rule's bound on what its
	// writes rely on. At most 5 s; positive.
	CopyHeadRereadInterval time.Duration
	// How many times one move reads its entry again after a 412 or an unknown outcome before the job gives the run
	// up to its retry, 16. Positive.
	CopyMoveRetryCount int
	// The keys one LIST of a copy's walk returns, 1,000. Positive.
	CopyListPageCount int
	// The moves that write one copy run makes before it queues its successor, so a 1M-entry ref's copy is many runs,
	// each within its job's time: 10,000. Non-positive: no bound.
	CopyRunMoveCount int
	// The log pages a copy reads looking for its PATH_EPOCH once the window paged it out, for the tail: 16. Positive.
	CopyLogPageCount int
	// DESIGN-DETAILS 9.2.6's source rule: how far below the window a PATH_EPOCH's map source may lie, in log pages
	// counted down from the one just below it, of which its check reads the one holding the source, a cached GET
	// of at most 70 KiB: 1. Non-positive reads none, so only a source the window holds commits.
	MapSourcePageCount int

	// §11.8's 5b: a one-part push's time_ms within this of evs's clock, 10 min, and a part's and a seal's within
	// SealTimeBound, 30 min; further ahead 429 TIME_AHEAD. Both positive.
	PushTimeBound time.Duration
	SealTimeBound time.Duration
	// §11.6's slot: at most 8 KiB, which step 6's PUT and every read of one hold it to. Positive.
	SlotMaxByteCount int64
	// §11.8 step 6: a slot that exists with equal bytes is this push's only while under this old, 23 h (§11.22's M2
	// row), as a re-uploaded segment is. Positive.
	SlotExistingMaxAge time.Duration
	// gen/<g>'s bound: a Signed GenRotate with its GenLink and leaf wrap, 16 KiB, well under a metadata object's
	// 4 KiB block count. Positive.
	GenerationRecordMaxByteCount int64
	// §11.12's push row: how many times an ERASE's slot rewrite reads and writes one slot again after a 412 or a lost
	// answer before it leaves the slot to the reconciler, 8. Non-negative.
	SlotRewriteRetryCount int
	// How long after an ERASE whose rewrites could not finish taskworker's evs.erasure_finish runs for its repo, 1
	// min; the client's retry finishes them too. Positive.
	ErasureFinishDelay time.Duration
}

// The design's values, and 4 KiB blocks until the nvme run.
func DefaultEvsSettings() *EvsSettings {
	return &EvsSettings{
		Place:                     sidecar.DefaultEvsRepoPlaceSettings(),
		InstanceFormat:            sidecar.EvsRepoFormat2,
		RepoCacheTtl:              5 * time.Second,
		RepoCacheCount:            100 * 1000,
		PriceBlockByteCount:       4 * 1024,
		RequestBodyMaxByteCount:   16 * 1024 * 1024,
		DrainTimeout:              30 * time.Second,
		UnavailableRetryAfter:     time.Second,
		StoreProbeInterval:        5 * time.Second,
		StoreProbeTimeout:         2 * time.Second,
		RevocationStreamInterval:  60 * time.Second,
		HeadCacheServeAge:         10 * time.Minute,
		HeadCacheTtl:              10 * time.Minute,
		FenceRetryCount:           8,
		BatchFlushDelay:           20 * time.Millisecond,
		BatchLightLoadRecordCount: 50,
		BatchLightLoadWindow:      time.Second,
		BatchWriteInFlightCount:   2,
		RecordCacheByteCount:      64 * 1024 * 1024,
		OverlayCacheCount:         100 * 1000,
		FoldStaleDeadline:         15 * time.Second,
		FoldHeadRereadMargin:      time.Second,
		FoldUnfoldedTriggerCount:  96,
		FoldVersionCount:          64,
		FoldTriggerInterval:       10 * time.Second,
		FoldIdleDelay:             10 * time.Minute,
		FoldCollectMargin:         150 * time.Millisecond,
		FoldBehindRetryAfter:      time.Second,
		FoldEntryRetryCount:       16,
		FoldListPageCount:         1000,
		FoldRefStateCount:         100 * 1000,
		LogPageCacheByteCount:     16 * 1024 * 1024,
		PushStepSevenWindow:       5 * time.Second,
		PushPageOutReserve:        time.Second,
		PushConflictRetryCount:    8,
		PushRerunCount:            8,
		PushRefusalRetryCount:     8,
		PushUnknownRereadCount:    3,
		PushUnknownRereadInterval: 200 * time.Millisecond,
		PushFenceMargin:           100 * time.Millisecond,
		RefusalFenceInterval:      time.Second,
		PushAttemptTimeout:        25 * time.Second,
		PushBodyMaxByteCount:      2 * 1024 * 1024,
		GenerationCacheCount:      100 * 1000,
		LeaseMaxDuration:          evsLeaseMaxDuration,

		ReadPathMaxCount:          64,
		ReadRangeMaxCount:         64,
		ReadRangeMaxByteCount:     32 * 1024 * 1024,
		ReadObjectMaxCount:        64,
		ReadFrameByteCount:        1024 * 1024,
		ReadSegmentWholeByteCount: 256 * 1024,
		ReadSegmentRangeAlign:     64 * 1024,
		ReadHeadRetryCount:        2,
		LogReplyStatementCount:    evsLogReplyMaxStatementCount,
		RefsListPageCount:         1000,

		LeaseMaxPrefixCount:             16,
		LeaseLife:                       7 * 24 * time.Hour,
		LeaseKeyTtl:                     8 * 24 * time.Hour,
		SubscriptionRequestMaxByteCount: 16 * 1024,
		LeaseSweepListPageCount:         1000,

		RepoTransitionRetryCount: 8,
		ShredListPageCount:       1000,
		ShredHoldRecheckInterval: 24 * time.Hour,

		CopyRepoOpsPerSecond:        50,
		CopyRepoSourcesOpsPerSecond: 150,
		CopyHeadRereadInterval:      5 * time.Second,
		CopyMoveRetryCount:          16,
		CopyListPageCount:           1000,
		CopyRunMoveCount:            10 * 1000,
		CopyLogPageCount:            16,
		MapSourcePageCount:          1,

		PushTimeBound:                10 * time.Minute,
		SealTimeBound:                30 * time.Minute,
		SlotMaxByteCount:             8 * 1024,
		SlotExistingMaxAge:           23 * time.Hour,
		GenerationRecordMaxByteCount: 16 * 1024,
		SlotRewriteRetryCount:        8,
		ErasureFinishDelay:           time.Minute,
	}
}

// The ceilings the design's arguments rest on, and the fields that must be positive.
func (self *EvsSettings) Validate() error {
	if self.Place == nil {
		return fmt.Errorf("%w: no place settings", ErrEvsSettings)
	}
	if self.PushTimeBound <= 0 || self.SealTimeBound <= 0 || self.SlotMaxByteCount <= 0 || self.SlotExistingMaxAge <= 0 || self.GenerationRecordMaxByteCount <= 0 {
		return fmt.Errorf("%w: a push's time bound, a slot's bound or age, or gen/<g>'s bound not positive", ErrEvsSettings)
	}
	if self.SlotRewriteRetryCount < 0 || self.ErasureFinishDelay <= 0 {
		return fmt.Errorf("%w: a slot rewrite's retries negative or the erasure reconciler's delay not positive", ErrEvsSettings)
	}
	if self.InstanceFormat != sidecar.EvsRepoFormat1 && self.InstanceFormat != sidecar.EvsRepoFormat2 {
		return fmt.Errorf("%w: instance format %d is neither 1 nor 2", ErrEvsSettings, self.InstanceFormat)
	}
	if evsRepoCacheMaxTtl < self.RepoCacheTtl {
		return fmt.Errorf("%w: repo/ cached %s, past step 4's %s", ErrEvsSettings, self.RepoCacheTtl, evsRepoCacheMaxTtl)
	}
	if self.Place.NotFoundTtl < 0 {
		return fmt.Errorf("%w: a negative place/ 404 ttl", ErrEvsSettings)
	}
	if evsHeadCacheMaxServeAge < self.HeadCacheServeAge {
		return fmt.Errorf("%w: a cached head served %s, past §11.9's %s", ErrEvsSettings, self.HeadCacheServeAge, evsHeadCacheMaxServeAge)
	}
	if self.HeadCacheTtl <= 0 || self.BatchLightLoadWindow <= 0 || self.BatchWriteInFlightCount <= 0 {
		return fmt.Errorf("%w: a head cache ttl, light-load window and batch write count must be positive", ErrEvsSettings)
	}
	if self.StoreProbeTimeout <= 0 {
		return fmt.Errorf("%w: a store probe timeout must be positive", ErrEvsSettings)
	}
	if self.FenceRetryCount < 0 {
		return fmt.Errorf("%w: a negative fence retry count", ErrEvsSettings)
	}
	if _, err := DefaultPriceTable(self.PriceBlockByteCount); err != nil {
		return fmt.Errorf("%w: %v", ErrEvsSettings, err)
	}
	if self.FoldStaleDeadline <= 0 || evsFoldMaxStaleDeadline < self.FoldStaleDeadline {
		return fmt.Errorf("%w: a fold write's deadline %s, outside (0, %s]", ErrEvsSettings, self.FoldStaleDeadline, evsFoldMaxStaleDeadline)
	}
	if self.FoldHeadRereadMargin < 0 || self.FoldStaleDeadline <= self.FoldHeadRereadMargin {
		return fmt.Errorf("%w: a fold's reread margin %s against its deadline %s", ErrEvsSettings, self.FoldHeadRereadMargin, self.FoldStaleDeadline)
	}
	if self.FoldCollectMargin < evsFoldMinCollectMargin {
		return fmt.Errorf("%w: a fold's collection margin %s, below §11.7's %s", ErrEvsSettings, self.FoldCollectMargin, evsFoldMinCollectMargin)
	}
	if self.FoldVersionCount <= 0 || self.FoldTriggerInterval <= 0 || self.FoldBehindRetryAfter <= 0 ||
		self.FoldEntryRetryCount <= 0 || self.FoldListPageCount <= 0 {
		return fmt.Errorf("%w: a fold's version count, trigger interval, retry after, retry count and list page must be positive", ErrEvsSettings)
	}
	if self.PushStepSevenWindow <= 0 || evsPushMaxStepSevenWindow < self.PushStepSevenWindow {
		return fmt.Errorf("%w: step 7's window %s, outside (0, %s]", ErrEvsSettings, self.PushStepSevenWindow, evsPushMaxStepSevenWindow)
	}
	if self.PushPageOutReserve < 0 || self.PushStepSevenWindow <= self.PushPageOutReserve {
		return fmt.Errorf("%w: a page-out's reserve %s against step 7's window %s", ErrEvsSettings, self.PushPageOutReserve, self.PushStepSevenWindow)
	}
	if self.PushFenceMargin < evsPushMinFenceMargin {
		return fmt.Errorf("%w: a fence margin %s, below §11.8's %s", ErrEvsSettings, self.PushFenceMargin, evsPushMinFenceMargin)
	}
	if self.PushConflictRetryCount <= 0 || self.PushRerunCount <= 0 || self.PushRefusalRetryCount <= 0 ||
		self.PushUnknownRereadCount <= 0 || self.PushUnknownRereadInterval < 0 || self.RefusalFenceInterval <= 0 ||
		self.PushAttemptTimeout <= 0 || self.PushBodyMaxByteCount <= 0 {
		return fmt.Errorf("%w: a push's retry counts, reread count, refusal fence interval, attempt timeout and body bound must be positive", ErrEvsSettings)
	}
	if self.LeaseMaxDuration <= 0 || evsLeaseMaxDuration < self.LeaseMaxDuration {
		return fmt.Errorf("%w: a lease bound %s, outside (0, %s]", ErrEvsSettings, self.LeaseMaxDuration, evsLeaseMaxDuration)
	}
	if self.ReadPathMaxCount <= 0 || self.ReadRangeMaxCount <= 0 || self.ReadRangeMaxByteCount <= 0 || self.ReadObjectMaxCount <= 0 ||
		self.ReadSegmentWholeByteCount <= 0 || self.ReadSegmentRangeAlign <= 0 || self.ReadHeadRetryCount <= 0 || self.RefsListPageCount <= 0 {
		return fmt.Errorf("%w: a read's bounds, segment sizes, head retries and refs page must be positive", ErrEvsSettings)
	}
	if self.ReadFrameByteCount <= 0 || sidecar.EvsReadFrameMaxByteCount <= self.ReadFrameByteCount {
		return fmt.Errorf("%w: a read frame's body %d, outside (0, %d)", ErrEvsSettings, self.ReadFrameByteCount, sidecar.EvsReadFrameMaxByteCount)
	}
	if self.LogReplyStatementCount <= 0 || evsLogReplyMaxStatementCount < self.LogReplyStatementCount {
		return fmt.Errorf("%w: a log page of %d statements, outside (0, %d]", ErrEvsSettings, self.LogReplyStatementCount, evsLogReplyMaxStatementCount)
	}
	if self.LeaseMaxPrefixCount <= 0 || self.LeaseLife <= 0 || self.SubscriptionRequestMaxByteCount <= 0 || self.LeaseSweepListPageCount <= 0 {
		return fmt.Errorf("%w: a lease request's prefixes and body, a lease's life and the sweep's list page must be positive", ErrEvsSettings)
	}
	if self.LeaseKeyTtl <= self.LeaseLife {
		return fmt.Errorf("%w: leases kept %s in a hash that lives %s", ErrEvsSettings, self.LeaseLife, self.LeaseKeyTtl)
	}
	if self.RepoTransitionRetryCount <= 0 || self.ShredListPageCount <= 0 || self.ShredHoldRecheckInterval <= 0 {
		return fmt.Errorf("%w: a transition's retry count, a shred's list page and its hold recheck must be positive", ErrEvsSettings)
	}
	if self.CopyRepoOpsPerSecond <= 0 || self.CopyRepoSourcesOpsPerSecond <= 0 || self.CopyMoveRetryCount <= 0 ||
		self.CopyListPageCount <= 0 || self.CopyLogPageCount <= 0 {
		return fmt.Errorf("%w: a copy's rates, retry count and list page must be positive", ErrEvsSettings)
	}
	if self.CopyHeadRereadInterval <= 0 || evsCopyMaxHeadRereadInterval < self.CopyHeadRereadInterval {
		return fmt.Errorf("%w: a copy's head reread %s, outside (0, %s]", ErrEvsSettings, self.CopyHeadRereadInterval, evsCopyMaxHeadRereadInterval)
	}
	return nil
}
