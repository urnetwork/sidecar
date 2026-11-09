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

// The engine's settings. Every field is read where it is used, from one instance.
type EvsSettings struct {
	// place/'s resolution: a 404 cached 5 s, the placements a process keeps (§11.8's resolve row).
	Place *sidecar.EvsRepoPlaceSettings

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
}

// The design's values, and 4 KiB blocks until the nvme run.
func DefaultEvsSettings() *EvsSettings {
	return &EvsSettings{
		Place:                     sidecar.DefaultEvsRepoPlaceSettings(),
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
	}
}

// The ceilings the design's arguments rest on, and the fields that must be positive.
func (self *EvsSettings) Validate() error {
	if self.Place == nil {
		return fmt.Errorf("%w: no place settings", ErrEvsSettings)
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
	return nil
}
