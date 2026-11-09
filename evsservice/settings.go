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
	return nil
}
