// What tunes the gkm engine (connect/CODESTYLE.md's settings rule): every timing, count and size that is policy
// rather than format, each a field here and read where it is used. A bound the design's argument needs, such as
// repo/'s 5 s cache (§10.6's checks row), is a ceiling Validate holds, so a setting can shorten it and never stretch
// it. Format values stay constants beside their formats: a ReaderKey's 7 days and gkm's 10 minutes of clock skew
// (gkm_delivery.go), a token's 64 repo scopes (§7.8), and a wrap batch's 256 and the drop-key route's 64 (§10.14).
//
// The rates are counted per process, in memory (plan-KEYS-rate-counters, decided): each limit is its rate times the
// process count, and a restart forgets it. The 24 h ReaderKey rule is exact, read from the stored object.

package gkmservice

import (
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// A settings value outside what the design allows.
var ErrGkmSettings = errors.New("gkm settings invalid")

// §10.6's checks row: repo/ is "cached at most 5 s", the bound a write in flight at a shred relies on, and the most
// RepoCacheTtl and FormCacheTtl may be.
const gkmRepoCacheMaxTtl = 5 * time.Second

// A limit of Count events per Interval, refilling evenly, so a quiet key may spend Count at once.
type GkmRate struct {
	Count    int
	Interval time.Duration
}

// Whether both parts are positive.
func (self GkmRate) valid() bool {
	return 0 < self.Count && 0 < self.Interval
}

// The engine's settings. Every field is read where it is used, from one instance.
type GkmServiceSettings struct {
	// place/'s resolution: a 404 cached 5 s, the placements a process keeps (§10.6's placement row).
	Place *sidecar.EvsRepoPlaceSettings

	// How long a repo/ read stays cached in a process: §10.6's "cached at most 5 s". At most 5 s; non-positive
	// caches nothing, every check reading the cluster.
	RepoCacheTtl time.Duration
	// The most repo/ objects one process caches; past it one is evicted. Non-positive caches none.
	RepoCacheCount int
	// How long a repo's GroupForms stay cached, so "the newest GroupForm names the group" reads as fresh as repo/
	// does. At most 5 s; non-positive caches nothing.
	FormCacheTtl time.Duration
	// The most repos whose GroupForms one process caches. Non-positive caches none.
	FormCacheCount int
	// The most GroupForms one repo's list reads. A re-form is rare (§10.8), so a repo past this is a fault, which
	// answers 503 and alarms.
	FormMaxCount int
	// The groups whose repo a process remembers. A group's repo never changes, since a re-form draws a new
	// group_id, so an evicted entry costs only its next resolution.
	GroupRepoCacheCount int
	// The most repos one request examines to find a group's: a token's 64 repo scopes (§7.8).
	GroupResolveRepoMaxCount int

	// The most bytes of a request body a route reads: 4 MiB, past a 1,000-leaf group's sealed GroupInfo of about
	// 2.8 MB (§10.6's sizes).
	RequestBodyMaxByteCount int64
	// The most bytes of one stored object a route reads: 4 MiB, the same bound.
	ObjectMaxByteCount int64
	// How many keys one LIST page asks for.
	ListPageCount int

	// How long Drain waits for requests in flight before it returns. Non-positive returns at once.
	DrainTimeout time.Duration
	// Retry-After on a 503 from a store or state that did not answer, which a retry may soon find answering: 1 s.
	// A closed gate answers its own reread interval instead (§19.11). Non-positive sends 1 s.
	UnavailableRetryAfter time.Duration
	// How often the readiness probe reads the first metadata cluster. Non-positive probes once, at start.
	StoreProbeInterval time.Duration
	// How long one probe read may take before the cluster reads as unreachable.
	StoreProbeTimeout time.Duration

	// The hints a request hands off, so no request waits on Redis: a hint is lossy, and a client that misses one
	// resyncs within the hour (§6.8). A hint past a full queue is dropped and counted.
	HintQueueCount int
	// The goroutines that send queued hints.
	HintWorkerCount int
	// How long one send may take.
	HintTimeout time.Duration

	// The most per-process rate entries a process keeps; past it, entries that have refilled go first.
	RateEntryCount int
	// §10.6's checks row: 60 commits an hour per uploader per group.
	CommitRate GkmRate
	// The claim checks' rate row: 60 claims an hour per uploader per group.
	ClaimRate GkmRate
	// The wrap checks' bound row: an uploader's STAGED objects in a group, 60 an hour per reader and live Delegation.
	StagedRate GkmRate
	// §10.6's KeyPackages row: 10 claims a minute per (claimer, target).
	KeyPackageClaimRate GkmRate

	// §10.6's KeyPackages row: up to 128 one-time KeyPackages per sidecar, beside its one last-resort.
	KeyPackageOneTimeMaxCount int
	// The same row's refill point: a claim that leaves a sidecar fewer than 32 one-time KeyPackages hints
	// key-packages-low to it.
	KeyPackageLowCount int
	// The longest a KeyPackage may stay valid past its upload: 90 days, a KeyPackage's life (§10.6), which gkm-4's
	// ttl repeats.
	KeyPackageMaxLifetime time.Duration
	// The refs whose last-resort flag a process remembers, which never changes for a ref, since the ref hashes the
	// KeyPackage that carries the flag.
	KeyPackageKindCacheCount int
	// §10.6's own row: a ReaderKey at most once per 24 h per sidecar after its first.
	ReaderKeyUploadInterval time.Duration
	// Reads that one POST /gkm/reader-keys issues at once.
	ReaderKeysReadConcurrency int
	// The most Welcomes one GET /gkm/welcomes answers. The client asks again once it has joined or acked them.
	WelcomesReplyMaxCount int
}

// The production defaults.
func DefaultGkmServiceSettings() *GkmServiceSettings {
	return &GkmServiceSettings{
		Place: sidecar.DefaultEvsRepoPlaceSettings(),

		RepoCacheTtl:             5 * time.Second,
		RepoCacheCount:           100 * 1000,
		FormCacheTtl:             5 * time.Second,
		FormCacheCount:           100 * 1000,
		FormMaxCount:             1000,
		GroupRepoCacheCount:      1000 * 1000,
		GroupResolveRepoMaxCount: 64,

		RequestBodyMaxByteCount: 4 * 1024 * 1024,
		ObjectMaxByteCount:      4 * 1024 * 1024,
		ListPageCount:           1000,

		DrainTimeout:          30 * time.Second,
		UnavailableRetryAfter: 1 * time.Second,
		StoreProbeInterval:    10 * time.Second,
		StoreProbeTimeout:     5 * time.Second,

		HintQueueCount:  64 * 1024,
		HintWorkerCount: 8,
		HintTimeout:     5 * time.Second,

		RateEntryCount:      1000 * 1000,
		CommitRate:          GkmRate{Count: 60, Interval: 1 * time.Hour},
		ClaimRate:           GkmRate{Count: 60, Interval: 1 * time.Hour},
		StagedRate:          GkmRate{Count: 60, Interval: 1 * time.Hour},
		KeyPackageClaimRate: GkmRate{Count: 10, Interval: 1 * time.Minute},

		KeyPackageOneTimeMaxCount: 128,
		KeyPackageLowCount:        32,
		KeyPackageMaxLifetime:     90 * 24 * time.Hour,
		KeyPackageKindCacheCount:  256 * 1024,
		ReaderKeyUploadInterval:   24 * time.Hour,
		ReaderKeysReadConcurrency: 16,
		WelcomesReplyMaxCount:     1024,
	}
}

// Refuses a value the design's argument cannot take.
func (self *GkmServiceSettings) Validate() error {
	if self.Place == nil {
		return fmt.Errorf("%w: no place settings", ErrGkmSettings)
	}
	if self.Place.NotFoundTtl < 0 {
		return fmt.Errorf("%w: a negative place/ 404 ttl", ErrGkmSettings)
	}
	if gkmRepoCacheMaxTtl < self.RepoCacheTtl || gkmRepoCacheMaxTtl < self.FormCacheTtl {
		return fmt.Errorf("%w: repo/ or GroupForms cached past §10.6's %s", ErrGkmSettings, gkmRepoCacheMaxTtl)
	}
	for _, count := range []struct {
		name  string
		value int64
	}{
		{name: "FormMaxCount", value: int64(self.FormMaxCount)},
		{name: "GroupResolveRepoMaxCount", value: int64(self.GroupResolveRepoMaxCount)},
		{name: "RequestBodyMaxByteCount", value: self.RequestBodyMaxByteCount},
		{name: "ObjectMaxByteCount", value: self.ObjectMaxByteCount},
		{name: "ListPageCount", value: int64(self.ListPageCount)},
		{name: "StoreProbeTimeout", value: int64(self.StoreProbeTimeout)},
		{name: "HintQueueCount", value: int64(self.HintQueueCount)},
		{name: "HintWorkerCount", value: int64(self.HintWorkerCount)},
		{name: "HintTimeout", value: int64(self.HintTimeout)},
		{name: "RateEntryCount", value: int64(self.RateEntryCount)},
		{name: "KeyPackageOneTimeMaxCount", value: int64(self.KeyPackageOneTimeMaxCount)},
		{name: "KeyPackageLowCount", value: int64(self.KeyPackageLowCount)},
		{name: "KeyPackageMaxLifetime", value: int64(self.KeyPackageMaxLifetime)},
		{name: "ReaderKeyUploadInterval", value: int64(self.ReaderKeyUploadInterval)},
		{name: "ReaderKeysReadConcurrency", value: int64(self.ReaderKeysReadConcurrency)},
		{name: "WelcomesReplyMaxCount", value: int64(self.WelcomesReplyMaxCount)},
	} {
		if count.value <= 0 {
			return fmt.Errorf("%w: %s must be positive", ErrGkmSettings, count.name)
		}
	}
	if self.KeyPackageOneTimeMaxCount < self.KeyPackageLowCount {
		return fmt.Errorf("%w: a refill point past the KeyPackage count", ErrGkmSettings)
	}
	for _, rate := range []GkmRate{self.CommitRate, self.ClaimRate, self.StagedRate, self.KeyPackageClaimRate} {
		if !rate.valid() {
			return fmt.Errorf("%w: a rate's count and interval must be positive", ErrGkmSettings)
		}
	}
	return nil
}
