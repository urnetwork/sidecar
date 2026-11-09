// The client's evs settings (§11.9, §11.11, §11.15), SidecarSettings.Evs: what an EvsClient, its verifying reader and
// its local tier read. DefaultEvsSettings is the only source of a default (connect/CODESTYLE.md:144), and a host
// adjusts what it returns per class rather than keeping a second copy, as a phone does for CatchUpByteCount. Format
// values every reader applies alike stay constants beside their formats: the 64 repo scopes a token carries
// (sidecarExchangeMaxRepoScopeCount), a chain's 17 records (EvsChainMaxRecordCount) and git's 2.34 floor
// (evsLocalGitMinVersion).
//
// Every number must be positive: SidecarSettings.validate's walk refuses anything else.
//
// On every leg.

package sidecar

import (
	"time"
)

// What an EvsClient reads.
type EvsSettings struct {
	// The longest one call to evs takes, its body streamed: 55 s, the lb's 60 s idle bound less a margin, since a
	// read reply streams up to 32 MiB of ranges (§11.9) and the push sender's own deadline is its caller's.
	RequestTimeout time.Duration
	// How many times a read retries a 429 or a 503 that refuses nothing, each after its retry_after_ms: 3. A push's
	// retries are the push sender's (§11.8's retry id row), never this.
	ReadRetryCount int
	// The longest retry_after_ms a read waits out before giving up with the refusal: 30 s.
	ReadRetryMaxWait time.Duration
	// The wait before a retry when evs names none: 1 s.
	ReadRetryWait time.Duration
	// The most one answer that is not a read stream may hold: 4 MiB, past every reply §11.20 gives (a log page is at
	// most 1,000 statements of 1 KiB).
	ReplyMaxByteCount int64
	// The most statements and proofs a head reader fetches to catch up from its pin (§11.9's budget): 4 MiB, a
	// phone's, which a desktop that replays keeps. Further behind, it re-pins at the head and marks the gap.
	CatchUpByteCount int64
	// The per-path read records a head reader keeps for one network, least recently used out
	// (g0-recheck-0-head-reader-read-paths#1): 16,384.
	HeadReadRecordCount int
	// The most of a delta base a reconstruction holds in memory: 1 MiB (§11.7); a larger base spills to the sealed
	// local store, so a whole path streams within R-EVS-14's 4 MiB on phones.
	DeltaBaseMemoryByteCount int64
	// The most of a segment a read fetches whole: 256 KiB (§11.9's rounds row); a larger one is read by
	// 64 KiB-aligned ranges.
	SegmentWholeByteCount int64
	// The most one system git command of the local tier runs: 5 min, past the receive hook's 3 min (§11.11).
	GitCommandTimeout time.Duration
	// How long a per-ref daemon lock waits before it gives up: 3 min, the hook's own bound (§11.11's journal row).
	RefLockTimeout time.Duration
}

// The desktop daemon's evs settings.
func DefaultEvsSettings() *EvsSettings {
	return &EvsSettings{
		RequestTimeout:           55 * time.Second,
		ReadRetryCount:           3,
		ReadRetryMaxWait:         30 * time.Second,
		ReadRetryWait:            1 * time.Second,
		ReplyMaxByteCount:        4 * 1024 * 1024,
		CatchUpByteCount:         4 * 1024 * 1024,
		HeadReadRecordCount:      16384,
		DeltaBaseMemoryByteCount: 1024 * 1024,
		SegmentWholeByteCount:    256 * 1024,
		GitCommandTimeout:        5 * time.Minute,
		RefLockTimeout:           3 * time.Minute,
	}
}
