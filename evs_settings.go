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
	// The most versions one History walks: 1,000, a page of the log's.
	HistoryVersionCount int
	// The trees a replay's tree builder keeps decoded, least recently used out: 64 MiB (DESIGN-DETAILS 8.2.2's
	// settings), which with the sink's pending chunk and one commit's changes is all a replay holds in memory.
	TreeCacheByteCount int64
	// The objects a replay's pack sink writes between two packs: 64 MiB (8.2.2), each pack then indexed into the bare
	// repository; export writes loose objects and has no chunk.
	ObjectSinkChunkByteCount int64
	// The first-parent ancestors of a new branch's tip searched for an overlay's base: 10,000 (DESIGN-DETAILS 8.2.4).
	OverlayBaseSearchCount int
	// The parts at which an import cuts a push: 512, the bound being 1,024 (DESIGN-DETAILS 8.2.6).
	ImportPushPartCount int
	// The sealed content at which an import cuts a push: 32 GiB.
	ImportPushByteCount int64
	// The time past which an import cuts a push whose parts would take longer to post at the rate measured: 10 min.
	ImportPostTime time.Duration
	// The sealed metadata an import assumes a commit takes before it is built: 1 KiB.
	ImportCommitEstimate int64
	// The parts past which one first-parent step is too large for one push, which the import then splits through
	// helper refs (QD-604): 960, the bound being 1,024.
	ImportStepPartCount int
	// The time past which a step whose parts would take longer to post is too large for one push: 20 min, a
	// statement's bound being 30.
	ImportStepPostTime time.Duration
	// The time past which a step whose content would take longer to upload is too large for one push: 18 h, a receipt
	// serving 22.
	ImportStepUploadTime time.Duration
	// The helper refs one import may make: 64 (QD-604).
	ImportHelperCount int
	// How deep one helper ref may nest inside another: 8 (QD-604).
	ImportHelperDepth int
	// The most of a segment a read fetches whole: 256 KiB (§11.9's rounds row); a larger one is read by
	// 64 KiB-aligned ranges.
	SegmentWholeByteCount int64
	// The most one system git command of the local tier runs: 5 min, past the receive hook's 3 min (§11.11).
	GitCommandTimeout time.Duration
	// How long a per-ref daemon lock waits before it gives up: 3 min, the hook's own bound (§11.11's journal row).
	RefLockTimeout time.Duration
	// The largest file, and the largest base, a write diffs: 8 MiB, past which a file is chunks anyway (§11.7). A phone
	// sets 1 MiB, since it never diffs a file over 1 MiB (§11.7's traps).
	DiffMaxByteCount int64
	// Segments one push uploads at once: 4 (§11.8's client step 2). A phone sets 2, running at most 2 transfers.
	UploadConcurrency int
	// Parts one push posts at once: 4 (§11.8's parts row). A phone sets 2.
	PartConcurrency int
	// How many times one push id's request, an upload or a lease goes again after a 429, a 503 or no answer, each one
	// attempt at a time with the same bytes (§11.8's retry id row): 40, past which the statement's own 10 min ends it.
	PushRetryCount int
	// The longest one wait between those attempts, whatever retry_after_ms says: 60 s.
	PushRetryMaxWait time.Duration
	// How many times one write builds its push again, under a new push id, after a refusal that asks for it
	// (SEGMENT_STALE, SEGMENT_GONE, SLOT_STALE, GATE_CLOSED, BASE_STALE, TIME_STALE), or re-tokenizes it after 412
	// PATH_EPOCH, the two counted together: 8.
	PushRebuildCount int
	// A retoken keeps a segment's receipt while it is under this old, 22 h, and uploads the segment again past it,
	// since evs adopts an upload only under 24 h old (DESIGN-DETAILS 9.2.5).
	RetokenReceiptMaxAge time.Duration
	// A creation that a ref's coming path epoch holds (412 PATH_EPOCH_DUE, or the planner's ErrEvsPathEpochDue) is
	// planned again after its retry_after_ms, or this long when it names none, 10 s, or at the ref's next verified
	// head, whichever comes first, at most PushRetryCount times before the caller gets EVS_PATH_EPOCH_DUE.
	PathEpochDueWait time.Duration

	// DESIGN-DETAILS 9.2.2's client settings. A new name is tokenized only on a head verified this recently: 5 s,
	// the window §11.5 publishes, in which a name's token sent on the epoch just left can reach evs after a cut-over.
	EpochFreshFor time.Duration
	// The most epochs one read names a path in: 8, what evs takes (EvsReadPathMaxEpochCount).
	ReadEpochCount int
	// The verified listings a client keeps in memory for lookups, by ref, directory and head version: 256.
	ListingCacheCount int
	// A writer raises evs_alarm epoch_overdue this long past a due's due_by_ms: 1 h (§11.6's alarm row).
	EpochOverdueAfter time.Duration
	// The most rounds one read takes across epoch moves, lookups and second asks before it gives up: 8.
	ReadEpochRoundCount int

	// DESIGN-DETAILS 9.2.2's mapper settings (evs_epoch_map.go). A mapper that did not rotate starts within a random
	// delay below this, 10 min, so two do not upload one map at once.
	MapperSpread time.Duration
	// A batched epoch is mapped this long before its due_by_ms: 2 h.
	MapperBatchedLead time.Duration
	// A map's part closes at this size: 7 MiB, under evs's 8 MiB; a phone sets 2 MiB, within R-EVS-14's 4 MiB.
	MapPartFillByteCount int
	// Parts uploaded at once: 4; a phone sets 2.
	MapUploadCount int
	// A map whose oldest part is older than this is abandoned: 20 h, as evs takes parts under 24 h old.
	MapMaxAge time.Duration
	// Tail refusals of one map before its mapper asks evs for the block: 2.
	MapTailRefusalCount int
	// A phone maps only while its index holds at most this many names, §11.6's bound: 100,000. Read only where
	// MapperMobile is set.
	MobileMapNameCount int
	// Whether this host is a phone, which maps only within MobileMapNameCount: the desktop daemon is not.
	MapperMobile bool
	// The most listings a listed index takes for one verified head to stand through a whole one: 8.
	ListedIndexRoundCount int
	// How many times a seal posts its parts again after 409 PARTS_MISSING: 3.
	PartsMissingRetryCount int
	// A git-mode push's seal lease, which it takes after its segments and before its parts: 120 s, the most evs grants
	// (§11.8's lease row).
	SealLeaseDuration time.Duration
	// How long a git-mode push in parts holds its seal lease before it takes it again, before its next part and before
	// its seal, so a push whose parts post past one lease keeps it (DESIGN-DETAILS 8.2.5's step 7; evs answers 200 for
	// a live lease of the push's own): 60 s, half of SealLeaseDuration. Non-positive takes it once.
	SealLeaseRenewInterval time.Duration
	// A deposit whose drop key the depositor rule does not take yet (ErrGkmWait: no newer rotation has reached this
	// device, or the newest lapsed) asks again after DropKeyWait, 30 s, at most DropKeyWaitCount times, 20, before
	// the caller gets ErrGkmWait (§11.12's deposits row: it waits for a newer rotation).
	DropKeyWait      time.Duration
	DropKeyWaitCount int
	// A repo a sidecar with no leaf creates waits keying for a member device to form its group (QD-638): CreateRepo
	// asks gkm for its generation 1 again after GroupFormWait, 10 s, at most GroupFormWaitCount times, 12, two of
	// gkm's 60 s pending hints, before it answers ErrEvsRepoKeying with the repo made, which a later CreateRepo with
	// ResumeRepoId waits on again. A non-positive count asks once.
	GroupFormWait      time.Duration
	GroupFormWaitCount int

	// §11.10's lease row: a subscription rereads its head fresh this long after its lease's 200, 5 s, so a commit an
	// evs process matched against leases read before the write is caught.
	SubscribeRereadDelay time.Duration
	// §11.10's renew row: a lease is renewed once it is this old, 24 h, at a random time within SubscribeRenewWindow,
	// 1 h, never because of a reconnect.
	SubscribeRenewAge    time.Duration
	SubscribeRenewWindow time.Duration
	// §11.10's gap row: every subscribed ref is read fresh, and its leases listed, this often at a random offset, 1 h.
	SubscribeResyncInterval time.Duration
	// §11.10's gap row: after an incomplete reset a background daemon first waits a random time below this, 10 min.
	SubscribeResetMaxWait time.Duration
	// A lease that did not answer 200 is tried again after this, doubling to SubscribeRetryMaxWait: 1 s to 5 min. A
	// final refusal waits SubscribeResyncInterval.
	SubscribeRetryMinWait time.Duration
	SubscribeRetryMaxWait time.Duration
	// How many tries Subscribe makes itself before it answers with the lease still owed, which the rounds keep
	// trying: 8.
	SubscribeRetryCount int
	// Whether this host is a background daemon, which waits out SubscribeResetMaxWait after an incomplete reset: the
	// desktop daemon is; an app in the foreground is not.
	SubscribeBackground bool
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
		HistoryVersionCount:      1000,
		TreeCacheByteCount:       64 * 1024 * 1024,
		ObjectSinkChunkByteCount: 64 * 1024 * 1024,
		OverlayBaseSearchCount:   10000,
		ImportPushPartCount:      512,
		ImportPushByteCount:      32 * 1024 * 1024 * 1024,
		ImportPostTime:           10 * time.Minute,
		ImportCommitEstimate:     1024,
		ImportStepPartCount:      960,
		ImportStepPostTime:       20 * time.Minute,
		ImportStepUploadTime:     18 * time.Hour,
		ImportHelperCount:        64,
		ImportHelperDepth:        8,
		SegmentWholeByteCount:    256 * 1024,
		GitCommandTimeout:        5 * time.Minute,
		RefLockTimeout:           3 * time.Minute,
		DiffMaxByteCount:         8 * 1024 * 1024,
		UploadConcurrency:        4,
		PartConcurrency:          4,
		PushRetryCount:           40,
		PushRetryMaxWait:         60 * time.Second,
		PushRebuildCount:         8,
		RetokenReceiptMaxAge:     22 * time.Hour,
		PathEpochDueWait:         10 * time.Second,
		EpochFreshFor:            5 * time.Second,
		ReadEpochCount:           8,
		ListingCacheCount:        256,
		EpochOverdueAfter:        time.Hour,
		ReadEpochRoundCount:      8,
		MapperSpread:             10 * time.Minute,
		MapperBatchedLead:        2 * time.Hour,
		MapPartFillByteCount:     7 * 1024 * 1024,
		MapUploadCount:           4,
		MapMaxAge:                20 * time.Hour,
		MapTailRefusalCount:      2,
		MobileMapNameCount:       100000,
		ListedIndexRoundCount:    8,
		PartsMissingRetryCount:   3,
		DropKeyWait:              30 * time.Second,
		DropKeyWaitCount:         20,
		GroupFormWait:            10 * time.Second,
		GroupFormWaitCount:       12,
		SealLeaseDuration:        120 * time.Second,
		SealLeaseRenewInterval:   60 * time.Second,
		SubscribeRereadDelay:     5 * time.Second,
		SubscribeRenewAge:        24 * time.Hour,
		SubscribeRenewWindow:     time.Hour,
		SubscribeResyncInterval:  time.Hour,
		SubscribeResetMaxWait:    10 * time.Minute,
		SubscribeRetryMinWait:    time.Second,
		SubscribeRetryMaxWait:    5 * time.Minute,
		SubscribeRetryCount:      8,
		SubscribeBackground:      true,
	}
}
