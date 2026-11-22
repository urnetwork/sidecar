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
	// The parts of a sealed push one read asks for at once, as a replaying reader takes its record (evs_push_record.go):
	// 64, the most one read names (§11.9's request row). Non-positive reads a part a round.
	PushPartReadCount int
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

	// DESIGN-DETAILS 8.2.2's receive and sync settings (evs_local_receive.go, evs_local_sync.go). The time an update
	// may spend waiting on evs to take what it refused for now (429, PATH_EPOCH_DUE, a lease), and on
	// P_r, before git hears `ng <ref> busy` or `remote outcome pending`: 3 min, the hook's own bound.
	ReceiveWaitTimeout time.Duration
	// The time an update may spend building, uploading and posting before git hears `ng <ref> too slow`: 30 min, a
	// statement's own bound for a push in parts.
	ReceivePublishTimeout time.Duration
	// Updates of one git push published at once: 4.
	ReceiveRefCount int
	// An owned ref's first push after a local update: 250 ms (§11.11's owned row).
	QueueFirstDelay time.Duration
	// Then at most one push per owned ref this often: 2 s.
	QueueInterval time.Duration
	// Added to an attempt's time bound (10 min, or 30 for a push in parts) before it is taken for dead without the
	// head having moved: 15 min, past any clock skew a statement's bound allows.
	JournalResolveMargin time.Duration
	// A pending attempt's outcome is asked again this often, beside each hint: 1 min.
	JournalResolveInterval time.Duration
	// Versions replayed between two settles, each batch flushed before its ref moves: 64.
	ReplayBatchVersionCount int
	// Every followed ref is replayed this often, beside hints and pushes' answers: 1 h, as a hint is lossy.
	SyncResyncInterval time.Duration
	// Conflict branches a ref may have before its sync stops settling, its local ref left alone: 64 (QD-602).
	ConflictBranchCount int
	// Between two git gc runs of one mount: 24 h.
	GcMinInterval time.Duration
	// git gc runs once `git count-objects -v` shows more loose objects than this, 2,000, or more packs than
	// GcPackCount, 50: a replay writes a pack each flush (DESIGN-DETAILS 8.2.11).
	GcLooseObjectCount int
	GcPackCount        int
	// What git gc prunes: unreachable objects older than this, 14 days, so a push refused or a replay stopped can
	// still be fetched again or resumed within it (DESIGN-DETAILS 8.2.11).
	GcPruneAge time.Duration
	// The largest file, and the largest base, a write diffs: 8 MiB, past which a file is chunks anyway (§11.7). A phone
	// sets 1 MiB, since it never diffs a file over 1 MiB (§11.7's traps).
	DiffMaxByteCount int64
	// Segments one push uploads at once: 4 (§11.8's client step 2). A phone sets 2, running at most 2 transfers.
	UploadConcurrency int
	// Parts one push posts at once: 4 (§11.8's parts row). A phone sets 2.
	PartConcurrency int
	// The new slots' bodies, framed as payload section 7, past which WritePaths splits a write into pushes each
	// within them (evs_write_split.go): the format's SealSlotBodiesMaxByteCount, 1 MiB, past which a push in parts'
	// seal cannot carry them (QD-819). At most that bound; a write whose bodies pass a lower one splits whether or not
	// it would go in parts.
	PushSlotBodiesByteCount int
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
	// A creation a mapper's block holds (412 PATH_EPOCH_DUE, §11.6's block row) is planned again after its
	// retry_after_ms, or this long when it names none, 10 s, or at the ref's next verified head, whichever comes first,
	// at most PushRetryCount times before the caller gets EVS_PATH_EPOCH_DUE.
	PathEpochDueWait time.Duration

	// DESIGN-DETAILS 9.2.2's client settings. A new name is tokenized only on a head verified this recently: 5 s,
	// the window §11.5 publishes, in which a name's token sent on the epoch just left can reach evs after a cut-over.
	EpochFreshFor time.Duration
	// The most epochs one read names a path in: 8, what evs takes (ReadPathMaxEpochCount).
	ReadEpochCount int
	// The format's bound on the epochs one read names a path in (EvsFormatSettings.ReadPathMaxEpochCount), which a
	// read keeps to whatever ReadEpochCount says.
	ReadPathMaxEpochCount int
	// The verified listings a client keeps in memory for lookups, by ref, directory and head version: 256.
	ListingCacheCount int
	// A writer raises evs_alarm epoch_overdue this long past a due's due_by_ms: 1 h (§11.6's alarm row).
	EpochOverdueAfter time.Duration
	// And raises it again for the same ref and due generation at most this often: 24 h (DESIGN-DETAILS 9.2.8).
	EpochOverdueAlarmInterval time.Duration
	// The most rounds one read takes across epoch moves, lookups and second asks before it gives up: 8.
	ReadEpochRoundCount int
	// §11.6's commit and due rows as the format sets them (EvsFormatSettings): the sources a head lists at most and
	// those every epoch waits while, all being batched (QD-1046), which the status, the alarm and the mapper wait by,
	// and how long after it is first held a REMOVE generation no head records falls due.
	PathEpochMaxSourceCount        int
	PathEpochBatchedMaxSourceCount int
	PathEpochBatchedDelay          time.Duration
	// §11.6's block row as the format sets it: a mapper whose tail evs refused MapTailRefusalCount times asks evs to
	// stop creation on the ref this long past due_by_ms, 10 min, for this long, 2 min, the most evs grants.
	MapBlockAfterDue time.Duration
	MapBlockDuration time.Duration
	// The ticks the mapper's loop holds asked and not yet run before a further ask is dropped, which its timer then
	// covers: 64.
	MapperWakeCount int

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
	// An erasure with no ERASE for this long is stalled, another device's to finish: 25 h (§11.12's reconcile row).
	ErasureStallAfter time.Duration
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
	// How many times CreateRepo files and places again under another id after evs answers 409 REPO_PLACED, another
	// creator having placed its id first (§11.8's place row; QD-927): 2. Each files a RepoCreate of its own.
	RepoPlacedRetryCount int
	// The groups step's mends, each a lifecycle route of no statement of its own (EvsRepo.ReseedPlace): a repo
	// re-seeded as deleted whose repo/ the step found keying, and activated, goes to deleted by a DELETE (owner decision
	// 602), and a restored repo whose repo/ the place created deleted goes to active by a restore (owner decision 618).
	// evs answers either 409 STATEMENT_MISSING while its projection does not yet hold the RepoDelete or RepoRestore
	// this device's state shows, which is asked again after ReseedDeleteWait, 1 s, at most ReseedDeleteWaitCount
	// times, 30, six of §8.9's 5 s targets for a statement to reach the gates, before the step answers the refusal
	// with repo/ left as the place or activate left it. A non-positive count asks once.
	ReseedDeleteWait      time.Duration
	ReseedDeleteWaitCount int

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
	// The paths one Subscribe takes, each a lease's token prefix: the format's bound on a lease request
	// (EvsFormatSettings.SubscriptionMaxPrefixCount), 16.
	SubscribeMaxPrefixCount int
	// The statements a pin raise of a followed ref carried that the subscriber holds for the ref's next delivery of
	// its changes (evs_subscribe.go's marks row): 1,024 a ref, about 1 MiB at format 1's 1 KiB a statement, none once
	// delivered, which is a round or so later. Past it a delivery reads the rest from GET .../log. Positive.
	SubscribeHeldStatementCount int

	// §16.2's evs_write on a git-mode ref (owner decision 141; EVS1-M3-01): how many tips WriteAtTip commits on
	// while the path stays at its base version, a moved tip building the commit again on the newer one: 3.
	WriteAtTipTryCount int
	// How many of a path's versions Lookup walks back from its newest for the first after an action's base_version
	// (§16.6's evs row): 10,000. Past it Lookup answers ErrEvsLookupUnknown, which leaves the use uncertain.
	LookupVersionCount int
	// The newest storage format this client reads (§11.6's format row; D-EVS-39): 2. At 1 it reads as a format-1
	// client does, answering every format-2 construct FORMAT_UNSUPPORTED, which a rollback and FS-72's tests run
	// (EVS2-M10-30). Reading format 2 also needs its reader installed (EvsClient.EnableFormat2Reader), and writing it
	// §19.11's format2 gate (Format2Admitted).
	MaxFormat int
	// How many times ReadHead reads a versionless file again from a fresh head after its content was replaced
	// mid-read, before it answers ErrEvsReplacedMidRead (§11.7's reads row), 3. Not negative; 0 never rereads.
	ReadReplacedRestartCount int
	// How many times a read whose head another read of the same client raised the pin past while it was in flight,
	// and which the pin store cannot place on the pinned history, is read again, fresh, before it answers
	// ErrEvsReadStale: 4. Each read again asks at the pin then, which only a further overlapping raise passes again.
	ReadStaleRetryCount int
	// The chains a client keeps per ref while a read of it is in flight, C at each version its other reads' raises
	// walked, which judge a head a raise passed (evs_pin_store.go's header): 1,024, at most about 64 KiB a ref and
	// none once no read is in flight, the oldest out first, past which such a head is read again.
	PinChainCount int

	// §11.11's git-lfs rows (evs_lfs_*.go). A git-lfs pointer is shorter than this, 1,024 bytes, git-lfs's own bound
	// (docs/spec.md): a longer blob is no pointer and requires nothing (R(c)'s requires row).
	LfsPointerMaxByteCount int64
	// The largest object the store and the transfer agent take, refused by name past it (EVS_FILE_TOO_LARGE):
	// 2,147,483,648 bytes, the file cap through M10 (plan-EVS2-file-cap).
	LfsObjectMaxByteCount int64
	// The objects one head read of ur/lfs asks for: 64 (§11.11's store row).
	LfsHeadReadPathCount int
	// The newest versions the store keeps in memory, least recently used out: 65,536.
	LfsNewestCacheCount int
	// The transfer agent precedes an object's complete event with a progress event when it is at least this large:
	// 8 MiB, a segment's bound, past which git-lfs's progress bar otherwise sits still.
	LfsProgressByteCount int64
	// The tip check (evs_lfs_tipcheck.go): an object whose newest version was signed under LfsFreshAge ago, 5 days,
	// is fresh; a check over LfsCheckMaxAge old, 1 h, runs again before a push id's first POST; and the hook names up
	// to LfsMissingShownCount, 20, of the objects it finds missing.
	LfsFreshAge          time.Duration
	LfsCheckMaxAge       time.Duration
	LfsMissingShownCount int
	// The daily prune (evs_lfs_prune.go; plan-EVS2-lfs-settings, QD-258): N, the window, is LfsPruneWindow, 30 days,
	// while the settings file sets none, and never under LfsPruneWindowFloor, 7 days, on which the tip check's 5-day
	// freshness rests; `ur evs lfs window` takes 7 to LfsWindowMaxDays, 365; and a prune whose removal loses
	// path-level CAS runs again from its start read at most LfsPruneRerunCount times, 3.
	LfsPruneWindow      time.Duration
	LfsPruneWindowFloor time.Duration
	LfsWindowMaxDays    uint32
	LfsPruneRerunCount  int

	// The drop engine (evs_drop_lineage.go, evs_drop_preview.go). A head-mode device walks at most this much history
	// for one drop, 4 MiB, counted at a statement's bound a version, past which a device that mirrors the repo drops
	// it (QD-705's HeadDropFetchByteCount).
	HeadDropFetchByteCount int64
	// A dry run is read again every DropPreviewPollInterval, 2 s, at most DropPreviewPollCount times, 300, before the
	// command gives up on it.
	DropPreviewPollInterval time.Duration
	DropPreviewPollCount    int
	// Drops names at most this many paths a drop covers: 1,024 (I-13).
	DropNamesCount int
	// The completed dry runs a client keeps for DropHistory to name by preview id, 16, the oldest out first
	// (evs_drop_push.go).
	DropPreviewKeepCount int
	// A cancel is refused on this device within DropCancelMargin of its drop's not_before_ms, 60 s, as evs refuses one
	// (§11.7's action row; owner decision 183).
	DropCancelMargin time.Duration
	// The checked DROP bodies a device keeps sealed on storage, 4 MiB a client, least recently used out, which a read
	// names in held_drops so evs sends none of them again (DESIGN-DETAILS 10.2.2's DropBodyKeepByteCount, 10.2.3).
	DropBodyKeepByteCount int64
	// A read whose reply left out a drop body the reader lacks is read again at most DropBodyReadCount times, 4, its
	// missing body first each time (10.2.3's reply size).
	DropBodyReadCount int
	// `ur status` names at most StatusPathCount versioned paths whose history holds most of a ref's storage, 5
	// (evs_storage_status.go).
	StatusPathCount int
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
		PushPartReadCount:        64,
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
		ReceiveWaitTimeout:       3 * time.Minute,
		ReceivePublishTimeout:    30 * time.Minute,
		ReceiveRefCount:          4,
		QueueFirstDelay:          250 * time.Millisecond,
		QueueInterval:            2 * time.Second,
		JournalResolveMargin:     15 * time.Minute,
		JournalResolveInterval:   time.Minute,
		ReplayBatchVersionCount:  64,
		SyncResyncInterval:       time.Hour,
		ConflictBranchCount:      64,
		GcMinInterval:            24 * time.Hour,
		GcLooseObjectCount:       2000,
		GcPackCount:              50,
		GcPruneAge:               14 * 24 * time.Hour,
		DiffMaxByteCount:         8 * 1024 * 1024,
		UploadConcurrency:        4,
		PartConcurrency:          4,
		PushSlotBodiesByteCount:  DefaultEvsFormatSettings().SealSlotBodiesMaxByteCount,
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

		ReadPathMaxEpochCount:          DefaultEvsFormatSettings().ReadPathMaxEpochCount,
		EpochOverdueAlarmInterval:      24 * time.Hour,
		PathEpochMaxSourceCount:        DefaultEvsFormatSettings().PathEpochMaxSourceCount,
		PathEpochBatchedMaxSourceCount: DefaultEvsFormatSettings().PathEpochBatchedMaxSourceCount,
		PathEpochBatchedDelay:          DefaultEvsFormatSettings().PathEpochBatchedDelay,
		MapBlockAfterDue:               DefaultEvsFormatSettings().PathEpochBlockAfterDue,
		MapBlockDuration:               DefaultEvsFormatSettings().PathEpochBlockMaxDuration,
		MapperWakeCount:                64,

		MapperSpread:             10 * time.Minute,
		MapperBatchedLead:        2 * time.Hour,
		MapPartFillByteCount:     7 * 1024 * 1024,
		MapUploadCount:           4,
		MapMaxAge:                20 * time.Hour,
		MapTailRefusalCount:      2,
		ErasureStallAfter:        25 * time.Hour,
		MobileMapNameCount:       100000,
		ListedIndexRoundCount:    8,
		PartsMissingRetryCount:   3,
		DropKeyWait:              30 * time.Second,
		DropKeyWaitCount:         20,
		GroupFormWait:            10 * time.Second,
		GroupFormWaitCount:       12,
		RepoPlacedRetryCount:     2,
		ReseedDeleteWait:         time.Second,
		ReseedDeleteWaitCount:    30,
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
		SubscribeMaxPrefixCount:  DefaultEvsFormatSettings().SubscriptionMaxPrefixCount,
		WriteAtTipTryCount:       3,
		LookupVersionCount:       10000,
		MaxFormat:                2,
		ReadReplacedRestartCount: 3,
		ReadStaleRetryCount:      4,
		PinChainCount:            1024,
		LfsPointerMaxByteCount:   1024,
		LfsObjectMaxByteCount:    2 * 1024 * 1024 * 1024,
		LfsHeadReadPathCount:     64,
		LfsNewestCacheCount:      65536,
		LfsProgressByteCount:     8 * 1024 * 1024,
		LfsFreshAge:              5 * 24 * time.Hour,
		LfsCheckMaxAge:           time.Hour,
		LfsMissingShownCount:     20,
		LfsPruneWindow:           30 * 24 * time.Hour,
		LfsPruneWindowFloor:      7 * 24 * time.Hour,
		LfsWindowMaxDays:         365,
		LfsPruneRerunCount:       3,
		HeadDropFetchByteCount:   4 * 1024 * 1024,
		DropPreviewPollInterval:  2 * time.Second,
		DropPreviewPollCount:     300,
		DropNamesCount:           1024,
		DropPreviewKeepCount:     16,
		DropCancelMargin:         60 * time.Second,
		DropBodyKeepByteCount:    4 * 1024 * 1024,
		DropBodyReadCount:        4,
		StatusPathCount:          5,

		SubscribeHeldStatementCount: 1024,
	}
}
