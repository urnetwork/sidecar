//go:build !ios_extension

// The sync engine (§11.14's Reads block, §16.10's sync row; D-EVS-50, D-EVS-51, FI-17, FI-23, I-19; DESIGN-DETAILS
// 7.2.7, which governs; SEARCH-M10-19): for each (repo, index ref) this device follows for search, the index files
// §18.4's policy has it keep, brought to one version of the ref at a time, and the snapshot a search reads. It is the
// only reader of evs for the index: a search, local or remote, reads the cache and never starts a round (QD-048).
//
// A round, one at a time a ref, a trigger during it running another after it:
//
//	1 head      the statements after the manifest's pin (replay), each change of the index noted, the pin ring fed,
//	            an index push naming another index_epoch than the ref's newest CUT before it alarmed (I-EVS-17), and
//	            an erasure set version from a signer who may not erase listed bad and alarmed at step 4, a push that
//	            removes every file of a bucket and writes a/m read as that bucket's roll-up; or past the catch-up
//	            budget, a re-pin and a listing, whose roll-ups are one entry and retain nothing
//	2 target    T = h; staged files T lists at their version stay, the rest go
//	3 reproduce SEARCH-M10-21's, behind searchSyncReproducer, nil until it lands, when every wanted file is fetched
//	4 fetch     search_fetch.go: the latest set, then the all set where it is kept, in a fixed order that reads
//	            nothing a search asked; a read answering collected restarts the round at step 1 on the new head
//	5 swap      search_retained.go: once every latest-set file T lists is held, staged or bad at T's version, the
//	            version table's runs, then the manifest at T (the swap), then the ref's version; rolled buckets kept
//	            or dropped by 7.2.7's three cases
//	6 swap all  once all's shards as T lists them are held or staged and the latest set is at T
//	7 retire    files and runs no manifest, plan or open snapshot names go
//
// Triggers (7.2.7): a hint or wake, leading-edge per repo over Search.HintCoalesce (QD-048); the app coming to the
// foreground; Search.ResyncInterval; a background window; "search more", which also asks for the all set. A round
// that fails on a read keeps its plan and staged files and is tried again after Search.SyncRetryInterval, doubling up
// to ResyncInterval, or at the next trigger. At most Search.SyncRoundCount rounds run at once, the most recently
// searched repos first. A ref read for search by a device that is not one of its owner's consented devices
// deposits a read receipt naming the round's wanted files before the round's first fetch, and starts at most one
// round a Search.NonWriterSyncInterval (§16.10's receipts).
//
// What a round ignores, alarming (FI-17): any path under the index prefix that is not §11.14's own, and every index
// file of a config, mailcfg or secret repo, which this engine never follows. The highest root this build reads is
// followed, so through a rebuild it serves i1 until i2 replaces it; a ref whose only root is newer has no snapshot
// and reads status update. A newer root's files are another build's and raise nothing.
//
// Barriers (testHookBarrier), keyed <repo>/<ref>: search.sync.replayed, .fetched (a file), .tables (the version table
// merged), .swapped, .retired. No key is created, derived or unwrapped here: a fetched record opens under the keys its
// source gives, which the cache never keeps.
//
// Not here: the settings file's signer, which the view judges where it reads it (SEARCH-M10-08); indexed_through,
// which searchSyncCoverage computes where one is given (SEARCH-M10-12's reader), and reads 0, claiming nothing, where
// none is; the erasure and drop paths, which call EndRepo and the cache's DropRetained (CORE-M10-04).
//
// On every leg but ios_extension: root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The ref's only index root is in a newer format or normalizer than this build reads: no snapshot, status update.
	ErrSearchSyncNewerRoot = errors.New("search sync: the index is in a newer format")
	// A round restarted on collected answers more than Search.SyncRestartCount times: tried again later.
	errSearchSyncRestarts = errors.New("search sync: the head kept moving under the round")
	// The engine was closed.
	ErrSearchSyncClosed = errors.New("search sync: closed")
	// The ref is not followed for search.
	ErrSearchSyncUnfollowed = errors.New("search sync: the ref is not followed")
	// A non-writer's round needs a read receipt first, and none can be deposited: nothing is fetched.
	errSearchSyncReceipt = errors.New("search sync: no read receipt could be deposited")
	// A background round's next read is past the day's budget (Search.BackgroundByteCount): held back.
	errSearchSyncHeldBack = errors.New("search sync: background budget spent")
)

// Why a round runs (DESIGN-DETAILS 7.2.7's triggers).
type SearchSyncReason int

const (
	// A hint (§11.10) or wake: leading-edge coalesced per repo over Search.HintCoalesce.
	SearchSyncHint SearchSyncReason = iota + 1
	// The app came to the foreground.
	SearchSyncForeground
	// Search.ResyncInterval passed.
	SearchSyncResync
	// A background window (RunSearchBackgroundSync).
	SearchSyncWindow
	// "search more": the all set too, kept or not (SEARCH-M10-20).
	SearchSyncMore
)

// What the sync engine reads of one index ref: evs, through the verifying reader (§11.9). Its adapter over EvsRepo
// verifies every statement, entry version and record before answering.
type searchSyncSource interface {
	// The statements after pin, oldest first, each verified, with their index changes; or catchUp, with the head as
	// §11.9 re-pins it, when they pass the catch-up budget.
	Replay(ctx context.Context, pin SearchSyncPin) (*searchSyncReplay, error)
	// Every file under the ref's index roots and its erasure set at the head, one read a directory.
	List(ctx context.Context) (*indexListing, error)
	// Whole files at their versions, as evs sealed them, with what opens each and what reopens it after the round
	// (QD-838, QD-845): its file id and the 72 B block wrapping its object key, from its segment's header or, for a
	// slot-keyed record, from the slot object the read answered, with that slot key's generation and the segment's
	// (SearchCacheRecord.SetSlotKey). A collected version answers with collected set and no record. At most the
	// engine's read limits a call.
	Fetch(ctx context.Context, files []*indexFileVersion) ([]*searchSyncFetched, error)
}

// What a replay found.
type searchSyncReplay struct {
	head       *indexRefHead
	statements []*searchSyncStatement
	catchUp    bool
}

// One verified push of the index ref, as far as the index is concerned.
type searchSyncStatement struct {
	version      uint64
	chain        [sha256.Size]byte
	signedTimeMs int64
	signer       Id
	// The index_epoch the push named, and whether it is a CUT (flag 512, which moves the epoch to its own version) or
	// a CLOSURE (which names none).
	indexEpoch uint64
	cut        bool
	closure    bool
	// Its changes under the index roots and the erasure set, by path.
	changes []*searchSyncChange
}

// One change: a new version of path, or its removal (file nil).
type searchSyncChange struct {
	path string
	file *indexFileVersion
}

// One file a fetch answered.
type searchSyncFetched struct {
	file   *indexFileVersion
	record *SearchCacheRecord
	// The version is replaced and its content gone (§11.9's collected): the round restarts on the new head.
	collected bool
}

// SEARCH-M10-21's step 3: for each merge, roll-up and CLOSURE replayed whose every input this device holds or has
// staged at the version the push's base lists, build it and compare content_sha256, answering the outputs it staged
// on a match. Nil until that task lands, when every wanted file is fetched.
type searchSyncReproducer interface {
	Reproduce(ctx context.Context, repoId Id, refId Id, manifest *SearchManifest, plan *SearchSyncPlan) ([]*SearchManifestFile, error)
}

// SEARCH-M10-12's coverage reading for one content ref, from the rows the snapshot's heads carry: indexed_through.
// Nil reads 0, which claims nothing.
type searchSyncCoverage func(ctx context.Context, repoId Id, contentRefId Id, rows []*SearchManifestCoverage) (uint64, error)

// What the engine runs on.
type searchSyncArgs struct {
	cache    *SearchCache
	settings *SidecarSearchSettings
	format   *IndexFormatSettings
	clock    Clock
	log      Logger
	// index_malformed's sink (Sidecar.searchEvents).
	events func(event SidecarEvent)
	// §11.9's read limits, the evs client's: paths and bytes a read.
	readPathCount int
	readByteCount int64
	reproducer    searchSyncReproducer
	coverage      searchSyncCoverage
	// What background rounds may download: SEARCH-M10-20's policy, Search.BackgroundByteCount a UTC day. Nil holds them
	// to nothing but the read limits. A "search more" round is held to its call's own budget instead.
	budget searchSyncBudget
}

// The background budget a round asks before each read and tells after (SearchPolicy).
type searchSyncBudget interface {
	AdmitBackground(repoId Id, byteCount int64) bool
	SpentBackground(repoId Id, byteCount int64)
}

// One ref the engine follows.
type searchSyncRefArgs struct {
	repoId   Id
	refId    Id
	repoKind protocol.RepoKind
	// The index rides ur/index, whose rows carry their ref_id; else the ref's own .ur-index/.
	companion bool
	source    searchSyncSource
	// Whether this device keeps the ref's all set: background hosts always, phones in a window (SEARCH-M10-20's
	// policy). Nil keeps it.
	keepAll func() bool
	// Read for search by a device that is not one of the owner-bound repo's owner's consented devices.
	nonWriter bool
	// Deposits §16.10's read receipt naming the round's wanted files, before the round's first fetch; a non-writer
	// with none fetches nothing.
	depositReceipt func(ctx context.Context, wanted []*SearchSyncWanted) error
	// Whether this device keeps the ref's latest set synced (SEARCH-M10-20's policy): false runs no round but "search
	// more"'s, as phones keep the team directory. Nil keeps it.
	keepLatest func() bool
	// Whether signer could erase the repo's documents at signedTimeMs: an admin of the repo, the directory's too
	// (§11.12's cut and directory rows). An erasure set version from any other signer is ignored and alarmed, and the
	// last set one who could signed keeps masking (§11.14's cut row). Required, so a composition cannot leave it out.
	mayErase func(signer Id, signedTimeMs int64) bool
}

// One followed ref's state. Fields past roundLock are the round's, read by snapshots under the engine's stateLock.
type searchSyncRef struct {
	args *searchSyncRefArgs
	// One round at a time a ref.
	roundLock sync.Mutex
	// One load of the manifest and plan, which a snapshot may run beside a round.
	loadLock sync.Mutex
	// The version table of the manifest's root; nil until a root is known. Set under the engine's stateLock.
	table *SearchVersionTable
	// The "search more" call a running round serves, under roundLock: its budget and its per-shard search
	// (search_more.go). Nil for every other round.
	moreRun *searchSyncMoreRun
	// The last round's error, nil after a success; under the engine's stateLock. A search names a repo whose read
	// receipt did not land from it (search_receipts.go).
	lastErr error

	// Under the engine's stateLock.
	due         time.Time
	more        bool
	running     bool
	again       bool
	retry       time.Duration
	roundAt     time.Time
	resyncAt    time.Time
	loaded      bool
	manifest    *SearchManifest
	manifestSer uint64
	plan        *SearchSyncPlan
	planSer     uint64
	// Snapshots open on this ref.
	open map[*SearchSyncSnapshot]bool
	// Unknown paths already alarmed, by path and version, so a round does not alarm one file twice.
	alarmed map[string]uint64
}

// A repo's leading-edge hint state (QD-048).
type searchSyncHints struct {
	// The end of the repo's coalescing interval, and whether a hint came inside it.
	intervalEnd time.Time
	pending     bool
}

// One index ref's sync, and the snapshots searches read. Construct with newSearchSync.
type SearchSync struct {
	args *searchSyncArgs

	stateLock sync.Mutex
	refs      map[[2]Id]*searchSyncRef
	hints     map[Id]*searchSyncHints
	closed    bool
	wake      chan struct{}
	cancel    context.CancelFunc
	done      chan struct{}
}

// An engine over args. Nothing runs until Start, or a caller's RunDue.
func newSearchSync(args *searchSyncArgs) (*SearchSync, error) {
	if args == nil || args.cache == nil || args.settings == nil || args.format == nil {
		return nil, fmt.Errorf("%w: a sync needs its cache and settings", ErrSearchCacheArgs)
	}
	settings := args.settings
	if settings.ResyncInterval <= 0 || settings.SyncRoundCount <= 0 || settings.SyncRetryInterval <= 0 ||
		settings.PinRingCount <= 0 || settings.RetainFactor <= 0 || settings.HintCoalesce <= 0 || settings.SyncRestartCount <= 0 {
		return nil, fmt.Errorf("%w: the sync's settings", ErrSearchCacheArgs)
	}
	if args.readPathCount <= 0 || args.readByteCount <= 0 {
		return nil, fmt.Errorf("%w: the sync's read limits", ErrSearchCacheArgs)
	}
	copied := *args
	copied.clock = clockOrReal(args.clock)
	copied.log = loggerOrDefault(args.log)
	if copied.events == nil {
		copied.events = func(SidecarEvent) {}
	}
	return &SearchSync{
		args:  &copied,
		refs:  map[[2]Id]*searchSyncRef{},
		hints: map[Id]*searchSyncHints{},
		wake:  make(chan struct{}, 1),
	}, nil
}

// Follows a ref for search: its rounds start at the next trigger. An index root in a config, mailcfg or secret repo is
// never followed (FI-17): ErrSearchSyncUnfollowed.
func (self *SearchSync) Follow(args *searchSyncRefArgs) error {
	if args == nil || args.source == nil || args.repoId == (Id{}) || args.refId == (Id{}) || args.mayErase == nil {
		return fmt.Errorf("%w: a followed ref needs its ids, source and erasure judge", ErrSearchCacheArgs)
	}
	switch args.repoKind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_SECRET,
		protocol.RepoKind_REPO_KIND_UNSPECIFIED:
		// §11.14's never row: these repos hold no index, and one found there is ignored
		return fmt.Errorf("%w: a %s repo holds no index", ErrSearchSyncUnfollowed, args.repoKind)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return ErrSearchSyncClosed
	}
	key := [2]Id{args.repoId, args.refId}
	if ref := self.refs[key]; ref != nil {
		ref.args = args
		return nil
	}
	self.refs[key] = &searchSyncRef{args: args, open: map[*SearchSyncSnapshot]bool{}, alarmed: map[string]uint64{}}
	return nil
}

// Stops following a ref. Its files stay until DropRef or eviction takes them; open snapshots keep theirs.
func (self *SearchSync) Unfollow(repoId Id, refId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.refs, [2]Id{repoId, refId})
}

// The barrier key of a ref: <repo>/<ref>.
func searchSyncBarrierKey(repoId Id, refId Id) string {
	return repoId.String() + "/" + refId.String()
}

// Asks for a round of a repo's followed refs, or of one (refId set), for reason. A hint is leading-edge per repo: the
// first in a quiet Search.HintCoalesce starts a round now, later ones in that interval start one at its end (QD-048).
// Every other reason is due now. Never called by a search.
func (self *SearchSync) Trigger(repoId Id, refId *Id, reason SearchSyncReason) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return
	}
	now := self.args.clock.Now()
	due := now
	if reason == SearchSyncHint {
		hints := self.hints[repoId]
		if hints == nil {
			hints = &searchSyncHints{}
			self.hints[repoId] = hints
		}
		if now.Before(hints.intervalEnd) {
			hints.pending = true
			due = hints.intervalEnd
		} else {
			hints.intervalEnd = now.Add(self.args.settings.HintCoalesce)
			hints.pending = false
		}
	}
	for key, ref := range self.refs {
		if key[0] != repoId || (refId != nil && key[1] != *refId) {
			continue
		}
		if reason == SearchSyncMore {
			ref.more = true
		}
		if ref.running {
			ref.again = true
		}
		if ref.due.IsZero() || due.Before(ref.due) {
			ref.due = due
		}
	}
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Runs every round due now, at most Search.SyncRoundCount at once, the most recently searched repos first, until none
// is due; answers when the next one is due, the zero time for none. A round's error is logged and retried, never
// returned: the caller is a timer.
func (self *SearchSync) RunDue(ctx context.Context) time.Time {
	for {
		due := self.dueRefs()
		if len(due) == 0 {
			return self.nextDue()
		}
		slots := make(chan struct{}, self.args.settings.SyncRoundCount)
		wait := sync.WaitGroup{}
		for _, ref := range due {
			slots <- struct{}{}
			wait.Add(1)
			go func() {
				defer wait.Done()
				defer func() { <-slots }()
				self.runRef(ctx, ref)
			}()
		}
		wait.Wait()
		if ctx.Err() != nil {
			return time.Time{}
		}
	}
}

// The refs due now, claimed as running, in the order rounds take them: the most recently searched repos first, then
// by ids, so the order reads nothing but sync state and whole repos (FI-23).
func (self *SearchSync) dueRefs() []*searchSyncRef {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.args.clock.Now()
	settings := self.args.settings
	due := []*searchSyncRef{}
	for _, ref := range self.refs {
		if !ref.resyncAt.IsZero() && !now.Before(ref.resyncAt) && (ref.due.IsZero() || ref.resyncAt.Before(ref.due)) {
			ref.due = ref.resyncAt
		}
		if ref.running || ref.due.IsZero() || now.Before(ref.due) {
			continue
		}
		if ref.args.keepLatest != nil && !ref.args.keepLatest() && !ref.more {
			// kept for "search more" alone: no background round
			ref.due = time.Time{}
			continue
		}
		if ref.args.nonWriter && !ref.roundAt.IsZero() && now.Before(ref.roundAt.Add(settings.NonWriterSyncInterval)) {
			// a non-writer's rounds are spaced (§16.10's receipts)
			ref.due = ref.roundAt.Add(settings.NonWriterSyncInterval)
			continue
		}
		ref.running = true
		ref.again = false
		ref.due = time.Time{}
		if hints := self.hints[ref.args.repoId]; hints != nil && hints.pending && !now.Before(hints.intervalEnd) {
			// the deferred round of a burst opens the next interval, so a busy repo costs one round an interval
			hints.pending = false
			hints.intervalEnd = now.Add(settings.HintCoalesce)
		}
		due = append(due, ref)
	}
	cache := self.args.cache
	searched := map[Id]time.Time{}
	for _, ref := range due {
		searched[ref.args.repoId] = cache.lastSearched(ref.args.repoId)
	}
	slices.SortFunc(due, func(a *searchSyncRef, b *searchSyncRef) int {
		return cmp.Or(
			searched[b.args.repoId].Compare(searched[a.args.repoId]),
			compareIndexKeys(a.args.repoId, b.args.repoId),
			compareIndexKeys(a.args.refId, b.args.refId),
		)
	})
	return due
}

// When the next round is due, the zero time for none.
func (self *SearchSync) nextDue() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	next := time.Time{}
	for _, ref := range self.refs {
		for _, at := range []time.Time{ref.due, ref.resyncAt} {
			if !at.IsZero() && (next.IsZero() || at.Before(next)) {
				next = at
			}
		}
	}
	return next
}

// One claimed round of ref, then its next due time: the resync after a success, the retry after a failure, at once
// when a trigger came during it.
func (self *SearchSync) runRef(ctx context.Context, ref *searchSyncRef) {
	more := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		more := ref.more
		ref.more = false
		return more
	}()
	err := self.round(ctx, ref, more)
	if errors.Is(err, errSearchSyncHeldBack) {
		// the day's background budget is spent: what is staged stays, and the next resync or "search more" goes on
		err = nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.args.clock.Now()
	settings := self.args.settings
	ref.running = false
	ref.roundAt = now
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			self.args.log.Warningf("[search]a sync round failed: %s", err)
		}
		if ref.retry <= 0 {
			ref.retry = settings.SyncRetryInterval
		} else {
			ref.retry = min(2*ref.retry, settings.ResyncInterval)
		}
		ref.more = ref.more || more
		if ref.due.IsZero() || now.Add(ref.retry).Before(ref.due) {
			ref.due = now.Add(ref.retry)
		}
	} else {
		ref.retry = 0
		ref.resyncAt = now.Add(settings.ResyncInterval)
	}
	if ref.again {
		ref.again = false
		ref.due = now
	}
}

// One round of a followed ref now, waiting for one already running: for "search more" (more asks for the all set)
// and tests. A search never calls it.
func (self *SearchSync) RunRound(ctx context.Context, repoId Id, refId Id, more bool) error {
	self.stateLock.Lock()
	ref := self.refs[[2]Id{repoId, refId}]
	closed := self.closed
	self.stateLock.Unlock()
	if closed {
		return ErrSearchSyncClosed
	}
	if ref == nil {
		return ErrSearchSyncUnfollowed
	}
	return self.round(ctx, ref, more)
}

// Runs rounds in the background as they come due, until Close.
func (self *SearchSync) Start(ctx context.Context) {
	self.stateLock.Lock()
	if self.closed || self.cancel != nil {
		self.stateLock.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	self.cancel = cancel
	self.done = make(chan struct{})
	done := self.done
	self.stateLock.Unlock()
	go func() {
		defer close(done)
		for {
			next := self.RunDue(runCtx)
			var timer <-chan time.Time
			if !next.IsZero() {
				timer = self.args.clock.After(next.Sub(self.args.clock.Now()))
			}
			select {
			case <-runCtx.Done():
				return
			case <-self.wake:
			case <-timer:
			}
		}
	}()
}

// Stops the background rounds, waiting for the one running, and ends every open snapshot.
func (self *SearchSync) Close() {
	self.stateLock.Lock()
	if self.closed {
		self.stateLock.Unlock()
		return
	}
	self.closed = true
	cancel, done := self.cancel, self.done
	snapshots := []*SearchSyncSnapshot{}
	for _, ref := range self.refs {
		for snapshot := range ref.open {
			snapshots = append(snapshots, snapshot)
		}
	}
	self.stateLock.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	for _, snapshot := range snapshots {
		snapshot.end()
	}
}

// Raises index_malformed for a file a push signed (§11.14's verify row; §5.4's event).
func (self *SearchSync) raiseMalformed(ref *searchSyncRef, path string, signer Id) {
	repoId, refId := ref.args.repoId, ref.args.refId
	self.args.events(SidecarEvent{Kind: SidecarEventIndexMalformed, RepoId: &repoId, RefId: &refId, Path: path, SidecarId: &signer})
}

// Loads the ref's manifest and plan from the cache once; one that does not decode is derived state, dropped.
func (self *SearchSync) load(ref *searchSyncRef) error {
	ref.loadLock.Lock()
	defer ref.loadLock.Unlock()
	self.stateLock.Lock()
	loaded := ref.loaded
	self.stateLock.Unlock()
	if loaded {
		return nil
	}
	cache, repoId, refId := self.args.cache, ref.args.repoId, ref.args.refId
	var manifest *SearchManifest
	content, manifestSer, err := searchLoadRefPart(cache, repoId, refId, SearchCachePartManifest)
	if err != nil {
		return err
	}
	if content != nil {
		manifest, err = searchDecodeManifest(content)
		if err == nil {
			err = manifest.check()
		}
		if err != nil {
			self.args.log.Warningf("[search]a search manifest did not decode: dropped")
			manifest = nil
		}
	}
	var plan *SearchSyncPlan
	content, planSer, err := searchLoadRefPart(cache, repoId, refId, SearchCachePartPlan)
	if err != nil {
		return err
	}
	if content != nil {
		plan, err = searchDecodePlan(content)
		if err != nil {
			self.args.log.Warningf("[search]a sync plan did not decode: dropped")
			plan = nil
		}
	}
	if manifest != nil {
		if err := self.openTable(ref, manifest.Root); err != nil {
			return err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref.loaded = true
	ref.manifest, ref.manifestSer = manifest, manifestSer
	ref.plan, ref.planSer = plan, planSer
	return nil
}

// Opens the version table of root, once a root is known or moves.
func (self *SearchSync) openTable(ref *searchSyncRef, root string) error {
	self.stateLock.Lock()
	current := ref.table
	self.stateLock.Unlock()
	if current != nil && current.root == root {
		return nil
	}
	table, err := NewSearchVersionTable(self.args.cache, ref.args.repoId, ref.args.refId, root)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref.table = table
	return nil
}

// The ref's manifest and plan as the round holds them.
func (self *SearchSync) state(ref *searchSyncRef) (*SearchManifest, *SearchSyncPlan) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return ref.manifest, ref.plan
}

// Writes the plan whole, or removes it where nothing is left to stage.
func (self *SearchSync) storePlan(ctx context.Context, ref *searchSyncRef, plan *SearchSyncPlan) error {
	cache, repoId, refId := self.args.cache, ref.args.repoId, ref.args.refId
	self.stateLock.Lock()
	previous := ref.planSer
	self.stateLock.Unlock()
	serial := uint64(0)
	if plan != nil {
		content, err := plan.encode()
		if err != nil {
			return err
		}
		if serial, err = searchStoreRefPart(ctx, cache, repoId, refId, SearchCachePartPlan, content, previous); err != nil {
			return err
		}
	} else if previous != 0 {
		if err := cache.RemoveDerived(searchManifestKey(repoId, refId, previous), SearchCachePartPlan); err != nil {
			return err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref.plan, ref.planSer = plan, serial
	return nil
}

// Writes the manifest whole: the swap.
func (self *SearchSync) storeManifest(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest) error {
	cache, repoId, refId := self.args.cache, ref.args.repoId, ref.args.refId
	content, err := manifest.encode()
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	previous := ref.manifestSer
	self.stateLock.Unlock()
	serial, err := searchStoreRefPart(ctx, cache, repoId, refId, SearchCachePartManifest, content, previous)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref.manifest, ref.manifestSer = manifest, serial
	return nil
}

// Whether the ref keeps its all set this round.
func (self *searchSyncRef) keepsAll(more bool) bool {
	return more || self.args.keepAll == nil || self.args.keepAll()
}

// One round of ref (see the file header), restarted at step 1 when a read answers collected, at most
// Search.SyncRestartCount times.
func (self *SearchSync) round(ctx context.Context, ref *searchSyncRef, more bool) error {
	err := self.roundWithRun(ctx, ref, more, nil)
	self.noteError(ref, err)
	return err
}

// Records a round's outcome for lastError.
func (self *SearchSync) noteError(ref *searchSyncRef, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref.lastErr = err
}

// The last round's error of a followed ref, nil after a success or for a ref not followed.
func (self *SearchSync) lastError(repoId Id, refId Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if ref := self.refs[[2]Id{repoId, refId}]; ref != nil {
		return ref.lastErr
	}
	return nil
}

// A round serving run, a "search more" call's, which holds its fetch of the all set to the call's budget and searches
// each shard as it lands (search_more.go); nil for every other round.
func (self *SearchSync) roundWithRun(ctx context.Context, ref *searchSyncRef, more bool, run *searchSyncMoreRun) error {
	ref.roundLock.Lock()
	defer ref.roundLock.Unlock()
	ref.moreRun = run
	defer func() { ref.moreRun = nil }()
	if err := self.load(ref); err != nil {
		return err
	}
	if err := self.args.cache.SweepRetained(); err != nil {
		return err
	}
	for restart := 0; ; restart += 1 {
		if self.args.settings.SyncRestartCount < restart {
			return errSearchSyncRestarts
		}
		restarted, err := self.roundOnce(ctx, ref, more)
		if err != nil {
			return err
		}
		if !restarted {
			return nil
		}
	}
}

// Steps 1 to 7 once: true where a read answered collected, so the round starts again on the new head.
func (self *SearchSync) roundOnce(ctx context.Context, ref *searchSyncRef, more bool) (bool, error) {
	key := searchSyncBarrierKey(ref.args.repoId, ref.args.refId)
	manifest, plan := self.state(ref)
	target, err := self.head(ctx, ref, manifest)
	if err != nil {
		return false, err
	}
	testHookBarrier("search.sync.replayed", key)
	if target.newer {
		// nothing this build reads: no snapshot, status update; what it held stays until a root it reads returns
		return false, ErrSearchSyncNewerRoot
	}
	if target.pin.Version == 0 {
		// a ref with no head holds no index yet
		return false, nil
	}
	// the head step 1 verified, which the cache's record of the ref follows from here
	if err := self.args.cache.SetRefVersion(ref.args.repoId, ref.args.refId, target.pin.Version); err != nil {
		return false, err
	}
	// step 2: the target, and what stays staged toward it
	next := &SearchSyncPlan{
		Root: target.root, Target: target.pin, IndexEpoch: target.indexEpoch, By: target.by, Wanted: target.listing,
		Rolled: target.rolled, Pins: target.pins,
	}
	if plan != nil && plan.Root == target.root {
		listed := map[string]uint64{}
		for _, wanted := range target.listing {
			listed[wanted.Path] = wanted.Version
		}
		for _, staged := range plan.Staged {
			if listed[staged.Path] == staged.Version {
				next.Staged = append(next.Staged, staged)
			}
		}
	}
	if err := self.openTable(ref, target.root); err != nil {
		return false, err
	}
	// step 3: reproduction, where a reproducer is given
	if reproducer := self.args.reproducer; reproducer != nil {
		outputs, err := reproducer.Reproduce(ctx, ref.args.repoId, ref.args.refId, manifest, next)
		if err != nil {
			return false, err
		}
		next.Staged = append(next.Staged, outputs...)
	}
	if err := self.storePlan(ctx, ref, next); err != nil {
		return false, err
	}
	// step 4 over the latest set, then step 5
	restarted, err := self.fetch(ctx, ref, manifest, next, true)
	if err != nil || restarted {
		return restarted, err
	}
	swapped, err := self.swapLatestStep(ctx, ref, manifest, next)
	if err != nil {
		return false, err
	}
	// step 4 over the all set where it is kept, then step 6, only ever at the latest set's pin
	if ref.keepsAll(more) {
		restarted, err := self.fetch(ctx, ref, swapped, next, false)
		if err != nil || restarted {
			return restarted, err
		}
		if err := self.swapAllStep(ctx, ref, swapped, next); err != nil {
			return false, err
		}
	}
	// step 7
	if err := self.retire(ref); err != nil {
		return false, err
	}
	testHookBarrier("search.sync.retired", key)
	return false, nil
}

// What step 1 found.
type searchSyncTarget struct {
	pin        SearchSyncPin
	indexEpoch uint64
	by         SearchSyncBy
	// The root this build follows, and every file the target lists under it and the erasure set.
	root    string
	listing []*SearchSyncWanted
	rolled  []*SearchSyncRolled
	pins    []SearchSyncPinPair
	// The ref holds index files only under roots newer than this build reads.
	newer bool
}

// Step 1: the head by replay from the manifest's pin, or by listing past the catch-up budget.
func (self *SearchSync) head(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest) (*searchSyncTarget, error) {
	pin := SearchSyncPin{}
	if manifest != nil {
		pin = manifest.Pin
	}
	replay, err := ref.args.source.Replay(ctx, pin)
	if err != nil {
		return nil, err
	}
	if replay.catchUp {
		return self.byListing(ctx, ref)
	}
	target := &searchSyncTarget{by: SearchSyncByReplay}
	current := map[string]*SearchSyncWanted{}
	epoch := uint64(0)
	windows := map[searchBucketRef]uint32{}
	if manifest != nil {
		for _, listed := range manifest.Listing {
			current[listed.Path] = listed
		}
		epoch = manifest.IndexEpoch
		for _, file := range manifest.Files {
			if file.WindowDays != 0 {
				if parsed, ok := indexParsePath(file.Path, ref.args.companion); ok {
					windows[searchBucketOf(parsed)] = file.WindowDays
				}
			}
		}
	}
	// buckets a statement since the pin changed a file of, by root and start day
	touched := map[searchBucketRef]bool{}
	for _, statement := range replay.statements {
		target.pins = append(target.pins, SearchSyncPinPair{Version: statement.version, Chain: statement.chain})
		changes := []*searchSyncChange{}
		for _, change := range statement.changes {
			if _, ok := indexParsePath(change.path, ref.args.companion); !ok {
				// FI-17: not §11.14's own, ignored and alarmed once a version
				version := uint64(0)
				if change.file != nil {
					version = change.file.version
				}
				self.alarmUnknown(ref, change.path, version, statement.signer)
				continue
			}
			changes = append(changes, change)
		}
		if 0 < len(changes) && !statement.closure && statement.indexEpoch != epoch {
			// §11.14's epoch row: an index push naming another epoch than the ref's newest CUT before it
			self.raiseMalformed(ref, changes[0].path, statement.signer)
		}
		if statement.cut {
			epoch = statement.version
		}
		// a push that removes every file of a bucket and writes a/m rolls that bucket up
		removed := map[string]bool{}
		writesAll := map[string]bool{}
		for _, change := range changes {
			parsed, _ := indexParsePath(change.path, ref.args.companion)
			if change.file == nil {
				removed[change.path] = true
			} else if parsed.kind == indexPathAllManifest {
				writesAll[searchRootOf(parsed)] = true
			}
		}
		for bucket, paths := range searchBucketPaths(current, ref.args.companion) {
			if !writesAll[bucket.root] || !searchAllRemoved(paths, removed) {
				continue
			}
			target.rolled = append(target.rolled, &SearchSyncRolled{
				StartDay: bucket.startDay, WindowDays: windows[bucket], AtVersion: statement.version,
				InputWhole: !touched[bucket] && windows[bucket] != 0,
			})
		}
		slices.SortFunc(target.rolled, func(a *SearchSyncRolled, b *SearchSyncRolled) int {
			return cmp.Or(cmp.Compare(a.AtVersion, b.AtVersion), cmp.Compare(a.StartDay, b.StartDay))
		})
		for _, change := range changes {
			parsed, _ := indexParsePath(change.path, ref.args.companion)
			if parsed.kind == indexPathBucketManifest || parsed.kind == indexPathBucketShard || parsed.kind == indexPathSlot || parsed.kind == indexPathLargeEntry {
				touched[searchBucketOf(parsed)] = true
			}
			if change.file == nil {
				delete(current, change.path)
				continue
			}
			current[change.path] = searchWantedOf(change.file, parsed)
		}
	}
	target.pin = SearchSyncPin{Version: replay.head.version, Chain: replay.head.chain, TimeMs: replay.head.signedTimeMs}
	target.indexEpoch = replay.head.indexEpoch
	if 0 < len(replay.statements) {
		last := replay.statements[len(replay.statements)-1]
		target.pin = SearchSyncPin{Version: last.version, Chain: last.chain, TimeMs: last.signedTimeMs}
		target.indexEpoch = epoch
	} else if manifest != nil {
		target.pin, target.indexEpoch = manifest.Pin, manifest.IndexEpoch
	}
	listing := []*SearchSyncWanted{}
	for _, listed := range current {
		listing = append(listing, listed)
	}
	return self.settleTarget(ref, target, listing)
}

// Step 1 past the catch-up budget: the head's pin, every file listed; the roll-ups it missed are found at the swap
// from a/m, and retain nothing.
func (self *SearchSync) byListing(ctx context.Context, ref *searchSyncRef) (*searchSyncTarget, error) {
	listed, err := ref.args.source.List(ctx)
	if err != nil {
		return nil, err
	}
	target := &searchSyncTarget{
		by:         SearchSyncByListing,
		pin:        SearchSyncPin{Version: listed.head.version, Chain: listed.head.chain, TimeMs: listed.head.signedTimeMs},
		indexEpoch: listed.head.indexEpoch,
		pins:       []SearchSyncPinPair{{Version: listed.head.version, Chain: listed.head.chain}},
	}
	listing := []*SearchSyncWanted{}
	for _, file := range listed.files {
		parsed, ok := indexParsePath(file.path, ref.args.companion)
		if !ok {
			self.alarmUnknown(ref, file.path, file.version, file.signerSidecarId)
			continue
		}
		listing = append(listing, searchWantedOf(file, parsed))
	}
	return self.settleTarget(ref, target, listing)
}

// Picks the root this build follows from a target's listing: the highest it reads. A ref whose files sit only under
// newer roots is newer; one with no root at all follows this build's own, empty.
func (self *SearchSync) settleTarget(ref *searchSyncRef, target *searchSyncTarget, listing []*SearchSyncWanted) (*searchSyncTarget, error) {
	readable := uint32(0)
	newer := false
	for _, listed := range listing {
		parsed, _ := indexParsePath(listed.Path, ref.args.companion)
		if parsed.kind == indexPathErasureSet {
			continue
		}
		if indexRootNumber < parsed.rootNumber {
			newer = true
			continue
		}
		readable = max(readable, parsed.rootNumber)
	}
	if readable == 0 {
		if newer {
			target.newer = true
			return target, nil
		}
		readable = indexRootNumber
	}
	target.root = indexNewPaths(ref.args.companion, readable).root
	slices.SortFunc(listing, func(a *SearchSyncWanted, b *SearchSyncWanted) int {
		return strings.Compare(a.Path, b.Path)
	})
	target.listing = listing
	return target, nil
}

// Alarms a path under the index prefix that is not §11.14's own, once a version (FI-17).
func (self *SearchSync) alarmUnknown(ref *searchSyncRef, path string, version uint64, signer Id) {
	self.stateLock.Lock()
	seen, ok := ref.alarmed[path]
	if !ok || seen != version {
		ref.alarmed[path] = version
	}
	self.stateLock.Unlock()
	if ok && seen == version {
		return
	}
	self.raiseMalformed(ref, path, signer)
}

// A listed file as a target holds it.
func searchWantedOf(file *indexFileVersion, parsed indexPath) *SearchSyncWanted {
	partition, _ := searchPartitionOfPath(parsed)
	return &SearchSyncWanted{
		Path: file.path, Version: file.version, ContentSha256: file.contentSha256, ByteCount: int64(file.byteCount),
		Partition: partition, Signer: file.signerSidecarId, CommitVersion: file.commitVersion, SignedTimeMs: file.signedTimeMs,
	}
}

// The root path a parsed path sits under.
func searchRootOf(parsed indexPath) string {
	return indexNewPaths(parsed.companion, parsed.rootNumber).root
}

// A bucket of one root.
type searchBucketRef struct {
	root     string
	startDay uint32
}

// The bucket a parsed path sits in.
func searchBucketOf(parsed indexPath) searchBucketRef {
	return searchBucketRef{root: searchRootOf(parsed), startDay: parsed.bucketStartDay}
}

// The paths of each bucket a listing holds.
func searchBucketPaths(current map[string]*SearchSyncWanted, companion bool) map[searchBucketRef][]string {
	buckets := map[searchBucketRef][]string{}
	for path := range current {
		parsed, ok := indexParsePath(path, companion)
		if !ok {
			continue
		}
		switch parsed.kind {
		case indexPathBucketManifest, indexPathBucketShard, indexPathSlot, indexPathLargeEntry:
			bucket := searchBucketOf(parsed)
			buckets[bucket] = append(buckets[bucket], path)
		}
	}
	return buckets
}

// Whether removed takes every one of paths.
func searchAllRemoved(paths []string, removed map[string]bool) bool {
	for _, path := range paths {
		if !removed[path] {
			return false
		}
	}
	return 0 < len(paths)
}

// Takes a snapshot of the ref for a search: the manifest's files and the version table's runs, held until Release so
// no swap or retirement removes them, with all's usability computed now (7.2.7's all row). ErrSidecarStoreAbsent for a
// ref with no manifest yet.
func (self *SearchSync) Snapshot(repoId Id, refId Id) (*SearchSyncSnapshot, error) {
	self.stateLock.Lock()
	ref := self.refs[[2]Id{repoId, refId}]
	closed := self.closed
	self.stateLock.Unlock()
	if closed {
		return nil, ErrSearchSyncClosed
	}
	if ref == nil {
		return nil, ErrSearchSyncUnfollowed
	}
	if err := self.load(ref); err != nil {
		return nil, err
	}
	held, err := self.args.cache.Ref(repoId, refId)
	if err != nil {
		return nil, err
	}
	// never waits for a round: the manifest is read and the snapshot counted open in one step under the state lock,
	// so a swap after it keeps every file and run the snapshot names until it is released (retire reads the open set)
	self.stateLock.Lock()
	manifest, table := ref.manifest, ref.table
	if manifest == nil {
		self.stateLock.Unlock()
		return nil, ErrSidecarStoreAbsent
	}
	snapshot := &SearchSyncSnapshot{sync: self, ref: ref, manifest: manifest, ended: make(chan struct{})}
	snapshot.allUsable = searchAllUsable(manifest, held)
	ref.open[snapshot] = true
	self.stateLock.Unlock()
	runIds := []SearchVersionRunId{}
	for _, run := range manifest.Runs {
		if run.Slot.Kind == SearchVersionAll && !snapshot.allUsable {
			continue
		}
		runIds = append(runIds, run.RunId)
	}
	if table != nil && 0 < len(runIds) {
		versions, err := table.Snapshot(runIds)
		if err != nil {
			snapshot.end()
			return nil, err
		}
		snapshot.versions = versions
	}
	return snapshot, nil
}

// Ends every open snapshot of the repo, releasing what it held: CORE-M10-04's ApplyErase, ApplyCut and an executed
// drop call it before they return, so the files an erasure replaced go at once (§16.10's pages row).
func (self *SearchSync) EndRepo(repoId Id) {
	self.stateLock.Lock()
	snapshots := []*SearchSyncSnapshot{}
	for key, ref := range self.refs {
		if key[0] != repoId {
			continue
		}
		for snapshot := range ref.open {
			snapshots = append(snapshots, snapshot)
		}
	}
	self.stateLock.Unlock()
	for _, snapshot := range snapshots {
		snapshot.end()
	}
}

// The frozen file set a running search holds (§11.14's swap row): one version of the index ref, whole, with all only
// while it is usable. Release it when the search ends; an erasure ends it first (Ended). Safe for concurrent use.
type SearchSyncSnapshot struct {
	sync      *SearchSync
	ref       *searchSyncRef
	manifest  *SearchManifest
	versions  *SearchVersionSnapshot
	allUsable bool
	once      sync.Once
	ended     chan struct{}
}

// The index ref's version the snapshot's latest set is whole at.
func (self *SearchSyncSnapshot) Pin() SearchSyncPin {
	return self.manifest.Pin
}

// Whether a manifest exists: every bucket file of the pin is held, staged or bad.
func (self *SearchSyncSnapshot) Whole() bool {
	return self.manifest != nil
}

// Whether all may be searched: held, and its pin the snapshot's or every roll-up between bridged by a bucket this
// device retained as the roll-up read it (7.2.7's all row).
func (self *SearchSyncSnapshot) AllUsable() bool {
	return self.allUsable
}

// The start of the oldest bucket the snapshot holds, in ms: where a search of the buckets alone covers from. 0 for
// none.
func (self *SearchSyncSnapshot) LatestFromMs() int64 {
	oldest := uint32(0)
	found := false
	for _, file := range self.manifest.Files {
		if file.Partition.All || !strings.Contains(file.Path, "/b/") {
			continue
		}
		if !found || file.Partition.StartDay < oldest {
			oldest, found = file.Partition.StartDay, true
		}
	}
	if !found {
		return 0
	}
	return int64(oldest) * indexDayMs
}

// The files that failed their checks at the version listed.
func (self *SearchSyncSnapshot) Bad() []*SearchManifestFile {
	bad := []*SearchManifestFile{}
	for _, file := range self.manifest.Files {
		if file.State == SearchManifestBad {
			bad = append(bad, file)
		}
	}
	return bad
}

// Every file the snapshot holds for search, each with its two times: the buckets', retained ones included, and all's
// where all is usable. Bad and newer files hold nothing and are left out.
func (self *SearchSyncSnapshot) Files() []*SearchManifestFile {
	files := []*SearchManifestFile{}
	for _, file := range self.manifest.Files {
		if file.State != SearchManifestHeld || (file.Partition.All && !self.allUsable) {
			continue
		}
		files = append(files, file)
	}
	return files
}

// The newest version up to which every push of a content ref is indexed, as the swap computed it; 0 where it is not
// known, which claims nothing.
func (self *SearchSyncSnapshot) IndexedThrough(contentRefId Id) uint64 {
	for _, content := range self.manifest.Content {
		if content.RefId == contentRefId {
			return content.IndexedThrough
		}
	}
	return 0
}

// The version table over the snapshot's runs, nil for an index with none.
func (self *SearchSyncSnapshot) Versions() *SearchVersionSnapshot {
	return self.versions
}

// The ring of (version, chain) pairs the rounds replayed, oldest first: 7.2.6's pin check.
func (self *SearchSyncSnapshot) Pins() []SearchSyncPinPair {
	return slices.Clone(self.manifest.Pins)
}

// A channel closed once an erasure, a CUT or a drop ended the snapshot, or the engine closed: a search reading it
// ends.
func (self *SearchSyncSnapshot) Ended() <-chan struct{} {
	return self.ended
}

// Releases what the snapshot holds; files and runs nothing else names then go. Safe to call again.
func (self *SearchSyncSnapshot) Release() {
	self.end()
}

// Ends and releases the snapshot once.
func (self *SearchSyncSnapshot) end() {
	self.once.Do(func() {
		close(self.ended)
		if self.versions != nil {
			self.versions.Close()
		}
		engine := self.sync
		engine.stateLock.Lock()
		delete(self.ref.open, self)
		engine.stateLock.Unlock()
		// files this snapshot alone held go now, unless a round is retiring them itself
		if self.ref.roundLock.TryLock() {
			defer self.ref.roundLock.Unlock()
			if err := engine.retire(self.ref); err != nil {
				engine.args.log.Warningf("[search]files a released snapshot held were not retired: %s", err)
			}
		}
	})
}
