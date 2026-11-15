//go:build !ios_extension

// The cold "search more" (§16.10's cold contract; §18.4's metered and caps rows; D-EVS-50, D-MCP-20, FI-23, FS-110;
// DESIGN-DETAILS 7.7; SEARCH-M10-20): every all shard the device lacks, fetched whole through the sync engine's round
// (its step 4 over the all set, swapped at the latest set's pin by its step 6), youngest first in a/m's fixed order,
// whatever the query, and each searched as it lands and verifies.
//
//	order     the round's own: the latest set first, then all's shards by descending n; what is fetched and when is a
//	          function of the device's sync state alone, never of the query, so the times show nothing of where the
//	          matches lie (I-19), and nothing stops early when enough hits arrive (D-MCP-20)
//	progress  a report at once when the call starts, within Search.MoreFirstProgress, then at least every
//	          Search.MoreProgressInterval and at each shard: the bytes fetched of the missing total, the shards searched,
//	          and complete false; every byte the call reads, the latest set's included, is reported as metered bytes,
//	          which the reads debit from the transfer balance (owner decision 10)
//	arrival   each shard is handed to the engine (OnShard) the moment it is staged, before the next read: the engine's
//	          search of it is what §16.10 holds within 100 ms on a desktop and 300 ms on a phone or page Worker
//	complete  only once every missing shard is searched; a call's download stops at Search.MoreByteCount, partial,
//	          and a call with its cursor fetches on from the first shard it has not searched, in the same fixed order,
//	          never restarting it: the round's plan keeps every shard staged, and the cursor names those searched
//	metered   a call whose missing all passes Search.MeteredMoreByteCount on a metered link fetches nothing and reports
//	          waiting=metered with the bytes, until the host asks again with AllowMetered
//	caps      past Search.AllCacheByteCount each shard is searched as it lands and the youngest within the cap stay;
//	          the rest go once searched, so all is not swapped and stays on demand
//	stale     an unusable all (a bridge lost, 7.2.7) is fetched by the same round before the call answers, so phase 2
//	          searches it once usable; with nothing missing a call forces at most one head refresh a repo a
//	          Search.HeadRefreshInterval
//
// The query never reaches here: the engine's OnShard holds it. Not safe for concurrent use: one call a SearchMore.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// The call's download reached Search.MoreByteCount: partial, its cursor going on.
	errSearchMoreBudget = errors.New("search more: the call's download budget is spent")
	// A call built without what it runs on.
	errSearchMoreArgs = errors.New("search more without its sync, policy, settings or ref")
)

// One "search more" call's hold on the round it runs (the sync engine's moreRun).
type searchSyncMoreRun struct {
	// Search.MoreByteCount, and what the call read so far.
	budget int64
	used   int64
	// Each held or bad all shard the moment it is staged: true drops it once searched (past a cap).
	landedFunc func(ctx context.Context, file *SearchManifestFile) (bool, error)
	// Shards an earlier call of this cursor searched, by path and version, which this call does not fetch again.
	searched map[SearchVersionFile]bool
	// Each read's bytes as it goes.
	spentFunc func(byteCount int64)
}

// Whether a read of byteCount may go: the first always, so a call moves; then while the call stays within its budget.
func (self *searchSyncMoreRun) admit(byteCount int64) bool {
	return self.used == 0 || self.used+byteCount <= self.budget
}

// Counts a read that went.
func (self *searchSyncMoreRun) spent(byteCount int64) {
	self.used += byteCount
	if self.spentFunc != nil {
		self.spentFunc(byteCount)
	}
}

// One staged all shard: searched, and whether it goes past a cap.
func (self *searchSyncMoreRun) landed(ctx context.Context, file *SearchManifestFile) (bool, error) {
	if self.landedFunc == nil {
		return false, nil
	}
	return self.landedFunc(ctx, file)
}

// Whether an earlier call of this cursor searched wanted's shard already.
func (self *searchSyncMoreRun) searchedBefore(wanted *SearchSyncWanted) bool {
	return self.searched[SearchVersionFile{Path: wanted.Path, Version: wanted.Version}]
}

// The all shards a ref lacks, in fetch order, and the manifest they were judged against: from the round in progress,
// else the last manifest's listing. A ref never synced answers no manifest.
func (self *SearchSync) moreMissing(repoId Id, refId Id) ([]*SearchSyncWanted, *SearchManifest, error) {
	self.stateLock.Lock()
	ref := self.refs[[2]Id{repoId, refId}]
	closed := self.closed
	self.stateLock.Unlock()
	if closed {
		return nil, nil, ErrSearchSyncClosed
	}
	if ref == nil {
		return nil, nil, ErrSearchSyncUnfollowed
	}
	if err := self.load(ref); err != nil {
		return nil, nil, err
	}
	manifest, plan := self.state(ref)
	if manifest == nil && plan == nil {
		return nil, nil, nil
	}
	if plan == nil {
		plan = &SearchSyncPlan{Root: manifest.Root, Target: manifest.Pin, IndexEpoch: manifest.IndexEpoch, Wanted: manifest.Listing}
	}
	lacking, err := self.lackingKeys(ref)
	if err != nil {
		return nil, nil, err
	}
	return searchFetchOrder(manifest, plan, lacking, ref.args.companion, false), manifest, nil
}

// Whether a snapshot of the ref now would search its all: held, and bridged to the snapshot's pin (7.2.7's all row).
func (self *SearchSync) allUsable(repoId Id, refId Id) bool {
	snapshot, err := self.Snapshot(repoId, refId)
	if err != nil {
		return false
	}
	defer snapshot.Release()
	return snapshot.AllUsable()
}

// One round of a followed ref for a "search more" call: the all set kept, held to run.
func (self *SearchSync) runMore(ctx context.Context, repoId Id, refId Id, run *searchSyncMoreRun) error {
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
	return self.roundWithRun(ctx, ref, true, run)
}

// Where a partial call stopped: what an earlier call searched, which the next does not fetch again. Opaque, in memory
// with its search's cursor, never persisted.
type SearchMoreCursor struct {
	repoId   Id
	refId    Id
	searched map[SearchVersionFile]bool
}

// What a call has done, as its reports give it.
type SearchMoreProgress struct {
	// B, the bytes of the all shards missing when the call began, and those of them fetched so far.
	MissingByteCount int64
	FetchedByteCount int64
	// Every byte the call read, the latest set's included: §16.10's metered_bytes.
	MeteredByteCount int64
	// The missing shards, and those searched so far.
	ShardCount    int
	SearchedCount int
	// "metered" while the call waits on AllowMetered.
	Waiting string
	// Every missing shard is searched.
	Complete bool
	// The call's download reached Search.MoreByteCount: its cursor goes on.
	Partial bool
	// The report's time on the policy's clock.
	At time.Time
}

// What a call runs on.
type SearchMoreArgs struct {
	Sync     *SearchSync
	Policy   *SearchPolicy
	Settings *SidecarSearchSettings
	RepoId   Id
	RefId    Id
	// The host repeated the call past the metered wait (§5.4's SearchRequest.AllowMetered).
	AllowMetered bool
	// A partial call's cursor: this call fetches on from where it stopped. Nil starts.
	Cursor *SearchMoreCursor
	// Each all shard as it lands and verifies, staged in the cache: the engine searches it now (SEARCH-M10-26's).
	// Nil searches nothing.
	OnShard func(ctx context.Context, file *SearchManifestFile) error
	// Each progress report, the first at once. Nil reports nothing.
	OnProgress func(progress SearchMoreProgress)
	// Nil is real time.
	Clock Clock
}

// One "search more" call.
type SearchMore struct {
	args  SearchMoreArgs
	clock Clock

	stateLock sync.Mutex
	progress  SearchMoreProgress
	cursor    *SearchMoreCursor
	// The all bytes kept so far against Search.AllCacheByteCount.
	keptAllBytes int64
}

// A call over args.
func NewSearchMore(args *SearchMoreArgs) (*SearchMore, error) {
	if args == nil || args.Sync == nil || args.Policy == nil || args.Settings == nil || args.RepoId == (Id{}) || args.RefId == (Id{}) {
		return nil, errSearchMoreArgs
	}
	if args.Settings.MoreByteCount <= 0 || args.Settings.MoreProgressInterval <= 0 || args.Settings.MoreFirstProgress <= 0 {
		return nil, fmt.Errorf("%w: the search more's settings", errInvalidSettings)
	}
	cursor := args.Cursor
	if cursor == nil || cursor.repoId != args.RepoId || cursor.refId != args.RefId {
		cursor = &SearchMoreCursor{repoId: args.RepoId, refId: args.RefId, searched: map[SearchVersionFile]bool{}}
	}
	return &SearchMore{args: *args, clock: clockOrReal(args.Clock), cursor: cursor}, nil
}

// The cursor a partial call leaves, which the next call of the same search takes.
func (self *SearchMore) Cursor() *SearchMoreCursor {
	return self.cursor
}

// The progress as it stands.
func (self *SearchMore) current() SearchMoreProgress {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.progress
}

// Reports the progress now.
func (self *SearchMore) report() {
	self.stateLock.Lock()
	self.progress.At = self.clock.Now()
	progress := self.progress
	self.stateLock.Unlock()
	if self.args.OnProgress != nil {
		self.args.OnProgress(progress)
	}
}

// Sets the missing set's figures.
func (self *SearchMore) setMissing(missing []*SearchSyncWanted) {
	byteCount := int64(0)
	for _, wanted := range missing {
		byteCount += wanted.ByteCount
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.progress.MissingByteCount = byteCount
	self.progress.ShardCount = len(missing)
}

// Runs the call: see the file header. Answers its last report; an error stops it, what it staged kept for the next.
func (self *SearchMore) Run(ctx context.Context) (SearchMoreProgress, error) {
	args := self.args
	// the missing set is local state: judged, then reported at once, before anything slow (§16.10's first report)
	missing, manifest, err := args.Sync.moreMissing(args.RepoId, args.RefId)
	if err != nil {
		return self.current(), err
	}
	missing = self.unsearched(missing)
	self.setMissing(missing)
	self.report()
	if manifest == nil {
		// never synced: a round brings the latest set, and with it a/m's listing, before the missing set is judged
		if err := args.Sync.RunRound(ctx, args.RepoId, args.RefId, false); err != nil {
			return self.current(), err
		}
		if missing, manifest, err = args.Sync.moreMissing(args.RepoId, args.RefId); err != nil {
			return self.current(), err
		}
		missing = self.unsearched(missing)
		self.setMissing(missing)
		self.report()
	}
	if waiting := args.Policy.MoreWaiting(self.current().MissingByteCount, args.AllowMetered); waiting != "" {
		self.stateLock.Lock()
		self.progress.Waiting = waiting
		self.stateLock.Unlock()
		self.report()
		return self.current(), nil
	}
	if manifest != nil {
		for _, file := range manifest.Files {
			if file.Partition.All && file.State == SearchManifestHeld {
				self.keptAllBytes += file.ByteCount
			}
		}
	}
	if len(missing) == 0 && args.Sync.allUsable(args.RepoId, args.RefId) && !args.Policy.MayRefreshHead(args.RepoId) {
		// nothing missing, all usable and the head refreshed lately: complete from the cache; an unusable all is
		// fetched before the call answers, whatever the refresh interval (DESIGN-DETAILS 7.7)
		self.complete()
		return self.current(), nil
	}

	done := make(chan struct{})
	ticked := sync.WaitGroup{}
	ticked.Add(1)
	go func() {
		defer ticked.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			case <-self.clock.After(args.Settings.MoreProgressInterval):
				self.report()
			}
		}
	}()
	run := &searchSyncMoreRun{
		budget:     args.Settings.MoreByteCount,
		searched:   self.cursor.searched,
		landedFunc: self.landed,
		spentFunc: func(byteCount int64) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.progress.MeteredByteCount += byteCount
		},
	}
	err = args.Sync.runMore(ctx, args.RepoId, args.RefId, run)
	close(done)
	ticked.Wait()
	switch {
	case errors.Is(err, errSearchMoreBudget):
		self.stateLock.Lock()
		self.progress.Partial = true
		self.stateLock.Unlock()
		self.report()
		return self.current(), nil
	case err != nil:
		return self.current(), err
	}
	// what is left is a shard the round could not search: a newer head's, fetched by the next call
	left, _, err := args.Sync.moreMissing(args.RepoId, args.RefId)
	if err != nil {
		return self.current(), err
	}
	if len(self.unsearched(left)) == 0 {
		self.complete()
		return self.current(), nil
	}
	self.report()
	return self.current(), nil
}

// Missing shards less those this cursor searched already.
func (self *SearchMore) unsearched(missing []*SearchSyncWanted) []*SearchSyncWanted {
	left := []*SearchSyncWanted{}
	for _, wanted := range missing {
		if !self.cursor.searched[SearchVersionFile{Path: wanted.Path, Version: wanted.Version}] {
			left = append(left, wanted)
		}
	}
	return left
}

// Marks the call complete and reports it.
func (self *SearchMore) complete() {
	self.stateLock.Lock()
	self.progress.Complete = true
	self.progress.Partial = false
	self.stateLock.Unlock()
	self.report()
}

// One all shard staged by the round: searched by the engine where it holds, counted, reported; past the cap it goes
// once searched.
func (self *SearchMore) landed(ctx context.Context, file *SearchManifestFile) (bool, error) {
	if file.State == SearchManifestHeld && self.args.OnShard != nil {
		if err := self.args.OnShard(ctx, file); err != nil {
			return false, err
		}
	}
	allCap := self.args.Settings.AllCacheByteCount
	self.stateLock.Lock()
	self.cursor.searched[SearchVersionFile{Path: file.Path, Version: file.Version}] = true
	self.progress.FetchedByteCount += file.ByteCount
	self.progress.SearchedCount += 1
	drop := false
	if file.State == SearchManifestHeld {
		if 0 < allCap && allCap < self.keptAllBytes+file.ByteCount {
			drop = true
		} else {
			self.keptAllBytes += file.ByteCount
		}
	}
	self.stateLock.Unlock()
	self.report()
	return drop, nil
}
