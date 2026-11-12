//go:build !ios_extension

// The index schedule (§11.14's merges when, roll-up trigger and runner, coverage and devices rows; DESIGN-DETAILS 1.2.4
// to 1.2.6; owner decisions 150, 157, 177; SEARCH-M10-11): on each tick, which of a device's index refs it merges,
// rolls up and backfills, by what the device is.
//
//	merges     an indexer serving the repo for search merges every due bucket first; a desktop or the daemon merges
//	           them where no indexer serves the repo, and its own bucket where it is out of slots; a phone or wasm
//	           only where it is out of slots, or on Wi-Fi while charging (mayRun)
//	roll-ups   the oldest bucket expired at the push's signed time: an indexer serving the repo rolls it at once;
//	           where one exists, any writer committing to the ref a day past the expiry with no roll-up landed; with
//	           none, the first desktop or daemon, or phone that mayRun, committing to the ref after the expiry
//	backfills  an indexer serving the repo, else a desktop or the daemon where none serves it (SEARCH-M10-12's)
//
// A device learns that it committed from Committed, which its writer calls with each index push's signed time, so a
// roll-up rides a writer's own commit as §11.14's runner row has it. Every time is a signed time or this device's
// clock reading for one, and expiry is judged at it (QD-689's reading 1). Racing merges or roll-ups of two devices are
// safe, one committing and the other refused (FS-74, FS-75), so the roles only spare work. The merger and the roller
// fail closed on what they cannot read; the schedule reports each tick's outcomes and errors, and nothing in it holds
// a lock across a merge or roll-up. Safe for concurrent use.

package sidecar

import (
	"context"
	"sync"
	"time"
)

// The schedule's own times. The format's limits are IndexFormatSettings'.
type IndexerSearchSettings struct {
	// How often each ref is looked at: 1 min, a reading, §16.10's hint coalescing.
	TickInterval time.Duration
	// Where an indexer serves the repo for search, how long past a bucket's expiry another writer committing to the
	// ref waits before it rolls the bucket itself: 24 h (§11.14's runner row, "a day past the expiry").
	IndexerGrace time.Duration
}

// The schedule's defaults, a fresh value each call.
func DefaultIndexerSearchSettings() *IndexerSearchSettings {
	return &IndexerSearchSettings{TickInterval: time.Minute, IndexerGrace: 24 * time.Hour}
}

// What a device is to the index's upkeep (§11.14's devices row).
type indexSearchDevice int

const (
	// An indexer serving the repo for search: its IndexerSet names search at a scope covering the repo.
	indexSearchDeviceIndexer indexSearchDevice = iota + 1
	// A desktop or the daemon.
	indexSearchDeviceDesktop
	// A phone or the browser's wasm.
	indexSearchDevicePhone
)

// One index ref's backfill, SEARCH-M10-12's: a push still unindexed BackfillAge after its commit, indexed into this
// device's own head.
type indexBackfiller interface {
	Backfill(ctx context.Context) error
}

// What the schedule keeps of one index ref.
type indexScheduleRefArgs struct {
	merger *IndexMerger
	roller *IndexRoller
	device indexSearchDevice
	// This device's sidecar_id, whose own files decide whether it is out of slots.
	self Id
	// Whether an indexer other than this device serves the repo for search, as the config's IndexerSet says (TEAM-M10-01).
	// Nil is none.
	indexerServes func() bool
	// A phone's or wasm's leave to merge and roll up: on Wi-Fi while charging (SEARCH-M10-20's conditions). Nil never.
	mayRun func() bool
	// Nil until SEARCH-M10-12's backfill is given.
	backfill indexBackfiller
}

// One index ref under the schedule.
type indexScheduleRef struct {
	args indexScheduleRefArgs

	stateLock sync.Mutex
	// The newest signed time this device committed an index push to the ref at, 0 for none.
	lastCommitMs int64
}

// Records that this device committed an index push to the ref, signed at signedTimeMs.
func (self *indexScheduleRef) Committed(signedTimeMs int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lastCommitMs = max(self.lastCommitMs, signedTimeMs)
}

// The newest commit recorded.
func (self *indexScheduleRef) lastCommit() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.lastCommitMs
}

// Whether another indexer serves the ref's repo for search.
func (self *indexScheduleRef) indexerServes() bool {
	return self.args.indexerServes != nil && self.args.indexerServes()
}

// Whether a phone may run upkeep now.
func (self *indexScheduleRef) mayRun() bool {
	return self.args.mayRun != nil && self.args.mayRun()
}

// What one tick did for one ref.
type indexScheduleTick struct {
	ref    *indexScheduleRef
	merges []*indexMergeOutcome
	rollup *indexRollupOutcome
	// Each step's error, in the order they ran; a failed step does not stop the next.
	errs []error
}

// The device's index refs and their upkeep.
type indexSchedule struct {
	settings *IndexerSearchSettings
	clock    Clock

	stateLock sync.Mutex
	refs      []*indexScheduleRef
}

// A schedule on settings, nil taking the defaults, and clock, nil real time.
func indexNewSchedule(settings *IndexerSearchSettings, clock Clock) *indexSchedule {
	if settings == nil {
		settings = DefaultIndexerSearchSettings()
	}
	return &indexSchedule{settings: settings, clock: clockOrReal(clock)}
}

// Puts a ref under the schedule.
func (self *indexSchedule) add(args *indexScheduleRefArgs) *indexScheduleRef {
	ref := &indexScheduleRef{args: *args}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refs = append(self.refs, ref)
	return ref
}

// Ticks every TickInterval on the schedule's clock until ctx ends, handing each tick's outcomes to observe, which may
// be nil.
func (self *indexSchedule) Run(ctx context.Context, observe func(ticks []*indexScheduleTick)) {
	for {
		ticks := self.tick(ctx)
		if observe != nil {
			observe(ticks)
		}
		select {
		case <-ctx.Done():
			return
		case <-self.clock.After(self.settings.TickInterval):
		}
	}
}

// One pass over every ref: its due merges, then its roll-up, then its backfill.
func (self *indexSchedule) tick(ctx context.Context) []*indexScheduleTick {
	refs := func() []*indexScheduleRef {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return append([]*indexScheduleRef{}, self.refs...)
	}()
	ticks := []*indexScheduleTick{}
	for _, ref := range refs {
		ticks = append(ticks, self.tickRef(ctx, ref))
	}
	return ticks
}

// One ref's pass.
func (self *indexSchedule) tickRef(ctx context.Context, ref *indexScheduleRef) *indexScheduleTick {
	tick := &indexScheduleTick{ref: ref}
	view, err := ref.args.merger.loadView(ctx)
	if err != nil {
		tick.errs = append(tick.errs, err)
		return tick
	}
	root := view.writeRoot()
	now := self.clock.Now()
	for _, startDay := range indexMergeDueBuckets(view, root, now.UnixMilli()) {
		bucket := root.bucket(startDay)
		writer := bucket.writer(ref.args.self)
		mine := writer != nil && indexWriterOutOfSlots(bucket, writer, view.settings)
		merge := false
		switch ref.args.device {
		case indexSearchDeviceIndexer:
			merge = true
		case indexSearchDeviceDesktop:
			merge = mine || !ref.indexerServes()
		case indexSearchDevicePhone:
			merge = mine || ref.mayRun()
		}
		if !merge {
			continue
		}
		outcome, err := ref.args.merger.Merge(ctx, root.number, startDay)
		tick.merges = append(tick.merges, outcome)
		if err != nil {
			tick.errs = append(tick.errs, err)
		}
	}
	if expired := indexOldestExpired(view, root, now.UnixMilli()); expired != nil && ref.args.roller != nil && self.mayRollUp(view, root, expired, ref) {
		outcome, err := ref.args.roller.Roll(ctx, root.number)
		tick.rollup = outcome
		if err != nil {
			tick.errs = append(tick.errs, err)
		}
	}
	backfill := ref.args.device == indexSearchDeviceIndexer || ref.args.device == indexSearchDeviceDesktop && !ref.indexerServes()
	if ref.args.backfill != nil && backfill {
		if err := ref.args.backfill.Backfill(ctx); err != nil {
			tick.errs = append(tick.errs, err)
		}
	}
	return tick
}

// §11.14's runner row for this device and the expired bucket: an indexer serving the repo at once; where one exists,
// a writer that committed a day past the expiry; with none, a desktop, or a phone that may run, that committed after
// it.
func (self *indexSchedule) mayRollUp(view *indexView, root *indexViewRoot, expired *indexViewBucket, ref *indexScheduleRef) bool {
	if ref.args.device == indexSearchDeviceIndexer {
		return true
	}
	capable := ref.args.device == indexSearchDeviceDesktop || ref.mayRun()
	expiryMs := indexBucketExpiryMs(view, root, expired)
	if ref.indexerServes() {
		return capable && expiryMs+self.settings.IndexerGrace.Milliseconds() <= ref.lastCommit()
	}
	return capable && expiryMs <= ref.lastCommit()
}

// The first time, in ms, at which bucket is expired: the end of the window after its own, which starts where it ends
// and is the next bucket's when that one starts there, else W days long (§11.14's latest row).
func indexBucketExpiryMs(view *indexView, root *indexViewRoot, bucket *indexViewBucket) int64 {
	days := root.windowDays(view.repoKind)
	for _, held := range root.buckets {
		if held.window.startDay == bucket.window.endDay() {
			days = held.window.days
		}
	}
	return int64(bucket.window.endDay()+days) * indexDayMs
}
