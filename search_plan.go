//go:build !ios_extension

// The search plan (§11.14's plan, retained, cjk and off rows; §16.10's phase rows; SEARCH-M10-22): per (repo, ref),
// which partitions a search reads and in what order, newest first: the current bucket, the previous one, any expired
// and retained buckets, then all's shards youngest first. Scope latest stops before all, and a since after all's newest
// time skips it, so a date range inside the buckets never needs all. Every bucket present is searched whatever its
// age, an expired one until its roll-up lands and a retained one until this device's all covers it, so search stays
// complete through a roll-up (R-EVS-22). The plan reads the index's state as the sync engine holds it, never the query
// beyond its dates, so what a search touches does not depend on what it asks (FI-23).
//
// A query is normalized under this build's tables; an index recording other ones is searched under these, missing
// only characters assigned between them, and the plan says so (§11.14's cjk row). One in a newer format, or written by
// a newer normalizer, reads status update, and one that is off or unbuilt reads off, for §11.14's off row to answer.

package sidecar

import (
	"cmp"
	"slices"
	"time"
)

// How far a search reaches (§5.4's SearchScope, which SEARCH-M10-26's types map onto this).
type searchPlanScope int

const (
	// The buckets and every all shard this device holds current: §5.4's SearchCached, the default.
	searchPlanCached searchPlanScope = iota
	// The buckets alone: §5.4's SearchLatest.
	searchPlanLatest
	// The buckets, then every all shard a/m names, held or not, those not held fetched by "search more": §5.4's
	// SearchAll.
	searchPlanAll
)

// The partition a plan step reads (§16.10's hit partition: current, previous, older, all).
type searchPartitionKind int

const (
	searchPartitionCurrent searchPartitionKind = iota + 1
	searchPartitionPrevious
	// An expired bucket, searched until its roll-up lands, or a retained one this device keeps until its all covers it.
	searchPartitionOlder
	searchPartitionAll
)

// What one (repo, ref)'s index offers a search on this device, as the snapshot it searches holds it.
type searchIndexHolding struct {
	repoId Id
	refId  Id
	// The tables its files record, IndexFileHeader's normalizer, unicode_version and text_module_version; a zero
	// normalizer where no file says, which reads as this build's.
	normalizer        uint32
	unicodeVersion    string
	textModuleVersion string
	// A file in a newer format.
	newerFormat bool
	// The index is off, or not built.
	off bool
	// The W a new bucket takes now.
	windowDays uint32
	// The buckets held, ascending: those at the snapshot's pin, and retained ones a roll-up dropped.
	buckets []*searchHeldBucket
	// The shards a/m names, and which this device holds current.
	allShards []*searchHeldShard
}

// One bucket a device holds.
type searchHeldBucket struct {
	window indexBucketWindow
	// Dropped by a roll-up, kept until this device's all covers it (§11.14's retained row).
	retained bool
}

// One all shard a/m names.
type searchHeldShard struct {
	n        uint32
	firstDay uint32
	lastDay  uint32
	// This device holds it current; a search reads one it lacks only through "search more".
	held bool
}

// One step of a ref's plan: a bucket, or an all shard.
type searchPlanStep struct {
	partition searchPartitionKind
	// Bucket steps.
	window   indexBucketWindow
	retained bool
	// All steps.
	shardNumber uint32
	held        bool
}

// How a ref reads to a search.
type searchRefStatus int

const (
	// Its partitions are searched.
	searchRefSearched searchRefStatus = iota + 1
	// A newer format or normalizer than this build's: status update, nothing searched.
	searchRefUpdate
	// Off or unbuilt: searched as §11.14's off row has it, without an index.
	searchRefOff
)

// One ref's plan.
type searchRefPlan struct {
	repoId Id
	refId  Id
	status searchRefStatus
	// The index records other tables than this build's: searched under these, and said so.
	otherTables bool
	steps       []*searchPlanStep
}

// What a plan reads.
type searchPlanArgs struct {
	holdings []*searchIndexHolding
	scope    searchPlanScope
	// Zero is unbounded.
	since time.Time
	// The reader's clock, which ages the buckets.
	nowMs int64
	// This build's tables.
	tables indexTables
}

// A search's plan, ref by ref in the order the holdings came.
type searchPlan struct {
	refs []*searchRefPlan
}

// Plans a search over the holdings.
func searchPlanFor(args *searchPlanArgs) *searchPlan {
	plan := &searchPlan{}
	for _, holding := range args.holdings {
		plan.refs = append(plan.refs, searchPlanRef(args, holding))
	}
	return plan
}

// One ref's plan.
func searchPlanRef(args *searchPlanArgs, holding *searchIndexHolding) *searchRefPlan {
	refPlan := &searchRefPlan{repoId: holding.repoId, refId: holding.refId, status: searchRefSearched}
	switch {
	case holding.off:
		refPlan.status = searchRefOff
		return refPlan
	case holding.newerFormat || indexNormalizerId < holding.normalizer || !args.tables.isNormalizerOne():
		refPlan.status = searchRefUpdate
		return refPlan
	}
	refPlan.otherTables = holding.normalizer != 0 &&
		(holding.unicodeVersion != args.tables.normVersion || holding.textModuleVersion != args.tables.textModuleVersion)

	// Buckets newest first, the retained after those still in the index; each aged at the reader's clock.
	present := []indexBucketWindow{}
	for _, bucket := range holding.buckets {
		if !bucket.retained {
			present = append(present, bucket.window)
		}
	}
	slices.SortFunc(present, func(a indexBucketWindow, b indexBucketWindow) int {
		return cmp.Compare(a.startDay, b.startDay)
	})
	ages := indexBucketAges(present, holding.windowDays, args.nowMs)
	ageOf := map[uint32]indexBucketAge{}
	for index, window := range present {
		ageOf[window.startDay] = ages[index]
	}
	buckets := slices.Clone(holding.buckets)
	slices.SortStableFunc(buckets, func(a *searchHeldBucket, b *searchHeldBucket) int {
		if a.retained != b.retained {
			if a.retained {
				return 1
			}
			return -1
		}
		return cmp.Compare(b.window.startDay, a.window.startDay)
	})
	for _, bucket := range buckets {
		step := &searchPlanStep{partition: searchPartitionOlder, window: bucket.window, retained: bucket.retained}
		if !bucket.retained {
			switch ageOf[bucket.window.startDay] {
			case indexBucketCurrent:
				step.partition = searchPartitionCurrent
			case indexBucketPrevious:
				step.partition = searchPartitionPrevious
			}
		}
		refPlan.steps = append(refPlan.steps, step)
	}

	if args.scope == searchPlanLatest || len(holding.allShards) == 0 {
		return refPlan
	}
	if !args.since.IsZero() && searchAllNewestEndMs(holding, present) <= args.since.UnixMilli() {
		return refPlan
	}
	shards := slices.Clone(holding.allShards)
	slices.SortFunc(shards, func(a *searchHeldShard, b *searchHeldShard) int {
		return cmp.Compare(b.n, a.n)
	})
	for _, shard := range shards {
		if args.scope == searchPlanCached && !shard.held {
			continue
		}
		refPlan.steps = append(refPlan.steps, &searchPlanStep{partition: searchPartitionAll, shardNumber: shard.n, held: shard.held})
	}
	return refPlan
}

// A bound past every entry time all holds, in ms. An entry rolled into all sat in a bucket older than every bucket
// still present, and an entry's day is never past the start of the bucket after its own (§11.14's entry row), so all's
// newest time is before the oldest present bucket's start; with none present, before the day after all's last.
func searchAllNewestEndMs(holding *searchIndexHolding, present []indexBucketWindow) int64 {
	if 0 < len(present) {
		return int64(present[0].startDay) * indexDayMs
	}
	end := uint32(0)
	for _, shard := range holding.allShards {
		end = max(end, shard.lastDay+1)
	}
	return int64(end) * indexDayMs
}

// What a view at a ref version offers a search, for a device holding the whole index: every bucket, and every all
// shard a/m names, held. Its tables are its slots' headers', where it has a slot.
func searchHoldingOf(view *indexView) *searchIndexHolding {
	holding := &searchIndexHolding{repoId: view.repoId, refId: view.refId, newerFormat: view.newerFormat}
	root := view.root(indexRootNumber)
	if root == nil {
		holding.off = true
		return holding
	}
	holding.off = root.off()
	holding.windowDays = root.windowDays(view.repoKind)
	for _, bucket := range root.buckets {
		holding.buckets = append(holding.buckets, &searchHeldBucket{window: bucket.window})
		for _, writer := range bucket.writers {
			for _, slot := range writer.slots {
				if holding.normalizer == 0 {
					holding.normalizer = slot.slot.header.Normalizer
					holding.unicodeVersion = slot.slot.header.UnicodeVersion
					holding.textModuleVersion = slot.slot.header.TextModuleVersion
				}
			}
		}
	}
	if root.allManifest != nil {
		for _, shard := range root.allManifest.Shards {
			holding.allShards = append(holding.allShards, &searchHeldShard{n: shard.N, firstDay: shard.FirstDay, lastDay: shard.LastDay, held: true})
		}
	}
	return holding
}
