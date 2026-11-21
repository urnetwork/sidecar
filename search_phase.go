//go:build !ios_extension

// A search's phases over the cache (§16.10's phase, merge, match and rank rows; §11.14's newest and plan rows; FI-21,
// FI-23, I-19; DESIGN-DETAILS 7.2.5 and 7.7; SEARCH-M10-26): one ref's snapshot opened for one search, its plan, and
// each partition read from the kept records through the wrapped object keys the cache keeps beside them (QD-838), so a
// search never reads evs.
//
//	phase 1  both latest buckets, an expired one until its roll-up lands, a retained one this device keeps until its
//	         all covers it, and the local layer, at once
//	phase 2  all, at once where the snapshot holds it usable (AllUsable); with "search more" (scope all) every shard
//	         it lacks fetched first, whole and in a/m's fixed order, each searched as it lands (search_more.go)
//	merge    per doc key the highest version over every partition searched and the local layer counts, probed in the
//	         snapshot's version table one candidate at a time, the erasure set's documents masked at or below their
//	         listed version (search_mask.go)
//
// Every phase-2 hit is older than every phase-1 hit, since all's rows were rolled up from buckets older than every
// bucket held, so a returned page is never revised. A kept record is opened with RK_g of its generation asked of gkm,
// one 64 KiB frame decrypted at a time, and its read closes when the search ends.
//
// Beside the engine's own pages, DESIGN-DETAILS 7.7 asks two things of it for an indexer's serving (SEARCH-M10-32):
// searchCandidatesAfter, the candidates of a set of snapshots after a watermark in 7.2.5's order, at most K and the one
// after, each its document's current entry; and searchVerifyCandidate, one candidate checked against a host's text.
//
// Not safe for concurrent use: one search's.

package sidecar

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The snapshot's version table as the mask and the match read it: a doc key's record, and a ref id's ref tombstone,
// one lookup a key, through the table's page cache. A key is a doc key or a ref id, never both (16 random bytes each).
func searchProbeOf(versions *SearchVersionSnapshot) searchVersionProbe {
	if versions == nil {
		return nil
	}
	return func(key [indexIdByteCount]byte) (searchVersionRecord, error) {
		refId := Id(key)
		probed, err := versions.Probe(key, &refId)
		if err != nil {
			return searchVersionRecord{}, err
		}
		record := searchVersionRecord{found: probed.Found, version: probed.Version, tombstone: probed.Tombstone, erasedThrough: probed.ErasedThrough}
		if !probed.Found && 0 < probed.RefTombstoneVersion {
			record = searchVersionRecord{found: true, version: probed.RefTombstoneVersion, tombstone: true}
		}
		return record, nil
	}
}

// One ref opened for one search: its snapshot, what its plan reads, and the reads it holds open.
type searchOpenedRef struct {
	engine  *SearchEngine
	scoped  *searchScopedRef
	repoId  Id
	refId   Id
	snap    *SearchSyncSnapshot
	holding *searchIndexHolding
	plan    *searchRefPlan
	source  *searchRankSource
	probe   searchVersionProbe
	local   *SearchLocalLayer
	// Kept records opened for this search, closed at its end.
	reads []*SearchCacheRecordRead
	// Where RK_g comes from in place of the engine's GkmClient: an indexer's serving, which asks gkm for nothing
	// (search_remote_corpus.go). Nil asks the engine's.
	keys GkmClient
	// The repo's searchable_days as its masks read it, taken at the search's open (searchSearchableSinceSeconds), so
	// the shards "search more" lands are masked by the same cut as the rest; 0 masks none.
	searchableSinceSeconds uint64
}

// What a snapshot offers a plan: its buckets, the retained ones among them, and all's shards held where all is usable.
func searchHoldingOfSnapshot(snapshot *SearchSyncSnapshot, repoId Id, refId Id, retained []SearchCacheRetained) *searchIndexHolding {
	manifest := snapshot.manifest
	companion := searchRootCompanion(manifest.Root)
	holding := &searchIndexHolding{repoId: repoId, refId: refId}
	retainedDays := map[uint32]bool{}
	for _, bucket := range retained {
		retainedDays[bucket.StartDay] = true
	}
	windows := map[uint32]uint32{}
	held := map[string]bool{}
	for _, file := range manifest.Files {
		parsed, ok := indexParsePath(file.Path, companion)
		if !ok {
			continue
		}
		if file.State == SearchManifestNewer {
			holding.newerFormat = true
		}
		if file.State != SearchManifestHeld {
			continue
		}
		held[file.Path] = true
		switch parsed.kind {
		case indexPathSettings:
			if settings, err := indexDecodeSettings(file.Small); err == nil {
				holding.off = settings.Off
				holding.windowDays = settings.WindowDays
			}
		case indexPathBucketManifest, indexPathBucketShard, indexPathSlot, indexPathLargeEntry:
			if file.WindowDays != 0 {
				windows[parsed.bucketStartDay] = file.WindowDays
			} else if _, ok := windows[parsed.bucketStartDay]; !ok {
				windows[parsed.bucketStartDay] = 0
			}
		}
	}
	if holding.windowDays == 0 {
		holding.windowDays = indexDefaultWindowDays
	}
	for startDay, days := range windows {
		if days == 0 {
			days = holding.windowDays
		}
		holding.buckets = append(holding.buckets, &searchHeldBucket{window: indexBucketWindow{startDay: startDay, days: days}, retained: retainedDays[startDay]})
	}
	slices.SortFunc(holding.buckets, func(a *searchHeldBucket, b *searchHeldBucket) int {
		return cmp.Compare(a.window.startDay, b.window.startDay)
	})
	paths := indexNewPaths(companion, indexRootNumber)
	for _, file := range manifest.Files {
		parsed, ok := indexParsePath(file.Path, companion)
		if !ok || parsed.kind != indexPathAllManifest || file.State != SearchManifestHeld {
			continue
		}
		allManifest, err := indexDecodeManifest(file.Small, true)
		if err != nil {
			continue
		}
		for _, shard := range allManifest.Shards {
			holding.allShards = append(holding.allShards, &searchHeldShard{
				n: shard.N, firstDay: shard.FirstDay, lastDay: shard.LastDay,
				held: snapshot.AllUsable() && held[paths.allShard(shard.N)],
			})
		}
	}
	return holding
}

// The registered fields of a repo's class: §16.8's for record logs, §16.11's for the directory, none for files and
// mail.
func searchRegistryOf(kind protocol.RepoKind) *IndexFieldRegistry {
	switch {
	case kind == protocol.RepoKind_REPO_KIND_DIRECTORY:
		return indexDirectoryFieldRegistry()
	case EvsRepoKindRecordClass(kind):
		return indexRecordFieldRegistry()
	}
	return nil
}

// Opens one kept file for reading: RK_g of its generation asked of gkm.
func (self *searchOpenedRef) openRead(ctx context.Context, file *SearchManifestFile) (*SearchCacheRecordRead, error) {
	key := SearchCacheKey{RepoId: self.repoId, RefId: self.refId, Path: file.Path, Version: file.Version}
	keys := self.keys
	if keys == nil {
		keys = self.engine.args.Gkm
	}
	read, err := self.engine.args.Cache.OpenRecordRead(ctx, key, keys)
	if err != nil {
		return nil, err
	}
	self.reads = append(self.reads, read)
	return read, nil
}

// A kept shard as the match reads it, frames decrypted as its lists are asked for.
func (self *searchOpenedRef) shardSource(ctx context.Context, file *SearchManifestFile, n uint32) (*searchShardSource, error) {
	read, err := self.openRead(ctx, file)
	if err != nil {
		return nil, err
	}
	reader, err := indexOpenShard(read, self.source.companion)
	if err != nil {
		return nil, err
	}
	return &searchShardSource{n: n, reader: reader}, nil
}

// A kept slot or large entry, read whole (at most a large entry's 1 MiB) and decoded.
func (self *searchOpenedRef) slotOf(ctx context.Context, file *SearchManifestFile) (*indexSlot, error) {
	read, err := self.openRead(ctx, file)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, read.indexLength())
	if err := indexNewFrameCursor(read).read(0, plaintext); err != nil {
		return nil, err
	}
	read.Close()
	return indexDecodeSlot(plaintext, file.ContentSha256[:], self.source.companion, self.engine.format)
}

// One bucket's partition: its shards, every writer's slots and large entries with each writer's head and what its
// manifest's watermark absorbed.
func (self *searchOpenedRef) bucketSource(ctx context.Context, step *searchPlanStep) (*searchPartitionSource, error) {
	companion := self.source.companion
	source := &searchPartitionSource{partition: step.partition}
	absorbed := map[Id]uint32{}
	type slotFile struct {
		slot *indexSlot
		file *SearchManifestFile
		path indexPath
	}
	slots := []*slotFile{}
	for _, file := range self.snap.Files() {
		parsed, ok := indexParsePath(file.Path, companion)
		if !ok || file.Partition.All || parsed.bucketStartDay != step.window.startDay {
			continue
		}
		switch parsed.kind {
		case indexPathBucketManifest:
			manifest, err := indexDecodeManifest(file.Small, false)
			if err != nil {
				continue
			}
			for _, watermark := range manifest.Absorbed {
				if writer, err := IdFromBytes(watermark.WriterSidecarId); err == nil {
					absorbed[writer] = watermark.Seq
				}
			}
		case indexPathBucketShard:
			shard, err := self.shardSource(ctx, file, parsed.shardNumber)
			if err != nil {
				return nil, err
			}
			source.shards = append(source.shards, shard)
		case indexPathSlot, indexPathLargeEntry:
			slot, err := self.slotOf(ctx, file)
			if err != nil {
				return nil, err
			}
			slots = append(slots, &slotFile{slot: slot, file: file, path: parsed})
		}
	}
	heads := map[Id]uint32{}
	for _, held := range slots {
		writer := Id(held.path.writerSidecarId)
		if held.path.kind == indexPathSlot && heads[writer] < held.slot.header.Seq {
			heads[writer] = held.slot.header.Seq
		}
	}
	for _, held := range slots {
		writer := Id(held.path.writerSidecarId)
		seq := held.slot.header.Seq
		head := held.path.kind == indexPathSlot && heads[writer] == seq
		source.slots = append(source.slots, &searchSlotSource{
			slot: held.slot, writer: writer, seq: seq, absorbed: !head && seq <= absorbed[writer],
			path: held.file.Path, signer: held.file.Signer,
		})
		if self.holding.normalizer == 0 {
			self.holding.normalizer = held.slot.header.Normalizer
			self.holding.unicodeVersion = held.slot.header.UnicodeVersion
			self.holding.textModuleVersion = held.slot.header.TextModuleVersion
		}
	}
	slices.SortFunc(source.shards, func(a *searchShardSource, b *searchShardSource) int { return cmp.Compare(a.n, b.n) })
	return source, nil
}

// One all shard's partition.
func (self *searchOpenedRef) allSource(ctx context.Context, n uint32) (*searchPartitionSource, error) {
	path := indexNewPaths(self.source.companion, indexRootNumber).allShard(n)
	for _, file := range self.snap.Files() {
		if file.Path != path {
			continue
		}
		shard, err := self.shardSource(ctx, file, n)
		if err != nil {
			return nil, err
		}
		return &searchPartitionSource{partition: searchPartitionAll, shards: []*searchShardSource{shard}}, nil
	}
	return nil, nil
}

// A staged all shard that "search more" handed over as it landed, held in the cache but in no snapshot yet.
func (self *searchOpenedRef) landedSource(ctx context.Context, file *SearchManifestFile) (*searchPartitionSource, error) {
	parsed, ok := indexParsePath(file.Path, self.source.companion)
	if !ok || parsed.kind != indexPathAllShard {
		return nil, nil
	}
	shard, err := self.shardSource(ctx, file, parsed.shardNumber)
	if err != nil {
		return nil, err
	}
	return &searchPartitionSource{partition: searchPartitionAll, shards: []*searchShardSource{shard}}, nil
}

// Matches one partition for the query, as a ranker input of the search's step.
func (self *searchOpenedRef) match(query *SearchQuery, source *searchPartitionSource, step int) (*searchRankInput, error) {
	result, err := searchMatch(&searchMatchArgs{
		query:             query,
		source:            source,
		maxCandidateCount: self.engine.args.Settings.TooBroadCandidateCount,
	})
	if err != nil {
		return nil, err
	}
	return &searchRankInput{source: self.source, partition: source.partition, step: step, result: result}, nil
}

// One partition a phase searched, kept for its near hits: the corrected query is matched in it as the query was.
type searchNearInput struct {
	ref    *searchOpenedRef
	source *searchPartitionSource
	step   int
}

// Phase 1's inputs: every bucket step of the plan, newest first, and the local layer; and each partition as its near
// hits are matched.
func (self *searchOpenedRef) phaseOne(ctx context.Context, query *SearchQuery, step *int) ([]*searchRankInput, []*searchNearInput, error) {
	inputs := []*searchRankInput{}
	near := []*searchNearInput{}
	add := func(source *searchPartitionSource) error {
		input, err := self.match(query, source, *step)
		if err != nil {
			return err
		}
		near = append(near, &searchNearInput{ref: self, source: source, step: *step})
		*step += 1
		inputs = append(inputs, input)
		return nil
	}
	for _, planStep := range self.plan.steps {
		if planStep.partition == searchPartitionAll {
			continue
		}
		source, err := self.bucketSource(ctx, planStep)
		if err != nil {
			return nil, nil, err
		}
		if err := add(source); err != nil {
			return nil, nil, err
		}
	}
	if self.local != nil {
		source, err := self.local.partition()
		if err != nil {
			return nil, nil, err
		}
		if source != nil {
			if err := add(source); err != nil {
				return nil, nil, err
			}
		}
	}
	return inputs, near, nil
}

// Phase 2's inputs where all is usable: each held all shard the plan names, youngest first.
func (self *searchOpenedRef) phaseTwo(ctx context.Context, query *SearchQuery, step *int) ([]*searchRankInput, error) {
	inputs := []*searchRankInput{}
	for _, planStep := range self.plan.steps {
		if planStep.partition != searchPartitionAll || !planStep.held {
			continue
		}
		source, err := self.allSource(ctx, planStep.shardNumber)
		if err != nil {
			return nil, err
		}
		if source == nil {
			continue
		}
		input, err := self.match(query, source, *step)
		if err != nil {
			return nil, err
		}
		*step += 1
		inputs = append(inputs, input)
	}
	return inputs, nil
}

// Ends the search's hold: its reads closed, its snapshot released.
func (self *searchOpenedRef) close() {
	for _, read := range self.reads {
		read.Close()
	}
	self.reads = nil
	if self.snap != nil {
		self.snap.Release()
	}
}

// One ref's coverage as the search holds it (§16.10's coverage row).
func (self *searchOpenedRef) coverage() SearchRepoCoverage {
	coverage := SearchRepoCoverage{RepoId: self.repoId, RefId: self.refId, State: "searched", All: SearchAllAbsent}
	if self.snap == nil {
		return coverage
	}
	coverage.PinVersion = self.snap.Pin().Version
	coverage.IndexedThrough = self.snap.IndexedThrough(self.refId)
	if fromMs := self.snap.LatestFromMs(); 0 < fromMs {
		coverage.LatestFrom = time.UnixMilli(fromMs).UTC()
	}
	coverage.AllTotal = len(self.holding.allShards)
	switch {
	case self.snap.AllUsable() && 0 < len(self.holding.allShards):
		coverage.All = SearchAllCurrent
		coverage.AllSearched = coverage.AllTotal
	case self.snap.manifest.All.Held:
		coverage.All = SearchAllStale
	}
	return coverage
}

// One candidate in DESIGN-DETAILS 7.2.5's order: newest first by time, then the repo's place in the request, then
// doc_key ascending.
type searchWatermark struct {
	timeMs    int64
	repoIndex uint16
	docKey    [indexIdByteCount]byte
}

// Whether a sits before b in the candidate order: newer, or at one time an earlier repo, or a lower doc_key. The zero
// watermark is before every candidate.
func searchWatermarkBefore(a searchWatermark, b searchWatermark) bool {
	if a == (searchWatermark{}) {
		return b != (searchWatermark{})
	}
	if a.timeMs != b.timeMs {
		return a.timeMs > b.timeMs
	}
	if a.repoIndex != b.repoIndex {
		return a.repoIndex < b.repoIndex
	}
	return compareIndexKeys(a.docKey, b.docKey) < 0
}

// A candidate as the order holds it: its place, and the ranked candidate it is.
type searchOrderedCandidate struct {
	place     searchWatermark
	candidate *searchRankCandidate
	row       *indexRow
}

// SEARCH-M10-32's iterator (DESIGN-DETAILS 7.7, 7.2.5's page): up to k candidates of the inputs after watermark, in
// the candidate order, each its document's current entry (masked as a search masks it) and inside the time filters,
// and the one after them, which names where the order goes on (nil where none is left). inputs are matched
// partitions whose sources carry each repo's place.
func searchCandidatesAfter(inputs []*searchRankInput, repoIndex func(source *searchRankSource) uint16, watermark searchWatermark, k int) ([]*searchOrderedCandidate, *searchOrderedCandidate, error) {
	ordered := []*searchOrderedCandidate{}
	for _, input := range inputs {
		for _, candidate := range input.result.candidates {
			ranked := &searchRankCandidate{source: input.source, candidate: candidate, step: input.step, partition: input.partition}
			if candidate.entry != nil {
				ranked.key, ranked.version, ranked.timeSeconds = candidate.entry.key, candidate.entry.version, candidate.entry.timeSeconds
			} else {
				key, version, timeSeconds, err := searchShardHeader(candidate.shard.reader, candidate.docId)
				if err != nil {
					return nil, nil, err
				}
				ranked.key, ranked.version, ranked.timeSeconds = key, version, timeSeconds
			}
			place := searchWatermark{timeMs: int64(ranked.timeSeconds) * 1000, repoIndex: repoIndex(input.source), docKey: ranked.key}
			if !searchWatermarkBefore(watermark, place) {
				continue
			}
			if !input.source.confirmer.filters.timeHolds(ranked.timeSeconds) {
				continue
			}
			ordered = append(ordered, &searchOrderedCandidate{place: place, candidate: ranked})
		}
	}
	slices.SortStableFunc(ordered, func(a *searchOrderedCandidate, b *searchOrderedCandidate) int {
		switch {
		case searchWatermarkBefore(a.place, b.place):
			return -1
		case searchWatermarkBefore(b.place, a.place):
			return 1
		}
		return cmp.Compare(b.candidate.version, a.candidate.version)
	})
	current := []*searchOrderedCandidate{}
	seen := map[searchSeenKey]bool{}
	for _, ordered := range ordered {
		candidate := ordered.candidate
		seenKey := searchSeenKey{repoId: candidate.source.repoId, key: candidate.key}
		if seen[seenKey] {
			continue
		}
		row, err := candidate.row()
		if err != nil {
			return nil, nil, err
		}
		verdict, err := candidate.source.mask.judge(&searchMaskCandidate{
			key: candidate.key, version: candidate.version, timeSeconds: candidate.timeSeconds, row: row,
			local: candidate.partition == searchPartitionLocal,
		})
		if err != nil {
			return nil, nil, err
		}
		if verdict != searchMaskCurrent {
			continue
		}
		seen[seenKey] = true
		ordered.row = row
		current = append(current, ordered)
		if k < len(current) {
			return current[:k], current[k], nil
		}
	}
	return current, nil, nil
}

// SEARCH-M10-32's verification (DESIGN-DETAILS 7.7): one candidate checked against the host's text view as far as it
// holds it: verified or rejected where it holds the version's text, else confirmed by its display fields or possible.
func searchVerifyCandidate(ctx context.Context, candidate *searchOrderedCandidate) (*searchConfirmation, error) {
	source := candidate.candidate.source
	row := candidate.row
	if row == nil {
		var err error
		if row, err = candidate.candidate.row(); err != nil {
			return nil, err
		}
	}
	refId := source.refId
	if source.companion {
		var err error
		if refId, err = IdFromBytes(row.refId); err != nil {
			return nil, err
		}
	}
	return source.confirmer.confirm(ctx, &searchConfirmCandidate{refId: refId, version: candidate.candidate.version, row: row})
}

// Matches a partition "search more" landed, which the search's snapshot holds no run of: a key the snapshot's table
// does not hold is judged by the landed shards themselves, whose row of it is all's one row of the key and older than
// every bucket entry the table holds (§11.14's newest row), the erasure set's masks still the table's.
func (self *searchOpenedRef) matchLanded(query *SearchQuery, source *searchPartitionSource, step int) (*searchRankInput, error) {
	base := self.probe
	probe := func(key [indexIdByteCount]byte) (searchVersionRecord, error) {
		record, err := base(key)
		if err != nil || record.found {
			return record, err
		}
		for _, shard := range source.shards {
			version, ok, err := searchShardVersionOf(shard.reader, key)
			if err != nil {
				return record, err
			}
			if ok {
				record.found, record.version = true, max(record.version, version)
			}
		}
		return record, nil
	}
	var localNewest searchLocalNewestFunc
	if self.local != nil {
		localNewest = self.local.newest
	}
	mask, err := newSearchMask(&searchMaskArgs{
		probe: probe, companion: self.source.companion, refId: self.refId, local: localNewest,
		searchableSinceSeconds: self.searchableSinceSeconds,
	})
	if err != nil {
		return nil, err
	}
	rankSource := &searchRankSource{repoId: self.repoId, refId: self.refId, companion: self.source.companion, mask: mask, confirmer: self.source.confirmer}
	result, err := searchMatch(&searchMatchArgs{
		query:             query,
		source:            source,
		maxCandidateCount: self.engine.args.Settings.TooBroadCandidateCount,
	})
	if err != nil {
		return nil, err
	}
	return &searchRankInput{source: rankSource, partition: searchPartitionAll, step: step, result: result}, nil
}

// A shard's version of key, found by its doc table, which sorts by doc_key: one doc table read a step.
func searchShardVersionOf(reader *indexShardReader, key [indexIdByteCount]byte) (uint64, bool, error) {
	low, high := 0, reader.documentCount()
	for low < high {
		middle := (low + high) / 2
		held, version, _, err := searchShardHeader(reader, uint32(middle))
		if err != nil {
			return 0, false, err
		}
		order := compareIndexKeys(held, key)
		switch {
		case order == 0:
			return version, true, nil
		case order < 0:
			low = middle + 1
		default:
			high = middle
		}
	}
	return 0, false, nil
}
