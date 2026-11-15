//go:build !ios_extension

// The sync round's swaps and retirement (DESIGN-DETAILS 7.2.7's steps 5 to 7, its all row and its retained cases;
// §11.14's swap and retained rows; D-EVS-51; FI-18; SEARCH-M10-19).
//
//	swap latest  once every latest-set file the target lists is held, staged or bad at its version: the version
//	             table's runs of every slot that changed, then the manifest at the target, then the ref's version.
//	             A bucket that rolled in (pin, T]: with all absent its files go; with all held and the bucket's copy
//	             the roll-up's input it joins rolled[] and is retained (SearchCache.RetainBucket); with all held and
//	             not, it joins rolled[] and its files go. A listing knows no input, so it retains nothing: its
//	             roll-ups, read from a/m, are one entry. All is behind the pin from here until the all swap
//	swap all     once all's shards as the target lists them are held or staged and the latest set is at the target:
//	             all's run, then the manifest with all's pin the target and rolled[] empty; the retained buckets go,
//	             through SearchCache.ApplyRolledThrough, once no open snapshot holds them
//	retire       files and runs no manifest, plan or open snapshot names go
//	usable       all is searched only while held and either at the snapshot's pin, or every roll-up between bridged
//	             by a bucket still in the cache's retained list, computed when a snapshot is taken: an ERASE or an
//	             executed drop (DropRetained), RetainFactor windows (SweepRetained) or eviction ends the bridge, and
//	             a search of the cache then reads the buckets alone (7.1's B)
//
// The manifest is written after the version table and before any file is retired, so a kill anywhere leaves a
// manifest whose runs and files exist.

package sidecar

import (
	"context"
	"fmt"
	"slices"
)

// The latest and all files a plan's target lists under its root and the erasure set.
func searchPlanSets(plan *SearchSyncPlan, companion bool) ([]*SearchSyncWanted, []*SearchSyncWanted) {
	rootNumber := uint32(0)
	if parsed, ok := indexParsePath(plan.Root+"/settings", companion); ok {
		rootNumber = parsed.rootNumber
	}
	latest, all := []*SearchSyncWanted{}, []*SearchSyncWanted{}
	for _, wanted := range plan.Wanted {
		parsed, ok := indexParsePath(wanted.Path, companion)
		if !ok || (parsed.kind != indexPathErasureSet && parsed.rootNumber != rootNumber) {
			continue
		}
		inLatest, rank := searchFetchRank(parsed)
		switch {
		case rank < 0:
		case inLatest:
			latest = append(latest, wanted)
		default:
			all = append(all, wanted)
		}
	}
	return latest, all
}

// The round's copy of a wanted file: staged, or held by the manifest at that version; nil for neither.
func searchHad(manifest *SearchManifest, plan *SearchSyncPlan, wanted *SearchSyncWanted) *SearchManifestFile {
	if staged := plan.staged(wanted.Path, wanted.Version); staged != nil {
		return staged
	}
	if manifest != nil {
		if file := manifest.file(wanted.Path); file != nil && file.Version == wanted.Version {
			return file
		}
	}
	return nil
}

// The run of one slot over inputs: none for no input, the one input's own run, the old manifest's run where its
// inputs are these, else a merge of them.
func (self *SearchSync) slotRun(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest, slot SearchVersionSlot, inputs []SearchVersionRunId) (*SearchManifestRun, error) {
	slices.Sort(inputs)
	inputs = slices.Compact(inputs)
	switch len(inputs) {
	case 0:
		return nil, nil
	case 1:
		return &SearchManifestRun{Slot: slot, RunId: inputs[0], Inputs: inputs}, nil
	}
	if manifest != nil {
		for _, run := range manifest.Runs {
			if run.Slot == slot && slices.Equal(run.Inputs, inputs) {
				return run, nil
			}
		}
	}
	sources := make([]SearchVersionSource, 0, len(inputs))
	for _, input := range inputs {
		sources = append(sources, &searchVersionRunSource{table: ref.table, runId: input})
	}
	runId, err := ref.table.Merge(ctx, slot, sources)
	if err != nil {
		return nil, err
	}
	return &SearchManifestRun{Slot: slot, RunId: runId, Inputs: inputs}, nil
}

// The erased run from the erasure set's documents, each masked at and below its listed version (§11.14's epoch row);
// nil where the set lists none or does not read.
func (self *SearchSync) erasedRun(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest, erasureSet *SearchManifestFile) (*SearchManifestRun, error) {
	if erasureSet == nil || erasureSet.State != SearchManifestHeld || erasureSet.Small == nil {
		return nil, nil
	}
	slot := SearchVersionSlot{Kind: SearchVersionErased}
	// the set's own (path, version), so an unchanged set keeps its run
	marker := SearchVersionRunId(erasureSet.Version)
	if manifest != nil {
		for _, run := range manifest.Runs {
			if run.Slot == slot && slices.Equal(run.Inputs, []SearchVersionRunId{marker}) {
				return run, nil
			}
		}
	}
	decoded, err := indexDecodeErasureSet(erasureSet.Small, self.args.format)
	if err != nil {
		return nil, nil
	}
	newest := map[[indexIdByteCount]byte]uint64{}
	for _, erasure := range decoded.Erasures {
		for _, erased := range erasure.Docs {
			key := [indexIdByteCount]byte(erased.DocKey)
			newest[key] = max(newest[key], erased.Version)
		}
	}
	if len(newest) == 0 {
		return nil, nil
	}
	records := make([]SearchVersionRecord, 0, len(newest))
	for key, version := range newest {
		records = append(records, SearchVersionRecord{Key: key, Version: version, File: SearchVersionFile{Path: erasureSet.Path, Version: erasureSet.Version}})
	}
	slices.SortFunc(records, func(a SearchVersionRecord, b SearchVersionRecord) int {
		return compareSearchVersionRecords(&a, &b)
	})
	runId, err := ref.table.Merge(ctx, slot, []SearchVersionSource{SearchVersionRecordsSource(records)})
	if err != nil {
		return nil, err
	}
	return &SearchManifestRun{Slot: slot, RunId: runId, Inputs: []SearchVersionRunId{marker}}, nil
}

// Step 5: the latest swap, once every latest-set file the target lists is held, staged or bad at its version.
// Answers the new manifest.
func (self *SearchSync) swapLatestStep(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest, plan *SearchSyncPlan) (*SearchManifest, error) {
	key := searchSyncBarrierKey(ref.args.repoId, ref.args.refId)
	latest, _ := searchPlanSets(plan, ref.args.companion)
	files := []*SearchManifestFile{}
	for _, wanted := range latest {
		file := searchHad(manifest, plan, wanted)
		if file == nil {
			return nil, fmt.Errorf("%w: a latest-set file was not fetched", ErrSearchCacheArgs)
		}
		files = append(files, file)
	}
	next, err := self.swapLatest(ctx, ref, manifest, plan, files)
	if err != nil {
		return nil, err
	}
	testHookBarrier("search.sync.tables", key)
	if err := self.args.cache.SetRefVersion(ref.args.repoId, ref.args.refId, plan.Target.Version); err != nil {
		return nil, err
	}
	if err := self.storeManifest(ctx, ref, next); err != nil {
		return nil, err
	}
	testHookBarrier("search.sync.swapped", key)
	if err := self.storeRemaining(ctx, ref, next, plan); err != nil {
		return nil, err
	}
	return next, nil
}

// Step 6: the all swap at the latest set's pin, once all's shards as the target lists them are held or staged; a
// round whose all set is not whole yet leaves all behind, and its staged shards wait in the plan.
func (self *SearchSync) swapAllStep(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest, plan *SearchSyncPlan) error {
	key := searchSyncBarrierKey(ref.args.repoId, ref.args.refId)
	if manifest.Pin.Version != plan.Target.Version {
		return nil
	}
	if manifest.All.Held && manifest.All.Pin.Version == manifest.Pin.Version && len(manifest.Rolled) == 0 {
		// all is at the pin already
		return nil
	}
	_, all := searchPlanSets(plan, ref.args.companion)
	allFiles := []*SearchManifestFile{}
	for _, wanted := range all {
		file := searchHad(manifest, plan, wanted)
		if file == nil {
			return nil
		}
		allFiles = append(allFiles, file)
	}
	swapped, err := self.swapAll(ctx, ref, manifest, allFiles)
	if err != nil {
		return err
	}
	testHookBarrier("search.sync.tables", key)
	if err := self.storeManifest(ctx, ref, swapped); err != nil {
		return err
	}
	testHookBarrier("search.sync.swapped", key)
	return self.storeRemaining(ctx, ref, swapped, plan)
}

// Keeps in the plan only what the manifest does not hold yet, all's shards waiting for the all swap, or removes it.
func (self *SearchSync) storeRemaining(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest, plan *SearchSyncPlan) error {
	remaining := &SearchSyncPlan{Root: plan.Root, Target: plan.Target, IndexEpoch: plan.IndexEpoch, By: plan.By, Wanted: plan.Wanted}
	for _, staged := range plan.Staged {
		if held := manifest.file(staged.Path); held == nil || held.Version != staged.Version {
			remaining.Staged = append(remaining.Staged, staged)
		}
	}
	plan.Staged = remaining.Staged
	if len(remaining.Staged) == 0 {
		return self.storePlan(ctx, ref, nil)
	}
	return self.storePlan(ctx, ref, remaining)
}

// The manifest of the latest swap: files the latest-set files at the target, retained buckets' and all's carried.
func (self *SearchSync) swapLatest(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest, plan *SearchSyncPlan, latest []*SearchManifestFile) (*SearchManifest, error) {
	companion := ref.args.companion
	next := &SearchManifest{
		Root: plan.Root, Pin: plan.Target, IndexEpoch: plan.IndexEpoch, Listing: plan.Wanted,
	}
	if manifest != nil {
		next.All = manifest.All
		next.Rolled = slices.Clone(manifest.Rolled)
		next.Pins = slices.Clone(manifest.Pins)
	}
	next.Pins = append(next.Pins, plan.Pins...)
	if count := self.args.settings.PinRingCount; count < len(next.Pins) {
		next.Pins = slices.Clone(next.Pins[len(next.Pins)-count:])
	}

	// the slots of the latest set, by bucket
	shardInputs := map[uint32][]SearchVersionRunId{}
	otherInputs := map[uint32][]SearchVersionRunId{}
	var erasureSet *SearchManifestFile
	listedBuckets := map[uint32]bool{}
	var allManifest *SearchManifestFile
	for _, file := range latest {
		parsed, _ := indexParsePath(file.Path, companion)
		next.Files = append(next.Files, file)
		switch parsed.kind {
		case indexPathErasureSet:
			erasureSet = file
		case indexPathAllManifest:
			allManifest = file
		case indexPathBucketShard:
			listedBuckets[parsed.bucketStartDay] = true
			if file.Run != 0 {
				shardInputs[parsed.bucketStartDay] = append(shardInputs[parsed.bucketStartDay], file.Run)
			}
		case indexPathSlot, indexPathLargeEntry:
			listedBuckets[parsed.bucketStartDay] = true
			if file.Run != 0 {
				otherInputs[parsed.bucketStartDay] = append(otherInputs[parsed.bucketStartDay], file.Run)
			}
		case indexPathBucketManifest:
			listedBuckets[parsed.bucketStartDay] = true
		}
	}
	for startDay := range listedBuckets {
		for _, slot := range []struct {
			kind   SearchVersionSlotKind
			inputs []SearchVersionRunId
		}{{SearchVersionShards, shardInputs[startDay]}, {SearchVersionOthers, otherInputs[startDay]}} {
			run, err := self.slotRun(ctx, ref, manifest, SearchVersionSlot{Kind: slot.kind, StartDay: startDay}, slot.inputs)
			if err != nil {
				return nil, err
			}
			if run != nil {
				next.Runs = append(next.Runs, run)
			}
		}
	}
	erased, err := self.erasedRun(ctx, ref, manifest, erasureSet)
	if err != nil {
		return nil, err
	}
	if erased != nil {
		next.Runs = append(next.Runs, erased)
	}

	held, err := self.args.cache.Ref(ref.args.repoId, ref.args.refId)
	if err != nil {
		return nil, err
	}
	retained := map[uint32]bool{}
	if held != nil {
		for _, bucket := range held.Retained {
			retained[bucket.StartDay] = true
		}
	}
	if manifest != nil {
		// the buckets that rolled in (pin, T]: 7.2.7's three cases
		now := self.args.clock.Now()
		for _, rolled := range plan.Rolled {
			if !manifest.All.Held {
				continue
			}
			next.Rolled = append(next.Rolled, &SearchManifestRolled{StartDay: rolled.StartDay, WindowDays: rolled.WindowDays, AtVersion: rolled.AtVersion})
			if !rolled.InputWhole || rolled.WindowDays == 0 {
				continue
			}
			if err := self.args.cache.RetainBucket(ref.args.repoId, ref.args.refId, rolled.StartDay, rolled.WindowDays, now); err != nil {
				return nil, err
			}
			retained[rolled.StartDay] = true
		}
		if plan.By == SearchSyncByListing && manifest.All.Held && allManifest != nil {
			// a listing's roll-ups: one entry past all's day, which no bucket bridges
			if day := searchRolledThroughDay(allManifest); manifest.All.RolledThroughDay < day {
				next.Rolled = append(next.Rolled, &SearchManifestRolled{StartDay: day, AtVersion: plan.Target.Version})
			}
		}
		// files carried: all's, and buckets the cache retains that the target no longer lists
		carried := map[uint32]bool{}
		for _, file := range manifest.Files {
			parsed, ok := indexParsePath(file.Path, companion)
			if !ok {
				continue
			}
			switch {
			case file.Partition.All:
				next.Files = append(next.Files, file)
			case parsed.kind == indexPathBucketManifest || parsed.kind == indexPathBucketShard || parsed.kind == indexPathSlot || parsed.kind == indexPathLargeEntry:
				if listedBuckets[parsed.bucketStartDay] || !retained[parsed.bucketStartDay] {
					continue
				}
				next.Files = append(next.Files, file)
				carried[parsed.bucketStartDay] = true
			}
		}
		for _, run := range manifest.Runs {
			switch run.Slot.Kind {
			case SearchVersionAll:
				next.Runs = append(next.Runs, run)
			case SearchVersionShards, SearchVersionOthers:
				if carried[run.Slot.StartDay] {
					next.Runs = append(next.Runs, run)
				}
			}
		}
	}
	next.Content, err = self.content(ctx, ref, next)
	if err != nil {
		return nil, err
	}
	return next, nil
}

// The all swap: all's shards at the target, its run, all's pin the target and rolled[] empty; retained buckets go once
// no snapshot is open on the ref.
func (self *SearchSync) swapAll(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest, allFiles []*SearchManifestFile) (*SearchManifest, error) {
	next := *manifest
	next.Files = []*SearchManifestFile{}
	next.Runs = []*SearchManifestRun{}
	inputs := []SearchVersionRunId{}
	for _, file := range allFiles {
		if file.Run != 0 {
			inputs = append(inputs, file.Run)
		}
	}
	run, err := self.slotRun(ctx, ref, manifest, SearchVersionSlot{Kind: SearchVersionAll}, inputs)
	if err != nil {
		return nil, err
	}
	rolledThroughDay := uint32(0)
	for _, file := range manifest.Files {
		parsed, _ := indexParsePath(file.Path, ref.args.companion)
		if parsed.kind == indexPathAllManifest {
			rolledThroughDay = searchRolledThroughDay(file)
		}
	}
	self.stateLock.Lock()
	snapshotsOpen := 0 < len(ref.open)
	self.stateLock.Unlock()
	dropRetained := !snapshotsOpen
	if dropRetained {
		if err := self.args.cache.ApplyRolledThrough(ref.args.repoId, ref.args.refId, rolledThroughDay); err != nil {
			return nil, err
		}
	}
	held, err := self.args.cache.Ref(ref.args.repoId, ref.args.refId)
	if err != nil {
		return nil, err
	}
	retained := map[uint32]bool{}
	if held != nil {
		for _, bucket := range held.Retained {
			retained[bucket.StartDay] = true
		}
	}
	listed := map[string]bool{}
	for _, wanted := range manifest.Listing {
		listed[wanted.Path] = true
	}
	keptBuckets := map[uint32]bool{}
	for _, file := range manifest.Files {
		if file.Partition.All {
			continue
		}
		if !listed[file.Path] {
			// a retained bucket's file: kept only while the cache retains it
			if !retained[file.Partition.StartDay] {
				continue
			}
			keptBuckets[file.Partition.StartDay] = true
		}
		next.Files = append(next.Files, file)
	}
	next.Files = append(next.Files, allFiles...)
	for _, run := range manifest.Runs {
		switch run.Slot.Kind {
		case SearchVersionAll:
		case SearchVersionShards, SearchVersionOthers:
			if !manifest.listsBucket(run.Slot.StartDay, ref.args.companion) && !keptBuckets[run.Slot.StartDay] {
				continue
			}
			next.Runs = append(next.Runs, run)
		default:
			next.Runs = append(next.Runs, run)
		}
	}
	if run != nil {
		next.Runs = append(next.Runs, run)
	}
	next.All = SearchManifestAll{Held: true, Pin: manifest.Pin, RolledThroughDay: rolledThroughDay}
	next.Rolled = nil
	return &next, nil
}

// Whether the manifest's listing holds a file of the bucket starting on startDay.
func (self *SearchManifest) listsBucket(startDay uint32, companion bool) bool {
	for _, wanted := range self.Listing {
		parsed, ok := indexParsePath(wanted.Path, companion)
		if !ok {
			continue
		}
		switch parsed.kind {
		case indexPathBucketManifest, indexPathBucketShard, indexPathSlot, indexPathLargeEntry:
			if parsed.bucketStartDay == startDay {
				return true
			}
		}
	}
	return false
}

// a/m's rolled_through_day, 0 where the file does not read.
func searchRolledThroughDay(allManifest *SearchManifestFile) uint32 {
	if allManifest.State != SearchManifestHeld || allManifest.Small == nil {
		return 0
	}
	decoded, err := indexDecodeManifest(allManifest.Small, true)
	if err != nil {
		return 0
	}
	return decoded.RolledThroughDay
}

// The coverage rows the latest set's heads carry, per content ref, and indexed_through where a reader is given.
func (self *SearchSync) content(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest) ([]*SearchManifestContent, error) {
	byRef := map[Id]*SearchManifestContent{}
	refIds := []Id{}
	for _, file := range manifest.Files {
		if file.State != SearchManifestHeld || len(file.Coverage) == 0 {
			continue
		}
		parsed, ok := indexParsePath(file.Path, ref.args.companion)
		if !ok {
			continue
		}
		for _, row := range file.Coverage {
			content := byRef[row.RefId]
			if content == nil {
				content = &SearchManifestContent{RefId: row.RefId}
				byRef[row.RefId] = content
				refIds = append(refIds, row.RefId)
			}
			content.Rows = append(content.Rows, &SearchManifestCoverage{Writer: Id(parsed.writerSidecarId), Version: row.Version, Horizon: row.Horizon})
		}
	}
	slices.SortFunc(refIds, func(a Id, b Id) int {
		return compareIndexKeys(a, b)
	})
	contents := make([]*SearchManifestContent, 0, len(refIds))
	for _, refId := range refIds {
		content := byRef[refId]
		if self.args.coverage != nil {
			indexedThrough, err := self.args.coverage(ctx, ref.args.repoId, refId, content.Rows)
			if err != nil {
				return nil, err
			}
			content.IndexedThrough = indexedThrough
		}
		contents = append(contents, content)
	}
	return contents, nil
}

// Whether all may be searched in a snapshot of manifest, with held the cache's record of the ref (7.2.7's all row):
// held, every shard still kept, and either at the manifest's pin or every roll-up between bridged by a retained
// bucket.
func searchAllUsable(manifest *SearchManifest, held *SearchCacheRef) bool {
	if !manifest.All.Held || held == nil {
		return false
	}
	kept := map[SearchCacheKey]bool{}
	for _, file := range held.Files {
		kept[file.Key] = true
	}
	for _, file := range manifest.Files {
		if file.Partition.All && file.State == SearchManifestHeld &&
			!kept[SearchCacheKey{RepoId: held.RepoId, RefId: held.RefId, Path: file.Path, Version: file.Version}] {
			// the cache's bound evicted all
			return false
		}
	}
	if manifest.All.Pin.Version == manifest.Pin.Version {
		return true
	}
	retained := map[uint32]bool{}
	for _, bucket := range held.Retained {
		retained[bucket.StartDay] = true
	}
	for _, rolled := range manifest.Rolled {
		if !retained[rolled.StartDay] {
			return false
		}
	}
	return true
}

// Step 7: removes every kept file and version run of the ref that no manifest, plan or open snapshot names.
func (self *SearchSync) retire(ref *searchSyncRef) error {
	repoId, refId := ref.args.repoId, ref.args.refId
	keepFiles := map[SearchCacheKey]bool{}
	keepRuns := []SearchVersionRunId{}
	name := func(manifest *SearchManifest) {
		if manifest == nil {
			return
		}
		for _, file := range manifest.Files {
			if file.State == SearchManifestHeld {
				keepFiles[SearchCacheKey{RepoId: repoId, RefId: refId, Path: file.Path, Version: file.Version}] = true
			}
			if file.Run != 0 {
				keepRuns = append(keepRuns, file.Run)
			}
		}
		for _, run := range manifest.Runs {
			keepRuns = append(keepRuns, run.RunId)
			keepRuns = append(keepRuns, run.Inputs...)
		}
	}
	self.stateLock.Lock()
	manifest, plan := ref.manifest, ref.plan
	name(manifest)
	if plan != nil {
		for _, staged := range plan.Staged {
			if staged.State == SearchManifestHeld {
				keepFiles[SearchCacheKey{RepoId: repoId, RefId: refId, Path: staged.Path, Version: staged.Version}] = true
			}
			if staged.Run != 0 {
				keepRuns = append(keepRuns, staged.Run)
			}
		}
	}
	for snapshot := range ref.open {
		name(snapshot.manifest)
	}
	table := ref.table
	self.stateLock.Unlock()
	held, err := self.args.cache.Ref(repoId, refId)
	if err != nil {
		return err
	}
	if held != nil {
		for _, file := range held.Files {
			if !keepFiles[file.Key] {
				if err := self.args.cache.Remove(file.Key); err != nil {
					return err
				}
			}
		}
	}
	if table != nil {
		return table.Retire(keepRuns)
	}
	return nil
}
