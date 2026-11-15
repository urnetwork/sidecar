//go:build !ios_extension

// The sync round's fetch (DESIGN-DETAILS 7.2.7's step 4; §11.14's fetch and verify rows; FI-23; SEARCH-M10-19): the
// wanted files a round does not hold or have staged, whole, never a range, up to the evs client's read limits a read
// (64 paths, 32 MiB), in an order that reads nothing but sync state:
//
//	latest set  the settings and the erasure set, then a/m, then buckets newest first, in each its manifest, its
//	            shards, then its slots and large entries by path
//	all set     where it is kept or "search more" asks for it: all's shards, youngest (highest n) first
//
// Each file: SearchCache.PutRecord, which keeps it only once its plaintext's SHA-256 is its entry version's
// content_sha256, with its wrapped object key and file id beside it (QD-838); then indexValidateFile over the kept copy; then staged in the plan with its two times, the window or
// coverage its header names, a small file's plaintext, and the version-table run built from it while its keys are at
// hand. A file that fails either check is listed bad at that version, its copy dropped, and raises index_malformed
// {repo, ref, path, signer}; a file in a newer format is listed newer and raises nothing. A read answering collected
// for a wanted version ends the fetch: the round starts again at step 1, on the new head (7.1's C).
//
// The plan is written after each read, so a round killed between reads resumes with what it staged.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Which set a wanted file is in, and its place in the fetch order (lower first).
func searchFetchRank(parsed indexPath) (latest bool, rank int) {
	switch parsed.kind {
	case indexPathSettings, indexPathErasureSet:
		return true, 0
	case indexPathAllManifest:
		return true, 1
	case indexPathBucketManifest:
		return true, 2
	case indexPathBucketShard:
		return true, 3
	case indexPathSlot, indexPathLargeEntry:
		return true, 4
	case indexPathAllShard:
		return false, 5
	}
	// the lock: a roll-up's, which no reader needs
	return false, -1
}

// Whether a manifest or plan already has path at version: held, bad or newer there.
func searchHas(manifest *SearchManifest, plan *SearchSyncPlan, path string, version uint64) bool {
	if manifest != nil {
		if file := manifest.file(path); file != nil && file.Version == version {
			return true
		}
	}
	return plan.staged(path, version) != nil
}

// The files of plan.Wanted under its root in the set asked (latest or all), in fetch order, that the round does not
// have yet.
func searchFetchOrder(manifest *SearchManifest, plan *SearchSyncPlan, companion bool, latest bool) []*SearchSyncWanted {
	type ordered struct {
		wanted *SearchSyncWanted
		parsed indexPath
		rank   int
	}
	rootNumber := uint32(0)
	if parsed, ok := indexParsePath(plan.Root+"/settings", companion); ok {
		rootNumber = parsed.rootNumber
	}
	files := []ordered{}
	for _, wanted := range plan.Wanted {
		parsed, ok := indexParsePath(wanted.Path, companion)
		if !ok || (parsed.kind != indexPathErasureSet && parsed.rootNumber != rootNumber) {
			continue
		}
		inLatest, rank := searchFetchRank(parsed)
		if rank < 0 || inLatest != latest || searchHas(manifest, plan, wanted.Path, wanted.Version) {
			continue
		}
		files = append(files, ordered{wanted: wanted, parsed: parsed, rank: rank})
	}
	slices.SortFunc(files, func(a ordered, b ordered) int {
		if a.rank <= 1 || b.rank <= 1 {
			return cmp.Or(cmp.Compare(a.rank, b.rank), strings.Compare(a.wanted.Path, b.wanted.Path))
		}
		if a.parsed.kind == indexPathAllShard {
			return cmp.Compare(b.parsed.shardNumber, a.parsed.shardNumber)
		}
		// buckets newest first, then manifest, shards, slots and large entries by path
		return cmp.Or(
			cmp.Compare(b.parsed.bucketStartDay, a.parsed.bucketStartDay),
			cmp.Compare(a.rank, b.rank),
			strings.Compare(a.wanted.Path, b.wanted.Path),
		)
	})
	wanted := make([]*SearchSyncWanted, 0, len(files))
	for _, file := range files {
		wanted = append(wanted, file.wanted)
	}
	return wanted
}

// Cuts files into reads of at most the engine's paths and bytes; a file past the bytes alone goes in a read of its own.
func (self *SearchSync) fetchBatches(files []*SearchSyncWanted) [][]*SearchSyncWanted {
	batches := [][]*SearchSyncWanted{}
	batch := []*SearchSyncWanted{}
	byteCount := int64(0)
	for _, file := range files {
		if 0 < len(batch) && (self.args.readPathCount <= len(batch) || self.args.readByteCount < byteCount+file.ByteCount) {
			batches = append(batches, batch)
			batch, byteCount = []*SearchSyncWanted{}, 0
		}
		batch = append(batch, file)
		byteCount += file.ByteCount
	}
	if 0 < len(batch) {
		batches = append(batches, batch)
	}
	return batches
}

// Step 4 over the latest set, or the all set: true where a read answered collected.
func (self *SearchSync) fetch(ctx context.Context, ref *searchSyncRef, manifest *SearchManifest, plan *SearchSyncPlan, latest bool) (bool, error) {
	files := searchFetchOrder(manifest, plan, ref.args.companion, latest)
	if len(files) == 0 {
		return false, nil
	}
	if ref.args.nonWriter {
		// §16.10's receipts: the reader deposits one naming the round's wanted files before it opens the first
		if ref.args.depositReceipt == nil {
			return false, errSearchSyncReceipt
		}
		if err := ref.args.depositReceipt(ctx, files); err != nil {
			return false, fmt.Errorf("%w: %w", errSearchSyncReceipt, err)
		}
	}
	for _, batch := range self.fetchBatches(files) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		asked := make([]*indexFileVersion, 0, len(batch))
		for _, wanted := range batch {
			asked = append(asked, &indexFileVersion{
				path: wanted.Path, version: wanted.Version, commitVersion: wanted.CommitVersion,
				contentSha256: wanted.ContentSha256, byteCount: int(wanted.ByteCount), signerSidecarId: wanted.Signer,
			})
		}
		fetched, err := ref.args.source.Fetch(ctx, asked)
		if err != nil {
			return false, err
		}
		byPath := map[string]*searchSyncFetched{}
		for _, answer := range fetched {
			if answer != nil && answer.file != nil {
				byPath[answer.file.path] = answer
			}
		}
		collected := false
		for _, wanted := range batch {
			answer := byPath[wanted.Path]
			switch {
			case answer == nil:
				return false, fmt.Errorf("%w: a read left a wanted file out", ErrSearchCacheArgs)
			case answer.collected:
				collected = true
				continue
			case answer.file.version != wanted.Version:
				return false, fmt.Errorf("%w: a read answered another version", ErrSearchCacheArgs)
			}
			staged, err := self.stage(ctx, ref, plan, wanted, answer.record)
			if err != nil {
				return false, err
			}
			plan.Staged = append(plan.Staged, staged)
			testHookBarrier("search.sync.fetched", searchSyncBarrierKey(ref.args.repoId, ref.args.refId))
		}
		if err := self.storePlan(ctx, ref, plan); err != nil {
			return false, err
		}
		if collected {
			// a wanted version was replaced: every file is brought to the new head together, never one alone
			return true, nil
		}
	}
	return false, nil
}

// Keeps, checks and stages one fetched file: held with its run, bad, or newer.
func (self *SearchSync) stage(ctx context.Context, ref *searchSyncRef, plan *SearchSyncPlan, wanted *SearchSyncWanted, record *SearchCacheRecord) (*SearchManifestFile, error) {
	cache, repoId, refId := self.args.cache, ref.args.repoId, ref.args.refId
	parsed, _ := indexParsePath(wanted.Path, ref.args.companion)
	staged := &SearchManifestFile{
		Path: wanted.Path, Version: wanted.Version, ContentSha256: wanted.ContentSha256, ByteCount: wanted.ByteCount,
		Partition: wanted.Partition, Signer: wanted.Signer,
	}
	key := SearchCacheKey{RepoId: repoId, RefId: refId, Path: wanted.Path, Version: wanted.Version}
	bad := func() (*SearchManifestFile, error) {
		staged.State = SearchManifestBad
		if err := cache.Remove(key); err != nil {
			return nil, err
		}
		self.raiseMalformed(ref, wanted.Path, wanted.Signer)
		return staged, nil
	}
	if record == nil {
		return nil, fmt.Errorf("%w: a read answered no record", ErrSearchCacheArgs)
	}
	// the record is kept as this round's listing names it, whatever the source said of it
	kept := *record
	kept.Key, kept.RefVersion, kept.ContentSha256, kept.Partition = key, plan.Target.Version, wanted.ContentSha256, wanted.Partition
	if err := cache.PutRecord(ctx, &kept); err != nil {
		if errors.Is(err, ErrSearchCacheContent) {
			return bad()
		}
		return nil, err
	}
	frames, err := cache.OpenRecord(key)
	if err != nil {
		return nil, err
	}
	source := frames.frameSource(kept.Header, kept.ObjectKey, kept.FileId)
	validated, err := indexValidateFile(parsed, source, wanted.ContentSha256[:], self.args.format)
	switch {
	case errors.Is(err, errIndexNewerFormat):
		staged.State = SearchManifestNewer
		if err := cache.Remove(key); err != nil {
			return nil, err
		}
		return staged, nil
	case isIndexMalformed(err):
		return bad()
	case err != nil:
		return nil, err
	}
	staged.State = SearchManifestHeld
	file := SearchVersionFile{Path: wanted.Path, Version: wanted.Version}
	switch parsed.kind {
	case indexPathSlot, indexPathLargeEntry:
		slot := validated.slot
		staged.WindowDays = slot.header.BucketDays
		for _, row := range slot.header.Coverage {
			refId, err := IdFromBytes(row.RefId)
			if err != nil {
				return bad()
			}
			staged.Coverage = append(staged.Coverage, &SearchManifestFileCoverage{RefId: refId, Version: row.Version, Horizon: row.Horizon})
		}
		for _, entry := range slot.entries {
			staged.observe(entry.timeSeconds)
		}
		if 0 < len(slot.entries) {
			staged.Run, err = ref.table.Merge(ctx, SearchVersionSlot{Kind: SearchVersionOthers, StartDay: parsed.bucketStartDay}, []SearchVersionSource{searchVersionEntriesSource(slot.entries, file)})
			if err != nil {
				return nil, err
			}
		}
	case indexPathBucketShard, indexPathAllShard:
		reader, err := indexOpenShardWithLayout(source, ref.args.companion, validated.shardLayout)
		if err != nil {
			return nil, err
		}
		slot := SearchVersionSlot{Kind: SearchVersionAll}
		if parsed.kind == indexPathBucketShard {
			slot = SearchVersionSlot{Kind: SearchVersionShards, StartDay: parsed.bucketStartDay}
			staged.WindowDays = reader.layout.header.BucketDays
		}
		if err := staged.observeShard(reader); err != nil {
			if isIndexMalformed(err) {
				return bad()
			}
			return nil, err
		}
		if 0 < reader.documentCount() || 0 < reader.layout.header.Tombstones {
			staged.Run, err = ref.table.Merge(ctx, slot, []SearchVersionSource{&searchVersionShardSource{reader: reader, file: file}})
			if err != nil {
				if isIndexMalformed(err) {
					return bad()
				}
				return nil, err
			}
		}
	default:
		// a small file: kept whole beside the manifest, which a snapshot reads with no record keys
		small := make([]byte, source.indexLength())
		if err := indexNewFrameCursor(source).read(0, small); err != nil {
			return nil, err
		}
		staged.Small = small
		if manifest, ok := validated.message.(interface{ GetDays() uint32 }); ok && parsed.kind == indexPathBucketManifest {
			staged.WindowDays = manifest.GetDays()
		}
	}
	return staged, nil
}

// Takes one row or entry time, in seconds, into the file's two times.
func (self *SearchManifestFile) observe(timeSeconds uint64) {
	timeMs := int64(timeSeconds) * 1000
	if self.TimeMinMs == 0 || timeMs < self.TimeMinMs {
		self.TimeMinMs = timeMs
	}
	if self.TimeMaxMs < timeMs {
		self.TimeMaxMs = timeMs
	}
}

// Takes every document's and tombstone's time of a shard into the file's two times, so a deletion sorts where its push
// does (7.7's trap).
func (self *SearchManifestFile) observeShard(reader *indexShardReader) error {
	for docId := range reader.documentCount() {
		document, err := reader.document(uint32(docId))
		if err != nil {
			return err
		}
		self.observe(document.timeSeconds)
	}
	input := &searchVersionShardInput{reader: reader}
	if err := input.readTombstones(); err != nil {
		return err
	}
	for _, tombstone := range input.tombstones {
		self.observe(tombstone.timeSeconds)
	}
	return nil
}
