// FI-20, roll-up (§22.8; §11.14's roll-up rows; I-EVS-11, I-EVS-12; DESIGN-DETAILS 1.2.5 and 1.7; owner decision 385;
// TEST-M10-02), over each index source's replay (fi_search.go). A push is a roll-up of a root when it writes or removes
// a file of that root's all (a/), a CLOSURE's or a DROP's rewrite in place aside:
//
//	one roll-up  each roll-up raises all's rolled_through_day, so no expired bucket is rolled by a second committed
//	             roll-up, and a bucket rolled once is never rolled again
//	leaving      a bucket, every file under its b/<S>/, leaves the index only in the roll-up whose rolled_through_day
//	             reaches its start, and in that push every file of it leaves
//	moved        the merge of its inputs: for each key of all and the rolled buckets, the newest entry c over them
//	             (an erasure's listed versions masked) goes on. A live c is all's row after the push, or, promoted, a
//	             newer bucket's shard's (owner decision 385), holding its row and every key of its postings, unless a
//	             newer bucket holds a newer entry of its key; a deleted c takes all's row away, and where a newer bucket
//	             holds an older entry of its key it is promoted there as a tombstone, so nothing older comes back. all
//	             holds nothing but those rows
//
// A rerun after a crash converging to that result is two runs' comparison of their files (SearchTestWorld.FileDigests),
// which a schedule makes; that searches merge an expired bucket until it rolls is FI-18's, by SearchOracle.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

var _ = RegisterInvariant(20, func(ctx context.Context, oracle *Oracle) error {
	return checkFi20(ctx, oracle)
})

func checkFi20(ctx context.Context, oracle *Oracle) error {
	errs := []error{}
	for _, replay := range searchReplaysOf(ctx, oracle) {
		if replay.readErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", replay.name, replay.readErr))
			continue
		}
		errs = append(errs, replay.fi20Findings...)
	}
	return errors.Join(errs...)
}

// A root's path prefix: .ur-index/i<n> on a file-mode ref, i<n> on ur/index.
func oracleIndexRootPrefix(path oracleIndexPath) string {
	prefix := fmt.Sprintf("i%d", path.root)
	if !path.companion {
		prefix = oracleIndexFileMode + prefix
	}
	return prefix
}

// Whether two full entries hold the same document: one row and every key of its postings.
func oracleIndexSameDocument(a *oracleIndexEntry, b *oracleIndexEntry) bool {
	if a.kind != b.kind || a.key != b.key || a.version != b.version || a.timeSeconds != b.timeSeconds || !slices.Equal(a.keys, b.keys) {
		return false
	}
	if a.row == nil || b.row == nil {
		return a.row == b.row
	}
	ra, rb := a.row, b.row
	return ra.docKind == rb.docKind && ra.flags == rb.flags && ra.size == rb.size && ra.chunk == rb.chunk && ra.trigrams == rb.trigrams &&
		ra.started == rb.started && ra.expires == rb.expires && bytes.Equal(ra.refId, rb.refId) && ra.locator == rb.locator && ra.fields == rb.fields
}

// The newest entry of each key over files, an erasure's listed versions masked.
func (self *searchReplay) newestOver(files []*oracleIndexFile) map[[16]byte]*oracleIndexEntry {
	newest := map[[16]byte]*oracleIndexEntry{}
	for _, file := range files {
		for _, entry := range file.keyedEntries() {
			if entry.version <= self.erased[entry.key] {
				continue
			}
			if current := newest[entry.key]; current == nil || searchNewer(entry, current) {
				newest[entry.key] = entry
			}
		}
	}
	return newest
}

// FI-20's clauses on one push: before is the head's files at its base, and the replay's files the head after it.
func (self *searchReplay) fi20Apply(push *SearchIndexPush, before map[string]*oracleIndexFile, written map[string]*oracleIndexFile) {
	settings := DefaultOracleIndexFormatSettings()
	rewrite := push.Kind == SearchIndexPushClosure || push.Kind == SearchIndexPushDrop
	fail := func(format string, a ...any) {
		self.fi20Findings = append(self.fi20Findings, fmt.Errorf("%s: ref version %d %s", self.name, push.RefVersion, fmt.Sprintf(format, a...)))
	}
	changed := slices.Concat(push.Removed, slices.Collect(maps.Keys(written)))
	roots := map[string]oracleIndexPath{}
	for _, path := range changed {
		if parsed, ok := oracleIndexParsePath(path, settings); ok && parsed.kind != oracleIndexPathErasureSet {
			roots[oracleIndexRootPrefix(parsed)] = parsed
		}
	}
	for _, prefix := range slices.Sorted(maps.Keys(roots)) {
		allTouched := slices.ContainsFunc(changed, func(path string) bool {
			parsed, ok := oracleIndexParsePath(path, settings)
			return ok && oracleIndexRootPrefix(parsed) == prefix &&
				(parsed.kind == oracleIndexPathAllManifest || parsed.kind == oracleIndexPathAllShard)
		})
		// a bucket is every file under b/<S>/, its manifest or not: a bucket only writers' heads hold has none yet
		bucketOf := func(path string) (uint32, bool) {
			parsed, ok := oracleIndexParsePath(path, settings)
			switch {
			case !ok || oracleIndexRootPrefix(parsed) != prefix:
				return 0, false
			case parsed.kind == oracleIndexPathBucketManifest, parsed.kind == oracleIndexPathBucketShard, parsed.kind == oracleIndexPathSlot, parsed.kind == oracleIndexPathLargeEntry:
				return parsed.bucket, true
			}
			return 0, false
		}
		bucketsBefore := map[uint32]bool{}
		for path := range before {
			if bucket, ok := bucketOf(path); ok {
				bucketsBefore[bucket] = true
			}
		}
		bucketsAfter := map[uint32]bool{}
		for path := range self.files {
			if bucket, ok := bucketOf(path); ok {
				bucketsAfter[bucket] = true
			}
		}
		removedBuckets := []uint32{}
		for bucket := range bucketsBefore {
			if !bucketsAfter[bucket] {
				removedBuckets = append(removedBuckets, bucket)
			}
		}
		slices.Sort(removedBuckets)
		if !allTouched && len(removedBuckets) == 0 {
			continue
		}
		if rewrite {
			if 0 < len(removedBuckets) {
				fail("is a rewrite in place that removes bucket %v", removedBuckets)
			}
			continue
		}
		rolledThrough := func(files map[string]*oracleIndexFile) (uint32, bool) {
			file := files[prefix+"/a/m"]
			if file == nil || file.manifest == nil {
				return 0, false
			}
			return file.manifest.RolledThroughDay, true
		}
		previousDay, previouslyRolled := rolledThrough(before)
		day, rolled := rolledThrough(self.files)
		if !rolled {
			fail("changes %s's all and leaves it no manifest", prefix)
			continue
		}
		if previouslyRolled && day <= previousDay {
			fail("rolls %s's all again through day %d, after a roll-up through day %d committed: a second roll-up", prefix, day, previousDay)
			continue
		}
		rolledBuckets := []uint32{}
		for bucket := range bucketsBefore {
			if bucket <= day && (!previouslyRolled || previousDay < bucket) {
				rolledBuckets = append(rolledBuckets, bucket)
			}
		}
		slices.Sort(rolledBuckets)
		for _, bucket := range removedBuckets {
			if !slices.Contains(rolledBuckets, bucket) {
				fail("removes bucket %d, which its roll-up through day %d does not reach", bucket, day)
			}
		}
		inputs := []*oracleIndexFile{}
		for path, file := range before {
			parsed, ok := oracleIndexParsePath(path, settings)
			if !ok || oracleIndexRootPrefix(parsed) != prefix || file == nil {
				continue
			}
			if parsed.kind == oracleIndexPathAllShard {
				inputs = append(inputs, file)
				continue
			}
			if slices.Contains(rolledBuckets, parsed.bucket) && strings.HasPrefix(path, fmt.Sprintf("%s/b/%d/", prefix, parsed.bucket)) {
				inputs = append(inputs, file)
				if _, ok := self.files[path]; ok {
					fail("keeps %s, a file of bucket %d, which it rolls", path, parsed.bucket)
				}
			}
		}
		for _, bucket := range rolledBuckets {
			if at, ok := self.rolled[bucket]; ok {
				fail("rolls bucket %d, which the roll-up at ref version %d rolled", bucket, at)
			}
			self.rolled[bucket] = push.RefVersion
		}
		allAfter := []*oracleIndexFile{}
		newerShards := []*oracleIndexFile{}
		newerFiles := []*oracleIndexFile{}
		for path, file := range self.files {
			parsed, ok := oracleIndexParsePath(path, settings)
			if !ok || oracleIndexRootPrefix(parsed) != prefix || file == nil {
				continue
			}
			switch parsed.kind {
			case oracleIndexPathAllShard:
				allAfter = append(allAfter, file)
			case oracleIndexPathBucketShard:
				newerShards = append(newerShards, file)
				newerFiles = append(newerFiles, file)
			case oracleIndexPathSlot, oracleIndexPathLargeEntry:
				newerFiles = append(newerFiles, file)
			}
		}
		carried := self.newestOver(inputs)
		allRows := self.newestOver(allAfter)
		newerNewest := self.newestOver(newerFiles)
		promoted := func(entry *oracleIndexEntry) bool {
			for _, shard := range newerShards {
				for _, held := range shard.keyedEntries() {
					if held.key == entry.key && (entry.live() && oracleIndexSameDocument(held, entry) || !entry.live() && !held.live() && entry.version <= held.version) {
						return true
					}
				}
			}
			return false
		}
		for _, key := range slices.SortedFunc(maps.Keys(carried), func(a [16]byte, b [16]byte) int { return bytes.Compare(a[:], b[:]) }) {
			entry := carried[key]
			row := allRows[key]
			newer := newerNewest[key]
			if entry.live() {
				switch {
				case row != nil && oracleIndexSameDocument(row, entry):
				case promoted(entry):
				case newer != nil && searchNewer(newer, entry):
				default:
					fail("leaves doc_key %x's live entry at %d, with its postings, in neither all nor a newer bucket", key, entry.version)
				}
				continue
			}
			if row != nil {
				fail("keeps all's row of doc_key %x at %d below its tombstone at %d", key, row.version, entry.version)
			}
			if newer != nil && newer.version < entry.version && !promoted(entry) {
				fail("drops doc_key %x's tombstone at %d above its older entry at %d in a newer bucket", key, entry.version, newer.version)
			}
		}
		for _, key := range slices.SortedFunc(maps.Keys(allRows), func(a [16]byte, b [16]byte) int { return bytes.Compare(a[:], b[:]) }) {
			row := allRows[key]
			if entry := carried[key]; entry == nil || !entry.live() || entry.version != row.version {
				fail("leaves all holding doc_key %x at %d, which is no newest entry of its inputs", key, row.version)
			}
		}
	}
}
