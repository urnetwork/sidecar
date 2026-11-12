//go:build !ios_extension

// Roll-ups (§11.14's Roll-up block as DESIGN-DETAILS 1.2.5 rewrites it; D-EVS-47; R4; I-EVS-11, I-EVS-12; QD-686,
// QD-689; SEARCH-M10-11): the push that moves an expired bucket S into the all partition and removes it, a function of
// S whole, every newer bucket, all, the erasure set, the runner's pad key and tables, and its signed time, so a rerun
// writes the same plaintext and a reproducer checks it.
//
// carried is each key's winner as a merge picks it over S's shards and every unabsorbed file of S, heads included,
// and each ref's newest ref tombstone, the erasure set's documents left out. Then per key, with n the newest entry of it
// in the newer buckets (heads, sealed slots, unabsorbed large entries and shards, tombstones counting) and a all's row:
//
//	n below carried        promote: carried goes into the shards of the newest bucket holding an entry of the key,
//	                       which keeps it until that bucket rolls (R4); a promoted tombstone still takes a
//	else, a tombstone      a goes when it is below; the tombstone goes
//	else                   the newer of carried and a is all's row
//
// and per ref tombstone r of S, all's rows of its ref below r go, and r is promoted to the newest newer bucket holding
// an entry of that ref below r, else it goes. Nothing is removed from a newer bucket: promotion is a merge of that
// bucket with the promoted entries as extra and nothing absorbed, so its manifest is replaced (or created) and fences
// it against every merge of it. all is laid out as a merge lays out a bucket, and holds no tombstone and one version a
// key (I-EVS-11); no all row is newer than the newest bucket entry of its key (I4).
//
// Coverage: per content ref a coverage row of S's names, I_R is indexed_through at the base (QD-209's rule), and
// unless a slot outside S carries a horizon row for it at or above I_R, the runner's own head in the bucket of its
// push takes {R, I_R, horizon true}, so what S's rows said outlives S (QD-689's reading 13). The push removes every
// file the listing holds under b/<S>/, and its runner frees the lock in it (evs_index_rollup_runner.go).
//
// Memory: this draft holds S, the newer buckets' key-to-version runs and all's shards decoded in RAM, where DESIGN-
// DETAILS 1.4 asks an app host for §5.9's version table or a sorted run in storage (QD-641).

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

// One bucket a roll-up reads, its shards decoded in its order.
type indexRollupBucket struct {
	bucket *indexViewBucket
	shards []*indexShard
}

// What one roll-up reads, all of it at the head after its lock committed.
type indexRollupArgs struct {
	view *indexView
	root *indexViewRoot
	// S whole, and every file the listing holds under b/<S>/, which the push removes.
	expired      *indexRollupBucket
	expiredFiles []*indexFileVersion
	// Every bucket newer than S, ascending.
	newer []*indexRollupBucket
	// all's shards decoded, in root.allShards' order.
	allShards []*indexShard
	// The runner, whose head takes the carried coverage, and its push's signed time.
	runner       Id
	signedTimeMs int64
	padKey       *indexPadKey
	tables       indexTables
	// I_R at the base for a content ref, by QD-209's rule (SEARCH-M10-12's coverage reading). Nil, or false for a ref,
	// carries the highest horizon row S's slots hold for it, a bound below I_R, so a reader may count fewer pushes
	// indexed than it could, never more.
	indexedThrough func(refId []byte) (uint64, bool)
}

// What a roll-up writes: one push's files and removals, beside the lock its runner frees.
type indexRollupResult struct {
	// In path order.
	files    []*indexPushFile
	removals []*indexPushRemoval
	// Diffs of S that did not compose, alarmed against their slots' signers.
	malformed []*indexMalformedDiff
	// The entries promoted, by the start day of the bucket that took them.
	promoted    map[uint32][]*indexEntry
	allManifest *protocol.IndexManifest
	// The horizon rows the runner's head took.
	carriedCoverage []*protocol.IndexCoverage
}

// The newest entry of one key in the newer buckets: its version, and the newest bucket, by index in args.newer,
// holding any entry of it.
type indexRollupNewest struct {
	version      uint64
	newestBucket int
}

// The newest entries of every key in the newer buckets, and per ref, per newer bucket, the lowest version of an entry
// of that ref there: what promotion asks of them.
type indexRollupNewer struct {
	keys map[[indexIdByteCount]byte]*indexRollupNewest
	// ref_id, then bucket index, then the lowest version of a row of the ref or of a ref tombstone of it.
	refs map[[indexIdByteCount]byte]map[int]uint64
}

// Reads every newer bucket's entries that count: shards, heads, sealed slots and unabsorbed large entries.
func indexRollupNewerEntries(newer []*indexRollupBucket) *indexRollupNewer {
	entries := &indexRollupNewer{keys: map[[indexIdByteCount]byte]*indexRollupNewest{}, refs: map[[indexIdByteCount]byte]map[int]uint64{}}
	visit := func(bucketIndex int, kind indexEntryKind, key [indexIdByteCount]byte, version uint64, row *indexRow) {
		refKey, hasRef := key, kind == indexEntryRefTombstone
		if kind != indexEntryRefTombstone {
			newest := entries.keys[key]
			if newest == nil {
				newest = &indexRollupNewest{version: version, newestBucket: bucketIndex}
				entries.keys[key] = newest
			}
			newest.version = max(newest.version, version)
			newest.newestBucket = max(newest.newestBucket, bucketIndex)
			if row != nil && len(row.refId) == indexIdByteCount {
				refKey, hasRef = [indexIdByteCount]byte(row.refId), true
			}
		}
		if !hasRef {
			return
		}
		lowest := entries.refs[refKey]
		if lowest == nil {
			lowest = map[int]uint64{}
			entries.refs[refKey] = lowest
		}
		if held, ok := lowest[bucketIndex]; !ok || version < held {
			lowest[bucketIndex] = version
		}
	}
	for bucketIndex, newerBucket := range newer {
		for _, shard := range newerBucket.shards {
			for _, document := range shard.documents {
				visit(bucketIndex, indexEntryFull, document.key, document.version, document.row)
			}
			for _, tombstone := range shard.tombstones {
				visit(bucketIndex, tombstone.kind, tombstone.key, tombstone.version, nil)
			}
		}
		for _, writer := range newerBucket.bucket.writers {
			for _, file := range writer.unabsorbed(newerBucket.bucket.absorbedSeq(writer.sidecarId)) {
				for _, entry := range file.slot.entries {
					visit(bucketIndex, entry.kind, entry.key, entry.version, entry.row)
				}
			}
		}
	}
	return entries
}

// The candidate as an entry a merge takes as extra.
func (self *indexMergeCandidate) entry() *indexEntry {
	return &indexEntry{kind: self.kind, key: self.key, version: self.version, timeSeconds: self.timeSeconds, row: self.row, keys: self.keys}
}

// 1.2.5's roll-up of args.expired: steps 3 to 6 but the lock, as one push's files and removals.
func indexRollup(ctx context.Context, args *indexRollupArgs) (*indexRollupResult, error) {
	view, root := args.view, args.root
	expired := args.expired
	carried, malformed, err := indexMergeCandidates(expired.bucket, expired.shards, nil, true, true, view.erased, map[Id]uint32{})
	if err != nil {
		return nil, err
	}
	newer := indexRollupNewerEntries(args.newer)

	allRows := map[[indexIdByteCount]byte]*indexShardDocument{}
	for _, shard := range args.allShards {
		for _, document := range shard.documents {
			allRows[document.key] = document
		}
	}
	removed := map[*indexShardDocument]bool{}
	appended := []*indexLayoutEntry{}
	promoted := map[int][]*indexEntry{}

	keys := make([][indexIdByteCount]byte, 0, len(carried.documents))
	for key := range carried.documents {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareIndexKeys)
	for _, key := range keys {
		winner := carried.documents[key]
		newest := newer.keys[key]
		all := allRows[key]
		switch {
		case newest != nil && newest.version < winner.version:
			promoted[newest.newestBucket] = append(promoted[newest.newestBucket], winner.entry())
			if winner.kind != indexEntryFull && all != nil {
				removed[all] = true
			}
		case winner.kind != indexEntryFull:
			if all != nil && all.version < winner.version {
				removed[all] = true
			}
		case all == nil || all.version < winner.version:
			if all != nil {
				removed[all] = true
			}
			appended = append(appended, winner.layoutEntry())
		}
	}
	refKeys := make([][indexIdByteCount]byte, 0, len(carried.refs))
	for key := range carried.refs {
		refKeys = append(refKeys, key)
	}
	slices.SortFunc(refKeys, compareIndexKeys)
	for _, refKey := range refKeys {
		refWinner := carried.refs[refKey]
		for _, document := range allRows {
			if bytes.Equal(document.row.refId, refKey[:]) && document.version < refWinner.version {
				removed[document] = true
			}
		}
		target := -1
		for bucketIndex, lowest := range newer.refs[refKey] {
			if lowest < refWinner.version {
				target = max(target, bucketIndex)
			}
		}
		if 0 <= target {
			promoted[target] = append(promoted[target], refWinner.entry())
		}
	}
	for _, document := range allRows {
		if view.erased(document.key, document.version) {
			removed[document] = true
		}
	}

	allLayout := []*indexLayoutShard{}
	for index, shard := range root.allShards {
		allLayout = append(allLayout, indexLayoutShardOf(shard.path.shardNumber, shard.file, args.allShards[index]))
	}
	laid, err := indexLayout(&indexLayoutArgs{
		root:     root,
		fileType: indexFileAllShard,
		shards:   allLayout,
		keepDocument: func(document *indexShardDocument) bool {
			return !removed[document]
		},
		keepTombstone: func(tombstone *indexShardTombstone) bool {
			return false
		},
		appended:  appended,
		padKey:    args.padKey,
		tables:    args.tables,
		companion: view.companion,
		settings:  view.settings,
	})
	if err != nil {
		return nil, err
	}
	result := &indexRollupResult{malformed: malformed, promoted: map[uint32][]*indexEntry{}}
	for _, file := range laid.files {
		result.files = append(result.files, &indexPushFile{path: file.path.String(), plaintext: file.file, replaces: file.replaces})
	}
	result.removals = append(result.removals, laid.removals...)
	result.allManifest = &protocol.IndexManifest{Shards: laid.manifestShards, RolledThroughDay: expired.bucket.window.startDay}
	allManifest, err := indexEncodeManifest(result.allManifest, true)
	if err != nil {
		return nil, err
	}
	replaces := uint64(0)
	if root.allManifestFile != nil {
		replaces = root.allManifestFile.version
	}
	result.files = append(result.files, &indexPushFile{path: root.paths.allManifest(), plaintext: allManifest, replaces: replaces})

	targets := []int{}
	for target := range promoted {
		targets = append(targets, target)
	}
	slices.Sort(targets)
	for _, target := range targets {
		newerBucket := args.newer[target]
		merged, err := indexMerge(&indexMergeArgs{
			root:      root,
			bucket:    newerBucket.bucket,
			shards:    newerBucket.shards,
			extra:     promoted[target],
			erased:    view.erased,
			padKey:    args.padKey,
			tables:    args.tables,
			companion: view.companion,
			settings:  view.settings,
		})
		if err != nil {
			return nil, err
		}
		result.files = append(result.files, merged.files()...)
		result.removals = append(result.removals, merged.removedShards...)
		result.malformed = append(result.malformed, merged.malformed...)
		result.promoted[newerBucket.bucket.window.startDay] = promoted[target]
	}

	head, err := indexRollupCoverageHead(ctx, args, result)
	if err != nil {
		return nil, err
	}
	result.files = append(result.files, head...)
	for _, file := range args.expiredFiles {
		result.removals = append(result.removals, &indexPushRemoval{path: file.path, version: file.version})
	}
	slices.SortFunc(result.files, func(a *indexPushFile, b *indexPushFile) int {
		return cmp.Compare(a.path, b.path)
	})
	slices.SortFunc(result.removals, func(a *indexPushRemoval, b *indexPushRemoval) int {
		return cmp.Compare(a.path, b.path)
	})
	return result, nil
}

// Step 5's coverage: the horizon rows S's coverage asks the runner's head to carry, and that head written through
// indexPlanHead with no document, in the bucket of the push's signed time, its own rows kept beside them.
func indexRollupCoverageHead(ctx context.Context, args *indexRollupArgs, result *indexRollupResult) ([]*indexPushFile, error) {
	view, root := args.view, args.root
	named := map[[indexIdByteCount]byte]bool{}
	expiredHorizon := map[[indexIdByteCount]byte]uint64{}
	for _, writer := range args.expired.bucket.writers {
		for _, slot := range writer.slots {
			for _, row := range slot.slot.header.Coverage {
				if len(row.RefId) != indexIdByteCount {
					continue
				}
				refId := [indexIdByteCount]byte(row.RefId)
				named[refId] = true
				if row.Horizon {
					expiredHorizon[refId] = max(expiredHorizon[refId], row.Version)
				}
			}
		}
	}
	outsideHorizon := map[[indexIdByteCount]byte]uint64{}
	for _, bucket := range root.buckets {
		if bucket == args.expired.bucket {
			continue
		}
		for _, writer := range bucket.writers {
			for _, slot := range writer.slots {
				for _, row := range slot.slot.header.Coverage {
					if row.Horizon && len(row.RefId) == indexIdByteCount {
						refId := [indexIdByteCount]byte(row.RefId)
						outsideHorizon[refId] = max(outsideHorizon[refId], row.Version)
					}
				}
			}
		}
	}
	refIds := make([][indexIdByteCount]byte, 0, len(named))
	for refId := range named {
		refIds = append(refIds, refId)
	}
	slices.SortFunc(refIds, compareIndexKeys)
	carriedRows := []*protocol.IndexCoverage{}
	for _, refId := range refIds {
		through, ok := uint64(0), false
		if args.indexedThrough != nil {
			through, ok = args.indexedThrough(refId[:])
		}
		if !ok {
			through, ok = expiredHorizon[refId]
		}
		if !ok {
			continue
		}
		if outside, held := outsideHorizon[refId]; held && through <= outside {
			continue
		}
		carriedRows = append(carriedRows, &protocol.IndexCoverage{RefId: bytes.Clone(refId[:]), Version: through, Horizon: true})
	}
	result.carriedCoverage = carriedRows
	if len(carriedRows) == 0 {
		return nil, nil
	}

	window, _ := indexBucketFor(root.bucketWindows(), root.windowDays(view.repoKind), args.signedTimeMs)
	coverage := []*protocol.IndexCoverage{}
	if bucket := root.bucket(window.startDay); bucket != nil {
		if writer := bucket.writer(args.runner); writer != nil && writer.head() != nil {
			coverage = append(coverage, writer.head().slot.header.Coverage...)
		}
	}
	coverage = indexRaiseHorizons(coverage, carriedRows)
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view:         view,
		root:         root,
		writer:       args.runner,
		signedTimeMs: args.signedTimeMs,
		tables:       args.tables,
		coverage:     coverage,
	})
	if err != nil {
		return nil, err
	}
	return plan.files(), nil
}

// coverage with each of rows' horizon rows raised into it: a ref's horizon row replaced by a higher one, its own row
// kept, in the format's order (by ref_id, then horizon false before true).
func indexRaiseHorizons(coverage []*protocol.IndexCoverage, rows []*protocol.IndexCoverage) []*protocol.IndexCoverage {
	raised := []*protocol.IndexCoverage{}
	for _, row := range coverage {
		raised = append(raised, &protocol.IndexCoverage{RefId: bytes.Clone(row.RefId), Version: row.Version, Horizon: row.Horizon})
	}
	for _, row := range rows {
		index := slices.IndexFunc(raised, func(held *protocol.IndexCoverage) bool {
			return held.Horizon && bytes.Equal(held.RefId, row.RefId)
		})
		switch {
		case index < 0:
			raised = append(raised, &protocol.IndexCoverage{RefId: bytes.Clone(row.RefId), Version: row.Version, Horizon: true})
		case raised[index].Version < row.Version:
			raised[index].Version = row.Version
		}
	}
	slices.SortFunc(raised, indexCompareCoverage)
	return raised
}
