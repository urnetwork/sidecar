//go:build !ios_extension

// Bucket merges (§11.14's Merges block as DESIGN-DETAILS 1.2.4 rewrites it; D-EVS-47; R3; QD-685, QD-688, QD-689;
// SEARCH-M10-10): a merge folds a bucket's sealed slots and unabsorbed large entries into its shards. It is a pure
// function of the bucket's manifest and shards, those files, the erasure set, the merger's pad key and the tables it
// names, so two mergers of one base build equal plaintext (FI-22) and a reproducer learns its inputs from the push:
// the files it replaces and the watermarks its manifest raises.
//
// A merge reads no head. A writer's head is its own until it seals (R2), and a diff rests only on its own writer's
// files (R1), which that writer keeps while the diff needs them, so every input composes (I2). The output is each
// document's newest version among the shards, the sealed slots, the unabsorbed large entries and any extra entries,
// every diff composed onto its own writer's base: at one version a tombstone, then the shards' own entry, then an
// extra entry, then the full entry from the lowest writer_sidecar_id and the lowest seq. Honest copies of one version
// are equal, so the order only makes the result a function. A live winner is a doc-table row with its postings, a
// tombstone goes to the tombstone table, and on ur/index a ref tombstone takes every row of its ref below its version;
// each stays for older partitions until the bucket rolls. layout appends the new winners in key order to the youngest
// shard, opening the next at the cap by take's search, drops each superseded entry from the shard holding it, so a
// bucket's shards hold one version a key (QD-688), joins adjacent shards that come to under ShardJoinByteCount, and
// removes an emptied one. The manifest's watermarks rise to the highest seq the merge read of each writer, never a
// head's.
//
// A merge writes and removes no file of any writer's: slots stay for their writers to reuse and large entries for
// their writers to remove. Its manifest, which every merge replaces or creates, is its fence against any other merge,
// promotion or push merging its own entries (1.2.7), so a merge whose winners are all the shards' own still commits
// it, and its writers can reuse their slots. The same function serves a push past PushDirectByteCount, which merges
// its own entries as extra without absorbing anything (indexMergeHeadPlan), and a roll-up's promotions into a newer
// bucket (evs_index_rollup.go); layout lays out the all partition too.
//
// Memory: this draft holds the bucket's decoded shards and its inputs' key sets in RAM, where DESIGN-DETAILS 1.4 asks
// an app host for a k-way pass over inputs in storage (QD-641); take measures a shard by encoding it.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"math"
	"slices"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A document whose row and postings pass a shard's cap in a shard of its own, so no layout can place it. A key set
	// within KeySetMax can be one (a chunk of some 200,000 distinct trigrams and more), and DESIGN-DETAILS 1.2.4 does not
	// say what a merge then writes: the merge fails closed and writes nothing (question
	// search-m10-10-document-past-a-shard).
	errIndexMergeUnplaceable = errors.New("index document fits no shard")
	// A merge's inputs do not line up: a shard decoded for none the bucket names, or one missing.
	errIndexMergeInputs = errors.New("index merge inputs do not match their bucket")
)

// What one merge reads, all of it at the merge's base.
type indexMergeArgs struct {
	// The root and the bucket. A bucket the base does not hold yet, which a push past PushDirectByteCount opens, is an
	// indexViewBucket holding its window alone.
	root   *indexViewRoot
	bucket *indexViewBucket
	// The bucket's shards decoded, one for each of bucket.shards and in its order.
	shards []*indexShard
	// Entries the merge takes beside its inputs: a push's own documents, full entries and tombstones, or a roll-up's
	// promoted versions and tombstones. No diff, and one entry a key.
	extra []*indexEntry
	// Whether the merge absorbs its writers' sealed slots and unabsorbed large entries. A push merging its own entries
	// and a promotion do not, so every watermark stands.
	absorb bool
	// Whether the ref's erasure set lists key at or above version. Nil lists nothing.
	erased func(key [indexIdByteCount]byte, version uint64) bool
	// K_index_g at the merger's newest generation, which pads every shard the merge changes and which their headers
	// name.
	padKey *indexPadKey
	// The tables the new shards' headers name.
	tables    indexTables
	companion bool
	settings  *IndexFormatSettings
}

// A diff a merge could not compose, since no other file of its writer's holds its base: index_malformed names the
// slot's signer (1.2.4; I1 says an honest slot never has one).
type indexMalformedDiff struct {
	path            string
	signerSidecarId Id
}

// What a merge writes: one push's files and removals, none of them a writer's.
type indexMergeResult struct {
	// Shards created or replaced, in path order; slot is nil on each.
	shards []*indexPlannedFile
	// Shards emptied or joined into a lower n, at the versions the base showed.
	removedShards []*indexPushRemoval
	// The bucket's manifest, replaced or created.
	manifest        *indexPlannedFile
	writtenManifest *protocol.IndexManifest
	malformed       []*indexMalformedDiff
}

// The files the merge writes, in path order, each under its path's CAS.
func (self *indexMergeResult) files() []*indexPushFile {
	files := []*indexPushFile{}
	for _, planned := range append(slices.Clone(self.shards), self.manifest) {
		files = append(files, &indexPushFile{path: planned.path.String(), plaintext: planned.file, replaces: planned.replaces})
	}
	slices.SortFunc(files, func(a *indexPushFile, b *indexPushFile) int {
		return cmp.Compare(a.path, b.path)
	})
	return files
}

// Where a merge candidate came from, in the tie order at one version after a tombstone.
type indexMergeSource int

const (
	indexMergeFromShard indexMergeSource = iota + 1
	indexMergeFromExtra
	indexMergeFromWriter
)

// One candidate for a key's winner: a full entry, diffs composed; a tombstone; or on ur/index a ref tombstone.
type indexMergeCandidate struct {
	kind        indexEntryKind
	key         [indexIdByteCount]byte
	version     uint64
	timeSeconds uint64
	row         *indexRow
	keys        indexKeySet
	source      indexMergeSource
	// A shard's own entry: its shard's place, and the row or tombstone it is.
	shardIndex     int
	shardDocument  *indexShardDocument
	shardTombstone *indexShardTombstone
	// A writer's file's entry: whose, and the file's seq.
	writer Id
	seq    uint32
}

// Whether a takes the key from b: the higher version; at one version a tombstone, then the shards' own entry, then an
// extra entry, then the full entry from the lowest writer_sidecar_id, then the lowest seq; of two shards' copies, the
// lower shard (1.2.4's winner).
func indexMergeBeats(a *indexMergeCandidate, b *indexMergeCandidate) bool {
	if a.version != b.version {
		return b.version < a.version
	}
	if aDead, bDead := a.kind != indexEntryFull, b.kind != indexEntryFull; aDead != bDead {
		return aDead
	}
	if a.source != b.source {
		return a.source < b.source
	}
	switch a.source {
	case indexMergeFromShard:
		return a.shardIndex < b.shardIndex
	case indexMergeFromWriter:
		if order := a.writer.Cmp(b.writer); order != 0 {
			return order < 0
		}
		return a.seq < b.seq
	}
	return false
}

// The candidate as a shard holds it: a row or a tombstone.
func (self *indexMergeCandidate) layoutEntry() *indexLayoutEntry {
	if self.kind == indexEntryFull {
		return &indexLayoutEntry{document: &indexShardDocument{key: self.key, version: self.version, timeSeconds: self.timeSeconds, row: self.row, keys: self.keys}}
	}
	return &indexLayoutEntry{tombstone: &indexShardTombstone{kind: self.kind, key: self.key, version: self.version, timeSeconds: self.timeSeconds}}
}

// An entry as a merge candidate from source.
func indexMergeCandidateOf(entry *indexEntry, source indexMergeSource) *indexMergeCandidate {
	return &indexMergeCandidate{
		kind:        entry.kind,
		key:         entry.key,
		version:     entry.version,
		timeSeconds: entry.timeSeconds,
		row:         entry.row,
		keys:        entry.keys,
		source:      source,
	}
}

// Each key's winner over candidates: documents by doc_key, ref tombstones by ref_id apart.
type indexMergeWinners struct {
	documents map[[indexIdByteCount]byte]*indexMergeCandidate
	refs      map[[indexIdByteCount]byte]*indexMergeCandidate
}

// No candidate yet.
func indexNewMergeWinners() *indexMergeWinners {
	return &indexMergeWinners{documents: map[[indexIdByteCount]byte]*indexMergeCandidate{}, refs: map[[indexIdByteCount]byte]*indexMergeCandidate{}}
}

// Takes candidate where it beats the key's winner so far.
func (self *indexMergeWinners) consider(candidate *indexMergeCandidate) {
	winners := self.documents
	if candidate.kind == indexEntryRefTombstone {
		winners = self.refs
	}
	if winner := winners[candidate.key]; winner == nil || indexMergeBeats(candidate, winner) {
		winners[candidate.key] = candidate
	}
}

// Drops each live winner below the winning ref tombstone of its ref: every row of that ref below its version goes
// (1.2.4, on ur/index).
func (self *indexMergeWinners) dropRefRows() {
	for key, winner := range self.documents {
		if winner.kind != indexEntryFull || len(winner.row.refId) != indexIdByteCount {
			continue
		}
		if refWinner := self.refs[[indexIdByteCount]byte(winner.row.refId)]; refWinner != nil && winner.version < refWinner.version {
			delete(self.documents, key)
		}
	}
}

// Whether a shard's own row is its key's winner.
func (self *indexMergeWinners) keepsDocument(document *indexShardDocument) bool {
	winner := self.documents[document.key]
	return winner != nil && winner.shardDocument == document
}

// Whether a shard's own tombstone is its key's winner.
func (self *indexMergeWinners) keepsTombstone(tombstone *indexShardTombstone) bool {
	winners := self.documents
	if tombstone.kind == indexEntryRefTombstone {
		winners = self.refs
	}
	winner := winners[tombstone.key]
	return winner != nil && winner.shardTombstone == tombstone
}

// The winners no shard holds yet, ascending by key, then kind: what layout appends.
func (self *indexMergeWinners) appended() []*indexLayoutEntry {
	entries := []*indexLayoutEntry{}
	for _, winners := range []map[[indexIdByteCount]byte]*indexMergeCandidate{self.documents, self.refs} {
		for _, winner := range winners {
			if winner.source != indexMergeFromShard {
				entries = append(entries, winner.layoutEntry())
			}
		}
	}
	slices.SortFunc(entries, indexCompareLayoutEntries)
	return entries
}

// The shards' entries, every extra entry and, when absorbing, every sealed slot's and unabsorbed large entry's entry
// as candidates, the erasure set's documents left out first: what a merge's winners are chosen from. Each writer's
// highest seq read joins watermarks. A diff composes onto its own writer's base; one whose base no other file of its
// writer's holds is malformed and left out.
func indexMergeCandidates(bucket *indexViewBucket, shards []*indexShard, extra []*indexEntry, absorb bool, includeHeads bool, erased func(key [indexIdByteCount]byte, version uint64) bool, watermarks map[Id]uint32) (*indexMergeWinners, []*indexMalformedDiff, error) {
	winners := indexNewMergeWinners()
	for shardIndex, shard := range shards {
		for _, document := range shard.documents {
			if !erased(document.key, document.version) {
				winners.consider(&indexMergeCandidate{
					kind: indexEntryFull, key: document.key, version: document.version, timeSeconds: document.timeSeconds,
					row: document.row, keys: document.keys, source: indexMergeFromShard, shardIndex: shardIndex, shardDocument: document,
				})
			}
		}
		for _, tombstone := range shard.tombstones {
			if !erased(tombstone.key, tombstone.version) {
				winners.consider(&indexMergeCandidate{
					kind: tombstone.kind, key: tombstone.key, version: tombstone.version, timeSeconds: tombstone.timeSeconds,
					source: indexMergeFromShard, shardIndex: shardIndex, shardTombstone: tombstone,
				})
			}
		}
	}
	extraKeys := map[[indexIdByteCount]byte]bool{}
	for _, entry := range extra {
		if entry.kind == indexEntryDiff {
			return nil, nil, indexMalformed("a diff among a merge's extra entries")
		}
		if extraKeys[entry.key] {
			return nil, nil, indexMalformed("a document twice among a merge's extra entries")
		}
		extraKeys[entry.key] = true
		if !erased(entry.key, entry.version) {
			winners.consider(indexMergeCandidateOf(entry, indexMergeFromExtra))
		}
	}
	malformed := []*indexMalformedDiff{}
	if absorb {
		for _, writer := range bucket.writers {
			absorbed := bucket.absorbedSeq(writer.sidecarId)
			head := writer.head()
			highest := absorbed
			for _, file := range writer.unabsorbed(absorbed) {
				if file == head && !includeHeads {
					continue
				}
				highest = max(highest, file.seq())
				for _, entry := range file.slot.entries {
					if erased(entry.key, entry.version) {
						continue
					}
					candidate := indexMergeCandidateOf(entry, indexMergeFromWriter)
					candidate.writer, candidate.seq = writer.sidecarId, file.seq()
					if entry.kind == indexEntryDiff {
						// A diff whose base version the set lists, while its own version it does not, loses its base to
						// the eraser's CLOSURE: it is left out and alarms nothing, as both of question
						// search-m10-46-erased-base-of-a-live-diff's options 1 and 2 read it.
						if erased(entry.key, entry.baseVersion) {
							continue
						}
						_, base := indexResolveBase(writer, entry.key, entry.baseVersion, file)
						var keys indexKeySet
						var err error
						if base != nil {
							keys, err = entry.delta.applyTo(base.keys)
						}
						if base == nil || err != nil || uint64(len(keys)) != entry.row.trigramCount {
							malformed = append(malformed, &indexMalformedDiff{path: file.file.path, signerSidecarId: file.file.signerSidecarId})
							continue
						}
						candidate.kind, candidate.keys = indexEntryFull, keys
					}
					winners.consider(candidate)
				}
			}
			if 0 < highest {
				watermarks[writer.sidecarId] = max(watermarks[writer.sidecarId], highest)
			}
		}
	}
	winners.dropRefRows()
	return winners, malformed, nil
}

// 1.2.4's merge of args.bucket at its base: the winners over its shards, its sealed slots and unabsorbed large entries
// when absorbing, and its extra entries; its shards laid out again; its manifest with each writer's watermark at the
// highest seq read. The result names no writer's file.
func indexMerge(args *indexMergeArgs) (*indexMergeResult, error) {
	bucket := args.bucket
	if len(args.shards) != len(bucket.shards) {
		return nil, errIndexMergeInputs
	}
	erased := args.erased
	if erased == nil {
		erased = func(key [indexIdByteCount]byte, version uint64) bool {
			return false
		}
	}
	watermarks := map[Id]uint32{}
	if bucket.manifest != nil {
		for _, watermark := range bucket.manifest.Absorbed {
			if writerId, err := IdFromBytes(watermark.WriterSidecarId); err == nil {
				watermarks[writerId] = watermark.Seq
			}
		}
	}
	winners, malformed, err := indexMergeCandidates(bucket, args.shards, args.extra, args.absorb, false, erased, watermarks)
	if err != nil {
		return nil, err
	}

	layoutShards := []*indexLayoutShard{}
	for index, shard := range bucket.shards {
		layoutShards = append(layoutShards, indexLayoutShardOf(shard.path.shardNumber, shard.file, args.shards[index]))
	}
	laid, err := indexLayout(&indexLayoutArgs{
		root:          args.root,
		fileType:      indexFileBucketShard,
		window:        bucket.window,
		shards:        layoutShards,
		keepDocument:  winners.keepsDocument,
		keepTombstone: winners.keepsTombstone,
		appended:      winners.appended(),
		padKey:        args.padKey,
		tables:        args.tables,
		companion:     args.companion,
		settings:      args.settings,
	})
	if err != nil {
		return nil, err
	}

	manifest := &protocol.IndexManifest{StartDay: bucket.window.startDay, Days: bucket.window.days, Shards: laid.manifestShards}
	writerIds := []Id{}
	for writerId := range watermarks {
		writerIds = append(writerIds, writerId)
	}
	slices.SortFunc(writerIds, func(a Id, b Id) int {
		return a.Cmp(b)
	})
	for _, writerId := range writerIds {
		if seq := watermarks[writerId]; 0 < seq {
			manifest.Absorbed = append(manifest.Absorbed, &protocol.IndexWatermark{WriterSidecarId: writerId.Bytes(), Seq: seq})
		}
	}
	manifestBytes, err := indexEncodeManifest(manifest, false)
	if err != nil {
		return nil, err
	}
	manifestPath, _ := indexParsePath(args.root.paths.bucketManifest(bucket.window.startDay), args.companion)
	replaces := uint64(0)
	if bucket.manifestFile != nil {
		replaces = bucket.manifestFile.version
	}
	return &indexMergeResult{
		shards:          laid.files,
		removedShards:   laid.removals,
		manifest:        &indexPlannedFile{path: manifestPath, file: manifestBytes, replaces: replaces},
		writtenManifest: manifest,
		malformed:       malformed,
	}, nil
}

// One entry layout places: a live row or a tombstone.
type indexLayoutEntry struct {
	document  *indexShardDocument
	tombstone *indexShardTombstone
}

// The entry's key and kind.
func (self *indexLayoutEntry) keyKind() ([indexIdByteCount]byte, indexEntryKind) {
	if self.document != nil {
		return self.document.key, indexEntryFull
	}
	return self.tombstone.key, self.tombstone.kind
}

// Ascending by key, then kind: the order layout appends in.
func indexCompareLayoutEntries(a *indexLayoutEntry, b *indexLayoutEntry) int {
	aKey, aKind := a.keyKind()
	bKey, bKind := b.keyKind()
	return cmp.Or(bytes.Compare(aKey[:], bKey[:]), cmp.Compare(aKind, bKind))
}

// One shard of a partition as layout holds it.
type indexLayoutShard struct {
	n uint32
	// The version the base showed, nil for a shard this layout opens.
	file       *indexFileVersion
	documents  []*indexShardDocument
	tombstones []*indexShardTombstone
	// While unchanged, its bytes before its pad, the replaced version's.
	unpaddedByteCount int
	changed           bool
}

// A partition's shard n as its base holds it.
func indexLayoutShardOf(n uint32, file *indexFileVersion, shard *indexShard) *indexLayoutShard {
	return &indexLayoutShard{
		n:                 n,
		file:              file,
		documents:         slices.Clone(shard.documents),
		tombstones:        slices.Clone(shard.tombstones),
		unpaddedByteCount: file.byteCount - shard.padByteCount,
	}
}

// Whether the shard holds nothing.
func (self *indexLayoutShard) empty() bool {
	return len(self.documents) == 0 && len(self.tombstones) == 0
}

// What one layout of a partition reads.
type indexLayoutArgs struct {
	root *indexViewRoot
	// indexFileBucketShard with its bucket's window, or indexFileAllShard.
	fileType uint32
	window   indexBucketWindow
	// The partition's shards by ascending n, as its base holds them.
	shards []*indexLayoutShard
	// Whether a shard's own row or tombstone stays where it is; each one that does not is dropped from its shard.
	keepDocument  func(document *indexShardDocument) bool
	keepTombstone func(tombstone *indexShardTombstone) bool
	// The entries to append, ascending by key then kind.
	appended  []*indexLayoutEntry
	padKey    *indexPadKey
	tables    indexTables
	companion bool
	settings  *IndexFormatSettings
}

// A partition laid out again: its shards after, every one changed encoded, and its manifest's shard rows.
type indexLayoutResult struct {
	// By ascending n.
	shards []*indexLayoutShard
	// Shards created or replaced, in path order.
	files []*indexPlannedFile
	// Shards emptied or joined into a lower n.
	removals       []*indexPushRemoval
	manifestShards []*protocol.IndexShard
}

// The header a laid-out shard takes, its pad's generation named, as build sets it.
func (self *indexLayoutArgs) header() *protocol.IndexFileHeader {
	header := indexNewFileHeader(self.fileType, self.tables)
	if self.fileType == indexFileBucketShard {
		header.BucketStartDay = self.window.startDay
		header.BucketDays = self.window.days
	}
	header.PadGeneration = self.padKey.generation
	return header
}

// The path of shard n.
func (self *indexLayoutArgs) path(n uint32) indexPath {
	text := self.root.paths.allShard(n)
	if self.fileType == indexFileBucketShard {
		text = self.root.paths.bucketShard(self.window.startDay, n)
	}
	path, _ := indexParsePath(text, self.companion)
	return path
}

// The shard as builders encode it, blocks of 64, before its pad.
func (self *indexLayoutArgs) unpadded(builder *indexShardBuilder, documents []*indexShardDocument, tombstones []*indexShardTombstone) ([]byte, error) {
	file, _, err := builder.encodeUnpadded(&indexShard{header: self.header(), documents: documents, tombstones: tombstones})
	return file, err
}

// 1.2.4's layout: (1) drop from each shard what it no longer keeps; (2) append args.appended to the youngest shard,
// shard 0 where there is none, taking by take's search and opening the highest n + 1 at the cap; (3) by ascending n,
// join each shard with the next while the two come to fewer than ShardJoinByteCount before their pads, testing the
// joined shard again with its next; (4) remove a shard left empty; (5) encode each changed shard by blocks of 64 with
// the keyed pad at padKey's generation. A shard nothing changed keeps its bytes and is not written.
func indexLayout(args *indexLayoutArgs) (*indexLayoutResult, error) {
	if args.padKey == nil {
		return nil, indexMalformed("a layout without its pad key")
	}
	builder := indexNewShardBuilder(args.companion)
	shards := slices.Clone(args.shards)
	for _, shard := range shards {
		documents := slices.DeleteFunc(slices.Clone(shard.documents), func(document *indexShardDocument) bool {
			return !args.keepDocument(document)
		})
		tombstones := slices.DeleteFunc(slices.Clone(shard.tombstones), func(tombstone *indexShardTombstone) bool {
			return !args.keepTombstone(tombstone)
		})
		if len(documents) != len(shard.documents) || len(tombstones) != len(shard.tombstones) {
			shard.documents, shard.tombstones, shard.changed = documents, tombstones, true
		}
	}

	appended := args.appended
	if 0 < len(appended) {
		if len(shards) == 0 {
			shards = append(shards, &indexLayoutShard{n: 0, changed: true})
		}
		youngest := shards[len(shards)-1]
		for 0 < len(appended) {
			count, err := indexTake(args, builder, youngest, appended)
			if err != nil {
				return nil, err
			}
			if count == 0 && youngest.empty() {
				return nil, errIndexMergeUnplaceable
			}
			for _, entry := range appended[:count] {
				if entry.document != nil {
					youngest.documents = append(youngest.documents, entry.document)
				} else {
					youngest.tombstones = append(youngest.tombstones, entry.tombstone)
				}
			}
			if 0 < count {
				youngest.changed = true
			}
			appended = appended[count:]
			if 0 < len(appended) {
				youngest = &indexLayoutShard{n: shards[len(shards)-1].n + 1, changed: true}
				shards = append(shards, youngest)
			}
		}
	}

	removals := []*indexPushRemoval{}
	remove := func(shard *indexLayoutShard) {
		if shard.file != nil {
			removals = append(removals, &indexPushRemoval{path: args.path(shard.n).String(), version: shard.file.version})
		}
	}
	unpaddedByteCount := func(shard *indexLayoutShard) (int, error) {
		if !shard.changed {
			return shard.unpaddedByteCount, nil
		}
		file, err := args.unpadded(builder, shard.documents, shard.tombstones)
		if err != nil {
			return 0, err
		}
		return len(file), nil
	}
	for index := 0; index+1 < len(shards); {
		first, err := unpaddedByteCount(shards[index])
		if err != nil {
			return nil, err
		}
		second, err := unpaddedByteCount(shards[index+1])
		if err != nil {
			return nil, err
		}
		if args.settings.ShardJoinByteCount <= first+second {
			index += 1
			continue
		}
		next := shards[index+1]
		shards[index].documents = append(shards[index].documents, next.documents...)
		shards[index].tombstones = append(shards[index].tombstones, next.tombstones...)
		shards[index].changed = true
		remove(next)
		shards = slices.Delete(shards, index+1, index+2)
	}
	kept := []*indexLayoutShard{}
	for _, shard := range shards {
		if shard.empty() {
			remove(shard)
			continue
		}
		kept = append(kept, shard)
	}

	result := &indexLayoutResult{shards: kept, removals: removals}
	for _, shard := range kept {
		if shard.changed {
			file, err := builder.build(&indexShard{header: args.header(), documents: shard.documents, tombstones: shard.tombstones}, args.padKey)
			if err != nil {
				return nil, err
			}
			replaces := uint64(0)
			if shard.file != nil {
				replaces = shard.file.version
			}
			result.files = append(result.files, &indexPlannedFile{path: args.path(shard.n), file: file, replaces: replaces})
		}
		result.manifestShards = append(result.manifestShards, indexManifestShardOf(shard))
	}
	slices.SortFunc(result.files, func(a *indexPlannedFile, b *indexPlannedFile) int {
		return cmp.Compare(a.path.String(), b.path.String())
	})
	slices.SortFunc(result.removals, func(a *indexPushRemoval, b *indexPushRemoval) int {
		return cmp.Compare(a.path, b.path)
	})
	return result, nil
}

// take's count (1.2.4): all of appended when the youngest shard takes them within the shard's cap, else the count c
// that lo = 0; hi = len; while lo < hi: mid = (lo + hi + 1) / 2; if the shard with appended[0:mid] encodes within the
// cap then lo = mid else hi = mid - 1; c = lo finds. A shard's length is not quite monotone in its documents, since
// re-blocking by 64 can save bytes when a key is added, so every implementation runs this same search. The cap is the
// shard encoder's own, which answers errIndexShardFull past it.
func indexTake(args *indexLayoutArgs, builder *indexShardBuilder, youngest *indexLayoutShard, appended []*indexLayoutEntry) (int, error) {
	fits := func(count int) (bool, error) {
		documents := slices.Clone(youngest.documents)
		tombstones := slices.Clone(youngest.tombstones)
		for _, entry := range appended[:count] {
			if entry.document != nil {
				documents = append(documents, entry.document)
			} else {
				tombstones = append(tombstones, entry.tombstone)
			}
		}
		_, err := args.unpadded(builder, documents, tombstones)
		switch {
		case errors.Is(err, errIndexShardFull):
			return false, nil
		case err != nil:
			return false, err
		}
		return true, nil
	}
	all, err := fits(len(appended))
	if err != nil || all {
		return len(appended), err
	}
	low, high := 0, len(appended)
	for low < high {
		middle := (low + high + 1) / 2
		ok, err := fits(middle)
		if err != nil {
			return 0, err
		}
		if ok {
			low = middle
		} else {
			high = middle - 1
		}
	}
	return low, nil
}

// A shard's manifest row: its n, its live documents, and the days its rows' and tombstones' times fall on (QD-406:
// each merge and roll-up computes them again).
func indexManifestShardOf(shard *indexLayoutShard) *protocol.IndexShard {
	row := &protocol.IndexShard{N: shard.n, Docs: uint32(len(shard.documents))}
	first := true
	day := func(timeSeconds uint64) {
		value := uint32(min(timeSeconds/(indexDayMs/1000), math.MaxUint32))
		if first || value < row.FirstDay {
			row.FirstDay = value
		}
		if first || row.LastDay < value {
			row.LastDay = value
		}
		first = false
	}
	for _, document := range shard.documents {
		day(document.timeSeconds)
	}
	for _, tombstone := range shard.tombstones {
		day(tombstone.timeSeconds)
	}
	return row
}

// The bucket's shards decoded at the view's base, in the bucket's order. A shard that does not decode fails the
// merge, since nothing can say what it held: errIndexMergeInputs, the view having alarmed it.
func indexDecodeBucketShards(ctx context.Context, view *indexView, shards []*indexViewShard) ([]*indexShard, error) {
	decoded := []*indexShard{}
	for _, shard := range shards {
		one, err := view.shard(ctx, shard)
		if err != nil {
			return nil, err
		}
		if one == nil {
			return nil, errIndexMergeInputs
		}
		decoded = append(decoded, one)
	}
	return decoded, nil
}

// A push past PushDirectByteCount (1.2.3): each bucket of a plan whose mergeInPush is set merges the push's own
// entries into its shards without absorbing, beside the writer's head the plan wrote without them. The plan's files
// and removals and every merge's, in path order, are the whole push.
func indexMergeHeadPlan(ctx context.Context, view *indexView, root *indexViewRoot, plan *indexHeadPlan, padKey *indexPadKey, tables indexTables) ([]*indexPushFile, []*indexPushRemoval, []*indexMalformedDiff, error) {
	files := plan.files()
	removals := plan.removals()
	malformed := []*indexMalformedDiff{}
	if !plan.mergeInPush {
		return files, removals, malformed, nil
	}
	for _, planned := range plan.buckets {
		if len(planned.direct) == 0 {
			continue
		}
		bucket := root.bucket(planned.window.startDay)
		if bucket == nil {
			bucket = &indexViewBucket{window: planned.window}
		}
		shards, err := indexDecodeBucketShards(ctx, view, bucket.shards)
		if err != nil {
			return nil, nil, nil, err
		}
		merged, err := indexMerge(&indexMergeArgs{
			root:      root,
			bucket:    bucket,
			shards:    shards,
			extra:     planned.direct,
			erased:    view.erased,
			padKey:    padKey,
			tables:    tables,
			companion: view.companion,
			settings:  view.settings,
		})
		if err != nil {
			return nil, nil, nil, err
		}
		files = append(files, merged.files()...)
		removals = append(removals, merged.removedShards...)
		malformed = append(malformed, merged.malformed...)
	}
	slices.SortFunc(files, func(a *indexPushFile, b *indexPushFile) int {
		return cmp.Compare(a.path, b.path)
	})
	slices.SortFunc(removals, func(a *indexPushRemoval, b *indexPushRemoval) int {
		return cmp.Compare(a.path, b.path)
	})
	return files, removals, malformed, nil
}
