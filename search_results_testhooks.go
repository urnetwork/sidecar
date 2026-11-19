//go:build sidecar_testhooks && !ios_extension && !js

// What FS-76's, FS-107's and FS-108's schedules add to a search world (SEARCH-M10-36; §11.14's confirm, drop, tombstone
// and verify rows; owner decision 584): a desktop's own text of the world's content, where a document's versions sit,
// a DROP's index rewrite at the head, a writer's racing tombstones, a slot holding an entry of the reserved kind 2, and
// the index's own decoder on a file's bytes.
//
//	text     a device made with SearchTestDeviceArgs.Text verifies its candidates against the bytes the world's
//	         content pushes wrote (SearchContentTextSource over every content version the ref holds), as a desktop
//	         mirroring the ref does, so its hits checked against its own text can equal SearchOracle's
//	held     FilesHolding names every index file at the head holding an entry, row or tombstone of a document, read
//	         whole and decoded; SearchTestEvsFilesHolding does the same through EvsRepo's index store
//	drop     Drop is SEARCH-M10-18's rewrite (indexDropRewrite) built at the head and committed as the DROP's push
//	         carries it, naming the head's index_epoch: every index file holding a listed version written again without
//	         it at its replaced length, each writer whose file it rewrote having its head written again (R2), and each
//	         bucket whose merged inputs it rewrote its manifest (R3). The content side, evs's DROP push writing
//	         through_version with the head's bytes, is evs's and not modeled: the world's content keeps the kept version
//	         as the path's newest, which is the version the kept entry names
//	removals PlanRemovals plans a writer's tombstones at the head as PlanPush plans live documents, committed later, so
//	         two writers race at a bucket boundary as §11.14's entry row has them
//	forged   ForgeReservedKindSlot commits, as a writer of its own, a slot well formed but for its one entry, of the
//	         reserved kind 2 (a diff's layout), which every decoder refuses, so a device lists the file bad and raises
//	         index_malformed naming that writer
//	decoder  SearchTestValidateIndexFile is the reading a device's sync judges a fetched file by (indexValidateFile),
//	         which FS-108 holds to refuse what SearchOracle's canonical decoder refuses
//
// Only the sidecar_testhooks build has it, which no release leg is (§22.4). Safe for concurrent use as the world is.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The world's content as a text source: the bytes of a path at an exact entry version, as the push that wrote it wrote
// them. A version the ref never held, or a removal, holds no text.
func (self *SearchTestWorld) textSource(repoId Id, refId Id) SearchTextSource {
	if repoId != self.repoId || refId != self.refId {
		return nil
	}
	return &SearchContentTextSource{
		Content: self.contentOf,
		Place: func(repoId Id) (protocol.RepoKind, bool) {
			return self.kind, false
		},
		Settings: self.format,
	}
}

// The world's content as a text source, as SearchTestDeviceArgs.Text gives one: what a device following several
// worlds' refs answers a ref's documents from (SearchTestNetworkDeviceArgs.Text).
func (self *SearchTestWorld) TextSource() SearchTextSource {
	return self.textSource(self.repoId, self.refId)
}

// See SearchContentTextSource.Content: never a fetch, only what the world's content pushes wrote.
func (self *SearchTestWorld) contentOf(ctx context.Context, repoId Id, refId Id, path []byte, version uint64) ([]byte, bool, error) {
	if repoId != self.repoId || refId != self.refId {
		return nil, false, nil
	}
	ref := self.ref
	ref.stateLock.Lock()
	defer ref.stateLock.Unlock()
	for _, held := range ref.contentVersions[string(path)] {
		if held.version == version && held.content != nil {
			return bytes.Clone(held.content), true, nil
		}
	}
	return nil, false, nil
}

// One index file at the head holding an entry, row or tombstone of a document.
type SearchTestHeld struct {
	Path string
	// The version it holds, and whether that is a full entry or a row rather than a tombstone.
	Version uint64
	Live    bool
}

// Every index file at the head holding an entry, row or tombstone of path's chunk, by file path: where a document's
// versions sit, which FS-107's and FS-108's clauses name (a writer's head, a sealed slot, a large entry, a bucket's or
// all's shard). A file that does not decode is an error.
func (self *SearchTestWorld) FilesHolding(path string, chunk uint32) ([]SearchTestHeld, error) {
	key, err := indexDocKey(self.refKey, self.refId, []byte(path), chunk)
	if err != nil {
		return nil, err
	}
	return searchTestFilesHolding(context.Background(), self.ref.store(Id{}), key, self.format)
}

// Every index file store lists at its head holding an entry, row or tombstone of key, each read whole: what
// FilesHolding answers, for the world's store and for EvsRepo's index store alike.
func searchTestFilesHolding(ctx context.Context, store indexRefStore, key [indexIdByteCount]byte, settings *IndexFormatSettings) ([]SearchTestHeld, error) {
	listing, err := store.List(ctx, 0)
	if err != nil {
		return nil, err
	}
	held := []SearchTestHeld{}
	for _, file := range listing.files {
		parsed, ok := indexParsePath(file.path, false)
		if !ok {
			continue
		}
		switch parsed.kind {
		case indexPathSlot, indexPathLargeEntry, indexPathBucketShard, indexPathAllShard:
		default:
			continue
		}
		plaintext, err := store.Read(ctx, file)
		if err != nil {
			return nil, err
		}
		switch parsed.kind {
		case indexPathSlot, indexPathLargeEntry:
			slot, err := indexDecodeSlot(plaintext, file.contentSha256[:], false, settings)
			if err != nil {
				return nil, err
			}
			for _, entry := range slot.entries {
				if entry.key == key {
					held = append(held, SearchTestHeld{Path: file.path, Version: entry.version, Live: entry.kind == indexEntryFull})
				}
			}
		default:
			shard, err := indexDecodeShard(plaintext, file.contentSha256[:], false)
			if err != nil {
				return nil, err
			}
			for _, document := range shard.documents {
				if document.key == key {
					held = append(held, SearchTestHeld{Path: file.path, Version: document.version, Live: true})
				}
			}
			for _, tombstone := range shard.tombstones {
				if tombstone.key == key {
					held = append(held, SearchTestHeld{Path: file.path, Version: tombstone.version})
				}
			}
		}
	}
	slices.SortFunc(held, func(a SearchTestHeld, b SearchTestHeld) int { return strings.Compare(a.Path, b.Path) })
	return held, nil
}

// Every index file of repo's file-mode ref refName (nil: main) at its head holding an entry, row or tombstone of
// path's chunk 0, read through EvsRepo as every index builder reads it: FilesHolding on real engines.
func SearchTestEvsFilesHolding(ctx context.Context, repo *EvsRepo, refName []byte, path string) ([]SearchTestHeld, error) {
	store := newIndexEvsStore(repo, refName, false)
	refId, err := store.refId(ctx)
	if err != nil {
		return nil, err
	}
	key, err := SearchTestEvsDocKey(ctx, repo, refId, path)
	if err != nil {
		return nil, err
	}
	return searchTestFilesHolding(ctx, store, key, DefaultIndexFormatSettings())
}

// writer's push of tombstones for removed documents, each at its path's chunk 0 and the version it names, planned at
// the head now and not committed, as PlanPush plans live documents: what a companion push carrying a removal, or a
// writer racing another at a bucket boundary, holds (FS-108's skew clause).
func (self *SearchTestWorld) PlanRemovals(ctx context.Context, writer Id, at time.Time, removed []*SearchTestDocument) (*SearchTestPlannedPush, error) {
	pending := []*indexPendingDocument{}
	for _, document := range removed {
		key, err := self.DocKey(document.Path)
		if err != nil {
			return nil, err
		}
		pending = append(pending, &indexPendingDocument{kind: indexEntryTombstone, key: key, version: document.Version})
	}
	view, err := self.view(ctx, writer)
	if err != nil {
		return nil, err
	}
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view: view, root: view.writeRoot(), writer: writer, signedTimeMs: at.UnixMilli(), tables: indexLinkedTables(),
		pending: pending, mayMerge: true,
	})
	if err != nil {
		return nil, err
	}
	if plan.mergeFirst || plan.mergeInPush {
		return nil, errors.New("search test world: a push that merges, which a schedule writes as shards")
	}
	return &SearchTestPlannedPush{store: self.ref.store(writer), push: &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: at.UnixMilli(),
		files: plan.files(), removals: plan.removals(),
	}}, nil
}

// The index's own decoder on plaintext as the index file path names it, the reading a device's sync judges a fetched
// file by (§11.14's verify row; indexValidateFile): nil where it takes the file, its refusal otherwise.
func SearchTestValidateIndexFile(path string, plaintext []byte) error {
	parsed, ok := indexParsePath(path, false)
	if !ok {
		return errors.New("search test world: no index path")
	}
	sum := sha256.Sum256(plaintext)
	_, err := indexValidateFile(parsed, indexBytesFrames(plaintext), sum[:], DefaultIndexFormatSettings())
	return err
}

// One path a DROP drops on the world's ref, as its builder walked the lineage.
type SearchTestDropPath struct {
	Path string
	// The entry versions the DROP lists: the path's versions with an entry below through_version.
	Listed []uint64
	// The version whose full entry stays where it is: at a written boundary the head's, through_version - 1; 0 at a
	// removed boundary, which keeps nothing.
	Kept uint64
}

// What a DROP's index rewrite did.
type SearchTestDrop struct {
	// The ref version its push committed at; 0 where no file held a listed version, so nothing was written.
	Version uint64
	// The files that held a listed version, the heads (R2) and manifests (R3) written again beside them, and the
	// entries, rows and tombstones taken out.
	RewrittenCount int
	HeadCount      int
	ManifestCount  int
	TakenCount     int
	// The index paths it wrote, sorted.
	Paths []string
}

// The index side of a DROP by signer at at (see the file header): built at the head as signer reads it and committed
// at once. ErrSearchTestConflict where a push changed a file it rewrites since; ErrSearchTestIndexEpoch where a CUT did.
func (self *SearchTestWorld) Drop(ctx context.Context, signer Id, at time.Time, paths []*SearchTestDropPath) (*SearchTestDrop, error) {
	dropped := []*indexDroppedPath{}
	for _, path := range paths {
		if path == nil || path.Path == "" {
			return nil, errors.New("search test world: a dropped path without its name")
		}
		listed := slices.Clone(path.Listed)
		slices.Sort(listed)
		dropped = append(dropped, &indexDroppedPath{path: path.Path, listed: slices.Compact(listed), kept: path.Kept})
	}
	view, err := self.view(ctx, signer)
	if err != nil {
		return nil, err
	}
	result, err := indexDropRewrite(ctx, &indexDropRewriteArgs{
		view: view, refKey: self.refKey, paths: dropped, settings: DefaultIndexDropSettings(),
	})
	if err != nil {
		return nil, err
	}
	drop := &SearchTestDrop{
		RewrittenCount: result.rewrittenCount, HeadCount: result.headCount, ManifestCount: result.manifestCount,
		TakenCount: result.takenCount,
	}
	if len(result.files) == 0 {
		return drop, nil
	}
	for _, file := range result.files {
		drop.Paths = append(drop.Paths, file.path)
	}
	committed, err := self.ref.store(signer).Commit(ctx, &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: at.UnixMilli(),
		files: result.files,
	})
	switch {
	case isIndexRefusal(err, indexRefusalConflict):
		return drop, ErrSearchTestConflict
	case isIndexRefusal(err, indexRefusalIndexEpoch):
		return drop, ErrSearchTestIndexEpoch
	case err != nil:
		return drop, err
	}
	drop.Version = committed.version
	return drop, nil
}

// Commits, as writer at at, a slot well formed but for its one entry, of the reserved kind 2 for document's doc_key
// (see the file header): writer's slot 0 in the bucket of at, which must hold no file of writer's. Answers the slot's
// path and the ref version it committed at.
func (self *SearchTestWorld) ForgeReservedKindSlot(ctx context.Context, writer Id, at time.Time, document *SearchTestDocument) (string, uint64, error) {
	prepared, err := self.prepare(document)
	if err != nil {
		return "", 0, err
	}
	view, err := self.view(ctx, writer)
	if err != nil {
		return "", 0, err
	}
	window := indexBucketWindow{startDay: SearchTestBucketStartDay(at), days: indexDefaultWindowDays}
	day := indexDayOf(at.UnixMilli())
	for _, bucket := range view.writeRoot().buckets {
		if bucket.window.holds(day) {
			window = bucket.window
		}
	}
	path, err := self.paths().slot(window.startDay, [indexIdByteCount]byte(writer.Bytes()), 0)
	if err != nil {
		return "", 0, err
	}
	listing, err := self.ref.store(writer).List(ctx, 0)
	if err != nil {
		return "", 0, err
	}
	for _, file := range listing.files {
		if file.path == path {
			return "", 0, errors.New("search test world: the forger's slot is taken")
		}
	}
	// a diff's layout: kind, doc_key, version, time, base version, row, added keys, removed keys
	body := append([]byte{byte(2)}, prepared.key[:]...)
	body = indexAppendVByte(body, document.Version)
	body = indexAppendVByte(body, indexEntrySeconds(at.UnixMilli()))
	body = indexAppendVByte(body, max(document.Version, 1)-1)
	if body, err = prepared.row.appendEncoded(body, false); err != nil {
		return "", 0, err
	}
	if body, err = prepared.keys.appendEncoded(body); err != nil {
		return "", 0, err
	}
	if body, err = (indexKeySet{}).appendEncoded(body); err != nil {
		return "", 0, err
	}
	header := indexNewFileHeader(indexFileSlot, indexLinkedTables())
	header.BucketStartDay = window.startDay
	header.BucketDays = window.days
	header.WriterSidecarId = writer.Bytes()
	header.Seq = 1
	header.Count = 1
	header.BodyLength = uint32(len(body))
	encoded, err := indexMarshalHeader(header)
	if err != nil {
		return "", 0, err
	}
	file := []byte(indexFileMagic)
	file = indexAppendVByte(file, uint64(len(encoded)))
	file = append(file, encoded...)
	file = append(file, body...)
	committed, err := self.ref.store(writer).Commit(ctx, &indexPush{
		pushId: NewId(), baseVersion: view.head.version, indexEpoch: view.head.indexEpoch, signedTimeMs: at.UnixMilli(),
		files: []*indexPushFile{{path: path, plaintext: file}},
	})
	if err != nil {
		return "", 0, searchTestErr(err)
	}
	return path, committed.version, nil
}
