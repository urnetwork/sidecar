//go:build !ios_extension

// A DROP's index rewrites (§11.14's drop, holds, limit and writers rows; R-EVS-23, D-EVS-65, FI-19, FS-76, FS-96;
// DESIGN-DETAILS 1.2.3's "who else writes a writer's files" and 1.7's note for SEARCH-M10-18, with full entries only,
// QD-1036; QD-1078; SEARCH-M10-18): a DROP push also rewrites in place, without the listed versions, each index file
// holding a listed version of a dropped path, so a dropped version's postings do not outlive its content.
//
//	listed     a lineage's listed versions are its versions with an entry below through_version (§11.7's action row),
//	           and every chunk of the path's name is a document of it: doc_key(K_ref, ref_id, name, chunk) for each
//	           chunk below ChunkScanCount, the most any version of a file of EvsFileMaxByteCount gives. The kept
//	           version's full entry stays where it is: at a written boundary the head's version, through_version - 1,
//	           whose content the DROP writes again as through_version. Every entry is full (owner decision 584), so
//	           nothing rests on what the rewrite takes and nothing is entered anew
//	files      every slot and large entry of every writer in every bucket, absorbed or not, every bucket shard and every
//	           all shard, under every root (i2 beside i1 during a rebuild), holding an entry, row or tombstone of a
//	           listed version, written again without it at the replaced version's exact length, as erase's rewrite is:
//	           a slot or large entry with zero bytes after its body, a shard by rewriteWithout with the replaced pad
//	           generation (QD-173). A rewrite that would come out longer is refused, never padded short. Each file the
//	           push writes also leaves out what the ref's erasure set lists, as every index push but a CLOSURE must
//	heads      R2: each writer whose file in a bucket the push rewrites has its head there replaced in the same push, as
//	           it stood where nothing in it is taken, so that writer's next push gets 409 and re-applies its entries
//	           (§11.14's writers row)
//	manifests  R3's fence: each bucket whose shards, sealed slots or large entries the push rewrites has its manifest
//	           replaced as it stands, so a merge built before the DROP reruns on the new state. A bucket with no
//	           manifest has none to replace, since a DROP creates no file (QD-1078): a merge creating one from inputs it
//	           read before the DROP may carry a listed version into its first shard, which the backfill below takes out
//	epoch      the rewrites name the head's index_epoch, since a DROP is not a CLOSURE; they write no ?closure=1 upload
//	           and spend no eraser's allowance (owner decision 146). A 409 INDEX_EPOCH, or a 409 naming only the
//	           rewrites' own paths, rebuilds them once under the person's same confirmation, and a second sends the DROP
//	           without them (EVS2-M10-21's loop); the rewrite lands at the DROP's commit, so a cancel loses nothing
//	backfill   a signer not holding the index leaves the rewrite to an indexer serving the repo for search, else the
//	           next capable writer, as a backfill (IndexBackfiller's tick): the content ref names its DROPs, and each
//	           one BackfillAge old has what the index at its head still holds of a listed version rewritten, in an
//	           index push of its own, so a DROP sent without its rewrites, or one a racing merge or roll-up undid, is
//	           mended within 10 min. Searches mask the older versions meanwhile, the newest version of each key winning,
//	           since the kept version's entry or the removal's tombstone is newer than every listed one
//	reproduce  the rewrite is a function of the index at the DROP's base and its lineages, so a host with the text
//	           builds it again and compares (SEARCH-M10-21's reproducer, through indexDropRewrite)
//	holds      a hold keeps the index content that existed at its placement, the versions a rewrite replaces among
//	           it, and never refuses the DROP or pauses an ERASE (§11.14's holds row; owner decision 184): nothing here
//	           reads a hold, and an erasure under one finds the held versions in the ref's history (evs_index_erase.go)
//	limit      at the storage limit or while spent heads ride content pushes and stop with them: a DROP whose rewrites
//	           upload a shard is refused, and goes again once without them, left to the backfill, since a DROP frees
//	           storage and its index must not block it (QD-1088; EVS2-M10-21's loop); a backfill's rewrite comes back to
//	           its schedule unsent and waits, search answering from the partitions as they stand, the listed versions
//	           masked by the kept one
//
// K_ref is derived here, from the repo key as every doc_key is (EvsRepoKey.DeriveKey hooks it); no other key is
// created, derived or unwrapped. Barriers evs.index.drop.built and evs.index.drop.pushed, keyed <repo>:<ref>. A path is
// this device's plaintext and goes into no log or error's text (I-13). Package-level functions are safe for concurrent
// use; a rewriter is too, each call its own view; a backfill's drop state is guarded by its lock.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A DROP's lineage whose listed versions this device did not walk as its body counts them: no rewrite is built from
	// it, and the backfill, or the reproducer, judges it from its own walk.
	errIndexDropLineage = errors.New("index drop lineage that does not count as its body")
	// A backfill's rewrite built AttemptCount times, each refused for a change under it: the schedule tries again.
	errIndexDropAttempts = errors.New("index drop rewrite refused at each attempt")
	// A rewriter made without what every rewrite needs.
	errIndexDropRewriterArgs = errors.New("index drop rewriter without its client, store, admins or settings")
)

// What a DROP's rewrites look for and how often a backfill builds one.
type IndexDropSettings struct {
	// The chunks of a dropped path's name whose doc_keys are looked for in the index: four times EvsFileMaxByteCount over
	// IndexFormatSettings.ChunkByteCount, plus two (8,194), since extractor 1's fields are within four times its input
	// (DESIGN-DETAILS 11's extraction bounds), so no version of a file the format holds gives a chunk past it. One HMAC a
	// chunk a path, some milliseconds a path at the default. Non-positive looks for none, so nothing is rewritten.
	ChunkScanCount int
	// Builds of one backfill's rewrite, the first included, before it gives up on the refusals it rebuilds after, and
	// reads of the index a signer's rewrite makes while pushes move the head under it: 8, as a backfill's own
	// (IndexBackfillSettings.AttemptCount). Non-positive is one.
	AttemptCount int
}

// The defaults, a fresh value each call.
func DefaultIndexDropSettings() *IndexDropSettings {
	format := DefaultIndexFormatSettings()
	return &IndexDropSettings{
		ChunkScanCount: int(4*int64(EvsFileMaxByteCount)/int64(format.ChunkByteCount)) + 2,
		AttemptCount:   8,
	}
}

// One lineage a DROP drops, as this device names it.
type indexDroppedPath struct {
	path string
	// The path versions the DROP lists, ascending: its versions with an entry below through_version.
	listed []uint64
	// The version whose full entry stays where it is: at a written boundary the head's, through_version - 1, whose
	// content the DROP writes again; 0 at a removed boundary, whose standing removal is not listed.
	kept uint64
}

// Whether the DROP lists version of the path and does not keep it.
func (self *indexDroppedPath) takes(version uint64) bool {
	if version == self.kept {
		return false
	}
	_, listed := slices.BinarySearch(self.listed, version)
	return listed
}

// A lineage of a DROP as its builder walked it (EvsDropLineage): its listed versions from the walk, which must count as
// the body does.
func indexDroppedPathOf(lineage *EvsDropLineage) (*indexDroppedPath, error) {
	if lineage == nil || lineage.DropPath == nil {
		return nil, errIndexDropLineage
	}
	through := lineage.DropPath.GetThroughVersion()
	dropped := &indexDroppedPath{path: lineage.Path}
	switch lineage.DropPath.GetBoundary() {
	case EvsDropBoundaryWritten:
		if through == 0 {
			return nil, errIndexDropLineage
		}
		dropped.kept = through - 1
	case EvsDropBoundaryRemoved:
	default:
		return nil, errIndexDropLineage
	}
	for _, version := range lineage.Versions {
		if version.Removed || len(version.EntrySha256) == 0 || through <= version.Version {
			continue
		}
		dropped.listed = append(dropped.listed, version.Version)
	}
	slices.Sort(dropped.listed)
	dropped.listed = slices.Compact(dropped.listed)
	if uint64(len(dropped.listed)) != uint64(lineage.DropPath.GetCount()) {
		return nil, errIndexDropLineage
	}
	return dropped, nil
}

// What a DROP takes out of one ref's index: each doc_key the index holds of a dropped path, with that path.
type indexDropListed struct {
	keyPaths map[[indexIdByteCount]byte]*indexDroppedPath
}

// Whether a rewrite takes an entry, row or tombstone of kind for key at version out: a listed version of a dropped
// path's chunk, but not the kept one. A ref tombstone names a ref, never a document.
func (self *indexDropListed) takes(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
	if kind == indexEntryRefTombstone {
		return false
	}
	path := self.keyPaths[key]
	return path != nil && path.takes(version)
}

// Every key the view's files hold: each writer's entries in every bucket, each bucket shard's and each all shard's
// rows and tombstones, under every root. A shard that does not read is left out, as the view alarms it.
func indexViewKeys(ctx context.Context, view *indexView) (map[[indexIdByteCount]byte]bool, error) {
	heldKeys := map[[indexIdByteCount]byte]bool{}
	shards := func(viewShards []*indexViewShard) error {
		for _, shard := range viewShards {
			decoded, err := view.shard(ctx, shard)
			if err != nil {
				return err
			}
			if decoded == nil {
				continue
			}
			for _, document := range decoded.documents {
				heldKeys[document.key] = true
			}
			for _, tombstone := range decoded.tombstones {
				heldKeys[tombstone.key] = true
			}
		}
		return nil
	}
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			for _, writer := range bucket.writers {
				for _, file := range slices.Concat(writer.slots, writer.large) {
					for _, entry := range file.slot.entries {
						heldKeys[entry.key] = true
					}
				}
			}
			if err := shards(bucket.shards); err != nil {
				return nil, err
			}
		}
		if err := shards(root.allShards); err != nil {
			return nil, err
		}
	}
	return heldKeys, nil
}

// The keys of paths the view holds: each chunk's doc_key under refKey on the view's ref, below ChunkScanCount. A name
// past what a doc_key takes has no document in any index.
func indexNewDropListed(ctx context.Context, view *indexView, refKey []byte, paths []*indexDroppedPath, settings *IndexDropSettings) (*indexDropListed, error) {
	listed := &indexDropListed{keyPaths: map[[indexIdByteCount]byte]*indexDroppedPath{}}
	held, err := indexViewKeys(ctx, view)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		if len(path.listed) == 0 || len(held) == 0 {
			continue
		}
		name := []byte(path.path)
		if indexNameMaxByteCount < len(name) {
			continue
		}
		for chunk := 0; chunk < settings.ChunkScanCount; chunk += 1 {
			key, err := indexDocKey(refKey, view.refId, name, uint32(chunk))
			if err != nil {
				return nil, err
			}
			if held[key] {
				listed.keyPaths[key] = path
			}
		}
	}
	return listed, nil
}

// What one DROP's rewrite writes.
type indexDropRewriteResult struct {
	// In path order, each replacing the version it names at that version's exact length.
	files []*indexPushFile
	// The files that held a listed version, and the heads (R2) and manifests (R3) written again beside them.
	rewrittenCount int
	headCount      int
	manifestCount  int
	// The entries, rows and tombstones of listed versions taken out.
	takenCount int
}

// What a DROP's rewrite is built from: the index at the DROP's base, K_ref, and the DROP's lineages.
type indexDropRewriteArgs struct {
	view     *indexView
	refKey   []byte
	paths    []*indexDroppedPath
	settings *IndexDropSettings
}

// The rewrites of a DROP at args.view: see the file header. A function of the index at the view's version and the
// lineages, so two devices that build it write the same plaintext. An erasure set that does not read, or a file in a
// newer format, leaves nothing known to be safe to write: the rewrite fails closed, and the backfill tries again.
func indexDropRewrite(ctx context.Context, args *indexDropRewriteArgs) (*indexDropRewriteResult, error) {
	view := args.view
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		return nil, err
	}
	listed, err := indexNewDropListed(ctx, view, args.refKey, args.paths, args.settings)
	if err != nil {
		return nil, err
	}
	if view.newerFormat {
		return nil, errIndexMergeNewerFormat
	}
	result := &indexDropRewriteResult{}
	if len(listed.keyPaths) == 0 {
		return result, nil
	}
	// what each file the push writes leaves out: the DROP's listed versions, and what the erasure set lists
	takes := func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
		return listed.takes(kind, key, version) || kind != indexEntryRefTombstone && guard.erased(key, version)
	}
	pathFiles := map[string]*indexPushFile{}
	rewriteShards := func(viewShards []*indexViewShard) (bool, error) {
		rewrote := false
		for _, shard := range viewShards {
			decoded, err := view.shard(ctx, shard)
			if err != nil {
				return false, err
			}
			if decoded == nil {
				continue
			}
			count := indexDropShardTaken(decoded, listed)
			if count == 0 {
				continue
			}
			plaintext, err := indexDropRewriteShard(decoded, shard.file, takes, view.companion)
			if err != nil {
				return false, err
			}
			pathFiles[shard.file.path] = &indexPushFile{path: shard.file.path, plaintext: plaintext, replaces: shard.file.version}
			result.rewrittenCount += 1
			result.takenCount += count
			rewrote = true
		}
		return rewrote, nil
	}
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			// whether a merge's inputs or outputs changed: its shards, sealed slots or large entries (R3)
			mergeInputs := false
			for _, writer := range bucket.writers {
				head := writer.head()
				touched := false
				for _, file := range slices.Concat(writer.slots, writer.large) {
					count := indexDropSlotTaken(file.slot, listed)
					if count == 0 {
						continue
					}
					plaintext, err := indexDropRewriteSlot(file, takes, view.companion, view.settings)
					if err != nil {
						return nil, err
					}
					pathFiles[file.file.path] = &indexPushFile{path: file.file.path, plaintext: plaintext, replaces: file.file.version}
					result.rewrittenCount += 1
					result.takenCount += count
					touched = true
					mergeInputs = mergeInputs || file != head
				}
				if !touched || head == nil || pathFiles[head.file.path] != nil {
					continue
				}
				// R2: the writer's head in the bucket, written again as it stood but for what the erasure set lists
				plaintext, err := indexDropRewriteSlot(head, takes, view.companion, view.settings)
				if err != nil {
					return nil, err
				}
				pathFiles[head.file.path] = &indexPushFile{path: head.file.path, plaintext: plaintext, replaces: head.file.version}
				result.headCount += 1
			}
			rewrote, err := rewriteShards(bucket.shards)
			if err != nil {
				return nil, err
			}
			if (mergeInputs || rewrote) && bucket.manifestFile != nil {
				// R3: the bucket's manifest as it stands, so a merge built before the DROP fails its CAS
				plaintext, err := indexDropManifestAsItStands(bucket.manifest, bucket.manifestFile)
				if err != nil {
					return nil, err
				}
				path := bucket.manifestFile.path
				pathFiles[path] = &indexPushFile{path: path, plaintext: plaintext, replaces: bucket.manifestFile.version}
				result.manifestCount += 1
			}
		}
		if _, err := rewriteShards(root.allShards); err != nil {
			return nil, err
		}
	}
	for _, file := range pathFiles {
		result.files = append(result.files, file)
	}
	slices.SortFunc(result.files, func(a *indexPushFile, b *indexPushFile) int {
		return bytes.Compare([]byte(a.path), []byte(b.path))
	})
	if err := guard.checkFiles(result.files, false); err != nil {
		return nil, err
	}
	return result, nil
}

// The entries of a slot or large entry a DROP's listing takes.
func indexDropSlotTaken(slot *indexSlot, listed *indexDropListed) int {
	count := 0
	for _, entry := range slot.entries {
		if listed.takes(entry.kind, entry.key, entry.version) {
			count += 1
		}
	}
	return count
}

// The rows and tombstones of a shard a DROP's listing takes.
func indexDropShardTaken(shard *indexShard, listed *indexDropListed) int {
	count := 0
	for _, document := range shard.documents {
		if listed.takes(indexEntryFull, document.key, document.version) {
			count += 1
		}
	}
	for _, tombstone := range shard.tombstones {
		if listed.takes(tombstone.kind, tombstone.key, tombstone.version) {
			count += 1
		}
	}
	return count
}

// A slot or large entry written again without what takes takes, its header but for count and body_length as it
// stood, at byteCount, the replaced version's length: zero bytes after the body. The file as it stood must be that
// long, and the rewrite no longer, or it is refused: nothing is padded short, so the size shows nothing.
func indexDropRewriteSlot(file *indexViewSlot, takes indexShardDrop, companion bool, settings *IndexFormatSettings) ([]byte, error) {
	byteCount := file.file.byteCount
	standing, err := indexEncodeSlot(file.slot, companion, settings)
	if err != nil {
		return nil, err
	}
	if len(standing) != byteCount || sha256.Sum256(standing) != file.file.contentSha256 {
		return nil, indexMalformed("a replaced file that is not the length its listing names")
	}
	kept := []*indexEntry{}
	for _, entry := range file.slot.entries {
		if !takes(entry.kind, entry.key, entry.version) {
			kept = append(kept, entry)
		}
	}
	if len(kept) == len(file.slot.entries) {
		// nothing taken: the replaced bytes as they stand
		return standing, nil
	}
	return indexDropSlotTo(&indexSlot{header: file.slot.header, entries: kept}, byteCount, companion, settings)
}

// A slot's entries under header padded with zeros to exactly byteCount, refused where they do not fit in it.
func indexDropSlotTo(slot *indexSlot, byteCount int, companion bool, settings *IndexFormatSettings) ([]byte, error) {
	// the length with no pad, read through a pad of one byte, since an empty large entry is refused without one
	slot.padByteCount = 1
	probe, err := indexEncodeSlot(slot, companion, settings)
	if err != nil {
		return nil, err
	}
	unpaddedByteCount := len(probe) - 1
	if byteCount < unpaddedByteCount {
		return nil, indexMalformed("a rewrite longer than what it replaces")
	}
	slot.padByteCount = byteCount - unpaddedByteCount
	return indexEncodeSlot(slot, companion, settings)
}

// A shard written again without what takes takes at the replaced version's length, by rewriteWithout (the replaced
// pad generation kept, the replaced partition where blocks of 64 do not fit). The shard as it stood must be the
// version its listing names, its length and its hash, or it is refused.
func indexDropRewriteShard(shard *indexShard, file *indexFileVersion, takes indexShardDrop, companion bool) ([]byte, error) {
	builder := indexNewShardBuilder(companion)
	standing, err := builder.encode(shard)
	if err != nil {
		return nil, err
	}
	if len(standing) != file.byteCount || sha256.Sum256(standing) != file.contentSha256 {
		return nil, indexMalformed("a replaced file that is not the length its listing names")
	}
	plaintext, _, err := builder.rewriteWithout(shard, takes, file.byteCount)
	return plaintext, err
}

// A bucket's manifest as it stands, which re-marshals to the bytes its version holds, since a manifest that read is
// canonical.
func indexDropManifestAsItStands(manifest *protocol.IndexManifest, file *indexFileVersion) ([]byte, error) {
	plaintext, err := indexMarshalSmall(manifest)
	if err != nil {
		return nil, err
	}
	if sha256.Sum256(plaintext) != file.contentSha256 {
		return nil, indexMalformed("a manifest that does not marshal to its own bytes")
	}
	return plaintext, nil
}

// What a DROP's rewriter writes with.
type indexDropRewriterArgs struct {
	client *EvsClient
	// The store a ref's own index reads through: the EvsRepo adapter, one a ref.
	store func(repo *EvsRepo, refName []byte) indexRefStore
	// Whether a settings or erasure set version's signer was a repo admin when it signed (indexAclAdmins). Required.
	isAdmin func(repoId Id) func(file *indexFileVersion) bool
	// Whether this device holds the ref's index whole, every bucket and the all partition, as a desktop, the daemon or
	// an indexer does: one that does not leaves the rewrite to the backfill (§11.14's drop row). Nil holds none.
	holdsIndex func(repoId Id, refName []byte) bool
	format     *IndexFormatSettings
	// Nil takes DefaultIndexDropSettings.
	settings *IndexDropSettings
	log      Logger
}

// The EvsDropIndexHook of one client: §11.14's DROP rewrites, built before each DROP push on what the index holds at
// the head. Construct with newIndexDropRewriter; Install sets Hook as the client's DROP index hook.
type IndexDropRewriter struct {
	args     *indexDropRewriterArgs
	settings *IndexDropSettings
}

// A rewriter over args.
func newIndexDropRewriter(args *indexDropRewriterArgs) (*IndexDropRewriter, error) {
	if args == nil || args.client == nil || args.store == nil || args.isAdmin == nil || args.format == nil {
		return nil, errIndexDropRewriterArgs
	}
	copied := *args
	copied.log = loggerOrDefault(args.log)
	settings := args.settings
	if settings == nil {
		settings = DefaultIndexDropSettings()
	}
	return &IndexDropRewriter{args: &copied, settings: settings}, nil
}

// Sets Hook as the client's DROP index hook; the function returned removes it.
func (self *IndexDropRewriter) Install() func() {
	self.args.client.SetDropIndexHook(self.Hook)
	return func() { self.args.client.SetDropIndexHook(nil) }
}

// The rewrites of a DROP push of args' lineages on repo: see the file header. Nil, with no error, leaves them to the
// backfill: outside the format2 gate, in a repo kind no index is written in, on a device that does not hold the index,
// and wherever the index does not read whole or a rewrite cannot be built safely. An error fails the DROP, and is given
// only where the device cannot go on at all: its context ended, or its repo key does not come.
func (self *IndexDropRewriter) Hook(ctx context.Context, repo *EvsRepo, args *EvsDropIndexArgs) (*EvsDropIndexRewrites, error) {
	client := self.args.client
	if args == nil || repo == nil || !client.Format2Admitted() {
		return nil, nil
	}
	refName := args.RefName
	if refName == nil {
		refName = EvsMainRefName
	}
	leave := func(reason string, err error) (*EvsDropIndexRewrites, error) {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err != nil {
			self.args.log.Infof("[index]a DROP's rewrites left to the backfill: %s: %v", reason, err)
		} else {
			self.args.log.Infof("[index]a DROP's rewrites left to the backfill: %s", reason)
		}
		return nil, nil
	}
	repoKind, err := repo.repoKind()
	if err != nil {
		return leave("the repo's kind did not read", err)
	}
	switch repoKind {
	case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_SECRET,
		protocol.RepoKind_REPO_KIND_UNSPECIFIED:
		// no index is written in these (§11.14's never row)
		return nil, nil
	}
	if self.args.holdsIndex == nil || !self.args.holdsIndex(repo.repoId, refName) {
		return leave("this device does not hold the index", nil)
	}
	paths := []*indexDroppedPath{}
	for _, lineage := range args.Lineages {
		dropped, err := indexDroppedPathOf(lineage)
		if err != nil {
			return leave("a lineage", err)
		}
		paths = append(paths, dropped)
	}
	repoKey, err := client.args.Gkm.EnsureWritable(ctx, repo.repoId)
	if err != nil {
		return nil, err
	}
	refKey, err := indexRefKey(repoKey)
	if err != nil {
		return nil, err
	}
	refId, err := repo.RefIdOf(ctx, refName)
	if err != nil {
		return leave("the ref's id", err)
	}
	// the index at one head: a push landing while it is read moves it, and it is read again, AttemptCount times at most
	var view *indexView
	var result *indexDropRewriteResult
	for attempt := 0; ; attempt += 1 {
		view, err = indexLoadView(ctx, &indexViewArgs{
			store: self.args.store(repo, refName), repoId: repo.repoId, refId: refId, repoKind: repoKind,
			isAdmin: self.args.isAdmin(repo.repoId), settings: self.args.format,
		})
		if err == nil {
			result, err = indexDropRewrite(ctx, &indexDropRewriteArgs{view: view, refKey: refKey, paths: paths, settings: self.settings})
		}
		if errors.Is(err, errIndexCollected) && attempt+1 < max(1, self.settings.AttemptCount) {
			continue
		}
		if err != nil {
			return leave("the index did not read whole or the rewrite did not build", err)
		}
		break
	}
	if len(result.files) == 0 {
		return nil, nil
	}
	testHookBarrier("evs.index.drop.built", repo.repoId.String()+":"+refId.String())
	rewrites := &EvsDropIndexRewrites{IndexEpoch: view.head.indexEpoch}
	for _, file := range result.files {
		replaces := file.replaces
		rewrites.Writes = append(rewrites.Writes, &EvsPathWrite{
			Path: file.path, Content: bytes.NewReader(file.plaintext), IfVersion: &replaces,
			Options: &EvsWriteOptions{Reserved: EvsReservedIndex},
		})
	}
	return rewrites, nil
}

// The DROPs of a content ref, as a backfill reads them: what a file-mode ref's reader implements beside
// indexContentRef where it can name a DROP's lineages. A reader that cannot leaves every DROP's rewrite to its signer.
type indexDropContent interface {
	// The DROP pushes committed at ref versions in (afterVersion, throughVersion], oldest first, each that passed this
	// device's checks (EVS2-M10-22's), its lineages as this device names them. A cancelled drop's are as any's: its
	// listed versions' postings were taken out at its commit, and a cancel restores none.
	Drops(ctx context.Context, afterVersion uint64, throughVersion uint64) ([]*indexContentDrop, error)
}

// One committed DROP push of a content ref.
type indexContentDrop struct {
	// The ref version it committed at, and its signed time_ms.
	version      uint64
	signedTimeMs int64
	paths        []*indexDroppedPath
}

// What a backfiller keeps of the DROPs it has looked at (§11.14's drop row): per content ref, the version of the newest
// DROP whose rewrite is done. Safe for concurrent use.
type indexDropBackfill struct {
	settings *IndexDropSettings

	stateLock   sync.Mutex
	refIdFloors map[Id]uint64
}

// A backfill's drop state, on settings (nil for the defaults).
func indexNewDropBackfill(settings *IndexDropSettings) *indexDropBackfill {
	if settings == nil {
		settings = DefaultIndexDropSettings()
	}
	return &indexDropBackfill{settings: settings, refIdFloors: map[Id]uint64{}}
}

// The newest DROP version of refId whose rewrite is done.
func (self *indexDropBackfill) floor(refId Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refIdFloors[refId]
}

// Raises refId's floor; never lowers it.
func (self *indexDropBackfill) raise(refId Id, version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refIdFloors[refId] = max(self.refIdFloors[refId], version)
}

// What one look at a ref's DROPs did.
type indexDropBackfillOutcome struct {
	// The DROPs looked at, and those whose rewrite committed.
	dropCount      int
	committedCount int
	// The pushes that committed.
	committed []*indexCommitted
}

// The backfill's DROP rewrites (§11.14's drop row): on a file-mode ref's own index, each DROP of the ref committed
// since the last look and BackfillAge old at the tick has what the index at its head still holds of a listed version
// rewritten, oldest first. A refusal to wait (429, a quota) or any other error comes back with the floor where it was,
// so the next tick looks again. Nil drops, ur/index, or a content ref that cannot name its DROPs, do nothing.
func (self *IndexBackfiller) backfillDrops(ctx context.Context) (*indexDropBackfillOutcome, error) {
	outcome := &indexDropBackfillOutcome{}
	drops := self.args.drops
	if drops == nil || self.args.companion {
		return outcome, nil
	}
	for _, content := range self.args.contents {
		if content.RefId() != self.args.refId {
			continue
		}
		dropContent, ok := content.(indexDropContent)
		if !ok {
			continue
		}
		head, err := content.Head(ctx)
		if err != nil {
			return outcome, err
		}
		floor := drops.floor(self.args.refId)
		if head.version <= floor {
			continue
		}
		contentDrops, err := dropContent.Drops(ctx, floor, head.version)
		if err != nil {
			return outcome, err
		}
		cutoffMs := self.clock.Now().UnixMilli() - self.settings.BackfillAge.Milliseconds()
		for _, drop := range contentDrops {
			if drop.version <= floor || head.version < drop.version {
				return outcome, fmt.Errorf("%w: a DROP at %d after %d", errIndexContentPushes, drop.version, floor)
			}
			floor = drop.version
			if cutoffMs < drop.signedTimeMs {
				// not BackfillAge old: left to its signer for now, and every later one with it
				break
			}
			outcome.dropCount += 1
			pushed, err := self.rewriteDrop(ctx, drop)
			if err != nil {
				return outcome, err
			}
			if pushed != nil {
				outcome.committedCount += 1
				outcome.committed = append(outcome.committed, pushed)
			}
			drops.raise(self.args.refId, drop.version)
		}
	}
	return outcome, nil
}

// One DROP's rewrite of what the index at its head still holds, in an index push of its own naming the head's epoch:
// rebuilt from the signed time after a 409, a 409 INDEX_EPOCH, a collected input or the push's life passing. Nil where
// nothing is left to take.
func (self *IndexBackfiller) rewriteDrop(ctx context.Context, drop *indexContentDrop) (*indexCommitted, error) {
	settings := self.args.drops.settings
	for attempt := 0; attempt < max(1, settings.AttemptCount); attempt += 1 {
		signedTime := self.clock.Now()
		view, err := self.loadView(ctx)
		if errors.Is(err, errIndexCollected) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result, err := indexDropRewrite(ctx, &indexDropRewriteArgs{view: view, refKey: self.args.refKey, paths: drop.paths, settings: settings})
		if errors.Is(err, errIndexCollected) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(result.files) == 0 {
			return nil, nil
		}
		guard, err := indexNewEpochGuard(view)
		if err != nil {
			return nil, err
		}
		push, err := guard.push(indexPushIndex, signedTime.UnixMilli(), result.files, nil)
		if err != nil {
			return nil, err
		}
		testHookBarrier("evs.index.drop.built", self.barrierKey())
		committed, err := indexSendPush(ctx, self.args.store, push, signedTime, self.clock, self.args.format.PushLife)
		switch {
		case isIndexRefusal(err, indexRefusalConflict), isIndexRefusal(err, indexRefusalIndexEpoch), errors.Is(err, errIndexPushLifePassed):
			continue
		case err != nil:
			return nil, err
		}
		testHookBarrier("evs.index.drop.pushed", self.barrierKey())
		return committed, nil
	}
	return nil, errIndexDropAttempts
}
