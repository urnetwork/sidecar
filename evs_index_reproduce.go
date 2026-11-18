//go:build !ios_extension

// Reproduction (§11.14's reproduce row; D-EVS-50, D-EVS-56, D-MCP-31, FI-22, FS-75, FS-76; DESIGN-DETAILS 1.2.8, 1.5
// and 7.2.7's step 3; SEARCH-M10-21): a device holding every input of a merge, roll-up or CLOSURE at its push's base
// builds the result itself and compares each new file's content_sha256 with the push's entry version. Equal, it keeps
// its own output and fetches nothing; unequal, it fetches the file and raises index_mismatch {repo, ref, path, signer:
// the push's}; lacking an input it downloads and raises nothing. After a CLOSURE the replaced versions are deleted from
// the cache. A team directory reader holding a writer's previous head and the bucket at the push's base derives the
// writer's next head from the card versions it folds itself (DeriveHead), fetching the head only where it differs, and
// then alarming.
//
//	inputs     the push's base is EvsPush.base_version; the listing there is what the device knows by replay, and the
//	           files are the copies it holds (its cache). A file it does not hold at that version is a lacking input.
//	merge      a push writing b/<S>/m and shards of S and no writer's file: indexMerge over S at the base, absorbing
//	           its sealed slots and unabsorbed large entries (1.2.4), so the new manifest's watermarks and the shards
//	           the push replaces name every input
//	roll-up    a push removing every file of b/<S>/ and writing a/m, the lock at its base held by its signer for S:
//	           indexRollup at the base as its runner, the lock freed, with the runner's coverage reading where one is
//	           given (it must be the runner's, or the head rows differ); a roll-up signed before S's expiry is the
//	           runner rolling early (1.5): every output alarms and is fetched
//	CLOSURE    each shard it rewrites, rebuilt without the erasure's documents and padded to the replaced length
//	           (rewriteWithout, QD-173), keeping the replaced pad generation; a slot or large entry it rewrites is
//	           fetched, SEARCH-M10-17's slot rewrite not being on sidecar, and alarms nothing
//	other      a writer's push, a build, a backfill or a DROP rewrite is fetched; hosts with the text check a writer's
//	           entries (evs_index_check_text.go)
//
// Outputs must not depend on the device: the pad key is K_index_g of the push's own generation, and a device without
// it downloads; the tables are the reproducer's own, and an input whose header names other tables is a lacking input,
// downloaded, since a merge on those tables would write other header bytes. Phones reproduce only in the foreground or
// a background window (mayReproduce), else download.
//
// index_mismatch carries a path, which reaches the sink and is never logged (I-13). No key is created, derived or
// unwrapped here: the pad key comes from the caller. Safe for concurrent use: each call reads its own view.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// An input of a push this device does not hold at the push's base, or a pad key of a generation it lacks: the
	// outputs are downloaded and nothing is raised.
	errIndexReproduceLacking = errors.New("index reproduction lacks an input")
	// A reproducer made without what every reproduction needs.
	errIndexReproducerArgs = errors.New("index reproducer without its format settings or pad keys")
)

// What a push is to a reproducer.
type indexReproduceKind int

const (
	// Not a kind this reproduces: its outputs are fetched.
	indexReproduceNone indexReproduceKind = iota
	indexReproduceMerge
	indexReproduceRollup
	indexReproduceClosure
	// A writer's head derived from a card version (DeriveHead).
	indexReproduceHead
)

// One file a push wrote: its new version, and the version it replaced, 0 for a creation.
type indexReproduceFile struct {
	file     *indexFileVersion
	replaces uint64
}

// One replayed push, as its verified statement and the listings around it give it.
type indexReproducePush struct {
	// The ref version it committed at, and the head it read (EvsPush.base_version).
	version      uint64
	baseVersion  uint64
	signer       Id
	signedTimeMs int64
	// The repo key generation it was sealed under, whose K_index_g pads the shards it writes.
	generation uint64
	// A CLOSURE, and the erasure its note names.
	closure   bool
	erasureId Id
	files     []*indexReproduceFile
	removals  []*indexPushRemoval
}

// What a reproducer reads the index at a push's base from.
type indexReproduceBase struct {
	// Every file at the push's base, as the device knows the listing by replay, with the head as of that version.
	listing *indexListing
	// The plaintext of a file version this device holds, checked against its content_sha256; false where it holds none.
	held func(ctx context.Context, file *indexFileVersion) ([]byte, bool, error)
}

// What a reproducer runs with.
type indexReproducerArgs struct {
	repoId    Id
	refId     Id
	repoKind  protocol.RepoKind
	companion bool
	isAdmin   func(file *indexFileVersion) bool
	format    *IndexFormatSettings
	tables    indexTables
	// K_index_g of a generation; errIndexReproduceLacking, or an error wrapping it, where the device holds none.
	padKeyOf func(ctx context.Context, generation uint64) (*indexPadKey, error)
	// Whether the device may reproduce now: a phone only in the foreground or a background window. Nil always may.
	mayReproduce func() bool
	// The roll-up runner's coverage reading, as the runner's own roller is given it (indexRollerArgs.indexedThrough).
	indexedThrough func(view *indexView, refId []byte) (uint64, bool)
	// index_mismatch's sink (Sidecar.searchEvents); nil drops. The outcome carries each event too.
	events func(event SidecarEvent)
}

// One index ref's reproducer.
type IndexReproducer struct {
	args indexReproducerArgs
}

// A reproducer of one index ref.
func indexNewReproducer(args *indexReproducerArgs) (*IndexReproducer, error) {
	if args == nil || args.format == nil || args.padKeyOf == nil {
		return nil, errIndexReproducerArgs
	}
	return &IndexReproducer{args: *args}, nil
}

// One output reproduced and matched: the plaintext the device keeps as its own.
type indexReproducedFile struct {
	file      *indexFileVersion
	plaintext []byte
}

// What one reproduction did.
type indexReproduceOutcome struct {
	kind indexReproduceKind
	// Matched outputs, which the device caches as its own and does not fetch.
	matched []*indexReproducedFile
	// Outputs to fetch: every one where an input lacks or the kind is not reproduced, else each mismatch.
	fetch []*indexFileVersion
	// A CLOSURE's replaced versions, which the cache deletes.
	replaced []*indexPushRemoval
	// index_mismatch for each output that differs, naming the push's signer.
	events  []SidecarEvent
	lacking bool
}

// A store over what the device holds at a push's base: the listing it knows and the copies it holds. It commits
// nothing.
type indexHeldStore struct {
	base *indexReproduceBase
}

// See indexRefStore.
func (self *indexHeldStore) Head(ctx context.Context) (*indexRefHead, error) {
	return self.base.listing.head, nil
}

// See indexRefStore.
func (self *indexHeldStore) List(ctx context.Context, refVersion uint64) (*indexListing, error) {
	if refVersion != 0 && refVersion != self.base.listing.head.version {
		return nil, errIndexReproduceLacking
	}
	return self.base.listing, nil
}

// See indexRefStore.
func (self *indexHeldStore) History(ctx context.Context, path string, refVersion uint64) ([]*indexFileVersion, error) {
	for _, file := range self.base.listing.files {
		if file.path == path {
			return []*indexFileVersion{file}, nil
		}
	}
	return nil, nil
}

// See indexRefStore.
func (self *indexHeldStore) Read(ctx context.Context, file *indexFileVersion) ([]byte, error) {
	plaintext, held, err := self.base.held(ctx, file)
	if err != nil {
		return nil, err
	}
	if !held {
		return nil, errIndexReproduceLacking
	}
	if sum := sha256.Sum256(plaintext); !bytes.Equal(sum[:], file.contentSha256[:]) {
		return nil, errIndexReproduceLacking
	}
	return plaintext, nil
}

// See indexRefStore.
func (self *indexHeldStore) Commit(ctx context.Context, push *indexPush) (*indexCommitted, error) {
	return nil, errIndexReproduceLacking
}

// The index at the push's base, from what the device holds.
func (self *IndexReproducer) loadBase(ctx context.Context, base *indexReproduceBase) (*indexView, error) {
	return indexLoadView(ctx, &indexViewArgs{
		store:     &indexHeldStore{base: base},
		repoId:    self.args.repoId,
		refId:     self.args.refId,
		repoKind:  self.args.repoKind,
		companion: self.args.companion,
		isAdmin:   self.args.isAdmin,
		settings:  self.args.format,
	})
}

// Every output fetched, nothing raised: a lacking input, a kind not reproduced, or a device that may not reproduce now.
func (self *IndexReproducer) fetchAll(push *indexReproducePush, kind indexReproduceKind, lacking bool) *indexReproduceOutcome {
	outcome := &indexReproduceOutcome{kind: kind, lacking: lacking}
	for _, written := range push.files {
		outcome.fetch = append(outcome.fetch, written.file)
	}
	return outcome
}

// What a push is, from what it writes and removes and the lock at its base: a merge of S, a roll-up of S, a CLOSURE,
// or none; and S.
func indexReproduceKindOf(push *indexReproducePush, root *indexViewRoot, companion bool) (indexReproduceKind, uint32) {
	if push.closure {
		return indexReproduceClosure, 0
	}
	writesAllManifest := false
	writesWriterFile := false
	manifestDays := []uint32{}
	for _, written := range push.files {
		path, ok := indexParsePath(written.file.path, companion)
		if !ok {
			return indexReproduceNone, 0
		}
		switch path.kind {
		case indexPathAllManifest:
			writesAllManifest = true
		case indexPathSlot, indexPathLargeEntry:
			writesWriterFile = true
		case indexPathBucketManifest:
			manifestDays = append(manifestDays, path.bucketStartDay)
		}
	}
	if writesAllManifest && root != nil && root.lock != nil && bytes.Equal(root.lock.HolderSidecarId, push.signer.Bytes()) {
		// a roll-up removes every file of the bucket its runner's lock names
		startDay := root.lock.BucketStartDay
		if bucket := root.bucket(startDay); bucket != nil && 0 < startDay {
			removed := map[string]bool{}
			for _, removal := range push.removals {
				removed[removal.path] = true
			}
			for _, file := range bucket.files() {
				if !removed[file.path] {
					return indexReproduceNone, 0
				}
			}
			return indexReproduceRollup, startDay
		}
	}
	if !writesAllManifest && !writesWriterFile && len(manifestDays) == 1 {
		return indexReproduceMerge, manifestDays[0]
	}
	return indexReproduceNone, 0
}

// Whether the tables a header names are this reproducer's own.
func (self *IndexReproducer) tablesMatch(header *protocol.IndexFileHeader) bool {
	return header.UnicodeVersion == self.args.tables.normVersion && header.TextModuleVersion == self.args.tables.textModuleVersion
}

// Whether every slot and large entry the view read names this reproducer's tables.
func (self *IndexReproducer) viewTablesMatch(view *indexView) bool {
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			for _, writer := range bucket.writers {
				for _, file := range slices.Concat(writer.slots, writer.large) {
					if !self.tablesMatch(file.slot.header) {
						return false
					}
				}
			}
		}
	}
	return true
}

// Reproduces push from what the device holds at its base: see the file header. A store's failure is the error; a
// lacking input or a kind not reproduced fetches every output and raises nothing.
func (self *IndexReproducer) Reproduce(ctx context.Context, push *indexReproducePush, base *indexReproduceBase) (*indexReproduceOutcome, error) {
	if self.args.mayReproduce != nil && !self.args.mayReproduce() {
		return self.fetchAll(push, indexReproduceNone, false), nil
	}
	view, err := self.loadBase(ctx, base)
	if errors.Is(err, errIndexReproduceLacking) {
		return self.fetchAll(push, indexReproduceNone, true), nil
	}
	if err != nil {
		return nil, err
	}
	if view.newerFormat || view.erasureSetUnreadable || !self.viewTablesMatch(view) {
		return self.fetchAll(push, indexReproduceNone, true), nil
	}
	root := view.writeRoot()
	kind, startDay := indexReproduceKindOf(push, root, self.args.companion)
	var built *indexReproduceBuilt
	switch kind {
	case indexReproduceMerge:
		built, err = self.merge(ctx, view, root, push, startDay)
	case indexReproduceRollup:
		built, err = self.rollup(ctx, view, root, push, startDay)
	case indexReproduceClosure:
		built, err = self.closure(ctx, view, root, push)
	default:
		return self.fetchAll(push, kind, false), nil
	}
	if errors.Is(err, errIndexReproduceLacking) {
		return self.fetchAll(push, kind, true), nil
	}
	if err != nil {
		return nil, err
	}
	outcome := self.compare(push, kind, built)
	if kind == indexReproduceClosure {
		for _, written := range push.files {
			if written.replaces != 0 {
				outcome.replaced = append(outcome.replaced, &indexPushRemoval{path: written.file.path, version: written.replaces})
			}
		}
	}
	return outcome, nil
}

// What a reproduction built: each output's plaintext by path, the removals it would make, the outputs it does not
// build, which are fetched with no alarm, and whether the push broke a rule whatever its bytes (a roll-up signed
// early), which alarms every output.
type indexReproduceBuilt struct {
	files     map[string][]byte
	removals  map[string]bool
	unbuilt   map[string]bool
	ruleBroke bool
}

// Each output compared with what was built: matched, or fetched and alarmed; a removal or an output the push left out
// alarms too, naming its path.
func (self *IndexReproducer) compare(push *indexReproducePush, kind indexReproduceKind, built *indexReproduceBuilt) *indexReproduceOutcome {
	outcome := &indexReproduceOutcome{kind: kind}
	mismatched := map[string]bool{}
	alarm := func(path string) {
		if mismatched[path] {
			return
		}
		mismatched[path] = true
		repoId, refId, signer := self.args.repoId, self.args.refId, push.signer
		event := SidecarEvent{Kind: SidecarEventIndexMismatch, RepoId: &repoId, RefId: &refId, Path: path, SidecarId: &signer}
		outcome.events = append(outcome.events, event)
		if self.args.events != nil {
			self.args.events(event)
		}
	}
	pushed := map[string]bool{}
	for _, written := range push.files {
		path := written.file.path
		pushed[path] = true
		if built.unbuilt[path] {
			outcome.fetch = append(outcome.fetch, written.file)
			continue
		}
		plaintext, ok := built.files[path]
		sum := sha256.Sum256(plaintext)
		if !ok || built.ruleBroke || !bytes.Equal(sum[:], written.file.contentSha256[:]) {
			alarm(path)
			outcome.fetch = append(outcome.fetch, written.file)
			continue
		}
		outcome.matched = append(outcome.matched, &indexReproducedFile{file: written.file, plaintext: plaintext})
	}
	paths := []string{}
	for path := range built.files {
		if !pushed[path] {
			paths = append(paths, path)
		}
	}
	removed := map[string]bool{}
	for _, removal := range push.removals {
		removed[removal.path] = true
		if !built.removals[removal.path] && !built.unbuilt[removal.path] {
			paths = append(paths, removal.path)
		}
	}
	for path := range built.removals {
		if !removed[path] {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	for _, path := range paths {
		alarm(path)
	}
	return outcome
}

// The pad key of the push's generation, or a lacking input.
func (self *IndexReproducer) padKey(ctx context.Context, push *indexReproducePush) (*indexPadKey, error) {
	padKey, err := self.args.padKeyOf(ctx, push.generation)
	if err != nil {
		return nil, err
	}
	if padKey == nil {
		return nil, errIndexReproduceLacking
	}
	return padKey, nil
}

// A merge of S at the base, absorbing its sealed slots and unabsorbed large entries.
func (self *IndexReproducer) merge(ctx context.Context, view *indexView, root *indexViewRoot, push *indexReproducePush, startDay uint32) (*indexReproduceBuilt, error) {
	bucket := root.bucket(startDay)
	if bucket == nil {
		return nil, errIndexReproduceLacking
	}
	shards, err := indexDecodeBucketShards(ctx, view, bucket.shards)
	if errors.Is(err, errIndexMergeInputs) {
		return nil, errIndexReproduceLacking
	}
	if err != nil {
		return nil, err
	}
	padKey, err := self.padKey(ctx, push)
	if err != nil {
		return nil, err
	}
	result, err := indexMerge(&indexMergeArgs{
		root:      root,
		bucket:    bucket,
		shards:    shards,
		absorb:    true,
		erased:    view.erased,
		padKey:    padKey,
		tables:    self.args.tables,
		companion: view.companion,
		settings:  view.settings,
	})
	if err != nil {
		return nil, err
	}
	built := &indexReproduceBuilt{files: map[string][]byte{}, removals: map[string]bool{}}
	for _, file := range result.files() {
		built.files[file.path] = file.plaintext
	}
	for _, removal := range result.removedShards {
		built.removals[removal.path] = true
	}
	return built, nil
}

// A roll-up of S at the base, as its runner built it, the lock it held freed; one signed before S's expiry broke R5's
// margin, which alarms whatever its bytes (1.5's runner that rolls early).
func (self *IndexReproducer) rollup(ctx context.Context, view *indexView, root *indexViewRoot, push *indexReproducePush, startDay uint32) (*indexReproduceBuilt, error) {
	expired := root.bucket(startDay)
	listing := view.store.(*indexHeldStore).base.listing
	args := &indexRollupArgs{view: view, root: root, runner: push.signer, signedTimeMs: push.signedTimeMs, tables: self.args.tables}
	bucketPrefix := root.paths.bucket(startDay) + "/"
	for _, file := range listing.files {
		if strings.HasPrefix(file.path, bucketPrefix) {
			args.expiredFiles = append(args.expiredFiles, file)
		}
	}
	decode := func(bucket *indexViewBucket) (*indexRollupBucket, error) {
		shards, err := indexDecodeBucketShards(ctx, view, bucket.shards)
		if errors.Is(err, errIndexMergeInputs) {
			return nil, errIndexReproduceLacking
		}
		if err != nil {
			return nil, err
		}
		return &indexRollupBucket{bucket: bucket, shards: shards}, nil
	}
	var err error
	if args.expired, err = decode(expired); err != nil {
		return nil, err
	}
	for _, bucket := range root.buckets {
		if expired.window.startDay < bucket.window.startDay {
			newer, err := decode(bucket)
			if err != nil {
				return nil, err
			}
			args.newer = append(args.newer, newer)
		}
	}
	if args.allShards, err = indexDecodeBucketShards(ctx, view, root.allShards); errors.Is(err, errIndexMergeInputs) {
		return nil, errIndexReproduceLacking
	} else if err != nil {
		return nil, err
	}
	if self.args.indexedThrough != nil {
		args.indexedThrough = func(refId []byte) (uint64, bool) {
			return self.args.indexedThrough(view, refId)
		}
	}
	if args.padKey, err = self.padKey(ctx, push); err != nil {
		return nil, err
	}
	result, err := indexRollup(ctx, args)
	if err != nil {
		return nil, err
	}
	built := &indexReproduceBuilt{files: map[string][]byte{}, removals: map[string]bool{}}
	for _, file := range result.files {
		built.files[file.path] = file.plaintext
	}
	for _, removal := range result.removals {
		built.removals[removal.path] = true
	}
	free, err := indexLockFreeFile(root, &indexHeldLock{version: root.lockFile.version})
	if err != nil {
		return nil, err
	}
	built.files[free.path] = free.plaintext
	built.ruleBroke = !indexBucketExpiredAt(view, root, expired, push.signedTimeMs)
	return built, nil
}

// A CLOSURE's shard rewrites, each without the erasure's documents and padded to the replaced length; a slot or large
// entry it rewrites is left unbuilt, fetched with no alarm.
func (self *IndexReproducer) closure(ctx context.Context, view *indexView, root *indexViewRoot, push *indexReproducePush) (*indexReproduceBuilt, error) {
	if view.erasureSet == nil {
		return nil, errIndexReproduceLacking
	}
	listed := map[[indexIdByteCount]byte]uint64{}
	found := false
	for _, erasure := range view.erasureSet.Erasures {
		if !bytes.Equal(erasure.ErasureId, push.erasureId.Bytes()) {
			continue
		}
		found = true
		for _, erased := range erasure.Docs {
			if len(erased.DocKey) == indexIdByteCount {
				key := [indexIdByteCount]byte(erased.DocKey)
				listed[key] = max(listed[key], erased.Version)
			}
		}
	}
	if !found {
		return nil, errIndexReproduceLacking
	}
	drop := func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool {
		listedVersion, ok := listed[key]
		return ok && kind != indexEntryRefTombstone && version <= listedVersion
	}
	listing := view.store.(*indexHeldStore).base.listing
	baseFiles := map[string]*indexFileVersion{}
	for _, file := range listing.files {
		baseFiles[file.path] = file
	}
	built := &indexReproduceBuilt{files: map[string][]byte{}, removals: map[string]bool{}, unbuilt: map[string]bool{}}
	builder := indexNewShardBuilder(view.companion)
	for _, written := range push.files {
		path, ok := indexParsePath(written.file.path, view.companion)
		replaced := baseFiles[written.file.path]
		if !ok || replaced == nil || replaced.version != written.replaces ||
			(path.kind != indexPathBucketShard && path.kind != indexPathAllShard) {
			built.unbuilt[written.file.path] = true
			continue
		}
		plaintext, err := view.store.Read(ctx, replaced)
		if err != nil {
			return nil, err
		}
		shard, err := indexDecodeShard(plaintext, replaced.contentSha256[:], view.companion)
		if err != nil {
			return nil, errIndexReproduceLacking
		}
		rewritten, _, err := builder.rewriteWithout(shard, drop, replaced.byteCount)
		if err != nil {
			return nil, err
		}
		built.files[written.file.path] = rewritten
	}
	return built, nil
}

// One card document a writer's push carries, and the version it replaces in the writer's files, 0 for a first.
type indexDeriveDocument struct {
	document *IndexDocument
	replaces uint64
	// A withdrawal's or a revocation's tombstone (§16.11's versions row): the document gives its name and the
	// tombstone's version, and nothing else of it is read.
	tombstone bool
}

// The entries a writer's push carries for derived, in their order: a full entry a document at its version, a tombstone
// for a withdrawal or a revocation and for a document D6 skips. One function for the writer and for every reader that
// derives its head, so both enter the same entries (§11.14's determinism).
func indexDerivePending(derived []*indexDeriveDocument, normalizer *indexNormalizer, refKey []byte, refId Id, companion bool, settings *IndexFormatSettings) ([]*indexPendingDocument, error) {
	pending := []*indexPendingDocument{}
	for _, one := range derived {
		key, err := indexDocKey(refKey, refId, one.document.Name, one.document.Chunk)
		if err != nil {
			return nil, err
		}
		if one.tombstone {
			pending = append(pending, &indexPendingDocument{kind: indexEntryTombstone, key: key, version: one.document.Version})
			continue
		}
		prepared, err := one.document.prepare(normalizer, companion, refId, settings)
		if err != nil {
			return nil, err
		}
		if prepared.skipped {
			pending = append(pending, &indexPendingDocument{kind: indexEntryTombstone, key: key, version: one.document.Version})
			continue
		}
		pending = append(pending, &indexPendingDocument{
			kind: indexEntryFull, key: key, version: one.document.Version, replaces: one.replaces,
			keys: prepared.keys, row: prepared.row,
		})
	}
	return pending, nil
}

// What a team directory reader derives a card writer's next head from (§11.14's reproduce row; §16.11).
type indexDeriveHeadArgs struct {
	// The writer's push: its signer, signed time and the files it wrote, its head among them.
	push *indexReproducePush
	base *indexReproduceBase
	// The card versions the push carries, as the reader's own fold of the log gives them.
	documents []*indexDeriveDocument
	// The content ref the cards are of, and K_ref.
	refId  Id
	refKey []byte
}

// Derives the head a card writer's push wrote, from the writer's files at the push's base and the card versions the
// reader folds itself (§16.11's readers call it): each output compared as Reproduce compares, the head fetched and
// alarmed where it differs, and every output fetched where an input lacks. A head is a function of 1.2.8's inputs, so
// an honest writer's matches.
func (self *IndexReproducer) DeriveHead(ctx context.Context, args *indexDeriveHeadArgs) (*indexReproduceOutcome, error) {
	if self.args.mayReproduce != nil && !self.args.mayReproduce() {
		return self.fetchAll(args.push, indexReproduceHead, false), nil
	}
	view, err := self.loadBase(ctx, args.base)
	if errors.Is(err, errIndexReproduceLacking) {
		return self.fetchAll(args.push, indexReproduceHead, true), nil
	}
	if err != nil {
		return nil, err
	}
	if view.newerFormat || view.erasureSetUnreadable || !self.viewTablesMatch(view) {
		return self.fetchAll(args.push, indexReproduceHead, true), nil
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return nil, err
	}
	pending, err := indexDerivePending(args.documents, normalizer, args.refKey, args.refId, view.companion, view.settings)
	if err != nil {
		return nil, err
	}
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view:         view,
		root:         view.writeRoot(),
		writer:       args.push.signer,
		signedTimeMs: args.push.signedTimeMs,
		tables:       self.args.tables,
		pending:      pending,
	})
	if err != nil {
		return nil, err
	}
	if plan.mergeFirst || plan.mergeInPush {
		// a head the writer could not write by itself is no card push's: fetched, nothing raised
		return self.fetchAll(args.push, indexReproduceHead, true), nil
	}
	built := &indexReproduceBuilt{files: map[string][]byte{}, removals: map[string]bool{}}
	for _, file := range plan.files() {
		built.files[file.path] = file.plaintext
	}
	for _, removal := range plan.removals() {
		built.removals[removal.path] = true
	}
	return self.compare(args.push, indexReproduceHead, built), nil
}
