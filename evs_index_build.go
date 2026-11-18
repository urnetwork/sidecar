//go:build !ios_extension

// Index builds (§11.14's on, rebuild and site loss rows; R-EVS-21, R-EVS-24, D-EVS-43, D-EVS-61, FS-72, FS-79;
// DESIGN-DETAILS 1.2.6's backfill as 1.7's note for SEARCH-M10-15 takes it; SEARCH-M10-15): a device holding the text
// writes a ref's whole index from its content at a pin, under the roll-up's lock. A build is a trailing push (R5) and
// keeps every builder's order: take t, the push's signed time; read the index at its head; take the lock; read each
// content ref R's head from evs, the pin p_R, after the index (a file-mode ref's own index pins its view's base, with
// no second read); build; send within IndexPushLife of t. What one push writes:
//
//	documents  each path standing at p_R in its effective version (16.2.5), extracted in one pass, one full entry a
//	           chunk, its time the signed time of the content push that made the version (QD-689's reading 5); the
//	           never row's paths, D6's skipped chunks, an unopenable version and every document the erasure set lists
//	           at or above its version are left out; a record log's run cards are folded at the push's epoch (15.2.9)
//	latest     a document whose time falls in the window holding t, or the one before it, goes into that bucket's
//	           shards through indexMerge, the documents as its extra and nothing absorbed
//	all        an older one goes into all's shards through layout, a/m naming them, with the window before the
//	           previous one as rolled through (a reading: every older window is in all)
//	head       the builder's own head in the bucket of t carries {R, h_R, horizon true} for each content ref, h_R being
//	           the pin, or one below a record log's first blocked card, so every push up to it reads indexed
//	rest       every other file of the root at the push's base goes, every writer's heads included, so R2 holds with
//	           nothing more: a writer whose head went gets 409 and plans again on the built root. The settings stay,
//	           since only an admin writes them, and the lock is freed in the same push
//
// The build is a function of the view at its base, the content at the pins, its signed time, the builder and the pad
// key, and two builders of one pin write equal shards and manifests (take and the tie order give that); only each
// builder's own head differs, by its writer. One build runs at a time a root, by the lock's CAS.
//
// "on" after an admin turned the index on, the build that ends a migration to format 2 (FirstBuild, EVS2-M10-30's
// clause), `ur evs index rebuild` and a site-loss rebuild from the text all run Build: each writes the root whole. A
// rebuild under a new normalizer or format writes .ur-index/i2 beside i1 and then removes i1; this build has one
// normalizer and one format, so it rebuilds the root it reads in place, and the i2 form waits for a second.
//
// Refusals: a 409 on a path or INDEX_EPOCH, a collected input or the life passing reruns from the read with the lock
// held, renewed at LockRenewAfter; a 409 on the lock stops the build (errIndexLockLost). A 429 and a quota refusal come
// back unsent, since a build adds payload and waits at the storage limit, and the lock lapses. An index in a newer
// format is never written over: errIndexBuildNewerFormat, status update. Config, mailcfg and secret repos hold no
// index: errIndexBuildExcluded.
//
// Barriers evs.index.build.locked, .built and .pushed, keyed <repo>:<ref>. No key is created, derived or unwrapped
// here: K_ref comes derived, doc_keys are MACs under it, and the pad key comes from the caller. A path is this device's
// own plaintext and goes into no log or error's text (I-13). Not safe for concurrent use.
//
// Memory: this draft holds every document's key set and row in RAM until the push is built, and reads every push of a
// content ref to learn its versions' times, where QD-641 asks an app host for a sorted run in storage.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A builder made without what every build needs.
	errIndexBuilderArgs = errors.New("index builder without its store, settings, pad key, builder, ref key or content refs")
	// A build refused AttemptCount times after its lock, each for a change under it: its lock lapses, and a later call
	// tries again.
	errIndexBuildAttempts = errors.New("index build refused at each attempt")
	// The ref holds an index in a newer format or normalizer than this build writes: never written over (status
	// update).
	errIndexBuildNewerFormat = errors.New("index in a newer format than this build writes")
	// A config, mailcfg or secret repo, which holds no index (§11.14's never row).
	errIndexBuildExcluded = errors.New("index build in a repo that holds no index")
	// Two documents of one doc_key in one build: a content reader gave a path twice.
	errIndexBuildDocumentTwice = errors.New("index build holds a document twice")
)

// The builder's own times and counts. The lock's term and grace and the push life are the format's
// (IndexFormatSettings).
type IndexBuilderSettings struct {
	// Builds of one build after its lock, the first included, before it gives up on the refusals it reruns: 8, a
	// reading. Non-positive is one.
	AttemptCount int
	// From a lock's take or renewal to its next renewal, while the build works: 15 min, half of LockTerm's 30 (§11.14's
	// lock row).
	LockRenewAfter time.Duration
}

// The builder's defaults, a fresh value each call.
func DefaultIndexBuilderSettings() *IndexBuilderSettings {
	return &IndexBuilderSettings{AttemptCount: 8, LockRenewAfter: 15 * time.Minute}
}

// What a builder reads its index and its content with.
type indexBuilderArgs struct {
	// The index's ref.
	store    indexRefStore
	repoId   Id
	refId    Id
	repoKind protocol.RepoKind
	// ur/index, whose content refs are the repo's git-mode refs and streams.
	companion bool
	// A general repo laid out as a group inbox (§15.7).
	groupInbox bool
	isAdmin    func(file *indexFileVersion) bool
	format     *IndexFormatSettings
	// Nil takes DefaultIndexBuilderSettings.
	settings *IndexBuilderSettings
	// The tables the headers name.
	tables indexTables
	// Nil is real time.
	clock Clock
	// This device's sidecar_id: the lock's holder, whose head carries the horizon rows.
	builder Id
	// K_ref, which every doc_key is a MAC under (§11.14's key row).
	refKey []byte
	// Every content ref the index covers, which this device must hold the text of: on a file-mode ref the ref itself;
	// on ur/index each git-mode ref and stream of the repo. A ref left out loses its entries at the build, and its
	// pushes read unindexed until a backfill covers them.
	contents []indexContentRef
	// K_index_g at the device's newest generation, which pads every shard.
	padKey func(ctx context.Context) (*indexPadKey, error)
	// A record log's run cards, nil on every other ref (evs_index_record.go).
	cards indexBackfillCards
}

// One index ref's builder.
type IndexBuilder struct {
	args     indexBuilderArgs
	settings *IndexBuilderSettings
	clock    Clock
}

// A builder of one index ref.
func indexNewBuilder(args *indexBuilderArgs) (*IndexBuilder, error) {
	if args == nil || args.store == nil || args.format == nil || args.padKey == nil || args.builder == (Id{}) ||
		len(args.refKey) == 0 || len(args.contents) == 0 {
		return nil, errIndexBuilderArgs
	}
	settings := args.settings
	if settings == nil {
		settings = DefaultIndexBuilderSettings()
	}
	builder := &IndexBuilder{args: *args, settings: settings, clock: clockOrReal(args.clock)}
	builder.args.contents = indexSortContents(args.contents)
	return builder, nil
}

// Why a build wrote nothing without failing.
type indexBuildSkip int

const (
	indexBuildNotSkipped indexBuildSkip = iota
	// The index is off: an admin's settings say so.
	indexBuildSkipOff
	// Another builder or roller holds the lock and has not lapsed.
	indexBuildSkipLocked
)

// What one content ref gave a build.
type indexBuildRef struct {
	refId Id
	// The pin p_R, and the horizon the build raises the ref to: the pin, or one below a record log's first blocked
	// card.
	pin     uint64
	horizon uint64
	// The entries the build wrote for the ref.
	entryCount int
}

// What one Build did.
type indexBuildOutcome struct {
	committed *indexCommitted
	skipped   indexBuildSkip
	refs      []*indexBuildRef
	plan      *indexBuildPlan
	// index_malformed for each file the view alarmed.
	events []SidecarEvent
	// Builds after the lock, the committed one included.
	attempts int
	lock     *indexHeldLock
}

// The barrier key of this ref: <repo>:<ref>, an opaque id with no slash (testhook.go; I-13).
func (self *IndexBuilder) barrierKey() string {
	return self.args.repoId.String() + ":" + self.args.refId.String()
}

// The ref's index at its head.
func (self *IndexBuilder) loadView(ctx context.Context) (*indexView, error) {
	return indexLoadView(ctx, &indexViewArgs{
		store:     self.args.store,
		repoId:    self.args.repoId,
		refId:     self.args.refId,
		repoKind:  self.args.repoKind,
		companion: self.args.companion,
		isAdmin:   self.args.isAdmin,
		settings:  self.args.format,
	})
}

// The build that ends a migration to storage format 2 (§23; FS-72, FS-79; EVS2-M10-30's clause): a migrated ref's
// index is empty, since format 1 wrote none, and this writes it whole, as an admin's "on" does.
func (self *IndexBuilder) FirstBuild(ctx context.Context) (*indexBuildOutcome, error) {
	return self.Build(ctx)
}

// One build of the ref's root: the lock taken, then built and committed with the lock freed, rerun with the lock held
// after each refusal it reruns, at most AttemptCount builds.
func (self *IndexBuilder) Build(ctx context.Context) (*indexBuildOutcome, error) {
	outcome := &indexBuildOutcome{}
	if indexRepoExcluded(self.args.repoKind) {
		return outcome, errIndexBuildExcluded
	}
	lockTime := self.clock.Now()
	view, err := self.loadView(ctx)
	if err != nil {
		return outcome, err
	}
	outcome.events = view.events()
	if view.erasureSetUnreadable {
		return outcome, errIndexErasureSetUnreadable
	}
	if view.newerFormat {
		return outcome, errIndexBuildNewerFormat
	}
	root := view.writeRoot()
	if root.off() {
		outcome.skipped = indexBuildSkipOff
		return outcome, nil
	}
	held, err := indexTakeLock(ctx, self.args.store, view, root, self.args.builder, 0, lockTime, self.clock)
	if errors.Is(err, errIndexLockHeld) {
		outcome.skipped = indexBuildSkipLocked
		return outcome, nil
	}
	if err != nil {
		return outcome, err
	}
	outcome.lock = held
	testHookBarrier("evs.index.build.locked", self.barrierKey())
	for outcome.attempts < max(1, self.settings.AttemptCount) {
		outcome.attempts += 1
		done, err := self.attempt(ctx, outcome)
		if err != nil || done {
			return outcome, err
		}
	}
	return outcome, errIndexBuildAttempts
}

// One build after the lock and its push. Answers whether the build is done; false with no error reruns it.
func (self *IndexBuilder) attempt(ctx context.Context, outcome *indexBuildOutcome) (bool, error) {
	// 1: the push's signed time, before any read
	signedTime := self.clock.Now()
	// 2: the index at its head
	view, err := self.loadView(ctx)
	if errors.Is(err, errIndexCollected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	outcome.events = view.events()
	if view.erasureSetUnreadable {
		return false, errIndexErasureSetUnreadable
	}
	if view.newerFormat {
		return false, errIndexBuildNewerFormat
	}
	root := view.writeRoot()
	if root.off() {
		outcome.skipped = indexBuildSkipOff
		return true, nil
	}
	if indexLockRenewDue(outcome.lock, signedTime.UnixMilli(), self.settings.LockRenewAfter) {
		renewed, err := indexRenewLock(ctx, self.args.store, view, root, outcome.lock, signedTime, self.clock)
		if err != nil {
			return false, err
		}
		outcome.lock = renewed
		return false, nil
	}
	if !indexLockHeldBy(root, outcome.lock, signedTime.UnixMilli()) {
		return false, errIndexLockLost
	}
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		return false, err
	}
	// the normalizer is the linked build's, as every extraction's; the headers name args.tables
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return false, err
	}

	// 3 and 4: each content ref's pin, read after the index, and its documents there
	outcome.refs = nil
	entries := []*indexEntry{}
	rows := []*protocol.IndexCoverage{}
	for _, content := range self.args.contents {
		ref, refEntries, err := self.collect(ctx, view, normalizer, content, signedTime)
		if errors.Is(err, errIndexCollected) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		outcome.refs = append(outcome.refs, ref)
		entries = append(entries, refEntries...)
		if 0 < ref.horizon {
			rows = append(rows, &protocol.IndexCoverage{RefId: ref.refId.Bytes(), Version: ref.horizon, Horizon: true})
		}
	}
	listing, err := self.args.store.List(ctx, view.head.version)
	if errors.Is(err, errIndexCollected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	padKey, err := self.args.padKey(ctx)
	if err != nil {
		return false, err
	}

	// 5: the root written whole
	plan, err := indexPlanBuild(ctx, &indexBuildPlanArgs{
		view:         view,
		root:         root,
		listing:      listing,
		entries:      entries,
		rows:         rows,
		builder:      self.args.builder,
		signedTimeMs: signedTime.UnixMilli(),
		padKey:       padKey,
		tables:       self.args.tables,
	})
	if err != nil {
		return false, err
	}
	outcome.plan = plan
	testHookBarrier("evs.index.build.built", self.barrierKey())

	// 6: sent within the push's life, the lock freed in it
	free, err := indexLockFreeFile(root, outcome.lock)
	if err != nil {
		return false, err
	}
	files := append(slices.Clone(plan.files), free)
	slices.SortFunc(files, func(a *indexPushFile, b *indexPushFile) int {
		return cmp.Compare(a.path, b.path)
	})
	push, err := guard.push(indexPushIndex, signedTime.UnixMilli(), files, plan.removals)
	if err != nil {
		return false, err
	}
	committed, err := indexSendPush(ctx, self.args.store, push, signedTime, self.clock, self.args.format.PushLife)
	switch {
	case indexRefusalNamesLock(err, root):
		return false, errIndexLockLost
	case isIndexRefusal(err, indexRefusalConflict), isIndexRefusal(err, indexRefusalIndexEpoch), errors.Is(err, errIndexPushLifePassed):
		return false, nil
	case err != nil:
		return false, err
	}
	outcome.committed = committed
	testHookBarrier("evs.index.build.pushed", self.barrierKey())
	return true, nil
}

// One content ref's pin and its documents there, as full entries.
func (self *IndexBuilder) collect(ctx context.Context, view *indexView, normalizer *indexNormalizer, content indexContentRef, signedTime time.Time) (*indexBuildRef, []*indexEntry, error) {
	refId := content.RefId()
	ref := &indexBuildRef{refId: refId}
	if !view.companion && refId == view.refId {
		// a file-mode ref's own index: its pin is the base, no second read
		ref.pin = view.head.version
	} else {
		head, err := content.Head(ctx)
		if err != nil {
			return nil, nil, err
		}
		ref.pin = head.version
	}
	ref.horizon = ref.pin
	if ref.pin == 0 {
		return ref, nil, nil
	}
	// each version's time is its content push's signed time (QD-689's reading 5)
	pushes, err := content.Pushes(ctx, 0, ref.pin)
	if err != nil {
		return nil, nil, err
	}
	versionTimeMs := map[uint64]int64{}
	for _, push := range pushes {
		versionTimeMs[push.version] = push.signedTimeMs
	}
	paths := []string{}
	err = content.Paths(ctx, ref.pin, func(path string, byteCount uint64) error {
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)

	extractor := &indexBuildExtractor{
		view:       view,
		normalizer: normalizer,
		refId:      refId,
		refKey:     self.args.refKey,
		groupInbox: self.args.groupInbox,
	}
	for _, path := range paths {
		if indexExcluded(indexPlace{repoKind: view.repoKind, groupInbox: self.args.groupInbox, path: path}) {
			continue
		}
		state, err := content.State(ctx, path, ref.pin)
		if err != nil {
			return nil, nil, err
		}
		if state.version == 0 || state.removed || state.unopenable {
			continue
		}
		timeMs, ok := versionTimeMs[state.commitVersion]
		if !ok {
			// a version whose push the reader did not give takes the build's own time, which places it no older
			timeMs = signedTime.UnixMilli()
		}
		if err := extractor.extract(path, state, timeMs); err != nil {
			return nil, nil, err
		}
	}

	// a record log's run cards, folded at the push's epoch after the log's erasure ref is read (15.2.9); a blocked card
	// holds the horizon below it, and the backfill takes what lies above
	if self.args.cards != nil && view.companion {
		epoch := view.head.indexEpoch
		if err := self.args.cards.ReadErasures(ctx); err != nil {
			return nil, nil, err
		}
		blocked, err := self.args.cards.BlockedFrom(ctx, refId, 0, ref.pin, epoch, view.erasureSet)
		if err != nil {
			return nil, nil, err
		}
		if blocked != 0 {
			ref.horizon = blocked - 1
		}
		versions := make([]uint64, 0, len(pushes))
		for _, push := range pushes {
			versions = append(versions, push.version)
		}
		cards, err := self.args.cards.Cards(ctx, refId, versions, ref.pin, epoch, view.erasureSet)
		if err != nil {
			return nil, nil, err
		}
		for _, card := range cards {
			if err := extractor.registered(card, signedTime.UnixMilli()); err != nil {
				return nil, nil, err
			}
		}
	}
	ref.entryCount = len(extractor.entries)
	return ref, extractor.entries, nil
}

// One content ref's extraction into full entries: a build's, and a host's check of another writer's entries against
// its own text (evs_index_check_text.go).
type indexBuildExtractor struct {
	view       *indexView
	normalizer *indexNormalizer
	refId      Id
	// K_ref, which every doc_key is a MAC under.
	refKey     []byte
	groupInbox bool
	// Whether a listed document is kept: a check compares what the text gives, erased or not.
	keepErased bool
	entries    []*indexEntry
}

// Adds a full entry for a chunk D6 keeps and the erasure set does not list.
func (self *indexBuildExtractor) take(name []byte, chunk uint32, version uint64, timeMs int64, keys indexKeySet, row *indexRow, skipped bool) error {
	if skipped {
		// the root is written whole, so a chunk D6 skips needs no tombstone: nothing of it stays
		return nil
	}
	key, err := indexDocKey(self.refKey, self.refId, name, chunk)
	if err != nil {
		return err
	}
	if !self.keepErased && self.view.erased(key, version) {
		return nil
	}
	self.entries = append(self.entries, &indexEntry{
		kind:        indexEntryFull,
		key:         key,
		version:     version,
		timeSeconds: indexEntrySeconds(timeMs),
		row:         row,
		keys:        keys,
	})
	return nil
}

// Extracts path's version at the pin: a registered class's documents as its source gives them, else the message or
// file in one pass, a binary giving nothing.
func (self *indexBuildExtractor) extract(path string, state *indexContentState, timeMs int64) error {
	view := self.view
	settings := view.settings
	name := []byte(path)
	if state.documents != nil {
		for _, document := range state.documents {
			if err := self.registered(document, timeMs); err != nil {
				return err
			}
		}
		return nil
	}
	if state.content == nil {
		return nil
	}
	kind := indexExtractorKind(indexPlace{repoKind: view.repoKind, groupInbox: self.groupInbox, path: path})
	streamArgs := &indexStreamArgs{
		template:   &IndexDocument{Kind: kind, Name: name, Version: state.version, Tainted: state.tainted, Outside: state.outside},
		byteCount:  state.byteCount,
		normalizer: self.normalizer,
		companion:  view.companion,
		refId:      self.refId,
		settings:   settings,
		emit: func(document *indexStreamDocument) error {
			return self.take(name, document.chunk, state.version, timeMs, document.keys, document.row, document.skipped)
		},
	}
	if kind == IndexDocMail {
		stream := indexExtractMailStream(streamArgs)
		block := make([]byte, settings.ExtractReadByteCount)
		for offset := int64(0); offset < int64(state.byteCount); {
			byteCount, err := state.content.ReadAt(block[:min(int64(len(block)), int64(state.byteCount)-offset)], offset)
			if 0 < byteCount {
				if _, err := stream.Write(block[:byteCount]); err != nil {
					return err
				}
				offset += int64(byteCount)
			}
			if err != nil && !(errors.Is(err, io.EOF) && offset == int64(state.byteCount)) {
				return err
			}
		}
		return stream.Close()
	}
	// a binary gives nothing, which on a root written whole is its removal
	_, err := indexExtractFileStream(streamArgs, state.content)
	return err
}

// Enters a registered class's document, a record entry or a run card, at its own name, chunk and version.
func (self *indexBuildExtractor) registered(document *IndexDocument, timeMs int64) error {
	prepared, err := document.prepare(self.normalizer, self.view.companion, self.refId, self.view.settings)
	if err != nil {
		return err
	}
	return self.take(document.Name, document.Chunk, document.Version, timeMs, prepared.keys, prepared.row, prepared.skipped)
}

// What one build writes, all of it at the build's base.
type indexBuildPlanArgs struct {
	view *indexView
	// The root the build writes, as the base holds it.
	root *indexViewRoot
	// Every file the ref lists at the base, which the build replaces or removes under its root.
	listing *indexListing
	// The documents, full entries each at its content push's time, one a doc_key.
	entries []*indexEntry
	// The horizon rows the builder's head carries.
	rows         []*protocol.IndexCoverage
	builder      Id
	signedTimeMs int64
	padKey       *indexPadKey
	tables       indexTables
}

// One build's push but the lock: the root written whole.
type indexBuildPlan struct {
	// In path order, each under its path's CAS at the base.
	files []*indexPushFile
	// Every other file of the root at the base, but its settings and its lock.
	removals []*indexPushRemoval
	// The documents each bucket took, by start day, and all's.
	bucketCounts map[uint32]int
	allCount     int
}

// The files the build writes but its own head and the lock: its buckets' shards and manifests and all's shards and
// a/m, which two builders of one pin write alike.
func (self *indexBuildPlan) contentFiles(builder Id, companion bool) []*indexPushFile {
	files := []*indexPushFile{}
	for _, file := range self.files {
		path, ok := indexParsePath(file.path, companion)
		if ok && (path.kind == indexPathSlot || path.kind == indexPathLargeEntry) && path.writerSidecarId == [indexIdByteCount]byte(builder.Bytes()) {
			continue
		}
		files = append(files, file)
	}
	return files
}

// The build's plan: the documents placed by their times into the window of the push's signed time, the one before it
// or all; each bucket built by indexMerge and all by layout, as from an empty root; the builder's head with the rows;
// and every file the base lists under the root replaced or removed, but the settings and the lock. A pure function of
// its arguments.
func indexPlanBuild(ctx context.Context, args *indexBuildPlanArgs) (*indexBuildPlan, error) {
	view, root := args.view, args.root
	settings := view.settings
	if view.erasureSetUnreadable {
		return nil, errIndexErasureSetUnreadable
	}
	// the root as the build leaves it: its counted settings, nothing else
	fresh := &indexViewRoot{number: root.number, paths: root.paths, settings: root.settings, settingsFile: root.settingsFile}
	windowDays := fresh.windowDays(view.repoKind)
	current, _ := indexBucketFor(nil, windowDays, args.signedTimeMs)
	previous := indexBucketWindow{}
	if windowDays <= current.startDay {
		previous = indexBucketWindow{startDay: current.startDay - windowDays, days: windowDays}
	}

	entries := slices.Clone(args.entries)
	slices.SortFunc(entries, func(a *indexEntry, b *indexEntry) int {
		return compareIndexKeys(a.key, b.key)
	})
	plan := &indexBuildPlan{bucketCounts: map[uint32]int{}}
	bucketEntries := map[uint32][]*indexEntry{}
	allEntries := []*indexLayoutEntry{}
	for index, entry := range entries {
		if 0 < index && entries[index-1].key == entry.key {
			return nil, errIndexBuildDocumentTwice
		}
		if entry.kind != indexEntryFull || view.erased(entry.key, entry.version) {
			continue
		}
		day := indexDayOf(int64(entry.timeSeconds) * 1000)
		switch {
		case current.startDay <= day:
			bucketEntries[current.startDay] = append(bucketEntries[current.startDay], entry)
		case previous.days != 0 && previous.startDay <= day:
			bucketEntries[previous.startDay] = append(bucketEntries[previous.startDay], entry)
		default:
			allEntries = append(allEntries, indexMergeCandidateOf(entry, indexMergeFromExtra).layoutEntry())
		}
	}

	files := []*indexPushFile{}
	startDays := []uint32{}
	for startDay := range bucketEntries {
		startDays = append(startDays, startDay)
	}
	slices.Sort(startDays)
	for _, startDay := range startDays {
		window := current
		if startDay != current.startDay {
			window = previous
		}
		merged, err := indexMerge(&indexMergeArgs{
			root:      fresh,
			bucket:    &indexViewBucket{window: window},
			extra:     bucketEntries[startDay],
			erased:    view.erased,
			padKey:    args.padKey,
			tables:    args.tables,
			companion: view.companion,
			settings:  settings,
		})
		if err != nil {
			return nil, err
		}
		files = append(files, merged.files()...)
		plan.bucketCounts[startDay] = len(bucketEntries[startDay])
	}

	slices.SortFunc(allEntries, indexCompareLayoutEntries)
	laid, err := indexLayout(&indexLayoutArgs{
		root:     fresh,
		fileType: indexFileAllShard,
		keepDocument: func(document *indexShardDocument) bool {
			return true
		},
		keepTombstone: func(tombstone *indexShardTombstone) bool {
			return false
		},
		appended:  allEntries,
		padKey:    args.padKey,
		tables:    args.tables,
		companion: view.companion,
		settings:  settings,
	})
	if err != nil {
		return nil, err
	}
	for _, file := range laid.files {
		files = append(files, &indexPushFile{path: file.path.String(), plaintext: file.file})
	}
	plan.allCount = len(allEntries)
	rolledThrough := uint32(0)
	if previous.days != 0 && windowDays <= previous.startDay {
		rolledThrough = previous.startDay - windowDays
	}
	allManifest, err := indexEncodeManifest(&protocol.IndexManifest{Shards: laid.manifestShards, RolledThroughDay: rolledThrough}, true)
	if err != nil {
		return nil, err
	}
	files = append(files, &indexPushFile{path: fresh.paths.allManifest(), plaintext: allManifest})

	// the builder's head in the bucket of t, carrying the horizon rows
	head, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view:         view,
		root:         fresh,
		writer:       args.builder,
		signedTimeMs: args.signedTimeMs,
		tables:       args.tables,
		coverage:     indexRaiseCoverage(nil, args.rows),
	})
	if err != nil {
		return nil, err
	}
	files = append(files, head.files()...)

	// every file the base lists under the root: replaced where the build writes its path, else removed, but the
	// settings, which only an admin writes, and the lock, which the build's push frees
	rootPrefix := root.paths.root + "/"
	listed := map[string]uint64{}
	for _, file := range args.listing.files {
		if strings.HasPrefix(file.path, rootPrefix) && file.path != root.paths.settings() && file.path != root.paths.lock() {
			listed[file.path] = file.version
		}
	}
	for _, file := range files {
		if version, ok := listed[file.path]; ok {
			file.replaces = version
			delete(listed, file.path)
		}
	}
	slices.SortFunc(files, func(a *indexPushFile, b *indexPushFile) int {
		return cmp.Compare(a.path, b.path)
	})
	for path, version := range listed {
		plan.removals = append(plan.removals, &indexPushRemoval{path: path, version: version})
	}
	slices.SortFunc(plan.removals, func(a *indexPushRemoval, b *indexPushRemoval) int {
		return cmp.Compare(a.path, b.path)
	})
	plan.files = files
	return plan, nil
}
