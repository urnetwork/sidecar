//go:build !ios_extension

// Backfills (§11.14's coverage and devices rows; DESIGN-DETAILS 1.2.6's backfill, 1.2.7's order and 1.2.8's table;
// 1.7's note for SEARCH-M10-12; 15.2.9's backfill row; 16.2.5's search row; QD-209; SEARCH-M10-12): a push still
// unindexed BackfillAge after its commit is indexed into this device's own head, by a device that holds its text, and
// the ref's horizon raised so every writer's pushes up to it read indexed.
//
// The build keeps every builder's order, which is its fence (R5): take t, the push's signed time; read the index at
// its head; read each content ref R's head from evs, the pin p_R, after the index (on a file-mode ref's own index R is
// the index's ref and the pin is the view's base, no second read); build; send within IndexPushLife of t. Then:
//
//	unindexed  R's pushes at or below p_R that coverage counts unindexed (evs_index_coverage.go)
//	h          the highest version at or below p_R such that every unindexed version at or below it is BackfillAge old
//	           at t; it stays below a push this device cannot judge under the prefix rules, and on a record log below
//	           the first version whose run card is blocked (15.2.9)
//	documents  each path whose newest effective change at p_R was made by an unindexed version at or below h: its state
//	           at p_R, its chunks extracted from R's text in one pass, or tombstones at its removal's version; a path
//	           changed again after h, or whose newest change is indexed, is left to that change's own entry (so a
//	           superseded entry is never written); the erasure set's documents and any whose content an ERASE left
//	           unopenable are skipped; a version the device ignores under the repo's prefix rules is never indexed; a
//	           ref DELETE gives a ref tombstone on ur/index; on a record log each run touched gets its card (15.2.9)
//	re-entry   a document whose unabsorbed diff has no base (1.2.9's malformed row; "re-enter a broken chain's
//	           version" in §11.14's chains row as 1.7 rewords it) is entered again from its text at p_R
//	coverage   {R, h, horizon} in every slot the push writes, beside its writer's rows carried forward; on ur/index
//	           also {R, p_R, own} where this device signed no push in (h, p_R] that is still unindexed
//
// A backfill is an index push: it names the head's index_epoch, and a 409 on a path, 409 INDEX_EPOCH, a collected
// input or the life passing rebuilds it from t. A 429 or a quota refusal comes back to the schedule unsent, and a
// push is never sent again as built. A plan with no free slot comes back for the schedule to merge first; a push past
// DirectBytes merges its own entries. Who backfills is the schedule's (indexer_search.go): an indexer serving the
// repo for search, else a desktop or the daemon where none serves it.
//
// Barriers evs.index.backfill.built and .pushed, keyed <repo>/<ref>. No key is created, derived or unwrapped here: K_ref
// comes derived, and doc_keys are MACs under it. A path is this device's own plaintext and goes into no log or
// error's text (I-13). Not safe for concurrent use.

package sidecar

import (
	"cmp"
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A backfill built AttemptCount times, each refused for a change under it: the schedule tries again later.
	errIndexBackfillAttempts = errors.New("index backfill refused at each attempt")
	// A backfiller built without what every backfill needs.
	errIndexBackfillerArgs = errors.New("index backfiller without its store, settings, writer, ref key or content refs")
)

// The backfiller's own times and counts. The push life is the format's (IndexFormatSettings).
type IndexBackfillSettings struct {
	// How long after its commit a push no rule counts indexed waits before a backfill takes it: 10 min (BackfillAge;
	// §11.14's coverage row), long enough for its committer's own companion push. Non-positive takes every unindexed
	// push at once.
	BackfillAge time.Duration
	// Builds of one backfill, the first included, before it gives up on the refusals it rebuilds after: 8, a reading.
	// Non-positive is one.
	AttemptCount int
}

// The backfiller's defaults, a fresh value each call.
func DefaultIndexBackfillSettings() *IndexBackfillSettings {
	return &IndexBackfillSettings{BackfillAge: 10 * time.Minute, AttemptCount: 8}
}

// What a record log's backfill asks of its run cards (DESIGN-DETAILS 15.2.8 and 15.2.9): SEARCH-M10-28's fold. Nil on
// every other ref.
type indexBackfillCards interface {
	// Reads the log's erasure ref from evs, not from a cache, brings the replica to it and applies every ERASE (15.2.9's
	// step 2a). The backfiller calls it before the first card it folds at an index epoch it has not built at.
	ReadErasures(ctx context.Context) error
	// The lowest version of stream refId in (afterVersion, pin] whose run's card is blocked at epoch (15.2.2), else 0.
	BlockedFrom(ctx context.Context, refId Id, afterVersion uint64, pin uint64, epoch uint64) (uint64, error)
	// The card of each run whose newest source entry at pin was created by one of versions: fold(R, r, pin, E) at
	// E * 2^32 + c(R, r, pin), a derived document named run/ || run_id at chunk 0. A run whose fold gives nothing is left
	// out.
	Cards(ctx context.Context, refId Id, versions []uint64, pin uint64, epoch uint64) ([]*IndexDocument, error)
}

// What a backfiller reads its index and its content with.
type indexBackfillArgs struct {
	// The index's ref, I.
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
	// Nil takes DefaultIndexBackfillSettings.
	settings *IndexBackfillSettings
	// The tables the headers name.
	tables indexTables
	// Nil is real time.
	clock Clock
	// This device's sidecar_id, whose head takes the backfill.
	writer Id
	// K_ref, which every doc_key is a MAC under (§11.14's key row).
	refKey []byte
	// The content refs the index covers: on a file-mode ref the ref itself; on ur/index each git-mode ref and stream
	// of the repo this device reads.
	contents []indexContentRef
	// The device's prefix judge for a content ref; nil, or nil for a ref, holds no rule set.
	verdictOf func(refId Id) indexPrefixVerdict
	// Whether the device may merge: desktops, the daemon and indexers (§11.14's devices row).
	mayMerge bool
	// K_index_g at the device's newest generation, for a push past DirectBytes, which merges.
	padKey func(ctx context.Context) (*indexPadKey, error)
	// A record log's run cards, nil on every other ref.
	cards indexBackfillCards
}

// One index ref's backfiller, which the schedule calls each tick.
type IndexBackfiller struct {
	args     indexBackfillArgs
	settings *IndexBackfillSettings
	clock    Clock

	stateLock sync.Mutex
	// Each content ref's indexed_through as last read, the floor of its next reading.
	refIdFloors map[Id]uint64
	// The index epoch at which this device last read the log's erasure ref for its cards, and whether it has.
	cardEpoch     uint64
	cardEpochRead bool
}

var _ indexBackfiller = (*IndexBackfiller)(nil)

// A backfiller of one index ref.
func indexNewBackfiller(args *indexBackfillArgs) (*IndexBackfiller, error) {
	if args.store == nil || args.format == nil || args.writer == (Id{}) || len(args.refKey) == 0 || len(args.contents) == 0 {
		return nil, errIndexBackfillerArgs
	}
	settings := args.settings
	if settings == nil {
		settings = DefaultIndexBackfillSettings()
	}
	backfiller := &IndexBackfiller{args: *args, settings: settings, clock: clockOrReal(args.clock), refIdFloors: map[Id]uint64{}}
	backfiller.args.contents = indexSortContents(args.contents)
	return backfiller, nil
}

// Why a backfill wrote nothing without failing.
type indexBackfillSkip int

const (
	indexBackfillNotSkipped indexBackfillSkip = iota
	// No push is due: every unindexed push is younger than BackfillAge, or none is unindexed.
	indexBackfillSkipNone
	// The index is off.
	indexBackfillSkipOff
)

// What one backfill did for one content ref.
type indexBackfillRef struct {
	refId Id
	// The pin p_R.
	pin uint64
	// Coverage as read at the build.
	coverage *indexCoverage
	// The horizon the push raises the ref to; 0 where nothing was due.
	h uint64
	// The entries the push carries for the ref, re-entries included.
	entryCount int
}

// What one Backfill did.
type indexBackfillOutcome struct {
	committed *indexCommitted
	skipped   indexBackfillSkip
	refs      []*indexBackfillRef
	// The documents entered again for a diff with no base.
	reentered [][indexIdByteCount]byte
	// index_malformed for each file the view alarmed and each diff a merge in the push could not compose.
	events []SidecarEvent
	// Builds, the committed one included.
	attempts int
}

// The schedule's call (indexer_search.go): one backfill of every due content ref.
func (self *IndexBackfiller) Backfill(ctx context.Context) error {
	_, err := self.backfill(ctx)
	return err
}

// The barrier key of this ref: <repo>/<ref>.
func (self *IndexBackfiller) barrierKey() string {
	return self.args.repoId.String() + "/" + self.args.refId.String()
}

// The index at its head.
func (self *IndexBackfiller) loadView(ctx context.Context) (*indexView, error) {
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

// A content ref's floor.
func (self *IndexBackfiller) floor(refId Id) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refIdFloors[refId]
}

// Raises a content ref's floor; never lowers it, since indexed_through never falls while the index is on.
func (self *IndexBackfiller) raiseFloor(refId Id, version uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refIdFloors[refId] = max(self.refIdFloors[refId], version)
}

// Forgets every floor: an index turned off has lost its rows, and the build that turns it on raises new ones.
func (self *IndexBackfiller) clearFloors() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refIdFloors = map[Id]uint64{}
}

// One backfill of every due content ref, rebuilt from t after each refusal it rebuilds after, at most AttemptCount
// builds.
func (self *IndexBackfiller) backfill(ctx context.Context) (*indexBackfillOutcome, error) {
	outcome := &indexBackfillOutcome{}
	for outcome.attempts < max(1, self.settings.AttemptCount) {
		outcome.attempts += 1
		done, err := self.attempt(ctx, outcome)
		if err != nil || done {
			return outcome, err
		}
	}
	return outcome, errIndexBackfillAttempts
}

// One build and its push. Answers whether the backfill is done; false with no error rebuilds it.
func (self *IndexBackfiller) attempt(ctx context.Context, outcome *indexBackfillOutcome) (bool, error) {
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
	outcome.refs = nil
	outcome.reentered = nil
	if view.erasureSetUnreadable {
		return false, errIndexErasureSetUnreadable
	}
	if view.newerFormat {
		return false, errIndexMergeNewerFormat
	}
	root := view.writeRoot()
	if root.off() {
		self.clearFloors()
		outcome.skipped = indexBackfillSkipOff
		return true, nil
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return false, err
	}
	build := &indexBackfillBuild{
		backfiller: self,
		view:       view,
		root:       root,
		signedTime: signedTime,
		normalizer: normalizer,
		refIdPaths: map[Id]map[string]bool{},
	}
	pins := map[Id]uint64{}
	for _, content := range self.args.contents {
		// 3 and 4: R's pin, read after the index, and what is due of it
		ref, err := build.refWork(ctx, content)
		if errors.Is(err, errIndexCollected) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		outcome.refs = append(outcome.refs, ref)
		pins[ref.refId] = ref.pin
	}
	reentered, err := build.reenter(ctx, pins)
	if errors.Is(err, errIndexCollected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	outcome.reentered = reentered
	if len(build.pending) == 0 && len(build.rows) == 0 {
		for _, ref := range outcome.refs {
			self.raiseFloor(ref.refId, ref.coverage.indexedThrough)
		}
		outcome.skipped = indexBackfillSkipNone
		return true, nil
	}

	// 5: the plan, every slot it writes carrying the writer's rows raised to the backfill's
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view:         view,
		root:         root,
		writer:       self.args.writer,
		signedTimeMs: signedTime.UnixMilli(),
		tables:       self.args.tables,
		pending:      build.pending,
		mayMerge:     self.args.mayMerge,
		coverage:     indexRaiseCoverage(indexWriterNewestRows(root, self.args.writer), build.rows),
	})
	if err != nil {
		return false, err
	}
	if plan.mergeFirst {
		return false, errIndexNoFreeSlot
	}
	files, removals := plan.files(), plan.removals()
	if plan.mergeInPush {
		if self.args.padKey == nil {
			return false, errIndexBackfillerArgs
		}
		padKey, err := self.args.padKey(ctx)
		if err != nil {
			return false, err
		}
		var malformed []*indexMalformedDiff
		files, removals, malformed, err = indexMergeHeadPlan(ctx, view, root, plan, padKey, self.args.tables)
		if err != nil {
			return false, indexRerunCollected(err)
		}
		outcome.events = append(outcome.events, indexMalformedEvents(view, malformed)...)
	}
	testHookBarrier("evs.index.backfill.built", self.barrierKey())

	// 6: sent within the push's life
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		return false, err
	}
	push, err := guard.push(indexPushIndex, signedTime.UnixMilli(), files, removals)
	if err != nil {
		return false, err
	}
	committed, err := indexSendPush(ctx, self.args.store, push, signedTime, self.clock, self.args.format.PushLife)
	switch {
	case isIndexRefusal(err, indexRefusalConflict), isIndexRefusal(err, indexRefusalIndexEpoch), errors.Is(err, errIndexPushLifePassed):
		return false, nil
	case err != nil:
		return false, err
	}
	outcome.committed = committed
	for _, ref := range outcome.refs {
		self.raiseFloor(ref.refId, max(ref.coverage.indexedThrough, ref.h))
	}
	testHookBarrier("evs.index.backfill.pushed", self.barrierKey())
	return true, nil
}

// One build's state, across its content refs.
type indexBackfillBuild struct {
	backfiller *IndexBackfiller
	view       *indexView
	root       *indexViewRoot
	signedTime time.Time
	normalizer *indexNormalizer
	// What the index holds of each key, loaded once a document needs it.
	held *indexHeldKeys
	// The entries the push carries, and the coverage rows it raises.
	pending []*indexPendingDocument
	rows    []*protocol.IndexCoverage
	// The paths entered for each content ref, so a re-entry adds none twice.
	refIdPaths map[Id]map[string]bool
}

// What one content ref gives the push: its pin, its coverage, h, and its entries and rows added to the build's.
func (self *indexBackfillBuild) refWork(ctx context.Context, content indexContentRef) (*indexBackfillRef, error) {
	args := &self.backfiller.args
	view := self.view
	refId := content.RefId()
	ref := &indexBackfillRef{refId: refId}
	if !view.companion && refId == view.refId {
		// a file-mode ref's own index: its pin is the base, no second read
		ref.pin = view.head.version
	} else {
		head, err := content.Head(ctx)
		if err != nil {
			return nil, err
		}
		ref.pin = head.version
	}
	var verdict indexPrefixVerdict
	if args.verdictOf != nil {
		verdict = args.verdictOf(refId)
	}
	coverage, err := indexCoverageOf(ctx, &indexCoverageArgs{
		view:       view,
		root:       self.root,
		content:    content,
		verdict:    verdict,
		through:    ref.pin,
		floor:      self.backfiller.floor(refId),
		groupInbox: args.groupInbox,
	})
	if err != nil {
		return nil, err
	}
	ref.coverage = coverage

	// h: every unindexed version at or below it BackfillAge old at t, and none this device cannot judge
	h := ref.pin
	cutoffMs := self.signedTime.UnixMilli() - self.backfiller.settings.BackfillAge.Milliseconds()
	for _, counted := range coverage.pushes {
		if counted.count != indexPushUnindexed {
			continue
		}
		if counted.unjudged || cutoffMs < counted.push.signedTimeMs {
			h = counted.push.version - 1
			break
		}
	}
	cards := args.cards != nil && view.companion
	epoch := view.head.indexEpoch
	if cards {
		blocked, err := args.cards.BlockedFrom(ctx, refId, max(coverage.horizon, self.backfiller.floor(refId)), ref.pin, epoch)
		if err != nil {
			return nil, err
		}
		if blocked != 0 && blocked <= h {
			h = blocked - 1
		}
	}
	due := []*indexCountedPush{}
	for _, counted := range coverage.pushes {
		if counted.count == indexPushUnindexed && counted.push.version <= h {
			due = append(due, counted)
		}
	}
	if len(due) == 0 {
		return ref, nil
	}
	ref.h = h
	entryCount := len(self.pending)

	// 4: each path whose newest effective change at the pin was made by a due version
	versionPushes := map[uint64]*indexCountedPush{}
	for _, counted := range coverage.pushes {
		versionPushes[counted.push.version] = counted
	}
	candidates := map[string]bool{}
	for _, counted := range due {
		for index, change := range counted.push.changes {
			if change.path == "" || indexCoverageExcluded(view, args.groupInbox, change) || (counted.ignored != nil && counted.ignored[index]) {
				continue
			}
			candidates[change.path] = true
		}
	}
	paths := []string{}
	for path := range candidates {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	for _, path := range paths {
		state, err := content.State(ctx, path, ref.pin)
		if err != nil {
			return nil, err
		}
		if state.version == 0 || h < state.commitVersion {
			// never stood, or changed again after h: left to that change's own entry
			continue
		}
		counted := versionPushes[state.commitVersion]
		if counted == nil || counted.count != indexPushUnindexed {
			// its newest change is indexed already, by its committer or below the horizon
			continue
		}
		if indexBackfillIgnoredAt(counted, path) || state.unopenable {
			continue
		}
		if err := self.enter(ctx, refId, path, state); err != nil {
			return nil, err
		}
	}
	// a ref DELETE gives a ref tombstone on ur/index, the newest of the due ones
	if view.companion {
		deleted := uint64(0)
		for _, counted := range due {
			if counted.push.deletesRef {
				deleted = counted.push.version
			}
		}
		if deleted != 0 {
			var key [indexIdByteCount]byte
			copy(key[:], refId.Bytes())
			self.pending = append(self.pending, &indexPendingDocument{kind: indexEntryRefTombstone, key: key, version: deleted})
		}
	}
	// a record log's cards of the runs the due versions touched, folded at the push's epoch after the erasure ref is
	// read at an epoch this device has not built at (15.2.9)
	if cards {
		versions := make([]uint64, 0, len(due))
		for _, counted := range due {
			versions = append(versions, counted.push.version)
		}
		if err := self.backfiller.readErasuresAt(ctx, epoch); err != nil {
			return nil, err
		}
		documents, err := args.cards.Cards(ctx, refId, versions, ref.pin, epoch)
		if err != nil {
			return nil, err
		}
		for _, document := range documents {
			if err := self.enterRegistered(ctx, refId, document); err != nil {
				return nil, err
			}
		}
	}
	ref.entryCount = len(self.pending) - entryCount

	// 5: the horizon at h; on ur/index the writer's own row at the pin, where it signed nothing above h still unindexed
	self.rows = append(self.rows, &protocol.IndexCoverage{RefId: refId.Bytes(), Version: h, Horizon: true})
	if view.companion {
		own := true
		for _, counted := range coverage.pushes {
			if counted.count == indexPushUnindexed && h < counted.push.version && counted.push.signer == args.writer {
				own = false
			}
		}
		if own {
			self.rows = append(self.rows, &protocol.IndexCoverage{RefId: refId.Bytes(), Version: ref.pin, Horizon: false})
		}
	}
	return ref, nil
}

// Whether the change of counted's push to path is one this device ignores under the prefix rules.
func indexBackfillIgnoredAt(counted *indexCountedPush, path string) bool {
	for index, change := range counted.push.changes {
		if change.path == path && counted.ignored != nil && counted.ignored[index] {
			return true
		}
	}
	return false
}

// Reads the log's erasure ref before the first card folded at epoch (15.2.9's step 2a), once an epoch.
func (self *IndexBackfiller) readErasuresAt(ctx context.Context, epoch uint64) error {
	read := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.cardEpochRead && self.cardEpoch == epoch
	}()
	if read {
		return nil
	}
	if err := self.args.cards.ReadErasures(ctx); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cardEpoch, self.cardEpochRead = epoch, true
	return nil
}

// What the index holds of a root's keys, loaded once a build needs it.
func (self *indexBackfillBuild) heldKeys(ctx context.Context) (*indexHeldKeys, error) {
	if self.held == nil {
		held, err := indexLoadHeldKeys(ctx, self.view, self.root)
		if err != nil {
			return nil, err
		}
		self.held = held
	}
	return self.held, nil
}

// Enters path's state at the pin: tombstones for a removal or a binary, else a full entry for each chunk extraction
// gives, a tombstone for a chunk D6 skips where its key was indexed, and tombstones for the chunks past the last that
// the index still holds live (a version with fewer chunks leaves tombstones from its count up).
func (self *indexBackfillBuild) enter(ctx context.Context, refId Id, path string, state *indexContentState) error {
	args := &self.backfiller.args
	settings := self.view.settings
	paths := self.refIdPaths[refId]
	if paths == nil {
		paths = map[string]bool{}
		self.refIdPaths[refId] = paths
	}
	if paths[path] {
		return nil
	}
	paths[path] = true
	held, err := self.heldKeys(ctx)
	if err != nil {
		return err
	}
	name := []byte(path)
	keyOf := func(chunk uint32) ([indexIdByteCount]byte, error) {
		return indexDocKey(args.refKey, refId, name, chunk)
	}
	tombstonesFrom := func(chunk uint32) error {
		for ; ; chunk += 1 {
			key, err := keyOf(chunk)
			if err != nil {
				return err
			}
			if !held.live(key, state.version) {
				return nil
			}
			self.pending = append(self.pending, &indexPendingDocument{kind: indexEntryTombstone, key: key, version: state.version})
		}
	}
	if state.removed {
		return tombstonesFrom(0)
	}
	replaces := uint64(0)
	if 1 < state.version {
		replaces = state.version - 1
	}
	chunkCount := uint32(0)
	take := func(chunk uint32, keys indexKeySet, row *indexRow, skipped bool) error {
		key, err := keyOf(chunk)
		if err != nil {
			return err
		}
		chunkCount = max(chunkCount, chunk+1)
		if skipped {
			if held.live(key, state.version) {
				self.pending = append(self.pending, &indexPendingDocument{kind: indexEntryTombstone, key: key, version: state.version})
			}
			return nil
		}
		self.pending = append(self.pending, &indexPendingDocument{kind: indexEntryFull, key: key, version: state.version, replaces: replaces, keys: keys, row: row})
		return nil
	}
	if state.documents != nil {
		for _, document := range state.documents {
			prepared, err := document.prepare(self.normalizer, self.view.companion, refId, settings)
			if err != nil {
				return err
			}
			if err := take(document.Chunk, prepared.keys, prepared.row, prepared.skipped); err != nil {
				return err
			}
		}
		return tombstonesFrom(chunkCount)
	}
	if state.content == nil {
		return nil
	}
	kind := indexExtractorKind(indexPlace{repoKind: self.view.repoKind, groupInbox: args.groupInbox, path: path})
	streamArgs := &indexStreamArgs{
		template:   &IndexDocument{Kind: kind, Name: name, Version: state.version, Tainted: state.tainted, Outside: state.outside},
		byteCount:  state.byteCount,
		normalizer: self.normalizer,
		companion:  self.view.companion,
		refId:      refId,
		settings:   settings,
		emit: func(document *indexStreamDocument) error {
			return take(document.chunk, document.keys, document.row, document.skipped)
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
		if err := stream.Close(); err != nil {
			return err
		}
		return tombstonesFrom(chunkCount)
	}
	text, err := indexExtractFileStream(streamArgs, state.content)
	if err != nil {
		return err
	}
	if !text {
		// a binary: a version turned binary is a tombstone wherever its key was indexed
		return tombstonesFrom(0)
	}
	return tombstonesFrom(chunkCount)
}

// Enters a registered class's derived document, a run card: a full entry at its own version, or a tombstone where D6
// skips it and its key was indexed.
func (self *indexBackfillBuild) enterRegistered(ctx context.Context, refId Id, document *IndexDocument) error {
	key, err := indexDocKey(self.backfiller.args.refKey, refId, document.Name, document.Chunk)
	if err != nil {
		return err
	}
	prepared, err := document.prepare(self.normalizer, self.view.companion, refId, self.view.settings)
	if err != nil {
		return err
	}
	if prepared.skipped {
		held, err := self.heldKeys(ctx)
		if err != nil {
			return err
		}
		if held.live(key, document.Version) {
			self.pending = append(self.pending, &indexPendingDocument{kind: indexEntryTombstone, key: key, version: document.Version})
		}
		return nil
	}
	self.pending = append(self.pending, &indexPendingDocument{kind: indexEntryFull, key: key, version: document.Version, keys: prepared.keys, row: prepared.row})
	return nil
}

// Enters again, from their text at their ref's pin, the documents whose unabsorbed diff has no base: the key of each
// such diff is matched to a path by the doc_keys a host with the text computes for each path's possible chunks (a
// chunk count past four times the path's bytes over ChunkByteCount no extraction gives, R3). Answers the keys entered.
func (self *indexBackfillBuild) reenter(ctx context.Context, pins map[Id]uint64) ([][indexIdByteCount]byte, error) {
	args := &self.backfiller.args
	baseless := indexBaselessDiffs(self.view, self.root)
	if len(baseless) == 0 {
		return nil, nil
	}
	entered := [][indexIdByteCount]byte{}
	for _, content := range args.contents {
		refId := content.RefId()
		pin := pins[refId]
		matched := []string{}
		err := content.Paths(ctx, pin, func(path string, byteCount uint64) error {
			chunkBound := 4*byteCount/uint64(self.view.settings.ChunkByteCount) + 1
			for chunk := uint64(0); chunk <= chunkBound; chunk += 1 {
				key, err := indexDocKey(args.refKey, refId, []byte(path), uint32(chunk))
				if err != nil {
					return err
				}
				if baseless[key] {
					entered = append(entered, key)
					matched = append(matched, path)
					return nil
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		slices.Sort(matched)
		for _, path := range slices.Compact(matched) {
			state, err := content.State(ctx, path, pin)
			if err != nil {
				return nil, err
			}
			if state.version == 0 || state.unopenable {
				continue
			}
			if err := self.enter(ctx, refId, path, state); err != nil {
				return nil, err
			}
		}
	}
	slices.SortFunc(entered, func(a [indexIdByteCount]byte, b [indexIdByteCount]byte) int {
		return compareIndexKeys(a, b)
	})
	return entered, nil
}

// The keys of root's unabsorbed diffs whose base no other file of their writer's holds (1.2.9's malformed row), less
// those whose base version the erasure set lists, which are excused (15.2.6).
func indexBaselessDiffs(view *indexView, root *indexViewRoot) map[[indexIdByteCount]byte]bool {
	baseless := map[[indexIdByteCount]byte]bool{}
	for _, bucket := range root.buckets {
		for _, writer := range bucket.writers {
			for _, file := range writer.unabsorbed(bucket.absorbedSeq(writer.sidecarId)) {
				if file.path.kind != indexPathSlot {
					continue
				}
				for _, entry := range file.slot.entries {
					if entry.kind != indexEntryDiff || view.erased(entry.key, entry.baseVersion) {
						continue
					}
					if base, _ := indexResolveBase(writer, entry.key, entry.baseVersion, file); base == nil {
						baseless[entry.key] = true
					}
				}
			}
		}
	}
	return baseless
}

// Each key's newest entry over every partition of a root: whether the index holds a document live, as a host with
// the text checks before it writes a tombstone.
type indexHeldKeys struct {
	keyNewests map[[indexIdByteCount]byte]indexHeldKey
}

// A key's newest entry: its version, and whether it is a live version rather than a tombstone.
type indexHeldKey struct {
	version uint64
	live    bool
}

// Reads every bucket's entries and the all partition's rows, a tombstone winning a tie.
func indexLoadHeldKeys(ctx context.Context, view *indexView, root *indexViewRoot) (*indexHeldKeys, error) {
	held := &indexHeldKeys{keyNewests: map[[indexIdByteCount]byte]indexHeldKey{}}
	consider := func(key [indexIdByteCount]byte, version uint64, live bool) {
		newest, ok := held.keyNewests[key]
		if !ok || newest.version < version || (newest.version == version && !live) {
			held.keyNewests[key] = indexHeldKey{version: version, live: live}
		}
	}
	for _, bucket := range root.buckets {
		documents, err := view.bucketDocuments(ctx, bucket)
		if err != nil {
			return nil, err
		}
		for key, entries := range documents.entries {
			for _, entry := range entries {
				switch entry.kind {
				case indexEntryFull, indexEntryDiff:
					consider(key, entry.version, true)
				case indexEntryTombstone:
					consider(key, entry.version, false)
				}
			}
		}
	}
	shards, err := indexDecodeBucketShards(ctx, view, root.allShards)
	if err != nil {
		return nil, err
	}
	for _, shard := range shards {
		for _, document := range shard.documents {
			consider(document.key, document.version, true)
		}
		for _, tombstone := range shard.tombstones {
			if tombstone.kind == indexEntryTombstone {
				consider(tombstone.key, tombstone.version, false)
			}
		}
	}
	return held, nil
}

// Whether the index holds key live at a version below version.
func (self *indexHeldKeys) live(key [indexIdByteCount]byte, version uint64) bool {
	newest, ok := self.keyNewests[key]
	return ok && newest.live && newest.version < version
}

// The content refs a backfiller holds, in ref_id order, so a build visits them alike every time.
func indexSortContents(contents []indexContentRef) []indexContentRef {
	sorted := slices.Clone(contents)
	slices.SortFunc(sorted, func(a indexContentRef, b indexContentRef) int {
		return cmp.Compare(string(a.RefId().Bytes()), string(b.RefId().Bytes()))
	})
	return sorted
}
