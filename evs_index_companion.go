//go:build !ios_extension

// Companion pushes (§11.14's companion row, §11.11's index row; R-EVS-21, D-EVS-49, FI-18, FS-74, FS-108; DESIGN-DETAILS
// 1.2.6's companion build, 1.2.7's fences and 1.7's note for SEARCH-M10-14; SEARCH-M10-14): for git-mode refs and
// record streams the index rides ur/index, where each committer publishes what its journal owes in a head of its own.
//
// A build, whose order is its fence (R5):
//
//	1 t = now, the push's signed time, taken before any read
//	2 ur/index's head from evs: base b, index_epoch, the erasure set, the writer's own files in the bucket of t; units
//	  journaled below the set's listed_since lose their key sets, extracted again below (the epoch guard)
//	3 for each content ref with a committed unit, its head read from evs, never a cache: the pin p_R
//	4 due: every committed unit with c <= p_R; per doc_key the unit with the highest c gives the document, dropped
//	  when superseded (R at p_R holds its path at a higher version or removed at a higher one, or R was deleted or
//	  re-created since), covered (a horizon row for R at the base is at or above c), erased (the erasure set lists it
//	  at or above its version) or ignored (EVS1-M6-04's judge ignores the unit's push under the repo's prefix
//	  rules, DESIGN-DETAILS 16.7's scope note); a ref DELETE gives a ref tombstone, the newest of a ref
//	5 plan(b, this writer, t, the documents left, coverage) (1.2.3), coverage the rows of this writer's newest head
//	  with {R, p_R, horizon false} for each R of step 3, raised even where every unit was dropped, so an ignored or
//	  superseded push stops reading as unindexed
//	6 sent within IndexPushLife of t: on its commit every due unit leaves; on 409 for a path, 409 INDEX_EPOCH, a 429
//	  or the life passing, the units are committed again and the build starts over at step 1, never resending a
//	  push as built
//
// Cadence (QD-511): a build at most once a Search.CompanionInterval while a unit is committed, at once when the
// committed units' entries would fill the writer's head, and before the device sleeps or exits (Flush). A build that
// leaves nothing and raises no row sends nothing, since a push of ur/index is charged to the content it indexes
// (§11.13). A unit whose put the bound stripped is extracted again from R's text at p_R, or dropped to be backfilled.
//
// Not here: a record log's card markers, step 2a's erasure-ref read at a new epoch, and again units (DESIGN-DETAILS
// 15.2.9), which wait on SEARCH-M10-28's cards; a sent unit whose outcome a restart cannot settle by push id returns to
// committed and is published again, its entries the same versions. Barriers evs.index.companion.built and .pushed,
// keyed <repo>/<ref>. Safe for concurrent use: one build at a time.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A build refused CompanionAttemptCount times: its units stay committed for the next.
	errIndexCompanionRefused = errors.New("index companion push refused")
	// A push past DirectBytes merges in the push, which pads under K_index_g, and no key source was given.
	errIndexCompanionPadKey = errors.New("index companion push merging with no pad key")
)

// What a companion builder builds with.
type indexCompanionArgs struct {
	journal *IndexJournal
	// ur/index's store, and the content refs its units name, by ref_id.
	store    indexRefStore
	contents func(refId Id) indexContentRef
	// EVS1-M6-04's judge for a content ref; nil judges nothing ignored.
	prefixVerdict func(refId Id) indexPrefixVerdict
	repoId        Id
	indexRefId    Id
	repoKind      protocol.RepoKind
	writer        Id
	isAdmin       func(file *indexFileVersion) bool
	tables        indexTables
	mayMerge      func() bool
	// K_index_g of the generation a merge inside the push pads under; nil refuses such a push, which waits.
	padKey   func(ctx context.Context) (*indexPadKey, error)
	refKey   []byte
	settings *SidecarSearchSettings
	format   *IndexFormatSettings
	clock    Clock
	log      Logger
}

// One repo's companion builder. Construct with newIndexCompanion.
type IndexCompanion struct {
	args *indexCompanionArgs
	// One build at a time.
	buildLock sync.Mutex

	stateLock  sync.Mutex
	lastPushAt time.Time
	dueNow     bool
}

// A builder over args.
func newIndexCompanion(args *indexCompanionArgs) (*IndexCompanion, error) {
	if args == nil || args.journal == nil || args.store == nil || args.contents == nil || args.isAdmin == nil ||
		args.settings == nil || args.format == nil || args.writer == (Id{}) {
		return nil, fmt.Errorf("%w: a companion needs its journal, store, contents, admins and settings", ErrSearchCacheArgs)
	}
	if args.settings.CompanionInterval <= 0 || args.settings.CompanionAttemptCount <= 0 {
		return nil, fmt.Errorf("%w: the companion's settings", ErrSearchCacheArgs)
	}
	copied := *args
	copied.clock = clockOrReal(args.clock)
	copied.log = loggerOrDefault(args.log)
	return &IndexCompanion{args: &copied}, nil
}

// The barrier key of ur/index: <repo>/<ref>.
func (self *IndexCompanion) barrierKey() string {
	return self.args.repoId.String() + "/" + self.args.indexRefId.String()
}

// Journals a unit (IndexJournal.Committed), and makes a build due at once when the committed units' entries would
// fill the writer's head.
func (self *IndexCompanion) Committed(unit *indexJournalUnit) error {
	if err := self.args.journal.Committed(unit); err != nil {
		return err
	}
	byteCount := 0
	err := self.args.journal.each(func(held *indexJournalUnit) (bool, error) {
		if held.state != indexJournalCommitted {
			return true, nil
		}
		for _, document := range held.documents {
			entry := &indexEntry{kind: indexEntryTombstone, key: document.key, version: document.version}
			if !document.remove && !document.refTombstone && document.keys != nil {
				entry = &indexEntry{kind: indexEntryFull, key: document.key, version: document.version, row: document.row, keys: document.keys}
			}
			encoded, err := entry.appendEncoded(nil, true, self.args.format)
			if err != nil {
				return false, err
			}
			byteCount += len(encoded)
		}
		return byteCount < self.args.format.SlotMaxByteCount, nil
	})
	if err != nil {
		return err
	}
	if self.args.format.SlotMaxByteCount <= byteCount {
		self.stateLock.Lock()
		self.dueNow = true
		self.stateLock.Unlock()
	}
	return nil
}

// Whether a unit is committed.
func (self *IndexCompanion) pending() (bool, error) {
	found := false
	err := self.args.journal.each(func(unit *indexJournalUnit) (bool, error) {
		found = unit.state == indexJournalCommitted
		return !found, nil
	})
	return found, err
}

// Builds when one is due: a committed unit and a CompanionInterval since the last push, or at once when the head
// would fill. Answers whether it built.
func (self *IndexCompanion) Tick(ctx context.Context) (bool, error) {
	pending, err := self.pending()
	if err != nil || !pending {
		return false, err
	}
	self.stateLock.Lock()
	due := self.dueNow || self.lastPushAt.IsZero() || !self.args.clock.Now().Before(self.lastPushAt.Add(self.args.settings.CompanionInterval))
	self.stateLock.Unlock()
	if !due {
		return false, nil
	}
	return true, self.build(ctx)
}

// Builds now if any unit is committed: before the device sleeps or exits.
func (self *IndexCompanion) Flush(ctx context.Context) error {
	pending, err := self.pending()
	if err != nil || !pending {
		return err
	}
	return self.build(ctx)
}

// When the next build is due, the zero time for none pending.
func (self *IndexCompanion) NextDue() (time.Time, error) {
	pending, err := self.pending()
	if err != nil || !pending {
		return time.Time{}, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.dueNow || self.lastPushAt.IsZero() {
		return self.args.clock.Now(), nil
	}
	return self.lastPushAt.Add(self.args.settings.CompanionInterval), nil
}

// One build, started over after each refusal it rebuilds after, at most CompanionAttemptCount times.
func (self *IndexCompanion) build(ctx context.Context) error {
	self.buildLock.Lock()
	defer self.buildLock.Unlock()
	for attempt := 0; attempt < self.args.settings.CompanionAttemptCount; attempt += 1 {
		done, err := self.attempt(ctx)
		if err != nil || done {
			return err
		}
	}
	return fmt.Errorf("%w: refused %d times", errIndexCompanionRefused, self.args.settings.CompanionAttemptCount)
}

// A content ref's work in one build.
type indexCompanionRef struct {
	content indexContentRef
	pin     uint64
	verdict indexPrefixVerdict
}

// One build and its push: true when done, false with no error to build again.
func (self *IndexCompanion) attempt(ctx context.Context) (bool, error) {
	args := self.args
	// 1: the push's signed time, before any read
	signedTime := args.clock.Now()
	// 2: ur/index at its head
	view, err := indexLoadView(ctx, &indexViewArgs{
		store: args.store, repoId: args.repoId, refId: args.indexRefId, repoKind: args.repoKind, companion: true,
		isAdmin: args.isAdmin, settings: args.format,
	})
	if errors.Is(err, errIndexCollected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	guard, err := indexNewEpochGuard(view)
	if err != nil {
		return false, err
	}
	if view.newerFormat {
		return false, errIndexMergeNewerFormat
	}
	root := view.writeRoot()
	// units begun below the set's listed_since are extracted again from the text, or dropped (the epoch guard)
	if _, err := guard.rebuildJournal(args.journal); err != nil {
		return false, err
	}
	units, err := args.journal.units()
	if err != nil {
		return false, err
	}
	committed := []*indexJournalUnit{}
	for _, unit := range units {
		if unit.state == indexJournalCommitted {
			committed = append(committed, unit)
		}
	}
	if root.off() {
		// an index turned off holds nothing to publish; the build that turns it on indexes from the text
		seqs := []uint64{}
		for _, unit := range committed {
			seqs = append(seqs, unit.seq)
		}
		return true, args.journal.remove(seqs)
	}
	// 3: each content ref's pin, read after the index
	refs := map[Id]*indexCompanionRef{}
	refIds := []Id{}
	for _, unit := range committed {
		if refs[unit.refId] != nil {
			continue
		}
		content := args.contents(unit.refId)
		if content == nil {
			continue
		}
		head, err := content.Head(ctx)
		if err != nil {
			return false, err
		}
		ref := &indexCompanionRef{content: content, pin: head.version}
		if args.prefixVerdict != nil {
			ref.verdict = args.prefixVerdict(unit.refId)
		}
		refs[unit.refId] = ref
		refIds = append(refIds, unit.refId)
	}
	slices.SortFunc(refIds, func(a Id, b Id) int { return compareIndexKeys(a, b) })
	// 4: what is due, and what of it leaves unpublished
	horizons := indexCompanionHorizons(root)
	due := []*indexJournalUnit{}
	dropped := []uint64{}
	newest := map[[indexIdByteCount]byte]*indexCompanionDocument{}
	refTombstones := map[Id]*indexJournalDocument{}
	// the normalizer is this build's; the headers name args.tables, as a backfill's do
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return false, err
	}
	for _, unit := range committed {
		ref := refs[unit.refId]
		if ref == nil || ref.pin < unit.version {
			continue
		}
		due = append(due, unit)
		if horizon := horizons[unit.refId]; unit.version <= horizon {
			// covered: a backfill indexed that push, or found it superseded
			dropped = append(dropped, unit.seq)
			continue
		}
		ignored, err := self.ignored(ctx, ref, unit)
		if err != nil {
			return false, err
		}
		if ignored {
			// a version this device ignores is indexed by no one; the row raised below counts its push
			dropped = append(dropped, unit.seq)
			continue
		}
		for _, document := range unit.documents {
			if document.refTombstone {
				refId := Id(document.key)
				if held := refTombstones[refId]; held == nil || held.version < document.version {
					refTombstones[refId] = document
				}
				continue
			}
			if held := newest[document.key]; held == nil || held.unit.version < unit.version {
				newest[document.key] = &indexCompanionDocument{unit: unit, document: document}
			}
		}
	}
	pending := []*indexPendingDocument{}
	keys := [][indexIdByteCount]byte{}
	for key := range newest {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareIndexKeys)
	for _, key := range keys {
		held := newest[key]
		document, unit := held.document, held.unit
		ref := refs[unit.refId]
		if guard.erased(document.key, document.version) {
			continue
		}
		state, err := ref.content.State(ctx, document.name, ref.pin)
		if err != nil {
			return false, err
		}
		if state.version != document.version || state.removed != document.remove {
			// superseded at the pin: the newer version is its own committer's, or a backfill's
			continue
		}
		pendingDocument, err := self.pendingOf(ctx, unit, document, state, normalizer)
		if err != nil {
			return false, err
		}
		if pendingDocument != nil {
			pending = append(pending, pendingDocument)
		}
	}
	for refId, document := range refTombstones {
		pending = append(pending, &indexPendingDocument{kind: indexEntryRefTombstone, key: [indexIdByteCount]byte(refId), version: document.version})
	}
	// 5: the plan, every slot it writes carrying the writer's rows raised to the pins
	rows := []*protocol.IndexCoverage{}
	for _, refId := range refIds {
		rows = append(rows, &protocol.IndexCoverage{RefId: refId.Bytes(), Version: refs[refId].pin})
	}
	ownRows := indexWriterNewestRows(root, args.writer)
	coverage := indexRaiseCoverage(ownRows, rows)
	if len(pending) == 0 && indexCoverageEqual(ownRows, coverage) {
		// nothing to publish and no row to raise: nothing sent, the units' versions already covered
		return true, args.journal.remove(append(dropped, indexUnitSeqs(due)...))
	}
	plan, err := indexPlanHead(ctx, &indexHeadPlanArgs{
		view: view, root: root, writer: args.writer, signedTimeMs: signedTime.UnixMilli(), tables: args.tables,
		pending: pending, mayMerge: args.mayMerge != nil && args.mayMerge(), coverage: coverage,
	})
	if err != nil {
		return false, err
	}
	if plan.mergeFirst {
		return false, errIndexNoFreeSlot
	}
	files, removals := plan.files(), plan.removals()
	if plan.mergeInPush {
		if args.padKey == nil {
			return false, errIndexCompanionPadKey
		}
		padKey, err := args.padKey(ctx)
		if err != nil {
			return false, err
		}
		files, removals, _, err = indexMergeHeadPlan(ctx, view, root, plan, padKey, args.tables)
		if err != nil {
			return false, indexRerunCollected(err)
		}
	}
	testHookBarrier("evs.index.companion.built", self.barrierKey())
	// 6: sent within the push's life, its units sent until the outcome is known
	push, err := guard.push(indexPushIndex, signedTime.UnixMilli(), files, removals)
	if err != nil {
		return false, err
	}
	seqs := indexUnitSeqs(due)
	if err := args.journal.setState(seqs, indexJournalSent, push.pushId); err != nil {
		return false, err
	}
	_, err = indexSendPush(ctx, args.store, push, signedTime, args.clock, args.format.PushLife)
	switch {
	case isIndexRefusal(err, indexRefusalConflict), isIndexRefusal(err, indexRefusalIndexEpoch),
		isIndexRefusal(err, indexRefusalRetry), errors.Is(err, errIndexPushLifePassed):
		// committed again, and built again from step 1: a push refused TIME_AHEAD is never resent as built
		return false, args.journal.setState(seqs, indexJournalCommitted, Id{})
	case err != nil:
		if stateErr := args.journal.setState(seqs, indexJournalCommitted, Id{}); stateErr != nil {
			return false, stateErr
		}
		return false, err
	}
	if err := args.journal.remove(append(dropped, seqs...)); err != nil {
		return false, err
	}
	self.stateLock.Lock()
	self.lastPushAt = args.clock.Now()
	self.dueNow = false
	self.stateLock.Unlock()
	testHookBarrier("evs.index.companion.pushed", self.barrierKey())
	return true, nil
}

// The unit giving one doc_key's document in a build.
type indexCompanionDocument struct {
	unit     *indexJournalUnit
	document *indexJournalDocument
}

// Whether EVS1-M6-04's judge ignores the unit's push under the repo's prefix rules: one call a unit.
func (self *IndexCompanion) ignored(ctx context.Context, ref *indexCompanionRef, unit *indexJournalUnit) (bool, error) {
	if ref.verdict == nil {
		return false, nil
	}
	pushes, err := ref.content.Pushes(ctx, unit.version-1, unit.version)
	if err != nil || len(pushes) == 0 {
		return false, err
	}
	push := pushes[0]
	for _, change := range push.changes {
		verdict, err := ref.verdict(ctx, push, change)
		if err != nil {
			return false, err
		}
		if verdict.Outcome == AclPrefixIgnored {
			return true, nil
		}
	}
	return false, nil
}

// One due document as the plan takes it: a put's entry as the journal holds it, or extracted again from R's text at
// the pin where the bound stripped it; a removal's tombstone. Nil for a stripped put whose text the device cannot read,
// which a backfill covers.
func (self *IndexCompanion) pendingOf(ctx context.Context, unit *indexJournalUnit, document *indexJournalDocument, state *indexContentState, normalizer *indexNormalizer) (*indexPendingDocument, error) {
	replaces := uint64(0)
	if 1 < document.version {
		replaces = document.version - 1
	}
	if document.remove {
		return &indexPendingDocument{kind: indexEntryTombstone, key: document.key, version: document.version}, nil
	}
	if document.keys != nil {
		return &indexPendingDocument{kind: indexEntryFull, key: document.key, version: document.version, replaces: replaces, keys: document.keys, row: document.row}, nil
	}
	if state.content == nil {
		return nil, nil
	}
	var found *indexPendingDocument
	kind := indexExtractorKind(indexPlace{repoKind: self.args.repoKind, path: document.name})
	streamArgs := &indexStreamArgs{
		template:   &IndexDocument{Kind: kind, Name: []byte(document.name), Version: document.version, Tainted: state.tainted, Outside: state.outside},
		byteCount:  state.byteCount,
		normalizer: normalizer,
		companion:  true,
		refId:      unit.refId,
		settings:   self.args.format,
		emit: func(extracted *indexStreamDocument) error {
			if extracted.chunk == document.chunk && !extracted.skipped {
				found = &indexPendingDocument{kind: indexEntryFull, key: document.key, version: document.version, replaces: replaces, keys: extracted.keys, row: extracted.row}
			}
			return nil
		},
	}
	if kind == IndexDocMail {
		return nil, nil
	}
	if _, err := indexExtractFileStream(streamArgs, state.content); err != nil {
		return nil, err
	}
	return found, nil
}

// The highest horizon row for each content ref over every slot of the root at the base: a backfill's (§11.14's
// coverage row).
func indexCompanionHorizons(root *indexViewRoot) map[Id]uint64 {
	horizons := map[Id]uint64{}
	for _, bucket := range root.buckets {
		for _, writer := range bucket.writers {
			for _, slot := range slices.Concat(writer.slots, writer.large) {
				for _, row := range slot.slot.header.Coverage {
					refId, err := IdFromBytes(row.RefId)
					if err == nil && row.Horizon {
						horizons[refId] = max(horizons[refId], row.Version)
					}
				}
			}
		}
	}
	return horizons
}

// Whether two coverage row lists say the same.
func indexCoverageEqual(a []*protocol.IndexCoverage, b []*protocol.IndexCoverage) bool {
	return slices.EqualFunc(a, b, func(x *protocol.IndexCoverage, y *protocol.IndexCoverage) bool {
		return bytes.Equal(x.RefId, y.RefId) && x.Version == y.Version && x.Horizon == y.Horizon
	})
}

// The sequences of units.
func indexUnitSeqs(units []*indexJournalUnit) []uint64 {
	seqs := make([]uint64, 0, len(units))
	for _, unit := range units {
		seqs = append(seqs, unit.seq)
	}
	return seqs
}
