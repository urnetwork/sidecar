//go:build !ios_extension

// The merge runner (§11.14's merges when and commit rows; DESIGN-DETAILS 1.2.4, 1.2.7 and 1.5; SEARCH-M10-10): which
// of a ref's buckets are due, and one merge of a bucket, committed as one push of its changed shards, its removals and
// its manifest, naming the head's index_epoch. A merge takes no lock and holds no state, so a refusal that says another
// push changed what it read reruns it on the new state: a 409 on a path (another merge, a promotion or a DROP's
// rewrite landed), 409 INDEX_EPOCH (a CUT moved the epoch, so it rereads the erasure set), an input that answers
// collected (its writer reused the slot, which only a merge already beaten can meet), and its push life passing
// before it was sent. A 429 or a quota refusal is returned unsent, since merges add payload and wait at the storage
// limit, and a push refused TIME_AHEAD is never sent again as built (R5). An unknown outcome is settled by the same
// push id before anything is rebuilt.
//
// Every build runs in one order: take its signed time; read the index head; build; upload; commit. A bucket is due
// when its sealed slots and unabsorbed large entries come to MergeDueByteCount or a writer of it is out of slots, and
// never when it is expired at the merge's signed time, which is the push's, never a device's clock. Who merges is the
// schedule's (indexer_search.go): an indexer serving the repo for search first, else a desktop or the daemon, and a
// phone only out of slots or on Wi-Fi while charging.
//
// Barriers evs.index.merge.built, .uploaded and .pushed, keyed <repo>/<ref>. The caller passes this build's linked
// tables, which it has checked are normalizer 1's, and the pad key of its newest generation. Not safe for concurrent
// use.

package sidecar

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A merge built AttemptCount times, each refused for a change under it: the caller tries again later.
	errIndexMergeAttempts = errors.New("index merge refused at each attempt")
	// An index file in a newer format sits in the root: nothing this build writes may replace what it cannot read.
	errIndexMergeNewerFormat = errors.New("index merge over a file in a newer format")
	// A merger built without what every merge needs.
	errIndexMergerArgs = errors.New("index merger without its store, settings, pad key or clock")
)

// The merge runner's own limits. The bucket's limits, ShardJoinByteCount and MergeDueByteCount among them, are the
// format's (IndexFormatSettings).
type IndexMergerSettings struct {
	// Builds of one merge, the first included, before it gives up on the refusals it reruns: 8, a reading. Each rerun
	// reads the new state, so this bounds the work a busy bucket costs, not what a merge writes. Non-positive is one.
	AttemptCount int
}

// The runner's defaults, a fresh value each call.
func DefaultIndexMergerSettings() *IndexMergerSettings {
	return &IndexMergerSettings{AttemptCount: 8}
}

// What a merger reads its ref and writes its pushes with.
type indexMergerArgs struct {
	store     indexRefStore
	repoId    Id
	refId     Id
	repoKind  protocol.RepoKind
	companion bool
	// Which settings versions count, as indexViewArgs.isAdmin.
	isAdmin func(file *indexFileVersion) bool
	format  *IndexFormatSettings
	// Nil takes DefaultIndexMergerSettings.
	settings *IndexMergerSettings
	// K_index_g at this device's newest generation of the repo, asked once a build.
	padKey func(ctx context.Context) (*indexPadKey, error)
	tables indexTables
	// Nil is real time.
	clock Clock
}

// One ref's merger.
type IndexMerger struct {
	args     indexMergerArgs
	settings *IndexMergerSettings
	clock    Clock
}

// A merger of one ref's buckets.
func indexNewMerger(args *indexMergerArgs) (*IndexMerger, error) {
	if args.store == nil || args.format == nil || args.padKey == nil {
		return nil, errIndexMergerArgs
	}
	settings := args.settings
	if settings == nil {
		settings = DefaultIndexMergerSettings()
	}
	return &IndexMerger{args: *args, settings: settings, clock: clockOrReal(args.clock)}, nil
}

// Why a merge wrote nothing without failing.
type indexMergeSkip int

const (
	indexMergeNotSkipped indexMergeSkip = iota
	// The bucket is not at the head: rolled up, or never written.
	indexMergeSkipGone
	// The index is off.
	indexMergeSkipOff
	// The bucket is expired at the merge's signed time: its roll-up takes it.
	indexMergeSkipExpired
	// No writer holds a sealed slot or an unabsorbed large entry there, so a merge would change nothing.
	indexMergeSkipNothing
)

// What one Merge did.
type indexMergeOutcome struct {
	// The commit, nil when the merge was skipped.
	committed *indexCommitted
	skipped   indexMergeSkip
	// What the merge wrote, nil when skipped.
	result *indexMergeResult
	// index_malformed for every diff the merge could not compose and every file its view alarmed.
	events []SidecarEvent
	// Builds made, the committed one included.
	attempts int
}

// The barrier key of this ref: <repo>/<ref>.
func (self *IndexMerger) barrierKey() string {
	return self.args.repoId.String() + "/" + self.args.refId.String()
}

// The ref's index at its head.
func (self *IndexMerger) loadView(ctx context.Context) (*indexView, error) {
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

// Whether a push signed at signedTime may still be sent at now: within life on the monotonic clock and on the wall
// clock both (R5).
func indexPushAlive(signedTime time.Time, now time.Time, life time.Duration) bool {
	return now.Sub(signedTime) <= life && now.Round(0).Sub(signedTime.Round(0)) <= life
}

// One merge of the bucket starting on startDay in root rootNumber, at the head and rerun on the new state after each
// refusal 1.5 reruns, at most AttemptCount builds. A 429, a quota refusal and an unknown outcome a second try did not
// settle are returned as the store's *indexRefusal, unsent again.
func (self *IndexMerger) Merge(ctx context.Context, rootNumber uint32, startDay uint32) (*indexMergeOutcome, error) {
	outcome := &indexMergeOutcome{}
	for outcome.attempts < max(1, self.settings.AttemptCount) {
		outcome.attempts += 1
		done, err := self.attempt(ctx, rootNumber, startDay, outcome)
		if err != nil || done {
			return outcome, err
		}
	}
	return outcome, errIndexMergeAttempts
}

// One build and its push. Answers whether the merge is done, committed or skipped; false with no error reruns it.
func (self *IndexMerger) attempt(ctx context.Context, rootNumber uint32, startDay uint32, outcome *indexMergeOutcome) (bool, error) {
	signedTime := self.clock.Now()
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
		return false, errIndexMergeNewerFormat
	}
	root := view.root(rootNumber)
	if root == nil {
		outcome.skipped = indexMergeSkipGone
		return true, nil
	}
	if root.off() {
		outcome.skipped = indexMergeSkipOff
		return true, nil
	}
	bucket := root.bucket(startDay)
	if bucket == nil {
		outcome.skipped = indexMergeSkipGone
		return true, nil
	}
	if indexBucketExpiredAt(view, root, bucket, signedTime.UnixMilli()) {
		outcome.skipped = indexMergeSkipExpired
		return true, nil
	}
	if indexBucketSealedByteCount(bucket) == 0 {
		outcome.skipped = indexMergeSkipNothing
		return true, nil
	}
	shards, err := indexDecodeBucketShards(ctx, view, bucket.shards)
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
		return false, err
	}
	outcome.result = result
	outcome.events = append(outcome.events, indexMalformedEvents(view, result.malformed)...)
	testHookBarrier("evs.index.merge.built", self.barrierKey())

	push := &indexPush{
		pushId:       NewId(),
		kind:         indexPushIndex,
		baseVersion:  view.head.version,
		indexEpoch:   view.head.indexEpoch,
		signedTimeMs: signedTime.UnixMilli(),
		files:        result.files(),
		removals:     result.removedShards,
	}
	testHookBarrier("evs.index.merge.uploaded", self.barrierKey())
	committed, err := indexSendPush(ctx, self.args.store, push, signedTime, self.clock, self.args.format.PushLife)
	if refusal, ok := indexRefusalOf(err); ok && (refusal.kind == indexRefusalConflict || refusal.kind == indexRefusalIndexEpoch) {
		return false, nil
	}
	if errors.Is(err, errIndexPushLifePassed) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	outcome.committed = committed
	testHookBarrier("evs.index.merge.pushed", self.barrierKey())
	return true, nil
}

// A push whose life passed before it was sent: it is built again from its first read, never sent as built (R5).
var errIndexPushLifePassed = errors.New("index push life passed unsent")

// Sends push while its life lasts, and settles an unknown outcome by the same push id once, still within the life:
// evs answers the committed result of a push id it holds (11.8's outcomes). A 429, which may be TIME_AHEAD, is
// returned as it stands and the push is never sent again as built.
func indexSendPush(ctx context.Context, store indexRefStore, push *indexPush, signedTime time.Time, clock Clock, life time.Duration) (*indexCommitted, error) {
	if !indexPushAlive(signedTime, clock.Now(), life) {
		return nil, errIndexPushLifePassed
	}
	committed, err := store.Commit(ctx, push)
	if !isIndexRefusal(err, indexRefusalOutcomeUnknown) {
		return committed, err
	}
	if !indexPushAlive(signedTime, clock.Now(), life) {
		return nil, err
	}
	return store.Commit(ctx, push)
}

// index_malformed for each diff a merge could not compose, naming its slot's signer.
func indexMalformedEvents(view *indexView, malformed []*indexMalformedDiff) []SidecarEvent {
	events := make([]SidecarEvent, 0, len(malformed))
	for _, diff := range malformed {
		repoId, refId, signerId := view.repoId, view.refId, diff.signerSidecarId
		events = append(events, SidecarEvent{Kind: SidecarEventIndexMalformed, SidecarId: &signerId, RepoId: &repoId, RefId: &refId, Path: diff.path})
	}
	return events
}

// Whether bucket is expired at signedTimeMs, by the root's windows, never a device's clock (QD-689's reading 1).
func indexBucketExpiredAt(view *indexView, root *indexViewRoot, bucket *indexViewBucket, signedTimeMs int64) bool {
	ages := indexBucketAges(root.bucketWindows(), root.windowDays(view.repoKind), signedTimeMs)
	for index, held := range root.buckets {
		if held.window.startDay == bucket.window.startDay {
			return ages[index] == indexBucketExpired
		}
	}
	return false
}

// Whether a writer of the bucket is out of slots: no slot it may reuse (absorbed, not its head and not kept), and
// its ring of slots that are not kept full, or all 16 in use, so its next seal must merge first (1.2.3).
func indexWriterOutOfSlots(bucket *indexViewBucket, writer *indexViewWriter, settings *IndexFormatSettings) bool {
	absorbed := bucket.absorbedSeq(writer.sidecarId)
	head := writer.head()
	kept := writer.kept(absorbed, nil)
	others := 0
	for _, slot := range writer.slots {
		if slot != head && slot.seq() <= absorbed && !kept[slot] {
			return false
		}
		if !kept[slot] {
			others += 1
		}
	}
	return settings.RingSlotCount <= others || indexWriterSlotCount <= len(writer.slots)
}

// The plaintext bytes of the bucket's sealed slots and unabsorbed large entries, every writer's: what a merge would
// absorb.
func indexBucketSealedByteCount(bucket *indexViewBucket) int {
	byteCount := 0
	for _, writer := range bucket.writers {
		head := writer.head()
		for _, file := range writer.unabsorbed(bucket.absorbedSeq(writer.sidecarId)) {
			if file != head {
				byteCount += file.file.byteCount
			}
		}
	}
	return byteCount
}

// The start days of root's buckets due for a merge at signedTimeMs (§11.14's when row): not expired then, and either
// their sealed slots and unabsorbed large entries come to MergeDueByteCount of plaintext, or a writer is out of slots.
func indexMergeDueBuckets(view *indexView, root *indexViewRoot, signedTimeMs int64) []uint32 {
	due := []uint32{}
	if root.off() {
		return due
	}
	for _, bucket := range root.buckets {
		if indexBucketExpiredAt(view, root, bucket, signedTimeMs) {
			continue
		}
		sealedByteCount := indexBucketSealedByteCount(bucket)
		outOfSlots := false
		for _, writer := range bucket.writers {
			outOfSlots = outOfSlots || indexWriterOutOfSlots(bucket, writer, view.settings)
		}
		if 0 < sealedByteCount && (view.settings.MergeDueByteCount <= sealedByteCount || outOfSlots) {
			due = append(due, bucket.window.startDay)
		}
	}
	return due
}

// The buckets of the ref's write root due for a merge now, at the head.
func (self *IndexMerger) Due(ctx context.Context) ([]uint32, error) {
	view, err := self.loadView(ctx)
	if err != nil {
		return nil, err
	}
	return indexMergeDueBuckets(view, view.writeRoot(), self.clock.Now().UnixMilli()), nil
}
