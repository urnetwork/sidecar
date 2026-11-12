//go:build !ios_extension

// The roll-up runner (§11.14's trigger, lock, steps, fence, crash and idempotent rows; DESIGN-DETAILS 1.2.5, 1.2.7 and
// 1.5; QD-686, QD-689; SEARCH-M10-11): one roll-up of a root's oldest bucket that is expired at the push's signed time,
// in the order every builder keeps: take t; read the index head; take the lock; read at the head after the lock
// commits; build; upload; commit. The lock's change in the last push is its fence: a 409 on the lock stops the runner,
// and any other 409, 409 INDEX_EPOCH, a collected input or a push life passing reruns from the read with the lock still
// held, renewed at LockRenewAfter. A runner that finds b/<S>/ gone and rolled_through_day at or past S stops. A 429
// and a quota refusal come back unsent again, since roll-ups add payload and wait at the storage limit, and the lock
// then lapses, as after a crash; nothing shows before the head CAS.
//
// Who runs a roll-up, and when, is the schedule's (indexer_search.go). Barriers evs.index.rollup.locked, .built,
// .uploaded and .pushed, keyed <repo>/<ref>; the batch write and the head CAS between the last two are evs's. Not safe
// for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A roll-up built AttemptCount times after its lock, each refused for a change under it: its lock lapses, and the
	// schedule tries again later.
	errIndexRollupAttempts = errors.New("index roll-up refused at each attempt")
	// A roller built without what every roll-up needs.
	errIndexRollerArgs = errors.New("index roller without its store, settings, pad key or runner")
)

// The roll-up runner's own limits. The lock's term and grace and the push life are the format's
// (IndexFormatSettings).
type IndexRollerSettings struct {
	// Builds of one roll-up after its lock, the first included, before it gives up on the refusals it reruns: 8, a
	// reading. Non-positive is one.
	AttemptCount int
	// From a lock's take or renewal to its next renewal, while the runner works: 15 min, half of LockTerm's 30
	// (§11.14's lock row; QD-689's reading 10).
	LockRenewAfter time.Duration
}

// The runner's defaults, a fresh value each call.
func DefaultIndexRollerSettings() *IndexRollerSettings {
	return &IndexRollerSettings{AttemptCount: 8, LockRenewAfter: 15 * time.Minute}
}

// What a roller reads its ref and writes its pushes with.
type indexRollerArgs struct {
	store     indexRefStore
	repoId    Id
	refId     Id
	repoKind  protocol.RepoKind
	companion bool
	isAdmin   func(file *indexFileVersion) bool
	format    *IndexFormatSettings
	// Nil takes DefaultIndexRollerSettings.
	settings *IndexRollerSettings
	padKey   func(ctx context.Context) (*indexPadKey, error)
	tables   indexTables
	// Nil is real time.
	clock Clock
	// This device's sidecar_id: the lock's holder, whose head carries S's coverage.
	runner Id
	// I_R of a content ref at a view's base, SEARCH-M10-12's coverage reading; nil carries S's own horizon rows.
	indexedThrough func(view *indexView, refId []byte) (uint64, bool)
}

// One ref's roller.
type IndexRoller struct {
	args     indexRollerArgs
	settings *IndexRollerSettings
	clock    Clock
}

// A roller of one ref's expired buckets.
func indexNewRoller(args *indexRollerArgs) (*IndexRoller, error) {
	if args.store == nil || args.format == nil || args.padKey == nil || args.runner == (Id{}) {
		return nil, errIndexRollerArgs
	}
	settings := args.settings
	if settings == nil {
		settings = DefaultIndexRollerSettings()
	}
	return &IndexRoller{args: *args, settings: settings, clock: clockOrReal(args.clock)}, nil
}

// Why a roll-up wrote nothing without failing.
type indexRollupSkip int

const (
	indexRollupNotSkipped indexRollupSkip = iota
	// No bucket is expired at the push's signed time.
	indexRollupSkipNone
	// The index is off, or its root is gone.
	indexRollupSkipOff
	// Another runner holds the lock and has not lapsed.
	indexRollupSkipLocked
	// b/<S>/ is gone and rolled_through_day is at or past S: another runner, or this one's earlier push, rolled it.
	indexRollupSkipRolled
)

// What one Roll did.
type indexRollupOutcome struct {
	committed *indexCommitted
	skipped   indexRollupSkip
	// The bucket rolled, or being rolled.
	startDay uint32
	result   *indexRollupResult
	// index_malformed for every diff of S that did not compose and every file its views alarmed.
	events []SidecarEvent
	// Builds after the lock, the committed one included.
	attempts int
	// The lock as last held.
	lock *indexHeldLock
}

// The barrier key of this ref: <repo>/<ref>.
func (self *IndexRoller) barrierKey() string {
	return self.args.repoId.String() + "/" + self.args.refId.String()
}

// The ref's index at its head.
func (self *IndexRoller) loadView(ctx context.Context) (*indexView, error) {
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

// The oldest of root's buckets expired at signedTimeMs, or nil.
func indexOldestExpired(view *indexView, root *indexViewRoot, signedTimeMs int64) *indexViewBucket {
	for _, bucket := range root.buckets {
		if indexBucketExpiredAt(view, root, bucket, signedTimeMs) {
			return bucket
		}
	}
	return nil
}

// One roll-up of root rootNumber's oldest bucket expired now: the lock taken, then built and committed with the lock
// freed, rerun with the lock held after each refusal 1.5 reruns, at most AttemptCount builds.
func (self *IndexRoller) Roll(ctx context.Context, rootNumber uint32) (*indexRollupOutcome, error) {
	outcome := &indexRollupOutcome{}
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
		return outcome, errIndexMergeNewerFormat
	}
	root := view.root(rootNumber)
	if root == nil || root.off() {
		outcome.skipped = indexRollupSkipOff
		return outcome, nil
	}
	expired := indexOldestExpired(view, root, lockTime.UnixMilli())
	if expired == nil {
		outcome.skipped = indexRollupSkipNone
		return outcome, nil
	}
	outcome.startDay = expired.window.startDay
	held, err := indexTakeLock(ctx, self.args.store, view, root, self.args.runner, outcome.startDay, lockTime, self.clock)
	if errors.Is(err, errIndexLockHeld) {
		outcome.skipped = indexRollupSkipLocked
		return outcome, nil
	}
	if err != nil {
		return outcome, err
	}
	outcome.lock = held
	testHookBarrier("evs.index.rollup.locked", self.barrierKey())
	for outcome.attempts < max(1, self.settings.AttemptCount) {
		outcome.attempts += 1
		done, err := self.attempt(ctx, rootNumber, outcome)
		if err != nil || done {
			return outcome, err
		}
	}
	return outcome, errIndexRollupAttempts
}

// One build after the lock and its push. Answers whether the roll-up is done; false with no error reruns it.
func (self *IndexRoller) attempt(ctx context.Context, rootNumber uint32, outcome *indexRollupOutcome) (bool, error) {
	signedTime := self.clock.Now()
	view, err := self.loadView(ctx)
	if errors.Is(err, errIndexCollected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	outcome.events = view.events()
	root := view.root(rootNumber)
	if root == nil || root.off() {
		outcome.skipped = indexRollupSkipOff
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
	expired := root.bucket(outcome.startDay)
	if expired == nil {
		if root.allManifest != nil && outcome.startDay <= root.allManifest.RolledThroughDay {
			outcome.skipped = indexRollupSkipRolled
			return true, nil
		}
		return false, errIndexLockLost
	}
	if view.erasureSetUnreadable {
		return false, errIndexErasureSetUnreadable
	}
	listing, err := self.args.store.List(ctx, view.head.version)
	if err != nil {
		return false, err
	}
	bucketPrefix := root.paths.bucket(outcome.startDay) + "/"
	expiredFiles := []*indexFileVersion{}
	for _, file := range listing.files {
		if strings.HasPrefix(file.path, bucketPrefix) {
			expiredFiles = append(expiredFiles, file)
		}
	}
	args := &indexRollupArgs{view: view, root: root, expiredFiles: expiredFiles, runner: self.args.runner, signedTimeMs: signedTime.UnixMilli(), tables: self.args.tables}
	decode := func(bucket *indexViewBucket) (*indexRollupBucket, error) {
		shards, err := indexDecodeBucketShards(ctx, view, bucket.shards)
		if err != nil {
			return nil, err
		}
		return &indexRollupBucket{bucket: bucket, shards: shards}, nil
	}
	if args.expired, err = decode(expired); err != nil {
		return false, indexRerunCollected(err)
	}
	for _, bucket := range root.buckets {
		if expired.window.startDay < bucket.window.startDay {
			newer, err := decode(bucket)
			if err != nil {
				return false, indexRerunCollected(err)
			}
			args.newer = append(args.newer, newer)
		}
	}
	if args.allShards, err = indexDecodeBucketShards(ctx, view, root.allShards); err != nil {
		return false, indexRerunCollected(err)
	}
	if self.args.indexedThrough != nil {
		args.indexedThrough = func(refId []byte) (uint64, bool) {
			return self.args.indexedThrough(view, refId)
		}
	}
	if args.padKey, err = self.args.padKey(ctx); err != nil {
		return false, err
	}
	result, err := indexRollup(ctx, args)
	if err != nil {
		return false, err
	}
	outcome.result = result
	outcome.events = append(outcome.events, indexMalformedEvents(view, result.malformed)...)
	testHookBarrier("evs.index.rollup.built", self.barrierKey())

	free, err := indexLockFreeFile(root, outcome.lock)
	if err != nil {
		return false, err
	}
	push := &indexPush{
		pushId:       NewId(),
		kind:         indexPushIndex,
		baseVersion:  view.head.version,
		indexEpoch:   view.head.indexEpoch,
		signedTimeMs: signedTime.UnixMilli(),
		files:        append(result.files, free),
		removals:     result.removals,
	}
	testHookBarrier("evs.index.rollup.uploaded", self.barrierKey())
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
	testHookBarrier("evs.index.rollup.pushed", self.barrierKey())
	return true, nil
}

// A collected input reruns the build: nil, so the caller's loop goes on; any other error stands.
func indexRerunCollected(err error) error {
	if errors.Is(err, errIndexCollected) {
		return nil
	}
	return err
}
