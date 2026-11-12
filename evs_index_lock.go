//go:build !ios_extension

// The roll-up's lock (§11.14's lock and fence rows; DESIGN-DETAILS 1.2.5 step 1 and 1.2.7; I-EVS-12; QD-689's readings
// 1 and 10): <root>/lock, one versionless IndexLock a root, through which one runner at a time rolls a bucket. A
// runner takes it by a push that changes the lock from a free version, the empty message or no file at all, or from
// a held one whose until_ms is LockGrace past the taker's signed time, to {itself, S, t + LockTerm}, and renews it by
// the same CAS at half its term while it works (IndexRollerSettings.LockRenewAfter). Every time here is a push's signed time, never a device's clock, so a
// reader 10 min off judges a lock as its taker did, and LockGrace, evs's bound on a signed time, keeps two honest
// runners from both believing they hold it; if they did, the lock's CAS decides.
//
// The roll-up's last push frees the lock from the version the runner holds, and that change is the fence: a runner
// whose lock lapsed and was taken gets 409 on the lock and stops, its uploads left to 11.13's orphan rule. A crash
// leaves the lock to lapse. Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// Another runner holds the lock, and its until_ms is not LockGrace past: it is left alone until then.
	errIndexLockHeld = errors.New("index lock held by another runner")
	// The lock this runner held was taken from under it, so its roll-up stops.
	errIndexLockLost = errors.New("index lock lost")
)

// A lock this runner holds: the lock file's version after its take or renewal, and the until_ms it set.
type indexHeldLock struct {
	holder   Id
	startDay uint32
	version  uint64
	untilMs  int64
	// The signed time of the push that took or renewed it.
	signedTimeMs int64
}

// Whether a taker signed at signedTimeMs finds root's lock free: no lock file, the empty message, or a held lock whose
// until_ms is at least LockGrace past. A lock file that does not read is no lock a taker can trust is free.
func indexLockFree(root *indexViewRoot, signedTimeMs int64, settings *IndexFormatSettings) bool {
	if root.lockFile == nil {
		return true
	}
	if root.lock == nil {
		return false
	}
	if len(root.lock.HolderSidecarId) == 0 {
		return true
	}
	return root.lock.UntilMs+settings.LockGrace.Milliseconds() <= signedTimeMs
}

// Whether root's lock is the one holder took for startDay, at the version held, and not yet past its until_ms at
// signedTimeMs.
func indexLockHeldBy(root *indexViewRoot, held *indexHeldLock, signedTimeMs int64) bool {
	return root.lockFile != nil && root.lock != nil && root.lockFile.version == held.version &&
		bytes.Equal(root.lock.HolderSidecarId, held.holder.Bytes()) && root.lock.BucketStartDay == held.startDay &&
		signedTimeMs < root.lock.UntilMs
}

// The lock file a push writes to hold the lock for holder and startDay until signedTimeMs + LockTerm, replacing
// replaces (0 creates it).
func indexLockFile(root *indexViewRoot, holder Id, startDay uint32, signedTimeMs int64, replaces uint64, settings *IndexFormatSettings) (*indexPushFile, error) {
	file, err := indexEncodeLock(&protocol.IndexLock{
		HolderSidecarId: holder.Bytes(),
		BucketStartDay:  startDay,
		UntilMs:         signedTimeMs + settings.LockTerm.Milliseconds(),
	})
	if err != nil {
		return nil, err
	}
	return &indexPushFile{path: root.paths.lock(), plaintext: file, replaces: replaces}, nil
}

// The lock file a roll-up's last push writes: the lock free, from the version its runner holds.
func indexLockFreeFile(root *indexViewRoot, held *indexHeldLock) (*indexPushFile, error) {
	file, err := indexEncodeLock(&protocol.IndexLock{})
	if err != nil {
		return nil, err
	}
	return &indexPushFile{path: root.paths.lock(), plaintext: file, replaces: held.version}, nil
}

// Whether a refusal names the lock among its conflicting paths.
func indexRefusalNamesLock(err error, root *indexViewRoot) bool {
	refusal, ok := indexRefusalOf(err)
	return ok && refusal.kind == indexRefusalConflict && slices.Contains(refusal.paths, root.paths.lock())
}

// Takes root's lock for holder and startDay with a push of the lock file alone, signed at signedTime and built at the
// view's head: errIndexLockHeld where another runner holds it and has not lapsed, or where the take's CAS loses to
// another taker. Any other refusal comes back as the store's.
func indexTakeLock(ctx context.Context, store indexRefStore, view *indexView, root *indexViewRoot, holder Id, startDay uint32, signedTime time.Time, clock Clock) (*indexHeldLock, error) {
	settings := view.settings
	signedTimeMs := signedTime.UnixMilli()
	mine := root.lock != nil && bytes.Equal(root.lock.HolderSidecarId, holder.Bytes()) && root.lock.BucketStartDay == startDay
	if !mine && !indexLockFree(root, signedTimeMs, settings) {
		return nil, errIndexLockHeld
	}
	replaces := uint64(0)
	if root.lockFile != nil {
		replaces = root.lockFile.version
	}
	return indexWriteLock(ctx, store, view, root, holder, startDay, signedTime, replaces, clock)
}

// Renews a held lock by the same CAS, from the version held: errIndexLockLost where another push changed it.
func indexRenewLock(ctx context.Context, store indexRefStore, view *indexView, root *indexViewRoot, held *indexHeldLock, signedTime time.Time, clock Clock) (*indexHeldLock, error) {
	renewed, err := indexWriteLock(ctx, store, view, root, held.holder, held.startDay, signedTime, held.version, clock)
	if errors.Is(err, errIndexLockHeld) {
		return nil, errIndexLockLost
	}
	return renewed, err
}

// One push of the lock file alone: held until signedTime + LockTerm.
func indexWriteLock(ctx context.Context, store indexRefStore, view *indexView, root *indexViewRoot, holder Id, startDay uint32, signedTime time.Time, replaces uint64, clock Clock) (*indexHeldLock, error) {
	file, err := indexLockFile(root, holder, startDay, signedTime.UnixMilli(), replaces, view.settings)
	if err != nil {
		return nil, err
	}
	committed, err := indexSendPush(ctx, store, &indexPush{
		pushId:       NewId(),
		kind:         indexPushIndex,
		baseVersion:  view.head.version,
		indexEpoch:   view.head.indexEpoch,
		signedTimeMs: signedTime.UnixMilli(),
		files:        []*indexPushFile{file},
	}, signedTime, clock, view.settings.PushLife)
	if refusal, ok := indexRefusalOf(err); ok && refusal.kind == indexRefusalConflict {
		return nil, errIndexLockHeld
	}
	if err != nil {
		return nil, err
	}
	held := &indexHeldLock{holder: holder, startDay: startDay, untilMs: signedTime.UnixMilli() + view.settings.LockTerm.Milliseconds(), signedTimeMs: signedTime.UnixMilli()}
	for _, written := range committed.files {
		if written.path == file.path {
			held.version = written.version
		}
	}
	return held, nil
}

// Whether a held lock is due its renewal at signedTimeMs: renewAfter, half its term by default, has passed since it
// was taken or renewed.
func indexLockRenewDue(held *indexHeldLock, signedTimeMs int64, renewAfter time.Duration) bool {
	return held.signedTimeMs+renewAfter.Milliseconds() <= signedTimeMs
}
