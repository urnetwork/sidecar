//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// One mount's locks (DESIGN-DETAILS 8.2.9):
//
//	P_r   the publish lock of ref r: held by whoever builds and sends a push for r, across the network (a receive, an
//	      owned ref's queue, an import, the mapper's PATH_EPOCH and a local rekey), so one device's pushes to one ref
//	      take turns and the second of two sibling pushes answers from the local ref
//	L_r   the apply lock of ref r: held for local state only (EvsGitRef, the journal, the tips log and `git
//	      update-ref`), never across a request to evs or a wait
//	M     the mount's upkeep lock: shared by every receive session, replay flush and publish; exclusive for git gc
//	order M (shared), then P_r, then L_r; L_r is never held while taking P_r or waiting on evs, and two refs' locks
//	      are never held together. The sync engine takes L_r alone, so it never waits on a push.
//
// A waiter gives up at its ctx, or at RefLockTimeout for P_r and L_r, never spinning: each waits on the holder's
// release channel. M's shared holders never wait behind an exclusive waiter, so a receive that holds it shared and
// waits for a replay that takes it shared again cannot deadlock behind git gc; gc waits for a moment with none.
//
// Desktop legs only. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"sync"
)

// A ref lock not taken within RefLockTimeout.
var ErrEvsRefLockTimeout = errors.New("evs: ref lock timed out")

// The locks of one mount's refs.
type EvsRefLocks struct {
	settings *EvsSettings
	clock    Clock

	stateLock sync.Mutex
	// each held ref's release, closed when it is released: the apply locks and the publish locks
	applyReleases   map[Id]chan struct{}
	publishReleases map[Id]chan struct{}
	// M: its shared holders, whether gc holds it, and a channel closed at each release
	upkeepShared    int
	upkeepExclusive bool
	upkeepChanged   chan struct{}
}

// No ref locked.
func NewEvsRefLocks(settings *EvsSettings, clock Clock) *EvsRefLocks {
	return &EvsRefLocks{
		settings: settings, clock: clockOrReal(clock), applyReleases: map[Id]chan struct{}{},
		publishReleases: map[Id]chan struct{}{}, upkeepChanged: make(chan struct{}),
	}
}

// Takes one of a family's locks for refId, waiting for its holder. The answer releases it, once.
func (self *EvsRefLocks) lockIn(ctx context.Context, releases map[Id]chan struct{}, refId Id) (func(), error) {
	deadline := self.clock.After(self.settings.RefLockTimeout)
	for {
		held, release := func() (chan struct{}, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if held := releases[refId]; held != nil {
				return held, nil
			}
			release := make(chan struct{})
			releases[refId] = release
			return nil, release
		}()
		if release != nil {
			var once sync.Once
			return func() {
				once.Do(func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					delete(releases, refId)
					close(release)
				})
			}, nil
		}
		select {
		case <-held:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline:
			return nil, ErrEvsRefLockTimeout
		}
	}
}

// Takes L_r, the apply lock.
func (self *EvsRefLocks) LockApply(ctx context.Context, refId Id) (func(), error) {
	return self.lockIn(ctx, self.applyReleases, refId)
}

// Takes P_r, the publish lock.
func (self *EvsRefLocks) LockPublish(ctx context.Context, refId Id) (func(), error) {
	return self.lockIn(ctx, self.publishReleases, refId)
}

// Whether L_r is held now.
func (self *EvsRefLocks) ApplyHeld(refId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.applyReleases[refId] != nil
}

// Whether P_r is held now.
func (self *EvsRefLocks) PublishHeld(refId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.publishReleases[refId] != nil
}

// Takes M shared, waiting only while gc holds it. The answer releases it, once.
func (self *EvsRefLocks) LockUpkeepShared(ctx context.Context) (func(), error) {
	for {
		changed, taken := func() (chan struct{}, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.upkeepExclusive {
				return self.upkeepChanged, false
			}
			self.upkeepShared += 1
			return nil, true
		}()
		if taken {
			var once sync.Once
			return func() {
				once.Do(func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.upkeepShared -= 1
					self.notifyUpkeepWithLock()
				})
			}, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Takes M exclusively, for git gc, once no one holds it. The answer releases it, once.
func (self *EvsRefLocks) LockUpkeepExclusive(ctx context.Context) (func(), error) {
	for {
		changed, taken := func() (chan struct{}, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.upkeepExclusive || 0 < self.upkeepShared {
				return self.upkeepChanged, false
			}
			self.upkeepExclusive = true
			return nil, true
		}()
		if taken {
			var once sync.Once
			return func() {
				once.Do(func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.upkeepExclusive = false
					self.notifyUpkeepWithLock()
				})
			}, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Wakes every waiter on M, which reads its state again.
func (self *EvsRefLocks) notifyUpkeepWithLock() {
	close(self.upkeepChanged)
	self.upkeepChanged = make(chan struct{})
}
