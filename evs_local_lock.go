//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// Per-ref daemon locks (§11.11's journal and locks rows): receive-pack's update of a ref, after evs's 200, and the sync
// engine's `git update-ref --stdin` of the same ref take its lock, so they never race on a ref. A waiter gives up at
// its ctx or after EvsSettings.RefLockTimeout, the hook's own 3 minutes, never spinning: each waits on the holder's
// release channel.
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
	// each held ref's release, closed when it is released
	refReleases map[string]chan struct{}
}

// No ref locked.
func NewEvsRefLocks(settings *EvsSettings, clock Clock) *EvsRefLocks {
	return &EvsRefLocks{settings: settings, clock: clockOrReal(clock), refReleases: map[string]chan struct{}{}}
}

// Takes ref's lock, waiting for its holder. The answer releases it, once.
func (self *EvsRefLocks) Lock(ctx context.Context, ref string) (func(), error) {
	deadline := self.clock.After(self.settings.RefLockTimeout)
	for {
		held, release := func() (chan struct{}, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if held := self.refReleases[ref]; held != nil {
				return held, nil
			}
			release := make(chan struct{})
			self.refReleases[ref] = release
			return nil, release
		}()
		if release != nil {
			var once sync.Once
			return func() {
				once.Do(func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					delete(self.refReleases, ref)
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

// Whether ref's lock is held now.
func (self *EvsRefLocks) Held(ref string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.refReleases[ref] != nil
}
