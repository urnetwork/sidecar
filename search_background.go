//go:build !ios_extension

// Search's background windows and triggers (§18.5's RunBackgroundSync; §18.4's windows row; §11.14's trigger row;
// SEARCH-M10-20): an OS-granted window, ctx's deadline its budget, in which a wifi_charging host keeps all and runs its
// background index work, stopping at the budget and resuming at the next; and the app coming to the foreground, which
// runs a round of every followed ref. A window runs the rounds the sync engine has due, each of every followed ref
// asked for once, until none is due or the budget ends; what a round staged stays for the next window. Phones then
// evict all shards no search used for Search.UnusedAllAge, search.state kept.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
)

// A window driver built without what it runs on.
var errSearchBackgroundArgs = errors.New("search background without its sync or policy")

// One network's background search work: SidecarSearchBackgroundSync's window, and the foreground trigger.
type SearchBackground struct {
	sync   *SearchSync
	policy *SearchPolicy
	// Where Search.UnusedAllAge evicts; nil evicts nothing.
	cache *SearchCache
}

// A driver of sync's rounds under policy.
func NewSearchBackground(sync *SearchSync, policy *SearchPolicy, cache *SearchCache) (*SearchBackground, error) {
	if sync == nil || policy == nil {
		return nil, errSearchBackgroundArgs
	}
	return &SearchBackground{sync: sync, policy: policy, cache: cache}, nil
}

// One OS window until ctx's deadline (see the file header). Answers nil when it ran until nothing was due or its
// budget ended; a ctx with no deadline is refused, since an OS window always has one.
func (self *SearchBackground) RunBackgroundSync(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return ErrSearchRequest
	}
	end := self.policy.BeginWindow(deadline)
	defer end()
	self.sync.triggerAll(SearchSyncWindow)
	self.sync.RunDue(ctx)
	if _, err := self.policy.EvictUnused(self.cache); err != nil {
		return err
	}
	if ctx.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return ctx.Err()
	}
	return nil
}

// The app came to the foreground (QD-158's SetSearchForeground, true): a round of every followed ref.
func (self *SearchBackground) Foreground() {
	self.sync.triggerAll(SearchSyncForeground)
}

// Asks for a round of every followed ref for reason. Never called by a search.
func (self *SearchSync) triggerAll(reason SearchSyncReason) {
	self.stateLock.Lock()
	repoIds := map[Id]bool{}
	for key := range self.refs {
		repoIds[key[0]] = true
	}
	self.stateLock.Unlock()
	for repoId := range repoIds {
		self.Trigger(repoId, nil, reason)
	}
}
