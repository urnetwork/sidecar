//go:build !ios_extension

// Search's device policy (§18.4's Search block; §16.10's sync, more and background rows; R-SDK-13, D-EVS-50,
// D-SDK-21, D-SDK-24, D-SDK-25, D-SDK-28, FI-23, FS-77; SEARCH-M10-20): how each host keeps a repo's index, from the
// host's settings, this device's overrides and the host's reports, never a query.
//
//	latest      buckets, a/m, the erasure set and the settings are synced on any host that searches the repo, but
//	            the team directory's on a host whose Search.DirectoryBuckets is off (phones), which fetches its
//	            cards while a view is open and its buckets and all only for "search more"
//	modes       all is kept by §18.4's mode in force: this device's override for the repo, else its override for
//	            every repo, sealed in search.state and never in the config repo, else the host's Search.AllPolicy;
//	            background keeps all at each roll-up and rewrite; wifi_charging in an OS-granted window, or while the
//	            app is in the foreground on an unmetered link and charging, never in Low Power Mode; on_demand only
//	            for "search more"; never not at all
//	caps        a host with Search.AllCacheByteCount keeps all only while the repo's all fits it, else on demand;
//	            Search.UnusedAllAge evicts all shards no search used that long, search.state kept
//	windows     background index work (merges, roll-ups) runs on a background host always, on a wifi_charging host
//	            only by the windows rule above, a roll-up only while the device holds all within its cap
//	budgets     background sync downloads stop at Search.BackgroundByteCount a UTC day a network, what is held back
//	            counted for search_status; a "search more" call stops at Search.MoreByteCount (search_more.go); a
//	            "search more" whose missing all passes Search.MeteredMoreByteCount on a metered link waits until it
//	            is asked again with AllowMetered; a forced head refresh is taken at most once a repo a
//	            Search.HeadRefreshInterval
//
// The quick burner keeps buckets in memory and never all (AllPolicy never, CacheByteCount 0); an ephemeral sidecar
// keeps its cache inside MemoryBudgetByteCount (CacheByteCount 0), and syncs all only for scope all (on_demand). The
// budget's day is the UTC day, and the counts live in memory, so a restart starts the day's count again (a reading).
// Safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A policy built without what it reads.
var errSearchPolicyArgs = errors.New("search policy without its settings or conditions")

// What a "search more" waits on before it fetches (§5.4's SearchProgress.Waiting).
const (
	SearchWaitingMetered = "metered"
)

// What a policy reads.
type SearchPolicyArgs struct {
	Settings *SidecarSearchSettings
	// This device's overrides (§5.9's state row); nil reads the host's default for every repo.
	State *SidecarSearchState
	// The host's reports, read at each decision. Required.
	Conditions func() SearchConditions
	// Nil is real time.
	Clock Clock
}

// One network's search policy on this device.
type SearchPolicy struct {
	settings   *SidecarSearchSettings
	state      *SidecarSearchState
	conditions func() SearchConditions
	clock      Clock

	stateLock sync.Mutex
	// OS windows in progress (RunSearchBackgroundSync), each until its deadline.
	windows map[*searchPolicyWindow]bool
	// The UTC day the background counts are of, its downloads, and by repo what the last read it refused wanted.
	budgetDay      int64
	backgroundUsed int64
	heldBack       map[Id]int64
	// When each repo's head was last refreshed by force.
	refreshedAt map[Id]time.Time
}

// One OS window.
type searchPolicyWindow struct {
	deadline time.Time
}

// A policy over args.
func NewSearchPolicy(args *SearchPolicyArgs) (*SearchPolicy, error) {
	if args == nil || args.Settings == nil || args.Conditions == nil {
		return nil, errSearchPolicyArgs
	}
	settings := args.Settings
	if !isSearchPolicy(settings.AllPolicy) {
		return nil, fmt.Errorf("%w: Search.AllPolicy is not one of §18.4's modes", errInvalidSettings)
	}
	if settings.BackgroundByteCount <= 0 || settings.MoreByteCount <= 0 || settings.MeteredMoreByteCount <= 0 ||
		settings.HeadRefreshInterval <= 0 || settings.AllCacheByteCount < 0 || settings.UnusedAllAge < 0 {
		return nil, fmt.Errorf("%w: the search policy's budgets", errInvalidSettings)
	}
	return &SearchPolicy{
		settings:    settings,
		state:       args.State,
		conditions:  args.Conditions,
		clock:       clockOrReal(args.Clock),
		windows:     map[*searchPolicyWindow]bool{},
		heldBack:    map[Id]int64{},
		refreshedAt: map[Id]time.Time{},
	}, nil
}

// The mode for all in force for repoId: this device's override, else the host's Search.AllPolicy. An override that
// cannot be read reads the host's default.
func (self *SearchPolicy) Mode(repoId Id) string {
	if self.state != nil {
		if mode, err := self.state.Policy(repoId); err == nil && isSearchPolicy(mode) {
			return mode
		}
	}
	return self.settings.AllPolicy
}

// Whether an OS window is open now.
func (self *SearchPolicy) inWindow() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	for window := range self.windows {
		if now.Before(window.deadline) {
			return true
		}
	}
	return false
}

// §18.4's windows rule for a wifi_charging host: in an OS window, or in the foreground on an unmetered link and
// charging; never while Low Power Mode or power saving pauses it.
func (self *SearchPolicy) windowsAllow() bool {
	conditions := self.conditions()
	if conditions.Paused() {
		return false
	}
	return self.inWindow() || (conditions.Foreground && !conditions.Metered() && conditions.OnCharge())
}

// Whether this device keeps repoId's all synced now (the sync engine's keepAll), all being allByteCount bytes as the
// device's listing knows it (0 where unknown): by the mode in force, within Search.AllCacheByteCount.
func (self *SearchPolicy) KeepsAll(repoId Id, allByteCount int64) bool {
	if allCap := self.settings.AllCacheByteCount; 0 < allCap && allCap < allByteCount {
		// past a cap all is kept on demand (§18.4's caps row)
		return false
	}
	switch self.Mode(repoId) {
	case SearchPolicyBackground:
		return true
	case SearchPolicyWifiCharging:
		return self.windowsAllow()
	}
	return false
}

// Whether this device keeps a repo's latest set synced (the buckets, a/m, the erasure set and the settings): always,
// but the team directory's where Search.DirectoryBuckets is off.
func (self *SearchPolicy) KeepsLatest(repoKind protocol.RepoKind) bool {
	return repoKind != protocol.RepoKind_REPO_KIND_DIRECTORY || self.settings.DirectoryBuckets
}

// Whether this device may run background index work now: the merges and roll-ups §11.14 assigns it (the index
// schedule's mayRun). A background host always; a wifi_charging host by the windows rule; on_demand and never hosts
// not.
func (self *SearchPolicy) MayRunBackgroundIndexWork() bool {
	switch self.settings.AllPolicy {
	case SearchPolicyBackground:
		return true
	case SearchPolicyWifiCharging:
		return self.windowsAllow()
	}
	return false
}

// Whether this device may run a roll-up now: background index work it may run, and only while it holds all within
// its cap (§18.4's windows row), else a capable writer runs it.
func (self *SearchPolicy) MayRollUp(allHeld bool, allByteCount int64) bool {
	if !self.MayRunBackgroundIndexWork() || !allHeld {
		return false
	}
	allCap := self.settings.AllCacheByteCount
	return allCap == 0 || allByteCount <= allCap
}

// Opens an OS window until deadline, its budget: wifi_charging syncs all and runs background work inside it. The
// answer ends it early.
func (self *SearchPolicy) BeginWindow(deadline time.Time) func() {
	window := &searchPolicyWindow{deadline: deadline}
	self.stateLock.Lock()
	self.windows[window] = true
	self.stateLock.Unlock()
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.windows, window)
	}
}

// The UTC day now falls in.
func searchPolicyDay(now time.Time) int64 {
	return now.UTC().Unix() / (24 * 60 * 60)
}

// Rolls the background counts to today, the lock held.
func (self *SearchPolicy) rollDayWithLock() {
	if day := searchPolicyDay(self.clock.Now()); day != self.budgetDay {
		self.budgetDay, self.backgroundUsed = day, 0
		clear(self.heldBack)
	}
}

// Whether a background read of byteCount for repoId may go now, within Search.BackgroundByteCount today; one that may
// not is what the repo's sync holds back, until tomorrow or a "search more".
func (self *SearchPolicy) AdmitBackground(repoId Id, byteCount int64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rollDayWithLock()
	if self.settings.BackgroundByteCount < self.backgroundUsed+byteCount {
		self.heldBack[repoId] = byteCount
		return false
	}
	delete(self.heldBack, repoId)
	return true
}

// Counts a background read that went.
func (self *SearchPolicy) SpentBackground(repoId Id, byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rollDayWithLock()
	self.backgroundUsed += byteCount
}

// Today's background downloads, and what the budget holds back of repoId's sync, for search_status.
func (self *SearchPolicy) BackgroundBytes(repoId Id) (used int64, heldBack int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rollDayWithLock()
	return self.backgroundUsed, self.heldBack[repoId]
}

// What a "search more" of missingByteCount waits on before it fetches: "metered" past Search.MeteredMoreByteCount on a
// metered link unless allowMetered, else nothing.
func (self *SearchPolicy) MoreWaiting(missingByteCount int64, allowMetered bool) string {
	if !allowMetered && self.settings.MeteredMoreByteCount < missingByteCount && self.conditions().Metered() {
		return SearchWaitingMetered
	}
	return ""
}

// Whether a forced head refresh of repoId may be taken now, at most one a Search.HeadRefreshInterval; true records it.
func (self *SearchPolicy) MayRefreshHead(repoId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	if at, ok := self.refreshedAt[repoId]; ok && now.Before(at.Add(self.settings.HeadRefreshInterval)) {
		return false
	}
	self.refreshedAt[repoId] = now
	return true
}

// Evicts all shards no search used for Search.UnusedAllAge, where the host sets one; search.state, which is not the
// cache's, stays. Answers the bytes freed.
func (self *SearchPolicy) EvictUnused(cache *SearchCache) (int64, error) {
	if self.settings.UnusedAllAge <= 0 || cache == nil {
		return 0, nil
	}
	return cache.EvictUnused(self.clock.Now().Add(-self.settings.UnusedAllAge))
}
