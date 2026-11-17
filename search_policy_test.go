//go:build !ios_extension

package sidecar

// SEARCH-M10-20 (§18.4's Search block; FS-77's policy cases, here on the sync engine's fake): the modes per host and
// their windows, a window keeping all only on an unmetered link while charging (QD-1000), an unreported condition
// counting as metered and not charging and a daemon host's as unmetered, Low Power Mode pausing background work,
// per-device overrides sealed in search.state and kept through eviction, the 25 MiB metered wait, the day's background
// budget, one forced head refresh a repo per interval, the caps and the directory row, and a cellular, unplugged phone
// fetching nothing of all.

import (
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A policy over settings, its conditions whatever conditions holds when asked.
func testNewSearchPolicy(t *testing.T, settings *SidecarSearchSettings, state *SidecarSearchState, clock Clock, conditions *SearchConditions) *SearchPolicy {
	t.Helper()
	policy, err := NewSearchPolicy(&SearchPolicyArgs{
		Settings:   settings,
		State:      state,
		Conditions: func() SearchConditions { return *conditions },
		Clock:      clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// A phone's search settings over the defaults: wifi_charging, its caps and no directory buckets (§18.4).
func testPhoneSearchSettings() *SidecarSearchSettings {
	settings := DefaultSidecarSettings().Search
	settings.AllPolicy = SearchPolicyWifiCharging
	settings.AllCacheByteCount = 256 * 1024 * 1024
	settings.UnusedAllAge = 30 * 24 * time.Hour
	settings.DirectoryBuckets = false
	settings.RemoteServe = false
	return settings
}

// §18.4's modes and windows: a desktop keeps all always; a phone only in an OS window or in the foreground, in both
// only on an unmetered link while charging and never in Low Power Mode (QD-1000), so a window on cellular, unplugged or
// in Low Power Mode keeps none, each row failing one condition alone; on_demand and never keep none.
func TestSearchPolicyModesAndWindows(t *testing.T) {
	clock := newIdentityTestClock()
	repoId := evsTestId("repo")
	desktop := testNewSearchPolicy(t, DefaultSidecarSettings().Search, nil, clock, &SearchConditions{DaemonHost: true})
	if !desktop.KeepsAll(repoId, 0) || !desktop.MayRunBackgroundIndexWork() {
		t.Fatal("a desktop does not keep all")
	}
	conditions := &SearchConditions{}
	phone := testNewSearchPolicy(t, testPhoneSearchSettings(), nil, clock, conditions)
	cases := []struct {
		name       string
		conditions SearchConditions
		window     bool
		keeps      bool
	}{
		{name: "unreported, background", conditions: SearchConditions{}, keeps: false},
		{name: "unreported, foreground", conditions: SearchConditions{Foreground: true}, keeps: false},
		{name: "cellular and unplugged, foreground", conditions: SearchConditions{Reported: true, Foreground: true}, keeps: false},
		{name: "cellular and charging, foreground", conditions: SearchConditions{Reported: true, Charging: true, Foreground: true}, keeps: false},
		{name: "wifi and unplugged, foreground", conditions: SearchConditions{Reported: true, Unmetered: true, Foreground: true}, keeps: false},
		{name: "wifi and charging, background", conditions: SearchConditions{Reported: true, Unmetered: true, Charging: true}, keeps: false},
		{name: "wifi and charging, foreground", conditions: SearchConditions{Reported: true, Unmetered: true, Charging: true, Foreground: true}, keeps: true},
		{name: "wifi and charging, foreground, low power", conditions: SearchConditions{Reported: true, Unmetered: true, Charging: true, Foreground: true, LowPower: true}, keeps: false},
		{name: "a window, wifi and charging", conditions: SearchConditions{Reported: true, Unmetered: true, Charging: true}, window: true, keeps: true},
		// a BGProcessingTask can require power and a network, never Wi-Fi: the link alone fails it
		{name: "a window, cellular", conditions: SearchConditions{Reported: true, Charging: true}, window: true, keeps: false},
		{name: "a window, unplugged", conditions: SearchConditions{Reported: true, Unmetered: true}, window: true, keeps: false},
		{name: "a window, low power", conditions: SearchConditions{Reported: true, Unmetered: true, Charging: true, LowPower: true}, window: true, keeps: false},
		{name: "a window, cellular and unplugged", conditions: SearchConditions{Reported: true}, window: true, keeps: false},
		{name: "a window, unreported", conditions: SearchConditions{}, window: true, keeps: false},
		{name: "a window, wifi and charging, foreground", conditions: SearchConditions{Reported: true, Unmetered: true, Charging: true, Foreground: true}, window: true, keeps: true},
	}
	for _, c := range cases {
		*conditions = c.conditions
		end := func() {}
		if c.window {
			end = phone.BeginWindow(clock.Now().Add(time.Minute))
		}
		if got := phone.KeepsAll(repoId, 0); got != c.keeps {
			t.Errorf("%s: keeps all %v", c.name, got)
		}
		if got := phone.MayRunBackgroundIndexWork(); got != c.keeps {
			t.Errorf("%s: may run background work %v", c.name, got)
		}
		end()
	}
	// a window past its deadline holds nothing open, on Wi-Fi while charging, where one inside it keeps all
	*conditions = SearchConditions{Reported: true, Unmetered: true, Charging: true}
	defer phone.BeginWindow(clock.Now().Add(time.Minute))()
	if !phone.KeepsAll(repoId, 0) {
		t.Fatal("a window on Wi-Fi while charging did not keep all")
	}
	clock.advance(2 * time.Minute)
	if phone.KeepsAll(repoId, 0) || phone.MayRunBackgroundIndexWork() {
		t.Error("a window past its deadline kept all")
	}
	for _, mode := range []string{SearchPolicyOnDemand, SearchPolicyNever} {
		settings := DefaultSidecarSettings().Search
		settings.AllPolicy = mode
		policy := testNewSearchPolicy(t, settings, nil, clock, &SearchConditions{DaemonHost: true})
		if policy.KeepsAll(repoId, 0) || policy.MayRunBackgroundIndexWork() {
			t.Errorf("%s keeps all", mode)
		}
	}
}

// D-SDK-23: a condition not yet reported counts as metered and not charging; a daemon host reports none and counts as
// unmetered.
func TestSearchConditionsUnreportedCountAsMetered(t *testing.T) {
	if unreported := (SearchConditions{}); !unreported.Metered() || unreported.OnCharge() || unreported.Paused() {
		t.Fatal("an unreported condition counts as unmetered or charging")
	}
	if daemon := (SearchConditions{DaemonHost: true}); daemon.Metered() || !daemon.OnCharge() {
		t.Fatal("a daemon host counts as metered")
	}
	if reported := (SearchConditions{Reported: true, Unmetered: true, Charging: true, LowPower: true, DaemonHost: true}); reported.Metered() || !reported.OnCharge() || !reported.Paused() {
		t.Fatal("reports are not taken as given")
	}
	got := searchConditionsOf(SidecarSearchConditions{Unmetered: true, Reported: true}, true, false)
	if got.Metered() || !got.Foreground || got.DaemonHost {
		t.Fatalf("a Sidecar's reports: %+v", got)
	}
}

// §18.4's override row: an override per repo or for every repo, sealed in search.state, which eviction keeps; ""
// restores the host's default.
func TestSearchPolicyOverridesInSearchState(t *testing.T) {
	world := newSearchStateTestWorld(t)
	state := world.state
	repoId, otherId := evsTestId("repo"), evsTestId("other")
	policy := testNewSearchPolicy(t, testPhoneSearchSettings(), state, world.clock, &SearchConditions{})
	if policy.Mode(repoId) != SearchPolicyWifiCharging {
		t.Fatal("the host's default is not in force")
	}
	if err := state.SetPolicy(&repoId, SearchPolicyBackground); err != nil {
		t.Fatal(err)
	}
	if policy.Mode(repoId) != SearchPolicyBackground || policy.Mode(otherId) != SearchPolicyWifiCharging {
		t.Fatal("a repo's override")
	}
	if !policy.KeepsAll(repoId, 0) || policy.KeepsAll(otherId, 0) {
		t.Fatal("an override to background does not keep all")
	}
	// eviction drops cache files, never the state
	cache := newTestSearchCacheWorld(t, 1<<30)
	if _, err := cache.cache.Evict(); err != nil {
		t.Fatal(err)
	}
	if err := cache.cache.DropAll(); err != nil {
		t.Fatal(err)
	}
	if policy.Mode(repoId) != SearchPolicyBackground {
		t.Fatal("eviction dropped the override")
	}
	if err := state.SetPolicy(nil, SearchPolicyNever); err != nil {
		t.Fatal(err)
	}
	if policy.Mode(repoId) != SearchPolicyNever || policy.Mode(otherId) != SearchPolicyNever {
		t.Fatal("the every-repo override")
	}
	if err := state.SetPolicy(nil, ""); err != nil {
		t.Fatal(err)
	}
	if policy.Mode(repoId) != SearchPolicyWifiCharging {
		t.Fatal("\"\" did not restore the host's default")
	}
}

// §18.4's metered row: a "search more" of more than 25 MiB on a metered link waits until asked with AllowMetered; under
// it, or unmetered, it proceeds.
func TestSearchPolicyMeteredWait(t *testing.T) {
	conditions := &SearchConditions{Reported: true}
	policy := testNewSearchPolicy(t, testPhoneSearchSettings(), nil, newIdentityTestClock(), conditions)
	big := int64(25*1024*1024 + 1)
	if policy.MoreWaiting(big, false) != SearchWaitingMetered {
		t.Fatal("a metered fetch past 25 MiB did not wait")
	}
	if policy.MoreWaiting(big, true) != "" || policy.MoreWaiting(25*1024*1024, false) != "" {
		t.Fatal("AllowMetered, or 25 MiB, waited")
	}
	*conditions = SearchConditions{}
	if policy.MoreWaiting(big, false) != SearchWaitingMetered {
		t.Fatal("an unreported link did not count as metered")
	}
	*conditions = SearchConditions{Reported: true, Unmetered: true}
	if policy.MoreWaiting(big, false) != "" {
		t.Fatal("an unmetered link waited")
	}
}

// §16.10's background row: background downloads stop at Search.BackgroundByteCount a UTC day, what is held back counted,
// and the next day's budget is whole.
func TestSearchPolicyBackgroundBudget(t *testing.T) {
	settings := DefaultSidecarSettings().Search
	settings.BackgroundByteCount = 1000
	clock := newIdentityTestClock()
	policy := testNewSearchPolicy(t, settings, nil, clock, &SearchConditions{DaemonHost: true})
	repoId := evsTestId("repo")
	if !policy.AdmitBackground(repoId, 600) {
		t.Fatal("a read within the budget held back")
	}
	policy.SpentBackground(repoId, 600)
	if policy.AdmitBackground(repoId, 500) {
		t.Fatal("a read past the budget went")
	}
	if used, heldBack := policy.BackgroundBytes(repoId); used != 600 || heldBack != 500 {
		t.Fatalf("used %d, held back %d", used, heldBack)
	}
	clock.advance(24 * time.Hour)
	if !policy.AdmitBackground(repoId, 500) {
		t.Fatal("the next day's budget is not whole")
	}
	if used, heldBack := policy.BackgroundBytes(repoId); used != 0 || heldBack != 0 {
		t.Fatalf("the next day: used %d, held back %d", used, heldBack)
	}
}

// §16.10's more row: at most one forced head refresh a repo a Search.HeadRefreshInterval.
func TestSearchPolicyHeadRefreshInterval(t *testing.T) {
	clock := newIdentityTestClock()
	policy := testNewSearchPolicy(t, DefaultSidecarSettings().Search, nil, clock, &SearchConditions{DaemonHost: true})
	repoId, otherId := evsTestId("repo"), evsTestId("other")
	if !policy.MayRefreshHead(repoId) || policy.MayRefreshHead(repoId) || !policy.MayRefreshHead(otherId) {
		t.Fatal("refreshes within the interval")
	}
	clock.advance(10 * time.Minute)
	if !policy.MayRefreshHead(repoId) {
		t.Fatal("no refresh after the interval")
	}
}

// §18.4's caps and directory rows: past the cap all is kept on demand and a phone rolls nothing up; a roll-up wants all
// held within the cap; phones keep no directory buckets synced.
func TestSearchPolicyCapsAndTheDirectory(t *testing.T) {
	settings := testPhoneSearchSettings()
	policy := testNewSearchPolicy(t, settings, nil, newIdentityTestClock(), &SearchConditions{Reported: true, Unmetered: true, Charging: true, Foreground: true})
	repoId := evsTestId("repo")
	if !policy.KeepsAll(repoId, settings.AllCacheByteCount) || policy.KeepsAll(repoId, settings.AllCacheByteCount+1) {
		t.Fatal("the cap")
	}
	if !policy.MayRollUp(true, settings.AllCacheByteCount) || policy.MayRollUp(false, 1) || policy.MayRollUp(true, settings.AllCacheByteCount+1) {
		t.Fatal("a roll-up's cap")
	}
	if policy.KeepsLatest(protocol.RepoKind_REPO_KIND_DIRECTORY) || !policy.KeepsLatest(protocol.RepoKind_REPO_KIND_GENERAL) {
		t.Fatal("the directory row on a phone")
	}
	desktop := testNewSearchPolicy(t, DefaultSidecarSettings().Search, nil, newIdentityTestClock(), &SearchConditions{DaemonHost: true})
	if !desktop.KeepsLatest(protocol.RepoKind_REPO_KIND_DIRECTORY) || !desktop.KeepsAll(repoId, 1<<40) {
		t.Fatal("a desktop's caps")
	}
}

// FS-77's policy clause on the sync engine: a cellular, unplugged phone's round brings the latest set and fetches nothing
// of all; on Wi-Fi while charging in the foreground the same ref's round fetches all.
func TestSearchPolicyCellularFetchesNothingOfAll(t *testing.T) {
	world := newTestSyncWorld(t, false)
	world.push(t, evsTestId("writer"), "doc", 3)
	testWriteAll(t, world, 3)
	conditions := &SearchConditions{Reported: true, Foreground: true}
	policy := testNewSearchPolicy(t, testPhoneSearchSettings(), nil, world.cache.clock, conditions)
	err := world.sync.Follow(&searchSyncRefArgs{
		repoId: world.repoId, refId: world.refId, repoKind: protocol.RepoKind_REPO_KIND_GENERAL, source: world.source,
		keepAll:  func() bool { return policy.KeepsAll(world.repoId, 0) },
		mayErase: func(Id, int64) bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	world.round(t)
	for _, fetched := range world.source.fetched() {
		if strings.Contains(fetched, "/a/") && !strings.Contains(fetched, "/a/m@") {
			t.Fatalf("a cellular phone fetched an all shard: %s", fetched)
		}
	}
	*conditions = SearchConditions{Reported: true, Unmetered: true, Charging: true, Foreground: true}
	world.sync.Trigger(world.repoId, nil, SearchSyncForeground)
	world.round(t)
	allShards := 0
	for _, fetched := range world.source.fetched() {
		if strings.Contains(fetched, "/a/") && !strings.Contains(fetched, "/a/m@") {
			allShards += 1
		}
	}
	if allShards != 3 {
		t.Fatalf("on Wi-Fi while charging the round fetched %d all shards", allShards)
	}
}

// §18.4's caps row: a phone evicts all shards no search used for 30 days; search.state stays.
func TestSearchPolicyEvictsUnusedAll(t *testing.T) {
	world := newTestSyncWorld(t, true)
	world.push(t, evsTestId("writer"), "doc", 2)
	testWriteAll(t, world, 2)
	world.round(t)
	settings := testPhoneSearchSettings()
	policy := testNewSearchPolicy(t, settings, nil, world.cache.clock, &SearchConditions{})
	before := world.cache.cache.ByteCount()
	world.cache.clock.advance(31 * 24 * time.Hour)
	freed, err := policy.EvictUnused(world.cache.cache)
	if err != nil {
		t.Fatal(err)
	}
	if freed == 0 || world.cache.cache.ByteCount() != before-freed {
		t.Fatalf("freed %d of %d", freed, before)
	}
	desktop := testNewSearchPolicy(t, DefaultSidecarSettings().Search, nil, world.cache.clock, &SearchConditions{DaemonHost: true})
	if freed, err := desktop.EvictUnused(world.cache.cache); err != nil || freed != 0 {
		t.Fatalf("a desktop evicted %d for age: %v", freed, err)
	}
	if _, err := policy.EvictUnused(nil); err != nil {
		t.Fatal(err)
	}
}
