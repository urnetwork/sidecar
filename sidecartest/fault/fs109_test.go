//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-109 on T2 (§22.8; §11.14's newest row, §5.9's version table, §18.4's targets; D-EVS-52, FI-18, FI-23;
// SEARCH-M10-38): mask memory. A ref with 20,000, then 80,000, recent nonmatching file updates in its buckets (the row's
// 500,000 and 1,000,000 at a tenth and less, below), and
// one all row that a newer nonmatching version masks; a fresh desktop, ios32 and Android app and page Worker each sync
// it, building the version table within Search.VersionMergeByteCount (1 MiB), then run a search alone and then
// DaemonSearchCount's searches at once, each matching the all row and three bucket documents: the masked row never
// shows and every result equals SearchOracle's, while the live heap after a forced collection, sampled at each record a
// search opens and each page it answers, less its value at the start stays within §18.4's working set for a search
// alone and within Search.MemoryByteCount for the ones at once. A search that collects the buckets' keys as it runs, the
// build D-EVS-52 forbids, fails the phone's working set at 80,000 keys, which shows the check catches its return.
//
// Scale: the sync engine stages a shard by reading each document through a one-frame cursor, some 65 µs a document of
// this row's on this host, so 500,000 updates take some 33 s a device and 1,000,000 a minute, past the 10 s §22.8 gave
// a step when these were sized (60 s since QD-1101); the counts here are 20,000 and 80,000, each device's sync a step
// of its own, and the full counts wait on the staging's cost (SEARCH-M10-38's report).
//
// Readings: the updates are new files in the previous bucket and then the current one, written as merged shards, since
// a writer's push of them would merge inside the push anyway; SearchOracle's ledger holds every
// document a query can match, the all row's two versions and the three bucket documents, and leaves out the 1,000,000
// updates, whose text shares no trigram with the query (checked here), so the oracle's answer is the same either way
// and it does not normalize a million texts a search. The concurrent searches run in one actor's goroutines. The heap
// is sampled at each record (gkm asked for RK_g) rather than each 64 KiB frame, since the frame read is the cache's
// (CORE-M10-01's) and has no hook; a page Worker here is the Worker's settings on this host, not wasm.
//
// The heap is the process's, so the row runs in a search heap process of its own (sidecartest's), where nothing another
// test left running allocates beside it; and the searches at once share a sampler of searches at once, which collects
// only with every search holding an engine slot parked at a sample of its own, since a sibling still reading frames
// through another's forced collection counted its frame buffers there: 8 MB to 58 MB at 80,000 on the desktop with
// nothing else in the process, and 111 MB under load (tip-check at abd1bdee), past Search.MemoryByteCount. The oracle's
// answer is taken before a sampler begins, so its work counts in no search's heap.
//
// Not here: the retained expired bucket the row also names, the T4 surrogates (sdk/sidecar_search_t4_test.go runs the
// phones' cells), and the app-host case at the later of M10-out and M8-out.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs109 = Register("FS-109", "", []Tier{TierT2}, Fs109MaskMemory)

// The row's query, and the text the updates hold, which shares none of its trigrams.
const (
	fs109Query      = "quarterly forecast"
	fs109UpdateText = "1000 2000 3000"
)

// The updates of the two phases: the first in the previous bucket, the second's more in the current one.
var fs109Counts = []int{20000, 80000}

// What FS-109's steps saw, which its invariants read.
type fs109State struct {
	world *searchWorld
	// the masked row's path, and every search's result by host and phase
	maskedPath string
	stateLock  sync.Mutex
	results    []*fs109Result
	devices    map[string]*fs109Device
}

// One search: its host, its hits, the oracle's matches, and whether it fetched anything.
type fs109Result struct {
	label   string
	hits    []string
	oracle  []string
	fetched int
}

func (self *fs109State) add(result *fs109Result) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.results = append(self.results, result)
}

// The row's documents: the all row's first version, matching; its newer version in the current bucket, not; and three
// bucket documents that match.
func fs109Documents(now time.Time) (*sidecar.SearchTestDocument, *sidecar.SearchTestDocument, []*sidecar.SearchTestDocument) {
	old := &sidecar.SearchTestDocument{Path: "plans/forecast.md", Version: 1, Title: "Old plan", Text: "the quarterly forecast as it stood", Time: now.Add(-200 * 24 * time.Hour)}
	newer := &sidecar.SearchTestDocument{Path: "plans/forecast.md", Version: 2, Title: "Lunch", Text: "unrelated words about lunch", Time: now}
	matching := []*sidecar.SearchTestDocument{}
	for index := range 3 {
		matching = append(matching, &sidecar.SearchTestDocument{
			Path: fmt.Sprintf("plans/recent-%d.md", index), Version: 1, Title: "Recent", Text: "this quarterly forecast is new", Time: now,
		})
	}
	return old, newer, matching
}

// The updates as one bulk of a bucket's shards.
func fs109Updates(prefix string, count int, at time.Time) *sidecar.SearchTestBulk {
	return &sidecar.SearchTestBulk{Prefix: prefix, Count: count, Version: 1, Document: &sidecar.SearchTestDocument{
		Path: prefix + "template", Version: 1, Text: fs109UpdateText, Time: at,
	}}
}

// Phase 1's index: all holding the masked row, the previous bucket 500,000 updates, the current one the masking
// version and the three matches, pushed by a writer as its head; the ledger the same documents but the updates.
func (self *fs109State) writeFirst(ctx context.Context, net *Net) error {
	world := self.world
	now := net.Clock().Now()
	old, newer, matching := fs109Documents(now)
	self.maskedPath = old.Path
	previous := now.Add(-30 * 24 * time.Hour)
	currentDay := sidecar.SearchTestBucketStartDay(now)
	rolledThrough := sidecar.SearchTestBucketStartDay(previous) - 30
	err := world.index.WriteShards(ctx, world.writerId, old.Time, &sidecar.SearchTestPartition{All: true, RolledThroughDay: rolledThrough, ShardDocumentCount: 1024}, []*sidecar.SearchTestDocument{old}, nil)
	if err != nil {
		return err
	}
	err = world.index.WriteShards(ctx, world.writerId, previous, &sidecar.SearchTestPartition{StartDay: sidecar.SearchTestBucketStartDay(previous), ShardDocumentCount: 16384}, nil, []*sidecar.SearchTestBulk{fs109Updates("notes/previous-", fs109Counts[0], previous)})
	if err != nil {
		return err
	}
	if err := world.index.PushDocuments(ctx, world.writerId, now, append([]*sidecar.SearchTestDocument{newer}, matching...)); err != nil {
		return err
	}
	if sidecar.SearchTestBucketStartDay(now) != currentDay {
		return errors.New("the clock left the current bucket while the index was written")
	}
	if err := world.record(old.Time, old); err != nil {
		return err
	}
	if err := world.ledger.RolledThrough(world.index.RepoId(), world.index.RefId(), rolledThrough); err != nil {
		return err
	}
	return world.record(now, append([]*sidecar.SearchTestDocument{newer}, matching...)...)
}

// Phase 2: more updates in the current bucket's shards, fs109Counts[1] in the buckets.
func (self *fs109State) writeSecond(ctx context.Context, net *Net) error {
	now := net.Clock().Now()
	return self.world.index.WriteShards(ctx, self.world.writerId, now, &sidecar.SearchTestPartition{StartDay: sidecar.SearchTestBucketStartDay(now), ShardDocumentCount: 16384}, nil, []*sidecar.SearchTestBulk{fs109Updates("notes/current-", fs109Counts[1]-fs109Counts[0], now)})
}

// A device of host at a phase, made and synced by sync's step and searched by the steps after.
type fs109Device struct {
	device   *sidecar.SearchTestDevice
	settings *sidecar.SidecarSearchSettings
	// the sampler the device's record hook feeds, swapped per search
	samplerLock sync.Mutex
	sampler     *sidecartest.SearchHeapSampler
}

func (self *fs109Device) current() *sidecartest.SearchHeapSampler {
	self.samplerLock.Lock()
	defer self.samplerLock.Unlock()
	return self.sampler
}

// A sample at a record a search opens: inside its page, holding one of the engine's slots.
func (self *fs109Device) sampleRecord() {
	if current := self.current(); current != nil {
		current.SampleHoldingSlot("record")
	}
}

// A sample between a search's pages, or before its first: holding no slot.
func (self *fs109Device) sample(label string) {
	if current := self.current(); current != nil {
		current.Sample(label)
	}
}

// A fresh sampler of one search, or with atOnce of the searches at once of the device's engine, its start the heap now,
// the device's cache left out as its disk.
func (self *fs109Device) startSampler(atOnce bool) *sidecartest.SearchHeapSampler {
	sampler := sidecartest.NewSearchHeapSamplerLeavingOut(self.device.CacheByteCount)
	if atOnce {
		sampler = sidecartest.NewSearchHeapSamplerOfSearches(self.device.CacheByteCount, self.device)
	}
	self.samplerLock.Lock()
	self.sampler = sampler
	self.samplerLock.Unlock()
	return sampler
}

// The device a step names.
func (self *fs109State) deviceOf(key string) *fs109Device {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.devices[key]
}

// A fresh device of host syncs the ref, building its table within the merge's bound and holding a record a document.
func (self *fs109State) sync(host *searchHost, updates int, key string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		device := &fs109Device{settings: host.settings()}
		made, err := self.world.device(ctx, host, device.settings, nil, 0, device.sampleRecord)
		if err != nil {
			return err
		}
		device.device = made
		self.stateLock.Lock()
		self.devices[key] = device
		self.stateLock.Unlock()
		if err := made.Sync(ctx); err != nil {
			return err
		}
		if held := made.VersionMergeHeldMax(); device.settings.VersionMergeByteCount < held {
			return fmt.Errorf("%s built the version table holding %d B, past %d B", key, held, device.settings.VersionMergeByteCount)
		}
		records, err := made.VersionRecordCount()
		if err != nil {
			return err
		}
		if records < int64(updates) {
			return fmt.Errorf("%s's version table holds %d records, fewer than the %d updates", key, records, updates)
		}
		return nil
	}
}

// One search of the row's query on device, its result recorded beside oracle, SearchOracle's answer taken before.
func (self *fs109State) search(ctx context.Context, device *fs109Device, label string, oracle []string) error {
	fetchedBefore := len(device.device.Fetches())
	result, err := device.device.Search(ctx, &sidecar.SearchRequest{Text: fs109Query, Scope: sidecar.SearchCached, Remote: "off"}, 64, func(page *sidecar.SearchTestPage) {
		device.sample("page")
	})
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	self.add(&fs109Result{label: label, hits: searchHitNames(result.Hits()), oracle: oracle, fetched: len(device.device.Fetches()) - fetchedBefore})
	return nil
}

// The device at key searches alone within its host's working set; with collect, the search holds every bucket row as
// the forbidden build would, and the step expects the working set to fail: by the budget, since a check that could not
// answer at all proves nothing about the build.
func (self *fs109State) alone(host *searchHost, key string, collect bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		device := self.deviceOf(key)
		if device == nil {
			return fmt.Errorf("no device %s", key)
		}
		oracle := self.world.oracleMatches(fs109Query)
		sampler := device.startSampler(false)
		var collected map[[16]byte]string
		if collect {
			var err error
			if collected, err = self.world.index.BucketRows(); err != nil {
				return err
			}
			device.sample("rows collected")
		}
		if err := self.search(ctx, device, key+" alone", oracle); err != nil {
			return err
		}
		withinErr := sampler.CheckWithin(key+"'s search alone", host.workingSetByteCount)
		if !collect || errors.Is(withinErr, sidecartest.ErrSearchHeapRefused) {
			return withinErr
		}
		if withinErr == nil {
			return fmt.Errorf("a search holding the buckets' %d rows stayed within %s's %d B working set: the check would miss the build D-EVS-52 forbids", len(collected), host.name, host.workingSetByteCount)
		}
		return nil
	}
}

// The device at key runs DaemonSearchCount searches at once within Search.MemoryByteCount, then ends. They share a
// sampler of searches at once, each telling it when it ends.
func (self *fs109State) atOnce(key string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		device := self.deviceOf(key)
		if device == nil {
			return fmt.Errorf("no device %s", key)
		}
		defer self.world.done(device.device)
		oracle := self.world.oracleMatches(fs109Query)
		sampler := device.startSampler(true)
		count := device.settings.DaemonSearchCount
		errs := make([]error, count)
		waitGroup := sync.WaitGroup{}
		for index := range count {
			waitGroup.Go(func() {
				defer sampler.SearchEnded()
				errs[index] = self.search(ctx, device, fmt.Sprintf("%s at once %d of %d", key, index+1, count), oracle)
			})
		}
		waitGroup.Wait()
		if err := errors.Join(errs...); err != nil {
			return err
		}
		return sampler.CheckWithin(fmt.Sprintf("%s's %d searches at once", key, count), device.settings.MemoryByteCount)
	}
}

// FI-18 as FS-109 holds it: the masked row never shows, and every search's hits are the oracle's.
func (self *fs109State) fi18() Invariant {
	return NewInvariant("FI-18 (FS-109's masked row and the oracle)", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, result := range self.results {
			for _, hit := range result.hits {
				if path, _, _ := cutVersion(hit); path == self.maskedPath {
					return fmt.Errorf("%s returned the masked row %s", result.label, hit)
				}
			}
			if !slices.Equal(result.hits, result.oracle) {
				return fmt.Errorf("%s found %v, and SearchOracle %v", result.label, result.hits, result.oracle)
			}
		}
		return nil
	})
}

// FI-23 as FS-109 holds it: a search reads only the cache, fetching nothing.
func (self *fs109State) fi23() Invariant {
	return NewInvariant("FI-23 (FS-109's searches fetch nothing)", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, result := range self.results {
			if result.fetched != 0 {
				return fmt.Errorf("%s fetched %d files", result.label, result.fetched)
			}
		}
		return nil
	})
}

// A hit's path and version from "path@version".
func cutVersion(name string) (string, string, bool) {
	for index := len(name) - 1; 0 <= index; index -= 1 {
		if name[index] == '@' {
			return name[:index], name[index+1:], true
		}
	}
	return name, "", false
}

// FS-109's schedule: each device's sync, its search alone and its searches at once steps of their own, each within
// §22.8's 60 s.
func Fs109MaskMemory(net *Net) *Schedule {
	state := &fs109State{devices: map[string]*fs109Device{}}
	steps := []*Step{{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
		world, err := newSearchWorld(net, "fs109")
		if err != nil {
			return err
		}
		state.world = world
		if shared := world.index.QueryTrigramsShared(fs109Query, fs109UpdateText); len(shared) != 0 {
			return fmt.Errorf("the updates' text shares %v with the query", shared)
		}
		return state.writeFirst(ctx, net)
	}}}
	for phase, updates := range fs109Counts {
		if phase == 1 {
			steps = append(steps, &Step{Actor: "writer", Action: state.writeSecond})
		}
		for _, host := range searchHosts() {
			key := fmt.Sprintf("%s at %d", host.name, updates)
			steps = append(steps,
				&Step{Actor: host.name, Action: state.sync(host, updates, key)},
				&Step{Actor: host.name, Action: state.alone(host, key, false)},
				&Step{Actor: host.name, Action: state.atOnce(key)},
			)
		}
	}
	// the forbidden build, planted on a phone at the larger count
	phone := searchHostNamed("ios32")
	planted := fmt.Sprintf("ios32 at %d, collecting", fs109Counts[1])
	steps = append(steps,
		&Step{Actor: "ios32", Action: state.sync(phone, fs109Counts[1], planted)},
		&Step{Actor: "ios32", Action: state.alone(phone, planted, true)},
		&Step{Actor: "ios32", Action: func(ctx context.Context, net *Net) error {
			state.world.close()
			return nil
		}},
	)
	return &Schedule{Id: "FS-109", Steps: steps, Check: []Invariant{state.fi18(), state.fi23()}, Tiers: []Tier{TierT2}}
}

// FS-109 on T2, with one explorer seed: its steps hold no barrier and no background action, so a seed reorders
// nothing, and each run builds a million updates' index again. In a search heap process of its own, where its heap
// checks answer.
func TestFs109(t *testing.T) {
	sidecartest.RunSearchHeapProcess(t, nil, func(t *testing.T) {
		settings := DefaultRuleSettings()
		settings.Seeds = settings.Seeds[:1]
		RunRow(t, "FS-109", "", settings)
	})
}
