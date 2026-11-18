//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-77 on T2 (§22.8; §11.14's devices rows, §18.4's Search block, §16.10's cold contract; D-SDK-21, D-SDK-23,
// D-SDK-24, D-SDK-25, FI-18, FI-23; SEARCH-M10-38): an ios32 and an Android app and a page Worker, each holding the
// buckets and not all. A search answers from the buckets at once, fetching nothing; with no indexer designated,
// "search more" fetches every all object the device lacks, whole and newest first, and lists its hits from the display
// fields: a hit whose title holds the query is confirmed with no fetch, the rest are possible matches until opened, and
// no body or note is fetched; two different queries from equal sync states, with and without more, give the same
// server-visible requests; a round on cellular and unplugged fetches nothing of all; a "search more" past
// MeteredMoreByteCount on a metered link waits, reporting waiting=metered and fetching nothing, until the host repeats
// it with AllowMetered, and a host that has reported no conditions counts as metered; each search stays within §18.4's
// working set, the heap sampled at each record a search opens and each page (a "search more"'s, whose download's staging
// runs inside it, measured and reported rather than failed). The windows (QD-1000): an iOS BGProcessingTask window on
// cellular, which can require power and a network but never Wi-Fi, and a window in Low Power Mode each bring the
// latest set and fetch no all; on Wi-Fi while charging in the background a phone syncs all only in an OS-granted
// window, which stops at its budget and resumes in the next, from the first shard it did not keep and fetching none it
// kept, until all is held and a cached search reads it with no fetch. A DropCache between two such windows (QD-1025)
// leaves the next window to fetch the latest set and all again, every shard the first kept included, and a cached
// search then finds the latest set's hits and all's; alone, a device that syncs one document, drops its cache and
// syncs again finds it again, its round after the drop fetching the latest set anew. The rule holds for the whole round
// (QD-1026; owner decision 583): a window on Wi-Fi while charging whose link turns metered, whose charger is unplugged
// or that enters Low Power Mode while it reads its first shard of all reads no further shard and ends before its
// budget, a window while the change holds reads none, and the next window the rule allows resumes from the staged plan,
// reading every other shard youngest first and never that one again, until all is held and a cached search reads it
// with no fetch; a "search more" under the same change reads every shard and completes, its metered wait judged at the
// call; and a window whose link turns metered in its first read reads the latest set whole and nothing of all.
//
// Readings: MeteredMoreByteCount stands at 64 KiB here, under this all's size, for §18.4's 25 MiB over a larger one;
// the candidates a phone lists, possible ones included, are held to SearchOracle's matches, since a phone holds no
// text to verify; the Worker here is the Worker's settings on this host, not wasm. The heap is the process's, so the
// row runs in a search heap process of its own (sidecartest's), where nothing another test left running allocates
// beside its searches, each of which runs alone. A window's budget is a deadline on the world's clock, which a timer
// there keeps as Sidecar.RunSearchBackgroundSync's keeps its own: the device's reads move the clock at a rate, a file a
// read, so the timer fires inside the read that reaches the deadline, and the round stops before its next read. The
// next window resumes through the sync's plan, where each read's files are staged as it lands (search_fetch.go): the
// read in flight at the end is not staged, since its staging sees the ended ctx, so the next window reads it again,
// and what the row holds is that no shard read before the end is read again. A change of the host's conditions partway
// through a round is a timer on the world's clock too, fired inside the read that crosses its time, as a report through
// Sidecar.SetSearchConditions lands while a read is in flight; that read lands and is staged, since a change, unlike a
// window's end, ends no ctx, and the rule is asked again before the next one.
//
// Not here, each listed for the review phase in SEARCH-M10-38's report: device overrides and the key origin's policy
// request, search.state across DropCache and eviction (the world's devices hold no SidecarSearchState), the quick
// burner, an erasure hint dropping a cached document, a replaced file answering collected, the Worker's key-origin
// conditions and Safari's and Firefox's hidden ones, phone merges in windows (FS-75), the T4 surrogates
// (sdk/sidecar_search_t4_test.go), and the app-host case at the later of M10-out and M8-out.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs77 = Register("FS-77", "", []Tier{TierT2}, Fs77PhoneSearch)

// What FS-77's steps saw.
type fs77State struct {
	world *searchWorld
	// paths of the latest set and of all, the titles' and the bodies' matches of the row's query
	stateLock sync.Mutex
	broken    []string
	traces    map[string][]string
}

func (self *fs77State) breaks(format string, arguments ...any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.broken = append(self.broken, fmt.Sprintf(format, arguments...))
}

// The two queries: one the titles hold, one only bodies hold in all.
const (
	fs77Query      = "harbor"
	fs77OtherQuery = "ferry"
)

// The index: two latest documents and a few in all, with filler so all spans several shards.
func (self *fs77State) write(ctx context.Context, net *Net) error {
	world, err := newSearchWorld(net, "fs77")
	if err != nil {
		return err
	}
	self.world = world
	now := net.Clock().Now()
	old := now.Add(-300 * 24 * time.Hour)
	latest := []*sidecar.SearchTestDocument{
		{Path: "notes/harbor.md", Version: 1, Title: "Harbor lights", Text: "the evening boat", Time: now},
		{Path: "notes/timetable.md", Version: 1, Title: "Timetable", Text: "the harbor ferry leaves at noon", Time: now},
	}
	archived := []*sidecar.SearchTestDocument{
		{Path: "archive/harbor-old.md", Version: 1, Title: "Harbor archive", Text: "an old note", Time: old},
		{Path: "archive/dawn.md", Version: 1, Title: "Dawn", Text: "the ferry at the harbor at dawn", Time: old},
	}
	if err := world.index.PushDocuments(ctx, world.writerId, now, latest); err != nil {
		return err
	}
	filler := &sidecar.SearchTestBulk{Prefix: "archive/filler-", Count: 8000, Version: 1, Document: &sidecar.SearchTestDocument{
		Path: "archive/filler-template", Version: 1, Text: "5150 5151", Time: old,
	}}
	rolledThrough := sidecar.SearchTestBucketStartDay(now) - 60
	err = world.index.WriteShards(ctx, world.writerId, old, &sidecar.SearchTestPartition{All: true, RolledThroughDay: rolledThrough, ShardDocumentCount: 2048}, archived, []*sidecar.SearchTestBulk{filler})
	if err != nil {
		return err
	}
	if err := world.record(old, archived...); err != nil {
		return err
	}
	if err := world.ledger.RolledThrough(world.index.RepoId(), world.index.RefId(), rolledThrough); err != nil {
		return err
	}
	return world.record(now, latest...)
}

// The oracle's matches for query over the partitions given.
func (self *fs77State) oracle(query string, partitions sidecartest.SearchScopePartitions) []string {
	world := self.world
	scope := &sidecartest.SearchScope{
		Partitions: partitions, Breadth: sidecartest.SearchBreadthNetwork, NetworkIds: []sidecar.Id{world.networkId}, ReaderId: world.readerId,
	}
	matches := []string{}
	for _, key := range world.oracle.Matches(query, scope) {
		matches = append(matches, fmt.Sprintf("%s@%d", key.Name, key.Version))
	}
	slices.Sort(matches)
	return matches
}

// Whether a fetch is of all's shards.
func fs77AllShard(path string) bool {
	return strings.Contains(path, "/a/") && !strings.HasSuffix(path, "/a/m")
}

// A phone or the Worker on cellular, unplugged and in the foreground: its round fetches nothing of all, a search answers
// from the buckets at once with nothing fetched, its title hit confirmed and its body hit possible, within the working
// set; then on Wi-Fi a "search more" fetches every all shard whole, newest first, nothing but index files, and lists
// all's hits from the display fields.
func (self *fs77State) phone(host *searchHost, query string, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		world := self.world
		conditions := sidecar.SearchConditions{Reported: true, Foreground: true}
		var sampler *sidecartest.SearchHeapSampler
		samplerLock := sync.Mutex{}
		sample := func(at string) {
			samplerLock.Lock()
			current := sampler
			samplerLock.Unlock()
			if current != nil {
				current.Sample(at)
			}
		}
		device, err := world.device(ctx, host, nil, func() sidecar.SearchConditions { return conditions }, 0, func() { sample("record") })
		if err != nil {
			return err
		}
		defer world.done(device)
		if err := device.Sync(ctx); err != nil {
			return err
		}
		for _, fetch := range device.Fetches() {
			if fs77AllShard(fetch.Path) {
				self.breaks("%s fetched all's %s in a round on cellular and unplugged", label, fetch.Path)
			}
		}
		fetchedBefore := len(device.Fetches())
		samplerLock.Lock()
		sampler = sidecartest.NewSearchHeapSamplerLeavingOut(device.CacheByteCount)
		samplerLock.Unlock()
		cached, err := device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: sidecar.SearchCached, Remote: "off"}, 64, func(page *sidecar.SearchTestPage) { sample("page") })
		if err != nil {
			return err
		}
		if fetched := len(device.Fetches()) - fetchedBefore; fetched != 0 {
			self.breaks("%s's search from the buckets fetched %d files", label, fetched)
		}
		if got, want := searchHitNames(cached.Hits()), self.oracle(query, sidecartest.SearchScopeLatest); !slices.Equal(got, want) {
			self.breaks("%s found %v in the buckets, and SearchOracle %v", label, got, want)
		}
		for _, hit := range cached.Hits() {
			titled := false
			for _, field := range hit.Fields {
				titled = titled || strings.Contains(strings.ToLower(field.Text), query)
			}
			switch {
			case titled && hit.State != sidecar.SearchConfirmed:
				self.breaks("%s: %s, whose title holds %q, is state %d, not confirmed", label, hit.Path, query, hit.State)
			case !titled && hit.State != sidecar.SearchPossible:
				self.breaks("%s: %s, whose display fields lack %q, is state %d, not possible", label, hit.Path, query, hit.State)
			}
		}
		if err := sampler.CheckWithin(label+"'s search from the buckets", host.workingSetByteCount); err != nil {
			self.breaks("%v", err)
		}

		// "search more" on Wi-Fi
		conditions = sidecar.SearchConditions{Reported: true, Foreground: true, Unmetered: true}
		fetchedBefore = len(device.Fetches())
		samplerLock.Lock()
		sampler = sidecartest.NewSearchHeapSamplerLeavingOut(device.CacheByteCount)
		samplerLock.Unlock()
		more, err := device.Search(ctx, &sidecar.SearchRequest{Text: query, Scope: sidecar.SearchAll, Remote: "off"}, 256, func(page *sidecar.SearchTestPage) { sample("page") })
		if err != nil {
			return err
		}
		fetches := device.Fetches()[fetchedBefore:]
		trace := searchAllShardsOf(searchTraceOf(fetches))
		self.stateLock.Lock()
		self.traces[label] = searchTraceOf(device.Fetches())
		self.stateLock.Unlock()
		shards := fs77AllShards(world)
		if len(trace) != len(shards) {
			self.breaks("%s's search more fetched %d all shards of %d", label, len(trace), len(shards))
		}
		for index := range min(len(trace), len(shards)) {
			if want := fs77TraceLine(shards[index]); trace[index] != want {
				self.breaks("%s's fetch %d of all was %s, not %s, whole, youngest first", label, index, trace[index], want)
				break
			}
		}
		for _, fetch := range fetches {
			if !strings.HasPrefix(fetch.Path, ".ur-index/") {
				self.breaks("%s fetched %s, which is no index file, before anything was opened", label, fetch.Path)
			}
		}
		if got, want := searchHitNames(more.Hits()), self.oracle(query, sidecartest.SearchScopeAll); !slices.Equal(got, want) {
			self.breaks("%s's search more found %v, and SearchOracle %v", label, got, want)
		}
		if last := more.Last(); last.FetchBytes != 0 || last.Waiting != "" {
			self.breaks("%s's search more ended with %d bytes to fetch, waiting %q", label, last.FetchBytes, last.Waiting)
		}
		// the download's staging runs inside the search here, which §18.4's working set does not plainly cover: measured and
		// reported, for SEARCH-M10-38's report, never failed
		if err := sampler.CheckWithin(label+"'s search more", host.workingSetByteCount); err != nil {
			fs77Measured.stateLock.Lock()
			fs77Measured.lines = append(fs77Measured.lines, err.Error())
			fs77Measured.stateLock.Unlock()
		}
		return nil
	}
}

// What FS-77's last run measured past a budget without failing on it, for its test's log.
var fs77Measured = struct {
	stateLock sync.Mutex
	lines     []string
}{}

// A "search more" on a metered link, and on one no condition was reported for, waits with waiting=metered and fetches
// nothing of all; repeated with AllowMetered, it fetches all.
func (self *fs77State) metered(host *searchHost, conditions sidecar.SearchConditions, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		settings := host.settings()
		settings.MeteredMoreByteCount = 64 * 1024
		device, err := self.world.device(ctx, host, settings, func() sidecar.SearchConditions { return conditions }, 0, nil)
		if err != nil {
			return err
		}
		defer self.world.done(device)
		if err := device.Sync(ctx); err != nil {
			return err
		}
		fetchedBefore := len(device.Fetches())
		waited, err := device.Search(ctx, &sidecar.SearchRequest{Text: fs77Query, Scope: sidecar.SearchAll, Remote: "off"}, 256, nil)
		if err != nil {
			return err
		}
		waiting := false
		for _, page := range waited.Pages {
			waiting = waiting || page.Progress.Waiting == sidecar.SearchWaitingMetered
		}
		for _, report := range waited.Reports {
			waiting = waiting || report.Progress.Waiting == sidecar.SearchWaitingMetered
		}
		if !waiting {
			self.breaks("%s: a search more past MeteredMoreByteCount did not report waiting=metered", label)
		}
		for _, fetch := range device.Fetches()[fetchedBefore:] {
			if fs77AllShard(fetch.Path) {
				self.breaks("%s fetched all's %s while waiting on the metered link", label, fetch.Path)
			}
		}
		allowed, err := device.Search(ctx, &sidecar.SearchRequest{Text: fs77Query, Scope: sidecar.SearchAll, Remote: "off", AllowMetered: true}, 256, nil)
		if err != nil {
			return err
		}
		fetchedAll := slices.ContainsFunc(device.Fetches()[fetchedBefore:], func(fetch sidecar.SearchTestFetch) bool { return fs77AllShard(fetch.Path) })
		if !fetchedAll || allowed.Last().Waiting != "" {
			self.breaks("%s: repeated with AllowMetered, the search more fetched all %t, waiting %q", label, fetchedAll, allowed.Last().Waiting)
		}
		return nil
	}
}

// All's shards at the head in the order a phone fetches them, youngest first.
func fs77AllShards(world *searchWorld) []sidecar.SearchTestFile {
	shards := []sidecar.SearchTestFile{}
	for _, file := range world.index.Files() {
		if file.AllShard {
			shards = append(shards, file)
		}
	}
	slices.SortFunc(shards, func(a sidecar.SearchTestFile, b sidecar.SearchTestFile) int {
		return fs110ShardNumber(b.Path) - fs110ShardNumber(a.Path)
	})
	return shards
}

// A file as a fetch trace's line names it (searchTraceOf).
func fs77TraceLine(file sidecar.SearchTestFile) string {
	return fmt.Sprintf("%s@%d:%d", file.Path, file.Version, file.ByteCount)
}

// The bytes a second a window's reads take on the world's clock: what moves the clock to a window's end.
const fs77ReadByteRate = 1000 * 1000

// FS-77's iOS BGProcessingTask window on cellular, whose name its failure carries.
const fs77CellularWindowLabel = "ios32 in a BGProcessingTask window on cellular"

// A window's ctx: the deadline it carries is on the world's clock, where only a timer of that clock ends it, since a
// ctx's own deadline reads real time, which the world's clock does not keep.
type fs77WindowContext struct {
	context.Context
	deadline time.Time
}

// The window's end, on the world's clock.
func (self *fs77WindowContext) Deadline() (time.Time, bool) {
	return self.deadline, true
}

// Runs one OS window of budget on device, as Sidecar.RunSearchBackgroundSync runs one on its own clock: a timer on the
// world's clock ends the window's ctx at the deadline, fired inside the read that moves the clock there, so the round
// stops before its next read. Answers the deadline, with nil where the window ran to its budget or out of work.
func fs77Window(ctx context.Context, net *Net, device *sidecar.SearchTestDevice, budget time.Duration) (time.Time, error) {
	clock := net.Clock()
	deadline := clock.Now().Add(budget)
	windowCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := clock.AfterFunc(budget, cancel)
	defer stop()
	err := device.RunBackgroundSync(&fs77WindowContext{Context: windowCtx, deadline: deadline})
	if windowCtx.Err() != nil && ctx.Err() == nil {
		// the window reached its budget: what it did not reach, the next one does
		return deadline, nil
	}
	return deadline, err
}

// A phone's OS window whose conditions allow no all: its round brings the latest set and fetches nothing of all.
// windowsRule, where given, is planted in the device's policy first.
func (self *fs77State) windowWithoutAll(host *searchHost, conditions sidecar.SearchConditions, label string, windowsRule func(conditions sidecar.SearchConditions, inWindow bool) bool) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		device, err := self.world.device(ctx, host, nil, func() sidecar.SearchConditions { return conditions }, 0, nil)
		if err != nil {
			return err
		}
		defer self.world.done(device)
		if windowsRule != nil {
			device.PlantSearchWindowsRule(windowsRule)
		}
		// no read moves the clock here: the window ends when its round does
		if _, err := fs77Window(ctx, net, device, time.Hour); err != nil {
			return err
		}
		fetches := device.Fetches()
		if len(fetches) == 0 {
			self.breaks("%s fetched nothing, not even the latest set", label)
		}
		for _, fetch := range fetches {
			if fs77AllShard(fetch.Path) {
				self.breaks("%s fetched all's %s", label, fetch.Path)
			}
		}
		return nil
	}
}

// An iOS BGProcessingTask window on cellular: one can require power and a network, never Wi-Fi, so it opens while
// charging on any link, and fetches no all (QD-1000).
func (self *fs77State) cellularWindow(windowsRule func(conditions sidecar.SearchConditions, inWindow bool) bool) func(ctx context.Context, net *Net) error {
	conditions := sidecar.SearchConditions{Reported: true, Charging: true}
	return self.windowWithoutAll(searchHostNamed("ios32"), conditions, fs77CellularWindowLabel, windowsRule)
}

// A phone in the background on Wi-Fi while charging, reading a file at a time at fs77ReadByteRate: a round outside a
// window brings the latest set and nothing of all, since such a phone syncs all only in an OS-granted window; a window
// whose budget ends partway through all stops at it, reading nothing after it; and the next window resumes from the
// first shard the last did not keep, reading again none that landed before the last one's end, youngest first, until
// all is held, which a cached search then reads with no fetch.
func (self *fs77State) wifiChargingWindows(host *searchHost, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		world := self.world
		conditions := sidecar.SearchConditions{Reported: true, Unmetered: true, Charging: true}
		device, err := world.index.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
			Settings: host.settings(), Conditions: func() sidecar.SearchConditions { return conditions },
			// a file a read, so a window's end falls between two of all's shards
			ReadByteRate: fs77ReadByteRate, ReadByteCount: 1,
		})
		if err != nil {
			return err
		}
		defer device.Close()
		if err := device.Sync(ctx); err != nil {
			return err
		}
		outside := device.Fetches()
		if len(outside) == 0 {
			self.breaks("%s's round outside a window fetched nothing, not even the latest set", label)
		}
		for _, fetch := range outside {
			if fs77AllShard(fetch.Path) {
				self.breaks("%s fetched all's %s in a round outside a window", label, fetch.Path)
			}
		}
		shards := fs77AllShards(world)
		if len(shards) < 3 {
			return fmt.Errorf("all holds %d shards, too few for a window to stop partway", len(shards))
		}
		order := []string{}
		allTime := time.Duration(0)
		for _, shard := range shards {
			order = append(order, fs77TraceLine(shard))
			allTime += fs77ReadTime(shard)
		}

		// the first window's budget ends halfway through its second read of all
		before := len(device.Fetches())
		deadline, err := fs77Window(ctx, net, device, fs77ReadTime(shards[0])+fs77ReadTime(shards[1])/2)
		if err != nil {
			return err
		}
		fetches := device.Fetches()[before:]
		lines := searchTraceOf(fetches)
		first := []string{}
		// the shards whose reads ended before the window's end, and how many ended at it or past it
		landed := map[string]bool{}
		pastEnd := 0
		for index, fetch := range fetches {
			if !fs77AllShard(fetch.Path) {
				continue
			}
			first = append(first, lines[index])
			if fetch.At.Before(deadline) {
				landed[lines[index]] = true
			} else {
				pastEnd += 1
			}
		}
		switch {
		case len(landed) == 0:
			self.breaks("%s's first window read none of all before its end: %v", label, first)
		case 1 < pastEnd:
			self.breaks("%s's first window read %d shards past its end, not at most the one in flight then: %v", label, pastEnd, first)
		case len(order) <= len(first):
			self.breaks("%s's first window read all, %v, past its budget", label, first)
		case !slices.Equal(first, order[:len(first)]):
			self.breaks("%s's first window read all as %v, not youngest first, %v", label, first, order)
		}

		// the next window, with the budget to finish: it reads on from the first shard that had not landed at the last
		// one's end, youngest first, never one that had, and the one in flight then again unless that read was kept
		before = len(device.Fetches())
		deadline, err = fs77Window(ctx, net, device, allTime+time.Minute)
		if err != nil {
			return err
		}
		if !net.Clock().Now().Before(deadline) {
			self.breaks("%s's second window ran to its budget, not until all was held", label)
		}
		second := searchAllShardsOf(searchTraceOf(device.Fetches()[before:]))
		pending := []string{}
		for _, line := range order {
			if !landed[line] {
				pending = append(pending, line)
			}
		}
		resumes := slices.Equal(second, pending) || (pastEnd == 1 && 0 < len(pending) && slices.Equal(second, pending[1:]))
		if !resumes {
			self.breaks("%s's second window read all as %v, not on from where the first, %v, ended: %v", label, second, first, pending)
		}

		// all is held: a cached search reads it, fetching nothing
		before = len(device.Fetches())
		cached, err := device.Search(ctx, &sidecar.SearchRequest{Text: fs77Query, Scope: sidecar.SearchCached, Remote: "off"}, 64, nil)
		if err != nil {
			return err
		}
		if fetched := len(device.Fetches()) - before; fetched != 0 {
			self.breaks("%s's cached search after the windows fetched %d files", label, fetched)
		}
		if got, want := searchHitNames(cached.Hits()), self.oracle(fs77Query, sidecartest.SearchScopeAll); !slices.Equal(got, want) {
			self.breaks("%s's cached search after the windows found %v, and SearchOracle over all %v", label, got, want)
		}
		return nil
	}
}

// FS-77's phone on Wi-Fi while charging whose cache is dropped between two OS windows (QD-1025).
const fs77DropLabel = "android on Wi-Fi while charging, its cache dropped between two windows"

// A phone on Wi-Fi while charging, reading a file at a time at fs77ReadByteRate, whose cache is dropped between two
// windows: a round outside a window brings the latest set, the first window part of all; after DropCache the next
// window, with the budget to finish, fetches the latest set again and every shard of all, youngest first, the ones the
// first window kept included, and a cached search then finds the latest set's hits and all's with no fetch. Before
// QD-1025's reset the window after the drop counted every dropped file as held, and the search found not even the
// latest set's hits.
func (self *fs77State) dropBetweenWindows(host *searchHost, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		world := self.world
		conditions := sidecar.SearchConditions{Reported: true, Unmetered: true, Charging: true}
		device, err := world.index.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
			Settings: host.settings(), Conditions: func() sidecar.SearchConditions { return conditions },
			ReadByteRate: fs77ReadByteRate, ReadByteCount: 1,
		})
		if err != nil {
			return err
		}
		defer device.Close()
		if err := device.Sync(ctx); err != nil {
			return err
		}
		shards := fs77AllShards(world)
		if len(shards) < 2 {
			return fmt.Errorf("all holds %d shards, too few for a window to stop partway", len(shards))
		}
		order := []string{}
		allTime := time.Duration(0)
		for _, shard := range shards {
			order = append(order, fs77TraceLine(shard))
			allTime += fs77ReadTime(shard)
		}
		before := len(device.Fetches())
		if _, err := fs77Window(ctx, net, device, fs77ReadTime(shards[0])+fs77ReadTime(shards[1])/2); err != nil {
			return err
		}
		if first := searchAllShardsOf(searchTraceOf(device.Fetches()[before:])); len(first) == 0 || len(order) <= len(first) {
			self.breaks("%s: the first window read %v of all, not part of it", label, first)
		}

		if err := device.DropCache(); err != nil {
			return err
		}
		before = len(device.Fetches())
		// the latest set's files are a few KiB, read in well under the hour beside all's time
		deadline, err := fs77Window(ctx, net, device, allTime+time.Hour)
		if err != nil {
			return err
		}
		if !net.Clock().Now().Before(deadline) {
			self.breaks("%s: the window after the drop ran to its budget, not until all was held", label)
		}
		fetches := device.Fetches()[before:]
		if !slices.ContainsFunc(fetches, func(fetch sidecar.SearchTestFetch) bool { return !fs77AllShard(fetch.Path) }) {
			self.breaks("%s: the window after the drop fetched none of the latest set", label)
		}
		if second := searchAllShardsOf(searchTraceOf(fetches)); !slices.Equal(second, order) {
			self.breaks("%s: the window after the drop read all as %v, not every shard youngest first, %v", label, second, order)
		}

		before = len(device.Fetches())
		cached, err := device.Search(ctx, &sidecar.SearchRequest{Text: fs77Query, Scope: sidecar.SearchCached, Remote: "off"}, 64, nil)
		if err != nil {
			return err
		}
		if fetched := len(device.Fetches()) - before; fetched != 0 {
			self.breaks("%s: the cached search after the windows fetched %d files", label, fetched)
		}
		got := searchHitNames(cached.Hits())
		for _, latest := range self.oracle(fs77Query, sidecartest.SearchScopeLatest) {
			if !slices.Contains(got, latest) {
				self.breaks("%s: the cached search after the windows found %v, without the latest set's %s", label, got, latest)
			}
		}
		if want := self.oracle(fs77Query, sidecartest.SearchScopeAll); !slices.Equal(got, want) {
			self.breaks("%s: the cached search after the windows found %v, and SearchOracle over all %v", label, got, want)
		}
		return nil
	}
}

// A device that syncs, finds the row's query in the buckets, drops its cache and syncs again: the round after the drop
// fetches the latest set anew, and the same cached search finds what it found before (QD-1025). Before the reset, that
// round fetched nothing and the search found nothing until a restart.
func (self *fs77State) dropAndSync(host *searchHost, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		device, err := self.world.device(ctx, host, nil, nil, 0, nil)
		if err != nil {
			return err
		}
		defer self.world.done(device)
		search := func() ([]string, error) {
			found, err := device.Search(ctx, &sidecar.SearchRequest{Text: fs77Query, Scope: sidecar.SearchCached, Remote: "off"}, 64, nil)
			if err != nil {
				return nil, err
			}
			return searchHitNames(found.Hits()), nil
		}
		want := self.oracle(fs77Query, sidecartest.SearchScopeLatest)
		if len(want) == 0 {
			return fmt.Errorf("SearchOracle finds nothing of %q for %s to find", fs77Query, label)
		}
		if err := device.Sync(ctx); err != nil {
			return err
		}
		if got, err := search(); err != nil {
			return err
		} else if !slices.Equal(got, want) {
			self.breaks("%s found %v before its drop, and SearchOracle %v", label, got, want)
		}
		fetched := len(device.Fetches())
		if err := device.DropCache(); err != nil {
			return err
		}
		if err := device.Sync(ctx); err != nil {
			return err
		}
		if len(device.Fetches()) == fetched {
			self.breaks("%s's round after its drop fetched nothing", label)
		}
		if got, err := search(); err != nil {
			return err
		} else if !slices.Equal(got, want) {
			self.breaks("%s found %v after its drop and a round, and SearchOracle %v", label, got, want)
		}
		return nil
	}
}

// A host's reports as Sidecar.SetSearchConditions keeps them, which a device's policy reads at each decision.
type fs77Conditions struct {
	stateLock  sync.Mutex
	conditions sidecar.SearchConditions
}

// The conditions last reported.
func (self *fs77Conditions) get() sidecar.SearchConditions {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.conditions
}

// Reports conditions.
func (self *fs77Conditions) set(conditions sidecar.SearchConditions) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.conditions = conditions
}

// One change partway through a round (QD-1026), and what a case's failure calls it.
type fs77Change struct {
	name       string
	conditions sidecar.SearchConditions
}

// What ends a phone's window work partway, each from Wi-Fi while charging: its link turning metered, its charger
// unplugged, Low Power Mode turned on; foreground as given.
func fs77Changes(foreground bool) []fs77Change {
	return []fs77Change{
		{name: "its link turns metered", conditions: sidecar.SearchConditions{Reported: true, Charging: true, Foreground: foreground}},
		{name: "its charger is unplugged", conditions: sidecar.SearchConditions{Reported: true, Unmetered: true, Foreground: foreground}},
		{name: "it enters Low Power Mode", conditions: sidecar.SearchConditions{Reported: true, Unmetered: true, Charging: true, LowPower: true, Foreground: foreground}},
	}
}

// A device of host on the world reading a file at a time at fs77ReadByteRate, so a change timed on the world's clock
// lands inside one read of all, its conditions what reports holds.
func (self *fs77State) readingDevice(ctx context.Context, host *searchHost, reports *fs77Conditions) (*sidecar.SearchTestDevice, error) {
	return self.world.index.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
		Settings: host.settings(), Conditions: reports.get, ReadByteRate: fs77ReadByteRate, ReadByteCount: 1,
	})
}

// A read's time on the world's clock, as the world's source takes it.
func fs77ReadTime(file sidecar.SearchTestFile) time.Duration {
	return time.Duration(int64(file.ByteCount) * int64(time.Second) / fs77ReadByteRate)
}

// A phone in the background on Wi-Fi while charging whose conditions change while its window reads the first shard of
// all (QD-1026): the window reads that shard and no further one, ending before its budget, since its round asks the
// windows rule again before each read of all; a window while the change holds reads nothing of all; and once Wi-Fi and
// the charger are back the next window resumes from the staged plan, reading every other shard youngest first and never
// the first again, until all is held, which a cached search then reads with no fetch.
func (self *fs77State) windowChangesMidRound(host *searchHost, change fs77Change, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		world := self.world
		allowed := sidecar.SearchConditions{Reported: true, Unmetered: true, Charging: true}
		reports := &fs77Conditions{conditions: allowed}
		device, err := self.readingDevice(ctx, host, reports)
		if err != nil {
			return err
		}
		defer device.Close()
		// outside a window: the latest set alone
		if err := device.Sync(ctx); err != nil {
			return err
		}
		if outside := searchAllShardsOf(searchTraceOf(device.Fetches())); len(outside) != 0 {
			self.breaks("%s: a round outside a window fetched all's %v", label, outside)
		}
		shards := fs77AllShards(world)
		if len(shards) < 3 {
			return fmt.Errorf("all holds %d shards, too few for a change to land partway", len(shards))
		}
		order := []string{}
		allTime := time.Duration(0)
		for _, shard := range shards {
			order = append(order, fs77TraceLine(shard))
			allTime += fs77ReadTime(shard)
		}

		// a window with the budget for all, the change landing halfway through its first read of all
		before := len(device.Fetches())
		stop := net.Clock().AfterFunc(fs77ReadTime(shards[0])/2, func() { reports.set(change.conditions) })
		deadline, err := fs77Window(ctx, net, device, allTime+time.Hour)
		stop()
		if err != nil {
			return err
		}
		if reports.get() != change.conditions {
			return fmt.Errorf("%s: the window read nothing for the change to land in", label)
		}
		if first := searchAllShardsOf(searchTraceOf(device.Fetches()[before:])); !slices.Equal(first, order[:1]) {
			self.breaks("%s: once %s while it read the first shard of all, the window read all as %v, not %v alone", label, change.name, first, order[:1])
		}
		if !net.Clock().Now().Before(deadline) {
			self.breaks("%s: once %s, the window ran on to its budget", label, change.name)
		}

		// a window while the change holds: nothing of all
		before = len(device.Fetches())
		if _, err := fs77Window(ctx, net, device, allTime+time.Hour); err != nil {
			return err
		}
		if held := searchAllShardsOf(searchTraceOf(device.Fetches()[before:])); len(held) != 0 {
			self.breaks("%s: a window after %s fetched all's %v", label, change.name, held)
		}

		// Wi-Fi and the charger back: the next window resumes from the staged plan and completes
		reports.set(allowed)
		before = len(device.Fetches())
		deadline, err = fs77Window(ctx, net, device, allTime+time.Hour)
		if err != nil {
			return err
		}
		if !net.Clock().Now().Before(deadline) {
			self.breaks("%s: the window the rule allowed again ran to its budget, not until all was held", label)
		}
		if rest := searchAllShardsOf(searchTraceOf(device.Fetches()[before:])); !slices.Equal(rest, order[1:]) {
			self.breaks("%s: the window the rule allowed again read all as %v, not on from the staged plan, %v", label, rest, order[1:])
		}
		before = len(device.Fetches())
		cached, err := device.Search(ctx, &sidecar.SearchRequest{Text: fs77Query, Scope: sidecar.SearchCached, Remote: "off"}, 64, nil)
		if err != nil {
			return err
		}
		if fetched := len(device.Fetches()) - before; fetched != 0 {
			self.breaks("%s: the cached search after the windows fetched %d files", label, fetched)
		}
		if got, want := searchHitNames(cached.Hits()), self.oracle(fs77Query, sidecartest.SearchScopeAll); !slices.Equal(got, want) {
			self.breaks("%s: the cached search after the windows found %v, and SearchOracle over all %v", label, got, want)
		}
		return nil
	}
}

// A phone in the foreground on Wi-Fi while charging whose "search more" sees the change while it reads its first shard
// of all: the call reads every shard youngest first and completes, since its metered wait is judged once at the call
// (MoreWaiting) and its round is not asked the windows rule again; it lists all's hits.
func (self *fs77State) moreReadsOnMidRound(host *searchHost, change fs77Change, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		world := self.world
		// unplugged at first, so its own round keeps no all
		reports := &fs77Conditions{conditions: sidecar.SearchConditions{Reported: true, Unmetered: true, Foreground: true}}
		device, err := self.readingDevice(ctx, host, reports)
		if err != nil {
			return err
		}
		defer device.Close()
		if err := device.Sync(ctx); err != nil {
			return err
		}
		if held := searchAllShardsOf(searchTraceOf(device.Fetches())); len(held) != 0 {
			self.breaks("%s: a round unplugged fetched all's %v", label, held)
		}
		shards := fs77AllShards(world)
		if len(shards) < 2 {
			return fmt.Errorf("all holds %d shards, too few for a change to land partway", len(shards))
		}
		order := []string{}
		for _, shard := range shards {
			order = append(order, fs77TraceLine(shard))
		}

		reports.set(sidecar.SearchConditions{Reported: true, Unmetered: true, Charging: true, Foreground: true})
		before := len(device.Fetches())
		stop := net.Clock().AfterFunc(fs77ReadTime(shards[0])/2, func() { reports.set(change.conditions) })
		more, err := device.Search(ctx, &sidecar.SearchRequest{Text: fs77Query, Scope: sidecar.SearchAll, Remote: "off"}, 256, nil)
		stop()
		if err != nil {
			return err
		}
		if reports.get() != change.conditions {
			return fmt.Errorf("%s: the search more read nothing for the change to land in", label)
		}
		if trace := searchAllShardsOf(searchTraceOf(device.Fetches()[before:])); !slices.Equal(trace, order) {
			self.breaks("%s: once %s while it read the first shard of all, the search more read all as %v, not every shard, %v", label, change.name, trace, order)
		}
		if last := more.Last(); last.FetchBytes != 0 || last.Waiting != "" {
			self.breaks("%s: the search more ended with %d bytes to fetch, waiting %q", label, last.FetchBytes, last.Waiting)
		}
		if got, want := searchHitNames(more.Hits()), self.oracle(fs77Query, sidecartest.SearchScopeAll); !slices.Equal(got, want) {
			self.breaks("%s: the search more found %v, and SearchOracle %v", label, got, want)
		}
		return nil
	}
}

// A phone in the background on Wi-Fi while charging whose first window's link turns metered inside its first read: the
// window reads every file of the latest set the head lists and nothing of all, and a cached search finds the latest
// set's hits.
func (self *fs77State) latestReadsOnMidRound(host *searchHost, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		world := self.world
		metered := sidecar.SearchConditions{Reported: true, Charging: true}
		reports := &fs77Conditions{conditions: sidecar.SearchConditions{Reported: true, Unmetered: true, Charging: true}}
		device, err := self.readingDevice(ctx, host, reports)
		if err != nil {
			return err
		}
		defer device.Close()
		// the first read moves the clock past a nanosecond, whatever file it takes
		stop := net.Clock().AfterFunc(time.Nanosecond, func() { reports.set(metered) })
		_, err = fs77Window(ctx, net, device, time.Hour)
		stop()
		if err != nil {
			return err
		}
		if reports.get() != metered {
			return fmt.Errorf("%s: the window read nothing for the change to land in", label)
		}
		fetches := device.Fetches()
		if held := searchAllShardsOf(searchTraceOf(fetches)); len(held) != 0 {
			self.breaks("%s: a window whose link turned metered in its first read fetched all's %v", label, held)
		}
		want := []string{}
		for _, file := range world.index.Files() {
			if !file.AllShard && !strings.HasSuffix(file.Path, "/lock") {
				want = append(want, file.Path)
			}
		}
		got := []string{}
		for _, fetch := range fetches {
			got = append(got, fetch.Path)
		}
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(got, want) {
			self.breaks("%s: a window whose link turned metered in its first read fetched %v of the latest set %v", label, got, want)
		}
		cached, err := device.Search(ctx, &sidecar.SearchRequest{Text: fs77Query, Scope: sidecar.SearchCached, Remote: "off"}, 64, nil)
		if err != nil {
			return err
		}
		if got, want := searchHitNames(cached.Hits()), self.oracle(fs77Query, sidecartest.SearchScopeLatest); !slices.Equal(got, want) {
			self.breaks("%s: the cached search after the window found %v, and SearchOracle over the latest set %v", label, got, want)
		}
		return nil
	}
}

// FS-77's changes partway through a round (QD-1026): each in an android window, each under an ios32 "search more", and
// the latest set read whole.
func (self *fs77State) midRoundSteps() []*Step {
	steps := []*Step{}
	for _, change := range fs77Changes(false) {
		label := "android in a window on Wi-Fi while charging, where " + change.name
		steps = append(steps, &Step{Actor: "android", Action: self.windowChangesMidRound(searchHostNamed("android"), change, label)})
	}
	for _, change := range fs77Changes(true) {
		label := "ios32's search more on Wi-Fi while charging, where " + change.name
		steps = append(steps, &Step{Actor: "ios32", Action: self.moreReadsOnMidRound(searchHostNamed("ios32"), change, label)})
	}
	steps = append(steps, &Step{Actor: "android", Action: self.latestReadsOnMidRound(searchHostNamed("android"), "android's first window, whose link turns metered in its first read")})
	return steps
}

// FI-23 as FS-77 holds it: two different queries from equal sync states give the same requests.
func (self *fs77State) fi23() Invariant {
	return NewInvariant("FI-23 (FS-77's equal requests)", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		one, other := self.traces["ios32 "+fs77Query], self.traces["ios32 "+fs77OtherQuery]
		if one != nil && other != nil && !slices.Equal(one, other) {
			return fmt.Errorf("two queries from equal states asked evs differently: %v and %v", one, other)
		}
		return nil
	})
}

// FI-18 as FS-77 holds it, with §18.4's rules: what the steps broke.
func (self *fs77State) fi18() Invariant {
	return NewInvariant("FI-18 (FS-77's phone search)", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if 0 < len(self.broken) {
			return errors.New(strings.Join(self.broken, "; "))
		}
		return nil
	})
}

// FS-77's schedule.
func Fs77PhoneSearch(net *Net) *Schedule {
	state := &fs77State{traces: map[string][]string{}}
	steps := []*Step{{Actor: "writer", Action: state.write}}
	for _, name := range []string{"ios32", "android", "worker"} {
		steps = append(steps, &Step{Actor: name, Action: state.phone(searchHostNamed(name), fs77Query, name+" "+fs77Query)})
	}
	steps = append(steps, &Step{Actor: "ios32", Action: state.phone(searchHostNamed("ios32"), fs77OtherQuery, "ios32 "+fs77OtherQuery)})
	steps = append(steps, &Step{Actor: "ios32", Action: state.metered(searchHostNamed("ios32"), sidecar.SearchConditions{Reported: true, Foreground: true}, "ios32 on cellular")})
	steps = append(steps, &Step{Actor: "android", Action: state.metered(searchHostNamed("android"), sidecar.SearchConditions{}, "android reporting nothing")})
	// the windows (QD-1000)
	lowPower := sidecar.SearchConditions{Reported: true, Unmetered: true, Charging: true, LowPower: true}
	steps = append(steps,
		&Step{Actor: "ios32", Action: state.cellularWindow(nil)},
		&Step{Actor: "ios32", Action: state.windowWithoutAll(searchHostNamed("ios32"), lowPower, "ios32 in a window in Low Power Mode", nil)},
		&Step{Actor: "android", Action: state.wifiChargingWindows(searchHostNamed("android"), "android on Wi-Fi while charging")},
		&Step{Actor: "android", Action: state.dropBetweenWindows(searchHostNamed("android"), fs77DropLabel)},
	)
	// the rule through a whole round (QD-1026)
	steps = append(steps, state.midRoundSteps()...)
	steps = append(steps, &Step{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
		state.world.close()
		return nil
	}})
	return &Schedule{Id: "FS-77", Steps: steps, Check: []Invariant{state.fi23(), state.fi18()}, Tiers: []Tier{TierT2}}
}

// FS-77 on T2, in a search heap process of its own, where its heap checks answer.
func TestFs77(t *testing.T) {
	sidecartest.RunSearchHeapProcess(t, nil, func(t *testing.T) {
		RunRow(t, "FS-77", "", nil)
		fs77Measured.stateLock.Lock()
		defer fs77Measured.stateLock.Unlock()
		for _, line := range fs77Measured.lines {
			t.Logf("measured: %s", line)
		}
	})
}

// FS-77's BGProcessingTask window on cellular catches a windows rule that ignores the link: planted in the phone's
// policy, a rule that keeps all in a window or the foreground on any link while charging fails FI-18 naming an all
// shard the window fetched, where the same case unplanted passes it. Nothing here samples the heap, so it runs in the
// test's own process.
func TestFs77FailsAWindowRuleIgnoringTheLink(t *testing.T) {
	ignoringLink := func(conditions sidecar.SearchConditions, inWindow bool) bool {
		return (inWindow || conditions.Foreground) && conditions.OnCharge() && !conditions.Paused()
	}
	for _, planted := range []bool{false, true} {
		state := &fs77State{traces: map[string][]string{}}
		var windowsRule func(conditions sidecar.SearchConditions, inWindow bool) bool
		if planted {
			windowsRule = ignoringLink
		}
		steps := []*Step{
			{Actor: "writer", Action: state.write},
			{Actor: "ios32", Action: state.cellularWindow(windowsRule)},
			{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
				state.world.close()
				return nil
			}},
		}
		net := sidecartest.NewNet(t.Context(), nil)
		result := Run(t.Context(), &Schedule{Id: "FS-77 window on cellular", Steps: steps, Check: []Invariant{state.fi18()}}, net)
		net.Close()
		switch {
		case !planted && result.Err != nil:
			t.Fatalf("unplanted: %s", result)
		case planted && result.Err == nil:
			t.Fatal("a windows rule ignoring the link passed FS-77's window on cellular")
		case planted && !strings.Contains(result.Err.Error(), fs77CellularWindowLabel+" fetched all's "):
			t.Fatalf("a windows rule ignoring the link failed, but not on the all it fetched on cellular: %s", result)
		}
	}
}

// FS-77's DropCache between two windows (QD-1025), alone: it samples no heap, so it runs in the test's own process.
func TestFs77DropCacheBetweenWindows(t *testing.T) {
	state := &fs77State{traces: map[string][]string{}}
	steps := []*Step{
		{Actor: "writer", Action: state.write},
		{Actor: "android", Action: state.dropBetweenWindows(searchHostNamed("android"), fs77DropLabel)},
		{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
			state.world.close()
			return nil
		}},
	}
	net := sidecartest.NewNet(t.Context(), nil)
	result := Run(t.Context(), &Schedule{Id: "FS-77 drop between windows", Steps: steps, Check: []Invariant{state.fi18()}}, net)
	net.Close()
	if result.Err != nil {
		t.Fatalf("%s", result)
	}
}

// FS-77's changes partway through a round (QD-1026), alone: they sample no heap, so they run in the test's own process.
// Before the fetch loop asked the windows rule again before each read of all, each window read every shard of all
// after its change.
func TestFs77ChangesPartwayThroughARound(t *testing.T) {
	state := &fs77State{traces: map[string][]string{}}
	steps := []*Step{{Actor: "writer", Action: state.write}}
	steps = append(steps, state.midRoundSteps()...)
	steps = append(steps, &Step{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
		state.world.close()
		return nil
	}})
	net := sidecartest.NewNet(t.Context(), nil)
	result := Run(t.Context(), &Schedule{Id: "FS-77 changes partway through a round", Steps: steps, Check: []Invariant{state.fi18()}}, net)
	net.Close()
	if result.Err != nil {
		t.Fatalf("%s", result)
	}
}

// QD-1025's reproduction on the search world: one pushed document, synced, which a cached search finds; after DropCache
// and another round the same search finds it again, the round fetching the latest set anew. Before the reset, the round
// after the drop fetched nothing and the search found nothing until a restart.
func TestFs77DropCacheSyncsAgain(t *testing.T) {
	state := &fs77State{traces: map[string][]string{}}
	steps := []*Step{
		{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
			world, err := newSearchWorld(net, "fs77 drop")
			if err != nil {
				return err
			}
			state.world = world
			now := net.Clock().Now()
			document := &sidecar.SearchTestDocument{Path: "notes/harbor.md", Version: 1, Title: "Harbor lights", Text: "the evening boat", Time: now}
			if err := world.index.PushDocuments(ctx, world.writerId, now, []*sidecar.SearchTestDocument{document}); err != nil {
				return err
			}
			return world.record(now, document)
		}},
		{Actor: "ios32", Action: state.dropAndSync(searchHostNamed("ios32"), "ios32")},
		{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
			state.world.close()
			return nil
		}},
	}
	net := sidecartest.NewNet(t.Context(), nil)
	result := Run(t.Context(), &Schedule{Id: "FS-77 drop and sync", Steps: steps, Check: []Invariant{state.fi18()}}, net)
	net.Close()
	if result.Err != nil {
		t.Fatalf("%s", result)
	}
	if want := []string{"notes/harbor.md@1"}; !slices.Equal(state.oracle(fs77Query, sidecartest.SearchScopeLatest), want) {
		t.Fatalf("SearchOracle finds %v, not the one document %v", state.oracle(fs77Query, sidecartest.SearchScopeLatest), want)
	}
}
