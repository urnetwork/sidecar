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
// runs inside it, measured and reported rather than failed).
//
// Readings: MeteredMoreByteCount stands at 64 KiB here, under this all's size, for §18.4's 25 MiB over a larger one;
// the candidates a phone lists, possible ones included, are held to SearchOracle's matches, since a phone holds no
// text to verify; the Worker here is the Worker's settings on this host, not wasm.
//
// Not here, each listed for the review phase in SEARCH-M10-38's report: an OS window on cellular (the policy keeps all
// in any window, which FS-77 says fetches none: question search-m10-38-window-on-cellular), a window's budget and
// resumption, Low Power Mode, device overrides and the key origin's policy request, search.state across DropCache and
// eviction (the world's devices hold no SidecarSearchState), the quick burner, an erasure hint dropping a cached
// document, a replaced file answering collected, the Worker's key-origin conditions and Safari's and Firefox's hidden
// ones, phone merges in windows (FS-75), the T4 surrogates (sdk/sidecar_search_t4_test.go), and the app-host case at
// the later of M10-out and M8-out.

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
		shards := []sidecar.SearchTestFile{}
		for _, file := range world.index.Files() {
			if file.AllShard {
				shards = append(shards, file)
			}
		}
		slices.SortFunc(shards, func(a sidecar.SearchTestFile, b sidecar.SearchTestFile) int {
			return fs110ShardNumber(b.Path) - fs110ShardNumber(a.Path)
		})
		if len(trace) != len(shards) {
			self.breaks("%s's search more fetched %d all shards of %d", label, len(trace), len(shards))
		}
		for index := range min(len(trace), len(shards)) {
			if want := fmt.Sprintf("%s@%d:%d", shards[index].Path, shards[index].Version, shards[index].ByteCount); trace[index] != want {
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
	steps = append(steps, &Step{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
		state.world.close()
		return nil
	}})
	return &Schedule{Id: "FS-77", Steps: steps, Check: []Invariant{state.fi23(), state.fi18()}, Tiers: []Tier{TierT2}}
}

func TestFs77(t *testing.T) {
	RunRow(t, "FS-77", "", nil)
	fs77Measured.stateLock.Lock()
	defer fs77Measured.stateLock.Unlock()
	for _, line := range fs77Measured.lines {
		t.Logf("measured: %s", line)
	}
}
