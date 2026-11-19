//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-110 on T2 (§22.8; §16.10's cold contract, §18.4's caps row; D-EVS-50, D-MCP-20, FI-18, FI-23; SEARCH-M10-38,
// QD-999): a cold "search more" with no indexer, at 10 MB/s on the fake clock, over one all partition (16.5 MB here,
// the row's 165 MB at a tenth, below), with four queries whose sole exact match is in the first, the middle or the last
// shard fetched, or in none. On a desktop, a phone and a page Worker, each query on a fresh device in the same sync
// state: the four fetch traces are equal in order and bytes, every all shard fetched whole, once, youngest first; the
// first progress lands within 500 ms, then at least once a second and at each shard; a shard's hit reaches the caller
// within the host's arrival bound after the shard lands, 100 ms on the desktop and 300 ms on the phone and the Worker,
// and never before it (QD-999: the bound is on delivery); the search is not complete until the last shard is searched,
// then complete, with its hit or with none, within B / R + 1 s. Again past a MoreByteCount boundary, the next call
// fetching on from the first unsearched shard and never again a searched one. A delay planted in the page loop past
// the bound fails the arrival clause (TestFs110FailsAHitPastTheArrivalBound).
//
// Scale: the sync engine stages each shard by reading every document through a one-frame cursor, so 165 MB of all, some
// 235,000 documents, takes some 15 s a search on this host, past the 10 s §22.8 gave a step when this was sized (60 s
// since QD-1101); the partition here is 16.5 MB in some 17 shards, the contract's bound B / R + 1 s scaling with it,
// and the full size waits on the staging's cost (SEARCH-M10-38's report).
//
// Readings: a desktop here holds all on demand (AllPolicy on_demand), standing for a desktop before its first round
// of all, since a desktop that keeps all has nothing to fetch; the boundary is MoreByteCount at 4 MiB, under this
// partition's size, standing for 1 GiB under a larger one; phones and the Worker are on Wi-Fi in the foreground and
// unplugged, so all is theirs on demand. A hit's time is when the page carrying it returns on the fake clock, and a
// shard's landing when its read ends. The fake clock moves by reads alone, and the device's reads take their turns
// (SearchTestDevice's turns): each goes only while a page waits on the download with nothing left to take, so a hit's
// delay after its shard landed is the page loop's own, which the engine keeps at none, and a read never charges the
// search's work with time the work does not take.
//
// Not here: the cache cap under all's size, which fails today (the Worker's cap at 8 MiB under this all: the page reads
// a hit's row from a shard the call dropped once searched, answering "the kept file was dropped"; SEARCH-M10-38's
// report), §22.8's median and p90 first hit over FS-76's query set (SEARCH-M10-40's search row), the T4 surrogates
// (sdk/sidecar_search_t4_test.go), the 1 GiB boundary itself, and the app-host case at the later of M10-out and M8-out.

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs110 = Register("FS-110", "", []Tier{TierT2}, Fs110ColdSearchMore)

// The row's partition, at a tenth, and its rate.
var (
	fs110AllByteCount int64 = 16500 * 1000
	fs110ReadByteRate int64 = 10 * 1000 * 1000
)

// What a filler document holds: digits, which share no trigram with the queries' letters.
const fs110FillerText = "4711 4712 4713"

// The four queries, by where their match sits in the fetch order; none's has no match.
var fs110Queries = []struct {
	place string
	word  string
}{
	{place: "first", word: "zebrafinch"},
	{place: "middle", word: "quokkamoth"},
	{place: "last", word: "axolotlwren"},
	{place: "none", word: "narwhalbee"},
}

// What FS-110's steps saw.
type fs110State struct {
	world *searchWorld
	// the all shards as the head lists them, youngest first, path to bytes
	shards    []string
	shardSize map[string]int
	// each match's path and the shard it sits in
	matchShard map[string]string
	matchPath  map[string]string
	// what each page holding hits spends before it answers, planted in the page loop; zero plants none
	answerDelay time.Duration
	// all's size in bytes; zero is the row's, fs110AllByteCount
	allByteCount int64

	stateLock sync.Mutex
	// every query's fetch trace of all, by host and query
	traces map[string][]string
	// what broke the contract
	broken []string
}

func (self *fs110State) breaks(format string, arguments ...any) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.broken = append(self.broken, fmt.Sprintf(format, arguments...))
}

// The path among 4,096 whose doc_key is least, greatest or nearest the middle, so the match lands in the last, first or
// middle shard fetched, youngest first being the highest n.
func (self *fs110State) placedPath(place string) (string, error) {
	best := ""
	var bestKey [16]byte
	for index := range 4096 {
		path := fmt.Sprintf("found/%s-%d.md", place, index)
		key, err := self.world.index.DocKey(path)
		if err != nil {
			return "", err
		}
		better := false
		switch place {
		case "first":
			better = best == "" || string(bestKey[:]) < string(key[:])
		case "last":
			better = best == "" || string(key[:]) < string(bestKey[:])
		case "middle":
			distance := func(key [16]byte) uint64 {
				value := uint64(key[0])<<8 | uint64(key[1])
				if value < 0x8000 {
					return 0x8000 - value
				}
				return value - 0x8000
			}
			better = best == "" || distance(key) < distance(bestKey)
		}
		if better {
			best, bestKey = path, key
		}
	}
	return best, nil
}

// The index: a current bucket of a few documents, and all of the state's size, each match in its place.
func (self *fs110State) write(ctx context.Context, net *Net) error {
	allByteCount := self.allByteCount
	if allByteCount == 0 {
		allByteCount = fs110AllByteCount
	}
	world, err := newSearchWorld(net, "fs110")
	if err != nil {
		return err
	}
	// a read a shard at a time: the fake clock moves a read at once, and a read of §11.9's 32 MiB would show as a pause
	// of its whole time between two reports
	world.readByteCount = 1100 * 1000
	self.world = world
	for _, query := range fs110Queries {
		if shared := world.index.QueryTrigramsShared(query.word, fs110FillerText); len(shared) != 0 {
			return fmt.Errorf("the filler shares %v with %s", shared, query.word)
		}
	}
	now := net.Clock().Now()
	old := now.Add(-400 * 24 * time.Hour)
	recent := []*sidecar.SearchTestDocument{{Path: "notes/today.md", Version: 1, Title: "Today", Text: "4800 4801", Time: now}}
	if err := world.index.PushDocuments(ctx, world.writerId, now, recent); err != nil {
		return err
	}
	self.matchPath = map[string]string{}
	matches := []*sidecar.SearchTestDocument{}
	for _, query := range fs110Queries {
		if query.place == "none" {
			continue
		}
		path, err := self.placedPath(query.place)
		if err != nil {
			return err
		}
		self.matchPath[query.word] = path
		matches = append(matches, &sidecar.SearchTestDocument{Path: path, Version: 1, Title: query.word, Text: query.word + " " + fs110FillerText, Time: old})
	}
	// rows of some 700 B, 1,400 a shard of about 1 MB: the partition's size in shards of a merge's size
	prefix := "archive/" + strings.Repeat("x", 480) + "/"
	filler := &sidecar.SearchTestBulk{Prefix: prefix, Count: int(allByteCount / 700), Version: 1, Document: &sidecar.SearchTestDocument{
		Path: prefix + "template", Version: 1, Title: strings.Repeat("7", 150), Text: fs110FillerText, Time: old,
	}}
	rolledThrough := sidecar.SearchTestBucketStartDay(now) - 60
	err = world.index.WriteShards(ctx, world.writerId, old, &sidecar.SearchTestPartition{All: true, RolledThroughDay: rolledThrough, ShardDocumentCount: 1400}, matches, []*sidecar.SearchTestBulk{filler})
	if err != nil {
		return err
	}
	self.shardSize = map[string]int{}
	for _, file := range world.index.Files() {
		if file.AllShard {
			self.shards = append(self.shards, file.Path)
			self.shardSize[file.Path] = file.ByteCount
		}
	}
	slices.SortFunc(self.shards, func(a string, b string) int { return fs110ShardNumber(b) - fs110ShardNumber(a) })
	total := int64(0)
	for _, path := range self.shards {
		total += int64(self.shardSize[path])
	}
	if total < allByteCount*9/10 {
		return fmt.Errorf("all holds %d B in %d shards, not the %d asked", total, len(self.shards), allByteCount)
	}
	self.matchShard = map[string]string{}
	for word, path := range self.matchPath {
		shard, err := world.index.ShardHolding(path)
		if err != nil {
			return err
		}
		self.matchShard[word] = shard
	}
	if self.matchShard["zebrafinch"] != self.shards[0] || self.matchShard["axolotlwren"] != self.shards[len(self.shards)-1] {
		return fmt.Errorf("the first and last matches sit in %s and %s, not the first and last shards fetched", self.matchShard["zebrafinch"], self.matchShard["axolotlwren"])
	}
	return nil
}

// An all shard's n, from its path.
func fs110ShardNumber(path string) int {
	n, _ := strconv.Atoi(path[strings.LastIndex(path, "/")+1:])
	return n
}

// One search more on a fresh device of host: its trace and reports held to the cold contract.
func (self *fs110State) searchMore(ctx context.Context, net *Net, host *searchHost, settings *sidecar.SidecarSearchSettings, label string, word string) error {
	world := self.world
	// on Wi-Fi in the foreground and unplugged, so a phone keeps all on demand and its "search more" finds it missing
	conditions := host.conditions
	conditions.Charging = false
	device, err := world.index.NewDevice(ctx, &sidecar.SearchTestDeviceArgs{
		Settings: settings, Conditions: func() sidecar.SearchConditions { return conditions }, ReadByteRate: fs110ReadByteRate,
		ReadByteCount: world.readByteCount, AnswerDelay: self.answerDelay,
	})
	if err != nil {
		return err
	}
	defer device.Close()
	if err := device.Sync(ctx); err != nil {
		return err
	}
	fetchedBefore := len(device.Fetches())
	for _, fetch := range device.Fetches() {
		if strings.Contains(fetch.Path, "/a/") && !strings.HasSuffix(fetch.Path, "/a/m") {
			return fmt.Errorf("%s fetched all's %s before the search: its cold state is not cold", label, fetch.Path)
		}
	}
	search, err := device.Search(ctx, &sidecar.SearchRequest{Text: word, Scope: sidecar.SearchAll, Remote: "off"}, 4096, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	fetches := device.Fetches()[fetchedBefore:]
	trace := searchAllShardsOf(searchTraceOf(fetches))
	self.stateLock.Lock()
	self.traces[label] = trace
	self.stateLock.Unlock()

	// every shard, once, whole, youngest first
	want := []string{}
	for _, path := range self.shards {
		want = append(want, fmt.Sprintf("%s@", path))
	}
	if len(trace) != len(want) {
		self.breaks("%s fetched %d all shards of %d", label, len(trace), len(want))
	}
	for index := range min(len(trace), len(want)) {
		if !strings.HasPrefix(trace[index], want[index]) || !strings.HasSuffix(trace[index], ":"+strconv.Itoa(self.shardSize[self.shards[index]])) {
			self.breaks("%s's fetch %d was %s, not %s whole", label, index, trace[index], self.shards[index])
			break
		}
	}
	landed := map[string]time.Time{}
	for _, fetch := range fetches {
		landed[fetch.Path] = fetch.At
	}

	// progress: the first within 500 ms, then no gap past a second, and one at each shard at least
	reports := search.Reports
	if len(reports) == 0 || search.Started.Add(settings.MoreFirstProgress).Before(reports[0].At) {
		self.breaks("%s's first progress came at %v, past %s", label, fs110At(reports, search.Started), settings.MoreFirstProgress)
	}
	for index := 1; index < len(reports); index += 1 {
		if gap := reports[index].At.Sub(reports[index-1].At); settings.MoreProgressInterval < gap {
			self.breaks("%s's progress paused %s between reports %d and %d", label, gap, index-1, index)
			break
		}
	}
	if len(reports) < len(self.shards) {
		self.breaks("%s reported %d times over %d shards", label, len(reports), len(self.shards))
	}

	// the hit: present only where the match is, reaching the caller within the arrival bound after its shard landed and
	// never before
	matchPath, hasMatch := self.matchPath[word]
	found := false
	for _, page := range search.Pages {
		for _, hit := range page.Hits {
			if hit.Path != matchPath {
				self.breaks("%s found %s, which holds nothing of %s", label, hit.Path, word)
				continue
			}
			found = true
			shard := self.matchShard[word]
			if page.At.Before(landed[shard]) {
				self.breaks("%s gave its hit at %v, before its shard %s landed at %v", label, page.At, shard, landed[shard])
			}
			if delay := page.At.Sub(landed[shard]); host.arrival < delay {
				self.breaks("%s gave its hit %s after its shard %s landed, past the arrival bound %s", label, delay, shard, host.arrival)
			}
		}
	}
	if found != hasMatch {
		self.breaks("%s: found %t, and its match exists %t", label, found, hasMatch)
	}

	// complete only once every shard is searched, within B / R + 1 s
	last := search.Pages[len(search.Pages)-1]
	for _, page := range search.Pages[:len(search.Pages)-1] {
		if page.Done {
			self.breaks("%s was done before its last page", label)
		}
	}
	total := int64(0)
	for _, path := range self.shards {
		total += int64(self.shardSize[path])
	}
	bound := time.Duration(total*int64(time.Second)/fs110ReadByteRate) + time.Second
	if !last.Done || last.Progress.FetchBytes != 0 {
		self.breaks("%s ended at %d bytes still to fetch, done %t", label, last.Progress.FetchBytes, last.Done)
	}
	if lastShard := self.shards[len(self.shards)-1]; last.At.Before(landed[lastShard]) {
		self.breaks("%s was complete at %v, before its last shard landed at %v", label, last.At, landed[lastShard])
	}
	if took := last.At.Sub(search.Started); bound < took {
		self.breaks("%s took %s, past B / R + 1 s = %s", label, took, bound)
	}
	return nil
}

// When the first report came, for a failure.
func fs110At(reports []*sidecar.SearchTestReport, started time.Time) time.Duration {
	if len(reports) == 0 {
		return -1
	}
	return reports[0].At.Sub(started)
}

// FI-23 as FS-110 holds it: every query's fetch trace of all is the first's, in order and bytes, on each host.
func (self *fs110State) fi23() Invariant {
	return NewInvariant("FI-23 (FS-110's traces)", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for label, trace := range self.traces {
			host, _, _ := strings.Cut(label, " ")
			reference := self.traces[host+" "+fs110Queries[0].word]
			if reference != nil && !slices.Equal(trace, reference) {
				return fmt.Errorf("%s's trace differs from %s's", label, host+" "+fs110Queries[0].word)
			}
		}
		return nil
	})
}

// FI-18 as FS-110 holds it, with §16.10's cold contract: what the searches broke.
func (self *fs110State) fi18() Invariant {
	return NewInvariant("FI-18 (FS-110's cold contract)", func(ctx context.Context, oracle *Oracle) error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if 0 < len(self.broken) {
			return errors.New(strings.Join(self.broken, "; "))
		}
		return nil
	})
}

// FS-110's hosts: a desktop holding all on demand, a phone, and the page Worker.
func fs110Hosts() []*searchHost {
	desktop := searchHostNamed("desktop")
	desktopSettings := desktop.settings
	desktop.settings = func() *sidecar.SidecarSearchSettings {
		onDemand := desktopSettings()
		onDemand.AllPolicy = "on_demand"
		return onDemand
	}
	return []*searchHost{desktop, searchHostNamed("ios32"), searchHostNamed("worker")}
}

// FS-110's schedule.
func Fs110ColdSearchMore(net *Net) *Schedule {
	state := &fs110State{traces: map[string][]string{}}
	steps := []*Step{{Actor: "writer", Action: state.write}}
	for _, host := range fs110Hosts() {
		for _, query := range fs110Queries {
			steps = append(steps, &Step{Actor: host.name, Action: func(ctx context.Context, net *Net) error {
				return state.searchMore(ctx, net, host, host.settings(), host.name+" "+query.word, query.word)
			}})
		}
	}
	// past MoreByteCount, the next call fetching on from the first unsearched shard and never again a searched one
	steps = append(steps, &Step{Actor: "desktop", Action: func(ctx context.Context, net *Net) error {
		host := fs110Hosts()[0]
		settings := host.settings()
		settings.MoreByteCount = 4 * 1024 * 1024
		return state.searchMore(ctx, net, host, settings, "desktop past MoreByteCount", fs110Queries[1].word)
	}})
	steps = append(steps, &Step{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
		state.world.close()
		return nil
	}})
	return &Schedule{Id: "FS-110", Steps: steps, Check: []Invariant{state.fi23(), state.fi18()}, Tiers: []Tier{TierT2}}
}

// FS-110 on T2, with one explorer seed: its steps hold no barrier and no background action, so a seed reorders nothing,
// and each run downloads all fourteen times.
func TestFs110(t *testing.T) {
	settings := DefaultRuleSettings()
	settings.Seeds = settings.Seeds[:1]
	RunRow(t, "FS-110", "", settings)
}

// FS-110's arrival clause holds the page loop to the bound: on the desktop and on the phone, a page that spends a
// planted delay just past the host's bound before it answers its hit, the match in the first shard fetched, fails
// FI-18 naming the late hit, where the same search unplanted passes it. All is 4.4 MB here, four shards, which is all
// the first shard's match needs.
func TestFs110FailsAHitPastTheArrivalBound(t *testing.T) {
	for _, host := range fs110Hosts()[:2] {
		for _, planted := range []bool{false, true} {
			state := &fs110State{traces: map[string][]string{}, allByteCount: 4400 * 1000}
			if planted {
				state.answerDelay = host.arrival + 10*time.Millisecond
			}
			label := host.name + " " + fs110Queries[0].word
			steps := []*Step{
				{Actor: "writer", Action: state.write},
				{Actor: host.name, Action: func(ctx context.Context, net *Net) error {
					return state.searchMore(ctx, net, host, host.settings(), label, fs110Queries[0].word)
				}},
				{Actor: "writer", Action: func(ctx context.Context, net *Net) error {
					state.world.close()
					return nil
				}},
			}
			net := sidecartest.NewNet(t.Context(), nil)
			result := Run(t.Context(), &Schedule{Id: "FS-110 arrival " + label, Steps: steps, Check: []Invariant{state.fi18()}}, net)
			net.Close()
			late := fmt.Sprintf("%s gave its hit %s after its shard ", label, state.answerDelay)
			switch {
			case !planted && result.Err != nil:
				t.Fatalf("%s unplanted failed: %s", label, result)
			case planted && result.Err == nil:
				t.Fatalf("%s with %s planted in the page loop passed FS-110's arrival clause", label, state.answerDelay)
			case planted && !strings.Contains(result.Err.Error(), late):
				t.Fatalf("%s with %s planted in the page loop failed, but not on its late hit: %s", label, state.answerDelay, result)
			}
		}
	}
}
