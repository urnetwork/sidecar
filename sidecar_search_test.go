//go:build !ios_extension

package sidecar

// CORE-M10-03: §5.4's search methods over a fake engine: Remote resolved from search.state and never asked on a host
// without the requester side, the mode and notice answers refused there (the daemon MCP runs on, and the daemon a
// remote-mode app reaches), a background window stopping at its budget on the Sidecar's clock and resuming, conditions
// as reported or read for the host, DropSearchCache keeping search.state, and search's three event kinds.

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"
)

// A Sidecar enrolled in a network of an open instance in memory, on a clock the test moves, with the events it raised.
type searchTestSidecar struct {
	sidecar   *Sidecar
	instance  *SidecarInstance
	backend   SidecarStoreBackend
	networkId Id
	clock     *searchTestClock

	stateLock sync.Mutex
	events    []SidecarEvent
}

// adjust, nil for none, changes the settings before the Sidecar is built: the defaults are a daemon host's.
func newSearchTestSidecar(t *testing.T, adjust func(settings *SidecarSettings)) *searchTestSidecar {
	t.Helper()
	backend := NewSidecarMemoryBackend()
	instance := newInstanceOn(t, backend, newFakeKeyStore())
	if err := instance.Unlock(testPass); err != nil {
		t.Fatal(err)
	}
	networkId := NewId()
	if _, err := instance.createKeychain(networkId); err != nil {
		t.Fatal(err)
	}
	clock := newSearchTestClock()
	settings := cheapKeychainSettings()
	settings.Clock = clock
	settings.Log = NewNoopLogger()
	if adjust != nil {
		adjust(settings)
	}
	sidecar := newSidecarBase(nil, settings)
	sidecar.instance = instance
	sidecar.networkId = &networkId
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sidecar.ctx = ctx
	world := &searchTestSidecar{sidecar: sidecar, instance: instance, backend: backend, networkId: networkId, clock: clock}
	sidecar.AddEventCallback(func(event SidecarEvent) {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.events = append(world.events, event)
	})
	return world
}

// An app host's settings: the requester side runs and it serves nothing (§18.4).
func searchAppHost(settings *SidecarSettings) {
	settings.Search.RemoteAsk = true
	settings.Search.RemoteServe = false
}

// The events raised so far.
func (self *searchTestSidecar) raised() []SidecarEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// A stream's source that answers one empty page and records its close.
type searchTestSource struct {
	closed chan struct{}
	once   sync.Once
}

func newSearchTestSource() *searchTestSource {
	return &searchTestSource{closed: make(chan struct{})}
}

func (self *searchTestSource) Next() ([]SearchHit, SearchProgress, bool, error) {
	return nil, SearchProgress{}, true, nil
}

func (self *searchTestSource) Close() {
	self.once.Do(func() { close(self.closed) })
}

// An engine that records what it was asked, with a background sync whose units the test lets it do one at a time.
type searchTestEngine struct {
	stateLock sync.Mutex
	requests  []SearchRequest
	sources   []*searchTestSource
	status    SearchStatus
	indexers  []SearchIndexer
	dropped   []*Id
	// background units done in all, kept across windows
	progress int
	// each unit waits for one of these
	steps chan struct{}
	// the progress a window started at, and each unit done
	started    chan int
	progressed chan int
}

func newSearchTestEngine() *searchTestEngine {
	return &searchTestEngine{steps: make(chan struct{}), started: make(chan int, 4), progressed: make(chan int, 16)}
}

func (self *searchTestEngine) Search(ctx context.Context, request *SearchRequest) (*SearchStream, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requests = append(self.requests, *request)
	source := newSearchTestSource()
	self.sources = append(self.sources, source)
	return NewSearchStream(source), nil
}

func (self *searchTestEngine) Status(repoId *Id) (*SearchStatus, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := self.status
	return &status, nil
}

func (self *searchTestEngine) RunBackgroundSync(ctx context.Context) error {
	self.stateLock.Lock()
	started := self.progress
	self.stateLock.Unlock()
	self.started <- started
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-self.steps:
			self.stateLock.Lock()
			self.progress += 1
			progress := self.progress
			self.stateLock.Unlock()
			self.progressed <- progress
		}
	}
}

func (self *searchTestEngine) Indexers() []SearchIndexer {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.indexers)
}

// The last request the engine saw.
func (self *searchTestEngine) lastRequest(t *testing.T) SearchRequest {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if len(self.requests) == 0 {
		t.Fatal("the engine saw no request")
	}
	return self.requests[len(self.requests)-1]
}

// An engine that drops its own cache, ending its searches first.
type searchTestDroppingEngine struct {
	*searchTestEngine
}

func (self *searchTestDroppingEngine) DropCache(repoId *Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dropped = append(self.dropped, repoId)
	return nil
}

func installSearchTestEngine(t *testing.T, sidecar *Sidecar, engine SidecarSearchEngine) {
	t.Helper()
	remove, err := sidecar.InstallSearchEngine(engine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
}

// With no engine installed nothing reads as a search that found nothing.
func TestSearchUnavailableWithoutEngine(t *testing.T) {
	world := newSearchTestSidecar(t, searchAppHost)
	if _, err := world.sidecar.Search(t.Context(), &SearchRequest{Text: "x"}); !errors.Is(err, ErrSidecarSearchUnavailable) {
		t.Errorf("search: %v", err)
	}
	if _, err := world.sidecar.GetSearchStatus(nil); !errors.Is(err, ErrSidecarSearchUnavailable) {
		t.Errorf("status: %v", err)
	}
	ctx, cancel := context.WithDeadline(t.Context(), world.clock.Now().Add(time.Minute))
	defer cancel()
	if err := world.sidecar.RunSearchBackgroundSync(ctx); !errors.Is(err, ErrSidecarSearchUnavailable) {
		t.Errorf("background: %v", err)
	}
	if indexers := world.sidecar.GetSearchIndexers(); len(indexers) != 0 {
		t.Errorf("indexers %v", indexers)
	}
	unenrolled := newSidecarBase(nil, cheapKeychainSettings())
	if _, err := unenrolled.SearchState(); !errors.Is(err, ErrSidecarSearchUnavailable) {
		t.Errorf("an unenrolled sidecar's state: %v", err)
	}
}

// Remote "" reads this network's mode on an app host, "off" stays local, anything else is refused; the page size
// defaults to Search.PageHitCount.
func TestSearchResolvesRemoteMode(t *testing.T) {
	world := newSearchTestSidecar(t, searchAppHost)
	engine := newSearchTestEngine()
	installSearchTestEngine(t, world.sidecar, engine)
	if err := world.sidecar.SetSearchRemote(SearchRemoteOwn); err != nil {
		t.Fatal(err)
	}
	stream, err := world.sidecar.Search(t.Context(), &SearchRequest{Text: "invoice", Repos: []Id{NewId()}})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if request := engine.lastRequest(t); request.Remote != SearchRemoteOwn || request.PageSize != 50 || len(request.Repos) != 1 {
		t.Errorf("the engine saw %+v", request)
	}
	if _, err := world.sidecar.Search(t.Context(), &SearchRequest{Text: "invoice", Remote: SearchRemoteOff, PageSize: 7}); err != nil {
		t.Fatal(err)
	}
	if request := engine.lastRequest(t); request.Remote != SearchRemoteOff || request.PageSize != 7 {
		t.Errorf("the engine saw %+v", request)
	}
	for _, bad := range []*SearchRequest{nil, {Remote: SearchRemoteOn}, {PageSize: -1}, {Scope: SearchScope(9)}} {
		if _, err := world.sidecar.Search(t.Context(), bad); !errors.Is(err, ErrSearchRequest) {
			t.Errorf("request %+v: %v", bad, err)
		}
	}
}

// The daemon's MCP sessions run on its daemon-host Sidecars, which run no requester side: the mode and the notice's
// answers are refused there and nothing is written, and a search resolves to off whatever is asked, so no MCP path sets
// a mode or an answer or sends a query to an indexer (§16.10).
func TestRemoteModeNeverFromMcp(t *testing.T) {
	world := newSearchTestSidecar(t, nil)
	if world.sidecar.settings.Search.RemoteAsk {
		t.Fatal("the default settings, a daemon's, run the requester side")
	}
	engine := newSearchTestEngine()
	installSearchTestEngine(t, world.sidecar, engine)
	before := backendSnapshot(t, world.backend)
	member := NewId()
	if err := world.sidecar.SetSearchRemote(SearchRemoteOn); !errors.Is(err, ErrSidecarSearchRefused) {
		t.Errorf("set remote: %v", err)
	}
	if err := world.sidecar.AcknowledgeSearchIndexer(&member, true); !errors.Is(err, ErrSidecarSearchRefused) {
		t.Errorf("acknowledge: %v", err)
	}
	if err := world.sidecar.AcknowledgeSearchIndexer(nil, false); !errors.Is(err, ErrSidecarSearchRefused) {
		t.Errorf("reset: %v", err)
	}
	after := backendSnapshot(t, world.backend)
	if len(after) != len(before) {
		t.Fatalf("a refused call wrote %d files", len(after)-len(before))
	}
	for path, content := range before {
		if !bytes.Equal(after[path], content) {
			t.Errorf("a refused call rewrote %s", path)
		}
	}
	if _, err := world.sidecar.Search(t.Context(), &SearchRequest{Text: "x"}); err != nil {
		t.Fatal(err)
	}
	if request := engine.lastRequest(t); request.Remote != SearchRemoteOff {
		t.Errorf("a daemon's search asked under %q", request.Remote)
	}
	if status, err := world.sidecar.GetSearchStatus(nil); err != nil || status.Remote != SearchRemoteOff {
		t.Errorf("status %+v %v", status, err)
	}
}

// The daemon a remote-mode app reaches (§18.7's control row) lists no indexer and refuses SetSearchRemote and
// AcknowledgeSearchIndexer, whatever its engine knows; an app host lists its engine's, with each notice's answer and the
// repos each served from search.state.
func TestRemoteHostRefusesSetRemote(t *testing.T) {
	indexerId, memberId, repoId := NewId(), NewId(), NewId()
	listed := []SearchIndexer{
		{SidecarId: NewId(), Name: "nas", Own: true, State: "online", Acknowledged: true},
		{SidecarId: indexerId, Name: "dana-nas", MemberId: &memberId, Member: "dana", State: "unknown"},
	}

	daemon := newSearchTestSidecar(t, nil)
	daemonEngine := newSearchTestEngine()
	daemonEngine.indexers = listed
	installSearchTestEngine(t, daemon.sidecar, daemonEngine)
	if indexers := daemon.sidecar.GetSearchIndexers(); len(indexers) != 0 {
		t.Errorf("a daemon listed %v", indexers)
	}
	if err := daemon.sidecar.SetSearchRemote(SearchRemoteOff); !errors.Is(err, ErrSidecarSearchRefused) {
		t.Errorf("set remote: %v", err)
	}
	if err := daemon.sidecar.AcknowledgeSearchIndexer(&memberId, true); !errors.Is(err, ErrSidecarSearchRefused) {
		t.Errorf("acknowledge: %v", err)
	}

	app := newSearchTestSidecar(t, searchAppHost)
	appEngine := newSearchTestEngine()
	appEngine.indexers = listed
	installSearchTestEngine(t, app.sidecar, appEngine)
	if err := app.sidecar.AcknowledgeSearchIndexer(&memberId, true); err != nil {
		t.Fatal(err)
	}
	state, err := app.sidecar.SearchState()
	if err != nil {
		t.Fatal(err)
	}
	if err := state.NoteServed(indexerId, repoId); err != nil {
		t.Fatal(err)
	}
	indexers := app.sidecar.GetSearchIndexers()
	if len(indexers) != 2 {
		t.Fatalf("listed %v", indexers)
	}
	// an own indexer needs no notice, whatever the engine said
	if indexers[0].Acknowledged {
		t.Error("an own indexer reads acknowledged")
	}
	if !indexers[1].Acknowledged || !slices.Equal(indexers[1].ServedRepoIds, []Id{repoId}) {
		t.Errorf("another member's indexer %+v", indexers[1])
	}
	if err := app.sidecar.AcknowledgeSearchIndexer(&memberId, false); err != nil {
		t.Fatal(err)
	}
	if mode, _ := state.Mode(); mode != SearchRemoteOwn {
		t.Errorf("a refusal left the mode %q", mode)
	}
	if indexers := app.sidecar.GetSearchIndexers(); indexers[1].Acknowledged {
		t.Error("a refused member reads acknowledged")
	}
}

// A background window's budget is its ctx's deadline on the Sidecar's clock: the sync stops there, the call answers nil,
// and the next window resumes where it stopped. A ctx with no deadline is refused.
func TestBackgroundSyncStopsAtBudget(t *testing.T) {
	world := newSearchTestSidecar(t, searchAppHost)
	engine := newSearchTestEngine()
	installSearchTestEngine(t, world.sidecar, engine)
	if err := world.sidecar.RunSearchBackgroundSync(t.Context()); !errors.Is(err, ErrSearchRequest) {
		t.Errorf("a window with no budget: %v", err)
	}

	window := func(units int) (started int, progress int) {
		ctx, cancel := context.WithDeadline(t.Context(), world.clock.Now().Add(30*time.Second))
		defer cancel()
		result := make(chan error, 1)
		go func() {
			result <- world.sidecar.RunSearchBackgroundSync(ctx)
		}()
		started = <-engine.started
		for range units {
			engine.steps <- struct{}{}
			progress = <-engine.progressed
		}
		// the window's timer is armed before the sync starts, and only it ends the window
		if pending := world.clock.pending(); pending != 1 {
			t.Fatalf("%d timers pending", pending)
		}
		select {
		case err := <-result:
			t.Fatalf("the window ended before its budget: %v", err)
		default:
		}
		world.clock.advance(30 * time.Second)
		if err := <-result; err != nil {
			t.Fatalf("a window that reached its budget answered %v", err)
		}
		return started, progress
	}
	if started, progress := window(3); started != 0 || progress != 3 {
		t.Errorf("first window: started at %d, reached %d", started, progress)
	}
	if started, progress := window(2); started != 3 || progress != 5 {
		t.Errorf("second window: started at %d, reached %d", started, progress)
	}
}

// Conditions read as reported; before a report a host reads metered and not charging, a daemon host unmetered.
func TestSearchConditionsAsReported(t *testing.T) {
	daemon := newSearchTestSidecar(t, nil)
	if conditions, _ := daemon.sidecar.SearchConditions(); !conditions.Unmetered || conditions.Charging || conditions.Reported {
		t.Errorf("a daemon's unreported conditions %+v", conditions)
	}
	app := newSearchTestSidecar(t, searchAppHost)
	conditions, changed := app.sidecar.SearchConditions()
	if conditions.Unmetered || conditions.Charging || conditions.LowPower || conditions.Reported {
		t.Errorf("an app's unreported conditions %+v", conditions)
	}
	app.sidecar.SetSearchConditions(true, true, false)
	select {
	case <-changed:
	default:
		t.Fatal("a report raised no change")
	}
	if conditions, _ := app.sidecar.SearchConditions(); !conditions.Unmetered || !conditions.Charging || conditions.LowPower || !conditions.Reported {
		t.Errorf("reported conditions %+v", conditions)
	}
	app.sidecar.SetSearchConditions(false, true, true)
	if conditions, _ := app.sidecar.SearchConditions(); conditions.Unmetered || !conditions.LowPower {
		t.Errorf("a second report %+v", conditions)
	}
}

// DropSearchCache drops the cache's files and keeps search.state; an engine that must end its searches first drops
// them itself.
func TestDropSearchCacheKeepsState(t *testing.T) {
	world := newSearchTestSidecar(t, searchAppHost)
	repoId := NewId()
	if err := world.sidecar.SetSearchPolicy(&repoId, SearchPolicyNever); err != nil {
		t.Fatal(err)
	}
	if err := world.sidecar.SetSearchRemote(SearchRemoteOwn); err != nil {
		t.Fatal(err)
	}
	cache, err := world.sidecar.SearchCache()
	if err != nil {
		t.Fatal(err)
	}
	key := SearchCacheKey{RepoId: repoId, RefId: NewId(), Path: ".ur-index/i1/b/20000/0", Version: 1}
	if err := cache.PutRecord(t.Context(), newTestSearchRecord(t, key, SearchCachePartition{StartDay: 20000}, testSearchPlaintext("bucket", 5000)).record); err != nil {
		t.Fatal(err)
	}
	if err := world.sidecar.DropSearchCache(nil); err != nil {
		t.Fatal(err)
	}
	if held, err := cache.Ref(key.RepoId, key.RefId); err != nil || held != nil {
		t.Errorf("the drop kept %+v %v", held, err)
	}
	state, err := world.sidecar.SearchState()
	if err != nil {
		t.Fatal(err)
	}
	if policy, _ := state.Policy(repoId); policy != SearchPolicyNever {
		t.Errorf("policy %q after the drop", policy)
	}
	if mode, _ := state.Mode(); mode != SearchRemoteOwn {
		t.Errorf("mode %q after the drop", mode)
	}

	engine := &searchTestDroppingEngine{searchTestEngine: newSearchTestEngine()}
	installSearchTestEngine(t, world.sidecar, engine)
	if err := world.sidecar.DropSearchCache(&repoId); err != nil {
		t.Fatal(err)
	}
	if len(engine.dropped) != 1 || engine.dropped[0] == nil || *engine.dropped[0] != repoId {
		t.Errorf("the engine dropped %v", engine.dropped)
	}
}

// Status carries the policy in force, this device's override or the host's default, and this network's mode.
func TestSearchStatusCarriesPolicyAndMode(t *testing.T) {
	world := newSearchTestSidecar(t, searchAppHost)
	engine := newSearchTestEngine()
	engine.status = SearchStatus{IndexOn: true, FormatSupported: true, Policy: "engine's", Remote: "engine's"}
	installSearchTestEngine(t, world.sidecar, engine)
	repoId := NewId()
	status, err := world.sidecar.GetSearchStatus(&repoId)
	if err != nil {
		t.Fatal(err)
	}
	if !status.IndexOn || status.Policy != SearchPolicyBackground || status.Remote != SearchRemoteOn {
		t.Errorf("status %+v", status)
	}
	if err := world.sidecar.SetSearchPolicy(nil, SearchPolicyOnDemand); err != nil {
		t.Fatal(err)
	}
	if err := world.sidecar.SetSearchPolicy(&repoId, SearchPolicyWifiCharging); err != nil {
		t.Fatal(err)
	}
	if err := world.sidecar.SetSearchRemote(SearchRemoteOff); err != nil {
		t.Fatal(err)
	}
	if status, _ := world.sidecar.GetSearchStatus(&repoId); status.Policy != SearchPolicyWifiCharging || status.Remote != SearchRemoteOff {
		t.Errorf("a repo's status %+v", status)
	}
	if status, _ := world.sidecar.GetSearchStatus(nil); status.Policy != SearchPolicyOnDemand {
		t.Errorf("every repo's status %+v", status)
	}
}

// A lock ends every open stream, as the cache's open cursors.
func TestLockedEndsOpenStreams(t *testing.T) {
	world := newSearchTestSidecar(t, searchAppHost)
	engine := newSearchTestEngine()
	installSearchTestEngine(t, world.sidecar, engine)
	stream, err := world.sidecar.Search(t.Context(), &SearchRequest{Text: "x"})
	if err != nil {
		t.Fatal(err)
	}
	cache, err := world.sidecar.SearchCache()
	if err != nil {
		t.Fatal(err)
	}
	// what the cache's lock watcher does when the instance leaves Open
	cache.Locked()
	select {
	case <-engine.sources[0].closed:
	default:
		t.Fatal("a lock left the stream open")
	}
	stream.Close()
}

// index_mismatch, index_malformed and search_alarm reach the Sidecar's events with what they name; search's sink passes
// no other kind.
func TestSearchEventsPassOnlySearchKinds(t *testing.T) {
	world := newSearchTestSidecar(t, searchAppHost)
	repoId, refId, signerId, indexerId := NewId(), NewId(), NewId(), NewId()
	world.sidecar.raiseIndexMismatch(repoId, refId, ".ur-index/i1/b/20000/0", signerId)
	world.sidecar.raiseIndexMalformed(repoId, refId, ".ur-index/i1/a/3", signerId)
	world.sidecar.raiseSearchAlarm(SidecarSearchAlarmOmission, indexerId, repoId)
	world.sidecar.searchEvents()(SidecarEvent{Kind: SidecarEventState})
	events := world.raised()
	if len(events) != 3 {
		t.Fatalf("%d events", len(events))
	}
	if events[0].Kind != SidecarEventIndexMismatch || *events[0].SidecarId != signerId || *events[0].RepoId != repoId ||
		*events[0].RefId != refId || events[0].Path != ".ur-index/i1/b/20000/0" {
		t.Errorf("mismatch %+v", events[0])
	}
	if events[1].Kind != SidecarEventIndexMalformed || events[1].Path != ".ur-index/i1/a/3" {
		t.Errorf("malformed %+v", events[1])
	}
	if events[2].Kind != SidecarEventSearchAlarm || events[2].SearchAlarm != SidecarSearchAlarmOmission ||
		*events[2].SidecarId != indexerId || *events[2].RepoId != repoId {
		t.Errorf("alarm %+v", events[2])
	}
}
