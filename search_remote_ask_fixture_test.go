//go:build !sidecar_http && !ios_extension

package sidecar

// The asker's fixtures (SEARCH-M10-33): a transport that carries each request to an in-process SearchRemoteServer on a
// fake corpus, holding or dropping calls as a test says; a local engine of canned hits; and an asker on the Team's real
// config, with its own search.state, on a clock the test moves.

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One call the transport carried.
type testSearchRemoteCall struct {
	indexerId Id
	request   *protocol.SearchRequest
}

// A transport to in-process servers, by indexer.
type testSearchRemoteTransport struct {
	requester testConfigDevice

	stateLock sync.Mutex
	servers   map[Id]*testSearchRemoteServer
	dead      map[Id]bool
	gates     map[Id]chan struct{}
	dropFirst map[Id]int
	calls     []testSearchRemoteCall
	called    chan struct{}
	// each SetSearchIndexer's indexer, in order, and a channel closed at the next
	named    []Id
	namedNow chan struct{}
	// each SetForeground's value, in order, and a channel closed at the next
	foreground    []bool
	foregroundNow chan struct{}
	asks          func(indexerId Id) bool
	seen          map[Id]time.Time
}

func newTestSearchRemoteTransport(requester testConfigDevice) *testSearchRemoteTransport {
	return &testSearchRemoteTransport{
		requester: requester, servers: map[Id]*testSearchRemoteServer{}, dead: map[Id]bool{}, gates: map[Id]chan struct{}{},
		dropFirst: map[Id]int{}, called: make(chan struct{}), namedNow: make(chan struct{}), foregroundNow: make(chan struct{}),
		seen: map[Id]time.Time{},
	}
}

func (self *testSearchRemoteTransport) Call(ctx context.Context, indexerId Id, body []byte, allowed func() bool) ([]byte, error) {
	if !allowed() {
		return nil, errSearchRemotePermission
	}
	request := &protocol.SearchRequest{}
	if err := proto.Unmarshal(body, request); err != nil {
		return nil, err
	}
	server, dead, gate, drop := func() (*testSearchRemoteServer, bool, chan struct{}, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls = append(self.calls, testSearchRemoteCall{indexerId: indexerId, request: request})
		close(self.called)
		self.called = make(chan struct{})
		drop := 0 < self.dropFirst[indexerId] && 0 < request.GetPage()
		if drop {
			self.dropFirst[indexerId] -= 1
		}
		return self.servers[indexerId], self.dead[indexerId], self.gates[indexerId], drop
	}()
	if dead || server == nil || drop {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return server.server.Handle(ctx, &SubprotocolRequest{
		SourceId: NewId(), Peer: &SubprotocolPeerIdentity{SidecarId: self.requester.sidecarId}, MessageType: protocol.MessageType_SEARCH, Body: body,
	})
}

func (self *testSearchRemoteTransport) Peer(indexerId Id) (bool, bool) {
	return false, false
}

func (self *testSearchRemoteTransport) SeenSince(indexerId Id, at time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	seen, ok := self.seen[indexerId]
	return ok && seen.After(at)
}

func (self *testSearchRemoteTransport) SetSearchIndexer(indexerId Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.named = append(self.named, indexerId)
	close(self.namedNow)
	self.namedNow = make(chan struct{})
}

// Waits until count namings have been made, woken by each, and answers them.
func (self *testSearchRemoteTransport) awaitNamed(t *testing.T, count int) []Id {
	t.Helper()
	for {
		named, namings := func() (chan struct{}, []Id) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.namedNow, slices.Clone(self.named)
		}()
		if count <= len(namings) {
			return namings
		}
		select {
		case <-named:
		case <-t.Context().Done():
			t.Fatalf("%d namings never came", count)
		}
	}
}

// The namings so far.
func (self *testSearchRemoteTransport) namings() []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.named)
}

// Waits until the client has told the transport the foreground count times, woken by each, and answers the values.
func (self *testSearchRemoteTransport) awaitForegrounds(t *testing.T, count int) []bool {
	t.Helper()
	for {
		told, foregrounds := func() (chan struct{}, []bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.foregroundNow, slices.Clone(self.foreground)
		}()
		if count <= len(foregrounds) {
			return foregrounds
		}
		select {
		case <-told:
		case <-t.Context().Done():
			t.Fatalf("the foreground was told %d times of %d", len(foregrounds), count)
		}
	}
}

func (self *testSearchRemoteTransport) SetForeground(foreground bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.foreground = append(self.foreground, foreground)
	close(self.foregroundNow)
	self.foregroundNow = make(chan struct{})
}

func (self *testSearchRemoteTransport) SetAsksSearch(asksSearch func(indexerId Id) bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asks = asksSearch
	return nil
}

// The calls so far.
func (self *testSearchRemoteTransport) callsNow() []testSearchRemoteCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls)
}

// Waits until count calls have been made, woken by each, never by time.
func (self *testSearchRemoteTransport) awaitCalls(t *testing.T, count int) []testSearchRemoteCall {
	t.Helper()
	for {
		called, calls := func() (chan struct{}, []testSearchRemoteCall) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.called, slices.Clone(self.calls)
		}()
		if count <= len(calls) {
			return calls
		}
		select {
		case <-called:
		case <-t.Context().Done():
			t.Fatalf("%d calls never came, %d did", count, len(calls))
		}
	}
}

// Holds every call to indexerId until release.
func (self *testSearchRemoteTransport) hold(indexerId Id) (release func()) {
	gate := make(chan struct{})
	self.stateLock.Lock()
	self.gates[indexerId] = gate
	self.stateLock.Unlock()
	var once sync.Once
	return func() { once.Do(func() { close(gate) }) }
}

// The local engine's canned hits: the device's own, by repo, and the requests it got.
type testSearchRemoteLocal struct {
	stateLock sync.Mutex
	hits      map[Id][]SearchHit
	requests  []SearchRequest
}

func (self *testSearchRemoteLocal) Search(ctx context.Context, request *SearchRequest) (*SearchStream, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requests = append(self.requests, *request)
	hits := []SearchHit{}
	for repoId, repoHits := range self.hits {
		if len(request.Repos) == 0 || slices.Contains(request.Repos, repoId) {
			hits = append(hits, repoHits...)
		}
	}
	return NewSearchStream(&testSearchRemoteLocalStream{hits: hits}), nil
}

func (self *testSearchRemoteLocal) Status(repoId *Id) (*SearchStatus, error) {
	return &SearchStatus{}, nil
}

// The downloads the local engine was asked for: its scope all requests.
func (self *testSearchRemoteLocal) downloads() []SearchRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	downloads := []SearchRequest{}
	for _, request := range self.requests {
		if request.Scope == SearchAll {
			downloads = append(downloads, request)
		}
	}
	return downloads
}

type testSearchRemoteLocalStream struct {
	hits  []SearchHit
	given bool
}

func (self *testSearchRemoteLocalStream) Next() ([]SearchHit, SearchProgress, bool, error) {
	if self.given {
		return nil, SearchProgress{}, true, nil
	}
	self.given = true
	return self.hits, SearchProgress{}, true, nil
}

func (self *testSearchRemoteLocalStream) Close() {}

// An asker on the Team's network.
type testSearchRemoteAsker struct {
	team      *testConfigSearchTeam
	asker     testConfigDevice
	world     *searchStateTestWorld
	clock     *searchTestClock
	settings  *SidecarSearchSettings
	transport *testSearchRemoteTransport
	local     *testSearchRemoteLocal
	client    *SearchRemoteClient

	eventLock sync.Mutex
	events    []SidecarEvent
}

func newTestSearchRemoteAsker(t *testing.T, team *testConfigSearchTeam, asker testConfigDevice) *testSearchRemoteAsker {
	t.Helper()
	world := newSearchStateTestWorld(t)
	fixture := &testSearchRemoteAsker{
		team: team, asker: asker, world: world, clock: world.clock, settings: world.settings,
		transport: newTestSearchRemoteTransport(asker), local: &testSearchRemoteLocal{hits: map[Id][]SearchHit{}},
	}
	client, err := NewSearchRemoteClient(&SearchRemoteClientArgs{
		Settings:   world.settings,
		Wire:       DefaultSearchWireSettings(),
		Config:     func() (*ConfigState, error) { return team.net.log.State(), nil },
		Services:   testConfigSearchServices,
		SelfId:     func() (Id, bool) { return asker.sidecarId, true },
		State:      world.state,
		Local:      fixture.local,
		Conditions: func() SearchConditions { return SearchConditions{Reported: true, Unmetered: true} },
		Events: func(event SidecarEvent) {
			fixture.eventLock.Lock()
			defer fixture.eventLock.Unlock()
			fixture.events = append(fixture.events, event)
		},
		DeviceName: func(sidecarId Id) string { return "device " + sidecarId.String()[:8] },
		Clock:      world.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.setTransport(fixture.transport)
	fixture.client = client
	t.Cleanup(client.Close)
	return fixture
}

// An in-process server for indexer, its corpus fake.
func (self *testSearchRemoteAsker) serve(t *testing.T, indexer testConfigDevice) *testSearchRemoteServer {
	t.Helper()
	server := newTestSearchRemoteServer(t, self.team, indexer)
	self.transport.stateLock.Lock()
	self.transport.servers[indexer.sidecarId] = server
	self.transport.stateLock.Unlock()
	return server
}

// W for a search over repoIds now: the own indexers it asks at once (search_remote_order.go).
func (self *testSearchRemoteAsker) ownAsk(t *testing.T, repoIds ...Id) []Id {
	t.Helper()
	view, err := self.client.orderView(repoIds)
	if err != nil {
		t.Fatal(err)
	}
	return slices.Clone(view.ownAsk)
}

// A "search more" over repos, remote on.
func (self *testSearchRemoteAsker) search(t *testing.T, repoIds ...Id) *SearchStream {
	t.Helper()
	mode, err := self.world.state.Mode()
	if err != nil {
		t.Fatal(err)
	}
	stream, err := self.client.Search(t.Context(), &SearchRequest{Text: "plan", Repos: repoIds, Scope: SearchAll, Remote: mode, PageSize: 50})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stream.Close)
	return stream
}

// One page, which must not fail.
type testSearchRemotePage struct {
	err      error
	hits     []SearchHit
	progress SearchProgress
	done     bool
}

func testSearchRemoteNext(t *testing.T, stream *SearchStream) testSearchRemotePage {
	t.Helper()
	hits, progress, done, err := stream.Next()
	if err != nil {
		t.Fatal(err)
	}
	return testSearchRemotePage{hits: hits, progress: progress, done: done}
}

// The next page, taken on a goroutine of its own while the test moves the clock.
func testSearchRemoteNextLater(stream *SearchStream) chan testSearchRemotePage {
	answer := make(chan testSearchRemotePage, 1)
	go func() {
		hits, progress, done, err := stream.Next()
		answer <- testSearchRemotePage{hits: hits, progress: progress, done: done, err: err}
	}()
	return answer
}

// The alarms raised so far of kind.
func (self *testSearchRemoteAsker) alarms(kind SidecarEventKind) []SidecarEvent {
	self.eventLock.Lock()
	defer self.eventLock.Unlock()
	alarms := []SidecarEvent{}
	for _, event := range self.events {
		if event.Kind == kind {
			alarms = append(alarms, event)
		}
	}
	return alarms
}

// The indexers the calls went to, page 0's alone where pageZero.
func testSearchRemoteCalled(calls []testSearchRemoteCall, pageZero bool) []Id {
	indexers := []Id{}
	for _, call := range calls {
		if pageZero && call.request.GetPage() != 0 {
			continue
		}
		indexers = append(indexers, call.indexerId)
	}
	return indexers
}

// A second and third own search indexer for Dana, member scope, consented for her by her laptop's admission, reading
// her vault by a share of hers (a vault's own consents are fixed at its creation) and the team repo.
func testSearchRemoteMoreOwn(t *testing.T, team *testConfigSearchTeam, labels ...string) []testConfigDevice {
	t.Helper()
	net := team.net
	devices := []testConfigDevice{}
	for _, label := range labels {
		device := net.device(label, team.dana)
		net.admitDevice(team.danaLaptop, device, 0)
		net.mustPost(team.danaLaptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(device, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, false))
		team.grantTeamRepo(device)
		net.mustPost(team.danaLaptop, bridge.SignedType_SIGNED_EVS_SHARE, &protocol.EvsShare{
			Header: net.header(), RepoId: team.danaVault.Bytes(), Subject: device.sidecarId.Bytes(),
		})
		team.mustRead(team.danaVault, device)
		devices = append(devices, device)
	}
	return devices
}

// The doc keys' labels among hits.
func testSearchRemoteHitLabels(hits []SearchHit, docs ...*testSearchRemoteDoc) []string {
	labels := []string{}
	for _, hit := range hits {
		for _, doc := range docs {
			if hit.DocKey == testSearchRemoteKey(doc.label) {
				labels = append(labels, doc.label)
			}
		}
	}
	return labels
}
