//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

// A remote search world (SEARCH-M10-39's FS-83, S12 and §22.7's search rows; SEARCH-M10-40's remote row): a network's
// devices on search worlds (the root's SearchTestWorld, one repo each, under sidecar_testhooks), each a
// SearchTestNetworkDevice over the repos it reads; indexers serving with SearchRemoteServer over their engines;
// requesters asking with SearchRemoteClient; and between them a transport standing for the pair's relays, which hands
// each request body to the indexer's handler with the requester as the authenticated peer, as the dispatcher's SEARCH
// rules do (rpc_search.go), and records what a relay sees of it: its size, each way, in order.
//
//	config     each device reads its own newest verified state through Config, by its sidecar_id: a test's real
//	           ConfigLog (an AdmissionNet's), so eligibility, consent and designations are §7.9's and §8.5's own
//	relay      each call's request and reply bodies' sizes by pair, in order (SearchRemotePages.FrameSizes): a body
//	           is one envelope's (§6.5), which the dispatcher frames in one size sequence a body size; T3's real
//	           relays capture the TransferFrames themselves. A search's calls are its own legs', by their search_ids,
//	           never a page an earlier search's leg asked before its stream closed
//	indexers   killed, a request to one fails at once as a leg whose deadline passed with no reply, and no Hello stands
//	           for its pairs (the deadline's own timing is the client's, which search_remote_ask_test.go holds on its
//	           clock); held, its reply waits for a release; a planted handler wraps its server's, which a mutant uses (an
//	           early short reply, a sync before answering)
//	budget     each indexer's own D-CORE-17 budget on the world's clock, its CPU meter CpuClock where a test gives one:
//	           a leg the requester stopped waiting for may still hold a slot when the test moves the clock, which on
//	           the one clock would count the whole move as compute
//	requests   a device's requests of servers while a search runs are its index sources' reads, "evs read <path>":
//	           what a device asks evs for an index, the only thing either device of a remote search could ask
//
// Safe for concurrent use.

package sidecartest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a remote search world is made of.
type SearchRemoteWorldArgs struct {
	Clock sidecar.SearchTestClock
	// The indexers' budgets' CPU meter, what RemoteCpuPerMinute and PageCpu are spent on; nil Clock.
	CpuClock sidecar.Clock
	// Each device's newest verified config state, by its sidecar_id, read at every send and page.
	Config func(sidecarId sidecar.Id) (*sidecar.ConfigState, error)
	// Opens a designation's sealed services; nil names search for every designation.
	Services func(indexer sidecar.ConfigIndexer) ([]protocol.IndexerService, bool)
	// SEARCH's wire values; nil the protocol's.
	Wire *sidecar.SearchWireSettings
}

// See the file header.
type SearchRemoteWorld struct {
	args     SearchRemoteWorldArgs
	wire     *sidecar.SearchWireSettings
	services func(indexer sidecar.ConfigIndexer) ([]protocol.IndexerService, bool)

	stateLock  sync.Mutex
	indexers   map[sidecar.Id]*SearchRemoteIndexer
	requesters map[sidecar.Id]*SearchRemoteRequester
	calls      []*SearchRemoteCall
	// closed and replaced at each call's start and end
	callsChanged chan struct{}
}

// Every designation offers search.
func searchRemoteWorldServices(indexer sidecar.ConfigIndexer) ([]protocol.IndexerService, bool) {
	return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}, true
}

// A world of args, holding no device yet.
func NewSearchRemoteWorld(args *SearchRemoteWorldArgs) (*SearchRemoteWorld, error) {
	if args == nil || args.Clock == nil || args.Config == nil {
		return nil, errors.New("search remote world: a clock and the devices' config")
	}
	world := &SearchRemoteWorld{
		args: *args, wire: args.Wire, services: args.Services, indexers: map[sidecar.Id]*SearchRemoteIndexer{},
		requesters: map[sidecar.Id]*SearchRemoteRequester{}, callsChanged: make(chan struct{}),
	}
	if world.wire == nil {
		world.wire = sidecar.DefaultSearchWireSettings()
	}
	if world.services == nil {
		world.services = searchRemoteWorldServices
	}
	return world, nil
}

// One request a requester's leg sent and what came back, as the transport carried it.
type SearchRemoteCall struct {
	RequesterId sidecar.Id
	IndexerId   sidecar.Id
	// The request as it parsed, and its body's size; the reply's body size, 0 for none; the error the leg took.
	Request          *protocol.SearchRequest
	RequestByteCount int
	ReplyByteCount   int
	Err              error
	Started          time.Time
	Ended            time.Time
	// The indexer's handler's own time on the wall clock: its compute for the page, apart from the relay's.
	HandleDuration time.Duration
	done           bool
}

// The repos the request named.
func (self *SearchRemoteCall) RepoIds() []sidecar.Id {
	ids := []sidecar.Id{}
	for _, repo := range self.Request.GetRepos() {
		if id, err := sidecar.IdFromBytes(repo.GetRepoId()); err == nil {
			ids = append(ids, id)
		}
	}
	return ids
}

// Every call so far, in the order they started, and a channel closed at the next change.
func (self *SearchRemoteWorld) Calls() ([]*SearchRemoteCall, chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calls := []*SearchRemoteCall{}
	for _, call := range self.calls {
		copied := *call
		calls = append(calls, &copied)
	}
	return calls, self.callsChanged
}

// Waits until count calls have started past after, or ctx ends.
func (self *SearchRemoteWorld) AwaitCalls(ctx context.Context, after int, count int) ([]*SearchRemoteCall, error) {
	for {
		calls, changed := self.Calls()
		if after+count <= len(calls) {
			return calls[after:], nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return calls[min(after, len(calls)):], fmt.Errorf("%w: %d of %d calls", ctx.Err(), len(calls)-after, count)
		}
	}
}

// Wakes every waiter on the calls, the lock held.
func (self *SearchRemoteWorld) changedWithLock() {
	close(self.callsChanged)
	self.callsChanged = make(chan struct{})
}

// One indexer: its device, its server, the budget the server admits by, and how the transport reaches it.
type SearchRemoteIndexer struct {
	SidecarId sidecar.Id
	Device    *sidecar.SearchTestNetworkDevice
	Server    *sidecar.SearchRemoteServer
	Budget    *sidecar.SidecarRemoteBudget
	world     *SearchRemoteWorld

	stateLock sync.Mutex
	down      bool
	// closed while it answers; a channel a held reply waits on
	held chan struct{}
	// wraps the server's handler: a mutant's
	planted func(handle sidecar.SubprotocolHandler) sidecar.SubprotocolHandler
}

// What an indexer serves with.
type SearchRemoteIndexerArgs struct {
	SidecarId sidecar.Id
	Refs      []*sidecar.SearchTestNetworkRef
	// The daemon's search settings, RemoteServe on; nil production's.
	Settings *sidecar.SidecarSearchSettings
	// The host's text of each ref, which a desktop holding a mirror verifies against: with it the indexer serves those
	// refs from text at its own index pin (SERVED_TEXT). Nil serves every ref from the index (SERVED_INDEX).
	Text func(repoId sidecar.Id, refId sidecar.Id) sidecar.SearchTextSource
	// Where its state lives; "" in memory.
	StateDirectory string
}

// An indexer of args, its device synced once.
func (self *SearchRemoteWorld) AddIndexer(ctx context.Context, args *SearchRemoteIndexerArgs) (*SearchRemoteIndexer, error) {
	settings := args.Settings
	if settings == nil {
		settings = sidecar.DefaultSidecarSettings().Search
		settings.RemoteServe = true
	}
	device, err := sidecar.NewSearchTestNetworkDevice(ctx, &sidecar.SearchTestNetworkDeviceArgs{
		Settings: settings, Conditions: func() sidecar.SearchConditions { return sidecar.SearchConditions{DaemonHost: true} },
		ReadByteCount: 32 * 1024 * 1024, Refs: args.Refs, Text: args.Text, StateDirectory: args.StateDirectory,
	})
	if err != nil {
		return nil, err
	}
	if err := device.Sync(ctx); err != nil {
		device.Close()
		return nil, err
	}
	budget, err := sidecar.NewSearchTestRemoteBudget(settings, self.args.Clock, self.args.CpuClock)
	if err != nil {
		device.Close()
		return nil, err
	}
	indexerId := args.SidecarId
	serverArgs := &sidecar.SearchRemoteServerArgs{
		Settings: settings, Wire: self.wire,
		Config:   func() (*sidecar.ConfigState, error) { return self.args.Config(indexerId) },
		Services: self.services,
		SelfId:   func() (sidecar.Id, bool) { return indexerId, true },
		Budget:   budget, State: device.State(), Engine: device.Engine(), Clock: self.args.Clock, Log: sidecar.NewNoopLogger(),
	}
	if args.Text != nil {
		serverArgs.TextPin = func(repoId sidecar.Id, refId sidecar.Id) (sidecar.SearchSyncPin, uint32, bool) {
			pin, companion, _, ok := device.OwnIndex(repoId, refId)
			if !ok || companion || args.Text(repoId, refId) == nil {
				return sidecar.SearchSyncPin{}, 0, false
			}
			return pin, 0, true
		}
	}
	server, err := sidecar.NewSearchRemoteServer(serverArgs)
	if err != nil {
		device.Close()
		return nil, err
	}
	indexer := &SearchRemoteIndexer{SidecarId: indexerId, Device: device, Server: server, Budget: budget, world: self}
	self.stateLock.Lock()
	self.indexers[indexerId] = indexer
	self.stateLock.Unlock()
	return indexer, nil
}

// Takes the indexer off the network: a request to it gets no reply, and no Hello stands for its pairs.
func (self *SearchRemoteIndexer) Kill() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.down = true
}

// Brings the indexer back.
func (self *SearchRemoteIndexer) Revive() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.down = false
}

// Holds every reply of the indexer until release: a slow indexer.
func (self *SearchRemoteIndexer) Hold() (release func()) {
	held := make(chan struct{})
	self.stateLock.Lock()
	self.held = held
	self.stateLock.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.stateLock.Lock()
			if self.held == held {
				self.held = nil
			}
			self.stateLock.Unlock()
			close(held)
		})
	}
}

// Wraps the server's handler with plant's, nil for none: what a mutant changes in what the indexer answers.
func (self *SearchRemoteIndexer) Plant(plant func(handle sidecar.SubprotocolHandler) sidecar.SubprotocolHandler) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.planted = plant
}

// Ends the indexer's server and device.
func (self *SearchRemoteIndexer) Close() {
	self.Server.Close()
	self.Device.Close()
}

// One requester: its device and its remote client, over the world's transport.
type SearchRemoteRequester struct {
	SidecarId sidecar.Id
	Device    *sidecar.SearchTestNetworkDevice
	Client    *sidecar.SearchRemoteClient
	world     *SearchRemoteWorld
	cancel    context.CancelFunc

	stateLock  sync.Mutex
	foreground bool
	seen       map[sidecar.Id]time.Time
}

// What a requester is made of.
type SearchRemoteRequesterArgs struct {
	SidecarId sidecar.Id
	Refs      []*sidecar.SearchTestNetworkRef
	// The app host's search settings; nil a phone's (sdk's host class): RemoteAsk on, RemoteServe off.
	Settings   *sidecar.SidecarSearchSettings
	Conditions func() sidecar.SearchConditions
	// Where its state lives; "" in memory.
	StateDirectory string
}

// A phone's search settings, as sdk's phone host class sets them.
func SearchRemotePhoneSettings() *sidecar.SidecarSearchSettings {
	settings := sidecar.DefaultSidecarSettings().Search
	settings.AllPolicy = sidecar.SearchPolicyWifiCharging
	settings.MemoryByteCount = 4*1024*1024 + 256*1024
	settings.DaemonSearchCount = 1
	settings.AllCacheByteCount = 256 * 1024 * 1024
	settings.UnusedAllAge = 30 * 24 * time.Hour
	settings.DirectoryBuckets = false
	settings.SyncRoundCount = 1
	settings.RemoteServe = false
	settings.RemoteAsk = true
	return settings
}

// A requester of args, its device synced once, its client following the world's transport until ctx ends.
func (self *SearchRemoteWorld) AddRequester(ctx context.Context, args *SearchRemoteRequesterArgs) (*SearchRemoteRequester, error) {
	settings := args.Settings
	if settings == nil {
		settings = SearchRemotePhoneSettings()
	}
	conditions := args.Conditions
	if conditions == nil {
		conditions = func() sidecar.SearchConditions {
			return sidecar.SearchConditions{Unmetered: true, Charging: true, Reported: true, Foreground: true}
		}
	}
	device, err := sidecar.NewSearchTestNetworkDevice(ctx, &sidecar.SearchTestNetworkDeviceArgs{
		Settings: settings, Conditions: conditions, ReadByteCount: 32 * 1024 * 1024, Refs: args.Refs, StateDirectory: args.StateDirectory,
	})
	if err != nil {
		return nil, err
	}
	if err := device.Sync(ctx); err != nil {
		device.Close()
		return nil, err
	}
	requesterId := args.SidecarId
	client, err := sidecar.NewSearchRemoteClient(&sidecar.SearchRemoteClientArgs{
		Settings: settings, Wire: self.wire,
		Config:     func() (*sidecar.ConfigState, error) { return self.args.Config(requesterId) },
		Services:   self.services,
		SelfId:     func() (sidecar.Id, bool) { return requesterId, true },
		State:      device.State(),
		Local:      device.Engine(),
		Conditions: conditions,
		Foreground: func() (bool, chan struct{}) { return true, nil },
		OwnIndex:   device.OwnIndex,
		Clock:      self.args.Clock,
		Log:        sidecar.NewNoopLogger(),
	})
	if err != nil {
		device.Close()
		return nil, err
	}
	clientCtx, cancel := context.WithCancel(ctx)
	requester := &SearchRemoteRequester{
		SidecarId: requesterId, Device: device, Client: client, world: self, cancel: cancel, seen: map[sidecar.Id]time.Time{},
	}
	sidecar.SetSearchTestRemoteTransport(clientCtx, client, &searchRemoteWorldTransport{requester: requester})
	self.stateLock.Lock()
	self.requesters[requesterId] = requester
	self.stateLock.Unlock()
	return requester, nil
}

// Ends the requester's client, its following of the transport and its device.
func (self *SearchRemoteRequester) Close() {
	self.Client.Close()
	self.cancel()
	self.Device.Close()
}

// What one remote search gave, and what it cost each side.
type SearchRemotePages struct {
	Hits     []sidecar.SearchHit
	Progress sidecar.SearchProgress
	// The calls its legs made, in order, and the index of the first in the world's log.
	Calls     []*SearchRemoteCall
	FirstCall int
	// What each device asked of servers while it ran: its index reads, as "evs read <path>@<version>", and the same by
	// the repo read, which tells a fallback's download (a repo no leg served) from the remote search's own.
	Requests map[sidecar.Id][]string
	Reads    map[sidecar.Id]map[sidecar.Id][]string
	// Each page's wall time from the call.
	PageTimes []time.Duration
}

// The search's "search more" in the network's mode, its pages read to done or pageCount. Each device's reads while it
// ran are what it asked of servers.
func (self *SearchRemoteRequester) Search(ctx context.Context, request *sidecar.SearchRequest, pageCount int) (*SearchRemotePages, error) {
	mode, err := self.Device.State().Mode()
	if err != nil {
		return nil, err
	}
	asked := *request
	asked.Scope = sidecar.SearchAll
	if asked.Remote == "" {
		asked.Remote = mode
	}
	before := self.world.fetchCounts()
	calls, _ := self.world.Calls()
	pages := &SearchRemotePages{FirstCall: len(calls), Requests: map[sidecar.Id][]string{}}
	started := time.Now()
	stream, err := self.Client.Search(ctx, &asked)
	if err != nil {
		return pages, err
	}
	defer stream.Close()
	for range pageCount {
		hits, progress, done, err := stream.Next()
		if err != nil {
			return pages, err
		}
		pages.PageTimes = append(pages.PageTimes, time.Since(started))
		pages.Hits = append(pages.Hits, hits...)
		pages.Progress = progress
		if done {
			break
		}
	}
	// this search's legs alone: a call of a leg an earlier search opened, a page it asked before its stream closed,
	// may still arrive after this one began
	calls, _ = self.world.Calls()
	earlier := map[uint64]bool{}
	for _, call := range calls[:pages.FirstCall] {
		if call.Request != nil {
			earlier[call.Request.GetSearchId()] = true
		}
	}
	for _, call := range calls[pages.FirstCall:] {
		if call.Request != nil && !earlier[call.Request.GetSearchId()] {
			pages.Calls = append(pages.Calls, call)
		}
	}
	pages.Requests, pages.Reads = self.world.fetchesSince(before)
	return pages, nil
}

// The size of each request body of the search from requester to indexer, and of each reply back, in the order the
// transport carried them: what a relay sees of the pair for the search.
func (self *SearchRemotePages) FrameSizes(requesterId sidecar.Id, indexerId sidecar.Id) ([]int, []int) {
	requests, replies := []int{}, []int{}
	for _, call := range self.Calls {
		if call.RequesterId != requesterId || call.IndexerId != indexerId {
			continue
		}
		requests = append(requests, call.RequestByteCount)
		if 0 < call.ReplyByteCount {
			replies = append(replies, call.ReplyByteCount)
		}
	}
	return requests, replies
}

// Every device's fetch count now, by sidecar_id and repo.
func (self *SearchRemoteWorld) fetchCounts() map[sidecar.Id]map[sidecar.Id]int {
	self.stateLock.Lock()
	devices := map[sidecar.Id]*sidecar.SearchTestNetworkDevice{}
	for id, indexer := range self.indexers {
		devices[id] = indexer.Device
	}
	for id, requester := range self.requesters {
		devices[id] = requester.Device
	}
	self.stateLock.Unlock()
	counts := map[sidecar.Id]map[sidecar.Id]int{}
	for id, device := range devices {
		counts[id] = map[sidecar.Id]int{}
		for _, repoId := range device.RepoIds() {
			counts[id][repoId] = len(device.Fetches(repoId))
		}
	}
	return counts
}

// Every device's index reads since before, as "evs read <path>@<version>", by sidecar_id, and by sidecar_id and repo.
func (self *SearchRemoteWorld) fetchesSince(before map[sidecar.Id]map[sidecar.Id]int) (map[sidecar.Id][]string, map[sidecar.Id]map[sidecar.Id][]string) {
	self.stateLock.Lock()
	devices := map[sidecar.Id]*sidecar.SearchTestNetworkDevice{}
	for id, indexer := range self.indexers {
		devices[id] = indexer.Device
	}
	for id, requester := range self.requesters {
		devices[id] = requester.Device
	}
	self.stateLock.Unlock()
	requests := map[sidecar.Id][]string{}
	reads := map[sidecar.Id]map[sidecar.Id][]string{}
	for id, device := range devices {
		requests[id] = []string{}
		reads[id] = map[sidecar.Id][]string{}
		for _, repoId := range device.RepoIds() {
			fetches := device.Fetches(repoId)
			for _, fetch := range fetches[min(before[id][repoId], len(fetches)):] {
				line := fmt.Sprintf("evs read %s@%d", fetch.Path, fetch.Version)
				requests[id] = append(requests[id], line)
				reads[id][repoId] = append(reads[id][repoId], line)
			}
		}
	}
	return requests, reads
}

// The requester's transport through the world: see the file header.
type searchRemoteWorldTransport struct {
	requester *SearchRemoteRequester

	stateLock      sync.Mutex
	searchIndexers []sidecar.Id
	foregrounds    []bool
}

// See sidecar.SearchTestRemoteTransport. A call of a search that has ended sends nothing, as a dispatcher's Call on an
// ended context does: a page its leg asked before its stream closed never reaches the indexer.
func (self *searchRemoteWorldTransport) Call(ctx context.Context, indexerId sidecar.Id, body []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	world := self.requester.world
	world.stateLock.Lock()
	indexer := world.indexers[indexerId]
	call := &SearchRemoteCall{RequesterId: self.requester.SidecarId, IndexerId: indexerId, RequestByteCount: len(body), Started: world.args.Clock.Now()}
	parsed := &protocol.SearchRequest{}
	if err := proto.Unmarshal(body, parsed); err == nil {
		call.Request = parsed
	}
	world.calls = append(world.calls, call)
	world.changedWithLock()
	world.stateLock.Unlock()
	reply, err := self.deliver(ctx, indexer, body, call)
	world.stateLock.Lock()
	call.ReplyByteCount, call.Err, call.Ended, call.done = len(reply), err, world.args.Clock.Now(), true
	world.changedWithLock()
	world.stateLock.Unlock()
	if err == nil {
		self.requester.stateLock.Lock()
		self.requester.seen[indexerId] = world.args.Clock.Now()
		self.requester.stateLock.Unlock()
	}
	return reply, err
}

// The indexer's answer to body, as the dispatcher's SEARCH rules hand it the request, or the leg's error.
func (self *searchRemoteWorldTransport) deliver(ctx context.Context, indexer *SearchRemoteIndexer, body []byte, call *SearchRemoteCall) ([]byte, error) {
	if indexer == nil {
		return nil, sidecar.ErrSearchTestRemoteAuth
	}
	indexer.stateLock.Lock()
	down, held, planted := indexer.down, indexer.held, indexer.planted
	indexer.stateLock.Unlock()
	if down {
		// no reply: the leg ends as at its deadline
		return nil, sidecar.ErrSearchTestRemoteTimeout
	}
	handle := indexer.Server.Handle
	if planted != nil {
		handle = planted(handle)
	}
	started := time.Now()
	reply, err := handle(ctx, &sidecar.SubprotocolRequest{
		SourceId:    self.requester.SidecarId,
		Peer:        &sidecar.SubprotocolPeerIdentity{SidecarId: self.requester.SidecarId},
		MessageType: protocol.MessageType_SEARCH,
		Body:        body,
	})
	call.HandleDuration = time.Since(started)
	if held != nil {
		select {
		case <-held:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return reply, err
}

// See sidecar.SearchTestRemoteTransport: a Hello stands with a live indexer, which shows bit 0.
func (self *searchRemoteWorldTransport) Peer(indexerId sidecar.Id) (bool, bool) {
	world := self.requester.world
	world.stateLock.Lock()
	indexer := world.indexers[indexerId]
	world.stateLock.Unlock()
	if indexer == nil {
		return false, false
	}
	indexer.stateLock.Lock()
	defer indexer.stateLock.Unlock()
	return true, !indexer.down
}

// See sidecar.SearchTestRemoteTransport: a live indexer this requester heard from after at.
func (self *searchRemoteWorldTransport) SeenSince(indexerId sidecar.Id, at time.Time) bool {
	servesSearch, standing := self.Peer(indexerId)
	if !servesSearch || !standing {
		return false
	}
	self.requester.stateLock.Lock()
	defer self.requester.stateLock.Unlock()
	seen, ok := self.requester.seen[indexerId]
	return ok && seen.After(at)
}

// See sidecar.SearchTestRemoteTransport: kept, as the dispatcher would count it.
func (self *searchRemoteWorldTransport) SetSearchIndexer(indexerId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.searchIndexers = append(self.searchIndexers, indexerId)
}

// See sidecar.SearchTestRemoteTransport: kept, as the dispatcher would follow it.
func (self *searchRemoteWorldTransport) SetForeground(foreground bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.foregrounds = append(self.foregrounds, foreground)
}

// See sidecar.SearchTestRemoteTransport: bit 1 marks nothing (owner decision 609), so the world keeps none.
func (self *searchRemoteWorldTransport) SetAsksSearch(asksSearch func(indexerId sidecar.Id) bool) error {
	return nil
}

// Ends every device the world made.
func (self *SearchRemoteWorld) Close() {
	self.stateLock.Lock()
	indexers := slices.Collect(maps.Values(self.indexers))
	requesters := slices.Collect(maps.Values(self.requesters))
	self.indexers = map[sidecar.Id]*SearchRemoteIndexer{}
	self.requesters = map[sidecar.Id]*SearchRemoteRequester{}
	self.stateLock.Unlock()
	for _, requester := range requesters {
		requester.Close()
	}
	for _, indexer := range indexers {
		indexer.Close()
	}
}

// FS-83's network (SEARCH-M10-39; DESIGN-DETAILS 7.2.2's eligibility, 7.6's rows), shared by FS-83, S12, §22.7's
// search rows and §22.8's remote row: a Team on an AdmissionNet, ACL's own compile deciding every repo's readers, with
//
//	members  m, whose first device consents its phone, desktop and NAS; b, whose first device consents its NAS
//	repos    m's vault and mailbox, owner-bound to m; b's vault, owner-bound to b and shared by EvsShare with m's
//	         phone, desktop and NAS; and a team repo the Owner's device creates and grants m's three devices and
//	         b's NAS
//	indexers m's desktop and NAS at member scope, b's NAS at member scope, the Owner's device at network scope
//
// so §11.14's rule lets m's phone ask m's two own indexers of its vault, mailbox and the team repo, b's NAS alone of
// b's vault (another member's, after its notice), and never m's own indexers of b's vault though they read it. Each
// repo is a search world of its own, written by the documents a test gives it, and each device a network device
// over the repos it reads. Names: "owner", "m first", "m phone", "m desktop", "m nas", "b first", "b nas"; repos
// "m vault", "m mailbox", "b vault", "team".
type SearchRemoteTeam struct {
	Net     *AdmissionNet
	Members map[string]sidecar.Id
	Devices map[string]*AdmissionDevice
	Repos   map[string]sidecar.Id
	Worlds  map[string]*sidecar.SearchTestWorld
	Remote  *SearchRemoteWorld
	// The indexers by device name, and m's phone, the requester; and the extra phones of m, "m phone 1" on, each a
	// requester reading m's vault and mailbox.
	Indexers   map[string]*SearchRemoteIndexer
	Phone      *SearchRemoteRequester
	Requesters []*SearchRemoteRequester
}

// What a remote team is made of.
type SearchRemoteTeamArgs struct {
	// The tier the network's api runs on: a Net's (Net.AdmissionTier), ACL's compile and the team tier set here.
	Tier *AdmissionTier
	// Each repo's documents, by repo name, pushed by its writer at the clock's now.
	Documents func(repo string) []*sidecar.SearchTestDocument
	// Each device's state directory by name, "" in memory; nil keeps every one in memory.
	StateDirectory func(device string) string
	// Each indexer's text of a repo by name, nil for none: with it the indexer serves that repo from text.
	Text func(indexer string, repo string) sidecar.SearchTextSource
	// Phones of m beside its own, each a requester of its own: a load's simulated requesters.
	Requesters int
	// The indexers' budgets' CPU meter (SearchRemoteWorldArgs.CpuClock); nil the network's clock.
	CpuClock sidecar.Clock
}

// The repos each device reads, as the team grants them.
var searchRemoteTeamReads = map[string][]string{
	"m phone":   {"m vault", "m mailbox", "b vault", "team"},
	"m desktop": {"m vault", "m mailbox", "b vault", "team"},
	"m nas":     {"m vault", "m mailbox", "b vault", "team"},
	"b nas":     {"b vault", "team"},
	"owner":     {"team"},
}

// The indexers, in the order they are built.
var searchRemoteTeamIndexers = []string{"m desktop", "m nas", "b nas", "owner"}

// A failure of the network's statements, which Do turns into its error.
type searchRemoteTeamFailure struct {
	err error
}

// The network's AdmissionT: a failure panics with it, for Do to recover.
type searchRemoteTeamFailer struct{}

// See AdmissionT.
func (searchRemoteTeamFailer) Helper() {}

// See AdmissionT: panics with the failure, for Do.
func (searchRemoteTeamFailer) Fatal(args ...any) {
	panic(searchRemoteTeamFailure{err: errors.New(fmt.Sprint(args...))})
}

// See AdmissionT: panics with the failure, for Do.
func (searchRemoteTeamFailer) Fatalf(format string, args ...any) {
	panic(searchRemoteTeamFailure{err: fmt.Errorf(format, args...)})
}

// See AdmissionT: the network's log goes nowhere.
func (searchRemoteTeamFailer) Logf(format string, args ...any) {}

// Runs body, which may land statements on the team's network, a statement that fails returning as its error.
func (self *SearchRemoteTeam) Do(body func() error) error {
	return searchRemoteTeamDo(body)
}

// Runs body, recovering a searchRemoteTeamFailure as its error and passing any other panic on.
func searchRemoteTeamDo(body func() error) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			failure, ok := recovered.(searchRemoteTeamFailure)
			if !ok {
				panic(recovered)
			}
			err = failure.err
		}
	}()
	return body()
}

// A remote team: see SearchRemoteTeam.
func NewSearchRemoteTeam(ctx context.Context, args *SearchRemoteTeamArgs) (team *SearchRemoteTeam, err error) {
	err = searchRemoteTeamDo(func() error {
		team, err = newSearchRemoteTeam(ctx, args)
		return err
	})
	return team, err
}

// NewSearchRemoteTeam's team, a failure of the network's statements panicking for Do.
func newSearchRemoteTeam(ctx context.Context, args *SearchRemoteTeamArgs) (*SearchRemoteTeam, error) {
	tier := *args.Tier
	tier.AclCompile = AclAdmissionCompile
	tier.Team = true
	net := NewAdmissionNet(searchRemoteTeamFailer{}, &tier)
	team := &SearchRemoteTeam{
		Net: net, Members: map[string]sidecar.Id{}, Devices: map[string]*AdmissionDevice{}, Repos: map[string]sidecar.Id{},
		Worlds: map[string]*sidecar.SearchTestWorld{}, Indexers: map[string]*SearchRemoteIndexer{},
	}
	owner := net.Owner()
	team.Devices["owner"] = owner
	for _, member := range []string{"m", "b"} {
		memberId, first := net.ConsentedMember(member)
		team.Members[member] = memberId
		team.Devices[member+" first"] = first
	}
	extraPhones := []string{}
	for index := range args.Requesters {
		extraPhones = append(extraPhones, fmt.Sprintf("m phone %d", index+1))
	}
	for _, name := range append([]string{"m phone", "m desktop", "m nas", "b nas"}, extraPhones...) {
		member := name[:1]
		device := net.Device(name, team.Members[member])
		net.AdmitDevice(team.Devices[member+" first"], device, 0)
		team.Devices[name] = device
	}
	create := func(signer string, name string, kind protocol.RepoKind) {
		repoId := net.Id("repo " + name)
		net.MustLand(net.Sign(team.Devices[signer], bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
			Header: net.Header(), RepoId: repoId.Bytes(), Kind: kind,
		}))
		team.Repos[name] = repoId
	}
	create("m first", "m vault", protocol.RepoKind_REPO_KIND_VAULT)
	create("m first", "m mailbox", protocol.RepoKind_REPO_KIND_MAILBOX)
	create("b first", "b vault", protocol.RepoKind_REPO_KIND_VAULT)
	create("owner", "team", protocol.RepoKind_REPO_KIND_GENERAL)
	for _, subject := range []string{"m phone", "m desktop", "m nas"} {
		net.MustLand(net.Sign(team.Devices["b first"], bridge.SignedType_SIGNED_EVS_SHARE, &protocol.EvsShare{
			Header: net.Header(), RepoId: team.Repos["b vault"].Bytes(), Subject: team.Devices[subject].SidecarId.Bytes(),
		}))
	}
	for _, reader := range []string{"m phone", "m desktop", "m nas", "b nas"} {
		net.MustLand(net.Sign(owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: net.Header(), RepoId: team.Repos["team"].Bytes(), Subject: team.Devices[reader].SidecarId.Bytes(),
			Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		}))
	}
	designate := func(signer string, subject string, scope protocol.IndexerScope) {
		net.MustLand(net.Sign(team.Devices[signer], bridge.SignedType_SIGNED_INDEXER_SET, &protocol.IndexerSet{
			Header: net.Header(), SidecarId: team.Devices[subject].SidecarId.Bytes(), Scope: scope,
			SealedServices: []byte("sealed services: opened only by a config reader"),
		}))
	}
	designate("m first", "m desktop", protocol.IndexerScope_INDEXER_SCOPE_MEMBER)
	designate("m first", "m nas", protocol.IndexerScope_INDEXER_SCOPE_MEMBER)
	designate("b first", "b nas", protocol.IndexerScope_INDEXER_SCOPE_MEMBER)
	designate("owner", "owner", protocol.IndexerScope_INDEXER_SCOPE_NETWORK)

	// the rule as the team states it, before a search relies on it
	state := net.State()
	phoneId := team.Devices["m phone"].SidecarId
	wantIndexers := map[string][]string{
		"m vault": {"m desktop", "m nas"}, "m mailbox": {"m desktop", "m nas"}, "b vault": {"b nas"}, "team": {"m desktop", "m nas", "owner"},
	}
	for repo, want := range wantIndexers {
		got := slices.Clone(state.SearchIndexersFor(phoneId, team.Repos[repo], searchRemoteWorldServices))
		wantIds := []sidecar.Id{}
		for _, name := range want {
			wantIds = append(wantIds, team.Devices[name].SidecarId)
		}
		slices.SortFunc(got, sidecar.Id.Cmp)
		slices.SortFunc(wantIds, sidecar.Id.Cmp)
		if !slices.Equal(got, wantIds) {
			return nil, fmt.Errorf("search remote team: %s answered by %v, not %v", repo, got, want)
		}
	}

	clock := net.Clock()
	kinds := map[string]protocol.RepoKind{
		"m vault": protocol.RepoKind_REPO_KIND_VAULT, "m mailbox": protocol.RepoKind_REPO_KIND_MAILBOX,
		"b vault": protocol.RepoKind_REPO_KIND_VAULT, "team": protocol.RepoKind_REPO_KIND_GENERAL,
	}
	writers := map[string]string{"m vault": "m first", "m mailbox": "m first", "b vault": "b first", "team": "owner"}
	for _, repo := range []string{"m vault", "m mailbox", "b vault", "team"} {
		world, err := sidecar.NewSearchTestWorld(&sidecar.SearchTestWorldArgs{
			RepoId: team.Repos[repo], RefId: net.Id("ref main " + repo), Clock: clock, Kind: kinds[repo],
		})
		if err != nil {
			return nil, err
		}
		if args.Documents != nil {
			if documents := args.Documents(repo); 0 < len(documents) {
				if err := world.PushDocuments(ctx, team.Devices[writers[repo]].SidecarId, clock.Now(), documents); err != nil {
					return nil, fmt.Errorf("%s's documents: %w", repo, err)
				}
			}
		}
		team.Worlds[repo] = world
	}
	remote, err := NewSearchRemoteWorld(&SearchRemoteWorldArgs{
		Clock:    clock,
		CpuClock: args.CpuClock,
		Config:   func(sidecarId sidecar.Id) (*sidecar.ConfigState, error) { return net.State(), nil },
	})
	if err != nil {
		return nil, err
	}
	team.Remote = remote
	refsOf := func(device string) []*sidecar.SearchTestNetworkRef {
		refs := []*sidecar.SearchTestNetworkRef{}
		reads, ok := searchRemoteTeamReads[device]
		if !ok {
			// an extra phone reads what m's devices read by being m's: its vault and mailbox
			reads = []string{"m vault", "m mailbox"}
		}
		for _, repo := range reads {
			refs = append(refs, &sidecar.SearchTestNetworkRef{World: team.Worlds[repo]})
		}
		return refs
	}
	stateDirectory := func(device string) string {
		if args.StateDirectory == nil {
			return ""
		}
		return args.StateDirectory(device)
	}
	for _, name := range searchRemoteTeamIndexers {
		indexerArgs := &SearchRemoteIndexerArgs{SidecarId: team.Devices[name].SidecarId, Refs: refsOf(name), StateDirectory: stateDirectory(name)}
		if args.Text != nil {
			indexerName := name
			indexerArgs.Text = func(repoId sidecar.Id, refId sidecar.Id) sidecar.SearchTextSource {
				for repo, id := range team.Repos {
					if id == repoId {
						return args.Text(indexerName, repo)
					}
				}
				return nil
			}
		}
		indexer, err := remote.AddIndexer(ctx, indexerArgs)
		if err != nil {
			remote.Close()
			return nil, fmt.Errorf("indexer %s: %w", name, err)
		}
		team.Indexers[name] = indexer
	}
	phone, err := remote.AddRequester(ctx, &SearchRemoteRequesterArgs{
		SidecarId: phoneId, Refs: refsOf("m phone"), StateDirectory: stateDirectory("m phone"),
	})
	if err != nil {
		remote.Close()
		return nil, fmt.Errorf("the phone: %w", err)
	}
	team.Phone = phone
	for _, name := range extraPhones {
		requester, err := remote.AddRequester(ctx, &SearchRemoteRequesterArgs{SidecarId: team.Id(name), Refs: refsOf(name), StateDirectory: stateDirectory(name)})
		if err != nil {
			remote.Close()
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		team.Requesters = append(team.Requesters, requester)
	}
	return team, nil
}

// The device named name's sidecar_id.
func (self *SearchRemoteTeam) Id(name string) sidecar.Id {
	return self.Devices[name].SidecarId
}

// The repo named name's id.
func (self *SearchRemoteTeam) RepoId(name string) sidecar.Id {
	return self.Repos[name]
}

// The device's name, by its sidecar_id, "" for none.
func (self *SearchRemoteTeam) NameOf(sidecarId sidecar.Id) string {
	for name, device := range self.Devices {
		if device.SidecarId == sidecarId {
			return name
		}
	}
	return ""
}

// The repo's name by its id, "" for none.
func (self *SearchRemoteTeam) RepoNameOf(repoId sidecar.Id) string {
	for name, id := range self.Repos {
		if id == repoId {
			return name
		}
	}
	return ""
}

// Ends the worlds and the network.
func (self *SearchRemoteTeam) Close() {
	if self.Remote != nil {
		self.Remote.Close()
	}
	self.Net.Close()
}

// A 16 B id from a label, for a test's repos, refs and writers.
func searchWorldId(label string) sidecar.Id {
	digest := sha256.Sum256([]byte("search world id " + label))
	return sidecar.Id(digest[:16])
}
