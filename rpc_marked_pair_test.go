//go:build !sidecar_http && !js

// The marked pair (PROTO-M10-04), FS-125's lifecycle cases at this layer on a fake clock and a fake of
// connect's window ledger: bit-1 Hellos mark before sending and on receipt, adopting as connect asks, and
// a repeat retires nothing; the Ping grid holds 55 minutes and the Hello stands past HelloCacheTimeout;
// a 3-minute suspension re-establishes by a Hello at the next foreground; a 3-minute drop in the
// foreground re-establishes by the search before the next tick; a failover search opens its own window;
// a window ending in the background clears the mode and the next search marks again; and HeadCheck's
// round counts the first-choice indexer in the foreground.

package sidecar

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// A log shared by a side's window ledger fake and its sends, so a test reads their order.
type testEvents struct {
	stateLock sync.Mutex
	events    []string
	// each event as recorded, for a test that waits on one
	recorded chan string
}

func newTestEvents() *testEvents {
	return &testEvents{recorded: make(chan string, 1024)}
}

func (self *testEvents) add(event string) {
	self.stateLock.Lock()
	self.events = append(self.events, event)
	self.stateLock.Unlock()
	select {
	case self.recorded <- event:
	default:
	}
}

func (self *testEvents) list() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
}

// Waits for an event equal to want, failing after testSubprotocolAwaitTimeout.
func (self *testEvents) await(t *testing.T, want string) {
	t.Helper()
	for {
		if testAwait(t, self.recorded, want) == want {
			return
		}
	}
}

// connect's C19 ledger faked: who is in the mode, the send window each opened at its mark, and every call
// logged with the peer's side name.
type testPeerWindows struct {
	events *testEvents
	names  func(peerId connect.Id) string
	clock  Clock

	stateLock  sync.Mutex
	accounting map[connect.Id]bool
	windows    map[connect.Id]*connect.PeerWindow
}

func (self *testPeerWindows) SetPeerWindowAccounting(peerId connect.Id, accounting bool) bool {
	self.stateLock.Lock()
	changed := self.accounting[peerId] != accounting
	self.accounting[peerId] = accounting
	if changed && accounting {
		start := self.clock.Now()
		self.windows[peerId] = &connect.PeerWindow{PeerId: peerId, Direction: connect.PeerWindowSend, StartTime: start, EndTime: start.Add(55 * time.Minute)}
	}
	self.stateLock.Unlock()
	self.events.add(fmt.Sprintf("set %s %t %t", self.names(peerId), accounting, changed))
	return changed
}

func (self *testPeerWindows) PeerWindow(peerId connect.Id) connect.PeerWindowStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status := connect.PeerWindowStatus{Accounting: self.accounting[peerId]}
	if window := self.windows[peerId]; window != nil && status.Accounting {
		windowCopy := *window
		status.Send = &windowCopy
	}
	return status
}

func (self *testPeerWindows) RetirePeerContracts(peerId connect.Id) {
	self.events.add("retire " + self.names(peerId))
}

func (self *testPeerWindows) NotePeerWindowActivity(peerId connect.Id) {
	self.events.add("activity " + self.names(peerId))
}

func (self *testPeerWindows) AdoptPeerWindowContract(peerId connect.Id, transferKey connect.TransferKey) bool {
	self.events.add("adopt " + self.names(peerId))
	return true
}

// Clears the mode, as connect does at a window that ended with no activity in its last stretch.
func (self *testPeerWindows) clear(peerId connect.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.accounting, peerId)
	delete(self.windows, peerId)
}

// A pair of an app host and an indexer, each on a window ledger fake logging with its sends, the
// indexer serving SEARCH; and a second indexer for failover.
type testMarkedWorld struct {
	pair     *testRpcPair
	app      *testRpcSide
	indexer  *testRpcSide
	indexer2 *testRpcSide
	names    map[connect.Id]string
}

func newTestMarkedWorld(t *testing.T) *testMarkedWorld {
	world := &testMarkedWorld{pair: newTestRpcPair(t), names: map[connect.Id]string{}}
	nameOf := func(peerId connect.Id) string {
		if name, ok := world.names[peerId]; ok {
			return name
		}
		return peerId.String()
	}
	world.pair.newPeerWindows = func(side *testRpcSide) subprotocolPeerWindows {
		side.windowEvents = newTestEvents()
		return &testPeerWindows{events: side.windowEvents, names: nameOf, clock: side.clock, accounting: map[connect.Id]bool{}, windows: map[connect.Id]*connect.PeerWindow{}}
	}
	world.app = world.pair.add(nil, nil)
	world.indexer = world.pair.add(nil, nil)
	world.indexer2 = world.pair.add(nil, nil)
	world.names[world.app.clientId] = "app"
	world.names[world.indexer.clientId] = "indexer"
	world.names[world.indexer2.clientId] = "indexer2"
	for _, side := range []*testRpcSide{world.app, world.indexer, world.indexer2} {
		side.onSend = func(envelope *protocol.Envelope, destinationId connect.Id) {
			side.windowEvents.add(fmt.Sprintf("send %s %s", protocol.MessageType(envelope.Type), nameOf(destinationId)))
		}
	}
	for _, indexer := range []*testRpcSide{world.indexer, world.indexer2} {
		if err := indexer.subprotocol.SetFeatures(SubprotocolFeatureServesSearch, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := indexer.subprotocol.Handle(protocol.MessageType_SEARCH, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
			return testSearchReply(t, request)
		}, nil); err != nil {
			t.Fatal(err)
		}
	}
	// the app asks both indexers, the first its first choice
	if err := world.app.subprotocol.SetFeatures(0, func(clientId Id) bool {
		return clientId == Id(world.indexer2.clientId)
	}); err != nil {
		t.Fatal(err)
	}
	return world
}

// The index of the first event equal to want at or after from, -1 for none.
func testEventIndex(events []string, want string, from int) int {
	for i := from; i < len(events); i += 1 {
		if events[i] == want {
			return i
		}
	}
	return -1
}

// Waits until the side's keepalive has armed count waits.
func testAwaitKeepaliveMark(t *testing.T, side *testRpcSide, count uint64) {
	t.Helper()
	for {
		mark, notify := side.subprotocol.keepaliveMark.Get()
		if count <= mark {
			return
		}
		select {
		case <-notify:
		case <-time.After(testSubprotocolAwaitTimeout):
			t.Fatalf("keepalive at %d of %d", mark, count)
		}
	}
}

// A bit-1 Hello marks before it is sent and adopts its answer's contract; the indexer marks on receipt,
// adopting the marking frame's contract, before it answers; a repeat while the mode holds retires
// nothing.
func TestBitOneHelloMarksBothSides(t *testing.T) {
	world := newTestMarkedWorld(t)
	world.app.subprotocol.MarkSearchPeer(Id(world.indexer.clientId))
	if err := world.app.subprotocol.EnsureHello(t.Context(), Id(world.indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	appEvents := world.app.windowEvents.list()
	set := testEventIndex(appEvents, "set indexer true true", 0)
	retire := testEventIndex(appEvents, "retire indexer", set)
	hello := testEventIndex(appEvents, "send HELLO indexer", retire)
	adopt := testEventIndex(appEvents, "adopt indexer", hello)
	if set < 0 || retire < 0 || hello < 0 || adopt < 0 {
		t.Errorf("the app's events %v", appEvents)
	}
	indexerEvents := world.indexer.windowEvents.list()
	set = testEventIndex(indexerEvents, "set app true true", 0)
	retire = testEventIndex(indexerEvents, "retire app", set)
	adopt = testEventIndex(indexerEvents, "adopt app", retire)
	result := testEventIndex(indexerEvents, "send HELLO_RESULT app", adopt)
	if set < 0 || retire < 0 || adopt < 0 || result < 0 {
		t.Errorf("the indexer's events %v", indexerEvents)
	}
	if testEventIndex(appEvents, "activity indexer", 0) < 0 || testEventIndex(indexerEvents, "activity app", 0) < 0 {
		t.Errorf("no activity noted")
	}

	// a session re-established while the mode holds retires nothing either side
	appFrom := len(world.app.windowEvents.list())
	indexerFrom := len(world.indexer.windowEvents.list())
	world.app.subprotocol.forgetPeer(world.indexer.clientId)
	if err := world.app.subprotocol.EnsureHello(t.Context(), Id(world.indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	if testEventIndex(world.app.windowEvents.list(), "retire indexer", appFrom) >= 0 || testEventIndex(world.indexer.windowEvents.list(), "retire app", indexerFrom) >= 0 {
		t.Errorf("a repeat bit-1 Hello retired")
	}
	// a peer this side does not ask is never marked
	if err := world.app.subprotocol.SetFeatures(0, nil); err != nil {
		t.Fatal(err)
	}
	if err := world.indexer.subprotocol.EnsureHello(t.Context(), Id(world.indexer2.clientId)); err != nil {
		t.Fatal(err)
	}
	for _, event := range world.indexer2.windowEvents.list() {
		if event == "set indexer true true" {
			t.Errorf("a Hello with no bit 1 marked")
		}
	}
}

// In the foreground the app Pings its first choice on a grid from the send window's start, one a minute
// for 55 minutes, and the pair's Hello stands past HelloCacheTimeout on both sides.
func TestKeepaliveGridHolds55Minutes(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	app.subprotocol.MarkSearchPeer(Id(indexer.clientId))
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	start := app.clock.Now()
	app.subprotocol.SetForeground(true)
	for minute := uint64(1); minute <= 55; minute += 1 {
		testAwaitKeepaliveMark(t, app, minute)
		// the indexer's clock first, so it never reads a Ping at an earlier minute than the app sent it
		indexer.clock.Advance(indexer.settings.MarkedKeepaliveInterval)
		app.clock.Advance(app.settings.MarkedKeepaliveInterval)
	}
	testAwaitKeepaliveMark(t, app, 56)
	pings := 0
	for _, envelope := range app.sent() {
		if envelope.Type == uint32(protocol.MessageType_PING) {
			pings += 1
		}
	}
	if pings != 55 {
		types := []string{}
		for _, envelope := range app.sent() {
			types = append(types, protocol.MessageType(envelope.Type).String())
		}
		t.Errorf("%d Pings in 55 minutes: %v", pings, types)
	}
	if !app.clock.Now().Equal(start.Add(55 * time.Minute)) {
		t.Errorf("off the grid: %s", app.clock.Now().Sub(start))
	}
	if !app.subprotocol.peerVerified(indexer.clientId) || !indexer.subprotocol.peerVerified(app.clientId) {
		t.Errorf("the pair's Hello lapsed inside its window")
	}
}

// A 3-minute suspension: the background sends nothing, and the next foreground re-establishes the lost
// session by a Hello at once.
func TestSuspensionReestablishesAtTheNextForeground(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	app.subprotocol.MarkSearchPeer(Id(indexer.clientId))
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	app.subprotocol.SetForeground(true)
	testAwaitKeepaliveMark(t, app, 1)
	app.subprotocol.SetForeground(false)
	sentBefore := len(app.sent())
	app.clock.Advance(3 * time.Minute)
	indexer.clock.Advance(3 * time.Minute)
	if len(app.sent()) != sentBefore {
		t.Errorf("a suspended app sent %d frames", len(app.sent())-sentBefore)
	}
	from := len(app.windowEvents.list())
	app.subprotocol.SetForeground(true)
	app.windowEvents.await(t, "send HELLO indexer")
	if testEventIndex(app.windowEvents.list(), "send PING indexer", from) >= 0 {
		t.Errorf("a Ping before the Hello that re-establishes")
	}
}

// A 3-minute drop in the foreground: the tick past MarkedSessionTimeout finds the session lost, and a
// search before the next tick re-establishes it at once by its own Hello.
func TestDropReestablishedByTheSearchBeforeTheNextTick(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	app.subprotocol.markedPair.Set(subprotocolMarkedPair{peerId: indexer.clientId, hasPeer: true, foreground: true})
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	// the drop: nothing arrives either way, and the session goes past its timeout
	app.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		return nil
	})
	app.clock.Advance(app.settings.MarkedSessionTimeout)
	indexer.clock.Advance(app.settings.MarkedSessionTimeout)
	ticked := make(chan struct{})
	waitCount, _ := app.clock.waitCount.Get()
	go func() {
		defer close(ticked)
		app.subprotocol.keepaliveTick(indexer.clientId, true)
	}()
	app.windowEvents.await(t, "send HELLO indexer")
	app.clock.awaitWaitCount(waitCount + 1)
	app.clock.Advance(app.settings.DefaultCallTimeout)
	testAwait(t, ticked, "the tick's end")
	if app.subprotocol.peerVerified(indexer.clientId) {
		t.Fatalf("the session survived the drop")
	}
	// the network returns a minute in, and a search before the next tick re-establishes at once
	app.setDeliver(nil)
	app.clock.Advance(time.Minute - app.settings.DefaultCallTimeout)
	from := len(app.windowEvents.list())
	if _, err := app.subprotocol.Call(t.Context(), Id(indexer.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 0, 1), nil); err != nil {
		t.Fatalf("the search: %v", err)
	}
	events := app.windowEvents.list()
	hello := testEventIndex(events, "send HELLO indexer", from)
	search := testEventIndex(events, "send SEARCH indexer", hello)
	if hello < 0 || search < 0 {
		t.Errorf("events %v", events[from:])
	}
}

// An indexer first asked on failover gets its bit-1 Hello at that search, which marks it first.
func TestFailoverSearchOpensItsOwnWindow(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	app.subprotocol.MarkSearchPeer(Id(world.indexer.clientId))
	if _, err := app.subprotocol.Call(t.Context(), Id(world.indexer2.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 2, 0, 1), nil); err != nil {
		t.Fatal(err)
	}
	events := app.windowEvents.list()
	set := testEventIndex(events, "set indexer2 true true", 0)
	retire := testEventIndex(events, "retire indexer2", set)
	hello := testEventIndex(events, "send HELLO indexer2", retire)
	adopt := testEventIndex(events, "adopt indexer2", hello)
	search := testEventIndex(events, "send SEARCH indexer2", adopt)
	if set < 0 || retire < 0 || hello < 0 || adopt < 0 || search < 0 {
		t.Errorf("events %v", events)
	}
}

// A window that ends in the background with no activity clears the mode: the background sends no
// keepalive, and the next search marks the pair again with a bit-1 Hello before it goes.
func TestBackgroundWindowEndClearsTheModeAndTheNextSearchMarksAgain(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	app.subprotocol.MarkSearchPeer(Id(indexer.clientId))
	if _, err := app.subprotocol.Call(t.Context(), Id(indexer.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 0, 1), nil); err != nil {
		t.Fatal(err)
	}
	sentBefore := len(app.sent())
	app.clock.Advance(55 * time.Minute)
	indexer.clock.Advance(55 * time.Minute)
	if len(app.sent()) != sentBefore {
		t.Errorf("a background app sent %d frames", len(app.sent())-sentBefore)
	}
	app.peerWindows.clear(indexer.clientId)
	from := len(app.windowEvents.list())
	if _, err := app.subprotocol.Call(t.Context(), Id(indexer.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 1, 1), nil); err != nil {
		t.Fatal(err)
	}
	events := app.windowEvents.list()
	set := testEventIndex(events, "set indexer true true", from)
	hello := testEventIndex(events, "send HELLO indexer", set)
	search := testEventIndex(events, "send SEARCH indexer", hello)
	if set < 0 || hello < 0 || search < 0 {
		t.Errorf("events %v", events[from:])
	}
}

// In the foreground, HeadCheck's round counts the first-choice indexer among its own picks, the others
// staying random; in the background the indexer is one candidate among the rest.
func TestHeadCheckRoundCountsTheIndexer(t *testing.T) {
	indexerId := NewId()
	candidates := []HeadCheckCandidate{{SidecarId: indexerId, Own: true}}
	peers := testHeadCheckPeerMap{indexerId: {Admitted: true}}
	for range 6 {
		sidecarId := NewId()
		candidates = append(candidates, HeadCheckCandidate{SidecarId: sidecarId, Own: true, SharesRepo: true})
		peers[sidecarId] = HeadCheckPeer{Admitted: true}
	}
	for seed := uint64(1); seed <= 20; seed += 1 {
		picks := headCheckRoundPicksWith(candidates, peers, Id{}, 4, testSeededRandom(seed), &indexerId)
		if len(picks) != 4 || picks[0] != indexerId {
			t.Errorf("seed %d: picks %v", seed, picks)
		}
	}
	// without it, the indexer shares no repo and loses to six that do
	for seed := uint64(1); seed <= 20; seed += 1 {
		if picks := headCheckRoundPicksWith(candidates, peers, Id{}, 4, testSeededRandom(seed), nil); slices.Contains(picks, indexerId) {
			t.Errorf("seed %d: the indexer picked in the background", seed)
		}
	}
}
