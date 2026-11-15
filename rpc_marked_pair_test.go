//go:build !sidecar_http && !js

// The marked pair (PROTO-M10-04), FS-125's lifecycle cases at this layer on a fake clock and a fake of
// connect's window ledger: bit-1 Hellos mark before sending and on receipt, adopting as connect asks, and
// a repeat retires nothing; the Ping grid holds 55 minutes and the Hello stands past HelloCacheTimeout;
// each side touches the session as of the frame that showed it live, the indexer before its Pong,
// however late its worker runs; a 3-minute suspension sends nothing, even for a wake armed as it began,
// and re-establishes by a Hello at the next foreground, as does a foreground return the keepalive never
// saw begin; a 3-minute drop in the foreground re-establishes by the search before the next tick; a
// failover search opens its own window; a window ending in the background clears the mode and the next
// search marks again; and HeadCheck's round counts the first warm indexer in the foreground.
//
// The warm pairs (PROTO-M10-06; DESIGN-DETAILS 7.2.3, QD-707), the same cases with three indexers named,
// two of them own: each pair's grid holds 55 minutes from its own window's start; an indexer leaving the
// list stops its Pings, even for a wake armed as it left, and leaves the others'; an id past
// MarkedPeerMaxCount is refused, by the instance's setting; a failover to an indexer outside the list
// opens its own window at the search and gets no keepalive; and an empty list names none.
//
// A PeerWindow call the fake holds stands for a goroutine the scheduler left behind, so a test forces the
// orders a loaded machine can run in, among them the one tip-check's full suite found at 71679a2 and
// c9e2751, with no sleep.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
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
}

func newTestEvents() *testEvents {
	return &testEvents{}
}

func (self *testEvents) add(event string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

func (self *testEvents) list() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.events)
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
	// the next PeerWindow call a test holds, nil for none
	hold *testPeerWindowHold
}

// One PeerWindow call held where it starts, as a goroutine the scheduler left behind is: held closes once
// the call arrives, and the call goes on once the test frees it. At this layer the calls are the
// keepalive's read of the window for its next wake and a touch's read of the mode.
type testPeerWindowHold struct {
	peerId   connect.Id
	held     chan struct{}
	release  chan struct{}
	freeOnce sync.Once
}

// Holds the next PeerWindow call for peerId, and frees it at the test's end if the test has not, before
// the sides close and join what it held.
func (self *testPeerWindows) holdPeerWindow(t *testing.T, peerId connect.Id) *testPeerWindowHold {
	hold := &testPeerWindowHold{peerId: peerId, held: make(chan struct{}), release: make(chan struct{})}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.hold = hold
	}()
	t.Cleanup(hold.free)
	return hold
}

// Lets the held call go on. Safe to call more than once.
func (self *testPeerWindowHold) free() {
	self.freeOnce.Do(func() {
		close(self.release)
	})
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
	var hold *testPeerWindowHold
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.hold != nil && self.hold.peerId == peerId {
			hold = self.hold
			self.hold = nil
		}
	}()
	if hold != nil {
		close(hold.held)
		<-hold.release
	}
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

// An app host and its indexers, each on a window ledger fake logging with its sends, every indexer
// serving SEARCH.
type testMarkedWorld struct {
	pair *testRpcPair
	app  *testRpcSide
	// the first two of indexers: the first choice, and a second for failover
	indexer  *testRpcSide
	indexer2 *testRpcSide
	// named indexer, indexer2, indexer3 and so on
	indexers []*testRpcSide
	names    map[connect.Id]string

	stateLock sync.Mutex
	// the app's Pings, in order
	pings []testMarkedPing
}

// A Ping the app sent: to whom, and when on the app's clock.
type testMarkedPing struct {
	name string
	time time.Time
}

// An app and two indexers, the app asking both: the first as whatever a test names warm, the second by
// SetFeatures' function.
func newTestMarkedWorld(t *testing.T) *testMarkedWorld {
	world := newTestMarkedWorldWith(t, 2, nil)
	if err := world.app.subprotocol.SetFeatures(0, func(clientId Id) bool {
		return clientId == Id(world.indexer2.clientId)
	}); err != nil {
		t.Fatal(err)
	}
	return world
}

// An app and indexerCount indexers, every side's settings adjusted by adjust. The app asks only those a
// test names.
func newTestMarkedWorldWith(t *testing.T, indexerCount int, adjust func(settings *SidecarProtocolSettings)) *testMarkedWorld {
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
	world.app = world.pair.add(nil, adjust)
	world.names[world.app.clientId] = "app"
	for i := range indexerCount {
		indexer := world.pair.add(nil, adjust)
		world.indexers = append(world.indexers, indexer)
		name := "indexer"
		if 0 < i {
			name = fmt.Sprintf("indexer%d", i+1)
		}
		world.names[indexer.clientId] = name
	}
	world.indexer = world.indexers[0]
	if 1 < indexerCount {
		world.indexer2 = world.indexers[1]
	}
	for _, side := range append([]*testRpcSide{world.app}, world.indexers...) {
		side.onSend = func(envelope *protocol.Envelope, destinationId connect.Id) {
			if side == world.app && envelope.Type == uint32(protocol.MessageType_PING) {
				func() {
					world.stateLock.Lock()
					defer world.stateLock.Unlock()
					world.pings = append(world.pings, testMarkedPing{name: nameOf(destinationId), time: side.clock.Now()})
				}()
			}
			side.windowEvents.add(fmt.Sprintf("send %s %s", protocol.MessageType(envelope.Type), nameOf(destinationId)))
		}
	}
	for _, indexer := range world.indexers {
		if err := indexer.subprotocol.SetFeatures(SubprotocolFeatureServesSearch, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := indexer.subprotocol.Handle(protocol.MessageType_SEARCH, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
			return testSearchReply(t, request)
		}, nil); err != nil {
			t.Fatal(err)
		}
	}
	return world
}

// Moves every side's clock on by step: the indexers' first, so none reads a Ping at an earlier time than
// the app sent it.
func (self *testMarkedWorld) advance(step time.Duration) {
	for _, indexer := range self.indexers {
		indexer.clock.Advance(step)
	}
	self.app.clock.Advance(step)
}

// When the app Pinged the indexer of that name, in order.
func (self *testMarkedWorld) pingTimes(name string) []time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	times := []time.Time{}
	for _, ping := range self.pings {
		if ping.name == name {
			times = append(times, ping.time)
		}
	}
	return times
}

// The ids of indexers, in order, as MarkSearchPeers takes them.
func testMarkedIds(indexers ...*testRpcSide) []Id {
	ids := []Id{}
	for _, indexer := range indexers {
		ids = append(ids, Id(indexer.clientId))
	}
	return ids
}

// Names the warm indexers and the foreground with no keepalive loop started, for a test that runs each
// tick itself.
func testMarkWithoutKeepalive(subprotocol *Subprotocol, foreground bool, peerIds ...connect.Id) {
	subprotocol.markedPairs.Set(subprotocolMarkedPairs{peers: &subprotocolMarkedPeers{peerIds: peerIds}, foreground: foreground})
}

// The events of a side that name the peer of that name, from index from on.
func testEventsNaming(events []string, name string, from int) []string {
	naming := []string{}
	for _, event := range events[from:] {
		if strings.HasSuffix(event, " "+name) || strings.Contains(event, " "+name+" ") {
			naming = append(naming, event)
		}
	}
	return naming
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

// When the Hello on record with peerId ends, and false with none on record.
func testSessionExpireTime(subprotocol *Subprotocol, peerId connect.Id) (time.Time, bool) {
	subprotocol.stateLock.Lock()
	defer subprotocol.stateLock.Unlock()
	identity, ok := subprotocol.sourceIdIdentities[peerId]
	return identity.expireTime, ok
}

// The type of each envelope in envelopes, in order.
func testEnvelopeTypes(envelopes []*protocol.Envelope) []string {
	types := []string{}
	for _, envelope := range envelopes {
		types = append(types, protocol.MessageType(envelope.Type).String())
	}
	return types
}

// Waits until the side's keepalive for peerId has armed count waits.
func testAwaitKeepaliveMark(t *testing.T, side *testRpcSide, peerId connect.Id, count uint64) {
	t.Helper()
	for {
		// subscribed before the count is read, so a wait armed after the read is not missed
		_, notify := side.subprotocol.keepaliveMark.Get()
		mark := func() uint64 {
			side.subprotocol.stateLock.Lock()
			defer side.subprotocol.stateLock.Unlock()
			if loop, ok := side.subprotocol.keepaliveLoops[peerId]; ok {
				return loop.markCount
			}
			return 0
		}()
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

// Whether the side runs a keepalive loop for peerId.
func testKeepaliveRuns(side *testRpcSide, peerId connect.Id) bool {
	side.subprotocol.stateLock.Lock()
	defer side.subprotocol.stateLock.Unlock()
	_, ok := side.subprotocol.keepaliveLoops[peerId]
	return ok
}

// Waits until the side's keepalive loop for peerId has ended.
func testAwaitKeepaliveEnd(t *testing.T, side *testRpcSide, peerId connect.Id) {
	t.Helper()
	for {
		_, notify := side.subprotocol.keepaliveMark.Get()
		if !testKeepaliveRuns(side, peerId) {
			return
		}
		select {
		case <-notify:
		case <-time.After(testSubprotocolAwaitTimeout):
			t.Fatalf("the keepalive has not ended")
		}
	}
}

// A bit-1 Hello marks before it is sent and adopts its answer's contract; the indexer marks on receipt,
// adopting the marking frame's contract, before it answers; a repeat while the mode holds retires
// nothing.
func TestBitOneHelloMarksBothSides(t *testing.T) {
	world := newTestMarkedWorld(t)
	if err := world.app.subprotocol.MarkSearchPeers(testMarkedIds(world.indexer)); err != nil {
		t.Fatal(err)
	}
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
// for 55 minutes, and the pair's Hello stands past HelloCacheTimeout on both sides. Each step of the
// clocks waits only for the app's tick to end, which its Pong ends, and the indexer touched its own
// record before it sent that Pong, so before each step both Hellos already stand past the next tick.
func TestKeepaliveGridHolds55Minutes(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(indexer)); err != nil {
		t.Fatal(err)
	}
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	start := app.clock.Now()
	app.subprotocol.SetForeground(true)
	for minute := uint64(1); minute <= 55; minute += 1 {
		testAwaitKeepaliveMark(t, app, indexer.clientId, minute)
		next := app.clock.Now().Add(app.settings.MarkedKeepaliveInterval)
		for _, c := range []struct {
			side   *testRpcSide
			peerId connect.Id
		}{{side: app, peerId: indexer.clientId}, {side: indexer, peerId: app.clientId}} {
			if expireTime, ok := testSessionExpireTime(c.side.subprotocol, c.peerId); !ok || !next.Before(expireTime) {
				t.Fatalf("minute %d: the %s's Hello ends %s in, by the next tick at %s", minute, world.names[c.side.clientId], expireTime.Sub(start), next.Sub(start))
			}
		}
		// the indexer's clock first, so it never reads a Ping at an earlier minute than the app sent it
		indexer.clock.Advance(indexer.settings.MarkedKeepaliveInterval)
		app.clock.Advance(app.settings.MarkedKeepaliveInterval)
	}
	testAwaitKeepaliveMark(t, app, indexer.clientId, 56)
	pings := 0
	for _, envelope := range app.sent() {
		if envelope.Type == uint32(protocol.MessageType_PING) {
			pings += 1
		}
	}
	if pings != 55 {
		t.Errorf("%d Pings in 55 minutes: %v", pings, testEnvelopeTypes(app.sent()))
	}
	if !app.clock.Now().Equal(start.Add(55 * time.Minute)) {
		t.Errorf("off the grid: %s", app.clock.Now().Sub(start))
	}
	if !app.subprotocol.peerVerified(indexer.clientId) || !indexer.subprotocol.peerVerified(app.clientId) {
		t.Errorf("the pair's Hello lapsed inside its window")
	}
}

// A 3-minute suspension: the background sends nothing, even with the move into it landing while the
// keepalive reads the window for its first wake and the suspension's first minute passing that wake
// before the loop looks at it; and the next foreground re-establishes the lost session by a Hello at
// once, before any Ping. Each read of the app's sends follows a wait the keepalive armed, so the read
// holds everything the loop sent before it.
func TestSuspensionReestablishesAtTheNextForeground(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(indexer)); err != nil {
		t.Fatal(err)
	}
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	sentBefore := len(app.sent())
	hold := app.peerWindows.holdPeerWindow(t, indexer.clientId)
	app.subprotocol.SetForeground(true)
	testAwait(t, hold.held, "the keepalive's first wake")
	app.subprotocol.SetForeground(false)
	step := app.settings.MarkedKeepaliveInterval
	app.clock.Advance(step)
	indexer.clock.Advance(step)
	hold.free()
	testAwaitKeepaliveMark(t, app, indexer.clientId, 1)
	app.clock.Advance(3*time.Minute - step)
	indexer.clock.Advance(3*time.Minute - step)
	app.subprotocol.SetForeground(true)
	testAwaitKeepaliveMark(t, app, indexer.clientId, 2)
	if types := testEnvelopeTypes(app.sent()[sentBefore:]); !slices.Equal(types, []string{"HELLO"}) {
		t.Errorf("sent from the suspension's start on: %v", types)
	}
}

// A move into the foreground the keepalive never sees as one, its tick waiting out a lost Ping's Pong
// through the whole background, still re-establishes the lost session by a Hello at once, not at the
// next tick.
func TestForegroundReturnDuringAPingReestablishesAtOnce(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(indexer)); err != nil {
		t.Fatal(err)
	}
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	app.subprotocol.SetForeground(true)
	testAwaitKeepaliveMark(t, app, indexer.clientId, 1)
	sentBefore := len(app.sent())
	// the first tick's Ping is lost, and the tick waits on its Pong
	app.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		return nil
	})
	waitCount, _ := app.clock.waitCount.Get()
	step := app.settings.MarkedKeepaliveInterval
	indexer.clock.Advance(step)
	app.clock.Advance(step)
	app.clock.awaitWaitCount(waitCount + 1)
	// the host suspends and returns while the tick waits, and the suspension outlasts the session
	app.subprotocol.SetForeground(false)
	app.subprotocol.SetForeground(true)
	app.setDeliver(nil)
	indexer.clock.Advance(3 * time.Minute)
	app.clock.Advance(3 * time.Minute)
	testAwaitKeepaliveMark(t, app, indexer.clientId, 2)
	if types := testEnvelopeTypes(app.sent()[sentBefore:]); !slices.Equal(types, []string{"PING", "HELLO"}) {
		t.Errorf("sent from the lost Ping on: %v", types)
	}
}

// The indexer records a Ping's session as of the Ping's arrival, and before its Pong goes. Forced here is
// the order tip-check's full suite ran TestKeepaliveGridHolds55Minutes in at 71679a2 and c9e2751: the
// Pong went out, the app's tick ended and the indexer's clock reached the session's end before the
// indexer's worker touched it, so the touch found it ended, the next Ping was refused and the tick after
// re-established by Hello. Held at its touch, the indexer has queued and sent no Pong; and a touch that
// runs only once the indexer's clock has reached the session's end keeps it standing
// MarkedSessionTimeout past the Ping, so the next Ping is answered.
func TestIndexerTouchesTheSessionAsOfThePingBeforeItsPong(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	testMarkWithoutKeepalive(app.subprotocol, false, indexer.clientId)
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	// a keepalive step before the Hello's own end, past which only the session keeps it
	step := app.settings.MarkedKeepaliveInterval
	app.clock.Advance(app.settings.HelloCacheTimeout - step)
	indexer.clock.Advance(app.settings.HelloCacheTimeout - step)
	arrivalTime := indexer.clock.Now()
	hold := indexer.peerWindows.holdPeerWindow(t, app.clientId)
	pinged := make(chan error, 1)
	go func() {
		pinged <- app.subprotocol.ping(t.Context(), indexer.clientId)
	}()
	testAwait(t, hold.held, "the indexer's touch")
	// the Hello's answer left the reply queue before the app's Hello ended, so what the queue or the
	// indexer's sends hold now is the Pong
	if queued, types := len(indexer.subprotocol.replies), testEnvelopeTypes(indexer.sent()); queued != 0 || slices.Contains(types, "PONG") {
		t.Errorf("before it touched the session the indexer queued %d replies and sent %v", queued, types)
	}
	indexer.clock.Advance(step)
	hold.free()
	if err := testAwait(t, pinged, "the Ping's end"); err != nil {
		t.Fatalf("the Ping: %v", err)
	}
	want := arrivalTime.Add(app.settings.MarkedSessionTimeout)
	if expireTime, ok := testSessionExpireTime(indexer.subprotocol, app.clientId); !ok || !expireTime.Equal(want) {
		t.Errorf("the indexer's Hello ends at %s (on record %t), want %s", expireTime, ok, want)
	}
	// the app's next Ping, at the indexer's minute, is answered
	app.clock.Advance(step)
	if err := app.subprotocol.ping(t.Context(), indexer.clientId); err != nil {
		t.Errorf("the next Ping: %v", err)
	}
}

// The app records a Pong's session as of the Pong's arrival: a touch that runs only once the app's clock
// has reached the session's end keeps it standing MarkedSessionTimeout past the Pong, and the session
// showed live then.
func TestRequesterTouchesTheSessionAsOfThePong(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	testMarkWithoutKeepalive(app.subprotocol, false, indexer.clientId)
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	step := app.settings.MarkedKeepaliveInterval
	app.clock.Advance(app.settings.HelloCacheTimeout - step)
	indexer.clock.Advance(app.settings.HelloCacheTimeout - step)
	arrivalTime := app.clock.Now()
	hold := app.peerWindows.holdPeerWindow(t, indexer.clientId)
	pinged := make(chan error, 1)
	go func() {
		pinged <- app.subprotocol.ping(t.Context(), indexer.clientId)
	}()
	testAwait(t, hold.held, "the app's touch")
	app.clock.Advance(step)
	hold.free()
	if err := testAwait(t, pinged, "the Ping's end"); err != nil {
		t.Fatalf("the Ping: %v", err)
	}
	want := arrivalTime.Add(app.settings.MarkedSessionTimeout)
	if expireTime, ok := testSessionExpireTime(app.subprotocol, indexer.clientId); !ok || !expireTime.Equal(want) {
		t.Errorf("the app's Hello ends at %s (on record %t), want %s", expireTime, ok, want)
	}
	if sessionTime, standing := app.subprotocol.sessionTime(indexer.clientId); !standing || !sessionTime.Equal(arrivalTime) {
		t.Errorf("the session showed live at %s (standing %t), want the Pong's %s", sessionTime, standing, arrivalTime)
	}
}

// A 3-minute drop in the foreground: the tick past MarkedSessionTimeout finds the session lost, and a
// search before the next tick re-establishes it at once by its own Hello.
func TestDropReestablishedByTheSearchBeforeTheNextTick(t *testing.T) {
	world := newTestMarkedWorld(t)
	app := world.app
	indexer := world.indexer
	testMarkWithoutKeepalive(app.subprotocol, true, indexer.clientId)
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	// the drop: nothing arrives either way, and the session goes past its timeout
	app.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		return nil
	})
	app.clock.Advance(app.settings.MarkedSessionTimeout)
	indexer.clock.Advance(app.settings.MarkedSessionTimeout)
	tickFrom := len(app.windowEvents.list())
	ticked := make(chan struct{})
	waitCount, _ := app.clock.waitCount.Get()
	go func() {
		defer close(ticked)
		app.subprotocol.keepaliveTick(indexer.clientId, true)
	}()
	// the tick's Hello has gone into the drop once the tick waits on its answer
	app.clock.awaitWaitCount(waitCount + 1)
	if testEventIndex(app.windowEvents.list(), "send HELLO indexer", tickFrom) < 0 {
		t.Errorf("the tick past the timeout sent no Hello: %v", app.windowEvents.list()[tickFrom:])
	}
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
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(world.indexer)); err != nil {
		t.Fatal(err)
	}
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
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(indexer)); err != nil {
		t.Fatal(err)
	}
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
		picks := headCheckRoundPicksWith(candidates, peers, Id{}, 4, DefaultSidecarProtocolSettings().HeadCheckRoundOtherMemberCount, testSeededRandom(seed), &indexerId)
		if len(picks) != 4 || picks[0] != indexerId {
			t.Errorf("seed %d: picks %v", seed, picks)
		}
	}
	// without it, the indexer shares no repo and loses to six that do
	for seed := uint64(1); seed <= 20; seed += 1 {
		if picks := headCheckRoundPicksWith(candidates, peers, Id{}, 4, DefaultSidecarProtocolSettings().HeadCheckRoundOtherMemberCount, testSeededRandom(seed), nil); slices.Contains(picks, indexerId) {
			t.Errorf("seed %d: the indexer picked in the background", seed)
		}
	}
}

// The first of the warm indexers is the one HeadCheck's round counts, and only in the foreground: the
// caller names its own indexers first, so it is the first-choice own one.
func TestForegroundSearchPeerIsTheFirstWarmIndexer(t *testing.T) {
	world := newTestMarkedWorldWith(t, 3, nil)
	app := world.app
	first, second, third := world.indexers[0], world.indexers[1], world.indexers[2]
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(second, first, third)); err != nil {
		t.Fatal(err)
	}
	if peerId, ok := app.subprotocol.foregroundSearchPeer(); ok {
		t.Errorf("%s counted in the background", world.names[peerId])
	}
	// no session stands, so each loop's tick at the foreground runs a Hello; the test waits them out
	app.subprotocol.SetForeground(true)
	for _, indexer := range world.indexers {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 1)
	}
	if peerId, ok := app.subprotocol.foregroundSearchPeer(); !ok || peerId != second.clientId {
		t.Errorf("counted %s (%t), want indexer2", world.names[peerId], ok)
	}
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(first, second)); err != nil {
		t.Fatal(err)
	}
	if peerId, ok := app.subprotocol.foregroundSearchPeer(); !ok || peerId != first.clientId {
		t.Errorf("counted %s (%t), want indexer", world.names[peerId], ok)
	}
	if err := app.subprotocol.MarkSearchPeers(nil); err != nil {
		t.Fatal(err)
	}
	if peerId, ok := app.subprotocol.foregroundSearchPeer(); ok {
		t.Errorf("%s counted with none named", world.names[peerId])
	}
}

// Three warm pairs, two own and one other member's, whose windows opened 20 s apart: in the foreground
// each is Pinged once a minute for 55 minutes on the grid from its own window's start, 20 s from the
// next pair's, and every pair's Hello stands past HelloCacheTimeout on both sides with no second Hello.
// Each step of the clocks reaches one pair's tick and waits for it to end, which its Pong ends.
func TestThreeKeepaliveGridsHold55Minutes(t *testing.T) {
	world := newTestMarkedWorldWith(t, 3, nil)
	app := world.app
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(world.indexers...)); err != nil {
		t.Fatal(err)
	}
	offset := 20 * time.Second
	windowStarts := []time.Time{}
	for i, indexer := range world.indexers {
		if 0 < i {
			world.advance(offset)
		}
		windowStarts = append(windowStarts, app.clock.Now())
		if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
			t.Fatal(err)
		}
	}
	app.subprotocol.SetForeground(true)
	// every pair's first wake is armed before the clocks move, and from then on a pair arms a wake only
	// as its own tick ends, which its step waits for: a clock a test moves between a loop's reading of it
	// and its arming would set that wake late, as no running clock does
	for _, indexer := range world.indexers {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 1)
	}
	interval := app.settings.MarkedKeepaliveInterval
	for step := range 3 * 55 {
		i := step % 3
		tick := uint64(step/3 + 1)
		indexer := world.indexers[i]
		testAwaitKeepaliveMark(t, app, indexer.clientId, tick)
		// this pair's tick is the next point on any grid, and its Hello stands past the one after
		due := windowStarts[i].Add(time.Duration(tick) * interval)
		if next := app.clock.Now().Add(offset); !next.Equal(due) {
			t.Fatalf("step %d: %s's tick %d is due %s in, the step reaches %s", step, world.names[indexer.clientId], tick, due.Sub(windowStarts[0]), next.Sub(windowStarts[0]))
		}
		for _, c := range []struct {
			side   *testRpcSide
			peerId connect.Id
		}{{side: app, peerId: indexer.clientId}, {side: indexer, peerId: app.clientId}} {
			if expireTime, ok := testSessionExpireTime(c.side.subprotocol, c.peerId); !ok || !due.Before(expireTime) {
				t.Fatalf("step %d: the %s's Hello ends %s in, by the tick at %s", step, world.names[c.side.clientId], expireTime.Sub(windowStarts[0]), due.Sub(windowStarts[0]))
			}
		}
		world.advance(offset)
		testAwaitKeepaliveMark(t, app, indexer.clientId, tick+1)
	}
	for i, indexer := range world.indexers {
		name := world.names[indexer.clientId]
		times := world.pingTimes(name)
		if len(times) != 55 {
			t.Errorf("%d Pings to %s in its 55 minutes", len(times), name)
			continue
		}
		for k, pingTime := range times {
			if want := windowStarts[i].Add(time.Duration(k+1) * interval); !pingTime.Equal(want) {
				t.Errorf("%s's Ping %d went %s into its window, off its grid", name, k+1, pingTime.Sub(windowStarts[i]))
				break
			}
		}
		if !app.subprotocol.peerVerified(indexer.clientId) || !indexer.subprotocol.peerVerified(app.clientId) {
			t.Errorf("the pair with %s lost its Hello inside its window", name)
		}
	}
	hellos := 0
	for _, envelope := range app.sent() {
		if envelope.Type == uint32(protocol.MessageType_HELLO) {
			hellos += 1
		}
	}
	if hellos != 3 {
		t.Errorf("%d Hellos for three pairs: %v", hellos, testEnvelopeTypes(app.sent()))
	}
	if !app.clock.Now().Equal(windowStarts[2].Add(55 * time.Minute)) {
		t.Errorf("ended %s into the last window", app.clock.Now().Sub(windowStarts[2]))
	}
}

// An indexer leaving the list stops its Pings and leaves the others': the one that leaves does so while
// its keepalive reads the window for its first wake, and the minute passes before the loop looks at that
// wake, so the tick the wake was armed for is dropped and the loop ends, with nothing sent to it; the
// two that stay are Pinged that minute and after, on their grids. Named again, it is re-established by a
// Hello at once and Pinged at its grid's next point.
func TestAPeerLeavingTheListStopsItsPingsAndLeavesTheOthers(t *testing.T) {
	world := newTestMarkedWorldWith(t, 3, nil)
	app := world.app
	staying := []*testRpcSide{world.indexers[0], world.indexers[2]}
	leaving := world.indexers[1]
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(world.indexers...)); err != nil {
		t.Fatal(err)
	}
	for _, indexer := range world.indexers {
		if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
			t.Fatal(err)
		}
	}
	start := app.clock.Now()
	leavingFrom := len(app.windowEvents.list())
	hold := app.peerWindows.holdPeerWindow(t, leaving.clientId)
	app.subprotocol.SetForeground(true)
	testAwait(t, hold.held, "the leaving indexer's first wake")
	for _, indexer := range staying {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 1)
	}
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(staying...)); err != nil {
		t.Fatal(err)
	}
	if app.subprotocol.asksSearch(leaving.clientId) {
		t.Errorf("bit 1 still goes to the indexer that left")
	}
	interval := app.settings.MarkedKeepaliveInterval
	world.advance(interval)
	// the wakes of the two that stay were armed before the list moved, and still fire
	for _, indexer := range staying {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 2)
	}
	hold.free()
	testAwaitKeepaliveEnd(t, app, leaving.clientId)
	for minute := uint64(2); minute <= 3; minute += 1 {
		world.advance(interval)
		for _, indexer := range staying {
			testAwaitKeepaliveMark(t, app, indexer.clientId, minute+1)
		}
	}
	for _, indexer := range staying {
		name := world.names[indexer.clientId]
		want := []time.Time{start.Add(interval), start.Add(2 * interval), start.Add(3 * interval)}
		if times := world.pingTimes(name); !slices.Equal(times, want) {
			t.Errorf("%s's Pings at %v, want one a minute for three", name, times)
		}
	}
	leavingName := world.names[leaving.clientId]
	if sent := testEventsNaming(app.windowEvents.list(), leavingName, leavingFrom); len(sent) != 0 {
		t.Errorf("after it left the list, toward %s: %v", leavingName, sent)
	}

	// named again in the foreground, three minutes on: its session is lost, so a Hello at once, and then
	// its grid, which is its window's still
	againFrom := len(app.windowEvents.list())
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(staying[0], staying[1], leaving)); err != nil {
		t.Fatal(err)
	}
	testAwaitKeepaliveMark(t, app, leaving.clientId, 1)
	if events := app.windowEvents.list(); testEventIndex(events, "send HELLO "+leavingName, againFrom) < 0 || len(world.pingTimes(leavingName)) != 0 {
		t.Errorf("named again, toward %s: %v", leavingName, testEventsNaming(events, leavingName, againFrom))
	}
	world.advance(interval)
	testAwaitKeepaliveMark(t, app, leaving.clientId, 2)
	for _, indexer := range staying {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 5)
	}
	if times := world.pingTimes(leavingName); !slices.Equal(times, []time.Time{start.Add(4 * interval)}) {
		t.Errorf("%s's Pings at %v, want one at its grid's fourth minute", leavingName, times)
	}
	for _, indexer := range staying {
		if times := world.pingTimes(world.names[indexer.clientId]); len(times) != 4 {
			t.Errorf("%s's Pings at %v, want four", world.names[indexer.clientId], times)
		}
	}
}

// A fourth id is refused: the three before it are kept warm, each opening its window by a bit-1 Hello at
// the foreground and Pinged at its minute, and the fourth gets no bit 1, no keepalive and no frame. A
// zero id and a repeat take no place. The cap is the instance's setting: a host set to one refuses the
// second, and one set to four keeps four.
func TestAnIdPastTheCapIsRefused(t *testing.T) {
	world := newTestMarkedWorldWith(t, 4, nil)
	app := world.app
	if app.settings.MarkedPeerMaxCount != 3 {
		t.Fatalf("MarkedPeerMaxCount %d", app.settings.MarkedPeerMaxCount)
	}
	warm := world.indexers[:3]
	fourth := world.indexers[3]
	fourthName := world.names[fourth.clientId]
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(world.indexers...)); !errors.Is(err, errSubprotocolMarkedPeers) {
		t.Fatalf("a fourth id: %v", err)
	}
	if app.subprotocol.asksSearch(fourth.clientId) || testKeepaliveRuns(app, fourth.clientId) {
		t.Errorf("the fourth id was named")
	}
	app.subprotocol.SetForeground(true)
	for _, indexer := range warm {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 1)
	}
	events := app.windowEvents.list()
	for _, indexer := range warm {
		name := world.names[indexer.clientId]
		set := testEventIndex(events, "set "+name+" true true", 0)
		hello := testEventIndex(events, "send HELLO "+name, set)
		if !app.subprotocol.asksSearch(indexer.clientId) || set < 0 || hello < 0 || !app.subprotocol.peerVerified(indexer.clientId) {
			t.Errorf("%s is not warm at the foreground: %v", name, testEventsNaming(events, name, 0))
		}
	}
	world.advance(app.settings.MarkedKeepaliveInterval)
	for _, indexer := range warm {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 2)
		if times := world.pingTimes(world.names[indexer.clientId]); len(times) != 1 {
			t.Errorf("%s's Pings at %v, want one", world.names[indexer.clientId], times)
		}
	}
	if toward := testEventsNaming(app.windowEvents.list(), fourthName, 0); len(toward) != 0 {
		t.Errorf("toward the refused id: %v", toward)
	}

	// a zero id and a repeat are passed over, and take no place under the cap
	repeated := []Id{Id(warm[0].clientId), {}, Id(warm[0].clientId), Id(warm[1].clientId), Id(warm[2].clientId)}
	if err := app.subprotocol.MarkSearchPeers(repeated); err != nil {
		t.Errorf("three ids, one twice, and a zero id: %v", err)
	}
	if peerIds := app.subprotocol.markedPairs.Value().peerIds(); !slices.Equal(peerIds, []connect.Id{warm[0].clientId, warm[1].clientId, warm[2].clientId}) {
		t.Errorf("named %v", peerIds)
	}

	one := newTestMarkedWorldWith(t, 2, func(settings *SidecarProtocolSettings) {
		settings.MarkedPeerMaxCount = 1
	})
	if err := one.app.subprotocol.MarkSearchPeers(testMarkedIds(one.indexers...)); !errors.Is(err, errSubprotocolMarkedPeers) {
		t.Errorf("a second id under a cap of one: %v", err)
	}
	if !one.app.subprotocol.asksSearch(one.indexer.clientId) || one.app.subprotocol.asksSearch(one.indexer2.clientId) {
		t.Errorf("a cap of one did not keep the first id alone")
	}
	four := newTestMarkedWorldWith(t, 4, func(settings *SidecarProtocolSettings) {
		settings.MarkedPeerMaxCount = 4
	})
	if err := four.app.subprotocol.MarkSearchPeers(testMarkedIds(four.indexers...)); err != nil {
		t.Errorf("four ids under a cap of four: %v", err)
	}
}

// A failover to an indexer outside the list: with three pairs warm, a search toward a fourth indexer the
// app's mode lets it ask runs that indexer's bit-1 Hello first, which opens its own window at the search,
// and the fourth then gets no keepalive, the three keeping theirs.
func TestFailoverOutsideTheListOpensItsOwnWindowAtTheSearch(t *testing.T) {
	world := newTestMarkedWorldWith(t, 4, nil)
	app := world.app
	warm := world.indexers[:3]
	outside := world.indexers[3]
	outsideName := world.names[outside.clientId]
	if err := app.subprotocol.SetFeatures(0, func(clientId Id) bool {
		return clientId == Id(outside.clientId)
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(warm...)); err != nil {
		t.Fatal(err)
	}
	app.subprotocol.SetForeground(true)
	for _, indexer := range warm {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 1)
	}
	if toward := testEventsNaming(app.windowEvents.list(), outsideName, 0); len(toward) != 0 {
		t.Errorf("before the search, toward the indexer outside the list: %v", toward)
	}
	if _, err := app.subprotocol.Call(t.Context(), Id(outside.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 4, 0, 1), nil); err != nil {
		t.Fatal(err)
	}
	events := app.windowEvents.list()
	set := testEventIndex(events, "set "+outsideName+" true true", 0)
	retire := testEventIndex(events, "retire "+outsideName, set)
	hello := testEventIndex(events, "send HELLO "+outsideName, retire)
	adopt := testEventIndex(events, "adopt "+outsideName, hello)
	search := testEventIndex(events, "send SEARCH "+outsideName, adopt)
	if set < 0 || retire < 0 || hello < 0 || adopt < 0 || search < 0 {
		t.Errorf("events %v", testEventsNaming(events, outsideName, 0))
	}
	world.advance(app.settings.MarkedKeepaliveInterval)
	for _, indexer := range warm {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 2)
		if times := world.pingTimes(world.names[indexer.clientId]); len(times) != 1 {
			t.Errorf("%s's Pings at %v, want one", world.names[indexer.clientId], times)
		}
	}
	if testKeepaliveRuns(app, outside.clientId) || len(world.pingTimes(outsideName)) != 0 {
		t.Errorf("the indexer outside the list got a keepalive")
	}
}

// An empty list names none: every keepalive ends, bit 1 goes to no one by the list, and the next minute
// sends nothing.
func TestAnEmptyListNamesNone(t *testing.T) {
	world := newTestMarkedWorldWith(t, 2, nil)
	app := world.app
	if err := app.subprotocol.MarkSearchPeers(testMarkedIds(world.indexers...)); err != nil {
		t.Fatal(err)
	}
	app.subprotocol.SetForeground(true)
	for _, indexer := range world.indexers {
		testAwaitKeepaliveMark(t, app, indexer.clientId, 1)
	}
	if err := app.subprotocol.MarkSearchPeers([]Id{}); err != nil {
		t.Fatal(err)
	}
	for _, indexer := range world.indexers {
		testAwaitKeepaliveEnd(t, app, indexer.clientId)
		if app.subprotocol.asksSearch(indexer.clientId) {
			t.Errorf("bit 1 still goes to %s", world.names[indexer.clientId])
		}
	}
	sentBefore := len(app.sent())
	world.advance(app.settings.MarkedKeepaliveInterval)
	if sent := app.sent()[sentBefore:]; len(sent) != 0 {
		t.Errorf("with none named the app sent %v", testEnvelopeTypes(sent))
	}
}
