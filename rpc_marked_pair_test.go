//go:build !sidecar_http && !js

// The marked pair (PROTO-M10-04), FS-125's lifecycle cases at this layer on a fake clock and a fake of
// connect's window ledger: bit-1 Hellos mark before sending and on receipt, adopting as connect asks, and
// a repeat retires nothing; the Ping grid holds 55 minutes and the Hello stands past HelloCacheTimeout;
// each side touches the session as of the frame that showed it live, the indexer before its Pong,
// however late its worker runs; a 3-minute suspension sends nothing, even for a wake armed as it began,
// and re-establishes by a Hello at the next foreground, as does a foreground return the keepalive never
// saw begin; a 3-minute drop in the foreground re-establishes by the search before the next tick; a
// failover search opens its own window; a window ending in the background clears the mode and the next
// search marks again; and HeadCheck's round counts the first-choice indexer in the foreground.
//
// A PeerWindow call the fake holds stands for a goroutine the scheduler left behind, so a test forces the
// orders a loaded machine can run in, among them the one tip-check's full suite found at 71679a2 and
// c9e2751, with no sleep.

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
// for 55 minutes, and the pair's Hello stands past HelloCacheTimeout on both sides. Each step of the
// clocks waits only for the app's tick to end, which its Pong ends, and the indexer touched its own
// record before it sent that Pong, so before each step both Hellos already stand past the next tick.
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
	testAwaitKeepaliveMark(t, app, 56)
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
	app.subprotocol.MarkSearchPeer(Id(indexer.clientId))
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
	testAwaitKeepaliveMark(t, app, 1)
	app.clock.Advance(3*time.Minute - step)
	indexer.clock.Advance(3*time.Minute - step)
	app.subprotocol.SetForeground(true)
	testAwaitKeepaliveMark(t, app, 2)
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
	app.subprotocol.MarkSearchPeer(Id(indexer.clientId))
	if err := app.subprotocol.EnsureHello(t.Context(), Id(indexer.clientId)); err != nil {
		t.Fatal(err)
	}
	app.subprotocol.SetForeground(true)
	testAwaitKeepaliveMark(t, app, 1)
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
	testAwaitKeepaliveMark(t, app, 2)
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
	app.subprotocol.markedPair.Set(subprotocolMarkedPair{peerId: indexer.clientId, hasPeer: true})
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
	app.subprotocol.markedPair.Set(subprotocolMarkedPair{peerId: indexer.clientId, hasPeer: true})
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
