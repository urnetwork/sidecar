//go:build !ios_extension && !sidecar_http && !js

package sidecar_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An OS's tables as a test sets them: each dump answers copies of sockets, or err; Owners names what owners holds by
// identity and records what it was asked for; destroyed is the notice channel.
type testListenersDiscoverer struct {
	destroyed chan struct{}

	stateLock sync.Mutex
	sockets   []*sidecar.ListenersSocket
	err       error
	owners    map[uint64]string
	asked     [][]uint64
	dumpCount int
	closed    bool
}

func newTestListenersDiscoverer() *testListenersDiscoverer {
	return &testListenersDiscoverer{destroyed: make(chan struct{}, 1), owners: map[uint64]string{}}
}

// What the next dumps answer.
func (self *testListenersDiscoverer) set(sockets []*sidecar.ListenersSocket, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sockets = sockets
	self.err = err
}

func (self *testListenersDiscoverer) Dump(ctx context.Context) ([]*sidecar.ListenersSocket, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dumpCount += 1
	if self.err != nil {
		return nil, self.err
	}
	sockets := []*sidecar.ListenersSocket{}
	for _, socket := range self.sockets {
		copied := *socket
		sockets = append(sockets, &copied)
	}
	return sockets, nil
}

func (self *testListenersDiscoverer) Owners(ctx context.Context, sockets []*sidecar.ListenersSocket) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	identities := []uint64{}
	for _, socket := range sockets {
		identities = append(identities, socket.Inode)
		if program, ok := self.owners[socket.Inode]; ok {
			socket.Owner = sidecar.ListenersOwnerProgram
			socket.Program = program
		}
	}
	slices.Sort(identities)
	self.asked = append(self.asked, identities)
	return nil
}

func (self *testListenersDiscoverer) Destroyed() <-chan struct{} {
	return self.destroyed
}

func (self *testListenersDiscoverer) EphemeralFirstPort() uint16 {
	return 32768
}

func (self *testListenersDiscoverer) Close() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	return nil
}

// The identities each Owners call was asked for, and the dumps made.
func (self *testListenersDiscoverer) record() ([][]uint64, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.asked), self.dumpCount
}

// A TCP socket on every IPv4 interface, port and identity as given.
func testListenersSocket(port uint16, identity uint64) *sidecar.ListenersSocket {
	return &sidecar.ListenersSocket{
		Protocol: protocol.ListenersProtocol_LISTENERS_PROTOCOL_TCP, Bind: netip.IPv4Unspecified(), Port: port, Inode: identity,
	}
}

// A poller on a fake clock over discoverer, each dump handed to the returned channel, closed at the test's end.
func newTestListenersPoller(t *testing.T, discoverer *testListenersDiscoverer) (*sidecar.ListenersPoller, *sidecartest.FakeClock, chan *sidecar.ListenersDump, *sidecar.ListenersSettings) {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecar.DefaultListenersSettings()
	dumps := make(chan *sidecar.ListenersDump, 16)
	poller, err := sidecar.NewListenersPoller(context.Background(), &sidecar.ListenersPollerArgs{
		Discoverer: discoverer,
		OnDump: func(dump *sidecar.ListenersDump) {
			dumps <- dump
		},
		Clock:    clock,
		Settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poller.Close)
	return poller, clock, dumps, settings
}

// The next dump, which a bounded wait must see: a failure, never a sleep.
func testNextDump(t *testing.T, dumps chan *sidecar.ListenersDump) *sidecar.ListenersDump {
	t.Helper()
	select {
	case dump := <-dumps:
		return dump
	case <-time.After(30 * time.Second):
		t.Fatal("no dump came")
		return nil
	}
}

// No dump has come: the poller holds no wake, so none can come until the test moves the clock or asks.
func testNoDump(t *testing.T, dumps chan *sidecar.ListenersDump) {
	t.Helper()
	select {
	case dump := <-dumps:
		t.Fatalf("a dump came: %v", dump)
	default:
	}
}

// Waits until the poller's goroutine has set count timers on the clock.
func testAwaitTimers(t *testing.T, clock *sidecartest.FakeClock, count int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := clock.AwaitTimers(ctx, count); err != nil {
		t.Fatalf("the poller set no timer: %v", err)
	}
}

// The poll: a dump as the poller starts, then one each PollInterval on the injected clock and none before.
func TestListenersPollerDumpsEachInterval(t *testing.T) {
	discoverer := newTestListenersDiscoverer()
	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1)}, nil)
	_, clock, dumps, settings := newTestListenersPoller(t, discoverer)
	first := testNextDump(t, dumps)
	if len(first.Sockets) != 1 || first.Sockets[0].Port != 5432 || first.EphemeralFirstPort != 32768 || !first.At.Equal(clock.Now()) {
		t.Fatalf("first dump %+v", first)
	}
	testAwaitTimers(t, clock, 1)
	clock.Advance(settings.PollInterval - time.Second)
	testNoDump(t, dumps)
	clock.Advance(time.Second)
	second := testNextDump(t, dumps)
	if !second.At.Equal(sidecartest.DefaultClockStart().Add(settings.PollInterval)) {
		t.Errorf("second dump at %v", second.At)
	}
	testAwaitTimers(t, clock, 1)
	clock.Advance(settings.PollInterval)
	testNextDump(t, dumps)
}

// A live ask dumps at once once DumpMinInterval since the last dump has passed, and its channel closes when that dump
// ends; the interval's schedule starts again from it.
func TestListenersPollerAskDumpsAtOnce(t *testing.T) {
	discoverer := newTestListenersDiscoverer()
	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1)}, nil)
	poller, clock, dumps, settings := newTestListenersPoller(t, discoverer)
	testNextDump(t, dumps)
	testAwaitTimers(t, clock, 1)
	clock.Advance(5 * time.Second)

	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1), testListenersSocket(8000, 2)}, nil)
	answered := poller.Ask()
	asked := testNextDump(t, dumps)
	<-answered
	if len(asked.Sockets) != 2 || !asked.At.Equal(sidecartest.DefaultClockStart().Add(5*time.Second)) {
		t.Fatalf("asked dump %+v", asked)
	}
	if last := poller.Last(); last != asked {
		t.Errorf("last %v", last)
	}

	// a second ask within DumpMinInterval waits for it, then dumps
	answered = poller.Ask()
	testAwaitTimers(t, clock, 1)
	testNoDump(t, dumps)
	clock.Advance(settings.DumpMinInterval)
	testNextDump(t, dumps)
	<-answered
}

// A destruction notice dumps at once, so a closed socket leaves the list before the next poll.
func TestListenersPollerDestructionNoticeDumpsAtOnce(t *testing.T) {
	discoverer := newTestListenersDiscoverer()
	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1), testListenersSocket(8000, 2)}, nil)
	_, clock, dumps, settings := newTestListenersPoller(t, discoverer)
	testNextDump(t, dumps)
	testAwaitTimers(t, clock, 1)
	clock.Advance(settings.DumpMinInterval)

	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1)}, nil)
	discoverer.destroyed <- struct{}{}
	dump := testNextDump(t, dumps)
	if len(dump.Sockets) != 1 || dump.Sockets[0].Port != 5432 {
		t.Errorf("after the notice %+v", dump.Sockets)
	}
	if !dump.At.Equal(sidecartest.DefaultClockStart().Add(settings.DumpMinInterval)) {
		t.Errorf("the notice's dump at %v", dump.At)
	}
}

// A dump cut by an error changes nothing: no dump is handed on, the last stays, the failure is counted; the next
// good dump goes on.
func TestListenersPollerKeepsTheLastDumpOnError(t *testing.T) {
	discoverer := newTestListenersDiscoverer()
	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1)}, nil)
	poller, clock, dumps, settings := newTestListenersPoller(t, discoverer)
	first := testNextDump(t, dumps)
	testAwaitTimers(t, clock, 1)

	discoverer.set(nil, errors.New("a short read"))
	clock.Advance(settings.PollInterval)
	// the failed dump has run once the poller waits again
	testAwaitTimers(t, clock, 1)
	if _, dumpCount := discoverer.record(); dumpCount != 2 {
		t.Fatalf("%d dumps", dumpCount)
	}
	testNoDump(t, dumps)
	if last := poller.Last(); last != first || len(last.Sockets) != 1 {
		t.Errorf("the last dump moved: %+v", last)
	}
	if failedDumps, _ := poller.FailureCounts(); failedDumps != 1 {
		t.Errorf("%d failed dumps", failedDumps)
	}

	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1), testListenersSocket(8000, 2)}, nil)
	clock.Advance(settings.PollInterval)
	if dump := testNextDump(t, dumps); len(dump.Sockets) != 2 {
		t.Errorf("after the error %+v", dump.Sockets)
	}
}

// Owners are looked up only for a socket new since the last dump; a cached one carries its owner without a lookup; the
// cache is trimmed when a socket goes, so its identity coming back is looked up again.
func TestListenersPollerLooksUpOwnersOfNewSocketsOnly(t *testing.T) {
	discoverer := newTestListenersDiscoverer()
	discoverer.owners[1] = "postgres"
	discoverer.owners[2] = "node"
	discoverer.owners[3] = "redis-server"
	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1), testListenersSocket(3000, 2)}, nil)
	poller, clock, dumps, settings := newTestListenersPoller(t, discoverer)
	first := testNextDump(t, dumps)
	for _, socket := range first.Sockets {
		if socket.Owner != sidecar.ListenersOwnerProgram || socket.Program == "" {
			t.Errorf("first dump's socket %+v", *socket)
		}
	}
	next := func() *sidecar.ListenersDump {
		testAwaitTimers(t, clock, 1)
		clock.Advance(settings.PollInterval)
		return testNextDump(t, dumps)
	}

	second := next()
	if second.Sockets[0].Program != "node" || second.Sockets[1].Program != "postgres" {
		t.Errorf("cached owners %+v %+v", *second.Sockets[0], *second.Sockets[1])
	}

	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(3000, 2), testListenersSocket(6379, 3)}, nil)
	third := next()
	if third.Sockets[1].Program != "redis-server" {
		t.Errorf("new socket %+v", *third.Sockets[1])
	}
	if poller.OwnerCachedForTest(1) || !poller.OwnerCachedForTest(2) || !poller.OwnerCachedForTest(3) {
		t.Error("the cache is not the live set")
	}

	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1), testListenersSocket(3000, 2), testListenersSocket(6379, 3)}, nil)
	next()
	asked, _ := discoverer.record()
	if want := [][]uint64{{1, 2}, {3}, {1}}; !slices.EqualFunc(asked, want, slices.Equal) {
		t.Errorf("owners asked %v, want %v", asked, want)
	}
}

// A socket the lookups leave unknown is asked for again at the next dump, never cached as unknown.
func TestListenersPollerAsksAgainForAnUnknownOwner(t *testing.T) {
	discoverer := newTestListenersDiscoverer()
	discoverer.set([]*sidecar.ListenersSocket{testListenersSocket(5432, 1)}, nil)
	poller, clock, dumps, settings := newTestListenersPoller(t, discoverer)
	if dump := testNextDump(t, dumps); dump.Sockets[0].Owner != sidecar.ListenersOwnerUnknown {
		t.Fatalf("named %+v", *dump.Sockets[0])
	}
	testAwaitTimers(t, clock, 1)
	discoverer.stateLock.Lock()
	discoverer.owners[1] = "postgres"
	discoverer.stateLock.Unlock()
	clock.Advance(settings.PollInterval)
	if dump := testNextDump(t, dumps); dump.Sockets[0].Program != "postgres" {
		t.Errorf("not asked again: %+v", *dump.Sockets[0])
	}
	if !poller.OwnerCachedForTest(1) {
		t.Error("not cached once named")
	}
}

// Close ends the poll, closes the discoverer and ends a waiting ask.
func TestListenersPollerClose(t *testing.T) {
	discoverer := newTestListenersDiscoverer()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	poller, err := sidecar.NewListenersPoller(context.Background(), &sidecar.ListenersPollerArgs{Discoverer: discoverer, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	testAwaitTimers(t, clock, 1)
	answered := poller.Ask()
	poller.Close()
	<-answered
	discoverer.stateLock.Lock()
	defer discoverer.stateLock.Unlock()
	if !discoverer.closed {
		t.Error("the discoverer is open")
	}
	if _, err := sidecar.NewListenersPoller(context.Background(), &sidecar.ListenersPollerArgs{}); !errors.Is(err, sidecar.ErrListenersNoDiscovery) {
		t.Errorf("a poller with no discoverer: %v", err)
	}
}
