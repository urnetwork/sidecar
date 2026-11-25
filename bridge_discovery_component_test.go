//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// §17.7.1's watches between two components (owner decision 778), §22.5's §17 row from M6, on fake dispatchers and a
// fake clock: a watch held until a change and answered within a round trip; a viewer keeping only what its host serves
// by the config and its router sends there, dropping the rest; a host lost after HostLossTimeout and a narrowing
// compile each withdrawing at once; a host serving nothing asked again after NotServingRetryInterval; and nothing a
// watch brought republished, so two hosts that watch each other publish no loop.

package sidecar

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A clock the test moves, firing each wait it reaches.
type discoveryTestClock struct {
	stateLock sync.Mutex
	now       time.Time
	waits     []discoveryTestWait
	// counts the waits armed, which a test reads to know a goroutine is parked
	armed *MonitorValue[int]
}

type discoveryTestWait struct {
	at   time.Time
	fire chan time.Time
}

func newDiscoveryTestClock() *discoveryTestClock {
	return &discoveryTestClock{now: discoveryTestNow, armed: NewMonitorValue(0)}
}

func (self *discoveryTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *discoveryTestClock) After(timeout time.Duration) <-chan time.Time {
	fire := make(chan time.Time, 1)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if timeout <= 0 {
			fire <- self.now
			return
		}
		self.waits = append(self.waits, discoveryTestWait{at: self.now.Add(timeout), fire: fire})
	}()
	self.armed.Update(func(count int) int { return count + 1 })
	return fire
}

func (self *discoveryTestClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	fire := self.After(timeout)
	stopped := make(chan struct{})
	go func() {
		select {
		case <-fire:
			function()
		case <-stopped:
		}
	}()
	once := sync.Once{}
	return func() bool {
		result := false
		once.Do(func() { close(stopped); result = true })
		return result
	}
}

// Waits until some goroutine waits for the clock to reach at, failing after a minute.
func (self *discoveryTestClock) awaitWaitAt(t *testing.T, at time.Time) {
	t.Helper()
	timeout := time.After(time.Minute)
	for {
		_, armed := self.armed.Get()
		found := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return slices.ContainsFunc(self.waits, func(wait discoveryTestWait) bool { return wait.at.Equal(at) })
		}()
		if found {
			return
		}
		select {
		case <-armed:
		case <-timeout:
			t.Fatalf("no wait for %v", at)
		}
	}
}

// Moves the clock by and fires every wait it reaches.
func (self *discoveryTestClock) Advance(by time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(by)
	kept := self.waits[:0]
	for _, wait := range self.waits {
		if wait.at.After(self.now) {
			kept = append(kept, wait)
			continue
		}
		wait.fire <- self.now
	}
	self.waits = kept
}

// A network of fake dispatchers: each node's watch handler, reached by its client id.
type discoveryTestNet struct {
	stateLock sync.Mutex
	nodes     map[Id]*discoveryTestDispatcher
	// client ids whose calls fail
	down map[Id]bool
	// counts calls, which a test waits on
	calls *MonitorValue[int]
}

func newDiscoveryTestNet() *discoveryTestNet {
	return &discoveryTestNet{nodes: map[Id]*discoveryTestDispatcher{}, down: map[Id]bool{}, calls: NewMonitorValue(0)}
}

// One node's dispatcher.
type discoveryTestDispatcher struct {
	net       *discoveryTestNet
	sidecarId Id
	clientId  Id
	stateLock sync.Mutex
	handler   SubprotocolHandler
}

func (self *discoveryTestNet) dispatcher(sidecarId Id, clientId Id) *discoveryTestDispatcher {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dispatcher := &discoveryTestDispatcher{net: self, sidecarId: sidecarId, clientId: clientId}
	self.nodes[clientId] = dispatcher
	return dispatcher
}

func (self *discoveryTestNet) setDown(clientId Id, down bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.down[clientId] = down
}

func (self *discoveryTestDispatcher) Handle(messageType protocol.MessageType, handler SubprotocolHandler, options *HandleOptions) (func(), error) {
	if messageType != protocol.MessageType_DNS_SD_WATCH {
		return nil, errors.New("unexpected type")
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.handler = handler
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.handler = nil
	}, nil
}

func (self *discoveryTestDispatcher) EnsureHello(ctx context.Context, clientId Id) error {
	self.net.stateLock.Lock()
	defer self.net.stateLock.Unlock()
	if self.net.down[clientId] || self.net.nodes[clientId] == nil {
		return errors.New("unreachable")
	}
	return nil
}

func (self *discoveryTestDispatcher) PeerIdentity(clientId Id) (*SubprotocolPeerIdentity, bool) {
	self.net.stateLock.Lock()
	defer self.net.stateLock.Unlock()
	node := self.net.nodes[clientId]
	if node == nil {
		return nil, false
	}
	return &SubprotocolPeerIdentity{SidecarId: node.sidecarId}, true
}

func (self *discoveryTestDispatcher) Call(ctx context.Context, clientId Id, messageType protocol.MessageType, body []byte, options *CallOptions) ([]byte, error) {
	self.net.calls.Update(func(count int) int { return count + 1 })
	target := func() SubprotocolHandler {
		self.net.stateLock.Lock()
		defer self.net.stateLock.Unlock()
		node := self.net.nodes[clientId]
		if self.net.down[clientId] || node == nil {
			return nil
		}
		node.stateLock.Lock()
		defer node.stateLock.Unlock()
		return node.handler
	}()
	if target == nil {
		return nil, errors.New("unreachable")
	}
	return target(ctx, &SubprotocolRequest{
		SourceId:    self.clientId,
		Peer:        &SubprotocolPeerIdentity{SidecarId: self.sidecarId},
		MessageType: messageType,
		Body:        body,
	})
}

// A gatherer that reports what the test sets.
type discoveryTestGatherer struct {
	stateLock sync.Mutex
	gathered  []*BridgeDiscoveryGathered
	reports   []func(gathered []*BridgeDiscoveryGathered)
	running   *MonitorValue[int]
}

func newDiscoveryTestGatherer(gathered ...*BridgeDiscoveryGathered) *discoveryTestGatherer {
	return &discoveryTestGatherer{gathered: gathered, running: NewMonitorValue(0)}
}

func (self *discoveryTestGatherer) Gather(ctx context.Context, types []string, report func(gathered []*BridgeDiscoveryGathered)) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.reports = append(self.reports, report)
		report(self.gathered)
	}()
	self.running.Update(func(count int) int { return count + 1 })
	<-ctx.Done()
	self.running.Update(func(count int) int { return count - 1 })
}

// Sets what the gatherer holds and reports it to each run.
func (self *discoveryTestGatherer) set(gathered ...*BridgeDiscoveryGathered) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.gathered = gathered
	for _, report := range self.reports {
		report(gathered)
	}
}

// Waits until value's monitor satisfies done, failing after a minute.
func discoveryTestAwait[T comparable](t *testing.T, value *MonitorValue[T], done func(value T) bool) {
	t.Helper()
	timeout := time.After(time.Minute)
	for {
		current, changed := value.Get()
		if done(current) {
			return
		}
		select {
		case <-changed:
		case <-timeout:
			t.Fatalf("waited a minute; holds %v", current)
		}
	}
}

// A two-host world: host A, whose LAN holds a shared printer and whose own files service it publishes, and viewer B,
// which watches A. The hook lets B reach what reach says.
type discoveryTestWorld struct {
	t        *testing.T
	clock    *discoveryTestClock
	net      *discoveryTestNet
	gatherer *discoveryTestGatherer
	host     *BridgeDiscoveryComponent
	viewer   *BridgeDiscoveryComponent
	hostId   Id
	viewerId Id
	// what B's resolver holds, at each OnView
	view *MonitorValue[string]

	stateLock sync.Mutex
	// whether B's routes still reach A, and whether B's router sends 192.168.50.0/24 to A
	reachesHost  bool
	routesSubnet bool
	reach        func(viewer Id, address netip.AddrPort, transport string) bool
}

// The view as a sorted string of "<name>@<address>:<port>".
func discoveryTestViewString(view []*BridgeDiscoveryViewInstance) string {
	names := []string{}
	for _, instance := range view {
		names = append(names, instance.Name+"@"+netip.AddrPortFrom(instance.Address, instance.Port).String())
	}
	slices.Sort(names)
	return "[" + joinStrings(names, " ") + "]"
}

// The strings joined by separator.
func joinStrings(parts []string, separator string) string {
	joined := ""
	for i, part := range parts {
		if 0 < i {
			joined += separator
		}
		joined += part
	}
	return joined
}

func newDiscoveryTestWorld(t *testing.T) *discoveryTestWorld {
	t.Helper()
	return newDiscoveryTestWorldOf(t, &discoveryTestWorldOptions{})
}

// What a world is built with beside its defaults.
type discoveryTestWorldOptions struct {
	// where both components log; nil for the default logger
	log Logger
	// what A's gatherer holds in place of its own files and the printer, and the host labels A shares in place of the
	// printer's; nil for the defaults
	gathered []*BridgeDiscoveryGathered
	shares   []string
	// hears each view B hands out, beside the world's own record of it; nil for none
	onView func(view []*BridgeDiscoveryViewInstance)
}

// A world as newDiscoveryTestWorld's, with options.
func newDiscoveryTestWorldOf(t *testing.T, options *discoveryTestWorldOptions) *discoveryTestWorld {
	t.Helper()
	world := &discoveryTestWorld{
		t:            t,
		clock:        newDiscoveryTestClock(),
		net:          newDiscoveryTestNet(),
		hostId:       Id{0xA1},
		viewerId:     Id{0xB1},
		view:         NewMonitorValue("[]"),
		reachesHost:  true,
		routesSubnet: true,
	}
	world.reach = func(viewer Id, address netip.AddrPort, transport string) bool { return viewer == world.viewerId }
	own := discoveryTestGathered("Host Files", "_smb._tcp", 445, "Host-A", "192.168.50.2")
	own.Own = true
	printer := discoveryTestGathered("Synthetic Printer", "_ipp._tcp", 631, "printer", "192.168.50.20")
	world.gatherer = newDiscoveryTestGatherer(own, printer)
	if options.gathered != nil {
		world.gatherer = newDiscoveryTestGatherer(options.gathered...)
	}
	shares := []string{"printer"}
	if options.shares != nil {
		shares = options.shares
	}
	hostRoutes := discoveryTestRoutes()
	var err error
	world.host, err = NewBridgeDiscoveryComponent(&BridgeDiscoveryArgs{
		SidecarId: world.hostId,
		Routes:    func() *BridgeDiscoveryRoutes { return hostRoutes },
		Reach: func(viewer Id, address netip.AddrPort, transport string) bool {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			return world.reach(viewer, address, transport)
		},
		HostLabel: func() string { return "host-a" },
		Gatherer:  world.gatherer,
		Clock:     world.clock,
		Log:       options.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.host.Close)
	world.host.loadState(newDiscoveryTestStore())
	if err := world.host.commitState(func(state *bridgeDiscoveryState) {
		state.Shares = nil
		for _, label := range shares {
			state.Shares = append(state.Shares, &bridgeDiscoveryShare{HostLabel: label, State: bridgeDiscoveryShareActive})
		}
	}); err != nil {
		t.Fatal(err)
	}
	viewerRoutes := func() *BridgeDiscoveryRoutes {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		routes := &BridgeDiscoveryRoutes{Blocks: []netip.Prefix{netip.MustParsePrefix("100.80.0.0/16")}, Addresses: []netip.Addr{netip.MustParseAddr("100.80.1.3")}}
		if world.reachesHost {
			routes.Hosts = []BridgeDiscoveryHost{{
				SidecarId: world.hostId,
				ClientId:  Id{0xA2},
				Prefixes:  []netip.Prefix{netip.MustParsePrefix("100.80.1.2/32"), netip.MustParsePrefix("192.168.50.0/24")},
				Name:      "host-a",
			}}
		}
		return routes
	}
	// the viewer calls again at once after each answer here, so a test's clock moves only for what it times
	viewerSettings := DefaultBridgeDiscoverySettings()
	viewerSettings.WatchMinInterval = 0
	world.viewer, err = NewBridgeDiscoveryComponent(&BridgeDiscoveryArgs{
		SidecarId: world.viewerId,
		Routes:    viewerRoutes,
		Settings:  viewerSettings,
		RouteTargets: func(address netip.Addr) []Id {
			world.stateLock.Lock()
			defer world.stateLock.Unlock()
			if address == netip.MustParseAddr("100.80.1.2") || (world.routesSubnet && netip.MustParsePrefix("192.168.50.0/24").Contains(address)) {
				return []Id{world.hostId}
			}
			return nil
		},
		Viewing: func() bool { return true },
		OnView: func(view []*BridgeDiscoveryViewInstance) {
			world.view.Set(discoveryTestViewString(view))
			if options.onView != nil {
				options.onView(view)
			}
		},
		Clock: world.clock,
		Log:   options.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.viewer.Close)
	world.viewer.loadState(newDiscoveryTestStore())
	return world
}

// Attaches both components on their dispatchers until the test ends.
func (self *discoveryTestWorld) attach() {
	ctx, cancel := context.WithCancel(context.Background())
	self.t.Cleanup(cancel)
	if err := self.host.attach(ctx, self.net.dispatcher(self.hostId, Id{0xA2})); err != nil {
		self.t.Fatal(err)
	}
	if err := self.viewer.attach(ctx, self.net.dispatcher(self.viewerId, Id{0xB2})); err != nil {
		self.t.Fatal(err)
	}
}

// Waits until B's view reads want.
func (self *discoveryTestWorld) awaitView(want string) {
	self.t.Helper()
	discoveryTestAwait(self.t, self.view, func(view string) bool { return view == want })
}

// The view B keeps once both are attached: A's own files at its overlay address and the shared printer at its LAN
// address, which A serves; a change at A reaches B within a round trip of the held watch.
func TestBridgeDiscoveryWatchCarriesAHostsViewAndItsChanges(t *testing.T) {
	world := newDiscoveryTestWorld(t)
	world.attach()
	world.awaitView("[Host Files@100.80.1.2:445 Synthetic Printer@192.168.50.20:631]")
	// the printer leaves A's LAN: A's held watch answers, and B withdraws it
	own := discoveryTestGathered("Host Files", "_smb._tcp", 445, "Host-A", "192.168.50.2")
	own.Own = true
	world.gatherer.set(own)
	world.awaitView("[Host Files@100.80.1.2:445]")
	// B never publishes what it watched: its host view serves nothing, so nothing loops back
	if view := world.viewer.hostView.Value(); 0 < len(view.published) {
		t.Fatalf("the viewer publishes %d instances", len(view.published))
	}
}

// B keeps an instance only at an address A serves by the config and its own router sends to A: once its router
// sends the subnet elsewhere, a LAN prefix of its own winning, the printer leaves its view, counted.
func TestBridgeDiscoveryViewerKeepsOnlyWhatItsHostServes(t *testing.T) {
	world := newDiscoveryTestWorld(t)
	world.attach()
	world.awaitView("[Host Files@100.80.1.2:445 Synthetic Printer@192.168.50.20:631]")
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.routesSubnet = false
	}()
	world.viewer.ViewingChanged()
	world.awaitView("[Host Files@100.80.1.2:445]")
	if devices := world.viewer.Devices(); len(devices.Remote) != 1 || devices.Remote[0].DroppedCount != 1 {
		t.Fatalf("the viewer's listing: %+v", devices.Remote)
	}
}

// A's hook decides who sees what: a viewer it lets reach nothing gets nothing; then a compile whose rows no longer
// reach A withdraws everything at once.
func TestBridgeDiscoveryHookAndCompileWithdraw(t *testing.T) {
	world := newDiscoveryTestWorld(t)
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		// only the overlay address's services
		world.reach = func(viewer Id, address netip.AddrPort, transport string) bool {
			return viewer == world.viewerId && address.Addr() == netip.MustParseAddr("100.80.1.2")
		}
	}()
	world.attach()
	world.awaitView("[Host Files@100.80.1.2:445]")
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.reachesHost = false
	}()
	world.viewer.ViewingChanged()
	world.awaitView("[]")
}

// A host whose watch fails keeps its instances until HostLossTimeout after its last answer, then loses them at once.
func TestBridgeDiscoveryHostLostAfterItsTimeout(t *testing.T) {
	world := newDiscoveryTestWorld(t)
	// records that outlive the test, so only the loss withdraws them
	own := discoveryTestGathered("Host Files", "_smb._tcp", 445, "Host-A", "192.168.50.2")
	own.Own = true
	own.Expires = discoveryTestNow.Add(24 * time.Hour)
	world.gatherer.set(own)
	world.attach()
	world.awaitView("[Host Files@100.80.1.2:445]")
	settings := DefaultBridgeDiscoverySettings()
	start := world.clock.Now()
	// the viewer's call is held at the host until its hold ends, and answers then; every call after fails
	world.clock.awaitWaitAt(t, start.Add(settings.Wire.WatchHoldTimeout))
	world.net.setDown(Id{0xA2}, true)
	world.clock.Advance(settings.Wire.WatchHoldTimeout)
	lastAnswer := world.clock.Now()
	retry := settings.WatchRetryInterval
	for world.clock.Now().Sub(lastAnswer) < settings.HostLossTimeout {
		if view := world.view.Value(); view == "[]" {
			t.Fatalf("lost %v after the last answer, under HostLossTimeout", world.clock.Now().Sub(lastAnswer))
		}
		world.clock.awaitWaitAt(t, world.clock.Now().Add(retry))
		world.clock.Advance(retry)
		retry = min(2*retry, settings.WatchRetryMaxInterval)
	}
	world.awaitView("[]")
}

// A host that serves nothing answers serving false at once and is asked again only after NotServingRetryInterval.
func TestBridgeDiscoveryNotServingIsAskedAgainLater(t *testing.T) {
	world := newDiscoveryTestWorld(t)
	// records that outlive the hour, as a LAN's are kept fresh by its responder
	own := discoveryTestGathered("Host Files", "_smb._tcp", 445, "Host-A", "192.168.50.2")
	own.Own = true
	own.Expires = discoveryTestNow.Add(3 * time.Hour)
	world.gatherer.set(own)
	if err := world.host.Set(DaemonBridgeDiscoveryOwn, DaemonBridgeDiscoveryOff, false); err != nil {
		t.Fatal(err)
	}
	if err := world.host.commitState(func(state *bridgeDiscoveryState) { state.Shares = nil }); err != nil {
		t.Fatal(err)
	}
	world.attach()
	// the viewer, told the host serves nothing, waits NotServingRetryInterval
	world.clock.awaitWaitAt(t, world.clock.Now().Add(DefaultBridgeDiscoverySettings().NotServingRetryInterval))
	calls := world.net.calls.Value()
	world.clock.Advance(DefaultBridgeDiscoverySettings().NotServingRetryInterval / 2)
	if world.net.calls.Value() != calls {
		t.Fatalf("asked again before NotServingRetryInterval")
	}
	if err := world.host.Set(DaemonBridgeDiscoveryOwn, DaemonBridgeDiscoveryOn, false); err != nil {
		t.Fatal(err)
	}
	world.clock.Advance(DefaultBridgeDiscoverySettings().NotServingRetryInterval / 2)
	world.awaitView("[Host Files@100.80.1.2:445]")
}

// A watch from a viewer the host's dispatcher could not name is refused, and a malformed body too.
func TestBridgeDiscoveryWatchRefusesWhatItCannotRead(t *testing.T) {
	world := newDiscoveryTestWorld(t)
	if _, err := world.host.handleWatch(context.Background(), &SubprotocolRequest{Body: []byte{}}); err == nil {
		t.Errorf("a watch with no peer was answered")
	}
	if _, err := world.host.handleWatch(context.Background(), &SubprotocolRequest{Peer: &SubprotocolPeerIdentity{SidecarId: world.viewerId}, Body: []byte{0xFF}}); err == nil {
		t.Errorf("a malformed watch was answered")
	}
}

// A sealed store in memory.
func newDiscoveryTestStore() SidecarStore {
	return newTestDnsMemoryStore()
}
