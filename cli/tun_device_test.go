// ur tun's loops (tun_device.go) and the daemon's bridges (bridge_wire.go) on fakes, T1: the device behind
// urTunInterface, the platform behind urTunSystem, the network's device.Bridge behind urTunBridge and the host behind
// urTunLinks. A burst routes through the bridge, the default route dropped and counted and a building link's refusal
// counted; a reply is copied behind the device's headroom; a sync sets the device to the bridge's addresses, routes and
// zones, and follows each change; the local addresses reach the bridge without the bridge's own resolvers and only when
// they change; close removes everything on each path; the default route rides the tun under exits and leaves it off
// exits, a platform's refusal holding the exits with its reason and the tun up; and the daemon refuses a platform with
// no tun, a network with no bridge, a second network and an app's held block. Every wait is on a channel, bounded by
// urTestTimeout.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a fake read hands over.
type testTunRead struct {
	packets [][]byte
	err     error
}

// A device and its configuration, recording each call and announcing it on events.
type testTunInterface struct {
	batchSize int
	reads     chan testTunRead
	closed    chan struct{}
	closeOnce sync.Once
	events    chan string

	stateLock     sync.Mutex
	writes        [][]byte
	writeOffsets  []int
	addresses     []netip.Addr
	addressSets   int
	routes        []netip.Prefix
	routeSets     int
	resolver      netip.Addr
	zones         []string
	resolverSets  int
	conflictCount int
	closeCount    int
	// whether the default route rides the device, and each SetExits asked
	exits     bool
	exitsSets []bool
	// what SetAddresses answers, nil for success
	addressErr error
	// what SetExits answers under exits, and off them; nil puts the route on, or takes it off
	exitsErr      error
	exitsClearErr error
}

var _ urTunInterface = (*testTunInterface)(nil)

func newTestTunInterface() *testTunInterface {
	return &testTunInterface{
		batchSize: 8,
		reads:     make(chan testTunRead),
		closed:    make(chan struct{}),
		events:    make(chan string, 1024),
	}
}

func (self *testTunInterface) announce(event string) {
	select {
	case self.events <- event:
	default:
	}
}

func (self *testTunInterface) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case read := <-self.reads:
		for i, packet := range read.packets {
			copy(bufs[i][offset:], packet)
			sizes[i] = len(packet)
		}
		return len(read.packets), read.err
	case <-self.closed:
		return 0, os.ErrClosed
	}
}

func (self *testTunInterface) Write(bufs [][]byte, offset int) (int, error) {
	self.stateLock.Lock()
	for _, buf := range bufs {
		self.writes = append(self.writes, bytes.Clone(buf[offset:]))
		self.writeOffsets = append(self.writeOffsets, offset)
	}
	self.stateLock.Unlock()
	self.announce("write")
	return len(bufs), nil
}

func (self *testTunInterface) BatchSize() int {
	return self.batchSize
}

func (self *testTunInterface) SetAddresses(addresses []netip.Addr) error {
	self.stateLock.Lock()
	addressErr := self.addressErr
	if addressErr == nil {
		self.addresses = slices.Clone(addresses)
	}
	self.addressSets += 1
	self.stateLock.Unlock()
	self.announce("addresses")
	return addressErr
}

func (self *testTunInterface) SetRoutes(routes []netip.Prefix) (int, error) {
	self.stateLock.Lock()
	self.routes = slices.Clone(routes)
	self.routeSets += 1
	conflictCount := self.conflictCount
	self.stateLock.Unlock()
	self.announce("routes")
	return conflictCount, nil
}

func (self *testTunInterface) SetResolver(resolver netip.Addr, zones []string) (string, error) {
	self.stateLock.Lock()
	self.resolver = resolver
	self.zones = slices.Clone(zones)
	self.resolverSets += 1
	self.stateLock.Unlock()
	self.announce("resolver")
	return "", nil
}

func (self *testTunInterface) SetExits(exits bool) (bool, error) {
	self.stateLock.Lock()
	self.exitsSets = append(self.exitsSets, exits)
	var err error
	switch {
	case exits && self.exitsErr != nil:
		// a refusal leaves nothing on
		self.exits = false
		err = self.exitsErr
	case exits:
		self.exits = true
	case self.exitsClearErr != nil:
		err = self.exitsClearErr
	default:
		self.exits = false
	}
	defaultRoute := self.exits
	self.stateLock.Unlock()
	self.announce("exits")
	return defaultRoute, err
}

func (self *testTunInterface) Close() error {
	self.closeOnce.Do(func() {
		self.stateLock.Lock()
		self.closeCount += 1
		self.exits = false
		self.routes = nil
		self.addresses = nil
		self.resolver = netip.Addr{}
		self.zones = nil
		self.stateLock.Unlock()
		close(self.closed)
	})
	self.announce("close")
	return nil
}

// A platform over one fake device.
type testTunSystem struct {
	iface   *testTunInterface
	openErr error
	holder  string

	stateLock sync.Mutex
	opened    []string
	local     []netip.Addr
	excludes  [][]netip.Addr
	// the watch's changed, once WatchLocal runs
	changed chan func()
}

var _ urTunSystem = (*testTunSystem)(nil)

func newTestTunSystem() *testTunSystem {
	return &testTunSystem{iface: newTestTunInterface(), changed: make(chan func(), 1)}
}

func (self *testTunSystem) Open(name string, mtu int) (urTunInterface, error) {
	self.stateLock.Lock()
	self.opened = append(self.opened, name)
	self.stateLock.Unlock()
	if self.openErr != nil {
		return nil, self.openErr
	}
	return self.iface, nil
}

func (self *testTunSystem) RoutedElsewhere(name string, prefix netip.Prefix) (string, error) {
	return self.holder, nil
}

func (self *testTunSystem) LocalAddresses(name string, exclude []netip.Addr) ([]netip.Addr, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.excludes = append(self.excludes, slices.Clone(exclude))
	return slices.Clone(self.local), nil
}

func (self *testTunSystem) WatchLocal(ctx context.Context, changed func()) error {
	select {
	case self.changed <- changed:
	default:
	}
	<-ctx.Done()
	return nil
}

func (self *testTunSystem) setLocal(local []netip.Addr) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.local = local
}

// A network's bridge whose router is a function, recording what it is fed.
type testTunBridge struct {
	events chan string

	stateLock      sync.Mutex
	routes         []netip.Prefix
	status         device.BridgeStatus
	zones          []string
	route          func(packet []byte) connect.UserNatClient
	localSets      [][]netip.Addr
	receive        connect.ReceivePacketFunction
	callbacks      map[int]func()
	nextCallbackId int
}

var _ urTunBridge = (*testTunBridge)(nil)

func newTestTunBridge() *testTunBridge {
	return &testTunBridge{
		events:    make(chan string, 1024),
		callbacks: map[int]func(){},
		status: device.BridgeStatus{
			State:      device.PostureEnforcingDocument,
			Block:      netip.MustParsePrefix("100.70.0.0/16"),
			Addresses:  []netip.Addr{netip.MustParseAddr("100.70.9.9")},
			EgressMode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO,
		},
		routes: []netip.Prefix{netip.MustParsePrefix("100.70.0.53/32"), netip.MustParsePrefix("100.70.1.2/32")},
		zones:  []string{"net.example"},
		route:  func(packet []byte) connect.UserNatClient { return nil },
	}
}

func (self *testTunBridge) RouteBurst(packets [][]byte, send func(client connect.UserNatClient, packets [][]byte)) {
	self.stateLock.Lock()
	route := self.route
	self.stateLock.Unlock()
	for i := range packets {
		send(route(packets[i]), packets[i:i+1])
	}
}

func (self *testTunBridge) Routes() []netip.Prefix {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.routes)
}

func (self *testTunBridge) SetLocalAddresses(addresses []netip.Addr) {
	self.stateLock.Lock()
	self.localSets = append(self.localSets, slices.Clone(addresses))
	self.stateLock.Unlock()
	select {
	case self.events <- "local":
	default:
	}
}

func (self *testTunBridge) SetReceivePacket(receive connect.ReceivePacketFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.receive = receive
}

func (self *testTunBridge) AddChangeCallback(callback func()) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	callbackId := self.nextCallbackId
	self.nextCallbackId += 1
	self.callbacks[callbackId] = callback
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.callbacks, callbackId)
	}
}

func (self *testTunBridge) Status() device.BridgeStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.status
}

func (self *testTunBridge) Decision() device.PostureDecision {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return device.PostureDecision{State: self.status.State, BridgeState: &bridge.BridgeState{NameZones: slices.Clone(self.zones)}}
}

// Calls every change callback, as an adoption does.
func (self *testTunBridge) changed() {
	self.stateLock.Lock()
	callbacks := []func(){}
	for _, callback := range self.callbacks {
		callbacks = append(callbacks, callback)
	}
	self.stateLock.Unlock()
	for _, callback := range callbacks {
		callback()
	}
}

func (self *testTunBridge) callbackCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.callbacks)
}

func (self *testTunBridge) lastLocal() ([][]netip.Addr, connect.ReceivePacketFunction) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.localSets), self.receive
}

// The host's half: where the links' replies go.
type testTunLinks struct {
	source connect.TransferPath

	stateLock sync.Mutex
	receive   func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte)
}

var _ urTunLinks = (*testTunLinks)(nil)

func (self *testTunLinks) setReceive(receive func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.receive = receive
}

func (self *testTunLinks) sourcePath() connect.TransferPath {
	return self.source
}

func (self *testTunLinks) current() func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.receive
}

// A link that takes each packet it is sent, or refuses each while it builds.
type testTunLink struct {
	refuse bool

	stateLock sync.Mutex
	packets   [][]byte
	sources   []connect.TransferPath
}

var _ connect.UserNatClient = (*testTunLink)(nil)

func (self *testTunLink) SendPacket(source connect.TransferPath, provideMode protocol.ProvideMode, packet []byte, timeout time.Duration) bool {
	if self.refuse {
		return false
	}
	self.stateLock.Lock()
	self.packets = append(self.packets, bytes.Clone(packet))
	self.sources = append(self.sources, source)
	self.stateLock.Unlock()
	connect.MessagePoolReturn(packet)
	return true
}

func (self *testTunLink) Close() {}

func (self *testTunLink) Shuffle() {}

func (self *testTunLink) SecurityPolicyStats(reset bool) connect.SecurityPolicyStats {
	return connect.SecurityPolicyStats{}
}

func (self *testTunLink) SetLocalSecurityBypass(localSecurityBypass bool) {}

func (self *testTunLink) taken() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.packets)
}

// Settings whose coalescing waits are short and whose poll never fires within a test.
func testUrTunSettings() *urTunSettings {
	settings := defaultUrTunSettings()
	settings.SyncDelay = time.Millisecond
	settings.LocalDelay = time.Millisecond
	settings.LocalPollInterval = time.Hour
	settings.SyncRetryInterval = time.Hour
	return settings
}

// Waits on events until done holds, each event a chance for it, bounded by urTestTimeout.
func waitTunEvents(t *testing.T, events chan string, what string, done func() bool) {
	t.Helper()
	deadline := time.After(urTestTimeout)
	for !done() {
		select {
		case <-events:
		case <-deadline:
			t.Fatalf("waited too long for %s", what)
		}
	}
}

// An IPv4 packet of protocol from source to destination with payload, its header's length and addresses set.
func testTunPacket(source string, destination string, protocol byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	packet[2] = byte(len(packet) >> 8)
	packet[3] = byte(len(packet))
	packet[8] = 64
	packet[9] = protocol
	sourceOctets := netip.MustParseAddr(source).As4()
	destinationOctets := netip.MustParseAddr(destination).As4()
	copy(packet[12:16], sourceOctets[:])
	copy(packet[16:20], destinationOctets[:])
	copy(packet[20:], payload)
	return packet
}

// A started tun over fresh fakes, closed at the test's end.
func startTestUrTun(t *testing.T) (*urTun, *testTunSystem, *testTunBridge, *testTunLinks, chan error) {
	t.Helper()
	system := newTestTunSystem()
	system.local = []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.1")}
	tunBridge := newTestTunBridge()
	links := &testTunLinks{source: connect.SourceId(connect.NewId())}
	reasons := make(chan error, 1)
	tun, err := startUrTun(context.Background(), &urTunArgs{
		Name:      "ur-test",
		NetworkId: sidecar.NewId(),
		System:    system,
		Bridge:    tunBridge,
		Links:     links,
		Settings:  testUrTunSettings(),
		OnClose: func(tun *urTun, reason error) {
			reasons <- reason
		},
		// each sync's end is an event, after the tun holds what it applied
		OnSync: func(err error) {
			system.iface.announce("synced")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tun.close)
	return tun, system, tunBridge, links, reasons
}

// A burst goes through the bridge: a link takes its run under the host's source, the default route's packets are
// dropped and counted, and a building link's refusal is counted, each packet with one owner.
func TestTunRoutesEachBurstThroughTheBridge(t *testing.T) {
	tun, system, tunBridge, links, _ := startTestUrTun(t)
	link := &testTunLink{}
	building := &testTunLink{refuse: true}
	toLink := testTunPacket("100.70.9.9", "100.70.1.2", 17, []byte("to the link"))
	toDefault := testTunPacket("100.70.9.9", "203.0.113.7", 17, []byte("to the default route"))
	toBuilding := testTunPacket("100.70.9.9", "100.70.1.3", 6, []byte("to a building link"))
	tunBridge.stateLock.Lock()
	tunBridge.route = func(packet []byte) connect.UserNatClient {
		switch netip.AddrFrom4([4]byte(packet[16:20])).String() {
		case "100.70.1.2":
			return link
		case "100.70.1.3":
			return building
		default:
			return nil
		}
	}
	tunBridge.stateLock.Unlock()
	system.iface.reads <- testTunRead{packets: [][]byte{toLink, toDefault, toBuilding, toLink}}
	// a second read follows only once the first batch has gone through the bridge
	system.iface.reads <- testTunRead{packets: [][]byte{toDefault}}
	system.iface.reads <- testTunRead{}
	taken := link.taken()
	if len(taken) != 2 || !bytes.Equal(taken[0], toLink) || !bytes.Equal(taken[1], toLink) {
		t.Fatalf("the link took %d packets", len(taken))
	}
	for _, source := range link.sources {
		if source != links.source {
			t.Fatal("a send named another source than the host's")
		}
	}
	status := tun.status()
	if status.ReadCount != 5 || status.SentCount != 2 || status.DefaultCount != 2 || status.RefusedCount != 1 {
		t.Fatalf("counts %+v", status)
	}
}

// A reply, a reject or a resolver's answer, is written at once behind the device's headroom, as a copy: the caller's
// buffer is its own again after the call.
func TestTunWritesRepliesBehindTheHeadroom(t *testing.T) {
	tun, system, tunBridge, links, _ := startTestUrTun(t)
	_, bridgeReceive := tunBridge.lastLocal()
	linkReceive := links.current()
	if bridgeReceive == nil || linkReceive == nil {
		t.Fatal("the tun took no replies")
	}
	reply := testTunPacket("100.70.1.2", "100.70.9.9", 17, []byte("a link's reply"))
	reject := testTunPacket("100.70.0.53", "100.70.9.9", 1, []byte("a reject"))
	written := bytes.Clone(reply)
	linkReceive(connect.TransferPath{}, protocol.ProvideMode_Network, nil, reply)
	clear(reply)
	bridgeReceive(connect.TransferPath{}, protocol.ProvideMode_Network, nil, reject)
	system.iface.stateLock.Lock()
	writes := slices.Clone(system.iface.writes)
	offsets := slices.Clone(system.iface.writeOffsets)
	system.iface.stateLock.Unlock()
	if len(writes) != 2 || !bytes.Equal(writes[0], written) || !bytes.Equal(writes[1], reject) {
		t.Fatalf("the device was written %d packets", len(writes))
	}
	for _, offset := range offsets {
		if offset != tun.settings.WriteHeadroomByteCount {
			t.Fatalf("a write left %d bytes of headroom", offset)
		}
	}
	if status := tun.status(); status.WrittenCount != 2 {
		t.Fatalf("written %d", status.WrittenCount)
	}
}

// A sync sets the device to the bridge's IPv4 addresses, its routes and its zones through <block>.0.53, and each change
// the bridge reports brings the next sync.
func TestTunSyncsAddressesRoutesAndNames(t *testing.T) {
	tun, system, tunBridge, _, _ := startTestUrTun(t)
	iface := system.iface
	iface.stateLock.Lock()
	addresses, routes, resolver, zones := iface.addresses, iface.routes, iface.resolver, iface.zones
	iface.stateLock.Unlock()
	if !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("100.70.9.9")}) {
		t.Fatalf("addresses %v", addresses)
	}
	if !slices.Equal(routes, tunBridge.Routes()) {
		t.Fatalf("routes %v", routes)
	}
	if resolver != netip.MustParseAddr("100.70.0.53") || !slices.Equal(zones, []string{"net.example"}) {
		t.Fatalf("resolver %v for %v", resolver, zones)
	}
	moved := []netip.Prefix{netip.MustParsePrefix("100.70.0.53/32"), netip.MustParsePrefix("10.20.0.0/16")}
	tunBridge.stateLock.Lock()
	tunBridge.routes = moved
	tunBridge.stateLock.Unlock()
	tunBridge.changed()
	waitTunEvents(t, iface.events, "the routes to follow", func() bool {
		return slices.Contains(tun.status().Routes, "10.20.0.0/16")
	})
	iface.stateLock.Lock()
	routes = slices.Clone(iface.routes)
	iface.stateLock.Unlock()
	if !slices.Equal(routes, moved) {
		t.Fatalf("routes %v", routes)
	}
	status := tun.status()
	if status.Resolver != "100.70.0.53" || len(status.Routes) != 2 || status.Block != "100.70.0.0/16" {
		t.Fatalf("status %+v", status)
	}
}

// The local addresses reach the bridge without the bridge's own resolvers, whose routes a carve would take, and again
// only when they change.
func TestTunFeedsLocalAddressesLeavingOutItsResolvers(t *testing.T) {
	_, system, tunBridge, _, _ := startTestUrTun(t)
	localSets, _ := tunBridge.lastLocal()
	want := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.1")}
	if len(localSets) != 1 || !slices.Equal(localSets[0], want) {
		t.Fatalf("local sets %v", localSets)
	}
	system.stateLock.Lock()
	excluded := slices.Clone(system.excludes)
	system.stateLock.Unlock()
	if len(excluded) == 0 || !slices.Contains(excluded[0], netip.MustParseAddr("100.70.0.53")) {
		t.Fatalf("excluded %v", excluded)
	}
	var changed func()
	select {
	case changed = <-system.changed:
	case <-time.After(urTestTimeout):
		t.Fatal("no watch")
	}
	// a resolver the platform lists is left out whatever the platform did with exclude
	system.setLocal(append(slices.Clone(want), netip.MustParseAddr("100.70.0.53"), netip.MustParseAddr("192.0.2.20")))
	changed()
	waitTunEvents(t, tunBridge.events, "the new local addresses", func() bool {
		localSets, _ := tunBridge.lastLocal()
		return len(localSets) == 2
	})
	localSets, _ = tunBridge.lastLocal()
	if !slices.Equal(localSets[1], []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20"),
		netip.MustParseAddr("198.51.100.1")}) {
		t.Fatalf("second set %v", localSets[1])
	}
}

// ur tun down's path: the device's configuration and the device go, the replies stop reaching it, the bridge's local
// addresses return to unknown, and the change callback goes.
func TestTunCloseRestoresEverything(t *testing.T) {
	tun, system, tunBridge, links, reasons := startTestUrTun(t)
	tun.close()
	select {
	case reason := <-reasons:
		if !errors.Is(reason, errUrTunClosed) {
			t.Fatalf("closed for %v", reason)
		}
	case <-time.After(urTestTimeout):
		t.Fatal("no close")
	}
	system.iface.stateLock.Lock()
	closeCount, routes := system.iface.closeCount, system.iface.routes
	system.iface.stateLock.Unlock()
	if closeCount != 1 || routes != nil {
		t.Fatalf("closed %d times, routes %v", closeCount, routes)
	}
	localSets, bridgeReceive := tunBridge.lastLocal()
	if bridgeReceive != nil || links.current() != nil {
		t.Fatal("replies still reach the device")
	}
	if last := localSets[len(localSets)-1]; last != nil {
		t.Fatalf("the local addresses stay %v", last)
	}
	if tunBridge.callbackCount() != 0 {
		t.Fatal("the change callback stays")
	}
	// a reply already on its way when the close ran writes nothing
	tun.write(connect.TransferPath{}, protocol.ProvideMode_Network, nil, testTunPacket("100.70.1.2", "100.70.9.9", 17, nil))
	system.iface.stateLock.Lock()
	defer system.iface.stateLock.Unlock()
	if len(system.iface.writes) != 0 {
		t.Fatal("a write after the close")
	}
}

// A device that fails under the tun ends it on that path too, with the device's error.
func TestTunClosesWhenTheDeviceFails(t *testing.T) {
	_, system, _, _, reasons := startTestUrTun(t)
	failure := errors.New("the device went away")
	system.iface.reads <- testTunRead{err: failure}
	select {
	case reason := <-reasons:
		if !errors.Is(reason, failure) {
			t.Fatalf("closed for %v", reason)
		}
	case <-time.After(urTestTimeout):
		t.Fatal("no close")
	}
	system.iface.stateLock.Lock()
	defer system.iface.stateLock.Unlock()
	if system.iface.closeCount != 1 {
		t.Fatal("the device stayed open")
	}
}

// A read that dropped segments its batch had no room for goes on.
func TestTunReadsOnPastDroppedSegments(t *testing.T) {
	tun, system, tunBridge, _, _ := startTestUrTun(t)
	link := &testTunLink{}
	tunBridge.stateLock.Lock()
	tunBridge.route = func(packet []byte) connect.UserNatClient { return link }
	tunBridge.stateLock.Unlock()
	packet := testTunPacket("100.70.9.9", "100.70.1.2", 17, []byte("kept"))
	system.iface.reads <- testTunRead{packets: [][]byte{packet}, err: errUrTunSegmentsDropped}
	system.iface.reads <- testTunRead{packets: [][]byte{packet}}
	system.iface.reads <- testTunRead{}
	if len(link.taken()) != 2 || tun.status().ReadCount != 2 {
		t.Fatalf("the link took %d", len(link.taken()))
	}
}

// Sets the bridge's egress mode and has it report the change, as an adoption does.
func (self *testTunBridge) setEgressMode(mode bridge.BridgeEgressMode) {
	self.stateLock.Lock()
	self.status.EgressMode = mode
	self.stateLock.Unlock()
	self.changed()
}

// Under exits the default route rides the tun, put on through the platform's SetExits rather than among the routes,
// which stay the bridge's export; off exits it comes off again, and the status follows both.
func TestTunCarriesTheDefaultRouteUnderExits(t *testing.T) {
	tun, system, tunBridge, _, _ := startTestUrTun(t)
	if status := tun.status(); status.DefaultRoute || status.ExitsHeld {
		t.Fatalf("auto: %+v", status)
	}
	tunBridge.setEgressMode(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS)
	waitTunEvents(t, system.iface.events, "a sync under exits", func() bool {
		return tun.status().DefaultRoute
	})
	system.iface.stateLock.Lock()
	routes, exits := slices.Clone(system.iface.routes), system.iface.exits
	system.iface.stateLock.Unlock()
	if !exits || !slices.Equal(routes, tunBridge.Routes()) {
		t.Fatalf("exits %t, routes %v", exits, routes)
	}
	for _, route := range routes {
		if route.Bits() == 0 {
			t.Fatal("the default route among the bridge's routes")
		}
	}
	if status := tun.status(); status.ExitsHeld || status.ExitsHeldReason != "" || status.EgressMode != "exits" {
		t.Fatalf("exits: %+v", status)
	}
	tunBridge.setEgressMode(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE)
	waitTunEvents(t, system.iface.events, "a sync off exits", func() bool {
		return !tun.status().DefaultRoute
	})
	system.iface.stateLock.Lock()
	defer system.iface.stateLock.Unlock()
	if system.iface.exits || system.iface.exitsSets[len(system.iface.exitsSets)-1] {
		t.Fatalf("the default route stayed: %v", system.iface.exitsSets)
	}
}

// A platform that will not put the default route on holds the exits: the status names why, the tun stays up with
// everything else it carries, the sync's error is the hold's, and the next sync puts the route on once it may.
func TestTunHoldsTheExitsWhereThePlatformRefuses(t *testing.T) {
	tun, system, tunBridge, _, _ := startTestUrTun(t)
	refusal := errors.New("the reverse path filter is strict")
	system.iface.stateLock.Lock()
	system.iface.exitsErr = refusal
	system.iface.stateLock.Unlock()
	syncErrs := make(chan error, 16)
	tun.onSync = func(err error) {
		syncErrs <- err
		system.iface.announce("synced")
	}
	tunBridge.setEgressMode(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS)
	waitTunEvents(t, system.iface.events, "a held sync", func() bool {
		return tun.status().ExitsHeld
	})
	status := tun.status()
	if status.DefaultRoute || !strings.Contains(status.ExitsHeldReason, refusal.Error()) || status.SyncError != "" {
		t.Fatalf("held: %+v", status)
	}
	select {
	case err := <-syncErrs:
		if !errors.Is(err, errUrTunExitsHeld) || errors.Is(err, refusal) {
			t.Fatalf("the sync's error %v", err)
		}
	case <-time.After(urTestTimeout):
		t.Fatal("no sync")
	}
	system.iface.stateLock.Lock()
	system.iface.exitsErr = nil
	closeCount := system.iface.closeCount
	system.iface.stateLock.Unlock()
	if closeCount != 0 {
		t.Fatal("a hold closed the tun")
	}
	tunBridge.changed()
	waitTunEvents(t, system.iface.events, "the exits once they may go on", func() bool {
		return tun.status().DefaultRoute
	})
	if status := tun.status(); status.ExitsHeld || status.ExitsHeldReason != "" {
		t.Fatalf("on: %+v", status)
	}
}

// A hold at the start, even one the platform answers with the device's privilege error, leaves the tun up: only a
// device the daemon may not configure ends a start.
func TestTunStartsWithTheExitsHeld(t *testing.T) {
	system := newTestTunSystem()
	system.iface.exitsErr = fmt.Errorf("%w: a rule refused", errUrTunPrivilege)
	networkId := sidecar.NewId()
	bridges, tunBridge := newTestUrBridgeDaemon(t, system, networkId, false)
	tunBridge.stateLock.Lock()
	tunBridge.status.EgressMode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	tunBridge.stateLock.Unlock()
	status, err := bridges.tunUp(networkId, nil)
	if err != nil || !status.ExitsHeld || status.DefaultRoute || !strings.Contains(status.ExitsHeldReason, "a rule refused") {
		t.Fatalf("up: %+v %v", status, err)
	}
	system.iface.stateLock.Lock()
	defer system.iface.stateLock.Unlock()
	if system.iface.closeCount != 0 {
		t.Fatal("a hold ended the start")
	}
}

// A default route that will not come off when the mode leaves exits is the sync's error, tried again, not a hold.
func TestTunRetriesADefaultRouteThatStays(t *testing.T) {
	tun, system, tunBridge, _, _ := startTestUrTun(t)
	tunBridge.setEgressMode(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS)
	waitTunEvents(t, system.iface.events, "a sync under exits", func() bool {
		return tun.status().DefaultRoute
	})
	system.iface.stateLock.Lock()
	system.iface.exitsClearErr = errors.New("a rule did not come off")
	system.iface.stateLock.Unlock()
	tunBridge.setEgressMode(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO)
	waitTunEvents(t, system.iface.events, "a sync off exits", func() bool {
		return tun.status().SyncError != ""
	})
	status := tun.status()
	if !status.DefaultRoute || status.ExitsHeld || !strings.Contains(status.SyncError, "did not come off") {
		t.Fatalf("stayed: %+v", status)
	}
}

// A long instance's device name is hashed to fit, and two long names stay apart.
func TestTunDeviceNameFitsTheInterfaceLimit(t *testing.T) {
	if name := urTunDeviceName("default", 15); name != "ur-default" {
		t.Fatalf("default's device %q", name)
	}
	first := urTunDeviceName("a-very-long-instance-name-number-1", 15)
	second := urTunDeviceName("a-very-long-instance-name-number-2", 15)
	if len(first) != 15 || !strings.HasPrefix(first, "ur-") || first == second {
		t.Fatalf("long names %q %q", first, second)
	}
	if first != urTunDeviceName("a-very-long-instance-name-number-1", 15) {
		t.Fatal("a name that changes")
	}
}

// A daemon's bridges over one fake network.
func newTestUrBridgeDaemon(t *testing.T, system urTunSystem, networkId sidecar.Id, paired bool) (*urBridgeDaemon, *testTunBridge) {
	t.Helper()
	tunBridge := newTestTunBridge()
	bridges := newUrBridgeDaemon(context.Background(), &urBridgeDaemonArgs{
		Instance: "test",
		System:   system,
		Settings: testUrTunSettings(),
	})
	t.Cleanup(bridges.close)
	if system != nil {
		_, err := bridges.addNetwork(&urBridgeNetwork{
			networkId:         networkId,
			bridge:            tunBridge,
			links:             &testTunLinks{},
			paired:            func() bool { return paired },
			componentSettings: sidecar.DefaultBridgeComponentSettings(),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return bridges, tunBridge
}

// Where the platform has no tun, and for a network whose bridge the daemon does not run, ur tun refuses and opens
// nothing.
func TestTunRefusesWhatItCannotCarry(t *testing.T) {
	bridges, _ := newTestUrBridgeDaemon(t, nil, sidecar.NewId(), false)
	if _, err := bridges.tunUp(sidecar.NewId(), nil); !errors.Is(err, errUrTunPlatform) {
		t.Fatalf("no platform: %v", err)
	}
	system := newTestTunSystem()
	unwired, _ := newTestUrBridgeDaemon(t, system, sidecar.NewId(), false)
	if _, err := unwired.tunUp(sidecar.NewId(), nil); !errors.Is(err, errUrBridgeUnwired) {
		t.Fatalf("no bridge: %v", err)
	}
	if _, err := unwired.bridgeNetwork(sidecar.NewId(), nil); !errors.Is(err, errUrBridgeUnwired) {
		t.Fatalf("no bridge for ur tun ip: %v", err)
	}
	system.stateLock.Lock()
	defer system.stateLock.Unlock()
	if len(system.opened) != 0 {
		t.Fatal("a device opened")
	}
}

// A refusal to open the device, for a missing privilege, reaches ur tun as it is.
func TestTunReportsAMissingPrivilege(t *testing.T) {
	system := newTestTunSystem()
	system.openErr = errUrTunPrivilege
	networkId := sidecar.NewId()
	bridges, _ := newTestUrBridgeDaemon(t, system, networkId, false)
	if _, err := bridges.tunUp(networkId, nil); !errors.Is(err, errUrTunPrivilege) {
		t.Fatalf("no privilege: %v", err)
	}
	if bridges.tunStatus() != nil {
		t.Fatal("a tun is held")
	}
}

// A device that opened but may not be configured, a privilege missing for its addresses, ends the start and closes the
// device; another failure of the first sync leaves the tun up, its reply naming it, for the sync to try again.
func TestTunEndsAStartItMayNotConfigure(t *testing.T) {
	system := newTestTunSystem()
	system.iface.addressErr = errUrTunPrivilege
	networkId := sidecar.NewId()
	bridges, _ := newTestUrBridgeDaemon(t, system, networkId, false)
	if _, err := bridges.tunUp(networkId, nil); !errors.Is(err, errUrTunPrivilege) {
		t.Fatalf("no privilege to configure: %v", err)
	}
	system.iface.stateLock.Lock()
	closeCount := system.iface.closeCount
	system.iface.stateLock.Unlock()
	if closeCount != 1 || bridges.tunStatus() != nil {
		t.Fatalf("closed %d times", closeCount)
	}
	other := newTestTunSystem()
	other.iface.addressErr = errors.New("an address the kernel refused")
	otherBridges, _ := newTestUrBridgeDaemon(t, other, networkId, false)
	status, err := otherBridges.tunUp(networkId, nil)
	if err != nil || !strings.Contains(status.SyncError, "refused") {
		t.Fatalf("another failure: %+v %v", status, err)
	}
}

// A paired sidecar's app holds the block on another interface: ur tun yields, naming it; an unpaired one comes up.
func TestTunYieldsToAnAppsBridge(t *testing.T) {
	system := newTestTunSystem()
	system.holder = "tun7"
	networkId := sidecar.NewId()
	bridges, _ := newTestUrBridgeDaemon(t, system, networkId, true)
	_, err := bridges.tunUp(networkId, nil)
	if !errors.Is(err, errUrTunYield) || !strings.Contains(err.Error(), "tun7") {
		t.Fatalf("paired: %v", err)
	}
	unpaired, _ := newTestUrBridgeDaemon(t, newTestTunSystem(), networkId, false)
	if _, err := unpaired.tunUp(networkId, nil); err != nil {
		t.Fatalf("unpaired: %v", err)
	}
}

// One tun an instance: up again for its network answers its status, up for another refuses, and down ends it once.
func TestTunCarriesOneNetworkAtATime(t *testing.T) {
	system := newTestTunSystem()
	networkId := sidecar.NewId()
	bridges, _ := newTestUrBridgeDaemon(t, system, networkId, false)
	status, err := bridges.tunUp(networkId, nil)
	if err != nil || status.Device != "ur-test" || status.NetworkId != networkId {
		t.Fatalf("up: %+v %v", status, err)
	}
	if again, err := bridges.tunUp(networkId, nil); err != nil || again.Device != "ur-test" {
		t.Fatalf("again: %v", err)
	}
	other := sidecar.NewId()
	if _, err := bridges.tunUp(other, nil); err == nil || !strings.Contains(err.Error(), "ur tun down first") {
		t.Fatalf("another network: %v", err)
	}
	if !bridges.tunDown() {
		t.Fatal("down found no tun")
	}
	if bridges.tunDown() || bridges.tunStatus() != nil {
		t.Fatal("a tun after down")
	}
	system.iface.stateLock.Lock()
	defer system.iface.stateLock.Unlock()
	if system.iface.closeCount != 1 {
		t.Fatal("the device stayed open")
	}
}

// ur tun ip shows the block and the address, refuses auto before its check, refuses an address §17.4 does not allow,
// and claims a good one only through the filer, refusing while it has not landed.
func TestTunIpShowsAndClaims(t *testing.T) {
	system := newTestTunSystem()
	networkId := sidecar.NewId()
	bridges, _ := newTestUrBridgeDaemon(t, system, networkId, false)
	ctx := context.Background()
	shown, err := urTunIp(ctx, bridges, networkId, nil, "")
	if err != nil || shown.Block != "100.70.0.0/16" || !slices.Equal(shown.Addresses, []string{"100.70.9.9"}) {
		t.Fatalf("show: %+v %v", shown, err)
	}
	if _, err := urTunIp(ctx, bridges, networkId, nil, urTunIpAuto); !errors.Is(err, errUrTunIpAuto) {
		t.Fatalf("auto: %v", err)
	}
	for _, refused := range []string{"100.71.1.9", "100.70.200.9", "100.70.0.9", "100.70.1.0", "100.70.1.255", "fd00::1", "nonsense"} {
		if _, err := urTunIp(ctx, bridges, networkId, nil, refused); err == nil {
			t.Errorf("%s was taken", refused)
		}
	}
	if _, err := urTunIp(ctx, bridges, networkId, nil, "100.70.1.9"); !errors.Is(err, errUrTunIpUnfiled) {
		t.Fatalf("no filer: %v", err)
	}
	claims := []netip.Addr{}
	previous := urBridgeClaimAddress
	t.Cleanup(func() { urBridgeClaimAddress = previous })
	urBridgeClaimAddress = func(ctx context.Context, running *sidecar.Sidecar, claimNetworkId sidecar.Id, address netip.Addr) error {
		if claimNetworkId != networkId {
			return errors.New("another network's claim")
		}
		claims = append(claims, address)
		return nil
	}
	claimed, err := urTunIp(ctx, bridges, networkId, nil, "100.70.1.9")
	if err != nil || claimed.Claimed != "100.70.1.9" || !slices.Equal(claims, []netip.Addr{netip.MustParseAddr("100.70.1.9")}) {
		t.Fatalf("a claim: %+v %v", claimed, err)
	}
	// still checked against the block before the filer sees it
	if _, err := urTunIp(ctx, bridges, networkId, nil, "100.70.0.9"); err == nil || len(claims) != 1 {
		t.Fatal("a services address reached the filer")
	}
}

// The commands against a daemon whose tun methods a test stands in for: ur tun prints the device, the block, the
// address, each route and the names, and ur tun ip what it shows.
func TestTunCommandsPrintWhatTheDaemonHolds(t *testing.T) {
	previous := urTunPlatform
	t.Cleanup(func() { urTunPlatform = previous })
	urTunPlatform = func(settings *urTunSettings, log sidecar.Logger) urTunSystem { return newTestTunSystem() }
	networkId := sidecar.NewId()
	daemon := &testUrSocketDaemon{}
	cli, stdout, _ := startTestUrSocketCli(t,
		daemon.method(urMethodTunUp, func(params json.RawMessage) (any, error) {
			return &urTunStatus{
				Device:       "ur-test",
				NetworkId:    networkId,
				State:        "enforcing_document",
				Block:        "100.70.0.0/16",
				Addresses:    []string{"100.70.9.9"},
				Routes:       []string{"100.70.0.53/32", "100.70.1.2/32"},
				Resolver:     "100.70.0.53",
				Zones:        []string{"net.example"},
				EgressMode:   "exits",
				DefaultRoute: true,
			}, nil
		}),
		daemon.method(urMethodTunIp, func(params json.RawMessage) (any, error) {
			return &urTunIpReply{NetworkId: networkId, Block: "100.70.0.0/16"}, nil
		}),
	)
	if code := cli.main(context.Background(), []string{"ur", "tun", "--network=work"}); code != urExitOk {
		t.Fatalf("ur tun exited %d", code)
	}
	printed := stdout.String()
	for _, want := range []string{"ur-test carries network", "100.70.0.0/16", "100.70.9.9", "100.70.1.2/32",
		"net.example through 100.70.0.53", "exits      the default route rides ur tun"} {
		if !strings.Contains(printed, want) {
			t.Errorf("ur tun printed no %q:\n%s", want, printed)
		}
	}
	if strings.Contains(printed, "held") {
		t.Errorf("ur tun printed the exits held:\n%s", printed)
	}
	params := &urTunParams{}
	daemon.lastParams(t, params)
	if params.Network != "work" {
		t.Fatalf("the network argument %q", params.Network)
	}
	stdout.Reset()
	if code := cli.main(context.Background(), []string{"ur", "tun", "ip"}); code != urExitOk {
		t.Fatalf("ur tun ip exited %d", code)
	}
	if !strings.Contains(stdout.String(), "address    none: ur tun ip <ip> claims one") {
		t.Fatalf("ur tun ip printed:\n%s", stdout.String())
	}
}

// Held exits print why, and that the host's other traffic keeps today's route; exits not asked for print nothing.
func TestTunPrintsTheHeldExits(t *testing.T) {
	cli, stdout, _ := newTestUrCli("/nonexistent/socket")
	printUrTunStatus(cli, &urTunStatus{
		Device:          "ur-test",
		EgressMode:      "exits",
		ExitsHeld:       true,
		ExitsHeldReason: "the reverse path filter is strict (rp_filter 1) on eth0",
	})
	printed := stdout.String()
	if !strings.Contains(printed, "exits      held: the reverse path filter is strict (rp_filter 1) on eth0; other "+
		"traffic keeps today's route") || strings.Contains(printed, "rides ur tun") {
		t.Fatalf("held:\n%s", printed)
	}
	stdout.Reset()
	printUrTunStatus(cli, &urTunStatus{Device: "ur-test", EgressMode: "auto"})
	if strings.Contains(stdout.String(), "exits") {
		t.Fatalf("auto:\n%s", stdout.String())
	}
}

// Where the platform has no tun, ur tun refuses before it reaches or spawns a daemon.
func TestTunCommandRefusesWithNoPlatform(t *testing.T) {
	previous := urTunPlatform
	t.Cleanup(func() { urTunPlatform = previous })
	urTunPlatform = nil
	cli, _, stderr := newTestUrCli("/nonexistent/socket")
	if code := cli.main(context.Background(), []string{"ur", "tun"}); code != urExitFailed {
		t.Fatalf("ur tun exited %d", code)
	}
	if !strings.Contains(stderr.String(), "Linux and WSL2") {
		t.Fatalf("stderr: %s", stderr.String())
	}
}
