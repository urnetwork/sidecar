//go:build windows

// ur tun on Windows (tun_windows.go, bridge_local_windows.go, bridge_dns_windows.go), with IP Helper, the resolver's
// policy table, the driver's load and the adapter behind fakes: the driver's load holds a DLL to its hash pin before its
// signature (the pins themselves, tun_wintun_test.go), an adapter an unelevated daemon may not create is refused in
// Windows' words, addresses and routes go on and come off as the sets ask, a prefix another interface holds is left to
// it, the exits bind the transport to the default route's interface before the halves go on and hold where the host
// refuses them, the resolver's rule follows the zones, and close removes everything. Under exits the carved addresses
// take their host routes (QD-869): an off-link resolver one by the default route's next hop and an on-link one none,
// a carve that changes adds and removes them, a default route that moves takes them with it, and leaving exits and
// closing remove them all. A real adapter, which takes an elevated run on Windows, is not run here.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// IP Helper's calls as the adapter makes them, and a table and adapters to answer from.
type testWindowsIpHelper struct {
	stateLock sync.Mutex
	calls     []string
	table     []urTunWindowsRoute
	adapters  []urTunWindowsAdapter
	addErr    error
	// what AddHostRoute and DeleteHostRoute answer for an address, nil for success
	hostAddErrs    map[netip.Addr]error
	hostDeleteErrs map[netip.Addr]error
}

var _ urTunWindowsIpHelper = (*testWindowsIpHelper)(nil)

func (self *testWindowsIpHelper) record(call string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, call)
}

func (self *testWindowsIpHelper) AddAddress(luid uint64, address netip.Addr) error {
	self.record("add address " + address.String())
	return nil
}

func (self *testWindowsIpHelper) DeleteAddress(luid uint64, address netip.Addr) error {
	self.record("delete address " + address.String())
	return nil
}

func (self *testWindowsIpHelper) AddRoute(luid uint64, prefix netip.Prefix, metric uint32) error {
	self.stateLock.Lock()
	err := self.addErr
	self.stateLock.Unlock()
	if err != nil {
		return err
	}
	self.record("add route " + prefix.String())
	return nil
}

func (self *testWindowsIpHelper) DeleteRoute(luid uint64, prefix netip.Prefix) error {
	self.record("delete route " + prefix.String())
	return nil
}

// A host route that goes on joins the table, as IP Helper's does, and leaves it as it comes off.
func (self *testWindowsIpHelper) AddHostRoute(luid uint64, address netip.Addr, nextHop netip.Addr, metric uint32) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.hostAddErrs[address]; err != nil {
		return err
	}
	self.calls = append(self.calls, testWindowsHostRouteCall("add", luid, address, nextHop))
	self.table = append(self.table, testWindowsHostRoute(luid, address, nextHop))
	return nil
}

func (self *testWindowsIpHelper) DeleteHostRoute(luid uint64, address netip.Addr, nextHop netip.Addr) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.hostDeleteErrs[address]; err != nil {
		return err
	}
	self.calls = append(self.calls, testWindowsHostRouteCall("delete", luid, address, nextHop))
	self.table = slices.DeleteFunc(self.table, func(held urTunWindowsRoute) bool {
		return held == testWindowsHostRoute(luid, address, nextHop)
	})
	return nil
}

// A host route as the table shows it: on link, the unspecified next hop.
func testWindowsHostRoute(luid uint64, address netip.Addr, nextHop netip.Addr) urTunWindowsRoute {
	if !nextHop.IsValid() {
		nextHop = netip.IPv4Unspecified()
	}
	return urTunWindowsRoute{dst: netip.PrefixFrom(address, 32), luid: luid, nextHop: nextHop,
		protocol: windows.MIB_IPPROTO_NETMGMT}
}

// A host route's call as the recorder keeps it.
func testWindowsHostRouteCall(verb string, luid uint64, address netip.Addr, nextHop netip.Addr) string {
	by := "the link"
	if nextHop.IsValid() {
		by = nextHop.String()
	}
	return fmt.Sprintf("%s host route %s by %s on %#x", verb, address, by, luid)
}

// Replaces the table's routes that match with routes.
func (self *testWindowsIpHelper) replaceRoutes(match func(held urTunWindowsRoute) bool, routes ...urTunWindowsRoute) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.table = append(slices.DeleteFunc(self.table, match), routes...)
}

func (self *testWindowsIpHelper) Routes() ([]urTunWindowsRoute, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.table), nil
}

func (self *testWindowsIpHelper) Adapters() ([]urTunWindowsAdapter, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.adapters), nil
}

func (self *testWindowsIpHelper) SetMtu(luid uint64, mtu int) error {
	self.record("mtu")
	return nil
}

func (self *testWindowsIpHelper) take() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calls := self.calls
	self.calls = nil
	return calls
}

// The resolver's rules as the adapter sets them.
type testWindowsResolver struct {
	stateLock sync.Mutex
	rules     map[string][]string
}

func (self *testWindowsResolver) Set(rule string, resolver netip.Addr, zones []string) (string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rules[rule] = append([]string{resolver.String()}, zones...)
	return "", nil
}

func (self *testWindowsResolver) Remove(rule string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.rules, rule)
	return nil
}

// An adapter with an interface luid that holds no ring.
type testWindowsDevice struct {
	events    chan tun.Event
	closeOnce sync.Once
	closed    chan struct{}
}

var _ tun.Device = (*testWindowsDevice)(nil)

func newTestWindowsDevice() *testWindowsDevice {
	return &testWindowsDevice{events: make(chan tun.Event, 1), closed: make(chan struct{})}
}

func (self *testWindowsDevice) File() *os.File {
	return nil
}

func (self *testWindowsDevice) Write(bufs [][]byte, offset int) (int, error) {
	return len(bufs), nil
}

func (self *testWindowsDevice) MTU() (int, error) {
	return connect.DefaultTunnelMtu, nil
}

func (self *testWindowsDevice) Name() (string, error) {
	return "ur-test", nil
}

func (self *testWindowsDevice) Events() <-chan tun.Event {
	return self.events
}

func (self *testWindowsDevice) BatchSize() int {
	return 1
}

func (self *testWindowsDevice) LUID() uint64 {
	return 0x99
}

func (self *testWindowsDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-self.closed
	return 0, os.ErrClosed
}

func (self *testWindowsDevice) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
		close(self.events)
	})
	return nil
}

// A Windows system over fakes, the driver loaded, its binding and kicks recorded.
type testWindowsWorld struct {
	system   *urTunWindowsSystem
	ipHelper *testWindowsIpHelper
	resolver *testWindowsResolver
	device   *testWindowsDevice
	created  int
	bindings chan [2]uint32
	kicks    chan struct{}
}

func newTestWindowsWorld(t *testing.T) *testWindowsWorld {
	t.Helper()
	world := &testWindowsWorld{
		ipHelper: &testWindowsIpHelper{hostAddErrs: map[netip.Addr]error{}, hostDeleteErrs: map[netip.Addr]error{}},
		resolver: &testWindowsResolver{rules: map[string][]string{}},
		device:   newTestWindowsDevice(),
		bindings: make(chan [2]uint32, 16),
		kicks:    make(chan struct{}, 16),
	}
	world.ipHelper.adapters = []urTunWindowsAdapter{
		{luid: 0x10, name: "Ethernet", index4: 10, index6: 10, metric4: 25, metric6: 25,
			addresses: []netip.Addr{netip.MustParseAddr("192.0.2.10")}, gateways: []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			resolvers: []netip.Addr{netip.MustParseAddr("192.0.2.53")}},
		{luid: 0x20, name: "Wi-Fi", index4: 20, index6: 21, metric4: 50, metric6: 50,
			addresses: []netip.Addr{netip.MustParseAddr("198.51.100.10")}},
		{luid: 0x99, name: "ur-test", index4: 99, index6: 99, addresses: []netip.Addr{netip.MustParseAddr("100.70.9.9")}},
	}
	world.ipHelper.table = []urTunWindowsRoute{
		{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x20, index: 20, metric: 0},
		{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x10, index: 10, metric: 0},
		{dst: netip.MustParsePrefix("::/0"), luid: 0x20, index: 21, metric: 0},
	}
	world.system = &urTunWindowsSystem{
		settings: testUrTunSettings(),
		log:      sidecar.NewNoopLogger(),
		pins:     defaultUrWintunPins(),
		ipHelper: world.ipHelper,
		resolver: world.resolver,
		loadDriver: func() error {
			return nil
		},
		create: func(name string, mtu int) (tun.Device, error) {
			world.created += 1
			return world.device, nil
		},
		setEgressInterface: func(index4 uint32, index6 uint32) {
			world.bindings <- [2]uint32{index4, index6}
		},
		networkChanged: func() {
			world.kicks <- struct{}{}
		},
	}
	return world
}

func (self *testWindowsWorld) open(t *testing.T) *urTunWindowsInterface {
	t.Helper()
	opened, err := self.system.Open("ur-test", connect.DefaultTunnelMtu)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	if calls := self.ipHelper.take(); !slices.Equal(calls, []string{"mtu"}) {
		t.Fatalf("opened with %v", calls)
	}
	return opened.(*urTunWindowsInterface)
}

// The driver's load comes first: one that refuses opens no adapter, and an adapter an unelevated daemon may not
// create is refused as errUrTunPrivilege, in Windows' words.
func TestTunWindowsOpensOnlyOverTheDriver(t *testing.T) {
	world := newTestWindowsWorld(t)
	world.system.loadDriver = func() error {
		return errUrWintunUnpinned
	}
	if _, err := world.system.Open("ur-test", connect.DefaultTunnelMtu); !errors.Is(err, errUrWintunUnpinned) || world.created != 0 {
		t.Fatalf("unpinned: %v, %d created", err, world.created)
	}
	world.system.loadDriver = func() error {
		return nil
	}
	world.system.create = func(name string, mtu int) (tun.Device, error) {
		return nil, windows.ERROR_ACCESS_DENIED
	}
	_, err := world.system.Open("ur-test", connect.DefaultTunnelMtu)
	if !errors.Is(err, errUrTunPrivilege) || !strings.Contains(err.Error(), "administrator") ||
		strings.Contains(err.Error(), "CAP_NET_ADMIN") {
		t.Fatalf("unelevated: %v", err)
	}
}

// The pins: a DLL of another hash than this architecture's pin is refused before its signature is read, held against
// writers meanwhile; one whose hash is the pin goes on to its signature, which a file the pinned signer did not sign
// fails; and no DLL where ur tun looks names where to get one. An architecture with no pin, which the release builds
// no ur.exe for, refuses before anything else.
func TestTunWindowsHoldsTheDriverToItsPins(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, urWintunDllName)
	content := []byte("not wintun")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := urWintunOpen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	pins := defaultUrWintunPins()
	err = urWintunCheck(file, path, pins)
	switch runtime.GOARCH {
	case "amd64", "arm64":
		if !errors.Is(err, errUrWintunRefused) || !strings.Contains(err.Error(), "SHA-256 is not the pinned one") {
			t.Fatalf("another hash: %v", err)
		}
	default:
		if !errors.Is(err, errUrWintunUnpinned) {
			t.Fatalf("unpinned: %v", err)
		}
	}
	// held against writers while it is open
	if err := os.WriteFile(path, []byte("planted"), 0o644); err == nil {
		t.Fatal("a writer reached the held file")
	}
	digest := sha256.Sum256(content)
	pins.DllSha256[runtime.GOARCH] = hex.EncodeToString(digest[:])
	if err := urWintunCheck(file, path, pins); !errors.Is(err, errUrWintunRefused) ||
		!strings.Contains(err.Error(), "signature does not verify") {
		t.Fatalf("pinned but unsigned: %v", err)
	}
	if err := urWintunLoad(pins, []string{filepath.Join(directory, "absent", urWintunDllName)}); !errors.Is(err, errUrWintunMissing) ||
		!strings.Contains(err.Error(), "wintun-0.14.1.zip") {
		t.Fatalf("missing: %v", err)
	}
}

// Addresses and routes go on and come off as the sets ask; a prefix another interface's route holds is counted and
// left to it.
func TestTunWindowsSetsWhatTheBridgeHolds(t *testing.T) {
	world := newTestWindowsWorld(t)
	iface := world.open(t)
	first := netip.MustParseAddr("100.70.9.9")
	second := netip.MustParseAddr("100.70.9.10")
	iface.SetAddresses([]netip.Addr{first, second})
	iface.SetAddresses([]netip.Addr{second})
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"add address 100.70.9.9", "add address 100.70.9.10", "delete address 100.70.9.9"}) {
		t.Fatalf("addresses: %v", calls)
	}
	held := netip.MustParsePrefix("192.168.7.0/24")
	world.ipHelper.table = append(world.ipHelper.table, urTunWindowsRoute{dst: held, luid: 0x10, index: 10})
	conflictCount, err := iface.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.70.1.2/32"), held})
	if err != nil || conflictCount != 1 {
		t.Fatalf("routes: %d %v", conflictCount, err)
	}
	iface.SetRoutes(nil)
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"add route 100.70.1.2/32", "delete route 100.70.1.2/32"}) {
		t.Fatalf("routes: %v", calls)
	}
}

// Under exits the binding goes on first, to the default route whose metrics add up least and IPv6's own, then the
// halves, then the kick; off exits the halves come off before the binding.
func TestTunWindowsExitsBindTheTransportFirst(t *testing.T) {
	world := newTestWindowsWorld(t)
	iface := world.open(t)
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("exits: %v %v", defaultRoute, err)
	}
	if binding := <-world.bindings; binding != [2]uint32{10, 21} {
		t.Fatalf("bound to %v", binding)
	}
	<-world.kicks
	halves := urTunExitsHalves()
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"add route " + halves[0].String(), "add route " + halves[1].String()}) {
		t.Fatalf("halves: %v", calls)
	}
	if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
		t.Fatalf("off: %v %v", defaultRoute, err)
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"delete route " + halves[0].String(), "delete route " + halves[1].String()}) {
		t.Fatalf("off: %v", calls)
	}
	if binding := <-world.bindings; binding != [2]uint32{0, 0} {
		t.Fatalf("unbound to %v", binding)
	}
}

// No default route outside the tun, or a half another program's route holds, holds the exits with nothing on.
func TestTunWindowsExitsHoldWhatTheHostRefuses(t *testing.T) {
	world := newTestWindowsWorld(t)
	iface := world.open(t)
	table := world.ipHelper.table
	world.ipHelper.table = nil
	if defaultRoute, err := iface.SetExits(true); defaultRoute || !errors.Is(err, errUrTunWindowsExitsNoDefault) {
		t.Fatalf("no default: %v %v", defaultRoute, err)
	}
	world.ipHelper.table = append(table, urTunWindowsRoute{dst: urTunExitsHalves()[1], luid: 0x20, index: 20})
	if defaultRoute, err := iface.SetExits(true); defaultRoute || !errors.Is(err, errUrTunWindowsExitsHalfInUse) {
		t.Fatalf("a held half: %v %v", defaultRoute, err)
	}
	if 0 < len(world.bindings) || 0 < len(world.ipHelper.take()) {
		t.Fatal("something went on")
	}
}

// The table of a host on 192.0.2.0/24 by Ethernet, the adapter Windows chooses, with Wi-Fi beside it: each adapter's
// default route by its gateway, its subnet on link, Ethernet's own address local, and loopback's.
func testWindowsHostTable() []urTunWindowsRoute {
	return []urTunWindowsRoute{
		{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x20, index: 20, nextHop: netip.MustParseAddr("198.51.100.1")},
		{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x10, index: 10, nextHop: netip.MustParseAddr("192.0.2.1")},
		{dst: netip.MustParsePrefix("::/0"), luid: 0x20, index: 21},
		{dst: netip.MustParsePrefix("192.0.2.0/24"), luid: 0x10, index: 10, nextHop: netip.IPv4Unspecified()},
		{dst: netip.MustParsePrefix("192.0.2.10/32"), luid: 0x10, index: 10, nextHop: netip.IPv4Unspecified(),
			protocol: windows.MIB_IPPROTO_LOCAL},
		{dst: netip.MustParsePrefix("198.51.100.0/24"), luid: 0x20, index: 20, nextHop: netip.IPv4Unspecified()},
		{dst: netip.MustParsePrefix("127.0.0.0/8"), luid: 0x1, index: 1, nextHop: netip.IPv4Unspecified(), loopback: true},
	}
}

// The carve of that host: its own address, its gateway, a resolver on its link, loopback, an IPv6 address, and
// resolvers beyond its networks.
func testWindowsCarve(offLink ...string) []netip.Addr {
	carve := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("2001:db8::53")}
	for _, address := range offLink {
		carve = append(carve, netip.MustParseAddr(address))
	}
	return carve
}

// Under exits a carved address the host reaches only by its default route, an off-link resolver, takes a host route
// by that route's next hop on its adapter, before the halves go on; the host's own address, its gateway, an on-link
// resolver, loopback and an IPv6 address take none. Off exits the carve waits. A sync that changed nothing writes
// nothing, though the host route now reads in the table; a carve that changes adds and removes them; and leaving exits
// takes them off after the halves and before the binding.
func TestTunWindowsCarvedHostRoutesFollowTheCarve(t *testing.T) {
	world := newTestWindowsWorld(t)
	world.ipHelper.table = testWindowsHostTable()
	iface := world.open(t)
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53")); err != nil {
		t.Fatal(err)
	}
	if calls := world.ipHelper.take(); 0 < len(calls) {
		t.Fatalf("off exits: %v", calls)
	}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("exits: %v %v", defaultRoute, err)
	}
	halves := urTunExitsHalves()
	want := []string{"add host route 203.0.113.53 by 192.0.2.1 on 0x10", "add route " + halves[0].String(),
		"add route " + halves[1].String()}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("exits: %v", calls)
	}
	// the halves read in the table from here, on the tun's adapter
	world.ipHelper.replaceRoutes(func(held urTunWindowsRoute) bool { return false },
		urTunWindowsRoute{dst: halves[0], luid: 0x99, index: 99, nextHop: netip.IPv4Unspecified()},
		urTunWindowsRoute{dst: halves[1], luid: 0x99, index: 99, nextHop: netip.IPv4Unspecified()})
	// a sync with nothing changed
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53")); err != nil {
		t.Fatal(err)
	}
	if calls := world.ipHelper.take(); 0 < len(calls) {
		t.Fatalf("nothing changed: %v", calls)
	}
	// the carve changes: one resolver leaves it and another joins
	if err := iface.SetCarved(testWindowsCarve("203.0.113.54")); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete host route 203.0.113.53 by 192.0.2.1 on 0x10", "add host route 203.0.113.54 by 192.0.2.1 on 0x10"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("a changed carve: %v", calls)
	}
	// a route of the host's own comes to hold the address: its host route would move it off that link
	world.ipHelper.replaceRoutes(func(held urTunWindowsRoute) bool { return false },
		urTunWindowsRoute{dst: netip.MustParsePrefix("203.0.113.0/24"), luid: 0x20, index: 20, nextHop: netip.IPv4Unspecified()})
	if err := iface.SetCarved(testWindowsCarve("203.0.113.54", "203.0.114.53")); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete host route 203.0.113.54 by 192.0.2.1 on 0x10", "add host route 203.0.114.53 by 192.0.2.1 on 0x10"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("an address a route came to hold: %v", calls)
	}
	<-world.bindings
	defaultRoute, err := iface.SetExits(false)
	if err != nil || defaultRoute {
		t.Fatalf("off: %v %v", defaultRoute, err)
	}
	want = []string{"delete route " + halves[0].String(), "delete route " + halves[1].String(),
		"delete host route 203.0.114.53 by 192.0.2.1 on 0x10"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("off: %v", calls)
	}
	if binding := <-world.bindings; binding != [2]uint32{0, 0} {
		t.Fatalf("unbound to %v", binding)
	}
	// off exits the carve waits again
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53", "203.0.114.53")); err != nil {
		t.Fatal(err)
	}
	if calls := world.ipHelper.take(); 0 < len(calls) {
		t.Fatalf("off exits again: %v", calls)
	}
}

// A default route that moves takes the host routes with it: to a new next hop on the same adapter with no new
// binding, to another adapter's route with one, and to a route that names no next hop on link, the old route off and
// the new one on at the sync's SetExits.
func TestTunWindowsCarvedHostRoutesFollowTheDefaultRoute(t *testing.T) {
	world := newTestWindowsWorld(t)
	world.ipHelper.table = testWindowsHostTable()
	iface := world.open(t)
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53")); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if binding := <-world.bindings; binding != [2]uint32{10, 21} {
		t.Fatalf("bound to %v", binding)
	}
	<-world.kicks
	world.ipHelper.take()
	isEthernetDefault := func(held urTunWindowsRoute) bool {
		return held.dst == netip.MustParsePrefix("0.0.0.0/0") && held.luid == 0x10
	}
	// another next hop on the same adapter
	world.ipHelper.replaceRoutes(isEthernetDefault, urTunWindowsRoute{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x10,
		index: 10, nextHop: netip.MustParseAddr("192.0.2.254")})
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	want := []string{"delete host route 203.0.113.53 by 192.0.2.1 on 0x10", "add host route 203.0.113.53 by 192.0.2.254 on 0x10"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("a new next hop: %v", calls)
	}
	if 0 < len(world.bindings) || 0 < len(world.kicks) {
		t.Fatal("bound again on the same adapter")
	}
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53")); err != nil || 0 < len(world.ipHelper.take()) {
		t.Fatalf("the carve after the move: %v", err)
	}
	// Ethernet's default route goes: Wi-Fi's is the host's
	world.ipHelper.replaceRoutes(isEthernetDefault)
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if binding := <-world.bindings; binding != [2]uint32{20, 21} {
		t.Fatalf("bound again to %v", binding)
	}
	<-world.kicks
	want = []string{"delete host route 203.0.113.53 by 192.0.2.254 on 0x10", "add host route 203.0.113.53 by 198.51.100.1 on 0x20"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("another adapter: %v", calls)
	}
	// a default route that names no next hop: the host route goes on link through its adapter
	world.ipHelper.replaceRoutes(func(held urTunWindowsRoute) bool {
		return held.dst == netip.MustParsePrefix("0.0.0.0/0")
	}, urTunWindowsRoute{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x20, index: 20, nextHop: netip.IPv4Unspecified()})
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete host route 203.0.113.53 by 198.51.100.1 on 0x20", "add host route 203.0.113.53 by the link on 0x20"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("a default route with no next hop: %v", calls)
	}
}

// What the host refuses of a host route: one already there by the time it is written is left to its holder and never
// removed; one IP Helper refuses is counted, with no address in the words, and tried again at the next SetCarved; one
// that will not come off is kept and tried again; and exits whose halves will not go on leave no host route on.
func TestTunWindowsCarvedHostRoutesHoldWhatTheHostRefuses(t *testing.T) {
	world := newTestWindowsWorld(t)
	world.ipHelper.table = testWindowsHostTable()
	iface := world.open(t)
	first := netip.MustParseAddr("203.0.113.53")
	second := netip.MustParseAddr("203.0.113.54")
	world.ipHelper.hostAddErrs[first] = windows.ERROR_OBJECT_ALREADY_EXISTS
	world.ipHelper.hostAddErrs[second] = windows.ERROR_NOT_ENOUGH_MEMORY
	if err := iface.SetCarved(testWindowsCarve(first.String(), second.String())); err != nil {
		t.Fatal(err)
	}
	// SetExits refuses nothing for a host route
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("exits: %v %v", defaultRoute, err)
	}
	world.ipHelper.take()
	err := iface.SetCarved(testWindowsCarve(first.String(), second.String()))
	if err == nil || strings.Contains(err.Error(), "203.0.113") ||
		!strings.Contains(err.Error(), "1 host routes of carved addresses did not go on") {
		t.Fatalf("a refused host route: %v", err)
	}
	if calls := world.ipHelper.take(); 0 < len(calls) {
		t.Fatalf("refused: %v", calls)
	}
	// IP Helper takes it at the next call
	delete(world.ipHelper.hostAddErrs, second)
	if err := iface.SetCarved(testWindowsCarve(first.String(), second.String())); err != nil {
		t.Fatal(err)
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"add host route 203.0.113.54 by 192.0.2.1 on 0x10"}) {
		t.Fatalf("tried again: %v", calls)
	}
	// one that will not come off stays this interface's, and goes at the next call
	world.ipHelper.hostDeleteErrs[second] = windows.ERROR_NOT_ENOUGH_MEMORY
	err = iface.SetCarved(testWindowsCarve())
	if err == nil || strings.Contains(err.Error(), "203.0.113") ||
		!strings.Contains(err.Error(), "1 host routes of addresses no longer carved did not come off") {
		t.Fatalf("a host route that would not come off: %v", err)
	}
	delete(world.ipHelper.hostDeleteErrs, second)
	if err := iface.SetCarved(testWindowsCarve()); err != nil {
		t.Fatal(err)
	}
	// the one already there was never this interface's to remove
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"delete host route 203.0.113.54 by 192.0.2.1 on 0x10"}) {
		t.Fatalf("removed: %v", calls)
	}
	if _, err := iface.SetExits(false); err != nil {
		t.Fatal(err)
	}
	world.ipHelper.take()
	// the halves will not go on: the host routes that went on before them come off with the exits
	delete(world.ipHelper.hostAddErrs, first)
	world.ipHelper.addErr = windows.ERROR_NOT_ENOUGH_MEMORY
	if err := iface.SetCarved(testWindowsCarve(first.String())); err != nil {
		t.Fatal(err)
	}
	if defaultRoute, err := iface.SetExits(true); defaultRoute || err == nil {
		t.Fatalf("halves that will not go on: %v %v", defaultRoute, err)
	}
	want := []string{"add host route 203.0.113.53 by 192.0.2.1 on 0x10", "delete host route 203.0.113.53 by 192.0.2.1 on 0x10"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("halves that will not go on: %v", calls)
	}
	// a half another program's route holds: nothing goes on at all
	world.ipHelper.addErr = nil
	world.ipHelper.replaceRoutes(func(held urTunWindowsRoute) bool { return false },
		urTunWindowsRoute{dst: urTunExitsHalves()[1], luid: 0x20, index: 20})
	if defaultRoute, err := iface.SetExits(true); defaultRoute || !errors.Is(err, errUrTunWindowsExitsHalfInUse) {
		t.Fatalf("a held half: %v %v", defaultRoute, err)
	}
	if calls := world.ipHelper.take(); 0 < len(calls) {
		t.Fatalf("a held half: %v", calls)
	}
}

// Close takes the carved addresses' host routes off with the exits, after the halves, and a closed interface takes
// no carve.
func TestTunWindowsCloseRemovesTheCarvedHostRoutes(t *testing.T) {
	world := newTestWindowsWorld(t)
	world.ipHelper.table = testWindowsHostTable()
	iface := world.open(t)
	iface.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.70.1.2/32")})
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53", "203.0.114.53")); err != nil {
		t.Fatal(err)
	}
	world.ipHelper.take()
	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}
	halves := urTunExitsHalves()
	want := []string{"delete route " + halves[0].String(), "delete route " + halves[1].String(),
		"delete host route 203.0.113.53 by 192.0.2.1 on 0x10", "delete host route 203.0.114.53 by 192.0.2.1 on 0x10",
		"delete route 100.70.1.2/32"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("close: %v", calls)
	}
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53")); !errors.Is(err, errUrTunClosed) {
		t.Fatalf("after close: %v", err)
	}
	for _, held := range world.ipHelper.table {
		if held.protocol == windows.MIB_IPPROTO_NETMGMT && held.dst.IsSingleIP() {
			t.Fatalf("a host route stayed: %+v", held)
		}
	}
}

// Which routes of the table reach a carved address: a route on the tun's adapter and another family's do not, so the
// address takes a host route; a route of the tun's own inside which it lies leaves it to the bridge; another program's
// host route is the host's way to it and this interface's own is not; and with no default route but the tun's, nothing
// goes on.
func TestTunWindowsCarvedHostRoutesReadTheTable(t *testing.T) {
	world := newTestWindowsWorld(t)
	adapters := world.ipHelper.adapters
	address := netip.MustParseAddr("203.0.113.53")
	gateway := netip.MustParseAddr("192.0.2.1")
	defaultRoute := urTunWindowsRoute{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x10, index: 10, nextHop: gateway}
	want := []urTunHostRoute{{address: address, gateway: gateway, link: 0x10}}
	inside := netip.MustParsePrefix("203.0.113.0/24")
	for name, held := range map[string]urTunWindowsRoute{
		"a route on the tun's adapter": {dst: inside, luid: 0x99},
		"IPv6's default route":         {dst: netip.MustParsePrefix("::/0"), luid: 0x20},
		"a default route Windows ranks after": {dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x20,
			nextHop: netip.MustParseAddr("198.51.100.1")},
	} {
		table := []urTunWindowsRoute{defaultRoute, held}
		if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, nil, nil); !slices.Equal(hostRoutes, want) {
			t.Errorf("%s: %v", name, hostRoutes)
		}
	}
	table := []urTunWindowsRoute{defaultRoute, {dst: inside, luid: 0x20}}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, nil, nil); 0 < len(hostRoutes) {
		t.Errorf("a route of the host's own: %v", hostRoutes)
	}
	table = []urTunWindowsRoute{defaultRoute, testWindowsHostRoute(0x10, address, gateway)}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, nil, nil); 0 < len(hostRoutes) {
		t.Errorf("another's host route: %v", hostRoutes)
	}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, nil, want); !slices.Equal(hostRoutes, want) {
		t.Errorf("its own host route: %v", hostRoutes)
	}
	table = []urTunWindowsRoute{defaultRoute}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, []netip.Prefix{inside}, nil); 0 < len(hostRoutes) {
		t.Errorf("inside a route of the tun's own: %v", hostRoutes)
	}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x10, nil, nil); 0 < len(hostRoutes) {
		t.Errorf("no default route but the tun's: %v", hostRoutes)
	}
}

// The rule follows the zones under the tun's name, a name that is no zone is left out, and close removes it with the
// routes and addresses.
func TestTunWindowsResolverRuleAndClose(t *testing.T) {
	world := newTestWindowsWorld(t)
	iface := world.open(t)
	iface.SetAddresses([]netip.Addr{netip.MustParseAddr("100.70.9.9")})
	iface.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.70.1.2/32")})
	if step, err := iface.SetResolver(netip.MustParseAddr("100.70.0.53"), []string{"Net.Example.", "a/b"}); step != "" || err != nil {
		t.Fatalf("resolver: %q %v", step, err)
	}
	rule := urTunWindowsRuleName("ur-test")
	if held := world.resolver.rules[rule]; !slices.Equal(held, []string{"100.70.0.53", "net.example"}) {
		t.Fatalf("rule %v", held)
	}
	world.ipHelper.take()
	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"delete route 100.70.1.2/32", "delete address 100.70.9.9"}) {
		t.Fatalf("close: %v", calls)
	}
	if _, held := world.resolver.rules[rule]; held {
		t.Fatal("the rule stayed")
	}
	if !regexp.MustCompile(`^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$`).MatchString(rule) ||
		rule != urTunWindowsRuleName("ur-test") || rule == urTunWindowsRuleName("ur-other") {
		t.Fatalf("rule name %s", rule)
	}
}

// The local addresses are every adapter's but the tun's, with gateways and resolvers; the block routed elsewhere is
// another adapter's route inside it, never a local address's own host route or one covering it.
func TestTunWindowsReadsTheHost(t *testing.T) {
	world := newTestWindowsWorld(t)
	addresses, err := world.system.LocalAddresses("ur-test", []netip.Addr{netip.MustParseAddr("192.0.2.53")})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.10")}
	if !slices.Equal(addresses, want) {
		t.Fatalf("local %v", addresses)
	}
	block := netip.MustParsePrefix("100.70.0.0/16")
	world.ipHelper.table = append(world.ipHelper.table,
		urTunWindowsRoute{dst: netip.MustParsePrefix("100.64.0.0/10"), luid: 0x10},
		urTunWindowsRoute{dst: netip.MustParsePrefix("100.70.4.4/32"), luid: 0x10, protocol: windows.MIB_IPPROTO_LOCAL},
		urTunWindowsRoute{dst: netip.MustParsePrefix("100.70.1.0/24"), luid: 0x99})
	if holder, err := world.system.RoutedElsewhere("ur-test", block); err != nil || holder != "" {
		t.Fatalf("held by %q: %v", holder, err)
	}
	world.ipHelper.table = append(world.ipHelper.table, urTunWindowsRoute{dst: block, luid: 0x20})
	if holder, err := world.system.RoutedElsewhere("ur-test", block); err != nil || holder != "Wi-Fi" {
		t.Fatalf("held by %q: %v", holder, err)
	}
}
