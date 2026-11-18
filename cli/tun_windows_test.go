//go:build windows

// ur tun on Windows (tun_windows.go, bridge_local_windows.go, bridge_dns_windows.go), with IP Helper, the resolver's
// policy table, the driver's load and the adapter behind fakes: the driver's load holds a DLL to its hash pin before its
// signature (the pins themselves, tun_wintun_test.go), an adapter an unelevated daemon may not create is refused in
// Windows' words, addresses and routes go on and come off as the sets ask, a prefix another interface holds is left to
// it, the exits bind the transport to the default route's interface before the halves go on and hold where the host
// refuses them, the resolver's rule follows the zones, and close removes everything. Under exits the carved addresses
// take their host routes (QD-869): an off-link resolver one by the default route's next hop and an on-link one none,
// a carve that changes adds and removes them, a default route that moves takes them with it, and leaving exits and
// closing remove them all; an off-link IPv6 resolver takes one by the IPv6 default route's link-local next hop the same
// way, beside IPv4's, which stand by IPv4's halves as IPv6's stand by IPv6's (QD-971). IPv6's halves go on after
// IPv4's and come off after them (QD-881), a refusal of them holding the exits where the host has an IPv6 default
// route and leaving IPv4's standing where it has none, and a row of either family on link names that family's
// unspecified next hop. A real adapter, which takes an elevated run on Windows, is not run here.

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
	// what AddRoute answers for a prefix ahead of addErr, nil for none
	addErrs map[netip.Prefix]error
	// what DeleteRoute answers for a prefix, nil for success
	deleteErrs map[netip.Prefix]error
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
	if prefixErr := self.addErrs[prefix]; prefixErr != nil {
		err = prefixErr
	}
	self.stateLock.Unlock()
	if err != nil {
		return err
	}
	self.record("add route " + prefix.String())
	return nil
}

func (self *testWindowsIpHelper) DeleteRoute(luid uint64, prefix netip.Prefix) error {
	self.stateLock.Lock()
	err := self.deleteErrs[prefix]
	self.stateLock.Unlock()
	if err != nil {
		return err
	}
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

// A host route of either family as the table shows it: on link, the unspecified next hop of its family.
func testWindowsHostRoute(luid uint64, address netip.Addr, nextHop netip.Addr) urTunWindowsRoute {
	if !nextHop.IsValid() {
		nextHop = netip.IPv4Unspecified()
		if address.Is6() {
			nextHop = netip.IPv6Unspecified()
		}
	}
	return urTunWindowsRoute{dst: netip.PrefixFrom(address, address.BitLen()), luid: luid, nextHop: nextHop,
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

// The calls that put each of the halves on, or take each off, in their order: IPv4's, then IPv6's (QD-881).
func testWindowsHalvesCalls(verb string) []string {
	calls := []string{}
	for _, half := range append(urTunExitsHalves(), urTunExitsIpv6Halves()...) {
		calls = append(calls, verb+" route "+half.String())
	}
	return calls
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

// Under exits the binding goes on first, to the default route whose metrics add up least and IPv6's own, then IPv4's
// halves and IPv6's, then the kick; off exits the halves come off, IPv4's first, before the binding.
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
	if calls := world.ipHelper.take(); !slices.Equal(calls, testWindowsHalvesCalls("add")) {
		t.Fatalf("halves: %v", calls)
	}
	if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
		t.Fatalf("off: %v %v", defaultRoute, err)
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, testWindowsHalvesCalls("delete")) {
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
	world.ipHelper.table = append(table, urTunWindowsRoute{dst: urTunExitsIpv6Halves()[0], luid: 0x20, index: 21})
	if defaultRoute, err := iface.SetExits(true); defaultRoute || !errors.Is(err, errUrTunWindowsExitsHalfInUse) {
		t.Fatalf("a held IPv6 half: %v %v", defaultRoute, err)
	}
	if 0 < len(world.bindings) || 0 < len(world.ipHelper.take()) {
		t.Fatal("something went on")
	}
}

// IPv6's halves under exits (QD-881). Where the host has an IPv6 default route, a refusal of an IPv6 half holds the
// exits, nothing left on, the error saying IPv6 would leave outside them; where it has none, the refusal holds nothing:
// IPv4's halves stand, kicked once, what of IPv6's went on comes off, and the next SetExits tries IPv6's again with no
// kick, putting them on once IP Helper takes them.
func TestTunWindowsExitsTakeIpv6sHalves(t *testing.T) {
	ipv6Halves := urTunExitsIpv6Halves()

	// a host with IPv6 of its own, by Wi-Fi: the refusal of the second IPv6 half holds the exits
	world := newTestWindowsWorld(t)
	iface := world.open(t)
	world.ipHelper.addErrs = map[netip.Prefix]error{ipv6Halves[1]: windows.ERROR_NOT_FOUND}
	defaultRoute, err := iface.SetExits(true)
	if defaultRoute || err == nil || !strings.Contains(err.Error(), "IPv6 would leave outside the exits") {
		t.Fatalf("a host with IPv6: %v %v", defaultRoute, err)
	}
	want := append(testWindowsHalvesCalls("add")[:3], testWindowsHalvesCalls("delete")[:3]...)
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("a host with IPv6: %v", calls)
	}
	if bound, unbound := <-world.bindings, <-world.bindings; bound != [2]uint32{10, 21} || unbound != [2]uint32{0, 0} {
		t.Fatalf("a host with IPv6: bindings %v %v", bound, unbound)
	}
	if 0 < len(world.kicks) || 0 < len(iface.exitsHalves) {
		t.Fatalf("a host with IPv6: kicked, or halves %v left", iface.exitsHalves)
	}

	// a host with none: IPv4's halves stand, and IPv6's that went on comes back off
	world = newTestWindowsWorld(t)
	world.ipHelper.table = slices.DeleteFunc(world.ipHelper.table, func(held urTunWindowsRoute) bool { return held.dst.Addr().Is6() })
	iface = world.open(t)
	world.ipHelper.addErrs = map[netip.Prefix]error{ipv6Halves[1]: windows.ERROR_NOT_FOUND}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("a host with no IPv6: %v %v", defaultRoute, err)
	}
	want = append(testWindowsHalvesCalls("add")[:3], "delete route "+ipv6Halves[0].String())
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) || !slices.Equal(iface.exitsHalves, urTunExitsHalves()) {
		t.Fatalf("a host with no IPv6: %v, halves %v", calls, iface.exitsHalves)
	}
	if binding := <-world.bindings; binding != [2]uint32{10, 0} {
		t.Fatalf("a host with no IPv6: bound to %v", binding)
	}
	<-world.kicks
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute || 0 < len(world.kicks) {
		t.Fatalf("again: %v %v", defaultRoute, err)
	}
	want = []string{"add route " + ipv6Halves[0].String(), "delete route " + ipv6Halves[0].String()}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("again: %v", calls)
	}
	world.ipHelper.addErrs = nil
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("taken: %v %v", defaultRoute, err)
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, testWindowsHalvesCalls("add")[2:]) {
		t.Fatalf("taken: %v", calls)
	}
	<-world.kicks
	if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
		t.Fatalf("off: %v %v", defaultRoute, err)
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, testWindowsHalvesCalls("delete")) {
		t.Fatalf("off: %v", calls)
	}
}

// A route row on link names the unspecified next hop of its prefix's family, an IPv6 half's and an IPv6 host route's
// IPv6's; one by a next hop names it, an IPv6 host route's link-local one among them (QD-971), and a next hop of
// another family is none.
func TestTunWindowsRouteRowsNameTheirFamilysNextHop(t *testing.T) {
	for _, c := range []struct {
		prefix  netip.Prefix
		nextHop netip.Addr
		want    netip.Addr
	}{
		{prefix: urTunExitsHalves()[0], want: netip.IPv4Unspecified()},
		{prefix: urTunExitsIpv6Halves()[1], want: netip.IPv6Unspecified()},
		{prefix: netip.MustParsePrefix("203.0.113.53/32"), nextHop: netip.MustParseAddr("192.0.2.1"),
			want: netip.MustParseAddr("192.0.2.1")},
		{prefix: netip.MustParsePrefix("2001:db8:ffff::53/128"), nextHop: netip.MustParseAddr("fe80::1"),
			want: netip.MustParseAddr("fe80::1")},
		{prefix: netip.MustParsePrefix("2001:db8:ffff::53/128"), want: netip.IPv6Unspecified()},
		{prefix: netip.MustParsePrefix("2001:db8:ffff::53/128"), nextHop: netip.MustParseAddr("192.0.2.1"),
			want: netip.IPv6Unspecified()},
	} {
		row, err := urTunWindowsRouteRow(0x99, c.prefix, c.nextHop, 0)
		if err != nil {
			t.Fatal(err)
		}
		destination, err := urTunWindowsSockaddrAddr(&row.DestinationPrefix.Prefix).Prefix(int(row.DestinationPrefix.PrefixLength))
		if err != nil || destination != c.prefix || urTunWindowsSockaddrAddr(&row.NextHop) != c.want {
			t.Fatalf("%s: %v by %v", c.prefix, destination, urTunWindowsSockaddrAddr(&row.NextHop))
		}
	}
}

// The table of a host on 192.0.2.0/24 by Ethernet, the adapter Windows chooses, with Wi-Fi beside it: each adapter's
// default route by its gateway, Wi-Fi's IPv6 one too, which names no next hop, its subnet on link, Wi-Fi's IPv6 prefix
// among them, Ethernet's own address local, and loopback's.
func testWindowsHostTable() []urTunWindowsRoute {
	return []urTunWindowsRoute{
		{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x20, index: 20, nextHop: netip.MustParseAddr("198.51.100.1")},
		{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x10, index: 10, nextHop: netip.MustParseAddr("192.0.2.1")},
		{dst: netip.MustParsePrefix("::/0"), luid: 0x20, index: 21},
		{dst: netip.MustParsePrefix("2001:db8::/64"), luid: 0x20, index: 21, nextHop: netip.IPv6Unspecified()},
		{dst: netip.MustParsePrefix("192.0.2.0/24"), luid: 0x10, index: 10, nextHop: netip.IPv4Unspecified()},
		{dst: netip.MustParsePrefix("192.0.2.10/32"), luid: 0x10, index: 10, nextHop: netip.IPv4Unspecified(),
			protocol: windows.MIB_IPPROTO_LOCAL},
		{dst: netip.MustParsePrefix("198.51.100.0/24"), luid: 0x20, index: 20, nextHop: netip.IPv4Unspecified()},
		{dst: netip.MustParsePrefix("127.0.0.0/8"), luid: 0x1, index: 1, nextHop: netip.IPv4Unspecified(), loopback: true},
	}
}

// The carve of that host: its own address, its gateway, a resolver on its link, loopback, an IPv6 resolver on Wi-Fi's
// link, and resolvers beyond its networks.
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
// resolver, loopback and an on-link IPv6 resolver take none. Off exits the carve waits. A sync that changed nothing
// writes nothing, though the host route now reads in the table; a carve that changes adds and removes them; and
// leaving exits takes them off after the halves and before the binding.
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
	want := append([]string{"add host route 203.0.113.53 by 192.0.2.1 on 0x10"}, testWindowsHalvesCalls("add")...)
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
		urTunWindowsRoute{dst: netip.MustParsePrefix("203.0.113.54/31"), luid: 0x20, index: 20, nextHop: netip.IPv4Unspecified()})
	if err := iface.SetCarved(testWindowsCarve("203.0.113.54", "203.0.113.60")); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete host route 203.0.113.54 by 192.0.2.1 on 0x10", "add host route 203.0.113.60 by 192.0.2.1 on 0x10"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("an address a route came to hold: %v", calls)
	}
	<-world.bindings
	defaultRoute, err := iface.SetExits(false)
	if err != nil || defaultRoute {
		t.Fatalf("off: %v %v", defaultRoute, err)
	}
	want = append(testWindowsHalvesCalls("delete"), "delete host route 203.0.113.60 by 192.0.2.1 on 0x10")
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("off: %v", calls)
	}
	if binding := <-world.bindings; binding != [2]uint32{0, 0} {
		t.Fatalf("unbound to %v", binding)
	}
	// off exits the carve waits again
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53", "203.0.113.60")); err != nil {
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
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53", "203.0.113.60")); err != nil {
		t.Fatal(err)
	}
	world.ipHelper.take()
	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}
	want := append(testWindowsHalvesCalls("delete"), "delete host route 203.0.113.53 by 192.0.2.1 on 0x10",
		"delete host route 203.0.113.60 by 192.0.2.1 on 0x10", "delete route 100.70.1.2/32")
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

// A half that will not come off at close goes with the adapter, so the host routes that waited on it come off once the
// adapter is closed: none outlives the tun.
func TestTunWindowsCloseRemovesTheCarvedHostRoutesOfAHeldHalf(t *testing.T) {
	world := newTestWindowsWorld(t)
	world.ipHelper.table = testWindowsHostTable()
	iface := world.open(t)
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if err := iface.SetCarved(testWindowsCarve("203.0.113.53")); err != nil {
		t.Fatal(err)
	}
	halves := urTunExitsHalves()
	world.ipHelper.deleteErrs = map[netip.Prefix]error{halves[1]: windows.ERROR_NOT_ENOUGH_MEMORY}
	// leaving exits keeps the host route while an IPv4 half is still on
	world.ipHelper.take()
	if defaultRoute, err := iface.SetExits(false); err == nil || !defaultRoute {
		t.Fatalf("a half that stays: %v %v", defaultRoute, err)
	}
	want := []string{"delete route " + halves[0].String()}
	for _, half := range urTunExitsIpv6Halves() {
		want = append(want, "delete route "+half.String())
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("a half that stays: %v", calls)
	}
	if err := iface.Close(); err == nil {
		t.Fatal("close answered nothing of the half that would not come off")
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"delete host route 203.0.113.53 by 192.0.2.1 on 0x10"}) {
		t.Fatalf("close: %v", calls)
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

// The IPv6 routes of the host testWindowsHostTable holds, whose IPv6 default route Windows chooses is Ethernet's, by a
// link-local router as a router advertisement leaves it, ahead of Wi-Fi's: Ethernet's prefix on link, its own address
// local, its link-local prefix, and IPv6's loopback.
func testWindowsIpv6HostTable() []urTunWindowsRoute {
	return []urTunWindowsRoute{
		{dst: netip.MustParsePrefix("::/0"), luid: 0x10, index: 10, nextHop: netip.MustParseAddr("fe80::1")},
		{dst: netip.MustParsePrefix("2001:db8:10::/64"), luid: 0x10, index: 10, nextHop: netip.IPv6Unspecified()},
		{dst: netip.MustParsePrefix("2001:db8:10::10/128"), luid: 0x10, index: 10, nextHop: netip.IPv6Unspecified(),
			protocol: windows.MIB_IPPROTO_LOCAL},
		{dst: netip.MustParsePrefix("fe80::/64"), luid: 0x10, index: 10, nextHop: netip.IPv6Unspecified()},
		{dst: netip.MustParsePrefix("::1/128"), luid: 0x1, index: 1, nextHop: netip.IPv6Unspecified(), loopback: true},
	}
}

// A dual-stack world: testWindowsHostTable's host with testWindowsIpv6HostTable's IPv6 routes.
func newTestWindowsDualWorld(t *testing.T) *testWindowsWorld {
	t.Helper()
	world := newTestWindowsWorld(t)
	world.ipHelper.table = append(testWindowsHostTable(), testWindowsIpv6HostTable()...)
	return world
}

// The carve of that host: testWindowsCarve's with ipv4OffLink, then Ethernet's own IPv6 address and router and IPv6's
// loopback, and the IPv6 resolvers beyond its links ipv6OffLink names.
func testWindowsDualCarve(ipv4OffLink string, ipv6OffLink ...string) []netip.Addr {
	carve := append(testWindowsCarve(ipv4OffLink), netip.MustParseAddr("2001:db8:10::10"), netip.MustParseAddr("fe80::1"),
		netip.MustParseAddr("::1"))
	for _, address := range ipv6OffLink {
		carve = append(carve, netip.MustParseAddr(address))
	}
	return carve
}

// Under exits an IPv6 address of the carve the host reaches only by its IPv6 default route, an off-link resolver,
// takes a host route by that route's link-local next hop on its adapter beside IPv4's, before the halves go on
// (QD-971); Ethernet's own IPv6 address, its router, a resolver on Wi-Fi's prefix and loopback take none. Off exits the
// carve waits. A sync that changed nothing writes nothing; a carve that changes adds and removes them, IPv4's left as
// they are; a route of the host's own that comes to hold one takes its host route off; and leaving exits takes both
// families' off after the halves and before the binding.
func TestTunWindowsCarvedIpv6HostRoutesFollowTheCarve(t *testing.T) {
	world := newTestWindowsDualWorld(t)
	iface := world.open(t)
	if err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", "2001:db8:ffff::53")); err != nil {
		t.Fatal(err)
	}
	if calls := world.ipHelper.take(); 0 < len(calls) {
		t.Fatalf("off exits: %v", calls)
	}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("exits: %v %v", defaultRoute, err)
	}
	want := append([]string{"add host route 203.0.113.53 by 192.0.2.1 on 0x10", "add host route 2001:db8:ffff::53 by fe80::1 on 0x10"},
		testWindowsHalvesCalls("add")...)
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("exits: %v", calls)
	}
	if binding := <-world.bindings; binding != [2]uint32{10, 10} {
		t.Fatalf("bound to %v", binding)
	}
	<-world.kicks
	// the halves of both families read in the table from here, on the tun's adapter
	halves := []urTunWindowsRoute{}
	for _, half := range append(urTunExitsHalves(), urTunExitsIpv6Halves()...) {
		nextHop := netip.IPv4Unspecified()
		if half.Addr().Is6() {
			nextHop = netip.IPv6Unspecified()
		}
		halves = append(halves, urTunWindowsRoute{dst: half, luid: 0x99, index: 99, nextHop: nextHop})
	}
	world.ipHelper.replaceRoutes(func(held urTunWindowsRoute) bool { return false }, halves...)
	// a sync with nothing changed
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", "2001:db8:ffff::53")); err != nil {
		t.Fatal(err)
	}
	if calls := world.ipHelper.take(); 0 < len(calls) || 0 < len(world.bindings) || 0 < len(world.kicks) {
		t.Fatalf("nothing changed: %v", calls)
	}
	// the carve changes: one IPv6 resolver leaves it and another joins
	if err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", "2001:db8:ffff::54")); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete host route 2001:db8:ffff::53 by fe80::1 on 0x10", "add host route 2001:db8:ffff::54 by fe80::1 on 0x10"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("a changed carve: %v", calls)
	}
	// a route of the host's own comes to hold the address: its host route would move it off that link
	world.ipHelper.replaceRoutes(func(held urTunWindowsRoute) bool { return false },
		urTunWindowsRoute{dst: netip.MustParsePrefix("2001:db8:ffff::/64"), luid: 0x20, index: 21, nextHop: netip.IPv6Unspecified()})
	if err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", "2001:db8:ffff::54", "2001:db8:fffe::53")); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete host route 2001:db8:ffff::54 by fe80::1 on 0x10", "add host route 2001:db8:fffe::53 by fe80::1 on 0x10"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("an address a route came to hold: %v", calls)
	}
	defaultRoute, err := iface.SetExits(false)
	if err != nil || defaultRoute {
		t.Fatalf("off: %v %v", defaultRoute, err)
	}
	want = append(testWindowsHalvesCalls("delete"), "delete host route 203.0.113.53 by 192.0.2.1 on 0x10",
		"delete host route 2001:db8:fffe::53 by fe80::1 on 0x10")
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("off: %v", calls)
	}
	if binding := <-world.bindings; binding != [2]uint32{0, 0} {
		t.Fatalf("unbound to %v", binding)
	}
	// off exits the carve waits again
	if err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", "2001:db8:ffff::53")); err != nil {
		t.Fatal(err)
	}
	if calls := world.ipHelper.take(); 0 < len(calls) {
		t.Fatalf("off exits again: %v", calls)
	}
}

// IPv6's default route that moves takes IPv6's host routes with it (QD-971): to another router on the same adapter
// with no new binding, and to Wi-Fi's IPv6 default route once Ethernet's goes, which names no next hop, on link on
// Wi-Fi's adapter, bound again. Where the host has no IPv6 default route left, IPv6's host routes come off while
// IPv4's stay; and one that comes back puts them on again.
func TestTunWindowsCarvedIpv6HostRoutesFollowTheIpv6DefaultRoute(t *testing.T) {
	world := newTestWindowsDualWorld(t)
	iface := world.open(t)
	if err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", "2001:db8:ffff::53")); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	<-world.bindings
	<-world.kicks
	world.ipHelper.take()
	isEthernetIpv6Default := func(held urTunWindowsRoute) bool {
		return held.dst == netip.MustParsePrefix("::/0") && held.luid == 0x10
	}
	// another router on the same adapter
	world.ipHelper.replaceRoutes(isEthernetIpv6Default, urTunWindowsRoute{dst: netip.MustParsePrefix("::/0"), luid: 0x10,
		index: 10, nextHop: netip.MustParseAddr("fe80::2")})
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	want := []string{"delete host route 2001:db8:ffff::53 by fe80::1 on 0x10", "add host route 2001:db8:ffff::53 by fe80::2 on 0x10"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("another router: %v", calls)
	}
	if 0 < len(world.bindings) || 0 < len(world.kicks) {
		t.Fatal("bound again on the same adapter")
	}
	// Ethernet's IPv6 default route goes: Wi-Fi's is the host's, on link
	world.ipHelper.replaceRoutes(isEthernetIpv6Default)
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if binding := <-world.bindings; binding != [2]uint32{10, 21} {
		t.Fatalf("bound again to %v", binding)
	}
	<-world.kicks
	want = []string{"delete host route 2001:db8:ffff::53 by fe80::2 on 0x10", "add host route 2001:db8:ffff::53 by the link on 0x20"}
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("Wi-Fi's IPv6 default route: %v", calls)
	}
	// no IPv6 default route is left: IPv6's host route comes off and IPv4's stays
	world.ipHelper.replaceRoutes(func(held urTunWindowsRoute) bool { return held.dst == netip.MustParsePrefix("::/0") })
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("no IPv6 default route: %v %v", defaultRoute, err)
	}
	if binding := <-world.bindings; binding != [2]uint32{10, 0} {
		t.Fatalf("bound with no IPv6 default route to %v", binding)
	}
	<-world.kicks
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"delete host route 2001:db8:ffff::53 by the link on 0x20"}) {
		t.Fatalf("no IPv6 default route: %v", calls)
	}
	if !slices.Equal(iface.hostRoutes, []urTunHostRoute{{address: netip.MustParseAddr("203.0.113.53"),
		gateway: netip.MustParseAddr("192.0.2.1"), link: 0x10}}) {
		t.Fatalf("no IPv6 default route: host routes %v", iface.hostRoutes)
	}
	// Ethernet's comes back
	world.ipHelper.replaceRoutes(func(held urTunWindowsRoute) bool { return false }, urTunWindowsRoute{
		dst: netip.MustParsePrefix("::/0"), luid: 0x10, index: 10, nextHop: netip.MustParseAddr("fe80::1")})
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if binding := <-world.bindings; binding != [2]uint32{10, 10} {
		t.Fatalf("bound again to %v", binding)
	}
	<-world.kicks
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"add host route 2001:db8:ffff::53 by fe80::1 on 0x10"}) {
		t.Fatalf("IPv6's default route back: %v", calls)
	}
}

// Each family's host routes stand by that family's halves (QD-971): an IPv6 half that will not come off keeps IPv6's
// host routes on, still following the carve, while IPv4's come off with IPv4's halves; an IPv6 one IP Helper refuses is
// counted with no address in the words and tried again; and once the adapter is closed, which takes the stuck half
// with it, they come off: none outlives the tun.
func TestTunWindowsCarvedIpv6HostRoutesStandByIpv6sHalves(t *testing.T) {
	world := newTestWindowsDualWorld(t)
	iface := world.open(t)
	if err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", "2001:db8:ffff::53")); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	world.ipHelper.deleteErrs = map[netip.Prefix]error{urTunExitsIpv6Halves()[1]: windows.ERROR_NOT_ENOUGH_MEMORY}
	world.ipHelper.take()
	if defaultRoute, err := iface.SetExits(false); err == nil || !defaultRoute {
		t.Fatalf("an IPv6 half that stays: %v %v", defaultRoute, err)
	}
	want := append(testWindowsHalvesCalls("delete")[:3], "delete host route 203.0.113.53 by 192.0.2.1 on 0x10")
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("an IPv6 half that stays: %v", calls)
	}
	// IPv6's follow the carve while its half stands, IPv4's waiting; one IP Helper refuses is counted and tried again
	moved := netip.MustParseAddr("2001:db8:ffff::54")
	world.ipHelper.hostAddErrs[moved] = windows.ERROR_NOT_ENOUGH_MEMORY
	err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", moved.String()))
	if err == nil || strings.Contains(err.Error(), "2001:db8") ||
		!strings.Contains(err.Error(), "1 host routes of carved addresses did not go on") {
		t.Fatalf("a refused IPv6 host route: %v", err)
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"delete host route 2001:db8:ffff::53 by fe80::1 on 0x10"}) {
		t.Fatalf("the carve with IPv6's half alone: %v", calls)
	}
	delete(world.ipHelper.hostAddErrs, moved)
	if err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", moved.String())); err != nil {
		t.Fatal(err)
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"add host route 2001:db8:ffff::54 by fe80::1 on 0x10"}) {
		t.Fatalf("tried again: %v", calls)
	}
	// the close takes the adapter and the stuck half with it, then IPv6's host route
	if err := iface.Close(); err == nil {
		t.Fatal("close answered nothing of the half that would not come off")
	}
	if calls := world.ipHelper.take(); !slices.Equal(calls, []string{"delete host route 2001:db8:ffff::54 by fe80::1 on 0x10"}) {
		t.Fatalf("close: %v", calls)
	}
	for _, held := range world.ipHelper.table {
		if held.protocol == windows.MIB_IPPROTO_NETMGMT && held.dst.IsSingleIP() {
			t.Fatalf("a host route stayed: %+v", held)
		}
	}
}

// Close takes both families' host routes off with the exits, after the halves.
func TestTunWindowsCloseRemovesTheCarvedIpv6HostRoutes(t *testing.T) {
	world := newTestWindowsDualWorld(t)
	iface := world.open(t)
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if err := iface.SetCarved(testWindowsDualCarve("203.0.113.53", "2001:db8:ffff::53", "2001:db8:fffe::53")); err != nil {
		t.Fatal(err)
	}
	world.ipHelper.take()
	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}
	want := append(testWindowsHalvesCalls("delete"), "delete host route 203.0.113.53 by 192.0.2.1 on 0x10",
		"delete host route 2001:db8:fffe::53 by fe80::1 on 0x10", "delete host route 2001:db8:ffff::53 by fe80::1 on 0x10")
	if calls := world.ipHelper.take(); !slices.Equal(calls, want) {
		t.Fatalf("close: %v", calls)
	}
	for _, held := range world.ipHelper.table {
		if held.protocol == windows.MIB_IPPROTO_NETMGMT && held.dst.IsSingleIP() {
			t.Fatalf("a host route stayed: %+v", held)
		}
	}
}

// Which routes of the table reach a carved IPv6 address (QD-971): a route on the tun's adapter, IPv4's default route
// and an IPv6 default route Windows ranks after do not, so the address takes a host route by the IPv6 default route
// Windows chooses; a route of the host's own does; another program's IPv6 host route is the host's way to it and this
// interface's own is not; with IPv4's default route alone it takes none; and a next hop of another family is no next
// hop, so it goes on link.
func TestTunWindowsCarvedIpv6HostRoutesReadTheTable(t *testing.T) {
	world := newTestWindowsWorld(t)
	adapters := world.ipHelper.adapters
	address := netip.MustParseAddr("2001:db8:ffff::53")
	gateway := netip.MustParseAddr("fe80::1")
	ipv6Default := urTunWindowsRoute{dst: netip.MustParsePrefix("::/0"), luid: 0x10, index: 10, nextHop: gateway}
	want := []urTunHostRoute{{address: address, gateway: gateway, link: 0x10}}
	inside := netip.MustParsePrefix("2001:db8:ffff::/64")
	for name, held := range map[string]urTunWindowsRoute{
		"a route on the tun's adapter": {dst: inside, luid: 0x99},
		"IPv4's default route": {dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x20,
			nextHop: netip.MustParseAddr("198.51.100.1")},
		"an IPv6 default route Windows ranks after": {dst: netip.MustParsePrefix("::/0"), luid: 0x20,
			nextHop: netip.MustParseAddr("fe80::20")},
	} {
		table := []urTunWindowsRoute{ipv6Default, held}
		if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, nil, nil); !slices.Equal(hostRoutes, want) {
			t.Errorf("%s: %v", name, hostRoutes)
		}
	}
	table := []urTunWindowsRoute{ipv6Default, {dst: inside, luid: 0x20, nextHop: netip.IPv6Unspecified()}}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, nil, nil); 0 < len(hostRoutes) {
		t.Errorf("a route of the host's own: %v", hostRoutes)
	}
	table = []urTunWindowsRoute{ipv6Default, testWindowsHostRoute(0x10, address, gateway)}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, nil, nil); 0 < len(hostRoutes) {
		t.Errorf("another's IPv6 host route: %v", hostRoutes)
	}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, nil, want); !slices.Equal(hostRoutes, want) {
		t.Errorf("its own IPv6 host route: %v", hostRoutes)
	}
	table = []urTunWindowsRoute{{dst: netip.MustParsePrefix("0.0.0.0/0"), luid: 0x10, index: 10,
		nextHop: netip.MustParseAddr("192.0.2.1")}}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, table, adapters, 0x99, nil, nil); 0 < len(hostRoutes) {
		t.Errorf("no IPv6 default route: %v", hostRoutes)
	}
	odd := urTunWindowsRoute{dst: netip.MustParsePrefix("::/0"), luid: 0x10, index: 10, nextHop: netip.MustParseAddr("192.0.2.1")}
	if hostRoutes := urTunWindowsHostRoutes([]netip.Addr{address}, []urTunWindowsRoute{odd}, adapters, 0x99, nil, nil); !slices.Equal(hostRoutes,
		[]urTunHostRoute{{address: address, link: 0x10}}) {
		t.Errorf("a next hop of another family: %v", hostRoutes)
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

// Whether iface holds every half, IPv4's and IPv6's, the default routes the plan takes; a test fails on a partial set.
func testWindowsHalvesHeld(t *testing.T, iface *urTunWindowsInterface) bool {
	t.Helper()
	iface.stateLock.Lock()
	halves := slices.Clone(iface.exitsHalves)
	iface.stateLock.Unlock()
	all := append(urTunExitsHalves(), urTunExitsIpv6Halves()...)
	if 0 < len(halves) && len(halves) != len(all) {
		t.Errorf("a partial set of halves %v", halves)
	}
	return len(halves) == len(all)
}

// Every combination of the plan for default traffic (QD-1052) over the Windows interface on its IP Helper recorder,
// through the tun's own sync: the halves of both families and the binding go on exactly where the plan takes the
// default route, and none outlives the tun.
func TestTunWindowsPlansDefaultTrafficForEveryCombination(t *testing.T) {
	testTunDefaultCasesOnPlatform(t, func(t *testing.T) (urTunInterface, func() bool) {
		world := newTestWindowsWorld(t)
		iface := world.open(t)
		return iface, func() bool { return testWindowsHalvesHeld(t, iface) }
	})
}

// Over the Windows interface on its recorder: default egress off takes the halves off at once and on puts them back,
// as do route local traffic and an exit that comes and goes, with the one adapter up throughout (QD-1052).
func TestTunWindowsSwitchesDefaultEgressWithNoRestart(t *testing.T) {
	world := newTestWindowsWorld(t)
	iface := world.open(t)
	testTunDefaultSwitchOnPlatform(t, iface, func() bool { return testWindowsHalvesHeld(t, iface) })
	if world.created != 1 {
		t.Fatalf("%d adapters created", world.created)
	}
}
