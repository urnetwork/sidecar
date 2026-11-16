//go:build darwin

// ur tun on macOS (tun_darwin.go, bridge_local_darwin.go, bridge_dns_darwin.go). Most run the device's calls behind a
// recording kernel and a fake utun, the carved addresses' host routes under exits among them (QD-869): an off-link
// resolver takes one by the default route's gateway and an on-link one none, a carve that changes adds and removes
// them, a default route that moves takes them with it, and leaving exits and closing remove them all. IPv6's halves go
// on after IPv4's and come off after them (QD-881), a refusal of them holding the exits where the host has an IPv6
// default route and leaving IPv4's standing where it has none. The rest run on
// this machine's own kernel where no root is needed: a daemon that runs as the person is refused a utun with words
// that send no one to sudo and leaves no device behind, and a host route too, an interface's flags read through the
// same ioctl path the device's set takes, and the routing socket's watch starts and ends. A real device and a real
// host route, which take root, run only where UR_TUN_TEST_DEVICE=darwin and the test runs as root:
//
//	sudo env UR_TUN_TEST_DEVICE=darwin go test -run TestTunDarwinDevice -v .
//
// Every wait is bounded by urTestTimeout.

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
)

// The utuns this host has now.
func testDarwinUtuns(t *testing.T) []string {
	t.Helper()
	links, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, link := range links {
		if strings.HasPrefix(link.Name, "utun") {
			names = append(names, link.Name)
		}
	}
	return names
}

// On this machine, run as the person: the open is refused with errUrTunPrivilege, in macOS's words, naming root and
// no sudo, through the daemon as directly, and no utun is left behind.
func TestTunDarwinRefusesWithoutRoot(t *testing.T) {
	if unix.Geteuid() == 0 {
		t.Skip("runs as root: the refusal is a person's")
	}
	before := testDarwinUtuns(t)
	system := newUrTunDarwinSystem(testUrTunSettings(), nil)
	_, err := system.Open("ur-test", connect.DefaultTunnelMtu)
	if !errors.Is(err, errUrTunPrivilege) {
		t.Fatalf("open: %v", err)
	}
	text := err.Error()
	t.Logf("the refusal: %s", text)
	if !strings.Contains(text, "root") || strings.Contains(strings.ToLower(text), "sudo") ||
		strings.Contains(text, "CAP_NET_ADMIN") {
		t.Fatalf("the refusal reads: %s", text)
	}
	networkId := sidecar.NewId()
	bridges, _ := newTestUrBridgeDaemon(t, system, networkId, false)
	if _, err := bridges.tunUp(networkId, nil); !errors.Is(err, errUrTunPrivilege) || bridges.tunStatus() != nil {
		t.Fatalf("through the daemon: %v", err)
	}
	if after := testDarwinUtuns(t); !slices.Equal(before, after) {
		t.Fatalf("utuns before %v, after %v", before, after)
	}
}

// The ioctl path the device's flags, addresses and up go through, on lo0, which needs no root to read.
func TestTunDarwinReadsAnInterfacesFlags(t *testing.T) {
	flags, err := urTunDarwinFlags("lo0")
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.IFF_UP == 0 || flags&unix.IFF_LOOPBACK == 0 {
		t.Fatalf("lo0's flags %#x", flags)
	}
	if _, err := urTunDarwinIfname("a-name-past-ifnamsiz"); err == nil {
		t.Fatal("a name past IFNAMSIZ")
	}
}

// A route's message, of either family: a whole address a host route with no mask, a wider prefix with its mask, IPv6's
// halves among them, each through the link address of the interface, and the dump's parse reads them back.
func TestTunDarwinRouteMessagesReadBack(t *testing.T) {
	for _, prefix := range []netip.Prefix{netip.MustParsePrefix("100.70.1.2/32"), netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"),
		netip.MustParsePrefix("2001:db8::/64"), netip.MustParsePrefix("2001:db8::7/128")} {
		message := urTunDarwinRouteMessage(unix.RTM_ADD, 42, prefix, 7, 9)
		wire, err := message.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, wire)
		if err != nil || len(messages) != 1 {
			t.Fatalf("%s: %d messages, %v", prefix, len(messages), err)
		}
		parsed, ok := messages[0].(*route.RouteMessage)
		if !ok || parsed.Type != unix.RTM_ADD || parsed.Index != 42 || parsed.Seq != 9 {
			t.Fatalf("%s: %+v", prefix, messages[0])
		}
		if prefix.IsSingleIP() != (parsed.Flags&unix.RTF_HOST != 0) || parsed.Flags&unix.RTF_STATIC == 0 {
			t.Fatalf("%s: flags %#x", prefix, parsed.Flags)
		}
		held, ok := urTunDarwinParseRoute(parsed)
		if !ok || held.dst != prefix || held.index != 42 || held.gateway.IsValid() {
			t.Fatalf("%s read back as %+v", prefix, held)
		}
		link, ok := parsed.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok || link.Index != 42 {
			t.Fatalf("%s: gateway %+v", prefix, parsed.Addrs[unix.RTAX_GATEWAY])
		}
	}
}

// The kernel's calls as the device makes them, and a table to answer from.
type testDarwinKernel struct {
	stateLock sync.Mutex
	calls     []string
	table     []urTunDarwinRoute
	// what AddRoute and DeleteRoute answer for a prefix, nil for success
	addErrs    map[netip.Prefix]error
	deleteErrs map[netip.Prefix]error
	// what AddHostRoute and DeleteHostRoute answer for an address, nil for success
	hostAddErrs    map[netip.Addr]error
	hostDeleteErrs map[netip.Addr]error
}

var _ urTunDarwinKernel = (*testDarwinKernel)(nil)

func (self *testDarwinKernel) record(call string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, call)
}

func (self *testDarwinKernel) SetUp(name string) error {
	self.record("up " + name)
	return nil
}

func (self *testDarwinKernel) AddAddress(name string, address netip.Addr) error {
	self.record("add address " + address.String())
	return nil
}

func (self *testDarwinKernel) DeleteAddress(name string, address netip.Addr) error {
	self.record("delete address " + address.String())
	return nil
}

func (self *testDarwinKernel) AddRoute(index int, prefix netip.Prefix) error {
	self.stateLock.Lock()
	err := self.addErrs[prefix]
	self.stateLock.Unlock()
	if err == nil {
		self.record("add route " + prefix.String())
	}
	return err
}

func (self *testDarwinKernel) DeleteRoute(index int, prefix netip.Prefix) error {
	self.stateLock.Lock()
	err := self.deleteErrs[prefix]
	self.stateLock.Unlock()
	if err == nil {
		self.record("delete route " + prefix.String())
	}
	return err
}

// The flags the kernel shows a static host route by a gateway with.
const testDarwinHostRouteFlags = unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_HOST | unix.RTF_STATIC

// A host route that goes on joins the table, as the kernel's does, and leaves it as it comes off.
func (self *testDarwinKernel) AddHostRoute(index int, address netip.Addr, gateway netip.Addr) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.hostAddErrs[address]; err != nil {
		return err
	}
	self.calls = append(self.calls, testDarwinHostRouteCall("add", index, address, gateway))
	self.table = append(self.table, urTunDarwinRoute{dst: netip.PrefixFrom(address, 32), index: index, gateway: gateway,
		flags: testDarwinHostRouteFlags})
	return nil
}

func (self *testDarwinKernel) DeleteHostRoute(index int, address netip.Addr, gateway netip.Addr) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err := self.hostDeleteErrs[address]; err != nil {
		return err
	}
	self.calls = append(self.calls, testDarwinHostRouteCall("delete", index, address, gateway))
	self.table = slices.DeleteFunc(self.table, func(held urTunDarwinRoute) bool {
		return held.dst == netip.PrefixFrom(address, 32) && held.index == index && held.gateway == gateway &&
			held.flags == testDarwinHostRouteFlags
	})
	return nil
}

// A host route's call as the recorder keeps it.
func testDarwinHostRouteCall(verb string, index int, address netip.Addr, gateway netip.Addr) string {
	by := "the link"
	if gateway.IsValid() {
		by = gateway.String()
	}
	return fmt.Sprintf("%s host route %s by %s on %d", verb, address, by, index)
}

// Replaces the table's routes that match with routes.
func (self *testDarwinKernel) replaceRoutes(match func(held urTunDarwinRoute) bool, routes ...urTunDarwinRoute) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.table = append(slices.DeleteFunc(self.table, match), routes...)
}

func (self *testDarwinKernel) Routes() ([]urTunDarwinRoute, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.table), nil
}

// Takes the calls so far.
func (self *testDarwinKernel) take() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calls := self.calls
	self.calls = nil
	return calls
}

// A utun that holds no file: its events end when it closes.
type testDarwinDevice struct {
	events    chan tun.Event
	closeOnce sync.Once
	closed    chan struct{}
}

var _ tun.Device = (*testDarwinDevice)(nil)

func newTestDarwinDevice() *testDarwinDevice {
	return &testDarwinDevice{events: make(chan tun.Event, 1), closed: make(chan struct{})}
}

func (self *testDarwinDevice) File() *os.File {
	return nil
}

func (self *testDarwinDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-self.closed
	return 0, os.ErrClosed
}

func (self *testDarwinDevice) Write(bufs [][]byte, offset int) (int, error) {
	return len(bufs), nil
}

func (self *testDarwinDevice) MTU() (int, error) {
	return connect.DefaultTunnelMtu, nil
}

func (self *testDarwinDevice) Name() (string, error) {
	return "utun99", nil
}

func (self *testDarwinDevice) Events() <-chan tun.Event {
	return self.events
}

func (self *testDarwinDevice) Close() error {
	self.closeOnce.Do(func() {
		close(self.closed)
		close(self.events)
	})
	return nil
}

func (self *testDarwinDevice) BatchSize() int {
	return 1
}

// A macOS system over a recording kernel, a fake utun numbered 99 and a resolver directory of the test's, whose
// binding and kick it records.
type testDarwinWorld struct {
	system   *urTunDarwinSystem
	kernel   *testDarwinKernel
	device   *testDarwinDevice
	bindings chan [2]uint32
	kicks    chan struct{}
}

func newTestDarwinWorld(t *testing.T) *testDarwinWorld {
	t.Helper()
	world := &testDarwinWorld{
		kernel: &testDarwinKernel{addErrs: map[netip.Prefix]error{}, hostAddErrs: map[netip.Addr]error{},
			hostDeleteErrs: map[netip.Addr]error{}},
		device:   newTestDarwinDevice(),
		bindings: make(chan [2]uint32, 16),
		kicks:    make(chan struct{}, 16),
	}
	world.kernel.table = []urTunDarwinRoute{
		{dst: netip.MustParsePrefix("0.0.0.0/0"), index: 4, gateway: netip.MustParseAddr("192.0.2.1"), flags: unix.RTF_UP | unix.RTF_GATEWAY},
		{dst: netip.MustParsePrefix("0.0.0.0/0"), index: 5, gateway: netip.MustParseAddr("198.51.100.1"), flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_IFSCOPE},
	}
	directory := t.TempDir()
	world.system = &urTunDarwinSystem{
		settings: testUrTunSettings(),
		log:      sidecar.NewNoopLogger(),
		kernel:   world.kernel,
		create: func(mtu int) (tun.Device, error) {
			return world.device, nil
		},
		interfaceIndex: func(name string) (int, error) {
			if name == "utun99" {
				return 99, nil
			}
			return 0, errors.New("no such interface")
		},
		resolverDirectory: filepath.Join(directory, "resolver"),
		resolvConfPath:    filepath.Join(directory, "resolv.conf"),
		setEgressInterface: func(index4 uint32, index6 uint32) {
			world.bindings <- [2]uint32{index4, index6}
		},
		networkChanged: func() {
			world.kicks <- struct{}{}
		},
	}
	return world
}

// Opens the fake utun, closed at the test's end.
func (self *testDarwinWorld) open(t *testing.T) *urTunDarwinInterface {
	t.Helper()
	opened, err := self.system.Open("ur-test", connect.DefaultTunnelMtu)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { opened.Close() })
	return opened.(*urTunDarwinInterface)
}

// The calls that put each of the halves on, or take each off, in their order: IPv4's, then IPv6's (QD-881).
func testDarwinHalvesCalls(verb string) []string {
	calls := []string{}
	for _, half := range append(urTunExitsHalves(), urTunExitsIpv6Halves()...) {
		calls = append(calls, verb+" route "+half.String())
	}
	return calls
}

// The device takes the kernel's name and comes up; addresses and routes go on and come off as the sets ask, a route
// another interface holds is counted and left to it, and the read wants the family header's room.
func TestTunDarwinSetsWhatTheBridgeHolds(t *testing.T) {
	world := newTestDarwinWorld(t)
	iface := world.open(t)
	if iface.Name() != "utun99" || !slices.Equal(world.kernel.take(), []string{"up utun99"}) {
		t.Fatalf("opened %s", iface.Name())
	}
	first := netip.MustParseAddr("100.70.9.9")
	second := netip.MustParseAddr("100.70.9.10")
	if err := iface.SetAddresses([]netip.Addr{first, second}); err != nil {
		t.Fatal(err)
	}
	if err := iface.SetAddresses([]netip.Addr{second}); err != nil {
		t.Fatal(err)
	}
	want := []string{"add address 100.70.9.9", "add address 100.70.9.10", "delete address 100.70.9.9"}
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("addresses: %v", calls)
	}
	held := netip.MustParsePrefix("192.168.7.0/24")
	world.kernel.addErrs[held] = unix.EEXIST
	peer := netip.MustParsePrefix("100.70.1.2/32")
	conflictCount, err := iface.SetRoutes([]netip.Prefix{peer, held})
	if err != nil || conflictCount != 1 {
		t.Fatalf("routes: %d %v", conflictCount, err)
	}
	if conflictCount, err := iface.SetRoutes(nil); err != nil || conflictCount != 0 {
		t.Fatalf("no routes: %d %v", conflictCount, err)
	}
	if calls := world.kernel.take(); !slices.Equal(calls, []string{"add route 100.70.1.2/32", "delete route 100.70.1.2/32"}) {
		t.Fatalf("routes: %v", calls)
	}
	if _, err := iface.Read([][]byte{make([]byte, 64)}, []int{0}, 0); err == nil {
		t.Fatal("a read with no room for the family header")
	}
}

// Under exits the binding goes on first, to the unscoped default route's interface, then IPv4's halves and IPv6's, then
// the kick; a sync with nothing moved changes nothing, a default route that moved binds again, and off exits the halves
// come off, IPv4's first, before the binding.
func TestTunDarwinExitsBindTheTransportFirst(t *testing.T) {
	world := newTestDarwinWorld(t)
	iface := world.open(t)
	world.kernel.take()
	defaultRoute, err := iface.SetExits(true)
	if err != nil || !defaultRoute {
		t.Fatalf("exits: %v %v", defaultRoute, err)
	}
	if binding := <-world.bindings; binding != [2]uint32{4, 4} {
		t.Fatalf("bound to %v", binding)
	}
	<-world.kicks
	if calls := world.kernel.take(); !slices.Equal(calls, testDarwinHalvesCalls("add")) {
		t.Fatalf("halves: %v", calls)
	}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute || 0 < len(world.kernel.take()) ||
		0 < len(world.bindings) || 0 < len(world.kicks) {
		t.Fatalf("again: %v %v", defaultRoute, err)
	}
	// the host's default route moved to another interface: the transport follows it
	world.kernel.stateLock.Lock()
	world.kernel.table = world.kernel.table[1:]
	world.kernel.stateLock.Unlock()
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if binding := <-world.bindings; binding != [2]uint32{5, 5} {
		t.Fatalf("bound again to %v", binding)
	}
	<-world.kicks
	defaultRoute, err = iface.SetExits(false)
	if err != nil || defaultRoute {
		t.Fatalf("off: %v %v", defaultRoute, err)
	}
	if calls := world.kernel.take(); !slices.Equal(calls, testDarwinHalvesCalls("delete")) {
		t.Fatalf("off: %v", calls)
	}
	if binding := <-world.bindings; binding != [2]uint32{0, 0} {
		t.Fatalf("unbound to %v", binding)
	}
}

// No default route outside the tun, or a half another program holds, holds the exits and leaves nothing on: no half,
// no binding.
func TestTunDarwinExitsHoldWhatTheHostRefuses(t *testing.T) {
	world := newTestDarwinWorld(t)
	iface := world.open(t)
	world.kernel.take()
	table := world.kernel.table
	world.kernel.table = nil
	if defaultRoute, err := iface.SetExits(true); defaultRoute || !errors.Is(err, errUrTunExitsNoDefault) {
		t.Fatalf("no default: %v %v", defaultRoute, err)
	}
	if 0 < len(world.bindings) || 0 < len(world.kernel.take()) {
		t.Fatal("something went on")
	}
	world.kernel.table = table
	halves := urTunExitsHalves()
	world.kernel.addErrs[halves[1]] = unix.EEXIST
	if defaultRoute, err := iface.SetExits(true); defaultRoute || !errors.Is(err, errUrTunExitsHalfInUse) {
		t.Fatalf("a held half: %v %v", defaultRoute, err)
	}
	if calls := world.kernel.take(); !slices.Equal(calls, []string{"add route " + halves[0].String(), "delete route " + halves[0].String()}) {
		t.Fatalf("a held half: %v", calls)
	}
	if bound, unbound := <-world.bindings, <-world.bindings; bound != [2]uint32{4, 4} || unbound != [2]uint32{0, 0} {
		t.Fatalf("bindings %v %v", bound, unbound)
	}
}

// IPv6's halves under exits (QD-881). Where the host has an IPv6 default route, the binding takes its interface for IPv6
// and a refusal of an IPv6 half holds the exits, nothing left on, the error saying IPv6 would leave outside them; where
// it has none, the refusal holds nothing: IPv4's halves stand, kicked once, what of IPv6's went on comes off, and the
// next SetExits tries IPv6's again with no kick, putting them on once the kernel takes them. A half of IPv6's another
// program holds holds the exits on either host.
func TestTunDarwinExitsTakeIpv6sHalves(t *testing.T) {
	ipv6Halves := urTunExitsIpv6Halves()
	ipv6DefaultRoute := urTunDarwinRoute{dst: netip.MustParsePrefix("::/0"), index: 6,
		gateway: netip.MustParseAddr("fe80::1"), flags: unix.RTF_UP | unix.RTF_GATEWAY}

	// a host with IPv6 of its own: the refusal of the second IPv6 half holds the exits
	world := newTestDarwinWorld(t)
	world.kernel.table = append(world.kernel.table, ipv6DefaultRoute)
	iface := world.open(t)
	world.kernel.take()
	world.kernel.addErrs[ipv6Halves[1]] = unix.ENETUNREACH
	defaultRoute, err := iface.SetExits(true)
	if defaultRoute || err == nil || !strings.Contains(err.Error(), "IPv6 would leave outside the exits") ||
		errors.Is(err, errUrTunExitsHalfInUse) {
		t.Fatalf("a host with IPv6: %v %v", defaultRoute, err)
	}
	want := append(testDarwinHalvesCalls("add")[:3], testDarwinHalvesCalls("delete")[:3]...)
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("a host with IPv6: %v", calls)
	}
	if bound, unbound := <-world.bindings, <-world.bindings; bound != [2]uint32{4, 6} || unbound != [2]uint32{0, 0} {
		t.Fatalf("a host with IPv6: bindings %v %v", bound, unbound)
	}
	if 0 < len(world.kicks) || 0 < len(iface.exitsHalves) {
		t.Fatalf("a host with IPv6: kicked, or halves %v left", iface.exitsHalves)
	}

	// a host with none: IPv4's halves stand, and IPv6's that went on comes back off
	world = newTestDarwinWorld(t)
	iface = world.open(t)
	world.kernel.take()
	world.kernel.addErrs[ipv6Halves[1]] = unix.ENETUNREACH
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("a host with no IPv6: %v %v", defaultRoute, err)
	}
	want = append(testDarwinHalvesCalls("add")[:3], "delete route "+ipv6Halves[0].String())
	if calls := world.kernel.take(); !slices.Equal(calls, want) || !slices.Equal(iface.exitsHalves, urTunExitsHalves()) {
		t.Fatalf("a host with no IPv6: %v, halves %v", calls, iface.exitsHalves)
	}
	if binding := <-world.bindings; binding != [2]uint32{4, 4} {
		t.Fatalf("a host with no IPv6: bound to %v", binding)
	}
	<-world.kicks
	// the next sync's SetExits tries IPv6's again and kicks nothing
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute || 0 < len(world.kicks) {
		t.Fatalf("again: %v %v", defaultRoute, err)
	}
	want = []string{"add route " + ipv6Halves[0].String(), "delete route " + ipv6Halves[0].String()}
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("again: %v", calls)
	}
	// once the kernel takes them they go on
	delete(world.kernel.addErrs, ipv6Halves[1])
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("taken: %v %v", defaultRoute, err)
	}
	if calls := world.kernel.take(); !slices.Equal(calls, testDarwinHalvesCalls("add")[2:]) {
		t.Fatalf("taken: %v", calls)
	}
	<-world.kicks
	if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
		t.Fatalf("off: %v %v", defaultRoute, err)
	}
	if calls := world.kernel.take(); !slices.Equal(calls, testDarwinHalvesCalls("delete")) {
		t.Fatalf("off: %v", calls)
	}

	// another program holds an IPv6 half: held on a host with no IPv6 too
	world = newTestDarwinWorld(t)
	iface = world.open(t)
	world.kernel.take()
	world.kernel.addErrs[ipv6Halves[0]] = unix.EEXIST
	if defaultRoute, err := iface.SetExits(true); defaultRoute || !errors.Is(err, errUrTunExitsHalfInUse) {
		t.Fatalf("a held IPv6 half: %v %v", defaultRoute, err)
	}
	want = append(testDarwinHalvesCalls("add")[:2], testDarwinHalvesCalls("delete")[:2]...)
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("a held IPv6 half: %v", calls)
	}
}

// Close takes the exits, IPv6's halves among them, the resolver files, the routes and the addresses off, and closes the
// device.
func TestTunDarwinCloseRemovesEverything(t *testing.T) {
	world := newTestDarwinWorld(t)
	iface := world.open(t)
	world.kernel.take()
	iface.SetAddresses([]netip.Addr{netip.MustParseAddr("100.70.9.9")})
	iface.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.70.1.2/32")})
	iface.SetExits(true)
	if step, err := iface.SetResolver(netip.MustParseAddr("100.70.0.53"), []string{"net.example"}); step != "" || err != nil {
		t.Fatalf("resolver: %q %v", step, err)
	}
	world.kernel.take()
	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}
	want := append(testDarwinHalvesCalls("delete"), "delete route 100.70.1.2/32", "delete address 100.70.9.9")
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("close: %v", calls)
	}
	if _, err := os.Stat(filepath.Join(world.system.resolverDirectory, "net.example")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the resolver file stayed: %v", err)
	}
	select {
	case <-world.device.closed:
	default:
		t.Fatal("the device stayed open")
	}
	if err := iface.SetAddresses(nil); !errors.Is(err, errUrTunClosed) {
		t.Fatalf("after close: %v", err)
	}
}

// The host's own routes beside its default routes, as a host on 192.0.2.0/24 holds them: its subnet on link, its own
// address local, a neighbor's cached link address, and loopback's.
func testDarwinHostTable() []urTunDarwinRoute {
	return []urTunDarwinRoute{
		{dst: netip.MustParsePrefix("192.0.2.0/24"), index: 4, flags: unix.RTF_UP | unix.RTF_CLONING},
		{dst: netip.MustParsePrefix("192.0.2.10/32"), index: 1, flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_LOCAL},
		{dst: netip.MustParsePrefix("192.0.2.1/32"), index: 4, flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_LLINFO | unix.RTF_WASCLONED},
		{dst: netip.MustParsePrefix("127.0.0.0/8"), index: 1, flags: unix.RTF_UP},
	}
}

// The carve of that host: its own address, its gateway, a resolver on its link, loopback, an IPv6 address, and
// resolvers beyond its networks.
func testDarwinCarve(offLink ...string) []netip.Addr {
	carve := []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("2001:db8::53")}
	for _, address := range offLink {
		carve = append(carve, netip.MustParseAddr(address))
	}
	return carve
}

// Under exits a carved address the host reaches only by its default route, an off-link resolver, takes a host route
// by that route's gateway and interface, before the halves go on; the host's own address, its gateway, an on-link
// resolver, loopback and an IPv6 address take none. Off exits the carve waits. A sync that changed nothing writes
// nothing, though the host route now reads in the table; a carve that changes adds and removes them; and leaving exits
// takes them off after the halves and before the binding.
func TestTunDarwinCarvedHostRoutesFollowTheCarve(t *testing.T) {
	world := newTestDarwinWorld(t)
	world.kernel.table = append(world.kernel.table, testDarwinHostTable()...)
	iface := world.open(t)
	world.kernel.take()
	if err := iface.SetCarved(testDarwinCarve("203.0.113.53")); err != nil {
		t.Fatal(err)
	}
	if calls := world.kernel.take(); 0 < len(calls) {
		t.Fatalf("off exits: %v", calls)
	}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("exits: %v %v", defaultRoute, err)
	}
	halves := urTunExitsHalves()
	want := append([]string{"add host route 203.0.113.53 by 192.0.2.1 on 4"}, testDarwinHalvesCalls("add")...)
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("exits: %v", calls)
	}
	// the halves read in the table from here, through the tun
	world.kernel.replaceRoutes(func(held urTunDarwinRoute) bool { return false },
		urTunDarwinRoute{dst: halves[0], index: 99, flags: unix.RTF_UP | unix.RTF_STATIC},
		urTunDarwinRoute{dst: halves[1], index: 99, flags: unix.RTF_UP | unix.RTF_STATIC})
	// a sync with nothing changed
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if err := iface.SetCarved(testDarwinCarve("203.0.113.53")); err != nil {
		t.Fatal(err)
	}
	if calls := world.kernel.take(); 0 < len(calls) {
		t.Fatalf("nothing changed: %v", calls)
	}
	// the carve changes: one resolver leaves it and another joins
	if err := iface.SetCarved(testDarwinCarve("203.0.113.54")); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete host route 203.0.113.53 by 192.0.2.1 on 4", "add host route 203.0.113.54 by 192.0.2.1 on 4"}
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("a changed carve: %v", calls)
	}
	// a route of the host's own comes to hold the address: its host route would move it off that link
	world.kernel.replaceRoutes(func(held urTunDarwinRoute) bool { return false },
		urTunDarwinRoute{dst: netip.MustParsePrefix("203.0.113.0/24"), index: 6, flags: unix.RTF_UP | unix.RTF_CLONING})
	if err := iface.SetCarved(testDarwinCarve("203.0.113.54", "198.51.100.53")); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete host route 203.0.113.54 by 192.0.2.1 on 4", "add host route 198.51.100.53 by 192.0.2.1 on 4"}
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("an address a route came to hold: %v", calls)
	}
	<-world.bindings
	defaultRoute, err := iface.SetExits(false)
	if err != nil || defaultRoute {
		t.Fatalf("off: %v %v", defaultRoute, err)
	}
	want = append(testDarwinHalvesCalls("delete"), "delete host route 198.51.100.53 by 192.0.2.1 on 4")
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("off: %v", calls)
	}
	if binding := <-world.bindings; binding != [2]uint32{0, 0} {
		t.Fatalf("unbound to %v", binding)
	}
	// off exits the carve waits again
	if err := iface.SetCarved(testDarwinCarve("203.0.113.53", "198.51.100.53")); err != nil {
		t.Fatal(err)
	}
	if calls := world.kernel.take(); 0 < len(calls) {
		t.Fatalf("off exits again: %v", calls)
	}
}

// A default route that moves takes the host routes with it: to a new gateway on the same interface with no new
// binding, and to another interface's route with one, the old route off and the new one on at the sync's SetExits.
func TestTunDarwinCarvedHostRoutesFollowTheDefaultRoute(t *testing.T) {
	world := newTestDarwinWorld(t)
	world.kernel.table = append(world.kernel.table, testDarwinHostTable()...)
	iface := world.open(t)
	if err := iface.SetCarved(testDarwinCarve("203.0.113.53")); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	<-world.bindings
	<-world.kicks
	world.kernel.take()
	isDefault := func(held urTunDarwinRoute) bool {
		return held.dst.Bits() == 0 && held.flags&unix.RTF_IFSCOPE == 0
	}
	// another gateway on the same link
	world.kernel.replaceRoutes(isDefault, urTunDarwinRoute{dst: netip.MustParsePrefix("0.0.0.0/0"), index: 4,
		gateway: netip.MustParseAddr("192.0.2.254"), flags: unix.RTF_UP | unix.RTF_GATEWAY})
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	want := []string{"delete host route 203.0.113.53 by 192.0.2.1 on 4", "add host route 203.0.113.53 by 192.0.2.254 on 4"}
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("a new gateway: %v", calls)
	}
	if 0 < len(world.bindings) || 0 < len(world.kicks) {
		t.Fatal("bound again on the same interface")
	}
	if err := iface.SetCarved(testDarwinCarve("203.0.113.53")); err != nil || 0 < len(world.kernel.take()) {
		t.Fatalf("the carve after the move: %v", err)
	}
	// the unscoped default route goes: the scoped one, on another interface, is the host's
	world.kernel.replaceRoutes(isDefault)
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if binding := <-world.bindings; binding != [2]uint32{5, 5} {
		t.Fatalf("bound again to %v", binding)
	}
	<-world.kicks
	want = []string{"delete host route 203.0.113.53 by 192.0.2.254 on 4", "add host route 203.0.113.53 by 198.51.100.1 on 5"}
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("another interface: %v", calls)
	}
	// a default route that names no gateway: the host route goes by its interface alone
	world.kernel.replaceRoutes(func(held urTunDarwinRoute) bool { return held.dst.Bits() == 0 },
		urTunDarwinRoute{dst: netip.MustParsePrefix("0.0.0.0/0"), index: 7, flags: unix.RTF_UP})
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	want = []string{"delete host route 203.0.113.53 by 198.51.100.1 on 5", "add host route 203.0.113.53 by the link on 7"}
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("a default route with no gateway: %v", calls)
	}
}

// What the host refuses of a host route: one whose address another route holds by the time it is written is left to
// that route and never removed; one the kernel refuses is counted, with no address in the words, and tried again at
// the next SetCarved; one that will not come off is kept and tried again; and exits another program's half holds
// leave no host route on.
func TestTunDarwinCarvedHostRoutesHoldWhatTheHostRefuses(t *testing.T) {
	world := newTestDarwinWorld(t)
	world.kernel.table = append(world.kernel.table, testDarwinHostTable()...)
	iface := world.open(t)
	world.kernel.take()
	first := netip.MustParseAddr("203.0.113.53")
	second := netip.MustParseAddr("203.0.113.54")
	world.kernel.hostAddErrs[first] = unix.EEXIST
	world.kernel.hostAddErrs[second] = unix.ENETUNREACH
	if err := iface.SetCarved(testDarwinCarve(first.String(), second.String())); err != nil {
		t.Fatal(err)
	}
	// SetExits refuses nothing for a host route
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("exits: %v %v", defaultRoute, err)
	}
	world.kernel.take()
	err := iface.SetCarved(testDarwinCarve(first.String(), second.String()))
	if err == nil || strings.Contains(err.Error(), "203.0.113") ||
		!strings.Contains(err.Error(), "1 host routes of carved addresses did not go on") {
		t.Fatalf("a refused host route: %v", err)
	}
	if calls := world.kernel.take(); 0 < len(calls) {
		t.Fatalf("refused: %v", calls)
	}
	// the kernel takes it at the next call
	delete(world.kernel.hostAddErrs, second)
	if err := iface.SetCarved(testDarwinCarve(first.String(), second.String())); err != nil {
		t.Fatal(err)
	}
	if calls := world.kernel.take(); !slices.Equal(calls, []string{"add host route 203.0.113.54 by 192.0.2.1 on 4"}) {
		t.Fatalf("tried again: %v", calls)
	}
	// one that will not come off stays this interface's, and goes at the next call
	world.kernel.hostDeleteErrs[second] = unix.ENOBUFS
	err = iface.SetCarved(testDarwinCarve())
	if err == nil || strings.Contains(err.Error(), "203.0.113") ||
		!strings.Contains(err.Error(), "1 host routes of addresses no longer carved did not come off") {
		t.Fatalf("a host route that would not come off: %v", err)
	}
	delete(world.kernel.hostDeleteErrs, second)
	if err := iface.SetCarved(testDarwinCarve()); err != nil {
		t.Fatal(err)
	}
	// the one another's route held was never this interface's to remove
	if calls := world.kernel.take(); !slices.Equal(calls, []string{"delete host route 203.0.113.54 by 192.0.2.1 on 4"}) {
		t.Fatalf("removed: %v", calls)
	}
	if _, err := iface.SetExits(false); err != nil {
		t.Fatal(err)
	}
	world.kernel.take()
	// a half another program holds: the host routes that went on before the halves come off with the partial set
	delete(world.kernel.hostAddErrs, first)
	halves := urTunExitsHalves()
	world.kernel.addErrs[halves[1]] = unix.EEXIST
	if err := iface.SetCarved(testDarwinCarve(first.String())); err != nil {
		t.Fatal(err)
	}
	if defaultRoute, err := iface.SetExits(true); defaultRoute || !errors.Is(err, errUrTunExitsHalfInUse) {
		t.Fatalf("a held half: %v %v", defaultRoute, err)
	}
	want := []string{"add host route 203.0.113.53 by 192.0.2.1 on 4", "add route " + halves[0].String(),
		"delete route " + halves[0].String(), "delete host route 203.0.113.53 by 192.0.2.1 on 4"}
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("a held half: %v", calls)
	}
}

// Close takes the carved addresses' host routes off with the exits, after the halves, and a closed interface takes
// no carve.
func TestTunDarwinCloseRemovesTheCarvedHostRoutes(t *testing.T) {
	world := newTestDarwinWorld(t)
	world.kernel.table = append(world.kernel.table, testDarwinHostTable()...)
	iface := world.open(t)
	iface.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.70.1.2/32")})
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if err := iface.SetCarved(testDarwinCarve("203.0.113.53", "198.51.100.53")); err != nil {
		t.Fatal(err)
	}
	world.kernel.take()
	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}
	want := append(testDarwinHalvesCalls("delete"), "delete host route 198.51.100.53 by 192.0.2.1 on 4",
		"delete host route 203.0.113.53 by 192.0.2.1 on 4", "delete route 100.70.1.2/32")
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("close: %v", calls)
	}
	if err := iface.SetCarved(testDarwinCarve("203.0.113.53")); !errors.Is(err, errUrTunClosed) {
		t.Fatalf("after close: %v", err)
	}
	for _, held := range world.kernel.table {
		if held.flags == testDarwinHostRouteFlags {
			t.Fatalf("a host route stayed: %+v", held)
		}
	}
}

// A half that will not come off at close goes with the device, so the host routes that waited on it come off once the
// device is closed: none outlives the tun.
func TestTunDarwinCloseRemovesTheCarvedHostRoutesOfAHeldHalf(t *testing.T) {
	world := newTestDarwinWorld(t)
	world.kernel.table = append(world.kernel.table, testDarwinHostTable()...)
	iface := world.open(t)
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	if err := iface.SetCarved(testDarwinCarve("203.0.113.53")); err != nil {
		t.Fatal(err)
	}
	halves := urTunExitsHalves()
	world.kernel.deleteErrs = map[netip.Prefix]error{halves[1]: unix.ENOBUFS}
	// leaving exits keeps the host route while an IPv4 half is still on
	world.kernel.take()
	if defaultRoute, err := iface.SetExits(false); err == nil || !defaultRoute {
		t.Fatalf("a half that stays: %v %v", defaultRoute, err)
	}
	want := []string{"delete route " + halves[0].String()}
	for _, half := range urTunExitsIpv6Halves() {
		want = append(want, "delete route "+half.String())
	}
	if calls := world.kernel.take(); !slices.Equal(calls, want) {
		t.Fatalf("a half that stays: %v", calls)
	}
	if err := iface.Close(); err == nil {
		t.Fatal("close answered nothing of the half that would not come off")
	}
	if calls := world.kernel.take(); !slices.Equal(calls, []string{"delete host route 203.0.113.53 by 192.0.2.1 on 4"}) {
		t.Fatalf("close: %v", calls)
	}
	for _, held := range world.kernel.table {
		if held.flags == testDarwinHostRouteFlags {
			t.Fatalf("a host route stayed: %+v", held)
		}
	}
}

// Which routes of the table reach a carved address: a scoped route, a cached entry and a route through the tun do
// not, so the address takes a host route; a route of the tun's own inside which it lies leaves it to the bridge; and
// with no default route but the tun's, nothing goes on.
func TestTunDarwinCarvedHostRoutesReadTheTable(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.53")
	gateway := netip.MustParseAddr("192.0.2.1")
	defaultRoute := urTunDarwinRoute{dst: netip.MustParsePrefix("0.0.0.0/0"), index: 4, gateway: gateway,
		flags: unix.RTF_UP | unix.RTF_GATEWAY}
	want := []urTunHostRoute{{address: address, gateway: gateway, link: 4}}
	inside := netip.MustParsePrefix("203.0.113.0/24")
	for name, held := range map[string]urTunDarwinRoute{
		"a scoped route":          {dst: inside, index: 6, flags: unix.RTF_UP | unix.RTF_IFSCOPE},
		"a cached entry":          {dst: netip.PrefixFrom(address, 32), index: 6, flags: unix.RTF_UP | unix.RTF_HOST | unix.RTF_LLINFO},
		"a route through the tun": {dst: inside, index: 99, flags: unix.RTF_UP},
		"a route that is down":    {dst: inside, index: 6},
		"IPv6's default route":    {dst: netip.MustParsePrefix("::/0"), index: 6, flags: unix.RTF_UP},
	} {
		table := []urTunDarwinRoute{defaultRoute, held}
		if hostRoutes := urTunDarwinHostRoutes([]netip.Addr{address}, table, 99, nil, nil); !slices.Equal(hostRoutes, want) {
			t.Errorf("%s: %v", name, hostRoutes)
		}
	}
	table := []urTunDarwinRoute{defaultRoute, {dst: inside, index: 6, flags: unix.RTF_UP}}
	if hostRoutes := urTunDarwinHostRoutes([]netip.Addr{address}, table, 99, nil, nil); 0 < len(hostRoutes) {
		t.Errorf("a route of the host's own: %v", hostRoutes)
	}
	// another program's host route at the address is the host's way to it, and this interface's own is not
	table = []urTunDarwinRoute{defaultRoute, {dst: netip.PrefixFrom(address, 32), index: 4, gateway: gateway, flags: testDarwinHostRouteFlags}}
	if hostRoutes := urTunDarwinHostRoutes([]netip.Addr{address}, table, 99, nil, nil); 0 < len(hostRoutes) {
		t.Errorf("another's host route: %v", hostRoutes)
	}
	if hostRoutes := urTunDarwinHostRoutes([]netip.Addr{address}, table, 99, nil, want); !slices.Equal(hostRoutes, want) {
		t.Errorf("its own host route: %v", hostRoutes)
	}
	table = []urTunDarwinRoute{defaultRoute}
	if hostRoutes := urTunDarwinHostRoutes([]netip.Addr{address}, table, 99, []netip.Prefix{inside}, nil); 0 < len(hostRoutes) {
		t.Errorf("inside a route of the tun's own: %v", hostRoutes)
	}
	if hostRoutes := urTunDarwinHostRoutes([]netip.Addr{address}, table, 4, nil, nil); 0 < len(hostRoutes) {
		t.Errorf("no default route but the tun's: %v", hostRoutes)
	}
}

// A host route's message: a host route by the gateway, static, with the interface named, which the dump's parse reads
// back with its gateway; and with no gateway, the interface's link address in the gateway's place.
func TestTunDarwinHostRouteMessagesReadBack(t *testing.T) {
	address := netip.MustParseAddr("203.0.113.53")
	gateway := netip.MustParseAddr("192.0.2.1")
	for _, messageType := range []int{unix.RTM_ADD, unix.RTM_DELETE} {
		wire, err := urTunDarwinHostRouteMessage(messageType, 4, address, gateway, 7, 9).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, wire)
		if err != nil || len(messages) != 1 {
			t.Fatalf("%d messages, %v", len(messages), err)
		}
		parsed, ok := messages[0].(*route.RouteMessage)
		if !ok || parsed.Type != messageType || parsed.Index != 4 || parsed.Seq != 9 ||
			parsed.Flags != unix.RTF_UP|unix.RTF_STATIC|unix.RTF_HOST|unix.RTF_GATEWAY {
			t.Fatalf("%+v", messages[0])
		}
		held, ok := urTunDarwinParseRoute(parsed)
		if !ok || held.dst != netip.PrefixFrom(address, 32) || held.index != 4 || held.gateway != gateway {
			t.Fatalf("read back as %+v", held)
		}
		if link, ok := parsed.Addrs[unix.RTAX_IFP].(*route.LinkAddr); !ok || link.Index != 4 {
			t.Fatalf("the interface: %+v", parsed.Addrs[unix.RTAX_IFP])
		}
		if parsed.Addrs[unix.RTAX_NETMASK] != nil {
			t.Fatalf("a host route with a mask: %+v", parsed.Addrs[unix.RTAX_NETMASK])
		}
	}
	wire, err := urTunDarwinHostRouteMessage(unix.RTM_ADD, 7, address, netip.Addr{}, 7, 9).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	messages, err := route.ParseRIB(route.RIBTypeRoute, wire)
	if err != nil || len(messages) != 1 {
		t.Fatalf("%d messages, %v", len(messages), err)
	}
	parsed := messages[0].(*route.RouteMessage)
	if link, ok := parsed.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr); !ok || link.Index != 7 ||
		parsed.Flags&unix.RTF_GATEWAY != 0 || parsed.Flags&unix.RTF_HOST == 0 {
		t.Fatalf("no gateway: %+v", parsed)
	}
}

// The resolver files: one a zone, lowercase, marked as the tun's; another program's file for a zone is left and the
// step names it; a zone the state no longer holds loses its file; a name that is no zone writes nothing; the revert
// takes the tun's own files alone; and the local addresses read the other program's nameserver, not the tun's.
func TestTunDarwinResolverFiles(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "resolver")
	settings := testUrTunSettings()
	log := sidecar.NewNoopLogger()
	resolver := netip.MustParseAddr("100.70.0.53")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(directory, "taken.example")
	if err := os.WriteFile(foreign, []byte("nameserver 192.0.2.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	step, set := urTunDarwinSetResolver(directory, "ur-test", resolver,
		[]string{"net.example", "Other.Example.", "taken.example", "../etc/passwd"}, settings, log)
	if !set || !strings.Contains(step, filepath.Join(urTunDarwinResolverDirectory, "taken.example")) ||
		!strings.Contains(step, "nameserver 100.70.0.53") || strings.Contains(step, "net.example") {
		t.Fatalf("set %v, step %q", set, step)
	}
	for _, zone := range []string{"net.example", "other.example"} {
		content, err := os.ReadFile(filepath.Join(directory, zone))
		if err != nil || string(content) != urTunDarwinResolverMarker("ur-test")+"\nnameserver 100.70.0.53\n" {
			t.Fatalf("%s: %q %v", zone, content, err)
		}
	}
	if content, _ := os.ReadFile(foreign); string(content) != "nameserver 192.0.2.53\n" {
		t.Fatalf("the foreign file reads %q", content)
	}
	if entries, _ := os.ReadDir(directory); len(entries) != 3 {
		t.Fatalf("%d files", len(entries))
	}
	if scoped := urTunDarwinScopedResolvers(directory); !slices.Equal(scoped, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
		t.Fatalf("scoped %v", scoped)
	}
	// the state drops a zone: its file goes
	if step, _ := urTunDarwinSetResolver(directory, "ur-test", resolver, []string{"net.example"}, settings, log); step != "" {
		t.Fatalf("step %q", step)
	}
	if _, err := os.Stat(filepath.Join(directory, "other.example")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a dropped zone's file: %v", err)
	}
	// another instance's file is not this tun's to remove
	urTunDarwinSetResolver(directory, "ur-other", resolver, []string{"else.example"}, settings, log)
	urTunDarwinRevertResolver(directory, "ur-test")
	entries, _ := os.ReadDir(directory)
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if !slices.Equal(names, []string{"else.example", "taken.example"}) {
		t.Fatalf("after the revert: %v", names)
	}
}

// The local addresses: every interface's but the tun's, lo0's among them, the gateways of routes not through the tun,
// and the resolvers of resolv.conf and of the resolver files no tun wrote, less exclude.
func TestTunDarwinReadsTheLocalAddresses(t *testing.T) {
	world := newTestDarwinWorld(t)
	world.kernel.table = append(world.kernel.table,
		urTunDarwinRoute{dst: netip.MustParsePrefix("10.20.0.0/16"), index: 99, gateway: netip.MustParseAddr("100.70.0.1"), flags: unix.RTF_UP | unix.RTF_GATEWAY})
	if err := os.WriteFile(world.system.resolvConfPath, []byte("nameserver 203.0.113.53\nnameserver 100.70.0.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	urTunDarwinSetResolver(world.system.resolverDirectory, "ur-test", netip.MustParseAddr("100.70.0.53"),
		[]string{"net.example"}, world.system.settings, world.system.log)
	if err := os.WriteFile(filepath.Join(world.system.resolverDirectory, "vpn.example"), []byte("nameserver 198.51.100.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	addresses, err := world.system.LocalAddresses("utun99", []netip.Addr{netip.MustParseAddr("100.70.0.53")})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"127.0.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.53", "198.51.100.53"} {
		if !slices.Contains(addresses, netip.MustParseAddr(want)) {
			t.Errorf("no %s in %v", want, addresses)
		}
	}
	for _, unwanted := range []string{"100.70.0.53", "100.70.0.1"} {
		if slices.Contains(addresses, netip.MustParseAddr(unwanted)) {
			t.Errorf("%s in %v", unwanted, addresses)
		}
	}
	if !slices.IsSortedFunc(addresses, netip.Addr.Compare) {
		t.Fatalf("unsorted: %v", addresses)
	}
}

// Another interface's route inside the block is an app's bridge holding it; a neighbor's cached address, a route
// that covers the block from outside and the tun's own are not.
func TestTunDarwinFindsTheBlockRoutedElsewhere(t *testing.T) {
	world := newTestDarwinWorld(t)
	block := netip.MustParsePrefix("100.70.0.0/16")
	world.kernel.table = []urTunDarwinRoute{
		{dst: netip.MustParsePrefix("100.64.0.0/10"), index: 4, flags: unix.RTF_UP},
		{dst: netip.MustParsePrefix("100.70.1.1/32"), index: 4, flags: unix.RTF_UP | unix.RTF_LLINFO | unix.RTF_WASCLONED},
		{dst: netip.MustParsePrefix("100.70.2.0/24"), index: 99, flags: unix.RTF_UP},
	}
	if holder, err := world.system.RoutedElsewhere("utun99", block); err != nil || holder != "" {
		t.Fatalf("held by %q: %v", holder, err)
	}
	world.kernel.table = append(world.kernel.table, urTunDarwinRoute{dst: block, index: 4242, flags: unix.RTF_UP})
	if holder, err := world.system.RoutedElsewhere("utun99", block); err != nil || holder != "index 4242" {
		t.Fatalf("held by %q: %v", holder, err)
	}
}

// The routing socket's watch on this machine: changed at once, and the watch ends with its context.
func TestTunDarwinWatchesTheRoutingSocket(t *testing.T) {
	system := newUrTunDarwinSystem(testUrTunSettings(), nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes := make(chan struct{}, 1024)
	done := make(chan error, 1)
	go func() {
		done <- system.WatchLocal(ctx, func() {
			select {
			case changes <- struct{}{}:
			default:
			}
		})
	}()
	select {
	case <-changes:
	case <-time.After(urTestTimeout):
		t.Fatal("no first change")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(urTestTimeout):
		t.Fatal("the watch did not end")
	}
	if !urTunDarwinLocalChange([]byte{0, 0, 0, unix.RTM_NEWADDR}) || urTunDarwinLocalChange([]byte{0, 0, 0, unix.RTM_MISS}) {
		t.Fatal("the change filter")
	}
}

// A real utun, as root only: the device comes up with the host's overlay address and the bridge's routes, its names'
// file goes in a resolver directory of the test's, and the close takes the routes and the device away.
func TestTunDarwinDeviceCarriesTheBridge(t *testing.T) {
	if os.Getenv("UR_TUN_TEST_DEVICE") != "darwin" || unix.Geteuid() != 0 {
		t.Skip("creates a utun and changes the host's routes: runs only as root with UR_TUN_TEST_DEVICE=darwin")
	}
	settings := testUrTunSettings()
	system := newUrTunDarwinSystem(settings, nil).(*urTunDarwinSystem)
	system.resolverDirectory = t.TempDir()
	tunBridge := newTestTunBridge()
	tun, err := startUrTun(context.Background(), &urTunArgs{
		Name:      "ur-test",
		NetworkId: sidecar.NewId(),
		System:    system,
		Bridge:    tunBridge,
		Links:     &testTunLinks{},
		Settings:  settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	name := tun.status().Device
	if !strings.HasPrefix(name, "utun") {
		t.Fatalf("device %q", name)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatal(err)
	}
	addresses, _ := link.Addrs()
	if !slices.ContainsFunc(addresses, func(address net.Addr) bool {
		return strings.HasPrefix(address.String(), "100.70.9.9")
	}) {
		t.Fatalf("addresses %v", addresses)
	}
	routes, err := system.kernel.Routes()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range tunBridge.Routes() {
		if !slices.ContainsFunc(routes, func(held urTunDarwinRoute) bool { return held.dst == want && held.index == link.Index }) {
			t.Errorf("no route %s through %s", want, name)
		}
	}
	if _, err := os.Stat(filepath.Join(system.resolverDirectory, "net.example")); err != nil {
		t.Fatal(err)
	}
	tun.close()
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("%s outlived the tun", name)
	}
	routes, _ = system.kernel.Routes()
	if slices.ContainsFunc(routes, func(held urTunDarwinRoute) bool { return held.index == link.Index }) {
		t.Fatal("a route outlived the tun")
	}
}

// On this machine's kernel, as root: a carved address's host route goes on by the host's own default route's gateway
// and interface, reads back in the table that way, and comes off, by the routing socket's messages as the tun writes
// them. The address is documentation's, which no host holds. As a person, the kernel refuses the same message.
func TestTunDarwinDeviceTakesAHostRoute(t *testing.T) {
	kernel := &urTunDarwinSockets{}
	table, err := kernel.Routes()
	if err != nil {
		t.Fatal(err)
	}
	address := netip.MustParseAddr("203.0.113.53")
	hostRoutes := urTunDarwinHostRoutes([]netip.Addr{address}, table, 0, nil, nil)
	if os.Getenv("UR_TUN_TEST_DEVICE") != "darwin" || unix.Geteuid() != 0 {
		if unix.Geteuid() != 0 && len(hostRoutes) == 1 {
			err := kernel.AddHostRoute(int(hostRoutes[0].link), address, hostRoutes[0].gateway)
			if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) {
				t.Fatalf("a person's host route: %v", err)
			}
			t.Logf("a person's host route is refused: %v", err)
		}
		t.Skip("changes the host's routes: runs only as root with UR_TUN_TEST_DEVICE=darwin")
	}
	if len(hostRoutes) != 1 {
		t.Skipf("this host reaches the address by a route of its own, or has no default route: %d host routes", len(hostRoutes))
	}
	hostRoute := hostRoutes[0]
	if err := kernel.AddHostRoute(int(hostRoute.link), address, hostRoute.gateway); err != nil {
		t.Fatal(err)
	}
	removed := false
	t.Cleanup(func() {
		if !removed {
			kernel.DeleteHostRoute(int(hostRoute.link), address, hostRoute.gateway)
		}
	})
	isHostRoute := func(held urTunDarwinRoute) bool {
		return held.dst == netip.PrefixFrom(address, 32) && held.index == int(hostRoute.link) &&
			held.gateway == hostRoute.gateway && held.flags&unix.RTF_HOST != 0 && held.flags&unix.RTF_STATIC != 0
	}
	if table, err = kernel.Routes(); err != nil || !slices.ContainsFunc(table, isHostRoute) {
		t.Fatalf("the host route does not read back: %v", err)
	}
	// its own host route is not the host's way to the address, and another's would be
	if again := urTunDarwinHostRoutes([]netip.Addr{address}, table, 0, nil, hostRoutes); !slices.Equal(again, hostRoutes) {
		t.Fatalf("over its own host route: %d host routes", len(again))
	}
	if other := urTunDarwinHostRoutes([]netip.Addr{address}, table, 0, nil, nil); 0 < len(other) {
		t.Fatalf("over another's host route: %d host routes", len(other))
	}
	if err := kernel.AddHostRoute(int(hostRoute.link), address, hostRoute.gateway); !errors.Is(err, unix.EEXIST) {
		t.Fatalf("a second add: %v", err)
	}
	if err := kernel.DeleteHostRoute(int(hostRoute.link), address, hostRoute.gateway); err != nil {
		t.Fatal(err)
	}
	removed = true
	if err := kernel.DeleteHostRoute(int(hostRoute.link), address, hostRoute.gateway); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("a second delete: %v", err)
	}
	if table, err = kernel.Routes(); err != nil || slices.ContainsFunc(table, isHostRoute) {
		t.Fatalf("the host route stayed: %v", err)
	}
}

// The routing table on this machine, which needs no root to read: loopback's own route is in it, through lo0.
func TestTunDarwinReadsTheRoutingTable(t *testing.T) {
	routes, err := (&urTunDarwinSockets{}).Routes()
	if err != nil {
		t.Fatal(err)
	}
	loopback, err := net.InterfaceByName("lo0")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(routes, func(held urTunDarwinRoute) bool {
		return held.index == loopback.Index && held.dst.Contains(netip.MustParseAddr("127.0.0.1"))
	}) {
		t.Fatalf("no loopback route in %d routes", len(routes))
	}
}

// Each ioctl's request names its argument's size in bits 16 to 28 (<sys/ioccom.h>'s IOCPARM_LEN), so each struct the
// device's calls pass is that size: struct ifreq's 32 bytes, struct ifaliasreq's 64.
func TestTunDarwinIoctlStructsFitTheirRequests(t *testing.T) {
	size := func(request uint) uintptr {
		return uintptr((request >> 16) & 0x1fff)
	}
	for _, each := range []struct {
		name    string
		request uint
		size    uintptr
	}{
		{"SIOCGIFFLAGS", unix.SIOCGIFFLAGS, unsafe.Sizeof(urTunDarwinIfreqFlags{})},
		{"SIOCSIFFLAGS", unix.SIOCSIFFLAGS, unsafe.Sizeof(urTunDarwinIfreqFlags{})},
		{"SIOCAIFADDR", unix.SIOCAIFADDR, unsafe.Sizeof(urTunDarwinIfaliasreq{})},
		{"SIOCDIFADDR", unix.SIOCDIFADDR, unsafe.Sizeof(urTunDarwinIfreqAddr{})},
	} {
		if size(each.request) != each.size {
			t.Errorf("%s takes %d bytes, and its struct is %d", each.name, size(each.request), each.size)
		}
	}
}
