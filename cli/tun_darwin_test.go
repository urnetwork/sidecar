//go:build darwin

// ur tun on macOS (tun_darwin.go, bridge_local_darwin.go, bridge_dns_darwin.go). Most run the device's calls behind a
// recording kernel and a fake utun; the rest run on this machine's own kernel where no root is needed: a daemon that
// runs as the person is refused a utun with words that send no one to sudo and leaves no device behind, an interface's
// flags read through the same ioctl path the device's set takes, and the routing socket's watch starts and ends. A
// real device, which takes root, runs only where UR_TUN_TEST_DEVICE=darwin and the test runs as root:
//
//	sudo env UR_TUN_TEST_DEVICE=darwin go test -run TestTunDarwinDevice -v .
//
// Every wait is bounded by urTestTimeout.

package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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

// A route's message: a /32 a host route with no mask, a wider prefix with its mask, each through the link address of
// the interface, and the dump's parse reads them back.
func TestTunDarwinRouteMessagesReadBack(t *testing.T) {
	for _, prefix := range []netip.Prefix{netip.MustParsePrefix("100.70.1.2/32"), netip.MustParsePrefix("10.20.0.0/16"),
		netip.MustParsePrefix("0.0.0.0/1")} {
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
		if (prefix.Bits() == 32) != (parsed.Flags&unix.RTF_HOST != 0) || parsed.Flags&unix.RTF_STATIC == 0 {
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
	// what AddRoute answers for a prefix, nil for success
	addErrs map[netip.Prefix]error
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
	self.record("delete route " + prefix.String())
	return nil
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
		kernel:   &testDarwinKernel{addErrs: map[netip.Prefix]error{}},
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

// Under exits the binding goes on first, to the unscoped default route's interface, then the halves, then the kick;
// a sync with nothing moved changes nothing, a default route that moved binds again, and off exits the halves come
// off before the binding.
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
	if calls := world.kernel.take(); !slices.Equal(calls, []string{"add route 0.0.0.0/1", "add route 128.0.0.0/1"}) {
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
	if calls := world.kernel.take(); !slices.Equal(calls, []string{"delete route 0.0.0.0/1", "delete route 128.0.0.0/1"}) {
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
	world.kernel.addErrs[netip.MustParsePrefix("128.0.0.0/1")] = unix.EEXIST
	if defaultRoute, err := iface.SetExits(true); defaultRoute || !errors.Is(err, errUrTunExitsHalfInUse) {
		t.Fatalf("a held half: %v %v", defaultRoute, err)
	}
	if calls := world.kernel.take(); !slices.Equal(calls, []string{"add route 0.0.0.0/1", "delete route 0.0.0.0/1"}) {
		t.Fatalf("a held half: %v", calls)
	}
	if bound, unbound := <-world.bindings, <-world.bindings; bound != [2]uint32{4, 4} || unbound != [2]uint32{0, 0} {
		t.Fatalf("bindings %v %v", bound, unbound)
	}
}

// Close takes the exits, the resolver files, the routes and the addresses off, and closes the device.
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
	want := []string{"delete route 0.0.0.0/1", "delete route 128.0.0.0/1", "delete route 100.70.1.2/32",
		"delete address 100.70.9.9"}
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
