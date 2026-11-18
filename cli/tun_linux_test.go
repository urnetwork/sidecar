//go:build linux

// ur tun on a real Linux kernel (tun_linux.go, bridge_local_linux.go, bridge_dns_linux.go). These change the host's
// interfaces and routes, so they run only inside a container made for them, which sets UR_TUN_TEST_DEVICE; elsewhere
// each skips. The run, from cli/, on a host with Docker:
//
//	CGO_ENABLED=0 GOOS=linux GOARCH=<the engine's arch> go test -c -o <dir>/cli.test .
//	docker run --rm --name sidecar-test-tun --cap-add NET_ADMIN --device /dev/net/tun -e UR_TUN_TEST_DEVICE=1 \
//	    -v <dir>:/t:ro alpine:3.22 /t/cli.test -test.run TestTunLinux -test.v
//	docker run --rm --name sidecar-test-tun-unprivileged --device /dev/net/tun -e UR_TUN_TEST_DEVICE=unprivileged \
//	    -v <dir>:/t:ro alpine:3.22 /t/cli.test -test.run TestTunLinuxRefusesWithoutNetAdmin -test.v
//	docker run --rm --name sidecar-test-tun-nodevice --cap-add NET_ADMIN -e UR_TUN_TEST_DEVICE=nodevice \
//	    -v <dir>:/t:ro alpine:3.22 /t/cli.test -test.run TestTunLinuxNamesAMissingDevice -test.v
//	docker run --rm --name sidecar-test-tun-isolated --network none --cap-add NET_ADMIN --device /dev/net/tun \
//	    --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 \
//	    -e UR_TUN_TEST_DEVICE=isolated -v <dir>:/t:ro alpine:3.22 /t/cli.test -test.run TestTunLinux -test.v
//
// The device comes up with the host's overlay address and the bridge's routes, a ping to a fixture peer's address rides
// the link the bridge routes it to and its reply returns through the device, a private name resolves through
// <block>.0.53 to the bridge's own resolver, and the close removes the device and its routes. With no CAP_NET_ADMIN the
// open refuses with errUrTunPrivilege, not a crash. In a namespace with no network, a tun of the test's stands for the
// physical path, and under exits the bridge's carved addresses leave by it rather than ur tun (QD-808). Every wait is a
// read with urTestTimeout's deadline. The exits' rules and routes and their throws are also tested through a netlink
// recorder that changes no host, which runs on any Linux, IPv6's half among them (QD-881): in that namespace with IPv6
// on, a datagram an unmarked socket sends to an IPv6 address beyond the host rides ur tun, and one a socket carrying the
// exits mark sends, as the daemon's own do, leaves by the test's tun.

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Skips unless the container for these tests runs them, in mode.
func requireTunContainer(t *testing.T, mode string) {
	t.Helper()
	if os.Getenv("UR_TUN_TEST_DEVICE") != mode {
		t.Skip("changes the host's interfaces: runs only in the sidecar-test-tun container")
	}
}

// The ones' complement sum RFC 791 and RFC 792 checksum with.
func testTunChecksum(data []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

// A fixture peer behind a link: it answers each ICMP echo request it is sent with the reply its peer would, through
// the links' receive, as a window client's return does.
type testTunEchoLink struct {
	links *testTunLinks
	testTunLink
}

func (self *testTunEchoLink) SendPacket(source connect.TransferPath, provideMode protocol.ProvideMode, packet []byte, timeout time.Duration) bool {
	defer connect.MessagePoolReturn(packet)
	headerByteCount := int(packet[0]&0x0F) * 4
	if len(packet) < headerByteCount+8 || packet[9] != 1 || packet[headerByteCount] != 8 {
		return true
	}
	reply := slices.Clone(packet)
	copy(reply[12:16], packet[16:20])
	copy(reply[16:20], packet[12:16])
	reply[8] = 64
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], testTunChecksum(reply[:headerByteCount]))
	icmp := reply[headerByteCount:]
	icmp[0] = 0
	icmp[2], icmp[3] = 0, 0
	binary.BigEndian.PutUint16(icmp[2:4], testTunChecksum(icmp))
	if receive := self.links.current(); receive != nil {
		receive(connect.TransferPath{}, protocol.ProvideMode_Network, nil, reply)
	}
	return true
}

// The tun over the real kernel: the device and its address and routes come up, a ping to a fixture peer rides its link
// and back, a private name resolves through <block>.0.53, and the close removes the device and its routes.
func TestTunLinuxDeviceCarriesTheBridge(t *testing.T) {
	requireTunContainer(t, "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settings := testUrTunSettings()
	system := newUrTunLinuxSystem(settings, nil)
	tunBridge := newTestTunBridge()
	links := &testTunLinks{}
	echo := &testTunEchoLink{links: links}
	peer := netip.MustParseAddr("100.70.1.2")
	resolverAddr := netip.MustParseAddr("100.70.0.53")
	zone := device.NewBridgeZone(map[string]uint32{"host1": binary.BigEndian.Uint32(peer.AsSlice())}, []string{"net.example"}, nil)
	resolver := device.NewBridgeResolverClient(ctx, func() *device.BridgeZone { return zone }, nil, nil)
	defer resolver.Close()
	tunBridge.route = func(packet []byte) connect.UserNatClient {
		switch netip.AddrFrom4([4]byte(packet[16:20])) {
		case peer:
			return echo
		case resolverAddr:
			return resolver
		}
		return nil
	}
	tun, err := startUrTun(ctx, &urTunArgs{
		Name:      "ur-test",
		NetworkId: sidecar.NewId(),
		System:    system,
		Bridge:    tunBridge,
		Links:     links,
		Settings:  settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.close()
	_, receive := tunBridge.lastLocal()
	resolver.SetReceive(receive)

	link, err := net.InterfaceByName("ur-test")
	if err != nil || link.Flags&net.FlagUp == 0 {
		t.Fatalf("the device: %v %v", link, err)
	}
	addresses, err := link.Addrs()
	if err != nil || !slices.ContainsFunc(addresses, func(address net.Addr) bool {
		return strings.HasPrefix(address.String(), "100.70.9.9/")
	}) {
		t.Fatalf("the device's addresses %v %v", addresses, err)
	}
	routes, err := urTunLinuxRoutes(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	carried := []netip.Prefix{}
	for _, route := range routes {
		if slices.Contains(route.oifs, link.Index) && route.table == unix.RT_TABLE_MAIN {
			carried = append(carried, route.dst)
		}
	}
	slices.SortFunc(carried, func(a netip.Prefix, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	if !slices.Equal(carried, tunBridge.Routes()) {
		t.Fatalf("routes through the device %v, the bridge's %v", carried, tunBridge.Routes())
	}
	if status := tun.status(); !strings.Contains(status.ResolverStep, "resolvectl") {
		t.Fatalf("no system bus here, and the step is %q", status.ResolverStep)
	}

	// a ping to the peer rides the link and its reply comes back through the device
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := []byte{8, 0, 0, 0, 0x12, 0x34, 0, 1, 'u', 'r', ' ', 't', 'u', 'n'}
	binary.BigEndian.PutUint16(request[2:4], testTunChecksum(request))
	if _, err := conn.WriteTo(request, &net.IPAddr{IP: peer.AsSlice()}); err != nil {
		t.Fatal(err)
	}
	conn.SetReadDeadline(time.Now().Add(urTestTimeout))
	answer := make([]byte, 1500)
	for {
		n, from, err := conn.ReadFrom(answer)
		if err != nil {
			t.Fatalf("no echo reply: %v", err)
		}
		if from.String() == peer.String() && 8 <= n && answer[0] == 0 && answer[4] == 0x12 && answer[5] == 0x34 {
			break
		}
	}

	// a private name resolves through the block's resolver, inside the tun
	lookup := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "udp", net.JoinHostPort(resolverAddr.String(), "53"))
		},
	}
	lookupCtx, lookupCancel := context.WithTimeout(ctx, urTestTimeout)
	defer lookupCancel()
	hosts, err := lookup.LookupHost(lookupCtx, "host1.net.example")
	if err != nil || !slices.Contains(hosts, peer.String()) {
		t.Fatalf("host1.net.example: %v %v", hosts, err)
	}

	// the close removes the device and every route through it
	tun.close()
	if _, err := net.InterfaceByName("ur-test"); err == nil {
		t.Fatal("the device outlived the close")
	}
	routes, err = urTunLinuxRoutes(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.dst == netip.PrefixFrom(peer, 32) || route.dst == netip.PrefixFrom(resolverAddr, 32) {
			t.Fatalf("a route outlived the close: %v", route.dst)
		}
	}
}

// With no CAP_NET_ADMIN, opening the device refuses with the privilege's error, not a crash.
func TestTunLinuxRefusesWithoutNetAdmin(t *testing.T) {
	requireTunContainer(t, "unprivileged")
	system := newUrTunLinuxSystem(testUrTunSettings(), nil)
	iface, err := system.Open("ur-test", 1280)
	if !errors.Is(err, errUrTunPrivilege) {
		if iface != nil {
			iface.Close()
		}
		t.Fatalf("an open with no privilege: %v", err)
	}
}

// A host with no /dev/net/tun, a container not given it, is named as such.
func TestTunLinuxNamesAMissingDevice(t *testing.T) {
	requireTunContainer(t, "nodevice")
	system := newUrTunLinuxSystem(testUrTunSettings(), nil)
	iface, err := system.Open("ur-test", 1280)
	if !errors.Is(err, errUrTunNoDevice) {
		if iface != nil {
			iface.Close()
		}
		t.Fatalf("an open with no device: %v", err)
	}
}

// Another interface's route inside the block holds it, as an app's bridge does; a broader route covering it, as a
// carrier's 100.64/10 does, does not.
func TestTunLinuxFindsTheBlockRoutedElsewhere(t *testing.T) {
	requireTunContainer(t, "1")
	system := newUrTunLinuxSystem(testUrTunSettings(), nil)
	app, err := system.Open("ur-app", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	block := netip.MustParsePrefix("100.70.0.0/16")
	if _, err := app.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}); err != nil {
		t.Fatal(err)
	}
	if holder, err := system.RoutedElsewhere("ur-test", block); err != nil || holder != "" {
		t.Fatalf("a covering route: %q %v", holder, err)
	}
	if _, err := app.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.70.4.0/24")}); err != nil {
		t.Fatal(err)
	}
	if holder, err := system.RoutedElsewhere("ur-test", block); err != nil || holder != "ur-app" {
		t.Fatalf("a route inside the block: %q %v", holder, err)
	}
	if holder, err := system.RoutedElsewhere("ur-app", block); err != nil || holder != "" {
		t.Fatalf("its own route: %q %v", holder, err)
	}
}

// A route another interface holds at the same prefix keeps it: the second is counted, and left to the first.
func TestTunLinuxLeavesAHeldRouteToItsHolder(t *testing.T) {
	requireTunContainer(t, "1")
	system := newUrTunLinuxSystem(testUrTunSettings(), nil)
	first, err := system.Open("ur-first", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := system.Open("ur-second", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	held := netip.MustParsePrefix("100.71.5.0/24")
	if conflictCount, err := first.SetRoutes([]netip.Prefix{held}); err != nil || conflictCount != 0 {
		t.Fatalf("the first: %d %v", conflictCount, err)
	}
	if conflictCount, err := second.SetRoutes([]netip.Prefix{held}); err != nil || conflictCount != 1 {
		t.Fatalf("the second: %d %v", conflictCount, err)
	}
	firstIndex := urTunLinuxIndex("ur-first")
	routes, err := urTunLinuxRoutes(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(routes, func(route urTunLinuxRoute) bool {
		return route.dst == held && slices.Contains(route.oifs, firstIndex)
	}) {
		t.Fatal("the first lost its route")
	}
	// the second's set removes nothing of the first's
	if _, err := second.SetRoutes(nil); err != nil {
		t.Fatal(err)
	}
	routes, err = urTunLinuxRoutes(unix.AF_INET)
	if err != nil || !slices.ContainsFunc(routes, func(route urTunLinuxRoute) bool { return route.dst == held }) {
		t.Fatalf("the first's route went: %v", err)
	}
}

// The local addresses hold the host's interfaces, its default gateway and its resolvers, never the tun's own address
// nor what the caller leaves out, and the watch reports an address that comes.
func TestTunLinuxReadsTheLocalAddresses(t *testing.T) {
	requireTunContainer(t, "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	system := newUrTunLinuxSystem(testUrTunSettings(), nil)
	own, err := system.Open("ur-test", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	if err := own.SetAddresses([]netip.Addr{netip.MustParseAddr("100.70.9.9")}); err != nil {
		t.Fatal(err)
	}
	resolvers := urReadResolvConf(urResolvConfPath)
	exclude := []netip.Addr{netip.MustParseAddr("100.70.0.53")}
	local, err := system.LocalAddresses("ur-test", exclude)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(local, netip.MustParseAddr("100.70.9.9")) {
		t.Fatal("the tun's own address is local")
	}
	for _, resolver := range resolvers {
		if !slices.Contains(local, resolver) && !slices.Contains(exclude, resolver) {
			t.Fatalf("the resolver %v is missing from %v", resolver, local)
		}
	}
	routes, err := urTunLinuxRoutes(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.dst.Bits() == 0 && route.table == unix.RT_TABLE_MAIN {
			for _, gateway := range route.gateways {
				if !slices.Contains(local, gateway) {
					t.Fatalf("the default gateway %v is missing from %v", gateway, local)
				}
			}
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range interfaces {
		if link.Name == "ur-test" || link.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := link.Addrs()
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() && !slices.Contains(local, prefix.Addr()) {
				t.Fatalf("%s's %v is missing from %v", link.Name, prefix.Addr(), local)
			}
		}
	}
	other, err := system.Open("ur-watched", 1280)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	changed := make(chan struct{}, 1)
	watchCtx, watchCancel := context.WithCancel(ctx)
	watchDone := make(chan error, 1)
	go func() {
		watchDone <- system.WatchLocal(watchCtx, func() {
			select {
			case changed <- struct{}{}:
			default:
			}
		})
	}()
	// the watch's first change says it watches; what comes after it is the address's
	select {
	case <-changed:
	case <-time.After(urTestTimeout):
		t.Fatal("the watch did not start")
	}
	if err := other.SetAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.77")}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	case <-time.After(urTestTimeout):
		t.Fatal("the watch saw no change")
	}
	watchCancel()
	select {
	case err := <-watchDone:
		if err != nil {
			t.Fatalf("the watch ended with %v", err)
		}
	case <-time.After(urTestTimeout):
		t.Fatal("the watch did not end with its context")
	}
}

// One request a test's rtnetlink was sent, and each mark connect was given, in the order they came.
type testTunNetlinkEvent struct {
	messageType uint16
	flags       uint16
	body        []byte
	// for a mark, the mark; messageType is 0
	mark uint32
}

// rtnetlink and connect's mark and kick as a test's recorder, changing nothing on the host: each request and mark in
// order, each answered by fail, and the routes and rules a dump lists.
type testTunNetlink struct {
	stateLock sync.Mutex
	events    []testTunNetlinkEvent
	kickCount int
	// the answer to each request, numbered from 0; nil answers success
	fail func(n int, messageType uint16) error
	// what each add of a throw route answers ahead of fail, nil for none, and ahead of it what one of a family answers
	throwErr        error
	familyThrowErrs map[uint8]error
	// what a request answers by its family and type ahead of fail, nil for none
	refuse func(family uint8, messageType uint16) error
	routes []urTunLinuxRoute
	rules  []urTunLinuxRule
	sent   int
}

// IPv4 multicast routing's family of policy rules (RTNL_FAMILY_IPMR), which x/sys does not name.
const testTunLinuxIpmrFamily = 128

var _ urTunNetlink = (*testTunNetlink)(nil)

func (self *testTunNetlink) Request(messageType uint16, flags uint16, body []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, testTunNetlinkEvent{messageType: messageType, flags: flags, body: slices.Clone(body)})
	n := self.sent
	self.sent += 1
	if messageType == unix.RTM_NEWROUTE && unix.SizeofRtMsg <= len(body) && body[7] == unix.RTN_THROW {
		if err := self.familyThrowErrs[body[0]]; err != nil {
			return err
		}
		if self.throwErr != nil {
			return self.throwErr
		}
	}
	if self.refuse != nil && 0 < len(body) {
		if err := self.refuse(body[0], messageType); err != nil {
			return err
		}
	}
	if self.fail != nil {
		return self.fail(n, messageType)
	}
	return nil
}

// Sets what each add of a throw route answers.
func (self *testTunNetlink) setThrowErr(throwErr error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.throwErr = throwErr
}

// Sets what each add of a throw route of family answers, nil for what the rest do.
func (self *testTunNetlink) setFamilyThrowErr(family uint8, throwErr error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.familyThrowErrs == nil {
		self.familyThrowErrs = map[uint8]error{}
	}
	self.familyThrowErrs[family] = throwErr
}

// Adds routes to what a dump lists, and takes out those that match.
func (self *testTunNetlink) replaceRoutes(match func(route urTunLinuxRoute) bool, routes ...urTunLinuxRoute) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routes = append(slices.DeleteFunc(self.routes, match), routes...)
}

// Sets what a request answers by its family and type.
func (self *testTunNetlink) setRefuse(refuse func(family uint8, messageType uint16) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refuse = refuse
}

func (self *testTunNetlink) Routes(family int) ([]urTunLinuxRoute, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.routes), nil
}

func (self *testTunNetlink) Rules(family int) ([]urTunLinuxRule, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.rules), nil
}

func (self *testTunNetlink) setEgressMark(mark uint32) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, testTunNetlinkEvent{mark: mark})
}

func (self *testTunNetlink) networkChanged() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.kickCount += 1
}

// The events since the last take, and the kicks so far.
func (self *testTunNetlink) take() ([]testTunNetlinkEvent, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	events := self.events
	self.events = nil
	return events, self.kickCount
}

// Writes each interface's rp_filter, all's among them, under a directory like /proc/sys/net/ipv4/conf.
func testTunReversePathFilters(t *testing.T, values map[string]int) string {
	t.Helper()
	path := t.TempDir()
	for name, value := range values {
		if err := os.MkdirAll(filepath.Join(path, name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, name, "rp_filter"), []byte(strconv.Itoa(value)+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// An interface at index 7 on a recorded system, whose main table's default routes, IPv4's and IPv6's, leave by eth0 at
// index 2 and whose reverse path filters are loose.
func newTestTunLinuxExits(t *testing.T) (*urTunLinuxInterface, *testTunNetlink) {
	t.Helper()
	netlink := &testTunNetlink{
		routes: []urTunLinuxRoute{
			{
				family:    unix.AF_INET,
				table:     unix.RT_TABLE_MAIN,
				protocol:  unix.RTPROT_DHCP,
				routeType: unix.RTN_UNICAST,
				dst:       netip.MustParsePrefix("0.0.0.0/0"),
				oifs:      []int{2},
				gateways:  []netip.Addr{netip.MustParseAddr("192.0.2.1")},
			},
			{
				family:    unix.AF_INET,
				table:     unix.RT_TABLE_MAIN,
				protocol:  unix.RTPROT_KERNEL,
				routeType: unix.RTN_UNICAST,
				dst:       netip.MustParsePrefix("192.0.2.0/24"),
				oifs:      []int{2},
			},
			testTunLinuxIpv6DefaultRoute(),
			{
				family:    unix.AF_INET6,
				table:     unix.RT_TABLE_MAIN,
				protocol:  unix.RTPROT_KERNEL,
				routeType: unix.RTN_UNICAST,
				dst:       netip.MustParsePrefix("2001:db8::/64"),
				oifs:      []int{2},
			},
		},
		rules: []urTunLinuxRule{
			{family: unix.AF_INET, table: unix.RT_TABLE_LOCAL, action: unix.FR_ACT_TO_TBL, suppressPrefixLength: -1},
			{family: unix.AF_INET, table: unix.RT_TABLE_MAIN, action: unix.FR_ACT_TO_TBL, priority: 32766, suppressPrefixLength: -1},
			{family: unix.AF_INET6, table: unix.RT_TABLE_LOCAL, action: unix.FR_ACT_TO_TBL, suppressPrefixLength: -1},
			{family: unix.AF_INET6, table: unix.RT_TABLE_MAIN, action: unix.FR_ACT_TO_TBL, priority: 32766, suppressPrefixLength: -1},
		},
	}
	system := newUrTunLinuxSystem(testUrTunSettings(), nil).(*urTunLinuxSystem)
	system.netlink = netlink
	system.ipv4ConfPath = testTunReversePathFilters(t, map[string]int{"all": 0, "eth0": 2})
	system.linkName = func(index int) (string, error) {
		if index == 2 {
			return "eth0", nil
		}
		return "", errors.New("no such interface")
	}
	system.setEgressMark = netlink.setEgressMark
	system.networkChanged = netlink.networkChanged
	return &urTunLinuxInterface{system: system, name: "ur-test", index: 7}, netlink
}

// The IPv6 default route of the recorded system's main table, by eth0's router, as a router advertisement leaves it.
func testTunLinuxIpv6DefaultRoute() urTunLinuxRoute {
	return urTunLinuxRoute{
		family:    unix.AF_INET6,
		table:     unix.RT_TABLE_MAIN,
		protocol:  unix.RTPROT_RA,
		routeType: unix.RTN_UNICAST,
		dst:       netip.MustParsePrefix("::/0"),
		oifs:      []int{2},
		gateways:  []netip.Addr{netip.MustParseAddr("fe80::1")},
	}
}

// Takes the recorded system's IPv6 default route out of its main table, as on a host whose IPv6 reaches no further than
// its own links.
func (self *testTunNetlink) dropIpv6DefaultRoute() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.routes = slices.DeleteFunc(self.routes, func(route urTunLinuxRoute) bool {
		return route.family == unix.AF_INET6 && route.dst.Bits() == 0
	})
}

// The family of a route or rule message, its body's first byte.
func testTunEventFamily(event testTunNetlinkEvent) uint8 {
	if len(event.body) == 0 {
		return 0
	}
	return event.body[0]
}

// A route message's body as the kernel reads it: the header's table, protocol, scope and type, and its attributes.
type testTunRouteMessage struct {
	family    uint8
	dstBits   uint8
	protocol  uint8
	scope     uint8
	routeType uint8
	table     uint32
	oif       uint32
	hasOif    bool
	hasDst    bool
	dst       netip.Addr
	// whether it names a gateway, which a throw may not
	hasGateway bool
}

func testTunParseRouteBody(body []byte) testTunRouteMessage {
	message := testTunRouteMessage{
		family:    body[0],
		dstBits:   body[1],
		table:     uint32(body[4]),
		protocol:  body[5],
		scope:     body[6],
		routeType: body[7],
	}
	for _, attribute := range urNetlinkAttributes(body[unix.SizeofRtMsg:]) {
		switch attribute.attributeType {
		case unix.RTA_TABLE:
			message.table = binary.NativeEndian.Uint32(attribute.value)
		case unix.RTA_OIF:
			message.oif = binary.NativeEndian.Uint32(attribute.value)
			message.hasOif = true
		case unix.RTA_DST:
			message.hasDst = true
			message.dst, _ = netip.AddrFromSlice(attribute.value)
		case unix.RTA_GATEWAY:
			message.hasGateway = true
		}
	}
	return message
}

// The throw routes events add and take off, in order, each checked for the shape the kernel takes: ur's, a whole
// address of its family in table, an IPv4 /32 or an IPv6 /128, naming no device or gateway, added exclusively in the
// universe's scope and taken off in any.
func testTunThrows(t *testing.T, events []testTunNetlinkEvent, table uint32) ([]netip.Addr, []netip.Addr) {
	t.Helper()
	addedAddrs := []netip.Addr{}
	removedAddrs := []netip.Addr{}
	for _, event := range events {
		if event.messageType != unix.RTM_NEWROUTE && event.messageType != unix.RTM_DELROUTE {
			continue
		}
		message := testTunParseRouteBody(event.body)
		if message.routeType != unix.RTN_THROW {
			continue
		}
		whole := (message.family == unix.AF_INET && message.dstBits == 32 && message.dst.Is4()) ||
			(message.family == unix.AF_INET6 && message.dstBits == 128 && message.dst.Is6())
		if !whole || !message.hasDst || message.table != table || message.protocol != urTunRouteProtocol ||
			message.hasOif || message.hasGateway {
			t.Fatalf("a throw's message %+v", message)
		}
		if event.messageType == unix.RTM_NEWROUTE {
			if event.flags != unix.NLM_F_CREATE|unix.NLM_F_EXCL || message.scope != unix.RT_SCOPE_UNIVERSE {
				t.Fatalf("a throw's add %+v, flags %#x", message, event.flags)
			}
			addedAddrs = append(addedAddrs, message.dst)
			continue
		}
		if message.scope != unix.RT_SCOPE_NOWHERE {
			t.Fatalf("a throw's delete %+v", message)
		}
		removedAddrs = append(removedAddrs, message.dst)
	}
	return addedAddrs, removedAddrs
}

// The types of events, in order, a mark's 0.
func testTunEventTypes(events []testTunNetlinkEvent) []uint16 {
	types := []uint16{}
	for _, event := range events {
		types = append(types, event.messageType)
	}
	return types
}

// The addresses a throw holds on iface now.
func testTunThrowAddrs(iface *urTunLinuxInterface) []netip.Addr {
	iface.stateLock.Lock()
	defer iface.stateLock.Unlock()
	return slices.Clone(iface.throwAddrs)
}

// The exits put on the mark first, then the default route through the device in the exits table, then wg-quick's two
// rules, `lookup main suppress_prefixlength 0` ahead of `not fwmark <mark> lookup <table>`, each ur's; then IPv6's
// default route in the same table and its two rules alike (QD-881), so the daemon's marked IPv6 sockets pass by IPv6's
// rule as its IPv4 ones pass by IPv4's; and kick connect once they are on; asked again, they send nothing more.
func TestTunLinuxExitsInstallWgQuicksRules(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	defaultRoute, err := iface.SetExits(true)
	if err != nil || !defaultRoute {
		t.Fatalf("on: %t %v", defaultRoute, err)
	}
	events, kickCount := netlink.take()
	if len(events) != 7 || kickCount != 1 {
		t.Fatalf("%d events, %d kicks", len(events), kickCount)
	}
	if events[0].messageType != 0 || events[0].mark != settings.ExitsMark {
		t.Fatalf("the mark did not go on first: %+v", events[0])
	}
	for i, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		route := events[1+3*i]
		message := testTunParseRouteBody(route.body)
		scope := uint8(unix.RT_SCOPE_LINK)
		if family == unix.AF_INET6 {
			scope = unix.RT_SCOPE_UNIVERSE
		}
		if route.messageType != unix.RTM_NEWROUTE || route.flags != unix.NLM_F_CREATE|unix.NLM_F_EXCL ||
			message.family != family || message.dstBits != 0 || message.hasDst || message.table != settings.ExitsTable ||
			message.protocol != urTunRouteProtocol || message.scope != scope || message.routeType != unix.RTN_UNICAST ||
			message.oif != 7 {
			t.Fatalf("family %d's default route: %+v %+v", family, route, message)
		}
		suppressEvent := events[2+3*i]
		suppress := urTunLinuxParseRule(suppressEvent.body)
		if suppressEvent.messageType != unix.RTM_NEWRULE || suppressEvent.flags != unix.NLM_F_CREATE|unix.NLM_F_EXCL ||
			suppress.family != family || suppress.action != unix.FR_ACT_TO_TBL || suppress.flags != 0 ||
			suppress.table != unix.RT_TABLE_MAIN || suppress.priority != settings.ExitsRulePriority ||
			suppress.suppressPrefixLength != 0 || suppress.markSet || suppress.protocol != urTunRouteProtocol {
			t.Fatalf("family %d's suppress rule: %+v", family, suppress)
		}
		markEvent := events[3+3*i]
		mark := urTunLinuxParseRule(markEvent.body)
		if markEvent.messageType != unix.RTM_NEWRULE || mark.family != family || mark.action != unix.FR_ACT_TO_TBL ||
			mark.flags != unix.FIB_RULE_INVERT || mark.table != settings.ExitsTable ||
			mark.priority != settings.ExitsRulePriority+1 || !mark.markSet || mark.mark != settings.ExitsMark ||
			mark.suppressPrefixLength != -1 || mark.protocol != urTunRouteProtocol {
			t.Fatalf("family %d's mark rule: %+v", family, mark)
		}
		// the mark rule's mask is every bit, as `fwmark M` without a mask is
		var mask uint32
		for _, attribute := range urNetlinkAttributes(markEvent.body[urTunLinuxRuleHeaderByteCount:]) {
			if attribute.attributeType == unix.FRA_FWMASK {
				mask = binary.NativeEndian.Uint32(attribute.value)
			}
		}
		if mask != math.MaxUint32 {
			t.Fatalf("family %d's mark rule's mask %#x", family, mask)
		}
	}
	defaultRoute, err = iface.SetExits(true)
	if events, kickCount := netlink.take(); err != nil || !defaultRoute || len(events) != 0 || kickCount != 1 {
		t.Fatalf("again: %t %v, %d events, %d kicks", defaultRoute, err, len(events), kickCount)
	}
}

// Off exits IPv4's rules come off before its route, the one that sends traffic to the tun first, each delete naming
// ur's own, then IPv6's the same way, and the mark last; asked again, nothing more is sent.
func TestTunLinuxExitsComeOffInReverse(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	installed, _ := netlink.take()
	defaultRoute, err := iface.SetExits(false)
	if err != nil || defaultRoute {
		t.Fatalf("off: %t %v", defaultRoute, err)
	}
	events, kickCount := netlink.take()
	if len(events) != 7 || kickCount != 1 {
		t.Fatalf("%d events, %d kicks", len(events), kickCount)
	}
	for i, family := range []uint8{unix.AF_INET, unix.AF_INET6} {
		markRule, route, suppressRule := events[3*i], events[1+3*i], events[2+3*i]
		if markRule.messageType != unix.RTM_DELRULE || !slices.Equal(markRule.body, installed[3+3*i].body) {
			t.Fatalf("family %d's mark rule did not come off first: %+v", family, markRule)
		}
		if route.messageType != unix.RTM_DELROUTE {
			t.Fatalf("family %d's route did not come off second: %+v", family, route)
		}
		if message := testTunParseRouteBody(route.body); message.family != family || message.table != settings.ExitsTable ||
			message.oif != 7 || message.protocol != urTunRouteProtocol || message.dstBits != 0 {
			t.Fatalf("family %d's route's delete: %+v", family, message)
		}
		if suppressRule.messageType != unix.RTM_DELRULE || !slices.Equal(suppressRule.body, installed[2+3*i].body) {
			t.Fatalf("family %d's suppress rule did not come off third: %+v", family, suppressRule)
		}
	}
	if events[6].messageType != 0 || events[6].mark != 0 {
		t.Fatalf("the mark did not come off last: %+v", events[6])
	}
	if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
		t.Fatalf("again: %t %v", defaultRoute, err)
	}
	if events, _ := netlink.take(); len(events) != 0 {
		t.Fatalf("off again sent %d", len(events))
	}
}

// A refusal partway through takes off what went on, the mark included, and kicks nothing.
func TestTunLinuxExitsRollBackAPartialSet(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	netlink.fail = func(n int, messageType uint16) error {
		if n == 2 {
			return unix.EPERM
		}
		return nil
	}
	defaultRoute, err := iface.SetExits(true)
	if err == nil || defaultRoute || !strings.Contains(err.Error(), "did not go on") {
		t.Fatalf("refused: %t %v", defaultRoute, err)
	}
	if errors.Is(err, errUrTunPrivilege) {
		t.Fatal("a hold reads as the device's privilege refusal")
	}
	events, kickCount := netlink.take()
	types := []uint16{}
	for _, event := range events {
		types = append(types, event.messageType)
	}
	want := []uint16{0, unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE, unix.RTM_DELROUTE, unix.RTM_DELRULE, 0}
	if !slices.Equal(types, want) || kickCount != 0 || events[len(events)-1].mark != 0 {
		t.Fatalf("events %v, %d kicks", types, kickCount)
	}
	if iface.exitsMark || iface.exitsRoute || iface.exitsSuppressRule || iface.exitsMarkRule {
		t.Fatal("something of the refused set stayed on")
	}
}

// Where the host routes IPv6 off itself, a refusal of IPv6's half holds the exits as one of IPv4's does (QD-881): what
// went on of both families comes off, IPv4's first and the mark last, nothing is kicked, and the error says IPv6 would
// leave outside the exits, so the host's IPv6 never rides today's route while its IPv4 rides the exits.
func TestTunLinuxExitsHoldWhereIpv6WouldLeave(t *testing.T) {
	cases := []struct {
		name string
		// the request refused, numbered from 0: IPv4's route, its two rules, then IPv6's route and its two rules
		n    int
		want []uint16
	}{
		{
			name: "IPv6's default route",
			n:    3,
			want: []uint16{0, unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE, unix.RTM_NEWROUTE, unix.RTM_DELRULE,
				unix.RTM_DELROUTE, unix.RTM_DELRULE, 0},
		},
		{
			name: "IPv6's rule that sends unmarked traffic to the tun",
			n:    5,
			want: []uint16{0, unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE, unix.RTM_NEWROUTE, unix.RTM_NEWRULE,
				unix.RTM_NEWRULE, unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELRULE, 0},
		},
	}
	for _, c := range cases {
		iface, netlink := newTestTunLinuxExits(t)
		netlink.fail = func(n int, messageType uint16) error {
			if n == c.n {
				return unix.EACCES
			}
			return nil
		}
		defaultRoute, err := iface.SetExits(true)
		if err == nil || defaultRoute || !strings.Contains(err.Error(), c.name) ||
			!strings.Contains(err.Error(), "IPv6 would leave outside the exits") {
			t.Fatalf("%s: %t %v", c.name, defaultRoute, err)
		}
		if errors.Is(err, errUrTunPrivilege) {
			t.Fatalf("%s: a hold reads as the device's privilege refusal", c.name)
		}
		events, kickCount := netlink.take()
		if types := testTunEventTypes(events); !slices.Equal(types, c.want) || kickCount != 0 || events[len(events)-1].mark != 0 {
			t.Fatalf("%s: events %v, %d kicks", c.name, types, kickCount)
		}
		if iface.exitsMark || iface.exitsRoute || iface.exitsSuppressRule || iface.exitsMarkRule || iface.exitsIpv6Route ||
			iface.exitsIpv6SuppressRule || iface.exitsIpv6MarkRule {
			t.Fatalf("%s: something of the refused set stayed on", c.name)
		}
	}
}

// Where the host routes no IPv6 off itself, a kernel that will not take IPv6's half, one without IPv6 or a device with
// it off, holds nothing (QD-881): IPv4's exits stand and are kicked once, and no IPv6 rule goes on with no route for it
// to reach. Each later SetExits tries IPv6's route again, kicking nothing, and once the kernel takes it IPv6's rules
// follow; off exits all of it comes off. A kernel that takes IPv6's route but not its rules has the route taken back.
func TestTunLinuxExitsStandOnIpv4WhereTheHostHasNoIpv6(t *testing.T) {
	refuseIpv6 := func(refusal error, messageTypes ...uint16) func(family uint8, messageType uint16) error {
		return func(family uint8, messageType uint16) error {
			if family == unix.AF_INET6 && slices.Contains(messageTypes, messageType) {
				return refusal
			}
			return nil
		}
	}
	for _, refusal := range []error{unix.EAFNOSUPPORT, unix.EACCES} {
		iface, netlink := newTestTunLinuxExits(t)
		netlink.dropIpv6DefaultRoute()
		netlink.setRefuse(refuseIpv6(refusal, unix.RTM_NEWROUTE, unix.RTM_NEWRULE))
		defaultRoute, err := iface.SetExits(true)
		if err != nil || !defaultRoute {
			t.Fatalf("%v: on: %t %v", refusal, defaultRoute, err)
		}
		events, kickCount := netlink.take()
		want := []uint16{0, unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE, unix.RTM_NEWROUTE}
		if types := testTunEventTypes(events); !slices.Equal(types, want) || kickCount != 1 ||
			testTunEventFamily(events[4]) != unix.AF_INET6 {
			t.Fatalf("%v: on: events %v, %d kicks", refusal, types, kickCount)
		}
		if !iface.exitsMarkRule || iface.exitsIpv6Route || iface.exitsIpv6SuppressRule || iface.exitsIpv6MarkRule {
			t.Fatalf("%v: IPv4's %t, IPv6's %t %t %t", refusal, iface.exitsMarkRule, iface.exitsIpv6Route,
				iface.exitsIpv6SuppressRule, iface.exitsIpv6MarkRule)
		}
		// the next sync's SetExits tries IPv6's route alone, and kicks nothing
		if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
			t.Fatalf("%v: again: %t %v", refusal, defaultRoute, err)
		}
		events, kickCount = netlink.take()
		if types := testTunEventTypes(events); !slices.Equal(types, []uint16{unix.RTM_NEWROUTE}) || kickCount != 1 {
			t.Fatalf("%v: again: events %v, %d kicks", refusal, types, kickCount)
		}
		// the kernel takes IPv6 now: its route and rules go on, and still nothing is kicked
		netlink.setRefuse(nil)
		if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
			t.Fatalf("%v: IPv6 taken: %t %v", refusal, defaultRoute, err)
		}
		events, kickCount = netlink.take()
		want = []uint16{unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE}
		if types := testTunEventTypes(events); !slices.Equal(types, want) || kickCount != 1 ||
			slices.ContainsFunc(events, func(event testTunNetlinkEvent) bool { return testTunEventFamily(event) != unix.AF_INET6 }) {
			t.Fatalf("%v: IPv6 taken: events %v, %d kicks", refusal, types, kickCount)
		}
		if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
			t.Fatalf("%v: off: %t %v", refusal, defaultRoute, err)
		}
		events, _ = netlink.take()
		want = []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELRULE, unix.RTM_DELRULE, unix.RTM_DELROUTE,
			unix.RTM_DELRULE, 0}
		if types := testTunEventTypes(events); !slices.Equal(types, want) {
			t.Fatalf("%v: off: events %v", refusal, types)
		}
	}

	// a kernel with IPv6 but none of its policy rules: IPv6's route goes on, its first rule is refused, and the route
	// comes back off, so IPv4's exits stand with nothing of IPv6's left behind
	iface, netlink := newTestTunLinuxExits(t)
	netlink.dropIpv6DefaultRoute()
	netlink.setRefuse(refuseIpv6(unix.EAFNOSUPPORT, unix.RTM_NEWRULE))
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("no IPv6 rules: %t %v", defaultRoute, err)
	}
	events, _ := netlink.take()
	want := []uint16{0, unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE, unix.RTM_NEWROUTE, unix.RTM_NEWRULE,
		unix.RTM_DELROUTE}
	if types := testTunEventTypes(events); !slices.Equal(types, want) || testTunEventFamily(events[6]) != unix.AF_INET6 ||
		iface.exitsIpv6Route || iface.exitsIpv6SuppressRule || !iface.exitsMarkRule {
		t.Fatalf("no IPv6 rules: events %v", types)
	}
}

// A rule already there, ur's from an end the daemon did not see, is taken as on.
func TestTunLinuxExitsTakeTheirOwnLeftoverRules(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	netlink.rules = append(netlink.rules, urTunLinuxRule{
		family:               unix.AF_INET,
		table:                iface.system.settings.ExitsTable,
		flags:                unix.FIB_RULE_INVERT,
		priority:             iface.system.settings.ExitsRulePriority + 1,
		mark:                 iface.system.settings.ExitsMark,
		markSet:              true,
		suppressPrefixLength: -1,
		protocol:             urTunRouteProtocol,
	})
	netlink.fail = func(n int, messageType uint16) error {
		if messageType == unix.RTM_NEWRULE {
			return unix.EEXIST
		}
		return nil
	}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("on over leftovers: %t %v", defaultRoute, err)
	}
}

// A rule that will not come off keeps the main table's rule ahead of it and the mark on, while the default route goes,
// so the rule finds an empty table, in each family; the next call takes the rest off.
func TestTunLinuxExitsKeepTheMarkWhileTheirRuleStays(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	netlink.take()
	netlink.fail = func(n int, messageType uint16) error {
		if messageType == unix.RTM_DELRULE {
			return unix.EBUSY
		}
		return nil
	}
	defaultRoute, err := iface.SetExits(false)
	if err == nil || defaultRoute {
		t.Fatalf("stuck: %t %v", defaultRoute, err)
	}
	events, _ := netlink.take()
	types := []uint16{}
	for _, event := range events {
		types = append(types, event.messageType)
	}
	if !slices.Equal(types, []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELRULE, unix.RTM_DELROUTE}) ||
		!iface.exitsMark || !iface.exitsSuppressRule || !iface.exitsIpv6SuppressRule {
		t.Fatalf("events %v, mark %t, suppress %t and %t", types, iface.exitsMark, iface.exitsSuppressRule,
			iface.exitsIpv6SuppressRule)
	}
	netlink.fail = nil
	if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
		t.Fatalf("again: %t %v", defaultRoute, err)
	}
	events, _ = netlink.take()
	types = types[:0]
	for _, event := range events {
		types = append(types, event.messageType)
	}
	if !slices.Equal(types, []uint16{unix.RTM_DELRULE, unix.RTM_DELRULE, unix.RTM_DELRULE, unix.RTM_DELRULE, 0}) ||
		iface.exitsMark {
		t.Fatalf("events %v", types)
	}
}

// The exits refuse, putting nothing on, a table another program's routes hold, a mark or table another program's rule
// of either family uses, and a strict reverse path filter, all's or the default route's interface's; a loose or absent
// filter, ur's own leftover rule of either family, and a multicast routing family's rule, which no lookup of the
// exits meets, do not refuse.
func TestTunLinuxExitsRefuseWhatTheHostHolds(t *testing.T) {
	cases := []struct {
		name    string
		change  func(iface *urTunLinuxInterface, netlink *testTunNetlink)
		refusal error
	}{
		{
			name: "a route in the table",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET6, table: iface.system.settings.ExitsTable,
					protocol: unix.RTPROT_BOOT, routeType: unix.RTN_UNICAST, dst: netip.MustParsePrefix("::/0"), oifs: []int{9}})
			},
			refusal: errUrTunExitsTableInUse,
		},
		{
			name: "another program's throw in the table",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET, table: iface.system.settings.ExitsTable,
					protocol: unix.RTPROT_BOOT, routeType: unix.RTN_THROW, dst: netip.MustParsePrefix("198.51.100.53/32")})
			},
			refusal: errUrTunExitsTableInUse,
		},
		{
			name: "ur's throw in the table, wider than a carve's /32",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET, table: iface.system.settings.ExitsTable,
					protocol: urTunRouteProtocol, routeType: unix.RTN_THROW, dst: netip.MustParsePrefix("198.51.100.0/24")})
			},
			refusal: errUrTunExitsTableInUse,
		},
		{
			name: "ur's own leftover throw",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET, table: iface.system.settings.ExitsTable,
					protocol: urTunRouteProtocol, routeType: unix.RTN_THROW, dst: netip.MustParsePrefix("198.51.100.53/32")})
			},
		},
		{
			name: "ur's own leftover IPv6 throw, which the kernel shows through loopback",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET6, table: iface.system.settings.ExitsTable,
					protocol: urTunRouteProtocol, routeType: unix.RTN_THROW, dst: netip.MustParsePrefix("2001:db8:ffff::53/128"),
					oifs: []int{1}})
			},
		},
		{
			name: "ur's IPv6 throw in the table, wider than a carve's /128",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET6, table: iface.system.settings.ExitsTable,
					protocol: urTunRouteProtocol, routeType: unix.RTN_THROW, dst: netip.MustParsePrefix("2001:db8:ffff::/64")})
			},
			refusal: errUrTunExitsTableInUse,
		},
		{
			name: "another program's IPv6 throw in the table",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET6, table: iface.system.settings.ExitsTable,
					protocol: unix.RTPROT_BOOT, routeType: unix.RTN_THROW, dst: netip.MustParsePrefix("2001:db8:ffff::53/128")})
			},
			refusal: errUrTunExitsTableInUse,
		},
		{
			name: "a rule on the mark",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.rules = append(netlink.rules, urTunLinuxRule{family: unix.AF_INET, table: 100, priority: 1000,
					mark: iface.system.settings.ExitsMark, markSet: true, suppressPrefixLength: -1, protocol: unix.RTPROT_BOOT})
			},
			refusal: errUrTunExitsMarkInUse,
		},
		{
			name: "a rule on the table",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.rules = append(netlink.rules, urTunLinuxRule{family: unix.AF_INET, table: iface.system.settings.ExitsTable,
					priority: 1000, suppressPrefixLength: -1, protocol: unix.RTPROT_BOOT})
			},
			refusal: errUrTunExitsMarkInUse,
		},
		{
			name: "the interface's filter strict",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				iface.system.ipv4ConfPath = testTunReversePathFilters(t, map[string]int{"all": 0, "eth0": 1})
			},
			refusal: errUrTunExitsStrictReversePath,
		},
		{
			name: "all's filter strict",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				iface.system.ipv4ConfPath = testTunReversePathFilters(t, map[string]int{"all": 1, "eth0": 2})
			},
			refusal: errUrTunExitsStrictReversePath,
		},
		{
			name: "a filter that does not read",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				iface.system.ipv4ConfPath = testTunReversePathFilters(t, map[string]int{"all": 0})
			},
			refusal: errors.New("did not read"),
		},
		{
			name: "filters off",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				iface.system.ipv4ConfPath = testTunReversePathFilters(t, map[string]int{"all": 0, "eth0": 0})
			},
		},
		{
			name: "ur's own leftover rule",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.rules = append(netlink.rules, urTunLinuxRule{family: unix.AF_INET, table: iface.system.settings.ExitsTable,
					flags: unix.FIB_RULE_INVERT, priority: iface.system.settings.ExitsRulePriority + 1,
					mark: iface.system.settings.ExitsMark, markSet: true, suppressPrefixLength: -1, protocol: urTunRouteProtocol})
			},
		},
		{
			name: "an IPv6 rule on the mark",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.rules = append(netlink.rules, urTunLinuxRule{family: unix.AF_INET6, table: 100, priority: 1000,
					mark: iface.system.settings.ExitsMark, markSet: true, suppressPrefixLength: -1, protocol: unix.RTPROT_BOOT})
			},
			refusal: errUrTunExitsMarkInUse,
		},
		{
			name: "an IPv6 rule on the table",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.rules = append(netlink.rules, urTunLinuxRule{family: unix.AF_INET6, table: iface.system.settings.ExitsTable,
					priority: 1000, suppressPrefixLength: -1, protocol: unix.RTPROT_BOOT})
			},
			refusal: errUrTunExitsMarkInUse,
		},
		{
			name: "ur's own leftover IPv6 rule",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.rules = append(netlink.rules, urTunLinuxRule{family: unix.AF_INET6, table: iface.system.settings.ExitsTable,
					flags: unix.FIB_RULE_INVERT, priority: iface.system.settings.ExitsRulePriority + 1,
					mark: iface.system.settings.ExitsMark, markSet: true, suppressPrefixLength: -1, protocol: urTunRouteProtocol})
			},
		},
		{
			name: "a multicast family's rule on the table",
			change: func(iface *urTunLinuxInterface, netlink *testTunNetlink) {
				netlink.rules = append(netlink.rules, urTunLinuxRule{family: testTunLinuxIpmrFamily, table: iface.system.settings.ExitsTable,
					priority: 1000, suppressPrefixLength: -1, protocol: unix.RTPROT_BOOT})
			},
		},
	}
	for _, c := range cases {
		iface, netlink := newTestTunLinuxExits(t)
		c.change(iface, netlink)
		defaultRoute, err := iface.SetExits(true)
		events, kickCount := netlink.take()
		if c.refusal == nil {
			if err != nil || !defaultRoute || kickCount != 1 {
				t.Errorf("%s: %t %v", c.name, defaultRoute, err)
			}
			continue
		}
		matched := errors.Is(err, c.refusal) || (err != nil && strings.Contains(err.Error(), c.refusal.Error()))
		if !matched || defaultRoute || len(events) != 0 || kickCount != 0 {
			t.Errorf("%s: %t %v, %d events, %d kicks", c.name, defaultRoute, err, len(events), kickCount)
		}
	}
}

// A device that only closes, for an interface whose Close is under test.
type testTunClosingDevice struct {
	events chan tun.Event
	closed bool
}

func (self *testTunClosingDevice) File() *os.File { return nil }

func (self *testTunClosingDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return 0, os.ErrClosed
}

func (self *testTunClosingDevice) Write(bufs [][]byte, offset int) (int, error) {
	return 0, os.ErrClosed
}

func (self *testTunClosingDevice) MTU() (int, error) { return 1280, nil }

func (self *testTunClosingDevice) Name() (string, error) { return "ur-test", nil }

func (self *testTunClosingDevice) Events() <-chan tun.Event { return self.events }

func (self *testTunClosingDevice) Close() error {
	self.closed = true
	return nil
}

func (self *testTunClosingDevice) BatchSize() int { return 1 }

// Close takes the exits off, IPv6's half among them and the mark last, before it removes the routes and closes the
// device.
func TestTunLinuxCloseTakesTheExitsOff(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	device := &testTunClosingDevice{events: make(chan tun.Event)}
	iface.device = device
	iface.eventsDone = make(chan struct{})
	close(iface.eventsDone)
	if _, err := iface.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.70.1.2/32")}); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	netlink.take()
	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}
	events, _ := netlink.take()
	types := []uint16{}
	for _, event := range events {
		types = append(types, event.messageType)
	}
	want := []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELRULE, unix.RTM_DELRULE, unix.RTM_DELROUTE,
		unix.RTM_DELRULE, 0, unix.RTM_DELROUTE}
	if !slices.Equal(types, want) || !device.closed || iface.exitsMark || iface.exitsIpv6Route || iface.exitsIpv6MarkRule {
		t.Fatalf("close: %v, device closed %t", types, device.closed)
	}
	// IPv6's route came off with IPv4's
	if message := testTunParseRouteBody(events[4].body); message.family != unix.AF_INET6 || message.dstBits != 0 ||
		message.table != iface.system.settings.ExitsTable {
		t.Fatalf("close: IPv6's route %+v", message)
	}
	if _, err := iface.SetExits(true); !errors.Is(err, errUrTunClosed) {
		t.Fatalf("exits after close: %v", err)
	}
}

// Under exits each carved IPv4 address takes a throw route in the exits table, after the table's default route and
// before the rule that sends lookups there (QD-808): an off-link resolver, whose lookup would meet the default route
// otherwise, and an on-link gateway and the host's own address, which the main and local tables answer first, take one
// alike; an IPv6 address on the host's own prefix takes none (QD-971). Off exits the carve only waits, and the same
// carve once the exits stand sends nothing more.
func TestTunLinuxExitsThrowEachCarvedAddress(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	resolver := netip.MustParseAddr("198.51.100.53")
	gateway := netip.MustParseAddr("192.0.2.1")
	own := netip.MustParseAddr("192.0.2.10")
	carvedAddrs := []netip.Addr{resolver, gateway, own, netip.MustParseAddr("2001:db8::53"), resolver}
	if err := iface.SetCarved(carvedAddrs); err != nil {
		t.Fatal(err)
	}
	if events, _ := netlink.take(); len(events) != 0 {
		t.Fatalf("off exits the carve sent %d", len(events))
	}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("on: %t %v", defaultRoute, err)
	}
	events, kickCount := netlink.take()
	want := []uint16{0, unix.RTM_NEWROUTE, unix.RTM_NEWROUTE, unix.RTM_NEWROUTE, unix.RTM_NEWROUTE, unix.RTM_NEWRULE,
		unix.RTM_NEWRULE, unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE}
	if types := testTunEventTypes(events); !slices.Equal(types, want) || kickCount != 1 {
		t.Fatalf("events %v, %d kicks", types, kickCount)
	}
	if message := testTunParseRouteBody(events[1].body); message.routeType != unix.RTN_UNICAST || message.dstBits != 0 ||
		message.oif != 7 {
		t.Fatalf("the default route did not go on first: %+v", message)
	}
	addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable)
	if !slices.Equal(addedAddrs, []netip.Addr{gateway, own, resolver}) || len(removedAddrs) != 0 {
		t.Fatalf("throws on %v, off %v", addedAddrs, removedAddrs)
	}
	if err := iface.SetCarved(carvedAddrs); err != nil {
		t.Fatal(err)
	}
	if events, _ := netlink.take(); len(events) != 0 {
		t.Fatalf("the same carve again sent %d", len(events))
	}
}

// Under exits a carve that changes moves the throws at once: the one of an address no longer carved comes off before
// the one of a new address goes on, and the rest stay.
func TestTunLinuxExitsKeepTheThrowsInStep(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	resolver := netip.MustParseAddr("198.51.100.53")
	gateway := netip.MustParseAddr("192.0.2.1")
	moved := netip.MustParseAddr("203.0.113.53")
	if err := iface.SetCarved([]netip.Addr{resolver, gateway}); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	netlink.take()
	if err := iface.SetCarved([]netip.Addr{gateway, moved}); err != nil {
		t.Fatal(err)
	}
	events, _ := netlink.take()
	addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable)
	if !slices.Equal(testTunEventTypes(events), []uint16{unix.RTM_DELROUTE, unix.RTM_NEWROUTE}) ||
		!slices.Equal(removedAddrs, []netip.Addr{resolver}) || !slices.Equal(addedAddrs, []netip.Addr{moved}) {
		t.Fatalf("events %v: on %v, off %v", testTunEventTypes(events), addedAddrs, removedAddrs)
	}
	if throwAddrs := testTunThrowAddrs(iface); !slices.Equal(throwAddrs, []netip.Addr{gateway, moved}) {
		t.Fatalf("throws held %v", throwAddrs)
	}
	// a carve that empties takes every throw off, and the exits stand
	if err := iface.SetCarved(nil); err != nil {
		t.Fatal(err)
	}
	events, _ = netlink.take()
	addedAddrs, removedAddrs = testTunThrows(t, events, settings.ExitsTable)
	if len(addedAddrs) != 0 || !slices.Equal(removedAddrs, []netip.Addr{gateway, moved}) || !iface.exitsRoute {
		t.Fatalf("emptied: on %v, off %v", addedAddrs, removedAddrs)
	}
}

// Off exits the throws come off with the default route, after the rule that sends lookups to the table and before the
// mark, and the carve waits for the next exits; Close takes them off too, so no throw outlives the tun, though the
// kernel would keep one past its device.
func TestTunLinuxExitsTakeTheirThrowsOff(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	carvedAddrs := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.53")}
	if err := iface.SetCarved(carvedAddrs); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	netlink.take()
	if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
		t.Fatalf("off: %t %v", defaultRoute, err)
	}
	events, _ := netlink.take()
	want := []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELROUTE, unix.RTM_DELROUTE, unix.RTM_DELRULE,
		unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELRULE, 0}
	if types := testTunEventTypes(events); !slices.Equal(types, want) {
		t.Fatalf("off: events %v", types)
	}
	if _, removedAddrs := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(removedAddrs, carvedAddrs) ||
		len(testTunThrowAddrs(iface)) != 0 {
		t.Fatalf("off: throws off %v, held %v", removedAddrs, testTunThrowAddrs(iface))
	}
	// off exits a carve sends nothing, and the next exits put it on
	if err := iface.SetCarved(carvedAddrs); err != nil {
		t.Fatal(err)
	}
	if events, _ := netlink.take(); len(events) != 0 {
		t.Fatalf("off exits the carve sent %d", len(events))
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	events, _ = netlink.take()
	if addedAddrs, _ := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(addedAddrs, carvedAddrs) {
		t.Fatalf("on again: throws on %v", addedAddrs)
	}
	device := &testTunClosingDevice{events: make(chan tun.Event)}
	iface.device = device
	iface.eventsDone = make(chan struct{})
	close(iface.eventsDone)
	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}
	events, _ = netlink.take()
	if types := testTunEventTypes(events); !slices.Equal(types, want) || !device.closed {
		t.Fatalf("close: events %v, device closed %t", types, device.closed)
	}
	if _, removedAddrs := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(removedAddrs, carvedAddrs) {
		t.Fatalf("close: throws off %v", removedAddrs)
	}
	if err := iface.SetCarved(carvedAddrs); !errors.Is(err, errUrTunClosed) {
		t.Fatalf("a carve after close: %v", err)
	}
}

// While the rule that sends lookups to the table will not come off, the throws stay as long as the default route does,
// since a lookup of a carved address still meets it; once the route is off they go, and the stuck rule finds a table
// that answers nothing.
func TestTunLinuxExitsKeepTheThrowsWhileTheTableAnswers(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	carvedAddrs := []netip.Addr{netip.MustParseAddr("198.51.100.53")}
	if err := iface.SetCarved(carvedAddrs); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	netlink.take()
	// the mark rule and the route both stick: the throw stays
	netlink.fail = func(n int, messageType uint16) error {
		if messageType == unix.RTM_DELRULE || messageType == unix.RTM_DELROUTE {
			return unix.EBUSY
		}
		return nil
	}
	if _, err := iface.SetExits(false); err == nil {
		t.Fatal("stuck: no error")
	}
	events, _ := netlink.take()
	if _, removedAddrs := testTunThrows(t, events, settings.ExitsTable); len(removedAddrs) != 0 ||
		!slices.Equal(testTunThrowAddrs(iface), carvedAddrs) {
		t.Fatalf("stuck: a throw came off with the table still answering: %v", testTunEventTypes(events))
	}
	// the route comes off, the rule still sticks: the throw goes with the route
	netlink.fail = func(n int, messageType uint16) error {
		if messageType == unix.RTM_DELRULE {
			return unix.EBUSY
		}
		return nil
	}
	if _, err := iface.SetExits(false); err == nil {
		t.Fatal("rule stuck: no error")
	}
	events, _ = netlink.take()
	want := []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELROUTE, unix.RTM_DELRULE, unix.RTM_DELROUTE}
	if _, removedAddrs := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(testTunEventTypes(events), want) ||
		!slices.Equal(removedAddrs, carvedAddrs) || len(testTunThrowAddrs(iface)) != 0 {
		t.Fatalf("rule stuck: events %v, throws held %v", testTunEventTypes(events), testTunThrowAddrs(iface))
	}
}

// A throw the kernel refuses holds nothing: the exits stand and are kicked, the address meets the table's default route
// until SetCarved, which answers the refusal without the address (I-13), puts it on once the kernel takes it; one the
// kernel already holds is taken as on.
func TestTunLinuxExitsStandWhenAThrowIsRefused(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	resolver := netip.MustParseAddr("198.51.100.53")
	if err := iface.SetCarved([]netip.Addr{resolver}); err != nil {
		t.Fatal(err)
	}
	netlink.setThrowErr(unix.ENOBUFS)
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("a refused throw held the exits: %t %v", defaultRoute, err)
	}
	if events, kickCount := netlink.take(); kickCount != 1 || !iface.exitsMarkRule || !iface.exitsSuppressRule ||
		len(testTunThrowAddrs(iface)) != 0 {
		t.Fatalf("on: events %v, %d kicks", testTunEventTypes(events), kickCount)
	}
	err := iface.SetCarved([]netip.Addr{resolver})
	if err == nil || !strings.Contains(err.Error(), "did not go on") || strings.Contains(err.Error(), resolver.String()) {
		t.Fatalf("a refused throw answered %v", err)
	}
	netlink.setThrowErr(nil)
	if err := iface.SetCarved([]netip.Addr{resolver}); err != nil {
		t.Fatal(err)
	}
	events, _ := netlink.take()
	if addedAddrs, _ := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(addedAddrs, []netip.Addr{resolver, resolver}) ||
		!slices.Equal(testTunThrowAddrs(iface), []netip.Addr{resolver}) {
		t.Fatalf("tried %v, held %v", addedAddrs, testTunThrowAddrs(iface))
	}
	gateway := netip.MustParseAddr("192.0.2.1")
	netlink.setThrowErr(unix.EEXIST)
	if err := iface.SetCarved([]netip.Addr{gateway, resolver}); err != nil {
		t.Fatalf("a throw already there: %v", err)
	}
	if throwAddrs := testTunThrowAddrs(iface); !slices.Equal(throwAddrs, []netip.Addr{resolver, gateway}) {
		t.Fatalf("held %v", throwAddrs)
	}
}

// A throw of ur's that the table kept past an end the daemon did not see neither refuses the exits nor outlives the
// carve: the one of an address still carved is taken as on and sent again by nothing, and the one of an address no
// longer carved comes off before the rules go on.
func TestTunLinuxExitsTakeTheirOwnLeftoverThrows(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	kept := netip.MustParseAddr("198.51.100.53")
	stale := netip.MustParseAddr("198.51.100.99")
	for _, address := range []netip.Addr{kept, stale} {
		netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET, table: settings.ExitsTable,
			protocol: urTunRouteProtocol, routeType: unix.RTN_THROW, dst: netip.PrefixFrom(address, 32)})
	}
	if err := iface.SetCarved([]netip.Addr{kept}); err != nil {
		t.Fatal(err)
	}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("on over leftovers: %t %v", defaultRoute, err)
	}
	events, _ := netlink.take()
	addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable)
	want := []uint16{0, unix.RTM_NEWROUTE, unix.RTM_DELROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE, unix.RTM_NEWROUTE,
		unix.RTM_NEWRULE, unix.RTM_NEWRULE}
	if !slices.Equal(testTunEventTypes(events), want) || len(addedAddrs) != 0 ||
		!slices.Equal(removedAddrs, []netip.Addr{stale}) || !slices.Equal(testTunThrowAddrs(iface), []netip.Addr{kept}) {
		t.Fatalf("events %v: on %v, off %v, held %v", testTunEventTypes(events), addedAddrs, removedAddrs,
			testTunThrowAddrs(iface))
	}
}

// The addresses of family a throw holds on iface now.
func testTunThrowAddrsOf(iface *urTunLinuxInterface, family uint8) []netip.Addr {
	throwAddrs := []netip.Addr{}
	for _, address := range testTunThrowAddrs(iface) {
		if address.Is4() == (family == unix.AF_INET) {
			throwAddrs = append(throwAddrs, address)
		}
	}
	return throwAddrs
}

// An interface on newTestTunLinuxExits's recorded system whose host holds its own IPv6 address too, a /128 off any
// prefix of its links in the local table, as DHCPv6 hands one out.
func newTestTunLinuxDualExits(t *testing.T) (*urTunLinuxInterface, *testTunNetlink) {
	t.Helper()
	iface, netlink := newTestTunLinuxExits(t)
	netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET6, table: unix.RT_TABLE_LOCAL,
		protocol: unix.RTPROT_KERNEL, routeType: unix.RTN_LOCAL, dst: netip.MustParsePrefix("2001:db8:10::10/128"),
		oifs: []int{2}})
	return iface, netlink
}

// The carve of the recorded system: an off-link IPv4 resolver and the on-link gateway, then its IPv6 addresses: the
// host's own, its link-local router, zoned as a resolver file may name it, a resolver on its prefix, IPv6's loopback,
// and the off-link IPv6 resolvers offLink names.
func testTunLinuxDualCarve(offLink ...string) []netip.Addr {
	carve := []netip.Addr{netip.MustParseAddr("198.51.100.53"), netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8:10::10"), netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("2001:db8::53"),
		netip.MustParseAddr("::1")}
	for _, address := range offLink {
		carve = append(carve, netip.MustParseAddr(address))
	}
	return carve
}

// Under exits each carved IPv6 address the host reaches only by its IPv6 default route, an off-link resolver, takes an
// IPv6 throw in the exits table after IPv6's default route there and before IPv6's rules, beside IPv4's throws, which
// are as they were (QD-971); the host's own IPv6 address, which the local table answers, a resolver on the host's
// prefix, which the main table does, its link-local router and loopback take none. The same carve once the exits stand
// sends nothing more.
func TestTunLinuxExitsThrowEachOffLinkIpv6Address(t *testing.T) {
	iface, netlink := newTestTunLinuxDualExits(t)
	settings := iface.system.settings
	resolver := netip.MustParseAddr("2001:db8:ffff::53")
	carve := testTunLinuxDualCarve(resolver.String())
	if err := iface.SetCarved(carve); err != nil {
		t.Fatal(err)
	}
	if events, _ := netlink.take(); len(events) != 0 {
		t.Fatalf("off exits the carve sent %d", len(events))
	}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("on: %t %v", defaultRoute, err)
	}
	events, kickCount := netlink.take()
	want := []uint16{0, unix.RTM_NEWROUTE, unix.RTM_NEWROUTE, unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE,
		unix.RTM_NEWROUTE, unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE}
	if types := testTunEventTypes(events); !slices.Equal(types, want) || kickCount != 1 {
		t.Fatalf("events %v, %d kicks", types, kickCount)
	}
	if message := testTunParseRouteBody(events[6].body); message.family != unix.AF_INET6 || message.routeType != unix.RTN_UNICAST ||
		message.dstBits != 0 || message.oif != 7 {
		t.Fatalf("IPv6's default route did not go on before its throw: %+v", message)
	}
	if testTunEventFamily(events[8]) != unix.AF_INET6 || testTunEventFamily(events[9]) != unix.AF_INET6 {
		t.Fatal("IPv6's rules did not follow its throw")
	}
	addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable)
	if !slices.Equal(addedAddrs, []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.53"), resolver}) ||
		len(removedAddrs) != 0 {
		t.Fatalf("throws on %v, off %v", addedAddrs, removedAddrs)
	}
	if message := testTunParseRouteBody(events[7].body); message.routeType != unix.RTN_THROW || message.dst != resolver {
		t.Fatalf("IPv6's throw did not follow its default route: %+v", message)
	}
	if err := iface.SetCarved(carve); err != nil {
		t.Fatal(err)
	}
	if events, _ := netlink.take(); len(events) != 0 {
		t.Fatalf("the same carve again sent %d", len(events))
	}
	if throwAddrs := testTunThrowAddrsOf(iface, unix.AF_INET6); !slices.Equal(throwAddrs, []netip.Addr{resolver}) {
		t.Fatalf("IPv6's throws held %v", throwAddrs)
	}
}

// Under exits IPv6's throws follow the carve and the host's IPv6 routes at each SetCarved, IPv4's left as they are
// (QD-971): a carve that changes takes the throw of an address no longer carved off before a new one's goes on; a route
// of the host's own that comes to hold an address takes its throw off; where the main table's IPv6 default route goes,
// so the host reaches none of them, they all come off, and they come back with it; and a carve that empties takes
// them off with the exits standing.
func TestTunLinuxExitsKeepTheIpv6ThrowsInStep(t *testing.T) {
	iface, netlink := newTestTunLinuxDualExits(t)
	settings := iface.system.settings
	first := netip.MustParseAddr("2001:db8:ffff::53")
	moved := netip.MustParseAddr("2001:db8:ffff::54")
	other := netip.MustParseAddr("2001:db8:fffe::53")
	ipv4Throws := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.53")}
	if err := iface.SetCarved(testTunLinuxDualCarve(first.String(), other.String())); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	netlink.take()
	step := func(what string, carve []netip.Addr, wantTypes []uint16, wantOn []netip.Addr, wantOff []netip.Addr,
		wantHeld []netip.Addr) {
		t.Helper()
		if err := iface.SetCarved(carve); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		events, _ := netlink.take()
		addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable)
		if types := testTunEventTypes(events); !slices.Equal(types, wantTypes) || !slices.Equal(addedAddrs, wantOn) ||
			!slices.Equal(removedAddrs, wantOff) {
			t.Fatalf("%s: events %v, on %v, off %v", what, types, addedAddrs, removedAddrs)
		}
		if held := testTunThrowAddrsOf(iface, unix.AF_INET6); !slices.Equal(held, wantHeld) {
			t.Fatalf("%s: IPv6's throws held %v", what, held)
		}
		if held := testTunThrowAddrsOf(iface, unix.AF_INET); !slices.Equal(held, ipv4Throws) {
			t.Fatalf("%s: IPv4's throws held %v", what, held)
		}
	}
	none := []netip.Addr{}
	step("a changed carve", testTunLinuxDualCarve(moved.String(), other.String()),
		[]uint16{unix.RTM_DELROUTE, unix.RTM_NEWROUTE}, []netip.Addr{moved}, []netip.Addr{first},
		[]netip.Addr{other, moved})
	// a route of the host's own comes to hold one: the main table answers it ahead of the exits table
	netlink.replaceRoutes(func(route urTunLinuxRoute) bool { return false }, urTunLinuxRoute{family: unix.AF_INET6,
		table: unix.RT_TABLE_MAIN, protocol: unix.RTPROT_BOOT, routeType: unix.RTN_UNICAST,
		dst: netip.MustParsePrefix("2001:db8:ffff::/64"), oifs: []int{3}})
	step("an address a route came to hold", testTunLinuxDualCarve(moved.String(), other.String()),
		[]uint16{unix.RTM_DELROUTE}, none, []netip.Addr{moved}, []netip.Addr{other})
	// the main table's IPv6 default route goes: the host reaches none of them, and the exits stand
	netlink.dropIpv6DefaultRoute()
	step("no IPv6 default route", testTunLinuxDualCarve(moved.String(), other.String()),
		[]uint16{unix.RTM_DELROUTE}, none, []netip.Addr{other}, none)
	// it comes back, through the tun's own device: still none
	netlink.replaceRoutes(func(route urTunLinuxRoute) bool { return false }, urTunLinuxRoute{family: unix.AF_INET6,
		table: unix.RT_TABLE_MAIN, protocol: unix.RTPROT_BOOT, routeType: unix.RTN_UNICAST,
		dst: netip.MustParsePrefix("::/0"), oifs: []int{7}})
	step("an IPv6 default route through the tun", testTunLinuxDualCarve(moved.String(), other.String()),
		[]uint16{}, none, none, none)
	// it comes back by eth0's router
	netlink.replaceRoutes(func(route urTunLinuxRoute) bool { return false }, testTunLinuxIpv6DefaultRoute())
	step("IPv6's default route back", testTunLinuxDualCarve(moved.String(), other.String()),
		[]uint16{unix.RTM_NEWROUTE}, []netip.Addr{other}, none, []netip.Addr{other})
	// a carve with no IPv6 address off the host takes IPv6's off, and IPv4's stay
	step("an emptied IPv6 carve", testTunLinuxDualCarve(), []uint16{unix.RTM_DELROUTE}, none, []netip.Addr{other}, none)
	if !iface.exitsIpv6Route || !iface.exitsIpv6MarkRule {
		t.Fatal("the exits fell")
	}
}

// Off exits IPv6's throws come off after IPv6's rule that sends lookups to the table and its default route, before its
// rule that keeps the main table's routes ahead and before the mark, as IPv4's come off in IPv4's half; off exits the
// carve sends nothing, the next exits put them on again, and Close takes them off too, so no throw outlives the tun.
func TestTunLinuxExitsTakeTheirIpv6ThrowsOff(t *testing.T) {
	iface, netlink := newTestTunLinuxDualExits(t)
	settings := iface.system.settings
	resolvers := []netip.Addr{netip.MustParseAddr("2001:db8:fffe::53"), netip.MustParseAddr("2001:db8:ffff::53")}
	carve := testTunLinuxDualCarve(resolvers[1].String(), resolvers[0].String())
	if err := iface.SetCarved(carve); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	netlink.take()
	want := []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELROUTE, unix.RTM_DELROUTE, unix.RTM_DELRULE,
		unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELROUTE, unix.RTM_DELROUTE, unix.RTM_DELRULE, 0}
	checkOff := func(what string, events []testTunNetlinkEvent) {
		t.Helper()
		if types := testTunEventTypes(events); !slices.Equal(types, want) {
			t.Fatalf("%s: events %v", what, types)
		}
		// IPv6's half comes off in its order: its rule, its default route, its throws, its other rule
		for i, family := range []uint8{unix.AF_INET6, unix.AF_INET6, unix.AF_INET6, unix.AF_INET6, unix.AF_INET6} {
			if testTunEventFamily(events[5+i]) != family {
				t.Fatalf("%s: event %d of family %d", what, 5+i, testTunEventFamily(events[5+i]))
			}
		}
		if _, removedAddrs := testTunThrows(t, events[5:], settings.ExitsTable); !slices.Equal(removedAddrs, resolvers) {
			t.Fatalf("%s: IPv6's throws off %v", what, removedAddrs)
		}
		if held := testTunThrowAddrs(iface); 0 < len(held) {
			t.Fatalf("%s: throws held %v", what, held)
		}
	}
	if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
		t.Fatalf("off: %t %v", defaultRoute, err)
	}
	events, _ := netlink.take()
	checkOff("off", events)
	if err := iface.SetCarved(carve); err != nil {
		t.Fatal(err)
	}
	if events, _ := netlink.take(); len(events) != 0 {
		t.Fatalf("off exits the carve sent %d", len(events))
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	events, _ = netlink.take()
	if addedAddrs, _ := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(addedAddrs,
		[]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.53"), resolvers[0], resolvers[1]}) {
		t.Fatalf("on again: throws on %v", addedAddrs)
	}
	device := &testTunClosingDevice{events: make(chan tun.Event)}
	iface.device = device
	iface.eventsDone = make(chan struct{})
	close(iface.eventsDone)
	if err := iface.Close(); err != nil {
		t.Fatal(err)
	}
	events, _ = netlink.take()
	checkOff("close", events)
	if !device.closed {
		t.Fatal("the device stayed open")
	}
}

// While IPv6's rule that sends lookups to the table and its default route there will not come off, IPv6's throws stay,
// since a lookup of a carved address still meets that route; once the route is off they go, and the stuck rule finds
// a table that answers nothing. IPv4's half comes off meanwhile with its own throws.
func TestTunLinuxExitsKeepTheIpv6ThrowsWhileTheTableAnswers(t *testing.T) {
	iface, netlink := newTestTunLinuxDualExits(t)
	settings := iface.system.settings
	resolver := netip.MustParseAddr("2001:db8:ffff::53")
	if err := iface.SetCarved(testTunLinuxDualCarve(resolver.String())); err != nil {
		t.Fatal(err)
	}
	if _, err := iface.SetExits(true); err != nil {
		t.Fatal(err)
	}
	netlink.take()
	// IPv6's rule and route both stick: its throw stays, and IPv4's go
	netlink.setRefuse(func(family uint8, messageType uint16) error {
		if family == unix.AF_INET6 && (messageType == unix.RTM_DELRULE || messageType == unix.RTM_DELROUTE) {
			return unix.EBUSY
		}
		return nil
	})
	if _, err := iface.SetExits(false); err == nil {
		t.Fatal("stuck: no error")
	}
	events, _ := netlink.take()
	if _, removedAddrs := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(removedAddrs,
		[]netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.53")}) ||
		!slices.Equal(testTunThrowAddrs(iface), []netip.Addr{resolver}) {
		t.Fatalf("stuck: throws off %v, held %v", removedAddrs, testTunThrowAddrs(iface))
	}
	// the route comes off, the rule still sticks: the throw goes with the route
	netlink.setRefuse(func(family uint8, messageType uint16) error {
		if family == unix.AF_INET6 && messageType == unix.RTM_DELRULE {
			return unix.EBUSY
		}
		return nil
	})
	if _, err := iface.SetExits(false); err == nil {
		t.Fatal("rule stuck: no error")
	}
	events, _ = netlink.take()
	want := []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELROUTE}
	if _, removedAddrs := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(testTunEventTypes(events), want) ||
		!slices.Equal(removedAddrs, []netip.Addr{resolver}) || len(testTunThrowAddrs(iface)) != 0 || !iface.exitsMark {
		t.Fatalf("rule stuck: events %v, throws held %v", testTunEventTypes(events), testTunThrowAddrs(iface))
	}
}

// An IPv6 throw the kernel refuses holds nothing: the exits stand and are kicked, IPv4's throws go on, and the address
// meets the table's default route until SetCarved, which answers the refusal without the address (I-13), puts it on
// once the kernel takes it; one the kernel already holds is taken as on.
func TestTunLinuxExitsStandWhenAnIpv6ThrowIsRefused(t *testing.T) {
	iface, netlink := newTestTunLinuxDualExits(t)
	resolver := netip.MustParseAddr("2001:db8:ffff::53")
	carve := testTunLinuxDualCarve(resolver.String())
	if err := iface.SetCarved(carve); err != nil {
		t.Fatal(err)
	}
	netlink.setFamilyThrowErr(unix.AF_INET6, unix.ENOBUFS)
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("a refused IPv6 throw held the exits: %t %v", defaultRoute, err)
	}
	if _, kickCount := netlink.take(); kickCount != 1 || !iface.exitsIpv6MarkRule || !iface.exitsIpv6SuppressRule ||
		len(testTunThrowAddrsOf(iface, unix.AF_INET6)) != 0 || len(testTunThrowAddrsOf(iface, unix.AF_INET)) != 2 {
		t.Fatalf("on: %d kicks, throws held %v", kickCount, testTunThrowAddrs(iface))
	}
	err := iface.SetCarved(carve)
	if err == nil || !strings.Contains(err.Error(), "did not go on") || strings.Contains(err.Error(), "2001:db8") {
		t.Fatalf("a refused IPv6 throw answered %v", err)
	}
	netlink.setFamilyThrowErr(unix.AF_INET6, nil)
	if err := iface.SetCarved(carve); err != nil {
		t.Fatal(err)
	}
	if held := testTunThrowAddrsOf(iface, unix.AF_INET6); !slices.Equal(held, []netip.Addr{resolver}) {
		t.Fatalf("tried again: held %v", held)
	}
	other := netip.MustParseAddr("2001:db8:fffe::53")
	netlink.setFamilyThrowErr(unix.AF_INET6, unix.EEXIST)
	if err := iface.SetCarved(testTunLinuxDualCarve(resolver.String(), other.String())); err != nil {
		t.Fatalf("an IPv6 throw already there: %v", err)
	}
	if held := testTunThrowAddrsOf(iface, unix.AF_INET6); !slices.Equal(held, []netip.Addr{resolver, other}) {
		t.Fatalf("held %v", held)
	}
}

// An IPv6 throw of ur's that the table kept past an end the daemon did not see neither refuses the exits nor outlives
// the carve: the one of an address still carved is taken as on and sent again by nothing, and the one of an address no
// longer carved comes off after IPv6's default route goes on and before its rules.
func TestTunLinuxExitsTakeTheirOwnLeftoverIpv6Throws(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	kept := netip.MustParseAddr("2001:db8:ffff::53")
	stale := netip.MustParseAddr("2001:db8:ffff::99")
	for _, address := range []netip.Addr{kept, stale} {
		netlink.routes = append(netlink.routes, urTunLinuxRoute{family: unix.AF_INET6, table: settings.ExitsTable,
			protocol: urTunRouteProtocol, routeType: unix.RTN_THROW, dst: netip.PrefixFrom(address, 128), oifs: []int{1}})
	}
	if err := iface.SetCarved([]netip.Addr{kept}); err != nil {
		t.Fatal(err)
	}
	if defaultRoute, err := iface.SetExits(true); err != nil || !defaultRoute {
		t.Fatalf("on over leftovers: %t %v", defaultRoute, err)
	}
	events, _ := netlink.take()
	addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable)
	want := []uint16{0, unix.RTM_NEWROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE, unix.RTM_NEWROUTE, unix.RTM_DELROUTE,
		unix.RTM_NEWRULE, unix.RTM_NEWRULE}
	if !slices.Equal(testTunEventTypes(events), want) || len(addedAddrs) != 0 ||
		!slices.Equal(removedAddrs, []netip.Addr{stale}) || !slices.Equal(testTunThrowAddrs(iface), []netip.Addr{kept}) {
		t.Fatalf("events %v: on %v, off %v, held %v", testTunEventTypes(events), addedAddrs, removedAddrs,
			testTunThrowAddrs(iface))
	}
}

// Which carved IPv6 addresses take a throw over the host's routes (QD-971): one the host reaches only by the main
// table's IPv6 default route through another interface, once; none that a more specific route of the main table holds,
// whatever its type but a throw, or one of the local table; none that is link-local, loopback, multicast or IPv4; and
// none where the main table has no IPv6 default route off the host, through the tun's own device or of another table.
func TestTunLinuxIpv6ThrowsReadTheRoutes(t *testing.T) {
	address := netip.MustParseAddr("2001:db8:ffff::53")
	ipv6Default := testTunLinuxIpv6DefaultRoute()
	inside := netip.MustParsePrefix("2001:db8:ffff::/64")
	route := func(table uint32, routeType uint8, dst netip.Prefix, oifs ...int) urTunLinuxRoute {
		return urTunLinuxRoute{family: unix.AF_INET6, table: table, protocol: unix.RTPROT_BOOT, routeType: routeType, dst: dst,
			oifs: oifs}
	}
	carve := []netip.Addr{address, address, netip.MustParseAddr("fe80::53"), netip.MustParseAddr("::1"),
		netip.MustParseAddr("ff02::1:3"), netip.MustParseAddr("198.51.100.53")}
	for name, c := range map[string]struct {
		routes []urTunLinuxRoute
		want   []netip.Addr
	}{
		"the default route alone": {routes: []urTunLinuxRoute{ipv6Default}, want: []netip.Addr{address}},
		"an IPv4 route that holds it": {routes: []urTunLinuxRoute{ipv6Default, {family: unix.AF_INET, table: unix.RT_TABLE_MAIN,
			routeType: unix.RTN_UNICAST, dst: netip.MustParsePrefix("198.51.100.0/24"), oifs: []int{2}}}, want: []netip.Addr{address}},
		"a route of another table": {routes: []urTunLinuxRoute{ipv6Default, route(100, unix.RTN_UNICAST, inside, 3)},
			want: []netip.Addr{address}},
		"a throw of the main table's": {routes: []urTunLinuxRoute{ipv6Default, route(unix.RT_TABLE_MAIN, unix.RTN_THROW, inside)},
			want: []netip.Addr{address}},
		"an on-link prefix": {routes: []urTunLinuxRoute{ipv6Default, route(unix.RT_TABLE_MAIN, unix.RTN_UNICAST, inside, 2)},
			want: []netip.Addr{}},
		"an unreachable route": {routes: []urTunLinuxRoute{ipv6Default, route(unix.RT_TABLE_MAIN, unix.RTN_UNREACHABLE, inside)},
			want: []netip.Addr{}},
		"a route through the tun": {routes: []urTunLinuxRoute{ipv6Default, route(unix.RT_TABLE_MAIN, unix.RTN_UNICAST, inside, 7)},
			want: []netip.Addr{}},
		"the local table": {routes: []urTunLinuxRoute{ipv6Default, route(unix.RT_TABLE_LOCAL, unix.RTN_LOCAL,
			netip.PrefixFrom(address, 128), 2)}, want: []netip.Addr{}},
		"no default route": {routes: []urTunLinuxRoute{}, want: []netip.Addr{}},
		"a default route through the tun": {routes: []urTunLinuxRoute{route(unix.RT_TABLE_MAIN, unix.RTN_UNICAST,
			netip.MustParsePrefix("::/0"), 7)}, want: []netip.Addr{}},
		"a default route of another table": {routes: []urTunLinuxRoute{route(100, unix.RTN_UNICAST,
			netip.MustParsePrefix("::/0"), 2)}, want: []netip.Addr{}},
		"an unreachable default route": {routes: []urTunLinuxRoute{route(unix.RT_TABLE_MAIN, unix.RTN_UNREACHABLE,
			netip.MustParsePrefix("::/0"))}, want: []netip.Addr{}},
	} {
		if throwAddrs := urTunLinuxIpv6Throws(carve, c.routes, 7); !slices.Equal(throwAddrs, c.want) {
			t.Errorf("%s: %v", name, throwAddrs)
		}
	}
}

// A device whose read waits for its close, for an interface under a running tun's loops.
type testTunIdleDevice struct {
	closed    chan struct{}
	closeOnce sync.Once
}

func newTestTunIdleDevice() *testTunIdleDevice {
	return &testTunIdleDevice{closed: make(chan struct{})}
}

func (self *testTunIdleDevice) File() *os.File { return nil }

func (self *testTunIdleDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-self.closed
	return 0, os.ErrClosed
}

func (self *testTunIdleDevice) Write(bufs [][]byte, offset int) (int, error) { return len(bufs), nil }

func (self *testTunIdleDevice) MTU() (int, error) { return 1280, nil }

func (self *testTunIdleDevice) Name() (string, error) { return "ur-test", nil }

func (self *testTunIdleDevice) Events() <-chan tun.Event { return nil }

func (self *testTunIdleDevice) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return nil
}

func (self *testTunIdleDevice) BatchSize() int { return 1 }

// A platform whose one device is a Linux interface over a recorder, and whose local addresses and watch are the fake
// platform's.
type testTunRecordedSystem struct {
	*testTunSystem
	linux *urTunLinuxInterface
}

func (self *testTunRecordedSystem) Open(name string, mtu int) (urTunInterface, error) {
	return self.linux, nil
}

// What a sync left: its error, and the throws the interface held once it ended.
type testTunCarveSync struct {
	err        error
	throwAddrs []netip.Addr
}

// Through the tun's own sync, over the Linux interface and a recorder: the local addresses the tun hands the bridge
// reach the exits table as throws once the exits stand, a local read that drops one has the next sync take its throw
// off, a throw the kernel refuses is the sync's error, tried again, with the exits standing, and the close takes every
// throw off.
func TestTunLinuxSyncKeepsTheCarveInTheExitsTable(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	iface.device = newTestTunIdleDevice()
	iface.eventsDone = make(chan struct{})
	close(iface.eventsDone)
	resolver := netip.MustParseAddr("198.51.100.53")
	gateway := netip.MustParseAddr("192.0.2.1")
	system := &testTunRecordedSystem{testTunSystem: newTestTunSystem(), linux: iface}
	system.setLocal([]netip.Addr{gateway, resolver, netip.MustParseAddr("2001:db8::53")})
	tunBridge := newTestTunBridge()
	tunBridge.status.EgressMode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	tunBridge.status.EgressExitCount = 1
	// no zones, so no sync reaches the host's resolver
	tunBridge.zones = nil
	syncs := make(chan testTunCarveSync, 1024)
	tun, err := startUrTun(context.Background(), &urTunArgs{
		Name:      "ur-test",
		NetworkId: sidecar.NewId(),
		System:    system,
		Bridge:    tunBridge,
		Links:     &testTunLinks{},
		Settings:  settings,
		OnSync: func(err error) {
			select {
			case syncs <- testTunCarveSync{err: err, throwAddrs: testTunThrowAddrs(iface)}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tun.close)
	waitSync := func(what string, done func(carveSync testTunCarveSync) bool) {
		t.Helper()
		deadline := time.After(urTestTimeout)
		for {
			select {
			case carveSync := <-syncs:
				if done(carveSync) {
					return
				}
			case <-deadline:
				t.Fatalf("waited too long for %s", what)
			}
		}
	}
	// the local read handing the bridge its addresses again, on the platform's watch
	readLocal := func(localAddrs []netip.Addr) {
		t.Helper()
		system.setLocal(localAddrs)
		tun.wantLocal()
		waitTunEvents(t, tunBridge.events, "the local read", func() bool {
			localSets, _ := tunBridge.lastLocal()
			return slices.Equal(localSets[len(localSets)-1], localAddrs)
		})
		// the bridge's own SetLocalAddresses calls its change callbacks; the fake's are called here
		tunBridge.changed()
	}

	// the first sync runs before the first local read, so the one after it puts the throws on
	waitSync("the carve's throws", func(carveSync testTunCarveSync) bool {
		return carveSync.err == nil && slices.Equal(carveSync.throwAddrs, []netip.Addr{gateway, resolver})
	})
	events, _ := netlink.take()
	if addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(addedAddrs,
		[]netip.Addr{gateway, resolver}) || len(removedAddrs) != 0 {
		t.Fatalf("throws on %v, off %v", addedAddrs, removedAddrs)
	}
	if status := tun.status(); !status.DefaultRoute || status.ExitsHeld || status.SyncError != "" {
		t.Fatalf("on: %+v", status)
	}

	// a resolver dropped from the host's addresses: the next sync takes its throw off
	readLocal([]netip.Addr{gateway})
	waitSync("the dropped address's throw to come off", func(carveSync testTunCarveSync) bool {
		return slices.Equal(carveSync.throwAddrs, []netip.Addr{gateway})
	})
	events, _ = netlink.take()
	if addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable); len(addedAddrs) != 0 ||
		!slices.Equal(removedAddrs, []netip.Addr{resolver}) {
		t.Fatalf("dropped: throws on %v, off %v", addedAddrs, removedAddrs)
	}

	// a throw the kernel refuses is the sync's error, not a hold, and goes on at a later sync
	netlink.setThrowErr(unix.ENOBUFS)
	readLocal([]netip.Addr{gateway, resolver})
	waitSync("a sync whose throw is refused", func(carveSync testTunCarveSync) bool { return carveSync.err != nil })
	status := tun.status()
	if !status.DefaultRoute || status.ExitsHeld || !strings.Contains(status.SyncError, "did not go on") ||
		strings.Contains(status.SyncError, resolver.String()) {
		t.Fatalf("refused: %+v", status)
	}
	netlink.setThrowErr(nil)
	tunBridge.changed()
	waitSync("the refused throw on a later sync", func(carveSync testTunCarveSync) bool {
		return carveSync.err == nil && slices.Equal(carveSync.throwAddrs, []netip.Addr{gateway, resolver})
	})
	if status := tun.status(); status.SyncError != "" || !status.DefaultRoute {
		t.Fatalf("retried: %+v", status)
	}

	// the close takes every throw off
	netlink.take()
	tun.close()
	events, _ = netlink.take()
	if addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable); len(addedAddrs) != 0 ||
		!slices.Equal(removedAddrs, []netip.Addr{gateway, resolver}) || len(testTunThrowAddrs(iface)) != 0 {
		t.Fatalf("close: throws on %v, off %v", addedAddrs, removedAddrs)
	}
}

// Through the tun's own sync, over the Linux interface and a recorder (QD-971): the off-link IPv6 resolvers among the
// local addresses the tun hands the bridge reach the exits table as IPv6 throws once the exits stand, beside IPv4's
// gateway, while the host's own IPv6 address and a resolver on its prefix take none; a local read that drops one has
// the next sync take its throw off; a sync that finds the IPv6 default route gone takes the rest off, the exits
// standing; and the close takes every throw off.
func TestTunLinuxSyncKeepsTheIpv6CarveInTheExitsTable(t *testing.T) {
	iface, netlink := newTestTunLinuxDualExits(t)
	settings := iface.system.settings
	iface.device = newTestTunIdleDevice()
	iface.eventsDone = make(chan struct{})
	close(iface.eventsDone)
	gateway := netip.MustParseAddr("192.0.2.1")
	resolver := netip.MustParseAddr("2001:db8:ffff::53")
	other := netip.MustParseAddr("2001:db8:fffe::53")
	// the host's own addresses, its link-local router, which goes with its IPv6 default route, among them
	host := []netip.Addr{gateway, netip.MustParseAddr("2001:db8:10::10"), netip.MustParseAddr("2001:db8::53")}
	router := netip.MustParseAddr("fe80::1")
	system := &testTunRecordedSystem{testTunSystem: newTestTunSystem(), linux: iface}
	system.setLocal(append(slices.Clone(host), router, resolver, other))
	tunBridge := newTestTunBridge()
	tunBridge.status.EgressMode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	tunBridge.status.EgressExitCount = 1
	// no zones, so no sync reaches the host's resolver
	tunBridge.zones = nil
	syncs := make(chan testTunCarveSync, 1024)
	tun, err := startUrTun(context.Background(), &urTunArgs{
		Name:      "ur-test",
		NetworkId: sidecar.NewId(),
		System:    system,
		Bridge:    tunBridge,
		Links:     &testTunLinks{},
		Settings:  settings,
		OnSync: func(err error) {
			select {
			case syncs <- testTunCarveSync{err: err, throwAddrs: testTunThrowAddrs(iface)}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tun.close)
	waitSync := func(what string, done func(carveSync testTunCarveSync) bool) {
		t.Helper()
		deadline := time.After(urTestTimeout)
		for {
			select {
			case carveSync := <-syncs:
				if done(carveSync) {
					return
				}
			case <-deadline:
				t.Fatalf("waited too long for %s", what)
			}
		}
	}
	// the local read handing the bridge its addresses again, on the platform's watch
	readLocal := func(localAddrs []netip.Addr) {
		t.Helper()
		want := slices.Clone(localAddrs)
		slices.SortFunc(want, netip.Addr.Compare)
		system.setLocal(localAddrs)
		tun.wantLocal()
		waitTunEvents(t, tunBridge.events, "the local read", func() bool {
			localSets, _ := tunBridge.lastLocal()
			return slices.Equal(localSets[len(localSets)-1], want)
		})
		// the bridge's own SetLocalAddresses calls its change callbacks; the fake's are called here
		tunBridge.changed()
	}

	// the first sync runs before the first local read, so the one after it puts the throws on
	waitSync("the carve's throws", func(carveSync testTunCarveSync) bool {
		return carveSync.err == nil && slices.Equal(carveSync.throwAddrs, []netip.Addr{gateway, other, resolver})
	})
	events, _ := netlink.take()
	if addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable); !slices.Equal(addedAddrs,
		[]netip.Addr{gateway, other, resolver}) || len(removedAddrs) != 0 {
		t.Fatalf("throws on %v, off %v", addedAddrs, removedAddrs)
	}
	if status := tun.status(); !status.DefaultRoute || status.ExitsHeld || status.SyncError != "" {
		t.Fatalf("on: %+v", status)
	}

	// a resolver dropped from the host's addresses: the next sync takes its throw off
	readLocal(append(slices.Clone(host), router, other))
	waitSync("the dropped IPv6 address's throw to come off", func(carveSync testTunCarveSync) bool {
		return slices.Equal(carveSync.throwAddrs, []netip.Addr{gateway, other})
	})
	events, _ = netlink.take()
	if addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable); len(addedAddrs) != 0 ||
		!slices.Equal(removedAddrs, []netip.Addr{resolver}) {
		t.Fatalf("dropped: throws on %v, off %v", addedAddrs, removedAddrs)
	}

	// the IPv6 default route goes, and its router with it from the host's addresses: the next sync takes IPv6's throws
	// off, and the exits stand
	netlink.dropIpv6DefaultRoute()
	readLocal(append(slices.Clone(host), other))
	waitSync("IPv6's throws to come off with its default route", func(carveSync testTunCarveSync) bool {
		return carveSync.err == nil && slices.Equal(carveSync.throwAddrs, []netip.Addr{gateway})
	})
	if status := tun.status(); !status.DefaultRoute || status.ExitsHeld || status.SyncError != "" {
		t.Fatalf("no IPv6 default route: %+v", status)
	}

	// the close takes every throw off
	netlink.take()
	tun.close()
	events, _ = netlink.take()
	if addedAddrs, removedAddrs := testTunThrows(t, events, settings.ExitsTable); len(addedAddrs) != 0 ||
		!slices.Equal(removedAddrs, []netip.Addr{gateway}) || len(testTunThrowAddrs(iface)) != 0 {
		t.Fatalf("close: throws on %v, off %v", addedAddrs, removedAddrs)
	}
}

// In the kernel, in the container's own network namespace: under exits a socket made unmarked takes the tun's way and
// one carrying the exits mark keeps the host's own, the two rules and the table's route stand as the unit tests say,
// and off exits all of it goes, connect's mark too. Never on a real host's routes.
func TestTunLinuxExitsRouteByTheMarkInTheKernel(t *testing.T) {
	requireTunContainer(t, "1")
	settings := testUrTunSettings()
	system := newUrTunLinuxSystem(settings, nil).(*urTunLinuxSystem)
	opened, err := system.Open("ur-exits", 1280)
	if err != nil {
		t.Fatal(err)
	}
	iface := opened.(*urTunLinuxInterface)
	defer iface.Close()
	overlay := netip.MustParseAddr("100.70.9.9")
	if err := iface.SetAddresses([]netip.Addr{overlay}); err != nil {
		t.Fatal(err)
	}
	// the local address the kernel picks toward an address beyond the host, unmarked or marked
	localToward := func(mark uint32) netip.Addr {
		t.Helper()
		dialer := &net.Dialer{}
		if mark != 0 {
			dialer.Control = func(network string, address string, raw syscall.RawConn) error {
				var markErr error
				if err := raw.Control(func(fd uintptr) {
					markErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
				}); err != nil {
					return err
				}
				return markErr
			}
		}
		conn, err := dialer.Dial("udp4", "198.51.100.7:9")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return netip.MustParseAddrPort(conn.LocalAddr().String()).Addr()
	}
	before := localToward(0)
	if before == overlay {
		t.Fatal("the tun took the host's traffic before the exits")
	}
	defaultRoute, err := iface.SetExits(true)
	if err != nil || !defaultRoute {
		t.Fatalf("on: %t %v", defaultRoute, err)
	}
	if connect.EgressMark() != settings.ExitsMark {
		t.Fatalf("connect's egress mark %#x", connect.EgressMark())
	}
	if local := localToward(0); local != overlay {
		t.Fatalf("an unmarked socket leaves from %v, not the tun", local)
	}
	if local := localToward(settings.ExitsMark); local != before {
		t.Fatalf("a marked socket leaves from %v, not the host's own %v", local, before)
	}
	rules, err := urTunLinuxRules(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	ours := []urTunLinuxRule{}
	for _, rule := range rules {
		if rule.protocol == urTunRouteProtocol {
			ours = append(ours, rule)
		}
	}
	if len(ours) != 2 || ours[0].priority != settings.ExitsRulePriority || ours[0].suppressPrefixLength != 0 ||
		ours[0].table != unix.RT_TABLE_MAIN || ours[1].priority != settings.ExitsRulePriority+1 ||
		ours[1].mark != settings.ExitsMark || ours[1].table != settings.ExitsTable || ours[1].flags&unix.FIB_RULE_INVERT == 0 {
		t.Fatalf("the kernel's rules of ur's %+v", ours)
	}
	routes, err := urTunLinuxRoutes(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(routes, func(route urTunLinuxRoute) bool {
		return route.table == settings.ExitsTable && route.dst.Bits() == 0 && slices.Contains(route.oifs, iface.index)
	}) {
		t.Fatal("no default route through the tun in the exits table")
	}
	if defaultRoute, err := iface.SetExits(false); err != nil || defaultRoute {
		t.Fatalf("off: %t %v", defaultRoute, err)
	}
	if local := localToward(0); local != before || connect.EgressMark() != 0 {
		t.Fatalf("off: an unmarked socket leaves from %v, connect's mark %#x", local, connect.EgressMark())
	}
	rules, err = urTunLinuxRules(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(rules, func(rule urTunLinuxRule) bool { return rule.protocol == urTunRouteProtocol }) {
		t.Fatal("a rule of ur's outlived the exits")
	}
}

// A Linux platform whose local addresses add a test's to the host's own, as a host whose resolver file names an
// off-link resolver does.
type testTunCarvingSystem struct {
	*urTunLinuxSystem

	stateLock  sync.Mutex
	extraAddrs []netip.Addr
}

func (self *testTunCarvingSystem) LocalAddresses(name string, exclude []netip.Addr) ([]netip.Addr, error) {
	addresses, err := self.urTunLinuxSystem.LocalAddresses(name, exclude)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, address := range self.extraAddrs {
		if !slices.Contains(addresses, address) {
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	return addresses, nil
}

func (self *testTunCarvingSystem) setExtra(extraAddrs []netip.Addr) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.extraAddrs = extraAddrs
}

// A link that takes each packet and signals it: a barrier behind everything the tun read before that packet.
type testTunBarrierLink struct {
	testTunLink
	taken chan struct{}
}

func (self *testTunBarrierLink) SendPacket(source connect.TransferPath, provideMode protocol.ProvideMode, packet []byte, timeout time.Duration) bool {
	connect.MessagePoolReturn(packet)
	select {
	case self.taken <- struct{}{}:
	default:
	}
	return true
}

// In the kernel, in a container's own network namespace with no network but what the test makes, so nothing leaves
// the host: a tun of the test's stands for the physical path, holding the main table's default route and an on-link
// /24. Under exits ur tun's sync puts a throw in the exits table for every carved IPv4 address; a packet to a carved
// off-link resolver and one to a carved on-link gateway leave by the physical path and never reach ur tun, so neither
// counts in default_count, while one to an address not carved rides ur tun; a packet to the host's own carved address
// still reaches its listener; a local read that drops the resolver takes its throw off at the next sync, after which
// its packets ride ur tun; and the close leaves the exits table and the rules empty of ur's.
func TestTunLinuxExitsPassTheCarveBackInTheKernel(t *testing.T) {
	requireTunContainer(t, "isolated")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settings := testUrTunSettings()
	linux := newUrTunLinuxSystem(settings, nil).(*urTunLinuxSystem)
	resolver := netip.MustParseAddr("198.51.100.53")
	gateway := netip.MustParseAddr("192.0.2.1")
	own := netip.MustParseAddr("192.0.2.2")
	uncarved := netip.MustParseAddr("198.51.100.54")

	// the physical path: its address, the main table's default route and an on-link /24
	phys, err := linux.Open("ur-phys", 1280)
	if err != nil {
		t.Fatal(err)
	}
	physAddrs := make(chan netip.Addr, 64)
	physDone := make(chan struct{})
	go func() {
		defer close(physDone)
		bufs := [][]byte{make([]byte, settings.ReadHeadroomByteCount+settings.ReadPacketByteCount)}
		sizes := []int{0}
		for {
			n, err := phys.Read(bufs, sizes, settings.ReadHeadroomByteCount)
			packet := bufs[0][settings.ReadHeadroomByteCount:]
			if n == 1 && 20 <= sizes[0] && packet[0]>>4 == 4 {
				select {
				case physAddrs <- netip.AddrFrom4([4]byte(packet[16:20])):
				default:
				}
			}
			if err != nil && !errors.Is(err, errUrTunSegmentsDropped) {
				return
			}
		}
	}()
	defer func() {
		phys.Close()
		<-physDone
	}()
	if err := phys.SetAddresses([]netip.Addr{own}); err != nil {
		t.Fatal(err)
	}
	physRoutes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("192.0.2.0/24")}
	if conflictCount, err := phys.SetRoutes(physRoutes); err != nil || conflictCount != 0 {
		t.Fatalf("the physical path's routes: %d %v", conflictCount, err)
	}

	system := &testTunCarvingSystem{urTunLinuxSystem: linux, extraAddrs: []netip.Addr{resolver, gateway}}
	tunBridge := newTestTunBridge()
	tunBridge.status.EgressMode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	tunBridge.status.EgressExitCount = 1
	tunBridge.zones = nil
	// every IPv4 packet the tun reads takes the default route, as a carved one does in the bridge, and counts in
	// default_count; the device's own IPv6, a tun's router solicitations and the like, goes to a link that takes it, and
	// a packet to marker goes to a barrier link
	marker := netip.MustParseAddr("198.51.100.55")
	sink := &testTunLink{}
	barrier := &testTunBarrierLink{taken: make(chan struct{}, 64)}
	var routedLock sync.Mutex
	routedAddrs := []netip.Addr{}
	tunBridge.route = func(packet []byte) connect.UserNatClient {
		if len(packet) < 20 || packet[0]>>4 != 4 {
			return sink
		}
		destination := netip.AddrFrom4([4]byte(packet[16:20]))
		if destination == marker {
			return barrier
		}
		routedLock.Lock()
		routedAddrs = append(routedAddrs, destination)
		routedLock.Unlock()
		return nil
	}
	synced := make(chan struct{}, 1024)
	tun, err := startUrTun(ctx, &urTunArgs{
		Name:      "ur-carve",
		NetworkId: sidecar.NewId(),
		System:    system,
		Bridge:    tunBridge,
		Links:     &testTunLinks{},
		Settings:  settings,
		OnSync: func(err error) {
			select {
			case synced <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.close()
	throwsInTable := func() []netip.Addr {
		t.Helper()
		routes, err := urTunLinuxRoutes(unix.AF_INET)
		if err != nil {
			t.Fatal(err)
		}
		throwAddrs := []netip.Addr{}
		for _, route := range routes {
			if urTunLinuxOwnThrow(route, settings.ExitsTable) {
				throwAddrs = append(throwAddrs, route.dst.Addr())
			}
		}
		slices.SortFunc(throwAddrs, netip.Addr.Compare)
		return throwAddrs
	}
	waitSync := func(what string, done func() bool) {
		t.Helper()
		deadline := time.After(urTestTimeout)
		for !done() {
			select {
			case <-synced:
			case <-deadline:
				t.Fatalf("waited too long for %s", what)
			}
		}
	}
	// the carve as the tun handed it to the bridge, the IPv4 addresses of it
	carvedIpv4 := func() []netip.Addr {
		tun.stateLock.Lock()
		defer tun.stateLock.Unlock()
		carvedAddrs := []netip.Addr{}
		for _, address := range tun.localAddrs {
			if address.Is4() {
				carvedAddrs = append(carvedAddrs, address)
			}
		}
		return carvedAddrs
	}
	send := func(destination netip.Addr) {
		t.Helper()
		conn, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination, 53)))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ur tun carve")); err != nil {
			t.Fatal(err)
		}
	}
	// sends a packet to marker and waits for the barrier link to take it: the tun reads in order and routes each read in
	// full before the next, so every packet it read before the marker is routed and counted by then
	settle := func() {
		t.Helper()
		send(marker)
		select {
		case <-barrier.taken:
		case <-time.After(urTestTimeout):
			t.Fatal("the marker never rode ur tun")
		}
	}
	routedOf := func() []netip.Addr {
		routedLock.Lock()
		defer routedLock.Unlock()
		return slices.Clone(routedAddrs)
	}

	// the carve's throws: every carved IPv4 address, the host's own and the on-link gateway among them
	waitSync("the carve's throws", func() bool {
		throwAddrs := throwsInTable()
		return slices.Contains(throwAddrs, resolver) && slices.Contains(throwAddrs, gateway) && slices.Contains(throwAddrs, own)
	})
	if throwAddrs, carvedAddrs := throwsInTable(), carvedIpv4(); !slices.Equal(throwAddrs, carvedAddrs) {
		t.Fatalf("throws %v for the carve %v", throwAddrs, carvedAddrs)
	}
	if status := tun.status(); !status.DefaultRoute || status.ExitsHeld {
		t.Fatalf("on: %+v", status)
	}

	// the carved ones leave by the physical path; the one not carved rides ur tun, and every packet ur tun read before
	// the marker after them counts in default_count, a carved one there among them
	send(resolver)
	send(gateway)
	send(uncarved)
	settle()
	physSeen := []netip.Addr{}
	deadline := time.After(urTestTimeout)
	for !slices.Contains(physSeen, resolver) || !slices.Contains(physSeen, gateway) {
		select {
		case address := <-physAddrs:
			physSeen = append(physSeen, address)
		case <-deadline:
			t.Fatalf("the physical path saw %v", physSeen)
		}
	}
	routedNow := routedOf()
	if !slices.Contains(routedNow, uncarved) || slices.Contains(routedNow, resolver) || slices.Contains(routedNow, gateway) ||
		slices.Contains(physSeen, uncarved) {
		t.Fatalf("ur tun read %v, the physical path %v", routedNow, physSeen)
	}
	if status := tun.status(); status.DefaultCount != uint64(len(routedNow)) {
		t.Fatalf("default_count %d for %v", status.DefaultCount, routedNow)
	}

	// the host's own carved address, whose throw the local table answers first, still reaches its listener
	listener, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(own, 0)))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ownConn, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer ownConn.Close()
	if _, err := ownConn.Write([]byte("own")); err != nil {
		t.Fatal(err)
	}
	listener.SetReadDeadline(time.Now().Add(urTestTimeout))
	received := make([]byte, 16)
	if n, err := listener.Read(received); err != nil || string(received[:n]) != "own" {
		t.Fatalf("the host's own address: %q %v", received[:n], err)
	}

	// a local read that drops the resolver takes its throw off at the next sync, and its packets ride ur tun
	system.setExtra([]netip.Addr{gateway})
	tun.wantLocal()
	waitTunEvents(t, tunBridge.events, "the local read without the resolver", func() bool {
		localSets, _ := tunBridge.lastLocal()
		return !slices.Contains(localSets[len(localSets)-1], resolver)
	})
	// the bridge's own SetLocalAddresses calls its change callbacks; the fake's are called here
	tunBridge.changed()
	waitSync("the resolver's throw to come off", func() bool {
		return !slices.Contains(throwsInTable(), resolver)
	})
	routedBefore := len(routedOf())
	send(resolver)
	settle()
	routedNow = routedOf()
	if !slices.Contains(routedNow[routedBefore:], resolver) {
		t.Fatalf("ur tun did not read the resolver no longer carved: %v", routedNow[routedBefore:])
	}
	if status := tun.status(); status.DefaultCount != uint64(len(routedNow)) {
		t.Fatalf("default_count %d for %v", status.DefaultCount, routedNow)
	}

	// the close leaves no throw, route or rule of ur's in the exits table
	tun.close()
	routes, err := urTunLinuxRoutes(unix.AF_UNSPEC)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.table == settings.ExitsTable {
			t.Fatalf("a route outlived the close in the exits table: %+v", route)
		}
	}
	rules, err := urTunLinuxRules(unix.AF_INET)
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(rules, func(rule urTunLinuxRule) bool { return rule.protocol == urTunRouteProtocol }) {
		t.Fatal("a rule of ur's outlived the close")
	}
}

// In the kernel, in a container's own network namespace with IPv6 on and no network but what the test makes, so nothing
// leaves the host: a tun of the test's stands for the physical path, with an IPv4 and an IPv6 address and the main
// table's default route of each family. Under exits ur tun's sync puts IPv6's default route in the exits table with
// its two rules beside IPv4's (QD-881): a datagram an unmarked socket sends to an IPv6 address beyond the host rides ur
// tun, where the bridge drops IPv6, and never the physical path; one a socket carrying the exits mark sends, as the
// daemon's own do, leaves by the physical path and never rides ur tun; and the close leaves nothing of ur's in the
// exits table or the rules of either family.
func TestTunLinuxExitsTakeIpv6InTheKernel(t *testing.T) {
	requireTunContainer(t, "isolated")
	if content, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err != nil || strings.TrimSpace(string(content)) != "0" {
		t.Skip("IPv6 is off in this namespace: run the container with net.ipv6.conf.all.disable_ipv6=0")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settings := testUrTunSettings()
	linux := newUrTunLinuxSystem(settings, nil).(*urTunLinuxSystem)
	physAddress := netip.MustParseAddr("2001:db8::2")
	unmarkedDestination := netip.MustParseAddr("2001:db8:1::7")
	markedDestination := netip.MustParseAddr("2001:db8:1::8")
	marker := netip.MustParseAddr("2001:db8:1::9")

	// the physical path, and the IPv6 destinations it carries in the order it reads them
	phys, err := linux.Open("ur-phys6", 1280)
	if err != nil {
		t.Fatal(err)
	}
	physIndex := urTunLinuxIndex("ur-phys6")
	physAddrs := make(chan netip.Addr, 64)
	physDone := make(chan struct{})
	go func() {
		defer close(physDone)
		bufs := [][]byte{make([]byte, settings.ReadHeadroomByteCount+settings.ReadPacketByteCount)}
		sizes := []int{0}
		for {
			n, err := phys.Read(bufs, sizes, settings.ReadHeadroomByteCount)
			packet := bufs[0][settings.ReadHeadroomByteCount:]
			if n == 1 && 40 <= sizes[0] && packet[0]>>4 == 6 {
				select {
				case physAddrs <- netip.AddrFrom16([16]byte(packet[24:40])):
				default:
				}
			}
			if err != nil && !errors.Is(err, errUrTunSegmentsDropped) {
				return
			}
		}
	}()
	defer func() {
		phys.Close()
		<-physDone
	}()
	if err := phys.SetAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.2")}); err != nil {
		t.Fatal(err)
	}
	physRoutes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("192.0.2.0/24")}
	if conflictCount, err := phys.SetRoutes(physRoutes); err != nil || conflictCount != 0 {
		t.Fatalf("the physical path's routes: %d %v", conflictCount, err)
	}
	// its IPv6 address, with no duplicate detection so it is a source at once, and the main table's IPv6 default route
	addressBody := make([]byte, unix.SizeofIfAddrmsg)
	addressBody[0] = unix.AF_INET6
	addressBody[1] = 64
	addressBody[2] = unix.IFA_F_NODAD
	addressBody[3] = unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(addressBody[4:8], uint32(physIndex))
	physOctets := physAddress.As16()
	addressBody = append(addressBody, urNetlinkAttribute(unix.IFA_LOCAL, physOctets[:])...)
	addressBody = append(addressBody, urNetlinkAttribute(unix.IFA_ADDRESS, physOctets[:])...)
	if err := linux.request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, addressBody); err != nil {
		t.Fatalf("the physical path's IPv6 address: %v", err)
	}
	ipv6Default := urTunLinuxRouteBody(physIndex, netip.PrefixFrom(netip.IPv6Unspecified(), 0), unix.RT_TABLE_MAIN, 0, true)
	if err := linux.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, ipv6Default); err != nil {
		t.Fatalf("the physical path's IPv6 default route: %v", err)
	}

	tunBridge := newTestTunBridge()
	tunBridge.status.EgressMode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	tunBridge.status.EgressExitCount = 1
	tunBridge.zones = nil
	// every packet ur tun reads goes to a link that takes it, the IPv6 destinations noted in order
	sink := &testTunLink{}
	tunAddrs := make(chan netip.Addr, 64)
	tunBridge.route = func(packet []byte) connect.UserNatClient {
		if 40 <= len(packet) && packet[0]>>4 == 6 {
			select {
			case tunAddrs <- netip.AddrFrom16([16]byte(packet[24:40])):
			default:
			}
		}
		return sink
	}
	synced := make(chan struct{}, 1024)
	tun, err := startUrTun(ctx, &urTunArgs{
		Name:      "ur-ipv6",
		NetworkId: sidecar.NewId(),
		System:    linux,
		Bridge:    tunBridge,
		Links:     &testTunLinks{},
		Settings:  settings,
		OnSync: func(err error) {
			select {
			case synced <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.close()
	tunIndex := urTunLinuxIndex("ur-ipv6")
	ipv6Route := func() bool {
		t.Helper()
		routes, err := urTunLinuxRoutes(unix.AF_INET6)
		if err != nil {
			t.Fatal(err)
		}
		return slices.ContainsFunc(routes, func(route urTunLinuxRoute) bool {
			return route.table == settings.ExitsTable && route.dst.Bits() == 0 && slices.Contains(route.oifs, tunIndex)
		})
	}
	deadline := time.After(urTestTimeout)
	for !ipv6Route() {
		select {
		case <-synced:
		case <-deadline:
			t.Fatal("waited too long for IPv6's default route in the exits table")
		}
	}
	rules, err := urTunLinuxRules(unix.AF_INET6)
	if err != nil {
		t.Fatal(err)
	}
	ours := []urTunLinuxRule{}
	for _, rule := range rules {
		if rule.protocol == urTunRouteProtocol {
			ours = append(ours, rule)
		}
	}
	if len(ours) != 2 || ours[0].priority != settings.ExitsRulePriority || ours[0].suppressPrefixLength != 0 ||
		ours[0].table != unix.RT_TABLE_MAIN || ours[1].priority != settings.ExitsRulePriority+1 ||
		ours[1].mark != settings.ExitsMark || ours[1].table != settings.ExitsTable || ours[1].flags&unix.FIB_RULE_INVERT == 0 {
		t.Fatalf("the kernel's IPv6 rules of ur's %+v", ours)
	}
	if status := tun.status(); !status.DefaultRoute || status.ExitsHeld {
		t.Fatalf("on: %+v", status)
	}

	send := func(destination netip.Addr, mark uint32) {
		t.Helper()
		dialer := &net.Dialer{}
		if mark != 0 {
			dialer.Control = func(network string, address string, raw syscall.RawConn) error {
				var markErr error
				if err := raw.Control(func(fd uintptr) {
					markErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
				}); err != nil {
					return err
				}
				return markErr
			}
		}
		conn, err := dialer.Dial("udp6", netip.AddrPortFrom(destination, 9).String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ur tun ipv6")); err != nil {
			t.Fatal(err)
		}
	}
	// what one of the devices carries until want, in order: a device reads what the kernel queued it in the order it was
	// queued, so a datagram sent before want that took that device comes before it
	until := func(addrs chan netip.Addr, want netip.Addr, what string) []netip.Addr {
		t.Helper()
		seen := []netip.Addr{}
		deadline := time.After(urTestTimeout)
		for !slices.Contains(seen, want) {
			select {
			case address := <-addrs:
				seen = append(seen, address)
			case <-deadline:
				t.Fatalf("%s carried %v, not %v", what, seen, want)
			}
		}
		return seen
	}
	// unmarked, as any program's socket: ur tun carries it, and the physical path does not
	send(unmarkedDestination, 0)
	until(tunAddrs, unmarkedDestination, "ur tun")
	// marked, as the daemon's own: the physical path carries it, and the unmarked one never reached it first
	send(markedDestination, settings.ExitsMark)
	if physSeen := until(physAddrs, markedDestination, "the physical path"); slices.Contains(physSeen, unmarkedDestination) {
		t.Fatalf("the physical path carried the unmarked datagram: %v", physSeen)
	}
	// and ur tun, which reads the marked one before a marker sent after it had it taken ur tun's way, never had it
	send(marker, 0)
	if tunSeen := until(tunAddrs, marker, "ur tun"); slices.Contains(tunSeen, markedDestination) {
		t.Fatalf("ur tun carried the marked datagram: %v", tunSeen)
	}

	// the close leaves nothing of ur's in the exits table or the rules, in either family
	tun.close()
	routes, err := urTunLinuxRoutes(unix.AF_UNSPEC)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.table == settings.ExitsTable {
			t.Fatalf("a route outlived the close in the exits table: %+v", route)
		}
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := urTunLinuxRules(family)
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(rules, func(rule urTunLinuxRule) bool { return rule.protocol == urTunRouteProtocol }) {
			t.Fatalf("a rule of ur's of family %d outlived the close", family)
		}
	}
}

// In the kernel, in a container's own network namespace with IPv6 on and no network but what the test makes, so nothing
// leaves the host (QD-971): a tun of the test's stands for the physical path, with an IPv4 and an IPv6 address, its
// IPv6 prefix on link, and the main table's default route of each family. Under exits ur tun's sync puts an IPv6 throw
// in the exits table for a carved off-link IPv6 resolver and none for a carved resolver on the prefix or the host's own
// IPv6 address; a datagram an unmarked socket sends to the off-link resolver leaves by the physical path and never
// rides ur tun, one to the on-link resolver leaves by it too, and one to an address not carved rides ur tun; a local
// read that drops the resolver takes its throw off at the next sync, after which its datagrams ride ur tun; and the
// close leaves nothing of ur's in the exits table.
func TestTunLinuxExitsPassTheIpv6CarveBackInTheKernel(t *testing.T) {
	requireTunContainer(t, "isolated")
	if content, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err != nil || strings.TrimSpace(string(content)) != "0" {
		t.Skip("IPv6 is off in this namespace: run the container with net.ipv6.conf.all.disable_ipv6=0")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	settings := testUrTunSettings()
	linux := newUrTunLinuxSystem(settings, nil).(*urTunLinuxSystem)
	physAddress := netip.MustParseAddr("2001:db8::2")
	resolver := netip.MustParseAddr("2001:db8:ffff::53")
	onLink := netip.MustParseAddr("2001:db8::53")
	uncarved := netip.MustParseAddr("2001:db8:ffff::54")

	// the physical path, and the IPv6 destinations it carries in the order it reads them
	phys, err := linux.Open("ur-phys6c", 1280)
	if err != nil {
		t.Fatal(err)
	}
	physIndex := urTunLinuxIndex("ur-phys6c")
	physAddrs := make(chan netip.Addr, 64)
	physDone := make(chan struct{})
	go func() {
		defer close(physDone)
		bufs := [][]byte{make([]byte, settings.ReadHeadroomByteCount+settings.ReadPacketByteCount)}
		sizes := []int{0}
		for {
			n, err := phys.Read(bufs, sizes, settings.ReadHeadroomByteCount)
			packet := bufs[0][settings.ReadHeadroomByteCount:]
			if n == 1 && 40 <= sizes[0] && packet[0]>>4 == 6 {
				select {
				case physAddrs <- netip.AddrFrom16([16]byte(packet[24:40])):
				default:
				}
			}
			if err != nil && !errors.Is(err, errUrTunSegmentsDropped) {
				return
			}
		}
	}()
	defer func() {
		phys.Close()
		<-physDone
	}()
	if err := phys.SetAddresses([]netip.Addr{netip.MustParseAddr("192.0.2.2")}); err != nil {
		t.Fatal(err)
	}
	physRoutes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("192.0.2.0/24")}
	if conflictCount, err := phys.SetRoutes(physRoutes); err != nil || conflictCount != 0 {
		t.Fatalf("the physical path's routes: %d %v", conflictCount, err)
	}
	// its IPv6 address on its /64, with no duplicate detection so it is a source at once, which puts the prefix on link,
	// and the main table's IPv6 default route
	addressBody := make([]byte, unix.SizeofIfAddrmsg)
	addressBody[0] = unix.AF_INET6
	addressBody[1] = 64
	addressBody[2] = unix.IFA_F_NODAD
	addressBody[3] = unix.RT_SCOPE_UNIVERSE
	binary.NativeEndian.PutUint32(addressBody[4:8], uint32(physIndex))
	physOctets := physAddress.As16()
	addressBody = append(addressBody, urNetlinkAttribute(unix.IFA_LOCAL, physOctets[:])...)
	addressBody = append(addressBody, urNetlinkAttribute(unix.IFA_ADDRESS, physOctets[:])...)
	if err := linux.request(unix.RTM_NEWADDR, unix.NLM_F_CREATE|unix.NLM_F_EXCL, addressBody); err != nil {
		t.Fatalf("the physical path's IPv6 address: %v", err)
	}
	ipv6Default := urTunLinuxRouteBody(physIndex, netip.PrefixFrom(netip.IPv6Unspecified(), 0), unix.RT_TABLE_MAIN, 0, true)
	if err := linux.request(unix.RTM_NEWROUTE, unix.NLM_F_CREATE|unix.NLM_F_EXCL, ipv6Default); err != nil {
		t.Fatalf("the physical path's IPv6 default route: %v", err)
	}

	system := &testTunCarvingSystem{urTunLinuxSystem: linux, extraAddrs: []netip.Addr{resolver, onLink}}
	tunBridge := newTestTunBridge()
	tunBridge.status.EgressMode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
	tunBridge.status.EgressExitCount = 1
	tunBridge.zones = nil
	// every packet ur tun reads goes to a link that takes it, the IPv6 destinations noted in order
	sink := &testTunLink{}
	tunAddrs := make(chan netip.Addr, 64)
	tunBridge.route = func(packet []byte) connect.UserNatClient {
		if 40 <= len(packet) && packet[0]>>4 == 6 {
			select {
			case tunAddrs <- netip.AddrFrom16([16]byte(packet[24:40])):
			default:
			}
		}
		return sink
	}
	synced := make(chan struct{}, 1024)
	tun, err := startUrTun(ctx, &urTunArgs{
		Name:      "ur-ipv6c",
		NetworkId: sidecar.NewId(),
		System:    system,
		Bridge:    tunBridge,
		Links:     &testTunLinks{},
		Settings:  settings,
		OnSync: func(err error) {
			select {
			case synced <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tun.close()
	ipv6ThrowsInTable := func() []netip.Addr {
		t.Helper()
		routes, err := urTunLinuxRoutes(unix.AF_INET6)
		if err != nil {
			t.Fatal(err)
		}
		throwAddrs := []netip.Addr{}
		for _, route := range routes {
			if urTunLinuxOwnThrow(route, settings.ExitsTable) {
				throwAddrs = append(throwAddrs, route.dst.Addr())
			}
		}
		return throwAddrs
	}
	waitSync := func(what string, done func() bool) {
		t.Helper()
		deadline := time.After(urTestTimeout)
		for !done() {
			select {
			case <-synced:
			case <-deadline:
				t.Fatalf("waited too long for %s", what)
			}
		}
	}
	send := func(destination netip.Addr) {
		t.Helper()
		conn, err := net.DialUDP("udp6", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(destination, 53)))
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ur tun ipv6 carve")); err != nil {
			t.Fatal(err)
		}
	}
	// what one of the devices carries until want, in order: a device reads what the kernel queued it in the order it was
	// queued, so a datagram sent before want that took that device comes before it
	until := func(addrs chan netip.Addr, want netip.Addr, what string) []netip.Addr {
		t.Helper()
		seen := []netip.Addr{}
		deadline := time.After(urTestTimeout)
		for !slices.Contains(seen, want) {
			select {
			case address := <-addrs:
				seen = append(seen, address)
			case <-deadline:
				t.Fatalf("%s carried %v, not %v", what, seen, want)
			}
		}
		return seen
	}

	// the off-link resolver's throw, and none for the on-link resolver or the host's own address
	waitSync("the off-link IPv6 resolver's throw", func() bool {
		return slices.Contains(ipv6ThrowsInTable(), resolver)
	})
	if throwAddrs := ipv6ThrowsInTable(); slices.Contains(throwAddrs, onLink) || slices.Contains(throwAddrs, physAddress) {
		t.Fatalf("IPv6's throws %v", throwAddrs)
	}
	if status := tun.status(); !status.DefaultRoute || status.ExitsHeld {
		t.Fatalf("on: %+v", status)
	}

	// the carved ones leave by the physical path, the on-link one by its prefix; the one not carved rides ur tun, and ur
	// tun, which reads in order, never read a carved one before it
	send(resolver)
	send(onLink)
	if physSeen := until(physAddrs, onLink, "the physical path"); !slices.Contains(physSeen, resolver) {
		t.Fatalf("the physical path carried %v, not the resolver", physSeen)
	}
	send(uncarved)
	if tunSeen := until(tunAddrs, uncarved, "ur tun"); slices.Contains(tunSeen, resolver) || slices.Contains(tunSeen, onLink) {
		t.Fatalf("ur tun carried a carved datagram: %v", tunSeen)
	}

	// a local read that drops the resolver takes its throw off at the next sync, and its datagrams ride ur tun
	system.setExtra([]netip.Addr{onLink})
	tun.wantLocal()
	waitTunEvents(t, tunBridge.events, "the local read without the resolver", func() bool {
		localSets, _ := tunBridge.lastLocal()
		return !slices.Contains(localSets[len(localSets)-1], resolver)
	})
	// the bridge's own SetLocalAddresses calls its change callbacks; the fake's are called here
	tunBridge.changed()
	waitSync("the resolver's throw to come off", func() bool {
		return !slices.Contains(ipv6ThrowsInTable(), resolver)
	})
	send(resolver)
	until(tunAddrs, resolver, "ur tun")

	// the close leaves nothing of ur's in the exits table
	tun.close()
	routes, err := urTunLinuxRoutes(unix.AF_UNSPEC)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range routes {
		if route.table == settings.ExitsTable {
			t.Fatalf("a route outlived the close in the exits table: %+v", route)
		}
	}
}

// Whether iface holds the exits whole, the mark, IPv4's and IPv6's default routes in the exits table and their rules,
// the default routes the plan takes; a test fails on a partial set.
func testTunLinuxExitsHeld(t *testing.T, iface *urTunLinuxInterface) bool {
	t.Helper()
	iface.stateLock.Lock()
	parts := []bool{iface.exitsMark, iface.exitsRoute, iface.exitsSuppressRule, iface.exitsMarkRule, iface.exitsIpv6Route,
		iface.exitsIpv6SuppressRule, iface.exitsIpv6MarkRule}
	iface.stateLock.Unlock()
	on := 0
	for _, part := range parts {
		if part {
			on += 1
		}
	}
	if 0 < on && on < len(parts) {
		t.Errorf("a partial set of the exits %v", parts)
	}
	return on == len(parts)
}

// An interface over the recorder, ready to run under a tun's loops.
func newTestTunLinuxPlanInterface(t *testing.T) (*urTunLinuxInterface, *testTunNetlink) {
	t.Helper()
	iface, netlink := newTestTunLinuxExits(t)
	iface.device = newTestTunIdleDevice()
	iface.eventsDone = make(chan struct{})
	close(iface.eventsDone)
	return iface, netlink
}

// Every combination of the plan for default traffic (QD-1052) over the Linux interface on the netlink recorder,
// through the tun's own sync: the mark, the exits table's default routes and wg-quick's rules of both families go on
// exactly where the plan takes the default route, and none outlives the tun.
func TestTunLinuxPlansDefaultTrafficForEveryCombination(t *testing.T) {
	testTunDefaultCasesOnPlatform(t, func(t *testing.T) (urTunInterface, func() bool) {
		iface, _ := newTestTunLinuxPlanInterface(t)
		return iface, func() bool { return testTunLinuxExitsHeld(t, iface) }
	})
}

// Over the Linux interface on the netlink recorder: default egress off takes the exits off at once, the rule that sends
// traffic to the tun first and the mark last, and on puts them back, as do route local traffic and an exit that comes
// and goes, with the one device up throughout (QD-1052).
func TestTunLinuxSwitchesDefaultEgressWithNoRestart(t *testing.T) {
	iface, netlink := newTestTunLinuxPlanInterface(t)
	testTunDefaultSwitchOnPlatform(t, iface, func() bool { return testTunLinuxExitsHeld(t, iface) })
	events, _ := netlink.take()
	for _, event := range events {
		if event.messageType == unix.RTM_NEWLINK || event.messageType == unix.RTM_DELLINK {
			t.Fatalf("a change touched the device's link: %d", event.messageType)
		}
	}
}
