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
//	    -e UR_TUN_TEST_DEVICE=isolated -v <dir>:/t:ro alpine:3.22 /t/cli.test -test.run TestTunLinux -test.v
//
// The device comes up with the host's overlay address and the bridge's routes, a ping to a fixture peer's address rides
// the link the bridge routes it to and its reply returns through the device, a private name resolves through
// <block>.0.53 to the bridge's own resolver, and the close removes the device and its routes. With no CAP_NET_ADMIN the
// open refuses with errUrTunPrivilege, not a crash. In a namespace with no network, a tun of the test's stands for the
// physical path, and under exits the bridge's carved addresses leave by it rather than ur tun (QD-808). Every wait is a
// read with urTestTimeout's deadline. The exits' rules and routes and their throws are also tested through a netlink
// recorder that changes no host, which runs on any Linux.

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
	// what each add of a throw route answers ahead of fail, nil for none
	throwErr error
	routes   []urTunLinuxRoute
	rules    []urTunLinuxRule
	sent     int
}

var _ urTunNetlink = (*testTunNetlink)(nil)

func (self *testTunNetlink) Request(messageType uint16, flags uint16, body []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, testTunNetlinkEvent{messageType: messageType, flags: flags, body: slices.Clone(body)})
	n := self.sent
	self.sent += 1
	if self.throwErr != nil && messageType == unix.RTM_NEWROUTE && unix.SizeofRtMsg <= len(body) && body[7] == unix.RTN_THROW {
		return self.throwErr
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

// An interface at index 7 on a recorded system, whose main table's default route leaves by eth0 at index 2 and whose
// reverse path filters are loose.
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
		},
		rules: []urTunLinuxRule{
			{family: unix.AF_INET, table: unix.RT_TABLE_LOCAL, action: unix.FR_ACT_TO_TBL, suppressPrefixLength: -1},
			{family: unix.AF_INET, table: unix.RT_TABLE_MAIN, action: unix.FR_ACT_TO_TBL, priority: 32766, suppressPrefixLength: -1},
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

// The throw routes events add and take off, in order, each checked for the shape the kernel takes: ur's, IPv4, a /32 in
// table, naming no device or gateway, added exclusively in the universe's scope and taken off in any.
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
		if message.family != unix.AF_INET || message.dstBits != 32 || !message.hasDst || !message.dst.Is4() ||
			message.table != table || message.protocol != urTunRouteProtocol || message.hasOif || message.hasGateway {
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
// rules, `lookup main suppress_prefixlength 0` ahead of `not fwmark <mark> lookup <table>`, each ur's, and kick connect
// once they are on; asked again, they send nothing more.
func TestTunLinuxExitsInstallWgQuicksRules(t *testing.T) {
	iface, netlink := newTestTunLinuxExits(t)
	settings := iface.system.settings
	defaultRoute, err := iface.SetExits(true)
	if err != nil || !defaultRoute {
		t.Fatalf("on: %t %v", defaultRoute, err)
	}
	events, kickCount := netlink.take()
	if len(events) != 4 || kickCount != 1 {
		t.Fatalf("%d events, %d kicks", len(events), kickCount)
	}
	if events[0].messageType != 0 || events[0].mark != settings.ExitsMark {
		t.Fatalf("the mark did not go on first: %+v", events[0])
	}
	route := events[1]
	message := testTunParseRouteBody(route.body)
	if route.messageType != unix.RTM_NEWROUTE || route.flags != unix.NLM_F_CREATE|unix.NLM_F_EXCL ||
		message.family != unix.AF_INET || message.dstBits != 0 || message.hasDst || message.table != settings.ExitsTable ||
		message.protocol != urTunRouteProtocol || message.scope != unix.RT_SCOPE_LINK || message.routeType != unix.RTN_UNICAST ||
		message.oif != 7 {
		t.Fatalf("the default route: %+v %+v", route, message)
	}
	suppress := urTunLinuxParseRule(events[2].body)
	if events[2].messageType != unix.RTM_NEWRULE || events[2].flags != unix.NLM_F_CREATE|unix.NLM_F_EXCL ||
		suppress.family != unix.AF_INET || suppress.action != unix.FR_ACT_TO_TBL || suppress.flags != 0 ||
		suppress.table != unix.RT_TABLE_MAIN || suppress.priority != settings.ExitsRulePriority ||
		suppress.suppressPrefixLength != 0 || suppress.markSet || suppress.protocol != urTunRouteProtocol {
		t.Fatalf("the suppress rule: %+v", suppress)
	}
	mark := urTunLinuxParseRule(events[3].body)
	if events[3].messageType != unix.RTM_NEWRULE || mark.family != unix.AF_INET || mark.action != unix.FR_ACT_TO_TBL ||
		mark.flags != unix.FIB_RULE_INVERT || mark.table != settings.ExitsTable ||
		mark.priority != settings.ExitsRulePriority+1 || !mark.markSet || mark.mark != settings.ExitsMark ||
		mark.suppressPrefixLength != -1 || mark.protocol != urTunRouteProtocol {
		t.Fatalf("the mark rule: %+v", mark)
	}
	// the mark rule's mask is every bit, as `fwmark M` without a mask is
	var mask uint32
	for _, attribute := range urNetlinkAttributes(events[3].body[urTunLinuxRuleHeaderByteCount:]) {
		if attribute.attributeType == unix.FRA_FWMASK {
			mask = binary.NativeEndian.Uint32(attribute.value)
		}
	}
	if mask != math.MaxUint32 {
		t.Fatalf("the mark rule's mask %#x", mask)
	}
	defaultRoute, err = iface.SetExits(true)
	if events, kickCount := netlink.take(); err != nil || !defaultRoute || len(events) != 0 || kickCount != 1 {
		t.Fatalf("again: %t %v, %d events, %d kicks", defaultRoute, err, len(events), kickCount)
	}
}

// Off exits the rules come off before the route, the one that sends traffic to the tun first, each delete naming ur's
// own, and the mark last; asked again, nothing more is sent.
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
	if len(events) != 4 || kickCount != 1 {
		t.Fatalf("%d events, %d kicks", len(events), kickCount)
	}
	if events[0].messageType != unix.RTM_DELRULE || !slices.Equal(events[0].body, installed[3].body) {
		t.Fatalf("the mark rule did not come off first: %+v", events[0])
	}
	if events[1].messageType != unix.RTM_DELROUTE {
		t.Fatalf("the route did not come off second: %+v", events[1])
	}
	if message := testTunParseRouteBody(events[1].body); message.table != settings.ExitsTable || message.oif != 7 ||
		message.protocol != urTunRouteProtocol || message.dstBits != 0 {
		t.Fatalf("the route's delete: %+v", message)
	}
	if events[2].messageType != unix.RTM_DELRULE || !slices.Equal(events[2].body, installed[2].body) {
		t.Fatalf("the suppress rule did not come off third: %+v", events[2])
	}
	if events[3].messageType != 0 || events[3].mark != 0 {
		t.Fatalf("the mark did not come off last: %+v", events[3])
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
// so the rule finds an empty table; the next call takes the rest off.
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
	if !slices.Equal(types, []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE}) || !iface.exitsMark || !iface.exitsSuppressRule {
		t.Fatalf("events %v, mark %t, suppress %t", types, iface.exitsMark, iface.exitsSuppressRule)
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
	if !slices.Equal(types, []uint16{unix.RTM_DELRULE, unix.RTM_DELRULE, 0}) || iface.exitsMark {
		t.Fatalf("events %v", types)
	}
}

// The exits refuse, putting nothing on, a table another program's routes hold, a mark or table another program's rule
// uses, and a strict reverse path filter, all's or the default route's interface's; a loose or absent filter, and ur's
// own leftover rule, do not refuse.
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

// Close takes the exits off, the mark last, before it removes the routes and closes the device.
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
	if !slices.Equal(types, []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELRULE, 0, unix.RTM_DELROUTE}) ||
		!device.closed || iface.exitsMark {
		t.Fatalf("close: %v, device closed %t", types, device.closed)
	}
	if _, err := iface.SetExits(true); !errors.Is(err, errUrTunClosed) {
		t.Fatalf("exits after close: %v", err)
	}
}

// Under exits each carved IPv4 address takes a throw route in the exits table, after the table's default route and
// before the rule that sends lookups there (QD-808): an off-link resolver, whose lookup would meet the default route
// otherwise, and an on-link gateway and the host's own address, which the main and local tables answer first, take one
// alike; an IPv6 address takes none, the table being IPv4's. Off exits the carve only waits, and the same carve once the
// exits stand sends nothing more.
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
		unix.RTM_NEWRULE}
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
	want := []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELROUTE, unix.RTM_DELROUTE, unix.RTM_DELRULE, 0}
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
	want := []uint16{unix.RTM_DELRULE, unix.RTM_DELROUTE, unix.RTM_DELROUTE}
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
	want := []uint16{0, unix.RTM_NEWROUTE, unix.RTM_DELROUTE, unix.RTM_NEWRULE, unix.RTM_NEWRULE}
	if !slices.Equal(testTunEventTypes(events), want) || len(addedAddrs) != 0 ||
		!slices.Equal(removedAddrs, []netip.Addr{stale}) || !slices.Equal(testTunThrowAddrs(iface), []netip.Addr{kept}) {
		t.Fatalf("events %v: on %v, off %v, held %v", testTunEventTypes(events), addedAddrs, removedAddrs,
			testTunThrowAddrs(iface))
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
