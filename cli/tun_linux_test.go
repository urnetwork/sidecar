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
//
// The device comes up with the host's overlay address and the bridge's routes, a ping to a fixture peer's address rides
// the link the bridge routes it to and its reply returns through the device, a private name resolves through
// <block>.0.53 to the bridge's own resolver, and the close removes the device and its routes. With no CAP_NET_ADMIN the
// open refuses with errUrTunPrivilege, not a crash. Every wait is a read with urTestTimeout's deadline.

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
	fail   func(n int, messageType uint16) error
	routes []urTunLinuxRoute
	rules  []urTunLinuxRule
	sent   int
}

var _ urTunNetlink = (*testTunNetlink)(nil)

func (self *testTunNetlink) Request(messageType uint16, flags uint16, body []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, testTunNetlinkEvent{messageType: messageType, flags: flags, body: slices.Clone(body)})
	n := self.sent
	self.sent += 1
	if self.fail != nil {
		return self.fail(n, messageType)
	}
	return nil
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
	hasDst    bool
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
		case unix.RTA_DST:
			message.hasDst = true
		}
	}
	return message
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
