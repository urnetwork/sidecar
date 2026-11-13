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
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"golang.org/x/sys/unix"

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
