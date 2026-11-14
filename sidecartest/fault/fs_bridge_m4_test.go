//go:build !sidecar_http && !ios_extension

// BRIDGE-M4-22's schedules on T2 (fs_bridge_m4.go): FS-38's M4 part and its forged case, and FS-56, each under every
// rule §22.8 gives its case; server/controller/connect_bridge_m4_test.go runs the same builders on T3. Beside them,
// §22.5's §17 rows end to end on the same world, blocks and reset against drain, and §17.4's carve on a sender.

package fault

import (
	"bytes"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

func TestFs38(t *testing.T) {
	RunRow(t, "FS-38", "", nil)
}

func TestFs38Forged(t *testing.T) {
	RunRow(t, "FS-38", "forged", nil)
}

func TestFs56(t *testing.T) {
	RunRow(t, "FS-56", "", nil)
}

// §22.5's §17 rows end to end on the BridgeNet, beside the schedules: blocks, and reset against drain.

// A host at fsBridgeHostAddress and one subject, on a world of the test's own.
func fsBridgeRowWorld(t *testing.T, net *sidecartest.Net) *fsBridgeWorld {
	t.Helper()
	world := newFsBridgeWorld()
	world.world = sidecartest.NewBridgeNet(t, net, nil)
	t.Cleanup(world.world.Close)
	hostDevice := world.world.AddDevice("host")
	world.subjects["subject"] = world.world.AddDevice("subject")
	world.host = world.world.StartHost(hostDevice, &sidecartest.BridgeNetHostSettings{Address: fsBridgeHostAddress})
	return world
}

// §22.5's blocks (D-BRIDGE-16, owner decision 132): a head whose block lies outside 100.64/10 and RFC 1918 is refused
// at the host's compile, which keeps the block it held and raises block_refused, and the host's address in the kept
// block still reaches its loopback service.
func TestBridgeBlockOutsideTheRangesKeepsThePrevious(t *testing.T) {
	net := sidecartest.NewNet(t.Context(), nil)
	defer net.Close()
	world := fsBridgeRowWorld(t, net)
	held := world.host.Rules().GetBlock()
	if !proto.Equal(held, sidecartest.BridgeNetPrefix(world.world.Settings().Block)) {
		t.Fatalf("the host holds block %v, not the one filed", held)
	}
	world.world.SetBlock(netip.MustParsePrefix("198.18.0.0/16"))
	world.world.Follow()
	if block := world.host.Rules().GetBlock(); !proto.Equal(block, held) {
		t.Fatalf("the host took the refused block %v", block)
	}
	if !slices.ContainsFunc(world.host.ComponentStatus().Alarms, func(alarm sidecar.BridgeAlarm) bool {
		return alarm.Reason == sidecar.SidecarBridgeAlarmBlockRefused
	}) {
		t.Fatalf("no block_refused: %+v", world.host.ComponentStatus().Alarms)
	}
	window := world.world.OpenWindow("window", world.subjects["subject"], world.host, nil)
	if err := fsTeamCatch(func() error {
		return (&fsBridgeFlows{world: world, window: window}).expectOpen("the kept block")
	}); err != nil {
		t.Fatal(err)
	}
}

// The document §22.5's withdrawals run under: every member device routes the two LANs its advertisers serve.
const fsBridgeWithdrawPolicy = `{"grants": [{"src": ["autogroup:member"], "dst": ["ip:192.0.2.0/24", "ip:198.51.100.0/24"], "via": ["autogroup:member"], "allow": ["route"]}]}`

// §22.5's reset against drain, end to end (§17.8's disposition, D-BRIDGE-7): under a document, two routes the host
// serves carry a live connection each; the route withdrawn to drain keeps its connection carrying bytes to the
// target, and the route withdrawn to reset ends its connection at once, its upstream socket closed and nothing after
// the withdrawal reaching the target.
func TestBridgeWithdrawResetEndsAndDrainKeeps(t *testing.T) {
	testNet := sidecartest.NewNet(t.Context(), nil)
	defer testNet.Close()
	world := fsBridgeRowWorld(t, testNet)
	host := world.host
	drained, reset := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("198.51.100.10")
	host.AddLan(drained)
	host.AddLan(reset)
	plan := world.world.SaveAclPolicy(fsBridgeWithdrawPolicy)
	ruleId := sidecartest.BridgeNetRouteRuleId(t, plan)
	hostDevice := host.Device
	drainedRoute := world.world.FileRoute(hostDevice, netip.MustParsePrefix("192.0.2.0/24"), [][]byte{ruleId}, []byte("site drained"))
	resetRoute := world.world.FileRoute(hostDevice, netip.MustParsePrefix("198.51.100.0/24"), [][]byte{ruleId}, []byte("site reset"))
	world.world.Follow()
	window := world.world.OpenWindow("window", world.subjects["subject"], host, nil)
	waitTimeout := world.world.Settings().WaitTimeout

	// a live connection to address, its first bytes at the target; and the index of its upstream socket's dial
	connectTo := func(address netip.Addr, payload []byte) (net.Conn, int) {
		t.Helper()
		dialCount := len(host.Dials())
		conn, err := window.DialTcp(netip.AddrPortFrom(address, host.Upstream.TcpPort()))
		if err != nil {
			t.Fatalf("to %s: %v", address, err)
		}
		if _, err := conn.Write(payload); err != nil {
			t.Fatal(err)
		}
		if !host.WaitDials(func(dials []sidecartest.BridgeNetDial) bool {
			return dialCount < len(dials) && len(payload) <= dials[dialCount].WrittenByteCount
		}) {
			t.Fatalf("the first bytes to %s never reached the target", address)
		}
		return conn, dialCount
	}
	drainedConn, drainedDial := connectTo(drained, []byte("before the drain"))
	defer drainedConn.Close()
	resetConn, resetDial := connectTo(reset, []byte("before the reset"))
	defer resetConn.Close()

	world.world.Withdraw(hostDevice, drainedRoute, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN)
	world.world.Withdraw(hostDevice, resetRoute, bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_RESET)
	world.world.Follow()

	if !host.WaitDials(func(dials []sidecartest.BridgeNetDial) bool { return dials[resetDial].Closed }) {
		t.Fatal("the reset route's connection kept its upstream socket")
	}
	resetConn.SetReadDeadline(time.Now().Add(waitTimeout))
	if _, err := resetConn.Read(make([]byte, 16)); err == nil {
		t.Fatal("the reset route's connection read on")
	}
	if written := host.Dials()[resetDial].WrittenByteCount; written != len("before the reset") {
		t.Fatalf("%d bytes reached the reset route's target", written)
	}
	after := []byte("after the drain")
	if _, err := drainedConn.Write(after); err != nil {
		t.Fatalf("the drained route's connection: %v", err)
	}
	if !host.WaitDials(func(dials []sidecartest.BridgeNetDial) bool {
		return len("before the drain")+len(after) <= dials[drainedDial].WrittenByteCount && !dials[drainedDial].Closed
	}) {
		t.Fatalf("the drained route's connection stopped carrying bytes: %+v", host.Dials()[drainedDial])
	}
}

// The sender's router on real links (§17.5): FS-38's and FS-56's sender rows run in the schedules (fs_bridge_m4.go);
// the carve runs here.

// A host at fsBridgeHostAddress and a sender, on a world of the test's own; senderSettings nil is the honest sender.
func fsBridgeSenderWorld(t *testing.T, testNet *sidecartest.Net, senderSettings *sidecartest.BridgeNetSenderSettings) (*sidecartest.BridgeNet, *sidecartest.BridgeNetHost, *sidecartest.BridgeNetSender) {
	t.Helper()
	world := sidecartest.NewBridgeNet(t, testNet, nil)
	t.Cleanup(world.Close)
	hostDevice := world.AddDevice("host")
	senderDevice := world.AddDevice("sender")
	host := world.StartHost(hostDevice, &sidecartest.BridgeNetHostSettings{Address: fsBridgeHostAddress})
	sender := world.StartSender(senderDevice, senderSettings)
	return world, host, sender
}

// §17.4's carve as a CGNAT fixture: the sender's carrier address lies inside the network's block; carved, it keeps its
// carrier path, the default route, while the host's overlay address in the same block still routes to its link and
// carries a connection.
func TestBridgeCgnatCarveKeepsTheCarrierPathAndOverlayReach(t *testing.T) {
	testNet := sidecartest.NewNet(t.Context(), nil)
	defer testNet.Close()
	world, host, sender := fsBridgeSenderWorld(t, testNet, nil)
	carrier := netip.MustParseAddr("100.80.200.1")
	if sender.TakesDefaultRoute(netip.AddrPortFrom(carrier, 443)) {
		t.Fatal("an unassigned block address took the default route before the carve: the fixture proves nothing")
	}
	sender.Bridge.SetLocalAddresses([]netip.Addr{carrier})
	if !sender.TakesDefaultRoute(netip.AddrPortFrom(carrier, 443)) {
		t.Fatal("the carved carrier address did not keep its carrier path")
	}
	if sender.TakesDefaultRoute(netip.AddrPortFrom(host.Address, host.Upstream.TcpPort())) {
		t.Fatal("the host's overlay address lost its link to the carve")
	}
	conn, err := sender.DialTcp(netip.AddrPortFrom(host.Address, host.Upstream.TcpPort()))
	if err != nil {
		t.Fatalf("the overlay connection after the carve: %v", err)
	}
	payload := []byte("past the carve")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if !host.Upstream.WaitFor(world.Settings().WaitTimeout, func(accepts []sidecartest.BridgeNetAccept, datagrams [][]byte) bool {
		return slices.ContainsFunc(accepts, func(accept sidecartest.BridgeNetAccept) bool { return bytes.Equal(accept.Bytes, payload) })
	}) {
		t.Fatal("the overlay payload never reached the host")
	}
}
