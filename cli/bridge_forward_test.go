// The daemon's half of ur bridge: the listing against BridgeStatus, the userspace stack over a fake link, and the
// backend's refusals while the daemon follows no config.

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The listing holds what BridgeStatus holds, value for value, and each ledger rule by its opaque id; a rule waiting
// on a key counts as a seal wait.
func TestUrBridgeListingMatchesBridgeStatus(t *testing.T) {
	networkId := sidecar.NewId()
	sidecarId := sidecar.NewId()
	other := sidecar.NewId()
	status := device.BridgeStatus{
		State:              device.PostureEnforcingDocument,
		Block:              netip.MustParsePrefix("100.80.0.0/16"),
		PreviousBlock:      netip.MustParsePrefix("100.70.0.0/16"),
		Addresses:          []netip.Addr{netip.MustParseAddr("100.80.3.9"), netip.MustParseAddr("100.80.3.10")},
		PinnedPairCount:    7,
		UnpinnedPickCount:  4,
		RouteConflictCount: 2,
		EgressMode:         bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS,
		Waits:              []device.BridgeWait{{Kind: device.BridgeWaitDelegation, Count: 2}, {Kind: device.BridgeWaitLink, Count: 1}},
		Alarms: []device.BridgeAlarm{
			{Kind: device.BridgeAlarmCarvedAddress, Reason: "a local address is a host's"},
			{Kind: device.BridgeAlarmRouteConflict, Reason: "a route overlaps a local network"},
		},
	}
	rules := []*sidecar.BridgeLedgerRule{
		{
			RuleId: []byte{0xaa, 0x01}, SignedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, Owner: other, Standing: true,
			Route: &bridge.BridgeRouteBody{Prefixes: []*bridge.BridgeIpv4Prefix{{Address: 10<<24 | 1<<16, Length: 24}}},
		},
		{
			RuleId: []byte{0xbb, 0x02}, SignedType: bridge.SignedType_SIGNED_BRIDGE_MAP, Owner: sidecarId, Expires: 99,
			Map: &bridge.BridgeMapBody{
				MatchPrefix: &bridge.BridgeIpv4Prefix{Address: 100<<24 | 80<<16 | 3<<8 | 9, Length: 32},
				Protocol:    6,
				Ports:       []*bridge.BridgePortRange{{First: 5432, Last: 5432}, {First: 8000, Last: 8010}},
			},
		},
		{RuleId: []byte{0xcc, 0x03}, SignedType: bridge.SignedType_SIGNED_BRIDGE_MAP, Owner: sidecarId, Pending: true},
		{RuleId: []byte{0xdd, 0x04}, SignedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, Owner: other, Void: true},
		{RuleId: []byte{0xee, 0x05}, SignedType: bridge.SignedType_SIGNED_BRIDGE_ROUTE, Owner: other, Pending: true, Withdrawn: &sidecar.BridgeLedgerWithdrawal{}},
	}
	want := &sidecar.DaemonBridgeList{
		NetworkId:     networkId,
		State:         "enforcing_doc",
		Waits:         map[string]int{"delegation": 2, "link": 1, "seal": 1},
		Block:         "100.80.0.0/16",
		PreviousBlock: "100.70.0.0/16",
		Addresses:     []string{"100.80.3.9", "100.80.3.10"},
		Rules: []*sidecar.DaemonBridgeRule{
			{RuleId: "aa01", Kind: "route", Owner: other, State: "active", Prefixes: []string{"10.1.0.0/24"}, Standing: true},
			{RuleId: "bb02", Kind: "map", Owner: sidecarId, Own: true, State: "active", Prefixes: []string{"100.80.3.9/32"}, Ports: []string{"tcp:5432", "tcp:8000-8010"}, ExpiresMs: 99},
			{RuleId: "cc03", Kind: "map", Owner: sidecarId, Own: true, State: "pending"},
			{RuleId: "dd04", Kind: "route", Owner: other, State: "void"},
			{RuleId: "ee05", Kind: "route", Owner: other, State: "withdrawn"},
		},
		PinnedCount:        7,
		UnpinnedCount:      4,
		CarvedOverlapCount: 1,
		RouteConflictCount: 2,
		Alarms:             []string{"carved_address", "route_conflict"},
		EgressMode:         "exits",
	}
	if got := urBridgeListOf(networkId, sidecarId, status, rules); !reflect.DeepEqual(got, want) {
		t.Fatalf("the listing:\n%+v\nwant\n%+v", got, want)
	}
	// a bridge with no state yet lists its wait and nothing else
	empty := urBridgeListOf(networkId, sidecarId, device.BridgeStatus{Waits: []device.BridgeWait{{Kind: device.BridgeWaitState}}}, nil)
	if !reflect.DeepEqual(empty, &sidecar.DaemonBridgeList{NetworkId: networkId, State: "pending", Waits: map[string]int{"state": 1}}) {
		t.Fatalf("a pending bridge: %+v", empty)
	}
}

// The fake link's far end as a route: each packet the stack sends is written into the far stack.
type testBridgeFarLink struct {
	testTunLink
	far *connect.Tun
}

func (self *testBridgeFarLink) SendPacket(source connect.TransferPath, provideMode protocol.ProvideMode, packet []byte, timeout time.Duration) bool {
	self.far.Write(bytes.Clone(packet))
	connect.MessagePoolReturn(packet)
	return true
}

// A forward's dial over the userspace stack round-trips TCP and UDP across a fake link: the stack's packets run
// through the bridge's RouteBurst to the link, whose far end is a second stack serving an echo, and the replies come
// back through the links' receiver. No OS tun is involved.
func TestUrBridgeStackRoundTripsTcpAndUdpOverAFakeLink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	farSettings := connect.DefaultTunSettings()
	farSettings.DisableIpv6 = true
	far, err := connect.CreateTun(ctx, farSettings)
	if err != nil {
		t.Fatal(err)
	}
	defer far.Close()
	farAddress := far.LocalAddresses()[0]
	tcpListener, err := far.ListenTCP(&net.TCPAddr{IP: farAddress.AsSlice(), Port: 7000})
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	udpConn, err := far.ListenUDP(&net.UDPAddr{IP: farAddress.AsSlice(), Port: 7001})
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	go func() {
		buffer := make([]byte, 2048)
		for {
			count, source, err := udpConn.ReadFrom(buffer)
			if err != nil {
				return
			}
			udpConn.WriteTo(buffer[:count], source)
		}
	}()

	tunBridge := newTestTunBridge()
	link := &testBridgeFarLink{far: far}
	var routed atomic.Int64
	tunBridge.route = func(packet []byte) connect.UserNatClient {
		routed.Add(1)
		return link
	}
	links := &testTunLinks{}
	stack, err := newUrBridgeStack(ctx, tunBridge, links, testUrTunSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer stack.close()
	stack.attach()
	receive := links.current()
	if receive == nil {
		t.Fatal("the stack took no receiver")
	}
	// the link's replies: what the far stack sends comes back through the links' receiver
	go func() {
		for {
			packet, err := far.Read()
			if err != nil {
				return
			}
			receive(connect.TransferPath{}, protocol.ProvideMode_Network, nil, packet)
			connect.MessagePoolReturn(packet)
		}
	}()

	for network, port := range map[string]uint16{"tcp": 7000, "udp": 7001} {
		conn, err := stack.dial(ctx, network, netip.AddrPortFrom(farAddress, port))
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		message := []byte("over the userspace stack by " + network)
		if _, err := conn.Write(message); err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		answer := make([]byte, len(message))
		if _, err := io.ReadFull(conn, answer); err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		if !bytes.Equal(answer, message) {
			t.Fatalf("%s answered %q", network, answer)
		}
		conn.Close()
	}
	if routed.Load() == 0 {
		t.Fatal("nothing ran through the bridge's burst")
	}
}

// While the daemon follows no network's config, every bridge method refuses, naming it, and nothing is filed or
// bound: on a network whose bridge the daemon holds, and on one it does not.
func TestUrBridgeMethodsRefuseWhileTheDaemonFollowsNoConfig(t *testing.T) {
	if urBridgeConfigOf != nil {
		t.Skip("the daemon follows its networks' config")
	}
	networkId := sidecar.NewId()
	bridges, _ := newTestUrBridgeDaemon(t, newTestTunSystem(), networkId, false)
	daemonBridges, err := newUrDaemonBridges(bridges, sidecar.DaemonLocalListen)
	if err != nil {
		t.Fatal(err)
	}
	origin := &sidecar.BridgeFileOrigin{Act: sidecar.SidecarActConfirmed}
	for _, id := range []sidecar.Id{networkId, sidecar.NewId()} {
		_, statusErr := daemonBridges.Status(context.Background(), id, nil)
		_, forwardErr := daemonBridges.Forward(context.Background(), id, nil, origin, &sidecar.DaemonBridgeForwardParams{Target: "peer", Port: 22, LocalPort: 0})
		_, exposeErr := daemonBridges.Expose(context.Background(), id, nil, origin, &sidecar.DaemonBridgeExposeParams{Exit: true})
		_, egressErr := daemonBridges.Egress(context.Background(), id, nil, origin, &sidecar.DaemonBridgeEgressParams{Mode: "none"})
		_, blockErr := daemonBridges.Block(context.Background(), id, nil, origin, &sidecar.DaemonBridgeBlockParams{Block: "cycle"})
		for name, err := range map[string]error{"status": statusErr, "forward": forwardErr, "expose": exposeErr, "egress": egressErr, "block": blockErr} {
			if !errors.Is(err, errUrBridgeUnwired) {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
	if daemonBridges.Active() {
		t.Fatal("a refused forward is held")
	}
	if len(daemonBridges.Methods()) != 6 {
		t.Fatalf("%d methods", len(daemonBridges.Methods()))
	}
}

// A backend over a network's config files through its filer, lists the device role's status with the shared block
// marked, resolves ids itself and names through the config, and refuses a forward's route where the config reads no
// grants.
func TestUrBridgeBackendJoinsTheDeviceRoleAndTheConfig(t *testing.T) {
	networkId := sidecar.NewId()
	otherNetworkId := sidecar.NewId()
	bridges, tunBridge := newTestUrBridgeDaemon(t, newTestTunSystem(), networkId, false)
	otherBridge := newTestTunBridge()
	if _, err := bridges.addNetwork(&urBridgeNetwork{networkId: otherNetworkId, bridge: otherBridge, links: &testTunLinks{}}); err != nil {
		t.Fatal(err)
	}
	sidecarId := sidecar.NewId()
	named := sidecar.NewId()
	previous := urBridgeConfigOf
	urBridgeConfigOf = func(ctx context.Context, network *urBridgeNetwork, running *sidecar.Sidecar) (*urBridgeConfig, error) {
		return &urBridgeConfig{
			SidecarId: sidecarId,
			Filer:     (*sidecar.BridgeFiler)(nil),
			Names: func() []*sidecar.DaemonBridgeName {
				return []*sidecar.DaemonBridgeName{{Name: "db", Address: "100.70.1.2"}}
			},
			Resolve: func(ctx context.Context, name string) (sidecar.Id, error) {
				if name == "db" {
					return named, nil
				}
				return sidecar.Id{}, errors.New("no such name")
			},
		}, nil
	}
	defer func() { urBridgeConfigOf = previous }()
	backends := &urBridgeBackends{bridges: bridges, networkIdBackends: map[sidecar.Id]*urBridgeBackend{}}
	defer backends.close()
	backend, err := backends.backend(context.Background(), networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := backends.backend(context.Background(), networkId, nil); err != nil || again != backend {
		t.Fatalf("a second backend for the network: %v", err)
	}
	list, err := backend.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// both test bridges hold the same block
	if list.Block != tunBridge.Status().Block.String() || !list.SharedBlock || len(list.Names) != 1 || list.NetworkId != networkId {
		t.Fatalf("the listing: %+v", list)
	}
	if backend.SidecarId() != sidecarId {
		t.Fatal("the backend files as another sidecar")
	}
	if id, err := backend.ResolveSidecar(context.Background(), named.String()); err != nil || id != named {
		t.Fatalf("an id: %v", err)
	}
	if id, err := backend.ResolveSidecar(context.Background(), "db"); err != nil || id != named {
		t.Fatalf("a name: %v", err)
	}
	if _, err := backend.ResolveSidecar(context.Background(), "stranger"); err == nil {
		t.Fatal("an unknown name resolved")
	}
	if _, err := backend.ForwardRoute(context.Background(), &sidecar.BridgeForwardRequest{}, nil); !errors.Is(err, errUrBridgeUnwired) {
		t.Fatalf("a forward's route with no grant reader: %v", err)
	}
}
