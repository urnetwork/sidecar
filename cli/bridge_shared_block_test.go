// Shared blocks (bridge_shared_block.go) on fakes, T1: the first-joined network routes a block two networks hold, the
// later one is withheld from it, warned of in ur status and alarmed once, ur tun carrying the later one puts nothing
// of the block on the device and drops what is bound there, and a cycle that moves either block clears it all. Every
// wait is on a channel, bounded by urTestTimeout.

package main

import (
	"bytes"
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// The order of judgment: join order first, unranked networks after by id, a draining block counted, and the owner the
// first-joined holder whichever of its blocks overlaps.
func TestSharedBlockGoesToTheFirstJoined(t *testing.T) {
	first := sidecar.NewId()
	second := sidecar.NewId()
	third := sidecar.NewId()
	shared := netip.MustParsePrefix("100.80.0.0/16")
	other := netip.MustParsePrefix("100.90.0.0/16")
	blocks := map[sidecar.Id][]netip.Prefix{
		first:  {shared},
		second: {shared},
		third:  {other},
	}
	got := urSharedBlocksOf([]sidecar.Id{first, second, third}, blocks)
	want := []urSharedBlock{{Block: shared, NetworkId: second, OwnerNetworkId: first}}
	if !slices.Equal(got, want) {
		t.Fatalf("first joined first: %+v", got)
	}
	// the other join order gives the block to the other network
	got = urSharedBlocksOf([]sidecar.Id{second, first, third}, blocks)
	want = []urSharedBlock{{Block: shared, NetworkId: first, OwnerNetworkId: second}}
	if !slices.Equal(got, want) {
		t.Fatalf("second joined first: %+v", got)
	}
	// a network sidecar.json does not name yet ranks after every one it does
	got = urSharedBlocksOf([]sidecar.Id{second}, blocks)
	if len(got) != 1 || got[0].NetworkId != first || got[0].OwnerNetworkId != second {
		t.Fatalf("an unranked network: %+v", got)
	}
	// a block one network drains is still its own while it drains; three holders give the later two to the first
	blocks = map[sidecar.Id][]netip.Prefix{
		first:  {other, shared},
		second: {shared},
		third:  {shared, netip.Prefix{}},
	}
	got = urSharedBlocksOf([]sidecar.Id{first, second, third}, blocks)
	want = []urSharedBlock{
		{Block: shared, NetworkId: second, OwnerNetworkId: first},
		{Block: shared, NetworkId: third, OwnerNetworkId: first},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("a draining block: %+v", got)
	}
	// blocks apart share nothing
	if got := urSharedBlocksOf(nil, map[sidecar.Id][]netip.Prefix{first: {shared}, second: {other}}); len(got) != 0 {
		t.Fatalf("apart: %+v", got)
	}
}

// What each network's alarm raised.
type testSharedBlockAlarms struct {
	stateLock sync.Mutex
	raised    map[sidecar.Id][]sidecar.SidecarBridgeAlarm
}

func (self *testSharedBlockAlarms) alarm(networkId sidecar.Id) func(alarm sidecar.SidecarBridgeAlarm) {
	return func(alarm sidecar.SidecarBridgeAlarm) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.raised[networkId] = append(self.raised[networkId], alarm)
	}
}

func (self *testSharedBlockAlarms) of(networkId sidecar.Id) []sidecar.SidecarBridgeAlarm {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.raised[networkId])
}

// Two networks on one daemon holding one block, the first joined first, and a tun for the platform.
type testSharedBlockWorld struct {
	bridges      *urBridgeDaemon
	system       *testTunSystem
	first        sidecar.Id
	second       sidecar.Id
	firstBridge  *testTunBridge
	secondBridge *testTunBridge
	alarms       *testSharedBlockAlarms
}

func newTestSharedBlockWorld(t *testing.T) *testSharedBlockWorld {
	t.Helper()
	world := &testSharedBlockWorld{
		system:       newTestTunSystem(),
		first:        sidecar.NewId(),
		second:       sidecar.NewId(),
		firstBridge:  newTestTunBridge(),
		secondBridge: newTestTunBridge(),
		alarms:       &testSharedBlockAlarms{raised: map[sidecar.Id][]sidecar.SidecarBridgeAlarm{}},
	}
	world.system.local = []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	// both hold 100.70.0.0/16; the second also routes a subnet outside it
	world.secondBridge.status.Addresses = []netip.Addr{netip.MustParseAddr("100.70.8.8")}
	world.secondBridge.routes = []netip.Prefix{
		netip.MustParsePrefix("100.70.0.53/32"),
		netip.MustParsePrefix("100.70.3.4/32"),
		netip.MustParsePrefix("10.20.0.0/16"),
	}
	world.bridges = newUrBridgeDaemon(context.Background(), &urBridgeDaemonArgs{
		Instance: "test",
		System:   world.system,
		Settings: testUrTunSettings(),
		JoinOrder: func() []sidecar.Id {
			return []sidecar.Id{world.first, world.second}
		},
		// each sync's end is an event, after the tun holds what it applied
		OnTunSync: func(err error) {
			world.system.iface.announce("synced")
		},
	})
	t.Cleanup(world.bridges.close)
	for _, network := range []*urBridgeNetwork{
		{networkId: world.first, bridge: world.firstBridge, links: &testTunLinks{}, alarm: world.alarms.alarm(world.first)},
		{networkId: world.second, bridge: world.secondBridge, links: &testTunLinks{}, alarm: world.alarms.alarm(world.second)},
	} {
		network.componentSettings = sidecar.DefaultBridgeComponentSettings()
		if _, err := world.bridges.addNetwork(network); err != nil {
			t.Fatal(err)
		}
	}
	return world
}

// What the device holds now.
func (self *testSharedBlockWorld) device() ([]netip.Addr, []netip.Prefix, netip.Addr, []string) {
	iface := self.system.iface
	iface.stateLock.Lock()
	defer iface.stateLock.Unlock()
	return slices.Clone(iface.addresses), slices.Clone(iface.routes), iface.resolver, slices.Clone(iface.zones)
}

// The later-joined network's tun leaves the shared block off: no address, route or name inside it, its subnet outside
// kept, a packet bound into the block dropped and counted while one outside rides its link; ur tun shows the block with
// the network that routes it, and the network raised shared_block once.
func TestSharedBlockWithheldFromTheLaterNetworksTun(t *testing.T) {
	world := newTestSharedBlockWorld(t)
	link := &testTunLink{}
	world.secondBridge.stateLock.Lock()
	world.secondBridge.route = func(packet []byte) connect.UserNatClient { return link }
	world.secondBridge.stateLock.Unlock()
	status, err := world.bridges.tunUp(world.second, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Withheld) != 1 || status.Withheld[0].Block != "100.70.0.0/16" || status.Withheld[0].OwnerNetworkId != world.first {
		t.Fatalf("withheld: %+v", status.Withheld)
	}
	addresses, routes, resolver, zones := world.device()
	if len(addresses) != 0 || !slices.Equal(routes, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}) ||
		resolver.IsValid() || len(zones) != 0 {
		t.Fatalf("the device holds %v %v %v %v", addresses, routes, resolver, zones)
	}
	if alarms := world.alarms.of(world.second); !slices.Equal(alarms, []sidecar.SidecarBridgeAlarm{sidecar.SidecarBridgeAlarmSharedBlock}) {
		t.Fatalf("the later network raised %v", alarms)
	}
	if alarms := world.alarms.of(world.first); len(alarms) != 0 {
		t.Fatalf("the first network raised %v", alarms)
	}
	// the exits' default route or a wider route could still bring a packet bound there: it reaches no link
	intoBlock := testTunPacket("192.0.2.10", "100.70.3.4", 17, []byte("into the shared block"))
	outside := testTunPacket("192.0.2.10", "10.20.1.1", 17, []byte("to the subnet"))
	world.system.iface.reads <- testTunRead{packets: [][]byte{intoBlock, outside, intoBlock}}
	world.system.iface.reads <- testTunRead{}
	taken := link.taken()
	if len(taken) != 1 || !bytes.Equal(taken[0], outside) {
		t.Fatalf("the link took %d packets", len(taken))
	}
	if tunStatus := world.bridges.tunStatus(); tunStatus.WithheldCount != 2 {
		t.Fatalf("withheld %d", tunStatus.WithheldCount)
	}
	// judged again with nothing changed, nothing is raised again
	world.bridges.judgeSharedBlocks()
	if alarms := world.alarms.of(world.second); len(alarms) != 1 {
		t.Fatalf("raised again: %v", alarms)
	}
}

// The first-joined network's tun carries the block as ever; the later network is the one withheld and warned of.
func TestSharedBlockStaysWithTheFirstJoinedNetwork(t *testing.T) {
	world := newTestSharedBlockWorld(t)
	status, err := world.bridges.tunUp(world.first, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Withheld) != 0 {
		t.Fatalf("withheld: %+v", status.Withheld)
	}
	addresses, routes, resolver, zones := world.device()
	if !slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("100.70.9.9")}) || len(routes) != 2 ||
		resolver != netip.MustParseAddr("100.70.0.53") || !slices.Equal(zones, []string{"net.example"}) {
		t.Fatalf("the device holds %v %v %v %v", addresses, routes, resolver, zones)
	}
	reply := urStatusSharedBlocksOf(world.bridges)
	if len(reply.Shared) != 1 || reply.Shared[0].NetworkId != world.second || reply.Shared[0].OwnerNetworkId != world.first ||
		reply.Shared[0].Block != "100.70.0.0/16" {
		t.Fatalf("status: %+v", reply.Shared)
	}
	if alarms := world.alarms.of(world.second); len(alarms) != 1 {
		t.Fatalf("the later network raised %v", alarms)
	}
}

// An admin cycles the later network's block: the share clears, its tun routes the new block and its names, ur status
// warns of nothing, and a later share raises the alarm again.
func TestSharedBlockClearsWhenABlockCycles(t *testing.T) {
	world := newTestSharedBlockWorld(t)
	if _, err := world.bridges.tunUp(world.second, nil, nil); err != nil {
		t.Fatal(err)
	}
	cycled := []netip.Prefix{netip.MustParsePrefix("100.71.0.53/32"), netip.MustParsePrefix("100.71.3.4/32")}
	world.secondBridge.stateLock.Lock()
	world.secondBridge.status.Block = netip.MustParsePrefix("100.71.0.0/16")
	world.secondBridge.status.Addresses = []netip.Addr{netip.MustParseAddr("100.71.8.8")}
	world.secondBridge.routes = cycled
	world.secondBridge.stateLock.Unlock()
	// a cycle reaches the daemon and the tun as a change of the bridge's; whichever judgment sees it first has the tun
	// sync again
	world.secondBridge.changed()
	world.bridges.judgeSharedBlocks()
	waitTunEvents(t, world.system.iface.events, "the cycled block on the device", func() bool {
		addresses, routes, resolver, _ := world.device()
		status := world.bridges.tunStatus()
		return slices.Equal(routes, cycled) && slices.Equal(addresses, []netip.Addr{netip.MustParseAddr("100.71.8.8")}) &&
			resolver == netip.MustParseAddr("100.71.0.53") && status != nil && len(status.Withheld) == 0
	})
	if reply := urStatusSharedBlocksOf(world.bridges); len(reply.Shared) != 0 {
		t.Fatalf("status still warns: %+v", reply.Shared)
	}
	// a later cycle back onto the first network's block shares it again, and alarms again
	world.secondBridge.stateLock.Lock()
	world.secondBridge.status.Block = netip.MustParsePrefix("100.70.0.0/16")
	world.secondBridge.stateLock.Unlock()
	world.bridges.judgeSharedBlocks()
	if alarms := world.alarms.of(world.second); len(alarms) != 2 {
		t.Fatalf("raised %v", alarms)
	}
	waitTunEvents(t, world.system.iface.events, "the block withheld again", func() bool {
		status := world.bridges.tunStatus()
		return status != nil && len(status.Withheld) == 1
	})
}

// A network whose bridge stops running holds no block here: the later network's share clears with it.
func TestSharedBlockClearsWhenTheOwnerStops(t *testing.T) {
	world := newTestSharedBlockWorld(t)
	world.bridges.judgeSharedBlocks()
	if len(world.bridges.sharedBlocksFor(world.second)) != 1 {
		t.Fatal("no share")
	}
	// the network a test added is forgotten as the daemon forgets a bridge it ends
	func() {
		world.bridges.stateLock.Lock()
		defer world.bridges.stateLock.Unlock()
		delete(world.bridges.networks, world.first)
	}()
	world.bridges.judgeSharedBlocks()
	if shared := world.bridges.sharedBlocksFor(world.second); len(shared) != 0 {
		t.Fatalf("still shared: %+v", shared)
	}
}

// ur status prints each withheld block as a warning naming both networks and the cycle; none prints nothing.
func TestStatusWarnsOfASharedBlock(t *testing.T) {
	world := newTestSharedBlockWorld(t)
	cli, stdout, _ := newTestUrCli("/nonexistent/socket")
	printUrSharedBlocksReply(cli, urStatusSharedBlocksOf(world.bridges))
	printed := stdout.String()
	for _, want := range []string{"warning:", world.second.String(), world.first.String(), "100.70.0.0/16",
		"joined this device first", "ur bridge block cycle"} {
		if !strings.Contains(printed, want) {
			t.Errorf("status printed no %q:\n%s", want, printed)
		}
	}
	stdout.Reset()
	printUrSharedBlocksReply(cli, &urStatusSharedBlocksReply{})
	if stdout.Len() != 0 {
		t.Fatalf("no share printed:\n%s", stdout.String())
	}
}

// ur tun prints a withheld block with the network that routes it.
func TestTunPrintsAWithheldBlock(t *testing.T) {
	cli, stdout, _ := newTestUrCli("/nonexistent/socket")
	owner := sidecar.NewId()
	printUrTunStatus(cli, &urTunStatus{
		Device:     "ur-test",
		Block:      "100.70.0.0/16",
		EgressMode: "auto",
		Withheld:   []urTunWithheld{{Block: "100.70.0.0/16", OwnerNetworkId: owner}},
	})
	printed := stdout.String()
	if !strings.Contains(printed, "shared     100.70.0.0/16 is network "+owner.String()+"'s on this device too") {
		t.Fatalf("printed:\n%s", printed)
	}
}
