// The daemon's config followers and the bridges built over them (QD-796), on sidecartest's Net: one instance hosting a
// Sidecar per network, each started with startUrConfigFollower as ur daemon starts it, each network an admission world
// whose log a FakeApi on the Net's cluster serves and whose in-memory config repo stands in for the head reader over
// evs (urDaemonConfigHeads). ur tun comes up over a network's bridge, built per network over that network's follower,
// where it answered "no bridge runs for this network" before, and each bridge compiles its own network's verified state
// from its follower's log and heads; a network whose follower refused its log answers why, and the other networks'
// bridges come up; and a Sidecar takes one follower. Every wait is on a channel or a monitor, bounded by a real-time
// guard only a broken wiring reaches.

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Networks of admission worlds on one Net, one instance hosting a Sidecar in each that the daemon's composition
// follows, a control daemon hosting them all, and the daemon's bridges over a fake platform with a tun.
type testUrFollowWorld struct {
	t        *testing.T
	ctx      context.Context
	net      *sidecartest.Net
	instance *sidecartest.TestInstance
	networks []*sidecartest.AdmissionNet
	system   *testTunSystem
	bridges  *urBridgeDaemon
}

// A world of networkCount networks, nothing hosted yet: the daemon's head reader hook reads each Sidecar's own
// network's config repo.
func newTestUrFollowWorld(t *testing.T, networkCount int) *testUrFollowWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	t.Cleanup(cancel)
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	world := &testUrFollowWorld{t: t, ctx: ctx, net: net, system: newTestTunSystem()}
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	for range networkCount {
		network := sidecartest.NewAdmissionNet(t, tier)
		t.Cleanup(network.Close)
		world.networks = append(world.networks, network)
	}
	previousHeads := urDaemonConfigHeads
	t.Cleanup(func() { urDaemonConfigHeads = previousHeads })
	urDaemonConfigHeads = func(running *sidecar.Sidecar) sidecar.ConfigHeadReader {
		return &testUrConfigHeads{world: world, running: running}
	}
	previousPlatform := urTunPlatform
	t.Cleanup(func() { urTunPlatform = previousPlatform })
	urTunPlatform = func(settings *urTunSettings, log sidecar.Logger) urTunSystem { return world.system }

	world.instance, err = net.StartInstance("daemon", &sidecartest.TestInstanceArgs{
		Start: func(running *sidecar.Sidecar) error {
			if startUrConfigFollower(running, sidecar.NewNoopLogger()) == nil {
				return errors.New("no follower started")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.instance.Close)
	world.bridges = newUrBridgeDaemon(ctx, &urBridgeDaemonArgs{
		Instance: "test",
		System:   world.system,
		Settings: testUrTunSettings(),
		Build: newUrBridgeBuild(&urBridgeBuildArgs{
			StateDirectory: t.TempDir(),
			Settings:       sidecar.DefaultSidecarSettings(),
			Log:            sidecar.NewNoopLogger(),
		}),
	})
	t.Cleanup(world.bridges.close)
	return world
}

// A Sidecar enrolled in network on the instance, anchored as anchor says, and admitted there by its owner's device.
func (self *testUrFollowWorld) host(network *sidecartest.AdmissionNet, anchor *sidecar.SidecarEnrollAnchor) *sidecar.Sidecar {
	self.t.Helper()
	running, err := self.instance.AddSidecarIn(network.NetworkId(), anchor)
	if err != nil {
		self.t.Fatal(err)
	}
	network.AdmitSidecar(network.Owner(), running.Identity(), network.Owner().MemberId, 0)
	return running
}

// Waits for running's follower to stand at network's tip.
func (self *testUrFollowWorld) standing(running *sidecar.Sidecar, network *sidecartest.AdmissionNet) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, urTestTimeout)
	defer cancel()
	client, err := running.ConfigFollower().WaitStanding(ctx)
	if err != nil {
		self.t.Fatalf("network %s: %v", network.NetworkId(), err)
	}
	if _, err := client.WaitFor(ctx, network.Tip().GetVersion()); err != nil {
		self.t.Fatalf("network %s at %d: %v", network.NetworkId(), network.Tip().GetVersion(), err)
	}
}

// A control daemon hosting each Sidecar under its network, serving the tun's methods over the world's bridges.
func (self *testUrFollowWorld) daemon(sidecars ...*sidecar.Sidecar) *testUrDaemon {
	self.t.Helper()
	return startTestUrDaemon(self.t, shortTestDirectory(self.t), func(daemon *sidecar.Daemon) {
		for _, running := range sidecars {
			if err := daemon.AddSidecar(*running.NetworkId(), running); err != nil {
				self.t.Fatal(err)
			}
		}
		for _, method := range urTunDaemonMethods(self.bridges) {
			if err := daemon.RegisterMethod(method); err != nil {
				self.t.Fatal(err)
			}
		}
	})
}

// Saves a config head holding a block of 100.<second>.0.0/16, signed by the network's owner, and lands its base.
func (self *testUrFollowWorld) saveBlock(network *sidecartest.AdmissionNet, second byte) {
	self.t.Helper()
	signed := network.Sign(network.Owner(), bridge.SignedType_SIGNED_BRIDGE_BLOCK, &bridge.BridgeBlock{
		Ipv4Prefix: &bridge.BridgeIpv4Prefix{Address: 100<<24 | uint32(second)<<16, Length: 16},
	})
	network.SaveHead(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadBridgeBlockPath, signed)
	})
}

// Waits until built's device role enforces a verified state.
func (self *testUrFollowWorld) awaitEnforcing(built *urBridgeNetwork) {
	self.t.Helper()
	changed := make(chan struct{}, 1)
	remove := built.bridge.AddChangeCallback(func() {
		select {
		case changed <- struct{}{}:
		default:
		}
	})
	defer remove()
	guard := time.After(urTestTimeout)
	for {
		switch built.bridge.Decision().State {
		case device.PostureEnforcingDocument, device.PostureEnforcingNoDocument:
			return
		}
		select {
		case <-changed:
		case <-guard:
			self.t.Fatalf("network %s's bridge is %s", built.networkId, built.bridge.Status().State)
		}
	}
}

// The bridges the daemon holds, by network.
func (self *testUrFollowWorld) heldBridges() map[sidecar.Id]*urBridgeNetwork {
	self.bridges.stateLock.Lock()
	defer self.bridges.stateLock.Unlock()
	held := map[sidecar.Id]*urBridgeNetwork{}
	for networkId, network := range self.bridges.networks {
		held[networkId] = network
	}
	return held
}

// The head reader the daemon's hook gives running: its own network's config repo.
type testUrConfigHeads struct {
	world   *testUrFollowWorld
	running *sidecar.Sidecar
}

func (self *testUrConfigHeads) ReadConfigHead(ctx context.Context, version uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	networkId := self.running.NetworkId()
	if networkId == nil {
		return nil, sidecar.ErrConfigHeadUnavailable
	}
	for _, network := range self.world.networks {
		if network.NetworkId() == *networkId {
			return network.Heads().ReadConfigHead(ctx, version, configHeadSha256)
		}
	}
	return nil, sidecar.ErrConfigHeadUnavailable
}

// ur tun brings the tun up over a network's bridge, built over that network's own follower, where it answered "no
// bridge runs for this network" before: each network's bridge, built when ur tun ip first asks for it, compiles its own
// network's verified state, the block its config head holds, from its own follower's log, rows and heads, and ur tun
// carries the first network's.
func TestTunBringsUpABridgeOverEachNetworksFollower(t *testing.T) {
	world := newTestUrFollowWorld(t, 2)
	blocks := []string{"100.80.0.0/16", "100.81.0.0/16"}
	sidecars := []*sidecar.Sidecar{}
	for i, network := range world.networks {
		running := world.host(network, nil)
		world.saveBlock(network, byte(80+i))
		world.standing(running, network)
		sidecars = append(sidecars, running)
	}
	daemon := world.daemon(sidecars...)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	for i, network := range world.networks {
		networkId := network.NetworkId()
		if code := cli.main(world.ctx, []string{"ur", "tun", "ip", "--network=" + networkId.String()}); code != urExitOk {
			t.Fatalf("ur tun ip for network %d exited %d: %s", i, code, stderr.String())
		}
		built := world.heldBridges()[networkId]
		if built == nil {
			t.Fatalf("no bridge was built for network %d", i)
		}
		world.awaitEnforcing(built)
		stdout.Reset()
		if code := cli.main(world.ctx, []string{"ur", "tun", "ip", "--network=" + networkId.String()}); code != urExitOk ||
			!strings.Contains(stdout.String(), "block      "+blocks[i]) {
			t.Fatalf("ur tun ip for network %d exited %d:\n%s%s", i, code, stdout.String(), stderr.String())
		}
	}
	held := world.heldBridges()
	first, second := world.networks[0].NetworkId(), world.networks[1].NetworkId()
	if len(held) != 2 || held[first].bridge == held[second].bridge {
		t.Fatalf("the daemon holds %d bridges", len(held))
	}

	stdout.Reset()
	if code := cli.main(world.ctx, []string{"ur", "tun", "--network=" + first.String()}); code != urExitOk {
		t.Fatalf("ur tun exited %d: %s", code, stderr.String())
	}
	if printed := stdout.String(); !strings.Contains(printed, "ur-test carries network "+first.String()+" (enforcing") ||
		!strings.Contains(printed, "block      "+blocks[0]) {
		t.Fatalf("ur tun printed:\n%s", printed)
	}
	if status := world.bridges.tunStatus(); status == nil || status.NetworkId != first {
		t.Fatalf("the tun is %+v", status)
	}
	if code := cli.main(world.ctx, []string{"ur", "tun", "down"}); code != urExitOk {
		t.Fatalf("ur tun down exited %d: %s", code, stderr.String())
	}
	for i, running := range sidecars {
		if running.ConfigFollower().Client() == nil || !running.Admitted() {
			t.Fatalf("network %d stopped following under its bridge", i)
		}
	}
}

// A network whose follower refused its log, an invite's anchor naming another genesis than api serves, has no bridge:
// ur status and ur tun say why, naming the refusal rather than an unwired daemon, and ur tun opens nothing; the other
// network's tun comes up over its own follower (CORE-M6-01).
func TestTunNamesTheRefusalOfANetworksFollower(t *testing.T) {
	world := newTestUrFollowWorld(t, 2)
	good, refused := world.networks[0], world.networks[1]
	goodSidecar := world.host(good, nil)
	other := sha256.Sum256([]byte("a genesis no network here signed"))
	refusedSidecar := world.host(refused, &sidecar.SidecarEnrollAnchor{GenesisSha256: other[:]})
	ctx, cancel := context.WithTimeout(world.ctx, urTestTimeout)
	defer cancel()
	if _, err := refusedSidecar.ConfigFollower().WaitStanding(ctx); !errors.Is(err, sidecar.ErrSidecarConfigRefused) {
		t.Fatalf("a follower shown another genesis: %v", err)
	}
	world.standing(goodSidecar, good)
	daemon := world.daemon(goodSidecar, refusedSidecar)

	// ur status names each network's follower: the position one stands at, and why the other refused
	statusCli, statusOut, _ := newTestUrCli(daemon.socketPath)
	printUrStatus(statusCli, &urStatusReply{Instance: "test", KeyStore: "memory",
		Networks: (&urDaemonNetwork{daemon: daemon.daemon}).networkStatuses()})
	if shown := statusOut.String(); !strings.Contains(shown, "config:   followed, at position") ||
		!strings.Contains(shown, "config:   refused: ") || !strings.Contains(shown, "another genesis") {
		t.Fatalf("ur status printed:\n%s", shown)
	}

	cli, _, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(world.ctx, []string{"ur", "tun", "--network=" + refused.NetworkId().String()}); code == urExitOk {
		t.Fatal("ur tun came up over a refused log")
	}
	if shown := stderr.String(); !strings.Contains(shown, "does not stand") || !strings.Contains(shown, "refused") ||
		strings.Contains(shown, "does not follow its config yet") {
		t.Fatalf("ur tun answered: %s", shown)
	}
	world.system.stateLock.Lock()
	opened := len(world.system.opened)
	world.system.stateLock.Unlock()
	if opened != 0 {
		t.Fatal("a device opened for a refused network")
	}
	stderr.Reset()
	if code := cli.main(world.ctx, []string{"ur", "tun", "--network=" + good.NetworkId().String()}); code != urExitOk {
		t.Fatalf("the other network's ur tun exited %d: %s", code, stderr.String())
	}
}

// The daemon runs one follower a Sidecar: a second start is refused and logged, and the first follows on; and a
// network that runs none gets no bridge, ur tun answering that the daemon does not follow its config.
func TestDaemonRunsOneFollowerASidecar(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	network := world.networks[0]
	running := world.host(network, nil)
	world.standing(running, network)
	first := running.ConfigFollower()
	if again := startUrConfigFollower(running, sidecar.NewNoopLogger()); again != nil {
		t.Fatal("a second follower started on one Sidecar")
	}
	if running.ConfigFollower() != first || first.Client() == nil {
		t.Fatal("the first follower stopped")
	}
	first.Close()
	if _, err := world.bridges.bridgeNetwork(network.NetworkId(), running); !errors.Is(err, errUrBridgeUnwired) {
		t.Fatalf("a network with no follower: %v", err)
	}
	if len(world.heldBridges()) != 0 {
		t.Fatal("a bridge was built with no follower")
	}
}
