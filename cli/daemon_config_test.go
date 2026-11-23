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
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"google.golang.org/protobuf/proto"
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
	return newTestUrFollowWorldWithSettings(t, networkCount, nil)
}

// Like a stock instance, with a new settings object for each device or restart.
func newTestUrFollowWorldWithSettings(t *testing.T, networkCount int, settings func() *sidecar.SidecarSettings) *testUrFollowWorld {
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
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	// The enrolled host and the other devices post to the same network sequencer.
	tier.NewApi = func(sidecar.Clock, sidecar.BlobCluster) sidecartest.AdmissionApi {
		return sidecartest.FakeApiAdmission(api)
	}
	tier.AclCompile = sidecartest.AclAdmissionCompile
	tier.AclSpendCheck = sidecar.NewSpendCheck(nil)
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
		Settings: settings,
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

type testUrForwardKeys struct{ key *sidecar.EvsRepoKey }

func (self testUrForwardKeys) CurrentConfigKey(context.Context) (*sidecar.EvsRepoKey, error) {
	return self.key, nil
}

func (self testUrForwardKeys) ConfigKeyAt(generation uint64) *sidecar.EvsRepoKey {
	if self.key.Generation() == generation {
		return self.key
	}
	return nil
}

// The native bridge files the regular member's request and checks its signed activation on the local log before
// returning the route. The first call binds no listener until the member's other device approves.
func TestUrDaemonFollowsVerifiedForwardApproval(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	network := world.networks[0]
	member, target := network.ConsentedMember("forward member")
	running, err := world.instance.AddSidecarIn(network.NetworkId(), nil)
	if err != nil {
		t.Fatal(err)
	}
	network.AdmitSidecar(target, running.Identity(), member, 0)
	requester := running.Identity().SidecarId
	world.saveBlock(network, 80)
	network.SaveAclPolicy([]byte(`{"requests":[{"src":["autogroup:member"],"dst":["autogroup:self"],"allow":["dial"]}]}`), nil)
	world.standing(running, network)
	now := network.Clock().Now()
	key, _, err := sidecar.NewGkmFirstGeneration(network.ConfigRepoId(), network.Id("forward config group"), &sidecar.GkmGenerationArgs{
		Cause: sidecar.GkmCauseRequest, Auth: network.Tip(), Time: now, HoldersSha256: make([]byte, sha256.Size),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(running.InstallConfigKeys(testUrForwardKeys{key}))
	header := network.Header()
	addressKind := bridge.SignedType_SIGNED_BRIDGE_ADDRESS
	sealed, err := sidecar.SealConfigBody(key, sidecar.NewConfigSealContext(addressKind, header), &bridge.BridgeAddressBody{Ipv4: 0x6450010e}, nil)
	if err != nil {
		t.Fatal(err)
	}
	network.MustLand(network.Sign(target, addressKind, &bridge.BridgeAddress{Header: header, SidecarId: target.SidecarId.Bytes(), SealedBody: sealed}))
	world.standing(running, network)
	control, err := newUrDaemonBridges(world.bridges, func(*sidecar.DaemonLocalListenArgs) (*sidecar.DaemonLocalListener, error) {
		t.Fatal("a pending forward attempted to bind a listener")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	origin := &sidecar.BridgeFileOrigin{Act: sidecar.SidecarActConfirmed}
	pending, err := control.Forward(world.ctx, network.NetworkId(), running, origin, &sidecar.DaemonBridgeForwardParams{
		Target: target.SidecarId.String(), Protocol: "tcp", Port: 5353, LocalPort: 10053, LifetimeSeconds: 900,
	})
	if err != nil || pending.ApprovalPendingId == nil {
		t.Fatalf("native forward request: %+v, %v", pending, err)
	}
	approvalId := *pending.ApprovalPendingId
	ledger, err := running.ApprovalLedger()
	if err != nil {
		t.Fatal(err)
	}
	entry, err := ledger.State(approvalId)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := sidecar.ParseStoredApprovalRequest(entry.Request)
	if err != nil {
		t.Fatal(err)
	}
	payload := stored.Action.PayloadSha256()
	deadline := stored.Action.Action.GetExpiresMillis()
	requestDigest := stored.Sha256()
	body, err := proto.Marshal(&protocol.ApprovalDecision{
		ApprovalId: approvalId.Bytes(), RequestSha256: requestDigest[:], PayloadSha256: payload[:],
		Decision: uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE), Uses: 1, NotAfterMillis: stored.Request.GetNotAfterMillis(),
		ApproverMemberId: member.Bytes(), Channel: uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		RequesterSidecarId: requester.Bytes(), AuthPin: network.Tip(), Version: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	kind := bridge.SignedType_SIGNED_APPROVAL_DECISION
	origin.Decision = &bridge.Signed{Body: body, SignerId: target.SidecarId.Bytes(), Type: uint32(kind),
		Signature: ed25519.Sign(target.Key, bridge.SignedBytes(sidecar.ApprovalPurpose, kind, body))}
	backends := &urBridgeBackends{bridges: world.bridges, networkIdBackends: map[sidecar.Id]*urBridgeBackend{}}
	defer backends.close()
	backend, err := backends.backend(world.ctx, network.NetworkId(), running)
	if err != nil {
		t.Fatal(err)
	}
	request := &sidecar.BridgeForwardRequest{Target: target.SidecarId, Protocol: 6, Port: 5353, LocalPort: 10053, Lifetime: 15 * time.Minute}
	filed, err := backend.Forward(world.ctx, origin, request)
	grantId := sidecar.AclGrantId(approvalId, payload)
	if err != nil || !bytes.Equal(filed.GrantId, grantId[:]) || filed.ApprovalId != approvalId {
		t.Fatalf("native approval receipt: %+v, %v", filed, err)
	}
	route, err := backend.ForwardRoute(world.ctx, request, filed.GrantId)
	if err != nil || !route.Live || route.Address != netip.MustParseAddr("100.80.1.14") || route.ExpiresAt.UnixMilli() != deadline {
		t.Fatalf("native approved route: %+v, %v", route, err)
	}
	acl, err := running.ConfigFollower().Client().State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	from := sidecar.AclSidecarSubject(requester)
	rules := acl.DialRules(from, sidecar.AclSidecarSubject(target.SidecarId), now)
	if len(rules) != 1 || !bytes.Equal(rules[0].GrantId, grantId[:]) || !rules[0].PortsLimited || rules[0].ExpiresMs != deadline {
		t.Fatalf("daemon's verified forward grant: %+v", rules)
	}
	if other := acl.DialRules(from, sidecar.AclSidecarSubject(network.Owner().SidecarId), now); len(other) != 0 {
		t.Fatalf("daemon's grants for a different member's device: %+v", other)
	}
	if _, err := backend.Close(world.ctx, &sidecar.BridgeFileOrigin{Act: sidecar.SidecarActConfirmed}, filed.GrantId, false); err != nil {
		t.Fatal(err)
	}
	network.Sync()
	world.standing(running, network)
	if withdrawn, err := backend.ForwardRoute(world.ctx, request, filed.GrantId); err != nil || withdrawn.Live {
		t.Fatalf("native withdrawn route: %+v, %v", withdrawn, err)
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

// Saves a config head holding a block of 100.<second>.0.0/16, signed by the network's owner, and lands its base, in
// place of the block the bootstrap drew; where it drew this very block, signed alike, the head holds it already.
func (self *testUrFollowWorld) saveBlock(network *sidecartest.AdmissionNet, second byte) {
	self.t.Helper()
	signed := network.Sign(network.Owner(), bridge.SignedType_SIGNED_BRIDGE_BLOCK, &bridge.BridgeBlock{
		Ipv4Prefix: &bridge.BridgeIpv4Prefix{Address: 100<<24 | uint32(second)<<16, Length: 16},
	})
	network.SaveHeadIfAny(func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
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

// The normal CLI bridge builder serves the authenticated config-backed methods after the follower is standing.
func TestBridgeStatusReadsItsStandingFollower(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	network := world.networks[0]
	running := world.host(network, nil)
	world.saveBlock(network, 80)
	world.standing(running, network)
	control, err := newUrDaemonBridges(world.bridges, sidecar.DaemonLocalListen)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	networkId := network.NetworkId()
	if _, err := control.Status(world.ctx, networkId, running); err != nil {
		t.Fatal(err)
	}
	world.awaitEnforcing(world.heldBridges()[networkId])
	status, err := control.Status(world.ctx, networkId, running)
	if err != nil || status.List == nil || status.List.NetworkId != networkId {
		t.Fatalf("standing network's bridge status: %+v, %v", status, err)
	}
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

// The stock TLS installer attaches to an enrolled daemon's verified follower. The real publish handler then
// evaluates the reserved system name, and removing the component makes that same handler unavailable again.
func TestUrDesktopTlsInstallsTheDaemonPublisher(t *testing.T) {
	world := newTestUrFollowWorld(t, 1)
	network := world.networks[0]
	running := world.host(network, nil)
	world.saveBlock(network, 80)
	world.standing(running, network)
	service := &urDesktopTls{
		running: running, follower: running.ConfigFollower(), stateDirectory: t.TempDir(), network: &urDaemonNetwork{},
	}
	if _, err := service.clientNames(world.ctx); err != nil {
		t.Fatalf("client names from the verified config head: %v", err)
	}
	var publish *sidecar.DaemonMethod
	for _, method := range sidecar.DaemonTlsMethods() {
		if method.Name == sidecar.DaemonMethodTlsPublish {
			publish = method
		}
	}
	if publish == nil {
		t.Fatal("the daemon has no TLS publish handler")
	}
	call := &sidecar.DaemonCall{Sidecar: running, Params: []byte(`{"host":"mta-sts","target":"8080"}`)}
	if _, err := publish.Handler(world.ctx, call); !errors.Is(err, sidecar.ErrTlsComponentAbsent) {
		t.Fatalf("publish before TLS installation: %v", err)
	}
	remove, err := service.install(world.ctx, sidecar.NewNoopLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	if _, err := publish.Handler(world.ctx, call); !errors.Is(err, sidecar.ErrTlsPublishHostTaken) {
		t.Fatalf("reserved publish through installed TLS: %v", err)
	}
	remove()
	if _, err := publish.Handler(world.ctx, call); !errors.Is(err, sidecar.ErrTlsComponentAbsent) {
		t.Fatalf("publish after removing TLS: %v", err)
	}
}
