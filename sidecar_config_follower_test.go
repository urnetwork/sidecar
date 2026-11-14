//go:build !ios_extension && !sidecar_http && !js

// A hosted network's config follower (QD-796) on sidecartest's Net: one instance hosting a Sidecar per network, as ur
// daemon does, each network an admission world whose log a FakeApi on the Net's cluster serves, each Sidecar following
// it through FollowConfig started before its enrollment, and the world's in-memory config repo standing in for the
// head reader over evs. Each network's log is followed with its own store, which a restart stands on with api's log
// refused; the acl follower evaluates a policy's local ports from the head; a follower that refuses its network's log
// leaves the other network following; one with no anchor and no first use follows nothing; a log is judged only at and
// past the anchored head; and a Sidecar takes one follower. Every wait is on a monitor or a channel, bounded by a
// real-time guard only a broken follower reaches.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How long, in real time, a step waits before it fails: a guard only, since every wait is on a monitor.
const configFollowTestTimeout = 60 * time.Second

// Networks of admission worlds on one Net, and one instance hosting a Sidecar in each, every Sidecar following its
// network's log from its start.
type configFollowWorld struct {
	t        *testing.T
	ctx      context.Context
	net      *sidecartest.Net
	instance *sidecartest.TestInstance
	networks []*sidecartest.AdmissionNet
	// the settings each follower starts on
	settings func() *sidecar.SidecarConfigFollowerSettings

	stateLock sync.Mutex
	// the head_alarms each Sidecar raised, by the Sidecar
	headAlarms map[*sidecar.Sidecar][]sidecar.SidecarEvent
}

// A world of networkCount networks, nothing hosted yet. settings nil is the daemon's: first use trusted, the full tail
// kept.
func newConfigFollowWorld(t *testing.T, networkCount int, settings func() *sidecar.SidecarConfigFollowerSettings) *configFollowWorld {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*configFollowTestTimeout)
	t.Cleanup(cancel)
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	if settings == nil {
		settings = func() *sidecar.SidecarConfigFollowerSettings {
			followerSettings := sidecar.DefaultSidecarConfigFollowerSettings()
			followerSettings.TrustFirstUse = true
			followerSettings.ConfigClient = sidecar.DefaultConfigClientSettings()
			followerSettings.ConfigClient.RetainFullTail = true
			return followerSettings
		}
	}
	world := &configFollowWorld{
		t:          t,
		ctx:        ctx,
		net:        net,
		settings:   settings,
		headAlarms: map[*sidecar.Sidecar][]sidecar.SidecarEvent{},
	}
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
	world.instance, err = net.StartInstance("daemon", &sidecartest.TestInstanceArgs{Start: world.follow})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.instance.Close)
	return world
}

// Starts running's follower, as ur daemon does at each Sidecar's start, and keeps its head_alarms.
func (self *configFollowWorld) follow(running *sidecar.Sidecar) error {
	running.AddEventCallback(func(event sidecar.SidecarEvent) {
		if event.Kind != sidecar.SidecarEventHeadAlarm {
			return
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.headAlarms[running] = append(self.headAlarms[running], event)
	})
	_, err := running.FollowConfig(&sidecar.SidecarConfigFollowerArgs{
		Heads:    &configFollowTestHeads{world: self, running: running},
		Settings: self.settings(),
	})
	return err
}

// The head_alarms running raised.
func (self *configFollowWorld) alarms(running *sidecar.Sidecar) []sidecar.SidecarEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]sidecar.SidecarEvent{}, self.headAlarms[running]...)
}

// The admission world of networkId, nil for none.
func (self *configFollowWorld) network(networkId sidecar.Id) *sidecartest.AdmissionNet {
	for _, network := range self.networks {
		if network.NetworkId() == networkId {
			return network
		}
	}
	return nil
}

// A Sidecar enrolled in network on the instance, anchored as anchor says, and admitted there by its owner's device
// under the owner's member.
func (self *configFollowWorld) host(network *sidecartest.AdmissionNet, anchor *sidecar.SidecarEnrollAnchor) *sidecar.Sidecar {
	self.t.Helper()
	running, err := self.instance.AddSidecarIn(network.NetworkId(), anchor)
	if err != nil {
		self.t.Fatal(err)
	}
	network.AdmitSidecar(network.Owner(), running.Identity(), network.Owner().MemberId, 0)
	return running
}

// Waits for running's follower to stand at network's tip, and answers its client.
func (self *configFollowWorld) standing(running *sidecar.Sidecar, network *sidecartest.AdmissionNet) *sidecar.ConfigClient {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, configFollowTestTimeout)
	defer cancel()
	follower := running.ConfigFollower()
	if follower == nil {
		self.t.Fatal("no follower runs")
	}
	client, err := follower.WaitStanding(ctx)
	if err != nil {
		self.t.Fatalf("the follower of network %s: %v", network.NetworkId(), err)
	}
	if _, err := client.WaitFor(ctx, network.Tip().GetVersion()); err != nil {
		self.t.Fatalf("the follower of network %s at %d: %v", network.NetworkId(), network.Tip().GetVersion(), err)
	}
	return client
}

// The genesis api serves for network, and its A_0.
func (self *configFollowWorld) genesis(network *sidecartest.AdmissionNet) [sha256.Size]byte {
	self.t.Helper()
	api, err := self.net.Api()
	if err != nil {
		self.t.Fatal(err)
	}
	projection, err := (&sidecartest.FakeApiConfigReader{Api: api, NetworkId: network.NetworkId()}).ReadConfigProjection(self.ctx, 0)
	if err != nil || len(projection.SignedGenesis) == 0 {
		self.t.Fatalf("network %s's genesis: %v", network.NetworkId(), err)
	}
	return bridge.GenesisChain(projection.SignedGenesis)
}

// A head reader over the admission world of whichever network running enrolls in, as the daemon's reader over evs
// reads its own network's config repo.
type configFollowTestHeads struct {
	world   *configFollowWorld
	running *sidecar.Sidecar
}

func (self *configFollowTestHeads) ReadConfigHead(ctx context.Context, version uint64, configHeadSha256 []byte) (*sidecar.ConfigHead, error) {
	networkId := self.running.NetworkId()
	if networkId == nil {
		return nil, sidecar.ErrConfigHeadUnavailable
	}
	network := self.world.network(*networkId)
	if network == nil {
		return nil, sidecar.ErrConfigHeadUnavailable
	}
	return network.Heads().ReadConfigHead(ctx, version, configHeadSha256)
}

// authlog/'s file of a Sidecar's network, as the follower's client kept it: whose network, and its pin.
type configFollowTestAuthlog struct {
	NetworkId sidecar.Id `json:"network_id"`
	Pin       *struct {
		N uint64 `json:"n"`
	} `json:"pin"`
}

// Reads running's authlog/ file.
func readConfigFollowTestAuthlog(t *testing.T, running *sidecar.Sidecar) *configFollowTestAuthlog {
	t.Helper()
	store, err := running.LocalStore().Directory("authlog", "authlog")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := store.Open("configlog")
	if err != nil {
		t.Fatalf("authlog/: %v", err)
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	document := &configFollowTestAuthlog{}
	if err := json.Unmarshal(data, document); err != nil || document.Pin == nil {
		t.Fatalf("authlog/ does not decode: %v", err)
	}
	return document
}

// A daemon hosting two networks follows each network's log with its own store: each Sidecar trusts its own network's
// genesis on first use, stands at its own tip and is admitted there alone; each network's authlog/ holds its own log;
// and after a restart, with api refusing every read of the log, each follower stands again on its own store alone, at
// the pin it held, and its Sidecar is admitted again.
func TestConfigFollowersKeepEachNetworksLogInItsOwnStore(t *testing.T) {
	world := newConfigFollowWorld(t, 2, nil)
	sidecars := []*sidecar.Sidecar{}
	pins := []*bridge.AuthPin{}
	for _, network := range world.networks {
		running := world.host(network, nil)
		client := world.standing(running, network)
		if client.NetworkId() != network.NetworkId() || !running.Admitted() {
			t.Fatalf("network %s: the client follows %s, admitted %t", network.NetworkId(), client.NetworkId(), running.Admitted())
		}
		anchor, err := running.Anchor()
		genesis := world.genesis(network)
		if err != nil || anchor.Source != sidecar.SidecarAnchorFirstUse || !bytes.Equal(anchor.GenesisSha256, genesis[:]) {
			t.Fatalf("network %s's anchor %+v: %v", network.NetworkId(), anchor, err)
		}
		sidecars = append(sidecars, running)
		pins = append(pins, client.Pin())
	}
	// neither network's state names the other's sidecar
	for i, running := range sidecars {
		other := sidecars[1-i].Identity().SidecarId
		if row := running.ConfigFollower().Client().State().SidecarRow(other); row != nil {
			t.Fatalf("network %d's log admits network %d's sidecar", i, 1-i)
		}
	}
	for i, running := range sidecars {
		kept := readConfigFollowTestAuthlog(t, running)
		if kept.NetworkId != world.networks[i].NetworkId() || kept.Pin.N != pins[i].GetVersion() {
			t.Fatalf("network %d's authlog/ holds network %s at %d, want %s at %d", i, kept.NetworkId, kept.Pin.N,
				world.networks[i].NetworkId(), pins[i].GetVersion())
		}
	}

	// the restart reads nothing of the log from api: each follower stands on its store
	if _, err := world.net.Faults().Add(&sidecartest.FaultPlan{
		Op:        sidecartest.FaultOpHttp,
		KeyPrefix: "/network/config/projection",
		Result:    sidecartest.FailBeforeApply,
		Repeat:    -1,
	}); err != nil {
		t.Fatal(err)
	}
	defer world.net.Faults().Clear()
	if err := world.instance.Restart(); err != nil {
		t.Fatal(err)
	}
	for i, network := range world.networks {
		running := world.instance.Sidecar(network.NetworkId())
		if running == nil {
			t.Fatalf("network %d is not hosted after the restart", i)
		}
		ctx, cancel := context.WithTimeout(world.ctx, configFollowTestTimeout)
		client, err := running.ConfigFollower().WaitStanding(ctx)
		cancel()
		if err != nil {
			t.Fatalf("network %d after the restart: %v", i, err)
		}
		if pin := client.Pin(); pin.GetVersion() != pins[i].GetVersion() || !bytes.Equal(pin.GetChain(), pins[i].GetChain()) {
			t.Fatalf("network %d restored at %d, held %d", i, pin.GetVersion(), pins[i].GetVersion())
		}
		if !running.Admitted() {
			t.Fatalf("network %d's sidecar is not admitted from its store", i)
		}
	}
}

// The acl follower runs on the follower's client and evaluates local policy from the head: a dial rule limited to
// tcp:22 opens tcp:22 to a member's device once the head's local policy compiles, and nothing else.
func TestConfigFollowerAclEvaluatesLocalPolicy(t *testing.T) {
	world := newConfigFollowWorld(t, 1, nil)
	network := world.networks[0]
	running := world.host(network, nil)
	world.standing(running, network)
	network.SaveAclPolicy([]byte(`{"grants": [{"src": ["autogroup:member"], "dst": ["autogroup:member"], "allow": ["dial"], "ip": ["tcp:22"]}]}`),
		sidecartest.AclSaveMembers{})
	client := world.standing(running, network)
	follower := running.ConfigFollower()
	aclFollower, engine := follower.AclFollower(), follower.AclEngine()
	if aclFollower == nil || engine == nil {
		t.Fatal("no acl follower runs on the standing follower")
	}
	ownerDevice := sidecar.AclSidecarSubject(network.Owner().SidecarId)
	allowed := func(ipProtocol uint32, port uint32) bool {
		return engine.AllowInbound(&sidecar.AclInbound{Source: ownerDevice, IpProtocol: ipProtocol, Port: port}, world.net.Clock().Now()).Allowed
	}
	guard := time.After(configFollowTestTimeout)
	for {
		// subscribed before the read, so an install between them wakes the wait
		_, changed := aclFollower.Local()
		if allowed(6, 22) {
			break
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatalf("tcp:22 stays closed at %d", engine.Pin().GetVersion())
		}
	}
	if engine.Pin().GetVersion() != client.Pin().GetVersion() {
		t.Fatalf("the engine holds %d, the client %d", engine.Pin().GetVersion(), client.Pin().GetVersion())
	}
	if allowed(6, 80) || allowed(17, 22) {
		t.Fatal("a port the rule does not name is open")
	}
	if local, _ := aclFollower.Local(); local == nil || follower.AclLocal() != local {
		t.Fatal("the follower answers another local policy than its acl follower installed")
	}
}

// A network whose follower refuses its log, an invite's anchor naming another genesis than api serves, raises
// head_alarm fork, judges nothing and admits nothing; the other network's follower stands, and follows on past it.
func TestConfigFollowerRefusalLeavesOtherNetworksFollowing(t *testing.T) {
	world := newConfigFollowWorld(t, 2, nil)
	good, refused := world.networks[0], world.networks[1]
	goodSidecar := world.host(good, nil)
	other := sha256.Sum256([]byte("a genesis no network here signed"))
	refusedSidecar := world.host(refused, &sidecar.SidecarEnrollAnchor{GenesisSha256: other[:]})

	ctx, cancel := context.WithTimeout(world.ctx, configFollowTestTimeout)
	defer cancel()
	if _, err := refusedSidecar.ConfigFollower().WaitStanding(ctx); !errors.Is(err, sidecar.ErrSidecarConfigRefused) ||
		!strings.Contains(err.Error(), "another genesis") {
		t.Fatalf("a follower shown another genesis: %v", err)
	}
	if refusedSidecar.Admitted() || refusedSidecar.ConfigFollower().Client() != nil {
		t.Fatal("a refused follower judges")
	}
	alarms := world.alarms(refusedSidecar)
	if len(alarms) != 1 || alarms[0].HeadAlarm != sidecar.SidecarHeadAlarmFork {
		t.Fatalf("head_alarms %+v", alarms)
	}

	world.standing(goodSidecar, good)
	if !goodSidecar.Admitted() || 0 < len(world.alarms(goodSidecar)) {
		t.Fatal("the other network does not follow")
	}
	tablet := good.Device("owner tablet", good.Owner().MemberId)
	good.AdmitDevice(good.Owner(), tablet, 0)
	if client := world.standing(goodSidecar, good); client.State().SidecarRow(tablet.SidecarId) == nil {
		t.Fatal("the other network's follower did not follow on")
	}
	if status := refusedSidecar.ConfigFollower().Status(); status.State != sidecar.SidecarConfigFollowerRefused {
		t.Fatalf("the refused follower is %s", status.State)
	}
}

// A Sidecar whose enrollment recorded no anchor, on a host that trusts no first use, follows nothing: its follower
// refuses, saying so, and no anchor is recorded.
func TestConfigFollowerWithNoAnchorFollowsNothingWithoutFirstUse(t *testing.T) {
	world := newConfigFollowWorld(t, 1, func() *sidecar.SidecarConfigFollowerSettings {
		return sidecar.DefaultSidecarConfigFollowerSettings()
	})
	running := world.host(world.networks[0], nil)
	ctx, cancel := context.WithTimeout(world.ctx, configFollowTestTimeout)
	defer cancel()
	if _, err := running.ConfigFollower().WaitStanding(ctx); !errors.Is(err, sidecar.ErrSidecarConfigRefused) ||
		!strings.Contains(err.Error(), "no genesis anchor") {
		t.Fatalf("no anchor and no first use: %v", err)
	}
	if _, err := running.Anchor(); !errors.Is(err, sidecar.ErrSidecarStoreAbsent) {
		t.Fatalf("an anchor was recorded: %v", err)
	}
	if running.Admitted() {
		t.Fatal("admitted with nothing followed")
	}
}

// An invite's head binds the log (I-16): a follower whose anchored head names another chain than the log holds at
// that position refuses with head_alarm fork, and one whose head is the log's stands.
func TestConfigFollowerStandsOnlyOnTheAnchoredHead(t *testing.T) {
	world := newConfigFollowWorld(t, 2, nil)
	honest, forged := world.networks[0], world.networks[1]
	honestGenesis, forgedGenesis := world.genesis(honest), world.genesis(forged)
	honestTip, forgedTip := honest.Tip(), forged.Tip()
	honestSidecar := world.host(honest, &sidecar.SidecarEnrollAnchor{
		GenesisSha256: honestGenesis[:], HeadVersion: honestTip.GetVersion(), HeadChain: honestTip.GetChain(),
	})
	otherChain := sha256.Sum256([]byte("a chain no log here holds"))
	forgedSidecar := world.host(forged, &sidecar.SidecarEnrollAnchor{
		GenesisSha256: forgedGenesis[:], HeadVersion: forgedTip.GetVersion(), HeadChain: otherChain[:],
	})

	world.standing(honestSidecar, honest)
	if !honestSidecar.Admitted() {
		t.Fatal("a log on its anchored head is not judged")
	}
	ctx, cancel := context.WithTimeout(world.ctx, configFollowTestTimeout)
	defer cancel()
	if _, err := forgedSidecar.ConfigFollower().WaitStanding(ctx); !errors.Is(err, sidecar.ErrSidecarConfigRefused) ||
		!errors.Is(err, sidecar.ErrSidecarAnchorMismatch) {
		t.Fatalf("another chain at the anchored head: %v", err)
	}
	if forgedSidecar.Admitted() {
		t.Fatal("a log off its anchored head is judged")
	}
	if alarms := world.alarms(forgedSidecar); len(alarms) != 1 || alarms[0].HeadAlarm != sidecar.SidecarHeadAlarmFork {
		t.Fatalf("head_alarms %+v", alarms)
	}
}

// A Sidecar takes one follower: a second is refused while the first runs, and once it closes the Sidecar has none, its
// authority comes off, and a new one may start.
func TestConfigFollowerIsOneASidecar(t *testing.T) {
	world := newConfigFollowWorld(t, 1, nil)
	network := world.networks[0]
	running := world.host(network, nil)
	world.standing(running, network)
	if _, err := running.FollowConfig(nil); !errors.Is(err, sidecar.ErrSidecarConfigFollowing) {
		t.Fatalf("a second follower: %v", err)
	}
	running.ConfigFollower().Close()
	if running.ConfigFollower() != nil || running.Admitted() {
		t.Fatal("a closed follower still judges")
	}
	if err := world.follow(running); err != nil {
		t.Fatalf("a follower after the first closed: %v", err)
	}
	world.standing(running, network)
	if !running.Admitted() {
		t.Fatal("the new follower does not judge")
	}
}
