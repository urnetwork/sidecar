// The daemon's wiring of the bridge (BRIDGE-M4-18, §17.10): one device.Bridge beside a network's Sidecar, on a
// posture store under the instance's state directory (device.NewFilePostureStore), with the CLI's BridgeHost
// (bridge_host.go) and the Sidecar's own signer and identity lookups, fed by the root's BridgeComponent through
// urBridgeSink, the adapter 12.2.5 names. The component is the Sidecar's "bridge" component: it follows the
// network's ConfigClient, compiles and serves bridge flows on each client generation (bridge_component.go).
//
// urBridgeDaemon holds the daemon's bridges, one a network, and the instance's one OS tun over one of them (ur tun,
// tun_device.go), which it closes with the daemon, so routes are restored on every path the daemon ends by.
//
// What the wiring needs of the network's config, the ConfigClient and the head, rows, keys and local policy beside
// it, comes from the daemon's config follower, which no task builds yet (question bridge-m4-16-daemon-config-follower).
// Until one does, urBridgeDaemon has nothing to build a network's bridge from: ur tun and ur tun ip refuse, naming it,
// the closed direction.

package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The daemon runs no bridge for the network.
var errUrBridgeUnwired = errors.New("no bridge runs for this network: the daemon does not follow its config yet")

// The bridge's pass-through to this host's resolvers for the names its zone does not hold (§12.9), from the platform
// where ur tun runs: bridge_dns_linux.go sets it. routed says whether an address is routed into the tun, where a query
// would loop back to the bridge's own resolver. Nil elsewhere: the resolver then answers a server failure for them.
var urBridgeResolverUpstream func(routed func(address netip.Addr) bool) device.BridgeResolverUpstream

// device.Bridge as the component's sink: each call through, a log run converted to the posture's, and the decision
// read off what the bridge adopted.
type urBridgeSink struct {
	bridge *device.Bridge
}

var _ sidecar.BridgeStateSink = (*urBridgeSink)(nil)

func (self *urBridgeSink) SetPending(pending *bridge.Pending) error {
	return self.bridge.SetPending(pending)
}

func (self *urBridgeSink) SetState(state *bridge.BridgeState, log *sidecar.BridgeStateLog) error {
	return self.bridge.SetState(state, urPostureLog(log))
}

func (self *urBridgeSink) ApplyDeltas(log *sidecar.BridgeStateLog) error {
	return self.bridge.ApplyDeltas(urPostureLog(log))
}

func (self *urBridgeSink) SetFork(fork bool) error {
	return self.bridge.SetFork(fork)
}

func (self *urBridgeSink) Decision() sidecar.BridgeSinkDecision {
	decision := self.bridge.Decision()
	sinkDecision := sidecar.BridgeSinkDecision{Pin: decision.Pin, Fork: decision.Fork}
	switch decision.State {
	case device.PostureLegacy:
		sinkDecision.State = sidecar.BridgeSinkLegacy
	case device.PostureEnforcingDocument, device.PostureEnforcingNoDocument:
		sinkDecision.State = sidecar.BridgeSinkEnforcing
	default:
		sinkDecision.State = sidecar.BridgeSinkPending
	}
	if decision.BridgeState != nil {
		sinkDecision.StatePin = decision.BridgeState.GetAuth()
	}
	return sinkDecision
}

func (self *urBridgeSink) Revoke(statementType bridge.SignedType, id []byte, n uint64) error {
	return self.bridge.Revoke(statementType, id, n)
}

func (self *urBridgeSink) EgressHook() connect.EgressHook {
	return self.bridge.EgressHook()
}

// A log run as the posture reads it.
func urPostureLog(log *sidecar.BridgeStateLog) *device.PostureLog {
	if log == nil {
		return nil
	}
	return &device.PostureLog{Entries: log.Entries, OpenRows: log.OpenRows}
}

// What the wiring is built over: a network's Sidecar and its config follower.
type urBridgeWireArgs struct {
	NetworkId sidecar.Id
	Sidecar   *sidecar.Sidecar
	// The network's config follower and what reads beside it (sidecar.BridgeComponentArgs).
	Config    sidecar.BridgeConfigSource
	Heads     sidecar.ConfigHeadReader
	Rows      sidecar.ConfigRowsSource
	RepoKeyAt func(generation uint64) *sidecar.EvsRepoKey
	AclLocal  func() *sidecar.AclLocalPolicy
	// The instance's state directory: the posture's store is bridge/<network_id> under it.
	StateDirectory  string
	DaemonListeners func() []string
	// The connect settings a link's generator dials with.
	SidecarSettings *sidecar.SidecarSettings
	// The component's settings, nil its defaults; ur tun ip reads AutoAddressEnabled from it.
	ComponentSettings *sidecar.BridgeComponentSettings
	Log               sidecar.Logger
}

// One network's bridge: the device role, its host and the component that feeds it.
type urBridgeWire struct {
	args              *urBridgeWireArgs
	componentSettings *sidecar.BridgeComponentSettings
	bridge            *device.Bridge
	// the bridge once built, which the resolver's pass-through reads from its own workers
	builtBridge atomic.Pointer[device.Bridge]
	host        *urBridgeHost
	component   *sidecar.BridgeComponent
	remove      func()
	cancel      context.CancelFunc
}

// Builds a network's bridge and adds its component to the Sidecar: the posture restored first, so the device role is
// in force before any generation serves (DP1, 12.2.5's step 1).
func newUrBridgeWire(ctx context.Context, args *urBridgeWireArgs) (*urBridgeWire, error) {
	if args == nil || args.Sidecar == nil || args.Config == nil {
		return nil, errUrBridgeUnwired
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &urBridgeWire{args: args, cancel: cancel, componentSettings: args.ComponentSettings}
	if self.componentSettings == nil {
		self.componentSettings = sidecar.DefaultBridgeComponentSettings()
	}
	store, err := device.NewFilePostureStore(filepath.Join(args.StateDirectory, "bridge", args.NetworkId.String()))
	if err != nil {
		cancel()
		return nil, err
	}
	settings := device.DefaultBridgeSettings()
	settings.LinkSign = self.sign
	settings.LinkTargetKey = self.targetKey
	if urBridgeResolverUpstream != nil {
		settings.ResolverUpstream = urBridgeResolverUpstream(self.routed)
	}
	self.host = newUrBridgeHost(cancelCtx, settings)
	self.bridge, err = device.NewBridge(cancelCtx, store, self.host, settings)
	if err != nil {
		cancel()
		return nil, err
	}
	self.builtBridge.Store(self.bridge)
	self.component, err = sidecar.NewBridgeComponent(cancelCtx, &sidecar.BridgeComponentArgs{
		NetworkId:       args.NetworkId,
		Identity:        args.Sidecar.Identity,
		Config:          args.Config,
		Heads:           args.Heads,
		Rows:            args.Rows,
		RepoKeyAt:       args.RepoKeyAt,
		AclLocal:        args.AclLocal,
		DaemonListeners: args.DaemonListeners,
		Log:             args.Log,
		OnAttach:        self.attach,
		Settings:        self.componentSettings,
	})
	if err != nil {
		self.bridge.Close()
		cancel()
		return nil, err
	}
	if err := self.component.SetDeviceRole(&urBridgeSink{bridge: self.bridge}); err != nil {
		self.close()
		return nil, err
	}
	self.remove, err = args.Sidecar.AddComponent(self.component)
	if err != nil {
		self.close()
		return nil, err
	}
	return self, nil
}

// Takes a client generation for the links the next builds mint under.
func (self *urBridgeWire) attach(env *sidecar.SidecarEnv) {
	if env.Identity == nil || env.SidecarApi == nil || env.Api == nil || self.args.SidecarSettings == nil {
		self.host.setGeneration(nil)
		return
	}
	self.host.setGeneration(&urBridgeGeneration{
		api:            env.SidecarApi,
		credentials:    &urBridgeCredentials{api: env.SidecarApi},
		byJwt:          env.Api.ByJwt(),
		sourceClientId: connect.Id(env.Identity.ClientId),
		strategy:       connect.NewClientStrategy(env.Ctx, self.args.SidecarSettings.Connect.ClientStrategySettings),
		apiUrl:         self.args.SidecarSettings.ApiUrl,
		platformUrl:    self.args.SidecarSettings.PlatformUrl,
	})
}

// device.BridgeSignFunction over the Sidecar's signer (§17.9's sign row): it refuses what it would not sign.
func (self *urBridgeWire) sign(ctx context.Context, delegation *bridge.WindowDelegation) ([]byte, error) {
	ids := []sidecar.Id{}
	for _, idBytes := range [][]byte{delegation.GetNetworkId(), delegation.GetSubjectSidecarId(), delegation.GetWindowClientId(), delegation.GetTargetSidecarId()} {
		id, err := sidecar.IdFromBytes(idBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: a delegation's id", sidecar.ErrBridgeDelegationRefused)
		}
		ids = append(ids, id)
	}
	return self.args.Sidecar.SignWindowDelegation(&sidecar.BridgeDelegationRequest{
		NetworkId:             ids[0],
		SubjectSidecarId:      ids[1],
		WindowClientId:        ids[2],
		WindowClientPublicKey: delegation.GetWindowClientPublicKey(),
		TargetSidecarId:       ids[3],
		NotAfter:              time.UnixMilli(delegation.GetNotAfterMs()),
	})
}

// device.BridgeTargetKeyFunction: the binding api answers for the target client, which the link verifies against the
// identity key the rules pin, so api stays untrusted (§17.9's target row).
func (self *urBridgeWire) targetKey(ctx context.Context, targetSidecarId connect.Id, targetClientId connect.Id) ([]byte, error) {
	generation := func() *urBridgeGeneration {
		self.host.stateLock.Lock()
		defer self.host.stateLock.Unlock()
		return self.host.generation
	}()
	if generation == nil {
		return nil, fmt.Errorf("%w: no client generation", errUrBridgeHostRefused)
	}
	record, err := generation.api.GetIdentityByClient(ctx, sidecar.Id(targetClientId))
	if err != nil {
		return nil, err
	}
	if record.SidecarId != sidecar.Id(targetSidecarId) {
		return nil, fmt.Errorf("%w: api names another sidecar for the target client", errUrBridgeHostRefused)
	}
	return record.Binding, nil
}

// Whether address is routed into the tun, where the resolver's pass-through would loop: the bridge's export holds it.
// False before the bridge is built.
func (self *urBridgeWire) routed(address netip.Addr) bool {
	built := self.builtBridge.Load()
	if built == nil {
		return false
	}
	return slices.ContainsFunc(built.Routes(), func(route netip.Prefix) bool {
		return route.Contains(address.Unmap())
	})
}

// Takes the network's bridge out of the Sidecar and ends it: the component first, then the device role and its links.
// The posture's store stays for the next start.
func (self *urBridgeWire) close() {
	if self.remove != nil {
		self.remove()
	} else if self.component != nil {
		self.component.Close()
	}
	if self.bridge != nil {
		self.bridge.Close()
	}
	self.cancel()
}

// The network's bridge as the daemon's tun methods reach it.
func (self *urBridgeWire) network() *urBridgeNetwork {
	return &urBridgeNetwork{
		networkId:         self.args.NetworkId,
		bridge:            self.bridge,
		links:             self.host,
		paired:            self.args.Sidecar.Paired,
		componentSettings: self.componentSettings,
		close:             self.close,
	}
}

// One network's bridge as the daemon's tun methods reach it: a wire's, or a test's fakes.
type urBridgeNetwork struct {
	networkId sidecar.Id
	bridge    urTunBridge
	links     urTunLinks
	// whether the network's sidecar is a paired child, whose app's device role may hold the block (§17.11's yield)
	paired            func() bool
	componentSettings *sidecar.BridgeComponentSettings
	// ends the bridge, nil for none
	close func()
}

// What builds a network's bridge over the daemon's config follower for it.
type urBridgeBuildFunction func(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar) (*urBridgeNetwork, error)

// What a daemon's bridges are built over.
type urBridgeDaemonArgs struct {
	Instance string
	// The platform's half of ur tun, nil where ur tun does not run (errUrTunPlatform).
	System urTunSystem
	// Builds a network's bridge on demand. Nil until the daemon follows a network's config (the file's comment), and
	// every network then answers errUrBridgeUnwired.
	Build    urBridgeBuildFunction
	Settings *urTunSettings
	Log      sidecar.Logger
}

// The daemon's bridges and the instance's one OS tun (the file's comment). Safe for concurrent use.
type urBridgeDaemon struct {
	ctx      context.Context
	cancel   context.CancelFunc
	instance string
	system   urTunSystem
	build    urBridgeBuildFunction
	settings *urTunSettings
	log      sidecar.Logger

	// serializes what starts or ends the tun and builds a bridge, which do I/O, so two ur tun calls cannot race
	operationLock sync.Mutex

	stateLock sync.Mutex
	networks  map[sidecar.Id]*urBridgeNetwork
	tun       *urTun
	closed    bool
}

// A daemon's bridges' args: the platform's half of ur tun where it runs, and no builder, since the daemon follows no
// network's config yet (the file's comment).
func urBridgeDaemonArgsOf(instance string, log sidecar.Logger) *urBridgeDaemonArgs {
	settings := defaultUrTunSettings()
	var system urTunSystem
	if urTunPlatform != nil {
		system = urTunPlatform(settings, log)
	}
	return &urBridgeDaemonArgs{Instance: instance, System: system, Settings: settings, Log: log}
}

// The daemon's bridges, living until ctx ends or close.
func newUrBridgeDaemon(ctx context.Context, args *urBridgeDaemonArgs) *urBridgeDaemon {
	cancelCtx, cancel := context.WithCancel(ctx)
	settings := args.Settings
	if settings == nil {
		settings = defaultUrTunSettings()
	}
	log := args.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	return &urBridgeDaemon{
		ctx:      cancelCtx,
		cancel:   cancel,
		instance: args.Instance,
		system:   args.System,
		build:    args.Build,
		settings: settings,
		log:      log,
		networks: map[sidecar.Id]*urBridgeNetwork{},
	}
}

// Holds a network's bridge, which the daemon's composition built; the returned function forgets it again.
func (self *urBridgeDaemon) addNetwork(network *urBridgeNetwork) (func(), error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, errUrTunClosed
	}
	if _, held := self.networks[network.networkId]; held {
		return nil, fmt.Errorf("a bridge runs for network %s already", network.networkId)
	}
	self.networks[network.networkId] = network
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.networks[network.networkId] == network {
			delete(self.networks, network.networkId)
		}
	}, nil
}

// The network's bridge: the one held, else one built now. Under operationLock.
func (self *urBridgeDaemon) networkWithLock(networkId sidecar.Id, running *sidecar.Sidecar) (*urBridgeNetwork, error) {
	network, closed := func() (*urBridgeNetwork, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.networks[networkId], self.closed
	}()
	if closed {
		return nil, errUrTunClosed
	}
	if network != nil {
		return network, nil
	}
	if self.build == nil || running == nil {
		return nil, errUrBridgeUnwired
	}
	network, err := self.build(self.ctx, networkId, running)
	if err != nil {
		return nil, err
	}
	if _, err := self.addNetwork(network); err != nil {
		if network.close != nil {
			network.close()
		}
		return nil, err
	}
	return network, nil
}

// Brings the instance's tun up over the network's bridge, or answers it as it is when it carries that network
// already. Refuses where the platform has no tun, while the tun carries another network, and when an app's bridge
// holds the block on this host (§17.11's yield): a paired sidecar's app runs the device role in its VPN component
// whenever that runs (owner decision 197), so a route inside the block on another interface is its.
func (self *urBridgeDaemon) tunUp(networkId sidecar.Id, running *sidecar.Sidecar) (*urTunStatus, error) {
	if self.system == nil {
		return nil, errUrTunPlatform
	}
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	current := func() *urTun {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.tun
	}()
	if current != nil {
		if current.networkId == networkId {
			return current.status(), nil
		}
		return nil, fmt.Errorf("ur tun carries network %s: ur tun down first", current.networkId)
	}
	network, err := self.networkWithLock(networkId, running)
	if err != nil {
		return nil, err
	}
	name := urTunDeviceName(self.instance, self.settings.DeviceNameByteCount)
	if block := network.bridge.Status().Block; block.IsValid() && network.paired != nil && network.paired() {
		holder, err := self.system.RoutedElsewhere(name, block)
		if err != nil {
			return nil, err
		}
		if holder != "" {
			return nil, fmt.Errorf("%w: its interface %s routes the network's block on this host", errUrTunYield, holder)
		}
	}
	tun, err := startUrTun(self.ctx, &urTunArgs{
		Name:      name,
		NetworkId: networkId,
		System:    self.system,
		Bridge:    network.bridge,
		Links:     network.links,
		Settings:  self.settings,
		Log:       self.log,
		OnClose:   self.forgetTun,
	})
	if err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.tun = tun
	}()
	self.log.Infof("[tun]%s up", networkId)
	return tun.status(), nil
}

// Forgets the tun once it has closed, on whichever path: the tun's OnClose.
func (self *urBridgeDaemon) forgetTun(tun *urTun, reason error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.tun == tun {
		self.tun = nil
	}
}

// Ends the tun, removing its routes. False when none was up.
func (self *urBridgeDaemon) tunDown() bool {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	tun := func() *urTun {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.tun
	}()
	if tun == nil {
		return false
	}
	tun.close()
	return true
}

// The tun's status, nil while it is down.
func (self *urBridgeDaemon) tunStatus() *urTunStatus {
	tun := func() *urTun {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.tun
	}()
	if tun == nil {
		return nil
	}
	return tun.status()
}

// The network's bridge for ur tun ip, built if it is not held. Refuses as networkWithLock does.
func (self *urBridgeDaemon) bridgeNetwork(networkId sidecar.Id, running *sidecar.Sidecar) (*urBridgeNetwork, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.networkWithLock(networkId, running)
}

// Ends the tun and every bridge, with the daemon. Waits for the tun's routes to go.
func (self *urBridgeDaemon) close() {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	var tun *urTun
	networks := []*urBridgeNetwork{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		tun = self.tun
		for _, network := range self.networks {
			networks = append(networks, network)
		}
		clear(self.networks)
	}()
	if tun != nil {
		tun.close()
	}
	for _, network := range networks {
		if network.close != nil {
			network.close()
		}
	}
	self.cancel()
}
