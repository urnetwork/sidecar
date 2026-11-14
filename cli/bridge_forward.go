// The daemon's half of ur bridge (BRIDGE-M4-20, §17.11): the root's DaemonBridges over each network's bridge, with
// the userspace stack a forward dials through.
//
// urBridgeStack is that stack: a connect.Tun whose packets run through the bridge's RouteBurst to the links and
// whose replies come back from the links, the rejects and the resolver, so a forward needs no OS tun and no root. A
// link's provider translates the stack's own source address, so the stack needs no overlay address of its own. The
// bridge and its links each have one receiver, which ur tun takes while it is up: a forward then dials through the
// OS, whose routes carry the network's addresses into ur tun, and takes the receiver back for the stack at its next
// dial once ur tun is down. A flow in flight across that change ends, and its client dials again.
//
// urBridgeBackend is one network's sidecar.DaemonBridgeBackend: the device role's status as the listing, the stack,
// and what the network's config gives, the filer, the ledger's rules and the grants' state, through urBridgeConfigOf.
// The daemon follows no network's config yet (bridge_wire.go's comment; question bridge-m4-16-daemon-config-follower),
// so urBridgeConfigOf is nil and every bridge method refuses, naming it, the closed direction.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The filings a network's bridge methods make: sidecar.BridgeFiler is one.
type urBridgeFiler interface {
	Expose(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeRouteRequest) (*sidecar.BridgeFiling, error)
	ExposeMap(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeMapRequest) (*sidecar.BridgeFiling, error)
	Forward(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeForwardRequest) (*sidecar.BridgeFiling, error)
	Close(ctx context.Context, origin *sidecar.BridgeFileOrigin, id []byte, reset bool) (*sidecar.BridgeFiling, error)
	SetEgress(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeEgressRequest) (*sidecar.BridgeFiling, error)
	SetBlock(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeBlockRequest) (*bridge.BridgeBlock, error)
}

var _ urBridgeFiler = (*sidecar.BridgeFiler)(nil)

// What a network's bridge methods read of its config, beyond the device role.
type urBridgeConfig struct {
	// The sidecar that files.
	SidecarId sidecar.Id
	Filer     urBridgeFiler
	// The ledger's rules at the newest verified state; nil lists none.
	Rules func(ctx context.Context) ([]*sidecar.BridgeLedgerRule, error)
	// The state's private names; nil lists none.
	Names func() []*sidecar.DaemonBridgeName
	// A private name or an overlay address as its sidecar; nil resolves ids alone.
	Resolve func(ctx context.Context, name string) (sidecar.Id, error)
	// Where a forward dials and whether its grant is active; nil refuses every forward.
	ForwardRoute func(ctx context.Context, request *sidecar.BridgeForwardRequest, grantId []byte) (*sidecar.DaemonBridgeForwardRoute, error)
}

// Builds a network's urBridgeConfig over the daemon's config follower for it: nil until the daemon follows a
// network's config (the file's comment), and every bridge method then refuses with errUrBridgeUnwired.
var urBridgeConfigOf func(ctx context.Context, network *urBridgeNetwork, running *sidecar.Sidecar) (*urBridgeConfig, error)

// The bridge's methods over a target that hosts its networks.
func urBridgeMethods(target urDaemonTarget) []*sidecar.DaemonMethod {
	network, ok := target.(*urDaemonNetwork)
	if !ok || network.bridges == nil || network.daemon == nil {
		return nil
	}
	bridges, err := newUrDaemonBridges(network.bridges, network.daemon.LocalListen)
	if err != nil {
		return nil
	}
	return bridges.Methods()
}

// The root's bridge methods over the daemon's bridges, ending with them.
func newUrDaemonBridges(bridges *urBridgeDaemon, listen func(args *sidecar.DaemonLocalListenArgs) (*sidecar.DaemonLocalListener, error)) (*sidecar.DaemonBridges, error) {
	backends := &urBridgeBackends{bridges: bridges, networkIdBackends: map[sidecar.Id]*urBridgeBackend{}}
	daemonBridges, err := sidecar.NewDaemonBridges(bridges.ctx, &sidecar.DaemonBridgesArgs{
		Backend: backends.backend,
		Listen:  listen,
		Log:     bridges.log,
	})
	if err != nil {
		return nil, err
	}
	context.AfterFunc(bridges.ctx, func() {
		daemonBridges.Close()
		backends.close()
	})
	return daemonBridges, nil
}

// Each network's backend, built on first use and kept until the daemon's bridges end.
type urBridgeBackends struct {
	bridges *urBridgeDaemon

	stateLock         sync.Mutex
	networkIdBackends map[sidecar.Id]*urBridgeBackend
	closed            bool
}

// sidecar.DaemonBridgesArgs.Backend: the network's backend, refusing where the daemon runs no bridge for it or
// follows no config for it.
func (self *urBridgeBackends) backend(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar) (sidecar.DaemonBridgeBackend, error) {
	network, err := self.bridges.bridgeNetwork(networkId, running)
	if err != nil {
		return nil, err
	}
	held := func() *urBridgeBackend {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.networkIdBackends[networkId]
	}()
	if held != nil && held.network == network {
		return held, nil
	}
	if urBridgeConfigOf == nil {
		return nil, errUrBridgeUnwired
	}
	config, err := urBridgeConfigOf(ctx, network, running)
	if err != nil {
		return nil, err
	}
	if config == nil || config.Filer == nil {
		return nil, errUrBridgeUnwired
	}
	built := &urBridgeBackend{backends: self, network: network, config: config}
	var replaced *urBridgeBackend
	kept := func() *urBridgeBackend {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil
		}
		if current := self.networkIdBackends[networkId]; current != nil && current.network == network {
			return current
		}
		replaced = self.networkIdBackends[networkId]
		self.networkIdBackends[networkId] = built
		return built
	}()
	if replaced != nil {
		replaced.close()
	}
	if kept == nil {
		return nil, errUrTunClosed
	}
	return kept, nil
}

// Ends every backend's stack.
func (self *urBridgeBackends) close() {
	backends := func() []*urBridgeBackend {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		backends := make([]*urBridgeBackend, 0, len(self.networkIdBackends))
		for _, backend := range self.networkIdBackends {
			backends = append(backends, backend)
		}
		clear(self.networkIdBackends)
		return backends
	}()
	for _, backend := range backends {
		backend.close()
	}
}

// Whether another network this daemon holds a bridge for has the same block (§17.17's shared block).
func (self *urBridgeBackends) sharedBlock(networkId sidecar.Id, block netip.Prefix) bool {
	if !block.IsValid() {
		return false
	}
	others := func() []*urBridgeNetwork {
		self.bridges.stateLock.Lock()
		defer self.bridges.stateLock.Unlock()
		others := []*urBridgeNetwork{}
		for otherId, other := range self.bridges.networks {
			if otherId != networkId {
				others = append(others, other)
			}
		}
		return others
	}()
	for _, other := range others {
		if other.bridge.Status().Block == block {
			return true
		}
	}
	return false
}

// One network's sidecar.DaemonBridgeBackend (the file's comment).
type urBridgeBackend struct {
	backends *urBridgeBackends
	network  *urBridgeNetwork
	config   *urBridgeConfig

	stateLock sync.Mutex
	// the userspace stack, made at the first forward's dial
	stack  *urBridgeStack
	closed bool
}

var _ sidecar.DaemonBridgeBackend = (*urBridgeBackend)(nil)

func (self *urBridgeBackend) SidecarId() sidecar.Id {
	return self.config.SidecarId
}

func (self *urBridgeBackend) List(ctx context.Context) (*sidecar.DaemonBridgeList, error) {
	status := self.network.bridge.Status()
	var rules []*sidecar.BridgeLedgerRule
	if self.config.Rules != nil {
		var err error
		rules, err = self.config.Rules(ctx)
		if err != nil {
			return nil, err
		}
	}
	list := urBridgeListOf(self.network.networkId, self.config.SidecarId, status, rules)
	if self.config.Names != nil {
		list.Names = self.config.Names()
	}
	list.SharedBlock = self.backends.sharedBlock(self.network.networkId, status.Block)
	return list, nil
}

func (self *urBridgeBackend) ResolveSidecar(ctx context.Context, name string) (sidecar.Id, error) {
	if id, err := sidecar.ParseId(name); err == nil {
		return id, nil
	}
	if self.config.Resolve == nil {
		return sidecar.Id{}, fmt.Errorf("%q is not a sidecar's id", name)
	}
	return self.config.Resolve(ctx, name)
}

func (self *urBridgeBackend) Expose(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeRouteRequest) (*sidecar.BridgeFiling, error) {
	return self.config.Filer.Expose(ctx, origin, request)
}

func (self *urBridgeBackend) ExposeMap(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeMapRequest) (*sidecar.BridgeFiling, error) {
	return self.config.Filer.ExposeMap(ctx, origin, request)
}

func (self *urBridgeBackend) Forward(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeForwardRequest) (*sidecar.BridgeFiling, error) {
	return self.config.Filer.Forward(ctx, origin, request)
}

func (self *urBridgeBackend) Close(ctx context.Context, origin *sidecar.BridgeFileOrigin, id []byte, reset bool) (*sidecar.BridgeFiling, error) {
	return self.config.Filer.Close(ctx, origin, id, reset)
}

func (self *urBridgeBackend) SetEgress(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeEgressRequest) (*sidecar.BridgeFiling, error) {
	return self.config.Filer.SetEgress(ctx, origin, request)
}

func (self *urBridgeBackend) SetBlock(ctx context.Context, origin *sidecar.BridgeFileOrigin, request *sidecar.BridgeBlockRequest) (*bridge.BridgeBlock, error) {
	return self.config.Filer.SetBlock(ctx, origin, request)
}

func (self *urBridgeBackend) ForwardRoute(ctx context.Context, request *sidecar.BridgeForwardRequest, grantId []byte) (*sidecar.DaemonBridgeForwardRoute, error) {
	if self.config.ForwardRoute == nil {
		return nil, errUrBridgeUnwired
	}
	return self.config.ForwardRoute(ctx, request, grantId)
}

// Dials over ur tun while it carries this network, whose routes hold the network's addresses, and over the userspace
// stack otherwise, which takes the bridge's receiver (the file's comment).
func (self *urBridgeBackend) DialForward(ctx context.Context, network string, address netip.AddrPort) (net.Conn, error) {
	if tun := self.backends.bridges.tunStatus(); tun != nil && tun.NetworkId == self.network.networkId {
		dialer := &net.Dialer{}
		return dialer.DialContext(ctx, network, address.String())
	}
	stack, err := func() (*urBridgeStack, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil, errUrTunClosed
		}
		if self.stack == nil {
			stack, err := newUrBridgeStack(self.backends.bridges.ctx, self.network.bridge, self.network.links, self.backends.bridges.settings)
			if err != nil {
				return nil, err
			}
			self.stack = stack
		}
		return self.stack, nil
	}()
	if err != nil {
		return nil, err
	}
	stack.attach()
	return stack.dial(ctx, network, address)
}

// Ends the backend's stack.
func (self *urBridgeBackend) close() {
	stack := func() *urBridgeStack {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		stack := self.stack
		self.stack = nil
		return stack
	}()
	if stack != nil {
		stack.close()
	}
}

// What the stack routes through: the bridge's burst and its one receiver.
type urBridgeStackBridge interface {
	RouteBurst(packets [][]byte, send func(client connect.UserNatClient, packets [][]byte))
	SetReceivePacket(receive connect.ReceivePacketFunction)
}

// The userspace stack a forward dials through (the file's comment).
type urBridgeStack struct {
	ctx      context.Context
	cancel   context.CancelFunc
	tun      *connect.Tun
	bridge   urBridgeStackBridge
	links    urTunLinks
	settings *urTunSettings
	done     chan struct{}
}

// A stack over the bridge and its links, reading until ctx ends or close. IPv4 only, as the bridge's block is.
func newUrBridgeStack(ctx context.Context, bridge urBridgeStackBridge, links urTunLinks, settings *urTunSettings) (*urBridgeStack, error) {
	if settings == nil {
		settings = defaultUrTunSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	tunSettings := connect.DefaultTunSettings()
	tunSettings.DisableIpv6 = true
	tun, err := connect.CreateTun(cancelCtx, tunSettings)
	if err != nil {
		cancel()
		return nil, err
	}
	self := &urBridgeStack{
		ctx:      cancelCtx,
		cancel:   cancel,
		tun:      tun,
		bridge:   bridge,
		links:    links,
		settings: settings,
		done:     make(chan struct{}),
	}
	go self.run()
	return self, nil
}

// Takes the bridge's and the links' receiver for the stack.
func (self *urBridgeStack) attach() {
	self.bridge.SetReceivePacket(self.receive)
	self.links.setReceive(self.receive)
}

// Reads the stack's packets until it closes, routing each batch through the bridge.
func (self *urBridgeStack) run() {
	defer close(self.done)
	packets := make([][]byte, max(1, self.settings.ReadBatchCount))
	for {
		n, err := self.tun.ReadBatch(packets)
		if err != nil {
			return
		}
		// takes every packet: each run's send owns its packets as the route it reaches says
		self.bridge.RouteBurst(packets[:n], self.send)
		clear(packets)
	}
}

// Sends one run of a burst on the route the bridge gave it, as ur tun does: a nil route is the default, which a
// forward does not carry, and a packet a route refuses is returned to the pool.
func (self *urBridgeStack) send(client connect.UserNatClient, packets [][]byte) {
	if client == nil {
		for _, packet := range packets {
			connect.MessagePoolReturn(packet)
		}
		return
	}
	source := self.links.sourcePath()
	if batchClient, ok := client.(connect.UserNatBatchClient); ok {
		batchClient.SendPacketBatch(source, protocol.ProvideMode_Network, packets, self.settings.SendTimeout)
		return
	}
	for _, packet := range packets {
		if !client.SendPacket(source, protocol.ProvideMode_Network, packet, self.settings.SendTimeout) {
			connect.MessagePoolReturn(packet)
		}
	}
}

// connect.ReceivePacketFunction for the links, the rejects and the resolver: borrows packet, so the stack gets a copy.
func (self *urBridgeStack) receive(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
	if len(packet) == 0 || self.ctx.Err() != nil {
		return
	}
	self.tun.Write(bytes.Clone(packet))
}

// Dials address on the stack: network is "tcp" or "udp".
func (self *urBridgeStack) dial(ctx context.Context, network string, address netip.AddrPort) (net.Conn, error) {
	return self.tun.DialContext(ctx, network, address.String())
}

// Ends the stack and every conn on it, and waits for its reader.
func (self *urBridgeStack) close() {
	self.cancel()
	self.tun.Close()
	<-self.done
}

// A wire prefix as text.
func urBridgePrefixText(prefix *bridge.BridgeIpv4Prefix) string {
	address := prefix.GetAddress()
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)}), int(min(prefix.GetLength(), 32))).String()
}

// One ledger rule as the listing shows it, by its opaque id.
func urBridgeRuleOf(rule *sidecar.BridgeLedgerRule, sidecarId sidecar.Id) *sidecar.DaemonBridgeRule {
	listed := &sidecar.DaemonBridgeRule{
		RuleId:    hex.EncodeToString(rule.RuleId),
		Kind:      "route",
		Owner:     rule.Owner,
		Own:       rule.Owner == sidecarId,
		State:     "active",
		Standing:  rule.Standing,
		ExpiresMs: rule.Expires,
	}
	if rule.SignedType == bridge.SignedType_SIGNED_BRIDGE_MAP {
		listed.Kind = "map"
	}
	switch {
	case rule.Withdrawn != nil:
		listed.State = "withdrawn"
	case rule.Void:
		listed.State = "void"
	case rule.Pending:
		listed.State = "pending"
	}
	if rule.Route != nil {
		for _, prefix := range rule.Route.GetPrefixes() {
			listed.Prefixes = append(listed.Prefixes, urBridgePrefixText(prefix))
		}
	}
	if rule.Map != nil {
		if rule.Map.GetMatchPrefix() != nil {
			listed.Prefixes = append(listed.Prefixes, urBridgePrefixText(rule.Map.GetMatchPrefix()))
		}
		protocolName := map[uint32]string{1: "icmp", 6: "tcp", 17: "udp"}[rule.Map.GetProtocol()]
		for _, ports := range rule.Map.GetPorts() {
			text := protocolName + ":" + strconv.FormatUint(uint64(ports.GetFirst()), 10)
			if ports.GetFirst() < ports.GetLast() {
				text += "-" + strconv.FormatUint(uint64(ports.GetLast()), 10)
			}
			listed.Ports = append(listed.Ports, text)
		}
		if len(rule.Map.GetPorts()) == 0 && protocolName != "" {
			listed.Ports = append(listed.Ports, protocolName)
		}
	}
	return listed
}

// A network's listing from its device role's status and the ledger's rules: every value BridgeStatus holds that
// `ur bridge` shows, as plain data, and each rule by its opaque id. A rule waiting on a generation's key counts as a
// seal wait (§17.17).
func urBridgeListOf(networkId sidecar.Id, sidecarId sidecar.Id, status device.BridgeStatus, rules []*sidecar.BridgeLedgerRule) *sidecar.DaemonBridgeList {
	list := &sidecar.DaemonBridgeList{
		NetworkId:          networkId,
		State:              status.State.String(),
		PinnedCount:        status.PinnedPairCount,
		UnpinnedCount:      status.UnpinnedPickCount,
		RouteConflictCount: status.RouteConflictCount,
	}
	if status.Block.IsValid() {
		list.Block = status.Block.String()
	}
	if status.PreviousBlock.IsValid() {
		list.PreviousBlock = status.PreviousBlock.String()
	}
	for _, address := range status.Addresses {
		list.Addresses = append(list.Addresses, address.String())
	}
	waits := map[string]int{}
	for _, wait := range status.Waits {
		waits[string(wait.Kind)] += max(wait.Count, 1)
	}
	for _, rule := range rules {
		list.Rules = append(list.Rules, urBridgeRuleOf(rule, sidecarId))
		if rule.Pending && rule.Withdrawn == nil {
			waits["seal"] += 1
		}
	}
	if 0 < len(waits) {
		list.Waits = waits
	}
	for _, alarm := range status.Alarms {
		list.Alarms = append(list.Alarms, string(alarm.Kind))
		if alarm.Kind == device.BridgeAlarmCarvedAddress {
			list.CarvedOverlapCount += 1
		}
	}
	switch status.EgressMode {
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO:
		list.EgressMode = "auto"
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS:
		list.EgressMode = "exits"
	case bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE:
		list.EgressMode = "none"
	}
	return list
}
