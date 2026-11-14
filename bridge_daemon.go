//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// The daemon's bridge methods (§17.11; BRIDGE-M4-20; R-BRIDGE-6, R-BRIDGE-8, D-BRIDGE-10, D-BRIDGE-13, D-BRIDGE-16,
// I-8, I-13): what `ur bridge` calls, each over one network's DaemonBridgeBackend, whose filings are BridgeFiler's, so
// a filing is built, approved, signed and recorded as MCP's bridge tools file it (bridge_file.go).
//
//	bridge.status   the network's listing (DaemonBridgeList: addresses, private names, rules, pin counts, waits, a
//	                shared block, carved overlaps) and the daemon's forwards for it; bridge_list's data (MCP-M4-01)
//	                and RECORD's worker card read List
//	bridge.expose   a BridgeRoute of this host's subnets or its exit, or a BridgeMap of a port of its overlay address
//	bridge.forward  a requested dial grant to a target's port, and a local listener that dials it over the userspace
//	                stack (bridge_daemon_forward.go)
//	bridge.close    ends a forward the daemon holds, or files bridge_close of a rule or a grant
//	bridge.egress   this subject's egress spec; Confirm
//	bridge.block    the network's block, re-rolled or chosen, an admin's; Confirm
//
// egress and block are DaemonMethod{Confirm: true}: the daemon runs them only from control with the ur's confirmation,
// never from mcp or hook (D-CORE-9), and the filer holds them to a person's confirmation again. A filing that waits
// for a person's decision answers its approval's id, and the caller asks again once the decision lands (§16.6): the
// gate answers a decided use from its record, so asking again files nothing twice.
//
// Replies carry ids, counts and this network's own addresses, never a key (I-13); errors and logs name opaque ids
// alone.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The bridge's control methods.
const (
	DaemonMethodBridgeStatus  = "bridge.status"
	DaemonMethodBridgeExpose  = "bridge.expose"
	DaemonMethodBridgeForward = "bridge.forward"
	DaemonMethodBridgeClose   = "bridge.close"
	DaemonMethodBridgeEgress  = "bridge.egress"
	DaemonMethodBridgeBlock   = "bridge.block"
)

// What bridge.egress takes for a mode, and the prefix of an exit tag (§17.11).
const (
	daemonBridgeEgressAuto      = "auto"
	daemonBridgeEgressNone      = "none"
	daemonBridgeEgressTagPrefix = "tag:"
	daemonBridgeBlockCycle      = "cycle"
	daemonBridgeProtocolTcp     = "tcp"
	daemonBridgeProtocolUdp     = "udp"
)

var (
	// A call's params that do not decode or name what the method cannot take. The text names nothing they held.
	ErrDaemonBridgeParams = errors.New("the bridge call's params are not what the method takes")
	// The daemon runs no bridge for the network: its backend is not built, the closed direction.
	ErrDaemonBridgeUnwired = errors.New("no bridge runs for this network")
	// The daemon holds no forward of the id.
	ErrDaemonBridgeNoForward = errors.New("the daemon holds no such forward")
	// The daemon holds ForwardMaxCount forwards.
	ErrDaemonBridgeForwardLimit = errors.New("the daemon holds its limit of forwards: close one first")
	// The forward's grant is not active: it expired, was revoked, or has not landed.
	ErrDaemonBridgeGrantEnded = errors.New("the forward's grant is not active")
	// The daemon's bridges are closed.
	ErrDaemonBridgeClosed = errors.New("the daemon's bridges are closed")
)

// Tunables of the daemon's bridge methods and forwards.
type DaemonBridgeSettings struct {
	// How many forwards the daemon holds at once: 64. Non-positive holds none.
	ForwardMaxCount int
	// How long a forward's dial over the userspace stack may take: 30 s.
	ForwardDialTimeout time.Duration
	// A TCP splice's buffer, each direction: 32 KiB.
	ForwardSpliceBufferByteCount int
	// The largest datagram a UDP forward relays: 65,535 B, UDP's own.
	ForwardUdpPacketByteCount int
	// How many UDP sources one forward relays at once, each with its own conn to the target: 256. A further source's
	// datagrams are dropped until one idles out.
	ForwardUdpFlowMaxCount int
	// How long a UDP source's conn stays with no datagram either way: 60 s.
	ForwardUdpIdleTimeout time.Duration
}

// The values above.
func DefaultDaemonBridgeSettings() *DaemonBridgeSettings {
	return &DaemonBridgeSettings{
		ForwardMaxCount:              64,
		ForwardDialTimeout:           30 * time.Second,
		ForwardSpliceBufferByteCount: 32 * 1024,
		ForwardUdpPacketByteCount:    65535,
		ForwardUdpFlowMaxCount:       256,
		ForwardUdpIdleTimeout:        60 * time.Second,
	}
}

// A private name the network's state holds, and the overlay address it answers.
type DaemonBridgeName struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// One rule the ledger holds: a route or a map, by its opaque id.
type DaemonBridgeRule struct {
	// The rule id, hex.
	RuleId string `json:"rule_id"`
	// "route" or "map".
	Kind string `json:"kind"`
	// Its advertiser or host.
	Owner Id `json:"owner"`
	// Whether this sidecar filed it.
	Own bool `json:"own,omitempty"`
	// "active", "pending", "void" or "withdrawn".
	State string `json:"state"`
	// A route's prefixes, 0.0.0.0/0 for an exit; a map's address.
	Prefixes []string `json:"prefixes,omitempty"`
	// A map's protocol and ports, as tcp:<first>[-<last>].
	Ports []string `json:"ports,omitempty"`
	// Whether a standing grant covers it, with no approval.
	Standing bool `json:"standing,omitempty"`
	// When a map ends, in ms; 0 for none.
	ExpiresMs int64 `json:"expires_ms,omitempty"`
}

// A network's bridge as `ur bridge` lists it: what device.BridgeStatus holds, mirrored as plain data, and the
// ledger's rules. Nothing secret.
type DaemonBridgeList struct {
	NetworkId Id `json:"network_id"`
	// §17.8's state in force: "pending", "legacy", "enforcing_document" or "enforcing_no_document".
	State string `json:"state"`
	// What the bridge waits on, by kind and count: "state", "delegation", "link", and "seal" for rules waiting on a
	// generation's key (§17.17).
	Waits map[string]int `json:"waits,omitempty"`
	// The network's block and the one a change replaced, which drains.
	Block         string `json:"block,omitempty"`
	PreviousBlock string `json:"previous_block,omitempty"`
	// Another network this daemon hosts holds the same block (§17.17's shared block).
	SharedBlock bool `json:"shared_block,omitempty"`
	// This host's overlay addresses.
	Addresses []string            `json:"addresses,omitempty"`
	Names     []*DaemonBridgeName `json:"names,omitempty"`
	Rules     []*DaemonBridgeRule `json:"rules,omitempty"`
	// The sender's pin table: the pairs it holds, and the picks routed unpinned (§17.5).
	PinnedCount   int    `json:"pinned_count"`
	UnpinnedCount uint64 `json:"unpinned_count"`
	// Local /32s that are a host's overlay address, and subnet routes a local network overlaps (§17.4, §17.7).
	CarvedOverlapCount int `json:"carved_overlap_count,omitempty"`
	RouteConflictCount int `json:"route_conflict_count,omitempty"`
	// Each alarm's class of fault, never a value.
	Alarms []string `json:"alarms,omitempty"`
	// "auto", "exits", "none", or empty for unspecified.
	EgressMode string `json:"egress_mode,omitempty"`
}

// Where a forward dials and how long it may: the backend's reading of the target and the forward's grant.
type DaemonBridgeForwardRoute struct {
	// The target's overlay address.
	Address netip.Addr
	// Whether a dial grant to the target's port is active for this sidecar now.
	Live bool
	// When that grant ends; zero for one that does not.
	ExpiresAt time.Time
}

// One network's bridge as the daemon's methods reach it. BridgeFiler is the filings; the device role's status, the
// ledger and the userspace stack are the rest, which the composition root joins (cli/bridge_forward.go).
type DaemonBridgeBackend interface {
	// The sidecar the backend files as.
	SidecarId() Id
	// The network's listing.
	List(ctx context.Context) (*DaemonBridgeList, error)
	// A target as a person names it, a sidecar id, a private name or an overlay address, as its sidecar.
	ResolveSidecar(ctx context.Context, name string) (Id, error)
	// BridgeFiler's filings.
	Expose(ctx context.Context, origin *BridgeFileOrigin, request *BridgeRouteRequest) (*BridgeFiling, error)
	ExposeMap(ctx context.Context, origin *BridgeFileOrigin, request *BridgeMapRequest) (*BridgeFiling, error)
	Forward(ctx context.Context, origin *BridgeFileOrigin, request *BridgeForwardRequest) (*BridgeFiling, error)
	Close(ctx context.Context, origin *BridgeFileOrigin, id []byte, reset bool) (*BridgeFiling, error)
	SetEgress(ctx context.Context, origin *BridgeFileOrigin, request *BridgeEgressRequest) (*BridgeFiling, error)
	SetBlock(ctx context.Context, origin *BridgeFileOrigin, request *BridgeBlockRequest) (*bridge.BridgeBlock, error)
	// Where a forward to the target's port dials, and whether and until when its grant is active. grantId is the
	// grant the forward's filing answered, nil under a standing grant.
	ForwardRoute(ctx context.Context, request *BridgeForwardRequest, grantId []byte) (*DaemonBridgeForwardRoute, error)
	// Dials address over the userspace stack, a connect.Tun whose packets run through Bridge.RouteBurst: network is
	// "tcp" or "udp".
	DialForward(ctx context.Context, network string, address netip.AddrPort) (net.Conn, error)
}

// The filings are BridgeFiler's own.
var _ interface {
	Expose(ctx context.Context, origin *BridgeFileOrigin, request *BridgeRouteRequest) (*BridgeFiling, error)
	ExposeMap(ctx context.Context, origin *BridgeFileOrigin, request *BridgeMapRequest) (*BridgeFiling, error)
	Forward(ctx context.Context, origin *BridgeFileOrigin, request *BridgeForwardRequest) (*BridgeFiling, error)
	Close(ctx context.Context, origin *BridgeFileOrigin, id []byte, reset bool) (*BridgeFiling, error)
	SetEgress(ctx context.Context, origin *BridgeFileOrigin, request *BridgeEgressRequest) (*BridgeFiling, error)
	SetBlock(ctx context.Context, origin *BridgeFileOrigin, request *BridgeBlockRequest) (*bridge.BridgeBlock, error)
} = (*BridgeFiler)(nil)

// What the daemon's bridges are built over.
type DaemonBridgesArgs struct {
	// The backend of a hosted network, built on demand; an error, or nil, where none runs (ErrDaemonBridgeUnwired).
	Backend func(ctx context.Context, networkId Id, running *Sidecar) (DaemonBridgeBackend, error)
	// Binds a forward's TCP listener: Daemon.LocalListen, so `ur status` lists it LAN-exposed (D-BRIDGE-10).
	Listen func(args *DaemonLocalListenArgs) (*DaemonLocalListener, error)
	// --listen's addresses for a forward that names none: the daemon's. Empty is every interface.
	ListenAddresses []string
	Clock           Clock
	Log             Logger
	Settings        *DaemonBridgeSettings
}

// The daemon's bridge methods and the forwards it holds.
type DaemonBridges struct {
	args     *DaemonBridgesArgs
	settings *DaemonBridgeSettings
	clock    Clock
	log      Logger
	ctx      context.Context
	cancel   context.CancelFunc

	stateLock sync.Mutex
	// each forward by its id
	forwards map[string]*daemonBridgeForward
	closed   bool
}

// The daemon's bridges, living until ctx ends or Close. Backend and Listen are required.
func NewDaemonBridges(ctx context.Context, args *DaemonBridgesArgs) (*DaemonBridges, error) {
	if args == nil || args.Backend == nil || args.Listen == nil {
		return nil, fmt.Errorf("%w: the daemon's bridges need a backend and a listener", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultDaemonBridgeSettings()
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	return &DaemonBridges{
		args:     args,
		settings: settings,
		clock:    clock,
		log:      loggerOrDefault(args.Log),
		ctx:      cancelCtx,
		cancel:   cancel,
		forwards: map[string]*daemonBridgeForward{},
	}, nil
}

// The network's backend, refusing where none runs.
func (self *DaemonBridges) backend(ctx context.Context, networkId Id, running *Sidecar) (DaemonBridgeBackend, error) {
	backend, err := self.args.Backend(ctx, networkId, running)
	if err != nil {
		return nil, err
	}
	if backend == nil {
		return nil, ErrDaemonBridgeUnwired
	}
	return backend, nil
}

// Who a call files as (§5.8, I-8): a person's confirmed control call, MCP, a hook, or an unconfirmed control call. A
// run's binding is MCP's to add on its own path (MCP-M4-01).
func daemonBridgeOrigin(call *DaemonCall) *BridgeFileOrigin {
	origin := &BridgeFileOrigin{Act: SidecarActUnconfirmed}
	switch {
	case call.Hello != nil && call.Hello.Mode == DaemonModeMcp:
		origin.Act = SidecarActMcp
	case call.Hello != nil && call.Hello.Mode == DaemonModeHook:
		origin.Act = SidecarActHook
	case call.Confirmed:
		origin.Act = SidecarActConfirmed
	}
	return origin
}

// bridge.status's params.
type DaemonBridgeStatusParams struct {
	Network string `json:"network,omitempty"`
}

// bridge.status's reply: the network's listing and the daemon's forwards for it.
type DaemonBridgeStatusReply struct {
	List     *DaemonBridgeList            `json:"list"`
	Forwards []*DaemonBridgeForwardStatus `json:"forwards,omitempty"`
}

// bridge.expose's params: subnets or an exit, which file a route, or a port, which files a map.
type DaemonBridgeExposeParams struct {
	Network string `json:"network,omitempty"`
	// A route's subnets, each an IPv4 prefix.
	Prefixes []string `json:"prefixes,omitempty"`
	// An exit route in place of subnets.
	Exit bool `json:"exit,omitempty"`
	// Remap the one prefix into the block's upper half (§17.7).
	Remap bool `json:"remap,omitempty"`
	// A map's port of this host's overlay address; 0 for a route.
	Port uint32 `json:"port,omitempty"`
	// "tcp" or "udp"; empty is tcp.
	Protocol string `json:"protocol,omitempty"`
	// Where a map dials: an IP, empty for 127.0.0.1, and a port, 0 for the port matched.
	Target     string `json:"target,omitempty"`
	TargetPort uint32 `json:"target_port,omitempty"`
}

// What a filing answers: the ids it filed, or the approval it waits on.
type DaemonBridgeFilingReply struct {
	// The decision the filing waits for: `ur approve <id>` on an approval-capable device, then the call again.
	ApprovalPendingId *Id `json:"approval_pending_id,omitempty"`
	// An exposure's or a closed rule's id, hex.
	RuleId string `json:"rule_id,omitempty"`
	// A forward's or a revoked grant's id, hex.
	GrantId string `json:"grant_id,omitempty"`
	// The decision a filing spent under; nil under a standing grant.
	ApprovalId *Id `json:"approval_id,omitempty"`
	// This host's overlay address a map answers on, and whether this call filed it.
	Address      string `json:"address,omitempty"`
	AddressFiled bool   `json:"address_filed,omitempty"`
	// bridge.forward's listener.
	Forward *DaemonBridgeForwardStatus `json:"forward,omitempty"`
	// bridge.close ended a forward the daemon held.
	ForwardClosed bool `json:"forward_closed,omitempty"`
	// bridge.block's block in force and the one draining.
	Block         string `json:"block,omitempty"`
	PreviousBlock string `json:"previous_block,omitempty"`
}

// bridge.forward's params (§17.11's forward client:port[:local ip]:local port).
type DaemonBridgeForwardParams struct {
	Network string `json:"network,omitempty"`
	// The target as the person named it.
	Target string `json:"target"`
	Port   uint32 `json:"port"`
	// "tcp" or "udp"; empty is tcp.
	Protocol string `json:"protocol,omitempty"`
	// The local port, 0 leaving it to the OS, and the addresses the listener binds: empty is the daemon's --listen,
	// else every interface (owner decision 84).
	LocalPort uint32   `json:"local_port,omitempty"`
	Listen    []string `json:"listen,omitempty"`
	// The grant's lifetime in seconds; 0 takes the requests rule's.
	LifetimeSeconds uint32 `json:"lifetime_seconds,omitempty"`
}

// bridge.close's params: a forward's id, or a rule's or a grant's, hex.
type DaemonBridgeCloseParams struct {
	Network string `json:"network,omitempty"`
	Id      string `json:"id"`
	// Reset the flows a closed rule carries in place of draining them.
	Reset bool `json:"reset,omitempty"`
}

// bridge.egress's params: auto, none, exits by sidecar, or an exit tag as tag:<id>.
type DaemonBridgeEgressParams struct {
	Network string   `json:"network,omitempty"`
	Mode    string   `json:"mode,omitempty"`
	Exits   []string `json:"exits,omitempty"`
}

// bridge.block's params: "cycle", or a /16.
type DaemonBridgeBlockParams struct {
	Network string `json:"network,omitempty"`
	Block   string `json:"block"`
}

// The bridge's control methods, which ur daemon registers.
func (self *DaemonBridges) Methods() []*DaemonMethod {
	return []*DaemonMethod{
		{
			Name:    DaemonMethodBridgeStatus,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeStatusParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				return self.Status(ctx, call.NetworkId, call.Sidecar)
			},
		},
		{
			Name:    DaemonMethodBridgeExpose,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeExposeParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				return self.Expose(ctx, call.NetworkId, call.Sidecar, daemonBridgeOrigin(call), params)
			},
		},
		{
			Name:    DaemonMethodBridgeForward,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeForwardParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				return self.Forward(ctx, call.NetworkId, call.Sidecar, daemonBridgeOrigin(call), params)
			},
		},
		{
			Name:    DaemonMethodBridgeClose,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeCloseParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				return self.CloseId(ctx, call.NetworkId, call.Sidecar, daemonBridgeOrigin(call), params)
			},
		},
		{
			Name:    DaemonMethodBridgeEgress,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeEgressParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				return self.Egress(ctx, call.NetworkId, call.Sidecar, daemonBridgeOrigin(call), params)
			},
		},
		{
			Name:    DaemonMethodBridgeBlock,
			Network: true,
			Confirm: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonBridgeBlockParams{}
				if err := decodeDaemonBridgeParams(call, params); err != nil {
					return nil, err
				}
				return self.Block(ctx, call.NetworkId, call.Sidecar, daemonBridgeOrigin(call), params)
			},
		},
	}
}

// A call's params into params, refusing a field it does not know; none is an empty object.
func decodeDaemonBridgeParams(call *DaemonCall, params any) error {
	if err := decodeDaemonSocketParams(call, params); err != nil {
		return ErrDaemonBridgeParams
	}
	return nil
}

// A filing's answer as a reply: its ids, or the approval it waits on. Any other error is the caller's.
func daemonBridgeFilingReply(filing *BridgeFiling, err error) (*DaemonBridgeFilingReply, error) {
	if err != nil {
		var pending *ApprovalPendingError
		if errors.As(err, &pending) {
			approvalId := pending.ApprovalId
			return &DaemonBridgeFilingReply{ApprovalPendingId: &approvalId}, nil
		}
		return nil, err
	}
	reply := &DaemonBridgeFilingReply{}
	if filing == nil {
		return reply, nil
	}
	reply.RuleId = hex.EncodeToString(filing.RuleId)
	reply.GrantId = hex.EncodeToString(filing.GrantId)
	if filing.ApprovalId != (Id{}) {
		approvalId := filing.ApprovalId
		reply.ApprovalId = &approvalId
	}
	if filing.Address.IsValid() {
		reply.Address = filing.Address.String()
		reply.AddressFiled = filing.AddressFiled
	}
	return reply, nil
}

// "tcp", "udp" or empty as the IP protocol number.
func daemonBridgeProtocol(name string) (uint32, error) {
	switch name {
	case "", daemonBridgeProtocolTcp:
		return bridgeProtocolTcp, nil
	case daemonBridgeProtocolUdp:
		return bridgeProtocolUdp, nil
	}
	return 0, fmt.Errorf("%w: a protocol is tcp or udp", ErrDaemonBridgeParams)
}

// The network's listing, with the daemon's forwards for it. What bridge_list and RECORD's worker card read.
func (self *DaemonBridges) Status(ctx context.Context, networkId Id, running *Sidecar) (*DaemonBridgeStatusReply, error) {
	backend, err := self.backend(ctx, networkId, running)
	if err != nil {
		return nil, err
	}
	list, err := backend.List(ctx)
	if err != nil {
		return nil, err
	}
	return &DaemonBridgeStatusReply{List: list, Forwards: self.Forwards(networkId)}, nil
}

// The daemon's forwards for a network, by local port then id.
func (self *DaemonBridges) Forwards(networkId Id) []*DaemonBridgeForwardStatus {
	forwards := func() []*daemonBridgeForward {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		forwards := []*daemonBridgeForward{}
		for _, forward := range self.forwards {
			if forward.networkId == networkId {
				forwards = append(forwards, forward)
			}
		}
		return forwards
	}()
	statuses := make([]*DaemonBridgeForwardStatus, 0, len(forwards))
	for _, forward := range forwards {
		statuses = append(statuses, forward.status())
	}
	slices.SortFunc(statuses, func(a *DaemonBridgeForwardStatus, b *DaemonBridgeForwardStatus) int {
		if a.LocalPort != b.LocalPort {
			return a.LocalPort - b.LocalPort
		}
		return strings.Compare(a.ForwardId, b.ForwardId)
	})
	return statuses
}

// Files a route of this host's subnets or its exit, or a map of a port of its overlay address.
func (self *DaemonBridges) Expose(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin, params *DaemonBridgeExposeParams) (*DaemonBridgeFilingReply, error) {
	backend, err := self.backend(ctx, networkId, running)
	if err != nil {
		return nil, err
	}
	if 0 < params.Port {
		if 0 < len(params.Prefixes) || params.Exit || params.Remap {
			return nil, fmt.Errorf("%w: an exposure is a port or subnets, not both", ErrDaemonBridgeParams)
		}
		protocolNumber, err := daemonBridgeProtocol(params.Protocol)
		if err != nil {
			return nil, err
		}
		request := &BridgeMapRequest{Protocol: protocolNumber, FirstPort: params.Port, TargetPort: params.TargetPort}
		if params.Target != "" {
			target, err := netip.ParseAddr(params.Target)
			if err != nil {
				return nil, fmt.Errorf("%w: a map dials an ip", ErrDaemonBridgeParams)
			}
			request.Target = target
		}
		return daemonBridgeFilingReply(backend.ExposeMap(ctx, origin, request))
	}
	if params.Target != "" || 0 < params.TargetPort || params.Protocol != "" {
		return nil, fmt.Errorf("%w: a route takes no port", ErrDaemonBridgeParams)
	}
	request := &BridgeRouteRequest{Exit: params.Exit, Remap: params.Remap}
	for _, text := range params.Prefixes {
		prefix, err := netip.ParsePrefix(text)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%w: a subnet is an ipv4 prefix", ErrDaemonBridgeParams)
		}
		request.Prefixes = append(request.Prefixes, prefix.Masked())
	}
	if params.Exit == (0 < len(request.Prefixes)) {
		return nil, fmt.Errorf("%w: an exposure names subnets, or an exit", ErrDaemonBridgeParams)
	}
	return daemonBridgeFilingReply(backend.Expose(ctx, origin, request))
}

// Files this subject's egress spec. The daemon runs it only for a person's confirmed control call.
func (self *DaemonBridges) Egress(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin, params *DaemonBridgeEgressParams) (*DaemonBridgeFilingReply, error) {
	if origin == nil || origin.Act != SidecarActConfirmed {
		return nil, fmt.Errorf("%w: an egress change takes a person's confirmation", ErrBridgeFileRefused)
	}
	backend, err := self.backend(ctx, networkId, running)
	if err != nil {
		return nil, err
	}
	request := &BridgeEgressRequest{Subject: backend.SidecarId()}
	switch {
	case params.Mode == daemonBridgeEgressAuto && len(params.Exits) == 0:
		request.Mode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO
	case params.Mode == daemonBridgeEgressNone && len(params.Exits) == 0:
		request.Mode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE
	case strings.HasPrefix(params.Mode, daemonBridgeEgressTagPrefix) && len(params.Exits) == 0:
		tagId, err := ParseId(strings.TrimPrefix(params.Mode, daemonBridgeEgressTagPrefix))
		if err != nil {
			return nil, fmt.Errorf("%w: an exit tag is tag:<id>", ErrDaemonBridgeParams)
		}
		request.Mode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
		request.ExitTagId = tagId
	case params.Mode == "" && 0 < len(params.Exits):
		request.Mode = bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS
		for _, name := range params.Exits {
			exitId, err := backend.ResolveSidecar(ctx, name)
			if err != nil {
				return nil, err
			}
			request.ExitSidecarIds = append(request.ExitSidecarIds, exitId)
		}
	default:
		return nil, fmt.Errorf("%w: an egress spec is auto, none, exits or tag:<id>", ErrDaemonBridgeParams)
	}
	return daemonBridgeFilingReply(backend.SetEgress(ctx, origin, request))
}

// Writes the network's block, re-rolled or chosen. The daemon runs it only for a person's confirmed control call.
func (self *DaemonBridges) Block(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin, params *DaemonBridgeBlockParams) (*DaemonBridgeFilingReply, error) {
	if origin == nil || origin.Act != SidecarActConfirmed {
		return nil, fmt.Errorf("%w: a block change takes a person's confirmation", ErrBridgeFileRefused)
	}
	backend, err := self.backend(ctx, networkId, running)
	if err != nil {
		return nil, err
	}
	request := &BridgeBlockRequest{}
	if params.Block == daemonBridgeBlockCycle {
		request.Cycle = true
	} else {
		prefix, err := netip.ParsePrefix(params.Block)
		if err != nil || !prefix.Addr().Is4() {
			return nil, fmt.Errorf("%w: a block is cycle or an ipv4 /16", ErrDaemonBridgeParams)
		}
		request.Prefix = prefix.Masked()
	}
	block, err := backend.SetBlock(ctx, origin, request)
	if err != nil {
		reply, replyErr := daemonBridgeFilingReply(nil, err)
		return reply, replyErr
	}
	reply := &DaemonBridgeFilingReply{}
	if prefix, ok := daemonBridgePrefixText(block.GetIpv4Prefix()); ok {
		reply.Block = prefix
	}
	if prefix, ok := daemonBridgePrefixText(block.GetPreviousPrefix()); ok {
		reply.PreviousBlock = prefix
	}
	return reply, nil
}

// A wire prefix as text, false for none.
func daemonBridgePrefixText(prefix *bridge.BridgeIpv4Prefix) (string, bool) {
	if prefix == nil || 32 < prefix.GetLength() {
		return "", false
	}
	return netip.PrefixFrom(bridgeAddressOf(prefix.GetAddress()), int(prefix.GetLength())).String(), true
}

// Ends a forward the daemon holds by its id, or files bridge_close of a rule or a grant, by its hex id. A forward's
// grant stays: closing its listener narrows nothing another forward may hold, and `ur bridge close <grant id>` revokes
// it.
func (self *DaemonBridges) CloseId(ctx context.Context, networkId Id, running *Sidecar, origin *BridgeFileOrigin, params *DaemonBridgeCloseParams) (*DaemonBridgeFilingReply, error) {
	forward := func() *daemonBridgeForward {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		forward := self.forwards[params.Id]
		if forward == nil || forward.networkId != networkId {
			return nil
		}
		return forward
	}()
	if forward != nil {
		forward.close(nil)
		return &DaemonBridgeFilingReply{ForwardClosed: true}, nil
	}
	id, err := hex.DecodeString(params.Id)
	if err != nil || len(id) == 0 {
		return nil, fmt.Errorf("%w: an id is a forward's, a rule's or a grant's", ErrDaemonBridgeParams)
	}
	backend, err := self.backend(ctx, networkId, running)
	if err != nil {
		return nil, err
	}
	reply, err := daemonBridgeFilingReply(backend.Close(ctx, origin, id, params.Reset))
	if err != nil {
		return nil, err
	}
	// a revoked grant ends the forwards it admitted at once, ahead of the log's own word
	self.GrantsChanged(networkId)
	return reply, nil
}

// Rereads every forward's grant for the network, closing each whose grant is no longer active: what the composition
// root calls when the network's config moves, so a GrantRevoke closes a forward's listener.
func (self *DaemonBridges) GrantsChanged(networkId Id) {
	forwards := func() []*daemonBridgeForward {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		forwards := []*daemonBridgeForward{}
		for _, forward := range self.forwards {
			if forward.networkId == networkId {
				forwards = append(forwards, forward)
			}
		}
		return forwards
	}()
	for _, forward := range forwards {
		forward.recheck(self.ctx)
	}
}

// Whether a forward is held, which keeps the daemon up as a socket forward does (§5.8).
func (self *DaemonBridges) Active() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return 0 < len(self.forwards)
}

// Ends every forward, with the daemon.
func (self *DaemonBridges) Close() {
	forwards := func() []*daemonBridgeForward {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		forwards := make([]*daemonBridgeForward, 0, len(self.forwards))
		for _, forward := range self.forwards {
			forwards = append(forwards, forward)
		}
		return forwards
	}()
	for _, forward := range forwards {
		forward.close(ErrDaemonBridgeClosed)
	}
	self.cancel()
}
