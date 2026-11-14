//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's bridge tools (MCP-M4-01; §17.9, §17.11, R-MCP-9, D-MCP-11, D-MCP-12, D-MCP-17, I-7, I-8, I-9, AD2):
// bridge_list at R, bridge_forward and bridge_expose at O, and bridge_close at W, each acting through the daemon's
// bridges (sidecar.DaemonBridges) on the call's network, so a filing is built, approved, signed and recorded as
// `ur bridge` files it: one path, BridgeFiler's (bridge_file.go), whoever asks.
//
//   - bridge_list() is the network's bridge as ur bridge lists it: its block, this host's overlay addresses, the
//     private names, the ledger's rules by opaque id and state, and the forwards this daemon holds. Names and rules
//     are what members' sidecars filed, so the result is a member's data.
//   - bridge_forward(target, port, local_port, protocol, expires) asks a dial grant to one target's port and listens
//     for it on 127.0.0.1, never the LAN: an agent's forward is its own host's alone. It returns the grant's id.
//   - bridge_expose(port, local_port, target, protocol, expires) files a BridgeMap of a port of this host's overlay
//     address, a host's first map filing its own BridgeAddress first; bridge_expose(cidrs) files a BridgeRoute of
//     this host's subnets, 0.0.0.0/0 alone an exit. It returns the rule's id.
//   - bridge_close(id) ends a forward this daemon holds by its forward id, or files a GrantRevoke of a forward's
//     grant or a BridgeWithdraw of one of this host's rules by its id. It narrows reach, so it takes no approval.
//
// forward and expose are outward (§5.4): the filer builds each action with NewCanonicalAction and passes it through
// Sidecar.Authorize under this call's run, which the tool binds here (BridgeFileOrigin.RunId), so a tainted run takes
// only I-9's evidence. With no decision yet the tool answers approval_pending and its approval's id, and the same call
// again, once a person has decided, spends the decision: the gate reserves the use before the filing and answers a
// decided use from its record, so calling again files nothing twice, a re-signed retry keeps its rule id (§17.8's
// SHA-256("urnetwork-sidecar-v1/bridge-rule" || effect_key)), and an approval activates at most its uses rules (AD2).
// A withdrawn rule's id is refused by bridge_close and never returns.
//
// Every filing is this sidecar's own resource: the filer derives the host from its own identity and refuses a
// BridgeAddress for another sidecar_id, a second one for an addressed host, and a GrantRevoke or BridgeWithdraw of
// another's grant or rule (§5.8), and the tools report those statements to McpGuard as the second line. BridgeBlock
// and BridgeEgress have no tool: they are a person's confirmed commands.
//
// Errors are constants and results carry ids, ports and this network's own addresses, never a key (I-7, I-13).

package mcp

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the bridge tools act through: *sidecar.DaemonBridges, or a test's. running is the call's hosted Sidecar, nil
// where the call's network is no Sidecar, as a test's may not be. Safe for concurrent use.
type McpBridges interface {
	// The network's listing and the daemon's forwards for it (ur bridge).
	Status(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar) (*sidecar.DaemonBridgeStatusReply, error)
	// A route of this host's subnets or its exit, or a map of a port of its overlay address.
	Expose(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar, origin *sidecar.BridgeFileOrigin,
		params *sidecar.DaemonBridgeExposeParams) (*sidecar.DaemonBridgeFilingReply, error)
	// A forward's grant and its local listener.
	Forward(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar, origin *sidecar.BridgeFileOrigin,
		params *sidecar.DaemonBridgeForwardParams) (*sidecar.DaemonBridgeFilingReply, error)
	// Ends a forward the daemon holds, or files bridge_close of a rule or a grant.
	CloseId(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar, origin *sidecar.BridgeFileOrigin,
		params *sidecar.DaemonBridgeCloseParams) (*sidecar.DaemonBridgeFilingReply, error)
}

var _ McpBridges = (*sidecar.DaemonBridges)(nil)

// Sets what the bridge tools act through: the daemon's bridges, which `ur bridge` shares. Nil answers unavailable.
func (self *McpServer) SetBridges(bridges McpBridges) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.bridges = bridges
}

// The server's bridges, nil for none.
func (self *McpServer) bridgesNow() McpBridges {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.bridges
}

// The addresses an agent's forward listens on: this host's loopback alone, where `ur bridge forward` takes the
// daemon's --listen (owner decision 84). An identifier of the tool, not a tunable: a tool cannot widen it.
var mcpBridgeForwardListenAddresses = []string{"127.0.0.1"}

// The route that is an exit (§17.7).
const mcpBridgeExitCidr = "0.0.0.0/0"

// The tools' statuses.
const (
	mcpBridgeStatusForwarding      = "forwarding"
	mcpBridgeStatusExposed         = "exposed"
	mcpBridgeStatusClosed          = "closed"
	mcpBridgeStatusForwardClosed   = "forward_closed"
	mcpBridgeStatusApprovalPending = "approval_pending"
)

// The tools' refusals, each constant.
var (
	errMcpBridgeUnavailable = NewMcpError(McpCodeUnavailable,
		"this daemon runs no bridge for this network yet: run ur bridge in your own terminal", false)
	errMcpBridgeArguments = NewMcpError(McpCodeInvalidArguments,
		"bridge_forward takes a target, its port and a local port; bridge_expose takes a port, or cidrs; bridge_close takes a forward's, a rule's or a grant's id; protocol is tcp or udp, and expires is an RFC 3339 time ahead", false)
	errMcpBridgeRefused = NewMcpError(McpCodeRefused,
		"the bridge refused this filing: it is not this sidecar's own resource, it is withdrawn already, or it would change nothing", false)
	errMcpBridgeHeld = NewMcpError(McpCodeRefused,
		"no approval of this could be spent: it was denied, cancelled, spent or expired, or no rule lets this sidecar ask", false)
	errMcpBridgeNoState = NewMcpError(McpCodeUnavailable,
		"the bridge has no verified state of the network to file against yet: try again later", true)
	errMcpBridgeUncertain = NewMcpError(McpCodeFailed,
		"the filing may have landed: call again with the same arguments, which files nothing twice", true)
	errMcpBridgeForwardLimit = NewMcpError(McpCodeFailedPrecondition,
		"this daemon holds its limit of forwards: bridge_close one first", false)
	errMcpBridgeGrantEnded = NewMcpError(McpCodeFailedPrecondition,
		"the forward's grant is not active: it expired, was revoked, or has not landed yet", true)
	errMcpBridgeNoForward = NewMcpError(McpCodeFailedPrecondition, "this daemon holds no such forward", false)
)

// bridge_list takes nothing but the network.
type mcpBridgeListIn struct{}

// One private name.
type mcpBridgeNameOut struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

// One rule of the ledger.
type mcpBridgeRuleOut struct {
	// The rule's id, hex: what bridge_close takes for one of this host's.
	RuleId string `json:"rule_id"`
	// route or map.
	Kind string `json:"kind"`
	// Its advertiser or host, a sidecar id.
	Owner string `json:"owner"`
	// This sidecar filed it.
	Own bool `json:"own"`
	// active, pending, void or withdrawn.
	State    string   `json:"state"`
	Prefixes []string `json:"prefixes,omitempty"`
	Ports    []string `json:"ports,omitempty"`
	// A standing grant covers it, with no approval.
	Standing bool `json:"standing,omitempty"`
	// When a map ends, RFC 3339; empty for none.
	Expires string `json:"expires,omitempty"`
}

// One forward this daemon holds.
type mcpBridgeForwardOut struct {
	// What bridge_close takes to end the listener.
	ForwardId string `json:"forward_id"`
	// The sidecar it dials, and the protocol and port there.
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	// The local port it listens on.
	LocalPort int `json:"local_port"`
	// A host on the LAN can reach the listener.
	LanExposed bool `json:"lan_exposed"`
	// Its grant's id, hex: what bridge_close takes to revoke the grant. Empty under a standing grant.
	GrantId string `json:"grant_id,omitempty"`
	// When its grant ends, RFC 3339; empty for one that does not.
	Expires string `json:"expires,omitempty"`
	// The connections it carries now.
	ConnCount int `json:"conn_count"`
}

// bridge_list's data.
type mcpBridgeListOut struct {
	// pending, legacy, enforcing_document or enforcing_no_document (§17.8).
	State string `json:"state"`
	// The network's block and the one a change replaced, which drains.
	Block         string `json:"block,omitempty"`
	PreviousBlock string `json:"previous_block,omitempty"`
	// This host's overlay addresses.
	Addresses []string               `json:"addresses"`
	Names     []*mcpBridgeNameOut    `json:"names"`
	Rules     []*mcpBridgeRuleOut    `json:"rules"`
	Forwards  []*mcpBridgeForwardOut `json:"forwards"`
	// auto, exits, none, or empty for unspecified.
	EgressMode string `json:"egress_mode,omitempty"`
}

// bridge_forward's arguments.
type mcpBridgeForwardIn struct {
	// The target sidecar: its id, a private name or its overlay address.
	Target string `json:"target"`
	// The port there.
	Port int `json:"port"`
	// The port on 127.0.0.1 the forward listens on.
	LocalPort int `json:"local_port"`
	// tcp or udp; tcp when omitted.
	Protocol string `json:"protocol,omitempty"`
	// When the grant ends, RFC 3339; the requests rule's lifetime when omitted, 1 h by default.
	Expires string `json:"expires,omitempty"`
}

// bridge_expose's arguments: a port, which files a map, or cidrs, which file a route.
type mcpBridgeExposeIn struct {
	// A map: the port of this host's overlay address it answers.
	Port int `json:"port,omitempty"`
	// The port the map dials on this host; port when omitted.
	LocalPort int `json:"local_port,omitempty"`
	// The address the map dials, an IP; 127.0.0.1 when omitted.
	Target string `json:"target,omitempty"`
	// tcp or udp; tcp when omitted.
	Protocol string `json:"protocol,omitempty"`
	// A route: this host's subnets, IPv4 prefixes, or 0.0.0.0/0 alone for its exit.
	Cidrs []string `json:"cidrs,omitempty"`
	// When a map ends, RFC 3339; none when omitted. A route takes none.
	Expires string `json:"expires,omitempty"`
}

// bridge_close's argument: a forward's id, or a rule's or a grant's, hex.
type mcpBridgeCloseIn struct {
	Id string `json:"id"`
}

// What a filing tool answers.
type mcpBridgeFilingOut struct {
	// forwarding, exposed, closed or forward_closed; or approval_pending with approval_id, the same call again
	// spending the decision once a person has made it.
	Status     string `json:"status"`
	ApprovalId string `json:"approval_id,omitempty"`
	// A forward's or a revoked grant's id, hex; empty under a standing grant.
	GrantId string `json:"grant_id,omitempty"`
	// An exposure's or a withdrawn rule's id, hex.
	RuleId string `json:"rule_id,omitempty"`
	// This host's overlay address a map answers on, and whether this call filed it.
	Address      string `json:"address,omitempty"`
	AddressFiled bool   `json:"address_filed,omitempty"`
	// A forward's listener.
	ForwardId string `json:"forward_id,omitempty"`
	LocalPort int    `json:"local_port,omitempty"`
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addBridgeTools(catalog, server.bridgesNow)
	})
}

// The hosted Sidecar a call's network is, nil for one that is none.
func mcpSidecarOf(network McpNetwork) *sidecar.Sidecar {
	switch hosted := network.(type) {
	case *sidecar.Sidecar:
		return hosted
	case *mcpSidecarNetwork:
		return hosted.Sidecar
	}
	return nil
}

// Who a tool's filing files as (§5.8, I-8, I-9): MCP, bound to the call's run, so the gate judges the run's taint and
// a decision binds the run that asked.
func mcpBridgeOrigin(call *McpCall) *sidecar.BridgeFileOrigin {
	runId := call.RunId
	return &sidecar.BridgeFileOrigin{Act: sidecar.SidecarActMcp, RunId: &runId, AgentRisk: sidecar.SidecarRiskNormal}
}

// An own-resource statement the guard hears of: the filer derives each from this sidecar's identity and refuses
// another's (bridge_file.go).
func mcpBridgeOwnStatement(signedType bridge.SignedType) McpTarget {
	return McpTarget{Kind: McpTargetStatement, SignedType: signedType, OwnResource: true}
}

// expires as a time, zero for none; a time not ahead of now is refused.
func mcpBridgeExpires(text string, now time.Time) (time.Time, error) {
	if text == "" {
		return time.Time{}, nil
	}
	expires, err := time.Parse(time.RFC3339, text)
	if err != nil || !now.Before(expires) {
		return time.Time{}, errMcpBridgeArguments
	}
	return expires, nil
}

// ms as RFC 3339 text, "" for none.
func mcpBridgeTimeText(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}

// tcp, udp or "".
func mcpBridgeProtocol(name string) (string, error) {
	switch name {
	case "", "tcp", "udp":
		return name, nil
	}
	return "", errMcpBridgeArguments
}

// A port from 1 to 65535.
func mcpBridgePort(port int) bool {
	return 1 <= port && port <= 65535
}

// Registers the four bridge tools on catalog, acting through what bridges answers per call.
func addBridgeTools(catalog *McpCatalog, bridges func() McpBridges) {
	now := func() time.Time { return catalog.clock.Now() }

	AddTool(catalog, &McpToolSpec[mcpBridgeListIn]{
		Name:        "bridge_list",
		Tier:        McpTierRead,
		Description: "Lists the network's bridge: its block, this host's overlay addresses, private names, the rules by id and state, and the forwards this daemon holds.",
		Access:      func(call *McpCall, in *mcpBridgeListIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpBridgeListIn, result *McpResult) (*mcpBridgeListOut, error) {
		held := bridges()
		if held == nil {
			return nil, errMcpBridgeUnavailable
		}
		reply, err := held.Status(ctx, call.NetworkId, mcpSidecarOf(call.Network))
		if err != nil {
			return nil, mcpBridgeError(err)
		}
		result.Member()
		result.SetSource("bridge:list")
		out := &mcpBridgeListOut{
			Addresses: []string{}, Names: []*mcpBridgeNameOut{}, Rules: []*mcpBridgeRuleOut{}, Forwards: []*mcpBridgeForwardOut{},
		}
		if list := reply.List; list != nil {
			out.State, out.Block, out.PreviousBlock, out.EgressMode = list.State, list.Block, list.PreviousBlock, list.EgressMode
			out.Addresses = append(out.Addresses, list.Addresses...)
			for _, name := range list.Names {
				out.Names = append(out.Names, &mcpBridgeNameOut{Name: name.Name, Address: name.Address})
			}
			for _, rule := range list.Rules {
				out.Rules = append(out.Rules, &mcpBridgeRuleOut{
					RuleId: rule.RuleId, Kind: rule.Kind, Owner: rule.Owner.String(), Own: rule.Own, State: rule.State,
					Prefixes: rule.Prefixes, Ports: rule.Ports, Standing: rule.Standing, Expires: mcpBridgeTimeText(rule.ExpiresMs),
				})
			}
		}
		for _, forward := range reply.Forwards {
			out.Forwards = append(out.Forwards, &mcpBridgeForwardOut{
				ForwardId: forward.ForwardId, Target: forward.Target.String(), Protocol: forward.Protocol, Port: int(forward.Port),
				LocalPort: forward.LocalPort, LanExposed: forward.LanExposed, GrantId: forward.GrantId,
				Expires: mcpBridgeTimeText(forward.ExpiresMs), ConnCount: forward.ConnCount,
			})
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpBridgeForwardIn]{
		Name:        "bridge_forward",
		Tier:        McpTierOutward,
		Description: "Asks a dial grant to one sidecar's port and listens for it on a port of 127.0.0.1; outward, so it may answer approval_pending until a person decides.",
		Access:      func(call *McpCall, in *mcpBridgeForwardIn) ([]McpAccess, error) { return nil, nil },
		Targets: func(call *McpCall, in *mcpBridgeForwardIn) ([]McpTarget, error) {
			return []McpTarget{mcpBridgeOwnStatement(bridge.SignedType_SIGNED_GRANT_ACTIVATE)}, nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpBridgeForwardIn, result *McpResult) (*mcpBridgeFilingOut, error) {
		protocolName, err := mcpBridgeProtocol(in.Protocol)
		if err != nil {
			return nil, err
		}
		if in.Target == "" || !mcpBridgePort(in.Port) || !mcpBridgePort(in.LocalPort) {
			return nil, errMcpBridgeArguments
		}
		at := now()
		expires, err := mcpBridgeExpires(in.Expires, at)
		if err != nil {
			return nil, err
		}
		params := &sidecar.DaemonBridgeForwardParams{
			Target: in.Target, Port: uint32(in.Port), Protocol: protocolName, LocalPort: uint32(in.LocalPort),
			Listen: append([]string{}, mcpBridgeForwardListenAddresses...),
		}
		if !expires.IsZero() {
			// whole seconds, rounded up, so the grant never ends before the time asked
			lifetime := expires.Sub(at)
			seconds := int64((lifetime + time.Second - 1) / time.Second)
			if seconds <= 0 || int64(^uint32(0)) < seconds {
				return nil, errMcpBridgeArguments
			}
			params.LifetimeSeconds = uint32(seconds)
		}
		held := bridges()
		if held == nil {
			return nil, errMcpBridgeUnavailable
		}
		result.SetSource("bridge:forward")
		reply, err := held.Forward(ctx, call.NetworkId, mcpSidecarOf(call.Network), mcpBridgeOrigin(call), params)
		return mcpBridgeFilingResult(reply, err, mcpBridgeStatusForwarding)
	})

	AddTool(catalog, &McpToolSpec[mcpBridgeExposeIn]{
		Name:        "bridge_expose",
		Tier:        McpTierOutward,
		Description: "Exposes a port of this host's overlay address, or this host's subnets as a route, to the network; outward, so it may answer approval_pending until a person decides.",
		Access:      func(call *McpCall, in *mcpBridgeExposeIn) ([]McpAccess, error) { return nil, nil },
		Targets: func(call *McpCall, in *mcpBridgeExposeIn) ([]McpTarget, error) {
			if 0 < in.Port {
				// a host's first map files its own address first (§17.4)
				return []McpTarget{mcpBridgeOwnStatement(bridge.SignedType_SIGNED_BRIDGE_ADDRESS), mcpBridgeOwnStatement(bridge.SignedType_SIGNED_BRIDGE_MAP)}, nil
			}
			return []McpTarget{mcpBridgeOwnStatement(bridge.SignedType_SIGNED_BRIDGE_ROUTE)}, nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpBridgeExposeIn, result *McpResult) (*mcpBridgeFilingOut, error) {
		params := &sidecar.DaemonBridgeExposeParams{}
		switch {
		case in.Port != 0 && len(in.Cidrs) == 0:
			protocolName, err := mcpBridgeProtocol(in.Protocol)
			if err != nil {
				return nil, err
			}
			if !mcpBridgePort(in.Port) || (in.LocalPort != 0 && !mcpBridgePort(in.LocalPort)) {
				return nil, errMcpBridgeArguments
			}
			if in.Target != "" {
				if _, err := netip.ParseAddr(in.Target); err != nil {
					return nil, errMcpBridgeArguments
				}
			}
			expires, err := mcpBridgeExpires(in.Expires, now())
			if err != nil {
				return nil, err
			}
			params.Port, params.Protocol, params.Target, params.TargetPort = uint32(in.Port), protocolName, in.Target, uint32(in.LocalPort)
			if !expires.IsZero() {
				params.ExpiresMs = expires.UnixMilli()
			}
		case in.Port == 0 && 0 < len(in.Cidrs):
			if in.LocalPort != 0 || in.Target != "" || in.Protocol != "" || in.Expires != "" {
				return nil, errMcpBridgeArguments
			}
			if len(in.Cidrs) == 1 && in.Cidrs[0] == mcpBridgeExitCidr {
				params.Exit = true
				break
			}
			for _, cidr := range in.Cidrs {
				prefix, err := netip.ParsePrefix(cidr)
				if err != nil || !prefix.Addr().Is4() || prefix.Bits() == 0 {
					return nil, errMcpBridgeArguments
				}
				params.Prefixes = append(params.Prefixes, prefix.Masked().String())
			}
		default:
			return nil, errMcpBridgeArguments
		}
		held := bridges()
		if held == nil {
			return nil, errMcpBridgeUnavailable
		}
		result.SetSource("bridge:expose")
		reply, err := held.Expose(ctx, call.NetworkId, mcpSidecarOf(call.Network), mcpBridgeOrigin(call), params)
		return mcpBridgeFilingResult(reply, err, mcpBridgeStatusExposed)
	})

	AddTool(catalog, &McpToolSpec[mcpBridgeCloseIn]{
		Name:        "bridge_close",
		Tier:        McpTierWrite,
		Description: "Ends a forward this daemon holds by its forward id, or revokes a forward's grant or withdraws one of this host's rules by its id.",
		Access:      func(call *McpCall, in *mcpBridgeCloseIn) ([]McpAccess, error) { return nil, nil },
		Targets: func(call *McpCall, in *mcpBridgeCloseIn) ([]McpTarget, error) {
			return []McpTarget{mcpBridgeOwnStatement(bridge.SignedType_SIGNED_GRANT_REVOKE), mcpBridgeOwnStatement(bridge.SignedType_SIGNED_BRIDGE_WITHDRAW)}, nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpBridgeCloseIn, result *McpResult) (*mcpBridgeFilingOut, error) {
		if in.Id == "" {
			return nil, errMcpBridgeArguments
		}
		held := bridges()
		if held == nil {
			return nil, errMcpBridgeUnavailable
		}
		result.SetSource("bridge:close")
		// a closed rule drains its flows (§17.8): a reset is a person's choice, at ur bridge close
		reply, err := held.CloseId(ctx, call.NetworkId, mcpSidecarOf(call.Network), mcpBridgeOrigin(call), &sidecar.DaemonBridgeCloseParams{Id: in.Id})
		return mcpBridgeFilingResult(reply, err, mcpBridgeStatusClosed)
	})
}

// A filing's reply as a tool answers it: its ids under done, or the approval it waits on.
func mcpBridgeFilingResult(reply *sidecar.DaemonBridgeFilingReply, err error, done string) (*mcpBridgeFilingOut, error) {
	if err != nil {
		var pending *sidecar.ApprovalPendingError
		if errors.As(err, &pending) {
			return &mcpBridgeFilingOut{Status: mcpBridgeStatusApprovalPending, ApprovalId: pending.ApprovalId.String()}, nil
		}
		return nil, mcpBridgeError(err)
	}
	if reply == nil {
		return nil, errMcpFailed
	}
	if reply.ApprovalPendingId != nil {
		return &mcpBridgeFilingOut{Status: mcpBridgeStatusApprovalPending, ApprovalId: reply.ApprovalPendingId.String()}, nil
	}
	out := &mcpBridgeFilingOut{
		Status: done, GrantId: reply.GrantId, RuleId: reply.RuleId, Address: reply.Address, AddressFiled: reply.AddressFiled,
	}
	if reply.ForwardClosed {
		out.Status = mcpBridgeStatusForwardClosed
	}
	if reply.ApprovalId != nil {
		out.ApprovalId = reply.ApprovalId.String()
	}
	if forward := reply.Forward; forward != nil {
		out.ForwardId, out.LocalPort = forward.ForwardId, forward.LocalPort
		if out.GrantId == "" {
			out.GrantId = forward.GrantId
		}
	}
	return out, nil
}

// A bridge error as a tool answers it: each class by its constant text, never an id, a prefix or a port (I-13).
func mcpBridgeError(err error) error {
	switch {
	case errors.Is(err, sidecar.ErrDaemonBridgeUnwired), errors.Is(err, sidecar.ErrDaemonBridgeClosed):
		return errMcpBridgeUnavailable
	case errors.Is(err, sidecar.ErrDaemonBridgeParams):
		return errMcpBridgeArguments
	case errors.Is(err, sidecar.ErrDaemonBridgeForwardLimit):
		return errMcpBridgeForwardLimit
	case errors.Is(err, sidecar.ErrDaemonBridgeGrantEnded):
		return errMcpBridgeGrantEnded
	case errors.Is(err, sidecar.ErrDaemonBridgeNoForward):
		return errMcpBridgeNoForward
	case errors.Is(err, sidecar.ErrBridgeFileUncertain), errors.Is(err, sidecar.ErrSidecarActPending):
		return errMcpBridgeUncertain
	case errors.Is(err, sidecar.ErrBridgeFileNoState), errors.Is(err, sidecar.ErrApprovalNoState):
		return errMcpBridgeNoState
	case errors.Is(err, sidecar.ErrBridgeFileRefused):
		return errMcpBridgeRefused
	case errors.Is(err, sidecar.ErrApprovalDenied), errors.Is(err, sidecar.ErrApprovalExpired), errors.Is(err, sidecar.ErrApprovalSpent),
		errors.Is(err, sidecar.ErrApprovalCancelled), errors.Is(err, sidecar.ErrApprovalNoLookup), errors.Is(err, sidecar.ErrApprovalRefused),
		errors.Is(err, sidecar.ErrApprovalUnknown), errors.Is(err, sidecar.ErrSidecarGateDenied):
		return errMcpBridgeHeld
	}
	return errMcpFailed
}
