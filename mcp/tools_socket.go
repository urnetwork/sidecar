//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's socket tools (SOCK-M5-14; §9.9, D-SOCK-8, D-MCP-17, I-7, I-8): socket_list and socket_status at R,
// socket_listen at O, or W under a covering grant, and socket_unlisten at W, each acting through the daemon's sockets
// (sidecar.DaemonSockets) on the call's network, which keep a listen until it is unlistened, as `ur socket` does.
//
//   - socket_list() lists the network's names as ur socket ls does: each seal opened on this device, one that does not
//     open dropped and counted, never shown raw (D-SOCK-13), each marked when this daemon listens on it. share/ names
//     are ur share's and stay out, since no tool shares. The names are what members' sidecars registered, so the result
//     is a member's data.
//   - socket_status(name) is the daemon's listen on name: whether it serves, drains, how many streams are in flight,
//     and the local port.
//   - socket_listen(name, local_port) listens an application name, forwarding each admitted stream to
//     127.0.0.1:<local_port>, serving false while that port refuses. Under a covering grant, §8's local allow of listen
//     on sock:<name> for this sidecar, it runs as W: rate-limited and recorded, its grant_id in the result. With none it
//     is outward, §5.4's gate with a CanonicalAction of kind listen naming the socket by its grant_dst alone, its token
//     path under the network's current K_sock (QD-772), and beside it the name and the local port as the request's
//     socket_name and local_port (QD-740), which the approver renders and the decision binds: the tool listens on the
//     name and the port it asked for and no other. The action is grant-backed as Sidecar.Listen's is
//     (sidecar.SocketListenGrantAction): its grant's fields come from the requests rule that takes it, on the grant
//     filer over the engine the gate reads its standing grants from, its effect the grant component's, which a
//     spendable decision runs into the GrantActivate the approval fixes; each action is kept as its request was filed
//     until its expiry, so the listen asked again after a person approves spends the decision rather than filing
//     anew; and a listen no requests rule takes names no rule, passing on a standing grant alone and refused with
//     nothing filed where none covers it. The use is done only once this device's engine holds the grant it
//     activated, waited on in the network's config, so the listen registers on a grant the log holds where the
//     sockets service reads it rather than being refused by the service. A use that came to not_done refuses the
//     listen and an uncertain one, its grant not yet in the engine among them, answers unavailable, which the same
//     listen asked again completes: the gate then passes it under the grant it activated, and the result names that
//     grant as it names one a use activated. A network whose K_sock this daemon does not hold yet
//     takes no outward listen, as its sockets would register none. tls/ is tls_publish's, smtp/ a receiver's, share/
//     ur share's and ur/ the platform's: each is refused here.
//   - socket_unlisten(name) ends the daemon's listen on name at once (§9.9's Close); streams accepted stay.
//
// No result holds a key, a seal, a token path or a credential (I-7), and the framework's matcher holds every result to
// that. The tools reach the daemon's sockets through McpSockets, which a test fakes.

package mcp

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What the socket tools act through: *sidecar.DaemonSockets, or a test's. Safe for concurrent use.
type McpSockets interface {
	// The network's names, unsealed on this device (ur socket ls).
	ListNames(ctx context.Context, networkId sidecar.Id) (*sidecar.DaemonSocketListReply, error)
	// The daemon's listen on name, false for none.
	Status(networkId sidecar.Id, name string) (*sidecar.DaemonSocketStatus, bool)
	// A listen on address forwarding to target (ur socket listen).
	Listen(ctx context.Context, networkId sidecar.Id, address string, target string) (*sidecar.DaemonSocketListenReply, error)
	// Ends the listen on name, false when there was none.
	Unlisten(networkId sidecar.Id, name string) bool
}

// The daemon's sockets, as the socket tools reach them through the server's McpDaemon.
func (self *daemonMcpDaemon) Sockets() McpSockets {
	return self.daemon.Sockets()
}

// The sockets of server's daemon, nil when it holds none, as a test's fake daemon may not.
func mcpSocketsOf(server *McpServer) McpSockets {
	holder, ok := server.daemon.(interface{ Sockets() McpSockets })
	if !ok {
		return nil
	}
	return holder.Sockets()
}

// The tools' refusals, each constant.
var (
	errMcpSocketName = NewMcpError(McpCodeInvalidArguments,
		"socket_listen, socket_status and socket_unlisten take an application socket name: tls/ is tls_publish's, and smtp/, share/ and ur/ names are not an agent's", false)
	errMcpSocketPort        = NewMcpError(McpCodeInvalidArguments, "local_port is a port from 1 to 65535", false)
	errMcpSocketUnavailable = NewMcpError(McpCodeUnavailable, "this daemon holds no sockets for tools: run ur status in your own terminal", false)
	errMcpSocketHeld        = NewMcpError(McpCodeRefused,
		"no grant covers this listen, and no approval of it could be spent: a person may grant this sidecar listen on the name", false)
	errMcpSocketTaken = NewMcpError(McpCodeFailedPrecondition, "this daemon already listens on that name: socket_unlisten it first", false)
)

// socket_list takes nothing but the network.
type mcpSocketListIn struct{}

// One name of the listing.
type mcpSocketNameOut struct {
	Name string `json:"name"`
	// This daemon listens on it.
	Listening bool `json:"listening"`
}

// socket_list's data.
type mcpSocketListOut struct {
	Names []*mcpSocketNameOut `json:"names"`
	// Seals this device could not open, dropped and never shown.
	DroppedCount int `json:"dropped_count"`
	// False when the listing stopped short of its last page.
	Complete bool `json:"complete"`
}

// socket_status, socket_unlisten: the name.
type mcpSocketNameIn struct {
	Name string `json:"name"`
}

// socket_status's data.
type mcpSocketStatusOut struct {
	Name string `json:"name"`
	// This daemon listens on it.
	Listening bool `json:"listening"`
	// It takes tickets: its local port answered the last dial.
	Serving bool `json:"serving"`
	// A drain has begun.
	Draining bool `json:"draining"`
	Inflight int  `json:"inflight"`
	// The local port it forwards to, 0 when not listening.
	LocalPort int `json:"local_port"`
}

// socket_listen's arguments.
type mcpSocketListenIn struct {
	Name      string `json:"name"`
	LocalPort int    `json:"local_port"`
}

// socket_listen's data.
type mcpSocketListenOut struct {
	// listening, or approval_pending with approval_id.
	Status string `json:"status"`
	// The covering grant's id, hex, when one let the listen run without an approval, or the grant an approval of it
	// activated.
	GrantId    string `json:"grant_id,omitempty"`
	ApprovalId string `json:"approval_id,omitempty"`
	// It takes tickets now: its local port answered.
	Serving bool `json:"serving"`
}

// socket_unlisten's data: unlistened, or not_listening when there was nothing to end.
type mcpSocketUnlistenOut struct {
	Status string `json:"status"`
}

// The application name text names, canonical, or errMcpSocketName.
func mcpApplicationSocketName(text string) (string, error) {
	name, namespace, err := sidecar.ParseSocketName(text)
	if err != nil || namespace != sidecar.SocketNamespaceApplication {
		return "", errMcpSocketName
	}
	return name, nil
}

// The local port of a forward's target, host:port, 0 when it reads as none.
func mcpSocketTargetPort(target string) int {
	index := strings.LastIndexByte(target, ':')
	if index < 0 {
		return 0
	}
	port, err := strconv.Atoi(target[index+1:])
	if err != nil {
		return 0
	}
	return port
}

// The §5.4 action an uncovered socket_listen on name, forwarding to localPort, goes through Authorize as, with its
// effect: kind listen naming the socket by grantDst alone (QD-772), grant-backed (the file header). The tool sets the
// request's detail beside it. A test replaces it.
type mcpSocketListenActionFunction func(ctx context.Context, call *McpCall, name string, localPort int, grantDst string) (*sidecar.SidecarAction, error)

// What an outward socket_listen builds its grant on: a grant filer over the engine the network's gate reads its
// standing grants from, nil while none stands.
type mcpSocketGrants interface {
	socketListenGrants() *sidecar.AclGrantFiler
}

// See mcpSocketGrants: over the hosted Sidecar and the engine its standing follower installs states in, or the engine
// the network was built on (McpNetworkOf).
func (self *mcpSidecarNetwork) socketListenGrants() *sidecar.AclGrantFiler {
	engine, _ := self.policy()
	if engine == nil {
		return nil
	}
	return sidecar.NewAclGrantFiler(self.Sidecar, engine)
}

// What an outward socket_listen waits on for the grant its approval activates to reach this device's engine before it
// registers (sidecar.SocketListenGrantArgs.Config): the network's verified config, nil while none stands, so a fresh
// grant leaves the use uncertain.
type mcpSocketGrantConfig interface {
	socketListenConfig() sidecar.AclGrantConfig
}

// See mcpSocketGrantConfig: the client whose follower installs states in the engine socketListenGrants builds on, or
// the client the network was built with.
func (self *mcpSidecarNetwork) socketListenConfig() sidecar.AclGrantConfig {
	_, client := self.policy()
	if client == nil {
		return nil
	}
	return client
}

// What an outward socket_listen's action is kept by (sidecar.GrantActionKeeper): its network, and the name and the
// local port its request binds beside it.
type mcpSocketListenKey struct {
	networkId sidecar.Id
	name      string
	localPort int
}

// The production action (the file header): sidecar.SocketListenGrantAction on the network's grant filer for its
// sidecar, each action kept until its expiry by one keeper for the server's life, its grant waited on in the network's
// config, then NewSidecarAction bound to the call's run and its session's agent. now reads the time a grant's expiry is
// measured from. sidecar.ErrSocketUnavailable where the network stands no engine or holds no identity yet, and
// sidecar.ErrAclGrantFile where no grant could cover the listen.
func newMcpSocketListenAction(now func() time.Time) mcpSocketListenActionFunction {
	keeper := sidecar.NewGrantActionKeeper[mcpSocketListenKey]()
	return func(ctx context.Context, call *McpCall, name string, localPort int, grantDst string) (*sidecar.SidecarAction, error) {
		var grants *sidecar.AclGrantFiler
		if holder, ok := call.Network.(mcpSocketGrants); ok {
			grants = holder.socketListenGrants()
		}
		var config sidecar.AclGrantConfig
		if holder, ok := call.Network.(mcpSocketGrantConfig); ok {
			config = holder.socketListenConfig()
		}
		var identity *sidecar.SidecarIdentity
		if network, ok := mcpToolNetworkOf(call); ok {
			identity = network.Identity()
		}
		if grants == nil || identity == nil {
			return nil, sidecar.ErrSocketUnavailable
		}
		runId := call.RunId
		agentId := mcpCallAgentId(call)
		stored, effect, err := sidecar.SocketListenGrantAction(ctx, &sidecar.SocketListenGrantArgs{
			Grants:   grants,
			Subject:  identity.SidecarId,
			GrantDst: grantDst,
			Detail:   mcpSocketListenDetail(name, localPort),
			RunId:    &runId,
			AgentId:  agentId,
			Config:   config,
		}, keeper, mcpSocketListenKey{networkId: call.NetworkId, name: name, localPort: localPort}, now())
		if err != nil {
			return nil, err
		}
		action, err := sidecar.NewSidecarAction(stored, sidecar.SidecarRiskNormal, sidecar.SidecarRiskNormal, &runId, agentId)
		if err != nil {
			return nil, err
		}
		action.Effect = effect
		return action, nil
	}
}

// The request's detail an outward listen on name forwarding to localPort binds (QD-740, QD-772).
func mcpSocketListenDetail(name string, localPort int) *sidecar.SidecarActionDetail {
	return &sidecar.SidecarActionDetail{SocketName: name, LocalPort: uint32(localPort)}
}

// What an outward socket_listen passes: the network's §5.4 gate, *sidecar.Sidecar's Authorize.
type mcpAuthorizer interface {
	Authorize(ctx context.Context, action *sidecar.SidecarAction, decision *bridge.Signed) error
}

// What an outward socket_listen blinds its name with: the network's K_sock ring, *sidecar.Sidecar's SocketKeyRing,
// nil while the daemon holds none.
type mcpSocketKeys interface {
	SocketKeyRing() *sidecar.SocketKeyRing
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addSocketTools(catalog, func() McpSockets { return mcpSocketsOf(server) }, newMcpSocketListenAction(server.clock.Now))
	})
}

// Registers the four socket tools on catalog, acting through what sockets answers per call and building an uncovered
// listen's action with listenAction.
func addSocketTools(catalog *McpCatalog, sockets func() McpSockets, listenAction mcpSocketListenActionFunction) {
	none := func(call *McpCall, in *mcpSocketNameIn) ([]McpAccess, error) { return nil, nil }

	AddTool(catalog, &McpToolSpec[mcpSocketListIn]{
		Name:        "socket_list",
		Tier:        McpTierRead,
		Description: "Lists the network's socket names, unsealed on this device, each marked when this daemon listens on it.",
		Access:      func(call *McpCall, in *mcpSocketListIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpSocketListIn, result *McpResult) (*mcpSocketListOut, error) {
		held := sockets()
		if held == nil {
			return nil, errMcpSocketUnavailable
		}
		reply, err := held.ListNames(ctx, call.NetworkId)
		if err != nil {
			return nil, mcpSocketError(err)
		}
		result.Member()
		result.SetSource("sockets:list")
		out := &mcpSocketListOut{Names: []*mcpSocketNameOut{}, DroppedCount: reply.DroppedCount, Complete: reply.Complete}
		for _, name := range reply.Names {
			if _, namespace, err := sidecar.ParseSocketName(name.Name); err != nil || namespace == sidecar.SocketNamespaceShare {
				continue
			}
			out.Names = append(out.Names, &mcpSocketNameOut{Name: name.Name, Listening: name.Local})
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpSocketNameIn]{
		Name:        "socket_status",
		Tier:        McpTierRead,
		Description: "Reports this daemon's listen on an application socket name: serving, draining, streams in flight and its local port.",
		Access:      none,
	}, func(ctx context.Context, call *McpCall, in *mcpSocketNameIn, result *McpResult) (*mcpSocketStatusOut, error) {
		name, err := mcpApplicationSocketName(in.Name)
		if err != nil {
			return nil, err
		}
		held := sockets()
		if held == nil {
			return nil, errMcpSocketUnavailable
		}
		result.SetSource("sockets:status")
		status, ok := held.Status(call.NetworkId, name)
		if !ok {
			return &mcpSocketStatusOut{Name: name}, nil
		}
		return &mcpSocketStatusOut{
			Name:      name,
			Listening: true,
			Serving:   status.Serving,
			Draining:  status.Draining,
			Inflight:  status.Inflight,
			LocalPort: mcpSocketTargetPort(status.Target),
		}, nil
	})

	AddTool(catalog, &McpToolSpec[mcpSocketListenIn]{
		Name:        "socket_listen",
		Tier:        McpTierOutward,
		Description: "Listens on an application socket name in this network, forwarding each stream to a port on 127.0.0.1; outward unless a grant covers it.",
		Access:      func(call *McpCall, in *mcpSocketListenIn) ([]McpAccess, error) { return nil, nil },
		Covering: func(call *McpCall, in *mcpSocketListenIn) (*McpAccess, error) {
			name, err := mcpApplicationSocketName(in.Name)
			if err != nil {
				return nil, err
			}
			return &McpAccess{
				Action:   protocol.AclAction_ACL_ACTION_LISTEN,
				Resource: sidecar.AclResource{Kind: sidecar.AclResourceSocket, Name: name},
			}, nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpSocketListenIn, result *McpResult) (*mcpSocketListenOut, error) {
		name, err := mcpApplicationSocketName(in.Name)
		if err != nil {
			return nil, err
		}
		if in.LocalPort < 1 || 65535 < in.LocalPort {
			return nil, errMcpSocketPort
		}
		held := sockets()
		if held == nil {
			return nil, errMcpSocketUnavailable
		}
		result.SetSource("sockets:listen")
		out := &mcpSocketListenOut{}
		grantId, covered := McpCoveringGrant(ctx)
		if covered {
			out.GrantId = hex.EncodeToString(grantId)
		} else {
			// outward: §5.4's gate first (I-8), whose answer may be pending
			authorizer, ok := call.Network.(mcpAuthorizer)
			if !ok {
				return nil, errMcpSocketHeld
			}
			// the action names the socket as a server may see it, its token path under the network's current K_sock
			// (QD-772), which a daemon holding none yet cannot derive, as its sockets could register none
			var ring *sidecar.SocketKeyRing
			if keys, ok := call.Network.(mcpSocketKeys); ok {
				ring = keys.SocketKeyRing()
			}
			if ring == nil {
				return nil, mcpSocketError(sidecar.ErrSocketUnavailable)
			}
			grantDst, err := sidecar.SocketListenGrantDst(name, ring.Current())
			if err != nil {
				return nil, errMcpSocketHeld
			}
			action, err := listenAction(ctx, call, name, in.LocalPort, grantDst)
			if errors.Is(err, sidecar.ErrSocketUnavailable) {
				return nil, mcpSocketError(err)
			}
			if err != nil {
				// no requests rule takes the listen and no standing grant covers it: nothing is filed
				return nil, errMcpSocketHeld
			}
			// the name and the port the listen below forwards to ride the request, so the approval is of this socket
			// and this port
			action.Detail = mcpSocketListenDetail(name, in.LocalPort)
			if err := authorizer.Authorize(ctx, action, nil); err != nil {
				var pending *sidecar.ApprovalPendingError
				if errors.As(err, &pending) {
					return &mcpSocketListenOut{Status: "approval_pending", ApprovalId: pending.ApprovalId.String()}, nil
				}
				return nil, errMcpSocketHeld
			}
			// the gate ran the listen's effect: its grant stands, or the use says why the listen cannot register
			if outcome := action.Outcome; outcome != nil {
				switch outcome.State {
				case sidecar.ApprovalOutcomeDone:
					if 0 < len(outcome.EffectRef) {
						out.GrantId = hex.EncodeToString(outcome.EffectRef)
					}
				case sidecar.ApprovalOutcomeNotDone:
					return nil, errMcpSocketHeld
				default:
					// uncertain: the same listen asked again completes its use under its key (AU4)
					return nil, mcpSocketError(sidecar.ErrSocketUnavailable)
				}
			}
		}
		reply, err := held.Listen(ctx, call.NetworkId, name, "127.0.0.1:"+strconv.Itoa(in.LocalPort))
		if err != nil {
			return nil, mcpSocketError(err)
		}
		if reply.ApprovalId != nil {
			out.Status = "approval_pending"
			out.ApprovalId = reply.ApprovalId.String()
			return out, nil
		}
		out.Status = "listening"
		out.Serving = reply.Status != nil && reply.Status.Serving
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpSocketNameIn]{
		Name:        "socket_unlisten",
		Tier:        McpTierWrite,
		Description: "Ends this daemon's listen on an application socket name at once; streams already accepted stay.",
		Access:      none,
	}, func(ctx context.Context, call *McpCall, in *mcpSocketNameIn, result *McpResult) (*mcpSocketUnlistenOut, error) {
		name, err := mcpApplicationSocketName(in.Name)
		if err != nil {
			return nil, err
		}
		held := sockets()
		if held == nil {
			return nil, errMcpSocketUnavailable
		}
		result.SetSource("sockets:unlisten")
		if held.Unlisten(call.NetworkId, name) {
			return &mcpSocketUnlistenOut{Status: "unlistened"}, nil
		}
		return &mcpSocketUnlistenOut{Status: "not_listening"}, nil
	})
}

// A sockets error as a tool answers it: §9.9's values by their constant texts, never a name (I-13).
func mcpSocketError(err error) error {
	switch {
	case errors.Is(err, sidecar.ErrDaemonSocketListening):
		return errMcpSocketTaken
	case errors.Is(err, sidecar.ErrSocketDenied):
		return NewMcpError(McpCodeRefused, "the network does not allow this socket", false)
	case errors.Is(err, sidecar.ErrSocketUnavailable), errors.Is(err, sidecar.ErrSocketBusy), errors.Is(err, sidecar.ErrSocketQuota):
		return NewMcpError(McpCodeUnavailable, "the sockets service cannot take this now: try again later", true)
	case errors.Is(err, sidecar.ErrSocketNoListener):
		return NewMcpError(McpCodeFailed, "no listener answered", true)
	}
	return errMcpFailed
}
