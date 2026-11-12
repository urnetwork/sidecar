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
//     is outward, §5.4's gate with a CanonicalAction of kind listen naming the socket and, beside it, the local port
//     as the request's local_port (QD-740), which the approver renders and the decision binds: the tool listens on
//     the port it asked for and no other. tls/ is tls_publish's, smtp/ a receiver's, share/ ur share's and ur/ the
//     platform's: each is refused here.
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
	// The covering grant's id, hex, when one let the listen run without an approval.
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

// The §5.4 action an uncovered socket_listen goes through Authorize as: kind listen naming the socket, built by
// NewCanonicalAction. A test replaces it.
type mcpSocketListenActionFunction func(call *McpCall, name string) (*sidecar.SidecarAction, error)

// The production action: NewCanonicalAction, then NewSidecarAction bound to the call's run.
func mcpSocketListenAction(call *McpCall, name string) (*sidecar.SidecarAction, error) {
	stored, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind:       uint32(sidecar.SidecarActionListen),
		SocketName: name,
	})
	if err != nil {
		return nil, err
	}
	runId := call.RunId
	return sidecar.NewSidecarAction(stored, sidecar.SidecarRiskNormal, sidecar.SidecarRiskNormal, &runId, nil)
}

// What an outward socket_listen passes: the network's §5.4 gate, *sidecar.Sidecar's Authorize.
type mcpAuthorizer interface {
	Authorize(ctx context.Context, action *sidecar.SidecarAction, decision *bridge.Signed) error
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addSocketTools(catalog, func() McpSockets { return mcpSocketsOf(server) }, mcpSocketListenAction)
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
			action, err := listenAction(call, name)
			if err != nil {
				return nil, errMcpSocketHeld
			}
			// the port the listen below forwards to rides the request, so the approval is of this port
			action.Detail = &sidecar.SidecarActionDetail{LocalPort: uint32(in.LocalPort)}
			if err := authorizer.Authorize(ctx, action, nil); err != nil {
				var pending *sidecar.ApprovalPendingError
				if errors.As(err, &pending) {
					return &mcpSocketListenOut{Status: "approval_pending", ApprovalId: pending.ApprovalId.String()}, nil
				}
				return nil, errMcpSocketHeld
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
