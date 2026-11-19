//go:build !js && !ios && !android && !sdk_mobile_bind

// One relay connection's session (§16.4, D-MCP-2): its hello, its agent and the instructions text picked at its start,
// its claims values (§16.11), its limits (limits.go), its run bindings, one per network (hook_bind.go), and its agent's
// id in each network. The agent is an attribution label, agent_asserted (X10; owner decision 47): the hello's, else the
// project's `.ur` default, read once at the session's start. A label that is not one leaves the session unable to serve
// calls, each refused, rather than recorded raw.
//
// The agent's durable agent_id is its network's (§5.5, owner decision 470; QD-981): one per (sidecar, label), which
// the network's Sidecar keeps in its keychain.ur (Sidecar.ResolveAgentId, an McpAgentNetwork's). The session takes it at
// its first call in each network, before the call's tool runs, and keeps it for its life, so an AgentRevoke reaches the
// label's next session and never one mid-way. Every tool binds what it writes and asks to it (mcpCallAgentId): the evs
// writes seal it in their push's provenance, and each outward action carries it to its approval's binding. A call that
// cannot take it is refused, and so is every call of a session with an agent in a network that keeps no agents' ids; a
// session with no agent has none and takes none.
//
// A session's run's taint lives in the run's file (D-MCP-16), never here: until a hook binds it, a session is
// unbound and acts under a placeholder run id the run store never saw, which reads tainted.
//
// Safe for concurrent use.

package mcp

import (
	"context"
	"errors"
	"sync"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
)

// A network that keeps its in-daemon agents' durable ids (§5.5, owner decision 470): *sidecar.Sidecar is one, and so is
// each tool view over one (McpNetworkOf, McpEvsNetworkOf), which embeds it. A session with an agent acts only in a
// network that is one.
type McpAgentNetwork interface {
	// The label's agent_id in this network's sidecar: the one its keychain.ur keeps for the label, else one drawn and
	// kept there now (Sidecar.ResolveAgentId).
	ResolveAgentId(label string) (sidecar.Id, error)
}

// A session with an agent called in a network that keeps no agents' ids.
var errMcpSessionAgentNoRegistry = errors.New("the network keeps no agent ids")

// One MCP session of the daemon.
type McpSession struct {
	server *McpServer
	// the relay's hello, PeerPid the daemon's own reading
	hello sidecar.DaemonHello
	// nil for none
	agent *sidecar.SidecarAgent
	// why the hello's or .ur's agent label was refused, nil when it was not
	agentErr     error
	instructions string
	// the session's claims, nil when its daemon reads none, and the value of the network it started in, nil when
	// none resolved then; both fixed at the start
	claims      McpSessionClaims
	startClaims *sidecar.SidecarClaimsResolution
	limits      *mcpSessionLimits
	// its search session, limits and cursors' end (session_search.go)
	search *mcpSessionSearch
	// the relay's harness process and ancestry, by the pid the system reports; empty when it cannot be read
	caller mcpCallerProcess

	stateLock     sync.Mutex
	serverSession *gomcp.ServerSession
	// each network's binding (hook_bind.go)
	networkIdBindings map[sidecar.Id]*mcpSessionBinding
	// the agent's id in each network it called in, taken at its first call there; nil before any
	networkIdAgentIds map[sidecar.Id]sidecar.Id
}

// A copy of the hello the session opened with. PeerPid is the system's report of the relay's pid.
func (self *McpSession) Hello() sidecar.DaemonHello {
	return self.hello
}

// The agent the session acts as, a copy, nil for none. Its source is always agent_asserted. It names no id: each
// network's is AgentId's.
func (self *McpSession) Agent() *sidecar.SidecarAgent {
	if self.agent == nil {
		return nil
	}
	return &sidecar.SidecarAgent{Label: self.agent.Label}
}

// The session's agent's durable agent_id in networkId (§5.5), a copy: the one the session took at its first call
// there, the same for the session's life. Nil for a session with no agent, and before its first call in networkId.
func (self *McpSession) AgentId(networkId sidecar.Id) *sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	agentId, ok := self.networkIdAgentIds[networkId]
	if !ok {
		return nil
	}
	return &agentId
}

// Takes the session's agent's id in networkId from network at the session's first call there, and keeps it: a call
// that races it keeps whichever was kept first, so the session names one id in a network. Nil at once for a session
// with no agent or one that holds its id already; errMcpSessionAgentNoRegistry for a network that keeps no agents' ids,
// and the network's error when its keychain cannot read or write the registration.
func (self *McpSession) resolveAgentId(networkId sidecar.Id, network McpNetwork) error {
	if self.agent == nil || self.AgentId(networkId) != nil {
		return nil
	}
	registry, ok := network.(McpAgentNetwork)
	if !ok {
		return errMcpSessionAgentNoRegistry
	}
	// the registry's own lock orders the keychain, so none of the session's is held across it
	agentId, err := registry.ResolveAgentId(self.agent.Label)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.networkIdAgentIds == nil {
		self.networkIdAgentIds = map[sidecar.Id]sidecar.Id{}
	}
	if _, ok := self.networkIdAgentIds[networkId]; !ok {
		self.networkIdAgentIds[networkId] = agentId
	}
	return nil
}

// The agent id the call's writes and actions bind to: its session's in its network, nil for none (AgentId).
func mcpCallAgentId(call *McpCall) *sidecar.Id {
	if call == nil || call.Session == nil {
		return nil
	}
	return call.Session.AgentId(call.NetworkId)
}

// The instructions text the session's go-sdk Server sends, fixed at its start.
func (self *McpSession) Instructions() string {
	return self.instructions
}

// The claims value the session started under, in the network it started in: what picked its instructions text. Nil
// when its daemon reads no claims or no network resolved at its start. A copy.
func (self *McpSession) StartClaims() *sidecar.SidecarClaimsResolution {
	if self.startClaims == nil {
		return nil
	}
	resolution := *self.startClaims
	return &resolution
}

// The claims value the session runs under in networkId: resolved at its first ask and the same for the session's
// life, whatever changes after (§16.10's claims row). Nil when its daemon reads no claims. A copy.
func (self *McpSession) Claims(ctx context.Context, networkId sidecar.Id) *sidecar.SidecarClaimsResolution {
	if self.claims == nil {
		return nil
	}
	resolved := self.claims.For(ctx, networkId)
	if resolved == nil {
		return nil
	}
	resolution := *resolved
	return &resolution
}

// Takes one of the session's W calls, refusing one past SessionWriteRate with a retryable McpCodeRateLimited error.
// The tool framework calls it for each W tool before the handler (MCP-M3-12).
func (self *McpSession) AdmitWrite() error {
	if !self.limits.admitWrite() {
		return errMcpRateLimited()
	}
	return nil
}

// The go-sdk session serving this one, nil before it connects.
func (self *McpSession) ServerSession() *gomcp.ServerSession {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.serverSession
}
