//go:build !js && !ios && !android && !sdk_mobile_bind

// One relay connection's session (§16.4, D-MCP-2): its hello, its agent and the instructions text picked at its start,
// its claims values (§16.11), its limits (limits.go), and its run bindings, one per network (hook_bind.go). The agent is an attribution label,
// agent_asserted (X10; owner decision 47): the hello's, else the project's `.ur` default, read once at the session's
// start. A label that is not one leaves the session unable to serve calls, each refused, rather than recorded raw.
//
// A session's run's taint lives in the run's file (D-MCP-16), never here: until a hook binds it, a session is
// unbound and acts under a placeholder run id the run store never saw, which reads tainted.
//
// Safe for concurrent use.

package mcp

import (
	"context"
	"sync"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
)

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
	// the relay's harness process and ancestry, by the pid the system reports; empty when it cannot be read
	caller mcpCallerProcess

	stateLock     sync.Mutex
	serverSession *gomcp.ServerSession
	// each network's binding (hook_bind.go)
	networkIdBindings map[sidecar.Id]*mcpSessionBinding
}

// A copy of the hello the session opened with. PeerPid is the system's report of the relay's pid.
func (self *McpSession) Hello() sidecar.DaemonHello {
	return self.hello
}

// The agent the session acts as, a copy, nil for none. Its source is always agent_asserted.
func (self *McpSession) Agent() *sidecar.SidecarAgent {
	if self.agent == nil {
		return nil
	}
	agent := *self.agent
	return &agent
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
