//go:build !js && !ios && !android && !sdk_mobile_bind

// One relay connection's session (§16.4, D-MCP-2): its hello, its agent and the instructions text picked at its start,
// and its limits (limits.go). The agent is an attribution label,
// agent_asserted (X10; owner decision 47): the hello's, else the project's `.ur` default, read once at the session's
// start. A label that is not one leaves the session unable to serve calls, each refused, rather than recorded raw.
//
// Safe for concurrent use.

package mcp

import (
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
	limits       *mcpSessionLimits

	stateLock     sync.Mutex
	serverSession *gomcp.ServerSession
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
