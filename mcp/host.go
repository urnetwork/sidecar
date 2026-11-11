//go:build !js && !ios && !android && !sdk_mobile_bind

// What a tool reads of the network a call acts on, beyond McpNetwork's state, runs and spool (server.go): McpNetwork
// as tools see it (MCP.md's seam table). Every tool call needs §8's local allow for the session's subject (owner
// decision 6), the sidecar itself, since in-daemon agents share their sidecar's grants (§5.5); the repo kinds McpGuard
// judges; and the credentials no result may carry (I-7).
//
// McpNetworkOf is the adapter over the root's Sidecar and its network's §8.9 AclEngine, which ACL-M2-15's follower
// installs into. The daemon does not hold an engine per network yet (no task has wired one into a hosted Sidecar),
// so DaemonOf still answers a bare Sidecar, which is no McpToolNetwork, and every tool call on it is refused: the
// closed direction, until that wiring passes McpNetworkOf instead.
//
// McpCallSink is where every W call goes as a tool_call entry, source observed, once it ends: Ingest.RecordMcpCall
// (ingest_tools.go) is one.

package mcp

import (
	"context"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One network as a tool reads it. Safe for concurrent use.
type McpToolNetwork interface {
	McpNetwork
	// Who the network's calls act as: the sidecar, every in-daemon agent sharing its grants. Nil before enrollment.
	Identity() *sidecar.SidecarIdentity
	// Whether a policy is installed: §8.9's engine holds a verified state. Every call is refused while none is.
	PolicyInstalled() bool
	// §8.9's local check of one grant for this sidecar at now: AclEngine.Check. False while no policy is installed.
	Allow(action protocol.AclAction, resource sidecar.AclResource, now time.Time) (check sidecar.AclCheck, installed bool)
	// A repo's kind at the installed state, UNSPECIFIED for one it does not hold or before a policy installs.
	RepoKind(repoId sidecar.Id) protocol.RepoKind
	// The credentials no result may carry, read now; an error while Locked or unenrolled.
	SecretMatcher() (*sidecar.SecretMatcher, error)
}

// One grant a call needs from §8's local evaluation: the action on the resource, for the session's subject.
type McpAccess struct {
	Action   protocol.AclAction
	Resource sidecar.AclResource
}

// Where every W call is recorded once it ends: name, its arguments and result as sent, its times, and its error, nil
// for a success. Implementations redact before they keep anything and never block the call (Ingest.RecordMcpCall).
type McpCallSink interface {
	RecordMcpCall(ctx context.Context, call *McpCall, toolName string, arguments []byte, result []byte, startedMillis int64, endedMillis int64, callErr error)
}

// The network a call reads through tools, false when it is no McpToolNetwork.
func mcpToolNetworkOf(call *McpCall) (McpToolNetwork, bool) {
	if call == nil || call.Network == nil {
		return nil, false
	}
	network, ok := call.Network.(McpToolNetwork)
	return network, ok
}

// A hosted Sidecar and its network's engine as tools read them.
type mcpSidecarNetwork struct {
	*sidecar.Sidecar
	engine *sidecar.AclEngine
}

// The tool view of hosted, its local allow and repo kinds from engine, whose installed state ACL's follower keeps.
func McpNetworkOf(hosted *sidecar.Sidecar, engine *sidecar.AclEngine) McpToolNetwork {
	return &mcpSidecarNetwork{Sidecar: hosted, engine: engine}
}

// Whether the engine holds a state.
func (self *mcpSidecarNetwork) PolicyInstalled() bool {
	return self.engine != nil && self.engine.State() != nil
}

// AclEngine.Check for the hosted sidecar, false before a state installs or before enrollment.
func (self *mcpSidecarNetwork) Allow(action protocol.AclAction, resource sidecar.AclResource, now time.Time) (sidecar.AclCheck, bool) {
	identity := self.Identity()
	if self.engine == nil || self.engine.State() == nil || identity == nil {
		return sidecar.AclCheck{}, false
	}
	return self.engine.Check(sidecar.AclSidecarSubject(identity.SidecarId), action, resource, now), true
}

// The installed state's repo row's kind.
func (self *mcpSidecarNetwork) RepoKind(repoId sidecar.Id) protocol.RepoKind {
	if self.engine == nil {
		return protocol.RepoKind_REPO_KIND_UNSPECIFIED
	}
	state := self.engine.State()
	if state == nil {
		return protocol.RepoKind_REPO_KIND_UNSPECIFIED
	}
	return state.Repo(repoId).GetKind()
}
