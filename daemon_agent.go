//go:build !js && !ios && !android && !sdk_mobile_bind

// Agents (§5.5, §5.8, CORE-M3-05; owner decisions 4, 47): an agent is an attribution label on this sidecar's client,
// asserted by its caller (source agent_asserted), any number of them, free. It holds no credential, no group key and no
// grant: the daemon signs, decrypts and enforces per-agent reads for it (owner decision 4), and a grant attaches to the
// sidecar, which any local process of the user may use (owner decision 47). Its bytes debit the network's balance
// through §20's path like the sidecar's own.
//
// A session's agent is its hello's agent, else its project's `.ur` default, else none. A label is short printable
// ASCII (SidecarAgentLabelSettings), so it can name a run and a record without escaping, and an invalid one is
// refused, never recorded raw.
//
// In each network an agent also has a durable agent_id (§5.5, owner decision 470; QD-981): the one its label's
// registration in that network's keychain.ur names (identity_agent.go's ResolveAgentId). A session takes it at its
// first call in the network and keeps it for its life, so an AgentRevoke reaches the label's next session, which draws
// the new registration's id, and never a session mid-way. A network's Sidecar that holds no agent's id now (Locked,
// not enrolled yet, revoked, or its keystore lost) gives the call none, and the call runs as before; any other failure
// to read or write the registration fails the call. MCP's sessions keep theirs the same way (mcp/session.go).

package sidecar

import (
	"errors"
	"fmt"
)

// §16.8's source of an agent's attribution: asserted by the caller, never proven.
const SidecarAgentSourceAsserted = "agent_asserted"

// The session's agent's registration could not be read or written in the call's network.
var errDaemonAgentId = errors.New("the session's agent id cannot be read from the network's keychain")

// One agent of this sidecar: a label and, in the network a call acts in, its registration's id. Nothing that
// authenticates or decrypts.
type SidecarAgent struct {
	Label string
	// The agent's durable agent_id in the call's network (§5.5): nil where none was resolved, for a call that names no
	// network or in a network whose Sidecar holds no agent's id now.
	Id *Id
}

// agent_asserted: the caller's word.
func (self SidecarAgent) Source() string {
	return SidecarAgentSourceAsserted
}

// An agent of label in the default form (SidecarAgentLabelSettings), refused unless it is one. It names no id yet.
func ParseSidecarAgent(label string) (SidecarAgent, error) {
	if err := DefaultSidecarAgentLabelSettings().Check(label); err != nil {
		return SidecarAgent{}, err
	}
	return SidecarAgent{Label: label}, nil
}

// The agent a session acts as: its hello's agent, else its project's `.ur` default, else nil. An invalid label in
// either is refused with ErrSidecarAgentLabel. Given the call's network and its hosted Sidecar, the agent carries its
// id there, the one the session took at its first call in networkId (the file header); a failure to read or write the
// registration then is errDaemonAgentId.
func (self *Daemon) sessionAgent(session *daemonSession, networkId Id, hosted *Sidecar) (*SidecarAgent, error) {
	label := session.hello.Agent
	if label == "" {
		project, err := self.sessionProject(session)
		if err != nil || project == nil || project.Agent == "" {
			// a .ur that does not parse names no agent; a network call reports it
			return nil, nil
		}
		label = project.Agent
	}
	agent, err := ParseSidecarAgent(label)
	if err != nil {
		return nil, err
	}
	if hosted == nil {
		return &agent, nil
	}
	if agentId, ok := session.networkIdAgentIds[networkId]; ok {
		agent.Id = &agentId
		return &agent, nil
	}
	agentId, err := hosted.ResolveAgentId(agent.Label)
	switch {
	case err == nil:
	case errors.Is(err, ErrSidecarStoreLocked), errors.Is(err, ErrSidecarKeystoreLost), errors.Is(err, ErrSidecarNoIdentity),
		errors.Is(err, ErrSidecarSignRefused):
		// a Sidecar that holds no agent's id now: the call names none, and a later one of the session asks again
		return &agent, nil
	default:
		return nil, fmt.Errorf("%w: %w", errDaemonAgentId, err)
	}
	if session.networkIdAgentIds == nil {
		session.networkIdAgentIds = map[Id]Id{}
	}
	session.networkIdAgentIds[networkId] = agentId
	agent.Id = &agentId
	return &agent, nil
}

// The agent hello's session acts as: its agent, else the `.ur` found from its cwd, else nil. It names no id, which is
// each network's: a call's (DaemonCall.Agent) or an MCP session's (McpSession.AgentId).
func (self *Daemon) Agent(hello *DaemonHello) (*SidecarAgent, error) {
	return self.sessionAgent(&daemonSession{hello: hello}, Id{}, nil)
}
