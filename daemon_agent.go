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
// the new registration's id, and never a session mid-way. Here, for control and hook calls, the id is attribution
// taken where it can be: a network's Sidecar that holds no agent's id now (Locked, not enrolled yet, revoked, its
// keystore lost) gives the call none, and so, logged, does a registration that cannot be read or written, and the call
// runs as before, since hook.event carries a run's taint and must not fail for want of an attribution. No handler here
// binds anything to the id yet. MCP's sessions, whose tools bind their writes and actions to it, take it the same way
// and refuse a call that cannot take it (mcp/session.go).

package sidecar

import (
	"errors"
)

// §16.8's source of an agent's attribution: asserted by the caller, never proven.
const SidecarAgentSourceAsserted = "agent_asserted"

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
// id there, the one the session took at its first call in networkId, or none where none can be taken now (the file
// header), which the session's next call asks for again.
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
		// a registration that cannot be read or written: the call runs with none, as above, and says so
		self.log.Errorf("[daemon]network %s cannot read or write a session's agent registration, so its call names no agent id: %v", networkId, err)
		return &agent, nil
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
