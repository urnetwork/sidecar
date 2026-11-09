//go:build !js && !ios && !android && !sdk_mobile_bind

// Agents (§5.5, §5.8, CORE-M3-05; owner decisions 4, 47): an agent is an attribution label on this sidecar's client,
// asserted by its caller (source agent_asserted), any number of them, free. It holds no credential, no group key and no
// grant: the daemon signs, decrypts and enforces per-agent reads for it (owner decision 4), and a grant attaches to the
// sidecar, which any local process of the user may use (owner decision 47). Its bytes debit the network's balance
// through §20's path like the sidecar's own.
//
// A session's agent is its hello's agent, else its project's `.ur` default, else none. A label is short printable
// ASCII, so it can name a run and a record without escaping, and an invalid one is refused, never recorded raw.

package sidecar

import (
	"errors"
)

// The longest agent label.
const sidecarAgentMaxByteCount = 64

// §16.8's source of an agent's attribution: asserted by the caller, never proven.
const SidecarAgentSourceAsserted = "agent_asserted"

// An agent label that is not one.
var ErrSidecarAgentLabel = errors.New("an agent label is 1 to 64 of A-Z, a-z, 0-9, '.', '_' and '-', starting with a letter or digit")

// One agent of this sidecar: a label, and nothing that authenticates or decrypts.
type SidecarAgent struct {
	Label string
}

// agent_asserted: the caller's word.
func (self SidecarAgent) Source() string {
	return SidecarAgentSourceAsserted
}

// An agent of label, refused unless it is one.
func ParseSidecarAgent(label string) (SidecarAgent, error) {
	if label == "" || sidecarAgentMaxByteCount < len(label) {
		return SidecarAgent{}, ErrSidecarAgentLabel
	}
	for i := 0; i < len(label); i += 1 {
		c := label[i]
		alphanumeric := ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')
		if !alphanumeric && (i == 0 || (c != '.' && c != '_' && c != '-')) {
			return SidecarAgent{}, ErrSidecarAgentLabel
		}
	}
	return SidecarAgent{Label: label}, nil
}

// The agent a session acts as: its hello's agent, else its project's `.ur` default, else nil. An invalid label in
// either is refused.
func (self *Daemon) sessionAgent(session *daemonSession) (*SidecarAgent, error) {
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
	return &agent, nil
}

// The agent hello's session acts as: its agent, else the `.ur` found from its cwd, else nil.
func (self *Daemon) Agent(hello *DaemonHello) (*SidecarAgent, error) {
	return self.sessionAgent(&daemonSession{hello: hello})
}
