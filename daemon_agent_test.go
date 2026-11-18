//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

// §22.5's §16 row: an agent is a label on this sidecar's client and, in a network, its registration's id, and nothing
// more. It holds no credential, group key or grant, so a reply carrying one leaks nothing, and its attribution is the
// caller's word.
func TestAgentHoldsNoCredential(t *testing.T) {
	agentType := reflect.TypeFor[SidecarAgent]()
	for i := 0; i < agentType.NumField(); i += 1 {
		if field := agentType.Field(i); field.Type.Kind() != reflect.String && field.Type != reflect.TypeFor[*Id]() {
			t.Errorf("SidecarAgent.%s is a %s, neither a label nor an id", field.Name, field.Type)
		}
	}
	agent, err := ParseSidecarAgent("api-refactor")
	if err != nil || agent.Source() != SidecarAgentSourceAsserted || agent.Id != nil {
		t.Fatalf("%+v %v", agent, err)
	}
	agentId := NewId()
	agent.Id = &agentId
	if err := checkDaemonReply(&agent); err != nil {
		t.Errorf("an agent fails the reply walk: %v", err)
	}
	for _, label := range []string{"", "-x", ".x", "two words", "a/b", "x\n", "é", string(make([]byte, 65))} {
		if _, err := ParseSidecarAgent(label); !errors.Is(err, ErrSidecarAgentLabel) {
			t.Errorf("%q: %v", label, err)
		}
	}

	// the hello's agent, else .ur's default, reaches each call as a label alone
	home := t.TempDir()
	writeTestFile(t, filepath.Join(home, ".ur"), "agent = \"from-dot-ur\"\n")
	daemon := newProjectTestDaemon(t, home)
	var seen []*SidecarAgent
	if err := daemon.RegisterMethod(&DaemonMethod{Name: "synthetic.whoami", Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
		seen = append(seen, call.Agent)
		return call.Agent, nil
	}}); err != nil {
		t.Fatal(err)
	}
	line := []byte(`{"jsonrpc":"2.0","id":1,"method":"synthetic.whoami"}`)
	daemon.dispatch(line, &daemonSession{hello: &DaemonHello{Mode: DaemonModeMcp, Agent: "from-hello", Cwd: home}}, runUnbounded)
	daemon.dispatch(line, &daemonSession{hello: &DaemonHello{Mode: DaemonModeMcp, Cwd: home}}, runUnbounded)
	daemon.dispatch(line, &daemonSession{hello: &DaemonHello{Mode: DaemonModeMcp}}, runUnbounded)
	response := daemon.dispatch(line, &daemonSession{hello: &DaemonHello{Mode: DaemonModeMcp, Agent: "not a label"}}, runUnbounded)
	if len(seen) != 3 || seen[0].Label != "from-hello" || seen[1].Label != "from-dot-ur" || seen[2] != nil {
		t.Fatalf("agents seen %+v", seen)
	}
	if seen[0].Id != nil || seen[1].Id != nil {
		t.Errorf("a call that names no network carries an agent id: %v %v", seen[0].Id, seen[1].Id)
	}
	if response.Error == nil || response.Error.Code != daemonRpcInvalidParams {
		t.Errorf("an invalid agent ran: %+v", response.Error)
	}
	if agent, err := daemon.Agent(&DaemonHello{Mode: DaemonModeMcp, Cwd: home}); err != nil || agent.Label != "from-dot-ur" || agent.Id != nil {
		t.Errorf("Agent: %+v %v", agent, err)
	}
}

// A daemon hosting hosted as networkId's, with synthetic.scoped (a Network method) and synthetic.unscoped, each keeping
// the agent its call carries on seen, which a call's answer empties first.
type agentIdTestDaemon struct {
	t      *testing.T
	daemon *Daemon
	seen   []*SidecarAgent
}

func newAgentIdTestDaemon(t *testing.T, networkId Id, hosted *Sidecar) *agentIdTestDaemon {
	t.Helper()
	self := &agentIdTestDaemon{t: t, daemon: newDispatchTestDaemon(t)}
	if err := self.daemon.AddSidecar(networkId, hosted); err != nil {
		t.Fatal(err)
	}
	handler := func(ctx context.Context, call *DaemonCall) (any, error) {
		self.seen = append(self.seen, call.Agent)
		return nil, nil
	}
	for _, method := range []*DaemonMethod{
		{Name: "synthetic.scoped", Network: true, Handler: handler},
		{Name: "synthetic.unscoped", Handler: handler},
	} {
		if err := self.daemon.RegisterMethod(method); err != nil {
			t.Fatal(err)
		}
	}
	return self
}

// A session of agent's label, "" for none.
func agentIdTestSession(agent string) *daemonSession {
	return &daemonSession{hello: &DaemonHello{Mode: DaemonModeControl, Version: "synthetic-version", Agent: agent}}
}

// The response to one call of method on session, and the agent the call carried when it ran.
func (self *agentIdTestDaemon) call(session *daemonSession, method string) (*daemonRpcResponse, *SidecarAgent, bool) {
	self.seen = nil
	response := self.daemon.dispatch([]byte(`{"jsonrpc":"2.0","id":1,"method":"`+method+`"}`), session, runUnbounded)
	if len(self.seen) == 0 {
		return response, nil, false
	}
	return response, self.seen[0], true
}

// The agent id a call of method on session carries, failing when the call did not run or carried no agent.
func (self *agentIdTestDaemon) agentIdOf(session *daemonSession, method string) *Id {
	self.t.Helper()
	response, agent, ran := self.call(session, method)
	if !ran || response.Error != nil || agent == nil {
		self.t.Fatalf("%s: ran %t, %+v, agent %+v", method, ran, response.Error, agent)
	}
	return agent.Id
}

// QD-981 through the daemon (owner decision 470): a Network method's call carries its session's agent's id in the call's
// network, the label's registration there, which a session takes at its first call and keeps. Two sessions of one
// label carry one id, as does a session after a restart over the same state; another label carries another; a call
// that names no network, and a session with no agent, carry none. After AgentRevoke a session open across it keeps its
// id, and the label's next session carries a new one, which holds.
func TestSessionAgentIdOnePerLabelAcrossRestart(t *testing.T) {
	backend, keyStore := NewSidecarMemoryBackend(), newFakeKeyStore()
	hosted, instance := newAgentRegistryTestSidecar(t, backend, keyStore, true)
	networkId := testBindingFields().NetworkId
	daemon := newAgentIdTestDaemon(t, networkId, hosted)

	first := daemon.agentIdOf(agentIdTestSession("builder"), "synthetic.scoped")
	if first == nil {
		t.Fatal("a Network method's call carries no agent id")
	}
	builderId := *first
	if registered, err := hosted.ResolveAgentId("builder"); err != nil || registered != builderId {
		t.Fatalf("the call carries %s, the registration names %s: %v", builderId, registered, err)
	}
	if second := daemon.agentIdOf(agentIdTestSession("builder"), "synthetic.scoped"); second == nil || *second != builderId {
		t.Errorf("a second session of the label carries %v, not %s", second, builderId)
	}
	reviewer := daemon.agentIdOf(agentIdTestSession("reviewer"), "synthetic.scoped")
	if reviewer == nil || *reviewer == builderId {
		t.Fatalf("another label carries %v beside %s", reviewer, builderId)
	}
	reviewerId := *reviewer
	if unscoped := daemon.agentIdOf(agentIdTestSession("builder"), "synthetic.unscoped"); unscoped != nil {
		t.Errorf("a call that names no network carries %s", unscoped)
	}
	if _, agent, ran := daemon.call(agentIdTestSession(""), "synthetic.scoped"); !ran || agent != nil {
		t.Errorf("a session with no agent: ran %t, agent %+v", ran, agent)
	}

	// a restart: the instance opens again on its backend and key store, and a new Sidecar and daemon stand over it
	instance.Close()
	restarted, _ := newAgentRegistryTestSidecar(t, backend, keyStore, false)
	daemon = newAgentIdTestDaemon(t, networkId, restarted)
	open := agentIdTestSession("builder")
	if again := daemon.agentIdOf(open, "synthetic.scoped"); again == nil || *again != builderId {
		t.Fatalf("after a restart the label carries %v, not %s", again, builderId)
	}
	if again := daemon.agentIdOf(agentIdTestSession("reviewer"), "synthetic.scoped"); again == nil || *again != reviewerId {
		t.Errorf("after a restart another label carries %v, not %s", again, reviewerId)
	}

	// AgentRevoke ends the registration: the open session keeps its id, the label's next session takes a new one
	if err := restarted.AgentRevoke(builderId); err != nil {
		t.Fatal(err)
	}
	if kept := daemon.agentIdOf(open, "synthetic.scoped"); kept == nil || *kept != builderId {
		t.Errorf("a session open across the revocation carries %v, not its own %s", kept, builderId)
	}
	next := daemon.agentIdOf(agentIdTestSession("builder"), "synthetic.scoped")
	if next == nil || *next == builderId || *next == reviewerId {
		t.Fatalf("the label's next session carries %v", next)
	}
	if again := daemon.agentIdOf(agentIdTestSession("builder"), "synthetic.scoped"); again == nil || *again != *next {
		t.Errorf("the new registration does not hold: %s, then %v", *next, again)
	}
}

// A network's Sidecar that holds no agent's id now, Locked or not enrolled yet, gives the call none and runs it, and
// the session asks again at its next call; a registration that does not decode fails the call with a constant text,
// and runs nothing.
func TestSessionAgentIdWhereNoneCanBeHeld(t *testing.T) {
	networkId := testBindingFields().NetworkId
	session := agentIdTestSession("builder")
	for name, hosted := range map[string]*Sidecar{
		"locked":      newSidecarBase(nil, cheapKeychainSettings()),
		"no identity": {},
	} {
		daemon := newAgentIdTestDaemon(t, networkId, hosted)
		response, agent, ran := daemon.call(session, "synthetic.scoped")
		if !ran || response.Error != nil || agent == nil || agent.Label != "builder" || agent.Id != nil {
			t.Errorf("%s: ran %t, %+v, agent %+v", name, ran, response.Error, agent)
		}
	}

	// the same session takes its id at its next call, once the network's sidecar holds one
	hosted, _, _ := newIdentityTestSidecar(t)
	daemon := newAgentIdTestDaemon(t, networkId, hosted)
	agentId := daemon.agentIdOf(session, "synthetic.scoped")
	if registered, err := hosted.ResolveAgentId("builder"); agentId == nil || err != nil || *agentId != registered {
		t.Fatalf("once the sidecar holds one the session carries %v, the registration %s: %v", agentId, registered, err)
	}

	// a registration that does not decode is a failure, never absence
	if err := hosted.coreSecrets.Put(sidecarAgentLabelRecordName("reviewer"), []byte("not a registration")); err != nil {
		t.Fatal(err)
	}
	response, _, ran := daemon.call(agentIdTestSession("reviewer"), "synthetic.scoped")
	if ran || response.Error == nil || response.Error.Code != DaemonRpcFailed || response.Error.Message != errDaemonAgentId.Error() {
		t.Errorf("a registration that does not decode: ran %t, %+v", ran, response.Error)
	}
	// a call that names no network reads no registration, and runs
	if _, agent, ran := daemon.call(agentIdTestSession("reviewer"), "synthetic.unscoped"); !ran || agent == nil || agent.Id != nil {
		t.Errorf("an unscoped call of the label: ran %t, agent %+v", ran, agent)
	}
}
