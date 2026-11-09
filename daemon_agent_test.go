//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

// §22.5's §16 row: an agent is a label on this sidecar's client and nothing more. It holds no credential, group key or
// grant, so a reply carrying one leaks nothing, and its attribution is the caller's word.
func TestAgentHoldsNoCredential(t *testing.T) {
	agentType := reflect.TypeFor[SidecarAgent]()
	for i := 0; i < agentType.NumField(); i += 1 {
		if field := agentType.Field(i); field.Type.Kind() != reflect.String {
			t.Errorf("SidecarAgent.%s is a %s, not a label", field.Name, field.Type)
		}
	}
	agent, err := ParseSidecarAgent("api-refactor")
	if err != nil || agent.Source() != SidecarAgentSourceAsserted {
		t.Fatalf("%+v %v", agent, err)
	}
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
	if response.Error == nil || response.Error.Code != daemonRpcInvalidParams {
		t.Errorf("an invalid agent ran: %+v", response.Error)
	}
	if agent, err := daemon.Agent(&DaemonHello{Mode: DaemonModeMcp, Cwd: home}); err != nil || agent.Label != "from-dot-ur" {
		t.Errorf("Agent: %+v %v", agent, err)
	}
}
