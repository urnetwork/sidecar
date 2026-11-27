//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
)

// DESIGN-COMPUTE §8.9's binding at the gateway (GW-M12-02): a bound call's run and union are its process's; an unbound
// call's union is over its grant's live harness processes alone, its run the grant's own, tainted; and every way the
// union cannot be read refuses the call, as the router's marks do.

// A process table a test fills: each pid's process, a missing one exited.
type testGatewayProcessTable struct {
	stateLock    sync.Mutex
	pidProcesses map[int]*ProcessInfo
}

func (self *testGatewayProcessTable) Process(pid int) (*ProcessInfo, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	process, ok := self.pidProcesses[pid]
	if !ok {
		return nil, ErrProcessUnknown
	}
	copied := *process
	return &copied, nil
}

// An unbound token's call is checked against the union over the grant's live harness processes, the handles of its
// live tokens whose processes still run, and records into the grant's own run, tainted from its start; a bound token's
// over its own process; and a union that does not read, or no binder, refuses the call.
func TestUnboundTokenUnionOfLiveRuns(t *testing.T) {
	world := newTestGatewayWorld(t, false)
	table := &testGatewayProcessTable{pidProcesses: map[int]*ProcessInfo{}}
	world.server.processes = table
	grant := world.make(&GatewayGrantsParams{Harness: "codex"}).Grants[0].Grant
	live := &GatewayRunHandle{Process: ProcessIdentity{Pid: 501, StartMillis: 10}, Above: []ProcessIdentity{{Pid: 400, StartMillis: 1}}}
	exited := &GatewayRunHandle{Process: ProcessIdentity{Pid: 502, StartMillis: 11}}
	reused := &GatewayRunHandle{Process: ProcessIdentity{Pid: 503, StartMillis: 12}}
	table.pidProcesses[501] = &ProcessInfo{Identity: live.Process, Name: "codex"}
	table.pidProcesses[503] = &ProcessInfo{Identity: ProcessIdentity{Pid: 503, StartMillis: 99}, Name: "codex"}
	tokens := map[string]string{}
	for name, handle := range map[string]*GatewayRunHandle{"live": live, "exited": exited, "reused": reused, "unbound": nil} {
		token, _, err := world.network.grants.Mint(context.Background(), grant.GrantId, handle)
		if err != nil {
			t.Fatal(err)
		}
		tokens[name] = token
	}
	callerOf := func(name string) *GatewayCaller {
		t.Helper()
		grant, record, err := world.network.grants.Authenticate(GatewayTokenSha256(tokens[name]))
		if err != nil {
			t.Fatal(err)
		}
		return &GatewayCaller{NetworkId: testNetworkId, Network: world.network, Store: world.network.grants, Grant: grant, Token: record}
	}

	if _, err := world.server.BindCall(context.Background(), callerOf("unbound"), ""); !errors.Is(err, ErrGatewayNoBinder) {
		t.Fatalf("no binder: %v", err)
	}
	boundRunId := NewId()
	binder := &testGatewayBinder{runId: boundRunId, union: &GatewayRunUnion{Tainted: true, Marks: []string{inferMarkLimitedUse}}}
	world.server.SetRunBinder(binder)

	binding, err := world.server.BindCall(context.Background(), callerOf("unbound"), "a-session")
	if err != nil {
		t.Fatal(err)
	}
	if len(binder.unions) != 1 || len(binder.unions[0]) != 1 || binder.unions[0][0].Key() != live.Key() {
		t.Fatalf("the unbound union was over %+v, want the live handle alone", binder.unions)
	}
	if binding.Handle != "" || !binding.Tainted || !slices.Equal(binding.Marks, []string{inferMarkLimitedUse}) || binding.GrantId != grant.GrantId ||
		binding.AgentId != grant.AgentId || binding.RunId == (Id{}) || binding.RunId == boundRunId {
		t.Fatalf("the unbound binding: %+v", binding)
	}
	if !world.network.runs.Tainted(binding.RunId) || !slices.Contains(world.network.runs.TaintReasons(binding.RunId), RunTaintUntrustedData) {
		t.Fatal("the grant's run of unbound calls is not tainted untrusted_data")
	}
	again, err := world.server.BindCall(context.Background(), callerOf("unbound"), "")
	if err != nil || again.RunId != binding.RunId {
		t.Fatalf("a second unbound call records elsewhere: %+v %v", again, err)
	}
	marks, err := world.server.BindingMarks(context.Background(), binding.InferBinding())
	if err != nil || !slices.Equal(marks, []string{inferMarkLimitedUse}) {
		t.Fatalf("the router's unbound marks: %v %v", marks, err)
	}

	bound, err := world.server.BindCall(context.Background(), callerOf("live"), "")
	if err != nil {
		t.Fatal(err)
	}
	last := binder.unions[len(binder.unions)-1]
	if bound.RunId != boundRunId || bound.Handle != live.Key() || len(last) != 1 || last[0].Key() != live.Key() || last[0].Above[0] != live.Above[0] {
		t.Fatalf("the bound binding %+v over %+v", bound, last)
	}
	if marks, err := world.server.BindingMarks(context.Background(), bound.InferBinding()); err != nil || len(marks) != 1 {
		t.Fatalf("the router's bound marks: %v %v", marks, err)
	}
	if _, err := world.server.BindingMarks(context.Background(), &InferBinding{GrantId: grant.GrantId, Handle: "777@1"}); err == nil {
		t.Fatal("marks of a handle no live token is")
	}
	if _, err := world.server.BindingMarks(context.Background(), &InferBinding{GrantId: NewId()}); !errors.Is(err, ErrGatewayGrantUnknown) {
		t.Fatalf("marks of a grant the gateway holds none of: %v", err)
	}

	binder.unionErr = ErrRunMarksUnread
	if _, err := world.server.BindCall(context.Background(), callerOf("live"), ""); !errors.Is(err, ErrRunMarksUnread) {
		t.Fatalf("a union that does not read: %v", err)
	}
	if _, err := world.server.BindingMarks(context.Background(), binding.InferBinding()); !errors.Is(err, ErrRunMarksUnread) {
		t.Fatalf("the router's marks when the union does not read: %v", err)
	}
}

// A process name reads as a harness's where it is one of the harness's names, or one of them and "-" and more, in any
// case, without .exe; nothing else does.
func TestHarnessProcessNames(t *testing.T) {
	names := DefaultGatewaySettings().HarnessProcessNames
	for _, each := range []struct {
		harness string
		name    string
		matches bool
	}{
		{harness: "codex", name: "codex", matches: true},
		{harness: "codex", name: "codex-aarch64-ap", matches: true},
		{harness: "codex", name: "Codex.exe", matches: true},
		{harness: "codex", name: "codexx", matches: false},
		{harness: "codex", name: "zsh", matches: false},
		{harness: "claude-code", name: "claude", matches: true},
		{harness: "claude-code", name: "node", matches: true},
		{harness: "claude-code", name: "iTerm2", matches: false},
		{harness: "opencode", name: "opencode", matches: false},
	} {
		if gatewayHarnessNameMatches(names[each.harness], each.name) != each.matches {
			t.Errorf("%s %s: want %v", each.harness, each.name, each.matches)
		}
	}
}
