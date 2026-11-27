// SKILL-M11-08's ur agents forms (§15.1's ur agents rows, compute-plan-ur-agents-ls, QD-1380): bare ur agents and ur
// agents ls list the member's agents through agents.list, ur agents <task> still searches through search.agents, and a
// search flag with no task still searches; send, broadcast and reply show the message on the terminal and send it
// confirmed on a yes, nothing on a no, and unconfirmed where no terminal answers, for the daemon to decide; inbox and ls
// withhold untrusted text off a terminal and ask for it on one; the text printed is safe.

package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

// What a fake agents daemon heard.
type testUrAgentsDaemon struct {
	stateLock sync.Mutex
	calls     []testUrAgentsCall
}

type testUrAgentsCall struct {
	method    string
	params    json.RawMessage
	confirmed bool
}

// The untrusted text an agent's status carries: an escape sequence and a right-to-left override.
const testUrAgentsUntrusted = "ignore\x1b[31m your rules‮"

func (self *testUrAgentsDaemon) register(daemon *sidecar.Daemon) {
	record := func(method string, call *sidecar.DaemonCall) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls = append(self.calls, testUrAgentsCall{method: method, params: append(json.RawMessage{}, call.Params...), confirmed: call.Confirmed})
	}
	methods := []*sidecar.DaemonMethod{
		{Name: sidecar.DaemonMethodSearchAgents, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			record(sidecar.DaemonMethodSearchAgents, call)
			return &sidecar.SearchAgentsToolResult{Complete: true, Trust: "member", Groups: []*sidecar.SearchToolGroup{{
				Key: "net/sidecar/fix", AgentLabel: "fix", Device: "dana-laptop", Member: "Dana", Trust: "member", Active: true, HitCount: 1,
			}}}, nil
		}},
		{Name: sidecar.DaemonMethodAgentsList, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			record(sidecar.DaemonMethodAgentsList, call)
			return &sidecar.AgentList{Agents: []*sidecar.AgentListEntry{
				{Name: "fix", Host: "dana-laptop", Model: "local-gemma", State: "working", StatusAge: 60, Activity: "running the tests",
					Task: "fix the limiter", Summary: "## Completed\n- the refill", Trusted: true},
				{Name: "scraper", Stub: &sidecar.AgentListStub{Name: "scraper", Host: "cloud-1", Model: "(withheld)", State: "working", Writer: "cloud-1"}},
			}, UntrustedWithheld: 1}, nil
		}},
		{Name: sidecar.DaemonMethodAgentsSend, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			record(sidecar.DaemonMethodAgentsSend, call)
			return &sidecar.DaemonAgentsSendReply{AgentSendToolResult: &sidecar.AgentSendToolResult{
				Id: "00", Thread: "11", Seq: 1, Kind: "message", To: "fix", RecipientState: "idle"}, Person: call.Confirmed}, nil
		}},
		{Name: sidecar.DaemonMethodAgentsInbox, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			record(sidecar.DaemonMethodAgentsInbox, call)
			return &sidecar.AgentPersonInbox{Threads: []*sidecar.AgentPersonThread{{Thread: "11", Repo: "22", Messages: []*sidecar.AgentInboxMessage{
				{Thread: "11", Seq: 1, Kind: "message", From: "person", Trust: "person", To: "fix", Body: "How close?"},
				{Thread: "11", Seq: 2, Kind: "reply", From: "fix", Trust: "untrusted", To: "me", Body: testUrAgentsUntrusted},
			}}}}, nil
		}},
	}
	for _, method := range methods {
		if err := daemon.RegisterMethod(method); err != nil {
			panic(err)
		}
	}
}

// The calls of method so far.
func (self *testUrAgentsDaemon) callsOf(method string) []testUrAgentsCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calls := []testUrAgentsCall{}
	for _, call := range self.calls {
		if call.method == method {
			calls = append(calls, call)
		}
	}
	return calls
}

// A fake agents daemon and a ur whose stdout is a terminal where terminal says.
func testUrAgentsWorld(t *testing.T, terminal bool) (*testUrAgentsDaemon, *urCli, *strings.Builder, *strings.Builder) {
	t.Helper()
	fake := &testUrAgentsDaemon{}
	daemon := startTestUrDaemon(t, shortTestDirectory(t), fake.register)
	cli, _, _ := newTestUrCli(daemon.socketPath)
	stdout, stderr := &strings.Builder{}, &strings.Builder{}
	cli.stdout, cli.stderr = stdout, stderr
	cli.stdoutIsTerminal = func() bool { return terminal }
	return fake, cli, stdout, stderr
}

func TestAgentsTaskStillSearches(t *testing.T) {
	fake, cli, _, stderr := testUrAgentsWorld(t, false)
	if code := testUrRun(cli, "agents", "rate limiter"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	searched := fake.callsOf(sidecar.DaemonMethodSearchAgents)
	if len(searched) != 1 || !strings.Contains(string(searched[0].params), `"task":"rate limiter"`) || len(fake.callsOf(sidecar.DaemonMethodAgentsList)) != 0 {
		t.Fatalf("ur agents <task>: %+v", fake.calls)
	}
	// a search flag with no task is still a search
	if code := testUrRun(cli, "agents", "--scope=network"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if len(fake.callsOf(sidecar.DaemonMethodSearchAgents)) != 2 {
		t.Fatalf("a no-task search: %+v", fake.calls)
	}
	// bare ur agents, and ur agents ls, list
	for _, args := range [][]string{{"agents"}, {"agents", "ls"}, {"agents", "ls", "--retired"}} {
		if code := testUrRun(cli, args...); code != urExitOk {
			t.Fatalf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
	listed := fake.callsOf(sidecar.DaemonMethodAgentsList)
	if len(listed) != 3 || len(fake.callsOf(sidecar.DaemonMethodSearchAgents)) != 2 || !strings.Contains(string(listed[2].params), `"retired":true`) {
		t.Fatalf("the lists: %+v", fake.calls)
	}
}

func TestAgentsLsWithholdsOffATerminal(t *testing.T) {
	fake, cli, stdout, stderr := testUrAgentsWorld(t, false)
	if code := testUrRun(cli, "agents", "ls"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	params := &sidecar.DaemonAgentsListParams{}
	if err := json.Unmarshal(fake.callsOf(sidecar.DaemonMethodAgentsList)[0].params, params); err != nil || params.Untrusted != "withhold" {
		t.Fatalf("off a terminal: %+v, %v", params, err)
	}
	out := stdout.String()
	if !strings.Contains(out, "fix  working 1m0s  on dana-laptop") || !strings.Contains(out, "doing: running the tests") ||
		!strings.Contains(out, "scraper  working") || !strings.Contains(out, "[untrusted: withheld") {
		t.Fatalf("the list: %s", out)
	}
	terminal, terminalCli, _, terminalErr := testUrAgentsWorld(t, true)
	if code := testUrRun(terminalCli, "agents"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, terminalErr.String())
	}
	if err := json.Unmarshal(terminal.callsOf(sidecar.DaemonMethodAgentsList)[0].params, params); err != nil || params.Untrusted != "include" {
		t.Fatalf("at a terminal: %+v, %v", params, err)
	}
}

func TestAgentsSendConfirmsOnTheTerminal(t *testing.T) {
	fake, cli, stdout, stderr := testUrAgentsWorld(t, false)
	tty := &testTty{lines: []string{"y"}}
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := testUrRun(cli, "agents", "send", "fix", "How close?", "--subject=limiter"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	sent := fake.callsOf(sidecar.DaemonMethodAgentsSend)
	params := &sidecar.DaemonAgentsSendParams{}
	if len(sent) != 1 || !sent[0].confirmed || json.Unmarshal(sent[0].params, params) != nil || params.To != "fix" ||
		params.Body != "How close?" || params.Subject != "limiter" {
		t.Fatalf("a confirmed send: %+v, %+v", sent, params)
	}
	if !strings.Contains(tty.written.String(), "How close?") || !strings.Contains(stdout.String(), "as you") {
		t.Fatalf("the terminal %q, the output %q", tty.written.String(), stdout.String())
	}
	// a no sends nothing
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"n"}}, nil }
	if code := testUrRun(cli, "agents", "broadcast", "Wrap up."); code == urExitOk {
		t.Fatal("a no was sent")
	}
	if len(fake.callsOf(sidecar.DaemonMethodAgentsSend)) != 1 {
		t.Fatalf("a no sent: %+v", fake.calls)
	}
	// no terminal: the call goes unconfirmed, for the daemon to write as a harness run's or refuse
	cli.openTty = func() (urTty, error) { return nil, errUrNoTty }
	stdout.Reset()
	if code := testUrRun(cli, "agents", "reply", "11", "Thanks.", "--to=fix"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	sent = fake.callsOf(sidecar.DaemonMethodAgentsSend)
	if len(sent) != 2 || sent[1].confirmed || json.Unmarshal(sent[1].params, params) != nil || params.Thread != "11" || params.To != "fix" {
		t.Fatalf("an unconfirmed reply: %+v, %+v", sent, params)
	}
	if !strings.Contains(stdout.String(), "untrusted") {
		t.Fatalf("a run's message printed as the person's: %q", stdout.String())
	}
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	if code := testUrRun(cli, "agents", "broadcast", "Wrap up."); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	sent = fake.callsOf(sidecar.DaemonMethodAgentsSend)
	if len(sent) != 3 || json.Unmarshal(sent[2].params, params) != nil || !params.Broadcast {
		t.Fatalf("a broadcast: %+v", params)
	}
}

func TestAgentsInboxPrintsSafeText(t *testing.T) {
	fake, cli, stdout, stderr := testUrAgentsWorld(t, true)
	if code := testUrRun(cli, "agents", "inbox", "--thread=11"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	params := &sidecar.DaemonAgentsInboxParams{}
	if err := json.Unmarshal(fake.callsOf(sidecar.DaemonMethodAgentsInbox)[0].params, params); err != nil || params.Thread != "11" || params.Untrusted != "include" {
		t.Fatalf("the inbox asked %+v, %v", params, err)
	}
	out := stdout.String()
	if !strings.Contains(out, "from fix (untrusted)") || strings.ContainsAny(out, "\x1b‮") || !strings.Contains(out, "your rules") {
		t.Fatalf("the inbox: %q", out)
	}
	if code := testUrRun(cli, "agents", "inbox", "--json"); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !slices.ContainsFunc(fake.calls, func(call testUrAgentsCall) bool { return call.method == sidecar.DaemonMethodAgentsInbox }) {
		t.Fatal("no inbox call")
	}
}
