package main

import (
	"context"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/docopt/docopt-go"

	"github.com/urnetwork/sidecar"
)

// One call a test's fake harness methods took.
type testUrHarnessCall struct {
	method    string
	params    json.RawMessage
	confirmed bool
}

// The daemon's harness methods as a test fakes them: harness.agent answers one agent, harness.events answers the
// replies the test queues in order, and every call is recorded with its confirmation; harness.close queues closed.
type testUrHarnessDaemon struct {
	agent   *sidecar.HarnessAgentReply
	replies chan *sidecar.HarnessEventsReply
	called  chan testUrHarnessCall

	stateLock sync.Mutex
	calls     []testUrHarnessCall
}

func newTestUrHarnessDaemon() *testUrHarnessDaemon {
	return &testUrHarnessDaemon{
		agent: &sidecar.HarnessAgentReply{Agent: sidecar.NewId().String(), Name: "helper", Run: sidecar.NewId().String(),
			Model: "engy-glm-5.2-high", Created: true},
		replies: make(chan *sidecar.HarnessEventsReply, 64),
		called:  make(chan testUrHarnessCall, 64),
	}
}

// Records a call.
func (self *testUrHarnessDaemon) record(name string, call *sidecar.DaemonCall) {
	recorded := testUrHarnessCall{method: name, params: call.Params, confirmed: call.Confirmed}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls = append(self.calls, recorded)
	}()
	self.called <- recorded
}

// The calls of method, in order.
func (self *testUrHarnessDaemon) callsOf(method string) []testUrHarnessCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	calls := []testUrHarnessCall{}
	for _, call := range self.calls {
		if call.method == method {
			calls = append(calls, call)
		}
	}
	return calls
}

// Waits for the next call of method, failing past the test's bound.
func (self *testUrHarnessDaemon) await(t *testing.T, method string) testUrHarnessCall {
	t.Helper()
	deadline := time.After(urTestTimeout)
	for {
		select {
		case call := <-self.called:
			if call.method == method {
				return call
			}
		case <-deadline:
			t.Fatalf("no %s call", method)
		}
	}
}

// Registers the fakes on daemon.
func (self *testUrHarnessDaemon) register(daemon *sidecar.Daemon) {
	answered := func(name string, answer func(ctx context.Context, call *sidecar.DaemonCall) (any, error)) *sidecar.DaemonMethod {
		return &sidecar.DaemonMethod{Name: name, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			self.record(name, call)
			return answer(ctx, call)
		}}
	}
	methods := []*sidecar.DaemonMethod{
		answered(sidecar.HarnessDaemonMethodAgent, func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			return self.agent, nil
		}),
		answered(sidecar.HarnessDaemonMethodPrompt, func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			return &sidecar.HarnessPromptReply{Disposition: sidecar.HarnessPromptStarted, Untrusted: !call.Confirmed}, nil
		}),
		{Name: sidecar.HarnessDaemonMethodEvents, Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			select {
			case reply := <-self.replies:
				return reply, nil
			case <-call.SessionDone:
				return &sidecar.HarnessEventsReply{Events: []json.RawMessage{}}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}},
		answered(sidecar.HarnessDaemonMethodRespondUi, func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			return nil, nil
		}),
		answered(sidecar.HarnessDaemonMethodClose, func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			self.replies <- &sidecar.HarnessEventsReply{Events: []json.RawMessage{}, Closed: true}
			return nil, nil
		}),
	}
	for _, method := range methods {
		if err := daemon.RegisterMethod(method); err != nil {
			panic(err)
		}
	}
}

// Queues one events reply of raw events.
func (self *testUrHarnessDaemon) queue(next uint64, closed bool, raws ...string) {
	events := []json.RawMessage{}
	for _, raw := range raws {
		events = append(events, json.RawMessage(raw))
	}
	self.replies <- &sidecar.HarnessEventsReply{Events: events, Next: next, Closed: closed}
}

// A terminal whose lines a test feeds one at a time, closing lines for the end of input.
type testUrHarnessTty struct {
	lines chan string
}

func (self *testUrHarnessTty) Write(p []byte) (int, error) {
	return len(p), nil
}

func (self *testUrHarnessTty) readSecretLine() ([]byte, error) {
	line, err := self.readLine()
	return []byte(line), err
}

func (self *testUrHarnessTty) readLine() (string, error) {
	line, ok := <-self.lines
	if !ok {
		return "", io.EOF
	}
	return line, nil
}

func (self *testUrHarnessTty) Close() error {
	return nil
}

// Whether text holds a C0 control but a newline, DEL or a C1 control.
func testUrHarnessHoldsControl(text string) bool {
	for _, r := range text {
		if (r < 0x20 && r != '\n') || r == 0x7f || (0x80 <= r && r <= 0x9f) || r == utf8.RuneError {
			return true
		}
	}
	return false
}

// --json prints each event raw, one a line: the same JSON value the daemon sent, a member this build does not know
// kept, with nothing a terminal reads as a control; and a line from stdin, no terminal, goes unconfirmed, an unknown
// run's.
func TestUrHarnessJsonPassesEventsRaw(t *testing.T) {
	fake := newTestUrHarnessDaemon()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), fake.register)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	stdout := newSyncBuffer()
	cli.stdout = stdout
	cli.stdin = strings.NewReader("hello there\n")
	agent := fake.agent.Agent
	raws := []string{
		`{"type":"agent_start","agent":"` + agent + `","seq":1}`,
		`{"type":"message_update","agent":"` + agent + `","seq":2,"usage":{"input":1},"assistantMessageEvent":{"type":"text_delta","contentIndex":0,"delta":"hi \u001b[2J"},"futureMember":{"kept":[1,2]}}`,
		"{\"type\":\"message_end\",\"agent\":\"" + agent + "\",\"seq\":3,\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"text\",\"text\":\"a\u009b2J‮b\"}]}}",
		`{"type":"agent_settled","agent":"` + agent + `","seq":4,"aborted":false,"stopReason":"ended"}`,
	}
	fake.queue(4, false, raws...)
	fake.queue(4, true)
	if code := cli.main(context.Background(), []string{"ur", "harness", "--json"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n")
	if len(lines) != len(raws) {
		t.Fatalf("%d lines for %d events:\n%s", len(lines), len(raws), stdout.String())
	}
	for i, line := range lines {
		sent, printed := any(nil), any(nil)
		if err := json.Unmarshal([]byte(raws[i]), &sent); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(line), &printed); err != nil {
			t.Fatalf("line %d is no JSON: %q", i, line)
		}
		if !reflect.DeepEqual(sent, printed) {
			t.Errorf("line %d: %v, sent %v", i, printed, sent)
		}
		if testUrHarnessHoldsControl(line) {
			t.Errorf("line %d holds a control: %q", i, line)
		}
	}
	if !strings.Contains(lines[1], `"futureMember"`) {
		t.Errorf("a member this build does not know was dropped: %s", lines[1])
	}
	prompts := fake.callsOf(sidecar.HarnessDaemonMethodPrompt)
	if len(prompts) != 1 || prompts[0].confirmed || !strings.Contains(string(prompts[0].params), "hello there") {
		t.Fatalf("prompts %+v", prompts)
	}
	if strings.Contains(stdout.String(), "unknown run") {
		t.Fatal("the view's own lines reached stdout under --json")
	}
}

// A line read from /dev/tty goes confirmed, the person's where no harness process is among ur's ancestors, as does the
// call that finds the agent; one read from stdin goes unconfirmed.
func TestUrHarnessInputFromTtyIsConfirmed(t *testing.T) {
	fake := newTestUrHarnessDaemon()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), fake.register)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	tty := &testUrHarnessTty{lines: make(chan string, 4)}
	tty.lines <- "hello from the person"
	tty.lines <- "/quit"
	cli.openTty = func() (urTty, error) { return tty, nil }
	if code := cli.main(context.Background(), []string{"ur", "harness", "--agent=helper"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	agents := fake.callsOf(sidecar.HarnessDaemonMethodAgent)
	prompts := fake.callsOf(sidecar.HarnessDaemonMethodPrompt)
	if len(agents) != 1 || !agents[0].confirmed || !strings.Contains(string(agents[0].params), `"name":"helper"`) {
		t.Fatalf("agent calls %+v", agents)
	}
	if len(prompts) != 1 || !prompts[0].confirmed {
		t.Fatalf("prompt calls %+v", prompts)
	}
	events := fake.callsOf(sidecar.HarnessDaemonMethodEvents)
	for _, call := range events {
		if !call.confirmed {
			t.Errorf("the person's view polled unconfirmed: %+v", call)
		}
	}
}

// A dialog takes the next line: a select's option by number goes back as a ui_response; a disclosure whose text this
// build cannot read is not acknowledged by "I understand", and an empty line declines it, Not now; /close ends the run.
func TestUrHarnessViewAnswersDialogsAndCloses(t *testing.T) {
	fake := newTestUrHarnessDaemon()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), fake.register)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	stdout := newSyncBuffer()
	cli.stdout = stdout
	tty := &testUrHarnessTty{lines: make(chan string)}
	cli.openTty = func() (urTty, error) { return tty, nil }
	agent := fake.agent.Agent
	finished := make(chan int, 1)
	go func() {
		finished <- cli.main(context.Background(), []string{"ur", "harness"})
	}()

	fake.queue(1, false, `{"type":"ui_request","agent":"`+agent+`","seq":1,"id":"ask_1","method":"select","title":"The model failed","options":["retry","another model","local"]}`)
	stdout.awaitContains(t, "2. another model")
	tty.lines <- "2"
	answer := fake.await(t, sidecar.HarnessDaemonMethodRespondUi)
	response := &sidecar.HarnessRespondUiParams{}
	if err := json.Unmarshal(answer.params, response); err != nil || !answer.confirmed || response.Response == nil ||
		response.Response.Value == nil || *response.Response.Value != "another model" {
		t.Fatalf("the answer %+v %+v", answer, response.Response)
	}

	fake.queue(2, false, `{"type":"ui_request","agent":"`+agent+`","seq":2,"id":"ask_2","method":"disclosure","disclosureId":"inference:engy","disclosureVersion":1}`)
	stdout.awaitContains(t, "not available here")
	tty.lines <- "I understand"
	stdout.awaitContains(t, "cannot be acknowledged here: acknowledge it in the app")
	tty.lines <- ""
	decline := fake.await(t, sidecar.HarnessDaemonMethodRespondUi)
	if err := json.Unmarshal(decline.params, response); err != nil || response.Response.Value == nil ||
		*response.Response.Value != sidecar.HarnessUiDisclosureDecline || response.Response.Acknowledged {
		t.Fatalf("the decline %+v", response.Response)
	}

	tty.lines <- "/close"
	fake.await(t, sidecar.HarnessDaemonMethodClose)
	select {
	case code := <-finished:
		if code != urExitOk {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
	case <-time.After(urTestTimeout):
		t.Fatal("the view did not end at /close")
	}
	if n := len(fake.callsOf(sidecar.HarnessDaemonMethodRespondUi)); n != 2 {
		t.Fatalf("%d answers went back", n)
	}
}

// --enclave refuses until the attach lands, reaching no daemon.
func TestUrHarnessEnclaveRefusesUntilAttachLands(t *testing.T) {
	fake := newTestUrHarnessDaemon()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), fake.register)
	cli, _, stderr := newTestUrCli(daemon.socketPath)
	if code := cli.main(context.Background(), []string{"ur", "harness", "--enclave=build1"}); code != urExitFailed {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr.String(), errUrHarnessAttachNotBuilt.Error()) {
		t.Fatalf("stderr %q", stderr.String())
	}
	fake.stateLock.Lock()
	defer fake.stateLock.Unlock()
	if len(fake.calls) != 0 {
		t.Fatalf("calls %+v", fake.calls)
	}
}

// What the test subcommand ran with, each run.
var testUrHarnessProbeRan = make(chan docopt.Opts, 16)

// A subcommand registered from its own file joins ur harness's usage and runs on its own words; a second registration
// of its name, or a usage line not its own, panics.
func TestUrHarnessSubcommandsRegisterThroughTheTable(t *testing.T) {
	const name = "probe-test"
	// registered once for every run of the test, so it records into the channel each run reads
	if urHarnessSubcommands[name] == nil {
		registerUrHarnessSubcommand(&urHarnessSubcommand{
			name:  name,
			usage: "  ur harness " + name + " [--flag]",
			run: func(ctx context.Context, cli *urCli, options docopt.Opts) error {
				testUrHarnessProbeRan <- options
				return nil
			},
		})
	}
	if !strings.Contains(urCommands["harness"].usage, "ur harness "+name+" [--flag]") {
		t.Fatalf("the usage lacks the subcommand:\n%s", urCommands["harness"].usage)
	}
	cli, stdout, stderr := newTestUrCli(shortTestDirectory(t) + "/none")
	if code := cli.main(context.Background(), []string{"ur", "harness", name, "--flag"}); code != urExitOk {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	select {
	case ran := <-testUrHarnessProbeRan:
		if flag, _ := ran.Bool("--flag"); !flag {
			t.Fatalf("the subcommand ran with %v", ran)
		}
	default:
		t.Fatal("the subcommand did not run")
	}
	if code := cli.main(context.Background(), []string{"ur", "harness", "--help"}); code != urExitOk || !strings.Contains(stdout.String(), name) {
		t.Fatalf("help: %d %s", code, stdout.String())
	}
	for _, subcommand := range []*urHarnessSubcommand{
		{name: name, usage: "  ur harness " + name, run: func(ctx context.Context, cli *urCli, options docopt.Opts) error { return nil }},
		{name: "probe-other", usage: "  ur harness elsewhere", run: func(ctx context.Context, cli *urCli, options docopt.Opts) error { return nil }},
	} {
		panicked := func() (panicked bool) {
			defer func() {
				panicked = recover() != nil
			}()
			registerUrHarnessSubcommand(subcommand)
			return false
		}()
		if !panicked {
			t.Errorf("registering %q did not panic", subcommand.name)
		}
	}
}
