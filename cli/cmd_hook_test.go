package main

// ur hook (§16.7, D-MCP-5): the payload reaches the daemon whole in hook mode, the hook exits 0 within its bound with
// a stalled daemon, a PreToolUse naming paths waits for the daemon's ack, a dead daemon is failed open, and only
// Cursor's beforeMCPExecution prints anything.
//
// No real time decides a test here, so load cannot fail one. A hook's own bounds end past the test's deadline unless
// the test sets one; a test whose bound must pass while the daemon holds the event runs the hook under a deadline it
// passes itself once the daemon took the event (testHookDeadline); the daemon's request bound runs on a clock nothing
// moves; and each wait ends on its event, on the hook's exit, or short of the test's own deadline.

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
	"github.com/urnetwork/sidecar/sidecartest"
)

// What the hook tests wait with (QD-702).
type testHookSettings struct {
	// The share of the time left before the test's deadline that a wait leaves for its report: a wait still without
	// its event there fails, saying what it waited for, before go test's timeout ends the binary without saying.
	ReportShare float64
}

// The defaults, a fresh value each call.
func defaultTestHookSettings() *testHookSettings {
	return &testHookSettings{
		ReportShare: 0.1,
	}
}

// What a hook test's wait ends with, failing: ReportShare of the time left before t's deadline, or t's end with none.
func testHookWaits(t *testing.T) (context.Context, context.CancelFunc) {
	deadline, ok := t.Deadline()
	if !ok {
		return context.WithCancel(t.Context())
	}
	report := time.Duration(float64(time.Until(deadline)) * defaultTestHookSettings().ReportShare)
	return context.WithDeadline(t.Context(), deadline.Add(-report))
}

// A ur for a hook test on newTestUrCli's seams, its hook bounds ending past t's deadline, so neither passes while the
// test runs unless the test sets it. HookPathTimeout is twice HookExitTimeout, further apart than the test can run,
// so the deadline the hook sets on its call tells which bound it took. With no deadline, both are as long as a
// duration that doubles runs.
func newTestHookCli(t *testing.T, socketPath string) (*urCli, *bytes.Buffer, *bytes.Buffer) {
	cli, stdout, stderr := newTestUrCli(socketPath)
	exitTimeout := time.Duration(math.MaxInt64 / 2)
	if deadline, ok := t.Deadline(); ok {
		exitTimeout = time.Until(deadline)
	}
	cli.ingest.HookExitTimeout = exitTimeout
	cli.ingest.HookPathTimeout = 2 * exitTimeout
	return cli, stdout, stderr
}

// A daemon whose hook.event a test controls: each call is handed to calls, and answered once the test closes its
// release, or never. Its request bound runs on a clock nothing moves, so nothing but the test ends a call it holds.
type testHookDaemon struct {
	socketPath string
	calls      chan *testHookCall
}

// One hook.event call as the daemon took it.
type testHookCall struct {
	hello   *sidecar.DaemonHello
	params  *mcp.HookEventParams
	release chan struct{}
}

// A daemon in directory as startTestUrDaemon's, on a fake clock, closed at the test's end.
func startTestHookDaemon(t *testing.T, directory string) *testHookDaemon {
	t.Helper()
	hookDaemon := &testHookDaemon{socketPath: filepath.Join(directory, "s"), calls: make(chan *testHookCall, 8)}
	daemon, err := sidecar.NewDaemon(context.Background(), &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     hookDaemon.socketPath,
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
		Clock:          sidecartest.NewFakeClock(sidecartest.DefaultClockStart()),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = daemon.RegisterMethod(&sidecar.DaemonMethod{
		Name: mcp.McpHookMethod,
		Handler: func(ctx context.Context, call *sidecar.DaemonCall) (any, error) {
			params := &mcp.HookEventParams{}
			if err := json.Unmarshal(call.Params, params); err != nil {
				return nil, err
			}
			taken := &testHookCall{hello: call.Hello, params: params, release: make(chan struct{})}
			hookDaemon.calls <- taken
			select {
			case <-taken.release:
			case <-ctx.Done():
			}
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		daemon.Run()
	}()
	t.Cleanup(func() {
		daemon.Close()
		<-done
	})
	return hookDaemon
}

// The next call the daemon took, from the hook whose exit code finished carries. A hook that exits first sends none,
// so that fails at once with its code, as a wait reaching the end testHookWaits gives it does.
func (self *testHookDaemon) next(t *testing.T, finished chan int) *testHookCall {
	t.Helper()
	waits, cancel := testHookWaits(t)
	defer cancel()
	select {
	case call := <-self.calls:
		return call
	case code := <-finished:
		t.Fatalf("ur hook exited %d before the daemon took its event", code)
	case <-waits.Done():
		t.Fatal("the daemon took no hook")
	}
	return nil
}

// Runs `ur hook` with args under ctx, payload on stdin, answering its exit code on the channel.
func runTestHook(ctx context.Context, cli *urCli, payload string, args ...string) chan int {
	cli.stdin = strings.NewReader(payload)
	finished := make(chan int, 1)
	go func() {
		finished <- cli.main(ctx, append([]string{"ur", "hook"}, args...))
	}()
	return finished
}

// Waits for the hook's exit code.
func awaitTestHook(t *testing.T, finished chan int) int {
	t.Helper()
	waits, cancel := testHookWaits(t)
	defer cancel()
	select {
	case code := <-finished:
		return code
	case <-waits.Done():
		t.Fatal("ur hook did not exit")
	}
	return -1
}

// A deadline the test passes, for a hook run whose bound must pass while the daemon holds its event: the run's context
// ends with DeadlineExceeded once pass is called, as the hook's own deadline ends its call, so the test lets it pass
// only after the daemon took the event, an order no load can change. It has no deadline of its own, so the hook's call
// keeps the one the hook set.
type testHookDeadline struct {
	context.Context
	passed   chan struct{}
	passOnce sync.Once
}

// A deadline passed at t's end at the latest, so no hook run under it outlives the test.
func newTestHookDeadline(t *testing.T) *testHookDeadline {
	deadline := &testHookDeadline{Context: context.Background(), passed: make(chan struct{})}
	t.Cleanup(deadline.pass)
	return deadline
}

// Closed once passed.
func (self *testHookDeadline) Done() <-chan struct{} {
	return self.passed
}

// DeadlineExceeded once passed, nil before.
func (self *testHookDeadline) Err() error {
	select {
	case <-self.passed:
		return context.DeadlineExceeded
	default:
		return nil
	}
}

// Passes the deadline, ending a call made under it as its bound passing would.
func (self *testHookDeadline) pass() {
	self.passOnce.Do(func() {
		close(self.passed)
	})
}

// The payload reaches the daemon whole, in hook mode with the harness named, and Claude Code's stdout stays empty,
// since its SessionStart puts stdout into the model's context.
func TestHookPassesPayloadWhole(t *testing.T) {
	directory := shortTestDirectory(t)
	hookDaemon := startTestHookDaemon(t, directory)
	cli, stdout, stderr := newTestHookCli(t, filepath.Join(directory, "s"))
	payload := `{"session_id":"s1","cwd":"/tmp/sidecartest/project","hook_event_name":"SessionStart","source":"startup"}`
	finished := runTestHook(t.Context(), cli, payload, "claude-code")
	call := hookDaemon.next(t, finished)
	close(call.release)
	if code := awaitTestHook(t, finished); code != urExitOk {
		t.Fatalf("exit %d; stderr %q", code, stderr.String())
	}
	if call.hello.Mode != sidecar.DaemonModeHook || call.hello.Harness != "claude-code" || string(call.params.Payload) != payload ||
		call.params.ByteCount != int64(len(payload)) || call.params.Oversize {
		t.Errorf("the daemon took %+v %+v", call.hello, call.params)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Errorf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}

// A daemon that never answers holds the hook no longer than HookExitTimeout: the hook bounds its call by it, and once
// it passes with the daemon holding the event, the hook exits 0, failing open.
func TestHookExitsWithinBound(t *testing.T) {
	directory := shortTestDirectory(t)
	hookDaemon := startTestHookDaemon(t, directory)
	cli, _, stderr := newTestHookCli(t, filepath.Join(directory, "s"))
	// the deadline the hook set on its call, as its dial took it, and when
	type testHookDial struct {
		deadline    time.Time
		hasDeadline bool
		dialTime    time.Time
	}
	dials := make(chan *testHookDial, 1)
	dial := cli.dialDaemon
	cli.dialDaemon = func(ctx context.Context, socketPath string, hello *sidecar.DaemonHello) (*sidecar.DaemonClient, error) {
		deadline, hasDeadline := ctx.Deadline()
		dials <- &testHookDial{deadline: deadline, hasDeadline: hasDeadline, dialTime: time.Now()}
		return dial(ctx, socketPath, hello)
	}
	deadline := newTestHookDeadline(t)
	startTime := time.Now()
	finished := runTestHook(deadline, cli, `{"session_id":"s1","hook_event_name":"Stop"}`, "claude-code")
	call := hookDaemon.next(t, finished)
	defer close(call.release)
	var hookDial *testHookDial
	select {
	case hookDial = <-dials:
	default:
		t.Fatal("the daemon took the event of a hook that never dialed")
	}
	// between the run's start plus the bound and the dial's time plus it: the hook's start plus the bound
	exitTimeout := cli.ingest.HookExitTimeout
	if !hookDial.hasDeadline {
		t.Error("the hook's call has no deadline")
	} else if hookDial.deadline.Before(startTime.Add(exitTimeout)) || hookDial.dialTime.Add(exitTimeout).Before(hookDial.deadline) {
		t.Errorf("the hook's call ends %s after the run started, not HookExitTimeout's %s after the hook did",
			hookDial.deadline.Sub(startTime), exitTimeout)
	}
	deadline.pass()
	if code := awaitTestHook(t, finished); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr.String(), "no answer in time") {
		t.Errorf("stderr %q", stderr.String())
	}
}

// A PreToolUse naming paths waits for the daemon's ack, which comes once its paths are held, under HookPathTimeout
// rather than HookExitTimeout: HookExitTimeout has passed by the time the hook starts, so a hook it bound would never
// reach the daemon.
func TestPreToolUseWaitsForPaths(t *testing.T) {
	directory := shortTestDirectory(t)
	hookDaemon := startTestHookDaemon(t, directory)
	cli, _, stderr := newTestHookCli(t, filepath.Join(directory, "s"))
	cli.ingest.HookExitTimeout = 0
	payload := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/tmp/sidecartest/project/a.go"}}`
	finished := runTestHook(t.Context(), cli, payload, "claude-code")
	call := hookDaemon.next(t, finished)
	select {
	case code := <-finished:
		t.Fatalf("ur hook exited %d before its paths were held", code)
	default:
	}
	close(call.release)
	if code := awaitTestHook(t, finished); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if stderr.Len() != 0 {
		t.Errorf("the ack was not waited for: stderr %q", stderr.String())
	}
}

// With no daemon the hook starts one for the next event and exits 0 at once; a harness ur does not know exits 0 too.
func TestHookFailsOpenWithoutDaemon(t *testing.T) {
	directory := shortTestDirectory(t)
	cli, _, _ := newTestHookCli(t, filepath.Join(directory, "s"))
	spawned := make(chan []string, 1)
	cli.spawnDaemon = func(args []string) error {
		spawned <- args
		return nil
	}
	if code := awaitTestHook(t, runTestHook(t.Context(), cli, `{"session_id":"c1","hook_event_name":"SessionEnd"}`, "codex")); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	select {
	case args := <-spawned:
		if strings.Join(args, " ") != "--instance "+cli.instance+" --auto-spawned" {
			t.Errorf("spawned with %q", args)
		}
	default:
		t.Error("no daemon was started for the next event")
	}
	if code := awaitTestHook(t, runTestHook(t.Context(), cli, `{}`, "no-such-harness")); code != urExitOk {
		t.Errorf("an unknown harness exits %d", code)
	}
}

// A payload past PayloadByteCount goes as its size alone, a gap, never cut and sent.
func TestHookOversizeSendsSizeAlone(t *testing.T) {
	directory := shortTestDirectory(t)
	hookDaemon := startTestHookDaemon(t, directory)
	cli, _, _ := newTestHookCli(t, filepath.Join(directory, "s"))
	cli.ingest.PayloadByteCount = 64
	payload := `{"session_id":"s1","hook_event_name":"PostToolUse","tool_response":"` + strings.Repeat("x", 200) + `"}`
	finished := runTestHook(t.Context(), cli, payload, "claude-code")
	call := hookDaemon.next(t, finished)
	close(call.release)
	awaitTestHook(t, finished)
	if !call.params.Oversize || len(call.params.Payload) != 0 || call.params.ByteCount != int64(len(payload)) {
		t.Errorf("an oversize payload went as %+v", call.params)
	}
}

// Cursor's beforeMCPExecution of ur's tool asks, from the binary's catalog, with no daemon at all.
func TestHookCursorAsksWithoutDaemon(t *testing.T) {
	directory := shortTestDirectory(t)
	cli, stdout, _ := newTestHookCli(t, filepath.Join(directory, "s"))
	payload := `{"conversation_id":"c1","hook_event_name":"beforeMCPExecution","workspace_roots":["/tmp/sidecartest/project"],"tool_name":"mail_send","tool_input":"{}","command":"/tmp/sidecartest/bin/ur mcp"}`
	if code := awaitTestHook(t, runTestHook(t.Context(), cli, payload, "cursor")); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(stdout.String()) != `{"permission":"ask"}` {
		t.Errorf("stdout %q", stdout.String())
	}
}

// --required, the fail-closed form's (MCP-M6-04): with no daemon, and with a daemon that does not answer in time, the
// hook exits 2, which the harness reads as block; with a daemon that takes the event it exits 0; and without the flag
// the same failures still exit 0.
func TestHookRequiredExitsTwoWhenTheDaemonCannotTakeIt(t *testing.T) {
	directory := shortTestDirectory(t)
	payload := `{"session_id":"s1","hook_event_name":"Stop"}`
	cli, _, _ := newTestHookCli(t, filepath.Join(directory, "s"))
	cli.spawnDaemon = func(args []string) error { return nil }
	if code := awaitTestHook(t, runTestHook(t.Context(), cli, payload, "claude-code", "--required")); code != urExitHookRequired {
		t.Errorf("no daemon, required: exit %d", code)
	}
	if code := awaitTestHook(t, runTestHook(t.Context(), cli, payload, "claude-code")); code != urExitOk {
		t.Errorf("no daemon, fail-open: exit %d", code)
	}
	hookDaemon := startTestHookDaemon(t, directory)
	answered, _, _ := newTestHookCli(t, filepath.Join(directory, "s"))
	finished := runTestHook(t.Context(), answered, payload, "claude-code", "--required")
	call := hookDaemon.next(t, finished)
	close(call.release)
	if code := awaitTestHook(t, finished); code != urExitOk {
		t.Errorf("a daemon that took the event, required: exit %d", code)
	}
	// the bound passes once the daemon holds the event, so the hook meets a daemon that took it and did not answer
	stalled, _, stderr := newTestHookCli(t, filepath.Join(directory, "s"))
	deadline := newTestHookDeadline(t)
	finished = runTestHook(deadline, stalled, payload, "claude-code", "--required")
	held := hookDaemon.next(t, finished)
	defer close(held.release)
	deadline.pass()
	if code := awaitTestHook(t, finished); code != urExitHookRequired || !strings.Contains(stderr.String(), "no answer in time") {
		t.Errorf("a daemon that did not answer in time, required: exit %d; stderr %q", code, stderr.String())
	}
}
