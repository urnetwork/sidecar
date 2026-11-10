package main

// ur hook (§16.7, D-MCP-5): the payload reaches the daemon whole in hook mode, the hook exits 0 within its bound with
// a stalled daemon, a PreToolUse naming paths waits for the daemon's ack, a dead daemon is failed open, and only
// Cursor's beforeMCPExecution prints anything.

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

// A daemon whose hook.event a test controls: each call is handed to calls, and answered when the test sends on its
// release, or never.
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

func startTestHookDaemon(t *testing.T, directory string) *testHookDaemon {
	t.Helper()
	hookDaemon := &testHookDaemon{calls: make(chan *testHookCall, 8)}
	daemon := startTestUrDaemon(t, directory, func(daemon *sidecar.Daemon) {
		daemon.RegisterMethod(&sidecar.DaemonMethod{
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
	})
	hookDaemon.socketPath = daemon.socketPath
	return hookDaemon
}

// The next call the daemon took.
func (self *testHookDaemon) next(t *testing.T) *testHookCall {
	t.Helper()
	select {
	case call := <-self.calls:
		return call
	case <-time.After(urTestTimeout):
		t.Fatal("the daemon took no hook")
	}
	return nil
}

// Runs `ur hook <harness>` with payload on stdin, answering its exit code on the channel.
func runTestHook(cli *urCli, harness string, payload string) chan int {
	cli.stdin = strings.NewReader(payload)
	finished := make(chan int, 1)
	go func() {
		finished <- cli.main(context.Background(), []string{"ur", "hook", harness})
	}()
	return finished
}

// Waits for the hook's exit code.
func awaitTestHook(t *testing.T, finished chan int) int {
	t.Helper()
	select {
	case code := <-finished:
		return code
	case <-time.After(urTestTimeout):
		t.Fatal("ur hook did not exit")
	}
	return -1
}

// The payload reaches the daemon whole, in hook mode with the harness named, and Claude Code's stdout stays empty,
// since its SessionStart puts stdout into the model's context.
func TestHookPassesPayloadWhole(t *testing.T) {
	directory := shortTestDirectory(t)
	hookDaemon := startTestHookDaemon(t, directory)
	cli, stdout, stderr := newTestUrCli(filepath.Join(directory, "s"))
	payload := `{"session_id":"s1","cwd":"/tmp/sidecartest/project","hook_event_name":"SessionStart","source":"startup"}`
	finished := runTestHook(cli, "claude-code", payload)
	call := hookDaemon.next(t)
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

// A daemon that never answers holds the hook no longer than HookExitTimeout: it exits 0, failing open.
func TestHookExitsWithinBound(t *testing.T) {
	directory := shortTestDirectory(t)
	hookDaemon := startTestHookDaemon(t, directory)
	cli, _, stderr := newTestUrCli(filepath.Join(directory, "s"))
	cli.ingest.HookExitTimeout = time.Millisecond
	finished := runTestHook(cli, "claude-code", `{"session_id":"s1","hook_event_name":"Stop"}`)
	call := hookDaemon.next(t)
	defer close(call.release)
	if code := awaitTestHook(t, finished); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr.String(), "no answer in time") {
		t.Errorf("stderr %q", stderr.String())
	}
}

// A PreToolUse naming paths waits for the daemon's ack, which comes once its paths are held, under HookPathTimeout
// rather than HookExitTimeout.
func TestPreToolUseWaitsForPaths(t *testing.T) {
	directory := shortTestDirectory(t)
	hookDaemon := startTestHookDaemon(t, directory)
	cli, _, stderr := newTestUrCli(filepath.Join(directory, "s"))
	cli.ingest.HookExitTimeout = time.Millisecond
	cli.ingest.HookPathTimeout = urTestTimeout
	payload := `{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/tmp/sidecartest/project/a.go"}}`
	finished := runTestHook(cli, "claude-code", payload)
	call := hookDaemon.next(t)
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
	cli, _, _ := newTestUrCli(filepath.Join(directory, "s"))
	spawned := make(chan []string, 1)
	cli.spawnDaemon = func(args []string) error {
		spawned <- args
		return nil
	}
	if code := awaitTestHook(t, runTestHook(cli, "codex", `{"session_id":"c1","hook_event_name":"SessionEnd"}`)); code != urExitOk {
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
	if code := awaitTestHook(t, runTestHook(cli, "no-such-harness", `{}`)); code != urExitOk {
		t.Errorf("an unknown harness exits %d", code)
	}
}

// A payload past PayloadByteCount goes as its size alone, a gap, never cut and sent.
func TestHookOversizeSendsSizeAlone(t *testing.T) {
	directory := shortTestDirectory(t)
	hookDaemon := startTestHookDaemon(t, directory)
	cli, _, _ := newTestUrCli(filepath.Join(directory, "s"))
	cli.ingest.PayloadByteCount = 64
	payload := `{"session_id":"s1","hook_event_name":"PostToolUse","tool_response":"` + strings.Repeat("x", 200) + `"}`
	finished := runTestHook(cli, "claude-code", payload)
	call := hookDaemon.next(t)
	close(call.release)
	awaitTestHook(t, finished)
	if !call.params.Oversize || len(call.params.Payload) != 0 || call.params.ByteCount != int64(len(payload)) {
		t.Errorf("an oversize payload went as %+v", call.params)
	}
}

// Cursor's beforeMCPExecution of ur's tool asks, from the binary's catalog, with no daemon at all.
func TestHookCursorAsksWithoutDaemon(t *testing.T) {
	directory := shortTestDirectory(t)
	cli, stdout, _ := newTestUrCli(filepath.Join(directory, "s"))
	payload := `{"conversation_id":"c1","hook_event_name":"beforeMCPExecution","workspace_roots":["/tmp/sidecartest/project"],"tool_name":"mail_send","tool_input":"{}","command":"/tmp/sidecartest/bin/ur mcp"}`
	if code := awaitTestHook(t, runTestHook(cli, "cursor", payload)); code != urExitOk {
		t.Fatalf("exit %d", code)
	}
	if strings.TrimSpace(stdout.String()) != `{"permission":"ask"}` {
		t.Errorf("stdout %q", stdout.String())
	}
}
