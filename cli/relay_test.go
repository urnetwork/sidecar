package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
)

// With no daemon answering, the relay spawns one, once, with the instance and the auto-spawned flag, and dials until
// it answers.
func TestRelaySpawnsDaemonOnce(t *testing.T) {
	directory := shortTestDirectory(t)
	cli, _, stderr := newTestUrCli(filepath.Join(directory, "s"))
	stdout := newSyncBuffer()
	cli.stdout = stdout
	var spawns atomic.Int32
	var spawnArgs []string
	cli.spawnDaemon = func(args []string) error {
		spawns.Add(1)
		spawnArgs = args
		startTestUrDaemon(t, directory, echoMcpMode)
		return nil
	}
	pipeReader, pipeWriter := io.Pipe()
	cli.stdin = pipeReader
	finished := make(chan int, 1)
	go func() {
		finished <- cli.main(context.Background(), []string{"ur", "--instance", "work", "mcp"})
	}()
	io.WriteString(pipeWriter, "ping\n")
	stdout.awaitContains(t, "echo: ping")
	pipeWriter.Close()
	select {
	case code := <-finished:
		if code != urExitOk {
			t.Errorf("exit %d; stderr %q", code, stderr.String())
		}
	case <-time.After(urTestTimeout):
		t.Fatal("the relay did not end")
	}
	if spawns.Load() != 1 {
		t.Errorf("spawned %d times", spawns.Load())
	}
	if strings.Join(spawnArgs, " ") != "--instance work --auto-spawned" {
		t.Errorf("spawned with %q", spawnArgs)
	}
}

// A relay that cannot reach a daemon says so on stderr; stdout, which the harness reads as MCP, stays empty.
func TestRelayNeverWritesLogsToStdout(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, cli *urCli, directory string)
	}{
		{name: "no daemon starts", setup: func(t *testing.T, cli *urCli, directory string) {
			cli.spawnDaemon = func(args []string) error { return errors.New("synthetic spawn failure") }
		}},
		{name: "no mcp mode", setup: func(t *testing.T, cli *urCli, directory string) {
			startTestUrDaemon(t, directory, nil)
		}},
		{name: "another version", setup: func(t *testing.T, cli *urCli, directory string) {
			cli.dialDaemon = func(ctx context.Context, socketPath string, hello *sidecar.DaemonHello) (*sidecar.DaemonClient, error) {
				return nil, &sidecar.DaemonHelloRefusal{Code: sidecar.DaemonHelloErrorVersionSkew, Version: "2026.1.1-old"}
			}
			cli.spawnDaemon = func(args []string) error {
				t.Error("a version-skewed daemon made the relay spawn another")
				return nil
			}
		}},
	}
	for _, c := range cases {
		directory := shortTestDirectory(t)
		cli, stdout, stderr := newTestUrCli(filepath.Join(directory, "s"))
		cli.settings.SpawnWaitTimeout = 50 * time.Millisecond
		c.setup(t, cli, directory)
		cli.stdin = strings.NewReader("{}\n")
		if code := cli.main(context.Background(), []string{"ur", "mcp"}); code != urExitFailed {
			t.Errorf("%s: exit %d", c.name, code)
		}
		if stdout.Len() != 0 {
			t.Errorf("%s: stdout %q", c.name, stdout.String())
		}
		if stderr.Len() == 0 {
			t.Errorf("%s: nothing on stderr", c.name)
		}
	}
}

// One session of a scripted mcp mode: what the relay sent it, line by line, and the way to end it.
type testScriptedSession struct {
	lines     chan []byte
	stream    io.ReadWriter
	writeLock sync.Mutex
	drop      chan struct{}
}

// The next line the relay sent this session, as an object.
func (self *testScriptedSession) next(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	select {
	case line := <-self.lines:
		message := map[string]json.RawMessage{}
		if err := json.Unmarshal(line, &message); err != nil {
			t.Fatalf("the relay sent %q", line)
		}
		return message
	case <-time.After(urTestTimeout):
		t.Fatal("the relay sent nothing")
	}
	return nil
}

// Answers the request message with result.
func (self *testScriptedSession) answer(t *testing.T, message map[string]json.RawMessage, result string) {
	t.Helper()
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if _, err := fmt.Fprintf(self.stream, `{"jsonrpc":"2.0","id":%s,"result":%s}`+"\n", message["id"], result); err != nil {
		t.Fatal(err)
	}
}

// An mcp mode that hands each session to the test, which answers it by hand and ends it by closing drop.
func scriptedMcpMode(sessions chan *testScriptedSession) func(daemon *sidecar.Daemon) {
	return func(daemon *sidecar.Daemon) {
		daemon.RegisterMode(sidecar.DaemonModeMcp, func(ctx context.Context, hello *sidecar.DaemonHello, stream io.ReadWriter) error {
			session := &testScriptedSession{lines: make(chan []byte, 64), stream: stream, drop: make(chan struct{})}
			sessions <- session
			reading := make(chan struct{})
			go func() {
				defer close(reading)
				reader := bufio.NewReader(stream)
				for {
					line, err := reader.ReadBytes('\n')
					if err != nil {
						return
					}
					session.lines <- bytes.TrimSuffix(line, []byte("\n"))
				}
			}()
			select {
			case <-session.drop:
			case <-reading:
			case <-ctx.Done():
			}
			return nil
		})
	}
}

// A relay on a daemon of the scripted mode, its harness's stdin a pipe the test writes and its stdout a buffer. The
// relay ends when the test closes the pipe.
type testRelay struct {
	sessions chan *testScriptedSession
	stdin    *io.PipeWriter
	stdout   *syncBuffer
	finished chan int
}

func startTestRelay(t *testing.T) *testRelay {
	t.Helper()
	directory := shortTestDirectory(t)
	sessions := make(chan *testScriptedSession, 8)
	startTestUrDaemon(t, directory, scriptedMcpMode(sessions))
	cli, _, _ := newTestUrCli(filepath.Join(directory, "s"))
	stdout := newSyncBuffer()
	cli.stdout = stdout
	stdinReader, stdinWriter := io.Pipe()
	cli.stdin = stdinReader
	relay := &testRelay{sessions: sessions, stdin: stdinWriter, stdout: stdout, finished: make(chan int, 1)}
	go func() {
		relay.finished <- cli.main(context.Background(), []string{"ur", "mcp"})
	}()
	t.Cleanup(func() {
		stdinWriter.Close()
		select {
		case <-relay.finished:
		case <-time.After(urTestTimeout):
			t.Error("the relay did not end")
		}
	})
	return relay
}

// The daemon's next session.
func (self *testRelay) nextSession(t *testing.T) *testScriptedSession {
	t.Helper()
	select {
	case session := <-self.sessions:
		return session
	case <-time.After(urTestTimeout):
		t.Fatal("no session opened")
	}
	return nil
}

// Writes a harness line.
func (self *testRelay) send(t *testing.T, line string) {
	t.Helper()
	if _, err := io.WriteString(self.stdin, line+"\n"); err != nil {
		t.Fatal(err)
	}
}

// A request lost with its daemon is answered at once with a retryable error, and the harness's session carries on
// over a new connection.
func TestRelayFailsInFlightRetryably(t *testing.T) {
	relay := startTestRelay(t)
	first := relay.nextSession(t)
	relay.send(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	first.answer(t, first.next(t), `{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"ur","version":"test"}}`)
	relay.stdout.awaitContains(t, `"id":1,"result"`)
	relay.send(t, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"evs_read","arguments":{}}}`)
	first.next(t)
	close(first.drop)

	relay.stdout.awaitContains(t, `"id":7,"error"`)
	answer := struct {
		Error struct {
			Code int64 `json:"code"`
			Data struct {
				Retryable bool `json:"retryable"`
			} `json:"data"`
		} `json:"error"`
	}{}
	for _, line := range strings.Split(relay.stdout.String(), "\n") {
		if strings.Contains(line, `"id":7`) {
			json.Unmarshal([]byte(line), &answer)
		}
	}
	if answer.Error.Code != mcp.McpCodeRestarted || !answer.Error.Data.Retryable {
		t.Errorf("the lost call's answer: %+v", answer)
	}
	second := relay.nextSession(t)
	second.answer(t, second.next(t), `{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"ur","version":"test"}}`)
	relay.send(t, `{"jsonrpc":"2.0","id":8,"method":"ping"}`)
	second.answer(t, second.next(t), `{}`)
	relay.stdout.awaitContains(t, `"id":8,"result"`)
}

// For pre-2026-07-28 peers a new connection gets the session again before any new line: the initialize, at the
// version the harness asked for, then initialized, then each subscription still held, all under the relay's ids, their
// answers kept from the harness.
func TestRelayReplaysInitializeAndSubscriptions(t *testing.T) {
	for _, version := range []string{"2024-11-05", "2025-11-25"} {
		relay := startTestRelay(t)
		first := relay.nextSession(t)
		relay.send(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"`+version+`","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
		first.answer(t, first.next(t), `{"protocolVersion":"`+version+`","capabilities":{},"serverInfo":{"name":"ur","version":"test"}}`)
		relay.send(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
		first.next(t)
		for id, uri := range map[int]string{2: "ur://approval/kept", 3: "ur://approval/dropped"} {
			relay.send(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"resources/subscribe","params":{"uri":%q}}`, id, uri))
			first.answer(t, first.next(t), `{}`)
			relay.stdout.awaitContains(t, fmt.Sprintf(`"id":%d,"result"`, id))
		}
		relay.send(t, `{"jsonrpc":"2.0","id":4,"method":"resources/unsubscribe","params":{"uri":"ur://approval/dropped"}}`)
		first.answer(t, first.next(t), `{}`)
		relay.stdout.awaitContains(t, `"id":4,"result"`)
		// a subscription the daemon refused is no part of the session
		relay.send(t, `{"jsonrpc":"2.0","id":5,"method":"resources/subscribe","params":{"uri":"ur://approval/refused"}}`)
		refused := first.next(t)
		fmt.Fprintf(first.stream, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32002,"message":"no such resource"}}`+"\n", refused["id"])
		relay.stdout.awaitContains(t, `"id":5,"error"`)
		close(first.drop)

		second := relay.nextSession(t)
		initialize := second.next(t)
		params := struct {
			ProtocolVersion string `json:"protocolVersion"`
		}{}
		json.Unmarshal(initialize["params"], &params)
		if string(initialize["method"]) != `"initialize"` || params.ProtocolVersion != version ||
			!strings.Contains(string(initialize["id"]), "ur-relay-replay-") {
			t.Fatalf("%s: the replay began with %v", version, initialize)
		}
		second.answer(t, initialize, `{"protocolVersion":"`+version+`","capabilities":{},"serverInfo":{"name":"ur","version":"test"}}`)
		if initialized := second.next(t); string(initialized["method"]) != `"notifications/initialized"` {
			t.Fatalf("%s: then %v", version, initialized)
		}
		subscribe := second.next(t)
		if string(subscribe["method"]) != `"resources/subscribe"` || !strings.Contains(string(subscribe["params"]), "ur://approval/kept") ||
			!strings.Contains(string(subscribe["id"]), "ur-relay-replay-") {
			t.Fatalf("%s: then %v", version, subscribe)
		}
		second.answer(t, subscribe, `{}`)
		relay.send(t, `{"jsonrpc":"2.0","id":6,"method":"ping"}`)
		ping := second.next(t)
		if string(ping["method"]) != `"ping"` {
			t.Fatalf("%s: after the replay the daemon read %v", version, ping)
		}
		second.answer(t, ping, `{}`)
		relay.stdout.awaitContains(t, `"id":6,"result"`)
		if strings.Contains(relay.stdout.String(), "ur-relay-replay-") {
			t.Errorf("%s: a replay's answer reached the harness: %s", version, relay.stdout.String())
		}
	}
}

// A 2026-07-28 peer keeps no session: its long-lived subscriptions/listen fails retryably like any call, and the new
// connection gets nothing replayed.
func TestNoReplayFor20260728(t *testing.T) {
	relay := startTestRelay(t)
	first := relay.nextSession(t)
	meta := `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
	relay.send(t, `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{`+meta+`}}`)
	first.answer(t, first.next(t), `{"protocolVersion":"2026-07-28","capabilities":{},"serverInfo":{"name":"ur","version":"test"}}`)
	relay.send(t, `{"jsonrpc":"2.0","id":2,"method":"subscriptions/listen","params":{`+meta+`,"notifications":{"resourcesUpdated":["ur://approval/x"]}}}`)
	first.next(t)
	close(first.drop)
	relay.stdout.awaitContains(t, `"id":2,"error"`)
	if !strings.Contains(relay.stdout.String(), `"retryable":true`) {
		t.Errorf("the listen's answer: %s", relay.stdout.String())
	}

	second := relay.nextSession(t)
	relay.send(t, `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{`+meta+`}}`)
	if first := second.next(t); string(first["method"]) != `"tools/list"` {
		t.Fatalf("the new connection first read %v", first)
	}
}

// `ur mcp` end to end: the harness's lines reach the daemon's real MCP server through the relay and its hello, and
// its answers come back on stdout, a call on a daemon with no network naming ur login.
func TestUrMcpEndToEnd(t *testing.T) {
	directory := shortTestDirectory(t)
	startTestUrDaemon(t, directory, func(daemon *sidecar.Daemon) {
		settings := sidecar.DefaultSidecarSettings()
		server := mcp.NewMcpServer(mcp.DaemonOf(daemon), mcp.NewMcpServerSettings(settings, sidecar.Version))
		daemon.RegisterMode(sidecar.DaemonModeMcp, server.Serve)
	})
	cli, _, stderr := newTestUrCli(filepath.Join(directory, "s"))
	stdout := newSyncBuffer()
	cli.stdout = stdout
	stdinReader, stdinWriter := io.Pipe()
	cli.stdin = stdinReader
	finished := make(chan int, 1)
	go func() {
		finished <- cli.main(context.Background(), []string{"ur", "mcp", "--harness=claude-code", "--agent=builder"})
	}()
	send := func(line string) {
		if _, err := io.WriteString(stdinWriter, line+"\n"); err != nil {
			t.Fatal(err)
		}
	}
	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	stdout.awaitContains(t, `"serverInfo":{"name":"ur"`)
	send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	stdout.awaitContains(t, `"id":2,"result"`)
	if !strings.Contains(stdout.String(), `"tools":[]`) {
		t.Errorf("tools/list: %s", stdout.String())
	}
	send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"evs_read","arguments":{}}}`)
	stdout.awaitContains(t, `"id":3,"error"`)
	if !strings.Contains(stdout.String(), "ur login") {
		t.Errorf("a call with no network: %s", stdout.String())
	}
	stdinWriter.Close()
	select {
	case code := <-finished:
		if code != urExitOk {
			t.Errorf("exit %d; stderr %q", code, stderr.String())
		}
	case <-time.After(urTestTimeout):
		t.Fatal("the relay did not end")
	}
}
