//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.4's server: one daemon serving many sessions (R-MCP-3), instructions fixed per session, only tools and
// subscribable resources advertised, the network resolved per call, and FAILED_PRECONDITION naming ur unlock or ur login
// for the person's own terminal.

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A short directory for a socket, since a test's temp directory can pass sun_path's 104 bytes on macOS.
func shortMcpTestDirectory(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "ur-mcp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return directory
}

// A daemon on its own socket with server as its mcp mode, closed at the test's end.
func startTestMcpDaemon(t *testing.T, server *McpServer) string {
	t.Helper()
	directory := shortMcpTestDirectory(t)
	socketPath := filepath.Join(directory, "s")
	daemon, err := sidecar.NewDaemon(context.Background(), &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     socketPath,
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := daemon.RegisterMode(sidecar.DaemonModeMcp, server.Serve); err != nil {
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
	return socketPath
}

// The session's stream as go-sdk's transport takes it.
type testStreamWriteCloser struct {
	writer io.Writer
}

func (self *testStreamWriteCloser) Write(p []byte) (int, error) {
	return self.writer.Write(p)
}

func (self *testStreamWriteCloser) Close() error {
	return nil
}

// R-MCP-3: one daemon serves many harnesses at once, each its own session with its own agent, through the relay's
// socket and hello, with go-sdk's own client at its newest version.
func TestOneDaemonManySessions(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	installTestEcho(server)
	socketPath := startTestMcpDaemon(t, server)

	ctx, cancel := context.WithTimeout(context.Background(), mcpTestTimeout)
	defer cancel()
	agents := []string{"alpha", "beta", "gamma"}
	sessions := []*gomcp.ClientSession{}
	for _, agent := range agents {
		client, err := sidecar.DialDaemon(ctx, socketPath, &sidecar.DaemonHello{
			Mode: sidecar.DaemonModeMcp, Version: sidecar.Version, Agent: agent, Harness: "claude-code",
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.Close() })
		stream := client.Stream()
		session, err := gomcp.NewClient(&gomcp.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx,
			&gomcp.IOTransport{Reader: io.NopCloser(stream), Writer: &testStreamWriteCloser{writer: stream}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { session.Close() })
		sessions = append(sessions, session)
	}
	if count := len(server.Sessions()); count != len(agents) {
		t.Fatalf("%d sessions open, want %d", count, len(agents))
	}
	waitGroup := sync.WaitGroup{}
	for i, session := range sessions {
		waitGroup.Go(func() {
			result, err := session.CallTool(ctx, &gomcp.CallToolParams{Name: "test_echo", Arguments: map[string]any{"text": agents[i]}})
			if err != nil {
				t.Errorf("%s: %s", agents[i], err)
				return
			}
			out := testEchoOut{}
			encoded, _ := json.Marshal(result.StructuredContent)
			if err := json.Unmarshal(encoded, &out); err != nil || out.Agent != agents[i] || out.Text != agents[i] {
				t.Errorf("%s's session answered %s", agents[i], encoded)
			}
		})
	}
	waitGroup.Wait()
}

// Each session keeps the instructions text picked at its start (D-MCP-29's trap): a change of the rule reaches only
// sessions started after it, at a legacy version and at 2026-07-28.
func TestInstructionsFixedPerSession(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	server.SetInstructionsFor(func(session *McpSession) string { return "text a" })
	first := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	// the first session has started: its text is picked before Serve reads a line
	first.call("ping", map[string]any{})
	server.SetInstructionsFor(func(session *McpSession) string { return "text b" })
	second := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})

	instructions := func(result map[string]json.RawMessage) string {
		text := ""
		json.Unmarshal(result["instructions"], &text)
		return text
	}
	if got := instructions(first.initialize("2025-11-25")); got != "text a" {
		t.Errorf("the first session's instructions are %q", got)
	}
	if got := instructions(second.initialize("2024-11-05")); got != "text b" {
		t.Errorf("the second session's instructions are %q", got)
	}
	if count := len(server.Sessions()); count != 2 {
		t.Errorf("sessions open: %d", count)
	}

	// 2026-07-28 has no initialize: server/discover carries the text
	third := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	discover := third.call("server/discover", map[string]any{"_meta": map[string]any{
		gomcp.MetaKeyProtocolVersion:    "2026-07-28",
		gomcp.MetaKeyClientInfo:         map[string]any{"name": "test", "version": "1"},
		gomcp.MetaKeyClientCapabilities: map[string]any{},
	}})
	if discover.Error != nil {
		t.Fatalf("server/discover: %s", discover.Error.Message)
	}
	result := map[string]json.RawMessage{}
	json.Unmarshal(discover.Result, &result)
	if got := instructions(result); got != "text b" {
		t.Errorf("the third session's instructions are %q", got)
	}
}

// The capabilities name tools and resources with subscribe, and nothing else: no prompts, sampling, elicitation,
// logging or completions.
func TestCapabilitiesAdvertiseOnlyToolsAndResources(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	installTestEcho(server)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	result := conn.initialize("2025-06-18")
	capabilities := map[string]json.RawMessage{}
	if err := json.Unmarshal(result["capabilities"], &capabilities); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for name := range capabilities {
		names = append(names, name)
	}
	if len(capabilities) != 2 || capabilities["tools"] == nil || capabilities["resources"] == nil {
		t.Fatalf("capabilities %v", names)
	}
	resources := struct {
		Subscribe   bool `json:"subscribe"`
		ListChanged bool `json:"listChanged"`
	}{}
	json.Unmarshal(capabilities["resources"], &resources)
	tools := struct {
		ListChanged bool `json:"listChanged"`
	}{}
	json.Unmarshal(capabilities["tools"], &tools)
	if !resources.Subscribe || resources.ListChanged || tools.ListChanged {
		t.Errorf("resources %s, tools %s: want subscribe on and a static list", capabilities["resources"], capabilities["tools"])
	}
}

// A call on a Locked network names ur unlock, for the person's own terminal, and runs nothing.
func TestLockedNamesUnlock(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	daemon.host(t, sidecar.SidecarStateLocked, clock)
	server := newTestMcpServer(daemon, clock)
	installTestEcho(server)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	conn.initialize("2025-11-25")
	wantMcpError(t, conn.callTool("test_echo", map[string]any{"text": "x"}), McpCodeFailedPrecondition, "ur unlock")
}

// A call on an Unenrolled network names ur login, as does a daemon hosting none, and a revoked device's.
func TestUnenrolledNamesLogin(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	server := newTestMcpServer(daemon, clock)
	installTestEcho(server)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	conn.initialize("2025-11-25")
	wantMcpError(t, conn.callTool("test_echo", map[string]any{"text": "x"}), McpCodeFailedPrecondition, "ur login")

	_, network := daemon.host(t, sidecar.SidecarStateUnenrolled, clock)
	wantMcpError(t, conn.callTool("test_echo", map[string]any{"text": "x"}), McpCodeFailedPrecondition, "ur login")

	network.setState(sidecar.SidecarStateRevoked)
	wantMcpError(t, conn.callTool("test_echo", map[string]any{"text": "x"}), McpCodeFailedPrecondition, "ur login")

	network.setState(sidecar.SidecarStateOffline)
	if response := conn.callTool("test_echo", map[string]any{"text": "x"}); response.Error != nil {
		t.Errorf("an Offline network's call: %s", response.Error.Message)
	}
}

// Each call resolves its own network: its network argument, else the only one hosted; with several and none named,
// FAILED_PRECONDITION.
func TestCallResolvesNetworkPerCall(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	firstId, _ := daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	installTestEcho(server)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	conn.initialize("2025-11-25")
	networkOf := func(response *testMcpResponse) string {
		t.Helper()
		if response.Error != nil {
			t.Fatalf("call: %s", response.Error.Message)
		}
		result := struct {
			StructuredContent testEchoOut `json:"structuredContent"`
		}{}
		json.Unmarshal(response.Result, &result)
		return result.StructuredContent.NetworkId
	}
	if got := networkOf(conn.callTool("test_echo", map[string]any{"text": "x"})); got != firstId.String() {
		t.Errorf("the only network: %s", got)
	}
	secondId, _ := daemon.host(t, sidecar.SidecarStateOnline, clock)
	wantMcpError(t, conn.callTool("test_echo", map[string]any{"text": "x"}), McpCodeFailedPrecondition, "several networks")
	if got := networkOf(conn.callTool("test_echo", map[string]any{"text": "x", "network": secondId.String()})); got != secondId.String() {
		t.Errorf("the named network: %s", got)
	}
}

// A hello whose agent label is not one leaves the session serving lists but refusing every call, recording nothing
// of the label.
func TestInvalidAgentRefusesCalls(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	installTestEcho(server)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp, Agent: "not a label!"})
	conn.initialize("2025-11-25")
	if response := conn.call("tools/list", map[string]any{}); response.Error != nil {
		t.Fatalf("tools/list: %s", response.Error.Message)
	}
	response := conn.callTool("test_echo", map[string]any{"text": "x"})
	wantMcpError(t, response, McpCodeInvalidSession, "agent label")
	if strings.Contains(response.Error.Message, "not a label!") {
		t.Errorf("the refusal echoes the label: %s", response.Error.Message)
	}
}

// A line past the request bound ends the session, as a control session's does.
func TestLineOverBoundClosesSession(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := NewMcpServerSettings(sidecar.DefaultSidecarSettings(), sidecar.Version)
	settings.Clock = clock
	settings.RequestByteCount = 1024
	server := NewMcpServer(newFakeMcpDaemon(), settings)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	conn.initialize("2025-11-25")
	go conn.send(`{"jsonrpc":"2.0","id":99,"method":"ping","params":{"pad":"` + strings.Repeat("x", 2048) + `"}}`)
	select {
	case <-conn.served:
	case <-contextDone(t):
		t.Fatal("the session outlived a line past its bound")
	}
}

// A channel closed at mcpTestTimeout.
func contextDone(t *testing.T) <-chan struct{} {
	ctx, cancel := context.WithTimeout(context.Background(), mcpTestTimeout)
	t.Cleanup(cancel)
	return ctx.Done()
}

// With no resource map a subscription is refused at subscribe; with one, its answer stands.
func TestSubscribeRefusedUnlessAdmitted(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	conn.initialize("2025-11-25")
	if response := conn.call("resources/subscribe", map[string]any{"uri": "ur://approval/x"}); response.Error == nil {
		t.Fatal("a subscription with no resource map was taken")
	}
	admitted := []string{}
	server.SetSubscribeCheck(func(ctx context.Context, session *McpSession, uri string) error {
		admitted = append(admitted, uri)
		return nil
	})
	if response := conn.call("resources/subscribe", map[string]any{"uri": "ur://approval/y"}); response.Error != nil {
		t.Fatalf("an admitted subscription: %s", response.Error.Message)
	}
	if len(admitted) != 1 || admitted[0] != "ur://approval/y" {
		t.Errorf("admitted %v", admitted)
	}
}
