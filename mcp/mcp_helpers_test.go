//go:build !js && !ios && !android && !sdk_mobile_bind

// What this package's tests share: a fake daemon whose networks a test puts in any state, sessions over in-memory
// pipes spoken to line by line, and test tools. Every wait is on a channel, bounded by mcpTestTimeout only so a broken
// test does not hang.

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How long a test waits on a session before calling itself broken. It bounds a hang and proves nothing.
const mcpTestTimeout = 30 * time.Second

// One network of a fake daemon: its run files in a fake store, which a restart reopens with nothing in memory.
type fakeMcpNetwork struct {
	stateLock sync.Mutex
	state     sidecar.SidecarState
	store     *sidecartest.FakeStore
	runs      *sidecar.RunStore
	spool     *sidecar.Spool
}

// A restart: a run store over the same files with nothing in memory.
func (self *fakeMcpNetwork) reopenRuns(t *testing.T, clock sidecar.Clock) {
	t.Helper()
	runs, err := sidecar.NewRunStore(self.store.Root(), sidecar.DefaultSidecarSettings().Mcp, clock)
	if err != nil {
		t.Fatal(err)
	}
	self.runs = runs
}

// Overwrites a run's file with bytes that do not read.
func (self *fakeMcpNetwork) corruptRun(t *testing.T, runId sidecar.Id) {
	t.Helper()
	writer, err := self.store.Root().Create("runs/" + runId.String())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.Write([]byte("not a run file"))
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
}

func (self *fakeMcpNetwork) setState(state sidecar.SidecarState) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.state = state
}

func (self *fakeMcpNetwork) Status() sidecar.SidecarStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return sidecar.SidecarStatus{State: self.state}
}

func (self *fakeMcpNetwork) Runs() (*sidecar.RunStore, error) {
	if self.runs == nil {
		return nil, sidecar.ErrSidecarStoreLocked
	}
	return self.runs, nil
}

func (self *fakeMcpNetwork) Spool() (*sidecar.Spool, error) {
	if self.spool == nil {
		return nil, sidecar.ErrSidecarStoreLocked
	}
	return self.spool, nil
}

// A daemon of networks a test sets, resolving as §5.8 does: the argument by id, else the only one.
type fakeMcpDaemon struct {
	stateLock       sync.Mutex
	networkIdHosted map[sidecar.Id]McpNetwork
}

func newFakeMcpDaemon() *fakeMcpDaemon {
	return &fakeMcpDaemon{networkIdHosted: map[sidecar.Id]McpNetwork{}}
}

// Hosts network, a real Sidecar among them, as networkId's, in place of any before.
func (self *fakeMcpDaemon) hostNetwork(networkId sidecar.Id, network McpNetwork) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkIdHosted[networkId] = network
}

// Hosts a network in state, with a run store over a fake store.
func (self *fakeMcpDaemon) host(t *testing.T, state sidecar.SidecarState, clock sidecar.Clock) (sidecar.Id, *fakeMcpNetwork) {
	t.Helper()
	store := sidecartest.NewFakeStore()
	runs, err := sidecar.NewRunStore(store.Root(), sidecar.DefaultSidecarSettings().Mcp, clock)
	if err != nil {
		t.Fatal(err)
	}
	networkId := sidecar.NewId()
	network := &fakeMcpNetwork{state: state, store: store, runs: runs}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkIdHosted[networkId] = network
	return networkId, network
}

func (self *fakeMcpDaemon) ResolveNetwork(hello *sidecar.DaemonHello, network string) (sidecar.Id, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if network != "" {
		networkId, err := sidecar.ParseId(network)
		if _, ok := self.networkIdHosted[networkId]; err != nil || !ok {
			return sidecar.Id{}, &sidecar.DaemonNetworkError{Reason: "unknown"}
		}
		return networkId, nil
	}
	switch len(self.networkIdHosted) {
	case 0:
		return sidecar.Id{}, &sidecar.DaemonNetworkError{Reason: "none"}
	case 1:
		for networkId := range self.networkIdHosted {
			return networkId, nil
		}
	}
	return sidecar.Id{}, &sidecar.DaemonNetworkError{Reason: "ambiguous"}
}

func (self *fakeMcpDaemon) Network(networkId sidecar.Id) (McpNetwork, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network, ok := self.networkIdHosted[networkId]
	if !ok {
		return nil, false
	}
	return network, true
}

func (self *fakeMcpDaemon) Agent(hello *sidecar.DaemonHello) (*sidecar.SidecarAgent, error) {
	if hello.Agent == "" {
		return nil, nil
	}
	agent, err := sidecar.ParseSidecarAgent(hello.Agent)
	if err != nil {
		return nil, err
	}
	return &agent, nil
}

// A server on daemon and clock with the default settings.
func newTestMcpServer(daemon McpDaemon, clock sidecar.Clock) *McpServer {
	settings := NewMcpServerSettings(sidecar.DefaultSidecarSettings(), sidecar.Version)
	settings.Clock = clock
	return NewMcpServer(daemon, settings)
}

// One session spoken to line by line over an in-memory pipe, its server's answers read on a goroutine of their own so
// the server never blocks on a write.
type testMcpConn struct {
	t    *testing.T
	conn net.Conn
	// one line at a time: a request's goroutine may still be in its Flush when the next line is sent
	sendLock sync.Mutex
	writer   *bufio.Writer
	nextId   int
	// each answer by id, and notifications in order
	stateLock     sync.Mutex
	idResponses   map[string]chan *testMcpResponse
	notifications []json.RawMessage
	// closed once Serve returns
	served chan struct{}
	// what Serve answered, and why reading ended: for a broken test's report
	serveErr error
	readErr  error
}

// A JSON-RPC response as a test reads it.
type testMcpResponse struct {
	Id     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int64           `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

// Starts a session of hello on server; it ends at the test's end.
func startTestMcpConn(t *testing.T, server *McpServer, hello *sidecar.DaemonHello) *testMcpConn {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	conn := &testMcpConn{
		t:           t,
		conn:        clientConn,
		writer:      bufio.NewWriter(clientConn),
		idResponses: map[string]chan *testMcpResponse{},
		served:      make(chan struct{}),
	}
	go func() {
		defer close(conn.served)
		err := server.Serve(ctx, hello, serverConn)
		conn.stateLock.Lock()
		conn.serveErr = err
		conn.stateLock.Unlock()
		serverConn.Close()
	}()
	go conn.read()
	t.Cleanup(func() {
		cancel()
		clientConn.Close()
		select {
		case <-conn.served:
		case <-time.After(mcpTestTimeout):
			t.Error("a session did not end")
		}
	})
	return conn
}

// Reads the server's lines until the pipe closes, handing each response to its waiter.
func (self *testMcpConn) read() {
	reader := bufio.NewReader(self.conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			self.stateLock.Lock()
			self.readErr = err
			for _, waiter := range self.idResponses {
				close(waiter)
			}
			self.idResponses = map[string]chan *testMcpResponse{}
			self.stateLock.Unlock()
			return
		}
		response := &testMcpResponse{}
		if json.Unmarshal(line, response) != nil || len(response.Id) == 0 {
			self.stateLock.Lock()
			self.notifications = append(self.notifications, json.RawMessage(line))
			self.stateLock.Unlock()
			continue
		}
		self.stateLock.Lock()
		waiter, ok := self.idResponses[string(response.Id)]
		delete(self.idResponses, string(response.Id))
		self.stateLock.Unlock()
		if ok {
			waiter <- response
		}
	}
}

// Writes one line.
func (self *testMcpConn) send(line string) error {
	self.sendLock.Lock()
	defer self.sendLock.Unlock()
	if _, err := self.writer.WriteString(line + "\n"); err != nil {
		return err
	}
	return self.writer.Flush()
}

// Sends a request and answers the channel its response arrives on, closed if the session ends first.
func (self *testMcpConn) start(method string, params any) <-chan *testMcpResponse {
	self.t.Helper()
	self.stateLock.Lock()
	self.nextId += 1
	id := fmt.Sprint(self.nextId)
	waiter := make(chan *testMcpResponse, 1)
	self.idResponses[id] = waiter
	self.stateLock.Unlock()
	encodedParams, err := json.Marshal(params)
	if err != nil {
		self.t.Fatal(err)
	}
	line := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":%q,"params":%s}`, id, method, encodedParams)
	go func() {
		if err := self.send(line); err != nil {
			self.stateLock.Lock()
			if _, ok := self.idResponses[id]; ok {
				delete(self.idResponses, id)
				close(waiter)
			}
			self.stateLock.Unlock()
		}
	}()
	return waiter
}

// Waits for a started request's response.
func (self *testMcpConn) await(waiter <-chan *testMcpResponse) *testMcpResponse {
	self.t.Helper()
	select {
	case response, ok := <-waiter:
		if !ok {
			self.t.Fatal("the session ended before its answer")
		}
		return response
	case <-time.After(mcpTestTimeout):
		self.t.Fatal("no answer")
	}
	return nil
}

// Sends a request and waits for its response.
func (self *testMcpConn) call(method string, params any) *testMcpResponse {
	self.t.Helper()
	return self.await(self.start(method, params))
}

// The legacy handshake at version: initialize, then initialized. Answers initialize's result.
func (self *testMcpConn) initialize(version string) map[string]json.RawMessage {
	self.t.Helper()
	response := self.call("initialize", map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "test", "version": "1"},
	})
	if response.Error != nil {
		self.t.Fatalf("initialize: %d %s", response.Error.Code, response.Error.Message)
	}
	if err := self.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		self.t.Fatal(err)
	}
	result := map[string]json.RawMessage{}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		self.t.Fatal(err)
	}
	return result
}

// Calls a tool, its arguments marshaled.
func (self *testMcpConn) callTool(name string, arguments any) *testMcpResponse {
	self.t.Helper()
	return self.call("tools/call", map[string]any{"name": name, "arguments": arguments})
}

// A response's error code and message, failing on a success.
func wantMcpError(t *testing.T, response *testMcpResponse, code int64, messagePart string) {
	t.Helper()
	if response.Error == nil {
		t.Fatalf("succeeded, want error %d: %s", code, response.Result)
	}
	if response.Error.Code != code || !strings.Contains(response.Error.Message, messagePart) {
		t.Fatalf("error %d %q, want %d naming %q", response.Error.Code, response.Error.Message, code, messagePart)
	}
}

// An echo tool's input and output.
type testEchoIn struct {
	Network string `json:"network,omitempty"`
	Text    string `json:"text"`
}

type testEchoOut struct {
	Text      string `json:"text"`
	Agent     string `json:"agent"`
	NetworkId string `json:"network_id"`
}

// Installs test_echo, which answers its text, its session's agent and its call's network.
func installTestEcho(server *McpServer) {
	server.Install(func(server *gomcp.Server) {
		gomcp.AddTool(server, &gomcp.Tool{Name: "test_echo", Description: "echoes"},
			func(ctx context.Context, request *gomcp.CallToolRequest, in testEchoIn) (*gomcp.CallToolResult, testEchoOut, error) {
				out := testEchoOut{Text: in.Text}
				if session := McpSessionOf(ctx); session != nil && session.Agent() != nil {
					out.Agent = session.Agent().Label
				}
				if call := McpCallOf(ctx); call != nil {
					out.NetworkId = call.NetworkId.String()
				}
				return nil, out, nil
			})
	})
}

// A blocking tool's controls: each call announces itself on entered and returns when released, or its context ends.
type testBlockTool struct {
	entered  chan context.Context
	released chan struct{}
}

func newTestBlockTool() *testBlockTool {
	return &testBlockTool{entered: make(chan context.Context, 64), released: make(chan struct{}, 64)}
}

// Installs test_block on server.
func (self *testBlockTool) install(server *McpServer) {
	server.Install(func(server *gomcp.Server) {
		gomcp.AddTool(server, &gomcp.Tool{Name: "test_block", Description: "blocks"},
			func(ctx context.Context, request *gomcp.CallToolRequest, in testEchoIn) (*gomcp.CallToolResult, testEchoOut, error) {
				self.entered <- ctx
				select {
				case <-self.released:
					return nil, testEchoOut{Text: in.Text}, nil
				case <-ctx.Done():
					return nil, testEchoOut{}, errors.New("cancelled")
				}
			})
	})
}

// Waits for the next call to enter.
func (self *testBlockTool) awaitEntered(t *testing.T) context.Context {
	t.Helper()
	select {
	case ctx := <-self.entered:
		return ctx
	case <-time.After(mcpTestTimeout):
		t.Fatal("no call entered")
	}
	return nil
}
