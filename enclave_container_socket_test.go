//go:build !js && !ios && !android && !sdk_mobile_bind

// The container socket (enclave_container_socket.go) on fake peer credentials across namespaces: a process tree whose
// container part starts at the container's first process, under the runtime and the daemon outside, and a host whose
// mcp mode and hook method stand in for the daemon's, binding a call to its harness process's newest run as the
// daemon's run binder does. Every answer is a tainted run's; a claim of another process is refused; the Harness's runs
// above the container never take its taint; a hook's new run is tainted before a call of its harness acts in it;
// writes under inbox/ are refused; a gateway token is minted only for the container's own grant.

package sidecar

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
)

// The container as the socket asks it: the pids inside, by their pid there, and the uids it maps.
type enclaveSocketTestScope struct {
	namespacePids map[int]int
	uidBase       uint32
	uidCount      uint32
}

func (self *enclaveSocketTestScope) Contains(pid int) (int, bool) {
	namespacePid, ok := self.namespacePids[pid]
	return namespacePid, ok
}

func (self *enclaveSocketTestScope) OwnsUid(uid uint32) bool {
	return self.uidBase <= uid && uid-self.uidBase < self.uidCount
}

// One tool call the fake mcp mode took: its tool, the run it acted in and whether that run read tainted then.
type enclaveSocketTestCall struct {
	tool    string
	runId   *Id
	tainted bool
}

// The daemon as the socket's host: its mcp mode binds a call to the newest run of the harness process, as the run
// binder does, and its hook method opens a run of that harness, untainted, as a fresh SessionStart does.
type enclaveSocketTestHost struct {
	t       *testing.T
	runs    *RunStore
	harness ProcessIdentity

	stateLock  sync.Mutex
	calls      []enclaveSocketTestCall
	dispatched []string
	// a run the fake opened during a call, which the call's answer must taint
	openedDuring []Id
	// when set, a hook event, having opened its run, reports it here and waits for the gate
	hookOpened chan Id
	hookGate   chan struct{}
}

// The harness's newest run, nil for none.
func (self *enclaveSocketTestHost) newestRun(t *testing.T) *Id {
	files, err := self.runs.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var newest *Id
	for _, file := range files {
		if file.ProcessId == self.harness.Pid && file.ProcessStartMillis == self.harness.StartMillis {
			if newest == nil || newest.Less(file.RunId) {
				runId := file.RunId
				newest = &runId
			}
		}
	}
	return newest
}

// Opens an untainted run of the harness.
func (self *enclaveSocketTestHost) openRun(t *testing.T) Id {
	runId := NewId()
	if err := self.runs.Create(context.Background(), &RunFile{
		RunId: runId, Harness: "claude-code", ProcessId: self.harness.Pid, ProcessStartMillis: self.harness.StartMillis,
	}); err != nil {
		t.Fatal(err)
	}
	return runId
}

// A host on runs for harness.
func newEnclaveSocketTestHost(t *testing.T, runs *RunStore, harness ProcessIdentity) *enclaveSocketTestHost {
	return &enclaveSocketTestHost{t: t, runs: runs, harness: harness}
}

func (self *enclaveSocketTestHost) Runs() (*RunStore, error) {
	return self.runs, nil
}

func (self *enclaveSocketTestHost) ServeMcp(ctx context.Context, hello *DaemonHello, stream io.ReadWriter) error {
	t := self.t
	reader := bufio.NewReader(stream)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return nil
		}
		request := struct {
			Id     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}{}
		if err := json.Unmarshal(line, &request); err != nil || request.Method != "tools/call" {
			continue
		}
		runId := self.newestRun(t)
		// an unbound session acts in a placeholder the store never saw, which reads tainted
		tainted := runId == nil || self.runs.Tainted(*runId)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.calls = append(self.calls, enclaveSocketTestCall{tool: request.Params.Name, runId: runId, tainted: tainted})
		}()
		if request.Params.Name == "open_run_during" {
			opened := self.openRun(t)
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.openedDuring = append(self.openedDuring, opened)
			}()
		}
		answer, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.Id, "result": map[string]any{"content": []any{}}})
		if _, err := stream.Write(append(answer, '\n')); err != nil {
			return err
		}
	}
}

func (self *enclaveSocketTestHost) RpcSession(hello *DaemonHello) func(ctx context.Context, line []byte) []byte {
	return func(ctx context.Context, line []byte) []byte {
		t := self.t
		request := &enclaveContainerRpcMessage{}
		if err := json.Unmarshal(line, request); err != nil {
			t.Errorf("the host took a line that is not a request: %s", line)
			return nil
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.dispatched = append(self.dispatched, request.Method)
		}()
		if request.Method == enclaveContainerHookMethod {
			opened := self.openRun(t)
			if self.hookOpened != nil {
				self.hookOpened <- opened
				<-self.hookGate
			}
		}
		answer, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": request.Id, "result": nil})
		return answer
	}
}

// The calls the fake mcp mode took.
func (self *enclaveSocketTestHost) took() []enclaveSocketTestCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.calls)
}

// A gateway with a container grant for codex and a grant of another kind for claude.
type enclaveSocketTestGateway struct {
	stateLock sync.Mutex
	minted    []string
	made      []*EnclaveContainerCaller
}

func (self *enclaveSocketTestGateway) ContainerGrant(ctx context.Context, harness string, agent string) (*EnclaveContainerGrant, error) {
	switch harness {
	case "codex":
		return &EnclaveContainerGrant{Harness: harness, Container: true}, nil
	case "claude":
		return &EnclaveContainerGrant{Harness: harness}, nil
	}
	return nil, nil
}

func (self *enclaveSocketTestGateway) MakeContainerGrant(ctx context.Context, caller *EnclaveContainerCaller, request *EnclaveContainerGrantRequest) (*EnclaveContainerGrant, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.made = append(self.made, caller)
	return &EnclaveContainerGrant{Harness: request.Harness, Container: true}, nil
}

func (self *enclaveSocketTestGateway) MintContainerToken(ctx context.Context, caller *EnclaveContainerCaller, grant *EnclaveContainerGrant) (*EnclaveContainerToken, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.minted = append(self.minted, grant.Harness)
	return &EnclaveContainerToken{Token: "ur_gw_synthetic-" + grant.Harness, ExpiresMillis: 3600000}, nil
}

// The pids of the fake tree: the daemon and the runtime outside; the container's first process, a harness, its MCP
// relay, a hook's shell and its ur hook inside; and the Harness's own pig outside.
const (
	enclaveSocketTestDaemon  = 5
	enclaveSocketTestNspawn  = 10
	enclaveSocketTestInit    = 100
	enclaveSocketTestClaude  = 200
	enclaveSocketTestRelay   = 300
	enclaveSocketTestShell   = 305
	enclaveSocketTestHook    = 310
	enclaveSocketTestOutside = 400
	enclaveSocketTestUid     = 524288
)

// One socket on fakes.
type enclaveSocketTest struct {
	t       *testing.T
	socket  *EnclaveContainerSocket
	host    *enclaveSocketTestHost
	runs    *RunStore
	harness ProcessIdentity
	// the Harness's run outside the container, which no container call may taint
	outsideRunId Id

	stateLock sync.Mutex
	peers     map[net.Conn]EnclaveContainerPeer
}

func newEnclaveSocketTest(t *testing.T, gateway EnclaveContainerGateway, inboxGuard EnclaveContainerInboxGuard) *enclaveSocketTest {
	_, runs, _ := newTestRunStoreOn(t, NewSidecarMemoryBackend())
	processes := testProcessTable{}
	processes.add(enclaveSocketTestDaemon, 1, 50, "ur")
	processes.add(enclaveSocketTestNspawn, enclaveSocketTestDaemon, 100, "systemd-nspawn")
	processes.add(enclaveSocketTestInit, enclaveSocketTestNspawn, 1000, "systemd")
	processes.add(enclaveSocketTestClaude, enclaveSocketTestInit, 2000, "claude")
	processes.add(enclaveSocketTestRelay, enclaveSocketTestClaude, 3000, "ur")
	processes.add(enclaveSocketTestShell, enclaveSocketTestClaude, 3050, "sh")
	processes.add(enclaveSocketTestHook, enclaveSocketTestShell, 3100, "ur")
	processes.add(enclaveSocketTestOutside, enclaveSocketTestDaemon, 4000, "pig")
	scope := &enclaveSocketTestScope{
		namespacePids: map[int]int{
			enclaveSocketTestInit: 1, enclaveSocketTestClaude: 7, enclaveSocketTestRelay: 12, enclaveSocketTestShell: 13, enclaveSocketTestHook: 14,
		},
		uidBase:  enclaveSocketTestUid,
		uidCount: 65536,
	}
	harness := ProcessIdentity{Pid: enclaveSocketTestClaude, StartMillis: 2000}
	host := newEnclaveSocketTestHost(t, runs, harness)
	test := &enclaveSocketTest{t: t, host: host, runs: runs, harness: harness, peers: map[net.Conn]EnclaveContainerPeer{}}
	socket, err := NewEnclaveContainerSocket(&EnclaveContainerSocketArgs{
		Version:    "v-test",
		Host:       host,
		Container:  scope,
		Gateway:    gateway,
		InboxGuard: inboxGuard,
		Processes:  processes,
		Peer: func(conn net.Conn) (EnclaveContainerPeer, error) {
			test.stateLock.Lock()
			defer test.stateLock.Unlock()
			peer, ok := test.peers[conn]
			if !ok {
				return EnclaveContainerPeer{}, errors.New("no peer")
			}
			return peer, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	test.socket = socket
	test.outsideRunId = NewId()
	if err := runs.Create(context.Background(), &RunFile{RunId: test.outsideRunId, Harness: "pig", ProcessId: enclaveSocketTestOutside, ProcessStartMillis: 4000}); err != nil {
		t.Fatal(err)
	}
	return test
}

// Notes the credentials SO_PEERCRED reports for conn.
func (self *enclaveSocketTest) setPeer(conn net.Conn, peer EnclaveContainerPeer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.peers[conn] = peer
}

// A session's client end.
type enclaveSocketTestClient struct {
	t      *testing.T
	conn   net.Conn
	reader *bufio.Reader
	done   chan error
}

// Opens a session as peer, sends hello and reads the daemon's answer to it, which is empty for a session served.
func (self *enclaveSocketTest) open(peer EnclaveContainerPeer, hello map[string]any) (*enclaveSocketTestClient, string) {
	client, server := net.Pipe()
	self.setPeer(server, peer)
	done := make(chan error, 1)
	go func() {
		done <- self.socket.serveConn(context.Background(), server)
		server.Close()
	}()
	session := &enclaveSocketTestClient{t: self.t, conn: client, reader: bufio.NewReader(client), done: done}
	self.t.Cleanup(func() { client.Close() })
	hello["ur_local"] = 1
	hello["version"] = "v-test"
	line, _ := json.Marshal(hello)
	if _, err := client.Write(append(line, '\n')); err != nil {
		return session, "closed"
	}
	answerLine, err := session.reader.ReadBytes('\n')
	if err != nil {
		return session, "closed"
	}
	answer := &daemonHelloAnswer{}
	if err := json.Unmarshal(answerLine, answer); err != nil {
		self.t.Fatalf("the hello's answer: %s", answerLine)
	}
	return session, answer.Error
}

// Sends one JSON-RPC request.
func (self *enclaveSocketTestClient) send(id int, method string, params any) {
	line, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	if _, err := self.conn.Write(append(line, '\n')); err != nil {
		self.t.Fatal(err)
	}
}

// Reads one answer: its result and its error's code, 0 for none.
func (self *enclaveSocketTestClient) answer() (json.RawMessage, int) {
	line, err := self.reader.ReadBytes('\n')
	if err != nil {
		self.t.Fatal(err)
	}
	response := &daemonRpcResponse{}
	if err := json.Unmarshal(line, response); err != nil {
		self.t.Fatalf("an answer that is not one: %s", line)
	}
	if response.Error != nil {
		return nil, response.Error.Code
	}
	return response.Result, 0
}

// A process of the container, as SO_PEERCRED reports it.
func enclaveSocketTestPeer(pid int) EnclaveContainerPeer {
	return EnclaveContainerPeer{Pid: pid, Uid: enclaveSocketTestUid, Gid: enclaveSocketTestUid}
}

// A tool call's arguments.
func enclaveSocketTestTool(name string, arguments map[string]any) map[string]any {
	return map[string]any{"name": name, "arguments": arguments}
}

func TestEnclaveContainerSocketTaintsEveryResult(t *testing.T) {
	test := newEnclaveSocketTest(t, nil, nil)
	runId := test.host.openRun(t)
	session, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{"mode": DaemonModeMcp, "pid": 12})
	if refusal != "" {
		t.Fatalf("the session was refused: %s", refusal)
	}
	// the session's start taints its harness's run, write-ahead
	if !test.runs.TaintRecorded(runId) {
		t.Error("the harness's run is not tainted at the session's start")
	}
	session.send(1, "tools/call", enclaveSocketTestTool("open_run_during", nil))
	if _, code := session.answer(); code != 0 {
		t.Fatalf("the call answered %d", code)
	}
	// a run opened during the call is tainted before its answer reached the caller
	opened := func() []Id {
		test.host.stateLock.Lock()
		defer test.host.stateLock.Unlock()
		return slices.Clone(test.host.openedDuring)
	}()
	if len(opened) != 1 || !test.runs.TaintRecorded(opened[0]) {
		t.Errorf("the run opened during the call is not tainted at its answer: %v", opened)
	}
	session.send(2, "tools/call", enclaveSocketTestTool("web_search", map[string]any{"objective": "synthetic"}))
	if _, code := session.answer(); code != 0 {
		t.Fatalf("the second call answered %d", code)
	}
	for _, call := range test.host.took() {
		if !call.tainted {
			t.Errorf("%s acted in an untainted run", call.tool)
		}
	}
	// the Harness's run, above the container, never takes the container's taint
	if test.runs.TaintRecorded(test.outsideRunId) {
		t.Error("a run of a harness outside the container was tainted")
	}
}

func TestEnclaveContainerSocketRunBinding(t *testing.T) {
	test := newEnclaveSocketTest(t, nil, nil)
	runId := test.host.openRun(t)

	// a hello naming another process is refused, and nothing reaches the daemon
	session, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{"mode": DaemonModeMcp, "pid": 4242})
	if refusal != enclaveContainerSocketClaimError {
		t.Errorf("a hello naming another process was answered %q", refusal)
	}
	if err := <-session.done; !errors.Is(err, ErrEnclaveContainerCaller) {
		t.Errorf("the refused session ended with %v", err)
	}
	// a process outside the container, or under a uid the container does not map, is refused before its hello
	for _, peer := range []EnclaveContainerPeer{
		enclaveSocketTestPeer(enclaveSocketTestOutside),
		{Pid: enclaveSocketTestRelay, Uid: 0, Gid: 0},
	} {
		session, refusal := test.open(peer, map[string]any{"mode": DaemonModeMcp})
		if refusal != "closed" {
			t.Errorf("the caller %+v was answered %q", peer, refusal)
		}
		if err := <-session.done; !errors.Is(err, ErrEnclaveContainerCaller) {
			t.Errorf("the caller %+v ended with %v", peer, err)
		}
	}
	if len(test.host.took()) != 0 {
		t.Errorf("a refused caller reached the daemon: %v", test.host.took())
	}

	// bound by its credentials, not its word: its harness is the nearest ancestor in the container that is no shell
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	test.setPeer(server, enclaveSocketTestPeer(enclaveSocketTestHook))
	caller, err := test.socket.bind(server)
	if err != nil {
		t.Fatal(err)
	}
	if caller.Harness != test.harness || caller.NamespacePid != 14 || !caller.Tainted {
		t.Errorf("the hook bound as %+v", caller)
	}
	for _, ancestor := range caller.Ancestors {
		if ancestor.Pid == enclaveSocketTestNspawn || ancestor.Pid == enclaveSocketTestDaemon {
			t.Errorf("the caller's ancestors run past the container: %v", caller.Ancestors)
		}
	}
	bound, err := test.socket.taintCaller(context.Background(), caller)
	if err != nil || bound == nil || *bound != runId || !test.runs.TaintRecorded(runId) {
		t.Errorf("the hook bound to %v, %v, want its harness's run, tainted", bound, err)
	}

	// a caller with no harness run acts in an unknown run, which reads tainted
	test.setPeer(server, enclaveSocketTestPeer(enclaveSocketTestInit))
	caller, err = test.socket.bind(server)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = test.socket.taintCaller(context.Background(), caller)
	if err != nil || bound != nil || !caller.Tainted || !test.runs.Tainted(NewId()) {
		t.Errorf("an unknown caller bound to %v, %v", bound, err)
	}

	// a hello naming its own pid in the container is served
	session, refusal = test.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{"mode": DaemonModeMcp, "pid": 12})
	if refusal != "" {
		t.Errorf("a hello naming the caller's own pid was answered %q", refusal)
	}
	session.conn.Close()
	<-session.done
}

func TestEnclaveContainerSocketKindsTainted(t *testing.T) {
	test := newEnclaveSocketTest(t, nil, nil)
	session, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{"mode": DaemonModeMcp})
	if refusal != "" {
		t.Fatalf("the session was refused: %s", refusal)
	}
	// a hook of the same harness opens an untainted run between the calls
	hook, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestHook), map[string]any{"mode": DaemonModeHook, "harness": "claude-code"})
	if refusal != "" {
		t.Fatalf("the hook's session was refused: %s", refusal)
	}
	// the calls that file kind 23 (web_fetch), 24 (agent_send) and 25 (a calendar write) in a tainted run
	for i, tool := range []string{"web_fetch", "agent_send", "calendar_event_add"} {
		hook.send(i+1, enclaveContainerHookMethod, map[string]any{"payload": "synthetic"})
		if _, code := hook.answer(); code != 0 {
			t.Fatalf("the hook answered %d", code)
		}
		session.send(i+1, "tools/call", enclaveSocketTestTool(tool, nil))
		if _, code := session.answer(); code != 0 {
			t.Fatalf("%s answered %d", tool, code)
		}
	}
	calls := test.host.took()
	if len(calls) != 3 {
		t.Fatalf("the daemon took %d calls", len(calls))
	}
	for _, call := range calls {
		if call.runId == nil || !call.tainted {
			t.Errorf("%s was filed in an untainted run (%v)", call.tool, call.runId)
		}
	}
}

// A hook event that opened a run holds its harness's order to its answer's taint: a call of that harness waits, and
// then acts in the run tainted.
func TestEnclaveContainerSocketOrdersHooksBeforeCalls(t *testing.T) {
	test := newEnclaveSocketTest(t, nil, nil)
	test.host.hookOpened = make(chan Id)
	test.host.hookGate = make(chan struct{})
	waiting := make(chan ProcessIdentity, 1)
	test.socket.onLockWait = func(harness ProcessIdentity) {
		waiting <- harness
	}
	hook, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestHook), map[string]any{"mode": DaemonModeHook, "harness": "claude-code"})
	if refusal != "" {
		t.Fatalf("the hook's session was refused: %s", refusal)
	}
	session, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{"mode": DaemonModeMcp})
	if refusal != "" {
		t.Fatalf("the session was refused: %s", refusal)
	}
	hookAnswered := make(chan int, 1)
	go func() {
		hook.send(1, enclaveContainerHookMethod, map[string]any{"payload": "synthetic"})
		_, code := hook.answer()
		hookAnswered <- code
	}()
	opened := <-test.host.hookOpened
	if test.runs.TaintRecorded(opened) {
		t.Fatal("the hook's run started tainted, so this shows nothing")
	}
	callAnswered := make(chan int, 1)
	go func() {
		session.send(1, "tools/call", enclaveSocketTestTool("agent_send", nil))
		_, code := session.answer()
		callAnswered <- code
	}()
	if harness := <-waiting; harness != test.harness {
		t.Errorf("the call waited on %v", harness)
	}
	if len(test.host.took()) != 0 {
		t.Fatal("the call reached the daemon while the hook held its harness")
	}
	close(test.host.hookGate)
	if code := <-hookAnswered; code != 0 {
		t.Fatalf("the hook answered %d", code)
	}
	if code := <-callAnswered; code != 0 {
		t.Fatalf("the call answered %d", code)
	}
	calls := test.host.took()
	if len(calls) != 1 || calls[0].runId == nil || *calls[0].runId != opened || !calls[0].tainted {
		t.Errorf("the call acted in %+v, want the hook's run tainted", calls)
	}
}

func TestEnclaveContainerSocketInboxRefused(t *testing.T) {
	test := newEnclaveSocketTest(t, nil, nil)
	session, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{"mode": DaemonModeMcp})
	if refusal != "" {
		t.Fatalf("the session was refused: %s", refusal)
	}
	refused := []map[string]any{
		enclaveSocketTestTool(enclaveContainerMcpEvsWrite, map[string]any{"repo": "agents", "path": "inbox/a1/m1.json", "content": "x"}),
		enclaveSocketTestTool(enclaveContainerMcpEvsDelete, map[string]any{"repo": "agents", "path": "inbox"}),
		enclaveSocketTestTool(enclaveContainerMcpEvsWrite, map[string]any{"repo": "agent-x", "path": "./inbox/a1/m2.json"}),
		enclaveSocketTestTool(enclaveContainerMcpEvsWrite, map[string]any{"repo": "agent-x", "path": "notes/../inbox/a1/m3.json"}),
		enclaveSocketTestTool(enclaveContainerMcpEvsDelete, map[string]any{"repo": "agent-x", "path": "/inbox/a1"}),
	}
	for i, params := range refused {
		session.send(i+1, "tools/call", params)
		if _, code := session.answer(); code != enclaveContainerSocketRefusedCode {
			t.Errorf("%v answered %d", params, code)
		}
	}
	forwarded := []map[string]any{
		enclaveSocketTestTool(enclaveContainerMcpEvsWrite, map[string]any{"repo": "agents", "path": "notes/inbox.md"}),
		enclaveSocketTestTool(enclaveContainerMcpEvsWrite, map[string]any{"repo": "agents", "path": "inboxes/a1"}),
		enclaveSocketTestTool("evs_read", map[string]any{"repo": "agents", "path": "inbox/a1/m1.json"}),
	}
	for i, params := range forwarded {
		session.send(100+i, "tools/call", params)
		if _, code := session.answer(); code != 0 {
			t.Errorf("%v answered %d", params, code)
		}
	}
	if got := len(test.host.took()); got != len(forwarded) {
		t.Errorf("the daemon took %d calls, want only the %d forwarded", got, len(forwarded))
	}

	// with SKILL's guard wired, an inbox path in a repo that keeps no inbox is an ordinary path
	guarded := newEnclaveSocketTest(t, nil, func(ctx context.Context, repo string, path string) bool {
		return repo == "agents"
	})
	session, _ = guarded.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{"mode": DaemonModeMcp})
	session.send(1, "tools/call", enclaveSocketTestTool(enclaveContainerMcpEvsWrite, map[string]any{"repo": "work", "path": "inbox/todo.md"}))
	if _, code := session.answer(); code != 0 {
		t.Errorf("an ordinary repo's inbox/ path answered %d", code)
	}
	session.send(2, "tools/call", enclaveSocketTestTool(enclaveContainerMcpEvsWrite, map[string]any{"repo": "agents", "path": "inbox/a1/m1.json"}))
	if _, code := session.answer(); code != enclaveContainerSocketRefusedCode {
		t.Errorf("the agents repo's inbox answered %d", code)
	}
}

func TestEnclaveContainerSocketGatewayToken(t *testing.T) {
	gateway := &enclaveSocketTestGateway{}
	test := newEnclaveSocketTest(t, gateway, nil)
	session, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{"mode": DaemonModeControl})
	if refusal != "" {
		t.Fatalf("the session was refused: %s", refusal)
	}
	session.send(1, EnclaveContainerGatewayTokenMethod, &EnclaveContainerTokenRequest{Harness: "codex"})
	result, code := session.answer()
	token := &EnclaveContainerToken{}
	if code != 0 || json.Unmarshal(result, token) != nil || !strings.HasPrefix(token.Token, "ur_gw_") {
		t.Errorf("the container's grant answered %d %s", code, result)
	}
	// another grant, and no grant, mint nothing
	for i, harness := range []string{"claude", "aider"} {
		session.send(2+i, EnclaveContainerGatewayTokenMethod, &EnclaveContainerTokenRequest{Harness: harness})
		if _, code := session.answer(); code != DaemonRpcFailed {
			t.Errorf("%s's token answered %d", harness, code)
		}
	}
	if !slices.Equal(gateway.minted, []string{"codex"}) {
		t.Errorf("minted for %v", gateway.minted)
	}
	session.send(4, EnclaveContainerGatewayGrantMethod, &EnclaveContainerGrantRequest{Harness: "opencode"})
	if _, code := session.answer(); code != 0 || len(gateway.made) != 1 || !gateway.made[0].Tainted || gateway.made[0].Harness != test.harness {
		t.Errorf("the grant request answered %d, made %v", code, gateway.made)
	}
	// nothing else of control passes, and no confirmation comes from a container
	session.send(5, "status", nil)
	if _, code := session.answer(); code != daemonRpcMethodNotFound {
		t.Errorf("status answered %d", code)
	}
	line, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 6, "method": EnclaveContainerGatewayGrantMethod,
		"params": map[string]any{"harness": "codex"}, "ur_confirmed": true})
	if _, err := session.conn.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, code := session.answer(); code != DaemonRpcConfirmationRequired {
		t.Errorf("a forged confirmation answered %d", code)
	}
	if len(test.host.dispatched) != 0 {
		t.Errorf("control calls reached the daemon's methods: %v", test.host.dispatched)
	}

	// with no gateway wired both refuse
	unwired := newEnclaveSocketTest(t, nil, nil)
	session, _ = unwired.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{"mode": DaemonModeControl})
	session.send(1, EnclaveContainerGatewayTokenMethod, &EnclaveContainerTokenRequest{Harness: "codex"})
	if _, code := session.answer(); code != DaemonRpcFailed {
		t.Errorf("an unwired gateway's token answered %d", code)
	}
}

func TestEnclaveContainerSocketRefusesOtherModes(t *testing.T) {
	test := newEnclaveSocketTest(t, nil, nil)
	session, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestRelay), map[string]any{
		"mode": DaemonModeGit, "repo": "net/repo", "service": daemonGitUploadPack,
	})
	if refusal != DaemonHelloErrorMode {
		t.Errorf("git through the container socket was answered %q", refusal)
	}
	<-session.done
	hook, refusal := test.open(enclaveSocketTestPeer(enclaveSocketTestHook), map[string]any{"mode": DaemonModeHook})
	if refusal != "" {
		t.Fatalf("the hook's session was refused: %s", refusal)
	}
	hook.send(1, "status", map[string]any{})
	if _, code := hook.answer(); code != daemonRpcMethodNotFound {
		t.Errorf("a hook session's other method answered %d", code)
	}
	if len(test.host.dispatched) != 0 {
		t.Errorf("the daemon took %v", test.host.dispatched)
	}
}

// A listener of conns a test hands it.
type enclaveSocketTestListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (self *enclaveSocketTestListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

func (self *enclaveSocketTestListener) Close() error {
	self.once.Do(func() { close(self.closed) })
	return nil
}

func (self *enclaveSocketTestListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "synthetic", Net: "unix"}
}

func TestEnclaveContainerSocketBoundsSessions(t *testing.T) {
	test := newEnclaveSocketTest(t, nil, nil)
	test.socket.settings = &EnclaveContainerSocketSettings{Path: "/run/ur/container/ur.sock", MountPath: "/run/ur/ur.sock", SessionCount: 1}
	listener := &enclaveSocketTestListener{conns: make(chan net.Conn), closed: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- test.socket.Serve(ctx, listener)
	}()
	first, firstServer := net.Pipe()
	test.setPeer(firstServer, enclaveSocketTestPeer(enclaveSocketTestRelay))
	listener.conns <- firstServer
	line, _ := json.Marshal(map[string]any{"ur_local": 1, "version": "v-test", "mode": DaemonModeMcp})
	if _, err := first.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(first).ReadBytes('\n'); err != nil {
		t.Fatal(err)
	}
	// the first session is open: a second is closed at once
	second, secondServer := net.Pipe()
	test.setPeer(secondServer, enclaveSocketTestPeer(enclaveSocketTestRelay))
	listener.conns <- secondServer
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Error("a session past the bound was served")
	}
	cancel()
	if err := <-served; err != nil {
		t.Errorf("the socket ended with %v", err)
	}
	first.Close()
	second.Close()
}
