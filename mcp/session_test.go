//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.4's session limits on a fake clock: a ninth call waits for a slot, a twenty-first W call in a second is refused,
// and a call ends at 30 s. And the session's agent id (§5.5, owner decision 470; QD-981): its network's registration,
// taken at the session's first call there and kept for its life, one per label across sessions and a restart, another
// for another label and in another network, a new one after AgentRevoke for the label's next session alone, none for a
// session with no agent, and a call refused where no id can be taken; each outward tool's action carrying it.

package mcp

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The fake's agent registry, as a Sidecar's keychain.ur keeps one (Sidecar.ResolveAgentId): each label's id drawn at
// its first ask and kept apart from the network's local state, so it outlives a restart that reopens the runs and a
// test's failing of that state's writes.
func (self *fakeMcpNetwork) ResolveAgentId(label string) (sidecar.Id, error) {
	if _, err := sidecar.ParseSidecarAgent(label); err != nil {
		return sidecar.Id{}, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if agentId, ok := self.labelAgentIds[label]; ok {
		return agentId, nil
	}
	if self.labelAgentIds == nil {
		self.labelAgentIds = map[string]sidecar.Id{}
	}
	agentId := sidecar.NewId()
	self.labelAgentIds[label] = agentId
	return agentId, nil
}

// test_agent_id's answer: the agent id its call binds to, empty for none, and the call's network.
type testAgentIdOut struct {
	AgentId   string `json:"agent_id"`
	NetworkId string `json:"network_id"`
}

// Installs test_agent_id, which answers what every tool binds its writes and actions to (mcpCallAgentId), and counts
// its runs on ran when it is set.
func installTestAgentId(server *McpServer, ran *atomic.Int32) {
	server.Install(func(server *gomcp.Server) {
		gomcp.AddTool(server, &gomcp.Tool{Name: "test_agent_id", Description: "answers the call's agent id"},
			func(ctx context.Context, request *gomcp.CallToolRequest, in testEchoIn) (*gomcp.CallToolResult, testAgentIdOut, error) {
				if ran != nil {
					ran.Add(1)
				}
				out := testAgentIdOut{}
				if call := McpCallOf(ctx); call != nil {
					out.NetworkId = call.NetworkId.String()
					if agentId := mcpCallAgentId(call); agentId != nil {
						out.AgentId = agentId.String()
					}
				}
				return nil, out, nil
			})
	})
}

// The agent id a call of test_agent_id on conn binds to in network, its id's text, or the only one for "".
func testAgentIdOf(t *testing.T, conn *testMcpConn, network string) string {
	t.Helper()
	arguments := map[string]any{"text": "x"}
	if network != "" {
		arguments["network"] = network
	}
	response := conn.callTool("test_agent_id", arguments)
	if response.Error != nil {
		t.Fatalf("test_agent_id: %d %s", response.Error.Code, response.Error.Message)
	}
	result := struct {
		StructuredContent testAgentIdOut `json:"structuredContent"`
	}{}
	if err := json.Unmarshal(response.Result, &result); err != nil {
		t.Fatal(err)
	}
	return result.StructuredContent.AgentId
}

// A session of hello on server, initialized.
func startTestAgentSession(t *testing.T, server *McpServer, agent string) *testMcpConn {
	t.Helper()
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp, Agent: agent})
	conn.initialize("2025-11-25")
	return conn
}

// The open session of agent's label on server; fails when there is not exactly one.
func testSessionOf(t *testing.T, server *McpServer, label string) *McpSession {
	t.Helper()
	var found *McpSession
	for _, session := range server.Sessions() {
		if agent := session.Agent(); agent != nil && agent.Label == label {
			if found != nil {
				t.Fatalf("two sessions of %s", label)
			}
			found = session
		}
	}
	if found == nil {
		t.Fatalf("no session of %s", label)
	}
	return found
}

// On a T2 sidecar: two sessions of one label take the one agent_id the network's keychain.ur registered for it, and so
// does a session after a restart over the same state; another label takes another, and a session with no agent none,
// its calls running all the same. Once AgentRevoke ends the registration, a session open since keeps its id and the
// label's next session takes a new one, which holds for the sessions after it.
func TestSessionAgentIdOnePerLabel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), mcpTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, sidecartest.DefaultNetSettings())
	defer net.Close()
	testSidecar, err := net.AddSidecar("daemon", nil)
	if err != nil {
		t.Fatal(err)
	}
	networkId := testSidecar.NetworkId()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	// a daemon over the sidecar as it stands, as a restarted daemon makes one
	newServer := func() *McpServer {
		daemon := newFakeMcpDaemon()
		daemon.hostNetwork(networkId, testSidecar.Sidecar())
		settings := NewMcpServerSettings(sidecar.DefaultSidecarSettings(), sidecar.Version)
		settings.Clock = clock
		settings.Processes = sidecartest.NewFakeProcessTable(clock)
		server := NewMcpServer(daemon, settings)
		server.Binder().SetConfigCheck(func(ctx context.Context, harness string, cwd string) (bool, error) { return false, nil })
		installTestAgentId(server, nil)
		return server
	}
	server := newServer()

	first := startTestAgentSession(t, server, "builder")
	builderId := testAgentIdOf(t, first, "")
	registered, err := testSidecar.Sidecar().ResolveAgentId("builder")
	if err != nil || builderId == "" || builderId != registered.String() {
		t.Fatalf("the session's id %q, the registration's %s: %v", builderId, registered, err)
	}
	if agentId := testSessionOf(t, server, "builder").AgentId(networkId); agentId == nil || agentId.String() != builderId {
		t.Errorf("McpSession.AgentId gives %v", agentId)
	}
	if got := testAgentIdOf(t, first, ""); got != builderId {
		t.Errorf("the session's second call names %q", got)
	}
	second := startTestAgentSession(t, server, "builder")
	if got := testAgentIdOf(t, second, ""); got != builderId {
		t.Errorf("a second session of the label names %q, not %s", got, builderId)
	}
	reviewer := startTestAgentSession(t, server, "reviewer")
	reviewerId := testAgentIdOf(t, reviewer, "")
	if reviewerId == "" || reviewerId == builderId {
		t.Errorf("another label names %q beside %s", reviewerId, builderId)
	}
	none := startTestAgentSession(t, server, "")
	if got := testAgentIdOf(t, none, ""); got != "" {
		t.Errorf("a session with no agent names %q", got)
	}

	// a restart: the sidecar and its instance again on their durable state alone, and a new daemon over them
	if err := testSidecar.Restart(); err != nil {
		t.Fatal(err)
	}
	if err := testSidecar.AwaitState(ctx, sidecar.SidecarStateOnline); err != nil {
		t.Fatal(err)
	}
	server = newServer()
	open := startTestAgentSession(t, server, "builder")
	if got := testAgentIdOf(t, open, ""); got != builderId {
		t.Fatalf("after a restart the label names %q, not %s", got, builderId)
	}
	if got := testAgentIdOf(t, startTestAgentSession(t, server, "reviewer"), ""); got != reviewerId {
		t.Errorf("after a restart another label names %q, not %s", got, reviewerId)
	}

	// AgentRevoke ends the registration: the open session keeps its id, the label's next session takes a new one
	if err := testSidecar.Sidecar().AgentRevoke(registered); err != nil {
		t.Fatal(err)
	}
	if got := testAgentIdOf(t, open, ""); got != builderId {
		t.Errorf("a session open across the revocation names %q, not its own %s", got, builderId)
	}
	next := testAgentIdOf(t, startTestAgentSession(t, server, "builder"), "")
	if next == "" || next == builderId || next == reviewerId {
		t.Fatalf("the label's session after the revocation names %q", next)
	}
	if got := testAgentIdOf(t, startTestAgentSession(t, server, "builder"), ""); got != next {
		t.Errorf("the new registration does not hold: %q, then %q", next, got)
	}
}

// One agent_id per (sidecar, label): a session acting in two networks takes each network's own id for its label, at
// its first call in each, and names each in its own network.
func TestSessionAgentIdPerNetwork(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	firstId, first := daemon.host(t, sidecar.SidecarStateOnline, clock)
	secondId, second := daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	installTestAgentId(server, nil)
	conn := startTestAgentSession(t, server, "builder")
	session := testSessionOf(t, server, "builder")
	if session.AgentId(firstId) != nil {
		t.Fatal("an id before the session's first call in the network")
	}
	inFirst := testAgentIdOf(t, conn, firstId.String())
	inSecond := testAgentIdOf(t, conn, secondId.String())
	wantFirst, err := first.ResolveAgentId("builder")
	if err != nil {
		t.Fatal(err)
	}
	wantSecond, err := second.ResolveAgentId("builder")
	if err != nil {
		t.Fatal(err)
	}
	if inFirst != wantFirst.String() || inSecond != wantSecond.String() || inFirst == inSecond {
		t.Fatalf("ids %q and %q, registered %s and %s", inFirst, inSecond, wantFirst, wantSecond)
	}
	if agentId := session.AgentId(firstId); agentId == nil || *agentId != wantFirst {
		t.Errorf("the session names %v in the first network", agentId)
	}
	if agentId := session.AgentId(secondId); agentId == nil || *agentId != wantSecond {
		t.Errorf("the session names %v in the second network", agentId)
	}
	if testAgentIdOf(t, conn, firstId.String()) != inFirst {
		t.Error("the first network's id moved")
	}
}

// A network as McpNetwork alone, keeping no agents' ids.
type testNoAgentsNetwork struct {
	network *fakeMcpNetwork
}

func (self *testNoAgentsNetwork) Status() sidecar.SidecarStatus {
	return self.network.Status()
}

func (self *testNoAgentsNetwork) Runs() (*sidecar.RunStore, error) {
	return self.network.Runs()
}

func (self *testNoAgentsNetwork) Spool() (*sidecar.Spool, error) {
	return self.network.Spool()
}

func (self *testNoAgentsNetwork) LocalStore() sidecar.SidecarStore {
	return self.network.LocalStore()
}

// A network whose registry fails while broken is set, as a keychain that cannot read or write does.
type testFailingAgentsNetwork struct {
	*fakeMcpNetwork
	broken atomic.Bool
}

func (self *testFailingAgentsNetwork) ResolveAgentId(label string) (sidecar.Id, error) {
	if self.broken.Load() {
		return sidecar.Id{}, sidecar.ErrSidecarStoreFailed
	}
	return self.fakeMcpNetwork.ResolveAgentId(label)
}

// A call that cannot take its session's agent id runs nothing: refused, retryably, while the network's keychain
// cannot read or write the registration, and taken at the next call once it can; refused for good in a network that
// keeps no agents' ids, where a session with no agent still runs.
func TestSessionAgentIdRefusedWhereNoneIsTaken(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	networkId, network := daemon.host(t, sidecar.SidecarStateOnline, clock)
	failing := &testFailingAgentsNetwork{fakeMcpNetwork: network}
	failing.broken.Store(true)
	daemon.hostNetwork(networkId, failing)
	server := newTestMcpServer(daemon, clock)
	var ran atomic.Int32
	installTestAgentId(server, &ran)

	conn := startTestAgentSession(t, server, "builder")
	response := conn.callTool("test_agent_id", map[string]any{"text": "x"})
	wantMcpError(t, response, McpCodeFailedPrecondition, "agent id cannot be read")
	if _, retryable := mcpErrorCode(t, responseError(response)); !retryable {
		t.Error("a registry that could not be read is not retryable")
	}
	if ran.Load() != 0 || testSessionOf(t, server, "builder").AgentId(networkId) != nil {
		t.Fatalf("a call whose registration failed ran %d times or left the session an id", ran.Load())
	}
	failing.broken.Store(false)
	want, err := network.ResolveAgentId("builder")
	if err != nil {
		t.Fatal(err)
	}
	if got := testAgentIdOf(t, conn, ""); got != want.String() || ran.Load() != 1 {
		t.Errorf("once the keychain reads, the session names %q, not %s, in %d runs", got, want, ran.Load())
	}

	// a network that keeps no agents' ids takes no call of a session with an agent, and every one of a session with none
	daemon.hostNetwork(networkId, &testNoAgentsNetwork{network: network})
	other := startTestAgentSession(t, server, "reviewer")
	refused := other.callTool("test_agent_id", map[string]any{"text": "x"})
	wantMcpError(t, refused, McpCodeFailedPrecondition, "keeps no agent ids")
	if _, retryable := mcpErrorCode(t, responseError(refused)); retryable || ran.Load() != 1 {
		t.Errorf("a network keeping no agents' ids: retryable %t, %d runs", retryable, ran.Load())
	}
	if got := testAgentIdOf(t, startTestAgentSession(t, server, ""), ""); got != "" || ran.Load() != 2 {
		t.Errorf("a session with no agent names %q in %d runs", got, ran.Load())
	}
}

// With eight calls in flight a ninth waits rather than being refused, and runs once one of the eight returns.
func TestNinthCallWaits(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	block := newTestBlockTool()
	block.install(server)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	conn.initialize("2025-11-25")
	session := server.Sessions()[0]
	waiting := make(chan struct{}, 1)
	session.limits.waitHook = func() {
		waiting <- struct{}{}
	}

	slotCount := server.settings.Mcp.SessionCallCount
	if slotCount != 8 {
		t.Fatalf("SessionCallCount is %d, want §16.4's 8", slotCount)
	}
	responses := []<-chan *testMcpResponse{}
	for i := 0; i < slotCount; i += 1 {
		response := conn.start("tools/call", map[string]any{"name": "test_block", "arguments": map[string]any{"text": "x"}})
		select {
		case answer, ok := <-response:
			if !ok {
				conn.stateLock.Lock()
				t.Fatalf("call %d: the session ended: serve %v, read %v", i, conn.serveErr, conn.readErr)
			}
			t.Fatalf("call %d answered before it blocked: %+v %s", i, answer.Error, answer.Result)
		case <-block.entered:
		case <-contextDone(t):
			t.Fatal("no call entered")
		}
		responses = append(responses, response)
	}
	ninth := conn.start("tools/call", map[string]any{"name": "test_block", "arguments": map[string]any{"text": "ninth"}})
	select {
	case <-waiting:
	case <-contextDone(t):
		t.Fatal("the ninth call did not wait")
	}
	select {
	case <-block.entered:
		t.Fatal("a ninth call ran with eight in flight")
	default:
	}
	if count := session.limits.inFlightCount(); count != slotCount {
		t.Fatalf("%d calls in flight", count)
	}
	block.released <- struct{}{}
	block.awaitEntered(t)
	for i := 0; i < slotCount; i += 1 {
		block.released <- struct{}{}
	}
	for _, response := range append(responses, ninth) {
		if answer := conn.await(response); answer.Error != nil {
			t.Errorf("a call failed: %s", answer.Error.Message)
		}
	}
}

// Twenty W calls in a second pass and the twenty-first is refused, retryably; time refills the bucket at the rate.
func TestTwentyFirstWriteRefused(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	server := newTestMcpServer(newFakeMcpDaemon(), clock)
	session := server.newSession(&sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	rate := server.settings.Mcp.SessionWriteRate
	if rate.Count != 20 || rate.Burst != 20 || rate.Interval != time.Second {
		t.Fatalf("SessionWriteRate is %+v, want §16.4's 20 a second", rate)
	}
	for i := 0; i < 20; i += 1 {
		if err := session.AdmitWrite(); err != nil {
			t.Fatalf("write %d refused: %s", i+1, err)
		}
	}
	err := session.AdmitWrite()
	if err == nil {
		t.Fatal("the twenty-first write passed")
	}
	if code, retryable := mcpErrorCode(t, err); code != McpCodeRateLimited || !retryable {
		t.Errorf("refused with %d, retryable %t", code, retryable)
	}
	// one token comes back each 50 ms
	clock.Advance(49 * time.Millisecond)
	if session.AdmitWrite() == nil {
		t.Error("a write passed before a token came back")
	}
	clock.Advance(1 * time.Millisecond)
	if err := session.AdmitWrite(); err != nil {
		t.Errorf("a write after 50 ms: %s", err)
	}
	if session.AdmitWrite() == nil {
		t.Error("two writes on one token")
	}
	// a second's idle refills the burst and no more
	clock.Advance(10 * time.Second)
	for i := 0; i < 20; i += 1 {
		if err := session.AdmitWrite(); err != nil {
			t.Fatalf("write %d after an idle second refused: %s", i+1, err)
		}
	}
	if session.AdmitWrite() == nil {
		t.Error("the burst grew past 20 while idle")
	}
}

// A call still running at 30 s is answered with a retryable timeout at once, and its context ends then, not before.
func TestCallTimesOutAt30s(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	daemon := newFakeMcpDaemon()
	daemon.host(t, sidecar.SidecarStateOnline, clock)
	server := newTestMcpServer(daemon, clock)
	block := newTestBlockTool()
	block.install(server)
	conn := startTestMcpConn(t, server, &sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp})
	conn.initialize("2025-11-25")
	if timeout := server.settings.Mcp.CallTimeout; timeout != 30*time.Second {
		t.Fatalf("CallTimeout is %s, want §16.4's 30 s", timeout)
	}

	response := conn.start("tools/call", map[string]any{"name": "test_block", "arguments": map[string]any{"text": "x"}})
	callCtx := block.awaitEntered(t)
	clock.Advance(30*time.Second - time.Nanosecond)
	if callCtx.Err() != nil {
		t.Fatal("the call's context ended before 30 s")
	}
	select {
	case <-response:
		t.Fatal("answered before 30 s")
	default:
	}
	clock.Advance(time.Nanosecond)
	if callCtx.Err() == nil {
		t.Fatal("the call's context outlived 30 s")
	}
	answer := conn.await(response)
	wantMcpError(t, answer, McpCodeTimeout, "time limit")
	if code, retryable := mcpErrorCode(t, responseError(answer)); code != McpCodeTimeout || !retryable {
		t.Errorf("timeout %d, retryable %t", code, retryable)
	}
}

// An error's code and retryable bit, as the wire carries them.
func mcpErrorCode(t *testing.T, err error) (int64, bool) {
	t.Helper()
	code, retryable, ok := McpErrorCode(err)
	if !ok {
		t.Fatalf("not an mcp error: %s", err)
	}
	return code, retryable
}

// A test response's error, as a handler's error would read.
func responseError(response *testMcpResponse) error {
	return &jsonrpc.Error{Code: response.Error.Code, Message: response.Error.Message, Data: response.Error.Data}
}
