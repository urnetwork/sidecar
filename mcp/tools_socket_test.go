//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's socket tools (SOCK-M5-14) on the tool framework, with the daemon's sockets faked: each tool's tier and hints;
// socket_listen running as W under a covering grant, recorded and naming the grant, and outward without one, its
// action held on record-m2-01-canonical-action-detail and a pending gate naming the approval; other namespaces and
// ports refused; the listing's share/ names left out and its trust a member's; and each MCP version's wire and output
// schemas on the four tools.

package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The daemon's sockets, faked: a listing, the listens it holds, and every Listen it was asked for.
type fakeMcpSockets struct {
	stateLock sync.Mutex
	listing   *sidecar.DaemonSocketListReply
	listens   map[string]*sidecar.DaemonSocketStatus
	asked     []string
}

func newFakeMcpSockets() *fakeMcpSockets {
	return &fakeMcpSockets{
		listing: &sidecar.DaemonSocketListReply{Names: []*sidecar.DaemonSocketName{}, Complete: true},
		listens: map[string]*sidecar.DaemonSocketStatus{},
	}
}

func (self *fakeMcpSockets) ListNames(ctx context.Context, networkId sidecar.Id) (*sidecar.DaemonSocketListReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.listing, nil
}

func (self *fakeMcpSockets) Status(networkId sidecar.Id, name string) (*sidecar.DaemonSocketStatus, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	status, ok := self.listens[name]
	return status, ok
}

func (self *fakeMcpSockets) Listen(ctx context.Context, networkId sidecar.Id, address string, target string) (*sidecar.DaemonSocketListenReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked = append(self.asked, address+" "+target)
	if _, ok := self.listens[address]; ok {
		return nil, sidecar.ErrDaemonSocketListening
	}
	status := &sidecar.DaemonSocketStatus{NetworkId: networkId, Kind: sidecar.DaemonSocketKindListen, Name: address, Target: target, Serving: true}
	self.listens[address] = status
	return &sidecar.DaemonSocketListenReply{Status: status}, nil
}

func (self *fakeMcpSockets) Unlisten(networkId sidecar.Id, name string) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	_, ok := self.listens[name]
	delete(self.listens, name)
	return ok
}

func (self *fakeMcpSockets) listensAsked() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.asked...)
}

// A tool network whose allowed grants carry a grant id, and whose §5.4 gate answers what a test sets.
type fakeMcpSocketNetwork struct {
	*fakeMcpToolNetwork
	grantId    []byte
	authorized []*sidecar.SidecarAction
	authorize  error
}

func (self *fakeMcpSocketNetwork) Allow(action protocol.AclAction, resource sidecar.AclResource, now time.Time) (sidecar.AclCheck, bool) {
	check, installed := self.fakeMcpToolNetwork.Allow(action, resource, now)
	if check.Allowed {
		check.GrantId = self.grantId
	}
	return check, installed
}

func (self *fakeMcpSocketNetwork) Authorize(ctx context.Context, action *sidecar.SidecarAction, decision *bridge.Signed) error {
	self.authorized = append(self.authorized, action)
	return self.authorize
}

// A server with the socket tools on fake sockets, a session of a harness's relay bound to a fresh run.
type testSocketToolEnv struct {
	*hookTestEnv
	network *fakeMcpSocketNetwork
	sockets *fakeMcpSockets
	catalog *McpCatalog
	sink    *testCallSink
	claude  *sidecartest.FakeHarness
}

func newTestSocketToolEnv(t *testing.T, listenAction mcpSocketListenActionFunction) *testSocketToolEnv {
	t.Helper()
	env := &testSocketToolEnv{hookTestEnv: newHookTestEnv(t), sockets: newFakeMcpSockets(), sink: &testCallSink{}}
	env.network = &fakeMcpSocketNetwork{fakeMcpToolNetwork: newFakeMcpToolNetwork(env.hookTestEnv.network, testToolCredential), grantId: []byte{0xab, 0xcd}}
	env.daemon.hostNetwork(env.networkId, env.network)
	env.catalog = NewMcpCatalog(env.server.settings.Mcp, env.clock, env.sink)
	if listenAction == nil {
		listenAction = mcpSocketListenAction
	}
	addSocketTools(env.catalog, func() McpSockets { return env.sockets }, listenAction)
	env.catalog.Install(env.server)
	env.claude = env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := env.claude.SessionStart("socket session", "startup"); err != nil {
		t.Fatal(err)
	}
	return env
}

// A session at version, 2026-07-28's taking none.
func (self *testSocketToolEnv) conn(version string) *testMcpConn {
	self.t.Helper()
	conn := startTestMcpConn(self.t, self.server, self.claude.RelayHello("builder"))
	if version != "2026-07-28" {
		conn.initialize(version)
	}
	return conn
}

// A tools/call at version.
func (self *testSocketToolEnv) callTool(conn *testMcpConn, version string, name string, arguments any) *testMcpResponse {
	self.t.Helper()
	params := map[string]any{"name": name, "arguments": arguments}
	if version == "2026-07-28" {
		params["_meta"] = testMcpLatestMeta()
	}
	return conn.call("tools/call", params)
}

// A result's data, decoded into data.
func testSocketToolData(t *testing.T, response *testMcpResponse, data any) *mcpResultEnvelope {
	t.Helper()
	envelope := testEnvelopeOf(t, response)
	if err := json.Unmarshal(envelope.Data, data); err != nil {
		t.Fatalf("data %s: %v", envelope.Data, err)
	}
	return envelope
}

// The four tools carry §16.5's tiers and hints, and the daemon's catalog holds them registered, none still unbuilt.
func TestSocketToolTiers(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	conn := env.conn("2025-06-18")
	listed := struct {
		Tools []struct {
			Name        string `json:"name"`
			Annotations struct {
				ReadOnlyHint  bool  `json:"readOnlyHint"`
				OpenWorldHint *bool `json:"openWorldHint"`
			} `json:"annotations"`
		} `json:"tools"`
	}{}
	response := conn.call("tools/list", map[string]any{})
	if response.Error != nil {
		t.Fatal(response.Error.Message)
	}
	json.Unmarshal(response.Result, &listed)
	want := map[string][2]bool{
		"socket_list":     {true, false},
		"socket_status":   {true, false},
		"socket_listen":   {false, true},
		"socket_unlisten": {false, false},
	}
	for _, tool := range listed.Tools {
		hints, ok := want[tool.Name]
		if !ok {
			continue
		}
		delete(want, tool.Name)
		if tool.Annotations.ReadOnlyHint != hints[0] || tool.Annotations.OpenWorldHint == nil || *tool.Annotations.OpenWorldHint != hints[1] {
			t.Errorf("%s's hints %+v", tool.Name, tool.Annotations)
		}
	}
	if len(want) != 0 {
		t.Errorf("not listed: %v", want)
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	if err := checkMcpCatalog(NewDaemonMcpCatalog(newTestMcpServer(newFakeMcpDaemon(), clock), nil)); err != nil {
		t.Error(err)
	}
}

// Under a covering grant socket_listen runs as W: no gate, the listen to 127.0.0.1, the grant's id in the result, and
// the call recorded as a W call is.
func TestSocketListenCoveredRunsAsWrite(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	env.network.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_LISTEN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceSocket, Name: "db/primary"}})
	conn := env.conn("2025-06-18")
	out := &mcpSocketListenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "DB/Primary", "local_port": 5432}), out)
	if out.Status != "listening" || out.GrantId != hex.EncodeToString([]byte{0xab, 0xcd}) || !out.Serving {
		t.Errorf("result %+v", out)
	}
	if asked := env.sockets.listensAsked(); len(asked) != 1 || asked[0] != "db/primary 127.0.0.1:5432" {
		t.Errorf("listens %q", asked)
	}
	if len(env.network.authorized) != 0 {
		t.Error("a covered listen went through the gate")
	}
	sunk := env.sink.sunk()
	if len(sunk) != 1 || sunk[0].toolName != "socket_listen" || sunk[0].err != nil {
		t.Errorf("sunk %+v", sunk)
	}
}

// With no covering grant socket_listen is outward: its action is built for §5.4's gate, and while the listen kind's row
// waits on its question that build refuses, so nothing listens and nothing is recorded as a W call.
func TestSocketListenUncoveredIsHeld(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	conn := env.conn("2025-06-18")
	wantMcpError(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432}), McpCodeRefused, "approval")
	if len(env.sockets.listensAsked()) != 0 || len(env.network.authorized) != 0 || len(env.sink.sunk()) != 0 {
		t.Error("a held listen acted")
	}
}

// Once the action builds, an uncovered listen passes the gate first: a pending gate names its approval and listens on
// nothing, an allowed one listens.
func TestSocketListenUncoveredPassesTheGate(t *testing.T) {
	built := func(call *McpCall, name string) (*sidecar.SidecarAction, error) {
		return &sidecar.SidecarAction{Kind: sidecar.SidecarActionListen, Canonical: []byte(name), Risk: sidecar.SidecarRiskNormal}, nil
	}
	env := newTestSocketToolEnv(t, built)
	approvalId := sidecar.NewId()
	env.network.authorize = &sidecar.ApprovalPendingError{ApprovalId: approvalId}
	conn := env.conn("2025-06-18")
	out := &mcpSocketListenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432}), out)
	if out.Status != "approval_pending" || out.ApprovalId != approvalId.String() || len(env.sockets.listensAsked()) != 0 {
		t.Errorf("a pending gate: %+v", out)
	}
	env.network.authorize = nil
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432}), out)
	if out.Status != "listening" || out.GrantId != "" || len(env.sockets.listensAsked()) != 1 || len(env.network.authorized) != 2 {
		t.Errorf("an allowed gate: %+v", out)
	}
}

// Only application names and real ports: tls/, smtp/, share/ and ur/ names and a port out of range are refused before
// anything acts.
func TestSocketToolsRefuseOtherNamespaces(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	conn := env.conn("2025-06-18")
	for _, name := range []string{"tls/443/blog", "smtp/25/mx", "share/abcdefghijklmnopqrstuvwxyz", "ur/smtpedge", "c/x", "db/../x"} {
		for _, tool := range []string{"socket_listen", "socket_status", "socket_unlisten"} {
			wantMcpError(t, env.callTool(conn, "2025-06-18", tool, map[string]any{"name": name, "local_port": 80}), McpCodeInvalidArguments, "")
		}
	}
	env.network.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_LISTEN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceSocket, Name: "db/primary"}})
	for _, port := range []int{0, 65536, -1} {
		wantMcpError(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": port}), McpCodeInvalidArguments, "")
	}
	if len(env.sockets.listensAsked()) != 0 {
		t.Error("a refused call listened")
	}
}

// socket_list is a member's data, leaves share/ names out and keeps the listing's counts; socket_status reports the
// daemon's listen; socket_unlisten ends it, as a W call.
func TestSocketListStatusAndUnlisten(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	env.sockets.listing = &sidecar.DaemonSocketListReply{
		Names: []*sidecar.DaemonSocketName{
			{Name: "db/primary", Local: true},
			{Name: "share/abcdefghijklmnopqrstuvwxyz"},
			{Name: "tls/443/blog"},
		},
		DroppedCount: 2,
	}
	env.sockets.listens["db/primary"] = &sidecar.DaemonSocketStatus{Name: "db/primary", Target: "127.0.0.1:5432", Serving: false, Inflight: 3}
	conn := env.conn("2025-06-18")
	list := &mcpSocketListOut{}
	envelope := testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_list", map[string]any{}), list)
	if envelope.Trust != McpTrustMember || len(list.Names) != 2 || list.Names[0].Name != "db/primary" || !list.Names[0].Listening ||
		list.Names[1].Name != "tls/443/blog" || list.DroppedCount != 2 || list.Complete {
		t.Errorf("list %+v, trust %s", list, envelope.Trust)
	}
	status := &mcpSocketStatusOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_status", map[string]any{"name": "db/primary"}), status)
	if !status.Listening || status.Serving || status.Inflight != 3 || status.LocalPort != 5432 {
		t.Errorf("status %+v", status)
	}
	unlisten := &mcpSocketUnlistenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_unlisten", map[string]any{"name": "db/primary"}), unlisten)
	if unlisten.Status != "unlistened" {
		t.Errorf("unlisten %+v", unlisten)
	}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_unlisten", map[string]any{"name": "db/primary"}), unlisten)
	if unlisten.Status != "not_listening" {
		t.Errorf("a second unlisten %+v", unlisten)
	}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_status", map[string]any{"name": "db/primary"}), status)
	if status.Listening {
		t.Errorf("status after the unlisten %+v", status)
	}
	if sunk := env.sink.sunk(); len(sunk) != 2 || sunk[0].toolName != "socket_unlisten" {
		t.Errorf("sunk %+v", sunk)
	}
}

// §22.5: at every MCP version each socket tool's result validates against that version's wire schema, and its
// structuredContent against the tool's declared outputSchema.
func TestSocketToolsSchemasAtEveryVersion(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	env.network.allow(McpAccess{Action: protocol.AclAction_ACL_ACTION_LISTEN, Resource: sidecar.AclResource{Kind: sidecar.AclResourceSocket, Name: "db/primary"}})
	env.sockets.listing = &sidecar.DaemonSocketListReply{Names: []*sidecar.DaemonSocketName{{Name: "db/primary"}}, Complete: true}
	calls := []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "socket_list", arguments: map[string]any{}},
		{tool: "socket_listen", arguments: map[string]any{"name": "db/primary", "local_port": 5432}},
		{tool: "socket_status", arguments: map[string]any{"name": "db/primary"}},
		{tool: "socket_unlisten", arguments: map[string]any{"name": "db/primary"}},
	}
	for _, version := range testMcpVersions {
		conn := env.conn(version)
		for _, call := range calls {
			response := env.callTool(conn, version, call.tool, call.arguments)
			if response.Error != nil {
				t.Fatalf("%s %s: %s", version, call.tool, response.Error.Message)
			}
			testValidateWire(t, version, response.Result)
			result := testWireResult{}
			json.Unmarshal(response.Result, &result)
			var structured any
			json.Unmarshal(result.StructuredContent, &structured)
			if err := testOutputSchema(t, conn, version, call.tool).Validate(structured); err != nil {
				t.Errorf("%s %s: structuredContent against outputSchema: %v", version, call.tool, err)
			}
		}
	}
}
