//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's bridge tools (MCP-M4-01) on the tool framework, with the daemon's bridges faked at the seam `ur bridge`
// shares: each tool's tier and hints; a forward and an exposure filed as MCP under the call's run, a forward's
// listener on loopback alone; a filing that waits answering approval_pending with its approval's id and the same call
// again answering its id; an exposure that is a map, a route or an exit; a retry answering the same rule id; close
// ending a forward, withdrawing a rule and revoking a grant, recorded as a W call is; what is not this sidecar's own
// answered with a constant refusal that names nothing; every malformed call refused before the bridges hear of it; and
// each MCP version's wire and output schemas on the four tools. The filings themselves, through the real gate, are
// record_effect_bridge_test.go's in the root.

package mcp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One call the fake bridges took.
type fakeMcpBridgeCall struct {
	method  string
	origin  *sidecar.BridgeFileOrigin
	expose  *sidecar.DaemonBridgeExposeParams
	forward *sidecar.DaemonBridgeForwardParams
	close   *sidecar.DaemonBridgeCloseParams
}

// The daemon's bridges, faked as the filer answers: a filing waits until the test approves, then files under an id
// that is a function of its params alone, as an approved use's rule id is of its effect key, so a retry answers the
// same id and files nothing more.
type fakeMcpBridges struct {
	stateLock sync.Mutex
	status    *sidecar.DaemonBridgeStatusReply
	approves  bool
	err       error
	// each filing's id by its params, and how many distinct filings there are
	filed map[string]string
	// ids closed
	closed []string
	calls  []fakeMcpBridgeCall
}

func newFakeMcpBridges() *fakeMcpBridges {
	return &fakeMcpBridges{
		status: &sidecar.DaemonBridgeStatusReply{List: &sidecar.DaemonBridgeList{State: "enforcing_document"}},
		filed:  map[string]string{},
	}
}

// The pending approval's id for a filing: a function of its params, as the gate's find-or-file answers one request
// for one action.
func fakeMcpBridgeApprovalId(key string) sidecar.Id {
	id := sidecar.Id{}
	copy(id[:], []byte(fmt.Sprintf("%-16s", key)))
	return id
}

// One filing under key: the error set, else pending until approved, else its id.
func (self *fakeMcpBridges) file(key string) (string, *sidecar.Id, error) {
	if self.err != nil {
		return "", nil, self.err
	}
	if !self.approves {
		approvalId := fakeMcpBridgeApprovalId(key)
		return "", &approvalId, nil
	}
	id, ok := self.filed[key]
	if !ok {
		id = hex.EncodeToString([]byte(fmt.Sprintf("%-32s", key))[:32])
		self.filed[key] = id
	}
	return id, nil, nil
}

func (self *fakeMcpBridges) Status(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar) (*sidecar.DaemonBridgeStatusReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, fakeMcpBridgeCall{method: "status"})
	if self.err != nil {
		return nil, self.err
	}
	return self.status, nil
}

func (self *fakeMcpBridges) Expose(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar, origin *sidecar.BridgeFileOrigin,
	params *sidecar.DaemonBridgeExposeParams) (*sidecar.DaemonBridgeFilingReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, fakeMcpBridgeCall{method: "expose", origin: origin, expose: params})
	encoded, _ := json.Marshal(params)
	ruleId, pending, err := self.file("expose " + string(encoded))
	if err != nil {
		return nil, err
	}
	if pending != nil {
		return &sidecar.DaemonBridgeFilingReply{ApprovalPendingId: pending}, nil
	}
	reply := &sidecar.DaemonBridgeFilingReply{RuleId: ruleId}
	if 0 < params.Port {
		reply.Address, reply.AddressFiled = "100.80.0.7", len(self.filed) == 1
	}
	return reply, nil
}

func (self *fakeMcpBridges) Forward(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar, origin *sidecar.BridgeFileOrigin,
	params *sidecar.DaemonBridgeForwardParams) (*sidecar.DaemonBridgeFilingReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, fakeMcpBridgeCall{method: "forward", origin: origin, forward: params})
	encoded, _ := json.Marshal(params)
	grantId, pending, err := self.file("forward " + string(encoded))
	if err != nil {
		return nil, err
	}
	if pending != nil {
		return &sidecar.DaemonBridgeFilingReply{ApprovalPendingId: pending}, nil
	}
	approvalId := fakeMcpBridgeApprovalId("spent")
	return &sidecar.DaemonBridgeFilingReply{
		GrantId: grantId, ApprovalId: &approvalId,
		Forward: &sidecar.DaemonBridgeForwardStatus{ForwardId: "0011223344556677", LocalPort: int(params.LocalPort), GrantId: grantId, Protocol: "tcp", Port: params.Port},
	}, nil
}

func (self *fakeMcpBridges) CloseId(ctx context.Context, networkId sidecar.Id, running *sidecar.Sidecar, origin *sidecar.BridgeFileOrigin,
	params *sidecar.DaemonBridgeCloseParams) (*sidecar.DaemonBridgeFilingReply, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.calls = append(self.calls, fakeMcpBridgeCall{method: "close", origin: origin, close: params})
	if self.err != nil {
		return nil, self.err
	}
	switch {
	case params.Id == "0011223344556677":
		return &sidecar.DaemonBridgeFilingReply{ForwardClosed: true}, nil
	case slices.Contains(self.closed, params.Id):
		// a withdrawn rule's id never returns (AD2)
		return nil, fmt.Errorf("%w: the rule is withdrawn already", sidecar.ErrBridgeFileRefused)
	case strings.HasPrefix(params.Id, "aa"):
		self.closed = append(self.closed, params.Id)
		return &sidecar.DaemonBridgeFilingReply{GrantId: params.Id}, nil
	case strings.HasPrefix(params.Id, "bb"):
		self.closed = append(self.closed, params.Id)
		return &sidecar.DaemonBridgeFilingReply{RuleId: params.Id}, nil
	}
	return nil, fmt.Errorf("%w: no rule of this host's and no forward's grant of its own under the id", sidecar.ErrBridgeFileRefused)
}

func (self *fakeMcpBridges) set(approves bool, err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.approves, self.err = approves, err
}

func (self *fakeMcpBridges) taken() []fakeMcpBridgeCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]fakeMcpBridgeCall{}, self.calls...)
}

func (self *fakeMcpBridges) filedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.filed)
}

// A server with one tool network, the bridge tools over fake bridges, and a Claude Code harness whose fresh session
// opened a run.
type testBridgeToolEnv struct {
	*hookTestEnv
	tools   *fakeMcpToolNetwork
	bridges *fakeMcpBridges
	catalog *McpCatalog
	sink    *testCallSink
	claude  *sidecartest.FakeHarness
	runId   sidecar.Id
}

func newTestBridgeToolEnv(t *testing.T) *testBridgeToolEnv {
	t.Helper()
	env := &testBridgeToolEnv{hookTestEnv: newHookTestEnv(t), bridges: newFakeMcpBridges(), sink: &testCallSink{}}
	env.tools = newFakeMcpToolNetwork(env.network, testToolCredential)
	env.daemon.hostNetwork(env.networkId, env.tools)
	env.catalog = NewMcpCatalog(env.server.settings.Mcp, env.clock, env.sink)
	addBridgeTools(env.catalog, func() McpBridges {
		if env.bridges == nil {
			return nil
		}
		return env.bridges
	})
	env.catalog.Install(env.server)
	env.claude = env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := env.claude.SessionStart("bridge session", "startup"); err != nil {
		t.Fatal(err)
	}
	env.runId = env.runOf("claude-code", "bridge session")
	return env
}

func (self *testBridgeToolEnv) conn(version string) *testMcpConn {
	self.t.Helper()
	conn := startTestMcpConn(self.t, self.server, self.claude.RelayHello("builder"))
	if version != "2026-07-28" {
		conn.initialize(version)
	}
	return conn
}

func (self *testBridgeToolEnv) callTool(conn *testMcpConn, version string, name string, arguments any) *testMcpResponse {
	self.t.Helper()
	params := map[string]any{"name": name, "arguments": arguments}
	if version == "2026-07-28" {
		params["_meta"] = testMcpLatestMeta()
	}
	return conn.call("tools/call", params)
}

// A filing tool's data.
func testBridgeFilingOf(t *testing.T, response *testMcpResponse) *mcpBridgeFilingOut {
	t.Helper()
	out := &mcpBridgeFilingOut{}
	if err := json.Unmarshal(testEnvelopeOf(t, response).Data, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The four tools carry §16.5's tiers and hints, and the daemon's catalog holds them registered, none still unbuilt.
func TestBridgeToolTiers(t *testing.T) {
	env := newTestBridgeToolEnv(t)
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
		"bridge_list":    {true, false},
		"bridge_forward": {false, true},
		"bridge_expose":  {false, true},
		"bridge_close":   {false, false},
	}
	for _, tool := range listed.Tools {
		hints, ok := want[tool.Name]
		if !ok {
			t.Errorf("%s is no bridge tool", tool.Name)
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
	daemonCatalog := NewDaemonMcpCatalog(newTestMcpServer(newFakeMcpDaemon(), clock), nil)
	if err := checkMcpCatalog(daemonCatalog); err != nil {
		t.Error(err)
	}
	for _, name := range []string{"bridge_list", "bridge_forward", "bridge_expose", "bridge_close"} {
		if !slices.Contains(daemonCatalog.Names(), name) || slices.Contains(mcpCatalogUnbuilt, name) {
			t.Errorf("%s is not registered in the daemon's catalog", name)
		}
	}
}

// An exposure is outward: with no decision it answers approval_pending and its approval's id, filing nothing, and the
// same call again, once approved, answers its rule id. It files as MCP under the call's run, and a further retry keeps
// the rule id and files nothing more. A map's first filing names the host's address it filed.
func TestBridgeExposeWaitsThenFilesItsRule(t *testing.T) {
	env := newTestBridgeToolEnv(t)
	conn := env.conn("2025-06-18")
	arguments := map[string]any{"port": 5432, "local_port": 15432}

	pending := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_expose", arguments))
	if pending.Status != "approval_pending" || pending.ApprovalId == "" || pending.RuleId != "" {
		t.Fatalf("with no decision: %+v", pending)
	}
	if env.bridges.filedCount() != 0 {
		t.Fatal("a waiting exposure filed a rule")
	}
	again := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_expose", arguments))
	if again.ApprovalId != pending.ApprovalId {
		t.Errorf("the same call asked a second approval: %s then %s", pending.ApprovalId, again.ApprovalId)
	}

	env.bridges.set(true, nil)
	filed := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_expose", arguments))
	if filed.Status != "exposed" || len(filed.RuleId) != 64 || filed.Address != "100.80.0.7" || !filed.AddressFiled || filed.GrantId != "" {
		t.Fatalf("once approved: %+v", filed)
	}
	retried := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_expose", arguments))
	if retried.RuleId != filed.RuleId || env.bridges.filedCount() != 1 {
		t.Errorf("a retry answered %s after %s, %d rules filed", retried.RuleId, filed.RuleId, env.bridges.filedCount())
	}

	calls := env.bridges.taken()
	if len(calls) != 4 {
		t.Fatalf("the bridges took %d calls", len(calls))
	}
	for _, call := range calls {
		if call.method != "expose" || call.origin == nil || call.origin.Act != sidecar.SidecarActMcp ||
			call.origin.RunId == nil || *call.origin.RunId != env.runId || call.origin.Decision != nil || call.origin.Check != nil {
			t.Fatalf("an exposure's origin: %+v", call.origin)
		}
		if call.expose.Port != 5432 || call.expose.TargetPort != 15432 || call.expose.Target != "" || call.expose.Exit ||
			len(call.expose.Prefixes) != 0 || call.expose.ExpiresMs != 0 {
			t.Errorf("an exposure's params: %+v", call.expose)
		}
	}
	// an O call is the gate's to record, not a W call's
	if sunk := env.sink.sunk(); len(sunk) != 0 {
		t.Errorf("an outward call was recorded as a W call: %+v", sunk)
	}
}

// A route names this host's subnets, masked, and 0.0.0.0/0 alone is its exit; a map takes its target, protocol and
// expiry.
func TestBridgeExposeRoutesAndMaps(t *testing.T) {
	env := newTestBridgeToolEnv(t)
	env.bridges.set(true, nil)
	conn := env.conn("2025-06-18")
	expires := env.clock.Now().Add(2 * time.Hour).UTC()

	route := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_expose", map[string]any{"cidrs": []string{"10.20.30.77/24", "192.168.4.0/22"}}))
	exit := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_expose", map[string]any{"cidrs": []string{"0.0.0.0/0"}}))
	mapped := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_expose", map[string]any{
		"port": 53, "target": "192.168.4.9", "protocol": "udp", "expires": expires.Format(time.RFC3339),
	}))
	if route.Status != "exposed" || exit.Status != "exposed" || mapped.Status != "exposed" ||
		route.RuleId == exit.RuleId || route.RuleId == mapped.RuleId || route.Address != "" {
		t.Fatalf("route %+v, exit %+v, map %+v", route, exit, mapped)
	}
	calls := env.bridges.taken()
	if got := calls[0].expose; !slices.Equal(got.Prefixes, []string{"10.20.30.0/24", "192.168.4.0/22"}) || got.Exit || got.Port != 0 {
		t.Errorf("the route's params: %+v", got)
	}
	if got := calls[1].expose; !got.Exit || len(got.Prefixes) != 0 {
		t.Errorf("the exit's params: %+v", got)
	}
	if got := calls[2].expose; got.Port != 53 || got.Target != "192.168.4.9" || got.Protocol != "udp" || got.TargetPort != 0 ||
		got.ExpiresMs != expires.Truncate(time.Second).UnixMilli() {
		t.Errorf("the map's params: %+v", got)
	}
}

// A forward is outward, bound to the call's run, and listens on this host's loopback alone, whatever the daemon's
// --listen is: it waits, then answers its grant's id and its listener. Its expiry is the grant's lifetime in whole
// seconds, never shorter than asked.
func TestBridgeForwardListensOnLoopbackUnderTheRun(t *testing.T) {
	env := newTestBridgeToolEnv(t)
	conn := env.conn("2025-06-18")
	target := sidecar.NewId().String()
	expires := env.clock.Now().Add(90*time.Minute + 300*time.Millisecond).UTC()
	arguments := map[string]any{"target": target, "port": 22, "local_port": 2222, "expires": expires.Format(time.RFC3339Nano)}

	pending := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_forward", arguments))
	if pending.Status != "approval_pending" || pending.ApprovalId == "" || pending.GrantId != "" || pending.ForwardId != "" {
		t.Fatalf("with no decision: %+v", pending)
	}
	env.bridges.set(true, nil)
	filed := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_forward", arguments))
	if filed.Status != "forwarding" || len(filed.GrantId) != 64 || filed.ForwardId != "0011223344556677" || filed.LocalPort != 2222 ||
		filed.ApprovalId == "" || filed.RuleId != "" {
		t.Fatalf("once approved: %+v", filed)
	}
	for _, call := range env.bridges.taken() {
		if call.method != "forward" || call.origin.Act != sidecar.SidecarActMcp || call.origin.RunId == nil || *call.origin.RunId != env.runId {
			t.Fatalf("a forward's origin: %+v", call.origin)
		}
		params := call.forward
		if params.Target != target || params.Port != 22 || params.LocalPort != 2222 || params.Protocol != "" ||
			!slices.Equal(params.Listen, []string{"127.0.0.1"}) {
			t.Errorf("a forward's params: %+v", params)
		}
		// 90 min and 300 ms rounds up to 5,401 s
		if params.LifetimeSeconds != 5401 {
			t.Errorf("the lifetime is %d s", params.LifetimeSeconds)
		}
	}
	// with no expires the requests rule's lifetime stands
	env.callTool(conn, "2025-06-18", "bridge_forward", map[string]any{"target": target, "port": 22, "local_port": 2223})
	calls := env.bridges.taken()
	if last := calls[len(calls)-1].forward; last.LifetimeSeconds != 0 {
		t.Errorf("with no expires the lifetime is %d s", last.LifetimeSeconds)
	}
}

// bridge_close is W: it ends a forward the daemon holds, withdraws one of this host's rules or revokes a forward's
// grant, each recorded as a W call is, and a withdrawn rule's id, or another sidecar's, is refused with a constant
// text that names no id.
func TestBridgeCloseWithdrawsRevokesAndRefuses(t *testing.T) {
	env := newTestBridgeToolEnv(t)
	conn := env.conn("2025-06-18")
	ruleId, grantId, otherId := strings.Repeat("bb", 32), strings.Repeat("aa", 32), strings.Repeat("cc", 32)

	forward := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_close", map[string]any{"id": "0011223344556677"}))
	if forward.Status != "forward_closed" || forward.RuleId != "" || forward.GrantId != "" {
		t.Errorf("a forward's close: %+v", forward)
	}
	rule := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_close", map[string]any{"id": ruleId}))
	if rule.Status != "closed" || rule.RuleId != ruleId || rule.GrantId != "" {
		t.Errorf("a rule's close: %+v", rule)
	}
	grant := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_close", map[string]any{"id": grantId}))
	if grant.Status != "closed" || grant.GrantId != grantId || grant.RuleId != "" {
		t.Errorf("a grant's close: %+v", grant)
	}
	for name, id := range map[string]string{"a withdrawn rule": ruleId, "a revoked grant": grantId, "another sidecar's rule": otherId} {
		response := env.callTool(conn, "2025-06-18", "bridge_close", map[string]any{"id": id})
		wantMcpError(t, response, McpCodeRefused, "the bridge refused this filing")
		if strings.Contains(response.Error.Message, id) {
			t.Errorf("%s: the refusal names the id", name)
		}
	}
	for _, call := range env.bridges.taken() {
		if call.method != "close" || call.origin.Act != sidecar.SidecarActMcp || call.close.Reset {
			t.Errorf("a close's call: %+v %+v", call.origin, call.close)
		}
	}
	sunk := env.sink.sunk()
	if len(sunk) != 6 {
		t.Fatalf("the sink saw %d W calls", len(sunk))
	}
	for i, call := range sunk {
		if call.toolName != "bridge_close" || (call.err != nil) != (3 <= i) {
			t.Errorf("W call %d: %s %v", i, call.toolName, call.err)
		}
	}
}

// bridge_list is R, a member's data: the block, this host's addresses, names, rules by id and state, and forwards.
func TestBridgeListNamesRulesAndForwards(t *testing.T) {
	env := newTestBridgeToolEnv(t)
	owner, target := sidecar.NewId(), sidecar.NewId()
	expiresMs := env.clock.Now().Add(time.Hour).Truncate(time.Second).UnixMilli()
	env.bridges.status = &sidecar.DaemonBridgeStatusReply{
		List: &sidecar.DaemonBridgeList{
			NetworkId: env.networkId, State: "enforcing_document", Block: "100.80.0.0/16", Addresses: []string{"100.80.0.7"},
			Names: []*sidecar.DaemonBridgeName{{Name: "db", Address: "100.80.0.9"}},
			Rules: []*sidecar.DaemonBridgeRule{
				{RuleId: strings.Repeat("bb", 32), Kind: "map", Owner: owner, Own: true, State: "active", Prefixes: []string{"100.80.0.7/32"}, Ports: []string{"tcp:5432"}, ExpiresMs: expiresMs},
				{RuleId: strings.Repeat("dd", 32), Kind: "route", Owner: target, State: "withdrawn", Prefixes: []string{"10.0.0.0/24"}, Standing: true},
			},
			EgressMode: "auto",
		},
		Forwards: []*sidecar.DaemonBridgeForwardStatus{
			{ForwardId: "0011223344556677", Target: target, Protocol: "tcp", Port: 22, LocalPort: 2222, GrantId: strings.Repeat("aa", 32), ExpiresMs: expiresMs, ConnCount: 2},
		},
	}
	conn := env.conn("2025-06-18")
	response := env.callTool(conn, "2025-06-18", "bridge_list", map[string]any{})
	out := &mcpBridgeListOut{}
	envelope := testSocketToolData(t, response, out)
	if envelope.Trust != McpTrustMember || envelope.Source != "bridge:list" {
		t.Errorf("the listing's tags: %s %s", envelope.Trust, envelope.Source)
	}
	wantExpires := time.UnixMilli(expiresMs).UTC().Format(time.RFC3339)
	if out.State != "enforcing_document" || out.Block != "100.80.0.0/16" || !slices.Equal(out.Addresses, []string{"100.80.0.7"}) ||
		len(out.Names) != 1 || out.Names[0].Name != "db" || out.EgressMode != "auto" {
		t.Errorf("the listing: %+v", out)
	}
	if len(out.Rules) != 2 || out.Rules[0].RuleId != strings.Repeat("bb", 32) || !out.Rules[0].Own || out.Rules[0].Owner != owner.String() ||
		out.Rules[0].Expires != wantExpires || out.Rules[1].State != "withdrawn" || !out.Rules[1].Standing || out.Rules[1].Expires != "" {
		t.Errorf("the rules: %+v %+v", out.Rules[0], out.Rules[1])
	}
	if len(out.Forwards) != 1 || out.Forwards[0].ForwardId != "0011223344556677" || out.Forwards[0].Target != target.String() ||
		out.Forwards[0].LocalPort != 2222 || out.Forwards[0].Expires != wantExpires || out.Forwards[0].ConnCount != 2 {
		t.Errorf("the forwards: %+v", out.Forwards)
	}
	// an empty bridge lists empty arrays, never null
	env.bridges.status = &sidecar.DaemonBridgeStatusReply{}
	envelope = testEnvelopeOf(t, env.callTool(conn, "2025-06-18", "bridge_list", map[string]any{}))
	for _, field := range []string{`"addresses":[]`, `"names":[]`, `"rules":[]`, `"forwards":[]`} {
		if !strings.Contains(string(envelope.Data), field) {
			t.Errorf("an empty listing lacks %s: %s", field, envelope.Data)
		}
	}
}

// Malformed calls are refused before the bridges hear of them, each with the tools' one constant text.
func TestBridgeToolsRefuseMalformedCalls(t *testing.T) {
	env := newTestBridgeToolEnv(t)
	env.bridges.set(true, nil)
	conn := env.conn("2025-06-18")
	target := sidecar.NewId().String()
	past := env.clock.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	ahead := env.clock.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	cases := []struct {
		name      string
		tool      string
		arguments map[string]any
	}{
		{"a forward with no target", "bridge_forward", map[string]any{"target": "", "port": 22, "local_port": 2222}},
		{"a forward to port 0", "bridge_forward", map[string]any{"target": target, "port": 0, "local_port": 2222}},
		{"a forward to port 65536", "bridge_forward", map[string]any{"target": target, "port": 65536, "local_port": 2222}},
		{"a forward with no local port", "bridge_forward", map[string]any{"target": target, "port": 22, "local_port": 0}},
		{"a forward over sctp", "bridge_forward", map[string]any{"target": target, "port": 22, "local_port": 2222, "protocol": "sctp"}},
		{"a forward that expired", "bridge_forward", map[string]any{"target": target, "port": 22, "local_port": 2222, "expires": past}},
		{"a forward with an expiry that is no time", "bridge_forward", map[string]any{"target": target, "port": 22, "local_port": 2222, "expires": "tomorrow"}},
		{"an exposure of nothing", "bridge_expose", map[string]any{}},
		{"an exposure of a port and subnets", "bridge_expose", map[string]any{"port": 80, "cidrs": []string{"10.0.0.0/24"}}},
		{"a map of port 70000", "bridge_expose", map[string]any{"port": 70000}},
		{"a map to a name", "bridge_expose", map[string]any{"port": 80, "target": "db.internal"}},
		{"a map over icmp", "bridge_expose", map[string]any{"port": 80, "protocol": "icmp"}},
		{"a map that expired", "bridge_expose", map[string]any{"port": 80, "expires": past}},
		{"a route with an expiry", "bridge_expose", map[string]any{"cidrs": []string{"10.0.0.0/24"}, "expires": ahead}},
		{"a route with a local port", "bridge_expose", map[string]any{"cidrs": []string{"10.0.0.0/24"}, "local_port": 80}},
		{"a route of an ipv6 subnet", "bridge_expose", map[string]any{"cidrs": []string{"fd00::/64"}}},
		{"a route of no prefix", "bridge_expose", map[string]any{"cidrs": []string{"10.0.0.1"}}},
		{"an exit beside a subnet", "bridge_expose", map[string]any{"cidrs": []string{"0.0.0.0/0", "10.0.0.0/24"}}},
		{"a close of nothing", "bridge_close", map[string]any{"id": ""}},
	}
	for _, c := range cases {
		response := env.callTool(conn, "2025-06-18", c.tool, c.arguments)
		if response.Error == nil || response.Error.Code != McpCodeInvalidArguments {
			t.Errorf("%s: %+v %s", c.name, response.Error, response.Result)
		}
	}
	// a key no tool names, and a network argument that is none
	wantMcpError(t, env.callTool(conn, "2025-06-18", "bridge_expose", map[string]any{"port": 80, "block": "100.80.0.0/16"}), McpCodeInvalidArguments, "")
	wantMcpError(t, env.callTool(conn, "2025-06-18", "bridge_forward", map[string]any{"target": target, "port": 22, "local_port": 2222, "listen": []string{"0.0.0.0"}}), McpCodeInvalidArguments, "")
	if calls := env.bridges.taken(); len(calls) != 0 {
		t.Errorf("a malformed call reached the bridges: %+v", calls)
	}
}

// Each of the bridge's answers reaches the agent as a constant text of its class, which names no id, prefix or port,
// and a daemon that runs no bridge answers unavailable.
func TestBridgeToolsAnswerConstantErrors(t *testing.T) {
	env := newTestBridgeToolEnv(t)
	conn := env.conn("2025-06-18")
	secretDetail := "sidecar 0123456789abcdef0123456789abcdef at 100.80.0.9:5432"
	cases := []struct {
		err       error
		code      int64
		part      string
		retryable bool
	}{
		{sidecar.ErrDaemonBridgeUnwired, McpCodeUnavailable, "runs no bridge", false},
		{fmt.Errorf("%w: %s", sidecar.ErrBridgeFileRefused, secretDetail), McpCodeRefused, "the bridge refused this filing", false},
		{fmt.Errorf("%w: %s", sidecar.ErrBridgeFileNoState, secretDetail), McpCodeUnavailable, "no verified state", true},
		{fmt.Errorf("%w: %s", sidecar.ErrBridgeFileUncertain, secretDetail), McpCodeFailed, "may have landed", true},
		{sidecar.ErrDaemonBridgeForwardLimit, McpCodeFailedPrecondition, "limit of forwards", false},
		{sidecar.ErrDaemonBridgeGrantEnded, McpCodeFailedPrecondition, "grant is not active", true},
		{fmt.Errorf("%w: %s", sidecar.ErrDaemonBridgeParams, secretDetail), McpCodeInvalidArguments, "bridge_forward takes", false},
		{sidecar.ErrApprovalDenied, McpCodeRefused, "no approval of this could be spent", false},
		{sidecar.ErrApprovalSpent, McpCodeRefused, "no approval of this could be spent", false},
		{sidecar.ErrApprovalCancelled, McpCodeRefused, "no approval of this could be spent", false},
		{sidecar.ErrApprovalExpired, McpCodeRefused, "no approval of this could be spent", false},
		{sidecar.ErrSidecarGateDenied, McpCodeRefused, "no approval of this could be spent", false},
		{errors.New("something else about " + secretDetail), McpCodeFailed, "", false},
	}
	target := sidecar.NewId().String()
	calls := map[string]map[string]any{
		"bridge_expose":  {"port": 5432},
		"bridge_forward": {"target": target, "port": 22, "local_port": 2222},
		"bridge_close":   {"id": strings.Repeat("bb", 32)},
		"bridge_list":    {},
	}
	for _, c := range cases {
		env.bridges.set(true, c.err)
		for tool, arguments := range calls {
			response := env.callTool(conn, "2025-06-18", tool, arguments)
			wantMcpError(t, response, c.code, c.part)
			if strings.Contains(response.Error.Message, "0123456789abcdef") || strings.Contains(response.Error.Message, "100.80.0.9") {
				t.Errorf("%s after %v: the error names what the filer named: %s", tool, c.err, response.Error.Message)
			}
			data := &McpErrorData{}
			json.Unmarshal(response.Error.Data, data)
			if data.Retryable != c.retryable {
				t.Errorf("%s after %v: retryable %t", tool, c.err, data.Retryable)
			}
		}
	}
	// a pending approval the filer answers as an error is a wait, not a failure
	approvalId := sidecar.NewId()
	env.bridges.set(true, &sidecar.ApprovalPendingError{ApprovalId: approvalId})
	if out := testBridgeFilingOf(t, env.callTool(conn, "2025-06-18", "bridge_expose", calls["bridge_expose"])); out.Status != "approval_pending" || out.ApprovalId != approvalId.String() {
		t.Errorf("a pending error: %+v", out)
	}

	env.bridges = nil
	for tool, arguments := range calls {
		wantMcpError(t, env.callTool(conn, "2025-06-18", tool, arguments), McpCodeUnavailable, "runs no bridge")
	}
}

// The tools report their filings to the guard as this sidecar's own resources, which it admits, and report nothing
// it refuses: no BridgeBlock, BridgeEgress or another's statement has a tool.
func TestBridgeToolsReportOwnResourceFilings(t *testing.T) {
	for _, signedType := range mcpOwnResourceStatements {
		own := mcpBridgeOwnStatement(signedType)
		if refusal := McpGuard([]McpTarget{own}); refusal != nil {
			t.Errorf("%s as this sidecar's own: %v", signedType, refusal)
		}
		own.OwnResource = false
		if refusal := McpGuard([]McpTarget{own}); refusal == nil {
			t.Errorf("%s as another's passed", signedType)
		}
	}
	// the running Sidecar a call's network is reaches the bridges, and a network that is none reaches as nil
	hosted := &sidecar.Sidecar{}
	if mcpSidecarOf(hosted) != hosted || mcpSidecarOf(McpNetworkOf(hosted, nil).(McpNetwork)) != hosted || mcpSidecarOf(&fakeMcpNetwork{}) != nil {
		t.Error("the call's Sidecar is not read from its network")
	}
}

// §22.5: at every MCP version each bridge tool's result validates against that version's wire schema, and its
// structuredContent against the tool's declared outputSchema, a waiting filing's and a filed one's alike.
func TestBridgeToolsSchemasAtEveryVersion(t *testing.T) {
	env := newTestBridgeToolEnv(t)
	target := sidecar.NewId()
	env.bridges.status = &sidecar.DaemonBridgeStatusReply{
		List: &sidecar.DaemonBridgeList{
			State: "enforcing_document", Block: "100.80.0.0/16", Addresses: []string{"100.80.0.7"},
			Rules: []*sidecar.DaemonBridgeRule{{RuleId: strings.Repeat("bb", 32), Kind: "route", Owner: target, Own: true, State: "active"}},
		},
		Forwards: []*sidecar.DaemonBridgeForwardStatus{{ForwardId: "0011223344556677", Target: target, Protocol: "tcp", Port: 22, LocalPort: 2222}},
	}
	calls := []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "bridge_list", arguments: map[string]any{}},
		{tool: "bridge_expose", arguments: map[string]any{"port": 5432}},
		{tool: "bridge_expose", arguments: map[string]any{"cidrs": []string{"10.0.0.0/24"}}},
		{tool: "bridge_forward", arguments: map[string]any{"target": target.String(), "port": 22, "local_port": 2222}},
		{tool: "bridge_close", arguments: map[string]any{"id": "0011223344556677"}},
	}
	for _, version := range testMcpVersions {
		for _, approves := range []bool{false, true} {
			env.bridges.set(approves, nil)
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
}
