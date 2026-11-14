//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's dns tools (MCP-M5-01) on the tool framework: the network's real DnsClient over a transport that stands in
// for the dns block, and §16.6's real gate from sidecartest's approval world, so a write files a request, waits, and
// spends its approval into one POST /dns/records carrying the decision, the action and the use's effect key. The tests
// hold each tool's tier and hints; a write waiting, then landing once; what the gate at the dns block sees of a write,
// which is no run id, agent id, recipient or preview (AD4); what an approver is shown, which is dns_value whatever an
// agent says of it (D-MCP-17); a delete; a write under a standing grant; the zone's listing; each refusal's constant
// text; and each MCP version's wire and output schemas. The route's own legs, a response lost after COMMIT, two api
// instances racing and a presentation past not_after, are server/api/approval_schedule_db_test.go's.

package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The dns block's address in the tests, a reserved name.
const testDnsUrl = "https://dns.example.test"

// One request the block took.
type testDnsRequest struct {
	method string
	path   string
	header http.Header
	body   []byte
}

// The dns block as the client's transport meets it: GET /dns/zone answers the zone set, and POST /dns/records
// answers the next status queued, else a write whose answer a use's Idempotency-Key fixes, as the use's row does.
type testDnsBlock struct {
	stateLock sync.Mutex
	zone      *sidecar.DnsZone
	// what the next writes answer in place of a write: a status and a code
	refusals  []*sidecar.DnsApiError
	version   uint64
	keyAnswer map[string][]byte
	requests  []testDnsRequest
}

func newTestDnsBlock(networkId sidecar.Id) *testDnsBlock {
	return &testDnsBlock{
		zone:      &sidecar.DnsZone{NetworkId: networkId, Root: "example.test.", Label: "acme", Version: 7, RecordSets: []sidecar.DnsZoneRecordSet{}},
		version:   7,
		keyAnswer: map[string][]byte{},
	}
}

func (self *testDnsBlock) RoundTrip(request *http.Request) (*http.Response, error) {
	var body []byte
	if request.Body != nil {
		body, _ = io.ReadAll(request.Body)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.requests = append(self.requests, testDnsRequest{method: request.Method, path: request.URL.Path, header: request.Header.Clone(), body: body})
	answer := func(status int, value any) (*http.Response, error) {
		encoded, _ := json.Marshal(value)
		return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
	}
	if request.Header.Get("Authorization") != "Bearer a-synthetic-service-token" {
		return answer(http.StatusUnauthorized, map[string]string{"code": sidecar.DnsApiCodeRefused})
	}
	switch request.Method + " " + request.URL.Path {
	case "GET " + sidecar.DnsZonePath:
		if self.zone == nil {
			return answer(http.StatusServiceUnavailable, map[string]string{"code": sidecar.DnsApiCodeUnavailable})
		}
		return answer(http.StatusOK, self.zone)
	case "POST " + sidecar.DnsRecordsPath:
		if 0 < len(self.refusals) {
			refusal := self.refusals[0]
			self.refusals = self.refusals[1:]
			return answer(refusal.Status, map[string]string{"code": refusal.Code, "message": refusal.Message})
		}
		key := request.Header.Get(sidecar.DnsIdempotencyKeyHeader)
		if stored, ok := self.keyAnswer[key]; ok && key != "" {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(stored))}, nil
		}
		self.version += 1
		encoded, _ := json.Marshal(&sidecar.DnsRecordsAnswer{Version: self.version})
		if key != "" {
			self.keyAnswer[key] = encoded
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(encoded))}, nil
	}
	return answer(http.StatusNotFound, map[string]string{"code": sidecar.DnsApiCodeInvalid})
}

func (self *testDnsBlock) refuse(status int, code string, message string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refusals = append(self.refusals, &sidecar.DnsApiError{Status: status, Code: code, Message: message})
}

// How many requests the block took.
func (self *testDnsBlock) requestCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.requests)
}

// The writes the block took.
func (self *testDnsBlock) writes() []testDnsRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	writes := []testDnsRequest{}
	for _, request := range self.requests {
		if request.method == http.MethodPost {
			writes = append(writes, request)
		}
	}
	return writes
}

// A tool network with a DnsClient and a gate: the approval world's real one, or, with standing set, a standing
// grant's pass, which runs the effect at once under no key.
type fakeMcpDnsNetwork struct {
	*fakeMcpToolNetwork
	t      *testing.T
	client *sidecar.DnsClient
	world  *sidecartest.ApprovalWorld
	// the run the tools' calls must bind
	runId sidecar.Id

	stateLock sync.Mutex
	standing  bool
	noGate    error
	// each action Authorize took, as the tool built it
	actions []*sidecar.SidecarAction
	// what the next action carries as the agent's words, which no dns tool sets
	summary string
}

func (self *fakeMcpDnsNetwork) Dns() (*sidecar.DnsClient, error) {
	if self.client == nil {
		return nil, errors.New("no dns url")
	}
	return self.client, nil
}

func (self *fakeMcpDnsNetwork) Authorize(ctx context.Context, action *sidecar.SidecarAction, decision *bridge.Signed) error {
	var standing bool
	var noGate error
	var summary string
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		kept := *action
		self.actions = append(self.actions, &kept)
		standing, noGate, summary = self.standing, self.noGate, self.summary
	}()
	if noGate != nil {
		return noGate
	}
	if action.RunId == nil || *action.RunId != self.runId || action.AgentId != nil {
		self.t.Errorf("the action's run binding: %v %v", action.RunId, action.AgentId)
	}
	if standing {
		effectRef, err := action.Effect.Run(ctx, nil)
		switch {
		case err == nil:
			action.Outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeDone, EffectRef: effectRef}
		case errors.Is(err, sidecar.ErrSidecarEffectNotDone):
			action.Outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeNotDone, Err: err}
		default:
			action.Outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeUncertain, Err: err}
		}
		return nil
	}
	// the world's run store holds the world's own run, so the session's run reads there as the world's
	worldRunId := self.world.RunId
	action.RunId = &worldRunId
	if summary != "" {
		action.Summary = summary
	}
	return self.world.Gate().Authorize(ctx, action, decision)
}

func (self *fakeMcpDnsNetwork) set(update func(network *fakeMcpDnsNetwork)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	update(self)
}

func (self *fakeMcpDnsNetwork) taken() []*sidecar.SidecarAction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]*sidecar.SidecarAction{}, self.actions...)
}

// A server with the dns tools over a network whose DnsClient calls the test block and whose gate is the approval
// world's, and a Claude Code harness whose fresh session opened a run.
type testDnsToolEnv struct {
	*hookTestEnv
	block   *testDnsBlock
	dns     *fakeMcpDnsNetwork
	world   *sidecartest.ApprovalWorld
	net     *sidecartest.Net
	catalog *McpCatalog
	sink    *testCallSink
	claude  *sidecartest.FakeHarness
	runId   sidecar.Id
}

func newTestDnsToolEnv(t *testing.T) *testDnsToolEnv {
	t.Helper()
	env := &testDnsToolEnv{hookTestEnv: newHookTestEnv(t), sink: &testCallSink{}}
	env.block = newTestDnsBlock(env.networkId)
	client, err := sidecar.NewDnsClient(&sidecar.DnsClientArgs{
		DnsUrl:    testDnsUrl,
		Transport: env.block,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return "a-synthetic-service-token", nil
		},
		NetworkId: env.networkId,
		Clock:     env.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	env.net = sidecartest.NewNet(t.Context(), nil)
	t.Cleanup(env.net.Close)
	if env.world, err = sidecartest.NewApprovalWorld(env.net, "daemon"); err != nil {
		t.Fatal(err)
	}
	env.dns = &fakeMcpDnsNetwork{fakeMcpToolNetwork: newFakeMcpToolNetwork(env.network, testToolCredential), t: t, client: client, world: env.world}
	env.daemon.hostNetwork(env.networkId, env.dns)
	env.catalog = NewMcpCatalog(env.server.settings.Mcp, env.clock, env.sink)
	addDnsTools(env.catalog)
	env.catalog.Install(env.server)
	env.claude = env.harness(sidecartest.FakeHarnessClaudeCode)
	if err := env.claude.SessionStart("dns session", "startup"); err != nil {
		t.Fatal(err)
	}
	env.runId = env.runOf("claude-code", "dns session")
	env.dns.runId = env.runId
	return env
}

func (self *testDnsToolEnv) conn(version string) *testMcpConn {
	self.t.Helper()
	conn := startTestMcpConn(self.t, self.server, self.claude.RelayHello("builder"))
	if version != "2026-07-28" {
		conn.initialize(version)
	}
	return conn
}

func (self *testDnsToolEnv) callTool(conn *testMcpConn, version string, name string, arguments any) *testMcpResponse {
	self.t.Helper()
	params := map[string]any{"name": name, "arguments": arguments}
	if version == "2026-07-28" {
		params["_meta"] = testMcpLatestMeta()
	}
	return conn.call("tools/call", params)
}

// A write's data.
func testDnsWriteOf(t *testing.T, response *testMcpResponse) *mcpDnsWriteOut {
	t.Helper()
	out := &mcpDnsWriteOut{}
	if err := json.Unmarshal(testEnvelopeOf(t, response).Data, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The phone's approval of the request a pending write named.
func (self *testDnsToolEnv) approve(pending *mcpDnsWriteOut) sidecar.Id {
	self.t.Helper()
	if pending.Status != "approval_pending" || pending.ApprovalId == "" {
		self.t.Fatalf("not pending: %+v", pending)
	}
	approvalId, err := sidecar.ParseId(pending.ApprovalId)
	if err != nil {
		self.t.Fatal(err)
	}
	notAfter := self.net.Clock().Now().Add(10 * time.Minute)
	if err := self.world.Approve(self.t.Context(), approvalId, 1, notAfter, nil); err != nil {
		self.t.Fatal(err)
	}
	return approvalId
}

// The three tools carry §16.5's tiers and hints, and the daemon's catalog holds them registered, none still unbuilt.
func TestDnsToolTiers(t *testing.T) {
	env := newTestDnsToolEnv(t)
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
		"dns_records": {true, false},
		"dns_set":     {false, true},
		"dns_delete":  {false, true},
	}
	for _, tool := range listed.Tools {
		hints, ok := want[tool.Name]
		if !ok {
			t.Errorf("%s is no dns tool", tool.Name)
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
	for _, name := range []string{"dns_records", "dns_set", "dns_delete"} {
		for _, unbuilt := range mcpCatalogUnbuilt {
			if unbuilt == name {
				t.Errorf("%s is still listed unbuilt", name)
			}
		}
	}
	// both writes are consumed at the server's gate, so the daemon's own table says so
	for _, kind := range []sidecar.SidecarActionKind{sidecar.SidecarActionDnsSet, sidecar.SidecarActionDnsDelete} {
		row, ok := sidecar.CanonicalActionFields(kind)
		if !ok || len(row.Server) == 0 {
			t.Errorf("kind %d has no server column", kind)
		}
	}
}

// dns_set is outward: with no decision it files a request and answers approval_pending, writing nothing; the same
// call again asks no second approval; once the phone approves, the call spends the approval into one write, which
// carries the decision, the action and the use's effect key, and answers the zone's version. A call again answers
// the same version from the gate's record and writes nothing more.
func TestDnsSetWaitsThenWritesOnce(t *testing.T) {
	env := newTestDnsToolEnv(t)
	conn := env.conn("2025-06-18")
	arguments := map[string]any{"name": "WWW.acme.example.test", "type": "a", "value": "192.0.2.10"}

	pending := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", arguments))
	if pending.Status != "approval_pending" || pending.ApprovalId == "" || pending.Version != 0 {
		t.Fatalf("with no decision: %+v", pending)
	}
	if writes := env.block.writes(); len(writes) != 0 {
		t.Fatalf("a waiting write reached the zone: %d", len(writes))
	}
	if again := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", arguments)); again.ApprovalId != pending.ApprovalId {
		t.Fatalf("the same call asked a second approval: %s then %s", pending.ApprovalId, again.ApprovalId)
	}
	approvalId := env.approve(pending)

	written := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", arguments))
	if written.Status != "written" || written.Version != 8 || written.ApprovalId != "" {
		t.Fatalf("once approved: %+v", written)
	}
	writes := env.block.writes()
	if len(writes) != 1 {
		t.Fatalf("%d writes", len(writes))
	}
	request := &sidecar.DnsRecordsRequest{}
	if err := json.Unmarshal(writes[0].body, request); err != nil {
		t.Fatal(err)
	}
	if len(request.Upserts) != 1 || len(request.Deletes) != 0 || request.ExpectVersion != nil {
		t.Fatalf("the write: %s", writes[0].body)
	}
	upsert := request.Upserts[0]
	if upsert.Name != "www.acme.example.test." || upsert.Type != "A" || len(upsert.Values) != 1 || upsert.Values[0] != "192.0.2.10" || upsert.Ttl != 0 {
		t.Errorf("the upsert: %+v", upsert)
	}
	if request.Approval == nil || len(request.Approval.Decisions) != 1 || len(request.Approval.Template) != 0 {
		t.Fatalf("the write's approval: %+v", request.Approval)
	}
	stored, err := sidecar.ParseStoredCanonicalAction(request.Approval.Action)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Action.GetDnsName() != upsert.Name || stored.Action.GetDnsType() != "A" || stored.Action.GetDnsValue() != "192.0.2.10" {
		t.Errorf("the action: %v", stored.Action)
	}
	effectKey := sidecar.ApprovalEffectKey(approvalId, stored.ActionId(approvalId))
	if got := writes[0].header.Get(sidecar.DnsIdempotencyKeyHeader); got != base64.RawURLEncoding.EncodeToString(effectKey[:]) {
		t.Errorf("the Idempotency-Key %q is not the use's effect key", got)
	}

	again := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", arguments))
	if again.Status != "written" || again.Version != written.Version || len(env.block.writes()) != 1 {
		t.Errorf("a call again: %+v, %d writes", again, len(env.block.writes()))
	}
	// another value is another action: its own approval, and no write on this one's
	other := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", map[string]any{"name": "www.acme.example.test", "type": "A", "value": "192.0.2.99"}))
	if other.Status != "approval_pending" || other.ApprovalId == pending.ApprovalId || len(env.block.writes()) != 1 {
		t.Errorf("another value: %+v, %d writes", other, len(env.block.writes()))
	}
	if sunk := env.sink.sunk(); len(sunk) != 0 {
		t.Errorf("an outward call was recorded as a W call: %+v", sunk)
	}
}

// §22.7's AD4 capture: what the gate at the dns block sees of an approved write. Its body, its headers, the action
// and each decision hold no run id, no agent id, no recipient and no preview, and the action passes the server
// column's check; the request this daemon filed holds the run, where no server reads it.
func TestDnsGateViewHoldsNoRunAgentOrPreview(t *testing.T) {
	env := newTestDnsToolEnv(t)
	conn := env.conn("2025-06-18")
	arguments := map[string]any{"name": "mail.acme.example.test.", "type": "TXT", "value": "v=spf1 -all"}
	approvalId := env.approve(testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", arguments)))
	if written := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", arguments)); written.Status != "written" {
		t.Fatalf("the write: %+v", written)
	}
	writes := env.block.writes()
	if len(writes) != 1 {
		t.Fatalf("%d writes", len(writes))
	}
	request := &sidecar.DnsRecordsRequest{}
	if err := json.Unmarshal(writes[0].body, request); err != nil || request.Approval == nil {
		t.Fatalf("the write: %s", writes[0].body)
	}
	stored, err := sidecar.ParseStoredCanonicalAction(request.Approval.Action)
	if err != nil {
		t.Fatal(err)
	}
	if err := sidecar.CheckCanonicalActionForServer(stored); err != nil {
		t.Errorf("the action a gate takes: %v", err)
	}
	if stored.Action.GetPreview() != "" || len(stored.Action.GetRecipients()) != 0 || stored.Action.GetPath() != "" ||
		len(stored.Action.GetSealedDetail()) != 0 {
		t.Errorf("the action holds what no gate sees: %v", stored.Action)
	}

	// every byte the block took, with each bytes field opened
	seen := [][]byte{writes[0].body, request.Approval.Action, request.Approval.Template}
	seen = append(seen, request.Approval.Decisions...)
	for _, decision := range request.Approval.Decisions {
		parsed, err := sidecar.ParseStoredApprovalDecision(decision)
		if err != nil {
			t.Fatal(err)
		}
		if sidecar.Id(parsed.Decision.GetApprovalId()) != approvalId {
			t.Errorf("a decision of another approval")
		}
	}
	for name, values := range writes[0].header {
		seen = append(seen, []byte(name+": "+strings.Join(values, ",")))
	}
	hidden := map[string]sidecar.Id{"the session's run id": env.runId, "the gate's run id": env.world.RunId, "the agent id": env.world.AgentId}
	for what, id := range hidden {
		forms := [][]byte{
			id.Bytes(), []byte(id.String()), []byte(hex.EncodeToString(id.Bytes())),
			[]byte(base64.StdEncoding.EncodeToString(id.Bytes())), []byte(base64.RawURLEncoding.EncodeToString(id.Bytes())),
		}
		for _, part := range seen {
			for _, form := range forms {
				if bytes.Contains(part, form) {
					t.Errorf("the gate's view holds %s", what)
				}
			}
		}
	}
	for _, word := range []string{"preview", "recipient", "summary", "run_id", "agent_id", "dns session", "claude"} {
		if bytes.Contains(bytes.ToLower(writes[0].body), []byte(word)) {
			t.Errorf("the write's body holds %q", word)
		}
	}
	// the run rides the request this daemon filed, which the approver's device reads and no server does
	filed := env.world.Log().Request(approvalId)
	if filed == nil || sidecar.Id(filed.Request.GetRunId()) != env.world.RunId {
		t.Errorf("the filed request's run: %v", filed)
	}
	actions := env.dns.taken()
	if len(actions) != 2 {
		t.Fatalf("%d actions", len(actions))
	}
}

// An approver shown a dns_set whose agent claims other rdata sees dns_value (D-MCP-17): the action takes no preview,
// the request the tool files renders the value the daemon built from the argument, and the agent's words show only
// as its untrusted summary, never as a field of the action.
func TestDnsValueRenderedNotPreview(t *testing.T) {
	env := newTestDnsToolEnv(t)
	conn := env.conn("2025-06-18")
	claimed := "sets www to 192.0.2.10, the staging host"
	env.dns.set(func(network *fakeMcpDnsNetwork) { network.summary = claimed })
	pending := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", map[string]any{
		"name": "www.acme.example.test", "type": "A", "value": "203.0.113.66",
	}))
	approvalId, err := sidecar.ParseId(pending.ApprovalId)
	if err != nil {
		t.Fatalf("not pending: %+v", pending)
	}
	filed := env.world.Log().Request(approvalId)
	if filed == nil {
		t.Fatal("no request filed")
	}
	render := sidecar.RenderApprovalRequest(filed)
	fields := map[string]string{}
	for _, field := range render.Fields {
		fields[field.Name] = field.Value
	}
	if fields["dns_value"] != "203.0.113.66" || fields["dns_name"] != "www.acme.example.test." || fields["dns_type"] != "A" {
		t.Errorf("the rendered action: %v", fields)
	}
	if render.Preview != "" || render.Summary != claimed {
		t.Errorf("the render's preview %q and summary %q", render.Preview, render.Summary)
	}
	for name, value := range fields {
		if strings.Contains(value, "192.0.2.10") {
			t.Errorf("the action's field %s carries the agent's claim: %s", name, value)
		}
	}
	text := render.Text()
	valueAt, claimAt := strings.Index(text, "dns_value: 203.0.113.66"), strings.Index(text, claimed)
	if valueAt < 0 || claimAt < 0 || claimAt < valueAt {
		t.Errorf("the approver's text shows the claim before or without the value:\n%s", text)
	}
	// no builder can give a dns_set a preview: the kind's row takes none
	if _, err := sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(sidecar.SidecarActionDnsSet), DnsName: "www.acme.example.test.", DnsType: "A", DnsValue: "203.0.113.66",
		Preview: "A 192.0.2.10",
	}); err == nil {
		t.Error("a dns_set with a preview was built")
	}
	// and the tool's own action carries no words of the agent's at all
	action, err := mcpDnsAction(&McpCall{RunId: env.runId}, sidecar.SidecarActionDnsSet, "www.acme.example.test.", "A", "203.0.113.66")
	if err != nil || action.Summary != "" || action.Detail != nil || action.AgentId != nil || *action.RunId != env.runId {
		t.Errorf("the tool's action: %+v %v", action, err)
	}
}

// dns_delete is outward the same way: it waits, then removes one RRset with one write that names no value.
func TestDnsDeleteWaitsThenRemoves(t *testing.T) {
	env := newTestDnsToolEnv(t)
	conn := env.conn("2025-06-18")
	arguments := map[string]any{"name": "old.acme.example.test", "type": "cname"}
	pending := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_delete", arguments))
	if len(env.block.writes()) != 0 {
		t.Fatal("a waiting delete reached the zone")
	}
	env.approve(pending)
	removed := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_delete", arguments))
	if removed.Status != "written" || removed.Version != 8 {
		t.Fatalf("once approved: %+v", removed)
	}
	writes := env.block.writes()
	if len(writes) != 1 {
		t.Fatalf("%d writes", len(writes))
	}
	request := &sidecar.DnsRecordsRequest{}
	json.Unmarshal(writes[0].body, request)
	if len(request.Deletes) != 1 || len(request.Upserts) != 0 || request.Deletes[0].Name != "old.acme.example.test." || request.Deletes[0].Type != "CNAME" ||
		request.Approval == nil {
		t.Errorf("the delete: %s", writes[0].body)
	}
	stored, err := sidecar.ParseStoredCanonicalAction(request.Approval.Action)
	if err != nil || sidecar.SidecarActionKind(stored.Action.GetKind()) != sidecar.SidecarActionDnsDelete || stored.Action.GetDnsValue() != "" {
		t.Errorf("the delete's action: %v %v", stored, err)
	}
	// a set of the same name is another kind's action, with its own approval
	set := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", map[string]any{"name": "old.acme.example.test", "type": "CNAME", "value": "new.acme.example.test."}))
	if set.Status != "approval_pending" || set.ApprovalId == pending.ApprovalId {
		t.Errorf("a set after the delete's approval: %+v", set)
	}
}

// Under a standing grant the gate runs the effect at once: one write with no approval and no Idempotency-Key.
func TestDnsSetUnderAStandingGrantWritesAtOnce(t *testing.T) {
	env := newTestDnsToolEnv(t)
	env.dns.set(func(network *fakeMcpDnsNetwork) { network.standing = true })
	conn := env.conn("2025-06-18")
	written := testDnsWriteOf(t, env.callTool(conn, "2025-06-18", "dns_set", map[string]any{"name": "api.acme.example.test", "type": "AAAA", "value": "2001:db8::10"}))
	if written.Status != "written" || written.Version != 8 || written.ApprovalId != "" {
		t.Fatalf("under a standing grant: %+v", written)
	}
	writes := env.block.writes()
	if len(writes) != 1 || writes[0].header.Get(sidecar.DnsIdempotencyKeyHeader) != "" {
		t.Fatalf("the write: %+v", writes)
	}
	request := &sidecar.DnsRecordsRequest{}
	json.Unmarshal(writes[0].body, request)
	if request.Approval != nil || len(request.Upserts) != 1 || request.Upserts[0].Values[0] != "2001:db8::10" {
		t.Errorf("the write: %s", writes[0].body)
	}
}

// dns_records is R, a member's data: the zone as GET /dns/zone answers this sidecar. A zone that cannot be read, and
// a network with no dns client, answer unavailable.
func TestDnsRecordsListsTheZone(t *testing.T) {
	env := newTestDnsToolEnv(t)
	env.block.zone.Alias = "acme.example"
	env.block.zone.RecordSets = []sidecar.DnsZoneRecordSet{
		{Name: "www.acme.example.test.", Type: "A", Ttl: 300, Kind: "user", Values: []string{"192.0.2.10", "192.0.2.11"}},
		{Name: "edge.acme.example.test.", Type: "A", Ttl: 60, Kind: "edge"},
	}
	conn := env.conn("2025-06-18")
	response := env.callTool(conn, "2025-06-18", "dns_records", map[string]any{})
	out := &mcpDnsRecordsOut{}
	envelope := testSocketToolData(t, response, out)
	if envelope.Trust != McpTrustMember || envelope.Source != "dns:zone" {
		t.Errorf("the listing's tags: %s %s", envelope.Trust, envelope.Source)
	}
	if out.Apex != "acme.example.test." || out.Alias != "acme.example" || out.Version != 7 || len(out.Records) != 2 {
		t.Fatalf("the zone: %+v", out)
	}
	if first := out.Records[0]; first.Name != "www.acme.example.test." || first.Type != "A" || first.Ttl != 300 || first.Kind != "user" || len(first.Values) != 2 {
		t.Errorf("the first record set: %+v", first)
	}
	if !strings.Contains(string(envelope.Data), `"values":[]`) {
		t.Errorf("a record set with no values is not an empty array: %s", envelope.Data)
	}
	if len(env.block.writes()) != 0 {
		t.Error("a read wrote")
	}

	env.dns.set(func(network *fakeMcpDnsNetwork) { network.client = nil })
	wantMcpError(t, env.callTool(conn, "2025-06-18", "dns_records", map[string]any{}), McpCodeUnavailable, "zone cannot be reached")
	wantMcpError(t, env.callTool(conn, "2025-06-18", "dns_set", map[string]any{"name": "www.acme.example.test", "type": "A", "value": "192.0.2.10"}), McpCodeUnavailable, "zone cannot be reached")
}

// A zone the block cannot answer is unavailable, not an empty zone.
func TestDnsRecordsUnavailableWhenTheZoneCannotBeRead(t *testing.T) {
	env := newTestDnsToolEnv(t)
	env.block.zone = nil
	conn := env.conn("2025-06-18")
	response := env.callTool(conn, "2025-06-18", "dns_records", map[string]any{})
	wantMcpError(t, response, McpCodeUnavailable, "zone cannot be reached")
	data := &McpErrorData{}
	json.Unmarshal(response.Error.Data, data)
	if !data.Retryable {
		t.Error("an unreachable zone is not retryable")
	}
}

// Malformed calls are refused before the gate and the zone hear of them.
func TestDnsToolsRefuseMalformedCalls(t *testing.T) {
	env := newTestDnsToolEnv(t)
	conn := env.conn("2025-06-18")
	cases := []struct {
		name      string
		tool      string
		arguments map[string]any
	}{
		{"a set with no name", "dns_set", map[string]any{"name": "", "type": "A", "value": "192.0.2.10"}},
		{"a set with no value", "dns_set", map[string]any{"name": "www.acme.example.test", "type": "A", "value": ""}},
		{"a set of a type no route takes", "dns_set", map[string]any{"name": "www.acme.example.test", "type": "NS", "value": "ns.example.test."}},
		{"a set with no type", "dns_set", map[string]any{"name": "www.acme.example.test", "type": "", "value": "192.0.2.10"}},
		{"a set of a name with a space", "dns_set", map[string]any{"name": "www acme.example.test", "type": "A", "value": "192.0.2.10"}},
		{"a set of a name with an escape", "dns_set", map[string]any{"name": "www\\.acme.example.test", "type": "A", "value": "192.0.2.10"}},
		{"a delete with no name", "dns_delete", map[string]any{"name": " ", "type": "A"}},
		{"a delete of a type no route takes", "dns_delete", map[string]any{"name": "www.acme.example.test", "type": "SOA"}},
	}
	for _, c := range cases {
		response := env.callTool(conn, "2025-06-18", c.tool, c.arguments)
		if response.Error == nil || response.Error.Code != McpCodeInvalidArguments {
			t.Errorf("%s: %+v %s", c.name, response.Error, response.Result)
		}
	}
	// keys no tool names: a ttl, a preview, and a value on a delete
	wantMcpError(t, env.callTool(conn, "2025-06-18", "dns_set", map[string]any{"name": "www.acme.example.test", "type": "A", "value": "192.0.2.10", "preview": "A 192.0.2.99"}), McpCodeInvalidArguments, "")
	wantMcpError(t, env.callTool(conn, "2025-06-18", "dns_delete", map[string]any{"name": "www.acme.example.test", "type": "A", "value": "192.0.2.10"}), McpCodeInvalidArguments, "")
	if actions := env.dns.taken(); len(actions) != 0 {
		t.Errorf("a malformed call reached the gate: %d", len(actions))
	}
	if count := env.block.requestCount(); count != 0 {
		t.Errorf("a malformed call reached the zone: %d", count)
	}
}

// Each of the zone's and the gate's answers reaches the agent as a constant text of its class, which names no
// record: a refusal and a limit as refused, a record the zone does not take as invalid, a version conflict as a
// failed precondition, an answer that cannot be told as uncertain and retryable, and a gate that holds the action as
// held.
func TestDnsToolsAnswerConstantErrors(t *testing.T) {
	env := newTestDnsToolEnv(t)
	env.dns.set(func(network *fakeMcpDnsNetwork) { network.standing = true })
	conn := env.conn("2025-06-18")
	arguments := map[string]any{"name": "secretname.acme.example.test", "type": "TXT", "value": "secretvalue"}
	cases := []struct {
		status    int
		code      string
		wantCode  int64
		part      string
		retryable bool
	}{
		{http.StatusForbidden, sidecar.DnsApiCodeRefused, McpCodeRefused, "the zone refused this write", false},
		{http.StatusForbidden, sidecar.DnsApiCodeSuspended, McpCodeRefused, "the zone refused this write", false},
		{http.StatusPaymentRequired, sidecar.DnsApiCodeQuota, McpCodeRefused, "the zone refused this write", false},
		{http.StatusConflict, sidecar.DnsApiCodeSpent, McpCodeRefused, "the zone refused this write", false},
		{http.StatusBadRequest, sidecar.DnsApiCodeInvalid, McpCodeInvalidArguments, "does not take this record", false},
		{http.StatusConflict, sidecar.DnsApiCodeVersionConflict, McpCodeFailedPrecondition, "the zone changed under this write", false},
		{http.StatusServiceUnavailable, sidecar.DnsApiCodeUnavailable, McpCodeFailed, "may have landed", true},
	}
	for _, c := range cases {
		env.block.refuse(c.status, c.code, "secretname.acme.example.test. TXT secretvalue")
		response := env.callTool(conn, "2025-06-18", "dns_set", arguments)
		wantMcpError(t, response, c.wantCode, c.part)
		if strings.Contains(response.Error.Message, "secretname") || strings.Contains(response.Error.Message, "secretvalue") {
			t.Errorf("%s: the error names the record: %s", c.code, response.Error.Message)
		}
		data := &McpErrorData{}
		json.Unmarshal(response.Error.Data, data)
		if data.Retryable != c.retryable {
			t.Errorf("%s: retryable %t", c.code, data.Retryable)
		}
	}
	for _, held := range []error{sidecar.ErrApprovalDenied, sidecar.ErrApprovalExpired, sidecar.ErrApprovalSpent, sidecar.ErrApprovalCancelled, sidecar.ErrSidecarGateDenied} {
		env.dns.set(func(network *fakeMcpDnsNetwork) { network.noGate = held })
		wantMcpError(t, env.callTool(conn, "2025-06-18", "dns_delete", map[string]any{"name": "www.acme.example.test", "type": "A"}), McpCodeRefused, "no approval of this could be spent")
	}
	env.dns.set(func(network *fakeMcpDnsNetwork) { network.noGate = sidecar.ErrApprovalNoState })
	wantMcpError(t, env.callTool(conn, "2025-06-18", "dns_delete", map[string]any{"name": "www.acme.example.test", "type": "A"}), McpCodeUnavailable, "zone cannot be reached")
}

// §22.5: at every MCP version each dns tool's result validates against that version's wire schema, and its
// structuredContent against the tool's declared outputSchema, a waiting write's and a landed one's alike.
func TestDnsToolsSchemasAtEveryVersion(t *testing.T) {
	env := newTestDnsToolEnv(t)
	env.block.zone.RecordSets = []sidecar.DnsZoneRecordSet{{Name: "www.acme.example.test.", Type: "A", Ttl: 300, Kind: "user", Values: []string{"192.0.2.10"}}}
	calls := []struct {
		tool      string
		arguments map[string]any
	}{
		{tool: "dns_records", arguments: map[string]any{}},
		{tool: "dns_set", arguments: map[string]any{"name": "www.acme.example.test", "type": "A", "value": "192.0.2.10"}},
		{tool: "dns_delete", arguments: map[string]any{"name": "www.acme.example.test", "type": "A"}},
	}
	for _, version := range testMcpVersions {
		for _, standing := range []bool{false, true} {
			env.dns.set(func(network *fakeMcpDnsNetwork) { network.standing = standing })
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
