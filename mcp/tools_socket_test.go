//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's socket tools (SOCK-M5-14) on the tool framework, with the daemon's sockets faked: each tool's tier and hints;
// socket_listen running as W under a covering grant, recorded and naming the grant, and outward without one, its
// action of kind listen naming the socket by its token path, with the name and the local port beside it (QD-740,
// QD-772), none while the daemon holds no K_sock, and a pending gate naming the approval; other namespaces and
// ports refused; the listing's share/ names left out and its trust a member's; and each MCP version's wire and output
// schemas on the four tools.
//
// The outward listen's action is grant-backed (sidecar.SocketListenGrantAction), built on a real grant filer over a
// real ACL engine whose one member's device is the tool network's sidecar, its rules naming sockets by token path:
// under a requests rule it names the rule and carries the grant component's effect, and the listen asked again
// presents the bytes its request was filed with, spending the decision; under a standing grant alone it names no rule
// and its standing effect runs under an empty key; with neither it is refused with nothing reaching the gate; and a
// use that came to not_done refuses the listen, an uncertain one answering unavailable. The gate itself is faked here:
// socket_listen_grant_test.go runs the same action through §16.6's real gate.

package mcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
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

// A tool network whose allowed grants carry a grant id, whose §5.4 gate answers what a test sets, whose K_sock ring
// is a synthetic key's, nil once a test takes it away, and whose grant filer is a real one over the rules a test
// installs (useGrants), none before.
type fakeMcpSocketNetwork struct {
	*fakeMcpToolNetwork
	grantId    []byte
	authorized []*sidecar.SidecarAction
	// the gate: this error where set; else as §16.6's step 2 under a standing grant, the effect run under an empty
	// key; else this outcome where set; else a pass with no outcome
	authorize error
	standing  bool
	outcome   *sidecar.SidecarOutcome
	ring      *sidecar.SocketKeyRing
	grants    *sidecar.AclGrantFiler
}

func (self *fakeMcpSocketNetwork) SocketKeyRing() *sidecar.SocketKeyRing {
	return self.ring
}

// See mcpSocketGrants.
func (self *fakeMcpSocketNetwork) socketListenGrants() *sidecar.AclGrantFiler {
	return self.grants
}

// A test's id from label.
func testSocketGrantId(label string) sidecar.Id {
	sum := sha256.Sum256([]byte(label))
	return sidecar.Id(sum[:16])
}

// A one-member network's state as the socket tools' grants read it: the tool network's sidecar, admitted as a member's
// device, and nothing else.
type testSocketAclView struct {
	sidecarId sidecar.Id
	memberId  sidecar.Id
}

func (self *testSocketAclView) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: 1, Chain: make([]byte, sha256.Size)}
}

func (self *testSocketAclView) Genesis() *bridge.Genesis {
	return nil
}

func (self *testSocketAclView) SidecarIds() []sidecar.Id {
	return []sidecar.Id{self.sidecarId}
}

func (self *testSocketAclView) Sidecar(sidecarId sidecar.Id) *sidecar.AclSidecar {
	if sidecarId != self.sidecarId {
		return nil
	}
	return &sidecar.AclSidecar{Row: &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), AdmittedAt: 1}, MemberId: self.memberId}
}

func (self *testSocketAclView) Member(memberId sidecar.Id) *bridge.MemberRow {
	if memberId != self.memberId {
		return nil
	}
	return &bridge.MemberRow{MemberId: memberId.Bytes(), Role: bridge.MemberRole_MEMBER_ROLE_MEMBER}
}

func (self *testSocketAclView) IsConfigWriter(sidecarId sidecar.Id) bool {
	return false
}

func (self *testSocketAclView) Parked(sidecarId sidecar.Id) bool {
	return false
}

func (self *testSocketAclView) Sponsor(sidecarId sidecar.Id) (sidecar.Id, bool) {
	return sidecar.Id{}, false
}

func (self *testSocketAclView) CascadeVoids(signer []byte, at uint64) bool {
	return false
}

// The network given a grant filer over an engine holding a standing listen rule on each of standing and a requests
// rule by which its member asks listen on each of requests and approves it itself, each socket by its token path
// under the network's current K_sock. The requests rule's id, nil for none.
func (self *fakeMcpSocketNetwork) useGrants(t *testing.T, standing []string, requests []string) []byte {
	t.Helper()
	tokenTargets := func(names []string) []*protocol.AclTarget {
		targets := []*protocol.AclTarget{}
		for _, name := range names {
			tokenPath, err := self.ring.Current().TokenPath(name)
			if err != nil {
				t.Fatal(err)
			}
			targets = append(targets, &protocol.AclTarget{SocketTokens: [][]byte{tokenPath}})
		}
		return targets
	}
	member := sidecar.AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()
	listen := []uint32{uint32(protocol.AclAction_ACL_ACTION_LISTEN)}
	rows := &protocol.AclRows{HasDocument: true}
	if 0 < len(standing) {
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId: testSocketGrantId("a standing listen").Bytes(), SrcAtoms: [][]byte{member}, Targets: tokenTargets(standing), Actions: listen,
		})
	}
	var ruleId []byte
	if 0 < len(requests) {
		ruleId = testSocketGrantId("a listen's requests rule").Bytes()
		rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
			RuleId: ruleId, SrcAtoms: [][]byte{member}, Targets: tokenTargets(requests), Actions: listen,
			ApproverAtoms: [][]byte{sidecar.AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
		})
	}
	sidecarId := self.Identity().SidecarId
	state, err := sidecar.NewAclState(rows, &testSocketAclView{sidecarId: sidecarId, memberId: testSocketGrantId("the network's member")})
	if err != nil {
		t.Fatal(err)
	}
	engine := sidecar.NewAclEngine(sidecarId, nil, nil, nil)
	if err := engine.Install(state, nil); err != nil {
		t.Fatal(err)
	}
	self.grants = sidecar.NewAclGrantFiler(nil, engine)
	return ruleId
}

// The grant_dst a listen on an application name carries under the network's current K_sock (QD-772).
func (self *fakeMcpSocketNetwork) listenGrantDst(t *testing.T, name string) string {
	t.Helper()
	tokenPath, err := self.ring.Current().TokenPath(name)
	if err != nil {
		t.Fatal(err)
	}
	return "sock:" + hex.EncodeToString(tokenPath)
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
	switch {
	case self.authorize != nil:
		return self.authorize
	case self.standing:
		if action.Effect == nil {
			return errors.New("an action with no effect")
		}
		effectRef, err := action.Effect.Run(ctx, nil)
		if err != nil {
			return err
		}
		action.Outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeDone, EffectRef: effectRef}
	case self.outcome != nil:
		outcome := *self.outcome
		action.Outcome = &outcome
	}
	return nil
}

// The stored action the gate saw at index.
func (self *fakeMcpSocketNetwork) asked(t *testing.T, index int) *sidecar.StoredCanonicalAction {
	t.Helper()
	if len(self.authorized) <= index {
		t.Fatalf("the gate saw %d actions, not %d", len(self.authorized), index+1)
	}
	stored, err := sidecar.ParseStoredCanonicalAction(self.authorized[index].Canonical)
	if err != nil {
		t.Fatal(err)
	}
	return stored
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
	ring, err := sidecar.NewSocketKeyRing(env.networkId, &protocol.SocketKeyFile{CurrentKey: bytes.Repeat([]byte{0x5a}, 32)}, sidecar.DefaultSocketKeyRingSettings())
	if err != nil {
		t.Fatal(err)
	}
	env.network = &fakeMcpSocketNetwork{fakeMcpToolNetwork: newFakeMcpToolNetwork(env.hookTestEnv.network, testToolCredential), grantId: []byte{0xab, 0xcd}, ring: ring}
	env.daemon.hostNetwork(env.networkId, env.network)
	env.catalog = NewMcpCatalog(env.server.settings.Mcp, env.clock, env.sink)
	if listenAction == nil {
		listenAction = newMcpSocketListenAction(env.clock.Now)
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

// With no covering grant socket_listen is outward: the production action reaches §5.4's gate as kind listen naming
// the socket by its grant_dst alone, the name's token path under the network's K_sock and never the name (QD-772),
// with no local port in its bytes and the tool's name and local port beside it as the request's, and a gate that
// refuses leaves nothing listening and nothing recorded as a W call. Under the requests rule that takes it the action
// carries the grant's fields, its subject this sidecar, the rule's id and the expiry the rule gives, and the grant
// component's effect, which the gate refuses an action without.
func TestSocketListenUncoveredAsksTheGate(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	ruleId := env.network.useGrants(t, nil, []string{"db/primary"})
	env.network.authorize = sidecar.ErrApprovalRefused
	conn := env.conn("2025-06-18")
	wantMcpError(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 15432}), McpCodeRefused, "approval")
	if len(env.sockets.listensAsked()) != 0 || len(env.sink.sunk()) != 0 {
		t.Error("a refused listen acted")
	}
	if len(env.network.authorized) != 1 {
		t.Fatalf("the gate saw %d actions", len(env.network.authorized))
	}
	action := env.network.authorized[0]
	stored := env.network.asked(t, 0)
	grantDst := env.network.listenGrantDst(t, "db/primary")
	if action.Kind != sidecar.SidecarActionListen || len(stored.Action.GetGrantDst()) != 1 || stored.Action.GetGrantDst()[0] != grantDst ||
		!action.Detail.Equal(&sidecar.SidecarActionDetail{SocketName: "db/primary", LocalPort: 15432}) {
		t.Errorf("the action: %+v, detail %+v", stored.Action, action.Detail)
	}
	if !bytes.Equal(stored.Action.GetRuleId(), ruleId) || !bytes.Equal(stored.Action.GetSubject(), env.network.Identity().SidecarId.Bytes()) ||
		!slices.Equal(stored.Action.GetGrantAllow(), []string{"listen"}) || stored.Action.GetExpiresMillis() != env.clock.Now().Add(time.Hour).UnixMilli() {
		t.Errorf("the grant's fields: %+v", stored.Action)
	}
	if action.Effect == nil {
		t.Error("the action carries no effect, which the gate refuses")
	}
	if bytes.Contains(action.Canonical, []byte("15432")) || bytes.Contains(action.Canonical, []byte("primary")) {
		t.Error("the action's bytes hold the local port or the name")
	}
	if err := sidecar.CheckCanonicalActionForServer(stored); err != nil {
		t.Errorf("the listen's action on a server path: %v", err)
	}
	// the decision binds the call's run and its session's agent (owner decision 470), beside the action's bytes and
	// never in them
	agentId, err := env.network.ResolveAgentId("builder")
	if err != nil {
		t.Fatal(err)
	}
	if runId := env.runOf("claude-code", "socket session"); action.RunId == nil || *action.RunId != runId || action.AgentId == nil || *action.AgentId != agentId {
		t.Errorf("the listen binds run %v and agent %v, not %s and %s", action.RunId, action.AgentId, runId, agentId)
	}
	if bytes.Contains(action.Canonical, agentId.Bytes()) {
		t.Error("the action's bytes hold the agent id")
	}
}

// A daemon that holds no K_sock for the network yet takes no outward listen: it could not name the socket in the form
// a server may see, and its sockets could register none. The answer is retryable, and nothing reaches the gate.
func TestSocketListenUncoveredWaitsForTheSocketKey(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	env.network.ring = nil
	conn := env.conn("2025-06-18")
	wantMcpError(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 15432}), McpCodeUnavailable, "")
	if len(env.network.authorized) != 0 || len(env.sockets.listensAsked()) != 0 {
		t.Error("a listen with no K_sock reached the gate or listened")
	}
}

// Once the action builds, an uncovered listen passes the gate first: a pending gate names its approval and listens on
// nothing, an allowed one listens.
func TestSocketListenUncoveredPassesTheGate(t *testing.T) {
	built := func(ctx context.Context, call *McpCall, name string, localPort int, grantDst string) (*sidecar.SidecarAction, error) {
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
	for _, action := range env.network.authorized {
		if !action.Detail.Equal(&sidecar.SidecarActionDetail{SocketName: "db/primary", LocalPort: 5432}) {
			t.Errorf("the gate saw detail %+v", action.Detail)
		}
	}
}

// Under a standing grant alone, a rule the engine holds that no requests rule beside it asks, the production action
// passes the gate: it names no rule and no expiry, only the grant's subject, socket and action, and carries the
// standing effect, which the gate's step 2 runs under an empty key to done, so the tool listens with no approval and
// names no grant it activated.
func TestSocketListenUncoveredPassesUnderAStandingGrant(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	env.network.useGrants(t, []string{"db/primary"}, nil)
	env.network.standing = true
	conn := env.conn("2025-06-18")
	out := &mcpSocketListenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432}), out)
	if out.Status != "listening" || out.GrantId != "" || out.ApprovalId != "" {
		t.Errorf("a standing grant's listen: %+v", out)
	}
	if asked := env.sockets.listensAsked(); len(asked) != 1 || asked[0] != "db/primary 127.0.0.1:5432" {
		t.Errorf("listens %q", asked)
	}
	stored := env.network.asked(t, 0)
	if len(stored.Action.GetRuleId()) != 0 || stored.Action.GetExpiresMillis() != 0 ||
		!slices.Equal(stored.Action.GetGrantDst(), []string{env.network.listenGrantDst(t, "db/primary")}) ||
		!bytes.Equal(stored.Action.GetSubject(), env.network.Identity().SidecarId.Bytes()) {
		t.Errorf("the standing listen's action: %+v", stored.Action)
	}
	if outcome := env.network.authorized[0].Outcome; outcome == nil || outcome.State != sidecar.ApprovalOutcomeDone {
		t.Errorf("the standing listen's outcome: %+v", outcome)
	}
}

// With no requests rule and no standing grant, a standing grant on another name only, the listen is refused before the
// gate, filing nothing and listening on nothing; and a network whose standing follower holds no engine yet takes no
// outward listen, answering retryably.
func TestSocketListenUncoveredRefusedWhereNoGrantCoversIt(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	conn := env.conn("2025-06-18")
	wantMcpError(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432}), McpCodeUnavailable, "")
	env.network.useGrants(t, []string{"db/replica"}, nil)
	wantMcpError(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432}), McpCodeRefused, "grant")
	if len(env.network.authorized) != 0 || len(env.sockets.listensAsked()) != 0 {
		t.Errorf("an uncovered listen reached the gate %d times or listened", len(env.network.authorized))
	}
}

// Under a requests rule the listen waits for a person, and asked again later presents the action its request was filed
// with, though the rule's expiry has moved on with the clock, so a decision on that request is what the gate spends:
// once the person approves, the gate's spend activates the grant and the tool listens, naming the grant. Another
// local port is another request's action.
func TestSocketListenAskedAgainSpendsTheApproval(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	ruleId := env.network.useGrants(t, nil, []string{"db/primary"})
	approvalId := sidecar.NewId()
	env.network.authorize = &sidecar.ApprovalPendingError{ApprovalId: approvalId}
	conn := env.conn("2025-06-18")
	listen := map[string]any{"name": "db/primary", "local_port": 5432}
	out := &mcpSocketListenOut{}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", listen), out)
	if out.Status != "approval_pending" || out.ApprovalId != approvalId.String() {
		t.Fatalf("the first listen: %+v", out)
	}
	filed := env.network.asked(t, 0)
	if !bytes.Equal(filed.Action.GetRuleId(), ruleId) || env.network.authorized[0].Effect == nil {
		t.Fatalf("the filed action: %+v", filed.Action)
	}

	env.clock.Advance(time.Minute)
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", listen), out)
	if again := env.network.asked(t, 1); out.Status != "approval_pending" || !bytes.Equal(again.Bytes, filed.Bytes) {
		t.Fatalf("asked again a minute on: %+v, another action %t", out, !bytes.Equal(again.Bytes, filed.Bytes))
	}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 6543}), out)
	if other := env.network.asked(t, 2); bytes.Equal(other.Bytes, filed.Bytes) {
		t.Error("another local port presented the first port's action")
	}

	// the person approved: the gate spends the decision into the grant its approval fixes
	grantId := bytes.Repeat([]byte{0x6b}, sha256.Size)
	env.network.authorize = nil
	env.network.outcome = &sidecar.SidecarOutcome{State: sidecar.ApprovalOutcomeDone, EffectRef: grantId}
	testSocketToolData(t, env.callTool(conn, "2025-06-18", "socket_listen", listen), out)
	if out.Status != "listening" || out.GrantId != hex.EncodeToString(grantId) {
		t.Errorf("the approved listen: %+v", out)
	}
	if spent := env.network.asked(t, 3); !bytes.Equal(spent.Bytes, filed.Bytes) {
		t.Error("the approved listen presented another action than its request's")
	}
	if asked := env.sockets.listensAsked(); len(asked) != 1 || asked[0] != "db/primary 127.0.0.1:5432" {
		t.Errorf("listens %q", asked)
	}
}

// A use that came to not_done refuses the listen, and an uncertain one answers retryably; neither listens.
func TestSocketListenRefusedWhereItsGrantDidNotActivate(t *testing.T) {
	env := newTestSocketToolEnv(t, nil)
	env.network.useGrants(t, nil, []string{"db/primary"})
	conn := env.conn("2025-06-18")
	for _, c := range []struct {
		state sidecar.ApprovalOutcomeState
		code  int64
	}{
		{state: sidecar.ApprovalOutcomeNotDone, code: McpCodeRefused},
		{state: sidecar.ApprovalOutcomeUncertain, code: McpCodeUnavailable},
	} {
		env.network.outcome = &sidecar.SidecarOutcome{State: c.state}
		wantMcpError(t, env.callTool(conn, "2025-06-18", "socket_listen", map[string]any{"name": "db/primary", "local_port": 5432}), c.code, "")
	}
	if len(env.sockets.listensAsked()) != 0 {
		t.Error("a listen whose grant did not activate listened")
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
