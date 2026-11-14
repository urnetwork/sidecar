// §22.7's actions row, its bridge clauses, on the path the MCP bridge tools take (MCP-M4-01; §16.6's bridge row,
// R-MCP-9, D-MCP-11, D-MCP-12, I-8, AD2): DaemonBridges, the seam mcp/tools_bridge.go calls, over the real BridgeFiler,
// with §16.6's real gate installed in place of bridge_file_test.go's seam gate, its P the test net's verified state
// and each decision signed by the member's consented device. So an exposure files a request and waits, an approval
// spends once into the rule whose id §17.8 derives from the spend's effect key, a call again answers the recorded
// outcome and files nothing, a filing whose answer was lost is found by the component's Lookup after a restart and
// stays one rule, a host's first map files its own address first, and what is not this sidecar's own is refused.
//
// The component itself is bridge_file.go's bridgeRuleEffect, which BRIDGE-M4-19 built with the filer: there is one,
// and the tools reach it through the filer rather than through a second copy here.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The filer as one network's DaemonBridgeBackend: its filings, with no listing and no forward route.
type testBridgeEffectBackend struct {
	world *testBridgeEffectWorld
}

func (self *testBridgeEffectBackend) SidecarId() Id {
	return self.world.hostId
}

func (self *testBridgeEffectBackend) List(ctx context.Context) (*DaemonBridgeList, error) {
	return &DaemonBridgeList{NetworkId: self.world.net.networkId}, nil
}

func (self *testBridgeEffectBackend) ResolveSidecar(ctx context.Context, name string) (Id, error) {
	return ParseId(name)
}

func (self *testBridgeEffectBackend) Expose(ctx context.Context, origin *BridgeFileOrigin, request *BridgeRouteRequest) (*BridgeFiling, error) {
	return self.world.filer.Expose(ctx, origin, request)
}

func (self *testBridgeEffectBackend) ExposeMap(ctx context.Context, origin *BridgeFileOrigin, request *BridgeMapRequest) (*BridgeFiling, error) {
	return self.world.filer.ExposeMap(ctx, origin, request)
}

func (self *testBridgeEffectBackend) Forward(ctx context.Context, origin *BridgeFileOrigin, request *BridgeForwardRequest) (*BridgeFiling, error) {
	return self.world.filer.Forward(ctx, origin, request)
}

func (self *testBridgeEffectBackend) Close(ctx context.Context, origin *BridgeFileOrigin, id []byte, reset bool) (*BridgeFiling, error) {
	return self.world.filer.Close(ctx, origin, id, reset)
}

func (self *testBridgeEffectBackend) SetEgress(ctx context.Context, origin *BridgeFileOrigin, request *BridgeEgressRequest) (*BridgeFiling, error) {
	return self.world.filer.SetEgress(ctx, origin, request)
}

func (self *testBridgeEffectBackend) SetBlock(ctx context.Context, origin *BridgeFileOrigin, request *BridgeBlockRequest) (*bridge.BridgeBlock, error) {
	return self.world.filer.SetBlock(ctx, origin, request)
}

func (self *testBridgeEffectBackend) ForwardRoute(ctx context.Context, request *BridgeForwardRequest, grantId []byte) (*DaemonBridgeForwardRoute, error) {
	return nil, ErrDaemonBridgeUnwired
}

func (self *testBridgeEffectBackend) DialForward(ctx context.Context, network string, address netip.AddrPort) (net.Conn, error) {
	return nil, ErrDaemonBridgeUnwired
}

// bridge_file_test.go's world with the real gate: an approval ledger and a run store on a local store, the approval
// family's log in memory, and the daemon's bridges over the filer.
type testBridgeEffectWorld struct {
	*testBridgeFileWorld
	localStore SidecarStore
	approvals  *testApprovalLog
	ledgerRows *ApprovalLedger
	runs       *RunStore
	inbox      *ApprovalInbox
	bridges    *DaemonBridges
	// removes the filer's registered Lookups and the installed gate, for a restart
	closeOpen func()
}

func newTestBridgeEffectWorld(t *testing.T) *testBridgeEffectWorld {
	t.Helper()
	fileWorld := newTestBridgeFileWorld(t, false)
	instance, _, _ := enrolledInstance(t)
	world := &testBridgeEffectWorld{
		testBridgeFileWorld: fileWorld,
		localStore:          instance.Store(&testNetworkId),
		approvals:           newTestApprovalLog(),
	}
	settings := defaultSidecarMcpSettings()
	var err error
	if world.ledgerRows, err = NewApprovalLedger(world.localStore, settings, world.clock); err != nil {
		t.Fatal(err)
	}
	if world.runs, err = NewRunStore(world.localStore, settings, world.clock); err != nil {
		t.Fatal(err)
	}
	if err := world.runs.Create(t.Context(), &RunFile{RunId: world.runId, Harness: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	world.open()
	t.Cleanup(func() { world.closeOpen() })
	return world
}

// Builds the filer, the inbox, the router and the gate afresh over the world's stores, as a daemon's restart does,
// and the daemon's bridges over them.
func (self *testBridgeEffectWorld) open() {
	self.t.Helper()
	if self.closeOpen != nil {
		self.closeOpen()
	}
	self.filer = self.newFiler()
	unregister := self.filer.Register()
	counter, err := NewApprovalPresenceCounts(self.localStore)
	if err != nil {
		self.t.Fatal(err)
	}
	args := &ApprovalArgs{
		SidecarId: self.hostId,
		Ledger:    self.ledgerRows,
		Approvals: self.approvals,
		Runs:      &testApprovalRunView{runs: self.runs},
		States: func() (ApprovalStates, error) {
			return NewConfigApprovalStates(self.net.log.State(), false, nil)
		},
		Counter:  counter,
		Clock:    self.clock,
		Settings: defaultSidecarMcpSettings(),
		Spend:    DefaultSpendSettings(),
		Log:      NewNoopLogger(),
	}
	inbox, err := NewApprovalInbox(args)
	if err != nil {
		self.t.Fatal(err)
	}
	router, err := NewApprovalRouter(args, inbox)
	if err != nil {
		self.t.Fatal(err)
	}
	gate, err := NewApprovalGate(args, inbox, router, &ApprovalGateArgs{Lookups: self.sidecar.effectLookup})
	if err != nil {
		self.t.Fatal(err)
	}
	uninstall := self.sidecar.InstallGate(gate)
	backend := &testBridgeEffectBackend{world: self}
	bridges, err := NewDaemonBridges(context.Background(), &DaemonBridgesArgs{
		Backend: func(ctx context.Context, networkId Id, running *Sidecar) (DaemonBridgeBackend, error) {
			if running != self.sidecar {
				return nil, ErrDaemonBridgeUnwired
			}
			return backend, nil
		},
		Listen: func(args *DaemonLocalListenArgs) (*DaemonLocalListener, error) {
			return nil, ErrDaemonBridgeUnwired
		},
		Clock: self.clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.inbox, self.bridges = inbox, bridges
	self.closeOpen = func() {
		bridges.Close()
		uninstall()
		unregister()
	}
}

// An exposure as bridge_expose calls it: MCP, under the world's run.
func (self *testBridgeEffectWorld) expose(params *DaemonBridgeExposeParams) (*DaemonBridgeFilingReply, error) {
	runId := self.runId
	origin := &BridgeFileOrigin{Act: SidecarActMcp, RunId: &runId, AgentRisk: SidecarRiskNormal}
	return self.bridges.Expose(context.Background(), self.net.networkId, self.sidecar, origin, params)
}

// A close as bridge_close calls it.
func (self *testBridgeEffectWorld) close(id []byte) (*DaemonBridgeFilingReply, error) {
	runId := self.runId
	origin := &BridgeFileOrigin{Act: SidecarActMcp, RunId: &runId, AgentRisk: SidecarRiskNormal}
	return self.bridges.CloseId(context.Background(), self.net.networkId, self.sidecar, origin, &DaemonBridgeCloseParams{Id: hex.EncodeToString(id)})
}

// The request the pending reply names, from the ledger.
func (self *testBridgeEffectWorld) pendingRequest(reply *DaemonBridgeFilingReply, err error) *StoredApprovalRequest {
	self.t.Helper()
	if err != nil {
		self.t.Fatal(err)
	}
	if reply.ApprovalPendingId == nil || reply.RuleId != "" {
		self.t.Fatalf("not pending: %+v", reply)
	}
	state, err := self.ledgerRows.State(*reply.ApprovalPendingId)
	if err != nil || state.Request == nil {
		self.t.Fatalf("no request for %s: %v", reply.ApprovalPendingId, err)
	}
	request, err := ParseStoredApprovalRequest(state.Request)
	if err != nil {
		self.t.Fatal(err)
	}
	return request
}

// The member's approval of request from its consented laptop, one use, put in the approval's log and read by the
// requester's inbox.
func (self *testBridgeEffectWorld) approve(request *StoredApprovalRequest) {
	self.t.Helper()
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	body := &protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               1,
		NotAfterMillis:     request.Request.GetNotAfterMillis(),
		ApproverMemberId:   self.member.Bytes(),
		Channel:            uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE),
		RequesterSidecarId: request.Request.GetRequesterSidecarId(),
		AuthPin:            self.net.log.State().Pin(),
		Version:            1,
	}
	stored, err := proto.Marshal(testSpendSignedBy(self.t, self.laptop.sidecarId, self.laptop.key, body))
	if err != nil {
		self.t.Fatal(err)
	}
	self.approvals.putDecision(request.ApprovalId(), stored)
	if err := self.inbox.Poll(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
}

// The rule id §17.8 derives from request's one use.
func testBridgeEffectRuleId(request *StoredApprovalRequest) string {
	approvalId := request.ApprovalId()
	ruleId := BridgeRuleId(ApprovalEffectKey(approvalId, request.Action.ActionId(approvalId)))
	return hex.EncodeToString(ruleId[:])
}

// bridge_expose files this host's own BridgeRoute through the gate: with no decision it files a request and waits,
// the same call again asks no second approval, and once the member's device approves, the call spends the approval
// into the rule whose id the effect key fixes, active in the log under this host. A call again, and a call after a
// restart, answer that rule from the gate's record: a replay adds no rule and no post.
func TestBridgeToolPathExposeFilesItsRouteThroughTheGate(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	params := &DaemonBridgeExposeParams{Prefixes: []string{"192.168.7.0/24"}}

	request := world.pendingRequest(world.expose(params))
	if world.api.postCount() != 0 {
		t.Fatalf("a waiting exposure posted %d statements", world.api.postCount())
	}
	if Id(request.Request.GetRequesterSidecarId()) != world.hostId || SidecarActionKind(request.Action.Action.GetKind()) != SidecarActionExpose ||
		!bytes.Equal(request.Action.Action.GetTargetSidecarId(), world.hostId.Bytes()) {
		t.Fatalf("the request: %v", request.Request)
	}
	if again := world.pendingRequest(world.expose(params)); again.ApprovalId() != request.ApprovalId() || world.approvals.filedCount() != 1 {
		t.Fatalf("the same call filed %d requests", world.approvals.filedCount())
	}

	world.approve(request)
	filed, err := world.expose(params)
	if err != nil {
		t.Fatal(err)
	}
	if filed.ApprovalPendingId != nil || filed.RuleId != testBridgeEffectRuleId(request) || filed.ApprovalId == nil || *filed.ApprovalId != request.ApprovalId() {
		t.Fatalf("the filing: %+v, want rule %s", filed, testBridgeEffectRuleId(request))
	}
	ruleId, _ := hex.DecodeString(filed.RuleId)
	rule := world.ledger().Rule(ruleId)
	if rule == nil || !rule.Active() || rule.Standing || rule.Owner != world.hostId || rule.ApprovalId != request.ApprovalId() {
		t.Fatalf("the rule: %+v", rule)
	}
	if posted := world.api.postedTypes(t); len(posted) != 1 || posted[0] != bridge.SignedType_SIGNED_BRIDGE_ROUTE {
		t.Fatalf("posted %v", posted)
	}

	replay, err := world.expose(params)
	if err != nil || replay.RuleId != filed.RuleId {
		t.Fatalf("a replay: %+v %v", replay, err)
	}
	world.open()
	restarted, err := world.expose(params)
	if err != nil || restarted.RuleId != filed.RuleId {
		t.Fatalf("a replay after a restart: %+v %v", restarted, err)
	}
	if world.api.postCount() != 1 || len(world.filingsOf(ruleId)) != 1 || world.approvals.filedCount() != 1 {
		t.Errorf("replays posted %d statements, %d filings of the rule, %d requests", world.api.postCount(), len(world.filingsOf(ruleId)), world.approvals.filedCount())
	}
	if uses := world.approvals.useBodies(); len(uses) != 1 {
		t.Errorf("%d uses filed for one approval", len(uses))
	}
}

// A kill after the filing: the post lands and its answer is lost, so the call answers uncertain with no outcome
// recorded. After a restart the same call finds the rule through the component's Lookup, or runs the effect again
// under the same key, which finds it in the log: one rule, one filing, its id the one the effect key fixed.
func TestBridgeToolPathKillAfterTheFilingLeavesOneRule(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	params := &DaemonBridgeExposeParams{Prefixes: []string{"172.16.4.0/24"}}
	request := world.pendingRequest(world.expose(params))
	world.approve(request)

	world.api.answers = []string{"lost"}
	if _, err := world.expose(params); !errors.Is(err, ErrBridgeFileUncertain) && !errors.Is(err, ErrSidecarActPending) {
		t.Fatalf("a filing whose answer was lost: %v", err)
	}
	world.open()
	found, err := world.expose(params)
	if err != nil {
		t.Fatal(err)
	}
	if found.RuleId != testBridgeEffectRuleId(request) {
		t.Fatalf("after the restart: %+v, want rule %s", found, testBridgeEffectRuleId(request))
	}
	ruleId, _ := hex.DecodeString(found.RuleId)
	if err := world.sidecar.PostPendingStatements(context.Background()); err != nil {
		t.Fatal(err)
	}
	ledger := world.ledger()
	active := 0
	for _, filing := range world.filingsOf(ruleId) {
		if entry := testBridgeEntryAt(t, ledger, filing.N); entry.Disposition == BridgeDispositionActive {
			active += 1
		}
	}
	if rule := ledger.Rule(ruleId); rule == nil || !rule.Active() || active != 1 {
		t.Fatalf("the rule: %+v, %d active filings of its id", rule, active)
	}
	// a further call answers the same rule and files nothing more
	posts := world.api.postCount()
	if again, err := world.expose(params); err != nil || again.RuleId != found.RuleId || world.api.postCount() != posts {
		t.Errorf("a further call: %+v %v, %d posts after %d", again, err, world.api.postCount(), posts)
	}
}

// A re-signed retry keeps its rule id: a filing whose post never applied answers uncertain, and the same call again
// files a new signature under the same id, which lands as the one active rule.
func TestBridgeToolPathResignedRetryKeepsItsRuleId(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	params := &DaemonBridgeExposeParams{Prefixes: []string{"10.20.0.0/16"}}
	request := world.pendingRequest(world.expose(params))
	world.approve(request)

	world.api.answers = []string{"dropped"}
	if _, err := world.expose(params); !errors.Is(err, ErrBridgeFileUncertain) && !errors.Is(err, ErrSidecarActPending) {
		t.Fatalf("a lost post: %v", err)
	}
	filed, err := world.expose(params)
	if err != nil {
		t.Fatal(err)
	}
	if filed.RuleId != testBridgeEffectRuleId(request) {
		t.Fatalf("the retry: %+v, want rule %s", filed, testBridgeEffectRuleId(request))
	}
	if err := world.sidecar.PostPendingStatements(context.Background()); err != nil {
		t.Fatal(err)
	}
	ruleId, _ := hex.DecodeString(filed.RuleId)
	ledger := world.ledger()
	active := 0
	for _, filing := range world.filingsOf(ruleId) {
		if entry := testBridgeEntryAt(t, ledger, filing.N); entry.Disposition == BridgeDispositionActive {
			active += 1
		}
	}
	if rule := ledger.Rule(ruleId); rule == nil || !rule.Active() || active != 1 || world.approvals.filedCount() != 1 {
		t.Fatalf("the rule: %+v, %d active filings, %d requests", rule, active, world.approvals.filedCount())
	}
}

// A host's first map files its own BridgeAddress, then the BridgeMap, under one approval; a second map asks its own
// approval and files no second address for the addressed host.
func TestBridgeToolPathFirstMapFilesItsAddressThenTheMap(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	first := &DaemonBridgeExposeParams{Port: 8443, TargetPort: 443, Target: "192.168.9.20"}
	request := world.pendingRequest(world.expose(first))
	if world.api.postCount() != 0 {
		t.Fatalf("a waiting map posted %d statements", world.api.postCount())
	}
	world.approve(request)
	filed, err := world.expose(first)
	if err != nil {
		t.Fatal(err)
	}
	posted := world.api.postedTypes(t)
	if len(posted) != 2 || posted[0] != bridge.SignedType_SIGNED_BRIDGE_ADDRESS || posted[1] != bridge.SignedType_SIGNED_BRIDGE_MAP {
		t.Fatalf("posted %v", posted)
	}
	ledger := world.ledger()
	held := ledger.Address(world.hostId)
	address, err := netip.ParseAddr(filed.Address)
	if err != nil || held == nil || !filed.AddressFiled || !testBridgeFileBlock.Contains(address) {
		t.Fatalf("the address: %+v %+v", held, filed)
	}
	ruleId, _ := hex.DecodeString(filed.RuleId)
	if rule := ledger.Rule(ruleId); rule == nil || !rule.Active() || rule.Map == nil || rule.Map.GetTargetPort() != 443 || rule.Owner != world.hostId {
		t.Fatalf("the map: %+v", rule)
	}

	second := &DaemonBridgeExposeParams{Port: 5432}
	secondRequest := world.pendingRequest(world.expose(second))
	if secondRequest.ApprovalId() == request.ApprovalId() {
		t.Fatal("a second map rode the first's approval")
	}
	world.approve(secondRequest)
	again, err := world.expose(second)
	if err != nil {
		t.Fatal(err)
	}
	if again.AddressFiled || again.Address != filed.Address || again.RuleId == filed.RuleId || len(world.api.postedTypes(t)) != 3 {
		t.Fatalf("a second map: %+v, %d posts", again, world.api.postCount())
	}
}

// An approval activates one rule: the action it decided. Another exposure under the same run asks its own approval
// and files nothing on the first's decision (AD2), and a spent approval's call again answers its own rule alone.
func TestBridgeToolPathAnApprovalActivatesItsOwnRuleAlone(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	approved := &DaemonBridgeExposeParams{Prefixes: []string{"192.168.7.0/24"}}
	request := world.pendingRequest(world.expose(approved))
	world.approve(request)
	filed, err := world.expose(approved)
	if err != nil {
		t.Fatal(err)
	}

	wider := &DaemonBridgeExposeParams{Prefixes: []string{"192.168.0.0/16"}}
	other := world.pendingRequest(world.expose(wider))
	if other.ApprovalId() == request.ApprovalId() || world.api.postCount() != 1 {
		t.Fatalf("a wider exposure rode the approval: %d posts", world.api.postCount())
	}
	exit := world.pendingRequest(world.expose(&DaemonBridgeExposeParams{Exit: true}))
	if exit.ApprovalId() == request.ApprovalId() || exit.ApprovalId() == other.ApprovalId() || world.api.postCount() != 1 {
		t.Fatalf("an exit rode an approval: %d posts", world.api.postCount())
	}
	if again, err := world.expose(approved); err != nil || again.RuleId != filed.RuleId || world.api.postCount() != 1 {
		t.Fatalf("the spent approval's call again: %+v %v", again, err)
	}
	if uses := world.approvals.useBodies(); len(uses) != 1 {
		t.Errorf("%d uses filed", len(uses))
	}
}

// bridge_close withdraws this host's own rule without an approval and refuses what is not its own: a withdrawn
// rule's id, which never returns (AD2), another sidecar's rule, another's grant, and an id nothing holds. Each
// refusal files nothing.
func TestBridgeToolPathCloseRefusesWhatIsNotItsOwn(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	params := &DaemonBridgeExposeParams{Prefixes: []string{"192.168.7.0/24"}}
	request := world.pendingRequest(world.expose(params))
	world.approve(request)
	filed, err := world.expose(params)
	if err != nil {
		t.Fatal(err)
	}
	ruleId, _ := hex.DecodeString(filed.RuleId)

	// another sidecar's rule: the laptop's own route, filed by its own key
	otherId := sha256.Sum256([]byte("the laptop's own route"))
	world.net.mustPost(world.laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, world.net.bridgeRoute(world.laptop, otherId[:],
		testBridgeSubnet(testBridgePrefix(10, 99, 0, 0, 24), "site")))
	requests, posts := world.approvals.filedCount(), world.api.postCount()
	if _, err := world.close(otherId[:]); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a withdraw of another sidecar's rule: %v", err)
	}
	if _, err := world.close(bytes.Repeat([]byte{0x5c}, sha256.Size)); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a close of an id nothing holds: %v", err)
	}
	if world.api.postCount() != posts {
		t.Fatalf("a refused close posted %d statements", world.api.postCount()-posts)
	}

	closed, err := world.close(ruleId)
	if err != nil || closed.RuleId != filed.RuleId || closed.ApprovalPendingId != nil {
		t.Fatalf("the close: %+v %v", closed, err)
	}
	if rule := world.ledger().Rule(ruleId); rule != nil && rule.Active() {
		t.Fatalf("the rule after its withdraw: %+v", rule)
	}
	if world.approvals.filedCount() != requests {
		t.Errorf("a close asked an approval")
	}
	posts = world.api.postCount()
	if _, err := world.close(ruleId); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a second withdraw of the rule: %v", err)
	}
	if world.api.postCount() != posts {
		t.Errorf("a refused close posted %d statements", world.api.postCount()-posts)
	}
	// the spent approval's call again answers the gate's record and files nothing: the withdrawn id never returns
	if again, err := world.expose(params); err == nil && again.RuleId == filed.RuleId {
		if rule := world.ledger().Rule(ruleId); rule != nil && rule.Active() {
			t.Errorf("the withdrawn rule returned: %+v", rule)
		}
	}
	if world.api.postCount() != posts {
		t.Errorf("a call again after the withdraw posted %d statements", world.api.postCount()-posts)
	}
}

// A tainted run's exposure takes no decision made before the taint: the request it files is marked tainted, an
// approval of the untainted request is not spent in the tainted run, and nothing is filed (I-9, TS1).
func TestBridgeToolPathTaintedRunAsksAfresh(t *testing.T) {
	world := newTestBridgeEffectWorld(t)
	params := &DaemonBridgeExposeParams{Prefixes: []string{"192.168.7.0/24"}}
	clean := world.pendingRequest(world.expose(params))
	if clean.Request.GetTainted() {
		t.Fatal("an untainted run's request is marked tainted")
	}
	if err := world.runs.Taint(t.Context(), world.runId, RunTaintUntrustedData); err != nil {
		t.Fatal(err)
	}
	world.approve(clean)
	tainted := world.pendingRequest(world.expose(params))
	if tainted.ApprovalId() == clean.ApprovalId() || !tainted.Request.GetTainted() {
		t.Fatalf("a tainted run's request: tainted %t, the clean one's id %t", tainted.Request.GetTainted(), tainted.ApprovalId() == clean.ApprovalId())
	}
	if world.api.postCount() != 0 {
		t.Fatalf("a tainted run filed on an untainted request's approval: %d posts", world.api.postCount())
	}
}
