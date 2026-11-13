//go:build !ios_extension

// BRIDGE-M4-19's filings on the test network through a real Sidecar's acts, its statements posted to the net's log
// and judged there with BRIDGE-M2-01's judge: §22.7's actions suite's bridge rows at the filer, which MCP-M4-01 runs
// again through the tools. An exposure files under the rule id its spend fixes and a re-signed retry keeps it; a kill
// between the filing and its outcome leaves one rule, which FindRule and Lookup find; a host's first map files its
// BridgeAddress, then the map; what is not this sidecar's own is refused before any act, as the verifiers refuse it;
// with no decision an exposure waits; a tainted run takes no standing grant and no stale decision; Close withdraws a
// rule and revokes a forward's grant; a forward's grant ends with its window; SetBlock refuses a block outside the
// ranges and a non-admin's; SetEgress files under the gate as kind egress_change (QD-799) once per effect key; and
// each filing writes one route entry.
//
// The gate here is §5.4's at the seam the filer meets, faithful to record_gate.go's steps: the real gate's own tests
// are MCP's, and MCP-M4-01 runs these rows through it.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The block the world's head carries.
var testBridgeFileBlock = netip.MustParsePrefix("100.80.0.0/16")

// A Sidecar at Unenrolled holding a fresh identity in networkId under sidecarId.
func newTestBridgeFileSidecar(t *testing.T, networkId Id, sidecarId Id) *Sidecar {
	t.Helper()
	binding := testBindingFields()
	binding.NetworkId = networkId
	binding.SidecarId = sidecarId
	_, secrets := newIdentityTestSecrets(t, networkId)
	keys, err := newSidecarIdentityKeys(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signedBinding, err := NewSidecarIdentityBinding(binding, keys.identitySeed, keys.clientKeySeed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistSidecarIdentity(secrets, keys, signedBinding); err != nil {
		t.Fatal(err)
	}
	sidecar := newSidecarBase(nil, cheapKeychainSettings())
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled}) {
		t.Fatal("no move to unenrolled")
	}
	if err := sidecar.adoptIdentity(secrets); err != nil {
		t.Fatal(err)
	}
	return sidecar
}

// The net's state as the filer reads it: its log, which applies each post at once.
type testBridgeFileConfig struct {
	net *testConfigNet
}

func (self testBridgeFileConfig) State() *ConfigState {
	return self.net.log.State()
}

func (self testBridgeFileConfig) WaitFor(ctx context.Context, n uint64) (*ConfigState, error) {
	if self.net.n < n {
		return nil, fmt.Errorf("the net is at %d, below %d", self.net.n, n)
	}
	return self.net.log.State(), nil
}

// An act authority whose pin is the net's tip, so every statement's header names a position the log holds.
type testBridgeFileAuthority struct {
	*testActAuthority
	net *testConfigNet
}

func (self *testBridgeFileAuthority) Pin() *bridge.AuthPin {
	return &bridge.AuthPin{Version: self.net.n, Chain: bytes.Clone(self.net.chain[:])}
}

// POST /network/config/delta onto the net: each post sequenced and judged there, answered with its entry, or 403 for a
// statement the log refused. A scripted answer "dropped" is a post that never applied and whose answer was lost, "lost"
// one that applied and whose answer was lost, and "refused" one api refused unsequenced. POST /network/auth-client goes
// to authClient, which answers a status and a body; nil refuses every mint.
type testBridgeFileApi struct {
	stateLock sync.Mutex
	net       *testConfigNet
	answers   []string
	// every post's Signed, in order
	posts      [][]byte
	authClient func(wire *sidecarAuthClientWire) (int, any)
}

func (self *testBridgeFileApi) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	request.Body.Close()
	if err != nil {
		return nil, err
	}
	respond := func(status int, value any) *http.Response {
		encoded, _ := json.Marshal(value)
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(encoded)), Header: http.Header{"Content-Type": {"application/json"}}, Request: request}
	}
	if strings.HasSuffix(request.URL.Path, "/network/auth-client") {
		wire := &sidecarAuthClientWire{}
		if err := json.Unmarshal(body, wire); err != nil {
			return nil, err
		}
		if self.authClient == nil {
			return respond(http.StatusForbidden, map[string]any{"error": "no mint here"}), nil
		}
		status, value := self.authClient(wire)
		return respond(status, value), nil
	}
	wire := &sidecarConfigDeltaWire{}
	if err := json.Unmarshal(body, wire); err != nil {
		return nil, err
	}
	answer := func() string {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.posts = append(self.posts, bytes.Clone(wire.Signed))
		if len(self.answers) == 0 {
			return "ok"
		}
		answer := self.answers[0]
		self.answers = self.answers[1:]
		return answer
	}()
	switch answer {
	case "dropped":
		return nil, errors.New("the post was lost")
	case "refused":
		return respond(http.StatusForbidden, map[string]any{"error": "The statement fails at the tip.", "code": "config_refused"}), nil
	}
	verdict := self.net.push(self.net.makeEntry(bridge.AuthEntryKindStatement, wire.Signed))
	if answer == "lost" {
		return nil, errors.New("the answer was lost")
	}
	if !verdict.Accepted() {
		return respond(http.StatusForbidden, map[string]any{"error": "The statement fails at the tip.", "code": "config_refused"}), nil
	}
	return respond(http.StatusOK, &sidecarConfigPinReply{N: verdict.Pin.GetVersion(), Chain: verdict.Pin.GetChain()}), nil
}

// Each post's statement type, in order.
func (self *testBridgeFileApi) postedTypes(t *testing.T) []bridge.SignedType {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	types := []bridge.SignedType{}
	for _, post := range self.posts {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(post, signed); err != nil {
			t.Fatal(err)
		}
		types = append(types, bridge.SignedType(signed.GetType()))
	}
	return types
}

// How many posts there were.
func (self *testBridgeFileApi) postCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.posts)
}

// The heads the net's writer saved, each carrying the world's block, or the head a writer saved last; and SetBlock's
// writer, which saves its edit of the head in force.
type testBridgeFileHeads struct {
	stateLock sync.Mutex
	net       *testConfigNet
	reader    *testConfigHeadReader
	// the signed BridgeBlock every head the net's writer saved holds, nil for none
	block []byte
	// the head a SaveHead saved, answered for every version from then on
	saved     *ConfigHead
	saveCount int
}

func (self *testBridgeFileHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.saved != nil {
		return self.saved, nil
	}
	head, err := self.reader.ReadConfigHead(ctx, configVersion, configHeadSha256)
	if err != nil || self.block == nil {
		return head, err
	}
	return head.WithFile(ConfigHeadBridgeBlockPath, self.block)
}

func (self *testBridgeFileHeads) SaveHead(ctx context.Context, edit func(head *ConfigHead) (*ConfigHead, error)) (*bridge.AuthPin, error) {
	base := self.net.log.State().Base()
	head, err := self.ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		return nil, err
	}
	next, err := edit(head)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.saved = next
	self.saveCount += 1
	return self.net.log.State().Pin(), nil
}

// The head saved last, nil for none.
func (self *testBridgeFileHeads) savedHead() (*ConfigHead, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.saved, self.saveCount
}

// The route entries the filer appended.
type testBridgeFileRecords struct {
	stateLock sync.Mutex
	drafts    []*RecordDraft
}

func (self *testBridgeFileRecords) Append(draft *RecordDraft) ([]*RecordEntryRef, error) {
	if err := RecordBodyValidate(draft.Kind, draft.Body); err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.drafts = append(self.drafts, draft)
	return []*RecordEntryRef{{}}, nil
}

// Every route entry, in order.
func (self *testBridgeFileRecords) routes(t *testing.T) []*RecordDraft {
	t.Helper()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	routes := []*RecordDraft{}
	for _, draft := range self.drafts {
		if draft.Kind != RecordKindRoute {
			t.Fatalf("a %s entry", draft.Kind)
		}
		routes = append(routes, draft)
	}
	return routes
}

// The filer's store in memory: whole files by name, each Create showing at its Commit.
type testBridgeFileStore struct {
	stateLock sync.Mutex
	files     map[string][]byte
}

func newTestBridgeFileStore() *testBridgeFileStore {
	return &testBridgeFileStore{files: map[string][]byte{}}
}

func (self *testBridgeFileStore) Open(name string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.files[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(value))), nil
}

func (self *testBridgeFileStore) Create(name string) (SidecarStoreWriter, error) {
	return &testBridgeFileStoreWriter{store: self, name: name}, nil
}

func (self *testBridgeFileStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.files, name)
	return nil
}

func (self *testBridgeFileStore) List(prefix string) ([]SidecarStoreEntry, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := []SidecarStoreEntry{}
	for name, value := range self.files {
		if strings.HasPrefix(name, prefix) {
			entries = append(entries, SidecarStoreEntry{Name: name, ByteCount: int64(len(value))})
		}
	}
	slices.SortFunc(entries, func(a SidecarStoreEntry, b SidecarStoreEntry) int { return strings.Compare(a.Name, b.Name) })
	return entries, nil
}

func (self *testBridgeFileStore) Directory(name string, class string) (SidecarStore, error) {
	return nil, errors.New("the filer's store holds no directory")
}

// The names kept under prefix.
func (self *testBridgeFileStore) names(prefix string) []string {
	entries, _ := self.List(prefix)
	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}

type testBridgeFileStoreWriter struct {
	store  *testBridgeFileStore
	name   string
	buffer bytes.Buffer
}

func (self *testBridgeFileStoreWriter) Write(data []byte) (int, error) {
	return self.buffer.Write(data)
}

func (self *testBridgeFileStoreWriter) Commit() error {
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	self.store.files[self.name] = bytes.Clone(self.buffer.Bytes())
	return nil
}

func (self *testBridgeFileStoreWriter) Close() error {
	return nil
}

// One call the gate took.
type testBridgeFileGateCall struct {
	kind      SidecarActionKind
	canonical []byte
	runId     *Id
	agentId   *Id
	effectKey []byte
}

// §5.4's gate at the seam the filer meets, as record_gate.go runs it: a standing grant passes an untainted run's action
// under an empty key; else the decision passed, or one the gate makes over exactly this action where it approves, as
// its inbox would hold one, spends under the effect key that approval fixes, a recorded final outcome answering a retry
// without running the effect again (AU4); with neither, the action waits. A tainted run takes no standing grant and only
// a decision on a request filed tainted (TS1, owner decision 142).
type testBridgeFileGate struct {
	t          testing.TB
	stateLock  sync.Mutex
	requester  Id
	approver   Id
	notAfterMs int64
	approves   bool
	standing   bool
	// runs that read tainted, and approvals whose request was filed tainted
	taintedRuns      map[Id]bool
	taintedApprovals map[Id]bool
	outcomes         map[string]*SidecarOutcome
	calls            []testBridgeFileGateCall
}

func (self *testBridgeFileGate) Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error {
	stored, err := ParseStoredCanonicalAction(action.Canonical)
	if err != nil {
		return err
	}
	call := testBridgeFileGateCall{kind: action.Kind, canonical: bytes.Clone(action.Canonical), runId: action.RunId, agentId: action.AgentId}
	var tainted, standing, approves bool
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		tainted = action.RunId != nil && self.taintedRuns[*action.RunId]
		standing, approves = self.standing, self.approves
	}()
	see := func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.calls = append(self.calls, call)
	}
	if standing && !tainted {
		see()
		effectRef, runErr := action.Effect.Run(ctx, nil)
		action.Outcome = approvalOutcomeOfRun(effectRef, runErr, false)
		return nil
	}
	payload := sha256.Sum256(stored.Bytes)
	if decision == nil && approves {
		decision = testBridgeDecision(self.t, hex.EncodeToString(payload[:]), stored.Bytes, 1, self.requester, self.approver, self.notAfterMs)
	}
	if decision == nil {
		see()
		return &ApprovalPendingError{ApprovalId: Id(payload[:len(Id{})])}
	}
	parsed, err := ParseSignedApprovalDecision(decision)
	if err != nil {
		return err
	}
	approvalId := Id(parsed.Decision.GetApprovalId())
	if tainted && !func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.taintedApprovals[approvalId]
	}() {
		// a decision on an untainted request is stale in a tainted run: the run asks afresh
		see()
		return &ApprovalPendingError{ApprovalId: approvalId}
	}
	effectKey := ApprovalEffectKey(approvalId, stored.ActionId(approvalId))
	call.effectKey = bytes.Clone(effectKey[:])
	see()
	recorded := func() *SidecarOutcome {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.outcomes[string(effectKey[:])]
	}()
	if recorded != nil && recorded.State.final() {
		action.Outcome = &SidecarOutcome{State: recorded.State, EffectRef: bytes.Clone(recorded.EffectRef)}
		return nil
	}
	signedBytes, err := proto.Marshal(decision)
	if err != nil {
		return err
	}
	spendCtx := withApprovalSpend(ctx, &ApprovalSpend{ApprovalId: approvalId, Decisions: [][]byte{signedBytes}, Action: bytes.Clone(stored.Bytes)})
	effectRef, runErr := action.Effect.Run(spendCtx, bytes.Clone(effectKey[:]))
	outcome := approvalOutcomeOfRun(effectRef, runErr, false)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.outcomes[string(effectKey[:])] = &SidecarOutcome{State: outcome.State, EffectRef: bytes.Clone(outcome.EffectRef)}
	}()
	action.Outcome = outcome
	return nil
}

// Drops the outcome recorded under effectKey, as a kill between the effect and its Outcome's fsync leaves the use.
func (self *testBridgeFileGate) forget(effectKey []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.outcomes, string(effectKey))
}

// The calls so far.
func (self *testBridgeFileGate) seen() []testBridgeFileGateCall {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]testBridgeFileGateCall{}, self.calls...)
}

// The world: a network whose member m holds a consented laptop and the filer's host, a real Sidecar posting to the
// net's log, a head carrying the block, an engine and a grant filer over the net's acl, a gate approving each action
// as m, and a record the route entries go to. With admin set, the host is the owner's device instead.
type testBridgeFileWorld struct {
	t       *testing.T
	net     *testConfigNet
	member  Id
	laptop  testConfigDevice
	hostId  Id
	sidecar *Sidecar
	clock   *identityTestClock
	api     *testBridgeFileApi
	gate    *testBridgeFileGate
	heads   *testBridgeFileHeads
	records *testBridgeFileRecords
	store   *testBridgeFileStore
	engine  *AclEngine
	filer   *BridgeFiler
	runId   Id
	agentId Id
}

func newTestBridgeFileWorld(t *testing.T, admin bool) *testBridgeFileWorld {
	t.Helper()
	net := newTestConfigNet(t)
	net.log.settings.AclSpendCheck = testBridgeSpendCheck{}
	net.log.settings.BridgeBodyJudge = testBridgeJudge()
	member, laptop := net.consentedMember("m")
	hostMember, admitter := member, laptop
	if admin {
		hostMember, admitter = net.ownerMemberId, net.owner
	}
	hostId := testConfigId("bridge file host")
	sidecar := newTestBridgeFileSidecar(t, net.networkId, hostId)
	admit := net.admission(testConfigDevice{sidecarId: hostId, memberId: hostMember, key: testConfigDeviceKey("bridge file host")}, nil, false, 0, 0)
	admit.IdentityPublicKey = bytes.Clone(sidecar.currentIdentity().IdentityPublicKey)
	net.mustPost(admitter, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit)
	// a requests rule by which a member asks a dial to its own member's devices, which its own member approves
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Requests = append(rows.Requests, &protocol.AclRequestRule{
			RuleId:        testConfigId("bridge file forward rule").Bytes(),
			SrcAtoms:      [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:       []*protocol.AclTarget{aclAutogroupTarget(protocol.AclAutogroup_ACL_AUTOGROUP_SELF)},
			Actions:       []uint32{uint32(protocol.AclAction_ACL_ACTION_DIAL)},
			ApproverAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SELF).Bytes()},
		})
	})

	clock := newIdentityTestClock()
	clock.current = time.UnixMilli(net.timeMs)
	sidecar.clock = clock
	api := &testBridgeFileApi{net: net}
	sidecarApi, err := newSidecarApi(sidecar.settings, api, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	sidecarApi.SetByJwt("a-synthetic-client-token-for-the-filer-tests")
	sidecarApi.setDpopSigner(func(method string, url string, ath string) (string, error) {
		return "a-synthetic-proof", nil
	})
	sidecar.sidecarApi = sidecarApi
	t.Cleanup(sidecar.InstallAuthority(&testBridgeFileAuthority{testActAuthority: newTestActAuthority(), net: net}))
	t.Cleanup(sidecar.InstallConfigKeys(&testConfigKeys{key: testConfigSealKey(1)}))
	gate := &testBridgeFileGate{
		t: t, requester: hostId, approver: member, notAfterMs: net.timeMs + testBridgeDayMs, approves: true,
		taintedRuns: map[Id]bool{}, taintedApprovals: map[Id]bool{}, outcomes: map[string]*SidecarOutcome{},
	}
	t.Cleanup(sidecar.InstallGate(gate))
	heads := &testBridgeFileHeads{net: net, reader: newTestConfigHeadReader(net)}
	block, err := bridgePrefixWire(testBridgeFileBlock)
	if err != nil {
		t.Fatal(err)
	}
	heads.block = net.sign(net.owner, bridge.SignedType_SIGNED_BRIDGE_BLOCK, &bridge.BridgeBlock{Ipv4Prefix: block})
	world := &testBridgeFileWorld{
		t: t, net: net, member: member, laptop: laptop, hostId: hostId, sidecar: sidecar, clock: clock, api: api, gate: gate,
		heads: heads, records: &testBridgeFileRecords{}, store: newTestBridgeFileStore(), engine: NewAclEngine(hostId, nil, nil, nil),
		runId: testConfigId("bridge file run"), agentId: testConfigId("bridge file agent"),
	}
	world.install()
	world.filer = world.newFiler()
	return world
}

// A filer over the world, as a restart opens one again over the same store.
func (self *testBridgeFileWorld) newFiler() *BridgeFiler {
	self.t.Helper()
	filer, err := NewBridgeFiler(&BridgeFilerArgs{
		Sidecar:    self.sidecar,
		Config:     testBridgeFileConfig{net: self.net},
		Heads:      self.heads,
		Grants:     NewAclGrantFiler(self.sidecar, self.engine),
		HeadWriter: func() BridgeHeadWriter { return self.heads },
		Records:    func() (RecordWriter, error) { return self.records, nil },
		Store:      self.store,
		Random:     mathrand.NewChaCha8([32]byte{0x19}),
		Clock:      self.clock,
		Log:        NewNoopLogger(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return filer
}

// Installs the net's acl state in the engine, as the host's follower does after an entry.
func (self *testBridgeFileWorld) install() {
	self.t.Helper()
	acl, err := self.net.log.State().Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	if err := self.engine.Install(acl, nil); err != nil {
		self.t.Fatal(err)
	}
}

// An agent's origin: MCP, bound to the world's run and agent.
func (self *testBridgeFileWorld) mcp() *BridgeFileOrigin {
	runId, agentId := self.runId, self.agentId
	return &BridgeFileOrigin{Act: SidecarActMcp, RunId: &runId, AgentId: &agentId}
}

// A person's confirmed command.
func (self *testBridgeFileWorld) confirmed() *BridgeFileOrigin {
	return &BridgeFileOrigin{Act: SidecarActConfirmed}
}

// The ledger of the net's reader at its tip, with generation 1's key.
func (self *testBridgeFileWorld) ledger() *BridgeLedger {
	return self.net.bridgeLedger()
}

// The bridge statements the log took under ruleId, in log order.
func (self *testBridgeFileWorld) filingsOf(ruleId []byte) []*BridgeLogStatement {
	filings := []*BridgeLogStatement{}
	for _, statement := range self.net.log.State().Bridge().Statements() {
		if bytes.Equal(statement.RuleId, ruleId) && statement.filesRule() {
			filings = append(filings, statement)
		}
	}
	return filings
}

// An exposure files its route under the rule id §17.8 derives from the spend's effect key: the log holds it active,
// its approval verified where it landed, its advertiser this host; the gate saw the run binding unchanged; and one route
// entry names it, opened, with its cidrs and approval.
func TestBridgeExposeFilesItsRouteUnderTheSpendsRuleId(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	filing, err := world.filer.Expose(ctx, world.mcp(), &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.7.0/24")}, SiteId: []byte("site")})
	if err != nil {
		t.Fatal(err)
	}
	calls := world.gate.seen()
	if len(calls) != 1 || calls[0].kind != SidecarActionExpose || *calls[0].runId != world.runId || *calls[0].agentId != world.agentId {
		t.Fatalf("the gate saw %+v", calls)
	}
	want := BridgeRuleId([sha256.Size]byte(calls[0].effectKey))
	if !bytes.Equal(filing.RuleId, want[:]) || filing.ApprovalId == (Id{}) {
		t.Fatalf("the filing: %+v", filing)
	}
	rule := world.ledger().Rule(filing.RuleId)
	if rule == nil || !rule.Active() || rule.Standing || rule.Owner != world.hostId || rule.ApprovalId != filing.ApprovalId {
		t.Fatalf("the rule: %+v", rule)
	}
	if got := world.api.postedTypes(t); len(got) != 1 || got[0] != bridge.SignedType_SIGNED_BRIDGE_ROUTE {
		t.Fatalf("posted %v", got)
	}
	routes := world.records.routes(t)
	if len(routes) != 1 {
		t.Fatalf("%d route entries", len(routes))
	}
	body := routes[0].Body.(*protocol.RouteBody)
	if body.GetEvent() != bridgeRouteRecordOpened || body.GetKind() != bridgeRouteRecordRoute || !bytes.Equal(body.GetRuleId(), filing.RuleId) ||
		len(body.GetCidrs()) != 1 || body.GetCidrs()[0] != "192.168.7.0/24" || !bytes.Equal(body.GetApprovalId(), filing.ApprovalId.Bytes()) ||
		!bytes.Equal(body.GetTargetSidecarId(), world.hostId.Bytes()) {
		t.Errorf("the route entry: %v", body)
	}
	if *routes[0].RunId != world.runId || *routes[0].AgentId != world.agentId || routes[0].Source != RecordSourceObserved || len(routes[0].ActionId) != sha256.Size {
		t.Errorf("the route entry's header: %+v", routes[0])
	}
}

// A re-signed retry keeps its rule id: a filing whose post never applied answers uncertain; the retry files a new
// signature under the same id, which lands; the first, posted again later with its same bytes, lands as a filing of the
// held id, which activates nothing; and one rule is in force, with one route entry.
func TestBridgeExposeRetryKeepsItsRuleId(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	request := &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}, SiteId: []byte("site")}
	world.api.answers = []string{"dropped"}
	if _, err := world.filer.Expose(ctx, world.mcp(), request); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a lost post: %v", err)
	}
	filing, err := world.filer.Expose(ctx, world.mcp(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := world.sidecar.PostPendingStatements(ctx); err != nil {
		t.Fatal(err)
	}
	filings := world.filingsOf(filing.RuleId)
	if len(filings) != 2 || bytes.Equal(filings[0].StatementId[:], filings[1].StatementId[:]) {
		t.Fatalf("%d filings of the id", len(filings))
	}
	ledger := world.ledger()
	testBridgeDisposition(t, ledger, filings[0].N, BridgeDispositionActive)
	testBridgeDisposition(t, ledger, filings[1].N, BridgeDispositionHeld)
	if rule := ledger.Rule(filing.RuleId); rule == nil || !rule.Active() {
		t.Fatalf("the rule: %+v", rule)
	}
	if routes := world.records.routes(t); len(routes) != 1 {
		t.Errorf("%d route entries for one filing", len(routes))
	}
}

// A kill between the filing and its Outcome: the retry runs the effect again under the same key, which finds the rule in
// the log and files nothing, so the log holds one filing; FindRule finds it and the component's Lookup answers done with
// its id, uncertain before it landed and for a key no filing fixes.
func TestBridgeFindRuleAfterAKillFindsOneRule(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	request := &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("172.16.4.0/24")}}
	route := &bridge.BridgeRouteBody{Prefixes: []*bridge.BridgeIpv4Prefix{testBridgePrefix(172, 16, 4, 0, 24)}, Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET}
	stored, err := bridgeRouteAction(world.hostId, route)
	if err != nil {
		t.Fatal(err)
	}
	payload := sha256.Sum256(stored.Bytes)
	approvalId := testConfigId("expose approval " + hex.EncodeToString(payload[:]))
	effectKey := ApprovalEffectKey(approvalId, stored.ActionId(approvalId))
	if outcome, err := world.filer.Lookup(ctx, stored.Bytes, effectKey[:]); err != nil || outcome.State != ApprovalOutcomeUncertain {
		t.Fatalf("before the filing: %+v %v", outcome, err)
	}

	first, err := world.filer.Expose(ctx, world.mcp(), request)
	if err != nil {
		t.Fatal(err)
	}
	world.gate.forget(effectKey[:])
	again, err := world.filer.Expose(ctx, world.mcp(), request)
	if err != nil || !bytes.Equal(again.RuleId, first.RuleId) {
		t.Fatalf("the retry: %+v %v", again, err)
	}
	if filings := world.filingsOf(first.RuleId); len(filings) != 1 {
		t.Fatalf("%d filings after a retry of a filing that landed", len(filings))
	}
	if world.api.postCount() != 1 {
		t.Errorf("%d posts", world.api.postCount())
	}
	rule, err := world.filer.FindRule(ctx, first.RuleId)
	if err != nil || rule == nil || !rule.Active() {
		t.Fatalf("FindRule: %+v %v", rule, err)
	}
	outcome, err := world.filer.Lookup(ctx, stored.Bytes, effectKey[:])
	if err != nil || outcome.State != ApprovalOutcomeDone || !bytes.Equal(outcome.EffectRef, first.RuleId) {
		t.Fatalf("Lookup: %+v %v", outcome, err)
	}
	if outcome, _ := world.filer.Lookup(ctx, stored.Bytes, bytes.Repeat([]byte{0x33}, sha256.Size)); outcome.State != ApprovalOutcomeUncertain {
		t.Errorf("a key no filing fixes: %+v", outcome)
	}
	if routes := world.records.routes(t); len(routes) != 1 {
		t.Errorf("%d route entries", len(routes))
	}
}

// A host's first map files its own BridgeAddress, then the map, which matches that address and completes; a second map
// files no second address.
func TestBridgeFirstMapFilesItsAddressThenTheMap(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	first, err := world.filer.ExposeMap(ctx, world.mcp(), &BridgeMapRequest{FirstPort: 8443, TargetPort: 443, Target: netip.MustParseAddr("192.168.9.20")})
	if err != nil {
		t.Fatal(err)
	}
	posted := world.api.postedTypes(t)
	if len(posted) != 2 || posted[0] != bridge.SignedType_SIGNED_BRIDGE_ADDRESS || posted[1] != bridge.SignedType_SIGNED_BRIDGE_MAP {
		t.Fatalf("posted %v", posted)
	}
	ledger := world.ledger()
	held := ledger.Address(world.hostId)
	if held == nil || !first.AddressFiled || !testBridgeFileBlock.Contains(first.Address) {
		t.Fatalf("the address: %+v %+v", held, first)
	}
	if want := bridgeAddressOf(testBridgeIpv4(100, 80, 0, 0) | held.HostBits); first.Address != want || held.HostBits&0x8000 != 0 {
		t.Errorf("the address %s, the ledger's host bits %#x", first.Address, held.HostBits)
	}
	rule := ledger.Rule(first.RuleId)
	if rule == nil || !rule.Active() || rule.Map == nil || rule.Map.GetTargetPort() != 443 {
		t.Fatalf("the map: %+v", rule)
	}
	address, _ := bridgeIpv4Of(first.Address)
	if rule.Map.GetMatchPrefix().GetAddress() != address || rule.Map.GetMatchPrefix().GetLength() != 32 {
		t.Errorf("the map matches %v", rule.Map.GetMatchPrefix())
	}

	second, err := world.filer.ExposeMap(ctx, world.mcp(), &BridgeMapRequest{FirstPort: 5432})
	if err != nil {
		t.Fatal(err)
	}
	if second.AddressFiled || second.Address != first.Address || len(world.api.postedTypes(t)) != 3 {
		t.Fatalf("a second map: %+v, %d posts", second, world.api.postCount())
	}
	if rule := world.ledger().Rule(second.RuleId); rule == nil || !rule.Active() || !bytes.Equal(rule.Map.GetTarget(), []byte{127, 0, 0, 1}) || rule.Map.GetTargetPort() != 5432 {
		t.Fatalf("the second map: %+v", rule)
	}
	routes := world.records.routes(t)
	if len(routes) != 2 || routes[0].Body.(*protocol.RouteBody).GetKind() != bridgeRouteRecordMap {
		t.Errorf("%d route entries", len(routes))
	}
}

// What is not this sidecar's own is refused at the filer before any act, and by the verifier for a statement that
// reaches it: a BridgeAddress for another sidecar_id, a second for an addressed host, a claim by an agent or a hook, a
// BridgeWithdraw of another's rule, a GrantRevoke of a grant this sidecar is no subject of, and a BridgeBlock,
// BridgeEgress or Suspend from MCP.
func TestBridgeFilerRefusesWhatIsNotItsOwn(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	view, err := world.filer.view(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.filer.claimAddress(ctx, world.mcp(), view, world.laptop.sidecarId, testBridgeIpv4(100, 80, 3, 7)); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("an address for another sidecar_id: %v", err)
	}
	for _, act := range []SidecarActOrigin{SidecarActMcp, SidecarActHook} {
		if _, err := world.filer.ClaimAddress(ctx, &BridgeFileOrigin{Act: act}, netip.MustParseAddr("100.80.3.7")); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("a claim from origin %d: %v", act, err)
		}
	}
	if _, err := world.filer.ClaimAddress(ctx, world.confirmed(), netip.MustParseAddr("100.80.3.7")); err != nil {
		t.Fatal(err)
	}
	if _, err := world.filer.ClaimAddress(ctx, world.confirmed(), netip.MustParseAddr("100.80.3.8")); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a second address for an addressed host: %v", err)
	}
	view, err = world.filer.view(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.filer.claimAddress(ctx, world.mcp(), view, world.hostId, testBridgeIpv4(100, 80, 3, 9)); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a second address through the map's path: %v", err)
	}

	// the laptop's own rule, which the host may not withdraw
	laptopRule := testBridgeRuleId("the laptop's")
	world.net.mustPost(world.laptop, bridge.SignedType_SIGNED_BRIDGE_ROUTE, world.net.bridgeRoute(world.laptop, laptopRule, testBridgeSubnet(testBridgePrefix(192, 168, 50, 0, 24), "lab")))
	posts := world.api.postCount()
	if _, err := world.filer.Close(ctx, world.mcp(), laptopRule, false); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a withdraw of another's rule: %v", err)
	}
	if _, err := world.filer.Close(ctx, world.mcp(), testBridgeRuleId("no such grant"), false); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a revoke of a grant that is not its own: %v", err)
	}
	if _, err := world.filer.SetBlock(ctx, world.mcp(), &BridgeBlockRequest{Cycle: true}); !errors.Is(err, ErrSidecarActMode) {
		t.Errorf("a block from MCP: %v", err)
	}
	if _, err := world.filer.SetEgress(ctx, world.mcp(), &BridgeEgressRequest{Subject: world.hostId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE}); !errors.Is(err, ErrSidecarActMode) {
		t.Errorf("an egress spec from MCP: %v", err)
	}
	act, err := world.sidecar.newAct(SidecarActMcp)
	if err != nil {
		t.Fatal(err)
	}
	if err := act.Add(bridge.SignedType_SIGNED_SUSPEND, &bridge.Suspend{Subject: world.laptop.sidecarId.Bytes(), SuspendId: aclTestSuspendId("from mcp")}); !errors.Is(err, ErrSidecarActMode) {
		t.Errorf("a Suspend from MCP: %v", err)
	}
	if world.api.postCount() != posts || len(world.gate.seen()) != 0 {
		t.Errorf("a refusal posted %d or reached the gate %d times", world.api.postCount()-posts, len(world.gate.seen()))
	}

	// the verifier refuses the same: a BridgeAddress for the laptop signed by the host's identity key
	header := world.net.header()
	foreign := &bridge.BridgeAddress{
		Header: header, SidecarId: world.laptop.sidecarId.Bytes(),
		SealedBody: world.net.bridgeSeal(bridge.SignedType_SIGNED_BRIDGE_ADDRESS, header, &bridge.BridgeAddressBody{Ipv4: testBridgeIpv4(100, 80, 4, 4)}, 1),
	}
	signed, err := world.sidecar.Sign(bridge.SignedPurposeBridge, bridge.SignedType_SIGNED_BRIDGE_ADDRESS, testConfigMarshal(t, foreign), nil)
	if err != nil {
		t.Fatal(err)
	}
	verdict := world.net.push(world.net.makeEntry(bridge.AuthEntryKindStatement, testConfigMarshal(t, signed)))
	if verdict.Accepted() || !errors.Is(verdict.Refusal, ErrConfigAuthority) {
		t.Errorf("the verifier took a BridgeAddress for another sidecar_id: %v", verdict.Refusal)
	}
}

// With no decision and no standing grant, an exposure waits for a person: ApprovalPendingError, nothing posted and no
// entry written.
func TestBridgeExposeWithNoActiveGrantWaits(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	world.gate.approves = false
	pending := &ApprovalPendingError{}
	if _, err := world.filer.Expose(context.Background(), world.mcp(), &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}}); !errors.As(err, &pending) {
		t.Fatalf("no grant: %v", err)
	}
	if _, err := world.filer.ExposeMap(context.Background(), world.mcp(), &BridgeMapRequest{FirstPort: 22}); !errors.As(err, &pending) {
		t.Fatalf("a map with no grant: %v", err)
	}
	if world.api.postCount() != 0 || len(world.records.routes(t)) != 0 {
		t.Errorf("%d posts and %d entries while waiting", world.api.postCount(), len(world.records.routes(t)))
	}
}

// A tainted run's binding reaches the gate unchanged: a standing grant passes an untainted run's route under a random
// id with no approval, and nothing in the tainted run; a decision on an untainted request waits there; a decision on
// a request the run filed tainted files.
func TestBridgeATaintedRunTakesOnlyFreshEvidence(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	world.gate.approves = false
	world.gate.standing = true
	world.gate.taintedRuns[world.runId] = true
	pending := &ApprovalPendingError{}
	tainted := &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}}
	if _, err := world.filer.Expose(ctx, world.mcp(), tainted); !errors.As(err, &pending) {
		t.Fatalf("a standing grant in a tainted run: %v", err)
	}
	cleanRun := testConfigId("an untainted run")
	standing, err := world.filer.Expose(ctx, &BridgeFileOrigin{Act: SidecarActMcp, RunId: &cleanRun}, &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("10.31.0.0/16")}})
	if err != nil {
		t.Fatal(err)
	}
	if rule := world.ledger().Rule(standing.RuleId); rule == nil || !rule.Standing || standing.ApprovalId != (Id{}) {
		t.Fatalf("the standing route: %+v", rule)
	}

	world.gate.standing = false
	route := &bridge.BridgeRouteBody{Prefixes: []*bridge.BridgeIpv4Prefix{testBridgePrefix(10, 30, 0, 0, 16)}, Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET}
	stored, err := bridgeRouteAction(world.hostId, route)
	if err != nil {
		t.Fatal(err)
	}
	stale := testBridgeDecision(t, "stale", stored.Bytes, 1, world.hostId, world.member, world.net.timeMs+testBridgeDayMs)
	origin := world.mcp()
	origin.Decision = stale
	if _, err := world.filer.Expose(ctx, origin, tainted); !errors.As(err, &pending) {
		t.Fatalf("a stale decision in a tainted run: %v", err)
	}
	fresh := testBridgeDecision(t, "fresh", stored.Bytes, 1, world.hostId, world.member, world.net.timeMs+testBridgeDayMs)
	world.gate.taintedApprovals[testConfigId("expose approval fresh")] = true
	origin.Decision = fresh
	filing, err := world.filer.Expose(ctx, origin, tainted)
	if err != nil {
		t.Fatal(err)
	}
	if rule := world.ledger().Rule(filing.RuleId); rule == nil || !rule.Active() || rule.ApprovalId != testConfigId("expose approval fresh") {
		t.Fatalf("the fresh decision's rule: %+v", rule)
	}
	for _, call := range world.gate.seen() {
		if call.runId == nil || (*call.runId != world.runId && *call.runId != cleanRun) || (call.agentId != nil && *call.agentId != world.agentId) {
			t.Errorf("the gate saw another binding: %+v", call)
		}
	}
}

// Close withdraws this host's rule, draining, and writes a closed entry; a second close of it is refused. It revokes a
// forward's grant this host is the subject of, and the grant leaves the engine's list.
func TestBridgeCloseWithdrawsItsRuleAndRevokesItsGrant(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	exposed, err := world.filer.Expose(ctx, world.mcp(), &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.30.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := world.filer.Close(ctx, world.mcp(), exposed.RuleId, false); err != nil {
		t.Fatal(err)
	}
	rule := world.ledger().Rule(exposed.RuleId)
	if rule == nil || rule.Withdrawn == nil || rule.Withdrawn.Mode != bridge.BridgeWithdrawMode_BRIDGE_WITHDRAW_MODE_DRAIN || rule.Active() {
		t.Fatalf("the withdrawn rule: %+v", rule)
	}
	if _, err := world.filer.Close(ctx, world.mcp(), exposed.RuleId, true); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a second close: %v", err)
	}

	forward, err := world.filer.Forward(ctx, world.mcp(), &BridgeForwardRequest{Target: world.laptop.sidecarId, Port: 22, LocalPort: 2222})
	if err != nil {
		t.Fatal(err)
	}
	world.install()
	listed := func() bool {
		for _, grant := range world.engine.Grants(AclSidecarSubject(world.hostId), world.clock.Now()) {
			if bytes.Equal(grant.GrantId, forward.GrantId) {
				return true
			}
		}
		return false
	}
	if len(forward.GrantId) != sha256.Size || !listed() {
		t.Fatalf("the forward's grant: %+v", forward)
	}
	if _, err := world.filer.Close(ctx, world.mcp(), forward.GrantId, false); err != nil {
		t.Fatal(err)
	}
	world.install()
	if listed() {
		t.Error("the revoked grant is still listed")
	}
	routes := world.records.routes(t)
	kinds := []string{}
	for _, route := range routes {
		body := route.Body.(*protocol.RouteBody)
		kinds = append(kinds, fmt.Sprintf("%d/%d/%d", body.GetEvent(), body.GetKind(), body.GetReason()))
	}
	want := []string{"1/3/0", "2/3/3", "1/1/0", "2/1/2"}
	if fmt.Sprint(kinds) != fmt.Sprint(want) {
		t.Errorf("the route entries %v, want %v", kinds, want)
	}
	if !bytes.Equal(routes[2].GrantId, forward.GrantId) || !bytes.Equal(routes[3].GrantId, forward.GrantId) {
		t.Error("a forward's entries name its grant")
	}
}

// A forward's grant is the requests rule's one agent, port and window (R-BRIDGE-6): its action seals the port, the
// request binds the local port, and the grant reaches its target for 1 h by default and not after, on a fake clock.
func TestBridgeForwardsGrantEndsWithItsWindow(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	forward, err := world.filer.Forward(ctx, world.mcp(), &BridgeForwardRequest{Target: world.laptop.sidecarId, Port: 22, LocalPort: 2222})
	if err != nil {
		t.Fatal(err)
	}
	calls := world.gate.seen()
	stored, err := ParseStoredCanonicalAction(calls[len(calls)-1].canonical)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Action.GetKind() != uint32(SidecarActionForward) || len(stored.Action.GetSealedDetail()) == 0 || bytes.Contains(stored.Bytes, []byte(":tcp:22")) {
		t.Fatalf("the forward's action: %+v", stored.Action)
	}
	expiresMs := world.clock.Now().UnixMilli() + aclRequestDefaultExpiryMs
	if stored.Action.GetExpiresMillis() != expiresMs {
		t.Errorf("the grant ends at %d, want an hour on, %d", stored.Action.GetExpiresMillis(), expiresMs)
	}
	world.install()
	// the engine lists a grant through its clock skew past the end the rows hold
	held := func(at time.Time) *AclGrantInfo {
		for _, grant := range world.engine.Grants(AclSidecarSubject(world.hostId), at) {
			if bytes.Equal(grant.GrantId, forward.GrantId) {
				return &grant
			}
		}
		return nil
	}
	skew := DefaultAclEngineSettings().ClockSkew
	if grant := held(world.clock.Now()); grant == nil || grant.ExpiresMs != expiresMs {
		t.Fatalf("the grant now: %+v", grant)
	}
	if held(time.UnixMilli(expiresMs).Add(skew-time.Millisecond)) == nil || held(time.UnixMilli(expiresMs).Add(skew+time.Millisecond)) != nil {
		t.Error("the grant does not end with its window")
	}
	if _, err := world.filer.Forward(ctx, world.mcp(), &BridgeForwardRequest{Target: world.hostId, Port: 22}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a forward to itself: %v", err)
	}
	if _, err := world.filer.Forward(ctx, world.mcp(), &BridgeForwardRequest{Target: world.laptop.sidecarId}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("a forward with no port: %v", err)
	}
}

// SetBlock (§22.5's §17 row): a chosen block outside 100.64/10 and RFC 1918, a /15 and the block in force are refused,
// nothing saved; an RFC 1918 /16 is saved signed by this admin's device, the block it replaces draining, and the head's
// reader takes it; cycle draws a /16 of 100.64/10 outside the two excluded; and a non-admin's device saves nothing.
func TestBridgeSetBlockRefusesABlockOutsideTheRanges(t *testing.T) {
	world := newTestBridgeFileWorld(t, true)
	ctx := context.Background()
	for _, refused := range []string{"169.254.0.0/16", "198.18.0.0/16", "10.20.0.0/15", "100.80.0.0/16"} {
		if _, err := world.filer.SetBlock(ctx, world.confirmed(), &BridgeBlockRequest{Prefix: netip.MustParsePrefix(refused)}); !errors.Is(err, ErrBridgeBlockRefused) {
			t.Errorf("%s: %v", refused, err)
		}
	}
	if _, count := world.heads.savedHead(); count != 0 {
		t.Fatalf("%d heads saved for refused blocks", count)
	}
	block, err := world.filer.SetBlock(ctx, world.confirmed(), &BridgeBlockRequest{Prefix: netip.MustParsePrefix("10.20.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	head, count := world.heads.savedHead()
	read, err := ReadBridgeBlock(head, world.net.log.State(), nil)
	if err != nil || count != 1 || !proto.Equal(read, block) {
		t.Fatalf("the saved block: %v %v", read, err)
	}
	if read.GetIpv4Prefix().GetAddress() != testBridgeIpv4(10, 20, 0, 0) || read.GetPreviousPrefix().GetAddress() != testBridgeIpv4(100, 80, 0, 0) ||
		read.GetDrainUntil() != world.clock.Now().Add(DefaultBridgeFilerSettings().BlockDrainTimeout).UnixMilli() {
		t.Errorf("the block: %v", read)
	}
	cycled, err := world.filer.SetBlock(ctx, world.confirmed(), &BridgeBlockRequest{Cycle: true})
	if err != nil {
		t.Fatal(err)
	}
	address := cycled.GetIpv4Prefix().GetAddress()
	if address>>16 < 100<<8|64 || 100<<8|127 < address>>16 || address>>16 == 100<<8|64 || address>>16 == 100<<8|100 ||
		cycled.GetPreviousPrefix().GetAddress() != testBridgeIpv4(10, 20, 0, 0) {
		t.Errorf("the cycled block: %v", cycled)
	}

	member := newTestBridgeFileWorld(t, false)
	if _, err := member.filer.SetBlock(ctx, member.confirmed(), &BridgeBlockRequest{Prefix: netip.MustParsePrefix("10.21.0.0/16")}); !errors.Is(err, ErrBridgeBlockRefused) {
		t.Errorf("a member's device: %v", err)
	}
	if _, count := member.heads.savedHead(); count != 0 {
		t.Error("a member's device saved a head")
	}
}

// The BridgeEgress statements the log took, in log order.
func (self *testBridgeFileWorld) egressFilings() []*BridgeLogStatement {
	filings := []*BridgeLogStatement{}
	for _, statement := range self.net.log.State().Bridge().Statements() {
		if statement.SignedType == bridge.SignedType_SIGNED_BRIDGE_EGRESS {
			filings = append(filings, statement)
		}
	}
	return filings
}

// The gate's last call.
func (self *testBridgeFileWorld) lastGateCall() testBridgeFileGateCall {
	self.t.Helper()
	calls := self.gate.seen()
	if len(calls) == 0 {
		self.t.Fatal("no call reached the gate")
	}
	return calls[len(calls)-1]
}

// SetEgress (QD-799): a person's confirmed command files its subject's BridgeEgress under §5.4's gate as kind
// egress_change, the action naming the subject, the mode and the exits; the log takes the mode in the clear and the
// exits sealed, auto leaving no spec; and the component's Lookup answers done with the statement's id. MCP, a hook and
// an unconfirmed call are refused before the gate, as is a device that is no admin's and not the subject's owner's or
// sponsor's, and shapes the readers would void; with no decision the change waits, filing nothing.
func TestBridgeSetEgressFilesUnderTheGate(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	none := &BridgeEgressRequest{Subject: world.hostId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE}
	for _, origin := range []*BridgeFileOrigin{world.mcp(), {Act: SidecarActHook}, {Act: SidecarActUnconfirmed}} {
		if _, err := world.filer.SetEgress(ctx, origin, none); !errors.Is(err, ErrSidecarActMode) {
			t.Errorf("origin %d: %v", origin.Act, err)
		}
	}
	// the owner's device belongs to another member, and this host's member is no admin
	if _, err := world.filer.SetEgress(ctx, world.confirmed(), &BridgeEgressRequest{Subject: world.net.owner.sidecarId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE}); !errors.Is(err, ErrBridgeFileRefused) {
		t.Errorf("another member's sidecar: %v", err)
	}
	for _, refused := range []*BridgeEgressRequest{
		{Subject: world.hostId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS},
		{Subject: world.hostId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE, ExitSidecarIds: []Id{world.laptop.sidecarId}},
		{Subject: world.hostId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, ExitSidecarIds: []Id{world.laptop.sidecarId, world.laptop.sidecarId}},
		{Subject: world.hostId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, ExitSidecarIds: []Id{world.laptop.sidecarId}, ExitTagId: testConfigId("exit tag")},
		{Subject: world.hostId},
		{Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO},
	} {
		if _, err := world.filer.SetEgress(ctx, world.confirmed(), refused); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("%+v: %v", refused, err)
		}
	}
	if world.api.postCount() != 0 || len(world.gate.seen()) != 0 {
		t.Fatal("a refused egress change reached the gate or the log")
	}
	world.gate.approves = false
	var pending *ApprovalPendingError
	if _, err := world.filer.SetEgress(ctx, world.confirmed(), none); !errors.As(err, &pending) {
		t.Fatalf("with no decision: %v", err)
	}
	if world.api.postCount() != 0 || len(world.store.names(bridgeFileEgressPrefix)) != 0 {
		t.Fatal("a waiting egress change filed")
	}
	world.gate.approves = true

	filing, err := world.filer.SetEgress(ctx, world.confirmed(), &BridgeEgressRequest{
		Subject: world.hostId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS, ExitSidecarIds: []Id{world.laptop.sidecarId},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := world.lastGateCall()
	stored, err := ParseStoredCanonicalAction(call.canonical)
	if err != nil {
		t.Fatal(err)
	}
	action := stored.Action
	if call.kind != SidecarActionEgressChange || action.GetVersion() != 1 || !bytes.Equal(action.GetSubject(), world.hostId.Bytes()) ||
		bridge.BridgeEgressMode(action.GetEgressMode()) != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS ||
		len(action.GetGrantDst()) != 1 || action.GetGrantDst()[0] != "sidecar:"+hex.EncodeToString(world.laptop.sidecarId.Bytes()) {
		t.Fatalf("the action: %v", action)
	}
	if filing.ApprovalId == (Id{}) || call.runId != nil {
		t.Errorf("the filing %+v, the run %v", filing, call.runId)
	}
	egress := world.ledger().Egress()
	if len(egress) != 1 || egress[0].Subject != world.hostId || egress[0].Mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS ||
		len(egress[0].ExitSidecarIds) != 1 || egress[0].ExitSidecarIds[0] != world.laptop.sidecarId {
		t.Fatalf("the egress spec: %+v", egress)
	}
	outcome, err := world.filer.LookupEgress(ctx, call.canonical, call.effectKey)
	landed := world.egressFilings()
	if err != nil || outcome.State != ApprovalOutcomeDone || len(landed) != 1 {
		t.Fatalf("Lookup: %+v %v, %d filings", outcome, err, len(landed))
	}
	if statementId, _ := bridgeSignedStatementId(world.api.posts[0]); !bytes.Equal(outcome.EffectRef, statementId[:]) {
		t.Error("Lookup answers another statement's id")
	}

	// none and then auto, bodiless, the last leaving no spec
	if _, err := world.filer.SetEgress(ctx, world.confirmed(), none); err != nil {
		t.Fatal(err)
	}
	if egress := world.ledger().Egress(); len(egress) != 1 || egress[0].Mode != bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE {
		t.Fatalf("after none: %+v", egress)
	}
	if _, err := world.filer.SetEgress(ctx, world.confirmed(), &BridgeEgressRequest{Subject: world.hostId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_AUTO}); err != nil {
		t.Fatal(err)
	}
	if egress := world.ledger().Egress(); len(egress) != 0 || len(world.egressFilings()) != 3 {
		t.Fatalf("after auto: %+v, %d filings", egress, len(world.egressFilings()))
	}
	if routes := world.records.routes(t); len(routes) != 0 {
		t.Errorf("%d route entries for egress changes", len(routes))
	}
}

// An egress change runs once per effect key. An answer lost after its statement applied reads uncertain, the retry
// finds the statement by the bytes its marker keeps and posts nothing, and Lookup answers done; a post that never
// applied leaves Lookup uncertain, and the retry posts the same bytes, which land once; bytes refused at that retry,
// which never land, are signed anew under the same key; and a refusal before anything landed keeps no marker, so Lookup
// answers not done.
func TestBridgeSetEgressRetryFindsItsStatement(t *testing.T) {
	ctx := context.Background()
	none := func(world *testBridgeFileWorld) *BridgeEgressRequest {
		return &BridgeEgressRequest{Subject: world.hostId, Mode: bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_NONE}
	}
	lookup := func(world *testBridgeFileWorld, call testBridgeFileGateCall) ApprovalOutcomeState {
		t.Helper()
		outcome, err := world.filer.LookupEgress(ctx, call.canonical, call.effectKey)
		if err != nil {
			t.Fatal(err)
		}
		return outcome.State
	}

	lost := newTestBridgeFileWorld(t, false)
	lost.api.answers = []string{"lost"}
	if _, err := lost.filer.SetEgress(ctx, lost.confirmed(), none(lost)); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a lost answer: %v", err)
	}
	call := lost.lastGateCall()
	if state := lookup(lost, call); state != ApprovalOutcomeDone || len(lost.store.names(bridgeFileEgressPrefix)) != 1 {
		t.Fatalf("Lookup after a lost answer: %v", state)
	}
	// a restart's filer, over the same store, retries the use
	lost.filer = lost.newFiler()
	if _, err := lost.filer.SetEgress(ctx, lost.confirmed(), none(lost)); err != nil {
		t.Fatal(err)
	}
	if lost.api.postCount() != 1 || len(lost.egressFilings()) != 1 {
		t.Fatalf("%d posts, %d filings after a retry of a statement that landed", lost.api.postCount(), len(lost.egressFilings()))
	}

	dropped := newTestBridgeFileWorld(t, false)
	dropped.api.answers = []string{"dropped"}
	if _, err := dropped.filer.SetEgress(ctx, dropped.confirmed(), none(dropped)); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a dropped post: %v", err)
	}
	call = dropped.lastGateCall()
	if state := lookup(dropped, call); state != ApprovalOutcomeUncertain || len(dropped.egressFilings()) != 0 {
		t.Fatalf("Lookup after a dropped post: %v", state)
	}
	if _, err := dropped.filer.SetEgress(ctx, dropped.confirmed(), none(dropped)); err != nil {
		t.Fatal(err)
	}
	if dropped.api.postCount() != 2 || len(dropped.egressFilings()) != 1 || !bytes.Equal(dropped.api.posts[0], dropped.api.posts[1]) {
		t.Fatalf("%d posts, %d filings: the retry did not post the same bytes once more", dropped.api.postCount(), len(dropped.egressFilings()))
	}
	if state := lookup(dropped, call); state != ApprovalOutcomeDone {
		t.Errorf("Lookup once the retry landed: %v", state)
	}

	anew := newTestBridgeFileWorld(t, false)
	anew.api.answers = []string{"dropped", "refused"}
	if _, err := anew.filer.SetEgress(ctx, anew.confirmed(), none(anew)); !errors.Is(err, ErrBridgeFileUncertain) {
		t.Fatalf("a dropped post: %v", err)
	}
	if _, err := anew.filer.SetEgress(ctx, anew.confirmed(), none(anew)); err != nil {
		t.Fatal(err)
	}
	if anew.api.postCount() != 3 || len(anew.egressFilings()) != 1 || bytes.Equal(anew.api.posts[2], anew.api.posts[0]) {
		t.Fatalf("%d posts, %d filings: refused bytes were not signed anew", anew.api.postCount(), len(anew.egressFilings()))
	}
	if state := lookup(anew, anew.lastGateCall()); state != ApprovalOutcomeDone {
		t.Errorf("Lookup after signing anew: %v", state)
	}

	refused := newTestBridgeFileWorld(t, false)
	refused.api.answers = []string{"refused"}
	if _, err := refused.filer.SetEgress(ctx, refused.confirmed(), none(refused)); !errors.Is(err, ErrSidecarEffectNotDone) {
		t.Fatalf("a refused post: %v", err)
	}
	if state := lookup(refused, refused.lastGateCall()); state != ApprovalOutcomeNotDone || len(refused.store.names(bridgeFileEgressPrefix)) != 0 {
		t.Errorf("Lookup after a refusal: %v", state)
	}
}

// Bodies the readers would void are refused before the gate asks anyone: an exit with prefixes, 0.0.0.0/0 as a subnet,
// an unmasked prefix, a remap of two prefixes, a map onto the block, an ICMP map with ports, a map already expired.
func TestBridgeFilerRefusesBodiesReadersWouldVoid(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	for _, route := range []*BridgeRouteRequest{
		{Exit: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}},
		{Prefixes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}},
		{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.7/24")}},
		{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("192.168.2.0/24")}, Remap: true},
		{Prefixes: []netip.Prefix{netip.MustParsePrefix("fd00::/64")}},
	} {
		if _, err := world.filer.Expose(ctx, world.mcp(), route); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("%+v: %v", route, err)
		}
	}
	for _, mapRequest := range []*BridgeMapRequest{
		{FirstPort: 80, Target: netip.MustParseAddr("100.80.9.9")},
		{Protocol: bridgeProtocolIcmp, FirstPort: 80},
		{FirstPort: 80, Expires: world.clock.Now().Add(-time.Second)},
		{Protocol: 47, FirstPort: 80},
		{FirstPort: 90, LastPort: 80},
	} {
		if _, err := world.filer.ExposeMap(ctx, world.mcp(), mapRequest); !errors.Is(err, ErrBridgeFileRefused) {
			t.Errorf("%+v: %v", mapRequest, err)
		}
	}
	if len(world.gate.seen()) != 0 || world.api.postCount() != 0 {
		t.Error("a refused body reached the gate or the log")
	}
	// an exit and a remap pass
	exit, err := world.filer.Expose(ctx, world.mcp(), &BridgeRouteRequest{Exit: true})
	if err != nil {
		t.Fatal(err)
	}
	remap, err := world.filer.Expose(ctx, world.mcp(), &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, Remap: true})
	if err != nil {
		t.Fatal(err)
	}
	ledger := world.ledger()
	if rule := ledger.Rule(exit.RuleId); rule == nil || !rule.Active() || rule.Route.GetKind() != bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_EXIT {
		t.Errorf("the exit: %+v", rule)
	}
	rule := ledger.Rule(remap.RuleId)
	if rule == nil || !rule.Active() || rule.Route.GetExposedPrefix().GetAddress() != testBridgeIpv4(100, 80, 128, 0) || rule.Route.GetExposedPrefix().GetLength() != 24 {
		t.Errorf("the remap: %+v", rule)
	}
}

// A route names the head's route rules that hold it for this advertiser, by the readers' own predicate: with no
// document, the implicit policy's; a rule of the head routing a prefix that holds the route is named, and one that does
// not, or one naming another target, is not.
func TestBridgeRouteNamesTheRouteRulesThatHoldIt(t *testing.T) {
	world := newTestBridgeFileWorld(t, false)
	ctx := context.Background()
	holding, other := testConfigId("a route rule holding the lab"), testConfigId("a route rule elsewhere")
	world.net.withAclRows(func(rows *protocol.AclRows) {
		for _, ruleId := range []Id{holding, other} {
			rows.Rules = append(rows.Rules, &protocol.AclRule{
				RuleId:   ruleId.Bytes(),
				SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
				Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_ROUTE)},
			})
		}
	})
	world.heads.reader = newTestConfigHeadReader(world.net)
	local := &AclLocalPolicy{Rules: []AclLocalRule{
		{RuleId: holding, Cidrs: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}},
		{RuleId: other, Cidrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
	}}
	world.filer.args.AclLocal = func() *AclLocalPolicy { return local }
	view, err := world.filer.view(ctx)
	if err != nil {
		t.Fatal(err)
	}
	route := &bridge.BridgeRouteBody{Prefixes: []*bridge.BridgeIpv4Prefix{testBridgePrefix(192, 168, 40, 0, 24)}, Kind: bridge.BridgeRouteKind_BRIDGE_ROUTE_KIND_SUBNET, Weight: 1}
	ruleIds := world.filer.routeRuleIds(view, route)
	if len(ruleIds) != 1 || !bytes.Equal(ruleIds[0], holding.Bytes()) {
		t.Fatalf("the route rules named: %x", ruleIds)
	}
	filing, err := world.filer.Expose(ctx, world.mcp(), &BridgeRouteRequest{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.40.0/24")}})
	if err != nil {
		t.Fatal(err)
	}
	if rule := world.ledger().Rule(filing.RuleId); rule == nil || len(rule.RouteRuleIds) != 1 || !bytes.Equal(rule.RouteRuleIds[0], holding.Bytes()) {
		t.Fatalf("the filed route's rules: %+v", rule)
	}
	// with no compiled policy and no document, the implicit policy's rules, which route no LAN prefix
	world.filer.args.AclLocal = nil
	if ruleIds := world.filer.routeRuleIds(view, route); len(ruleIds) != 0 {
		t.Errorf("the implicit policy named rules: %x", ruleIds)
	}
}
