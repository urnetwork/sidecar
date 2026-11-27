//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension && !windows

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// DESIGN-COMPUTE §8.6's grants (GW-M12-02): made at most at the agent's default, a raise above it filed as kind 21 and
// standing only once approved, revoked with their tokens at once, kept across a restart, bounded, and holding the port
// while any stands.

// One network as the gateway reads it, over an enrolled in-memory instance: its runs, its grant store, and its agents'
// ids by label.
type testGatewayNetwork struct {
	instance *SidecarInstance
	runs     *RunStore
	grants   *GatewayGrantStore

	stateLock     sync.Mutex
	labelAgentIds map[string]Id
}

// See GatewayNetwork.
func (self *testGatewayNetwork) Runs() (*RunStore, error) {
	return self.runs, nil
}

// See GatewayNetwork.
func (self *testGatewayNetwork) GatewayGrants() (*GatewayGrantStore, error) {
	return self.grants, nil
}

// See GatewayNetwork: an id drawn at a label's first ask and kept.
func (self *testGatewayNetwork) ResolveAgentId(label string) (Id, error) {
	if err := DefaultSidecarAgentLabelSettings().Check(label); err != nil {
		return Id{}, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	agentId, ok := self.labelAgentIds[label]
	if !ok {
		agentId = NewId()
		self.labelAgentIds[label] = agentId
	}
	return agentId, nil
}

// A store over the same files, with nothing in memory: what a restarted daemon reads.
func (self *testGatewayNetwork) reopen(settings *GatewaySettings, clock Clock) *GatewayGrantStore {
	return NewGatewayGrantStore(&GatewayGrantStoreArgs{
		Store: func() (SidecarStore, error) {
			return self.instance.Store(&testNetworkId).Directory(gatewayGrantDirectoryName, gatewayGrantClass)
		},
		Settings: settings,
		Clock:    clock,
	})
}

// An enrolled, unlocked instance holding testNetworkId, and the network over it.
func newTestGatewayNetwork(t *testing.T, settings *GatewaySettings, clock Clock) *testGatewayNetwork {
	t.Helper()
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, testNetworkId)
	runs, err := NewRunStore(instance.Store(&testNetworkId), defaultSidecarMcpSettings(), clock)
	if err != nil {
		t.Fatal(err)
	}
	network := &testGatewayNetwork{instance: instance, runs: runs, labelAgentIds: map[string]Id{}}
	network.grants = network.reopen(settings, clock)
	return network
}

// The daemon's hosted networks as a test gives them: a network argument names one by id, and none names the only one.
type testGatewayHosts struct {
	networks []GatewayHostedNetwork
}

// See GatewayHosts.
func (self *testGatewayHosts) GatewayNetworks() []GatewayHostedNetwork {
	return self.networks
}

// See GatewayHosts.
func (self *testGatewayHosts) ResolveNetwork(hello *DaemonHello, network string) (Id, error) {
	if network == "" && len(self.networks) == 1 {
		return self.networks[0].NetworkId, nil
	}
	for _, hosted := range self.networks {
		if hosted.NetworkId.String() == network {
			return hosted.NetworkId, nil
		}
	}
	return Id{}, fmt.Errorf("no network %q", network)
}

// A raiser that answers what a test sets, recording what it was asked.
type testGatewayRaiser struct {
	stateLock sync.Mutex
	asked     []*ComputeBudgetRaiseArgs
	answer    func(args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error)
}

func (self *testGatewayRaiser) raise(ctx context.Context, network GatewayNetwork, args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error) {
	self.stateLock.Lock()
	copied := *args
	self.asked = append(self.asked, &copied)
	answer := self.answer
	self.stateLock.Unlock()
	return answer(args)
}

// A gateway over one test network, its state under a temporary directory, with the defaults $5 a day and $50 a month
// per agent where defaults is set.
type testGatewayWorld struct {
	t         *testing.T
	clock     *recordTestClock
	settings  *GatewaySettings
	network   *testGatewayNetwork
	hosts     *testGatewayHosts
	raiser    *testGatewayRaiser
	server    *GatewayServer
	directory string
}

func newTestGatewayWorld(t *testing.T, defaults bool) *testGatewayWorld {
	t.Helper()
	clock := newRecordTestClock()
	settings := DefaultGatewaySettings()
	settings.PortFirst, settings.PortLast = 30000, 31999
	network := newTestGatewayNetwork(t, settings, clock)
	world := &testGatewayWorld{
		t:        t,
		clock:    clock,
		settings: settings,
		network:  network,
		hosts:    &testGatewayHosts{networks: []GatewayHostedNetwork{{NetworkId: testNetworkId, Network: network}}},
		raiser: &testGatewayRaiser{answer: func(args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error) {
			return nil, ErrComputeBudgetRaiseUnavailable
		}},
		directory: t.TempDir(),
	}
	args := &GatewayServerArgs{
		StateDirectory: world.directory,
		Settings:       settings,
		Clock:          clock,
		RaiseBudget:    world.raiser.raise,
	}
	if defaults {
		args.BudgetDefaults = func(ctx context.Context, network GatewayNetwork, agentId Id) (*GatewayBudgetCaps, error) {
			return &GatewayBudgetCaps{DayNanoUsd: 5 * testGatewayUsd, MonthNanoUsd: 50 * testGatewayUsd}, nil
		}
	}
	world.server = NewGatewayServer(args)
	t.Cleanup(world.server.Close)
	world.server.SetHosts(world.hosts)
	world.server.Start()
	return world
}

// One US dollar in nano-USD.
const testGatewayUsd int64 = 1_000_000_000

// Makes a grant of harness through the server, as gateway.grants' make does, failing the test on an error.
func (self *testGatewayWorld) make(params *GatewayGrantsParams) *GatewayGrantsReply {
	self.t.Helper()
	params.Action = GatewayGrantsActionMake
	reply, err := self.server.MakeGrant(context.Background(), &DaemonHello{Mode: DaemonModeControl}, params)
	if err != nil {
		self.t.Fatal(err)
	}
	return reply
}

// A pointer to amount dollars in nano-USD.
func testGatewayAmount(dollars int64) *int64 {
	amount := dollars * testGatewayUsd
	return &amount
}

// A grant's budget at or under the agent's default stands as asked; one above it stands at the default, its raise filed
// as kind 21 naming the grant, until the approved raise comes back; with no defaults readable a grant names no budget of
// its own; and a raise that cannot be filed leaves the grant at the default, saying why.
func TestGrantAboveDefaultFilesKind21(t *testing.T) {
	world := newTestGatewayWorld(t, true)
	under := world.make(&GatewayGrantsParams{Harness: "codex", DayNanoUsd: testGatewayAmount(3)})
	if grant := under.Grants[0].Grant; grant.DayNanoUsd == nil || *grant.DayNanoUsd != 3*testGatewayUsd || len(under.Raises) != 0 {
		t.Fatalf("a budget under the default: %+v, raises %+v", grant, under.Raises)
	}

	approvalId := NewId()
	world.raiser.answer = func(args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error) {
		return &ComputeBudgetRaiseResult{Outcome: ComputeBudgetRaisePending, ApprovalId: &approvalId}, nil
	}
	above := world.make(&GatewayGrantsParams{Harness: "claude-code", DayNanoUsd: testGatewayAmount(20), MonthNanoUsd: testGatewayAmount(40)})
	grant := above.Grants[0].Grant
	if grant.DayNanoUsd != nil || grant.MonthNanoUsd == nil || *grant.MonthNanoUsd != 40*testGatewayUsd {
		t.Fatalf("a day above the default stands at it, a month under it as asked: %+v", grant)
	}
	if len(above.Raises) != 1 || above.Raises[0].Outcome != GatewayRaisePending || *above.Raises[0].ApprovalId != approvalId {
		t.Fatalf("the raise: %+v", above.Raises)
	}
	if len(grant.PendingRaises) != 1 || grant.PendingRaises[0].ApprovalId != approvalId || grant.PendingRaises[0].AmountNanoUsd != 20*testGatewayUsd {
		t.Fatalf("the pending raise: %+v", grant.PendingRaises)
	}
	asked := world.raiser.asked[len(world.raiser.asked)-1]
	if asked.GrantId == nil || *asked.GrantId != grant.GrantId || asked.AgentId != nil || asked.Period != "day" ||
		asked.AmountNanoUsd != 20*testGatewayUsd || asked.CurrentNanoUsd != 5*testGatewayUsd {
		t.Fatalf("kind 21 filed as %+v", asked)
	}

	world.raiser.answer = func(args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error) {
		return &ComputeBudgetRaiseResult{Outcome: ComputeBudgetRaiseDone}, nil
	}
	approved := world.make(&GatewayGrantsParams{Harness: "claude-code", DayNanoUsd: testGatewayAmount(20), MonthNanoUsd: testGatewayAmount(40)})
	grant = approved.Grants[0].Grant
	if grant.DayNanoUsd == nil || *grant.DayNanoUsd != 20*testGatewayUsd || len(grant.PendingRaises) != 0 {
		t.Fatalf("the approved raise: %+v", grant)
	}

	world.raiser.answer = func(args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error) {
		return nil, ErrComputeBudgetRaiseUnavailable
	}
	unfiled := world.make(&GatewayGrantsParams{Harness: "codex", Agent: "second", MonthNanoUsd: testGatewayAmount(80)})
	if unfiled.Grants[0].Grant.MonthNanoUsd != nil || unfiled.Raises[0].Outcome != GatewayRaiseNotFiled || unfiled.Raises[0].Reason == "" {
		t.Fatalf("a raise not filed: %+v %+v", unfiled.Grants[0].Grant, unfiled.Raises)
	}

	closed := newTestGatewayWorld(t, false)
	_, err := closed.server.MakeGrant(context.Background(), &DaemonHello{}, &GatewayGrantsParams{Action: GatewayGrantsActionMake, Harness: "codex", DayNanoUsd: testGatewayAmount(1)})
	if !errors.Is(err, ErrGatewayGrantInvalid) {
		t.Fatalf("a budget with no defaults readable: %v", err)
	}
	if views, _ := closed.network.grants.Views(testNetworkId); len(views) != 0 {
		t.Fatalf("a refused grant was made: %+v", views)
	}
	if made := closed.make(&GatewayGrantsParams{Harness: "codex"}); made.Grants[0].Grant.DayNanoUsd != nil {
		t.Fatalf("a grant at the default: %+v", made.Grants[0].Grant)
	}
}

// A revoked grant's tokens are refused at once, and its port is let go once no grant stands.
func TestRevokedGrantRefusesItsTokens(t *testing.T) {
	world := newTestGatewayWorld(t, false)
	grant := world.make(&GatewayGrantsParams{Harness: "codex"}).Grants[0].Grant
	if status := world.server.Status(); !status.Hold || status.Port == 0 {
		t.Fatalf("a made grant holds no port: %+v", status)
	}
	tokens := []string{}
	for i := 0; i < 2; i += 1 {
		token, _, err := world.network.grants.Mint(context.Background(), grant.GrantId, nil)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, token)
	}
	reply, err := world.server.RevokeGrant(context.Background(), grant.GrantId)
	if err != nil || !reply.Revoked {
		t.Fatalf("revoke: %+v %v", reply, err)
	}
	for _, token := range tokens {
		if _, _, err := world.network.grants.Authenticate(GatewayTokenSha256(token)); !errors.Is(err, ErrGatewayTokenUnknown) {
			t.Errorf("a revoked grant's token: %v", err)
		}
	}
	if _, _, err := world.network.grants.Mint(context.Background(), grant.GrantId, nil); !errors.Is(err, ErrGatewayGrantUnknown) {
		t.Errorf("a revoked grant minted: %v", err)
	}
	if status := world.server.Status(); status.Hold || status.Serving {
		t.Errorf("no grant stands, the port is still held: %+v", status)
	}
	if again, err := world.server.RevokeGrant(context.Background(), grant.GrantId); err == nil && again.Revoked {
		t.Error("a revoked grant revoked again")
	}
}

// Grants and token hashes are kept across a restart, an expired grant mints nothing, one harness and agent hold one
// grant, and a grant past GrantTokenCount drops its oldest token.
func TestGrantStoreKeepsAndBounds(t *testing.T) {
	clock := newRecordTestClock()
	settings := DefaultGatewaySettings()
	settings.GrantTokenCount = 2
	settings.GrantCount = 2
	network := newTestGatewayNetwork(t, settings, clock)
	agentId := NewId()
	grant, isNew, err := network.grants.Make(context.Background(), &GatewayGrantArgs{Harness: "codex", AgentLabel: "codex", AgentId: agentId,
		Models: []string{"chutes-*"}})
	if err != nil || !isNew {
		t.Fatalf("make: %v %v", isNew, err)
	}
	again, isNew, err := network.grants.Make(context.Background(), &GatewayGrantArgs{Harness: "codex", AgentLabel: "codex", AgentId: agentId})
	if err != nil || isNew || again.GrantId != grant.GrantId || len(again.Models) != 0 {
		t.Fatalf("the same harness and agent again: %+v %v %v", again, isNew, err)
	}
	tokens := []string{}
	for i := 0; i < 3; i += 1 {
		token, _, err := network.grants.Mint(context.Background(), grant.GrantId, nil)
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, token)
		clock.advance(time.Second)
	}
	reopened := network.reopen(settings, clock)
	if _, _, err := reopened.Authenticate(GatewayTokenSha256(tokens[0])); !errors.Is(err, ErrGatewayTokenUnknown) {
		t.Errorf("the oldest token past the bound: %v", err)
	}
	for _, token := range tokens[1:] {
		if got, _, err := reopened.Authenticate(GatewayTokenSha256(token)); err != nil || got.GrantId != grant.GrantId {
			t.Errorf("a token after a restart: %v", err)
		}
	}
	if _, _, err := network.grants.Make(context.Background(), &GatewayGrantArgs{Harness: "claude-code", AgentLabel: "claude-code", AgentId: NewId()}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := network.grants.Make(context.Background(), &GatewayGrantArgs{Harness: "opencode", AgentLabel: "opencode", AgentId: NewId()}); !errors.Is(err, ErrGatewayGrantInvalid) {
		t.Errorf("a grant past GrantCount: %v", err)
	}
	expiring, _, err := network.grants.Make(context.Background(), &GatewayGrantArgs{Harness: "codex", AgentLabel: "codex", AgentId: agentId,
		ExpiresMillis: clock.Now().Add(time.Minute).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Minute)
	if _, _, err := network.grants.Mint(context.Background(), expiring.GrantId, nil); !errors.Is(err, ErrGatewayGrantUnknown) {
		t.Errorf("an expired grant minted: %v", err)
	}
	if _, _, err := network.grants.Authenticate(GatewayTokenSha256(tokens[2])); !errors.Is(err, ErrGatewayGrantUnknown) {
		t.Errorf("an expired grant's token: %v", err)
	}
	for _, bad := range []*GatewayGrantArgs{
		{Harness: "", AgentLabel: "codex", AgentId: agentId},
		{Harness: "Codex", AgentLabel: "codex", AgentId: agentId},
		{Harness: strings.Repeat("a", 65), AgentLabel: "codex", AgentId: agentId},
		{Harness: "codex", AgentLabel: "", AgentId: agentId},
		{Harness: "codex", AgentLabel: "codex", AgentId: agentId, DayNanoUsd: testGatewayAmount(-1)},
		{Harness: "codex", AgentLabel: "codex", AgentId: agentId, ExpiresMillis: clock.Now().UnixMilli()},
	} {
		if _, _, err := network.grants.Make(context.Background(), bad); !errors.Is(err, ErrGatewayGrantInvalid) {
			t.Errorf("%+v made: %v", bad, err)
		}
	}
}

// A make refuses a model glob that is no glob within a canonical name, and lists only what stands.
func TestGrantModelGlobsChecked(t *testing.T) {
	world := newTestGatewayWorld(t, false)
	for _, models := range [][]string{{"Chutes-*"}, {"chutes/*"}, {""}} {
		_, err := world.server.MakeGrant(context.Background(), &DaemonHello{}, &GatewayGrantsParams{Action: GatewayGrantsActionMake, Harness: "codex", Models: models})
		if !errors.Is(err, ErrGatewayGrantInvalid) {
			t.Errorf("%q: %v", models, err)
		}
	}
	grant := world.make(&GatewayGrantsParams{Harness: "codex", Models: []string{"chutes-*-tee-*", "local-*"}}).Grants[0].Grant
	if !grant.AllowsModel("chutes-qwen3.8-27b-tee-high") || !grant.AllowsModel("local-gemma-4-e4b-off") || grant.AllowsModel("engy-glm-5.2-off") {
		t.Errorf("the grant's list: %+v", grant.Models)
	}
	listed, err := world.server.ListGrants("", &DaemonHello{})
	if err != nil || len(listed.Grants) != 1 || listed.Grants[0].BindCommand != "ur gateway token --harness codex" {
		t.Fatalf("list: %+v %v", listed, err)
	}
}
