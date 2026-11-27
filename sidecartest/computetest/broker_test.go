package computetest

// CTEST-M12-01's tests that hold on both legs: the broker's guard refusing an unadmitted sidecar before any handler,
// a design route no area built answering not_built behind the whole guard, the tokens its test sidecars mint, and the
// auth state's budgets. broker_testhooks_test.go plants handlers; broker_localstack_test.go runs on real stores.

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/computeservice"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A broker on T2 with network a holding member alice and her consented laptop, stopped at the test's end.
type testBrokerWorld struct {
	broker  *Broker
	network *BrokerNetwork
	aliceId sidecar.Id
	laptop  *BrokerSidecar
}

func newTestBrokerWorld(t *testing.T, args *BrokerArgs) *testBrokerWorld {
	t.Helper()
	broker, err := NewBroker(args)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broker.Stop)
	network, err := broker.AddNetwork("a", 0)
	if err != nil {
		t.Fatal(err)
	}
	aliceId, err := network.AddMember("alice", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	if err != nil {
		t.Fatal(err)
	}
	laptop, err := network.AddSidecar(&BrokerSidecarArgs{Label: "laptop", MemberId: aliceId, Consented: true})
	if err != nil {
		t.Fatal(err)
	}
	return &testBrokerWorld{broker: broker, network: network, aliceId: aliceId, laptop: laptop}
}

// Fails unless response answered status with code.
func requireBrokerRefusal(t *testing.T, label string, response *BrokerResponse, status int, code computeservice.ComputeRefusalCode) {
	t.Helper()
	refusal := response.Refusal()
	if response.Status != status || refusal == nil || refusal.Code != code {
		t.Fatalf("%s: answered %d %q, want %d %q", label, response.Status, response.Body, status, code)
	}
}

// The design routes a consented member device reaches the handler of with no body: a sidecar's, no admission, no
// approval and no Idempotency-Key, so on either leg nothing but the handler's own answer stands after the guard.
func testBrokerPlainRoutes(broker *Broker) []*computeservice.ComputeRoute {
	routes := []*computeservice.ComputeRoute{}
	for _, route := range broker.Engine().Routes() {
		if route.Auth == computeservice.ComputeRouteAuthSidecar && !route.Admission && route.Approval == 0 && !route.IdempotencyKey && !route.Hijacks {
			routes = append(routes, route)
		}
	}
	return routes
}

// A request path for a route's pattern, each path value an id.
func testBrokerPath(route *computeservice.ComputeRoute) string {
	path := route.Pattern
	for _, value := range []string{"{id}", "{vendor}", "{item}"} {
		path = strings.ReplaceAll(path, value, "00000000000000000000000000000001")
	}
	return path
}

// A sidecar the state does not hold, or no longer honors, is refused 403 scope at the guard's second step, whatever
// the route and before its handler; a token that does not authenticate is 401, and a network whose state is not loaded
// or a rev/ that cannot be read is 503, never an allow (D-CSRV-1, §14.2's Auth row).
func TestBrokerRefusesAnUnadmittedSidecar(t *testing.T) {
	world := newTestBrokerWorld(t, nil)
	ctx := context.Background()
	state := world.broker.AuthState()
	route := computeservice.ComputeRouteCatalog

	stranger, err := world.network.Unadmitted("stranger", world.aliceId)
	if err != nil {
		t.Fatal(err)
	}
	response, err := stranger.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "an unadmitted sidecar", response, http.StatusForbidden, computeservice.ComputeRefusalScope)

	// another network's sidecar presenting a token of network a
	other, err := world.broker.AddNetwork("b", 0)
	if err != nil {
		t.Fatal(err)
	}
	bobId, err := other.AddMember("bob", bridge.MemberRole_MEMBER_ROLE_OWNER)
	if err != nil {
		t.Fatal(err)
	}
	bobPhone, err := other.AddSidecar(&BrokerSidecarArgs{Label: "bob-phone", MemberId: bobId, Consented: true})
	if err != nil {
		t.Fatal(err)
	}
	crossed := *bobPhone
	crossed.NetworkId = world.network.NetworkId
	response, err = crossed.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "another network's sidecar", response, http.StatusForbidden, computeservice.ComputeRefusalScope)

	standings := []struct {
		label  string
		change func(admitted *FakeComputeSidecar)
	}{
		{label: "parked", change: func(admitted *FakeComputeSidecar) { admitted.Parked = true }},
		{label: "suspended", change: func(admitted *FakeComputeSidecar) { admitted.Suspended = true }},
		{label: "past its not_after", change: func(admitted *FakeComputeSidecar) { admitted.NotAfter = world.broker.Clock().Now() }},
	}
	for _, c := range standings {
		phone, err := world.network.AddSidecar(&BrokerSidecarArgs{Label: "phone " + c.label, MemberId: world.aliceId, Consented: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := state.Change(phone.SidecarId, c.change); err != nil {
			t.Fatal(err)
		}
		response, err := phone.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireBrokerRefusal(t, c.label, response, http.StatusForbidden, computeservice.ComputeRefusalScope)
	}

	// an untagged admission whose member is gone, and a removed one
	carolId, err := world.network.AddMember("carol", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	if err != nil {
		t.Fatal(err)
	}
	carolLaptop, err := world.network.AddSidecar(&BrokerSidecarArgs{Label: "carol-laptop", MemberId: carolId})
	if err != nil {
		t.Fatal(err)
	}
	state.RemoveMember(world.network.NetworkId, carolId)
	response, err = carolLaptop.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "a removed member's sidecar", response, http.StatusForbidden, computeservice.ComputeRefusalScope)
	removed, err := world.network.AddSidecar(&BrokerSidecarArgs{Label: "removed", MemberId: world.aliceId})
	if err != nil {
		t.Fatal(err)
	}
	state.Remove(removed.SidecarId)
	response, err = removed.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "a removed sidecar", response, http.StatusForbidden, computeservice.ComputeRefusalScope)

	// tokens that do not authenticate
	response, err = world.broker.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "no token", response, http.StatusUnauthorized, computeservice.ComputeRefusalUnauthenticated)
	response, err = world.broker.Do(ctx, http.MethodGet, "/v1/catalog", nil, map[string]string{"Authorization": "Bearer " + world.laptop.TokenFor("evs")})
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "another audience's token", response, http.StatusUnauthorized, computeservice.ComputeRefusalUnauthenticated)
	revoked, err := world.network.AddSidecar(&BrokerSidecarArgs{Label: "revoked", MemberId: world.aliceId})
	if err != nil {
		t.Fatal(err)
	}
	state.Revoke(revoked.SidecarId)
	response, err = revoked.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "a voided sidecar", response, http.StatusUnauthorized, computeservice.ComputeRefusalUnauthenticated)

	// a state that cannot answer is never an allow
	state.SetRevocationFault(errors.New("rev/ does not answer"))
	response, err = world.laptop.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "an unreadable rev/", response, http.StatusServiceUnavailable, computeservice.ComputeRefusalUnavailable)
	state.SetRevocationFault(nil)
	state.UnloadNetwork(world.network.NetworkId)
	response, err = world.laptop.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "an unloaded network", response, http.StatusServiceUnavailable, computeservice.ComputeRefusalUnavailable)

	// every refusal left its line, naming the route and code and nothing a caller sent
	scopeLines := 0
	for _, line := range world.broker.ServiceLog().Lines() {
		if line.Route != route {
			t.Errorf("a line for route %q", line.Route)
		}
		if line.Code == computeservice.ComputeRefusalScope {
			scopeLines += 1
		}
		if 0 < len(line.RowIds) {
			t.Errorf("a refusal named rows %v", line.RowIds)
		}
	}
	if scopeLines != 7 {
		t.Errorf("%d scope lines, want 7", scopeLines)
	}
}

// Every design route no linked area has built answers 503 not_built to a consented member device, after the whole
// guard, and is listed unbuilt; a route a group names answers 503 unavailable once that group is unlinked, before it
// could answer not_built, so the group's step runs first (§14.3, CSRV-M12-01's seam).
func TestBrokerAnswersNotBuiltForAnUnregisteredRoute(t *testing.T) {
	world := newTestBrokerWorld(t, nil)
	ctx := context.Background()
	unbuilt := world.broker.UnbuiltRoutes()
	answered := 0
	for _, route := range testBrokerPlainRoutes(world.broker) {
		if !slices.Contains(unbuilt, route.Name) {
			continue
		}
		answered += 1
		response, err := world.laptop.Do(ctx, route.Method, testBrokerPath(route), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireBrokerRefusal(t, route.Name, response, http.StatusServiceUnavailable, computeservice.ComputeRefusalNotBuilt)
	}
	for _, name := range unbuilt {
		if !slices.ContainsFunc(world.broker.Engine().Routes(), func(route *computeservice.ComputeRoute) bool { return route.Name == name }) {
			t.Errorf("%s is listed unbuilt and is no design route", name)
		}
	}
	t.Logf("%d plain routes answered not_built; %d design routes unbuilt in all", answered, len(unbuilt))

	// a group's route, unbuilt, refused at the group's step once the group is unlinked
	for _, route := range testBrokerPlainRoutes(world.broker) {
		if route.Group == "" || !slices.Contains(unbuilt, route.Name) {
			continue
		}
		world.broker.Unlink(route.Group)
		response, err := world.laptop.Do(ctx, route.Method, testBrokerPath(route), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireBrokerRefusal(t, route.Name+" unlinked", response, http.StatusServiceUnavailable, computeservice.ComputeRefusalUnavailable)
		world.broker.Link(route.Group)
		break
	}

	// a closed gate answers 503 with the gate's retry time, before the route
	world.broker.Gates().OpenService(sidecar.ServiceGateCompute)
	response, err := world.laptop.Do(ctx, http.MethodGet, "/v1/catalog", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	requireBrokerRefusal(t, "a closed gate", response, http.StatusServiceUnavailable, computeservice.ComputeRefusalUnavailable)
	if response.Header.Get("Retry-After") == "" {
		t.Error("a closed gate named no retry time")
	}
}

// A test sidecar's token authenticates for the compute audience as its sidecar, member and network, good for the
// settings' life on the broker's clock, and a token for another audience never does.
func TestBrokerTokensAreTheirSidecars(t *testing.T) {
	world := newTestBrokerWorld(t, nil)
	ctx := context.Background()
	principal, err := world.broker.Authenticator().Authenticate(ctx, computeservice.ComputeAudience, world.laptop.Token())
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Id(*principal.SidecarId) != world.laptop.SidecarId || sidecar.Id(*principal.MemberId) != world.aliceId || sidecar.Id(principal.NetworkId) != world.network.NetworkId || sidecar.Id(principal.ClientId) != world.laptop.ClientId {
		t.Fatalf("the token names %+v", principal)
	}
	if got := principal.ExpiresAt.Sub(principal.IssuedAt); got != DefaultBrokerSettings().TokenLife {
		t.Errorf("a token lives %s", got)
	}
	if _, err := world.broker.Authenticator().Authenticate(ctx, computeservice.ComputeAudience, world.laptop.TokenFor("evs")); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("another audience's token: %v", err)
	}
	expiring := world.laptop.Token()
	world.broker.FakeClock().Advance(DefaultBrokerSettings().TokenLife)
	if _, err := world.broker.Authenticator().Authenticate(ctx, computeservice.ComputeAudience, expiring); !errors.Is(err, sidecar.ErrAuthenticationRefused) {
		t.Errorf("a token past its life: %v", err)
	}
	if world.broker.Tier() != BrokerTierT2 {
		t.Errorf("a broker on fakes runs at %s", world.broker.Tier())
	}
	// the broker's own Env grants no database: a table answers not granted on T2
	if _, err := world.broker.Op(ctx, world.network.NetworkId, sidecar.NewId()); err == nil {
		t.Error("an operation row read on T2")
	}
}

// The budget lines an operation's subjects count to: §16.5's defaults by agent and device, then the policy's lines
// for the operation's sidecar, agent, member or network, and none of another subject's (§16.4, §16.5).
func TestFakeComputeAuthStateBudgetLines(t *testing.T) {
	world := newTestBrokerWorld(t, nil)
	state := world.broker.AuthState()
	agentId := sidecar.NewId()
	strangerId := sidecar.NewId()
	state.SetBudgetLines(world.network.NetworkId, []*model.ComputeBudgetLine{
		{SubjectId: world.aliceId, Budget: "member", Period: model.ComputeBudgetPeriodMonth, CapNanoUsd: 100 * 1_000_000_000},
		{SubjectId: strangerId, Budget: "member", Period: model.ComputeBudgetPeriodDay, CapNanoUsd: 1_000_000_000},
	})
	memberId := world.aliceId
	lines, err := state.BudgetLines(context.Background(), &controller.ComputeBudgetSubjects{
		NetworkId: world.network.NetworkId,
		Kind:      model.ComputeChargeKindInference,
		SidecarId: world.laptop.SidecarId,
		AgentId:   &agentId,
		MemberId:  &memberId,
	})
	if err != nil {
		t.Fatal(err)
	}
	ledger := model.DefaultComputeLedgerSettings()
	want := []*model.ComputeBudgetLine{
		{SubjectId: agentId, Budget: model.ComputeBudgetAgent, Period: model.ComputeBudgetPeriodDay, CapNanoUsd: ledger.DefaultAgentDayNanoUsd},
		{SubjectId: agentId, Budget: model.ComputeBudgetAgent, Period: model.ComputeBudgetPeriodMonth, CapNanoUsd: ledger.DefaultAgentMonthNanoUsd},
		{SubjectId: world.laptop.SidecarId, Budget: model.ComputeBudgetCeiling, Period: model.ComputeBudgetPeriodDay, CapNanoUsd: ledger.DefaultDeviceCeilingDayNanoUsd},
		{SubjectId: world.aliceId, Budget: "member", Period: model.ComputeBudgetPeriodMonth, CapNanoUsd: 100 * 1_000_000_000},
	}
	if len(lines) != len(want) {
		t.Fatalf("lines %v", lines)
	}
	for i := range want {
		if *lines[i] != *want[i] {
			t.Errorf("line %d is %+v, want %+v", i, lines[i], want[i])
		}
	}
	if _, err := state.BudgetLines(context.Background(), &controller.ComputeBudgetSubjects{NetworkId: sidecar.NewId(), SidecarId: world.laptop.SidecarId}); !errors.Is(err, ErrFakeComputeAuthUnknown) {
		t.Errorf("a network the state does not hold: %v", err)
	}
	// the compute block's view reads §16.5's defaults until a block narrows it, and nothing before the network loads
	view, err := state.ComputePolicy(world.network.NetworkId)
	if err != nil || view.Block() != nil {
		t.Fatalf("the view %v, %v", view, err)
	}
	state.UnloadNetwork(world.network.NetworkId)
	if _, err := state.ComputePolicy(world.network.NetworkId); !errors.Is(err, sidecar.ErrComputePolicyUnread) {
		t.Errorf("an unloaded network's policy: %v", err)
	}
}
