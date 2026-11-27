//go:build sidecar_localstack && sidecar_testhooks

package computetest

// CTEST-M12-01 on the local test stack (sidecartest/localstack, local/stack.sh): the same broker on the stack's Redis
// Cluster, its admissions writing the abuse hold's projection there, and the ledger's projection scripts, which have no
// FakeRedis twins, taking a hold and settling it through the broker's Env, read back through Projection. Each run
// draws its networks from a seed of its own, so tracks running side by side touch no key of another's, and deletes
// what it wrote. Each fails, rather than skips, when the stack is down.

import (
	"context"
	"net/http"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/computeservice"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest/localstack"
)

// A broker on the stack's Redis Cluster, main and {cmpa}'s alike, with a network and a consented member device.
func newTestBrokerOnTheStack(t *testing.T, handlers map[string]computeservice.ComputeHandler) (*testBrokerWorld, sidecar.Redis) {
	t.Helper()
	redis, err := localstack.NewRedis(t.Context(), nil)
	if err != nil {
		t.Fatalf("the local stack's Redis Cluster: %v", err)
	}
	t.Cleanup(redis.Close)
	broker, err := NewBroker(&BrokerArgs{
		Seed:            "localstack " + t.Name() + " " + sidecar.NewId().String(),
		Redis:           redis,
		AdmissionsRedis: redis,
		Handlers:        handlers,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(broker.Stop)
	network, err := broker.AddNetwork("a", 0)
	if err != nil {
		t.Fatal(err)
	}
	aliceId, err := network.AddMember("alice", bridge.MemberRole_MEMBER_ROLE_OWNER)
	if err != nil {
		t.Fatal(err)
	}
	laptop, err := network.AddSidecar(&BrokerSidecarArgs{Label: "laptop", MemberId: aliceId, Consented: true})
	if err != nil {
		t.Fatal(err)
	}
	return &testBrokerWorld{broker: broker, network: network, aliceId: aliceId, laptop: laptop}, redis
}

// The broker serves an admission route on the stack's Redis: its abuse hold check reads the projection there, misses,
// reads the row's stand-in and projects it, so the key is on the stack after the call, and the planted handler runs.
func TestBrokerRunsOnTheLocalStack(t *testing.T) {
	handler := &testBrokerHandler{rowId: sidecar.NewId()}
	world, redis := newTestBrokerOnTheStack(t, map[string]computeservice.ComputeHandler{computeservice.ComputeRouteInfer: handler.serve})
	ctx := context.Background()
	key := model.ComputeAbuseHoldRedisKey(world.network.NetworkId)
	t.Cleanup(func() { redis.Delete(context.Background(), []string{key}) })
	if world.broker.Tier() != BrokerTierT3 {
		t.Fatalf("a broker on the stack runs at %s", world.broker.Tier())
	}
	response, err := world.laptop.Do(ctx, http.MethodPost, "/v1/infer", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != http.StatusOK || len(handler.served()) != 1 {
		t.Fatalf("answered %d %q", response.Status, response.Body)
	}
	state, err := model.ComputeAbuseHoldProjected(ctx, redis, world.network.NetworkId)
	if err != nil || state == nil || state.Held() {
		t.Fatalf("the stack holds %+v, %v", state, err)
	}
	// a second call reads the projection, not the row
	if _, err := world.laptop.Do(ctx, http.MethodPost, "/v1/infer", nil, nil); err != nil {
		t.Fatal(err)
	}
	if world.broker.AbuseHolds().ReadCount() != 1 {
		t.Errorf("%d rows read", world.broker.AbuseHolds().ReadCount())
	}
}

// The ledger's Redis half on the stack through the broker's Env (§9.7): a rebuilt projection, a TEE call's hold taken
// on the budget lines the state resolves, confirmed and settled once, each step read back through Projection; a
// settlement repeated changes nothing. The operation's row is PostgreSQL's, which no sidecar test reaches, so it is
// server's T3 (server/computet3) that holds the row's half.
func TestBrokerHoldsAndSettlesThroughTheLedgerOnTheLocalStack(t *testing.T) {
	world, redis := newTestBrokerOnTheStack(t, nil)
	ctx := context.Background()
	env := world.broker.Env()
	settings := model.DefaultComputeLedgerSettings()
	networkId := world.network.NetworkId
	const usd = int64(1_000_000_000)
	agentId := sidecar.NewId()
	memberId := world.aliceId
	subjects := &controller.ComputeBudgetSubjects{
		NetworkId: networkId,
		Kind:      model.ComputeChargeKindInference,
		SidecarId: world.laptop.SidecarId,
		AgentId:   &agentId,
		MemberId:  &memberId,
	}
	subjectIds := []sidecar.Id{networkId, world.laptop.SidecarId, agentId, memberId}
	t.Cleanup(func() {
		keys := []string{model.ComputeProjectionKey(networkId), model.ComputeProjectionKey(networkId) + ":u"}
		for _, subjectId := range subjectIds {
			keys = append(keys, model.ComputeBudgetKey(networkId, subjectId))
		}
		for _, key := range keys {
			redis.Delete(context.Background(), []string{key})
		}
	})

	if err := model.ComputeProjectionRebuild(env, ctx, settings, &model.ComputeProjectionSnapshot{
		NetworkId: networkId,
		Account:   &model.ComputeProjectionAccount{Version: 1, SettledNanoUsd: 10 * usd, State: model.ComputeAccountStateActive},
	}); err != nil {
		t.Fatal(err)
	}
	lines, err := world.broker.AuthState().BudgetLines(ctx, subjects)
	if err != nil {
		t.Fatal(err)
	}
	opKey := sidecar.NewId()
	hold, err := model.ComputeProjectionHold(env, ctx, settings, &model.ComputeHoldRequest{
		NetworkId:      networkId,
		OpKey:          opKey,
		Kind:           model.ComputeChargeKindInference,
		Path:           model.ComputeHoldPathTee,
		HoldNanoUsd:    2 * usd,
		ReserveNanoUsd: 2 * usd,
		Lines:          lines,
	})
	if err != nil || hold.Outcome != model.ComputeHoldTaken {
		t.Fatalf("the hold: %+v, %v", hold, err)
	}
	projection, err := world.broker.Projection(ctx, networkId)
	if err != nil {
		t.Fatal(err)
	}
	if !projection.Present || projection.HoldsNanoUsd != 2*usd || projection.AvailableNanoUsd() != 8*usd {
		t.Fatalf("held: %+v", projection)
	}
	outcome, err := model.ComputeProjectionConfirm(env, ctx, settings, networkId, opKey, subjectIds)
	if err != nil || outcome != model.ComputeScriptConfirmed {
		t.Fatalf("the confirm: %s, %v", outcome, err)
	}
	settle := &model.ComputeSettleRequest{
		NetworkId:      networkId,
		OpKey:          opKey,
		Kind:           model.ComputeChargeKindInference,
		Path:           model.ComputeHoldPathTee,
		AmountNanoUsd:  3 * usd / 4,
		ReserveNanoUsd: 2 * usd,
		StartTime:      hold.Time,
		Lines:          lines,
		SubjectIds:     subjectIds,
	}
	for range 2 {
		outcome, err = model.ComputeProjectionSettle(env, ctx, settings, settle)
		if err != nil || outcome != model.ComputeScriptSettled {
			t.Fatalf("the settlement: %s, %v", outcome, err)
		}
		projection, err = world.broker.Projection(ctx, networkId)
		if err != nil {
			t.Fatal(err)
		}
		if projection.HoldsNanoUsd != 0 || projection.UnsettledNanoUsd != 3*usd/4 || projection.AvailableNanoUsd() != 10*usd-3*usd/4 {
			t.Fatalf("settled: %+v", projection)
		}
	}
}
