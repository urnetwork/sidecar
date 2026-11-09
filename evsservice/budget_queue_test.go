package evsservice

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A waiter of networkId for price priced bytes, all immediate.
func testP1Waiter(networkId connect.Id, price int64, weight int64, at time.Time) *writeBudgetP1Waiter {
	return &writeBudgetP1Waiter{
		networkId:   networkId,
		cost:        sidecar.WriteCost{ImmediateByteCount: price},
		weight:      weight,
		enqueueTime: at,
		decided:     make(chan struct{}),
	}
}

// Serves the queue's next waiter, as dispatch does.
func serveNext(queue *writeBudgetP1Queue) *writeBudgetP1Waiter {
	waiter := queue.nextWithLock()
	if waiter != nil {
		waiter.state = writeBudgetAdmitted
		queue.removeWithLock(waiter)
	}
	return waiter
}

// WFQ as a property: over any stretch where every network has work waiting, each is served priced
// bytes in proportion to its weight, whatever the sizes and arrival order, to within one waiter each.
func TestWriteBudgetFairQueueServesNetworksByWeight(t *testing.T) {
	start := governorTestStart()
	for seed := range uint64(20) {
		random := rand.New(rand.NewPCG(seed, seed+1))
		queue := newWriteBudgetP1Queue()
		networkIds := []connect.Id{connect.NewId(), connect.NewId(), connect.NewId()}
		weights := []int64{1, 4, 16}
		for i := range 3000 {
			network := random.IntN(3)
			price := 50 + random.Int64N(100)
			queue.enqueueWithLock(testP1Waiter(networkIds[network], price, weights[network], start.Add(time.Duration(i)*time.Millisecond)))
		}
		served := map[connect.Id]int64{}
		var servedSum int64
		// a stretch short enough that no network runs dry
		for servedSum < 20000 {
			waiter := serveNext(queue)
			served[waiter.networkId] += waiter.cost.ByteCount()
			servedSum += waiter.cost.ByteCount()
		}
		var weightSum int64
		for _, weight := range weights {
			weightSum += weight
		}
		for i, networkId := range networkIds {
			want := float64(servedSum) * float64(weights[i]) / float64(weightSum)
			if got := float64(served[networkId]); got < want-300 || want+300 < got {
				t.Errorf("seed %d: weight %d served %.0f of %d, want %.0f", seed, weights[i], got, servedSum, want)
			}
		}
	}
}

// A network's waiters are served in the order they came, and an idle network starts at the queue's
// virtual time, with no credit for having waited for nothing.
func TestWriteBudgetFairQueueKeepsANetworksOrder(t *testing.T) {
	start := governorTestStart()
	queue := newWriteBudgetP1Queue()
	busy := connect.NewId()
	waiters := []*writeBudgetP1Waiter{}
	for i := range 5 {
		waiter := testP1Waiter(busy, 100, 1, start.Add(time.Duration(i)*time.Millisecond))
		waiters = append(waiters, waiter)
		queue.enqueueWithLock(waiter)
	}
	for i := range 3 {
		if waiter := serveNext(queue); waiter != waiters[i] {
			t.Fatalf("served out of order at %d", i)
		}
	}
	// an idle network queues now at the queue's virtual time, with no credit for having waited for
	// nothing, so it interleaves with the busy network's rest, an equal tag going to the earlier arrival
	idle := connect.NewId()
	queue.enqueueWithLock(testP1Waiter(idle, 100, 1, start.Add(time.Second)))
	queue.enqueueWithLock(testP1Waiter(idle, 100, 1, start.Add(time.Second)))
	order := []connect.Id{}
	for waiter := serveNext(queue); waiter != nil; waiter = serveNext(queue) {
		order = append(order, waiter.networkId)
	}
	want := []connect.Id{busy, idle, busy, idle}
	for i := range want {
		if order[i] != want[i] {
			t.Errorf("served %v, want %v", order, want)
			break
		}
	}
}

// The heaviest is the most queued priced bytes per weight, and a network alone has none heavier than
// itself to make room for.
func TestWriteBudgetHeaviestNetworkIsByQueuedBytesPerWeight(t *testing.T) {
	start := governorTestStart()
	queue := newWriteBudgetP1Queue()
	team := connect.NewId()
	community := connect.NewId()
	for range 16 {
		queue.enqueueWithLock(testP1Waiter(team, 100, 16, start))
	}
	if _, ok := queue.heaviestNetworkWithLock(); ok {
		t.Error("a network alone was the heaviest")
	}
	queue.enqueueWithLock(testP1Waiter(community, 200, 1, start))
	// the team's 1,600 over 16 is 100, community's 200 over 1 is 200
	if heaviest, ok := queue.heaviestNetworkWithLock(); !ok || heaviest != community {
		t.Errorf("heaviest %v", heaviest)
	}
	if queue.queuedByteCount != 1800 {
		t.Errorf("queued %d", queue.queuedByteCount)
	}
}

// Weights come from Quota.Limits's store_weight, refreshed off the hot path: unread or stale reads
// Community's 1, and an absent key never reads as no weight.
func TestWriteBudgetWeightsComeFromQuotaAndGoStale(t *testing.T) {
	settings := governorTestSettings()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	quota := sidecartest.NewFakeQuota(clock, sidecartest.NewFaultQueue(), nil)
	team := connect.NewId()
	absent := connect.NewId()
	quota.SetLimits(team, &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{"store_weight": 16}})
	quota.SetLimits(absent, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{}})
	weights := newWriteBudgetWeights(settings, quota)
	if weight := weights.weight(team, clock.Now()); weight != 1 {
		t.Errorf("unread: %d", weight)
	}
	weights.weight(absent, clock.Now())
	weights.refresh(t.Context(), clock)
	if weight := weights.weight(team, clock.Now()); weight != 16 {
		t.Errorf("read: %d", weight)
	}
	if weight := weights.weight(absent, clock.Now()); weight != 1 {
		t.Errorf("absent key: %d", weight)
	}
	clock.Advance(settings.WeightMaxAge + time.Millisecond)
	if weight := weights.weight(team, clock.Now()); weight != 1 {
		t.Errorf("stale: %d", weight)
	}
	// a network unused past the active window is forgotten at the next refresh
	clock.Advance(settings.WeightActiveWindow + time.Millisecond)
	weights.refresh(t.Context(), clock)
	if _, ok := weights.networkIdWeights[team]; ok {
		t.Error("an idle network kept its weight")
	}
}
