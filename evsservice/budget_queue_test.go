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

// A queue with a share no test's admissions reach, so every network stays below its weighted share.
func newTestP1Queue() *writeBudgetP1Queue {
	queue := newWriteBudgetP1Queue(2)
	queue.startIntervalWithLock(1000 * 1000 * 1000 * 1000)
	return queue
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
		queue := newTestP1Queue()
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
	queue := newTestP1Queue()
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

// Offers waiter as the account does: queued, then served at once while it is the next the queue serves and left
// covers it. Returns whether it was.
func offerNow(queue *writeBudgetP1Queue, left *int64, waiter *writeBudgetP1Waiter) bool {
	queue.enqueueWithLock(waiter)
	for {
		next := queue.nextWithLock()
		if next == nil || *left < next.cost.ByteCount() {
			return waiter.state == writeBudgetAdmitted
		}
		*left -= next.cost.ByteCount()
		next.state = writeBudgetAdmitted
		queue.removeWithLock(next)
	}
}

// Runs the shed rule to its end on the queue as it stands, refusing as the account does, and returns the networks it
// refused in order.
func shedAll(queue *writeBudgetP1Queue) []connect.Id {
	refused := []connect.Id{}
	for {
		networkId, ok := queue.shedNetworkWithLock()
		if !ok {
			return refused
		}
		for _, waiter := range queue.networkWaitersWithLock(networkId) {
			waiter.state = writeBudgetRefused
			queue.removeWithLock(waiter)
		}
		refused = append(refused, networkId)
	}
}

// With no share every network is past it, and the heaviest by queued priced bytes per weight is refused first; a
// network alone has none lighter to make room for, and the last network waiting is kept.
func TestWriteBudgetShedRefusesTheHeaviestByQueuedBytesPerWeight(t *testing.T) {
	start := governorTestStart()
	queue := newWriteBudgetP1Queue(2)
	queue.startIntervalWithLock(0)
	team := connect.NewId()
	community := connect.NewId()
	for range 16 {
		queue.enqueueWithLock(testP1Waiter(team, 100, 16, start))
	}
	if refused := shedAll(queue); len(refused) != 0 {
		t.Fatalf("a network alone was refused: %v", refused)
	}
	queue.enqueueWithLock(testP1Waiter(community, 200, 1, start))
	if queue.queuedByteCount != 1800 {
		t.Errorf("queued %d", queue.queuedByteCount)
	}
	// the team's 1,600 over 16 is 100, community's 200 over 1 is 200
	if refused := shedAll(queue); len(refused) != 1 || refused[0] != community {
		t.Errorf("refused %v, want the community network alone", refused)
	}
	if queue.queuedByteCount != 1600 {
		t.Errorf("queued %d after the shed", queue.queuedByteCount)
	}
}

// §11.13's shed row (owner decision 617): past the delay a flood is refused, and light networks waiting behind it
// below their shares, equally loaded, are all kept, by that pass and every later one. The shed before refused every
// waiting network but the last, equal loads by id.
func TestWriteBudgetShedKeepsEqualLightLoads(t *testing.T) {
	start := governorTestStart()
	queue := newWriteBudgetP1Queue(2)
	queue.startIntervalWithLock(1000)
	left := int64(1000)
	flood := connect.NewId()
	// alone in the window, the flood's share is the whole 1,000: it takes it, and the rest of its 30 waits
	admitted := 0
	for range 30 {
		if offerNow(queue, &left, testP1Waiter(flood, 100, 4, start)) {
			admitted += 1
		}
	}
	if admitted != 10 {
		t.Fatalf("the flood took %d at once", admitted)
	}
	// three light networks new to the window ask behind it, each below its share with the share spent
	lights := []connect.Id{connect.NewId(), connect.NewId(), connect.NewId()}
	for _, light := range lights {
		if offerNow(queue, &left, testP1Waiter(light, 100, 1, start)) {
			t.Fatal("a light network was served from a spent share")
		}
	}
	if refused := shedAll(queue); len(refused) != 1 || refused[0] != flood {
		t.Fatalf("refused %v, want the flood alone", refused)
	}
	if refused := shedAll(queue); len(refused) != 0 {
		t.Fatalf("a later pass refused %v of the equal light loads", refused)
	}
	// the next interval serves them first
	queue.startIntervalWithLock(1000)
	left = 1000
	for range lights {
		if serveNext(queue) == nil {
			t.Fatal("a light network was not served at the next share")
		}
	}
}

// A uniform overload still sheds: every waiting network past its share and equally loaded, with none lighter served,
// the shed refuses by id, the larger first, and keeps the last network waiting.
func TestWriteBudgetShedRefusesAUniformOverloadById(t *testing.T) {
	start := governorTestStart()
	queue := newWriteBudgetP1Queue(2)
	queue.startIntervalWithLock(0)
	networkIds := []connect.Id{connect.NewId(), connect.NewId(), connect.NewId()}
	for _, networkId := range networkIds {
		queue.enqueueWithLock(testP1Waiter(networkId, 100, 1, start))
	}
	// and one of weight 4 with four times the bytes, equally loaded per weight
	team := connect.NewId()
	queue.enqueueWithLock(testP1Waiter(team, 400, 4, start))
	networkIds = append(networkIds, team)
	refused := shedAll(queue)
	if len(refused) != len(networkIds)-1 {
		t.Fatalf("refused %v of %d", refused, len(networkIds))
	}
	for i := 1; i < len(refused); i += 1 {
		if !refused[i].LessThan(refused[i-1]) {
			t.Errorf("refused %v, not the larger id first", refused)
		}
	}
	if queue.emptyWithLock() {
		t.Error("the last network waiting was refused")
	}
}

// A network below its share is never refused while a flood holds more than its weighted share: a flood whose few
// waiters weigh less than a light network's one waiter is not refused for it, and the light network, below its share,
// is not refused though it is the heavier per weight. The shed before refused the light network.
func TestWriteBudgetShedRefusesNoLightNetworkWhileAFloodHoldsMore(t *testing.T) {
	start := governorTestStart()
	queue := newWriteBudgetP1Queue(2)
	pro := connect.NewId()
	community := connect.NewId()
	// both in the window, the share 500: the Pro network's share 400 and the Community network's 100
	queue.askWithLock(pro, 4)
	queue.askWithLock(community, 1)
	queue.startIntervalWithLock(500)
	left := int64(500)
	for range 4 {
		if !offerNow(queue, &left, testP1Waiter(pro, 100, 4, start)) {
			t.Fatal("the Pro network below its share was not served at once")
		}
	}
	if offerNow(queue, &left, testP1Waiter(pro, 100, 4, start)) {
		t.Fatal("the Pro network past its share was served")
	}
	// the share's last 100 does not cover the Community network's push of 200
	if offerNow(queue, &left, testP1Waiter(community, 200, 1, start)) {
		t.Fatal("served past the share")
	}
	if next := queue.nextWithLock(); next == nil || next.networkId != community {
		t.Fatalf("next %v, want the Community network's, the Pro network past its share", next)
	}
	if refused := shedAll(queue); len(refused) != 0 {
		t.Errorf("refused %v", refused)
	}
}

// An admission at once advances its network's finish tag as a queued one does. A network served at once while
// another's waiter stands past its share queues behind that waiter at the next interval; had its admissions left its
// tag and the virtual time where they were, its waiter's smaller price would have put it first.
func TestWriteBudgetImmediateAdmissionAdvancesItsFinishTag(t *testing.T) {
	start := governorTestStart()
	queue := newWriteBudgetP1Queue(2)
	early := connect.NewId()
	late := connect.NewId()
	// both in the window, the share 400: 200 each
	queue.askWithLock(early, 1)
	queue.askWithLock(late, 1)
	queue.startIntervalWithLock(400)
	left := int64(400)
	// early's 200 at once, tag 200, and its next 200 queues past its share at 400
	if !offerNow(queue, &left, testP1Waiter(early, 200, 1, start)) {
		t.Fatal("early was not served at once")
	}
	earlyQueued := testP1Waiter(early, 200, 1, start)
	if offerNow(queue, &left, earlyQueued) {
		t.Fatal("early past its share was served")
	}
	// late's two of 100 at once though early waits, tags 300 and 400, and its third queues past its share at 500
	for range 2 {
		if !offerNow(queue, &left, testP1Waiter(late, 100, 1, start)) {
			t.Fatal("late below its share was not served at once")
		}
	}
	lateQueued := testP1Waiter(late, 100, 1, start)
	if offerNow(queue, &left, lateQueued) {
		t.Fatal("late past its share was served")
	}
	if earlyQueued.finishTag != 400 || lateQueued.finishTag != 500 || queue.virtualTime != 400 {
		t.Errorf("tags %v and %v at virtual time %v", earlyQueued.finishTag, lateQueued.finishTag, queue.virtualTime)
	}
	queue.startIntervalWithLock(400)
	if next := queue.nextWithLock(); next != earlyQueued {
		t.Errorf("next %v, want early's waiter, tagged before late's", next.networkId)
	}
}

// A waiter that leaves unadmitted leaves no mark on its network's order: its next waiter starts from its last
// admission, where the queue's virtual time is, and an equal tag goes to the earlier queued.
func TestWriteBudgetUnadmittedWaitersLeaveNoMarkOnTheOrder(t *testing.T) {
	start := governorTestStart()
	queue := newTestP1Queue()
	probing := connect.NewId()
	other := connect.NewId()
	for range 5 {
		waiter := testP1Waiter(probing, 100, 1, start)
		queue.enqueueWithLock(waiter)
		waiter.state = writeBudgetAbandoned
		queue.removeWithLock(waiter)
	}
	probe := testP1Waiter(probing, 100, 1, start)
	queue.enqueueWithLock(probe)
	queue.enqueueWithLock(testP1Waiter(other, 100, 1, start))
	if next := queue.nextWithLock(); next != probe {
		t.Errorf("next %v, want the probing network's, its abandoned waiters forgotten", next.networkId)
	}
}

// The share window: a network that asked in the last interval has its weighted share held for it, and one that has
// not asked for the window's intervals leaves it, so the share goes whole to the networks still asking.
func TestWriteBudgetShareWindowHoldsAndThenReleasesAQuietNetworksShare(t *testing.T) {
	start := governorTestStart()
	queue := newWriteBudgetP1Queue(2)
	busy := connect.NewId()
	quiet := connect.NewId()
	queue.askWithLock(quiet, 1)
	takeAll := func() int64 {
		queue.startIntervalWithLock(1000)
		left := int64(1000)
		var byteCount int64
		for {
			waiter := testP1Waiter(busy, 100, 1, start)
			if !offerNow(queue, &left, waiter) {
				waiter.state = writeBudgetAbandoned
				queue.removeWithLock(waiter)
				return byteCount
			}
			byteCount += 100
		}
	}
	// quiet asked in the last interval: half the share is held for it
	if byteCount := takeAll(); byteCount != 500 {
		t.Errorf("busy took %d with quiet in the window, want 500", byteCount)
	}
	if byteCount := takeAll(); byteCount != 1000 {
		t.Errorf("busy took %d once quiet left the window, want the whole 1000", byteCount)
	}
	if _, ok := queue.networkIdNetworks[quiet]; ok {
		t.Error("quiet stayed in the window")
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
