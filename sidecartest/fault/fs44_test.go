package fault

// FS-44 (§20.6, FI-13 (a); QUOTA-M2-13) on T2: the usage producer every engine runs, QuotaUsageBatcher, over
// the fake Quota and a fake clock, with FI-13's oracle reading the fake's balances and counts after every
// step. A producer killed before ReportUsage loses at most its open window and never debits twice; a response
// lost and retried debits once; a drain loses nothing; api unavailable for 11 min drops the batch, counted,
// and it is never applied. The lease rows of DESIGN-DETAILS 13.6 as the fake shows them: an edge killed with
// bytes spent and unreported debits nothing and its reservation is gone at 15 min, and two hosts on one
// balance never take it below zero. The carve's own steps (a kill between a carve and its post, a third copy
// after the flush, the floor clamp) are Redis's, and run at T3 in server's quotahost.
//
// The batcher arms its next wait only once a round has ended, so a step ends at the timer it waits on, never
// at a sleep.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

type fs44World struct {
	clock     *sidecartest.FakeClock
	faults    *sidecartest.FaultQueue
	quota     *sidecartest.FakeQuota
	metrics   *sidecartest.FakeMetrics
	oracle    *sidecartest.QuotaOracle
	batcher   *sidecar.QuotaUsageBatcher
	start     time.Time
	networkId connect.Id
	balanceId connect.Id
}

const fs44BalanceByteCount = int64(1 << 30)

// An evs producer on §20.6's defaults waiting at its first window's end, and one network with a balance.
func newFs44World(t *testing.T) *fs44World {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	quota := sidecartest.NewFakeQuota(clock, faults, nil)
	metrics := sidecartest.NewFakeMetrics(nil)
	world := &fs44World{
		clock:     clock,
		faults:    faults,
		quota:     quota,
		metrics:   metrics,
		oracle:    sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(quota)),
		start:     clock.Now(),
		networkId: connect.NewId(),
		balanceId: connect.NewId(),
	}
	quota.SetBalances(world.networkId, []*sidecartest.QuotaBalance{{BalanceId: world.balanceId, ByteCount: fs44BalanceByteCount}})
	world.oracle.Grant(world.networkId, fs44BalanceByteCount)
	host := &sidecar.ServiceHost{Quota: quota, Metrics: metrics, Clock: clock}
	batcher, err := sidecar.NewQuotaUsageBatcher(t.Context(), host, sidecar.QuotaProducerEvs, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(batcher.Close)
	world.batcher = batcher
	world.awaitTimerAt(t, world.at(60*time.Second))
	return world
}

func (self *fs44World) at(timeout time.Duration) time.Time {
	return self.start.Add(timeout)
}

// Returns once the clock has a timer pending at at. The real-time bound only fails a test that would hang.
func (self *fs44World) awaitTimerAt(t *testing.T, at time.Time) {
	t.Helper()
	for {
		pending, added := self.clock.WatchTimers()
		if slices.ContainsFunc(pending, func(pendingTime time.Time) bool { return pendingTime.Equal(at) }) {
			return
		}
		select {
		case <-added:
		case <-time.After(10 * time.Second):
			t.Fatalf("no timer at %s, pending %v", at, pending)
		}
	}
}

// Moves the clock to the producer's timer at at, and returns once the round it starts has ended in the
// producer's next wait, at next. FI-13 (a)'s upper bound is checked there.
func (self *fs44World) step(t *testing.T, at time.Duration, next time.Duration) {
	t.Helper()
	self.awaitTimerAt(t, self.at(at))
	self.clock.AdvanceTo(self.at(at))
	self.awaitTimerAt(t, self.at(next))
	self.check(t)
}

func (self *fs44World) check(t *testing.T) {
	t.Helper()
	if err := self.oracle.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func (self *fs44World) checkSettled(t *testing.T) {
	t.Helper()
	if err := self.oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// The producer meters byteCount: the oracle is told as the bytes move.
func (self *fs44World) meter(t *testing.T, byteCount int64) {
	t.Helper()
	if err := self.batcher.AddTransfer(self.networkId, sidecar.QuotaMeterEvs, byteCount); err != nil {
		t.Fatal(err)
	}
	self.oracle.Meter(self.networkId, sidecar.QuotaMeterEvs, byteCount)
	self.check(t)
}

func (self *fs44World) debited() int64 {
	return fs44BalanceByteCount - self.quota.Balances(self.networkId)[0].ByteCount
}

// A producer killed before ReportUsage: the window it had open is lost, at most that one, and what it sent
// before stays debited once.
func TestFs44KilledBeforeReportUsage(t *testing.T) {
	world := newFs44World(t)
	world.meter(t, 100)
	world.step(t, 60*time.Second, 120*time.Second)
	world.checkSettled(t)
	world.meter(t, 40)
	// the kill, 30 s into the second window
	world.clock.Advance(30 * time.Second)
	world.batcher.Close()
	world.oracle.Lose(world.networkId, sidecar.QuotaMeterEvs, 40)
	world.check(t)
	world.clock.Advance(24 * time.Hour)
	world.checkSettled(t)
	if got := world.debited(); got != 100 {
		t.Fatalf("%d debited after the kill, want the first window's 100", got)
	}
	if sent := world.quota.SentBatches(); len(sent) != 1 {
		t.Fatalf("%d batches reached api", len(sent))
	}
}

// A ReportUsage response lost and retried: the batch goes again under its id and debits once.
func TestFs44LostResponseRetried(t *testing.T) {
	world := newFs44World(t)
	if _, err := world.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	world.meter(t, 100)
	// the window closes, api applies the batch and the answer is lost: the retry waits RetryTimeout
	world.step(t, 60*time.Second, 65*time.Second)
	if got := world.debited(); got != 100 {
		t.Fatalf("%d debited at the lost answer", got)
	}
	world.step(t, 65*time.Second, 120*time.Second)
	world.checkSettled(t)
	sent := world.quota.SentBatches()
	if len(sent) != 2 || sent[0].BatchId != sent[1].BatchId {
		t.Fatalf("the retry: %d sends", len(sent))
	}
	if applied := world.quota.Batches(); len(applied) != 1 {
		t.Fatalf("%d batches applied", len(applied))
	}
	if got := world.debited(); got != 100 {
		t.Fatalf("%d debited after the retry", got)
	}
	if unfired := world.faults.Unfired(); len(unfired) != 0 {
		t.Fatalf("the lost answer never fired: %v", unfired)
	}
}

// A producer killed while its batch is unanswered, the batch applied (§22.8's unknown rule): one window lost
// to the producer's knowledge, and debited once whichever way it went.
func TestFs44KilledWithAnAppliedBatchUnanswered(t *testing.T) {
	world := newFs44World(t)
	if _, err := world.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	world.meter(t, 100)
	world.step(t, 60*time.Second, 65*time.Second)
	world.batcher.Close()
	world.oracle.Lose(world.networkId, sidecar.QuotaMeterEvs, 100)
	world.clock.Advance(24 * time.Hour)
	world.checkSettled(t)
	if got := world.debited(); got != 100 {
		t.Fatalf("%d debited", got)
	}
	if applied := world.quota.Batches(); len(applied) != 1 {
		t.Fatalf("%d batches applied", len(applied))
	}
}

// A SIGTERM drain: the open window is sent at once and nothing is lost, a lost answer on the way included.
func TestFs44DrainLosesNothing(t *testing.T) {
	world := newFs44World(t)
	world.meter(t, 100)
	world.step(t, 60*time.Second, 120*time.Second)
	world.meter(t, 40)
	world.clock.Advance(10 * time.Second)
	if _, err := world.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: sidecartest.ApplyThenDrop}); err != nil {
		t.Fatal(err)
	}
	drained := make(chan error, 1)
	go func() {
		drained <- world.batcher.Drain(t.Context())
	}()
	// the drain's send lost its answer: the retry waits RetryTimeout on the clock
	world.awaitTimerAt(t, world.at(75*time.Second))
	world.check(t)
	world.clock.AdvanceTo(world.at(75 * time.Second))
	select {
	case err := <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the drain never returned")
	}
	world.batcher.Close()
	world.checkSettled(t)
	if got := world.debited(); got != 140 {
		t.Fatalf("%d debited after the drain, want 140", got)
	}
	if applied := world.quota.Batches(); len(applied) != 2 {
		t.Fatalf("%d batches applied", len(applied))
	}
}

// api unavailable for 11 min: the batch is retried under its id for its 10 min horizon, then dropped, counted
// for the alert, and never applied; the windows after api returns apply as ever.
func TestFs44ApiUnavailableElevenMinutes(t *testing.T) {
	world := newFs44World(t)
	// every attempt of the batch's ten minutes: one at its window's close and one each RetryTimeout after
	if _, err := world.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: sidecartest.FailBeforeApply, Repeat: 119}); err != nil {
		t.Fatal(err)
	}
	world.meter(t, 100)
	for at := 60 * time.Second; at < 660*time.Second; at += 5 * time.Second {
		world.step(t, at, at+5*time.Second)
	}
	if got := world.metrics.Value("urnetwork_quota_usage_batches_dropped_total", sidecar.QuotaProducerEvs); got != 0 {
		t.Fatalf("dropped %v batches inside the horizon", got)
	}
	// ten minutes after its window closed the batch is dropped, not sent
	world.step(t, 660*time.Second, 720*time.Second)
	world.oracle.Lose(world.networkId, sidecar.QuotaMeterEvs, 100)
	if got := world.metrics.Value("urnetwork_quota_usage_batches_dropped_total", sidecar.QuotaProducerEvs); got != 1 {
		t.Fatalf("dropped %v batches", got)
	}
	if got := world.metrics.Value("urnetwork_quota_usage_dropped_bytes_total", sidecar.QuotaProducerEvs); got != 100 {
		t.Fatalf("dropped %v bytes", got)
	}
	if got := world.metrics.Value("urnetwork_quota_usage_send_failures_total", sidecar.QuotaProducerEvs); got != 120 {
		t.Fatalf("%v failed sends", got)
	}
	if unfired := world.faults.Unfired(); len(unfired) != 0 {
		t.Fatalf("api's outage ended early: %v", unfired)
	}
	// api is back in the eleventh minute: the dropped batch is never applied, and the next window is
	world.meter(t, 7)
	world.step(t, 720*time.Second, 780*time.Second)
	world.checkSettled(t)
	if applied := world.quota.Batches(); len(applied) != 1 || applied[0].Events[0].TransferByteCount != 7 {
		t.Fatalf("applied %+v", applied)
	}
	if got := world.debited(); got != 7 {
		t.Fatalf("%d debited, want the later window's 7", got)
	}
	if violations := world.metrics.Violations(); len(violations) != 0 {
		t.Fatalf("metrics %v", violations)
	}
}

// DESIGN-DETAILS 13.6's lease row as the fake shows it: an edge killed with bytes spent on a lease and never
// reported debits nothing, and its reservation is gone LeaseTokenLifetime later.
func TestFs44EdgeKilledBeforeItsPost(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	quota := sidecartest.NewFakeQuota(clock, sidecartest.NewFaultQueue(), nil)
	oracle := sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(quota))
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	table := sidecartest.NewActorTable(clock, driver)
	networkId := connect.NewId()
	quota.SetBalances(networkId, []*sidecartest.QuotaBalance{{ByteCount: fs44BalanceByteCount}})
	oracle.Grant(networkId, fs44BalanceByteCount)
	edge := table.Actor(t.Context(), "tlsedge1")
	lease, refusal, err := quota.Lease(edge.Context(), networkId, sidecar.QuotaMeterTls)
	if err != nil || refusal != nil {
		t.Fatalf("lease: %v, %+v", err, refusal)
	}
	if !lease.Spend(3000) {
		t.Fatal("spend refused")
	}
	oracle.Meter(networkId, sidecar.QuotaMeterTls, 3000)
	if err := oracle.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	edge.Kill()
	oracle.Lose(networkId, sidecar.QuotaMeterTls, 3000)
	if got := quota.Balances(networkId)[0].ReservedByteCount; got == 0 {
		t.Fatal("the kill released the reservation at once")
	}
	clock.Advance(sidecartest.DefaultFakeQuotaSettings().LeaseTokenLifetime)
	balance := quota.Balances(networkId)[0]
	if balance.ByteCount != fs44BalanceByteCount || balance.ReservedByteCount != 0 {
		t.Fatalf("after the token's lifetime: %+v", balance)
	}
	clock.Advance(24 * time.Hour)
	if err := oracle.CheckSettled(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// FS-44's twin for balances as the fake shows it: two hosts lease one balance that holds less than two
// draws. What they reserve never passes the balance, each debits what it spent once, and the balance ends at
// zero, never below.
func TestFs44TwoHostsOnOneBalance(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecartest.DefaultFakeQuotaSettings()
	quota := sidecartest.NewFakeQuota(clock, sidecartest.NewFaultQueue(), settings)
	oracle := sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(quota))
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	table := sidecartest.NewActorTable(clock, driver)
	networkId := connect.NewId()
	draw := settings.LeaseDrawByteCount
	room := draw + draw/2
	quota.SetLimits(networkId, &sidecar.QuotaLimits{Tier: "pro"})
	quota.SetBalances(networkId, []*sidecartest.QuotaBalance{{ByteCount: room}})
	oracle.Grant(networkId, room)
	edges := []*sidecartest.Actor{table.Actor(t.Context(), "tlsedge1"), table.Actor(t.Context(), "tlsedge2")}
	spends := []int64{draw, draw / 2}
	// both reserve before either spends: the second finds what the first left
	leases := []sidecar.QuotaLease{}
	for index, edge := range edges {
		lease, refusal, err := quota.Lease(edge.Context(), networkId, sidecar.QuotaMeterTls)
		if err != nil || refusal != nil {
			t.Fatalf("lease %d: %v, %+v", index, err, refusal)
		}
		defer lease.Close()
		leases = append(leases, lease)
	}
	for index, lease := range leases {
		if !lease.Spend(spends[index]) {
			t.Fatalf("host %d: its reservation refused %d", index, spends[index])
		}
		oracle.Meter(networkId, sidecar.QuotaMeterTls, spends[index])
		// past what it reserved: refused, since the balance has nothing more to reserve
		if lease.Spend(1) {
			t.Fatalf("host %d spent past the balance", index)
		}
		balance := quota.Balances(networkId)[0]
		if room < balance.ReservedByteCount {
			t.Fatalf("%d reserved of %d", balance.ReservedByteCount, room)
		}
		if err := oracle.Check(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	for index, edge := range edges {
		batch := &sidecar.UsageBatch{
			BatchId:  connect.NewId(),
			Producer: sidecar.QuotaProducerTlsEdge,
			Events:   []*sidecar.UsageEvent{{NetworkId: networkId, Meter: sidecar.QuotaMeterTls, TransferByteCount: spends[index]}},
		}
		for range 2 {
			if err := quota.ReportUsage(edge.Context(), batch); err != nil {
				t.Fatal(err)
			}
			if err := oracle.Check(t.Context()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := oracle.CheckSettled(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := quota.Balances(networkId)[0].ByteCount; got != 0 {
		t.Fatalf("the balance ended at %d, want zero", got)
	}
}
