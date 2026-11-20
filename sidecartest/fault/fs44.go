// FS-44 (§20.6, FI-13 (a); QUOTA-M2-13) on a Net: the usage producer every engine runs, QuotaUsageBatcher, over the
// Net's fake Quota and its clock, the producer started under its actor, so a plan on the Net's queue reaches its sends
// and the schedule's own steps move its windows. FI-13's oracle (sidecartest.QuotaOracle) reads the fake's balances and
// counts after every step: FI-13's own binding is QUOTA-M2-13's and unbound, so fault.FI(13) fails closed, and each
// schedule checks FI-13 (a)'s upper bound as its world reads it (FI-13/fs44), the oracle told what the producer metered
// and what a kill or a drop loses; a step checks (a)'s lower bound, every metered byte not lost debited once, where
// nothing is in flight.
//
// The registered case, Fs44KilledBeforeReportUsage: a producer killed before ReportUsage loses at most its open window,
// and what it sent before stays debited once. The clauses beside it (clauses.go): a response lost and retried debits
// once; a producer killed with an applied batch unanswered debits it once; a SIGTERM drain loses nothing, a lost answer
// on the way included; api unavailable for 11 min drops the batch, counted and alerted, and never applies it; and
// DESIGN-DETAILS 13.6's lease rows as the fake shows them, an edge killed with bytes spent and unreported debiting
// nothing, its reservation gone a token's lifetime later, and two hosts on one balance never taking it below zero. The
// carve's own steps (a kill between a carve and its post, a third copy after the flush) are Redis's, and run on T3 in
// server's quotahost, whose tests are FS-44's T3 run.
//
// FS-44 is on §22.8's unknown list, but the fake Quota's calls are host calls, which the unknown rule's dry run does not
// count as writes (every_write.go), so on T2 the rule loses no answer of these schedules; the clauses lose ReportUsage's
// answers by their own plans. The producer arms its next wait only once a round has ended, so a step ends at the timer
// it waits on, never at a sleep (owner decision 549). Each world's ids are its own, so no run sees another's.

package fault

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs44 = Register("FS-44", "", []Tier{TierT2}, Fs44KilledBeforeReportUsage)

// What FS-44's world is built with.
type Fs44WorldSettings struct {
	// The network's one balance: 1 GiB, past what any schedule meters.
	BalanceByteCount int64
	// Real time a step waits for the producer to arm the timer it names before it fails: a guard against a producer
	// that never arms it, never a wait a schedule orders: 10 s.
	TimerTimeout time.Duration
	// The Net's fake Quota's settings, which the lease clauses read: sidecartest's defaults, which the Net's fakes take.
	Quota *sidecartest.FakeQuotaSettings
}

func DefaultFs44WorldSettings() *Fs44WorldSettings {
	return &Fs44WorldSettings{
		BalanceByteCount: 1024 * 1024 * 1024,
		TimerTimeout:     10 * time.Second,
		Quota:            sidecartest.DefaultFakeQuotaSettings(),
	}
}

// One network with one balance on the Net's fake Quota, and an evs producer on §20.6's defaults.
type fs44World struct {
	net       *Net
	settings  *Fs44WorldSettings
	quota     *sidecartest.FakeQuota
	metrics   *sidecartest.FakeMetrics
	oracle    *sidecartest.QuotaOracle
	networkId connect.Id

	stateLock sync.Mutex
	// the Net's time at Setup, from which the schedule names the producer's timers
	start   time.Time
	batcher *sidecar.QuotaUsageBatcher
}

func newFs44World(net *Net, settings *Fs44WorldSettings) *fs44World {
	if settings == nil {
		settings = DefaultFs44WorldSettings()
	}
	quota := net.Fakes().Quota
	return &fs44World{
		net:       net,
		settings:  settings,
		quota:     quota,
		metrics:   net.Fakes().Metrics,
		oracle:    sidecartest.NewQuotaOracle(sidecartest.NewFakeQuotaOracleSource(quota)),
		networkId: connect.NewId(),
	}
}

// FI-13 (a)'s upper bound as the world reads it, after every step.
func (self *fs44World) check() Invariant {
	return NewInvariant("FI-13/fs44", func(ctx context.Context, oracle *Oracle) error {
		return self.oracle.Check(ctx)
	})
}

// A step action: the network's balance, set and told to the oracle, and an evs producer started under the step's
// actor, which returns once the producer waits at its first window's end.
func (self *fs44World) setup(ctx context.Context, net *Net) error {
	self.quota.SetBalances(self.networkId, []*sidecartest.QuotaBalance{{BalanceId: connect.NewId(), ByteCount: self.settings.BalanceByteCount}})
	self.oracle.Grant(self.networkId, self.settings.BalanceByteCount)
	start := net.Clock().Now()
	host := &sidecar.ServiceHost{Quota: self.quota, Metrics: self.metrics, Clock: net.Clock()}
	batcher, err := sidecar.NewQuotaUsageBatcher(ctx, host, sidecar.QuotaProducerEvs, nil)
	if err != nil {
		return err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.start = start
		self.batcher = batcher
	}()
	return self.awaitTimerAt(ctx, start.Add(60*time.Second))
}

func (self *fs44World) at(offset time.Duration) time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.start.Add(offset)
}

func (self *fs44World) producer() *sidecar.QuotaUsageBatcher {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.batcher
}

// Returns once the Net's clock holds a timer at at.
func (self *fs44World) awaitTimerAt(ctx context.Context, at time.Time) error {
	clock := self.net.Clock()
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, func(pendingTime time.Time) bool { return pendingTime.Equal(at) }) {
			return nil
		}
		select {
		case <-added:
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(self.settings.TimerTimeout):
			return fmt.Errorf("the producer armed no timer at %s, pending %v", at, pending)
		}
	}
}

// A step action: the clock moves to the producer's timer at at, and the step ends once the round it starts has ended
// in the producer's next wait, at next.
func (self *fs44World) stepTo(at time.Duration, next time.Duration) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if err := self.awaitTimerAt(ctx, self.at(at)); err != nil {
			return err
		}
		net.Clock().AdvanceTo(self.at(at))
		return self.awaitTimerAt(ctx, self.at(next))
	}
}

// A step action: the producer meters byteCount for the network, the oracle told as the bytes move.
func (self *fs44World) meter(byteCount int64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if err := self.producer().AddTransfer(self.networkId, sidecar.QuotaMeterEvs, byteCount); err != nil {
			return err
		}
		self.oracle.Meter(self.networkId, sidecar.QuotaMeterEvs, byteCount)
		return nil
	}
}

// A step action: the producer is killed, its open window and unanswered batches gone with it, of which lostByteCount
// metered bytes may never debit.
func (self *fs44World) kill(lostByteCount int64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		self.producer().Close()
		self.oracle.Lose(self.networkId, sidecar.QuotaMeterEvs, lostByteCount)
		return nil
	}
}

// A step action: FI-13 (a) whole, with nothing in flight: every metered byte not lost has debited, once.
func (self *fs44World) settled(ctx context.Context, net *Net) error {
	return self.oracle.CheckSettled(sidecartest.InspectContext(ctx))
}

// A step action: the balance has given debited bytes in all.
func (self *fs44World) expectDebited(debited int64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if got := self.settings.BalanceByteCount - self.quota.Balances(self.networkId)[0].ByteCount; got != debited {
			return fmt.Errorf("%d debited, want %d", got, debited)
		}
		return nil
	}
}

// A step action: the fake Quota was sent sent batches and applied applied of them.
func (self *fs44World) expectBatches(sent int, applied int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		sentBatches, appliedBatches := self.quota.SentBatches(), self.quota.Batches()
		if len(sentBatches) != sent || len(appliedBatches) != applied {
			return fmt.Errorf("%d batches sent and %d applied, want %d and %d", len(sentBatches), len(appliedBatches), sent, applied)
		}
		return nil
	}
}

// A step action: the producer's metric name reads value.
func (self *fs44World) expectMetric(name string, value float64) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		if got := self.metrics.Value(name, sidecar.QuotaProducerEvs); got != value {
			return fmt.Errorf("%s reads %v, want %v", name, got, value)
		}
		return nil
	}
}

// The next ReportUsage applies and loses its answer.
func fs44LoseNextAnswer() *Step {
	return &Step{Fault: &FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: ApplyThenDrop}}
}

// See the file header.
func Fs44KilledBeforeReportUsage(net *Net) *Schedule {
	world := newFs44World(net, nil)
	steps := []*Step{
		{Actor: "producer", Action: world.setup},
		{Actor: "producer", Action: world.meter(100)},
		{Actor: "check", Action: world.stepTo(60*time.Second, 120*time.Second)},
		{Actor: "check", Action: world.settled},
		{Actor: "producer", Action: world.meter(40)},
		// the kill, 30 s into the second window
		{Advance: 30 * time.Second},
		{Actor: "producer", Action: world.kill(40)},
		{Advance: 24 * time.Hour},
		{Actor: "check", Action: world.settled},
		{Actor: "check", Action: world.expectDebited(100)},
		{Actor: "check", Action: world.expectBatches(1, 1)},
	}
	return &Schedule{Id: "FS-44", Steps: steps, Check: []Invariant{world.check()}}
}

// A ReportUsage response lost and retried: the batch goes again under its id and debits once.
func Fs44LostResponseRetried(net *Net) *Schedule {
	world := newFs44World(net, nil)
	steps := []*Step{
		{Actor: "producer", Action: world.setup},
		fs44LoseNextAnswer(),
		{Actor: "producer", Action: world.meter(100)},
		// the window closes, api applies the batch and the answer is lost: the retry waits RetryTimeout
		{Actor: "check", Action: world.stepTo(60*time.Second, 65*time.Second)},
		{Actor: "check", Action: world.expectDebited(100)},
		{Actor: "check", Action: world.stepTo(65*time.Second, 120*time.Second)},
		{Actor: "check", Action: world.settled},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			sent := world.quota.SentBatches()
			if len(sent) != 2 || sent[0].BatchId != sent[1].BatchId {
				return fmt.Errorf("the retry: %d sends, not two of one batch", len(sent))
			}
			return nil
		}},
		{Actor: "check", Action: world.expectBatches(2, 1)},
		{Actor: "check", Action: world.expectDebited(100)},
	}
	return &Schedule{Id: "FS-44 lost response retried", Steps: steps, Check: []Invariant{world.check()}}
}

// A producer killed while its batch is unanswered, the batch applied (§22.8's unknown rule): one window lost to the
// producer's knowledge, and debited once whichever way it went.
func Fs44KilledWithAnAppliedBatchUnanswered(net *Net) *Schedule {
	world := newFs44World(net, nil)
	steps := []*Step{
		{Actor: "producer", Action: world.setup},
		fs44LoseNextAnswer(),
		{Actor: "producer", Action: world.meter(100)},
		{Actor: "check", Action: world.stepTo(60*time.Second, 65*time.Second)},
		{Actor: "producer", Action: world.kill(100)},
		{Advance: 24 * time.Hour},
		{Actor: "check", Action: world.settled},
		{Actor: "check", Action: world.expectDebited(100)},
		{Actor: "check", Action: world.expectBatches(1, 1)},
	}
	return &Schedule{Id: "FS-44 killed with an applied batch unanswered", Steps: steps, Check: []Invariant{world.check()}}
}

// A SIGTERM drain: the open window is sent at once and nothing is lost, a lost answer on the way included. The drain
// waits on the producer's retry timer, so it runs on a goroutine of the producer's, as the process's SIGTERM handler
// does, and the step that moves the clock to the retry lets it end.
func Fs44DrainLosesNothing(net *Net) *Schedule {
	world := newFs44World(net, nil)
	drained := make(chan error, 1)
	steps := []*Step{
		{Actor: "producer", Action: world.setup},
		{Actor: "producer", Action: world.meter(100)},
		{Actor: "check", Action: world.stepTo(60*time.Second, 120*time.Second)},
		{Actor: "producer", Action: world.meter(40)},
		{Advance: 10 * time.Second},
		fs44LoseNextAnswer(),
		{Actor: "producer", Action: func(ctx context.Context, net *Net) error {
			producer := world.producer()
			go func() {
				drained <- producer.Drain(ctx)
			}()
			return nil
		}},
		// the drain's send lost its answer: the retry waits RetryTimeout on the clock
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			if err := world.awaitTimerAt(ctx, world.at(75*time.Second)); err != nil {
				return err
			}
			net.Clock().AdvanceTo(world.at(75 * time.Second))
			select {
			case err := <-drained:
				return err
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(world.settings.TimerTimeout):
				return errors.New("the drain never returned")
			}
		}},
		{Actor: "producer", Action: world.kill(0)},
		{Actor: "check", Action: world.settled},
		{Actor: "check", Action: world.expectDebited(140)},
		{Actor: "check", Action: world.expectBatches(3, 2)},
	}
	return &Schedule{Id: "FS-44 drain loses nothing", Steps: steps, Check: []Invariant{world.check()}}
}

// api unavailable for 11 min: the batch is retried under its id for its 10 min horizon, then dropped, counted for the
// alert, and never applied; the windows after api returns apply as ever.
func Fs44ApiUnavailableElevenMinutes(net *Net) *Schedule {
	world := newFs44World(net, nil)
	steps := []*Step{
		{Actor: "producer", Action: world.setup},
		// every attempt of the batch's ten minutes: one at its window's close and one each RetryTimeout after
		{Fault: &FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "quota.ReportUsage", Result: FailBeforeApply, Repeat: 119}},
		{Actor: "producer", Action: world.meter(100)},
	}
	for at := 60 * time.Second; at < 660*time.Second; at += 5 * time.Second {
		steps = append(steps, &Step{Actor: "check", Action: world.stepTo(at, at+5*time.Second)})
	}
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.expectMetric("urnetwork_quota_usage_batches_dropped_total", 0)},
		// ten minutes after its window closed the batch is dropped, not sent
		{Actor: "check", Action: world.stepTo(660*time.Second, 720*time.Second)},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			world.oracle.Lose(world.networkId, sidecar.QuotaMeterEvs, 100)
			return nil
		}},
		{Actor: "check", Action: world.expectMetric("urnetwork_quota_usage_batches_dropped_total", 1)},
		{Actor: "check", Action: world.expectMetric("urnetwork_quota_usage_dropped_bytes_total", 100)},
		{Actor: "check", Action: world.expectMetric("urnetwork_quota_usage_send_failures_total", 120)},
		// api is back in the eleventh minute: the dropped batch is never applied, and the next window is
		{Actor: "producer", Action: world.meter(7)},
		{Actor: "check", Action: world.stepTo(720*time.Second, 780*time.Second)},
		{Actor: "check", Action: world.settled},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			applied := world.quota.Batches()
			if len(applied) != 1 || applied[0].Events[0].TransferByteCount != 7 {
				return fmt.Errorf("applied %d batches, not the later window's alone", len(applied))
			}
			if violations := world.metrics.Violations(); len(violations) != 0 {
				return fmt.Errorf("metrics %v", violations)
			}
			return nil
		}},
		{Actor: "check", Action: world.expectDebited(7)},
	}...)
	return &Schedule{Id: "FS-44 api unavailable eleven minutes", Steps: steps, Check: []Invariant{world.check()}}
}

// DESIGN-DETAILS 13.6's lease row as the fake shows it: an edge killed with bytes spent on a lease and never reported
// debits nothing, and its reservation is gone a token's lifetime later.
func Fs44EdgeKilledBeforeItsPost(net *Net) *Schedule {
	world := newFs44World(net, nil)
	steps := []*Step{
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			world.quota.SetBalances(world.networkId, []*sidecartest.QuotaBalance{{ByteCount: world.settings.BalanceByteCount}})
			world.oracle.Grant(world.networkId, world.settings.BalanceByteCount)
			return nil
		}},
		{Actor: "tlsedge1", Action: func(ctx context.Context, net *Net) error {
			lease, refusal, err := world.quota.Lease(ctx, world.networkId, sidecar.QuotaMeterTls)
			if err != nil || refusal != nil {
				return fmt.Errorf("the lease: %v, %+v", err, refusal)
			}
			if !lease.Spend(3000) {
				return errors.New("the lease refused its spend")
			}
			world.oracle.Meter(world.networkId, sidecar.QuotaMeterTls, 3000)
			return nil
		}},
		{Actor: "tlsedge1", Kill: true},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			world.oracle.Lose(world.networkId, sidecar.QuotaMeterTls, 3000)
			if got := world.quota.Balances(world.networkId)[0].ReservedByteCount; got == 0 {
				return errors.New("the kill released the reservation at once")
			}
			return nil
		}},
		{Advance: world.settings.Quota.LeaseTokenLifetime},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			balance := world.quota.Balances(world.networkId)[0]
			if balance.ByteCount != world.settings.BalanceByteCount || balance.ReservedByteCount != 0 {
				return fmt.Errorf("after the token's lifetime: %d left, %d reserved", balance.ByteCount, balance.ReservedByteCount)
			}
			return nil
		}},
		{Advance: 24 * time.Hour},
		{Actor: "check", Action: world.settled},
	}
	return &Schedule{Id: "FS-44 edge killed before its post", Steps: steps, Check: []Invariant{world.check()}}
}

// FS-44's twin for balances as the fake shows it: two hosts lease one balance that holds less than two draws. What
// they reserve never passes the balance, each debits what it spent once, its batch sent twice, and the balance ends at
// zero, never below.
func Fs44TwoHostsOnOneBalance(net *Net) *Schedule {
	world := newFs44World(net, nil)
	draw := world.settings.Quota.LeaseDrawByteCount
	room := draw + draw/2
	spends := []int64{draw, draw / 2}
	edges := []string{"tlsedge1", "tlsedge2"}
	leases := make([]sidecar.QuotaLease, len(edges))
	steps := []*Step{
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			world.quota.SetLimits(world.networkId, &sidecar.QuotaLimits{Tier: "pro"})
			world.quota.SetBalances(world.networkId, []*sidecartest.QuotaBalance{{ByteCount: room}})
			world.oracle.Grant(world.networkId, room)
			return nil
		}},
	}
	// both reserve before either spends: the second finds what the first left
	for index, edge := range edges {
		steps = append(steps, &Step{Actor: edge, Action: func(ctx context.Context, net *Net) error {
			lease, refusal, err := world.quota.Lease(ctx, world.networkId, sidecar.QuotaMeterTls)
			if err != nil || refusal != nil {
				return fmt.Errorf("%s's lease: %v, %+v", edge, err, refusal)
			}
			leases[index] = lease
			return nil
		}})
	}
	for index, edge := range edges {
		steps = append(steps, &Step{Actor: edge, Action: func(ctx context.Context, net *Net) error {
			lease := leases[index]
			if !lease.Spend(spends[index]) {
				return fmt.Errorf("%s: its reservation refused %d", edge, spends[index])
			}
			world.oracle.Meter(world.networkId, sidecar.QuotaMeterTls, spends[index])
			// past what it reserved: refused, since the balance has nothing more to reserve
			if lease.Spend(1) {
				return fmt.Errorf("%s spent past the balance", edge)
			}
			if reserved := world.quota.Balances(world.networkId)[0].ReservedByteCount; room < reserved {
				return fmt.Errorf("%d reserved of %d", reserved, room)
			}
			return nil
		}})
	}
	for index, edge := range edges {
		batch := &sidecar.UsageBatch{
			BatchId:  connect.NewId(),
			Producer: sidecar.QuotaProducerTlsEdge,
			Events:   []*sidecar.UsageEvent{{NetworkId: world.networkId, Meter: sidecar.QuotaMeterTls, TransferByteCount: spends[index]}},
		}
		for range 2 {
			steps = append(steps, &Step{Actor: edge, Action: func(ctx context.Context, net *Net) error {
				return world.quota.ReportUsage(ctx, batch)
			}})
		}
		steps = append(steps, &Step{Actor: edge, Action: func(ctx context.Context, net *Net) error {
			leases[index].Close()
			return nil
		}})
	}
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.settled},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			if got := world.quota.Balances(world.networkId)[0].ByteCount; got != 0 {
				return fmt.Errorf("the balance ended at %d, want zero", got)
			}
			return nil
		}},
	}...)
	return &Schedule{Id: "FS-44 two hosts on one balance", Steps: steps, Check: []Invariant{world.check()}}
}
