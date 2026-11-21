package fault

// FS-61 on T2 (EVSB-M2-07): the registered case and the clauses of fs61.go, each under every rule §22.8 gives the row,
// on the Net's host. No schedule there holds a barrier, so these run on both legs.
//
// The world here, the budget loop over fs61.go's fake drive counters beside real process budgets on one fake clock of
// its own, is FS-81's (fs81_test.go), which holds a process's admissions between the loop's steps.

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

type fs61World struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	settings *evsservice.BudgetLoopSettings
	counters *fs61Counters
	loop     *evsservice.BudgetLoop
	clients  []*evsservice.WriteBudgetClient
}

// The loop over a saved state of bucket B and calibration 1, or none when bucket is negative.
func newFs61World(t *testing.T, bucketByteCount int64) *fs61World {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	settings := evsservice.DefaultBudgetLoopSettings()
	// weights reread once an hour, so the only timers a step waits for are the processes' ticks
	settings.Budget.WeightRefreshInterval = time.Hour
	if 0 <= bucketByteCount {
		state := &evsservice.GovernorState{
			Seq:             1,
			TimeMs:          clock.Now().Add(-settings.Budget.Interval).UnixMilli(),
			BucketByteCount: bucketByteCount,
			Calibration:     1,
		}
		if err := evsservice.SaveGovernorState(ctx, host.Redis, settings.Budget, "meta-1", state); err != nil {
			t.Fatal(err)
		}
	}
	counters := &fs61Counters{}
	loop, err := evsservice.NewBudgetLoop(host.ServiceHost(), "meta-1", counters, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	return &fs61World{
		t:        t,
		ctx:      ctx,
		clock:    clock,
		host:     host,
		settings: settings,
		counters: counters,
		loop:     loop,
	}
}

// A process budget, started, its first tick waited out.
func (self *fs61World) addClient() *evsservice.WriteBudgetClient {
	self.t.Helper()
	next := self.clock.Now().Add(self.settings.Budget.Interval)
	before := self.timerCount(next)
	client, err := evsservice.NewWriteBudget(self.ctx, self.host.ServiceHost(), []string{"meta-1"}, self.settings.Budget)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	self.clients = append(self.clients, client)
	self.awaitTimers(next, before+1)
	return client
}

// The timers pending at exactly at.
func (self *fs61World) timerCount(at time.Time) int {
	pending, _ := self.clock.WatchTimers()
	count := 0
	for _, pendingAt := range pending {
		if pendingAt.Equal(at) {
			count += 1
		}
	}
	return count
}

// Returns once count timers are pending at exactly at. A process re-arms its interval's timer only after its
// tick, so this is how a step knows every tick is done. Field ttls in the fake Redis set timers too, on the
// interval's grid, so a caller counts the ones there before it moves the clock.
func (self *fs61World) awaitTimers(at time.Time, count int) {
	self.t.Helper()
	for {
		pending, added := self.clock.WatchTimers()
		found := 0
		for _, pendingAt := range pending {
			if pendingAt.Equal(at) {
				found += 1
			}
		}
		if count <= found {
			return
		}
		select {
		case <-added:
		case <-self.ctx.Done():
			self.t.Fatal(self.ctx.Err())
		}
	}
}

// One interval: the drives write byteCount, the processes tick at its end, and the loop steps when stepping.
func (self *fs61World) interval(byteCount uint64, stepping bool) *evsservice.WriteBudgetAllowance {
	self.t.Helper()
	self.counters.write(byteCount)
	next := self.clock.Now().Add(2 * self.settings.Budget.Interval)
	before := self.timerCount(next)
	self.clock.Advance(self.settings.Budget.Interval)
	self.awaitTimers(next, before+len(self.clients))
	if !stepping {
		return nil
	}
	return self.loop.Step(self.ctx)
}

// The refill r, drive bytes an interval, and the drive writes an interval at dwpd.
func fs61IntervalBytes(settings *evsservice.WriteBudgetSettings, dwpd float64) uint64 {
	return uint64(dwpd * float64(settings.DriveByteCount) / (24 * time.Hour).Seconds() * settings.Interval.Seconds())
}

func TestFs61(t *testing.T) {
	RunRow(t, "FS-61", "", nil)
}

func TestFs61P0ProceedsAtOnceWithItsBytesByKind(t *testing.T) {
	RunRegisteredClause(t, "FS-61", "p0 proceeds at once with its bytes by kind", nil)
}

func TestFs61GovernorKilledProcessesFallBack(t *testing.T) {
	RunRegisteredClause(t, "FS-61", "governor killed processes fall back", nil)
}

func TestFs61BudgetKeysPassTheSchemaGuard(t *testing.T) {
	RunRegisteredClause(t, "FS-61", "budget keys pass the schema guard", nil)
}
