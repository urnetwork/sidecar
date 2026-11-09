package fault

// FS-61 (§22.8, FI-14; EVSB-M2-07), its first clauses on T2: the budget loop over fake drive counters beside
// real process budgets, on one fake clock. The drives are the PM9A3 set's, so the refill is 0.768 DWPD of
// 1.92 TB. The loop steps from the test, and each process ticks on its own goroutine at the interval's end,
// which the test waits out by its next timer, so every step sees what each side has done and nothing races.
//
// Here: allowances fall within 10 s at 0.9 DWPD's rate; P0 issues at once, its bytes by kind, while B is empty
// and T is zero; the governor killed, processes hold their share 60 s, then half, and a new process starts at
// the refill over twice the process count; the {nvb_<set>} keys every process and the loop write pass the
// schema guard's family check. The Pro flood against a Community network's p99 runs in evsservice's
// budget_loop_test.go, which can hold a process's queue between ticks. The 26 h tail is EVSB-M2-16's.

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The busiest drive and one beside it, moved by hand.
type fs61Counters struct {
	stateLock sync.Mutex
	written   [2]uint64
}

func (self *fs61Counters) ReadDriveCounters(ctx context.Context, clusterId string) (*evsservice.DriveCounterReading, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &evsservice.DriveCounterReading{
		Drives: []*evsservice.DriveCounter{
			{DriveId: "0-0-0", WrittenByteCount: self.written[0]},
			{DriveId: "0-0-1", WrittenByteCount: self.written[1]},
		},
	}, nil
}

// The busiest drive writes byteCount, the other a little less.
func (self *fs61Counters) write(byteCount uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.written[0] += byteCount
	self.written[1] += byteCount * 9 / 10
}

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

// Whether a P1 of price priced bytes is admitted now, out of the process's share: a ctx already ended leaves
// the queue at once when the share does not cover it.
func fs61AdmitNow(client *evsservice.WriteBudgetClient, networkId connect.Id, price int64) bool {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	grant, err := client.AdmitP1(ctx, "meta-1", networkId, sidecar.WriteCost{ImmediateByteCount: price})
	if err != nil {
		return false
	}
	grant.Close()
	return true
}

// Spends the process's P1 share in units, returning the priced bytes admitted.
func fs61SpendShare(client *evsservice.WriteBudgetClient, networkId connect.Id, unit int64) int64 {
	var spent int64
	for fs61AdmitNow(client, networkId, unit) {
		spent += unit
	}
	return spent
}

// The refill r, drive bytes an interval, and the drive writes an interval at dwpd.
func fs61IntervalBytes(settings *evsservice.WriteBudgetSettings, dwpd float64) uint64 {
	return uint64(dwpd * float64(settings.DriveByteCount) / (24 * time.Hour).Seconds() * settings.Interval.Seconds())
}

// FS-61: a process spends all of T at exact prices while the drives write what it priced, and then the drives
// write at 0.9 DWPD's rate for the same priced bytes. Within 10 s the allowance in priced bytes has fallen, and
// B with it.
func TestFs61AllowancesFallWithinTenSecondsAtNinetyPercentDwpd(t *testing.T) {
	settings := evsservice.DefaultBudgetLoopSettings()
	depth := int64(settings.Budget.RefillDwpd * float64(settings.Budget.DriveByteCount) / 24)
	world := newFs61World(t, depth)
	networkId := connect.NewId()
	unit := int64(64 * 1024)
	first := world.loop.Step(world.ctx)
	if first == nil {
		t.Fatal("the loop did not publish")
	}
	client := world.addClient()
	refill := fs61IntervalBytes(world.settings.Budget, world.settings.Budget.RefillDwpd)
	// the process takes its share once the loop has seen its report
	world.interval(0, true)
	var steady *evsservice.WriteBudgetAllowance
	for range 6 {
		spent := fs61SpendShare(client, networkId, unit)
		steady = world.interval(uint64(spent), true)
	}
	if steady.TotalByteCount < int64(refill)*9/10 {
		t.Fatalf("steady T %d against a refill of %d", steady.TotalByteCount, refill)
	}
	busy := fs61IntervalBytes(world.settings.Budget, 0.9)
	var fell *evsservice.WriteBudgetAllowance
	for i := range 2 {
		fs61SpendShare(client, networkId, unit)
		allowance := world.interval(busy, true)
		if allowance.TotalByteCount < steady.TotalByteCount && allowance.BucketByteCount < steady.BucketByteCount {
			fell = allowance
			t.Logf("T fell from %d to %d and B from %d to %d in %d s", steady.TotalByteCount, allowance.TotalByteCount, steady.BucketByteCount, allowance.BucketByteCount, 5*(i+1))
			break
		}
	}
	if fell == nil {
		t.Fatal("the allowance did not fall within 10 s")
	}
	if fell.Calibration <= 1 {
		t.Fatalf("k %v after the drives wrote past the priced bytes", fell.Calibration)
	}
}

// FS-61: P0 issues at once while B is empty and T is zero, P1 waits, and P0's bytes come back by kind: in the
// process's issued metric, in the allowance's measured P0 and in its forgiven excess.
func TestFs61P0ProceedsAtOnceWithItsBytesByKind(t *testing.T) {
	world := newFs61World(t, 0)
	world.loop.Step(world.ctx)
	client := world.addClient()
	world.interval(0, true)
	networkId := connect.NewId()
	refill := fs61IntervalBytes(world.settings.Budget, world.settings.Budget.RefillDwpd)
	kinds := []sidecar.WriteP0Kind{sidecar.WriteP0KindRevocation, sidecar.WriteP0KindShred, sidecar.WriteP0KindErasure, sidecar.WriteP0KindRotation}
	var last *evsservice.WriteBudgetAllowance
	for range 4 {
		// a storm of twice the refill, split over four kinds, every write issued on arrival
		for _, kind := range kinds {
			ctx := client.IssueP0(world.ctx, "meta-1", kind, int64(refill)/2)
			if class, ok := sidecar.WriteClassOf(ctx); !ok || class != sidecar.WriteClassP0 {
				t.Fatalf("P0 of kind %s carries class %v", kind, class)
			}
		}
		last = world.interval(2*refill, true)
	}
	if last.TotalByteCount != 0 || last.BucketByteCount != 0 {
		t.Fatalf("T %d and B %d while P0 takes twice the refill", last.TotalByteCount, last.BucketByteCount)
	}
	if fs61AdmitNow(client, networkId, 1) {
		t.Fatal("P1 issued while P0 holds the bucket empty")
	}
	for _, kind := range kinds {
		issued := world.host.Metrics.Value("urnetwork_evs_budget_issued_bytes_total", "meta-1", "p0", string(kind))
		if issued != float64(4*(int64(refill)/2)) {
			t.Errorf("issued P0 of kind %s: %v", kind, issued)
		}
		if last.P0ExcessByteCounts[kind] <= 0 {
			t.Errorf("no forgiven excess counted for kind %s", kind)
		}
		if forgiven := world.host.Metrics.Value("urnetwork_evs_budget_p0_forgiven_bytes_total", "meta-1", string(kind)); forgiven <= 0 {
			t.Errorf("forgiven series for kind %s: %v", kind, forgiven)
		}
	}
	if last.P0MeasuredByteCount < int64(2*refill)*9/10 {
		t.Fatalf("P0 measured %d of twice the refill", last.P0MeasuredByteCount)
	}
}

// FS-61: the governor killed, a process runs its last share for 60 s, then half of it; a process started after
// the kill, which never had an allowance, runs within the refill over twice the process count.
func TestFs61GovernorKilledProcessesFallBack(t *testing.T) {
	settings := evsservice.DefaultBudgetLoopSettings()
	depth := int64(settings.Budget.RefillDwpd * float64(settings.Budget.DriveByteCount) / 24)
	world := newFs61World(t, depth)
	networkId := connect.NewId()
	world.loop.Step(world.ctx)
	client := world.addClient()
	world.interval(0, true)
	world.interval(0, true)
	unit := int64(1024 * 1024)
	share := fs61SpendShare(client, networkId, unit)
	world.interval(uint64(share), true)
	share = fs61SpendShare(client, networkId, unit)
	if share <= 0 {
		t.Fatal("no share before the kill")
	}

	// killed: no step from here on. The process's next tick takes the last allowance the loop published, and
	// from that read it holds the share for FallbackAfter, through the allowance's lapse
	world.interval(0, false)
	if spent := fs61SpendShare(client, networkId, unit); spent != share {
		t.Fatalf("the last allowance gave %d, want %d", spent, share)
	}
	elapsed := time.Duration(0)
	for elapsed+world.settings.Budget.Interval < world.settings.Budget.FallbackAfter {
		world.interval(0, false)
		elapsed += world.settings.Budget.Interval
		if spent := fs61SpendShare(client, networkId, unit); spent != share {
			t.Fatalf("%s after the last fresh allowance the share was %d, want the last %d", elapsed, spent, share)
		}
	}
	world.interval(0, false)
	elapsed += world.settings.Budget.Interval
	half := fs61SpendShare(client, networkId, unit)
	if half < share/2-unit || share/2 < half {
		t.Fatalf("%s after the last fresh allowance the share was %d, want half of %d", elapsed, half, share)
	}

	// a process that never had an allowance: the refill over twice the two processes reporting, as the saved
	// state counts them, P1 taking all but unfunded P2's part
	late := world.addClient()
	refill := fs61IntervalBytes(world.settings.Budget, world.settings.Budget.RefillDwpd)
	total := int64(refill) / (2 * 2)
	want := total - int64(float64(total)*world.settings.Budget.UnfundedShare)
	if spent := fs61SpendShare(late, networkId, 1024); spent < want-1024 || want < spent {
		t.Fatalf("a new process spent %d, want about %d", spent, want)
	}
}

// The keys the loop and every process write to {nvb_<set>} are one family §2.8's evs-10 names, so the schema
// guard's store check passes them: the reports of evs, gkm, api and taskworker processes alike, which differ
// only in their process ids.
func TestFs61BudgetKeysPassTheSchemaGuard(t *testing.T) {
	world := newFs61World(t, -1)
	world.loop.Step(world.ctx)
	for range 4 {
		world.addClient()
	}
	world.interval(1000, true)
	keys := slices.Sorted(func(yield func(string) bool) {
		for key := range world.host.Redis.Dump() {
			if !yield(key) {
				return
			}
		}
	})
	if !slices.Contains(keys, "{nvb_meta-1}") {
		t.Fatalf("no {nvb_meta-1} among %v", keys)
	}
	reports, err := evsservice.ReadWriteBudgetReports(world.ctx, world.host.Redis, "meta-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 4 {
		t.Fatalf("%d reports from four processes", len(reports))
	}
	guard, err := sidecartest.LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := guard.CheckStores(world.ctx, &sidecartest.SchemaGuardStores{RedisKeys: keys})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("the guard refuses the budget's keys: %v", findings)
	}
}
