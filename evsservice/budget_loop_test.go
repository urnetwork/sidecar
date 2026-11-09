package evsservice

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Drives whose counters a test moves by hand.
type testDriveCounters struct {
	stateLock sync.Mutex
	drives    []*DriveCounter
	reading   DriveCounterReading
	err       error
}

func newTestDriveCounters(driveIds ...string) *testDriveCounters {
	counters := &testDriveCounters{}
	for _, driveId := range driveIds {
		counters.drives = append(counters.drives, &DriveCounter{DriveId: driveId})
	}
	return counters
}

func (self *testDriveCounters) ReadDriveCounters(ctx context.Context, clusterId string) (*DriveCounterReading, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return nil, self.err
	}
	reading := self.reading
	reading.Drives = nil
	for _, drive := range self.drives {
		copied := *drive
		reading.Drives = append(reading.Drives, &copied)
	}
	return &reading, nil
}

// Each drive writes byteCounts in turn.
func (self *testDriveCounters) write(byteCounts ...uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i, byteCount := range byteCounts {
		self.drives[i].WrittenByteCount += byteCount
	}
}

func (self *testDriveCounters) drive(i int) *DriveCounter {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.drives[i]
}

// A loop on meta-1 over one fake host, its refill 1,000 drive bytes an interval at k = 1, D 720,000.
type budgetLoopFixture struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	settings *BudgetLoopSettings
	counters *testDriveCounters
}

func newBudgetLoopFixture(t *testing.T) *budgetLoopFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(governorTestStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	settings := DefaultBudgetLoopSettings()
	settings.Budget = governorTestSettings()
	return &budgetLoopFixture{
		t:        t,
		ctx:      ctx,
		clock:    clock,
		host:     host,
		settings: settings,
		counters: newTestDriveCounters("0-0-0", "0-0-1"),
	}
}

func (self *budgetLoopFixture) newLoop() *BudgetLoop {
	self.t.Helper()
	loop, err := NewBudgetLoop(self.host.ServiceHost(), "meta-1", self.counters, nil, self.settings)
	if err != nil {
		self.t.Fatal(err)
	}
	return loop
}

// The allowance in {nvb_meta-1}, nil when none is live.
func (self *budgetLoopFixture) published() *WriteBudgetAllowance {
	self.t.Helper()
	allowance, err := readWriteBudgetAllowance(self.ctx, self.host.Redis, "meta-1")
	if err != nil {
		self.t.Fatal(err)
	}
	return allowance
}

func (self *budgetLoopFixture) savedState() *GovernorState {
	self.t.Helper()
	state, err := LoadGovernorState(self.ctx, self.host.Redis, "meta-1")
	if err != nil {
		self.t.Fatal(err)
	}
	return state
}

// One interval later, the loop steps.
func (self *budgetLoopFixture) step(loop *BudgetLoop) *WriteBudgetAllowance {
	self.clock.Advance(self.settings.Budget.Interval)
	return loop.Step(self.ctx)
}

// A loop with no saved state publishes from B = 0 and saves the readings it took.
func TestBudgetLoopPublishesAndSavesEachStep(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	loop := fixture.newLoop()
	allowance := loop.Step(fixture.ctx)
	if allowance == nil || !loop.Holding() {
		t.Fatal("the first step published nothing")
	}
	// B starts at zero, its floor, and gains one interval of refill: the first reading is a baseline
	if allowance.BucketByteCount != 1000 {
		t.Fatalf("B %d, want 1000", allowance.BucketByteCount)
	}
	if fixture.published() == nil {
		t.Fatal("no allowance in {nvb_meta-1}")
	}
	fixture.counters.write(400, 300)
	allowance = fixture.step(loop)
	if allowance.MeasuredByteCount != 400 || allowance.BucketByteCount != 1600 {
		t.Fatalf("measured %d and B %d, want 400 and 1600", allowance.MeasuredByteCount, allowance.BucketByteCount)
	}
	state := fixture.savedState()
	if state.BucketByteCount != 1600 || state.CounterReadings["0-0-0"] != 400 || state.CounterReadings["0-0-1"] != 300 {
		t.Fatalf("saved B %d and readings %v", state.BucketByteCount, state.CounterReadings)
	}
}

// A new holder resumes B, W and the readings exactly, so the bucket continues as if one loop ran on.
func TestBudgetLoopResumesAcrossALeaseChange(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	first := fixture.newLoop()
	first.Step(fixture.ctx)
	for range 5 {
		fixture.counters.write(200, 100)
		fixture.step(first)
	}
	before := fixture.savedState()
	if err := releaseBudgetLease(fixture.ctx, fixture.host.Redis, "meta-1", first.holderId); err != nil {
		t.Fatal(err)
	}

	second := fixture.newLoop()
	fixture.counters.write(500, 100)
	allowance := fixture.step(second)
	if allowance == nil {
		t.Fatal("the new holder published nothing")
	}
	// the readings carried over, so the 500 written meanwhile drains B, and no write is forgotten or new
	want := before.BucketByteCount + 1000 - 500
	if allowance.MeasuredByteCount != 500 || allowance.BucketByteCount != want {
		t.Fatalf("measured %d and B %d, want 500 and %d", allowance.MeasuredByteCount, allowance.BucketByteCount, want)
	}
	if allowance.Seq != before.Seq+1 {
		t.Fatalf("seq %d after %d", allowance.Seq, before.Seq)
	}
}

// One loop holds the lease; another publishes nothing until the first stops renewing and its ttl lapses.
func TestBudgetLoopLeaseHeldElsewherePublishesNothing(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	first := fixture.newLoop()
	second := fixture.newLoop()
	if first.Step(fixture.ctx) == nil {
		t.Fatal("the first loop did not publish")
	}
	if second.Step(fixture.ctx) != nil || second.Holding() {
		t.Fatal("a second loop stepped beside the holder")
	}
	// the first stops renewing: within the lease's ttl the second takes over
	fixture.clock.Advance(fixture.settings.LeaseTtl)
	if second.Step(fixture.ctx) == nil {
		t.Fatal("the second loop did not take the lapsed lease")
	}
	if first.Step(fixture.ctx) != nil || first.Holding() {
		t.Fatal("the first loop stepped after losing the lease")
	}
}

// A drive under heal takes the heal's writes, so the busiest of the others drains B.
func TestBudgetLoopSkipsAHealingDrive(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	loop := fixture.newLoop()
	loop.Step(fixture.ctx)
	fixture.counters.drive(0).Healing = true
	fixture.counters.write(50000, 300)
	allowance := fixture.step(loop)
	if allowance.MeasuredByteCount != 300 {
		t.Fatalf("measured %d, want the drive not under heal's 300", allowance.MeasuredByteCount)
	}
}

// A counter that falls is a reboot: a fresh baseline, never a credit.
func TestBudgetLoopCounterResetIsABaseline(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	loop := fixture.newLoop()
	loop.Step(fixture.ctx)
	fixture.counters.write(900, 900)
	fixture.step(loop)
	fixture.counters.drive(0).WrittenByteCount = 10
	fixture.counters.write(0, 200)
	allowance := fixture.step(loop)
	if allowance.MeasuredByteCount != 200 {
		t.Fatalf("measured %d, want the other drive's 200", allowance.MeasuredByteCount)
	}
	if state := fixture.savedState(); state.CounterReadings["0-0-0"] != 10 {
		t.Fatalf("the fallen counter's baseline is %d", state.CounterReadings["0-0-0"])
	}
	fixture.counters.write(70, 0)
	if allowance := fixture.step(loop); allowance.MeasuredByteCount != 70 {
		t.Fatalf("measured %d after the baseline, want 70", allowance.MeasuredByteCount)
	}
}

// A drive not under heal with no reading publishes nothing, and the step that reads it again drains B by all
// it wrote meanwhile.
func TestBudgetLoopMissingDrivePublishesNothing(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	loop := fixture.newLoop()
	loop.Step(fixture.ctx)
	before := fixture.savedState()
	fixture.counters.drive(1).Missing = true
	fixture.counters.write(300, 300)
	if allowance := fixture.step(loop); allowance != nil {
		t.Fatal("published with a drive missing")
	}
	if state := fixture.savedState(); state.Seq != before.Seq || state.CounterReadings["0-0-0"] != 0 {
		t.Fatal("a step with a drive missing saved a state")
	}
	// past the allowance's ttl the processes find none and take the fallback row
	fixture.clock.Advance(fixture.settings.Budget.AllowanceTtl)
	if fixture.published() != nil {
		t.Fatal("an allowance outlived its ttl")
	}
	fixture.counters.drive(1).Missing = false
	fixture.counters.write(400, 0)
	allowance := fixture.step(loop)
	if allowance == nil || allowance.MeasuredByteCount != 700 {
		t.Fatalf("the step after the gap measured %v", allowance)
	}
	// one interval's refill against everything written: B errs low
	if allowance.BucketByteCount != max(0, before.BucketByteCount+1000-700) {
		t.Fatalf("B %d after the gap", allowance.BucketByteCount)
	}
}

// A healing drive with no reading does not hold the others back, and a source that fails publishes nothing.
func TestBudgetLoopMissingHealingDriveStillPublishes(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	loop := fixture.newLoop()
	loop.Step(fixture.ctx)
	fixture.counters.drive(0).Healing = true
	fixture.counters.drive(0).Missing = true
	fixture.counters.write(0, 250)
	if allowance := fixture.step(loop); allowance == nil || allowance.MeasuredByteCount != 250 {
		t.Fatalf("published %v", allowance)
	}
	fixture.counters.err = context.DeadlineExceeded
	if allowance := fixture.step(loop); allowance != nil {
		t.Fatal("published with no counters")
	}
}

// §19.9's at_limit from admin info's use, kept while admin info is unread.
func TestBudgetLoopSetsAtLimit(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	loop := fixture.newLoop()
	fixture.counters.reading = DriveCounterReading{UsageKnown: true, RawUsageByteCount: 81, RawCapacityByteCount: 100}
	if allowance := loop.Step(fixture.ctx); !allowance.AtLimit {
		t.Fatal("81% raw use is not at the limit")
	}
	fixture.counters.reading = DriveCounterReading{}
	if allowance := fixture.step(loop); !allowance.AtLimit {
		t.Fatal("an unread admin info dropped the last value")
	}
	fixture.counters.reading = DriveCounterReading{UsageKnown: true, RawUsageByteCount: 10, RawCapacityByteCount: 100, UsedInodeCount: 69, FreeInodeCount: 31}
	if allowance := fixture.step(loop); allowance.AtLimit {
		t.Fatal("69% of inodes is at the limit")
	}
	fixture.counters.reading = DriveCounterReading{UsageKnown: true, UsedInodeCount: 70, FreeInodeCount: 30}
	if allowance := fixture.step(loop); !allowance.AtLimit {
		t.Fatal("70% of inodes is not at the limit")
	}
}

// Puts a batch of byteCount bytes on meta-1 in minute.
func putTestBatch(t *testing.T, host *sidecartest.FakeHost, minute uint32, seq uint32, byteCount int) string {
	t.Helper()
	cluster, err := host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	key := BatchKey(minute, 7, seq)
	if _, err := cluster.PutIfNoneMatch(sidecar.WithWriteClass(t.Context(), sidecar.WriteClassP1), key, make([]byte, byteCount), nil); err != nil {
		t.Fatal(err)
	}
	return key
}

// The trap: credit for evacuation stays in W while its batches stand on the cluster, though no process reports
// that work queued, and lapses once evacuation has deleted them.
func TestBudgetLoopKeepsEvacuationsCreditWhileItsBatchesStand(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	loop := fixture.newLoop()
	now := fixture.clock.Now()
	oldMinute := BatchMinute(now.Add(-24 * time.Hour))
	key := putTestBatch(t, fixture.host, oldMinute, 1, 2048)
	putTestBatch(t, fixture.host, oldMinute+1, 1, 2048)
	// a batch of the minute now is not settled, so it is not listed yet
	putTestBatch(t, fixture.host, BatchMinute(now), 1, 2048)

	// one process admitted pushes whose deferred part moved 30,000 into W, and reports no P2 work
	report := &WriteBudgetReport{ProcessId: "p1", StartMs: now.UnixMilli(), TimeMs: now.UnixMilli()}
	writeReport := func() {
		report.TimeMs = fixture.clock.Now().UnixMilli()
		if err := writeWriteBudgetReport(fixture.ctx, fixture.host.Redis, fixture.settings.Budget, "meta-1", report); err != nil {
			t.Fatal(err)
		}
	}
	writeReport()
	loop.Step(fixture.ctx)
	report.CreditByteCount = 30000
	writeReport()
	allowance := fixture.step(loop)
	batchCost := evacuationBatchCost(fixture.settings.Budget.PriceTable, 2048)
	if allowance.FundedBacklogByteCount != 2*batchCost {
		t.Fatalf("funded backlog %d, want two batches' %d", allowance.FundedBacklogByteCount, 2*batchCost)
	}
	if allowance.WalletByteCount != min(30000, 2*batchCost) {
		t.Fatalf("W %d, want the credit clamped to the batches standing", allowance.WalletByteCount)
	}

	// evacuation deletes the first minute once it is past 25 h, and the relist finds it gone
	cluster, err := fixture.host.Blobs.Cluster("meta-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := cluster.Delete(sidecar.WithWriteClass(fixture.ctx, sidecar.WriteClassP2), key); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(fixture.settings.BatchRelistAge)
	writeReport()
	allowance = fixture.step(loop)
	if allowance.FundedBacklogByteCount != 2*batchCost {
		t.Fatalf("funded backlog %d once both minutes are due a relist", allowance.FundedBacklogByteCount)
	}
	// both old minutes are relisted over the next steps: the deleted one drops, and the settled new one is
	// listed by the cursor
	for range 3 {
		writeReport()
		allowance = fixture.step(loop)
	}
	if allowance.FundedBacklogByteCount != 2*batchCost {
		t.Fatalf("funded backlog %d, want the second old minute and the newer one", allowance.FundedBacklogByteCount)
	}
}

// Every LIST of a step is bounded, so a long backlog is listed over several steps.
func TestBudgetLoopListsALongBacklogInBoundedSteps(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	fixture.settings.BatchListLimit = 2
	fixture.settings.BatchListPageCount = 2
	loop := fixture.newLoop()
	start := BatchMinute(fixture.clock.Now().Add(-2 * time.Hour))
	for i := range uint32(10) {
		putTestBatch(t, fixture.host, start+i, 1, 100)
	}
	listCount := func() int {
		return fixture.host.Blobs.RequestCount("meta-1", "list")
	}
	before := listCount()
	loop.Step(fixture.ctx)
	if got := listCount() - before; got != 2 {
		t.Fatalf("a step made %d LISTs, want 2", got)
	}
	if got := loop.batches.costByteCount(); got != 4*evacuationBatchCost(fixture.settings.Budget.PriceTable, 100) {
		t.Fatalf("after one step the backlog holds %d", got)
	}
	for range 3 {
		fixture.step(loop)
	}
	if got := loop.batches.costByteCount(); got != 10*evacuationBatchCost(fixture.settings.Budget.PriceTable, 100) {
		t.Fatalf("after four steps the backlog holds %d", got)
	}
}

// §19.8's series: B, P0's forgiven excess by kind, the refill ratio, a liability and its drain time, and the
// busiest drive's DWPD.
func TestBudgetLoopExportsTheBudgetSeries(t *testing.T) {
	fixture := newBudgetLoopFixture(t)
	loop := fixture.newLoop()
	now := fixture.clock.Now()
	report := &WriteBudgetReport{ProcessId: "p1", StartMs: now.UnixMilli(), TimeMs: now.UnixMilli()}
	writeReport := func() {
		report.TimeMs = fixture.clock.Now().UnixMilli()
		if err := writeWriteBudgetReport(fixture.ctx, fixture.host.Redis, fixture.settings.Budget, "meta-1", report); err != nil {
			t.Fatal(err)
		}
	}
	writeReport()
	loop.Step(fixture.ctx)
	// P0 rotations write 5,000 in an interval B enters at 1,000 and refills by 1,000: the 3,000 past what B
	// held is forgiven
	report.P0ByteCounts = map[sidecar.WriteP0Kind]int64{sidecar.WriteP0KindRotation: 5000}
	report.P1QueuedByteCount = 800
	writeReport()
	fixture.counters.write(5000, 10)
	allowance := fixture.step(loop)
	if allowance.BucketByteCount != 0 {
		t.Fatalf("B %d, want 0", allowance.BucketByteCount)
	}
	metrics := fixture.host.Metrics
	if got := metrics.Value(budgetBucketMetricName, "meta-1"); got != 0 {
		t.Errorf("bucket gauge %v", got)
	}
	if got := metrics.Value(budgetP0ForgivenMetricName, "meta-1", "rotation"); got != 3000 {
		t.Errorf("forgiven %v, want 3000", got)
	}
	// two steps of refill in the window, 5,000 of P0
	if got := metrics.Value(budgetP0RefillRatioMetricName, "meta-1"); math.Abs(got-2.5) > 1e-9 {
		t.Errorf("refill ratio %v, want 2.5", got)
	}
	if got := metrics.Value(budgetLiabilityMetricName, "meta-1", "p1_queued"); got != 800 {
		t.Errorf("queued P1 liability %v", got)
	}
	if got := metrics.Value(budgetDrainMetricName, "meta-1", "p1_queued"); !math.IsInf(got, 1) {
		t.Errorf("drain %v with nothing admitted in the window, want +Inf", got)
	}
	// an hour of steps later the 24 h window has its first snapshot an hour back
	for range 720 {
		fixture.counters.write(1000, 10)
		writeReport()
		fixture.step(loop)
	}
	got := metrics.Value(fileClusterDriveDwpdMetricName, "meta-1", "24h")
	want := float64(720*1000) / float64(fixture.settings.Budget.DriveByteCount) / (1.0 / 24)
	if math.Abs(got-want) > want*0.01 {
		t.Errorf("24h DWPD %v, want about %v", got, want)
	}
	if violations := metrics.Violations(); len(violations) != 0 {
		t.Errorf("metric rules broken: %v", violations)
	}
}

// FS-61's flood clause: a Pro network flooding pushes is refused first, 429 with retry_after_ms, its refused
// pushes moving no P2 work into the wallet, while a Community network's one push an interval is admitted
// within the interval it asked in. Here and not in sidecartest/fault, since the schedule holds the process's
// queue between its ticks.
func TestFs61ProFloodIsRefusedFirstWhileCommunityKeepsItsP99(t *testing.T) {
	fixture := newBudgetFixture(t)
	pro := connect.NewId()
	community := connect.NewId()
	fixture.host.Quota.SetLimits(pro, &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{"store_weight": 4}})
	fixture.host.Quota.SetLimits(community, &sidecar.QuotaLimits{Tier: "free", Limits: map[string]int64{"store_weight": 1}})
	fixture.client.weights.weight(pro, fixture.clock.Now())
	fixture.client.weights.weight(community, fixture.clock.Now())
	fixture.client.weights.refresh(t.Context(), fixture.clock)
	fixture.warm(1000)
	cost := sidecar.WriteCost{ImmediateByteCount: 60, DeferredByteCount: 40}

	var admittedCredit int64
	var proRefused, proAdmitted int
	var communityWaits []time.Duration
	for range 10 {
		share := fixture.left().P1ByteCount
		started := fixture.clock.Now()
		pros := []*pendingAdmission{}
		for range 30 {
			pros = append(pros, fixture.admitAsync(t.Context(), pro, cost))
		}
		// the share admits its pushes at once and the rest of the flood waits
		atOnce := int(share / cost.ByteCount())
		fixture.awaitWaits(fixture.waitSeen + 30 - atOnce)
		communityPush := fixture.admitAsync(t.Context(), community, cost)
		fixture.awaitWaits(fixture.waitSeen + 1)
		// past the shed delay the heaviest network by queued bytes per weight is refused whole
		fixture.clock.Advance(fixture.settings.ShedDelay)
		for _, pending := range pros {
			pending.wait(t)
			refusal := &sidecar.WriteRefusal{}
			switch {
			case pending.err == nil:
				proAdmitted += 1
				admittedCredit += cost.DeferredByteCount
				pending.grant.Close()
			case errors.As(pending.err, &refusal) && refusal.RetryAfterMs() == 5000:
				proRefused += 1
			default:
				t.Fatalf("a Pro push ended %v", pending.err)
			}
		}
		if communityPush.decided() {
			t.Fatal("the Community push was decided before the next share")
		}
		fixture.interval(cost.ImmediateByteCount * int64(atOnce+1))
		communityPush.wait(t)
		if communityPush.err != nil {
			t.Fatalf("the Community push was refused: %v", communityPush.err)
		}
		communityPush.grant.Close()
		admittedCredit += cost.DeferredByteCount
		communityWaits = append(communityWaits, fixture.clock.Now().Sub(started))
	}
	if proRefused == 0 || proAdmitted == 0 {
		t.Fatalf("Pro: %d admitted, %d refused", proAdmitted, proRefused)
	}
	for _, wait := range communityWaits {
		if fixture.settings.Interval+fixture.settings.ShedDelay < wait {
			t.Fatalf("a Community push waited %s", wait)
		}
	}
	// a refused push moved nothing into credit, so the P2 work it would have caused is shed with it
	if report := fixture.report(); report.CreditByteCount != admittedCredit {
		t.Fatalf("credit %d, want the admitted pushes' %d", report.CreditByteCount, admittedCredit)
	}
}
