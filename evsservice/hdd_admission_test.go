package evsservice

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An admission on seg-1 whose goroutine the test drives, with figures written as the hdd loop would.
type hddFixture struct {
	t         *testing.T
	ctx       context.Context
	clock     *sidecartest.FakeClock
	host      *sidecartest.FakeHost
	admission *HddAdmission
}

func newHddFixture(t *testing.T) *hddFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(governorTestStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	admission, err := newHddAdmission(ctx, host.ServiceHost(), "seg-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admission.Close)
	return &hddFixture{t: t, ctx: ctx, clock: clock, host: host, admission: admission}
}

// Publishes figures as the hdd loop does.
func (self *hddFixture) figures(driveOps float64, capacityOps int64) {
	self.t.Helper()
	figures := &HddFigures{ClusterId: "seg-1", TimeMs: self.clock.Now().UnixMilli(), DriveOpsPerSecond: driveOps, CapacityOps: capacityOps}
	if err := publishHddFigures(self.ctx, self.host.Redis, figures, 15*time.Second); err != nil {
		self.t.Fatal(err)
	}
}

// One interval of the admission's goroutine: the weights' reread, then the tick, as run does.
func (self *hddFixture) tick() {
	self.clock.Advance(self.admission.settings.Interval)
	self.admission.weights.refresh(self.ctx, self.clock)
	self.admission.tick(self.ctx)
}

func (self *hddFixture) refused(networkId connect.Id, class HddUploadClass) bool {
	self.t.Helper()
	err := self.admission.Admit(networkId, 1024, class)
	if err == nil {
		return false
	}
	refusal := &HddRefusal{}
	if !errors.As(err, &refusal) || refusal.ClusterId != "seg-1" || refusal.RetryAfter != 5*time.Second {
		self.t.Fatalf("refused with %v", err)
	}
	return true
}

// Past the line the heaviest network by bytes per weight is refused first, and the lighter ones pass.
func TestHddAdmissionRefusesTheHeaviestNetworkFirst(t *testing.T) {
	fixture := newHddFixture(t)
	heavy := connect.NewId()
	light := connect.NewId()
	team := connect.NewId()
	fixture.host.Quota.SetLimits(team, &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{"store_weight": 16}})
	fixture.admission.weights.weight(team, fixture.clock.Now())
	fixture.admission.weights.refresh(fixture.ctx, fixture.clock)
	if err := fixture.admission.Admit(heavy, 9000, HddUploadOrdinary); err != nil {
		t.Fatal(err)
	}
	if err := fixture.admission.Admit(light, 1000, HddUploadOrdinary); err != nil {
		t.Fatal(err)
	}
	// a Team network uploading more than the heavy one, but less per its weight
	if err := fixture.admission.Admit(team, 16000, HddUploadOrdinary); err != nil {
		t.Fatal(err)
	}
	// 600 of a capacity of 1,000: a sixth of the operations are past the line, and the heavy network's
	// 9,000 of 26,000 bytes covers it
	fixture.figures(600, 1000)
	fixture.tick()
	if !fixture.refused(heavy, HddUploadOrdinary) {
		t.Fatal("the heaviest network was admitted")
	}
	if fixture.refused(light, HddUploadOrdinary) || fixture.refused(team, HddUploadOrdinary) {
		t.Fatal("a lighter network was refused")
	}
	if got := fixture.host.Metrics.Value(hddAdmissionRefusedMetricName, "seg-1"); got != 1 {
		t.Fatalf("refusals counted %v", got)
	}

	// further past the line the next heaviest goes too
	fixture.figures(900, 1000)
	fixture.tick()
	if !fixture.refused(heavy, HddUploadOrdinary) || !fixture.refused(team, HddUploadOrdinary) {
		t.Fatal("the next heaviest network was admitted far past the line")
	}
}

// Authorization, deletion, shredding, erasure and closure uploads pass at the line.
func TestHddAdmissionPassesEachExemptClassAtTheLine(t *testing.T) {
	fixture := newHddFixture(t)
	heavy := connect.NewId()
	if err := fixture.admission.Admit(heavy, 9000, HddUploadOrdinary); err != nil {
		t.Fatal(err)
	}
	fixture.figures(1000, 1000)
	fixture.tick()
	if !fixture.refused(heavy, HddUploadOrdinary) {
		t.Fatal("an ordinary upload passed past the line")
	}
	for _, class := range []HddUploadClass{HddUploadAuthorization, HddUploadDeletion, HddUploadShredding, HddUploadErasure, HddUploadClosure} {
		if fixture.refused(heavy, class) {
			t.Errorf("class %d refused at the line", class)
		}
	}
}

// With no capacity published, or no live figures at all, nothing is refused however busy the drives are.
func TestHddAdmissionWithNoCapacityRefusesNothing(t *testing.T) {
	fixture := newHddFixture(t)
	heavy := connect.NewId()
	if err := fixture.admission.Admit(heavy, 9000, HddUploadOrdinary); err != nil {
		t.Fatal(err)
	}
	fixture.figures(1000000, 0)
	fixture.tick()
	if fixture.refused(heavy, HddUploadOrdinary) {
		t.Fatal("refused with no capacity set")
	}
	fixture.figures(1000, 1000)
	fixture.tick()
	if !fixture.refused(heavy, HddUploadOrdinary) {
		t.Fatal("admitted past the line")
	}
	// the loop stops: once its figures' ttl ends the admission refuses no one
	fixture.clock.Advance(15 * time.Second)
	fixture.tick()
	if fixture.refused(heavy, HddUploadOrdinary) {
		t.Fatal("refused on figures past their ttl")
	}
}

// Admit and CountPut make no Redis op: the figures come in, and the PUT report goes out, on the admission's own
// interval.
func TestHddAdmissionInlinePathMakesNoRedisOp(t *testing.T) {
	fixture := newHddFixture(t)
	fixture.figures(1000, 1000)
	networkId := connect.NewId()
	fixture.admission.Admit(networkId, 100, HddUploadOrdinary)
	fixture.tick()
	fixture.host.Redis.ResetOpCounts()
	for range 1000 {
		fixture.admission.Admit(networkId, 100, HddUploadOrdinary)
		fixture.admission.Admit(connect.NewId(), 100, HddUploadErasure)
		fixture.admission.CountPut()
	}
	if counts := fixture.host.Redis.OpCounts(); len(counts) != 0 {
		t.Fatalf("Admit or CountPut made Redis ops: %v", counts)
	}
	// the interval carries the count out
	fixture.tick()
	reports, err := readHddPutReports(fixture.ctx, fixture.host.Redis, "seg-1")
	if err != nil || len(reports) != 1 || reports[0].PutCount != 1000 || reports[0].ProcessId != fixture.admission.processId {
		t.Fatalf("reports %+v %v, want this process's 1,000 PUTs", reports, err)
	}
}

// A segment cluster's HDD counters, moved by hand.
type testHddCounters struct {
	stateLock sync.Mutex
	drives    []*DriveCounter
}

func (self *testHddCounters) ReadDriveCounters(ctx context.Context, clusterId string) (*DriveCounterReading, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reading := &DriveCounterReading{}
	for _, drive := range self.drives {
		copied := *drive
		reading.Drives = append(reading.Drives, &copied)
	}
	return reading, nil
}

func (self *testHddCounters) operate(reads uint64, writes uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, drive := range self.drives {
		drive.ReadsCompleted += reads
		drive.WritesCompleted += writes
	}
}

// The loop holds the cluster's lease, publishes its drive operations a second with a 15 s ttl and the capacity
// sidecar.yml sets, publishes no capacity before one is set, and nothing while a drive's reading is missing.
func TestHddLoopPublishesUnderItsLeaseWithItsTtl(t *testing.T) {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(governorTestStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	counters := &testHddCounters{drives: []*DriveCounter{{DriveId: "0-0-0"}, {DriveId: "0-0-1"}}}
	loop, err := NewHddLoop(host.ServiceHost(), "seg-1", counters, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewHddLoop(host.ServiceHost(), "seg-1", counters, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// the first reading is a baseline
	if loop.Step(ctx) != nil || !loop.Holding() {
		t.Fatal("published from a baseline, or took no lease")
	}
	if other.Step(ctx) != nil || other.Holding() {
		t.Fatal("a second loop stepped beside the holder")
	}
	counters.operate(30, 20)
	clock.Advance(5 * time.Second)
	figures := loop.Step(ctx)
	if figures == nil || figures.DriveOpsPerSecond != 20 || figures.CapacityOps != 0 {
		t.Fatalf("figures %+v, want 20 operations a second and no capacity", figures)
	}
	if err := host.Gates.Set("sidecar:\n  file_clusters:\n    seg-1:\n      hdd_capacity_ops: 4000\n"); err != nil {
		t.Fatal(err)
	}
	counters.operate(10, 0)
	clock.Advance(5 * time.Second)
	if figures := loop.Step(ctx); figures == nil || figures.DriveOpsPerSecond != 4 || figures.CapacityOps != 4000 {
		t.Fatalf("figures %+v", figures)
	}
	if got := host.Metrics.Value(hddCapacityMetricName, "seg-1"); got != 4000 {
		t.Fatalf("capacity gauge %v", got)
	}

	// a missing drive publishes nothing, and the next rate spans the gap
	counters.drives[1].Missing = true
	counters.operate(25, 25)
	clock.Advance(5 * time.Second)
	if loop.Step(ctx) != nil {
		t.Fatal("published with a drive missing")
	}
	counters.drives[1].Missing = false
	clock.Advance(5 * time.Second)
	if figures := loop.Step(ctx); figures == nil || figures.DriveOpsPerSecond != 10 {
		t.Fatalf("figures after the gap %+v, want 100 operations over 10 s", figures)
	}
	// the figures lapse 15 s after the loop stops
	clock.Advance(15 * time.Second)
	if figures, err := readHddFigures(ctx, host.Redis, "seg-1"); err != nil || figures != nil {
		t.Fatalf("figures outlived their ttl: %+v %v", figures, err)
	}
	// and the other loop takes the lapsed lease, taking its own baseline first
	if other.Step(ctx) != nil || !other.Holding() {
		t.Fatal("the other loop did not take the lapsed lease")
	}
}

// A segment cluster with an hdd loop and no evs process yet, the loop not yet stepped.
type hddPutsFixture struct {
	t     *testing.T
	ctx   context.Context
	clock *sidecartest.FakeClock
	host  *sidecartest.FakeHost
	loop  *HddLoop
}

func newHddPutsFixture(t *testing.T) *hddPutsFixture {
	ctx := t.Context()
	clock := sidecartest.NewFakeClock(governorTestStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	loop, err := NewHddLoop(host.ServiceHost(), "seg-1", &testHddCounters{drives: []*DriveCounter{{DriveId: "0-0-0"}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &hddPutsFixture{t: t, ctx: ctx, clock: clock, host: host, loop: loop}
}

// An evs process's admission on seg-1, its goroutine driven by the test.
func (self *hddPutsFixture) process() *HddAdmission {
	self.t.Helper()
	admission, err := newHddAdmission(self.ctx, self.host.ServiceHost(), "seg-1", nil)
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(admission.Close)
	return admission
}

// Whether the puts gauge was ever set: FakeMetrics reads a series never set as zero.
func (self *hddPutsFixture) gaugeSet() bool {
	return slices.Contains(self.host.Metrics.Dump(), hddPutsMetricName+" seg-1")
}

func (self *hddPutsFixture) gauge() float64 {
	return self.host.Metrics.Value(hddPutsMetricName, "seg-1")
}

// count PUTs stored for admission.
func countHddPuts(admission *HddAdmission, count int) {
	for range count {
		admission.CountPut()
	}
}

// The loop sums each process's segment PUTs a second over the span between that process's own last two reports,
// counts a process started since its last step from that start, keeps a rate until the next report lands, and
// sums a process no longer once its report lapses.
func TestHddLoopSumsEachProcessesPutsOverItsOwnReports(t *testing.T) {
	fixture := newHddPutsFixture(t)
	step := func(want float64) {
		t.Helper()
		fixture.loop.Step(fixture.ctx)
		if got := fixture.gauge(); got != want {
			t.Fatalf("%v PUTs a second, want %v", got, want)
		}
	}
	// with no evs process reporting, the cluster stores no PUTs
	step(0)
	if !fixture.gaugeSet() {
		t.Fatal("no zero set with no process reporting")
	}
	first := fixture.process()
	second := fixture.process()

	// both started at the loop's last step, so everything they counted is new: 30 and 20 over 5 s
	countHddPuts(first, 30)
	countHddPuts(second, 20)
	fixture.clock.Advance(5 * time.Second)
	first.tick(fixture.ctx)
	second.tick(fixture.ctx)
	step(10)

	countHddPuts(first, 10)
	fixture.clock.Advance(5 * time.Second)
	first.tick(fixture.ctx)
	second.tick(fixture.ctx)
	step(2)

	// the second's report runs late: its rate of none stands until it lands, and then spans its own 10 s
	countHddPuts(second, 10)
	fixture.clock.Advance(5 * time.Second)
	first.tick(fixture.ctx)
	step(0)
	fixture.clock.Advance(5 * time.Second)
	first.tick(fixture.ctx)
	second.tick(fixture.ctx)
	step(1)

	// the second stops: once its report's ttl ends, the first's 3 a second is the sum
	second.Close()
	for range 4 {
		countHddPuts(first, 15)
		fixture.clock.Advance(5 * time.Second)
		first.tick(fixture.ctx)
		fixture.loop.Step(fixture.ctx)
	}
	if got := fixture.gauge(); got != 3 {
		t.Fatalf("%v PUTs a second after the second process stopped, want 3", got)
	}
	reports, err := readHddPutReports(fixture.ctx, fixture.host.Redis, "seg-1")
	if err != nil || len(reports) != 1 || reports[0].ProcessId != first.processId {
		t.Fatalf("reports %+v %v, want the first's alone", reports, err)
	}
}

// A loop that takes the lease has only baselines, so it leaves the gauge as it was until each live process has a
// rate, rather than publishing a sum that is not the cluster's.
func TestHddLoopLeavesThePutsGaugeOnBaselines(t *testing.T) {
	fixture := newHddPutsFixture(t)
	other, err := NewHddLoop(fixture.host.ServiceHost(), "seg-1", &testHddCounters{drives: []*DriveCounter{{DriveId: "0-0-0"}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	process := fixture.process()
	fixture.loop.Step(fixture.ctx)
	countHddPuts(process, 50)
	fixture.clock.Advance(5 * time.Second)
	process.tick(fixture.ctx)
	fixture.loop.Step(fixture.ctx)
	if got := fixture.gauge(); got != 10 {
		t.Fatalf("%v PUTs a second, want 10", got)
	}

	// the first loop stops; the process goes on at 1 a second while the lease lapses
	for range 4 {
		countHddPuts(process, 5)
		fixture.clock.Advance(5 * time.Second)
		process.tick(fixture.ctx)
	}
	if other.Step(fixture.ctx); !other.Holding() {
		t.Fatal("the other loop did not take the lapsed lease")
	}
	if got := fixture.gauge(); got != 10 {
		t.Fatalf("a new holder set %v from a baseline", got)
	}
	countHddPuts(process, 5)
	fixture.clock.Advance(5 * time.Second)
	process.tick(fixture.ctx)
	other.Step(fixture.ctx)
	if got := fixture.gauge(); got != 1 {
		t.Fatalf("%v PUTs a second, want 1", got)
	}
}

// Each case the loop meets in one process's reports: a rate over its own span, a report not yet replaced, a
// process started since the last step, and a count that fell or a clock that went back, each a baseline.
func TestHddLoopRatesEachReportCase(t *testing.T) {
	fixture := newHddPutsFixture(t)
	startMs := fixture.clock.Now().UnixMilli()
	report := func(processId string, processStartMs int64, timeMs int64, putCount int64) {
		t.Helper()
		putReport := &HddPutReport{ProcessId: processId, StartMs: processStartMs, TimeMs: timeMs, PutCount: putCount}
		if err := writeHddPutReport(fixture.ctx, fixture.host.Redis, "seg-1", putReport, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	stepPuts := func(want float64, wantComplete bool) {
		t.Helper()
		got, complete := fixture.loop.stepPuts(fixture.ctx, fixture.clock.Now())
		if complete != wantComplete || (complete && got != want) {
			t.Fatalf("%v PUTs a second, complete %t; want %v, %t", got, complete, want, wantComplete)
		}
	}

	// a process running before the loop's first step is a baseline there
	report("steady", startMs-60000, startMs, 100)
	stepPuts(0, false)
	// 20 over its own 4 s, and one started since the step, 8 over the 4 s it ran
	fixture.clock.Advance(5 * time.Second)
	report("steady", startMs-60000, startMs+4000, 120)
	report("young", startMs+1000, startMs+5000, 8)
	stepPuts(7, true)
	// no new report from steady, so its 5 stands; young's count fell, a baseline
	fixture.clock.Advance(5 * time.Second)
	report("young", startMs+1000, startMs+10000, 3)
	stepPuts(0, false)
	// young is rated again; steady's clock went back, a baseline
	fixture.clock.Advance(5 * time.Second)
	report("young", startMs+1000, startMs+15000, 13)
	report("steady", startMs-60000, startMs+3000, 130)
	stepPuts(0, false)
	fixture.clock.Advance(5 * time.Second)
	report("young", startMs+1000, startMs+20000, 23)
	report("steady", startMs-60000, startMs+19000, 146)
	stepPuts(3, true)
}

// A report whose ttl never landed, from a process that died between its write and its ttl, holds the gauge as a
// baseline until it is past the loop's bound, and is then dropped and its field deleted, so nothing stands in
// {nvb_} past its published ttl.
func TestHddLoopDeletesAPutReportPastItsTtl(t *testing.T) {
	fixture := newHddPutsFixture(t)
	fixture.loop.Step(fixture.ctx)
	nowMs := fixture.clock.Now().UnixMilli()
	encoded, err := json.Marshal(&HddPutReport{ProcessId: "dead", StartMs: nowMs - 60000, TimeMs: nowMs, PutCount: 100})
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.host.Redis.HashSet(fixture.ctx, writeBudgetKey("seg-1"), map[string][]byte{hddPutReportFieldPrefix + "dead": encoded}); err != nil {
		t.Fatal(err)
	}
	live := fixture.process()
	for range 3 {
		countHddPuts(live, 5)
		fixture.clock.Advance(5 * time.Second)
		live.tick(fixture.ctx)
		fixture.loop.Step(fixture.ctx)
		if got := fixture.gauge(); got != 0 {
			t.Fatalf("set %v while a process was a baseline", got)
		}
	}
	countHddPuts(live, 5)
	fixture.clock.Advance(5 * time.Second)
	live.tick(fixture.ctx)
	fixture.loop.Step(fixture.ctx)
	if got := fixture.gauge(); got != 1 {
		t.Fatalf("%v PUTs a second, want the live process's 1", got)
	}
	if _, found, err := fixture.host.Redis.HashGet(fixture.ctx, writeBudgetKey("seg-1"), hddPutReportFieldPrefix+"dead"); err != nil || found {
		t.Fatalf("the lapsed report's field stands: %t %v", found, err)
	}
}
