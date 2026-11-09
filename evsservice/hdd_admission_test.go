package evsservice

import (
	"context"
	"errors"
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

// Admit makes no Redis op: the figures come in on the admission's own interval.
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
	}
	if counts := fixture.host.Redis.OpCounts(); len(counts) != 0 {
		t.Fatalf("Admit made Redis ops: %v", counts)
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
