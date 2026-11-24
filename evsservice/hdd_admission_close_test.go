package evsservice

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The admission's one PUT report on seg-1.
func hddCloseReport(t *testing.T, redis sidecar.Redis, admission *HddAdmission) *HddPutReport {
	t.Helper()
	reports, err := readHddPutReports(t.Context(), redis, "seg-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 || reports[0].ProcessId != admission.processId {
		for _, report := range reports {
			t.Logf("report %+v", *report)
		}
		t.Fatalf("%d reports, want the process's alone", len(reports))
	}
	return reports[0]
}

// The gap the close fills: PUTs the cluster stored for a process after its last interval's report reach the hdd
// loop's urnetwork_filecluster_hdd_puts once the process closes, though its host's ctx ended first. Close writes the
// report once the goroutine has returned, and the loop rates those PUTs over the span since the report it last saw.
// Without the close's report the loop keeps the last interval's rate, and the PUTs after it never reach the gauge.
func TestHddAdmissionCloseReportsThePutsSinceTheLastTick(t *testing.T) {
	fixture := newHddPutsFixture(t)
	settings := DefaultHddAdmissionSettings()
	start := fixture.clock.Now()
	// no process reports yet, so one started from here counts from its start
	fixture.loop.Step(fixture.ctx)
	hostCtx, cancel := context.WithCancel(fixture.ctx)
	defer cancel()
	admission, err := NewHddAdmission(hostCtx, fixture.host.ServiceHost(), "seg-1", settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admission.Close)
	awaitBudgetTimerAt(t, fixture.clock, start.Add(settings.Interval), nil)

	// the interval's 30 over its 5 s
	countHddPuts(admission, 30)
	fixture.clock.Advance(settings.Interval)
	// the tick is done once the goroutine waits for the next
	awaitBudgetTimerAt(t, fixture.clock, start.Add(2*settings.Interval), nil)
	fixture.loop.Step(fixture.ctx)
	if got := fixture.gauge(); got != 6 {
		t.Fatalf("%v PUTs a second after the interval, want 6", got)
	}

	// 4 more within the next 2 s; then the host's ctx ends, as a host's may before it closes its parts
	countHddPuts(admission, 4)
	fixture.clock.Advance(2 * time.Second)
	cancel()
	admission.Close()

	report := hddCloseReport(t, fixture.host.Redis, admission)
	if report.StartMs != start.UnixMilli() || report.TimeMs != fixture.clock.Now().UnixMilli() || report.PutCount != 34 {
		t.Errorf("the last report %+v, want 34 PUTs as of the close", *report)
	}
	fixture.loop.Step(fixture.ctx)
	if got := fixture.gauge(); got != 2 {
		t.Errorf("%v PUTs a second after the close, want the 4 over its last 2 s", got)
	}
}

// A close just after a report counts nothing twice: its report carries the total from the start, as every report
// does, so with nothing stored since, the loop rates the close's span at none rather than counting the interval's
// PUTs again. A second Close writes nothing, so what is counted after the first goes nowhere, and the loop reading
// the last report again keeps its rate of none.
func TestHddAdmissionCloseAfterAReportCountsNothingTwice(t *testing.T) {
	fixture := newHddPutsFixture(t)
	start := fixture.clock.Now()
	fixture.loop.Step(fixture.ctx)
	admission := fixture.process()
	countHddPuts(admission, 30)
	fixture.clock.Advance(5 * time.Second)
	admission.tick(fixture.ctx)
	fixture.loop.Step(fixture.ctx)
	if got := fixture.gauge(); got != 6 {
		t.Fatalf("%v PUTs a second after the interval, want 6", got)
	}

	fixture.clock.Advance(time.Second)
	admission.Close()
	closeTimeMs := fixture.clock.Now().UnixMilli()
	fixture.loop.Step(fixture.ctx)
	if got := fixture.gauge(); got != 0 {
		t.Errorf("%v PUTs a second over a close that stored nothing new, want 0", got)
	}

	countHddPuts(admission, 5)
	fixture.host.Redis.ResetOpCounts()
	admission.Close()
	if counts := fixture.host.Redis.OpCounts(); len(counts) != 0 {
		t.Errorf("a second Close made Redis ops: %v", counts)
	}
	report := hddCloseReport(t, fixture.host.Redis, admission)
	if report.StartMs != start.UnixMilli() || report.TimeMs != closeTimeMs || report.PutCount != 30 {
		t.Errorf("the report after the second Close %+v, want the first Close's 30", *report)
	}
	// within the last report's ttl
	fixture.clock.Advance(5 * time.Second)
	fixture.loop.Step(fixture.ctx)
	if got := fixture.gauge(); got != 0 {
		t.Errorf("%v PUTs a second reading the last report again, want 0", got)
	}
}

// Close's report is bounded: with Redis taking its write and never answering, Close returns once
// CloseReportTimeout passes on the host's clock, and the report in Redis stays the last tick's.
func TestHddAdmissionCloseReportIsBounded(t *testing.T) {
	fixture := newHddFixture(t)
	settings := fixture.admission.settings
	// shorter than the fake's own request timeout, so the bound that ends the write is Close's
	if sidecartest.DefaultFakeRedisSettings().RequestTimeout <= settings.CloseReportTimeout {
		t.Fatalf("a close bound of %s", settings.CloseReportTimeout)
	}
	countHddPuts(fixture.admission, 3)
	fixture.tick()
	tickTimeMs := fixture.clock.Now().UnixMilli()
	countHddPuts(fixture.admission, 2)
	fixture.clock.Advance(time.Second)
	fired, err := fixture.host.Redis.Faults().Add(&sidecartest.FaultPlan{
		Op:         sidecartest.FaultOpRedis,
		KeyPrefix:  writeBudgetKey("seg-1"),
		Result:     sidecartest.Delay,
		Delay:      sidecartest.DelayNeverLands,
		WritesOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		fixture.admission.Close()
	}()
	// the write parks before Close can return, which it cannot until the clock moves
	select {
	case <-fired:
	case <-closed:
		t.Fatal("Close returned without writing a report")
	case <-t.Context().Done():
		t.Fatal("Close wrote no report")
	}
	select {
	case <-closed:
		t.Fatal("Close returned while its report went unanswered")
	default:
	}
	fixture.clock.Advance(settings.CloseReportTimeout)
	select {
	case <-closed:
	case <-t.Context().Done():
		t.Fatal("Close outlived its bound")
	}
	if report := hddCloseReport(t, fixture.host.Redis, fixture.admission); report.TimeMs != tickTimeMs || report.PutCount != 3 {
		t.Errorf("the report after a bounded Close %+v, want the tick's 3", *report)
	}
}

// A CloseReportTimeout that is not positive turns the last report off: Close ends the goroutine and writes
// nothing, so the report in Redis stays the last tick's.
func TestHddAdmissionCloseWithNoBoundWritesNothing(t *testing.T) {
	clock := sidecartest.NewFakeClock(governorTestStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	settings := DefaultHddAdmissionSettings()
	settings.CloseReportTimeout = 0
	start := clock.Now()
	admission, err := NewHddAdmission(t.Context(), host.ServiceHost(), "seg-1", settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admission.Close)
	awaitBudgetTimerAt(t, clock, start.Add(settings.Interval), nil)
	countHddPuts(admission, 3)
	clock.Advance(settings.Interval)
	awaitBudgetTimerAt(t, clock, start.Add(2*settings.Interval), nil)
	countHddPuts(admission, 2)
	clock.Advance(time.Second)
	host.Redis.ResetOpCounts()
	admission.Close()
	select {
	case <-admission.runDone:
	case <-t.Context().Done():
		t.Fatal("the goroutine outlived Close")
	}
	if counts := host.Redis.OpCounts(); len(counts) != 0 {
		t.Errorf("Close with no bound made Redis ops: %v", counts)
	}
	if report := hddCloseReport(t, host.Redis, admission); report.TimeMs != start.Add(settings.Interval).UnixMilli() || report.PutCount != 3 {
		t.Errorf("the report after Close %+v, want the tick's 3", *report)
	}
}

// The fake Redis with its next figures read held once armed, as a call that outlives its ctx is: the read says it
// has begun, and goes on only once released.
type hddHeldReadRedis struct {
	sidecar.Redis
	armed       atomic.Bool
	entered     chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

// The first figures read once armed waits for release whatever its ctx, then answers as the fake does, as every
// other read does at once.
func (self *hddHeldReadRedis) HashGet(ctx context.Context, key string, field string) ([]byte, bool, error) {
	if field == hddFiguresField && self.armed.CompareAndSwap(true, false) {
		close(self.entered)
		<-self.release
	}
	return self.Redis.HashGet(ctx, key, field)
}

// Lets the held read go. Safe more than once.
func (self *hddHeldReadRedis) releaseRead() {
	self.releaseOnce.Do(func() {
		close(self.release)
	})
}

// A process's admission with its goroutine, its interval's tick held in its figures read, as one stuck in Redis
// is, and Close running beside it, its bound on the clock.
type hddHeldTickFixture struct {
	t         *testing.T
	settings  *HddAdmissionSettings
	clock     *sidecartest.FakeClock
	host      *sidecartest.FakeHost
	redis     *hddHeldReadRedis
	admission *HddAdmission
	// when the held tick wrote its report
	tickTimeMs int64
	// closed as Close returns
	closed chan struct{}
}

// 3 PUTs before the interval's tick, which writes its report and is then held in its figures read, 2 more after
// that report, a second on, then Close waiting, neither the tick nor the bound let go.
func newHddHeldTickFixture(t *testing.T) *hddHeldTickFixture {
	settings := DefaultHddAdmissionSettings()
	clock := sidecartest.NewFakeClock(governorTestStart())
	host := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, nil)
	sidecartest.RegisterEvsTwins(host.Redis)
	redis := &hddHeldReadRedis{Redis: host.Redis, entered: make(chan struct{}), release: make(chan struct{})}
	serviceHost := host.ServiceHost()
	serviceHost.Redis = redis
	start := clock.Now()
	admission, err := NewHddAdmission(t.Context(), serviceHost, "seg-1", settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admission.Close)
	// first at cleanup: a test that stopped early lets the tick go, so neither Close waits on it
	t.Cleanup(redis.releaseRead)
	awaitBudgetTimerAt(t, clock, start.Add(settings.Interval), nil)
	countHddPuts(admission, 3)
	redis.armed.Store(true)
	clock.Advance(settings.Interval)
	select {
	case <-redis.entered:
	case <-t.Context().Done():
		t.Fatal("the interval's tick read no figures")
	}
	fixture := &hddHeldTickFixture{
		t:          t,
		settings:   settings,
		clock:      clock,
		host:       host,
		redis:      redis,
		admission:  admission,
		tickTimeMs: clock.Now().UnixMilli(),
		closed:     make(chan struct{}),
	}
	countHddPuts(admission, 2)
	clock.Advance(time.Second)
	go func() {
		defer close(fixture.closed)
		admission.Close()
	}()
	// Close has armed its bound, so it waits for the tick or the bound from here; it cannot return before it arms it
	awaitBudgetTimerAt(t, clock, clock.Now().Add(settings.CloseReportTimeout), fixture.closed)
	select {
	case <-fixture.closed:
		t.Fatal("Close returned beside a tick still running")
	default:
	}
	if report := fixture.report(); report.TimeMs != fixture.tickTimeMs || report.PutCount != 3 {
		t.Fatalf("the report while the tick runs %+v, want the tick's 3", *report)
	}
	return fixture
}

// The process's report in Redis.
func (self *hddHeldTickFixture) report() *HddPutReport {
	self.t.Helper()
	return hddCloseReport(self.t, self.host.Redis, self.admission)
}

// Returns once ch closes.
func (self *hddHeldTickFixture) await(ch chan struct{}, what string) {
	self.t.Helper()
	select {
	case <-ch:
	case <-self.t.Context().Done():
		self.t.Fatalf("%s never ended", what)
	}
}

// Close writes its report only once the goroutine has returned, so no interval's report, taken before the close,
// lands after the last: while the tick runs Close writes nothing, and once it ends Close's report holds every PUT,
// those counted after the tick's report too, as of the close.
func TestHddAdmissionCloseReportsOnceTheTickHasEnded(t *testing.T) {
	fixture := newHddHeldTickFixture(t)
	fixture.redis.releaseRead()
	fixture.await(fixture.closed, "Close")
	fixture.await(fixture.admission.runDone, "the ticking goroutine")
	if report := fixture.report(); report.TimeMs != fixture.clock.Now().UnixMilli() || report.PutCount != 5 {
		t.Errorf("the last report %+v, want 5 PUTs as of the close", *report)
	}
}

// The bound holds when a tick hangs: Close returns at its bound having written nothing, and the tick, let go after
// it, writes nothing more either, its own report written before its read. The PUTs since that report are lost, as
// a killed process's last interval is, and nothing stale lands after a last report.
func TestHddAdmissionCloseWritesNothingPastItsBoundBesideATick(t *testing.T) {
	fixture := newHddHeldTickFixture(t)
	fixture.clock.Advance(fixture.settings.CloseReportTimeout)
	fixture.await(fixture.closed, "Close")
	if report := fixture.report(); report.TimeMs != fixture.tickTimeMs || report.PutCount != 3 {
		t.Errorf("the report after Close past its bound %+v, want the tick's 3", *report)
	}
	fixture.redis.releaseRead()
	fixture.await(fixture.admission.runDone, "the ticking goroutine")
	if report := fixture.report(); report.TimeMs != fixture.tickTimeMs || report.PutCount != 3 {
		t.Errorf("the report once the tick past the close ended %+v, want the tick's 3", *report)
	}
}
