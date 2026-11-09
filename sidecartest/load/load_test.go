package load

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// How long a test waits on the run before it fails rather than hangs: a bound on a broken test, never
// the proof, since time here moves only on the fake clock.
const loadTestGuardTimeout = 10 * time.Second

// One server, first come first served: each request holds it for service on the fake clock, and a
// service of zero answers at once. It counts requests entered and released, so a test knows when the
// run has caught up.
type queueSink struct {
	clock   *sidecartest.FakeClock
	service time.Duration
	fail    func(arrival int64) error

	stateLock sync.Mutex
	waiting   []chan struct{}
	busy      bool
	entered   int64
	released  int64
	enteredAt map[int64]time.Time
	changed   chan struct{}
}

func newQueueSink(clock *sidecartest.FakeClock, service time.Duration) *queueSink {
	return &queueSink{clock: clock, service: service, enteredAt: map[int64]time.Time{}, changed: make(chan struct{})}
}

func (self *queueSink) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

func (self *queueSink) progress() (entered int64, released int64, changed <-chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.entered, self.released, self.changed
}

// The workload: enter, wait for service, answer. The service timer is set before the entry counts, so
// a test that sees the entry sees the timer.
func (self *queueSink) do(ctx context.Context, arrival int64) error {
	done := make(chan struct{})
	start := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.enteredAt[arrival] = self.clock.Now()
		if self.service == 0 {
			close(done)
			return
		}
		self.waiting = append(self.waiting, done)
		if !self.busy {
			self.busy = true
			start = true
		}
	}()
	if start {
		self.clock.AfterFunc(self.service, self.finish)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.entered += 1
		if self.service == 0 {
			self.released += 1
		}
		self.notifyWithLock()
	}()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	if self.fail != nil {
		return self.fail(arrival)
	}
	return nil
}

// The head's service ends, on the fake clock's goroutine, and the next starts.
func (self *queueSink) finish() {
	next := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		close(self.waiting[0])
		self.waiting = self.waiting[1:]
		self.released += 1
		next = 0 < len(self.waiting)
		self.busy = next
		self.notifyWithLock()
	}()
	if next {
		self.clock.AfterFunc(self.service, self.finish)
	}
}

// Runs driver on clock to its end: after every step, waits until each launched arrival has entered the
// sink and each released request has ended, then moves the clock to the next timer.
func runOnFakeClock(t *testing.T, clock *sidecartest.FakeClock, driver *Driver, sink *queueSink) *Report {
	t.Helper()
	reports := make(chan *Report, 1)
	go func() {
		reports <- driver.Run(context.Background())
	}()
	settled := func() {
		for {
			progress, driverChanged := driver.Progress()
			entered, released, sinkChanged := sink.progress()
			if 0 < progress.Launched && entered == progress.Launched-progress.Refused && progress.Completed-progress.Refused == released {
				return
			}
			select {
			case <-driverChanged:
			case <-sinkChanged:
			case <-time.After(loadTestGuardTimeout):
				t.Fatalf("the run never caught up: %+v, %d entered, %d released", progress, entered, released)
			}
		}
	}
	for {
		settled()
		select {
		case report := <-reports:
			return report
		default:
		}
		pending := clock.PendingTimers()
		if len(pending) == 0 {
			select {
			case report := <-reports:
				return report
			case <-time.After(loadTestGuardTimeout):
				t.Fatal("nothing is pending and the run did not end")
			}
		}
		clock.AdvanceTo(pending[0])
	}
}

// Pacing holds the set rate: every arrival enters the sink exactly when it is due, warm-up arrivals
// are left out of the figures, and an instant sink keeps the offered pace.
func TestDriverHoldsTheSetRateOnAFixtureSink(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	start := clock.Now()
	sink := newQueueSink(clock, 0)
	driver := NewDriver(&DriverSettings{
		Name: "pacing", Rate: 10, Warmup: time.Second, Steady: 5 * time.Second, MaxFailureKinds: 4, Clock: clock,
	}, sink.do)
	report := runOnFakeClock(t, clock, driver, sink)

	if report.Scheduled != 50 || report.Arrivals != 50 || report.Succeeded != 50 || report.Failed != 0 {
		t.Errorf("scheduled %d, arrivals %d, succeeded %d, failed %d; want 50, 50, 50, 0", report.Scheduled, report.Arrivals, report.Succeeded, report.Failed)
	}
	if len(sink.enteredAt) != 60 {
		t.Fatalf("%d arrivals entered the sink, want 10 warm-up and 50 steady", len(sink.enteredAt))
	}
	for arrival := int64(0); arrival < 60; arrival += 1 {
		if want := start.Add(time.Duration(arrival) * 100 * time.Millisecond); !sink.enteredAt[arrival].Equal(want) {
			t.Errorf("arrival %d entered at %v, due at %v", arrival, sink.enteredAt[arrival].Sub(start), want.Sub(start))
		}
	}
	if report.AchievedPerSecond != 10 || report.OfferedPerSecond != 10 {
		t.Errorf("offered %v a second and achieved %v, want 10 and 10", report.OfferedPerSecond, report.AchievedPerSecond)
	}
	if report.LatencyMillis.Count != 50 || report.LatencyMillis.Max != 0 {
		t.Errorf("latency %+v, want 50 attempts at 0 ms", report.LatencyMillis)
	}
}

// A slowed sink shows queueing in the percentiles, not a lower arrival rate: one server of 150 ms at
// 10 arrivals a second leaves arrival k waiting for k services, so its latency is 150 + 50k ms.
func TestSlowSinkShowsQueueingNotALowerRate(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	start := clock.Now()
	sink := newQueueSink(clock, 150*time.Millisecond)
	driver := NewDriver(&DriverSettings{Name: "queueing", Rate: 10, Steady: 3 * time.Second, Clock: clock}, sink.do)
	report := runOnFakeClock(t, clock, driver, sink)

	if report.Scheduled != 30 || report.Arrivals != 30 || report.Succeeded != 30 {
		t.Errorf("scheduled %d, arrivals %d, succeeded %d; want 30 each", report.Scheduled, report.Arrivals, report.Succeeded)
	}
	for arrival := int64(0); arrival < 30; arrival += 1 {
		if want := start.Add(time.Duration(arrival) * 100 * time.Millisecond); !sink.enteredAt[arrival].Equal(want) {
			t.Errorf("arrival %d entered at %v, due at %v: the pace fell behind the sink", arrival, sink.enteredAt[arrival].Sub(start), want.Sub(start))
		}
	}
	// k = 0..29: p50 is the 15th smallest, k = 14
	latency := report.LatencyMillis
	if latency.Min != 150 || latency.P50 != 850 || latency.P99 != 1600 || latency.Max != 1600 {
		t.Errorf("latency %+v, want min 150, p50 850, p99 and max 1600", latency)
	}
	// 20 services end by the 3 s steady phase's end, the 20th at it: below the offered 10 a second
	if want := 20.0 / 3; report.AchievedPerSecond != want {
		t.Errorf("achieved %v a second, want %v", report.AchievedPerSecond, want)
	}
}

// Failed attempts appear beside the successes, by kind, and never in the successes' percentiles.
func TestFailedAttemptsAppearInTheReport(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	sink := newQueueSink(clock, 0)
	sink.fail = func(arrival int64) error {
		if arrival%4 == 0 {
			return errors.New("planted failure")
		}
		return nil
	}
	driver := NewDriver(&DriverSettings{Name: "failures", Rate: 10, Steady: 2 * time.Second, MaxFailureKinds: 4, Clock: clock}, sink.do)
	report := runOnFakeClock(t, clock, driver, sink)

	if report.Failed != 5 || report.Succeeded != 15 {
		t.Errorf("failed %d and succeeded %d, want 5 and 15", report.Failed, report.Succeeded)
	}
	if report.FailureKinds["planted failure"] != 5 {
		t.Errorf("failure kinds %v", report.FailureKinds)
	}
	if report.FailedLatencyMillis.Count != 5 || report.LatencyMillis.Count != 15 {
		t.Errorf("failed latency over %d attempts and latency over %d, want 5 and 15", report.FailedLatencyMillis.Count, report.LatencyMillis.Count)
	}
	data, err := report.Json()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"failed": 5`) || !strings.Contains(string(data), `"failed_latency_ms"`) {
		t.Errorf("the JSON does not carry the failures beside the latency:\n%s", data)
	}
}

// An overload past MaxInFlight shows as failed attempts at the full arrival rate, never a slower pace.
func TestOverloadPastMaxInFlightCountsAsFailures(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	sink := newQueueSink(clock, time.Second)
	driver := NewDriver(&DriverSettings{Name: "overload", Rate: 10, Steady: time.Second, MaxInFlight: 2, Clock: clock}, sink.do)
	report := runOnFakeClock(t, clock, driver, sink)

	if report.Arrivals != 10 || report.Failed != 8 || report.Succeeded != 2 {
		t.Errorf("arrivals %d, failed %d, succeeded %d; want 10, 8, 2", report.Arrivals, report.Failed, report.Succeeded)
	}
	if report.FailureKinds[FailureRefusedByDriver] != 8 {
		t.Errorf("failure kinds %v", report.FailureKinds)
	}
}

// A smoke report is refused as gate evidence, as is a full run that names no target or build; a full
// run naming them is accepted.
func TestSmokeReportIsRefusedAsGateEvidence(t *testing.T) {
	full := &Report{
		Name: "evs push", Targets: []string{"evs-push-p50"}, Host: "perf-host", Scheduled: 10, Arrivals: 10,
		Settings: map[string]string{"evs.batch": "on"}, CommitSet: map[string]string{"sidecar": "abc123"},
	}
	if err := full.GateEvidence(); err != nil {
		t.Errorf("a full run refused: %v", err)
	}
	smoke := *full
	smoke.Smoke = true
	if err := smoke.GateEvidence(); err == nil || !strings.Contains(err.Error(), "smoke") {
		t.Errorf("a smoke run accepted: %v", err)
	}
	unnamed := *full
	unnamed.Targets = nil
	unnamed.CommitSet = nil
	if err := unnamed.GateEvidence(); err == nil || !strings.Contains(err.Error(), "no target") || !strings.Contains(err.Error(), "no commit set") {
		t.Errorf("a run naming no target or build accepted: %v", err)
	}
	cancelled := *full
	cancelled.Arrivals = 4
	if err := cancelled.GateEvidence(); err == nil || !strings.Contains(err.Error(), "only 4 of its 10") {
		t.Errorf("a cancelled run accepted: %v", err)
	}
}

// The JSON shape reads back whole, and a field it does not hold is refused.
func TestReportRoundTripsAsJson(t *testing.T) {
	report := &Report{
		Name: "round trip", Targets: []string{"acl-gates"}, Scheduled: 3, Arrivals: 3, Succeeded: 2, Failed: 1,
		LatencyMillis: PercentilesOf([]time.Duration{time.Millisecond, 3 * time.Millisecond}),
		FailureKinds:  map[string]int64{"planted": 1},
		Samples:       []Sample{{Goroutines: 4, RedisKeys: -1}},
	}
	data, err := report.Json()
	if err != nil {
		t.Fatal(err)
	}
	read, err := ParseReport(data)
	if err != nil {
		t.Fatal(err)
	}
	if read.Name != report.Name || read.LatencyMillis != report.LatencyMillis || read.FailureKinds["planted"] != 1 || read.Samples[0].Goroutines != 4 {
		t.Errorf("read back %+v", read)
	}
	if _, err := ParseReport([]byte(`{"name": "x", "p50_guess": 3}`)); err == nil {
		t.Error("a field the shape does not hold was accepted")
	}
}

// Percentiles by nearest rank over a known set.
func TestPercentilesByNearestRank(t *testing.T) {
	durations := []time.Duration{}
	for millis := 100; 1 <= millis; millis -= 1 {
		durations = append(durations, time.Duration(millis)*time.Millisecond)
	}
	percentiles := PercentilesOf(durations)
	if percentiles.Count != 100 || percentiles.Min != 1 || percentiles.P50 != 50 || percentiles.P90 != 90 || percentiles.P99 != 99 || percentiles.P999 != 100 || percentiles.Max != 100 || percentiles.Mean != 50.5 {
		t.Errorf("%+v", percentiles)
	}
	if empty := PercentilesOf(nil); empty != (Percentiles{}) {
		t.Errorf("no durations: %+v", empty)
	}
}

// The sampler reads heap, goroutines and a fake Redis's keys, and keeps each reading.
func TestSamplerReadsHeapGoroutinesAndRedisKeys(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	ctx := context.Background()
	redis := sidecartest.NewFakeRedis(ctx, clock, nil, nil, nil)
	defer redis.Close()
	for _, key := range []string{"{scp_a}ver", "{scp_b}ver", "{evsq_c}q"} {
		if err := redis.Set(ctx, key, []byte("v"), 0); err != nil {
			t.Fatal(err)
		}
	}
	sampler := NewSampler(&SamplerSettings{Interval: time.Second, Clock: clock}, &FakeRedisKeys{Redis: redis})
	sample := sampler.Sample(ctx)
	if sample.RedisKeys != 3 || sample.Goroutines < 1 || sample.HeapAllocBytes == 0 || !sample.At.Equal(clock.Now()) {
		t.Errorf("%+v", sample)
	}
	if err := redis.Delete(ctx, []string{"{scp_a}ver"}); err != nil {
		t.Fatal(err)
	}
	if again := sampler.Sample(ctx); again.RedisKeys != 2 {
		t.Errorf("after a delete: %+v", again)
	}
	if len(sampler.Samples()) != 2 {
		t.Errorf("%d samples kept", len(sampler.Samples()))
	}
	noRedis := NewSampler(&SamplerSettings{Interval: time.Second, Clock: clock}, nil)
	if sample := noRedis.Sample(ctx); sample.RedisKeys != -1 {
		t.Errorf("no Redis read as %d keys", sample.RedisKeys)
	}
}
