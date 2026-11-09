// §22.8's harness conventions (TEST-M2-13; R-TEST-7, D-TEST-7, R-TEST-2), which every area's load
// harness reports in: EVS1-M2-43, PROTO-M2-07, TEAM-M2-14, KEYS-M2-31, SOCK-M5-17, TLS-M5-26,
// SMTP-M9-32, EVSB-M2-21 and SEARCH-M10-40.
//
//   - Driver paces a workload at a set rate, open loop: arrival n is due at start + n/rate whatever the
//     earlier ones are doing, and its latency runs from when it was due, so a slow system shows as
//     queueing in the percentiles and never as a lower arrival rate, which a closed loop would hide.
//     A warm-up phase runs first and is left out of the figures.
//   - Report is the one JSON shape a run reports in: percentiles with failed attempts beside them
//     (connect/CODESTYLE.md:215), allocations, rates, the effective settings, the commit set, and
//     Smoke on a run too small to prove anything, which is never a gate's evidence.
//   - Sampler reads heap, goroutines and Redis keys, for the soak's baseline (TEST-M2-14).
//
// A load run may use real time, unlike a schedule, so an area's run builds under the sidecar_load tag
// and stays out of test.sh. The driver itself reads a Clock, so its own tests run on a fake one and
// prove its pacing exactly. Benchmarks run the effective constructor settings with features on
// (R-TEST-2): the caller records them in Report.Settings.
//
// A Driver runs once. Its methods are safe for concurrent use.

package load

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One attempt of the workload: arrival is its number from 0. An error is a failed attempt, which the
// report counts beside the successes, never in place of them.
type Workload func(ctx context.Context, arrival int64) error

// What a run paces and how long it runs.
type DriverSettings struct {
	// The workload's name, as the report names it.
	Name string
	// Arrivals a second. Must be positive.
	Rate float64
	// Arrivals before the steady phase, run and left out of the figures, so caches and pools are warm.
	// Zero runs none.
	Warmup time.Duration
	// The phase the figures come from. Must be positive.
	Steady time.Duration
	// The most attempts in flight at once. An arrival past it is not run and counts as a failed attempt
	// of kind refused-by-driver, so an overload shows as failures and queueing, never as a lower
	// arrival rate. Non-positive bounds nothing.
	MaxInFlight int
	// The most distinct error texts the report keeps by kind; the rest count under "other". Non-positive
	// keeps none by text.
	MaxFailureKinds int
	// What the driver reads time from. nil is real time, which a load run under sidecar_load uses.
	Clock sidecartest.Clock
}

// One second's pace, a minute of steady load after ten seconds of warm-up, and up to 16 failure kinds.
func DefaultDriverSettings() *DriverSettings {
	return &DriverSettings{
		Name:            "load",
		Rate:            1,
		Warmup:          10 * time.Second,
		Steady:          time.Minute,
		MaxFailureKinds: 16,
	}
}

// The failure kind of an arrival the driver did not run because MaxInFlight attempts were in flight.
const FailureRefusedByDriver = "refused-by-driver"

// One attempt as the driver saw it.
type attempt struct {
	arrival int64
	due     time.Time
	ended   time.Time
	steady  bool
	err     error
	refused bool
}

// Paces one run of a workload.
type Driver struct {
	settings *DriverSettings
	workload Workload
	clock    sidecartest.Clock

	stateLock sync.Mutex
	started   bool
	launched  int64
	refused   int64
	completed int64
	// arrivals of the steady phase launched, refused ones included
	steadyLaunched int64
	inFlight       int
	attempts       []*attempt
	// steady-phase allocation readings, at its start and its end
	allocationsAtStart *runtime.MemStats
	allocationsAtEnd   *runtime.MemStats
	// closed and replaced at each change of launched or completed
	progressChanged chan struct{}
	// the next arrival's timer, stopped on cancellation
	stopNext func() bool
	// set once no arrival may launch: after the last, or on cancellation
	arrivalsEnded bool
}

// A driver of workload. Settings are read once: a Rate or Steady that is not positive panics, since
// such a run measures nothing.
func NewDriver(settings *DriverSettings, workload Workload) *Driver {
	if settings.Rate <= 0 || settings.Steady <= 0 || settings.Warmup < 0 {
		panic(fmt.Sprintf("load: a run needs a positive rate and steady phase, not %v and %v", settings.Rate, settings.Steady))
	}
	clock := settings.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	copied := *settings
	return &Driver{
		settings:        &copied,
		workload:        workload,
		clock:           clock,
		progressChanged: make(chan struct{}),
	}
}

// How far a run has come: arrivals launched, those refused for MaxInFlight among them, and attempts
// ended, refused ones included.
type Progress struct {
	Launched  int64
	Refused   int64
	Completed int64
}

// How far the run has come, and a channel that closes at its next change: how a test on a fake clock
// knows the run has caught up before it moves time, with no sleep.
func (self *Driver) Progress() (Progress, <-chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return Progress{Launched: self.launched, Refused: self.refused, Completed: self.completed}, self.progressChanged
}

func (self *Driver) notifyWithLock() {
	close(self.progressChanged)
	self.progressChanged = make(chan struct{})
}

// When arrival n is due: its own product of the rate, so no rounding accumulates.
func (self *Driver) due(start time.Time, n int64) time.Time {
	return start.Add(time.Duration(float64(n) * float64(time.Second) / self.settings.Rate))
}

// Runs the workload: every arrival due before the steady phase ends, then waits for each attempt to
// end, or for ctx, and reports. Attempts get ctx, so cancelling it ends the run early, and the report
// says how many steady attempts had not ended.
func (self *Driver) Run(ctx context.Context) *Report {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.started {
			panic("load: a Driver runs once")
		}
		self.started = true
	}()
	start := self.clock.Now()
	warmupEnd := start.Add(self.settings.Warmup)
	steadyEnd := warmupEnd.Add(self.settings.Steady)
	report := &Report{
		Name:             self.settings.Name,
		Started:          start,
		WarmupMillis:     self.settings.Warmup.Milliseconds(),
		SteadyMillis:     self.settings.Steady.Milliseconds(),
		OfferedPerSecond: self.settings.Rate,
		Settings:         map[string]string{},
		CommitSet:        map[string]string{},
	}

	attempts := sync.WaitGroup{}
	arrivalsDone := make(chan struct{})
	var closeArrivals sync.Once
	// No arrival launches once this runs, so every attempts.Add happens before Run's Wait or not at all.
	endArrivals := func() {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.arrivalsEnded = true
		}()
		closeArrivals.Do(func() { close(arrivalsDone) })
	}

	// the steady phase's allocations, read at its edges on the run's clock
	readAllocations := func(into **runtime.MemStats) func() {
		return func() {
			stats := &runtime.MemStats{}
			runtime.ReadMemStats(stats)
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			*into = stats
		}
	}
	stopStartReading := self.clock.AfterFunc(warmupEnd.Sub(self.clock.Now()), readAllocations(&self.allocationsAtStart))
	stopEndReading := self.clock.AfterFunc(steadyEnd.Sub(self.clock.Now()), readAllocations(&self.allocationsAtEnd))

	arrive := func(n int64, due time.Time) {
		steady := !due.Before(warmupEnd)
		launch := false
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.arrivalsEnded {
				return
			}
			self.launched += 1
			if steady {
				self.steadyLaunched += 1
			}
			if 0 < self.settings.MaxInFlight && self.settings.MaxInFlight <= self.inFlight {
				self.refused += 1
				self.completed += 1
				self.attempts = append(self.attempts, &attempt{arrival: n, due: due, ended: due, steady: steady, refused: true})
			} else {
				self.inFlight += 1
				launch = true
				attempts.Add(1)
			}
			self.notifyWithLock()
		}()
		if !launch {
			return
		}
		go func() {
			defer attempts.Done()
			err := self.workload(ctx, n)
			ended := self.clock.Now()
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.inFlight -= 1
			self.completed += 1
			self.attempts = append(self.attempts, &attempt{arrival: n, due: due, ended: ended, steady: steady, err: err})
			self.notifyWithLock()
		}()
	}
	var schedule func(n int64)
	schedule = func(n int64) {
		due := self.due(start, n)
		stop := self.clock.AfterFunc(due.Sub(self.clock.Now()), func() {
			if ctx.Err() != nil {
				endArrivals()
				return
			}
			// the next arrival's timer is set before this one launches, so a fake clock's test that sees
			// this launch also sees the next arrival pending; the last one ends the arrivals only after it
			// launches
			last := !self.due(start, n+1).Before(steadyEnd)
			if !last {
				schedule(n + 1)
			}
			arrive(n, due)
			if last {
				endArrivals()
			}
		})
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.stopNext = stop
	}
	schedule(0)

	select {
	case <-arrivalsDone:
	case <-ctx.Done():
		self.stateLock.Lock()
		stop := self.stopNext
		self.stateLock.Unlock()
		if stop != nil {
			stop()
		}
		endArrivals()
	}
	attempts.Wait()
	stopStartReading()
	stopEndReading()
	report.Ended = self.clock.Now()

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.fillWithLock(report, ctx.Err())
	return report
}

// The figures of the steady phase, from the attempts the driver recorded.
func (self *Driver) fillWithLock(report *Report, cancelled error) {
	successes := []time.Duration{}
	failures := []time.Duration{}
	succeededInPhase := int64(0)
	steadyEnd := report.Started.Add(time.Duration(report.WarmupMillis+report.SteadyMillis) * time.Millisecond)
	report.FailureKinds = map[string]int64{}
	for _, attempt := range self.attempts {
		if !attempt.steady {
			continue
		}
		if attempt.err == nil && !attempt.refused && !attempt.ended.After(steadyEnd) {
			succeededInPhase += 1
		}
		latency := attempt.ended.Sub(attempt.due)
		switch {
		case attempt.refused:
			report.Failed += 1
			report.FailureKinds[FailureRefusedByDriver] += 1
			failures = append(failures, latency)
		case attempt.err != nil:
			report.Failed += 1
			kind := attempt.err.Error()
			if _, kept := report.FailureKinds[kind]; !kept && self.settings.MaxFailureKinds <= len(report.FailureKinds) {
				kind = "other"
			}
			report.FailureKinds[kind] += 1
			failures = append(failures, latency)
		default:
			successes = append(successes, latency)
		}
	}
	report.Scheduled = 0
	for n := int64(0); ; n += 1 {
		due := self.due(report.Started, n)
		if !due.Before(report.Started.Add(time.Duration(report.WarmupMillis+report.SteadyMillis) * time.Millisecond)) {
			break
		}
		if !due.Before(report.Started.Add(time.Duration(report.WarmupMillis) * time.Millisecond)) {
			report.Scheduled += 1
		}
	}
	report.Arrivals = self.steadyLaunched
	report.Succeeded = int64(len(successes))
	report.AchievedPerSecond = float64(succeededInPhase) / (float64(report.SteadyMillis) / 1000)
	report.LatencyMillis = PercentilesOf(successes)
	report.FailedLatencyMillis = PercentilesOf(failures)
	if self.allocationsAtStart != nil && self.allocationsAtEnd != nil {
		report.Allocations = Allocations{
			Bytes:   self.allocationsAtEnd.TotalAlloc - self.allocationsAtStart.TotalAlloc,
			Objects: self.allocationsAtEnd.Mallocs - self.allocationsAtStart.Mallocs,
		}
		if completed := report.Succeeded + report.Failed; 0 < completed {
			report.Allocations.BytesPerAttempt = float64(report.Allocations.Bytes) / float64(completed)
			report.Allocations.ObjectsPerAttempt = float64(report.Allocations.Objects) / float64(completed)
		}
	}
	if cancelled != nil {
		report.Notes = append(report.Notes, fmt.Sprintf("the run was cancelled (%v) with %d of %d steady arrivals launched", cancelled, report.Arrivals, report.Scheduled))
	}
}
