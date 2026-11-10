package load

// TEST-M2-14's subscriber workload on T2: §22.8's 1,000 subscribers on one repo, each leased through evs's own
// route and hinted through step 8 as built, at a low pace on a fake clock, so every commit's hints are counted
// exactly; and the workload's own accounting of a hint that never comes, on a target that withholds one.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Runs workload on clock to its end: after every move, waits until each launched commit has ended or waits on its
// hints' timeout, and quiet, when given, holds, then moves the clock to the next timer. The run is under way first,
// so no move comes before its first commit.
func runSubscribersOnFakeClock(t *testing.T, clock *sidecartest.FakeClock, workload *SubscriberWorkload, quiet func() (bool, <-chan struct{})) *SubscriberReport {
	t.Helper()
	reports := make(chan *SubscriberReport, 1)
	go func() {
		reports <- workload.Run(context.Background())
	}()
	settle := func() {
		for {
			progress, driverChanged := workload.Progress()
			waiting, waitChanged := workload.Waiting()
			quietNow, quietChanged := true, (<-chan struct{})(nil)
			if quiet != nil {
				quietNow, quietChanged = quiet()
			}
			if 0 < progress.Launched && progress.Launched == progress.Completed+waiting && quietNow {
				return
			}
			select {
			case <-driverChanged:
			case <-waitChanged:
			case <-quietChanged:
			case <-reports:
				t.Fatal("the run ended before the harness saw it settle")
			case <-time.After(loadTestGuardTimeout):
				t.Fatalf("the run never caught up: %+v, %d waiting", progress, waiting)
			}
		}
	}
	for {
		settle()
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

// 1,000 subscribers on one repo at two commits a second: every steady commit hints every subscriber, the report
// counts each subscriber's latency once a commit, names the target, and on a fake clock is a smoke that no gate
// takes.
func TestSubscriberWorkloadHintsAThousandSubscribersOnOneRepo(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	fakes := sidecartest.NewFakeHost(t.Context(), clock, nil, nil, sidecartest.DefaultFakeHostSettings())
	defer fakes.Redis.Close()
	world, err := NewEvsSubscriberWorld(t.Context(), fakes, fakes.ServiceHost(), clock, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer world.Close()
	settings := DefaultSubscriberSettings()
	settings.Driver = &DriverSettings{Name: "evs-subscribers", Rate: 2, Warmup: time.Second, Steady: 5 * time.Second, MaxFailureKinds: 4, Clock: clock}
	workload := NewSubscriberWorkload(settings, world)
	// every step 8 done, so each hint that needs no clock has come before time moves
	quiet := func() (bool, <-chan struct{}) {
		started, finished, changed := world.Engine().StepEights()
		return started == finished, changed
	}
	report := runSubscribersOnFakeClock(t, clock, workload, quiet)

	if report.Subscribers != SubscribersPerRepo {
		t.Fatalf("%d subscribers", report.Subscribers)
	}
	if report.Report.Scheduled != 10 || report.Report.Succeeded != 10 || report.Report.Failed != 0 {
		t.Fatalf("commits scheduled %d, succeeded %d, failed %d (%v)", report.Report.Scheduled, report.Report.Succeeded, report.Report.Failed, report.Report.FailureKinds)
	}
	if report.MissedHints != 0 || report.HintLatencyMillis.Count != 10*SubscribersPerRepo {
		t.Fatalf("missed %d, latencies %d", report.MissedHints, report.HintLatencyMillis.Count)
	}
	if len(report.Report.Targets) != 1 || report.Report.Targets[0] != SubscriberTargetId {
		t.Fatalf("targets %v", report.Report.Targets)
	}
	// time stands still on a fake clock, so the run proves delivery and nothing about latency
	report.Report.Smoke = true
	if err := report.GateEvidence(); err == nil || !strings.Contains(err.Error(), "smoke") {
		t.Fatalf("a smoke reached a gate: %v", err)
	}
}

// A target whose hints never reach one subscriber: each steady commit counts that subscriber missed and fails, and
// the report is no evidence even were it no smoke.
type withholdingTarget struct {
	subscribers int
	withheld    int

	stateLock sync.Mutex
	version   uint64
	hinted    func(subscriber int, version uint64)
}

func (self *withholdingTarget) Subscribers() int {
	return self.subscribers
}

func (self *withholdingTarget) Watch(hinted func(subscriber int, version uint64)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.hinted = hinted
}

func (self *withholdingTarget) Commit(ctx context.Context, arrival int64) (uint64, error) {
	self.stateLock.Lock()
	self.version += 1
	version := self.version
	hinted := self.hinted
	self.stateLock.Unlock()
	for subscriber := range self.subscribers {
		if subscriber != self.withheld {
			hinted(subscriber, version)
		}
	}
	return version, nil
}

func TestSubscriberWorkloadCountsAHintThatNeverComes(t *testing.T) {
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := DefaultSubscriberSettings()
	settings.Driver = &DriverSettings{Name: "withheld", Rate: 1, Warmup: time.Second, Steady: 3 * time.Second, MaxFailureKinds: 4, Clock: clock}
	workload := NewSubscriberWorkload(settings, &withholdingTarget{subscribers: 5, withheld: 3})
	report := runSubscribersOnFakeClock(t, clock, workload, nil)
	if report.MissedHints != 3 || report.Report.Failed != 3 || report.Report.Succeeded != 0 {
		t.Fatalf("missed %d, failed %d, succeeded %d", report.MissedHints, report.Report.Failed, report.Report.Succeeded)
	}
	if len(report.Report.Targets) != 0 {
		t.Fatalf("5 subscribers named a target: %v", report.Report.Targets)
	}
	report.Report.Targets = []string{SubscriberTargetId}
	report.Report.Host = "a host"
	report.Report.CommitSet = map[string]string{"sidecar": "a commit"}
	if err := report.GateEvidence(); err == nil || !strings.Contains(err.Error(), "missed 3 hints") {
		t.Fatalf("missed hints reached a gate: %v", err)
	}
}
