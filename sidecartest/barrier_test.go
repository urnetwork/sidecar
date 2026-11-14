package sidecartest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newBarrierFixture(t *testing.T, settings *BarrierDriverSettings) (*BarrierDriver, *ActorTable) {
	driver := NewBarrierDriver(settings)
	t.Cleanup(driver.Close)
	return driver, NewActorTable(NewFakeClock(DefaultClockStart()), driver)
}

func awaitEnded(t *testing.T, run *ActorRun) {
	t.Helper()
	select {
	case <-run.Ended():
	case <-time.After(10 * time.Second):
		t.Fatal("the run did not end")
	}
}

func TestBarrierPassesWhatNoArmNames(t *testing.T) {
	driver, _ := newBarrierFixture(t, nil)
	driver.Hit("evs.head_cas.before", "01JTESTREPO")
	trace := driver.Trace()
	if len(trace) != 1 || trace[0].Kind != BarrierPassed || trace[0].Name != "evs.head_cas.before" {
		t.Errorf("trace %v", trace)
	}
}

func TestBarrierHoldsAnArmedSiteUntilReleased(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	if err := driver.Arm("evs.head_cas.before", "", 0); err != nil {
		t.Fatal(err)
	}
	stepsDone := 0
	run := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		driver.Hit("evs.head_cas.before", "")
		stepsDone += 1
		return nil
	})

	if err := driver.AwaitHeld(t.Context(), "evs.head_cas.before", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case <-run.Ended():
		t.Fatal("ended while held")
	default:
	}
	if err := driver.Release("evs.head_cas.before"); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, run)
	if stepsDone != 1 {
		t.Errorf("%d steps after the barrier", stepsDone)
	}
}

func TestBarrierKeyHoldsOneInstanceAndNotAnother(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	site := BarrierSite("evs.head_cas", "repoA")
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	other := driver.Start(table.Actor(t.Context(), "writerB"), func() error {
		driver.Hit("evs.head_cas", "repoB")
		return nil
	})
	awaitEnded(t, other)

	held := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		driver.Hit("evs.head_cas", "repoA")
		return nil
	})
	if err := driver.AwaitHeld(t.Context(), site, ""); err != nil {
		t.Fatal(err)
	}
	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, held)
}

func TestBarrierNameAloneMatchesEveryKey(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	if err := driver.Arm("evs.head_cas", "", 0); err != nil {
		t.Fatal(err)
	}
	run := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		driver.Hit("evs.head_cas", "repoA")
		return nil
	})
	if err := driver.AwaitHeld(t.Context(), "evs.head_cas", ""); err != nil {
		t.Fatal(err)
	}
	if err := driver.Release("evs.head_cas"); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, run)
}

func TestBarrierReleaseOfNothingFails(t *testing.T) {
	driver, _ := newBarrierFixture(t, nil)
	if err := driver.Release("evs.head_cas"); err == nil {
		t.Error("released a site nobody is held at")
	}
}

func TestBarrierAwaitFailsNamingItsSite(t *testing.T) {
	settings := DefaultBarrierDriverSettings()
	settings.AwaitTimeout = 1 * time.Millisecond
	driver, _ := newBarrierFixture(t, settings)
	err := driver.AwaitHeld(t.Context(), "evs.head_cas", "")
	if err == nil || !strings.Contains(err.Error(), "evs.head_cas") {
		t.Errorf("err %v", err)
	}
}

func TestBarrierNamingRule(t *testing.T) {
	cases := []struct {
		name string
		key  string
		bad  bool
	}{
		{name: "evs.head_cas"},
		{name: "evs.head_cas.before"},
		{name: "evs.head_cas.after", key: "01JTESTREPO"},
		{name: "evs.step7.put", key: "018f3a2c-0000-7000-8000-000000000000"},
		{name: "mls.commit", key: "a1b2:c3d4"},
		{name: "head_cas", bad: true},
		{name: "Evs.HeadCas", bad: true},
		{name: "evs head cas", bad: true},
		{name: "evs.", bad: true},
		{name: "", bad: true},
		{name: "evs.head_cas", key: "a/b/c", bad: true},
		{name: "evs.head_cas", key: "my file.txt", bad: true},
		{name: "evs.head_cas", key: "person@example.org", bad: true},
		{name: "evs.head_cas", key: strings.Repeat("x", 129), bad: true},
	}
	for _, c := range cases {
		if violation := barrierViolation(c.name, c.key); (violation != "") != c.bad {
			t.Errorf("name %q key %q: violation %q, want bad %v", c.name, c.key, violation, c.bad)
		}
	}
}

func TestBarrierReportsABrokenNameOnce(t *testing.T) {
	driver, _ := newBarrierFixture(t, nil)
	driver.Hit("not-a-barrier", "")
	driver.Hit("not-a-barrier", "")
	driver.Hit("evs.head_cas", "some/path")
	if violations := driver.Violations(); len(violations) != 2 {
		t.Errorf("violations %v", violations)
	}
}

func TestBarrierArmRefusesABrokenSite(t *testing.T) {
	driver, _ := newBarrierFixture(t, nil)
	if err := driver.Arm("not-a-barrier", "", 0); err == nil {
		t.Error("armed a broken name")
	}
	if err := driver.Arm("evs.head_cas@a/b", "", 0); err == nil {
		t.Error("armed a broken key")
	}
}

func TestBarrierSkipLetsEarlierArrivalsPass(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	if err := driver.Arm("evs.retry", "", 2); err != nil {
		t.Fatal(err)
	}
	passed := 0
	run := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		for range 3 {
			driver.Hit("evs.retry", "")
			passed += 1
		}
		return nil
	})
	if err := driver.AwaitHeld(t.Context(), "evs.retry", ""); err != nil {
		t.Fatal(err)
	}
	if err := driver.Release("evs.retry"); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, run)
	if passed != 3 {
		t.Errorf("passed %d", passed)
	}
	held := 0
	for _, event := range driver.Trace() {
		if event.Kind == BarrierHeld {
			held += 1
		}
	}
	if held != 1 {
		t.Errorf("%d holds", held)
	}
}

func TestBarrierArmForOneActorLetsAnotherPass(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	if err := driver.Arm("evs.head_cas", "writerB", 0); err != nil {
		t.Fatal(err)
	}
	writerA := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		driver.Hit("evs.head_cas", "")
		return nil
	})
	awaitEnded(t, writerA)

	writerB := driver.Start(table.Actor(t.Context(), "writerB"), func() error {
		driver.Hit("evs.head_cas", "")
		return nil
	})
	if err := driver.AwaitHeld(t.Context(), "evs.head_cas", "writerB"); err != nil {
		t.Fatal(err)
	}
	if err := driver.Release(ActorBarrierSite("writerB", "evs.head_cas")); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, writerB)
}

func TestBarrierReleaseChoosesAmongActorsHeldAtOneSite(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	for range 2 {
		if err := driver.Arm("evs.head_cas", "", 0); err != nil {
			t.Fatal(err)
		}
	}
	finished := []string{}
	start := func(name string) *ActorRun {
		return driver.Start(table.Actor(t.Context(), name), func() error {
			driver.Hit("evs.head_cas", "")
			finished = append(finished, name)
			return nil
		})
	}
	writerA := start("writerA")
	if err := driver.AwaitHeld(t.Context(), "evs.head_cas", "writerA"); err != nil {
		t.Fatal(err)
	}
	writerB := start("writerB")
	if err := driver.AwaitHeld(t.Context(), "evs.head_cas", "writerB"); err != nil {
		t.Fatal(err)
	}

	// the later arrival goes first, because the schedule says so
	if err := driver.Release(ActorBarrierSite("writerB", "evs.head_cas")); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, writerB)
	if err := driver.Release("evs.head_cas"); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, writerA)
	if !slices.Equal(finished, []string{"writerB", "writerA"}) {
		t.Errorf("finished %v", finished)
	}
}

// With no seed the baton moves only at a hold, a block or an end, so each actor's writes here are
// unsynchronized on purpose: the race detector would report any overlap.
func TestBatonRunsActorsOneAtATimeInArrivalOrder(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	order := []string{}
	runs := []*ActorRun{}
	for _, name := range []string{"writerA", "writerB", "writerC"} {
		runs = append(runs, driver.Start(table.Actor(t.Context(), name), func() error {
			for step := range 3 {
				order = append(order, fmt.Sprintf("%s%d", name, step))
				driver.Hit("evs.step", "")
			}
			return nil
		}))
	}
	for _, run := range runs {
		awaitEnded(t, run)
	}
	want := []string{"writerA0", "writerA1", "writerA2", "writerB0", "writerB1", "writerB2", "writerC0", "writerC1", "writerC2"}
	if !slices.Equal(order, want) {
		t.Errorf("order %v", order)
	}
}

func exploreOrder(t *testing.T, seed int64) []string {
	driver, table := newBarrierFixture(t, nil)
	driver.SetSeed(seed)
	order := []string{}
	// queues every actor before any of them runs, as a schedule's step does
	driver.Pause()
	runs := []*ActorRun{}
	for _, name := range []string{"writerA", "writerB", "writerC"} {
		runs = append(runs, driver.Start(table.Actor(t.Context(), name), func() error {
			for step := range 4 {
				order = append(order, fmt.Sprintf("%s%d", name, step))
				driver.Hit("evs.step", "")
			}
			return nil
		}))
	}
	driver.Resume()
	for _, run := range runs {
		awaitEnded(t, run)
	}
	return order
}

func TestSeedGivesOneOrderAndAnotherSeedAnother(t *testing.T) {
	first := exploreOrder(t, 7)
	if again := exploreOrder(t, 7); !slices.Equal(first, again) {
		t.Errorf("one seed gave two orders:\n%v\n%v", first, again)
	}
	orders := map[string]bool{}
	for seed := range int64(20) {
		orders[strings.Join(exploreOrder(t, seed), " ")] = true
	}
	if len(orders) < 2 {
		t.Errorf("20 seeds gave %d orders", len(orders))
	}
}

func TestPauseKeepsActorsFromStartingUntilResume(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	driver.Pause()
	run := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		return nil
	})
	func() {
		driver.stateLock.Lock()
		defer driver.stateLock.Unlock()
		if driver.batonHolder != nil || len(driver.batonWaiters) != 1 {
			t.Errorf("holder %v waiters %d", driver.batonHolder, len(driver.batonWaiters))
		}
	}()
	driver.Resume()
	awaitEnded(t, run)
}

func TestBlockingLetsAnotherActorRun(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	unblock := make(chan struct{})
	order := []string{}
	writerA := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		order = append(order, "a-before")
		driver.Blocking(func() { <-unblock })
		order = append(order, "a-after")
		return nil
	})
	writerB := driver.Start(table.Actor(t.Context(), "writerB"), func() error {
		order = append(order, "b")
		close(unblock)
		return nil
	})
	awaitEnded(t, writerA)
	awaitEnded(t, writerB)
	if !slices.Equal(order, []string{"a-before", "b", "a-after"}) {
		t.Errorf("order %v", order)
	}
}

func TestSettleWaitsForEveryActorToStop(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	if err := driver.Arm("evs.head_cas", "", 0); err != nil {
		t.Fatal(err)
	}
	steps := 0
	writerA := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		steps += 1
		driver.Hit("evs.head_cas", "")
		return nil
	})
	if err := driver.Settle(t.Context()); err != nil {
		t.Fatal(err)
	}
	if steps != 1 {
		t.Errorf("settled at step %d", steps)
	}
	if held := driver.HeldSites(); len(held) != 1 {
		t.Errorf("held %v", held)
	}
	if err := driver.Release("evs.head_cas"); err != nil {
		t.Fatal(err)
	}
	if err := driver.Settle(t.Context()); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, writerA)
}

func TestAnActorBlockedOutOfSightLosesTheBaton(t *testing.T) {
	settings := DefaultBarrierDriverSettings()
	settings.StallTimeout = 1 * time.Millisecond
	settings.StallSampleInterval = 1 * time.Millisecond
	driver, table := newBarrierFixture(t, settings)
	blocked := make(chan struct{})
	defer close(blocked)
	driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		// a wait no fake reports
		<-blocked
		return nil
	})
	writerB := driver.Start(table.Actor(t.Context(), "writerB"), func() error {
		return nil
	})
	if err := driver.Settle(t.Context()); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, writerB)
	if !slices.ContainsFunc(driver.Trace(), func(event *BarrierEvent) bool {
		return event.Kind == BarrierStalled && event.Actor == "writerA"
	}) {
		t.Errorf("no stall in the trace: %v", driver.Trace())
	}
}

func stallTestSettings() *BarrierDriverSettings {
	settings := DefaultBarrierDriverSettings()
	settings.StallTimeout = 1 * time.Millisecond
	settings.StallSampleInterval = 1 * time.Millisecond
	return settings
}

// Works, on the calling goroutine and with no barrier, until the driver has read actorName's goroutines
// past the stall bound and found it working, or stop is set.
func workUntilFoundSlow(driver *BarrierDriver, actorName string, stop *atomic.Bool) {
	for !stop.Load() && !slices.Contains(driver.SlowActors(), actorName) {
	}
}

func hasStall(trace []*BarrierEvent) bool {
	return slices.ContainsFunc(trace, func(event *BarrierEvent) bool {
		return event.Kind == BarrierStalled
	})
}

func traceLines(trace []*BarrierEvent) []string {
	lines := []string{}
	for _, event := range trace {
		lines = append(lines, strings.Join(strings.Fields(event.String()), " "))
	}
	return lines
}

// An actor busy between two barriers for longer than the stall bound is slow, not blocked: it keeps the
// baton, and the actor behind it runs only after it, as the schedule has it.
func TestAnActorWorkingPastTheStallBoundKeepsTheBaton(t *testing.T) {
	driver, table := newBarrierFixture(t, stallTestSettings())
	stop := &atomic.Bool{}
	defer stop.Store(true)
	writerA := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		workUntilFoundSlow(driver, "writerA", stop)
		driver.Hit("evs.head_cas.before", "")
		return nil
	})
	writerB := driver.Start(table.Actor(t.Context(), "writerB"), func() error {
		driver.Hit("evs.head_cas.before", "")
		return nil
	})
	if err := driver.Settle(t.Context()); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, writerA)
	awaitEnded(t, writerB)
	want := []string{
		"ran writerA",
		"passed writerA evs.head_cas.before",
		"ran writerB",
		"passed writerB evs.head_cas.before",
	}
	if lines := traceLines(driver.Trace()); !slices.Equal(lines, want) {
		t.Errorf("trace %q", lines)
	}
	if slow := driver.SlowActors(); !slices.Equal(slow, []string{"writerA"}) {
		t.Errorf("slow %v", slow)
	}
}

// The same for an actor that waits, where no barrier sees, on a goroutine of its own that is still
// working, as a push in parts waits for its parts.
func TestAnActorWaitingOnItsOwnWorkingGoroutineKeepsTheBaton(t *testing.T) {
	driver, table := newBarrierFixture(t, stallTestSettings())
	stop := &atomic.Bool{}
	defer stop.Store(true)
	writerA := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		outer := make(chan struct{})
		go func() {
			defer close(outer)
			inner := make(chan struct{})
			go func() {
				defer close(inner)
				workUntilFoundSlow(driver, "writerA", stop)
			}()
			<-inner
		}()
		<-outer
		driver.Hit("evs.head_cas.before", "")
		return nil
	})
	writerB := driver.Start(table.Actor(t.Context(), "writerB"), func() error {
		return nil
	})
	if err := driver.Settle(t.Context()); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, writerA)
	awaitEnded(t, writerB)
	want := []string{
		"ran writerA",
		"passed writerA evs.head_cas.before",
		"ran writerB",
	}
	if lines := traceLines(driver.Trace()); !slices.Equal(lines, want) {
		t.Errorf("trace %q", lines)
	}
}

// And for one that waits on a goroutine it did not start, which is still working: a goroutine no actor
// owns runs free, and what it does may be what the holder waits for.
func TestAnActorWaitingOnAFreeWorkingGoroutineKeepsTheBaton(t *testing.T) {
	driver, table := newBarrierFixture(t, stallTestSettings())
	stop := &atomic.Bool{}
	defer stop.Store(true)
	work := make(chan struct{})
	worked := make(chan struct{})
	go func() {
		defer close(worked)
		<-work
		workUntilFoundSlow(driver, "writerA", stop)
	}()
	writerA := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		close(work)
		<-worked
		return nil
	})
	writerB := driver.Start(table.Actor(t.Context(), "writerB"), func() error {
		return nil
	})
	if err := driver.Settle(t.Context()); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, writerA)
	awaitEnded(t, writerB)
	if lines := traceLines(driver.Trace()); !slices.Equal(lines, []string{"ran writerA", "ran writerB"}) {
		t.Errorf("trace %q", lines)
	}
}

// An actor that waits out of sight on a run it started itself is blocked: that run is under the baton,
// which its starter holds. It loses the baton as any blocked actor does.
func TestAnActorWaitingOnARunItStartedLosesTheBaton(t *testing.T) {
	driver, table := newBarrierFixture(t, stallTestSettings())
	writerA := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		evs1 := driver.Start(table.Actor(t.Context(), "evs1"), func() error {
			return nil
		})
		// no Blocking around it
		<-evs1.Ended()
		return nil
	})
	if err := driver.Settle(t.Context()); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, writerA)
	want := []string{"ran writerA", "stalled writerA", "ran evs1"}
	if lines := traceLines(driver.Trace()); !slices.Equal(lines, want) {
		t.Errorf("trace %q", lines)
	}
}

// A working actor keeps the baton only until §22.8's wait, which fails with what the actor was seen
// doing and takes nothing from it.
func TestAnActorWorkingPastTheAwaitTimeoutFailsTheWait(t *testing.T) {
	settings := stallTestSettings()
	settings.AwaitTimeout = 200 * time.Millisecond
	driver, table := newBarrierFixture(t, settings)
	stop := &atomic.Bool{}
	writerA := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		for !stop.Load() {
		}
		return nil
	})
	writerB := driver.Start(table.Actor(t.Context(), "writerB"), func() error {
		return nil
	})
	err := driver.Settle(t.Context())
	if err == nil || !strings.Contains(err.Error(), "waited 200ms for the actors to settle, with writerA holding the baton") {
		t.Errorf("err %v", err)
	}
	trace := driver.Trace()
	if lines := traceLines(trace); !slices.Equal(lines, []string{"ran writerA"}) {
		t.Errorf("trace %q", lines)
	}
	stop.Store(true)
	awaitEnded(t, writerA)
	awaitEnded(t, writerB)
}

// What stands between a hold and its stall is settings.StallSampleCount readings in a row that find it
// blocked: short of that many the actor keeps the baton, and the wait's error says what the last saw.
func TestABlockedActorKeepsTheBatonShortOfTheReadingsItTakes(t *testing.T) {
	settings := stallTestSettings()
	settings.StallSampleCount = 1 << 30
	settings.AwaitTimeout = 100 * time.Millisecond
	driver, table := newBarrierFixture(t, settings)
	blocked := make(chan struct{})
	writerA := driver.Start(table.Actor(t.Context(), "writerA"), func() error {
		<-blocked
		return nil
	})
	err := driver.Settle(t.Context())
	if err == nil || !strings.Contains(err.Error(), "with writerA holding the baton") || !strings.Contains(err.Error(), "chan receive") {
		t.Errorf("err %v", err)
	}
	if trace := driver.Trace(); hasStall(trace) {
		t.Errorf("trace %q", traceLines(trace))
	}
	close(blocked)
	awaitEnded(t, writerA)
}

func TestParseGoroutineDump(t *testing.T) {
	dump := strings.Join([]string{
		"goroutine 41 [running]:",
		"github.com/urnetwork/sidecar/sidecartest.dumpGoroutines(0x100000)",
		"\t/src/sidecartest/barrier_stall.go:68 +0x34",
		"created by testing.(*T).Run in goroutine 1",
		"\t/go/src/testing/testing.go:2101 +0x3a8",
		"",
		"goroutine 1 [chan receive, 3 minutes]:",
		"testing.(*T).Run(0x14000102a80, {0x1029d2f4b, 0x2a}, 0x102b5d2c0)",
		"\t/go/src/testing/testing.go:2102 +0x3c4",
		"",
		"goroutine 57 gp=0x14000503dc0 m=nil [select, locked to thread] {actor: writerA, \"a key\": \"[x]:\"}:",
		"github.com/urnetwork/sidecar/sidecartest.(*BarrierDriver).awaitBaton(0x140001a2000, 0x14000196000)",
		"\t/src/sidecartest/barrier.go:590 +0x1a0",
		"created by github.com/urnetwork/sidecar/sidecartest.(*BarrierDriver).Start in goroutine 41",
		"\t/src/sidecartest/barrier.go:652 +0x2c0",
		"",
		"goroutine 58 [IO wait]:",
		"internal/poll.runtime_pollWait(0x1034c8a00, 0x72)",
		"\t/go/src/runtime/netpoll.go:351 +0xa0",
		"created by net/http.(*Server).Serve in goroutine 57",
		"\t/go/src/net/http/server.go:3454 +0x3d8",
		"",
		"goroutine 59 [sync.Mutex.Lock (scan)]:",
		"sync.(*Mutex).Lock(...)",
		"",
	}, "\n")
	states := parseGoroutineDump([]byte(dump))
	got := []string{}
	for _, state := range states {
		got = append(got, fmt.Sprintf("%d|%s|%s|%d", state.id, state.state, state.function, state.creatorId))
	}
	want := []string{
		"41|running|github.com/urnetwork/sidecar/sidecartest.dumpGoroutines|1",
		"1|chan receive|testing.(*T).Run|0",
		"57|select|github.com/urnetwork/sidecar/sidecartest.(*BarrierDriver).awaitBaton|41",
		"58|IO wait|internal/poll.runtime_pollWait|57",
		"59|sync.Mutex.Lock (scan)|sync.(*Mutex).Lock|0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("states %q", got)
	}
}

// The runtime's own dump reads back: this goroutine first and running, and one it started parked on a
// channel under its id.
func TestDumpGoroutinesReadsTheRuntimesDump(t *testing.T) {
	parked := make(chan struct{})
	defer close(parked)
	arrived := make(chan uint64)
	go func() {
		arrived <- currentGoroutineId()
		<-parked
	}()
	startedId := <-arrived
	// a buffer too small to hold it, so it grows
	states := dumpGoroutines(1)
	if len(states) == 0 || states[0].id != currentGoroutineId() || states[0].state != "running" {
		t.Fatalf("first %+v", states[0])
	}
	index := slices.IndexFunc(states, func(state *goroutineState) bool { return state.id == startedId })
	if index < 0 {
		t.Fatalf("goroutine %d is not in the dump", startedId)
	}
	// between its send and its receive it may still be on its way to park
	if started := states[index]; started.creatorId != currentGoroutineId() || (started.state != "chan receive" && started.state != "runnable") {
		t.Errorf("started %+v", started)
	}
}

func TestGoroutinesBlocked(t *testing.T) {
	sampler := &goroutineState{id: 1, state: "running"}
	cases := []struct {
		name            string
		states          []*goroutineState
		runGoroutineIds map[uint64]bool
		blocked         bool
	}{
		{"parked alone", []*goroutineState{sampler, {id: 7, state: "chan receive"}}, nil, true},
		{"not started", []*goroutineState{sampler}, nil, false},
		{"runnable", []*goroutineState{sampler, {id: 7, state: "runnable"}}, nil, false},
		{"in a system call", []*goroutineState{sampler, {id: 7, state: "syscall"}}, nil, false},
		{"on the network", []*goroutineState{sampler, {id: 7, state: "IO wait"}}, nil, false},
		{"a state not known", []*goroutineState{sampler, {id: 7, state: "chan receive (scan)"}}, nil, false},
		{"sleeping", []*goroutineState{sampler, {id: 7, state: "sleep"}}, nil, true},
		{"its own parked", []*goroutineState{sampler, {id: 7, state: "select"}, {id: 8, state: "sync.Mutex.Lock", creatorId: 7}}, nil, true},
		{"its own's own on the network", []*goroutineState{
			sampler, {id: 7, state: "select"}, {id: 8, state: "sync.WaitGroup.Wait", creatorId: 7}, {id: 9, state: "IO wait", creatorId: 8},
		}, nil, false},
		{"another's on the network", []*goroutineState{sampler, {id: 7, state: "select"}, {id: 9, state: "IO wait", creatorId: 3}}, nil, true},
		{"another's in a system call", []*goroutineState{sampler, {id: 7, state: "select"}, {id: 9, state: "syscall", creatorId: 3}}, nil, true},
		{"another's runnable", []*goroutineState{sampler, {id: 7, state: "select"}, {id: 9, state: "runnable", creatorId: 3}}, nil, false},
		{"a run it started on the network", []*goroutineState{
			sampler, {id: 7, state: "select"}, {id: 8, state: "IO wait", creatorId: 7}, {id: 9, state: "IO wait", creatorId: 8},
		}, map[uint64]bool{7: true, 8: true}, true},
	}
	for _, each := range cases {
		blocked, seen := goroutinesBlocked(each.states, 7, each.runGoroutineIds)
		if blocked != each.blocked || seen == "" {
			t.Errorf("%s: blocked %t, seen %q", each.name, blocked, seen)
		}
	}
}

func TestAKilledActorHeldAtABarrierRunsNothingMore(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	if err := driver.Arm("evs.head_cas", "", 0); err != nil {
		t.Fatal(err)
	}
	actor := table.Actor(t.Context(), "evs1")
	ranAfter := false
	deferredRan := make(chan struct{})
	run := driver.Start(actor, func() error {
		defer close(deferredRan)
		driver.Hit("evs.head_cas", "")
		ranAfter = true
		return nil
	})
	if err := driver.AwaitHeld(t.Context(), "evs.head_cas", ""); err != nil {
		t.Fatal(err)
	}

	actor.Kill()
	driver.AbandonHeld("evs1")

	awaitEnded(t, run)
	if err := actor.Context().Err(); err != context.Canceled {
		t.Errorf("context %v", err)
	}
	if run.Err() != nil {
		t.Errorf("err %v", run.Err())
	}
	select {
	case <-deferredRan:
		t.Fatal("a deferred call ran in a dead process")
	default:
	}

	driver.Reap()
	select {
	case <-deferredRan:
	case <-time.After(10 * time.Second):
		t.Fatal("the goroutine never left")
	}
	if ranAfter {
		t.Error("code after the barrier ran")
	}
}

func TestARunningActorStopsAtItsNextBarrierOnceKilled(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	actor := table.Actor(t.Context(), "evs1")
	killed := make(chan struct{})
	reached := make(chan struct{})
	ranAfter := false
	run := driver.Start(actor, func() error {
		close(reached)
		<-killed
		driver.Hit("evs.head_cas", "")
		ranAfter = true
		return nil
	})
	<-reached
	actor.Kill()
	close(killed)
	awaitEnded(t, run)
	driver.Reap()
	if ranAfter {
		t.Error("code after the barrier ran")
	}
}

func TestARestartedActorIsANewIncarnation(t *testing.T) {
	_, table := newBarrierFixture(t, nil)
	first := table.Actor(t.Context(), "evs1")
	if table.Actor(t.Context(), "evs1") != first {
		t.Error("a running actor got a second incarnation")
	}
	first.Kill()
	second := table.Actor(t.Context(), "evs1")
	if second == first {
		t.Fatal("a killed actor was reused")
	}
	if second.Context().Err() != nil {
		t.Errorf("the new incarnation's context: %v", second.Context().Err())
	}
}

func TestActorContextCarriesItsNameAndClock(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	driver := NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	table := NewActorTable(clock, driver)
	actor := table.Actor(t.Context(), "evs2")
	actor.SetClockOffset(clock, 150*time.Millisecond)

	if name := ActorName(actor.Context()); name != "evs2" {
		t.Errorf("name %q", name)
	}
	if ActorName(t.Context()) != "" {
		t.Error("a plain context named an actor")
	}
	if got := clockOf(actor.Context(), clock).Now().Sub(clock.Now()); got != 150*time.Millisecond {
		t.Errorf("offset %v", got)
	}
	if clockOf(t.Context(), clock) != Clock(clock) {
		t.Error("a plain context did not fall back")
	}
}

func TestBarrierEventReadsInATrace(t *testing.T) {
	event := &BarrierEvent{Kind: BarrierHeld, Name: "evs.head_cas", Key: "repoA", Actor: "writerA"}
	if text := event.String(); !strings.Contains(text, "evs.head_cas@repoA") || !strings.Contains(text, "writerA") {
		t.Errorf("text %q", text)
	}
}
