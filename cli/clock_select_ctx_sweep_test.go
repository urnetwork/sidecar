// The ur daemon's waits on its clock end with its context (clock-select-ctx-sweep; the root's
// clock_select_ctx_sweep_test.go has the sweep's account): the shared blocks' judgment, which waited on real time and
// now waits on the daemon's clock, and the cap on the core's clock checks each selected on the daemon's end beside a
// timer and went on whenever select took the timer as the end landed, judging the shared blocks, which raises
// shared_block for a share that is new, or running the core's checks, which publish at now, past the end. Each now
// answers the end whatever else was ready. The proof is sidecartest.EndingClock, which ends the context as a wait's
// timer fires, over 64 rounds.

package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Where the daemon's clocks stand in these cases.
func clockSelectUrTestStart() time.Time {
	return time.Date(2026, time.November, 27, 9, 0, 0, 0, time.UTC)
}

// Waits for done within a minute, failing the test with what otherwise.
func clockSelectUrAwait(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Minute):
		t.Fatalf("%s did not end within a minute", what)
	}
}

// The cap on the core's clocks checks nothing once the daemon has ended: it checks after each interval of the daemon's
// clock, and an end landing as the second wait fires ends the cap after the one check before it, in each of 64 rounds.
// A cap that took the timer's case ran the core's checks past the end.
func TestUrBridgeDaemonClockCapChecksNothingAfterItEnds(t *testing.T) {
	interval := time.Minute
	for round := range 64 {
		clock := sidecartest.NewEndingClock(clockSelectUrTestStart(), sidecartest.EndingClockCounts(interval))
		daemon := newUrBridgeDaemon(context.Background(), &urBridgeDaemonArgs{
			Settings:           testUrTunSettings(),
			ClockCheckInterval: interval,
			Clock:              clock,
		})
		checkCount := &atomic.Int64{}
		daemon.addClockCheck(func() {
			checkCount.Add(1)
		})
		clock.Arm(2, daemon.cancel)
		clock.Open()
		clockSelectUrAwait(t, daemon.clockCapDone, "the cap")
		daemon.cancel()
		if checks := checkCount.Load(); checks != 1 || clock.Waits() != 2 {
			t.Fatalf("round %d: %d checks after %d waits, want 1 after 2", round, checks, clock.Waits())
		}
	}
}

// The shared blocks are judged no more once the daemon has ended: the judgment runs after each SharedBlockInterval of
// the daemon's clock, and an end landing as the second wait fires ends it after the one judgment before it, in each of
// 64 rounds. Each judgment is followed by the next wait, so a judgment past the end shows as a wait asked past it: a
// loop that took the timer's case judged on the dead daemon, which raises shared_block for a share that is new.
func TestUrBridgeDaemonJudgesNoSharedBlocksAfterItEnds(t *testing.T) {
	settings := testUrTunSettings()
	for round := range 64 {
		clock := sidecartest.NewEndingClock(clockSelectUrTestStart(), sidecartest.EndingClockCounts(settings.SharedBlockInterval))
		// no cap and no resume watch, so the judgment's are the daemon's only waits
		daemon := newUrBridgeDaemon(context.Background(), &urBridgeDaemonArgs{Settings: settings, Clock: clock})
		clock.Arm(2, daemon.cancel)
		clock.Open()
		clockSelectUrAwait(t, daemon.sharedDone, "the judgment")
		daemon.cancel()
		if clock.Asks() != 2 {
			t.Fatalf("round %d: %d waits, want the 2 of 1 judgment and the end", round, clock.Asks())
		}
	}
}
