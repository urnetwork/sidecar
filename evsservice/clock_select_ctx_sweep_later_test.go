package evsservice

// The evs service's later waits that end with their context (clock-sweep-later-pass; the root's
// clock_select_ctx_sweep_test.go holds the account). The write budget's ticks, a drop's pace and the orphan GC's pace
// each selected on their end beside a clock's timer, and whenever select took the timer as the end landed they went on:
// a tick lapsed the shares, dispatched the waiters and moved the totals that Close's last reports then write, and a pace
// answered nil, so its HEAD or DELETE went on the dead context and its failure was answered or counted. Each now answers
// the end whatever else was ready. The proof is sidecartest.EndingClock, which ends the context as the wait's timer
// fires, over 64 rounds, which leave the old coin no chance (at most (1/2)^64) to pass.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// Waits for done within the barrier driver's bound, failing the test with what otherwise: a guard, never the proof.
func clockSweepLaterAwait(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(sidecartest.DefaultBarrierDriverSettings().AwaitTimeout):
		t.Fatalf("%s did not end", what)
	}
}

// The write budget ticks nothing once it has ended: it ticks each account at once and after each Interval, and an end
// landing as the second wait fires ends the ticks after the two before it, in each of 64 rounds. A loop that took the
// timer's case ticked on the dead budget, which lapses the shares, dispatches the waiters and moves the totals Close's
// last reports write with a live context.
func TestWriteBudgetTicksNothingAfterItEnds(t *testing.T) {
	settings := DefaultWriteBudgetSettings()
	clusterId := "meta-1"
	for round := range 64 {
		clock := sidecartest.NewEndingClock(sidecartest.DefaultClockStart(), sidecartest.EndingClockCounts(settings.Interval))
		host := sidecartest.NewFakeHost(t.Context(), sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), nil, nil, sidecartest.DefaultFakeHostSettings())
		serviceHost := host.ServiceHost()
		serviceHost.Clock = clock
		client, err := newWriteBudgetClient(t.Context(), serviceHost, []string{clusterId}, settings)
		if err != nil {
			t.Fatal(err)
		}
		clock.Arm(2, client.cancel)
		clock.Open()
		done := make(chan struct{})
		go func() {
			defer close(done)
			client.runAccounts()
		}()
		clockSweepLaterAwait(t, done, "the ticks")
		account := client.clusterIdAccounts[clusterId]
		account.stateLock.Lock()
		ticks := account.epoch
		account.stateLock.Unlock()
		if ticks != 2 || clock.Waits() != 2 {
			t.Fatalf("round %d: %d ticks and %d waits, want 2 of each", round, ticks, clock.Waits())
		}
	}
}

// A drop's pace lets nothing more go once the run has ended: with the second's one request spent, the next waits for
// the next second's start, and an end landing as that wait fires answers the run's error, in each of 64 rounds. A pace
// that took the timer's case found the second come and answered nil, and the HEAD or DELETE after it went on the dead
// context, whose failure the run then answered for the id.
func TestDropDeletePaceAnswersTheEndOfTheRun(t *testing.T) {
	for round := range 64 {
		clock := sidecartest.NewEndingClock(sidecartest.DefaultClockStart(), sidecartest.EndingClockCounts(time.Second))
		ctx, cancel := context.WithCancel(context.Background())
		run := &dropDeleteRun{
			deleter:   &DropDelete{clock: clock},
			ctx:       ctx,
			request:   &DropDeleteRequest{DeletesPerSecond: 1},
			paceStart: clock.Now(),
			paceCount: 1,
		}
		clock.Arm(1, cancel)
		clock.Open()
		if err := run.pace(); !errors.Is(err, context.Canceled) || clock.Waits() != 1 {
			t.Fatalf("round %d: the pace answered %v after %d waits, want canceled after 1", round, err, clock.Waits())
		}
	}
}

// The orphan GC's pace lets no DELETE go once its context has ended: with the segment cluster's next turn a DeleteRate's
// interval on, an end landing as that turn's wait fires, the clock moving to it as a real timer finds it passed,
// answers the context's error and claims no turn, in each of 64 rounds. A pace that took the timer's case claimed the
// turn and answered nil, and its DELETE went on the dead context to be counted failed.
func TestOrphanGcPaceAnswersTheEndOfItsContext(t *testing.T) {
	settings := DefaultOrphanGcSettings()
	interval := time.Second / time.Duration(settings.DeleteRate)
	clusterId := "segments-1"
	for round := range 64 {
		clock := sidecartest.NewEndingClock(sidecartest.DefaultClockStart(), sidecartest.EndingClockCounts(interval))
		clock.MoveOnFire()
		next := clock.Now().Add(interval)
		gc := &OrphanGc{
			deps: &OrphanGcDeps{SegmentClusterBusy: func(ctx context.Context, clusterId string) bool {
				return false
			}},
			settings:               settings,
			clock:                  clock,
			clusterNextDeleteTimes: map[string]time.Time{clusterId: next},
		}
		ctx, cancel := context.WithCancel(context.Background())
		clock.Arm(1, cancel)
		clock.Open()
		err := gc.pace(ctx, clusterId)
		gc.stateLock.Lock()
		claimed := gc.clusterNextDeleteTimes[clusterId] != next
		gc.stateLock.Unlock()
		if !errors.Is(err, context.Canceled) || claimed || clock.Waits() != 1 {
			t.Fatalf("round %d: the pace answered %v, a turn claimed %t, after %d waits; want canceled, none claimed, after 1", round, err, claimed, clock.Waits())
		}
	}
}
