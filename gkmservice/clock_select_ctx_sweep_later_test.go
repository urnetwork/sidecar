package gkmservice

// The gkm reconciler's hint loop ends with its context (clock-sweep-later-pass; the root's clock_select_ctx_sweep_test.go
// holds the account). The loop selected on the reconciler's end beside its timer and a wake, and whenever select took
// the timer as the end landed it passed once more: it read the states the gate cache holds, which no dead context
// refuses, took the noted changes off their list, and asked the cache to load a network whose state it lacked. It now
// answers the end whatever else was ready. The proof is sidecartest.EndingClock, which ends the context as the loop's
// timer fires, over 64 rounds, which leave the old coin no chance (at most (1/2)^64) to pass.

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The hint loop passes no more once the reconciler has ended: holding no network, it passes at once and after each
// interval of the closed gates' hints, and an end landing as the second wait fires ends the loop after the two passes
// before it, idle as the end's case leaves it, in each of 64 rounds. A loop that took the timer's case passed on the
// dead reconciler.
func TestGkmReconcilerPassesNoMoreAfterItEnds(t *testing.T) {
	settings := DefaultGkmReconcilerSettings()
	interval := min(settings.PendingHintInterval, settings.DroppedLeafHintInterval)
	for round := range 64 {
		clock := sidecartest.NewEndingClock(sidecartest.DefaultClockStart(), sidecartest.EndingClockCounts(interval))
		ctx, cancel := context.WithCancel(context.Background())
		// what the loop reads of a reconciler: its context, settings, state, clock, tables and monitors
		reconciler := &GkmReconciler{
			ctx:            ctx,
			cancel:         cancel,
			settings:       settings,
			state:          newFakeGkmReconcilerState(),
			clock:          clock,
			log:            sidecar.NewNoopLogger(),
			networkEntries: map[sidecar.Id]*gkmReconcilerNetwork{},
			pendingChanges: map[sidecar.Id]*GkmStateChange{},
			closedGates:    map[sidecar.Id]*gkmClosedGate{},
			wake:           make(chan struct{}, 1),
			passCount:      sidecar.NewMonitorValue(0),
			idle:           sidecar.NewMonitorValue(false),
		}
		clock.Arm(2, cancel)
		clock.Open()
		done := make(chan struct{})
		go func() {
			defer close(done)
			reconciler.run()
		}()
		select {
		case <-done:
		case <-time.After(sidecartest.DefaultBarrierDriverSettings().AwaitTimeout):
			t.Fatalf("round %d: the hint loop did not end", round)
		}
		if passes, _ := reconciler.Passes(); passes != 2 || clock.Waits() != 2 || !reconciler.idle.Value() {
			t.Fatalf("round %d: %d passes and %d waits, idle %t; want 2 of each, idle", round, passes, clock.Waits(), reconciler.idle.Value())
		}
	}
}
