package evsservice

// The evs service's waits that end with their context (clock-select-ctx-sweep). The purge's pace selected on the
// purge's end beside the timer for the next DELETE's turn and answered nil whenever select took the timer as the purge
// ended, so its caller issued that DELETE on the dead context. It now answers the end whatever else was ready. The
// proof is sidecartest.EndingClock, which ends the purge as the turn's timer fires and moves to the turn's time, as a
// real timer finds it passed, over 64 rounds, which leave the old coin no chance (at most (1/2)^64) to pass.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
)

// The purge's pace lets no DELETE issue once the purge has ended: with one DELETE just taken its turn, the next
// waits until 1/DeleteRate s on, and an end landing as that wait's timer fires answers the purge's error, in each of
// 64 rounds; a purge ended before the wait asks the clock for nothing. A pace that took the timer's case found the
// turn come and answered nil, and its DELETE went out on the dead context.
func TestPurgerPaceAnswersTheEndOfThePurge(t *testing.T) {
	settings := DefaultPurgerSettings()
	turn := time.Second / time.Duration(settings.DeleteRate)
	// a purger on clock, its pace's own select in force (no wait seam)
	newPurgerOn := func(clock *sidecartest.EndingClock) *Purger {
		hostClock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
		host := sidecartest.NewFakeHost(t.Context(), hostClock, nil, nil, sidecartest.DefaultFakeHostSettings())
		serviceHost := host.ServiceHost()
		serviceHost.Clock = clock
		purger, err := newPurger(t.Context(), serviceHost, &PurgerDeps{Settings: settings})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(purger.Close)
		return purger
	}
	for round := range 64 {
		clock := sidecartest.NewEndingClock(sidecartest.DefaultClockStart(), sidecartest.EndingClockCounts(turn))
		clock.MoveOnFire()
		purger := newPurgerOn(clock)
		clock.Open()
		// the first DELETE takes its turn at once
		if err := purger.pace(); err != nil {
			t.Fatalf("round %d: the first turn: %v", round, err)
		}
		clock.Arm(1, purger.cancel)
		if err := purger.pace(); !errors.Is(err, context.Canceled) || clock.Waits() != 1 {
			t.Fatalf("round %d: the second turn answered %v after %d waits, want the purge's end after 1", round, err, clock.Waits())
		}
	}
	clock := sidecartest.NewEndingClock(sidecartest.DefaultClockStart(), nil)
	purger := newPurgerOn(clock)
	clock.Open()
	if err := purger.pace(); err != nil {
		t.Fatalf("the first turn: %v", err)
	}
	purger.cancel()
	if err := purger.pace(); !errors.Is(err, context.Canceled) || clock.Asks() != 0 {
		t.Fatalf("an ended purge's turn answered %v after %d waits, want its end after none", err, clock.Asks())
	}
}
