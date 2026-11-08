package sidecartest

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/device"
)

// One fake serves the root and the device role (TEST-M0-02): device/ declares the root's method set
// again, since it may not import the root.
var (
	_ sidecar.Clock = (*FakeClock)(nil)
	_ device.Clock  = (*FakeClock)(nil)
	_ sidecar.Clock = (*offsetClock)(nil)
	_ device.Clock  = (*offsetClock)(nil)
)

// A host's view of the shared clock goes into its ServiceHost and a Sidecar's settings as it is, so
// FS-1's evs2 reads 150 ms ahead while its timers run on the shared clock.
func TestAnOffsetViewIsAHostsClock(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	view := clock.WithOffset(150 * time.Millisecond)
	host := &sidecar.ServiceHost{Clock: view}
	if got := host.ClockOrReal().Now().Sub(clock.Now()); got != 150*time.Millisecond {
		t.Fatalf("the host reads %s ahead", got)
	}
	settings := &sidecar.SidecarSettings{Clock: view}
	fired := settings.ClockOrReal().After(time.Second)
	clock.Advance(time.Second)
	select {
	case <-fired:
	default:
		t.Fatal("a timer on the view did not fire when the shared clock passed it")
	}
}

func TestFakeClockStartsWhereItIsToldAndStays(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	if !clock.Now().Equal(DefaultClockStart()) {
		t.Errorf("now %v", clock.Now())
	}
	first := clock.Now()
	if !clock.Now().Equal(first) {
		t.Error("the clock moved with nobody advancing it")
	}
}

func TestFakeClockFiresOnlyWhenMovedPast(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	fired := clock.After(10 * time.Second)

	clock.Advance(9 * time.Second)
	select {
	case <-fired:
		t.Fatal("fired before its time")
	default:
	}

	clock.Advance(1 * time.Second)
	select {
	case at := <-fired:
		if want := DefaultClockStart().Add(10 * time.Second); !at.Equal(want) {
			t.Errorf("fired at %v, want %v", at, want)
		}
	default:
		t.Fatal("did not fire at its time")
	}
}

func TestFakeClockFiresTimersInTimeOrderEachAtItsTime(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	start := clock.Now()
	var offsets []time.Duration
	note := func() {
		offsets = append(offsets, clock.Now().Sub(start))
	}
	clock.AfterFunc(3*time.Second, note)
	clock.AfterFunc(1*time.Second, func() {
		note()
		// added during the move, nearer than the 3 s timer, so it runs first
		clock.AfterFunc(1*time.Second, note)
	})

	clock.Advance(10 * time.Second)

	want := []time.Duration{1 * time.Second, 2 * time.Second, 3 * time.Second}
	if len(offsets) != len(want) {
		t.Fatalf("offsets %v", offsets)
	}
	for i := range want {
		if offsets[i] != want[i] {
			t.Errorf("offset %d: %v, want %v", i, offsets[i], want[i])
		}
	}
	if !clock.Now().Equal(start.Add(10 * time.Second)) {
		t.Errorf("ended at %v", clock.Now())
	}
}

func TestFakeClockTimersAtOneTimeFireInTheOrderSet(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	var order []int
	for i := 0; i < 5; i += 1 {
		clock.AfterFunc(1*time.Second, func() { order = append(order, i) })
	}
	clock.Advance(1 * time.Second)
	for i := 0; i < 5; i += 1 {
		if len(order) != 5 || order[i] != i {
			t.Fatalf("order %v", order)
		}
	}
}

func TestFakeClockStopCancelsATimerOnce(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	calls := 0
	stop := clock.AfterFunc(1*time.Second, func() { calls += 1 })
	if !stop() {
		t.Error("the first stop found nothing to stop")
	}
	if stop() {
		t.Error("the second stop stopped something")
	}
	clock.Advance(2 * time.Second)
	if calls != 0 {
		t.Errorf("%d calls after stop", calls)
	}
}

func TestFakeClockZeroTimeoutFiresAtOnce(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	select {
	case <-clock.After(0):
	default:
		t.Fatal("a zero timeout waited")
	}
	calls := 0
	if stop := clock.AfterFunc(0, func() { calls += 1 }); stop() {
		t.Error("a function already called was stopped")
	}
	if calls != 1 {
		t.Errorf("%d calls", calls)
	}
}

func TestFakeClockRefusesToMoveBack(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("a negative move passed")
		}
	}()
	NewFakeClock(DefaultClockStart()).Advance(-1 * time.Second)
}

func TestFakeClockAwaitTimersSeesAWaiterArrive(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	woke := make(chan struct{})
	go func() {
		defer close(woke)
		<-clock.After(5 * time.Second)
	}()

	if err := clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	clock.Advance(5 * time.Second)
	<-woke
}

func TestFakeClockAwaitTimersEndsWithItsContext(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := clock.AwaitTimers(ctx, 1); err != context.Canceled {
		t.Errorf("err %v", err)
	}
}

func TestOffsetClockReadsAheadAndWaitsOnTheSharedClock(t *testing.T) {
	clock := NewFakeClock(DefaultClockStart())
	fast := clock.WithOffset(150 * time.Millisecond)
	if got := fast.Now().Sub(clock.Now()); got != 150*time.Millisecond {
		t.Errorf("offset %v", got)
	}

	fired := fast.After(1 * time.Second)
	clock.Advance(999 * time.Millisecond)
	select {
	case <-fired:
		t.Fatal("an offset shortened a timeout")
	default:
	}
	clock.Advance(1 * time.Millisecond)
	select {
	case <-fired:
	default:
		t.Fatal("did not fire")
	}
}
