package sidecar

import (
	"testing"
	"time"
)

// A nil Clock reads real time, in a Sidecar's settings as in a host (TEST-M0-02).
func TestANilClockReadsRealTime(t *testing.T) {
	clock := (&SidecarSettings{}).ClockOrReal()
	if _, ok := clock.(RealClock); !ok {
		t.Fatalf("a nil clock reads %T", clock)
	}
	before := time.Now()
	now := clock.Now()
	after := time.Now()
	if now.Before(before) || now.After(after) {
		t.Fatalf("real time read %s outside [%s, %s]", now, before, after)
	}
}

// A clock the host set is the one read.
func TestASetClockIsTheOneRead(t *testing.T) {
	clock := fixedClock{at: time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)}
	if got := (&SidecarSettings{Clock: clock}).ClockOrReal().Now(); !got.Equal(clock.at) {
		t.Fatalf("read %s, want %s", got, clock.at)
	}
}

// Real time's waits keep the interface's promises: a timeout that is not positive fires at once, and
// stopping a call still to come returns true and the call never runs.
func TestRealClockKeepsTheClockPromises(t *testing.T) {
	clock := RealClock{}
	select {
	case <-clock.After(0):
	case <-time.After(time.Minute):
		t.Fatal("a zero timeout did not fire")
	}
	called := make(chan struct{})
	stop := clock.AfterFunc(time.Hour, func() { close(called) })
	if !stop() {
		t.Fatal("stopping a call still to come returned false")
	}
	if stop() {
		t.Fatal("stopping a stopped call returned true")
	}
	select {
	case <-called:
		t.Fatal("a stopped call ran")
	default:
	}
}

// A clock that stays at one time and never fires, for a test of which clock is read.
type fixedClock struct {
	at time.Time
}

func (self fixedClock) Now() time.Time {
	return self.at
}

func (self fixedClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self fixedClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}
