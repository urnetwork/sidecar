// Holds the root's Clock to operator-core's method set on every leg (QD-856): the alias on every leg but
// sidecar_http, and clock_http.go's own interface on that one, which the page Worker's run reads
// (TestHttpLegPassesInAWorker names the test).

package sidecar

import (
	"reflect"
	"slices"
	"testing"
	"time"
)

// operator-core's Clock, method for method, so sidecartest's FakeClock serves either.
func TestClockTwinHoldsOperatorCoresMethods(t *testing.T) {
	clockType := reflect.TypeFor[Clock]()
	if clockType.Kind() != reflect.Interface {
		t.Fatalf("Clock is a %s", clockType.Kind())
	}
	methods := []string{}
	for index := 0; index < clockType.NumMethod(); index += 1 {
		method := clockType.Method(index)
		methods = append(methods, method.Name+" "+method.Type.String())
	}
	want := []string{
		"After func(time.Duration) <-chan time.Time",
		"AfterFunc func(time.Duration, func()) func() bool",
		"Now func() time.Time",
	}
	if !slices.Equal(methods, want) {
		t.Errorf("Clock's methods are %q, want %q", methods, want)
	}
}

// A nil Clock reads real time on every leg, and a set one is read as it is.
func TestClockTwinReadsRealTimeForNil(t *testing.T) {
	if _, ok := clockOrReal(nil).(RealClock); !ok {
		t.Errorf("a nil clock reads %T", clockOrReal(nil))
	}
	settings := &SidecarSettings{}
	if _, ok := settings.ClockOrReal().(RealClock); !ok {
		t.Errorf("unset settings read %T", settings.ClockOrReal())
	}
	clock := &clockTwinFixedClock{now: time.UnixMilli(1_700_000_000_000)}
	settings.Clock = clock
	if settings.ClockOrReal() != Clock(clock) || clockOrReal(clock) != Clock(clock) {
		t.Errorf("a set clock is not the one read")
	}
	if !settings.ClockOrReal().Now().Equal(clock.now) {
		t.Errorf("now %v", settings.ClockOrReal().Now())
	}
}

// A clock that stands still, to be told from RealClock.
type clockTwinFixedClock struct {
	now time.Time
}

func (self *clockTwinFixedClock) Now() time.Time {
	return self.now
}

func (self *clockTwinFixedClock) After(timeout time.Duration) <-chan time.Time {
	return make(chan time.Time)
}

func (self *clockTwinFixedClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool { return true }
}
