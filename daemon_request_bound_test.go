//go:build !js && !ios && !android && !sdk_mobile_bind

package sidecar

// A control request's bound (QD-518) on a clock the test moves: it expires once at its timeout; a person's wait stops
// it, the request's own work before the wait staying counted and the rest running once the last wait ends; it never
// expires once its request ended; and runBounded's handler, waiting on a person, is neither timed out nor ended
// meanwhile, and is timed out once its own work passes the bound.

import (
	"context"
	"testing"
	"time"
)

// The bound expires once, at its timeout and not before; a wait after that changes nothing.
func TestRequestBoundExpiresAtItsTimeout(t *testing.T) {
	clock := newPresenceActTestClock()
	expired := 0
	bound := newDaemonRequestBound(clock, 30*time.Second, func() { expired += 1 })
	defer bound.end()
	clock.advance(30*time.Second - time.Millisecond)
	if expired != 0 {
		t.Fatal("the bound expired before its timeout")
	}
	clock.advance(time.Millisecond)
	if expired != 1 {
		t.Fatalf("the bound expired %d times at its timeout", expired)
	}
	resume := bound.personWait()
	resume()
	clock.advance(time.Hour)
	if expired != 1 {
		t.Fatalf("the bound expired %d times in all", expired)
	}
}

// A person's wait stops the bound: the request's own work before it stays counted, and once the last wait under way
// ends the bound runs on with the rest. Waits nest, and a wait's end counts once however often it is called.
func TestRequestBoundStandsStillWhileAPersonIsAsked(t *testing.T) {
	clock := newPresenceActTestClock()
	expired := 0
	bound := newDaemonRequestBound(clock, 30*time.Second, func() { expired += 1 })
	defer bound.end()
	clock.advance(10 * time.Second)
	resume := bound.personWait()
	clock.advance(10 * time.Minute)
	if expired != 0 {
		t.Fatal("the bound expired while the person was asked")
	}
	resumeInner := bound.personWait()
	resume()
	resume()
	clock.advance(10 * time.Minute)
	if expired != 0 {
		t.Fatal("the bound expired while a wait was still under way")
	}
	resumeInner()
	clock.advance(20*time.Second - time.Millisecond)
	if expired != 0 {
		t.Fatal("the bound expired before the rest of its own work's time passed")
	}
	clock.advance(time.Millisecond)
	if expired != 1 {
		t.Fatalf("the bound expired %d times once its own work's time passed", expired)
	}
}

// A wait that starts once the request's own work has spent the bound leaves nothing when it ends: the bound expires at
// once.
func TestRequestBoundSpentBeforeAWaitExpiresAfterIt(t *testing.T) {
	clock := newPresenceActTestClock()
	expired := 0
	bound := newDaemonRequestBound(clock, 30*time.Second, func() { expired += 1 })
	defer bound.end()
	// the clock passes the bound without firing it yet, as a busy host's timer may
	func() {
		clock.stateLock.Lock()
		defer clock.stateLock.Unlock()
		clock.now = clock.now.Add(31 * time.Second)
	}()
	resume := bound.personWait()
	clock.advance(time.Minute)
	if expired != 0 {
		t.Fatal("the bound expired while the person was asked")
	}
	resume()
	clock.advance(0)
	if expired != 1 {
		t.Fatalf("the spent bound expired %d times after the wait", expired)
	}
}

// A bound whose request ended never expires, and a wait on it changes nothing; a context with no bounded request has no
// bound to stop, and one carrying a bound stops that one.
func TestRequestBoundEndsWithItsRequest(t *testing.T) {
	clock := newPresenceActTestClock()
	expired := 0
	bound := newDaemonRequestBound(clock, 30*time.Second, func() { expired += 1 })
	resume := bound.personWait()
	bound.end()
	resume()
	bound.personWait()()
	clock.advance(time.Hour)
	if expired != 0 {
		t.Fatal("an ended request's bound expired")
	}

	daemonPersonWait(context.Background())()
	other := newDaemonRequestBound(clock, 30*time.Second, func() { expired += 1 })
	defer other.end()
	resumeOther := daemonPersonWait(withDaemonRequestBound(context.Background(), other))
	clock.advance(time.Hour)
	if expired != 0 {
		t.Fatal("the context's bound expired while the person was asked")
	}
	resumeOther()
	clock.advance(30 * time.Second)
	if expired != 1 {
		t.Fatalf("the context's bound expired %d times once its work's time passed", expired)
	}
}

// runBounded's handler waiting on a person is outside the bound: its context stays live however long the person takes,
// and once the wait ended its own work is timed out at the bound.
func TestRunBoundedLeavesThePersonsWaitOut(t *testing.T) {
	daemon := newDispatchTestDaemon(t)
	clock := newPresenceActTestClock()
	daemon.clock = clock
	asked := make(chan struct{})
	answered := make(chan struct{})
	working := make(chan struct{})
	waitErrs := make(chan error, 1)
	type outcome struct {
		err      error
		timedOut bool
	}
	outcomes := make(chan outcome, 1)
	go func() {
		_, err, timedOut := daemon.runBounded(func(ctx context.Context) (any, error) {
			resume := daemonPersonWait(ctx)
			close(asked)
			<-answered
			waitErrs <- ctx.Err()
			resume()
			close(working)
			// the request's own work runs past the bound
			<-ctx.Done()
			return nil, ctx.Err()
		})
		outcomes <- outcome{err: err, timedOut: timedOut}
	}()
	<-asked
	clock.advance(time.Hour)
	close(answered)
	if err := <-waitErrs; err != nil {
		t.Fatalf("the handler's context ended while the person was asked: %v", err)
	}
	<-working
	clock.advance(daemon.settings.Local.RequestTimeout)
	if finished := <-outcomes; !finished.timedOut {
		t.Fatalf("the handler's own work past the bound was not timed out: %v", finished.err)
	}
}
