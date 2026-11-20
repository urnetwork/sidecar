//go:build sidecar_testhooks

// QD-1117's race, forced at mxedge.wake_hold.begin: holdForReceiver's acquire publishes the hold count, which
// AwaitWakeHoldCount waits on, and only then does the session reach hint, which reads the clock for the hint's
// version and joins hintGroup, which AwaitWakeHints waits on. Held between the two, a wait on the count alone runs
// ahead of the hint, as TestWakeHoldHintsTheRoutesReceiversOnceForced's did before it waited for the hold's first
// Find timer; the Find timer is armed only once hint has returned, so a wait for it holds until the hint has joined.

package mxedgeservice_test

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
)

// A wake router whose first held session stops at mxedge.wake_hold.begin, past acquire and short of hint, until
// release closes or the test ends; held closes once it has stopped there. The dialer answers that session's miss.
func newTestHeldWakeRouter(t *testing.T) (router *testRouter, receiverId sidecar.Id, held chan struct{}, release chan struct{}) {
	t.Helper()
	held = make(chan struct{})
	release = make(chan struct{})
	ended := make(chan struct{})
	var holding atomic.Bool
	installTestHooks(t, func(name string) {
		if name == "mxedge.wake_hold.begin" && holding.CompareAndSwap(false, true) {
			close(held)
			select {
			case <-release:
			case <-ended:
			}
		}
	})
	receiverId = testRouteNetworkId("receiver of a held hold")
	router = newTestWakeRouter(t, nil, []sidecar.Id{receiverId})
	// after the router's cleanups, so it runs before them: the engine's close waits for the held session
	t.Cleanup(func() { close(ended) })
	router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	return router, receiverId, held, release
}

// Held there, the count already reads 1 and no hint has joined the group, so AwaitWakeHints returns at once and the
// receiver has no hint: the test's "0 hints" failure. A move of the clock there, as the test's next session's
// STARTTLS quiet period made, comes before the hint reads it, so the hint's version is the moved clock's and not the
// miss's: its version failure. The hint is not lost: once the hold goes on, it reaches the receiver.
func TestWakeHintAwaitedOnTheHoldCountAloneComesEarly(t *testing.T) {
	router, receiverId, held, release := newTestHeldWakeRouter(t)
	router.heldFrom(testWakeSenders[0])
	missTime := router.clock.Now()
	<-held
	router.service.AwaitWakeHoldCount(1)
	router.service.AwaitWakeHints()
	if hints := router.host.Push.AllHints(); len(hints) != 0 {
		t.Fatalf("%d hints before the hold reached its hint", len(hints))
	}
	router.clock.Advance(router.settings.StartTlsQuietTimeout)
	movedTime := router.clock.Now()
	close(release)
	router.awaitTimerAt(movedTime.Add(router.settings.WakeHoldFindInterval))
	router.service.AwaitWakeHints()
	hints := router.host.Push.Hints(testWakeClientOf(receiverId))
	if len(hints) != 1 {
		t.Fatalf("the receiver had %d hints once the hold went on", len(hints))
	}
	if version := hints[0].Version; version != uint64(movedTime.UnixMilli()) || version == uint64(missTime.UnixMilli()) {
		t.Errorf("the hint's version %d, the miss at %d and the moved clock at %d", version, missTime.UnixMilli(), movedTime.UnixMilli())
	}
}

// The wait that closes it: held there, no timer is due at missTime + WakeHoldFindInterval, so a wait for the hold's
// first Find timer looks, finds none and waits. Only then does the hold go on, and once its timer is armed the hint
// has joined the group: AwaitWakeHints waits for it, and the receiver has its hint, versioned at the miss.
func TestWakeHintAwaitedAfterTheFindTimerTakesTheHint(t *testing.T) {
	router, receiverId, held, release := newTestHeldWakeRouter(t)
	router.heldFrom(testWakeSenders[0])
	missTime := router.clock.Now()
	<-held
	router.service.AwaitWakeHoldCount(1)
	findTime := missTime.Add(router.settings.WakeHoldFindInterval)
	// router.awaitTimerAt's loop, which here lets the hold go on once it has looked and found no timer due then
	looked := false
	for {
		pending, added := router.clock.WatchTimers()
		if slices.ContainsFunc(pending, func(timer time.Time) bool { return timer.Equal(findTime) }) {
			break
		}
		if !looked {
			looked = true
			close(release)
		}
		select {
		case <-added:
		case <-router.ctx.Done():
			t.Fatal("no timer at", findTime)
		}
	}
	if !looked {
		t.Fatal("the Find timer was armed before the hold reached its hint")
	}
	router.service.AwaitWakeHints()
	hints := router.host.Push.Hints(testWakeClientOf(receiverId))
	if len(hints) != 1 || hints[0].Version != uint64(missTime.UnixMilli()) {
		t.Fatalf("hints %+v, the miss at %d", hints, missTime.UnixMilli())
	}
	if value := router.host.Metrics.Value("urnetwork_mxedge_wake_hints_total", "sent"); value != 1 {
		t.Errorf("%v hints counted sent", value)
	}
}
