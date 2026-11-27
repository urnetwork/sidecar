// The Forwarder's times dated before their causes could be seen (bridge_forward.go's comment, wantCompileAt): each
// test holds the Forwarder's goroutine just after the sink, Status or the log shows a cause, moves the clock there as
// an observer that saw it would, from another goroutine, and then lets the Forwarder go on. A time dated after the
// move lands past it by the move, which the clock, moved once, never reaches: what stalled the app host's
// FwdAppWithinTargets, whose step moved the Net's clock to CompileDelay after the grant once the posture showed the
// grant's pin, while the Forwarder had not yet read the clock for its want (1 in 112 tip-check runs). Each test but
// the last fails on the code before that change; the last guards a read that already came before its hold. No sleeps:
// the holds are channels, and settle is a barrier on the loop's goroutine.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// One point the Forwarder's goroutine is held at, once: taken closes when it gets there, and it goes on once release
// closes.
type testForwarderWakeHold struct {
	// for the sink, the call it holds in: "deltas" after the take, "fork" after the fork's report, "decision" before
	// the read; for the log, text the line holds
	at string
	// for a decision read, whether this read is the one; nil for the first
	when    func() bool
	taken   chan struct{}
	release chan struct{}
}

func newTestForwarderWakeHold(at string, when func() bool) *testForwarderWakeHold {
	return &testForwarderWakeHold{at: at, when: when, taken: make(chan struct{}), release: make(chan struct{})}
}

// Holds the calling goroutine at the armed hold when matches says this is its point, once.
func testForwarderWakeHoldIf(armed *atomic.Pointer[testForwarderWakeHold], matches func(hold *testForwarderWakeHold) bool) {
	hold := armed.Load()
	if hold == nil || !matches(hold) || !armed.CompareAndSwap(hold, nil) {
		return
	}
	close(hold.taken)
	<-hold.release
}

// Waits until the Forwarder is held, then has seen run with it held, as an observer of what it showed, and lets it go
// on.
func (self *testForwarderWakeHold) meet(seen func()) {
	<-self.taken
	seen()
	close(self.release)
}

// The world's sink, holding the Forwarder after a call that shows a cause: its take of a page, which shows the new
// pin before ApplyDeltas returns as the posture's adoption does, a fork's report, or before a read of its decision.
type testForwarderWakeSink struct {
	*testForwarderSink
	armed atomic.Pointer[testForwarderWakeHold]
}

// A wake sink over the world's sink, which its next Forwarder is built over.
func newTestForwarderWakeSink(world *testForwarderWorld) *testForwarderWakeSink {
	sink := &testForwarderWakeSink{testForwarderSink: world.sink}
	world.forwardSink = sink
	return sink
}

// Arms a hold in call ("deltas", "fork" or "decision"), at the first such call for which when holds, nil for any.
func (self *testForwarderWakeSink) hold(call string, when func() bool) *testForwarderWakeHold {
	hold := newTestForwarderWakeHold(call, when)
	self.armed.Store(hold)
	return hold
}

func (self *testForwarderWakeSink) holdIn(call string) {
	testForwarderWakeHoldIf(&self.armed, func(hold *testForwarderWakeHold) bool {
		return hold.at == call && (hold.when == nil || hold.when())
	})
}

func (self *testForwarderWakeSink) ApplyDeltas(log *BridgeStateLog) error {
	err := self.testForwarderSink.ApplyDeltas(log)
	self.holdIn("deltas")
	return err
}

func (self *testForwarderWakeSink) SetFork(fork bool) error {
	err := self.testForwarderSink.SetFork(fork)
	self.holdIn("fork")
	return err
}

func (self *testForwarderWakeSink) Decision() BridgeSinkDecision {
	self.holdIn("decision")
	return self.testForwarderSink.Decision()
}

// A log that drops every line but holds the Forwarder at the first warning holding the armed hold's text: what a
// compile or a follow logs right after Status counts its failure.
type testForwarderWakeLog struct {
	armed atomic.Pointer[testForwarderWakeHold]
}

// A wake log, which the world's next Forwarder is built over.
func newTestForwarderWakeLog(world *testForwarderWorld) *testForwarderWakeLog {
	log := &testForwarderWakeLog{}
	world.forwardLog = log
	return log
}

// Arms a hold at the first warning whose line holds text.
func (self *testForwarderWakeLog) hold(text string) *testForwarderWakeHold {
	hold := newTestForwarderWakeHold(text, nil)
	self.armed.Store(hold)
	return hold
}

func (self *testForwarderWakeLog) Info(args ...any) {
}

func (self *testForwarderWakeLog) Infof(format string, args ...any) {
}

func (self *testForwarderWakeLog) Warningf(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	testForwarderWakeHoldIf(&self.armed, func(hold *testForwarderWakeHold) bool {
		return strings.Contains(line, hold.at)
	})
}

func (self *testForwarderWakeLog) Errorf(format string, args ...any) {
}

func (self *testForwarderWakeLog) V(level int32) Verbose {
	return NewNoopLogger().V(level)
}

// A Forwarder at CompileDelay 2 s over a wake sink, settled with its first state, the clock at that compile.
func newTestForwarderWakeCompiled(t *testing.T) (*testForwarderWorld, *testForwarderWakeSink, *Forwarder) {
	world := newTestForwarderWorld(t)
	world.settings.CompileDelay = 2 * time.Second
	sink := newTestForwarderWakeSink(world)
	forwarder := world.forwarderIn(context.Background())
	world.settle(forwarder)
	world.advance(forwarder, world.settings.CompileDelay)
	if world.stateCount() != 1 {
		t.Fatalf("the first compile: %v", world.events.list())
	}
	return world, sink, forwarder
}

// The app host's stall: an opening the sink took, whose new pin an observer saw and moved the clock CompileDelay past,
// as FwdAppWithinTargets's step does once WaitApplied sees the grant's pin, is compiled at that time with no further
// move. The want was dated after the take, so the compile came due CompileDelay past the move and never ran.
func TestACompileAPageWantsComesItsDelayAfterTheSinkTookThePage(t *testing.T) {
	world, sink, forwarder := newTestForwarderWakeCompiled(t)
	net := world.net
	net.consentedMember("an opening the observer sees taken")
	opened := net.n
	world.publish()
	hold := sink.hold("deltas", nil)
	forwarder.ReceiveHint(opened)
	hold.meet(func() {
		// what WaitApplied reads: the opening taken, wanting a compile, no compile yet
		if decision := world.sink.Decision(); decision.Pin.GetVersion() != opened || !decision.CompileWanted || decision.StatePin.GetVersion() == opened {
			t.Errorf("the sink at the hold: %+v", decision)
		}
		world.clock.Advance(world.settings.CompileDelay)
	})
	world.settle(forwarder)
	if status := forwarder.Status(); status.CompileCount != 2 || status.CompiledPin.GetVersion() != opened {
		t.Fatalf("the opening was not compiled CompileDelay after the sink took it: %+v", status)
	}
	if events := world.events.list(); events[len(events)-1] != fmt.Sprintf("state %d of %d entries", opened, opened) {
		t.Errorf("the sink's calls: %v", events)
	}
}

// A witness that ends a fork: the compile the fork held back is wanted from before the sink showed the fork's end, so
// an observer that saw the end and moved the clock CompileDelay past it finds the compile run then.
func TestACompileAForksEndWantsComesItsDelayAfterTheSinkShowedTheEnd(t *testing.T) {
	world, sink, forwarder := newTestForwarderWakeCompiled(t)
	net := world.net
	if err := forwarder.Witness(net.log.State().Pin(), true); err != nil {
		t.Fatal(err)
	}
	net.consentedMember("joined while forked")
	world.hint(forwarder)
	// the compile that entry wanted comes due and runs into the fork, which leaves nothing wanted
	world.advance(forwarder, world.settings.CompileDelay)
	if world.stateCount() != 1 || forwarder.Status().CompileCount != 1 {
		t.Fatalf("a compile ran while forked: %v", world.events.list())
	}
	hold := sink.hold("fork", nil)
	witnessed := make(chan error, 1)
	go func() {
		witnessed <- forwarder.Witness(net.log.State().Pin(), false)
	}()
	hold.meet(func() {
		if decision := world.sink.Decision(); decision.Fork {
			t.Errorf("the sink at the hold still forked: %+v", decision)
		}
		world.clock.Advance(world.settings.CompileDelay)
	})
	if err := <-witnessed; err != nil {
		t.Fatal(err)
	}
	world.settle(forwarder)
	if status := forwarder.Status(); status.CompileCount != 2 || status.CompiledPin.GetVersion() != net.n {
		t.Fatalf("the compile the fork held back did not come CompileDelay after its end: %+v", status)
	}
}

// A follow into a sink pending on its anchor wants its compile from the follow's start: an observer that saw the
// stored tip in Status, before the follow ended, and moved the clock CompileDelay past it finds the first state
// handed then.
func TestACompileAPendingFollowWantsComesItsDelayAfterTheFollowBegan(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.settings.CompileDelay = 2 * time.Second
	sink := newTestForwarderWakeSink(world)
	tip := world.net.n
	tipName := forwarderNumberName(forwarderLogPrefix, tip)
	// the first read of the sink's decision once the store holds the tip is the page's, after Status shows it
	hold := sink.hold("decision", func() bool {
		entries, err := world.forwardStore.List(tipName)
		return err == nil && len(entries) == 1
	})
	forwarder := world.forwarderIn(context.Background())
	hold.meet(func() {
		if status := forwarder.Status(); status.Tip.GetVersion() != tip || status.Decision.State != BridgeSinkPending {
			t.Errorf("the status at the hold: %+v", status)
		}
		world.clock.Advance(world.settings.CompileDelay)
	})
	world.settle(forwarder)
	if world.stateCount() != 1 || forwarder.Status().CompiledPin.GetVersion() != tip {
		t.Fatalf("the pending sink's first state did not come CompileDelay after the follow: %v, %+v", world.events.list(), forwarder.Status())
	}
}

// fsAppBelowThePin's wait: a compile that failed retries CompileRetryInterval after the failure Status counted, so an
// observer that saw the count and moved the clock by the interval finds the retry run then.
func TestAFailedCompileRetriesItsIntervalAfterStatusCountedIt(t *testing.T) {
	world := newTestForwarderWorld(t)
	world.forwardHeads.onRead = func(ctx context.Context) error {
		return errors.New("the test's heads are unreachable")
	}
	log := newTestForwarderWakeLog(world)
	hold := log.hold("did not run")
	forwarder := world.forwarderIn(context.Background())
	hold.meet(func() {
		if status := forwarder.Status(); status.CompileErrorCount != 1 {
			t.Errorf("the status at the hold: %+v", status)
		}
		world.clock.Advance(world.settings.CompileRetryInterval)
	})
	world.settle(forwarder)
	if status := forwarder.Status(); status.CompileErrorCount != 2 {
		t.Fatalf("the retry did not come CompileRetryInterval after the failure: %+v", status)
	}
}

// A follow that failed is retried FollowRetryInterval after the follow Status counted, so an observer that saw the
// count and moved the clock by the interval finds the retry run then. A guard: the code before the change read the
// clock just after the count and before this hold, the first call out after it, and the change moves the read before
// the count, a gap nothing outside can hold the Forwarder in; this fails if the read moves past the log or the
// lapse check, which may call into the sink.
func TestAFailedFollowRetriesItsIntervalAfterStatusCountedIt(t *testing.T) {
	world := newTestForwarderWorld(t)
	log := newTestForwarderWakeLog(world)
	forwarder := world.forwarder()
	world.api.fail.Store(true)
	hold := log.hold("the follow stopped")
	forwarder.ReceiveHint(0)
	hold.meet(func() {
		if status := forwarder.Status(); status.FollowCount != 2 {
			t.Errorf("the status at the hold: %+v", status)
		}
		world.clock.Advance(world.settings.FollowRetryInterval)
	})
	world.settle(forwarder)
	if status := forwarder.Status(); status.FollowCount != 3 {
		t.Fatalf("the retry did not come FollowRetryInterval after the failed follow: %+v", status)
	}
}
