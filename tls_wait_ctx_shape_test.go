//go:build !sidecar_http && !ios_extension

// The TLS waits end with their context (the orderer's shape, from tls-orderer-poll-hang): the CT watch's loop, the
// certificate manager's loop, its order poll and its pass lock. Each selected on a context's end beside a timer, a
// hint or a free lock, and select takes any of its ready cases at random, so an end landing as the other case was
// ready let one more pass or step run on the dead context, and the loops asked the clock for another wait after it.
// Each now answers the end once its context has ended, whatever else was ready, and asks the clock for nothing then.
// The proof is a clock that ends the context as a wait's timer fires, so both cases are ready when select runs, over
// 64 rounds, which leave the old coin no chance (at most (3/4)^64) to pass.

package sidecar

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// A clock for a loop whose waits must end with its context. Its waits are held until the test opens it, so the test
// arms it before the loop asks; then each counted wait fires at once, until the counted one at which it runs end as
// the timer fires, as a cancel landing with the timer does. A counted wait after that one never fires, nor does a wait
// of a timeout it does not count, so a loop beside the one under test stays parked.
type tlsWaitEndingClock struct {
	now time.Time
	// the timeout of the waits it counts; zero counts every wait
	countedTimeout time.Duration
	// how long a test waits on a loop it drives: a guard against a broken test, never the proof
	guard time.Duration
	// closed when the test lets the waits through
	opened   chan struct{}
	openOnce sync.Once

	stateLock sync.Mutex
	// the counted wait, from 1, at which end runs; 0 for none
	endIndex int
	end      func()
	// the counted waits asked so far
	waitCount int
	// every wait asked so far, counted or not
	askCount int
}

// A held clock reading now that counts the waits of countedTimeout, every wait when it is zero. It opens when the test
// ends at the latest, so no loop stays held past it.
func newTlsWaitEndingClock(t *testing.T, now time.Time, countedTimeout time.Duration) *tlsWaitEndingClock {
	clock := &tlsWaitEndingClock{
		now:            now,
		countedTimeout: countedTimeout,
		guard:          30 * time.Second,
		opened:         make(chan struct{}),
	}
	t.Cleanup(clock.open)
	return clock
}

func (self *tlsWaitEndingClock) Now() time.Time {
	return self.now
}

func (self *tlsWaitEndingClock) After(timeout time.Duration) <-chan time.Time {
	<-self.opened
	var end func()
	fires := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.askCount += 1
		if self.countedTimeout != 0 && timeout != self.countedTimeout {
			return false
		}
		self.waitCount += 1
		if self.waitCount == self.endIndex {
			end = self.end
		}
		return self.endIndex == 0 || self.waitCount <= self.endIndex
	}()
	// the end lands before the timer's channel is handed back, so the waiter's select finds both ready
	if end != nil {
		end()
	}
	fire := make(chan time.Time, 1)
	if fires {
		fire <- self.now
	}
	return fire
}

func (self *tlsWaitEndingClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool {
		return true
	}
}

// Runs end as the index-th counted wait, from 1, fires.
func (self *tlsWaitEndingClock) arm(index int, end func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.endIndex = index
	self.end = end
}

// Lets the waits through.
func (self *tlsWaitEndingClock) open() {
	self.openOnce.Do(func() {
		close(self.opened)
	})
}

// The counted waits asked so far.
func (self *tlsWaitEndingClock) waits() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.waitCount
}

// Every wait asked so far.
func (self *tlsWaitEndingClock) asks() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.askCount
}

// Waits for done within the clock's guard, failing the test with what otherwise.
func (self *tlsWaitEndingClock) awaitDone(t *testing.T, done chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(self.guard):
		t.Fatalf("%s did not end within %v", what, self.guard)
	}
}

// A certificate manager under ctx on fixture's keychain, store and names, its clock clock. When the test ends it is
// closed, its clock opened, and its loop's end awaited.
func newTlsWaitTestManager(ctx context.Context, t *testing.T, fixture *tlsCertFixture, clock *tlsWaitEndingClock) *TlsCertManager {
	t.Helper()
	manager, err := NewTlsCertManager(ctx, &TlsCertManagerArgs{
		NetworkId: fixture.networkId,
		SidecarId: fixture.sidecarId,
		Settings:  fixture.settings,
		Keys:      fixture.keys,
		Sign:      testTlsSign(fixture.identity, fixture.sidecarId[:]),
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			return "service token for " + resource, nil
		},
		Names: fixture.names,
		Store: fixture.store,
		Clock: clock,
		Log:   NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		manager.Close()
		clock.open()
		select {
		case <-manager.done:
		case <-time.After(clock.guard):
			t.Errorf("the manager's loop did not end within %v of its close", clock.guard)
		}
	})
	return manager
}

// The CT watch's loop starts no pass once its context has ended: a cancel landing as its third wait's timer fires ends
// the loop after the two passes before that wait, with no wait after it, in each of 64 rounds; and a watch whose
// context ended before it started asks the clock for nothing and makes no pass. A loop that took the timer's case
// made a pass on the dead context, which reads no names, rows or sources and so marks the watch degraded at its close.
func TestTlsCtWatchRunStartsNoPassAfterItsContextEnds(t *testing.T) {
	fixture := newTlsCtFixture(t)
	// the passes the loop made before it ended: each asks first whether the sidecar listens, and, told no, ends there
	run := func(ctx context.Context, clock *tlsWaitEndingClock) int {
		stateLock := sync.Mutex{}
		passCount := 0
		args := fixture.args()
		args.Clock = clock
		args.Listening = func() bool {
			stateLock.Lock()
			defer stateLock.Unlock()
			passCount += 1
			return false
		}
		watch, err := newTlsCtWatch(ctx, args)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			clock.open()
			watch.Close()
		})
		clock.open()
		clock.awaitDone(t, watch.done, "the watch's loop")
		stateLock.Lock()
		defer stateLock.Unlock()
		return passCount
	}
	for round := range 64 {
		ctx, cancel := context.WithCancel(context.Background())
		clock := newTlsWaitEndingClock(t, fixture.clock.Now(), 0)
		clock.arm(3, cancel)
		if passCount := run(ctx, clock); passCount != 2 || clock.waits() != 3 {
			t.Fatalf("round %d: %d passes and %d waits, want 2 passes and 3 waits", round, passCount, clock.waits())
		}
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	clock := newTlsWaitEndingClock(t, fixture.clock.Now(), 0)
	if passCount := run(ended, clock); passCount != 0 || clock.asks() != 0 {
		t.Fatalf("a context ended before the watch: %d passes and %d waits", passCount, clock.asks())
	}
}

// The manager's wait asks the clock for nothing once the caller's context or the manager has ended, and answers the
// end where its timer fired as either ended, in each of 64 rounds: the context's error for the caller's, and
// ErrTlsCertManagerClosed for the manager's. A live wait answers nil once its timer fires.
func TestTlsCertManagerWaitEndsWithItsContexts(t *testing.T) {
	fixture := newTlsCertFixture(t)
	fixture.manager.Close()
	timeout := fixture.settings.CertOrderPollInterval
	newManager := func() (*TlsCertManager, *tlsWaitEndingClock) {
		// the manager's own loop asks only for the resync, which this clock never fires
		clock := newTlsWaitEndingClock(t, fixture.clock.Now(), timeout)
		manager := newTlsWaitTestManager(context.Background(), t, fixture, clock)
		clock.open()
		return manager, clock
	}

	manager, clock := newManager()
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.wait(ended, timeout); !errors.Is(err, context.Canceled) || clock.waits() != 0 {
		t.Fatalf("an ended context's wait: %v, %d asked of the clock", err, clock.waits())
	}
	if err := manager.wait(context.Background(), timeout); err != nil || clock.waits() != 1 {
		t.Fatalf("a live wait: %v, %d asked of the clock", err, clock.waits())
	}
	manager.Close()
	if err := manager.wait(context.Background(), timeout); !errors.Is(err, ErrTlsCertManagerClosed) || clock.waits() != 1 {
		t.Fatalf("a closed manager's wait: %v, %d asked of the clock", err, clock.waits())
	}

	for round := range 64 {
		manager, clock := newManager()
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(1, cancel)
		if err := manager.wait(ctx, timeout); !errors.Is(err, context.Canceled) {
			t.Fatalf("round %d, a timer fired as the context ended: %v", round, err)
		}
		manager, clock = newManager()
		clock.arm(1, manager.Close)
		if err := manager.wait(context.Background(), timeout); !errors.Is(err, ErrTlsCertManagerClosed) {
			t.Fatalf("round %d, a timer fired as the manager closed: %v", round, err)
		}
	}
}

// No pass or step starts on an ended context: with the pass lock free, acquirePass answers the caller's context's
// end, or ErrTlsCertManagerClosed once the manager has closed, in each of 64 rounds, and the lock stays free. A
// select between a free lock and an ended context took the lock as often as the end.
func TestTlsCertManagerAcquirePassRefusesAnEndedContext(t *testing.T) {
	fixture := newTlsCertFixture(t)
	// nothing is attached, so the manager's own loop stays parked and the lock free
	manager := fixture.manager
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for round := range 64 {
		if err := manager.acquirePass(ended); !errors.Is(err, context.Canceled) {
			t.Fatalf("round %d, an ended context: %v", round, err)
		}
	}
	// the lock is free: a live context takes it
	if err := manager.acquirePass(context.Background()); err != nil {
		t.Fatalf("a live context: %v", err)
	}
	manager.releasePass()
	manager.Close()
	for round := range 64 {
		if err := manager.acquirePass(context.Background()); !errors.Is(err, ErrTlsCertManagerClosed) {
			t.Fatalf("round %d, a closed manager: %v", round, err)
		}
	}
	select {
	case manager.passLock <- struct{}{}:
	default:
		t.Fatalf("a refused pass kept the lock")
	}
}

// EnsureTlsCertificate takes no step once its context has ended: a cancel landing as its third poll's timer fires
// ends the poll with the context's error after the three status reads before it, in each of 64 rounds, and the
// manager closing there answers ErrTlsCertManagerClosed the same way. The poll took the timer's case as often as
// the end, and then a status read ran on the dead context when its pass lock was free.
func TestTlsCertManagerEnsureTakesNoStepAfterItsContextEnds(t *testing.T) {
	fixture := newTlsCertFixture(t)
	fixture.manager.Close()
	// the order polls' status reads so far
	statusReads := func() int {
		fixture.api.stateLock.Lock()
		defer fixture.api.stateLock.Unlock()
		return fixture.api.statusCount
	}
	// one api and store through every round: the first round's order stays open, and each round polls it again
	poll := func(round int, closeManager bool) {
		clock := newTlsWaitEndingClock(t, fixture.clock.Now(), fixture.settings.CertOrderPollInterval)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		manager := newTlsWaitTestManager(context.Background(), t, fixture, clock)
		// the attachment's pass reads the rows beside the poll; this clock never fires its loop's waits
		manager.SetApi(fixture.api)
		want := error(context.Canceled)
		end := cancel
		if closeManager {
			want = ErrTlsCertManagerClosed
			end = manager.Close
		}
		clock.arm(3, end)
		clock.open()
		before := statusReads()
		_, err := manager.EnsureTlsCertificate(ctx)
		if reads := statusReads() - before; !errors.Is(err, want) || reads != 3 || clock.waits() != 3 {
			t.Fatalf("round %d, closing the manager %t: %v after %d status reads and %d polls, want %v after 3 of each", round, closeManager, err, reads, clock.waits(), want)
		}
		// the round's manager ends before the next one reads the store
		manager.Close()
		clock.awaitDone(t, manager.done, "the manager's loop")
	}
	for round := range 64 {
		poll(round, false)
		poll(round, true)
	}
	if orderCount := fixture.api.orderCount(); orderCount != 1 {
		t.Errorf("%d orders for one certificate", orderCount)
	}
}

// The manager's loop starts no pass once the manager has closed: a close landing as a wait's timer fires, with a hint
// standing, ends the loop after the one pass before that wait, with no wait after it, in each of 64 rounds, whether
// that wait was the spacing after the pass or the next resync; and a manager closed before its loop began asks the
// clock for nothing and makes no pass. A loop that took the hint's or the timer's case started a pass on the closed
// manager, and asked the clock for the next wait after it.
func TestTlsCertManagerRunStartsNoPassAfterItCloses(t *testing.T) {
	fixture := newTlsCertFixture(t)
	fixture.manager.Close()
	for round := range 64 {
		// the second wait is the spacing after the first pass, and the third the next resync
		for _, endIndex := range []int{2, 3} {
			ctx, cancel := context.WithCancel(context.Background())
			clock := newTlsWaitEndingClock(t, fixture.clock.Now(), 0)
			manager := newTlsWaitTestManager(ctx, t, fixture, clock)
			// the attachment's request stands as the loop starts, and the end raises another
			manager.SetApi(fixture.api)
			before := fixture.api.certsReads()
			clock.arm(endIndex, func() {
				manager.Hint(PushNotice{Topic: PushTopicTls})
				cancel()
			})
			clock.open()
			clock.awaitDone(t, manager.done, "the manager's loop")
			if reads := fixture.api.certsReads() - before; reads != 1 || clock.waits() != endIndex {
				t.Fatalf("round %d, ending at wait %d: %d passes and %d waits, want 1 pass and %d waits", round, endIndex, reads, clock.waits(), endIndex)
			}
		}
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	clock := newTlsWaitEndingClock(t, fixture.clock.Now(), 0)
	manager := newTlsWaitTestManager(ended, t, fixture, clock)
	before := fixture.api.certsReads()
	manager.SetApi(fixture.api)
	clock.open()
	clock.awaitDone(t, manager.done, "the manager's loop")
	if reads := fixture.api.certsReads() - before; reads != 0 || clock.asks() != 0 {
		t.Fatalf("a manager closed before its loop: %d passes and %d waits", reads, clock.asks())
	}
}
