// A loop's count is published only once the loop has armed its wait for the next round, so whoever sees a round
// counted may move the clock by the loop's interval and reach the next: the sending set's checks and §14.7's breaker's
// median reads, as the engine's probe loop already did. tip-check at d3bf9753 found the sending set counting a check
// before it armed the next check's wait: TestSendingSetRechecksPeriodically's recheck awaited the count and moved the
// clock at once, the move passed no timer, the wait was armed an interval past the moved clock, and the test ran out
// its 30 s waiting for a check that only another move would bring.
//
// Each test holds its loop at that arming, on a clock that holds it, and does there what a test that sees the count
// does: if the round is counted already, it moves the clock then, in the window a count before the arming leaves
// open. Counted first, the loop fails each test every run; armed first, the round is not counted while the arming is
// held, so the move comes after it.

package smtpedgeservice_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// A FakeClock that holds a loop's first arming of a wait of interval until letArm: that After signals arming, waits,
// and only then sets its timer. Every other call reaches the FakeClock as it is.
type armingHoldClock struct {
	*sidecartest.FakeClock
	interval time.Duration

	held        atomic.Bool
	arming      chan struct{}
	release     chan struct{}
	releaseOnce sync.Once
}

func newArmingHoldClock(clock *sidecartest.FakeClock, interval time.Duration) *armingHoldClock {
	return &armingHoldClock{
		FakeClock: clock,
		interval:  interval,
		arming:    make(chan struct{}),
		release:   make(chan struct{}),
	}
}

func (self *armingHoldClock) After(timeout time.Duration) <-chan time.Time {
	if timeout == self.interval && self.held.CompareAndSwap(false, true) {
		close(self.arming)
		<-self.release
	}
	return self.FakeClock.After(timeout)
}

// Waits until the loop has reached the arming the clock holds.
func (self *armingHoldClock) awaitArming(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-self.arming:
	case <-ctx.Done():
		t.Fatal("the loop never armed its next wait")
	}
}

// Lets the held arming set its timer. Once is enough; more do nothing.
func (self *armingHoldClock) letArm() {
	self.releaseOnce.Do(func() { close(self.release) })
}

// While the loop is held at its arming of the second round's wait: if await already finds the first round counted, a
// test may move the clock now, and does. Then the arming goes on, and if the clock has not moved, it moves once the
// first round is counted, as recheck moves it. Either way the second round must come.
func moveAtTheHeldArming(t *testing.T, ctx context.Context, clock *armingHoldClock, await func(ctx context.Context, count int) error) {
	t.Helper()
	clock.awaitArming(t, ctx)
	// an await on a ctx already ended answers at once: whether the count is in
	ended, end := context.WithCancel(ctx)
	end()
	moved := false
	if await(ended, 1) == nil {
		clock.FakeClock.Advance(clock.interval)
		moved = true
	}
	clock.letArm()
	if !moved {
		if err := await(ctx, 1); err != nil {
			t.Fatal(err)
		}
		clock.FakeClock.Advance(clock.interval)
	}
	if err := await(ctx, 2); err != nil {
		t.Fatalf("the clock moved one interval once the first round was counted, and the second round never came: %v", err)
	}
}

func TestSendingSetCountsACheckOnlyOnceTheNextIsArmed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	fakeClock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, fakeClock, nil, nil, nil)
	mxWorldSettings := sidecartest.DefaultMxWorldSettings()
	mxWorldSettings.Clock = fakeClock
	world, err := sidecartest.NewMxWorld(mxWorldSettings)
	if err != nil {
		t.Fatal(err)
	}
	world.SetPtr(testSendingAddress, testHeloName)
	world.AddMx(testHeloName, testSendingAddress, nil)
	settings := worldSettings()
	clock := newArmingHoldClock(fakeClock, settings.FcrdnsCheckInterval)
	set := smtpedgeservice.NewSmtpSendingSet(ctx, settings, clock, host.Metrics, world, world, nil)
	t.Cleanup(set.Close)
	// before Close, which waits for the loop
	t.Cleanup(clock.letArm)

	moveAtTheHeldArming(t, ctx, clock, set.AwaitChecks)
	if usable := set.Usable(); len(usable) != 1 || usable[0].Address != testSendingAddress {
		t.Fatalf("usable %v after two checks", usable)
	}
}

func TestBreakerCountsAMedianReadOnlyOnceTheNextIsArmed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	fakeClock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, fakeClock, nil, nil, nil)
	sidecartest.RegisterSmtpQuotaScripts(host.Redis)
	settings := worldSettings()
	clock := newArmingHoldClock(fakeClock, settings.BreakerMedianRefreshInterval)
	serviceHost := *host.ServiceHost()
	serviceHost.Clock = clock
	quota, err := smtpedgeservice.NewSmtpQuota(ctx, &serviceHost, settings)
	if err != nil {
		t.Fatal(err)
	}
	breaker := quota.Breaker()
	t.Cleanup(breaker.Close)
	t.Cleanup(clock.letArm)

	moveAtTheHeldArming(t, ctx, clock, breaker.AwaitMedianReads)
}
