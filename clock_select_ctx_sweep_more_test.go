//go:build !sidecar_http && !js && !ios_extension

// More of the root's waits that end with their context (clock-select-ctx-sweep; clock_select_ctx_sweep_test.go has the
// first and the sweep's account). Each loop here did something outward or durable on a pass it ran after its context
// ended, when select took a timer or a wake as the end landed: the stream sender handed connect a refused frame again
// after the dispatcher closed, the DNS watch passed on the dead context and marked itself degraded, a scim_signer pass
// took its lock on an ended context and read the queue, the share signer renewer certified a new signer seed that never
// lands, and the token manager refreshed past the end, ending its generation as expired.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// tlsWaitEndingClock with MoveOnFire: a clock for a loop that reads the time again after its wait, as a real timer's
// firing finds it passed. Its waits are held until the test opens it; each counted wait then fires at once, the clock
// moving to its time, until the counted one at which it runs end before it hands the timer back. A counted wait after
// that one never fires, nor does one it does not count. AfterFunc never calls. Safe for concurrent use.
type clockSelectMovingClock struct {
	// whether it counts a wait of timeout; nil counts every wait
	counts func(timeout time.Duration) bool
	guard  time.Duration
	// closed when the test lets the waits through
	opened   chan struct{}
	openOnce sync.Once

	stateLock sync.Mutex
	now       time.Time
	// the counted wait, from 1, at which end runs; 0 for none
	endIndex  int
	end       func()
	waitCount int
	askCount  int
}

var _ Clock = (*clockSelectMovingClock)(nil)

// A held clock reading now, counting the waits counts takes, every wait when it is nil, opened when the test ends.
func newClockSelectMovingClock(t *testing.T, now time.Time, counts func(timeout time.Duration) bool) *clockSelectMovingClock {
	clock := &clockSelectMovingClock{now: now, counts: counts, guard: 30 * time.Second, opened: make(chan struct{})}
	t.Cleanup(clock.open)
	return clock
}

func (self *clockSelectMovingClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

func (self *clockSelectMovingClock) After(timeout time.Duration) <-chan time.Time {
	<-self.opened
	var end func()
	fires, firedAt := func() (bool, time.Time) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.askCount += 1
		if self.counts != nil && !self.counts(timeout) {
			return false, time.Time{}
		}
		self.waitCount += 1
		if self.waitCount == self.endIndex {
			end = self.end
		}
		fires := self.endIndex == 0 || self.waitCount <= self.endIndex
		if fires {
			self.now = self.now.Add(max(0, timeout))
		}
		return fires, self.now
	}()
	// the end lands before the timer's channel is handed back, so the waiter's select finds both ready
	if end != nil {
		end()
	}
	fire := make(chan time.Time, 1)
	if fires {
		fire <- firedAt
	}
	return fire
}

func (self *clockSelectMovingClock) AfterFunc(timeout time.Duration, function func()) (stop func() bool) {
	return func() bool {
		return true
	}
}

// Runs end as the index-th counted wait, from 1, fires.
func (self *clockSelectMovingClock) arm(index int, end func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.endIndex = index
	self.end = end
}

func (self *clockSelectMovingClock) open() {
	self.openOnce.Do(func() {
		close(self.opened)
	})
}

func (self *clockSelectMovingClock) waits() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.waitCount
}

// Waits for done within the clock's guard, failing the test with what otherwise.
func (self *clockSelectMovingClock) awaitDone(t *testing.T, done chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(self.guard):
		t.Fatalf("%s did not end within %v", what, self.guard)
	}
}

// The stream sender hands connect nothing more once the dispatcher has closed: a frame connect refuses waits
// CallSendRetryInterval, and a close landing as that pause's timer fires ends the sender after the one send, in each
// of 64 rounds, asking the clock for no second pause. A sender that took the timer's case sent the frame again after
// the close.
func TestSubprotocolStreamSenderSendsNothingAfterTheDispatcherCloses(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	for round := range 64 {
		clock := newTlsWaitEndingClock(t, clockSelectTestStart(), settings.CallSendRetryInterval)
		ctx, cancel := context.WithCancel(context.Background())
		sendCount := &atomic.Int64{}
		// what the sender reads of a dispatcher: its context, settings, clock, stream queue and connect's send, which
		// refuses every frame at once
		subprotocol := &Subprotocol{
			ctx:      ctx,
			settings: settings,
			clock:    clock,
			send: func(destinationId connect.Id, envelope *protocol.Envelope, ack connect.AckFunction, timeout time.Duration, opts ...any) (bool, error) {
				sendCount.Add(1)
				return false, nil
			},
		}
		subprotocol.streams.outbound = []*streamOutbound{{
			destinationId: connect.NewId(),
			envelope:      &protocol.Envelope{Version: WireVersionMajor, Type: uint32(protocol.MessageType_STREAM_RESET)},
		}}
		subprotocol.handlers.Add(1)
		clock.arm(1, cancel)
		clock.open()
		subprotocol.runStreamSender()
		cancel()
		if sends := sendCount.Load(); sends != 1 || clock.waits() != 1 {
			t.Fatalf("round %d: %d sends and %d pauses, want 1 of each", round, sends, clock.waits())
		}
	}
}

// A DNS watch over resolvers on clock under ctx, its settings settings, publishing testDnsWatchHost.
func newClockSelectTestDnsWatch(t *testing.T, ctx context.Context, resolvers *testDnsWatchResolvers, clock Clock, settings *DnsWatchSettings) *DnsWatch {
	t.Helper()
	zone := testDnsWatchFollowupZone(NewId())
	watch, err := NewDnsWatch(ctx, &DnsWatchArgs{
		Resolver: resolvers,
		Store:    newTestDnsMemoryStore(),
		Zone: func(ctx context.Context) (*DnsZone, error) {
			return zone, nil
		},
		PublishedHosts: func() []string { return []string{testDnsWatchHost} },
		Clock:          clock,
		Settings:       settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.Close)
	return watch
}

// The DNS watch makes no pass once its context has ended: it passes after each wait, and an end landing as the second
// wait's timer fires ends the loop after the one pass before it, in each of 64 rounds; and a pass on an ended context
// asks no resolver and leaves the status as it stood. A loop that took the timer's case passed on the dead context,
// whose lookups failed, so the watch read as degraded.
func TestDnsWatchMakesNoPassAfterItsContextEnds(t *testing.T) {
	settings := DefaultDnsWatchSettings()
	settings.Jitter = 0
	wait := max(settings.Interval, settings.PassMinWait)
	for round := range 64 {
		resolvers := newTestDnsWatchResolvers(2)
		testDnsWatchFollowupHealthy(resolvers)
		clock := newTlsWaitEndingClock(t, clockSelectTestStart(), wait)
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(2, cancel)
		watch := newClockSelectTestDnsWatch(t, ctx, resolvers, clock, settings)
		clock.open()
		clock.awaitDone(t, watch.done, "the watch's loop")
		// a pass asks each resolver once about the host's A
		if asked := resolvers.asked(testDnsWatchHost, DnsWatchTypeA); asked != 2 || clock.waits() != 2 || watch.Status().Degraded {
			t.Fatalf("round %d: %d A lookups and %d waits, degraded %t, want 2 of each and not degraded", round, asked, clock.waits(), watch.Status().Degraded)
		}
	}

	resolvers := newTestDnsWatchResolvers(2)
	testDnsWatchFollowupHealthy(resolvers)
	// a clock that counts no wait of the loop's, so the loop stays parked while the test passes by hand
	clock := newTlsWaitEndingClock(t, clockSelectTestStart(), wait+time.Second)
	watch := newClockSelectTestDnsWatch(t, context.Background(), resolvers, clock, settings)
	clock.open()
	watch.Pass(context.Background())
	before := watch.Status()
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if alarmed := watch.Pass(ended); alarmed || resolvers.asked(testDnsWatchHost, DnsWatchTypeA) != 2 || watch.Status() != before {
		t.Fatalf("a pass on an ended context: alarmed %t, %d A lookups, status %+v (before %+v)", alarmed, resolvers.asked(testDnsWatchHost, DnsWatchTypeA), watch.Status(), before)
	}
}

// A scim_signer pass on an ended context reads nothing: with its pass lock free, Pass answers the context's error in
// each of 64 rounds and leaves the lock free. A lock taken beside an ended context, which select took as often as the
// end, ran the pass on the dead context, which reads the queue and signs what it may.
func TestConfigScimSignerPassRefusesAnEndedContext(t *testing.T) {
	net := newTestConfigNet(t)
	sidecar, _, _, _ := newTestMemberRemoveSidecar(t, net)
	signer := NewConfigScimSigner(context.Background(), sidecar, &testScimChangeSource{}, &ConfigScimSignerSettings{PassMaxCount: 64})
	defer signer.Close()
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for round := range 64 {
		if pass, err := signer.Pass(ended); !errors.Is(err, context.Canceled) || pass != nil {
			t.Fatalf("round %d: a pass on an ended context answered %+v, %v", round, pass, err)
		}
	}
	select {
	case signer.passLock <- struct{}{}:
		<-signer.passLock
	default:
		t.Fatal("a refused pass kept the lock")
	}
}

// The share signer renewer makes no pass once its context has ended: it passes at once and after each wait, and an end
// landing as the second wait's timer fires ends Run after the two passes before it, in each of 64 rounds. A loop that
// took the timer's case passed on the dead context, where a due share's renewal certifies a new seed that never lands.
func TestBridgeShareSignerRenewerMakesNoPassAfterItsContextEnds(t *testing.T) {
	holder := newTestBridgeShareHolder(t)
	settings := DefaultBridgeShareSignerSettings()
	for round := range 64 {
		clock := newTlsWaitEndingClock(t, holder.world.clock.Now(), settings.RenewInterval)
		passCount := &atomic.Int64{}
		renewer, err := NewBridgeShareSignerRenewer(&BridgeShareSignerRenewerArgs{
			Keyring:    holder.keys.keyring,
			Config:     testBridgeFileConfig{net: holder.world.net},
			Heads:      holder.world.heads,
			HeadWriter: func() BridgeHeadWriter { return testBridgeShareHolderWriter{holder: holder} },
			// each pass reads the generation first, once for a share that is not due
			Generation: func(ctx context.Context) (uint64, error) {
				passCount.Add(1)
				holder.stateLock.Lock()
				defer holder.stateLock.Unlock()
				return holder.generation, nil
			},
			Clock: clock,
			Log:   NewNoopLogger(),
		})
		if err != nil {
			t.Fatal(err)
		}
		// the renewal the holder's own start owes lands first, so each pass of the round reads the share as not due
		if _, err := renewer.RenewAll(context.Background()); err != nil {
			t.Fatal(err)
		}
		passCount.Store(0)
		ctx, cancel := context.WithCancel(context.Background())
		clock.arm(2, cancel)
		clock.open()
		renewer.Run(ctx, nil)
		cancel()
		if passes := passCount.Load(); passes != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d passes and %d waits, want 2 of each", round, passes, clock.waits())
		}
	}
}

// The token manager refreshes nothing once it has closed: with api answering 503 to every refresh, a failed refresh
// waits its retry, and a close landing as that wait's timer fires, the clock past the token's exp, ends the loop with
// the generation untouched, in each of 64 rounds. A loop that took the timer's case tried the token again, found its
// exp passed, and ended the generation as expired for a manager already closed.
func TestTokenManagerRefreshesNothingAfterItCloses(t *testing.T) {
	for round := range 64 {
		refreshCount := &atomic.Int64{}
		fixture := newTokenTestFixture(t, testInitialJwt(), func(request *http.Request, body []byte) (*http.Response, error) {
			refreshCount.Add(1)
			return syntheticResponse(request, http.StatusServiceUnavailable, `{}`, nil), nil
		})
		clock := newClockSelectMovingClock(t, sdkScheduleNow, nil)
		var manager *sidecarTokenManager
		fixture.start(t, 1, func(args *sidecarTokenManagerArgs) {
			args.Clock = clock
			// past the 7-day token's exp from its refresh point
			args.RetryTimeout = func() time.Duration { return 30 * 24 * time.Hour }
		})
		manager = fixture.manager
		// the second wait is the retry after the refresh at the drawn point
		clock.arm(2, manager.cancel)
		clock.open()
		clock.awaitDone(t, manager.done, "the token manager's loop")
		fixture.stateLock.Lock()
		refused := append([]SidecarStateReason{}, fixture.refused...)
		fixture.stateLock.Unlock()
		if len(refused) != 0 || refreshCount.Load() != 1 || clock.waits() != 2 {
			t.Fatalf("round %d: refused %v after %d refreshes and %d waits, want none after 1 refresh and 2 waits", round, refused, refreshCount.Load(), clock.waits())
		}
	}
}

// A scim change source that answers an empty queue, counting its reads, a dead context's included.
type clockSelectScimSource struct {
	readCount atomic.Int64
}

func (self *clockSelectScimSource) ScimMemberRevokes(ctx context.Context) ([]Id, error) {
	self.readCount.Add(1)
	return nil, nil
}

// A scim_signer's loop makes no pass once it has closed: designated, it passes at once and after each PollInterval,
// each pass reading the queue, and a close landing as the second wait's timer fires ends the loop after the two passes
// before it, in each of 64 rounds, asking the clock for no third wait. A loop that took the timer's case passed again
// on the closed signer.
func TestConfigScimSignerLoopMakesNoPassAfterItCloses(t *testing.T) {
	net := newTestConfigNet(t)
	sidecar, authority, _, _ := newTestMemberRemoveSidecar(t, net)
	net.designateScimSigner(sidecar.currentIdentity().SidecarId, 2)
	authority.setState(net.log.State())
	settings := &ConfigScimSignerSettings{PassMaxCount: 64, PollInterval: time.Minute}
	for round := range 64 {
		clock := newTlsWaitEndingClock(t, clockSelectTestStart(), settings.PollInterval)
		// no signer runs between rounds, so the sidecar's clock is the round's alone
		sidecar.clock = clock
		source := &clockSelectScimSource{}
		signer := NewConfigScimSigner(context.Background(), sidecar, source, settings)
		clock.arm(2, signer.Close)
		clock.open()
		clock.awaitDone(t, signer.runDone, "the scim_signer's loop")
		if reads := source.readCount.Load(); reads != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d queue reads and %d waits, want 2 of each", round, reads, clock.waits())
		}
	}
}
