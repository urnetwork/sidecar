package tlsedgeservice_test

// The TLS edge's waits end with their context (clock-select-ctx-sweep). Serve's and the PROXY listener's accept
// retries and the kill loop's wait each selected on the engine's end beside a clock's timer and went on whenever
// select took the timer as the engine ended: an accept loop accepted again past the end, and could admit and serve a
// connection on the dead engine before its listener's close landed, and the kill loop reloaded the switch on the dead
// context, counting a load. Each now answers the end whatever else was ready. The proof is sidecartest.EndingClock,
// which ends the engine as a wait's timer fires, over 64 rounds, which leave the old coin no chance (at most
// (1/2)^64) to pass.

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// How long a case waits on a loop it drives: a guard against a broken test, never the proof.
const clockSelectTestGuard = 30 * time.Second

// An accept that failed for now, as a descriptor running out does.
type clockSelectTemporaryError struct{}

func (self clockSelectTemporaryError) Error() string {
	return "accept failed for now"
}

func (self clockSelectTemporaryError) Timeout() bool {
	return false
}

func (self clockSelectTemporaryError) Temporary() bool {
	return true
}

// A TCP listener on a documentation address whose first accept fails for now and whose later ones answer that it
// closed, counting each.
type clockSelectTestListener struct {
	acceptCount atomic.Int64
}

var _ net.Listener = (*clockSelectTestListener)(nil)

func (self *clockSelectTestListener) Accept() (net.Conn, error) {
	if self.acceptCount.Add(1) == 1 {
		return nil, clockSelectTemporaryError{}
	}
	return nil, net.ErrClosed
}

func (self *clockSelectTestListener) Close() error {
	return nil
}

func (self *clockSelectTestListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}
}

// An engine under ctx on clock with store, closed when the test ends.
func newClockSelectTestService(t *testing.T, ctx context.Context, clock *sidecartest.EndingClock, store tlsedgeservice.TlsEdgeStore, settings *tlsedgeservice.TlsEdgeSettings) *tlsedgeservice.TlsEdgeService {
	t.Helper()
	host := sidecartest.NewFakeHost(ctx, sidecartest.NewFakeClock(clock.Now()), nil, nil, nil)
	serviceHost := host.ServiceHost()
	serviceHost.Clock = clock
	service, err := tlsedgeservice.NewTlsEdgeService(ctx, serviceHost, store, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		clock.Open()
		service.Close()
	})
	return service
}

// Waits for done within the guard.
func clockSelectAwait(t *testing.T, done chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(clockSelectTestGuard):
		t.Fatalf("%s did not happen within %v", what, clockSelectTestGuard)
	}
}

// Serve accepts nothing once the engine has ended: an accept that fails for now waits AcceptRetryDelay, and an end
// landing as that wait's timer fires ends Serve after the one accept, in each of 64 rounds. A loop that took the timer's
// case accepted again on the dead engine.
func TestTlsEdgeServeAcceptsNothingAfterTheEngineEnds(t *testing.T) {
	settings := testServiceSettings()
	for round := range 64 {
		ctx, cancel := context.WithCancel(context.Background())
		clock := sidecartest.NewEndingClock(sidecartest.DefaultClockStart(), sidecartest.EndingClockCounts(settings.AcceptRetryDelay))
		service := newClockSelectTestService(t, ctx, clock, nil, settings)
		listener := &clockSelectTestListener{}
		clock.Arm(1, cancel)
		clock.Open()
		if err := service.Serve(listener); err != nil || listener.acceptCount.Load() != 1 || clock.Waits() != 1 {
			t.Fatalf("round %d: %v after %d accepts and %d waits, want nil after 1 of each", round, err, listener.acceptCount.Load(), clock.Waits())
		}
		cancel()
	}
}

// The PROXY listener accepts nothing once it has ended: an accept that fails for now waits AcceptRetryTimeout, and an
// end landing as that wait's timer fires ends its loop after the one accept, in each of 64 rounds. A loop that took the
// timer's case accepted again past the end.
func TestProxyHeaderListenerAcceptsNothingAfterItEnds(t *testing.T) {
	for round := range 64 {
		settings := tlsedgeservice.DefaultProxyHeaderSettings()
		clock := sidecartest.NewEndingClock(sidecartest.DefaultClockStart(), sidecartest.EndingClockCounts(settings.AcceptRetryTimeout))
		settings.Clock = clock
		inner := &clockSelectTestListener{}
		ctx, cancel := context.WithCancel(context.Background())
		ended := make(chan struct{})
		clock.Arm(1, func() {
			cancel()
			close(ended)
		})
		listener, err := tlsedgeservice.NewProxyHeaderListener(ctx, inner, settings)
		if err != nil {
			t.Fatal(err)
		}
		clock.Open()
		clockSelectAwait(t, ended, "the end at the accept's retry")
		// Close returns once the accept loop has
		listener.Close()
		if accepts := inner.acceptCount.Load(); accepts != 1 || clock.Waits() != 1 {
			t.Fatalf("round %d: %d accepts and %d waits, want 1 of each", round, accepts, clock.Waits())
		}
	}
}

// The kill loop reloads nothing once the engine has ended: it reloads at once and then each KillReloadInterval, and
// an end landing as the second interval's timer fires, the clock at the reload's time, ends the loop after the two
// reloads before it, in each of 64 rounds. A loop that took the timer's case found the reload due and reloaded on the
// dead context, counting the load.
func TestTlsEdgeKillLoopReloadsNothingAfterTheEngineEnds(t *testing.T) {
	settings := testServiceSettings()
	// apart from the visitor keys' minute, so the clock counts the kill loop's waits alone
	settings.KillReloadInterval = 61 * time.Second
	for round := range 64 {
		ctx, cancel := context.WithCancel(context.Background())
		clock := sidecartest.NewEndingClock(sidecartest.DefaultClockStart(), sidecartest.EndingClockCounts(settings.KillReloadInterval))
		clock.MoveOnFire()
		ended := make(chan struct{})
		clock.Arm(2, func() {
			cancel()
			close(ended)
		})
		service := newClockSelectTestService(t, ctx, clock, sidecartest.NewFakeTlsEdgeStore(nil), settings)
		clock.Open()
		clockSelectAwait(t, ended, "the end at the second reload's wait")
		// Close returns once the loops have
		service.Close()
		if loads, _ := service.KillLoads(); loads != 2 || clock.Waits() != 2 {
			t.Fatalf("round %d: %d reloads and %d waits, want 2 of each", round, loads, clock.Waits())
		}
	}
}
