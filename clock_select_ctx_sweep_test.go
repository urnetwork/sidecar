//go:build !sidecar_http && !js && !ios_extension

// The root's waits that end with their context (clock-select-ctx-sweep, after tls-wait-ctx-shape). Go's select takes
// any of its ready cases at random, so a loop that selects on a context's end beside a clock's timer ran one more pass
// after the end whenever both were ready at once and the timer's case won. Each loop here did something outward on
// that pass: the TLS front's probe dialed its target and set the listener's serving, its update loop sent the
// registration an update, a CT pass on an ended context read the names and marked the watch degraded, the rpc send
// loop handed connect the envelope again, and the mail receiver listened again, setting its status from the listen,
// or ran a key pass that publishes, serves, rotates and retires. Each now answers the end once its context has ended,
// whatever else was ready, and asks the clock for nothing then.
//
// The proof is tls-wait-ctx-shape's clock (tlsWaitEndingClock), which ends the context as a wait's timer fires, so
// both cases are ready when select runs, over 64 rounds, which leave the old coin no chance (at most (1/2)^64) to pass.
// The engines' cases are in each engine's clock_select_ctx_sweep_test.go, the config writer's in
// clock_select_ctx_sweep_external_test.go, and the certificate manager's Close in clock_select_ctx_sweep_hooks_test.go.

package sidecar

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// Where the sweep's clocks stand.
func clockSelectTestStart() time.Time {
	return time.Date(2026, time.November, 26, 9, 0, 0, 0, time.UTC)
}

// A TlsFront under ctx on the front tests' fakes and clock, its target dialed by dial (the default dialer when nil),
// and its registration's lists sent by updateTls (none when nil). It is closed when the test ends.
func newClockSelectTestFront(
	t *testing.T,
	ctx context.Context,
	clock Clock,
	settings *TlsFrontSettings,
	dial func(ctx context.Context) (net.Conn, error),
	updateTls func(update *TlsFrontUpdate) error,
) *TlsFront {
	t.Helper()
	front, err := NewTlsFront(ctx, &TlsFrontArgs{
		Settings: settings,
		Target: &TlsFrontTarget{
			Name:         tlsFrontTestName,
			ServerNames:  []string{tlsFrontTestServerName},
			AppMode:      "http",
			LocalAddress: "127.0.0.1:8080",
		},
		Listener:  newTlsFrontTestListener(NewId()),
		NetworkId: NewId(),
		SidecarId: NewId(),
		Policy:    newTlsFrontTestPolicy(),
		Certificate: func(serverName string) (*tls.Certificate, error) {
			return nil, errors.New("no certificate in this test")
		},
		Secrets: newTlsFrontTestSecrets(),
		Limits: func(ctx context.Context) (*QuotaLimits, error) {
			return &QuotaLimits{Tier: "pro"}, nil
		},
		DialTarget: dial,
		UpdateTls:  updateTls,
		Clock:      clock,
		Log:        NewNoopLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		front.Close()
	})
	return front
}

// The front's probe makes no probe once the front has ended: an end landing as a wait after the first probe fires ends
// the loop with that probe its last, whether the wait was the probe's least spacing (the first) or the rest of its
// interval (the second), in each of 64 rounds, and an end at the first asks the clock for no second wait; a front whose
// context ended before it began probes nothing and asks the clock for nothing. A loop that took the timer's case dialed
// the target again on the dead front and set the listener's serving from that dial.
func TestTlsFrontProbeMakesNoProbeAfterTheFrontEnds(t *testing.T) {
	settings := DefaultTlsFrontSettings()
	// the dials the front's probe made before its loop returned
	run := func(ctx context.Context, clock *tlsWaitEndingClock) int64 {
		dialCount := &atomic.Int64{}
		front := newClockSelectTestFront(t, ctx, clock, settings, func(ctx context.Context) (net.Conn, error) {
			dialCount.Add(1)
			return nil, errors.New("the target refuses")
		}, nil)
		clock.open()
		clock.awaitDone(t, front.probeDone, "the probe loop")
		return dialCount.Load()
	}
	for round := range 64 {
		for _, endIndex := range []int{1, 2} {
			ctx, cancel := context.WithCancel(context.Background())
			// the probe's waits are the front's only ones
			clock := newTlsWaitEndingClock(t, clockSelectTestStart(), 0)
			clock.arm(endIndex, cancel)
			if dials := run(ctx, clock); dials != 1 || clock.waits() != endIndex {
				t.Fatalf("round %d, ending at wait %d: %d dials and %d waits, want 1 dial and %d waits", round, endIndex, dials, clock.waits(), endIndex)
			}
			cancel()
		}
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	clock := newTlsWaitEndingClock(t, clockSelectTestStart(), 0)
	if dials := run(ended, clock); dials != 0 || clock.asks() != 0 {
		t.Fatalf("a front ended before it began: %d dials and %d waits", dials, clock.asks())
	}
}

// The front's update loop sends nothing once the front has ended: with every send refused, each look waits
// TargetProbeMinInterval to try again, and an end landing as the second wait fires ends the loop after the two sends
// before it, in each of 64 rounds; a front whose context ended before it began sends nothing and asks the clock for
// nothing. A loop that took the timer's case sent the registration another update for the dead front.
func TestTlsFrontUpdatesSendNothingAfterTheFrontEnds(t *testing.T) {
	settings := DefaultTlsFrontSettings()
	// no probe, so the update loop's are the front's only waits
	settings.TargetProbeInterval = 0
	// the sends the update loop made before it returned
	run := func(ctx context.Context, clock *tlsWaitEndingClock) int64 {
		sendCount := &atomic.Int64{}
		front := newClockSelectTestFront(t, ctx, clock, settings, nil, func(update *TlsFrontUpdate) error {
			sendCount.Add(1)
			return errors.New("the registration refuses")
		})
		clock.open()
		clock.awaitDone(t, front.updatesDone, "the update loop")
		return sendCount.Load()
	}
	for round := range 64 {
		ctx, cancel := context.WithCancel(context.Background())
		clock := newTlsWaitEndingClock(t, clockSelectTestStart(), settings.TargetProbeMinInterval)
		clock.arm(2, cancel)
		if sends := run(ctx, clock); sends != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d sends and %d waits, want 2 of each", round, sends, clock.waits())
		}
		cancel()
	}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	clock := newTlsWaitEndingClock(t, clockSelectTestStart(), 0)
	if sends := run(ended, clock); sends != 0 || clock.asks() != 0 {
		t.Fatalf("a front ended before it began: %d sends and %d waits", sends, clock.asks())
	}
}

// A CT pass on a context that has ended runs none: with the names refused, a pass that ran would mark the watch
// degraded, and one on an ended context leaves the status as the live pass before it left it, raises nothing, and
// answers the alarms standing.
func TestTlsCtWatchPassOnAnEndedContextRunsNone(t *testing.T) {
	fixture := newTlsCtFixture(t)
	standing := fixture.pass()
	if fixture.watch.Degraded() {
		t.Fatal("the live pass was degraded")
	}
	events := len(fixture.eventsSoFar())
	fixture.set(func() {
		fixture.namesErr = errors.New("the names are refused")
	})
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if answered := fixture.watch.Pass(ended); answered != standing || fixture.watch.Degraded() || len(fixture.eventsSoFar()) != events {
		t.Fatalf("a pass on an ended context: %d alarms (%d standing), degraded %t, %d events (%d before)",
			answered, standing, fixture.watch.Degraded(), len(fixture.eventsSoFar()), events)
	}
	// the same refusal on a live context is degraded, so the names were the pass's to read
	if fixture.pass(); !fixture.watch.Degraded() {
		t.Fatal("a live pass with the names refused was not degraded")
	}
}

// The rpc send loop hands connect nothing more once the call's context or the dispatcher has ended: a send connect
// refuses waits CallSendRetryInterval, and an end landing as that pause's timer fires ends the call after the one
// send, CANCELLED for the call's context and errSubprotocolClosed for the dispatcher's, in each of 64 rounds, asking
// the clock for no second pause. A loop that took the timer's case sent the envelope again after the end.
func TestSubprotocolSendEnvelopesUntilSendsNothingAfterTheEnd(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	// the sends one call made and its answer
	run := func(endCall bool) (int64, error, *tlsWaitEndingClock) {
		clock := newTlsWaitEndingClock(t, clockSelectTestStart(), settings.CallSendRetryInterval)
		subprotocolCtx, subprotocolCancel := context.WithCancel(context.Background())
		defer subprotocolCancel()
		callCtx, callCancel := context.WithCancel(context.Background())
		defer callCancel()
		sendCount := &atomic.Int64{}
		// what the send loop reads of a dispatcher: its context, settings, clock, counts and connect's send, which
		// refuses every envelope at once
		subprotocol := &Subprotocol{
			ctx:      subprotocolCtx,
			settings: settings,
			clock:    clock,
			send: func(destinationId connect.Id, envelope *protocol.Envelope, ack connect.AckFunction, timeout time.Duration, opts ...any) (bool, error) {
				sendCount.Add(1)
				return false, nil
			},
		}
		end := callCancel
		if !endCall {
			end = subprotocolCancel
		}
		clock.arm(1, end)
		clock.open()
		envelopes := []*protocol.Envelope{{Version: WireVersionMajor, Type: uint32(testCallType), RequestId: 7}}
		err := subprotocol.sendEnvelopesUntil(callCtx, connect.NewId(), envelopes, ignoreSubprotocolAck, clock.Now().Add(time.Minute), 7, func(before bool) {})
		return sendCount.Load(), err, clock
	}
	for round := range 64 {
		sends, err, clock := run(true)
		if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_CANCELLED || sends != 1 || clock.waits() != 1 {
			t.Fatalf("round %d, the call's end: %v after %d sends and %d pauses, want CANCELLED after 1 of each", round, err, sends, clock.waits())
		}
		sends, err, clock = run(false)
		if !errors.Is(err, errSubprotocolClosed) || sends != 1 || clock.waits() != 1 {
			t.Fatalf("round %d, the dispatcher's end: %v after %d sends and %d pauses, want it closed after 1 of each", round, err, sends, clock.waits())
		}
	}
}

// The mail receiver asks for no listen once its context has ended: with every listen refused, each waits
// ListenRetryInterval to ask again, and an end landing as the second wait fires ends the loop after the two listens
// before it, Start's and the first wait's, in each of 64 rounds, the status keeping the refusal it showed. A loop that
// took the timer's case listened again on the dead context and set the status from that listen.
func TestMailReceiverListensNoMoreAfterItsContextEnds(t *testing.T) {
	refused := errors.New("the listen is refused")
	for round := range 64 {
		world := newMailReceiverTestWorld(t, nil)
		world.listenAnswers = []func() (MailReceiverListener, error){
			func() (MailReceiverListener, error) { return nil, refused },
		}
		clock := newTlsWaitEndingClock(t, world.clock.Now(), DefaultMailReceiverSettings().ListenRetryInterval)
		receiver := world.newReceiver(func(args *MailReceiverArgs) {
			args.Clock = clock
		})
		clock.arm(2, world.cancel)
		if err := world.start(); !errors.Is(err, refused) {
			t.Fatalf("round %d: the first listen answered %v", round, err)
		}
		clock.open()
		clock.awaitDone(t, receiver.done, "the receiver's loop")
		if calls, _ := world.listenCalls.Get(); calls != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d listens and %d waits, want 2 of each", round, calls, clock.waits())
		}
		if problem := receiver.Status().Problem; problem != "listen: "+refused.Error() {
			t.Fatalf("round %d: the status reads %q", round, problem)
		}
	}
}

// The mail receiver makes no key pass once its context has ended: serving a listen, it passes at once and then at
// each wait its pass sets, and an end landing as the second wait fires ends the key loop after the two passes before
// it, in each of 64 rounds, and the receiver's loop with it, asking the clock for nothing more. A loop that took the
// timer's case ran a pass on the dead context, which publishes, serves, rotates and retires.
func TestMailReceiverMakesNoKeyPassAfterItsContextEnds(t *testing.T) {
	for round := range 64 {
		world := newMailReceiverTestWorld(t, nil)
		// every wait the receiver asks: the key loop's while it serves, and the listen loop's after
		clock := newTlsWaitEndingClock(t, world.clock.Now(), 0)
		passCount := &atomic.Int64{}
		receiver := world.newReceiver(func(args *MailReceiverArgs) {
			args.Clock = clock
			// each pass reads the names first, after its records
			args.Names = func(ctx context.Context) ([]string, error) {
				passCount.Add(1)
				return slices.Clone(testMailReceiverNames), nil
			}
		})
		clock.arm(2, world.cancel)
		if err := world.start(); err != nil {
			t.Fatalf("round %d: the first listen answered %v", round, err)
		}
		clock.open()
		clock.awaitDone(t, receiver.done, "the receiver's loop")
		if passes := passCount.Load(); passes != 2 || clock.waits() != 2 {
			t.Fatalf("round %d: %d key passes and %d waits, want 2 of each", round, passes, clock.waits())
		}
	}
}
