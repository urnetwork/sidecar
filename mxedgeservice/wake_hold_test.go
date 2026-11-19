// §15.6's wake hold (MAIL-M8-05) on the router, on a fake clock and a scripted dialer: a receiver that registers 12 s
// into a hold takes the session, a hold that finds none closes the handshake at 30 s, the 5th hold for a network and
// one past the process's bound close at once, the hint is a forced MailHint{RECEIVER_NEEDED} to the route's receivers
// that the hold never waits on, and the hold is off by default. Nothing here sleeps: a step waits on a pipe, a monitor
// or a timer it can see armed.

package mxedgeservice_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Documentation senders in five distinct /24s and /48s, so the network's per-sender cap counts each once.
var testWakeSenders = []string{"203.0.113.9", "198.51.100.9", "192.0.2.9", "2001:db8:1::9", "2001:db8:2::9"}

// A refusal as the dialer answers it.
func testSocketError(err error) error {
	return &sidecar.SocketCodeError{Err: err}
}

// A router with the hold on and the test network's route listing receiverIds, each bound to its client in the fake
// push as the host's resolver would bind it.
func newTestWakeRouter(t *testing.T, settings func(settings *mxedgeservice.MxEdgeSettings), receiverIds []sidecar.Id) *testRouter {
	t.Helper()
	router := newTestRouter(t, &testRouterOptions{settings: func(s *mxedgeservice.MxEdgeSettings) {
		s.WakeHold = true
		if settings != nil {
			settings(s)
		}
	}})
	router.setRoute(testRouteLabel, &mxedgeservice.MailRoute{
		NetworkId:          router.networkId,
		Label:              testRouteLabel,
		Host:               "mx",
		ReceiverSidecarIds: receiverIds,
	})
	for _, receiverId := range receiverIds {
		router.host.Push.BindSidecar(connect.Id(receiverId), testWakeClientOf(receiverId))
	}
	return router
}

// The client a receiver sidecar is bound to in these tests.
func testWakeClientOf(receiverId sidecar.Id) connect.Id {
	clientId := connect.Id(receiverId)
	clientId[15] ^= 0xc1
	return clientId
}

// Moves the clock to at, once a timer there is armed: the hold's next wait.
func (self *testRouter) advanceToTimer(at time.Time) {
	self.t.Helper()
	self.awaitTimerAt(at)
	self.clock.AdvanceTo(at)
}

// The next dial the dialer began.
func (self *testRouter) nextDial() *testReceiver {
	self.t.Helper()
	select {
	case receiver := <-self.dialer.dialing:
		return receiver
	case <-self.ctx.Done():
		self.t.Fatal("no dial")
		return nil
	}
}

// A receiver that registers 12 s into the hold takes the held session: the Find is asked again every 2 s, the 12 s
// one opens, and the session splices from the hello on, its record a splice's. The hint went out once, at the miss.
func TestWakeHoldTakesAReceiverThatRegistersAt12s(t *testing.T) {
	receiverId := testRouteNetworkId("receiver at 12 s")
	router := newTestWakeRouter(t, nil, []sidecar.Id{receiverId})
	// the miss at 0 s, then the retries at 2 s to 10 s find no one
	for range 6 {
		router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	}
	client, _ := router.dialFrom(testSender, testRouteSni)
	missTime := router.clock.Now()
	router.service.AwaitWakeHoldCount(1)
	for retry := 1; retry <= 5; retry += 1 {
		router.advanceToTimer(missTime.Add(time.Duration(retry) * 2 * time.Second))
		router.nextDial()
	}
	// the receiver registered between 10 s and 12 s: the 12 s Find opens its stream
	router.advanceToTimer(missTime.Add(12 * time.Second))
	receiver := router.nextDial()
	if got := receiver.request.HelloBytes; string(got) != string(testRouterHello(testRouteSni, 64)) {
		t.Errorf("the held hello reached the receiver's open as %x", got)
	}
	router.service.AwaitSpliceCount(1)
	router.service.AwaitWakeHoldCount(0)
	toReceiver := testRouteCapture(4096)
	go client.conn.Write(toReceiver)
	if got := receiver.readFull(t, len(toReceiver)); string(got) != string(toReceiver) {
		t.Error("the sender's bytes after the hold reached the receiver changed")
	}
	// the receiver's StreamClose ends a sender connection that cannot half-close
	receiver.writer.Close()
	client.expectEnd()
	router.service.AwaitSessionCount(0)

	if value := router.host.Metrics.Value("urnetwork_mxedge_wake_holds_total", "taken"); value != 1 {
		t.Errorf("%v holds counted taken", value)
	}
	router.service.AwaitWakeHints()
	if value := router.host.Metrics.Value("urnetwork_mxedge_wake_hints_total", "sent"); value != 1 {
		t.Errorf("%v hints counted sent", value)
	}
	records := router.flushRecords()
	if len(records) != 1 || !strings.HasPrefix(records[0].Result, "splice_") || records[0].NetworkId != router.networkId {
		t.Errorf("records %+v", records)
	}
}

// A hold no receiver comes for closes in the handshake 30 s after its miss, and not before: at 28 s the session is
// still held with nothing said, and by 30 s it has its alert, its record is no_receiver's and the closed-handshake
// memory answers the sender's plaintext retry 451.
func TestWakeHoldClosesTheHandshakeAt30s(t *testing.T) {
	receiverId := testRouteNetworkId("receiver never")
	router := newTestWakeRouter(t, nil, []sidecar.Id{receiverId})
	for range 15 {
		router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	}
	client, _ := router.dialFrom(testSender, testRouteSni)
	missTime := router.clock.Now()
	router.service.AwaitWakeHoldCount(1)
	for retry := 1; retry <= 14; retry += 1 {
		router.advanceToTimer(missTime.Add(time.Duration(retry) * 2 * time.Second))
		router.nextDial()
	}
	// 28 s: still held, the sender told nothing
	router.service.AwaitWakeHoldCount(1)
	router.advanceToTimer(missTime.Add(30 * time.Second))
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertInternalError))
	client.expectEnd()
	router.service.AwaitSessionCount(0)
	if code := router.plaintextReplyTo(testSender); code != "451" {
		t.Errorf("a plaintext retry after the hold got %s, not 451", code)
	}
	router.service.AwaitSessionCount(0)
	if value := router.host.Metrics.Value("urnetwork_mxedge_wake_holds_total", "expired"); value != 1 {
		t.Errorf("%v holds counted expired", value)
	}
	if value := router.host.Metrics.Value("urnetwork_mxedge_sessions_total", "no_receiver"); value != 1 {
		t.Errorf("%v sessions counted no_receiver", value)
	}
	records := router.flushRecords()
	if len(records) != 1 || records[0].Result != "no_receiver" || records[0].NetworkId != router.networkId {
		t.Errorf("records %+v", records)
	}
	if dials := len(router.dialer.Receivers()); dials != 15 {
		t.Errorf("%d dials, want the miss and 14 retries", dials)
	}
}

// Reaches TLS from sender and sends a hello naming the test network, returning once the dialer has been asked.
func (self *testRouter) heldFrom(sender string) *testClient {
	self.t.Helper()
	client, _ := self.dialFrom(sender, testRouteSni)
	return client
}

// The 5th session missing for one network closes in the handshake at once while four are held: the per-network bound.
func TestWakeHoldFifthForANetworkClosesAtOnce(t *testing.T) {
	receiverId := testRouteNetworkId("receiver of five")
	router := newTestWakeRouter(t, nil, []sidecar.Id{receiverId})
	for range 5 {
		router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	}
	for index, sender := range testWakeSenders[:4] {
		router.heldFrom(sender)
		router.service.AwaitWakeHoldCount(index + 1)
	}
	fifth := router.heldFrom(testWakeSenders[4])
	fifth.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertInternalError))
	fifth.expectEnd()
	router.service.AwaitSessionCount(4)
	router.service.AwaitWakeHoldCount(4)
	if value := router.host.Metrics.Value("urnetwork_mxedge_wake_holds_total", "full"); value != 1 {
		t.Errorf("%v holds counted full", value)
	}
}

// One session past the process's bound closes at once, whatever its network: here a bound of 2, both taken by the
// test network, refuses another network's miss. TestWakeHoldsBoundsAtTheDesignsNumbers holds 1,000 itself.
func TestWakeHoldPastTheProcessBoundClosesAtOnce(t *testing.T) {
	receiverId := testRouteNetworkId("receiver of the process")
	router := newTestWakeRouter(t, func(settings *mxedgeservice.MxEdgeSettings) {
		settings.WakeHoldCount = 2
	}, []sidecar.Id{receiverId})
	otherNetworkId := testRouteNetworkId("another network")
	otherLabel := "zz98yx76wv"
	router.setRoute(otherLabel, &mxedgeservice.MailRoute{NetworkId: otherNetworkId, Label: otherLabel, Host: "mx", ReceiverSidecarIds: []sidecar.Id{receiverId}})
	router.host.Quota.SetBalance(connect.Id(otherNetworkId), testRouteBalance)
	for range 3 {
		router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	}
	router.heldFrom(testWakeSenders[0])
	router.service.AwaitWakeHoldCount(1)
	router.heldFrom(testWakeSenders[1])
	router.service.AwaitWakeHoldCount(2)
	third, _ := router.dialFrom(testWakeSenders[2], "mx."+otherLabel+"."+testRouteRoot)
	third.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertInternalError))
	third.expectEnd()
	router.service.AwaitSessionCount(2)
	if value := router.host.Metrics.Value("urnetwork_mxedge_wake_holds_total", "full"); value != 1 {
		t.Errorf("%v holds counted full", value)
	}
}

// The holds' bounds at §15.6's own numbers: 4 for a network, then 1,000 across networks, the 1,001st refused, and a
// release making room again. Only a network's first hold is the one that hints.
func TestWakeHoldsBoundsAtTheDesignsNumbers(t *testing.T) {
	settings := testRouterSettings()
	if settings.WakeHoldCount != 1000 || settings.WakeHoldNetworkCount != 4 || settings.WakeHoldTimeout != 30*time.Second {
		t.Fatalf("§15.6 holds 30 s, 1,000 a process and 4 a network, not %v, %d and %d",
			settings.WakeHoldTimeout, settings.WakeHoldCount, settings.WakeHoldNetworkCount)
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	holds := mxedgeservice.NewWakeHolds(t.Context(), nil, settings, clock, sidecartest.NewFakeMetrics(nil))
	networkIds := []sidecar.Id{}
	for index := range 250 {
		var networkId sidecar.Id
		networkId[0], networkId[1] = byte(index), byte(index>>8)
		networkIds = append(networkIds, networkId)
		for hold := range 4 {
			first, ok := holds.Acquire(networkId)
			if !ok || first != (hold == 0) {
				t.Fatalf("hold %d of network %d: ok %v first %v", hold, index, ok, first)
			}
		}
		if _, ok := holds.Acquire(networkId); ok {
			t.Fatalf("a 5th hold for network %d", index)
		}
	}
	var lastNetworkId sidecar.Id
	lastNetworkId[2] = 1
	if _, ok := holds.Acquire(lastNetworkId); ok {
		t.Fatal("a 1,001st hold in the process")
	}
	holds.Release(networkIds[7])
	if first, ok := holds.Acquire(lastNetworkId); !ok || !first {
		t.Errorf("after a release: ok %v first %v", ok, first)
	}
}

// The hint is a forced MailHint{RECEIVER_NEEDED, mx} on topic mail, kind 0x1702, its version the clock's ms at the
// miss, to every receiver the route lists; one the host cannot resolve is missed, never an error. A second session
// held for the same network hints no one again.
func TestWakeHoldHintsTheRoutesReceiversOnceForced(t *testing.T) {
	receiverIds := []sidecar.Id{testRouteNetworkId("receiver newest"), testRouteNetworkId("receiver older")}
	router := newTestWakeRouter(t, nil, receiverIds[:1])
	router.setRoute(testRouteLabel, &mxedgeservice.MailRoute{NetworkId: router.networkId, Label: testRouteLabel, Host: "mx", ReceiverSidecarIds: receiverIds})
	for range 2 {
		router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	}
	router.heldFrom(testWakeSenders[0])
	missTime := router.clock.Now()
	router.service.AwaitWakeHoldCount(1)
	router.service.AwaitWakeHints()
	router.heldFrom(testWakeSenders[1])
	router.service.AwaitWakeHoldCount(2)
	router.service.AwaitWakeHints()

	hints := router.host.Push.Hints(testWakeClientOf(receiverIds[0]))
	if len(hints) != 1 {
		t.Fatalf("the receiver had %d hints, want one for both holds", len(hints))
	}
	hint := hints[0]
	body := &protocol.MailHint{}
	if err := proto.Unmarshal(hint.Body, body); err != nil {
		t.Fatal(err)
	}
	if !hint.Forced || hint.Topic != sidecar.PushTopicMail || hint.Kind != 0x1702 || hint.Version != uint64(missTime.UnixMilli()) ||
		body.GetKind() != protocol.MailHintKind_MAIL_HINT_RECEIVER_NEEDED || body.GetHost() != "mx" {
		t.Errorf("hint %+v, body %v", hint, body)
	}
	if missed := router.host.Push.MissedSidecarIds(); len(missed) != 1 || missed[0] != connect.Id(receiverIds[1]) {
		t.Errorf("missed %v", missed)
	}
}

// A Push whose hint does not return until released: the hold must go on without it.
type testBlockingPush struct {
	release chan struct{}
	entered chan struct{}

	stateLock sync.Mutex
	hints     []*sidecar.ClientHint
}

func (self *testBlockingPush) Hint(ctx context.Context, clientIds []connect.Id, hint *sidecar.ClientHint) error {
	return errors.New("not by client")
}

func (self *testBlockingPush) HintSidecars(ctx context.Context, sidecarIds []connect.Id, hint *sidecar.ClientHint) error {
	self.stateLock.Lock()
	self.hints = append(self.hints, hint)
	self.stateLock.Unlock()
	close(self.entered)
	select {
	case <-self.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// The router never blocks on the wake: with the hint's call stuck, the 2 s retry still runs and takes the receiver,
// and the stuck hint, once released, counts as sent.
func TestWakeHoldNeverWaitsOnTheHint(t *testing.T) {
	receiverId := testRouteNetworkId("receiver of a slow push")
	push := &testBlockingPush{release: make(chan struct{}), entered: make(chan struct{})}
	router := newTestRouter(t, &testRouterOptions{
		settings: func(settings *mxedgeservice.MxEdgeSettings) {
			settings.WakeHold = true
			// the hint's own bound far past the hold, so only its release ends it
			settings.WakeHintTimeout = time.Hour
		},
		push: push,
	})
	router.setRoute(testRouteLabel, &mxedgeservice.MailRoute{NetworkId: router.networkId, Label: testRouteLabel, Host: "mx", ReceiverSidecarIds: []sidecar.Id{receiverId}})
	router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	client := router.heldFrom(testSender)
	missTime := router.clock.Now()
	<-push.entered
	router.advanceToTimer(missTime.Add(2 * time.Second))
	receiver := router.nextDial()
	router.service.AwaitSpliceCount(1)
	close(push.release)
	router.service.AwaitWakeHints()
	if value := router.host.Metrics.Value("urnetwork_mxedge_wake_hints_total", "sent"); value != 1 {
		t.Errorf("%v hints counted sent", value)
	}
	receiver.writer.Close()
	client.expectEnd()
	router.service.AwaitSessionCount(0)
}

// With sockets unavailable the session is held and asked for again, but no receiver is hinted, since they may well be
// online: the 2 s retry opens.
func TestWakeHoldWaitsOutSocketsUnavailableWithoutAHint(t *testing.T) {
	receiverId := testRouteNetworkId("receiver behind sockets")
	router := newTestWakeRouter(t, nil, []sidecar.Id{receiverId})
	router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketUnavailable)})
	client := router.heldFrom(testSender)
	missTime := router.clock.Now()
	router.service.AwaitWakeHoldCount(1)
	router.advanceToTimer(missTime.Add(2 * time.Second))
	receiver := router.nextDial()
	router.service.AwaitSpliceCount(1)
	if hints := router.host.Push.AllHints(); len(hints) != 0 {
		t.Errorf("sockets unavailable hinted %d", len(hints))
	}
	receiver.writer.Close()
	client.expectEnd()
	router.service.AwaitSessionCount(0)
}

// What closes a hold at once, each as M7's close: a busy answer to a retry, which no wait mends; and a route that
// lists no receiver, which holds nothing at all.
func TestWakeHoldClosesAtOnceForWhatNoWaitMends(t *testing.T) {
	receiverId := testRouteNetworkId("receiver busy")
	router := newTestWakeRouter(t, nil, []sidecar.Id{receiverId})
	router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketBusy)})
	client := router.heldFrom(testSender)
	missTime := router.clock.Now()
	router.service.AwaitWakeHoldCount(1)
	router.advanceToTimer(missTime.Add(2 * time.Second))
	router.nextDial()
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertInternalError))
	client.expectEnd()
	router.service.AwaitSessionCount(0)
	if value := router.host.Metrics.Value("urnetwork_mxedge_sessions_total", "receiver_busy"); value != 1 {
		t.Errorf("%v sessions counted receiver_busy", value)
	}
	if value := router.host.Metrics.Value("urnetwork_mxedge_wake_holds_total", "refused"); value != 1 {
		t.Errorf("%v holds counted refused", value)
	}

	unlisted := newTestWakeRouter(t, nil, nil)
	unlisted.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	unlisted.expectClosedHandshake(testSender, testRouteSni, mxedgeservice.MxTlsAlertInternalError)
	if hints := unlisted.host.Push.AllHints(); len(hints) != 0 {
		t.Errorf("a route with no receiver hinted %d", len(hints))
	}
	if dials := len(unlisted.dialer.Receivers()); dials != 1 {
		t.Errorf("a route with no receiver dialed %d times", dials)
	}
}

// A drain ends a hold at once: the held session closes in the handshake and the drain returns, with no wait for the
// hold's 30 s.
func TestWakeHoldEndsAtADrain(t *testing.T) {
	receiverId := testRouteNetworkId("receiver of a drain")
	router := newTestWakeRouter(t, nil, []sidecar.Id{receiverId})
	router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	client := router.heldFrom(testSender)
	router.service.AwaitWakeHoldCount(1)
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		router.service.Drain()
	}()
	client.expectBytes(testAlertRecord(mxedgeservice.MxTlsAlertInternalError))
	client.expectEnd()
	<-drained
	if value := router.host.Metrics.Value("urnetwork_mxedge_wake_holds_total", "ended"); value != 1 {
		t.Errorf("%v holds counted ended", value)
	}
}

// Off by default (plan-MAIL-hints' interim): a miss with receivers listed closes at once, as M7's, and hints no one.
func TestWakeHoldIsOffByDefault(t *testing.T) {
	if mxedgeservice.DefaultMxEdgeSettings().WakeHold {
		t.Fatal("the wake hold is on by default")
	}
	receiverId := testRouteNetworkId("receiver of the default")
	router := newTestRouter(t, nil)
	router.setRoute(testRouteLabel, &mxedgeservice.MailRoute{NetworkId: router.networkId, Label: testRouteLabel, Host: "mx", ReceiverSidecarIds: []sidecar.Id{receiverId}})
	router.dialer.answer(&testDialAnswer{err: testSocketError(sidecar.ErrSocketNoListener)})
	router.expectClosedHandshake(testSender, testRouteSni, mxedgeservice.MxTlsAlertInternalError)
	if hints := router.host.Push.AllHints(); len(hints) != 0 {
		t.Errorf("the default hinted %d", len(hints))
	}
}
