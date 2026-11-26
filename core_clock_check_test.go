//go:build !js && !ios && !android && !sdk_mobile_bind && !windows && !sidecar_http && !ios_extension

// The core's wall-clock ends after sleep or a clock step (core_clock_check.go; owner decision 789's seam, QD-1422), on
// a clock whose wall time jumps while its timers stand still (testSleepingClock): a tls/ or smtp/ stream's grant end,
// and a daemon forward's grant expiry, the host slept past are left to their standing timers with no check, and the
// check ends them at once, a stream reset with RST_REVOKED and a forward closed with its connections, while one whose
// end is still ahead is armed again from the wall clock and ends at its end, not later; Sidecar.CheckClock reaches the
// sockets component and passes over a component with no clock; and a revocation acts at once with no check, which a
// check after it keeps.

package sidecar

import (
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The reset code the far end of a stream reads.
func testClockCheckResetCode(end *socketPipeEnd) protocol.StreamResetCode {
	_, err := end.Read(make([]byte, 1))
	var resetErr *socketStreamResetError
	if !errors.As(err, &resetErr) {
		return protocol.StreamResetCode_RST_UNSPECIFIED
	}
	return resetErr.Code
}

// Waits for the far side to end conn: fails where it answers bytes, or where it is still open at the guard, which
// bounds a failure and is never the proof.
func testClockCheckConnEnded(t *testing.T, conn net.Conn, what string) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(testClockCheckGuardTimeout))
	_, err := conn.Read(make([]byte, 1))
	switch {
	case err == nil:
		t.Fatalf("%s: the connection is open", what)
	case errors.Is(err, os.ErrDeadlineExceeded):
		t.Fatalf("%s: the connection is still open", what)
	}
}

// A listen fixture whose listeners read the sleeping clock over the fixture's own, which keeps its registrar and the
// tickets it makes: the two read the same time until the device sleeps.
func newTestClockCheckListenFixture(t *testing.T) (*testListenFixture, *testSleepingClock) {
	t.Helper()
	fixture := newTestListenFixture(t)
	clock := newTestSleepingClock(fixture.clock)
	// before any listener reads it, on this goroutine
	fixture.component.clock = clock
	return fixture, clock
}

// Opens a stream on listener whose ticket's grant ends at grantEnd, zero for a ticket that names no end.
func testClockCheckOpen(t *testing.T, fixture *testListenFixture, listener *SocketListener, grantEnd time.Time) *socketPipeEnd {
	t.Helper()
	end, err := fixture.open(listener, fixture.request(fixture.ticket(t, listener, func(ticket *protocol.SocketTicket) {
		if !grantEnd.IsZero() {
			ticket.GrantExpireTimeMillis = uint64(grantEnd.UnixMilli())
		}
	})))
	if err != nil {
		t.Fatal(err)
	}
	return end
}

// A stream whose grant ended while the device slept stays open and counted with no check, its wait standing on the
// awake clock; CheckClock resets it with RST_REVOKED at once. A stream whose end is still ahead is armed again from the
// wall clock: the awake clock moving a second short of what remains leaves it, and the second more resets it, where
// its first wait would have run an hour on. A stream whose ticket names no end stays.
func TestSocketListenCheckClockEndsAStreamTheDeviceSleptPast(t *testing.T) {
	fixture, clock := newTestClockCheckListenFixture(t)
	listener := fixture.listen(t, "db/primary", nil)
	defer listener.Close()
	start := clock.Now()
	near := testClockCheckOpen(t, fixture, listener, start.Add(10*time.Minute))
	far := testClockCheckOpen(t, fixture, listener, start.Add(3*time.Hour))
	testClockCheckOpen(t, fixture, listener, time.Time{})
	if count := listener.inflightCount(); count != 3 {
		t.Fatalf("%d in flight", count)
	}

	clock.sleep(time.Hour)
	if count := listener.inflightCount(); count != 3 {
		t.Fatalf("%d in flight after the sleep with no check", count)
	}
	fixture.component.CheckClock()
	// the check's reset ran on this goroutine, the test clock calling a wait already due at once
	if count := listener.inflightCount(); count != 2 {
		t.Fatalf("%d in flight after the check", count)
	}
	if code := testClockCheckResetCode(near); code != protocol.StreamResetCode_RST_REVOKED {
		t.Fatalf("the stream the device slept past: %s", code)
	}

	fixture.clock.advance(2*time.Hour - time.Second)
	if count := listener.inflightCount(); count != 2 {
		t.Fatalf("a second before its end the later stream ended: %d in flight", count)
	}
	fixture.clock.advance(time.Second)
	if count := listener.inflightCount(); count != 1 {
		t.Fatalf("%d in flight at the later end", count)
	}
	if code := testClockCheckResetCode(far); code != protocol.StreamResetCode_RST_REVOKED {
		t.Fatalf("the later stream at its end: %s", code)
	}
}

// A check with no sleep arms each wait again at the same end; checks of a listener whose stream ended do nothing; and
// a revocation resets its stream at once, with no check, which a check after it leaves ended.
func TestSocketListenCheckClockKeepsWhatIsNotDueAndARevocation(t *testing.T) {
	fixture, clock := newTestClockCheckListenFixture(t)
	listener := fixture.listen(t, "db/primary", nil)
	defer listener.Close()
	start := clock.Now()
	timed := testClockCheckOpen(t, fixture, listener, start.Add(time.Hour))
	revoked := testClockCheckOpen(t, fixture, listener, time.Time{})
	fixture.component.CheckClock()
	fixture.component.CheckClock()
	if count := listener.inflightCount(); count != 2 {
		t.Fatalf("%d in flight after checks with nothing due", count)
	}

	fixture.policy.set(func(policy *testSocketPolicy) { policy.inbound = map[Id]bool{} })
	fixture.component.PolicyChanged()
	if count := listener.inflightCount(); count != 0 {
		t.Fatalf("%d in flight after the revocation", count)
	}
	if code := testClockCheckResetCode(revoked); code != protocol.StreamResetCode_RST_REVOKED {
		t.Fatalf("at a revocation: %s", code)
	}
	if code := testClockCheckResetCode(timed); code != protocol.StreamResetCode_RST_REVOKED {
		t.Fatalf("the timed stream at the revocation: %s", code)
	}
	fixture.component.CheckClock()
	if count := listener.inflightCount(); count != 0 {
		t.Fatalf("%d in flight after a check following the revocation", count)
	}
	// the timers the check armed went with their streams: the hour passes with nothing left to reset
	fixture.clock.advance(time.Hour)
	if count := listener.inflightCount(); count != 0 {
		t.Fatalf("%d in flight", count)
	}
}

// A component that counts its clock checks.
type testClockCheckComponent struct {
	name   string
	checks atomic.Int64
}

func (self *testClockCheckComponent) Name() string {
	return self.name
}

func (self *testClockCheckComponent) Attach(env *SidecarEnv) error {
	return nil
}

func (self *testClockCheckComponent) Close() {}

func (self *testClockCheckComponent) CheckClock() {
	self.checks.Add(1)
}

// A component with no clock.
type testClocklessComponent struct{}

func (self *testClocklessComponent) Name() string {
	return "clockless"
}

func (self *testClocklessComponent) Attach(env *SidecarEnv) error {
	return nil
}

func (self *testClocklessComponent) Close() {}

// Sidecar.CheckClock reaches every listed component that keeps a clock, once each, the sockets component among them,
// whose stream the device slept past it resets; a component with no clock is passed over; and a Sidecar with no
// connect leg does nothing.
func TestSidecarCheckClockReachesItsClockComponents(t *testing.T) {
	fixture, clock := newTestClockCheckListenFixture(t)
	listener := fixture.listen(t, "db/primary", nil)
	defer listener.Close()
	stream := testClockCheckOpen(t, fixture, listener, clock.Now().Add(time.Minute))
	counted := &testClockCheckComponent{name: "counted"}
	leg := &sidecarConnectLeg{}
	for _, component := range []SidecarComponent{fixture.component, counted, &testClocklessComponent{}} {
		if err := leg.addComponent(component); err != nil {
			t.Fatal(err)
		}
	}
	running := &Sidecar{leg: leg}

	clock.sleep(time.Hour)
	running.CheckClock()
	if checks := counted.checks.Load(); checks != 1 {
		t.Fatalf("a clock component was checked %d times", checks)
	}
	if count := listener.inflightCount(); count != 0 {
		t.Fatalf("%d in flight after the check", count)
	}
	if code := testClockCheckResetCode(stream); code != protocol.StreamResetCode_RST_REVOKED {
		t.Fatalf("the sockets component's stream: %s", code)
	}
	(&Sidecar{}).CheckClock()
}

// The daemon's bridges, their forwards reading the sleeping clock over the test's.
func newTestClockCheckDaemonBridges(t *testing.T) (*testDaemonBridges, *testSleepingClock) {
	t.Helper()
	world := newTestDaemonBridges(t)
	clock := newTestSleepingClock(world.clock)
	// before any forward reads it, on this goroutine
	world.bridges.clock = clock
	return world, clock
}

// A forward whose grant's expiry the host slept past keeps its listener and its connection with no check, its wait
// standing on the awake clock; CheckClock closes it at once, resetting the connection and unbinding the listener. A
// forward whose expiry is still ahead is armed again from the wall clock: the awake clock moving a second short of what
// remains leaves it, and the second more ends it, where its first wait would have run an hour on.
func TestDaemonBridgesCheckClockClosesAForwardTheHostSleptPast(t *testing.T) {
	world, clock := newTestClockCheckDaemonBridges(t)
	start := clock.Now()
	world.backend.set(func() { world.backend.expiresAt = start.Add(time.Hour) })
	near := world.forward(t, "tcp", []string{"127.0.0.1"})
	nearConn := testDaemonBridgeConn(t, near)
	world.backend.set(func() { world.backend.expiresAt = start.Add(3 * time.Hour) })
	far := world.forward(t, "tcp", []string{"127.0.0.1"})
	farConn := testDaemonBridgeConn(t, far)

	clock.sleep(2 * time.Hour)
	if forwards := world.bridges.Forwards(world.networkId); len(forwards) != 2 {
		t.Fatalf("%d forwards after the sleep with no check", len(forwards))
	}
	world.bridges.CheckClock()
	// the check closed it on this goroutine: forgotten and unbound before its connection was reset
	if forwards := world.bridges.Forwards(world.networkId); len(forwards) != 1 || forwards[0].ForwardId != far.ForwardId {
		t.Fatalf("the forwards after the check: %+v", forwards)
	}
	testClockCheckConnEnded(t, nearConn, "the forward the host slept past")
	if late, err := net.Dial("tcp", near.LocalAddresses[0]); err == nil {
		late.Close()
		t.Fatal("the listener outlived its grant's expiry past the check")
	}

	world.clock.Advance(time.Hour - time.Second)
	if forwards := world.bridges.Forwards(world.networkId); len(forwards) != 1 {
		t.Fatalf("a second before its expiry the later forward ended: %d forwards", len(forwards))
	}
	world.clock.Advance(time.Second)
	// the reset arrives once the forward has closed
	testClockCheckConnEnded(t, farConn, "the later forward at its expiry")
	if forwards := world.bridges.Forwards(world.networkId); len(forwards) != 0 || world.bridges.Active() {
		t.Fatal("the later forward outlived its grant")
	}
}

// A check with nothing due leaves a forward serving; a forward with no expiry takes no wait; and a revocation closes a
// forward at once at the reread, with no check, which a check after it leaves closed.
func TestDaemonBridgesCheckClockKeepsWhatIsNotDueAndARevocation(t *testing.T) {
	world, clock := newTestClockCheckDaemonBridges(t)
	world.backend.set(func() { world.backend.expiresAt = clock.Now().Add(time.Hour) })
	timed := world.forward(t, "tcp", []string{"127.0.0.1"})
	world.bridges.CheckClock()
	world.bridges.CheckClock()
	conn := testDaemonBridgeConn(t, timed)
	if forwards := world.bridges.Forwards(world.networkId); len(forwards) != 1 {
		t.Fatalf("%d forwards after checks with nothing due", len(forwards))
	}
	world.backend.set(func() { world.backend.expiresAt = time.Time{} })
	open := world.forward(t, "tcp", []string{"127.0.0.1"})
	if open.ExpiresMs != 0 {
		t.Fatalf("a forward with no expiry lists %d", open.ExpiresMs)
	}
	world.bridges.CheckClock()

	world.backend.set(func() { world.backend.live = false })
	world.bridges.GrantsChanged(world.networkId)
	if forwards := world.bridges.Forwards(world.networkId); len(forwards) != 0 {
		t.Fatalf("%d forwards after the revocation", len(forwards))
	}
	testClockCheckConnEnded(t, conn, "the revoked forward")
	world.bridges.CheckClock()
	if forwards := world.bridges.Forwards(world.networkId); len(forwards) != 0 {
		t.Fatalf("%d forwards after a check following the revocation", len(forwards))
	}
}
