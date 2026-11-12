//go:build !sidecar_http && !js

// §22.8's clocks ±10 min on a ticket (TEST-M2-16; §9.6's listener admission, step 4): a listener whose clock runs 10 min
// fast or slow of the sockets service's learns the service's offset from its registration answer, and admits a ticket
// the service signed on its own clock for that ticket's 30 s, by the service's time, and refuses it after. Without the
// offset a fast listener refuses every fresh ticket and a slow one takes each for 10 min past its expiry, inside a
// replay set that keeps it only until then. sidecartest's pairing row (clock_skew.go) cannot reach the registrar, which
// this package holds, so the listener's offsets are written out here, -10 min, 0 and +10 min, with the service on the
// shared clock as §19.6 holds it. A token's expiry and a push's time bound run in sidecartest.

package sidecar

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

func TestSocketListenSkewedListenerAdmitsByTheServiceClock(t *testing.T) {
	for _, skew := range []time.Duration{0, -10 * time.Minute, 10 * time.Minute} {
		fixture := newTestListenFixture(t)
		// the service's clock moves with the listener's, skew behind it
		serviceNow := func() time.Time {
			return fixture.clock.Now().Add(-skew)
		}
		func() {
			fixture.service.stateLock.Lock()
			defer fixture.service.stateLock.Unlock()
			fixture.service.serverTime = serviceNow
		}()
		listener := fixture.listen(t, "db/primary", nil)
		testSocketAwait(t, fixture.service.pages, "the first page")

		// tickets the service signs now, on its own clock, each good for 30 s of it
		issuedMillis := uint64(serviceNow().UnixMilli())
		onServiceClock := func(ticket *protocol.SocketTicket) {
			ticket.IssueTimeMillis = issuedMillis
			ticket.ExpireTimeMillis = issuedMillis + 30_000
		}
		fresh := fixture.ticket(t, listener, onServiceClock)
		late := fixture.ticket(t, listener, onServiceClock)
		expired := fixture.ticket(t, listener, onServiceClock)

		if dialerEnd, err := fixture.open(listener, fixture.request(fresh)); err != nil {
			t.Errorf("skew %s: a fresh ticket refused %s: %v", skew, testRejectCode(err), err)
		} else {
			dialerEnd.Close()
		}
		fixture.clock.advance(29 * time.Second)
		if dialerEnd, err := fixture.open(listener, fixture.request(late)); err != nil {
			t.Errorf("skew %s: a ticket 1 s inside its window refused %s: %v", skew, testRejectCode(err), err)
		} else {
			dialerEnd.Close()
		}
		fixture.clock.advance(2 * time.Second)
		if _, err := fixture.open(listener, fixture.request(expired)); testRejectCode(err) != protocol.StreamRejectCode_SR_INVALID {
			t.Errorf("skew %s: a ticket 1 s past its window ended %v, not invalid", skew, err)
		}
		listener.Close()
	}
}
