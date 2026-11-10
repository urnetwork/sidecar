//go:build !sidecar_http && !js

// §22.5's PEER_TIMEOUT row on a fake clock (PROTO-M5-02): a peer silent past PingTimeout gets a Ping, and
// past PeerSilenceTimeout every stream with it resets PEER_TIMEOUT, while a peer whose Pong comes back
// keeps its streams; a peer the state revokes while streams run has them reset REVOKED. Each step moves
// the clock to the time the keepalive has armed its wait for, so nothing rests on a sleep.

package sidecar

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Waits until side's stream keepalive has armed its wait for at, failing past 10 s of real time.
func testAwaitStreamKeepaliveArmed(t *testing.T, side *testRpcSide, at time.Time) {
	t.Helper()
	guard := time.After(10 * time.Second)
	for {
		armed, changed := side.subprotocol.streamKeepaliveArmed.Get()
		if armed.Equal(at) {
			return
		}
		select {
		case <-changed:
		case <-guard:
			t.Fatalf("the stream keepalive armed %v, never %v", armed, at)
		}
	}
}

// Delivers nothing from one side to the other, as a partitioned relay would.
func testPartition(pair *testRpcPair, from *testRpcSide) {
	pair.stateLock.Lock()
	defer pair.stateLock.Unlock()
	pair.deliver = func(sender *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		if sender == from {
			return nil
		}
		return envelope
	}
}

// A silent peer: a Ping at PingTimeout, then every stream with it reset PEER_TIMEOUT at
// PeerSilenceTimeout, before connect's 60 s exit, with nothing on the clock moved but by the test.
func TestStreamPeerTimeoutResets(t *testing.T) {
	pair, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	first, firstAccepted := testStreamOpen(t, b, a, incomings, nil)
	_, secondAccepted := testStreamOpen(t, b, a, incomings, nil)
	defer first.Close()
	start := a.clock.Now()
	testAwaitStreamKeepaliveArmed(t, a, start.Add(a.settings.PingTimeout))
	testPartition(pair, b)
	pings := len(testSentTypes(a))

	a.clock.Advance(a.settings.PingTimeout)
	sent := testAwaitSent(t, a, func(sent []*protocol.Envelope) bool {
		return testFirstSent(sent[pings:], protocol.MessageType_PING) != nil
	})
	if ping := testFirstSent(sent[pings:], protocol.MessageType_PING); 0 < len(ping.Body) || ping.Flags != 0 {
		t.Errorf("ping %+v", ping)
	}
	testAwaitStreamKeepaliveArmed(t, a, start.Add(a.settings.PeerSilenceTimeout))
	for _, stream := range []*SubprotocolStream{firstAccepted, secondAccepted} {
		if _, err := stream.Write([]byte("still open")); err != nil {
			t.Fatalf("reset before the silence bound: %v", err)
		}
	}

	a.clock.Advance(a.settings.PeerSilenceTimeout - a.settings.PingTimeout)
	var resetErr *StreamResetError
	for _, stream := range []*SubprotocolStream{firstAccepted, secondAccepted} {
		if _, err := stream.Read(make([]byte, 8)); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_PEER_TIMEOUT || !resetErr.Local {
			t.Errorf("a silent peer's stream reads %v", err)
		}
	}
	if stats := a.subprotocol.StreamStats(); stats.PeerTimeoutResetCount != 2 || stats.PingCount != 1 {
		t.Errorf("stats %+v", stats)
	}
	if 60*time.Second <= a.settings.PeerSilenceTimeout {
		t.Errorf("the silence bound %v is not before connect's 60 s exit", a.settings.PeerSilenceTimeout)
	}
	testStreamsSettled(t, a)
}

// Its twin: a peer that answers each Ping keeps its streams past PeerSilenceTimeout and beyond, a Ping
// going PingTimeout after each Pong.
func TestStreamKeepalivePongKeepsThePeer(t *testing.T) {
	_, a, b := newTestStreamSides(t, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted := testStreamOpen(t, b, a, incomings, nil)
	testAwaitStreamKeepaliveArmed(t, a, a.clock.Now().Add(a.settings.PingTimeout))
	for range 4 {
		before := len(testSentTypes(a))
		a.clock.Advance(a.settings.PingTimeout)
		testAwaitSent(t, a, func(sent []*protocol.Envelope) bool {
			return testFirstSent(sent[before:], protocol.MessageType_PING) != nil
		})
		// the Pong moves the next Ping to PingTimeout from now
		testAwaitStreamKeepaliveArmed(t, a, a.clock.Now().Add(a.settings.PingTimeout))
	}
	if _, err := accepted.Write([]byte("alive")); err != nil {
		t.Fatalf("a live peer's stream: %v", err)
	}
	if got := testStreamReadFull(t, opened, 5); string(got) != "alive" {
		t.Errorf("read %q", got)
	}
	if stats := a.subprotocol.StreamStats(); stats.PeerTimeoutResetCount != 0 || stats.PingCount != 4 {
		t.Errorf("stats %+v", stats)
	}
	opened.Close()
	accepted.Close()
}

// A peer the state revokes while its streams run has them reset REVOKED at the keepalive's next wake, at
// most PingTimeout on, and one that stays admitted while the state moves keeps them.
func TestStreamRevokedPeerResets(t *testing.T) {
	pair, authority, aIdentity, bIdentity := newTestAdmissionPair(t)
	a := pair.add(aIdentity, nil)
	b := pair.add(bIdentity, nil)
	incomings := testStreamAccepting(t, a, testStreamTarget)
	opened, accepted := testStreamOpen(t, b, a, incomings, nil)
	start := a.clock.Now()
	testAwaitStreamKeepaliveArmed(t, a, start.Add(a.settings.PingTimeout))
	// the state moves without touching b: its streams stand
	authority.admit(NewId(), make([]byte, 32), nil)
	a.clock.Advance(a.settings.PingTimeout)
	testAwaitStreamKeepaliveArmed(t, a, start.Add(2*a.settings.PingTimeout))
	if _, err := accepted.Write([]byte("standing")); err != nil {
		t.Fatalf("a standing peer's stream: %v", err)
	}
	if got := testStreamReadFull(t, opened, 8); string(got) != "standing" {
		t.Errorf("read %q", got)
	}
	revokedAt := authority.Pin().GetVersion() + 1
	authority.edit(bIdentity.sidecarId, func(row *bridge.SidecarRow) {
		row.RevokedAt = revokedAt
	})
	a.clock.Advance(a.settings.PingTimeout)
	var resetErr *StreamResetError
	if _, err := accepted.Read(make([]byte, 8)); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_REVOKED {
		t.Errorf("a revoked peer's stream reads %v", err)
	}
	if _, err := opened.Read(make([]byte, 8)); !errors.As(err, &resetErr) || resetErr.Code != protocol.StreamResetCode_RST_REVOKED || resetErr.Local {
		t.Errorf("the revoked peer read %v", err)
	}
}
