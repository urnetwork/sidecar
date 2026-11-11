package sidecartest

// FS-126 on T2 (PROTO-M6-02; D-PROTO-10, D-PROTO-8, QD-045, QD-210): SidecarProtocolSettings.EnablePeerP2p is off by
// default; with it on, a same-network pair moves from relay to P2P and back under a live RPC and a live stream, the
// peer's Hello and its binding to the session key holding across each move, since a route is not an identity; and
// a ControlId push forged over P2P stays dropped with the setting on, push coming only over platform carriers. The
// Net's links stand in for the carrier: SetLink's TransportType is what each frame reaches its receiver on. Bytes on
// P2P debiting nothing is §20.6's, on T3 (server/connect/sidecar_p2p_t3_test.go).

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Sidecar settings with EnablePeerP2p on.
func testP2pSettings() *sidecar.SidecarSettings {
	settings := sidecar.DefaultSidecarSettings()
	settings.ProtocolSettings.EnablePeerP2p = true
	return settings
}

// Relay-only is the default, here and in the release's settings.
func TestP2pOffByDefault(t *testing.T) {
	if sidecar.DefaultSidecarProtocolSettings().EnablePeerP2p || sidecar.DefaultSidecarSettings().ProtocolSettings.EnablePeerP2p {
		t.Fatal("P2P is on by default")
	}
}

// With P2P on, a pair's RPC and stream run on relay, on P2P and on relay again, and each side's view of the other's
// Hello, its binding, generation and identity key, is the same before and after each move.
func TestP2pPairMovesAndBackUnderALiveRpcAndStream(t *testing.T) {
	net := newTestNet(t)
	sidecars, _, err := net.AddSubprotocolSidecarsWith(testP2pSettings, "laptop", "desktop")
	if err != nil {
		t.Fatal(err)
	}
	a, b := sidecars[0], sidecars[1]
	if _, err := b.Subprotocol().Handle(testSubprotocolCallType, func(ctx context.Context, request *sidecar.SubprotocolRequest) ([]byte, error) {
		return bytes.Clone(request.Body), nil
	}, nil); err != nil {
		t.Fatal(err)
	}
	streams := make(chan *sidecar.SubprotocolStream, 1)
	if _, err := b.Subprotocol().Listen("p2p-test", func(ctx context.Context, incoming *sidecar.StreamIncoming) error {
		streams <- incoming.Stream
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	call := func(body string) {
		t.Helper()
		answer, err := a.Subprotocol().Call(t.Context(), sidecar.Id(b.ClientId()), testSubprotocolCallType, []byte(body), nil)
		if err != nil || string(answer) != body {
			t.Fatalf("the call %q: %q, %v", body, answer, err)
		}
	}
	call("on relay")
	peerOfB, ok := a.Subprotocol().PeerIdentity(sidecar.Id(b.ClientId()))
	if !ok {
		t.Fatal("no Hello")
	}
	peerOfA, ok := b.Subprotocol().PeerIdentity(sidecar.Id(a.ClientId()))
	if !ok {
		t.Fatal("no Hello at the other side")
	}
	stream, err := a.Subprotocol().OpenStream(t.Context(), sidecar.Id(b.ClientId()), &sidecar.StreamOpenRequest{Target: "p2p-test"})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	accepted := testAwaitValue(t, streams, "the accepted stream")
	defer accepted.Close()
	relay := func(data string) {
		t.Helper()
		if _, err := stream.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
		read := make([]byte, len(data))
		if _, err := io.ReadFull(accepted, read); err != nil || string(read) != data {
			t.Fatalf("the stream carried %q, %v", read, err)
		}
	}
	relay("before the move")
	holds := func(when string) {
		t.Helper()
		for _, c := range []struct {
			side *SubprotocolSidecar
			peer *SubprotocolSidecar
			was  *sidecar.SubprotocolPeerIdentity
		}{{side: a, peer: b, was: peerOfB}, {side: b, peer: a, was: peerOfA}} {
			peer, ok := c.side.Subprotocol().PeerIdentity(sidecar.Id(c.peer.ClientId()))
			if !ok || peer.SidecarId != c.was.SidecarId || peer.Generation != c.was.Generation ||
				!bytes.Equal(peer.Binding, c.was.Binding) || !bytes.Equal(peer.IdentityPublicKey, c.was.IdentityPublicKey) {
				t.Errorf("%s: %s's view of %s changed: %+v", when, c.side.Name, c.peer.Name, peer)
			}
		}
	}

	// to P2P, both ways
	net.SetLink(a.ClientId(), b.ClientId(), &LinkConditions{TransportType: connect.TransportTypeP2p})
	net.SetLink(b.ClientId(), a.ClientId(), &LinkConditions{TransportType: connect.TransportTypeP2p})
	call("on P2P")
	relay("across the move")
	holds("on P2P")

	// and back
	net.SetLink(a.ClientId(), b.ClientId(), nil)
	net.SetLink(b.ClientId(), a.ClientId(), nil)
	call("on relay again")
	relay("back on relay")
	holds("back on relay")
}

// D-PROTO-8 stays the control with P2P on: a ControlId push over a P2P link, what a P2P peer forging ControlId
// delivers, is dropped before the sidecar's push sees it.
func TestP2pForgedControlIdStaysDroppedWithP2pOn(t *testing.T) {
	net := newTestNet(t)
	sidecars, _, err := net.AddSubprotocolSidecarsWith(testP2pSettings, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	laptop := sidecars[0]
	notices := make(chan sidecar.PushNotice, 16)
	if _, err := laptop.Subprotocol().Subscribe(sidecar.PushTopicTeam, func(notice sidecar.PushNotice) {
		select {
		case notices <- notice:
		default:
		}
	}); err != nil {
		t.Fatal(err)
	}
	resident, err := net.AddResident(laptop.ClientId())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), testPushTimeout)
	defer cancel()
	client := laptop.Client().Client
	net.SetLink(connect.ControlId, laptop.ClientId(), &LinkConditions{TransportType: connect.TransportTypeP2p})
	droppedBefore := client.SubprotocolStats().DroppedControlSource
	if err := resident.SendPushAcked(ctx, protocol.MessageType_PUSH_HINT, &protocol.PushHint{Seq: 1, Topic: sidecar.PushTopicTeam, Version: 7}); err != nil {
		t.Fatal(err)
	}
	if dropped := client.SubprotocolStats().DroppedControlSource; dropped != droppedBefore+1 {
		t.Errorf("connect dropped %d ControlId frames over P2P, want 1", dropped-droppedBefore)
	}
	expectNoTopicNotice(t, notices, sidecar.PushTopicTeam)
}

// The next value on values, failing t when none comes in testPushTimeout.
func testAwaitValue[T any](t *testing.T, values <-chan T, what string) T {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), testPushTimeout)
	defer cancel()
	select {
	case value := <-values:
		return value
	case <-ctx.Done():
		t.Fatalf("no %s", what)
	}
	var zero T
	return zero
}
