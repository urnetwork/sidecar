//go:build !sidecar_http && !js

// §6.8's client on the connect legs: the resident's PushReset and PushHint frames from ControlId over a
// platform carrier reach the machine through the dispatcher, Subscribe reaches the subscribers through
// the Subprotocol, a frame that does not decode asks for a resync, and the same frames from a peer are
// dropped at the source guard.

package sidecar

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// A push frame from ControlId, as the resident sends it.
func testPushFrame(t testing.TB, messageType protocol.MessageType, message proto.Message) *protocol.Envelope {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	envelope := testRequest(messageType, body)
	envelope.Flags = EnvelopeFlagNoReply
	return envelope
}

func TestPushClientTakesTheResidentsFrames(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	if _, err := fixture.subprotocol.Subscribe(PushTopicTeam, func(notice PushNotice) {}); !errors.Is(err, ErrSidecarPushUnattached) {
		t.Fatalf("Subscribe with no client: %v", err)
	}
	fetches := make(chan struct{}, 16)
	client, err := newPushClient(t.Context(), &PushClientEnv{
		Subprotocol: fixture.subprotocol,
		Store:       newTestPushStore(),
		Clock:       newTestEnvelopeClock(),
		Log:         NewNoopLogger(),
	}, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		fetches <- struct{}{}
		return &protocol.PollResponse{Reset_: &protocol.PushReset{Epoch: 1, Complete: true}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	testAwait(t, fetches, "the first resync")
	notices := make(chan PushNotice, 16)
	remove, err := fixture.subprotocol.Subscribe(PushTopicTeam, func(notice PushNotice) {
		notices <- notice
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	platform := connect.Peer{TransportType: connect.TransportTypeH1}
	fixture.receive(connect.ControlId, testPushFrame(t, protocol.MessageType_PUSH_RESET, &protocol.PushReset{
		Epoch: 9, Complete: true, Versions: []*protocol.TopicVersion{{Topic: PushTopicTeam, Version: 3}},
	}), platform)
	if notice := testAwait(t, notices, "the reset's notice"); notice.Version != 3 || !notice.Resync {
		t.Errorf("notice %+v", notice)
	}
	fixture.receive(connect.ControlId, testPushFrame(t, protocol.MessageType_PUSH_HINT, &protocol.PushHint{
		Seq: 1, Topic: PushTopicTeam, Version: 4, Kind: 0x1201, Hint: []byte{2},
	}), platform)
	if notice := testAwait(t, notices, "the hint's notice"); notice.Version != 4 || notice.Resync || notice.Kind != 0x1201 {
		t.Errorf("notice %+v", notice)
	}
	if client.Version(PushTopicTeam) != 4 || !client.Consistent() {
		t.Errorf("team %d", client.Version(PushTopicTeam))
	}

	// a hint frame from a peer is dropped at the guard, verified or not
	peerId := connect.NewId()
	fixture.verify(peerId, "a")
	fixture.receive(peerId, testPushFrame(t, protocol.MessageType_PUSH_HINT, &protocol.PushHint{
		Seq: 2, Topic: PushTopicTeam, Version: 99,
	}), testNetworkPeer("a"))
	// and a frame that does not decode asks for a resync
	broken := testRequest(protocol.MessageType_PUSH_HINT, []byte{0xff})
	broken.Flags = EnvelopeFlagNoReply
	fixture.receive(connect.ControlId, broken, platform)
	testAwait(t, fetches, "the resync a broken frame asks for")
	if client.Version(PushTopicTeam) != 4 {
		t.Errorf("a peer's push applied: team %d", client.Version(PushTopicTeam))
	}
	if _, err := newPushClient(t.Context(), &PushClientEnv{Subprotocol: fixture.subprotocol, Store: newTestPushStore(), Clock: newTestEnvelopeClock()}, func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error) {
		return nil, ctx.Err()
	}); err == nil {
		t.Errorf("a second push client on one Subprotocol")
	}
}

// A running Sidecar's generation carries a PushClient: a core hint from its resident reaches the core,
// which counts it as the bare resync it is at M1.
func TestCoreHintReachesTheSidecarThroughThePush(t *testing.T) {
	instance, enrollment := newTestEnrolledInstance(t)
	platform := newTestSidecarPlatform()
	sidecar := newTestRunningSidecar(t, instance, &enrollment.networkId, testSidecarSettings(platform))
	platform.connected.Set(true)
	awaitSidecarStatus(t, sidecar, atStatus(SidecarStateOnline, 1))
	generation := sidecar.runningGeneration()
	if generation == nil {
		t.Fatal("no generation")
	}
	connectGeneration := generation.leg.(*sidecarConnectGeneration)
	notices := make(chan PushNotice, 8)
	remove, err := connectGeneration.subprotocol.Subscribe(PushTopicCore, func(notice PushNotice) {
		notices <- notice
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	platformPeer := connect.Peer{TransportType: connect.TransportTypeH1}
	for seq := uint64(1); seq <= 2; seq += 1 {
		connectGeneration.subprotocol.receive(connect.SourceId(connect.ControlId), testPushFrame(t, protocol.MessageType_PUSH_HINT, &protocol.PushHint{
			Seq: seq, Topic: PushTopicCore, Version: 10 + seq, Kind: uint32(protocol.MessageType_CORE_HINT), Hint: []byte{0x08, 0x02},
		}), platformPeer)
		for {
			if notice := testAwait(t, notices, "core's notice"); notice.Version == 10+seq {
				break
			}
		}
	}
	// the second notice came after every subscriber of the first had run, on the one push goroutine
	if count := sidecar.Stats().CoreHintCount; count < 1 {
		t.Errorf("core hints %d", count)
	}
}
