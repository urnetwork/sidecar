//go:build !sidecar_http && !js

// Overload at the boundary connect calls (connect/CODESTYLE.md, overload tests): one peer's consumer is
// held, its queue fills, the next envelope is refused at once with RESOURCE_EXHAUSTED and the inline
// handler never waits, while a sibling peer's work goes through untouched. Once the consumer is let go
// the held peer's queue drains in order, and every pool buffer comes back once, which closeBalanced
// reconciles.

package sidecar

import (
	"context"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

func TestFullPeerQueueRefusesAtOnceAndASiblingProgresses(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	queueCount := fixture.settings.PeerQueueMessageCount
	heldId, siblingId := connect.NewId(), connect.NewId()
	heldPeer, siblingPeer := testNetworkPeer("held"), testNetworkPeer("sibling")
	fixture.verify(heldId, "held")
	fixture.verify(siblingId, "sibling")

	entered := make(chan uint64, 1)
	release := make(chan struct{})
	dispatched := make(chan uint64, 2*queueCount)
	remove, err := fixture.subprotocol.setMessageTypeDispatch(testHeldMessageType, func(ctx context.Context, message *subprotocolMessage) {
		select {
		case entered <- message.envelope.RequestId:
		default:
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		dispatched <- message.envelope.RequestId
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	siblings := fixture.collect(t, testFreeMessageType)

	// the first is the worker's, held in its function
	first := testRequest(testHeldMessageType, testEnvelopeBody(64))
	fixture.receive(heldId, first, heldPeer)
	if requestId := testAwait(t, entered, "held dispatch"); requestId != first.RequestId {
		t.Fatalf("held %d, want %d", requestId, first.RequestId)
	}
	wantOrder := []uint64{first.RequestId}
	for i := range queueCount {
		request := testRequest(testHeldMessageType, testEnvelopeBody(64+i))
		fixture.receive(heldId, request, heldPeer)
		wantOrder = append(wantOrder, request.RequestId)
	}
	stats := &fixture.subprotocol.stats
	if held := stats.heldBufferCount.Load(); held != int64(queueCount)+1 {
		t.Errorf("%d buffers held, want %d", held, queueCount+1)
	}

	// the next is refused without waiting on the held worker
	overflow := testRequest(testHeldMessageType, testEnvelopeBody(32))
	returned := make(chan struct{})
	go func() {
		fixture.receive(heldId, overflow, heldPeer)
		close(returned)
	}()
	testAwait(t, returned, "return from the inline handler")
	if count := stats.queueFullCount.Load(); count != 1 {
		t.Errorf("queue full %d", count)
	}
	refusal := fixture.nextSent(t)
	if code := refusal.errorCode(t); code != protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED || refusal.envelope.RequestId != overflow.RequestId || refusal.destinationId != heldId {
		t.Errorf("refusal: code %v id %d to %s", code, refusal.envelope.RequestId, refusal.destinationId)
	}
	if held := stats.heldBufferCount.Load(); held != int64(queueCount)+1 {
		t.Errorf("the refusal kept a buffer: %d held", held)
	}

	// a sibling's request goes through while the held peer's worker waits
	sibling := testRequest(testFreeMessageType, testEnvelopeBody(16))
	fixture.receive(siblingId, sibling, siblingPeer)
	if message := testAwait(t, siblings, "sibling dispatch"); message.envelope.RequestId != sibling.RequestId || message.sourceId != siblingId {
		t.Errorf("sibling %d from %s", message.envelope.RequestId, message.sourceId)
	}
	if len(dispatched) != 0 {
		t.Fatal("the held worker ran while held")
	}

	// let go, the held peer's queue drains in order
	close(release)
	for i, want := range wantOrder {
		if got := testAwait(t, dispatched, "drained dispatch"); got != want {
			t.Fatalf("dispatch %d: %d, want %d", i, got, want)
		}
	}
	fixture.closeBalanced(t)
	if len(dispatched) != 0 || len(fixture.sent) != 0 {
		t.Errorf("%d more dispatched, %d more sent", len(dispatched), len(fixture.sent))
	}
}

// The inline refusal path allocates nothing: a refusal is a value offered to a channel.
func TestInlineRefusalAllocatesNothing(t *testing.T) {
	fixture := newTestSubprotocol(t, func(env *SubprotocolEnv) {
		env.Settings.PeerQueueMessageCount = 1
	})
	sourceId := connect.NewId()
	peer := testNetworkPeer("a")
	request := testRequest(protocol.MessageType_PING, nil)
	gate := make(chan struct{})
	func() {
		fixture.stateLock.Lock()
		defer fixture.stateLock.Unlock()
		fixture.sendGate = gate
	}()
	defer close(gate)
	// the sender holds one and the queue one, so every later refusal is dropped before a send
	fixture.receive(sourceId, request, peer)
	fixture.nextSent(t)
	fixture.receive(sourceId, request, peer)
	// AllocsPerRun counts the whole process, and the worker still finishing the second request, or a
	// goroutine an earlier test left, can allocate while the refusals run. A refusal that allocates
	// does so every time, so the least of three measures is the refusal path's own count.
	measure := func() float64 {
		return testing.AllocsPerRun(100, func() {
			fixture.receive(sourceId, request, peer)
		})
	}
	allocs := min(measure(), measure(), measure())
	if 0 < allocs {
		t.Errorf("%.1f allocations per refusal", allocs)
	}
}

// A source whose queue is never quite empty keeps reusing one slice: steady load, one envelope in and
// one out with others always waiting, holds the slice to a full queue's worth however long it runs.
func TestPeerQueueStaysBoundedUnderSteadyLoad(t *testing.T) {
	peer := &subprotocolPeer{sourceId: connect.NewId()}
	waitingCount := 3
	next := uint64(0)
	push := func() {
		next += 1
		peer.pushWithLock(subprotocolInbound{requestId: next})
	}
	for range waitingCount {
		push()
	}
	want := uint64(1)
	for range 10000 {
		push()
		if item := peer.popWithLock(); item.requestId != want {
			t.Fatalf("popped %d, want %d", item.requestId, want)
		}
		want += 1
		if 2*(waitingCount+1) < cap(peer.queuedItems) {
			t.Fatalf("slice grew to %d for %d waiting", cap(peer.queuedItems), peer.queuedCountWithLock())
		}
	}
	if count := peer.queuedCountWithLock(); count != waitingCount {
		t.Errorf("%d waiting, want %d", count, waitingCount)
	}
}
