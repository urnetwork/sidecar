//go:build !sidecar_http && !js

// §6.6's idempotency for mutating handlers: a retry runs nothing twice and gets the kept bytes; a
// response past 16 KiB is not kept, and its retry gets ALREADY_EXISTS with the handler's result_ref; a
// retry while the first run is live joins it; expiry and the byte caps evict, after which a retry runs
// again; and a handler that is not mutating runs for each retry.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// A retry of a mutating call runs the handler once and returns the kept bytes; a non-mutating
// handler's retry runs it again.
func TestMutatingRetryRunsOnce(t *testing.T) {
	for _, mutating := range []bool{true, false} {
		pair := newTestRpcPair(t)
		a := pair.add(nil, nil)
		b := pair.add(nil, nil)
		var runCount atomic.Int64
		remove, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
			return []byte{byte(runCount.Add(1))}, nil
		}, &HandleOptions{Mutating: mutating})
		if err != nil {
			t.Fatal(err)
		}
		requestId := newRequestId()
		first, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, nil, &CallOptions{RequestId: requestId})
		if err != nil {
			t.Fatal(err)
		}
		second, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, nil, &CallOptions{RequestId: requestId})
		if err != nil {
			t.Fatal(err)
		}
		if mutating && (runCount.Load() != 1 || !bytes.Equal(first, second)) {
			t.Errorf("mutating: %d runs, %v then %v", runCount.Load(), first, second)
		}
		if !mutating && runCount.Load() != 2 {
			t.Errorf("not mutating: %d runs", runCount.Load())
		}
		remove()
	}
}

// A response past IdempotencyMaxResponseByteCount reaches its first caller whole and is not kept: a
// retry gets ALREADY_EXISTS with the result_ref the handler set, and the handler ran once.
func TestLargeResponseRetryGetsAlreadyExists(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	var runCount atomic.Int64
	large := bytes.Repeat([]byte{0x5a}, 16*1024+1)
	remove, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		runCount.Add(1)
		request.ResultRef = []byte("synthetic-ref")
		return large, nil
	}, &HandleOptions{Mutating: true})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	requestId := newRequestId()
	first, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, nil, &CallOptions{RequestId: requestId})
	if err != nil || !bytes.Equal(first, large) {
		t.Fatalf("%d B, %v", len(first), err)
	}
	_, err = a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, nil, &CallOptions{RequestId: requestId})
	var exists *SubprotocolError
	if !errors.As(err, &exists) || exists.Code != protocol.ErrorCode_ERR_ALREADY_EXISTS || string(exists.ResultRef) != "synthetic-ref" {
		t.Fatalf("err %v", err)
	}
	if runCount.Load() != 1 {
		t.Errorf("%d runs", runCount.Load())
	}
	// what the cache holds for it is the entry, not the response
	if held := b.subprotocol.idempotency.peerByteCount(a.clientId); held <= 0 || 1024 < held {
		t.Errorf("held %d B", held)
	}
}

// A retry that arrives while the first run is live joins it: one run, and both requests answered.
func TestConcurrentRetryJoinsTheLiveRun(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	release := make(chan struct{})
	started := make(chan struct{}, 2)
	var runCount atomic.Int64
	remove, err := b.subprotocol.Handle(testCallBlockType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		runCount.Add(1)
		started <- struct{}{}
		<-release
		return []byte("once"), nil
	}, &HandleOptions{Mutating: true})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	requestId := newRequestId()
	results := testStartCall(a, context.Background(), b, testCallBlockType, nil, &CallOptions{RequestId: requestId})
	testAwait(t, started, "handler")
	// the retry, as a's dispatcher sent the first: the same envelope again, then a marker behind it on
	// the same worker, whose run means the retry was dispatched
	markers := make(chan struct{}, 1)
	removeMarker, err := b.subprotocol.Handle(testMarkerMessageType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		markers <- struct{}{}
		return nil, nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer removeMarker()
	retry := testSentOfType(a, testCallBlockType)[0]
	b.subprotocol.receive(connect.SourceId(a.clientId), retry, a.peer())
	b.subprotocol.receive(connect.SourceId(a.clientId), testRequest(testMarkerMessageType, nil), a.peer())
	testAwait(t, markers, "marker")
	if count := b.subprotocol.stats.idempotentJoinCount.Load(); count != 1 {
		t.Fatalf("%d joins", count)
	}
	select {
	case <-started:
		t.Fatal("a second run started")
	default:
	}
	close(release)
	result := testAwait(t, results, "call")
	if result.err != nil || string(result.body) != "once" {
		t.Fatalf("%q, %v", result.body, result.err)
	}
	b.subprotocol.Close()
	if runCount.Load() != 1 {
		t.Errorf("%d runs", runCount.Load())
	}
	if responses := testSentOfType(b, testCallBlockType+1); len(responses) != 2 {
		t.Errorf("%d answers", len(responses))
	}
}

// A kept answer expires IdempotencyTimeout after its run, and a retry after that runs again.
func TestIdempotencyExpires(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	clock := newTestEnvelopeClock()
	cache := newIdempotencyCache(settings, NewSubprotocolBudget(settings, 128*1024*1024), clock)
	key := rpcCallKey{sourceId: connect.NewId(), requestId: 1}
	begin, entry := cache.begin(key)
	if begin != idempotencyRun {
		t.Fatalf("begin %d", begin)
	}
	cache.finish(entry, cache.outcomeOf([]byte("kept"), nil, nil))
	clock.Advance(settings.IdempotencyTimeout - time.Nanosecond)
	if begin, entry := cache.begin(key); begin != idempotencyAnswered || string(entry.outcome.body) != "kept" {
		t.Fatalf("before expiry: %d", begin)
	}
	clock.Advance(time.Nanosecond)
	if begin, _ := cache.begin(key); begin != idempotencyRun {
		t.Errorf("after expiry: %d", begin)
	}
	if held := cache.peerByteCount(key.sourceId); held != 0 {
		t.Errorf("expired, and %d B held", held)
	}
}

// The per-peer cap evicts that peer's oldest answers first and leaves another peer's alone; the
// process cap refuses to keep what would pass it.
func TestIdempotencyCapsEvict(t *testing.T) {
	settings := DefaultSidecarProtocolSettings()
	settings.IdempotencyPeerByteCount = 3 * (idempotencyEntryOverheadByteCount + 100)
	clock := newTestEnvelopeClock()
	budget := NewSubprotocolBudget(settings, 128*1024*1024)
	cache := newIdempotencyCache(settings, budget, clock)
	peerId := connect.NewId()
	otherId := connect.NewId()
	keep := func(sourceId connect.Id, requestId uint64) {
		begin, entry := cache.begin(rpcCallKey{sourceId: sourceId, requestId: requestId})
		if begin != idempotencyRun {
			t.Fatalf("%d: begin %d", requestId, begin)
		}
		cache.finish(entry, cache.outcomeOf(make([]byte, 100), nil, nil))
	}
	keep(otherId, 1)
	for requestId := uint64(1); requestId <= 4; requestId += 1 {
		keep(peerId, requestId)
	}
	if begin, _ := cache.begin(rpcCallKey{sourceId: peerId, requestId: 1}); begin != idempotencyRun {
		t.Errorf("the oldest was kept past the peer's cap")
	}
	for requestId := uint64(2); requestId <= 4; requestId += 1 {
		if begin, _ := cache.begin(rpcCallKey{sourceId: peerId, requestId: requestId}); begin != idempotencyAnswered {
			t.Errorf("%d: evicted", requestId)
		}
	}
	if begin, _ := cache.begin(rpcCallKey{sourceId: otherId, requestId: 1}); begin != idempotencyAnswered {
		t.Errorf("another peer's answer was evicted")
	}

	// a process budget with no room keeps nothing
	tight := DefaultSidecarProtocolSettings()
	tight.IdempotencyProcessByteCount = idempotencyEntryOverheadByteCount
	tightCache := newIdempotencyCache(tight, NewSubprotocolBudget(tight, 128*1024*1024), clock)
	key := rpcCallKey{sourceId: peerId, requestId: 9}
	_, entry := tightCache.begin(key)
	tightCache.finish(entry, tightCache.outcomeOf(make([]byte, 100), nil, nil))
	if begin, _ := tightCache.begin(key); begin != idempotencyRun {
		t.Errorf("kept past the process cap")
	}
	cache.close()
	if usage := budget.currentUsage(); usage.idempotencyByteCount != 0 {
		t.Errorf("%d B still reserved after close", usage.idempotencyByteCount)
	}
}
