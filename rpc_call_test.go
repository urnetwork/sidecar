//go:build !sidecar_http && !js

// §6.6's peer RPC between two dispatchers: round trips plain and chunked, the timeout's default, cap and
// refusal, an immediate send refusal sent again under its request_id, a lost response returned with its
// id and not retried, the response shapes that fail without retry, Cancel reaching a running handler,
// handlers' refusals, a peer's bound on runs, and a gate that closed under a call. Every wait is on the
// sides' fake clocks.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// Types from the unreleased experimental services (§6.11), whose results are each + 1.
const (
	testCallType      = protocol.MessageType(0x8011)
	testCallBlockType = protocol.MessageType(0x8013)
)

// Registers an echo on side for testCallType: the body back with "!" after it.
func testEchoHandler(t testing.TB, side *testRpcSide, options *HandleOptions) *atomic.Int64 {
	t.Helper()
	runCount := &atomic.Int64{}
	remove, err := side.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		runCount.Add(1)
		return append(bytes.Clone(request.Body), '!'), nil
	}, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(remove)
	return runCount
}

// The requests of messageType a side sent, in order.
func testSentOfType(side *testRpcSide, messageType protocol.MessageType) []*protocol.Envelope {
	envelopes := []*protocol.Envelope{}
	for _, envelope := range side.sent() {
		if envelope.Type == uint32(messageType) {
			envelopes = append(envelopes, envelope)
		}
	}
	return envelopes
}

type testCallResult struct {
	body []byte
	err  error
}

// Starts a call on its own goroutine.
func testStartCall(side *testRpcSide, ctx context.Context, to *testRpcSide, messageType protocol.MessageType, body []byte, options *CallOptions) <-chan testCallResult {
	results := make(chan testCallResult, 1)
	go func() {
		response, err := side.subprotocol.Call(ctx, Id(to.clientId), messageType, body, options)
		results <- testCallResult{body: response, err: err}
	}()
	return results
}

func TestCallRoundTrip(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	testEchoHandler(t, b, nil)
	response, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("ping"), nil)
	if err != nil || string(response) != "ping!" {
		t.Fatalf("%q, %v", response, err)
	}
	// the request carried a random id and the default timeout
	requests := testSentOfType(a, testCallType)
	if len(requests) != 1 || requests[0].RequestId == 0 || requests[0].TimeoutMs != 15000 {
		t.Errorf("requests %v", requests)
	}
	// and the answer was the request's type + 1, echoing its id
	responses := testSentOfType(b, testCallType+1)
	if len(responses) != 1 || responses[0].RequestId != requests[0].RequestId || responses[0].Flags != EnvelopeFlagResponse {
		t.Errorf("responses %v", responses)
	}
}

// Bodies past 4,016 B ride chunks both ways and arrive whole.
func TestCallChunkedRoundTrip(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	remove, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return bytes.Repeat(request.Body, 2), nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	body := make([]byte, 10*1024)
	for i := range body {
		body[i] = byte(i * 7)
	}
	response, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, bytes.Repeat(body, 2)) {
		t.Errorf("a %d B response", len(response))
	}
	if requests := testSentOfType(a, testCallType); len(requests) != 3 || requests[0].Chunk == nil {
		t.Errorf("%d request envelopes", len(requests))
	}
	if responses := testSentOfType(b, testCallType+1); len(responses) != 6 {
		t.Errorf("%d response envelopes", len(responses))
	}
}

// timeout_ms: DefaultCallTimeout when the caller sets none, the caller's up to 55 s, and a larger one
// refused before anything is sent.
func TestCallTimeoutDefaultCapAndRefusal(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	testEchoHandler(t, b, nil)
	for _, c := range []struct {
		timeout   time.Duration
		timeoutMs uint32
	}{
		{timeout: 0, timeoutMs: 15000},
		{timeout: 3 * time.Second, timeoutMs: 3000},
		{timeout: MaxCallTimeout, timeoutMs: 55000},
	} {
		before := len(testSentOfType(a, testCallType))
		if _, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, nil, &CallOptions{Timeout: c.timeout}); err != nil {
			t.Fatal(err)
		}
		requests := testSentOfType(a, testCallType)
		if len(requests) != before+1 || requests[before].TimeoutMs != c.timeoutMs {
			t.Errorf("timeout %v: sent %d", c.timeout, requests[len(requests)-1].TimeoutMs)
		}
	}
	before := len(testSentOfType(a, testCallType))
	_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, nil, &CallOptions{Timeout: MaxCallTimeout + time.Millisecond})
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_INVALID_ARGUMENT {
		t.Errorf("past the cap: %v", err)
	}
	if len(testSentOfType(a, testCallType)) != before {
		t.Errorf("a refused call was sent")
	}
}

// A send connect refuses before the deadline goes again after CallSendRetryInterval with the same
// request_id, and the call succeeds.
func TestCallRetriesAnImmediateRefusalWithTheSameId(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	testEchoHandler(t, b, nil)
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	func() {
		a.stateLock.Lock()
		defer a.stateLock.Unlock()
		a.refuseCount = 2
	}()
	waitCount, _ := a.clock.waitCount.Get()
	results := testStartCall(a, context.Background(), b, testCallType, []byte("x"), nil)
	for refusal := 1; refusal <= 2; refusal += 1 {
		a.clock.awaitWaitCount(waitCount + refusal)
		a.clock.Advance(a.settings.CallSendRetryInterval)
	}
	result := testAwait(t, results, "call")
	if result.err != nil || string(result.body) != "x!" {
		t.Fatalf("%q, %v", result.body, result.err)
	}
	requests := testSentOfType(a, testCallType)
	if len(requests) != 3 || requests[0].RequestId != requests[1].RequestId || requests[1].RequestId != requests[2].RequestId {
		t.Errorf("%d sends", len(requests))
	}
	if count := a.subprotocol.stats.callSendRetryCount.Load(); count != 2 {
		t.Errorf("%d retries", count)
	}
}

// A request that went out and got no answer returns DEADLINE_EXCEEDED at the call's deadline with its
// request_id, having sent it once; the caller's retry under that id gets the mutating handler's kept
// answer, and the handler ran once.
func TestCallLostResponseReturnsItsId(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	runCount := testEchoHandler(t, b, &HandleOptions{Mutating: true})
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	dropping := atomic.Bool{}
	dropping.Store(true)
	dropped := make(chan struct{}, 1)
	b.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
		if from == b && envelope.Type == uint32(testCallType+1) && dropping.Load() {
			select {
			case dropped <- struct{}{}:
			default:
			}
			return nil
		}
		return envelope
	})
	waitCount, _ := a.clock.waitCount.Get()
	results := testStartCall(a, context.Background(), b, testCallType, []byte("x"), &CallOptions{Timeout: 5 * time.Second})
	// the handler ran and answered, the answer was lost, and the caller waits on its deadline
	testAwait(t, dropped, "the lost response")
	a.clock.awaitWaitCount(waitCount + 1)
	a.clock.Advance(5 * time.Second)
	result := testAwait(t, results, "call")
	var lost *SubprotocolError
	if !errors.As(result.err, &lost) || lost.Code != protocol.ErrorCode_ERR_DEADLINE_EXCEEDED || lost.RequestId == 0 {
		t.Fatalf("err %v", result.err)
	}
	if requests := testSentOfType(a, testCallType); len(requests) != 1 || requests[0].RequestId != lost.RequestId {
		t.Errorf("%d sends", len(requests))
	}

	dropping.Store(false)
	response, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("x"), &CallOptions{RequestId: lost.RequestId})
	if err != nil || string(response) != "x!" {
		t.Fatalf("%q, %v", response, err)
	}
	if runCount.Load() != 1 {
		t.Errorf("the handler ran %d times", runCount.Load())
	}
}

// An answer of another type, an Error with a code no sender sets, and an Error carrying OK each fail the
// call without retry.
func TestCallFailsOnAnswersOutsideTheProtocol(t *testing.T) {
	for _, c := range []struct {
		name    string
		rewrite func(envelope *protocol.Envelope)
	}{
		{name: "another type", rewrite: func(envelope *protocol.Envelope) {
			envelope.Type = uint32(testCallType + 3)
		}},
		{name: "an unknown code", rewrite: func(envelope *protocol.Envelope) {
			envelope.Type = uint32(protocol.MessageType_ERROR)
			envelope.Flags = EnvelopeFlagResponse | EnvelopeFlagError
			envelope.Body, _ = proto.Marshal(&protocol.Error{Code: 999})
		}},
		{name: "OK", rewrite: func(envelope *protocol.Envelope) {
			envelope.Type = uint32(protocol.MessageType_ERROR)
			envelope.Flags = EnvelopeFlagResponse | EnvelopeFlagError
			envelope.Body, _ = proto.Marshal(&protocol.Error{Code: 0})
		}},
		{name: "an Error without its flag", rewrite: func(envelope *protocol.Envelope) {
			envelope.Type = uint32(protocol.MessageType_ERROR)
			envelope.Body, _ = proto.Marshal(&protocol.Error{Code: uint32(protocol.ErrorCode_ERR_NOT_FOUND)})
		}},
	} {
		pair := newTestRpcPair(t)
		a := pair.add(nil, nil)
		b := pair.add(nil, nil)
		testEchoHandler(t, b, nil)
		b.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
			if from == b && envelope.Type == uint32(testCallType+1) {
				c.rewrite(envelope)
			}
			return envelope
		})
		_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, nil, nil)
		if !errors.Is(err, ErrSubprotocolResponse) {
			t.Errorf("%s: %v", c.name, err)
		}
		if requests := testSentOfType(a, testCallType); len(requests) != 1 {
			t.Errorf("%s: %d sends", c.name, len(requests))
		}
	}
}

// A caller's cancel sends Cancel, which ends the running handler's ctx, and the call answers CANCELLED;
// the handler's answer is not sent.
func TestCancelReachesARunningHandler(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	started := make(chan struct{})
	causes := make(chan error, 1)
	remove, err := b.subprotocol.Handle(testCallBlockType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		close(started)
		<-ctx.Done()
		causes <- context.Cause(ctx)
		return nil, ctx.Err()
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	ctx, cancel := context.WithCancel(context.Background())
	results := testStartCall(a, ctx, b, testCallBlockType, nil, nil)
	testAwait(t, started, "handler")
	cancel()
	result := testAwait(t, results, "call")
	if code, _ := SubprotocolErrorCode(result.err); code != protocol.ErrorCode_ERR_CANCELLED {
		t.Fatalf("err %v", result.err)
	}
	if cause := testAwait(t, causes, "cause"); !errors.Is(cause, errHandlerCancelled) {
		t.Errorf("cause %v", cause)
	}
	cancels := testSentOfType(a, protocol.MessageType_CANCEL)
	if len(cancels) != 1 || cancels[0].Flags != EnvelopeFlagNoReply || len(cancels[0].Body) != 0 {
		t.Errorf("cancels %v", cancels)
	}
	b.subprotocol.Close()
	if responses := testSentOfType(b, testCallBlockType+1); len(responses) != 0 {
		t.Errorf("a cancelled run answered")
	}
	if count := b.subprotocol.stats.cancelledCount.Load(); count != 1 {
		t.Errorf("cancelled %d", count)
	}
}

// A handler's ctx ends at timeout_ms from the request's arrival, on the receiver's clock, and the run
// answers DEADLINE_EXCEEDED.
func TestHandlerDeadlineFollowsTimeoutMs(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	started := make(chan struct{})
	remove, err := b.subprotocol.Handle(testCallBlockType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	results := testStartCall(a, context.Background(), b, testCallBlockType, nil, &CallOptions{Timeout: 4 * time.Second})
	testAwait(t, started, "handler")
	b.clock.Advance(4 * time.Second)
	result := testAwait(t, results, "call")
	if code, _ := SubprotocolErrorCode(result.err); code != protocol.ErrorCode_ERR_DEADLINE_EXCEEDED {
		t.Fatalf("err %v", result.err)
	}
}

// A handler's refusal answers with its code and message; any other error, and a panic, with
// UNAVAILABLE naming nothing.
func TestHandlerRefusals(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	var mode atomic.Int32
	remove, err := b.subprotocol.Handle(testCallType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		switch mode.Load() {
		case 0:
			return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_NOT_FOUND, Message: "no such thing", RetryAfter: 2 * time.Second}
		case 1:
			return nil, errors.New("an internal detail")
		}
		panic("synthetic handler panic")
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	_, err = a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, nil, nil)
	var refusal *SubprotocolError
	if !errors.As(err, &refusal) || refusal.Code != protocol.ErrorCode_ERR_NOT_FOUND || refusal.Message != "no such thing" || refusal.RetryAfter != 2*time.Second {
		t.Errorf("err %v", err)
	}
	for _, m := range []int32{1, 2} {
		mode.Store(m)
		_, err = a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, nil, nil)
		if !errors.As(err, &refusal) || refusal.Code != protocol.ErrorCode_ERR_UNAVAILABLE || refusal.Message != "" {
			t.Errorf("mode %d: err %v", m, err)
		}
	}
}

// Handle takes no type the dispatcher answers itself and no push type.
func TestHandleRefusesReservedTypes(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	handler := func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		return nil, nil
	}
	for _, messageType := range []protocol.MessageType{
		protocol.MessageType_MESSAGE_TYPE_NONE, protocol.MessageType_HELLO, protocol.MessageType_HELLO_RESULT,
		protocol.MessageType_PING, protocol.MessageType_PONG, protocol.MessageType_CANCEL, protocol.MessageType_ERROR,
		protocol.MessageType_PUSH_RESET, protocol.MessageType_PUSH_HINT,
	} {
		if _, err := a.subprotocol.Handle(messageType, handler, nil); !errors.Is(err, errHandleType) {
			t.Errorf("%v: %v", messageType, err)
		}
	}
	remove, err := a.subprotocol.Handle(testCallType, handler, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.subprotocol.Handle(testCallType, handler, nil); err == nil {
		t.Errorf("a second handler for one type")
	}
	remove()
}

// A body past the peer's Hello max_body_byte_count is TOO_LARGE here, sent nowhere.
func TestCallTooLargeForThePeer(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, func(settings *SidecarProtocolSettings) {
		settings.ReassemblyMaxBodyByteCount = 8 * 1024
	})
	testEchoHandler(t, b, nil)
	_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, make([]byte, 8*1024+1), nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_TOO_LARGE {
		t.Errorf("err %v", err)
	}
	if len(testSentOfType(a, testCallType)) != 0 {
		t.Errorf("a body past the peer's bound was sent")
	}
}

// A peer that no longer holds this side's Hello refuses the call at its gate; the caller runs one fresh
// Hello and sends the same request again, which no handler had run.
func TestCallRunsHelloAgainWhenThePeerForgot(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	runCount := testEchoHandler(t, b, nil)
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	b.subprotocol.forgetPeer(a.clientId)
	response, err := a.subprotocol.Call(t.Context(), Id(b.clientId), testCallType, []byte("y"), nil)
	if err != nil || string(response) != "y!" {
		t.Fatalf("%q, %v", response, err)
	}
	requests := testSentOfType(a, testCallType)
	if len(requests) != 2 || requests[0].RequestId != requests[1].RequestId || runCount.Load() != 1 {
		t.Errorf("%d sends, %d runs", len(requests), runCount.Load())
	}
	if hellos := testSentOfType(a, protocol.MessageType_HELLO); len(hellos) != 2 {
		t.Errorf("%d Hellos", len(hellos))
	}
}

// Past PeerQueueMessageCount handler runs from one peer, a request is answered RESOURCE_EXHAUSTED at
// once, and the runs in flight go on.
func TestHandlerRunsBoundedPerPeer(t *testing.T) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, func(settings *SidecarProtocolSettings) {
		settings.PeerQueueMessageCount = 1
	})
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	remove, err := b.subprotocol.Handle(testCallBlockType, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		started <- struct{}{}
		<-release
		return []byte("done"), nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	first := testStartCall(a, context.Background(), b, testCallBlockType, nil, nil)
	testAwait(t, started, "handler")
	_, err = a.subprotocol.Call(t.Context(), Id(b.clientId), testCallBlockType, nil, nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED {
		t.Errorf("err %v", err)
	}
	close(release)
	if result := testAwait(t, first, "first call"); result.err != nil || string(result.body) != "done" {
		t.Errorf("%q, %v", result.body, result.err)
	}
}

// A Required peer with no session: the send's error surfaces as UNAVAILABLE with reason encryption.
func TestCallSurfacesAMissingSessionAsEncryption(t *testing.T) {
	err := sendFailure(connect.ErrEncryptionRequiredNotEstablished, 7)
	var unavailable *SubprotocolError
	if !errors.As(err, &unavailable) || unavailable.Code != protocol.ErrorCode_ERR_UNAVAILABLE || unavailable.Reason != SubprotocolReasonEncryption || unavailable.RequestId != 7 {
		t.Errorf("err %v", err)
	}
}
