//go:build !sidecar_http && !js

// SEARCH's envelope rules (PROTO-M10-01), FS-83's size cases at this layer: every request one envelope
// of exactly 4,016 B with timeout_ms 10,000 whatever ctx says, every reply steps × 16,384 B in its one
// frame-size sequence, a request of another size answered INVALID at the requester's steps without its
// handler, an answer of another size never sent, no Cancel for a search given up, and no idempotency
// cache under a retry.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
)

// A SEARCH body of exactly the request size: a SearchRequest of steps, padded.
func testSearchRequestBody(t *testing.T, searchId uint64, page uint32, steps uint32) []byte {
	t.Helper()
	request := &protocol.SearchRequest{SearchVersion: 1, SearchId: searchId, Page: page, Steps: steps, Scope: 1, Query: "needle"}
	for padByteCount := DefaultSearchWireSettings().RequestByteCount - proto.Size(request) - 4; padByteCount <= DefaultSearchWireSettings().RequestByteCount; padByteCount += 1 {
		if padByteCount < 0 {
			continue
		}
		request.Pad = make([]byte, padByteCount)
		if proto.Size(request) == DefaultSearchWireSettings().RequestByteCount {
			body, err := proto.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
	t.Fatal("no padding reaches the request's size")
	return nil
}

// A pair where b serves SEARCH with answer, counting its runs.
func newTestSearchPair(t *testing.T, answer func(request *SubprotocolRequest) ([]byte, error)) (*testRpcSide, *testRpcSide, chan *SubprotocolRequest) {
	pair := newTestRpcPair(t)
	a := pair.add(nil, nil)
	b := pair.add(nil, nil)
	if err := b.subprotocol.SetFeatures(SubprotocolFeatureServesSearch, nil); err != nil {
		t.Fatal(err)
	}
	runs := make(chan *SubprotocolRequest, 16)
	if _, err := b.subprotocol.Handle(protocol.MessageType_SEARCH, func(ctx context.Context, request *SubprotocolRequest) ([]byte, error) {
		runs <- request
		return answer(request)
	}, &HandleOptions{Mutating: true}); err != nil {
		t.Fatal(err)
	}
	return a, b, runs
}

// A padded SearchReply OK of steps.
func testSearchReply(t *testing.T, request *SubprotocolRequest) ([]byte, error) {
	searchRequest := &protocol.SearchRequest{}
	if err := proto.Unmarshal(request.Body, searchRequest); err != nil {
		return nil, err
	}
	return padSearchReply(&protocol.SearchReply{
		SearchVersion: 1,
		SearchId:      searchRequest.SearchId,
		Page:          searchRequest.Page,
		Status:        uint32(protocol.SearchStatus_SEARCH_OK),
	}, int(searchRequest.Steps), DefaultSearchWireSettings())
}

// Every request is one envelope of 4,016 B with no chunk header and timeout_ms 10,000, whether the
// caller's ctx or options ask less; every reply is steps × 16,384 B as 4 × steps envelopes of 4,016 B
// and a final one of 320 × steps B.
func TestSearchFrameSizes(t *testing.T) {
	a, b, _ := newTestSearchPair(t, func(request *SubprotocolRequest) ([]byte, error) {
		return testSearchReply(t, request)
	})
	for steps := uint32(1); steps <= uint32(DefaultSearchWireSettings().MaxStepCount); steps += 1 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Hour)
		sentBefore := len(a.sent())
		repliedBefore := len(b.sent())
		answer, err := a.subprotocol.Call(ctx, Id(b.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 7, 0, steps), &CallOptions{Timeout: 2 * time.Second})
		cancel()
		if err != nil {
			t.Fatalf("steps %d: %v", steps, err)
		}
		if len(answer) != int(steps)*DefaultSearchWireSettings().StepByteCount {
			t.Errorf("steps %d: a reply of %d B", steps, len(answer))
		}
		requests := []*protocol.Envelope{}
		for _, envelope := range a.sent()[sentBefore:] {
			if envelope.Type == uint32(protocol.MessageType_SEARCH) {
				requests = append(requests, envelope)
			}
		}
		if len(requests) != 1 || requests[0].Chunk != nil || len(requests[0].Body) != DefaultSearchWireSettings().RequestByteCount || requests[0].TimeoutMs != 10000 {
			t.Errorf("steps %d: requests %d, first %+v", steps, len(requests), requests[0].Chunk)
		}
		sizes := []int{}
		for _, envelope := range b.sent()[repliedBefore:] {
			if envelope.Type == uint32(protocol.MessageType_SEARCH_RESULT) {
				sizes = append(sizes, len(envelope.Body))
			}
		}
		want := []int{}
		for range 4 * steps {
			want = append(want, MaxEnvelopeBodyByteCount)
		}
		want = append(want, 320*int(steps))
		if !slices.Equal(sizes, want) {
			t.Errorf("steps %d: reply envelopes %v", steps, sizes)
		}
	}
}

// A request body off 4,016 B is refused before it is sent.
func TestSearchRequestOfAnotherSizeIsNeverSent(t *testing.T) {
	a, b, _ := newTestSearchPair(t, func(request *SubprotocolRequest) ([]byte, error) {
		return testSearchReply(t, request)
	})
	if err := a.subprotocol.EnsureHello(t.Context(), Id(b.clientId)); err != nil {
		t.Fatal(err)
	}
	sentBefore := len(a.sent())
	for _, byteCount := range []int{0, DefaultSearchWireSettings().RequestByteCount - 1, DefaultSearchWireSettings().RequestByteCount + 1, 2 * DefaultSearchWireSettings().RequestByteCount} {
		_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), protocol.MessageType_SEARCH, make([]byte, byteCount), nil)
		if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_INVALID_ARGUMENT {
			t.Errorf("%d B: %v", byteCount, err)
		}
	}
	if len(a.sent()) != sentBefore {
		t.Errorf("a request of the wrong size went out")
	}
}

// A request that arrives off 4,016 B reaches no handler and is answered INVALID at the requester's steps,
// as large as an answer, never a small Error.
func TestSearchRequestOfAnotherSizeIsAnsweredInvalidAtItsSteps(t *testing.T) {
	a, b, runs := newTestSearchPair(t, func(request *SubprotocolRequest) ([]byte, error) {
		return testSearchReply(t, request)
	})
	for steps := uint32(1); steps <= uint32(DefaultSearchWireSettings().MaxStepCount); steps += 1 {
		short := testSearchRequestBody(t, 9, 1, steps)
		request := &protocol.SearchRequest{}
		proto.Unmarshal(short, request)
		request.Pad = request.Pad[:len(request.Pad)-10]
		body, _ := proto.Marshal(request)
		a.setDeliver(func(from *testRpcSide, to *testRpcSide, envelope *protocol.Envelope) *protocol.Envelope {
			if from == a && envelope.Type == uint32(protocol.MessageType_SEARCH) {
				envelope.Body = body
			}
			return envelope
		})
		answer, err := a.subprotocol.Call(t.Context(), Id(b.clientId), protocol.MessageType_SEARCH, short, nil)
		if err != nil {
			t.Fatalf("steps %d: %v", steps, err)
		}
		reply := &protocol.SearchReply{}
		if err := proto.Unmarshal(answer, reply); err != nil {
			t.Fatal(err)
		}
		if len(answer) != int(steps)*DefaultSearchWireSettings().StepByteCount || reply.Status != uint32(protocol.SearchStatus_SEARCH_INVALID) ||
			reply.SearchId != 9 || reply.Page != 1 || !bytes.Equal(reply.Pad, make([]byte, len(reply.Pad))) {
			t.Errorf("steps %d: %d B, status %d", steps, len(answer), reply.Status)
		}
	}
	select {
	case <-runs:
		t.Errorf("a handler ran for a request of the wrong size")
	default:
	}
}

// An answer whose size no reply may take is never sent: the request answers UNAVAILABLE.
func TestSearchAnswerOfAnotherSizeIsNeverSent(t *testing.T) {
	a, b, _ := newTestSearchPair(t, func(request *SubprotocolRequest) ([]byte, error) {
		return make([]byte, DefaultSearchWireSettings().StepByteCount-1), nil
	})
	_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 0, 1), nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_UNAVAILABLE {
		t.Errorf("an answer off its size: %v", err)
	}
	for _, envelope := range b.sent() {
		if envelope.Type == uint32(protocol.MessageType_SEARCH_RESULT) {
			t.Errorf("a SEARCH_RESULT of %d B went out", len(envelope.Body))
		}
	}
}

// A SEARCH_RESULT that arrives off a reply's sizes fails the call, never retried; one of each step
// passes.
func TestSearchResultOfAnotherSizeFailsTheCall(t *testing.T) {
	for _, byteCount := range []int{0, 1000, DefaultSearchWireSettings().StepByteCount - 1, DefaultSearchWireSettings().StepByteCount + 1, (DefaultSearchWireSettings().MaxStepCount + 1) * DefaultSearchWireSettings().StepByteCount} {
		response := &rpcResponse{envelope: &protocol.Envelope{Type: uint32(protocol.MessageType_SEARCH_RESULT), Flags: EnvelopeFlagResponse, Body: make([]byte, byteCount)}}
		if _, err := searchResponseBody(response, DefaultSearchWireSettings()); !errors.Is(err, ErrSubprotocolResponse) {
			t.Errorf("a SEARCH_RESULT of %d B: %v", byteCount, err)
		}
	}
	for steps := 1; steps <= DefaultSearchWireSettings().MaxStepCount; steps += 1 {
		response := &rpcResponse{envelope: &protocol.Envelope{Type: uint32(protocol.MessageType_SEARCH_RESULT), Flags: EnvelopeFlagResponse, Body: make([]byte, steps*DefaultSearchWireSettings().StepByteCount)}}
		if _, err := searchResponseBody(response, DefaultSearchWireSettings()); err != nil {
			t.Errorf("%d steps: %v", steps, err)
		}
	}
	// a reply of another type answers no search
	response := &rpcResponse{envelope: &protocol.Envelope{Type: uint32(testCallType + 1), Flags: EnvelopeFlagResponse, Body: make([]byte, DefaultSearchWireSettings().StepByteCount)}}
	if _, err := searchResponseBody(response, DefaultSearchWireSettings()); !errors.Is(err, ErrSubprotocolResponse) {
		t.Errorf("another type: %v", err)
	}
}

// A search given up sends no Cancel, where any other call does.
func TestSearchIsNeverCancelled(t *testing.T) {
	release := make(chan struct{})
	a, b, runs := newTestSearchPair(t, func(request *SubprotocolRequest) ([]byte, error) {
		<-release
		return testSearchReply(t, request)
	})
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() {
		_, err := a.subprotocol.Call(ctx, Id(b.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 0, 1), nil)
		result <- err
	}()
	testAwait(t, runs, "the search's run")
	cancel()
	if code, _ := SubprotocolErrorCode(testAwait(t, result, "the call's end")); code != protocol.ErrorCode_ERR_CANCELLED {
		t.Errorf("a given-up search: %v", code)
	}
	for _, envelope := range a.sent() {
		if envelope.Type == uint32(protocol.MessageType_CANCEL) {
			t.Errorf("a Cancel for a search")
		}
	}
}

// SEARCH mutates nothing: a retry under the same request_id runs the handler again, answered from the
// indexer's cursor, never from the idempotency cache, whatever options the handler was given.
func TestSearchRetryNeverHitsTheIdempotencyCache(t *testing.T) {
	a, b, runs := newTestSearchPair(t, func(request *SubprotocolRequest) ([]byte, error) {
		return testSearchReply(t, request)
	})
	options := &CallOptions{RequestId: 0x5ea2c4}
	for range 2 {
		if _, err := a.subprotocol.Call(t.Context(), Id(b.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 3, 0, 1), options); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		testAwait(t, runs, "a run")
	}
	if count := b.subprotocol.stats.idempotentAnswerCount.Load(); count != 0 {
		t.Errorf("%d answers from the cache", count)
	}
}

// On control, SEARCH reaches a sidecar advertising bit 0 and no other; its reply passes on control.
func TestControlContractCarriesSearchOnlyToBitZero(t *testing.T) {
	a, b, runs := newTestSearchPair(t, func(request *SubprotocolRequest) ([]byte, error) {
		return testSearchReply(t, request)
	})
	a.setContractClass(connectprotocol.ContractClass_ContractClassControl)
	b.setContractClass(connectprotocol.ContractClass_ContractClassControl)
	if _, err := a.subprotocol.Call(t.Context(), Id(b.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 0, 1), nil); err != nil {
		t.Fatalf("SEARCH on control to bit 0: %v", err)
	}
	testAwait(t, runs, "the run")
	if err := b.subprotocol.SetFeatures(0, nil); err != nil {
		t.Fatal(err)
	}
	_, err := a.subprotocol.Call(t.Context(), Id(b.clientId), protocol.MessageType_SEARCH, testSearchRequestBody(t, 1, 0, 1), nil)
	if code, _ := SubprotocolErrorCode(err); code != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("SEARCH on control without bit 0: %v", err)
	}
}
