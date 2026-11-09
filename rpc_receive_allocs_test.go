//go:build !sidecar_http && !js && !sidecar_testhooks && !race

// §22.5's §6 row "receive allocs", recorded as PROTO-M1-11's baseline for PROTO-M5-05: the allocations
// one envelope costs from connect's typed delivery through its dispatch, on the path production runs.
// envelopeCodec owns no instances, so connect's delivery makes one Envelope per receive with its
// reflection factory (connect/subprotocol.go's newSubprotocolMessageFactory) and decodes into it; the
// inline handler checks it and queues it for its source's worker, which dispatches it. Each run waits for
// its dispatch, so a run counts its worker's share.
//
// §22.5 names no number, so the gate PROTO-M5-05 holds is no regression from the figures in
// testdata/receive_allocs.json, which this test reads and, under -update-receive-allocs, writes. Only the
// release leg is measured: sidecar_testhooks and the race detector change what a receive costs.

package sidecar

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

var updateReceiveAllocs = flag.Bool("update-receive-allocs", false, "rewrite testdata/receive_allocs.json")

const testReceiveAllocsPath = "testdata/receive_allocs.json"

// The baseline's file: allocations per receive, by kind.
type testReceiveAllocs struct {
	Comment string `json:"comment"`
	// A verified peer's request, its body bodyByteCount long, queued and dispatched to a function.
	Request float64 `json:"request"`
	// A ControlId push over h1, queued and dispatched to the push's function.
	Push float64 `json:"push"`
}

// The request body's length: a small RPC, well inside one envelope.
const testReceiveAllocsBodyByteCount = 256

// The allocations of one receive of envelopeBytes from sourceId, from connect's decode to the dispatch
// function's return, the least of three measures, since AllocsPerRun counts the whole process and a
// goroutine an earlier test left may allocate while one runs.
func testMeasureReceiveAllocs(t *testing.T, fixture *testSubprotocol, messageType protocol.MessageType, sourceId connect.Id, envelopeBytes []byte, peer connect.Peer) float64 {
	t.Helper()
	dispatched := make(chan struct{})
	remove, err := fixture.subprotocol.setMessageTypeDispatch(messageType, func(ctx context.Context, message *subprotocolMessage) {
		dispatched <- struct{}{}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	envelopeType := reflect.TypeFor[protocol.Envelope]()
	source := connect.SourceId(sourceId)
	receive := func() {
		// connect's typed delivery: a fresh instance from the factory, the codec's decode, the handler
		envelope := reflect.New(envelopeType).Interface().(*protocol.Envelope)
		if err := (envelopeCodec{}).Unmarshal(envelopeBytes, envelope); err != nil {
			t.Fatal(err)
		}
		fixture.subprotocol.receive(source, envelope, peer)
		<-dispatched
	}
	// the source's worker and queue exist before the measure, as on a live peer
	receive()
	measure := func() float64 {
		return testing.AllocsPerRun(200, receive)
	}
	return min(measure(), measure(), measure())
}

func TestReceiveAllocsHoldTheBaseline(t *testing.T) {
	fixture := newTestSubprotocol(t, nil)
	sourceId := connect.NewId()
	fixture.verify(sourceId, "peer")
	requestBytes, err := proto.Marshal(testRequest(testFreeMessageType, make([]byte, testReceiveAllocsBodyByteCount)))
	if err != nil {
		t.Fatal(err)
	}
	hintBody, err := proto.Marshal(&protocol.PushHint{Seq: 1, Topic: PushTopicTeam, Version: 2, Kind: 0x0201, Hint: make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}
	pushBytes, err := proto.Marshal(&protocol.Envelope{Version: WireVersionMajor, Type: uint32(protocol.MessageType_PUSH_HINT), RequestId: 1, Flags: EnvelopeFlagNoReply, Body: hintBody})
	if err != nil {
		t.Fatal(err)
	}
	controlPeer := connect.Peer{TransportType: connect.TransportTypeH1}
	measured := &testReceiveAllocs{
		Comment: "Allocations per receive from connect's decode through dispatch, the release leg (rpc_receive_allocs_test.go). " +
			"PROTO-M5-05 holds these as the baseline: no regression. go test -run TestReceiveAllocsHoldTheBaseline -update-receive-allocs rewrites this file.",
		Request: testMeasureReceiveAllocs(t, fixture, testFreeMessageType, sourceId, requestBytes, testNetworkPeer("peer")),
		Push:    testMeasureReceiveAllocs(t, fixture, protocol.MessageType_PUSH_HINT, connect.ControlId, pushBytes, controlPeer),
	}
	fixture.closeBalanced(t)
	t.Logf("allocations per receive: request %.1f, push %.1f", measured.Request, measured.Push)

	if *updateReceiveAllocs {
		encoded, err := json.MarshalIndent(measured, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testReceiveAllocsPath, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	encoded, err := os.ReadFile(testReceiveAllocsPath)
	if err != nil {
		t.Fatal(err)
	}
	baseline := &testReceiveAllocs{}
	if err := json.Unmarshal(encoded, baseline); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		kind     string
		measured float64
		baseline float64
	}{
		{kind: "request", measured: measured.Request, baseline: baseline.Request},
		{kind: "push", measured: measured.Push, baseline: baseline.Push},
	} {
		if c.baseline <= 0 {
			t.Errorf("%s: the baseline records no figure", c.kind)
			continue
		}
		if c.baseline < c.measured {
			t.Errorf("%s: %.1f allocations per receive, past the baseline's %.1f", c.kind, c.measured, c.baseline)
		}
	}
}
