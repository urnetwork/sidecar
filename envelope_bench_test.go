//go:build !sidecar_http && !js && !sidecar_testhooks && !race

package sidecar

// §22.5's §6 row "receive allocs" as testdata/budgets.yml's receive-allocs row runs it (PROTO-M5-05; D-PROTO-11):
// one verified peer's request from connect's typed delivery, a fresh Envelope from connect's reflection factory
// and envelopeCodec's decode, through the real inline handler to its source's worker and its dispatch, on
// production's protocol settings. §22.5 names no number, so the row's limit is PROTO-M1-11's recorded baseline,
// testdata/receive_allocs.json's request figure: no regression. What it measures is the data for D-PROTO-11's
// pooled codec, which is built only if §22 shows it worthwhile (External).

import (
	"context"
	"reflect"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

func BenchmarkSubprotocolReceive(b *testing.B) {
	fixture := newTestSubprotocol(b, nil)
	sourceId := connect.NewId()
	fixture.verify(sourceId, "peer")
	envelopeBytes, err := proto.Marshal(testRequest(testFreeMessageType, make([]byte, testReceiveAllocsBodyByteCount)))
	if err != nil {
		b.Fatal(err)
	}
	dispatched := make(chan struct{})
	remove, err := fixture.subprotocol.setMessageTypeDispatch(testFreeMessageType, func(ctx context.Context, message *subprotocolMessage) {
		dispatched <- struct{}{}
	})
	if err != nil {
		b.Fatal(err)
	}
	envelopeType := reflect.TypeFor[protocol.Envelope]()
	source := connect.SourceId(sourceId)
	peer := testNetworkPeer("peer")
	receive := func() {
		envelope := reflect.New(envelopeType).Interface().(*protocol.Envelope)
		if err := (envelopeCodec{}).Unmarshal(envelopeBytes, envelope); err != nil {
			b.Fatal(err)
		}
		fixture.subprotocol.receive(source, envelope, peer)
		<-dispatched
	}
	// the source's worker and queue exist before the measure, as on a live peer
	receive()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		receive()
	}
	b.StopTimer()
	remove()
	fixture.closeBalanced(b)
}
