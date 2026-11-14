// §13.6's accounting: one lease per network in a process, shared by its connections and closed with the
// last, and no byte moving when there is nothing to lease from.

package tlsedgeservice_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// A network's connections share one lease, and the next connection after the last ended asks again.
func TestTlsEdgeLeaseSharedByANetworksConnections(t *testing.T) {
	world := newTestPathWorld(t, nil)
	first, firstStream, _ := world.open(t, "blog")
	second, secondStream, _ := world.open(t, "shop")
	third, thirdStream, _ := world.open(t, "blog")
	// a byte back says a connection is past its lease
	for _, stream := range []*testPathStream{firstStream, secondStream, thirdStream} {
		stream.listenerWrite(t, []byte{1})
	}
	for _, conn := range []io.Reader{first, second, third} {
		testVisitorRead(t, conn, 1)
	}
	if got := world.quota.leaseCount.Load(); got != 1 {
		t.Fatalf("%d leases for three connections of one network", got)
	}
	for _, conn := range []interface{ CloseWrite() error }{first, second, third} {
		conn.CloseWrite()
	}
	for _, stream := range []*testPathStream{firstStream, secondStream, thirdStream} {
		stream.listenerReadAll(t)
		stream.listenerCloseWrite()
		stream.awaitEngineClose(t)
	}
	world.awaitEnded(t, 3)

	fourth, fourthStream, hello := world.open(t, "blog")
	fourthStream.listenerWrite(t, []byte{1})
	testVisitorRead(t, fourth, 1)
	if got := world.quota.leaseCount.Load(); got != 2 {
		t.Fatalf("%d leases after the first was closed", got)
	}
	// the closed lease gave back what it did not spend: the balance is short only what moved
	if err := world.service.UsageDrainForTest(world.ctx); err != nil {
		t.Fatal(err)
	}
	if got := world.host.Quota.TransferUsed(connect.Id(world.networkId), sidecar.QuotaMeterTls); got != int64(4*len(hello)+4) {
		t.Fatalf("%d B billed for four hellos of %d B and four bytes", got, len(hello))
	}
}

// With no Quota there is nothing to spend from: the connection is refused with internal_error and the
// stream the dialer opened is reset, so no unaccounted byte moves.
func TestTlsEdgeLeaseNoQuotaRefuses(t *testing.T) {
	world := newTestPathWorldOn(t, sidecartestStore(), nil, func(host *sidecar.ServiceHost) {
		host.Quota = nil
	})
	answer := world.answer(t, testEdgeHello(world.name("blog"), []string{"h2"}, 0))
	if !bytes.Equal(answer, testAlertBytes(tlsedgeservice.TlsAlertInternalError)) {
		t.Fatalf("no quota answered %x", answer)
	}
	if code := world.dialer.awaitOpened(t).awaitReset(t); code != protocol.StreamResetCode_RST_CANCELLED {
		t.Fatalf("the stream reset with %v", code)
	}
	world.awaitEnded(t, 1)
	if got := world.host.Metrics.Value("urnetwork_tlsedge_connections_total", "setup_failed"); got != 1 {
		t.Fatalf("%v failed setups counted", got)
	}
}
