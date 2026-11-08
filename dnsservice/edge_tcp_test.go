package dnsservice_test

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// How long a test waits on a real socket before calling the test hung. A safety net only: every
// timeout the edge applies runs on the fake clock.
const edgeTcpTestHang = 30 * time.Second

// Serves TCP on a loopback listener until the test ends, returning its address.
func (self *testEdge) serveTcp(t testing.TB) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		served <- self.edge.Serve(listener)
	}()
	t.Cleanup(func() {
		listener.Close()
		<-served
	})
	return listener.Addr().String()
}

func edgeTcpDial(t testing.TB, address string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(edgeTcpTestHang))
	t.Cleanup(func() { conn.Close() })
	return conn
}

func edgeTcpWrite(t testing.TB, conn net.Conn, message *dns.Msg) {
	t.Helper()
	data, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(data)))
	if _, err := conn.Write(append(framed, data...)); err != nil {
		t.Fatal(err)
	}
}

// The next reply on conn, or the error that ended it.
func edgeTcpRead(conn net.Conn) (*dns.Msg, error) {
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBytes); err != nil {
		return nil, err
	}
	data := make([]byte, binary.BigEndian.Uint16(lengthBytes))
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	reply := &dns.Msg{}
	return reply, reply.Unpack(data)
}

// Whether the edge closed conn: a read ends at once with no reply, not at the safety deadline.
func edgeTcpClosed(conn net.Conn) bool {
	_, err := edgeTcpRead(conn)
	var netErr net.Error
	return err != nil && !(errors.As(err, &netErr) && netErr.Timeout())
}

// Waits until the edge serves count TCP connections.
func (self *testEdge) awaitTcpCount(t testing.TB, count int) {
	t.Helper()
	for {
		current, changed := self.edge.TcpCountForTest()
		if current == count {
			return
		}
		select {
		case <-changed:
		case <-t.Context().Done():
			t.Fatalf("tcp count %d, want %d", current, count)
		}
	}
}

// Over TCP the edge answers queries in order on one connection, pipelined, with no RRL.
func TestEdgeTcpAnswersPipelinedQueriesInOrder(t *testing.T) {
	edge := newTestEdge(t, edgeTestSettings(t))
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	conn := edgeTcpDial(t, edge.serveTcp(t))
	names := []string{"www.net1.", "a.net1.", "nosuch.", "b.net1.", "c.net1.", "www.net1."}
	for index, name := range names {
		query := edgeTestQuery(name+edgeTestRoot, dns.TypeMX, true)
		query.Id = uint16(index + 1)
		edgeTcpWrite(t, conn, query)
	}
	for index, name := range names {
		reply, err := edgeTcpRead(conn)
		if err != nil {
			t.Fatal(err)
		}
		if reply.Id != uint16(index+1) || reply.Question[0].Name != name+edgeTestRoot {
			t.Errorf("reply %d %v", index, reply)
		}
		edge.wantSigned(t, reply)
	}
}

// tcp.connections_per_source: a source's third connection is closed at accept, and once one of its
// two closes it may connect again.
func TestEdgeTcpCapsConnectionsPerSource(t *testing.T) {
	edge := newTestEdge(t, edgeTestSettings(t))
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	address := edge.serveTcp(t)
	first := edgeTcpDial(t, address)
	second := edgeTcpDial(t, address)
	edge.awaitTcpCount(t, 2)
	third := edgeTcpDial(t, address)
	if !edgeTcpClosed(third) {
		t.Error("a third connection from one source was served")
	}
	if refused := edge.host.Metrics.Value("urnetwork_dnsedge_tcp_refused_total", "source"); refused != 1 {
		t.Errorf("refused %v", refused)
	}
	for _, conn := range []net.Conn{first, second} {
		edgeTcpWrite(t, conn, edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, false))
		if reply, err := edgeTcpRead(conn); err != nil || len(reply.Answer) != 1 {
			t.Errorf("an admitted connection %v %v", reply, err)
		}
	}
	first.Close()
	edge.awaitTcpCount(t, 1)
	again := edgeTcpDial(t, address)
	edgeTcpWrite(t, again, edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, false))
	if reply, err := edgeTcpRead(again); err != nil || len(reply.Answer) != 1 {
		t.Errorf("a connection after one closed %v %v", reply, err)
	}
}

// tcp.connections bounds every source together.
func TestEdgeTcpCapsConnectionsInAll(t *testing.T) {
	settings := edgeTestSettings(t)
	settings.Tcp.ConnectionsPerSource = 8
	settings.Tcp.ConnectionCount = 1
	edge := newTestEdge(t, settings)
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	address := edge.serveTcp(t)
	edgeTcpDial(t, address)
	edge.awaitTcpCount(t, 1)
	if !edgeTcpClosed(edgeTcpDial(t, address)) {
		t.Error("a connection past tcp.connections was served")
	}
	if refused := edge.host.Metrics.Value("urnetwork_dnsedge_tcp_refused_total", "total"); refused != 1 {
		t.Errorf("refused %v", refused)
	}
}

// tcp.idle_timeout_s on the fake clock: a connection that sends nothing is closed when it passes, a
// query restarts it, and a connection that goes quiet after its queries is closed in turn.
func TestEdgeTcpClosesAnIdleConnection(t *testing.T) {
	edge := newTestEdge(t, edgeTestSettings(t))
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	address := edge.serveTcp(t)
	idle := time.Duration(edge.settings.Tcp.IdleTimeoutSeconds) * time.Second

	silent := edgeTcpDial(t, address)
	if err := edge.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	edge.clock.Advance(idle)
	if !edgeTcpClosed(silent) {
		t.Fatal("a silent connection outlived the idle timeout")
	}
	edge.awaitTcpCount(t, 0)

	busy := edgeTcpDial(t, address)
	if err := edge.clock.AwaitTimers(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	edge.clock.Advance(idle * 6 / 10)
	// two answers in turn: once the second is in, the timer armed at connect has been stopped, since
	// it is stopped before the timer the second query was read under is armed
	for range 2 {
		edgeTcpWrite(t, busy, edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, false))
		if _, err := edgeTcpRead(busy); err != nil {
			t.Fatal(err)
		}
	}
	edge.clock.Advance(idle * 6 / 10)
	edgeTcpWrite(t, busy, edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, false))
	if reply, err := edgeTcpRead(busy); err != nil || len(reply.Answer) != 1 {
		t.Fatalf("past the first idle bound a busy connection got %v %v", reply, err)
	}
	edge.clock.Advance(idle)
	if !edgeTcpClosed(busy) {
		t.Error("a connection idle after its queries stayed open")
	}
}

// Drain takes no new connection and closes those waiting for a query, then returns.
func TestEdgeTcpDrainClosesConnectionsAndTakesNoNew(t *testing.T) {
	edge := newTestEdge(t, edgeTestSettings(t))
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	address := edge.serveTcp(t)
	conn := edgeTcpDial(t, address)
	edgeTcpWrite(t, conn, edgeTestQuery("www.net1."+edgeTestRoot, dns.TypeA, false))
	if _, err := edgeTcpRead(conn); err != nil {
		t.Fatal(err)
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		edge.edge.Drain()
	}()
	if !edgeTcpClosed(conn) {
		t.Error("a waiting connection stayed open through Drain")
	}
	select {
	case <-drained:
	case <-t.Context().Done():
		t.Fatal("Drain did not return")
	}
	if !edgeTcpClosed(edgeTcpDial(t, address)) {
		t.Error("a connection while draining was served")
	}
	if refused := edge.host.Metrics.Value("urnetwork_dnsedge_tcp_refused_total", "draining"); refused != 1 {
		t.Errorf("refused %v", refused)
	}
}

// Close ends Serve and ServePacket with nil, and every connection.
func TestEdgeCloseEndsEveryListener(t *testing.T) {
	edge := newTestEdge(t, edgeTestSettings(t))
	edge.publish(t, edgeTestView(t, edge.settings, 7, edgeTestRows()))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	served := make(chan error, 2)
	go func() { served <- edge.edge.Serve(listener) }()
	packetConn := newTestPacketConn()
	go func() { served <- edge.edge.ServePacket(packetConn) }()
	conn := edgeTcpDial(t, listener.Addr().String())
	edge.awaitTcpCount(t, 1)
	edge.edge.Close()
	for range 2 {
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("served %v", err)
			}
		case <-t.Context().Done():
			t.Fatal("a listener outlived Close")
		}
	}
	if !edgeTcpClosed(conn) {
		t.Error("a connection outlived Close")
	}
	if err := edge.edge.ServePacket(newTestPacketConn()); err != nil {
		t.Errorf("serving after Close %v", err)
	}
}
