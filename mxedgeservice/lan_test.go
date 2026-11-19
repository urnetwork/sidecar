package mxedgeservice_test

// MAIL-M9-05's LAN listener: only smtpedge's hosts reach it, any other LAN peer closed unanswered, and a LAN session,
// once its PROXY line names the sending address, gets the lb's banner and dialog and spends the same per-sender caps.
// The PROXY line itself is tlsedgeservice's listener's, which the host stacks over this one (server/mxedgehost), so
// here a conn carries the address its line would name.
// A routed LAN session splices as an lb one does, the receiver seeing the hello and every TLS byte after it unchanged.

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/urnetwork/sidecar/mxedgeservice"
)

// A LAN connection as the bound listener takes it: its socket's peer, the smtpedge host, and the sending address its
// PROXY line names.
type testLanSocketConn struct {
	net.Conn
	peer   net.Addr
	sender net.Addr
}

func (self *testLanSocketConn) RemoteAddr() net.Addr {
	return self.peer
}

// What the PROXY header listener over the LAN listener hands the engine: the conn, its RemoteAddr the line's sender.
type testLanProxyListener struct {
	net.Listener
}

func (self *testLanProxyListener) Accept() (net.Conn, error) {
	conn, err := self.Listener.Accept()
	if err != nil {
		return nil, err
	}
	socket := conn.(*testLanSocketConn)
	return &testServerConn{Conn: socket.Conn, sender: socket.sender}, nil
}

// The engine serving a LAN listener beside its lb one, smtpedge's hosts at 10.20.0.0/24.
type testLanWorld struct {
	engine *testEngine
	raw    *testListener
	lan    *mxedgeservice.MxLanListener
}

func newTestLanWorld(t *testing.T) *testLanWorld {
	t.Helper()
	settings := testSettings()
	settings.LanPort = 2526
	settings.LanSources = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	return serveTestLan(t, newTestEngine(t, &testEngineOptions{settings: settings}))
}

// engine, whose settings name a lan_port and its sources, serving a LAN listener beside its lb one.
func serveTestLan(t *testing.T, engine *testEngine) *testLanWorld {
	t.Helper()
	raw := newTestListener()
	lan, err := mxedgeservice.NewMxLanListener(raw, engine.settings)
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() {
		served <- engine.service.Serve(&testLanProxyListener{Listener: lan})
	}()
	t.Cleanup(func() {
		raw.Close()
		<-served
	})
	return &testLanWorld{engine: engine, raw: raw, lan: lan}
}

// Connects from peer over the LAN, its PROXY line naming sender, and returns before anything is read.
func (self *testLanWorld) dial(t *testing.T, peer string, sender string) *testClient {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close() })
	self.raw.conns <- &testLanSocketConn{
		Conn:   serverConn,
		peer:   &net.TCPAddr{IP: net.ParseIP(peer), Port: 40000},
		sender: &net.TCPAddr{IP: net.ParseIP(sender), Port: 2525},
	}
	return &testClient{t: t, conn: clientConn, reader: bufio.NewReader(clientConn)}
}

// A LAN peer that is none of smtpedge's hosts is closed unanswered, and counted; the next listed one is served.
func TestLanListenerAdmitsOnlySmtpedgeHosts(t *testing.T) {
	world := newTestLanWorld(t)
	stranger := world.dial(t, "10.20.1.9", testSender)
	stranger.expectEnd()
	if count := world.lan.RefusedCount(); count != 1 {
		t.Fatalf("refused %d", count)
	}
	client := world.dial(t, "10.20.0.5", testSender)
	client.expect("220 " + testBannerHostName + " ESMTP")
	client.write("QUIT\r\n")
	client.expect("221 2.0.0 Bye")
	client.expectEnd()
}

// A LAN session is a normal sender's: the lb's banner and EHLO, and the per-sender cap counted by the address its
// PROXY line names, across the lb's port and the LAN's alike.
func TestLanSessionGetsTheSameDialogAndCaps(t *testing.T) {
	world := newTestLanWorld(t)
	engine := world.engine
	client := world.dial(t, "10.20.0.5", testSender)
	client.expect("220 " + testBannerHostName + " ESMTP")
	client.write("EHLO relay.example\r\n")
	client.expectEhlo()

	// the sender's other sessions arrive at the lb's port; one more over the LAN passes its cap
	for range engine.settings.SenderSessionCount - 1 {
		engine.open(testSender)
	}
	over := world.dial(t, "10.20.0.6", testSender)
	over.expect("421 4.7.0 " + testBannerHostName + " Too many sessions, try again later")
	over.expectEnd()
	client.write("QUIT\r\n")
	client.expect("221 2.0.0 Bye")
}

// A lan_port with no source is refused, so no LAN listener opens that every host could reach.
func TestLanPortNeedsItsSources(t *testing.T) {
	settings := testSettings()
	settings.LanPort = 2526
	if err := settings.Validate(); err == nil {
		t.Fatal("a lan_port with no lan_sources validated")
	}
	if _, err := mxedgeservice.NewMxLanListener(newTestListener(), settings); err == nil {
		t.Fatal("a LAN listener with no source opened")
	}
	settings.LanPort = 0
	if err := settings.Validate(); err != nil {
		t.Fatalf("no lan_port: %v", err)
	}
}

// A routed LAN session splices as an lb one does (X6, X7): the receiver's first bytes are the hello verbatim, every TLS
// byte after it arrives unchanged in both directions, and MailIngress names the sending address the PROXY line named,
// never the smtpedge host's.
func TestLanSessionSplicesTlsBytesUnchanged(t *testing.T) {
	router := newTestRouter(t, &testRouterOptions{settings: func(settings *mxedgeservice.MxEdgeSettings) {
		settings.LanPort = 2526
		settings.LanSources = []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")}
	}})
	world := serveTestLan(t, router.testEngine)
	client := world.dial(t, "10.20.0.5", testSender)
	client.expect("220 " + testBannerHostName + " ESMTP")
	client.write("EHLO " + testRouteEhlo + "\r\n")
	client.expectEhlo()
	quietAt := router.clock.Now().Add(router.settings.StartTlsQuietTimeout)
	client.write("STARTTLS\r\n")
	router.awaitTimerAt(quietAt)
	router.clock.Advance(router.settings.StartTlsQuietTimeout)
	client.expect("220 2.0.0 Ready to start TLS")
	hello := testRouterHello(testRouteSni, 64)
	client.write(string(hello))
	var receiver *testReceiver
	select {
	case receiver = <-router.dialer.dialing:
	case <-router.ctx.Done():
		t.Fatal("no dial")
	}
	if !bytes.Equal(receiver.request.HelloBytes, hello) {
		t.Errorf("the hello reached the dial as %x", receiver.request.HelloBytes)
	}
	ingress := receiver.ingress
	if !bytes.Equal(ingress.GetSenderIp(), netip.MustParseAddr(testSender).AsSlice()) || ingress.GetSenderPort() != 2525 ||
		ingress.GetSni() != testRouteSni || ingress.GetEhloName() != testRouteEhlo {
		t.Errorf("MailIngress %v", ingress)
	}

	toReceiver := testRouteCapture(100 * 1024)
	go client.conn.Write(toReceiver)
	if got := receiver.readFull(t, len(toReceiver)); !bytes.Equal(got, toReceiver) {
		t.Error("the sender's bytes reached the receiver changed")
	}
	toSender := testRouteCapture(70 * 1024)[3:]
	go receiver.writer.Write(toSender)
	got := make([]byte, len(toSender))
	if _, err := io.ReadFull(client.reader, got); err != nil || !bytes.Equal(got, toSender) {
		t.Errorf("the receiver's bytes reached the sender changed: %v", err)
	}
	receiver.writer.Close()
	client.expectEnd()
	router.service.AwaitSessionCount(0)
	if count := world.lan.RefusedCount(); count != 0 {
		t.Errorf("refused %d", count)
	}
}
