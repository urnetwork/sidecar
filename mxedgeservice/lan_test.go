package mxedgeservice_test

// MAIL-M9-05's LAN listener: only smtpedge's hosts reach it, any other LAN peer closed unanswered, and a LAN session,
// once its PROXY line names the sending address, gets the lb's banner and dialog and spends the same per-sender caps.
// The PROXY line itself is tlsedgeservice's listener's, which the host stacks over this one (server/mxedgehost), so
// here a conn carries the address its line would name.

import (
	"bufio"
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
	engine := newTestEngine(t, &testEngineOptions{settings: settings})
	raw := newTestListener()
	lan, err := mxedgeservice.NewMxLanListener(raw, settings)
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
