//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-23's direct listener on MAIL-M7-14's session world: a session through MailDirectListener greets, refuses
// plaintext MAIL with 530, takes STARTTLS, then deposits and answers 250 with a MailIngress built locally; a byte behind
// STARTTLS resets; and the caps answer 421 before the greeting.

package sidecar

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/textproto"
	"slices"
	"strings"
	"testing"
)

// A pipe end that reads as a TCP connection from a sender's address.
type mailDirectTestConn struct {
	net.Conn
	remote *net.TCPAddr
}

func (self *mailDirectTestConn) RemoteAddr() net.Addr {
	return self.remote
}

// A direct listener over the session world's receiver and sessions.
func newMailDirectTestListener(t *testing.T, world *mailSessionTestWorld, settings *MailDirectSettings) *MailDirectListener {
	t.Helper()
	listener, err := NewMailDirectListener(&MailDirectListenerArgs{
		Receiver: world.receiver, Sessions: world.server, HostName: "mx.acme.root.example", Clock: world.clock, Settings: settings,
	})
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

// A sender's TCP connection to the listener from address, the listener's end served on its own goroutine.
func dialMailDirectTest(t *testing.T, world *mailSessionTestWorld, listener *MailDirectListener, address string) (net.Conn, chan struct{}) {
	t.Helper()
	senderEnd, listenerEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		listener.serveConn(world.ctx, &mailDirectTestConn{Conn: listenerEnd, remote: &net.TCPAddr{IP: net.ParseIP(address), Port: 40000}})
	}()
	t.Cleanup(func() {
		senderEnd.Close()
		<-done
	})
	return senderEnd, done
}

// A session through the listener: the greeting, plaintext MAIL refused with 530, STARTTLS, then EHLO, the envelope and
// DATA over TLS, deposited and answered 250, the trailer's MailIngress built from the connection.
func TestMailDirectListenerDepositsAndAnswers250(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	listener := newMailDirectTestListener(t, world, nil)
	conn, _ := dialMailDirectTest(t, world, listener, "192.0.2.25")
	plain := textproto.NewConn(conn)
	if code, message, err := plain.ReadResponse(220); err != nil || !strings.Contains(message, "mx.acme.root.example") {
		t.Fatalf("the greeting %d %q: %v", code, message, err)
	}
	command := func(text *textproto.Conn, line string, want int) string {
		t.Helper()
		if err := text.PrintfLine("%s", line); err != nil {
			t.Fatal(err)
		}
		code, message, err := text.ReadResponse(want)
		if err != nil {
			t.Fatalf("%q answered %d %q: %v", line, code, message, err)
		}
		return message
	}
	if message := command(plain, "EHLO out.sender.example", 250); !strings.Contains(message, "STARTTLS") {
		t.Fatalf("EHLO lists no STARTTLS: %q", message)
	}
	command(plain, "MAIL FROM:<bounce@sender.example>", 530)
	command(plain, "STARTTLS", 220)
	tlsConn := tls.Client(conn, &tls.Config{ServerName: testMailReceiverServerName, InsecureSkipVerify: true})
	if err := tlsConn.HandshakeContext(world.ctx); err != nil {
		t.Fatal(err)
	}
	sender := &mailSessionTestSender{t: t, conn: tlsConn, text: textproto.NewConn(tlsConn)}
	sender.envelope(testMailSessionAlice)
	message := testMailSessionMessage("direct")
	codes, messages := sender.data(message)
	if code := <-codes; code != 250 {
		t.Fatalf("reply %d %s", code, <-messages)
	}
	deposits := world.takenDeposits()
	if len(deposits) != 1 || !bytes.Equal(deposits[0].message, message) {
		t.Fatalf("deposits %+v", deposits)
	}
	ingress := deposits[0].trailer.GetIngress()
	if ingress.GetVersion() != mailFormatVersion || !bytes.Equal(ingress.GetSenderIp(), []byte{192, 0, 2, 25}) || ingress.GetSenderPort() != 40000 ||
		ingress.GetSni() != testMailReceiverServerName || ingress.GetEhloName() != "out.sender.example" || ingress.GetPtrName() != "" ||
		len(ingress.GetIpListings()) != 0 || ingress.GetReceiveTimeMillis() == 0 {
		t.Fatalf("the ingress %v", ingress)
	}
	if !slices.Equal(deposits[0].trailer.GetRecipients(), []string{testMailSessionAlice}) {
		t.Fatalf("recipients %v", deposits[0].trailer.GetRecipients())
	}
}

// A byte behind STARTTLS resets the connection with no 220, and a command not of the dialog gets 502.
func TestMailDirectListenerResetsAByteBehindStartTls(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	listener := newMailDirectTestListener(t, world, nil)
	conn, done := dialMailDirectTest(t, world, listener, "192.0.2.26")
	plain := textproto.NewConn(conn)
	if _, _, err := plain.ReadResponse(220); err != nil {
		t.Fatal(err)
	}
	if err := plain.PrintfLine("VRFY someone"); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := plain.ReadResponse(502); code != 502 {
		t.Fatalf("VRFY answered %d", code)
	}
	if err := plain.PrintfLine("EHLO out.sender.example"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := plain.ReadResponse(250); err != nil {
		t.Fatal(err)
	}
	// STARTTLS and a smuggled command in one write
	if _, err := io.WriteString(conn, "STARTTLS\r\nMAIL FROM:<x@sender.example>\r\n"); err != nil {
		t.Fatal(err)
	}
	<-done
	if line, err := plain.ReadLine(); err == nil {
		t.Fatalf("a reply after a smuggled byte: %q", line)
	}
}

// Past the per-sender cap a connection gets 421 before any greeting, while another sender is still served.
func TestMailDirectListenerCapsAnswer421(t *testing.T) {
	world := newMailSessionTestWorld(t, nil)
	settings := DefaultMailDirectSettings()
	settings.SenderSessionCount = 1
	listener := newMailDirectTestListener(t, world, settings)
	first, _ := dialMailDirectTest(t, world, listener, "192.0.2.30")
	if _, _, err := textproto.NewConn(first).ReadResponse(220); err != nil {
		t.Fatal(err)
	}
	second, _ := dialMailDirectTest(t, world, listener, "192.0.2.30")
	if code, _, _ := textproto.NewConn(second).ReadResponse(421); code != 421 {
		t.Fatalf("the second session from one sender answered %d", code)
	}
	other, _ := dialMailDirectTest(t, world, listener, "198.51.100.30")
	if _, _, err := textproto.NewConn(other).ReadResponse(220); err != nil {
		t.Fatalf("another sender: %v", err)
	}
}
