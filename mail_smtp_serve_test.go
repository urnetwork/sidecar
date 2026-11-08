//go:build !js && !sidecar_http

// What mailSmtpServe holds without the fork: a server lacking its method refuses, the peer gets no
// byte, and the connection does not outlive the call. A server with that method is a fake here, so
// this proves the assertion and not a session. The rows MAIL-M5-02 names for a live session (no 220,
// EHLO answered, REQUIRETLS advertised, STARTTLS and AUTH not, Close ending it) arrive with the fork.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// The client's clock, so the test certificate is valid whatever day this runs.
var mailSmtpServeTestTime = time.Date(2026, time.November, 6, 0, 0, 0, 0, time.UTC)

// The server's half of a finished handshake over net.Pipe, as a receiver holds it after tls.Server,
// and what the client's half read until its connection ended. A test receives from that channel
// before it returns, which is what joins the client's goroutine.
func mailSmtpServeHandshake(t *testing.T) (*tls.Conn, <-chan []byte) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mx.example"},
		DNSNames:     []string{"mx.example"},
		NotBefore:    mailSmtpServeTestTime.Add(-time.Hour),
		NotAfter:     mailSmtpServeTestTime.Add(time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})
	server := tls.Server(serverConn, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: privateKey}},
		MinVersion:   tls.VersionTLS13,
	})
	client := tls.Client(clientConn, &tls.Config{
		RootCAs:    roots,
		ServerName: "mx.example",
		MinVersion: tls.VersionTLS13,
		Time:       func() time.Time { return mailSmtpServeTestTime },
	})

	readBytes := make(chan []byte, 1)
	go func() {
		// reading on past the handshake takes the server's session tickets, which it writes
		// inside its own handshake and net.Pipe does not buffer
		received, err := io.ReadAll(client)
		if err != nil {
			t.Errorf("client read: %v", err)
		}
		readBytes <- received
	}()
	if err := server.Handshake(); err != nil {
		t.Fatal(err)
	}
	return server, readBytes
}

// A server with the fork's method, as *smtp.Server will have it. Holds the conn it was given and
// answers sessionErr.
type testMailSmtpConnServer struct {
	conn       *tls.Conn
	sessionErr error
}

func (self *testMailSmtpConnServer) ServeTlsConn(conn *tls.Conn) error {
	self.conn = conn
	return self.sessionErr
}

// Upstream's server has Serve and no ServeTlsConn, which is what the release fixture links.
type testMailSmtpUpstreamServer struct{}

func (self *testMailSmtpUpstreamServer) Serve(listener net.Listener) error {
	return nil
}

func TestMailSmtpServeRefusesAServerWithoutTheForksMethod(t *testing.T) {
	for _, server := range []any{&testMailSmtpUpstreamServer{}, nil} {
		conn, readBytes := mailSmtpServeHandshake(t)
		err := mailSmtpServe(server, conn)
		<-readBytes
		if !errors.Is(err, errMailSmtpServeRefused) {
			t.Errorf("mailSmtpServe(%T): %v", server, err)
		}
	}
}

// RFC 3207 §4.2: nothing may follow the handshake unprompted. io.ReadAll ending without error is the
// close_notify, so this also shows the refusal ended the connection in order.
func TestMailSmtpServeRefusalWritesNoByte(t *testing.T) {
	conn, readBytes := mailSmtpServeHandshake(t)
	mailSmtpServe(&testMailSmtpUpstreamServer{}, conn)
	if received := <-readBytes; len(received) != 0 {
		t.Fatalf("the peer read %q", received)
	}
}

func TestMailSmtpServeRefusalClosesTheConnection(t *testing.T) {
	conn, readBytes := mailSmtpServeHandshake(t)
	mailSmtpServe(&testMailSmtpUpstreamServer{}, conn)
	<-readBytes
	if _, err := conn.Write([]byte("220 mx.example\r\n")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a write after the refusal: %v", err)
	}
}

func TestMailSmtpServeRunsAServerWithTheForksMethod(t *testing.T) {
	conn, readBytes := mailSmtpServeHandshake(t)
	server := &testMailSmtpConnServer{}
	err := mailSmtpServe(server, conn)
	<-readBytes
	if err != nil {
		t.Fatalf("mailSmtpServe: %v", err)
	}
	if server.conn != conn {
		t.Fatal("the server did not get the conn")
	}
}

// A session's error is not a refusal, so a caller can tell a server that ran from one that could not.
func TestMailSmtpServeAnswersASessionsError(t *testing.T) {
	conn, readBytes := mailSmtpServeHandshake(t)
	sessionErr := errors.New("session ended")
	err := mailSmtpServe(&testMailSmtpConnServer{sessionErr: sessionErr}, conn)
	<-readBytes
	if !errors.Is(err, sessionErr) || errors.Is(err, errMailSmtpServeRefused) {
		t.Fatalf("mailSmtpServe: %v", err)
	}
}

// The contract holds even for a server that leaves the conn open when its session ends.
func TestMailSmtpServeClosesTheConnectionAfterASession(t *testing.T) {
	conn, readBytes := mailSmtpServeHandshake(t)
	mailSmtpServe(&testMailSmtpConnServer{}, conn)
	<-readBytes
	if _, err := conn.Write([]byte("250 ok\r\n")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a write after the session: %v", err)
	}
}

func TestMailSmtpServeIsOffTheHttpLeg(t *testing.T) {
	buildContext := sidecarHttpBuildContext()
	matched, err := buildContext.MatchFile(".", "mail_smtp_serve.go")
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Error("mail_smtp_serve.go builds on the sidecar_http leg")
	}
}
