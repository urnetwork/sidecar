//go:build !js && !sidecar_http

// What mailSmtpServe holds while plan-MAIL-go-smtp-fork is unanswered: a session is refused, the peer
// gets no byte, and the connection does not outlive the call. The rows MAIL-M5-02 names for a live
// session (no 220, EHLO answered, REQUIRETLS advertised, STARTTLS and AUTH not, Close ending it) need
// ServeConn, so they arrive with it.

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

func TestMailSmtpServeRefusesAHandshakenConnection(t *testing.T) {
	server, readBytes := mailSmtpServeHandshake(t)
	err := mailSmtpServe(server)
	<-readBytes
	if !errors.Is(err, errMailSmtpServeRefused) {
		t.Fatalf("mailSmtpServe: %v", err)
	}
}

// RFC 3207 §4.2: nothing may follow the handshake unprompted. io.ReadAll ending without error is the
// close_notify, so this also shows the refusal ended the connection in order.
func TestMailSmtpServeRefusalWritesNoByte(t *testing.T) {
	server, readBytes := mailSmtpServeHandshake(t)
	mailSmtpServe(server)
	if received := <-readBytes; len(received) != 0 {
		t.Fatalf("the peer read %q", received)
	}
}

func TestMailSmtpServeRefusalClosesTheConnection(t *testing.T) {
	server, readBytes := mailSmtpServeHandshake(t)
	mailSmtpServe(server)
	<-readBytes
	if _, err := server.Write([]byte("220 mx.example\r\n")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a write after the refusal: %v", err)
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
