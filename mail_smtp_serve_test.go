//go:build !js && !sidecar_http

// What mailSmtpServe holds. Against a server without the fork's method, as the release fixture links
// upstream go-smtp, it refuses, the peer gets no byte, and the connection does not outlive the call;
// those run on fakes, since in this tree *smtp.Server always has the method. Against the fork, over
// net.Pipe after a real TLS 1.3 handshake: a session starts with no 220 and answers EHLO, advertising
// REQUIRETLS and neither STARTTLS nor AUTH, and Close ends it live (MAIL-M5-02).

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
	"log"
	"math/big"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
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

// A receiver's backend as the session tests need it: every command taken, and no AUTH offered, since
// its sessions are not smtp.AuthSession (§15.5's session advertises no AUTH).
type testMailSmtpBackend struct{}

func (self *testMailSmtpBackend) NewSession(conn *smtp.Conn) (smtp.Session, error) {
	return &testMailSmtpSession{}, nil
}

type testMailSmtpSession struct{}

func (self *testMailSmtpSession) Reset() {}

func (self *testMailSmtpSession) Logout() error {
	return nil
}

func (self *testMailSmtpSession) Mail(from string, options *smtp.MailOptions) error {
	return nil
}

func (self *testMailSmtpSession) Rcpt(to string, options *smtp.RcptOptions) error {
	return nil
}

func (self *testMailSmtpSession) Data(reader io.Reader) error {
	_, err := io.Copy(io.Discard, reader)
	return err
}

// A server as a receiver configures one: REQUIRETLS on, and a TLS config set, so that STARTTLS's
// absence shows the fork read the connection as TLS and not a server with no TLS to offer. Its error
// log writes nothing, since go-smtp's default writes to stderr and a line can name an address (I-13).
func testMailSmtpServer(tlsConfig *tls.Config) *smtp.Server {
	server := smtp.NewServer(&testMailSmtpBackend{})
	server.Domain = "mx.example"
	server.EnableREQUIRETLS = true
	server.TLSConfig = tlsConfig
	server.ErrorLog = log.New(io.Discard, "", 0)
	return server
}

// net.Pipe answers a read after its own Close with io.ErrClosedPipe, where a socket answers
// net.ErrClosed, which go-smtp takes as a session ended on its side. This answers as a socket does.
type testMailSmtpSocket struct {
	net.Conn
}

func (self testMailSmtpSocket) Read(data []byte) (int, error) {
	n, err := self.Conn.Read(data)
	if errors.Is(err, io.ErrClosedPipe) {
		err = net.ErrClosed
	}
	return n, err
}

// Both ends of a finished TLS 1.3 handshake over net.Pipe, as a receiver holds its end after
// tls.Server: the server's end, its config, and the client's end. Session tickets are off, because
// net.Pipe does not buffer and a client that speaks first would not read them.
func mailSmtpServeSessionPipe(t *testing.T) (*tls.Conn, *tls.Config, *tls.Conn) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mx.example"},
		DNSNames:     []string{"mx.example"},
		NotBefore:    mailSmtpServeTestTime.Add(-time.Hour),
		NotAfter:     mailSmtpServeTestTime.Add(time.Hour),
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)

	serverPipe, clientPipe := net.Pipe()
	t.Cleanup(func() {
		serverPipe.Close()
		clientPipe.Close()
	})
	serverConfig := &tls.Config{
		Certificates:           []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: privateKey}},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}
	server := tls.Server(testMailSmtpSocket{Conn: serverPipe}, serverConfig)
	client := tls.Client(clientPipe, &tls.Config{
		RootCAs:    roots,
		ServerName: "mx.example",
		MinVersion: tls.VersionTLS13,
		Time:       func() time.Time { return mailSmtpServeTestTime },
	})
	serverHandshake := make(chan error, 1)
	go func() {
		serverHandshake <- server.Handshake()
	}()
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverHandshake; err != nil {
		t.Fatal(err)
	}
	return server, serverConfig, client
}

// Runs MailSmtpServe in a goroutine and answers what it returns.
func mailSmtpServeGo(server *smtp.Server, conn *tls.Conn) <-chan error {
	served := make(chan error, 1)
	go func() {
		served <- MailSmtpServe(server, conn)
	}()
	return served
}

// Reads conn to its end in a goroutine, as a sender waiting on the receiver does. A tls.Conn's Close
// writes close_notify, which net.Pipe delivers only to a reader.
func mailSmtpServeReadAll(conn io.Reader) <-chan []byte {
	readBytes := make(chan []byte, 1)
	go func() {
		received, _ := io.ReadAll(conn)
		readBytes <- received
	}()
	return readBytes
}

// Sends EHLO and answers the reply's extensions, keyword to parameters.
func mailSmtpServeEhlo(t *testing.T, text *textproto.Conn) map[string]string {
	t.Helper()
	if err := text.PrintfLine("EHLO sender.example"); err != nil {
		t.Fatal(err)
	}
	_, message, err := text.ReadResponse(250)
	if err != nil {
		t.Fatalf("EHLO: %v", err)
	}
	lines := strings.Split(message, "\n")
	if lines[0] != "Hello sender.example" {
		t.Fatalf("EHLO's first line: %q", lines[0])
	}
	extensionParameters := map[string]string{}
	for _, line := range lines[1:] {
		keyword, parameters, _ := strings.Cut(line, " ")
		extensionParameters[keyword] = parameters
	}
	return extensionParameters
}

// RFC 3207 §4.2: after the handshake the client speaks first, so a 220 would be the first line it reads,
// ahead of EHLO's 250.
func TestMailSmtpServeStartsASessionWithNoGreeting(t *testing.T) {
	conn, tlsConfig, client := mailSmtpServeSessionPipe(t)
	served := mailSmtpServeGo(testMailSmtpServer(tlsConfig), conn)

	text := textproto.NewConn(client)
	extensionParameters := mailSmtpServeEhlo(t, text)
	if _, ok := extensionParameters["REQUIRETLS"]; !ok {
		t.Errorf("REQUIRETLS is not advertised: %v", extensionParameters)
	}
	if _, ok := extensionParameters["STARTTLS"]; ok {
		t.Errorf("STARTTLS is advertised after the handshake: %v", extensionParameters)
	}
	if _, ok := extensionParameters["AUTH"]; ok {
		t.Errorf("AUTH is advertised: %v", extensionParameters)
	}

	if err := text.PrintfLine("QUIT"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := text.ReadResponse(221); err != nil {
		t.Fatalf("QUIT: %v", err)
	}
	if received := <-mailSmtpServeReadAll(client); len(received) != 0 {
		t.Fatalf("the client read %q after 221", received)
	}
	if err := <-served; err != nil {
		t.Fatalf("MailSmtpServe: %v", err)
	}
}

// A sender's REQUIRETLS is taken, which needs the session to see the *tls.Conn, and a second STARTTLS
// is refused.
func TestMailSmtpServeSessionSeesTheTlsConn(t *testing.T) {
	conn, tlsConfig, client := mailSmtpServeSessionPipe(t)
	served := mailSmtpServeGo(testMailSmtpServer(tlsConfig), conn)

	text := textproto.NewConn(client)
	mailSmtpServeEhlo(t, text)
	if err := text.PrintfLine("STARTTLS"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := text.ReadResponse(502); err != nil {
		t.Fatalf("STARTTLS: %v", err)
	}
	if err := text.PrintfLine("MAIL FROM:<sender@sender.example> REQUIRETLS"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := text.ReadResponse(250); err != nil {
		t.Fatalf("MAIL with REQUIRETLS: %v", err)
	}

	if err := text.PrintfLine("QUIT"); err != nil {
		t.Fatal(err)
	}
	text.ReadResponse(221)
	<-mailSmtpServeReadAll(client)
	if err := <-served; err != nil {
		t.Fatalf("MailSmtpServe: %v", err)
	}
}

func TestMailSmtpServeEndsOnClose(t *testing.T) {
	conn, tlsConfig, client := mailSmtpServeSessionPipe(t)
	server := testMailSmtpServer(tlsConfig)
	served := mailSmtpServeGo(server, conn)

	text := textproto.NewConn(client)
	mailSmtpServeEhlo(t, text)

	readBytes := mailSmtpServeReadAll(client)
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("MailSmtpServe: %v", err)
	}
	if received := <-readBytes; len(received) != 0 {
		t.Fatalf("the client read %q after Close", received)
	}
	if _, err := conn.Write([]byte("250 OK\r\n")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a write after Close: %v", err)
	}
}

// A closed server's refusal is the fork's, and is not mailSmtpServe's, so a caller can tell a server
// shutting down from one that cannot run a session at all.
func TestMailSmtpServeAnswersAClosedServer(t *testing.T) {
	conn, tlsConfig, client := mailSmtpServeSessionPipe(t)
	server := testMailSmtpServer(tlsConfig)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	readBytes := mailSmtpServeReadAll(client)
	err := MailSmtpServe(server, conn)
	if !errors.Is(err, smtp.ErrServerClosed) || errors.Is(err, errMailSmtpServeRefused) {
		t.Fatalf("MailSmtpServe on a closed server: %v", err)
	}
	if received := <-readBytes; len(received) != 0 {
		t.Fatalf("the client read %q", received)
	}
}

func TestMailSmtpServeRefusesANilServer(t *testing.T) {
	conn, _, client := mailSmtpServeSessionPipe(t)
	readBytes := mailSmtpServeReadAll(client)
	if err := MailSmtpServe(nil, conn); !errors.Is(err, errMailSmtpServeRefused) {
		t.Fatalf("MailSmtpServe(nil): %v", err)
	}
	if received := <-readBytes; len(received) != 0 {
		t.Fatalf("the client read %q", received)
	}
}
