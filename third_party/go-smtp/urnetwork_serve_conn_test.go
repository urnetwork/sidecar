package smtp_test

import (
	"context"
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

// The client's clock, so that the test certificate is valid on any day.
var serveConnTestTime = time.Date(2026, time.November, 8, 0, 0, 0, 0, time.UTC)

// A backend whose sessions accept everything and offer no AUTH, since they
// do not implement smtp.AuthSession.
type serveConnBackend struct {
	froms chan string
}

func (be *serveConnBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	return &serveConnSession{backend: be}, nil
}

type serveConnSession struct {
	backend *serveConnBackend
}

func (s *serveConnSession) Reset() {}

func (s *serveConnSession) Logout() error {
	return nil
}

func (s *serveConnSession) Mail(from string, opts *smtp.MailOptions) error {
	if s.backend.froms != nil {
		s.backend.froms <- from
	}
	return nil
}

func (s *serveConnSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	return nil
}

func (s *serveConnSession) Data(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

func serveConnTestServer(be smtp.Backend) *smtp.Server {
	s := smtp.NewServer(be)
	s.Domain = "mx.example"
	s.EnableREQUIRETLS = true
	s.ErrorLog = log.New(io.Discard, "", 0)
	return s
}

// net.Pipe answers a read after its own Close with io.ErrClosedPipe, where a
// socket answers net.ErrClosed, which is what the server takes as a session
// closed on its side. This makes the pipe answer as a socket does.
type serveConnTestSocket struct {
	net.Conn
}

func (c serveConnTestSocket) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if errors.Is(err, io.ErrClosedPipe) {
		err = net.ErrClosed
	}
	return n, err
}

// How long a client waits on the server before it gives up. Only a broken
// server meets it: a server that greets when it must not, or misses a
// close, would otherwise leave a net.Pipe client blocked until the test
// binary's own timeout.
const serveConnTestWatchdog = 2 * time.Minute

// The server's and the client's end of a connection.
func serveConnTestPlainPipe(t *testing.T) (server net.Conn, client net.Conn) {
	t.Helper()

	serverConn, clientConn := net.Pipe()
	t.Cleanup(func() {
		serverConn.Close()
		clientConn.Close()
	})
	clientConn.SetDeadline(time.Now().Add(serveConnTestWatchdog))
	return serveConnTestSocket{serverConn}, clientConn
}

// The two ends of a TLS connection over net.Pipe. The server's end has not
// run its handshake: the client's handshake runs once the server's end
// reads or calls Handshake. Session tickets are off, because net.Pipe does
// not buffer and the client would not read them before it writes.
func serveConnTestPipe(t *testing.T) (server *tls.Conn, client *tls.Conn, serverConfig *tls.Config) {
	t.Helper()

	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mx.example"},
		DNSNames:     []string{"mx.example"},
		NotBefore:    serveConnTestTime.Add(-time.Hour),
		NotAfter:     serveConnTestTime.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)

	serverConfig = &tls.Config{
		Certificates:           []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey}},
		MinVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
	}
	serverConn, clientConn := serveConnTestPlainPipe(t)
	server = tls.Server(serverConn, serverConfig)
	client = tls.Client(clientConn, &tls.Config{
		RootCAs:    roots,
		ServerName: "mx.example",
		MinVersion: tls.VersionTLS13,
		Time:       func() time.Time { return serveConnTestTime },
	})
	return server, client, serverConfig
}

// Runs both handshakes, as a proxy that answered STARTTLS leaves them.
func serveConnTestHandshake(t *testing.T, server *tls.Conn, client *tls.Conn) {
	t.Helper()

	done := serveConnTestGo(server.Handshake)
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// Runs fn in a goroutine and returns what it returns.
func serveConnTestGo(fn func() error) <-chan error {
	result := make(chan error, 1)
	go func() {
		result <- fn()
	}()
	return result
}

// What a read to the end got.
type serveConnTestRead struct {
	data []byte
	err  error
}

// Reads r to its end in a goroutine, as a client that waits on the server
// does. A tls.Conn's Close writes close_notify, which net.Pipe delivers only
// to a reader.
func serveConnTestReadAll(r io.Reader) <-chan serveConnTestRead {
	result := make(chan serveConnTestRead, 1)
	go func() {
		data, err := io.ReadAll(r)
		result <- serveConnTestRead{data, err}
	}()
	return result
}

// Fails unless a read to the end got nothing but its end.
func serveConnTestNothingRead(t *testing.T, read <-chan serveConnTestRead) {
	t.Helper()

	got := <-read
	if len(got.data) != 0 {
		t.Fatalf("the client read %q", got.data)
	}
	if got.err != nil {
		t.Fatalf("the client's read: %v", got.err)
	}
}

// Sends EHLO and returns the reply's extensions, keyword to parameters.
func serveConnTestEhlo(t *testing.T, text *textproto.Conn) map[string]string {
	t.Helper()

	if err := text.PrintfLine("EHLO client.example"); err != nil {
		t.Fatal(err)
	}
	_, message, err := text.ReadResponse(250)
	if err != nil {
		t.Fatalf("EHLO: %v", err)
	}
	lines := strings.Split(message, "\n")
	if lines[0] != "Hello client.example" {
		t.Fatalf("EHLO's first line: %q", lines[0])
	}
	extensions := map[string]string{}
	for _, line := range lines[1:] {
		keyword, parameters, _ := strings.Cut(line, " ")
		extensions[keyword] = parameters
	}
	return extensions
}

// Sends QUIT, and checks that nothing follows the 221.
func serveConnTestQuit(t *testing.T, text *textproto.Conn, client io.Reader) {
	t.Helper()

	if err := text.PrintfLine("QUIT"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := text.ReadResponse(221); err != nil {
		t.Fatalf("QUIT: %v", err)
	}
	serveConnTestNothingRead(t, serveConnTestReadAll(client))
}

func TestUrnetworkServeTlsConnStartsWithoutGreeting(t *testing.T) {
	server, client, serverConfig := serveConnTestPipe(t)
	serveConnTestHandshake(t, server, client)

	s := serveConnTestServer(&serveConnBackend{})
	s.TLSConfig = serverConfig
	result := serveConnTestGo(func() error {
		return s.ServeTlsConn(server)
	})

	// A greeting would be the first line the client reads, before EHLO's.
	text := textproto.NewConn(client)
	extensions := serveConnTestEhlo(t, text)

	if _, ok := extensions["REQUIRETLS"]; !ok {
		t.Errorf("REQUIRETLS is not advertised: %v", extensions)
	}
	if _, ok := extensions["STARTTLS"]; ok {
		t.Errorf("STARTTLS is advertised on a connection that ran it: %v", extensions)
	}
	if _, ok := extensions["AUTH"]; ok {
		t.Errorf("AUTH is advertised by a backend without AuthSession: %v", extensions)
	}

	serveConnTestQuit(t, text, client)
	if err := <-result; err != nil {
		t.Fatalf("ServeTlsConn: %v", err)
	}
}

// The session sees the connection's TLS state, which REQUIRETLS needs, and a
// second STARTTLS is refused.
func TestUrnetworkServeTlsConnKeepsTheTlsConn(t *testing.T) {
	server, client, serverConfig := serveConnTestPipe(t)
	serveConnTestHandshake(t, server, client)

	froms := make(chan string, 1)
	s := serveConnTestServer(&serveConnBackend{froms: froms})
	s.TLSConfig = serverConfig
	result := serveConnTestGo(func() error {
		return s.ServeTlsConn(server)
	})

	text := textproto.NewConn(client)
	serveConnTestEhlo(t, text)

	if err := text.PrintfLine("STARTTLS"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := text.ReadResponse(502); err != nil {
		t.Fatalf("STARTTLS: %v", err)
	}
	if err := text.PrintfLine("MAIL FROM:<sender@client.example> REQUIRETLS"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := text.ReadResponse(250); err != nil {
		t.Fatalf("MAIL with REQUIRETLS: %v", err)
	}
	if from := <-froms; from != "sender@client.example" {
		t.Fatalf("MAIL: %q", from)
	}

	serveConnTestQuit(t, text, client)
	if err := <-result; err != nil {
		t.Fatalf("ServeTlsConn: %v", err)
	}
}

// A connection whose handshake has not run gets it before the session, as
// Serve's TLS connections do, and still no greeting after it.
func TestUrnetworkServeTlsConnRunsAPendingHandshake(t *testing.T) {
	server, client, _ := serveConnTestPipe(t)

	s := serveConnTestServer(&serveConnBackend{})
	result := serveConnTestGo(func() error {
		return s.ServeTlsConn(server)
	})

	text := textproto.NewConn(client)
	extensions := serveConnTestEhlo(t, text)
	if _, ok := extensions["REQUIRETLS"]; !ok {
		t.Errorf("REQUIRETLS is not advertised: %v", extensions)
	}

	serveConnTestQuit(t, text, client)
	if err := <-result; err != nil {
		t.Fatalf("ServeTlsConn: %v", err)
	}
}

func TestUrnetworkServeTlsConnEndsOnClose(t *testing.T) {
	server, client, _ := serveConnTestPipe(t)
	serveConnTestHandshake(t, server, client)

	s := serveConnTestServer(&serveConnBackend{})
	result := serveConnTestGo(func() error {
		return s.ServeTlsConn(server)
	})

	text := textproto.NewConn(client)
	serveConnTestEhlo(t, text)

	read := serveConnTestReadAll(client)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatalf("ServeTlsConn: %v", err)
	}
	serveConnTestNothingRead(t, read)
	if _, err := server.Write([]byte("250 OK\r\n")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a write after Close: %v", err)
	}
}

func TestUrnetworkServeTlsConnHoldsShutdown(t *testing.T) {
	server, client, _ := serveConnTestPipe(t)
	serveConnTestHandshake(t, server, client)

	s := serveConnTestServer(&serveConnBackend{})
	result := serveConnTestGo(func() error {
		return s.ServeTlsConn(server)
	})

	text := textproto.NewConn(client)
	serveConnTestEhlo(t, text)

	shutdown := serveConnTestGo(func() error {
		return s.Shutdown(context.Background())
	})

	// Shutdown has begun once a new connection is refused. One that comes
	// first is served: it greets, and its client then hangs up.
	for {
		probeServer, probeClient := serveConnTestPlainPipe(t)
		probe := serveConnTestGo(func() error {
			return s.ServeConn(probeServer, smtp.ServeConnOptions{})
		})
		greeting := make([]byte, 1)
		probeClient.Read(greeting)
		probeClient.Close()
		if errors.Is(<-probe, smtp.ErrServerClosed) {
			break
		}
	}

	// The live session still answers, and holds Shutdown.
	if err := text.PrintfLine("NOOP"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := text.ReadResponse(250); err != nil {
		t.Fatalf("NOOP during Shutdown: %v", err)
	}
	select {
	case err := <-shutdown:
		t.Fatalf("Shutdown returned with a live session: %v", err)
	default:
	}

	serveConnTestQuit(t, text, client)
	if err := <-result; err != nil {
		t.Fatalf("ServeTlsConn: %v", err)
	}
	if err := <-shutdown; err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestUrnetworkServeConnRefusesAfterClose(t *testing.T) {
	server, client, _ := serveConnTestPipe(t)
	serveConnTestHandshake(t, server, client)

	s := serveConnTestServer(&serveConnBackend{})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	read := serveConnTestReadAll(client)
	if err := s.ServeTlsConn(server); !errors.Is(err, smtp.ErrServerClosed) {
		t.Fatalf("ServeTlsConn after Close: %v", err)
	}
	serveConnTestNothingRead(t, read)
}

func TestUrnetworkServeConnRefusesAfterStartTlsOnAPlainConn(t *testing.T) {
	server, client := serveConnTestPlainPipe(t)

	s := serveConnTestServer(&serveConnBackend{})
	read := serveConnTestReadAll(client)
	err := s.ServeConn(server, smtp.ServeConnOptions{AfterStartTls: true})
	if !errors.Is(err, smtp.ErrServeConnNotTls) {
		t.Fatalf("ServeConn: %v", err)
	}
	serveConnTestNothingRead(t, read)
}

// Without AfterStartTls, a connection is served as Serve serves it.
func TestUrnetworkServeConnGreetsWithoutAfterStartTls(t *testing.T) {
	server, client := serveConnTestPlainPipe(t)

	s := serveConnTestServer(&serveConnBackend{})
	result := serveConnTestGo(func() error {
		return s.ServeConn(server, smtp.ServeConnOptions{})
	})

	text := textproto.NewConn(client)
	if _, message, err := text.ReadResponse(220); err != nil || !strings.HasPrefix(message, "mx.example ESMTP") {
		t.Fatalf("greeting: %q %v", message, err)
	}
	extensions := serveConnTestEhlo(t, text)
	if _, ok := extensions["REQUIRETLS"]; ok {
		t.Errorf("REQUIRETLS is advertised on a plain connection: %v", extensions)
	}

	serveConnTestQuit(t, text, client)
	if err := <-result; err != nil {
		t.Fatalf("ServeConn: %v", err)
	}
}
