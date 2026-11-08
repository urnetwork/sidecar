// The four handshake parsers the client and the edge share, fuzzed together over a stream of
// handshake messages: a bug in them is on both sides of the trust boundary. Each input is also split
// at every offset, as records may fragment it, and every ClientHello both sides accept is compared
// with what crypto/tls's server read from the same octets. The seeds in testdata/fuzz/FuzzTlsParse are
// real flights, written by TestWriteTlsParseCorpus.

package smtpproof

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Every whole message a stream holds, and what is left over, when records split it at offset.
func testSplitHandshake(stream []byte, offset int) ([][]byte, []byte) {
	var buffer tlsHandshakeBuffer
	var messages [][]byte
	drain := func() {
		for {
			message := buffer.next()
			if message == nil {
				return
			}
			messages = append(messages, bytes.Clone(message))
		}
	}
	buffer.add(stream[:offset])
	drain()
	buffer.add(stream[offset:])
	drain()
	return messages, buffer.pending
}

// What crypto/tls's server reads from a ClientHello message, or false if it refuses the message.
func testCryptoTlsReadsClientHello(t *testing.T, message []byte) (*tls.ClientHelloInfo, bool) {
	t.Helper()
	clientConn, serverConn := testPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	for offset := 0; offset < len(message); offset += tlsMaxPlaintextBytes {
		clientConn.Write(tlsFrameRecord(tlsRecordHandshake, 0x0301, message[offset:min(offset+tlsMaxPlaintextBytes, len(message))]))
	}
	// the server reads what was written and then end of stream, so a message it waits on cannot hang it
	clientConn.writeStream.close()
	var info *tls.ClientHelloInfo
	server := tls.Server(serverConn, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			info = hello
			return nil, errors.New("read")
		},
	})
	server.Handshake()
	return info, info != nil
}

// Where both parsers take a ClientHello, they must read the fields E1 decides on alike: an MX on
// crypto/tls reading another name or suite than the edge did is the attack E1's SNI check stops.
func testExpectClientHelloAsCryptoTls(t *testing.T, message []byte, hello *tlsClientHello) {
	t.Helper()
	info, ok := testCryptoTlsReadsClientHello(t, message)
	if !ok {
		return
	}
	if info.ServerName != hello.serverName {
		t.Errorf("server name %q, crypto/tls read %q", hello.serverName, info.ServerName)
	}
	if !slices.Equal(info.CipherSuites, hello.suites) {
		t.Errorf("suites %x, crypto/tls read %x", hello.suites, info.CipherSuites)
	}
	if !slices.Equal(info.Extensions, hello.extensionIds) {
		t.Errorf("extensions %v, crypto/tls read %v", hello.extensionIds, info.Extensions)
	}
}

func FuzzTlsParse(f *testing.F) {
	f.Add([]byte{tlsHandshakeClientHello, 0, 0, 2, 3, 3})
	f.Add([]byte{tlsHandshakeServerHello, 0, 0, 0, tlsHandshakeCertificate, 0, 0, 4, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, stream []byte) {
		messages, pending := testSplitHandshake(stream, len(stream))
		// every offset for a short stream; past that a spread of them, so one input stays cheap
		step := max(1, len(stream)/512)
		for offset := 0; offset <= len(stream); offset += step {
			split, splitPending := testSplitHandshake(stream, offset)
			if !slices.EqualFunc(split, messages, bytes.Equal) || !bytes.Equal(splitPending, pending) {
				t.Fatalf("split at %d gives other messages", offset)
			}
		}
		for _, message := range messages {
			body := message[4:]
			switch message[0] {
			case tlsHandshakeClientHello:
				if hello, err := tlsParseClientHello(body); err == nil {
					testExpectClientHelloAsCryptoTls(t, message, hello)
				}
			case tlsHandshakeServerHello:
				tlsParseServerHello(body)
			case tlsHandshakeCertificate:
				tlsParseCertificate(tlsVersion13, body)
				tlsParseCertificate(tlsVersion12, body)
			case tlsHandshakeServerKeyExchange:
				tlsParseServerKeyExchange(body)
			}
		}
		// and each parser over the raw octets, which the buffer may never frame as a message
		tlsParseClientHello(stream)
		tlsParseServerHello(stream)
		tlsParseCertificate(tlsVersion13, stream)
		tlsParseCertificate(tlsVersion12, stream)
		tlsParseServerKeyExchange(stream)
	})
}

// The handshake payloads of one direction of a trace, in order: what FuzzTlsParse takes.
func testHandshakeStream(trace []*testTraceEntry, fromClient bool) []byte {
	var stream []byte
	for _, entry := range trace {
		if entry.record != nil && entry.fromClient == fromClient && entry.record[0] == tlsRecordHandshake {
			stream = append(stream, entry.record[tlsRecordHeaderBytes:]...)
		}
	}
	return stream
}

func TestTlsParseReadsWhatCryptoTlsNegotiated(t *testing.T) {
	// a real handshake per leg: the ClientHello as crypto/tls's server read it, and the ServerHello as
	// that server wrote it, version and suite from its own connection state
	for _, leg := range testTlsLegs() {
		send := testRunSend(t, leg, testMxDefaults(), DefaultProverSettings(), testJob("a body line\r\n", "bob"))
		testExpectOneTransaction(t, leg, send, testJob("a body line\r\n", "bob"))
		clientMessages, _ := testSplitHandshake(testHandshakeStream(send.edge.trace, true), 0)
		if len(clientMessages) == 0 || clientMessages[0][0] != tlsHandshakeClientHello {
			t.Fatalf("%s: no ClientHello in the trace", leg.name)
		}
		hello, err := tlsParseClientHello(clientMessages[0][4:])
		if err != nil {
			t.Fatalf("%s: %v", leg.name, err)
		}
		if _, ok := testCryptoTlsReadsClientHello(t, clientMessages[0]); !ok {
			t.Fatalf("%s: crypto/tls refused this client's hello", leg.name)
		}
		testExpectClientHelloAsCryptoTls(t, clientMessages[0], hello)

		serverMessages, _ := testSplitHandshake(testHandshakeStream(send.edge.trace, false), 0)
		serverHello, err := tlsParseServerHello(serverMessages[0][4:])
		if err != nil {
			t.Fatalf("%s: %v", leg.name, err)
		}
		state := send.edge.session
		state.stateLock.Lock()
		version, suite := state.version, state.suite
		state.stateLock.Unlock()
		if serverHello.version != version || serverHello.suite != suite {
			t.Errorf("%s: parsed %#x %#x, the gate holds %#x %#x", leg.name, serverHello.version, serverHello.suite, version, suite)
		}
		if leg.suites[0] != suite {
			t.Errorf("%s: crypto/tls chose %#x", leg.name, suite)
		}
	}
}

func TestTlsParseFindsNoDifferenceOverItsCorpus(t *testing.T) {
	// the committed corpus runs as FuzzTlsParse's seeds too; this says it is there, so a lost directory
	// does not pass silently
	entries, err := os.ReadDir(filepath.Join("testdata", "fuzz", "FuzzTlsParse"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 6 {
		t.Errorf("%d seeds", len(entries))
	}
}

// Writes FuzzTlsParse's seeds from real flights: every leg's ClientHello, its server's clear flight,
// a retried handshake, a 1.3 Certificate and a 1.2 flight asking for a client certificate. Set
// SMTPPROOF_WRITE_CORPUS to rewrite them.
func TestWriteTlsParseCorpus(t *testing.T) {
	if os.Getenv("SMTPPROOF_WRITE_CORPUS") == "" {
		t.Skip("set SMTPPROOF_WRITE_CORPUS to rewrite testdata/fuzz/FuzzTlsParse")
	}
	directory := filepath.Join("testdata", "fuzz", "FuzzTlsParse")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name string, stream []byte) {
		content := "go test fuzz v1\n[]byte(" + strconv.Quote(string(stream)) + ")\n"
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, leg := range testTlsLegs() {
		fixture := testBdatGateCapture(t, leg)
		name := strings.ReplaceAll(leg.name, " ", "-")
		write(name+"-client", testHandshakeStream(fixture.trace, true))
		write(name+"-server", testHandshakeStream(fixture.trace, false))
	}

	// a retry: both ClientHellos, and the HelloRetryRequest with the ServerHello after it
	retry := testRecordedHandshake(t, &tls.Config{
		Certificates:     []tls.Certificate{testEcdsaCertificate(t)},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}, testClientSettings())
	write("tls13-retry-client", retry.clientStream)
	write("tls13-retry-server", retry.serverStream)

	// 1.3's Certificate travels encrypted, so it is built here as the flight holds it
	certificate := testEcdsaCertificate(t).Certificate[0]
	entry := []byte{0}
	list := append([]byte{byte(len(certificate) >> 16), byte(len(certificate) >> 8), byte(len(certificate))}, certificate...)
	list = append(list, 0, 0)
	entry = append(entry, byte(len(list)>>16), byte(len(list)>>8), byte(len(list)))
	entry = append(entry, list...)
	write("tls13-certificate", tlsHandshakeMessage(tlsHandshakeCertificate, entry))

	requested := testRecordedHandshake(t, &tls.Config{
		Certificates: []tls.Certificate{testRsaCertificate(t)},
		MaxVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequestClientCert,
	}, testClientSettings())
	write("tls12-certificate-request-server", requested.serverStream)
	t.Logf("wrote %s", directory)
}

// A handshake's two directions as the wire carried them, handshake payloads only.
type testRecordedFlights struct {
	clientStream []byte
	serverStream []byte
}

// A connection whose two directions are copied as they pass, so the flights can be read back.
type testRecordingConn struct {
	*testConn
	read []byte
}

func (self *testRecordingConn) Read(buffer []byte) (int, error) {
	size, err := self.testConn.Read(buffer)
	self.read = append(self.read, buffer[:size]...)
	return size, err
}

// The handshake payloads of a run of whole records.
func testRecordPayloads(raw []byte) []byte {
	var stream []byte
	for tlsRecordHeaderBytes <= len(raw) {
		size := tlsRecordHeaderBytes + (int(raw[3])<<8 | int(raw[4]))
		if len(raw) < size {
			break
		}
		if raw[0] == tlsRecordHandshake {
			stream = append(stream, raw[tlsRecordHeaderBytes:size]...)
		}
		raw = raw[size:]
	}
	return stream
}

func testRecordedHandshake(t *testing.T, serverConfig *tls.Config, settings *tlsClientSettings) *testRecordedFlights {
	t.Helper()
	clientConn, serverConn := testPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	recordingClient := &testRecordingConn{testConn: clientConn}
	recordingServer := &testRecordingConn{testConn: serverConn}
	server := tls.Server(recordingServer, serverConfig)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Handshake()
	}()
	client := newTlsClient(recordingClient, settings)
	if _, err := client.handshake(t.Context()); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	// only the clear part of each flight is handshake records; 1.3's encrypted rest is application data
	return &testRecordedFlights{
		clientStream: testRecordPayloads(recordingServer.read),
		serverStream: testRecordPayloads(recordingClient.read),
	}
}

func TestRecordedFlightsHoldTheHellos(t *testing.T) {
	flights := testRecordedHandshake(t, &tls.Config{Certificates: []tls.Certificate{testEcdsaCertificate(t)}, MaxVersion: tls.VersionTLS12}, testClientSettings())
	client, _ := testSplitHandshake(flights.clientStream, 0)
	server, _ := testSplitHandshake(flights.serverStream, 0)
	var types []string
	for _, message := range server {
		types = append(types, fmt.Sprint(message[0]))
	}
	if len(client) < 2 || client[0][0] != tlsHandshakeClientHello || len(server) < 4 || server[0][0] != tlsHandshakeServerHello {
		t.Errorf("client %d messages, server types %v", len(client), types)
	}
}
