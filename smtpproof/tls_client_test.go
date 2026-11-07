// Proves the client against an independent peer. Go's crypto/tls server is the oracle: its
// KeyLogWriter prints the traffic secrets it derived, so these tests show that the HS and master
// secret this client exports regenerate exactly what the real peer computed.

package smtpproof

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const testMxHost = "mx.recipient.example"

// One direction of a buffered in-memory stream. net.Pipe is unbuffered, which TCP and the spliced
// stream are not: a peer writing while the other also writes would deadlock there and only there.
type testStream struct {
	stateLock sync.Mutex
	monitor   *sync.Cond
	pending   []byte
	closed    bool
	deadline  time.Time
}

func newTestStream() *testStream {
	stream := &testStream{}
	stream.monitor = sync.NewCond(&stream.stateLock)
	return stream
}

func (self *testStream) write(data []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return 0, io.ErrClosedPipe
	}
	self.pending = append(self.pending, data...)
	self.monitor.Broadcast()
	return len(data), nil
}

func (self *testStream) read(buffer []byte) (int, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for len(self.pending) == 0 {
		if self.closed {
			return 0, io.EOF
		}
		if !self.deadline.IsZero() && !time.Now().Before(self.deadline) {
			return 0, os.ErrDeadlineExceeded
		}
		self.monitor.Wait()
	}
	size := copy(buffer, self.pending)
	self.pending = self.pending[size:]
	return size, nil
}

func (self *testStream) close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	self.monitor.Broadcast()
}

// Only a deadline already in the past is honored, which is how tlsClient cancels: tests here run on
// barriers and channels, never on a timer.
func (self *testStream) setDeadline(deadline time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.deadline = deadline
	self.monitor.Broadcast()
}

// One end of a buffered connection.
type testConn struct {
	readStream  *testStream
	writeStream *testStream
}

func (self *testConn) Read(buffer []byte) (int, error)  { return self.readStream.read(buffer) }
func (self *testConn) Write(data []byte) (int, error)   { return self.writeStream.write(data) }
func (self *testConn) LocalAddr() net.Addr              { return &net.IPAddr{} }
func (self *testConn) RemoteAddr() net.Addr             { return &net.IPAddr{} }
func (self *testConn) SetReadDeadline(time.Time) error  { return nil }
func (self *testConn) SetWriteDeadline(time.Time) error { return nil }

func (self *testConn) Close() error {
	self.readStream.close()
	self.writeStream.close()
	return nil
}

func (self *testConn) SetDeadline(deadline time.Time) error {
	self.readStream.setDeadline(deadline)
	return nil
}

func testPipe() (*testConn, *testConn) {
	clientToServer := newTestStream()
	serverToClient := newTestStream()
	return &testConn{readStream: serverToClient, writeStream: clientToServer},
		&testConn{readStream: clientToServer, writeStream: serverToClient}
}

// A self-signed certificate for the test MX, under a generated key.
func testCertificate(t *testing.T, key crypto.Signer) tls.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: testMxHost},
		DNSNames:     []string{testMxHost},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func testEcdsaCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate(t, key)
}

func testRsaCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate(t, key)
}

func testEd25519Certificate(t *testing.T) tls.Certificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testCertificate(t, key)
}

func testVerifyAny(chain []*x509.Certificate) error {
	return nil
}

func testClientSettings() *tlsClientSettings {
	settings := defaultTlsClientSettings()
	settings.serverName = testMxHost
	settings.verifyPeer = testVerifyAny
	return settings
}

// A connected client and crypto/tls server, with the server's key log.
type testTlsPair struct {
	client    *tlsClient
	result    *tlsHandshakeResult
	server    *tls.Conn
	serverLog *bytes.Buffer
}

func (self *testTlsPair) logged(t *testing.T, label string) []byte {
	t.Helper()
	for _, line := range strings.Split(self.serverLog.String(), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == label {
			secret, err := hex.DecodeString(fields[2])
			if err != nil {
				t.Fatal(err)
			}
			return secret
		}
	}
	t.Fatalf("server logged no %s", label)
	return nil
}

func testHandshake(t *testing.T, serverConfig *tls.Config, settings *tlsClientSettings) *testTlsPair {
	t.Helper()
	clientConn, serverConn := testPipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})
	pair := &testTlsPair{serverLog: &bytes.Buffer{}}
	serverConfig.KeyLogWriter = pair.serverLog
	pair.server = tls.Server(serverConn, serverConfig)
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- pair.server.Handshake()
	}()
	pair.client = newTlsClient(clientConn, settings)
	result, err := pair.client.handshake(context.Background())
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	pair.result = result
	return pair
}

// Proves application data flows both ways through sealed records, at the sequence numbers given.
func testExchange(t *testing.T, pair *testTlsPair, firstSeq uint64) {
	t.Helper()
	sealed, err := pair.client.sealApplication([]byte("EHLO sender.example\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if sealed.seq != firstSeq {
		t.Errorf("client seq %d, want %d", sealed.seq, firstSeq)
	}
	received := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 64)
		size, _ := pair.server.Read(buffer)
		pair.server.Write([]byte("250 mx.recipient.example\r\n"))
		received <- buffer[:size]
	}()
	if err := pair.client.writeSealed(sealed); err != nil {
		t.Fatal(err)
	}
	record, err := pair.client.readRecord(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := <-received; string(got) != "EHLO sender.example\r\n" {
		t.Errorf("server read %q", got)
	}
	if string(record.content) != "250 mx.recipient.example\r\n" {
		t.Errorf("client read %q", record.content)
	}
	if record.seq != firstSeq {
		t.Errorf("server seq %d, want %d", record.seq, firstSeq)
	}
	if record.recordType != tlsRecordApplicationData {
		t.Errorf("record type %d", record.recordType)
	}
}

func TestTlsClient13ExportsTheHsThatRegeneratesEveryTrafficSecret(t *testing.T) {
	cases := []struct {
		certificate func(*testing.T) tls.Certificate
		suite       uint16
	}{
		{certificate: testEcdsaCertificate, suite: tlsSuiteAes128GcmSha256},
		{certificate: testRsaCertificate, suite: tlsSuiteAes128GcmSha256},
		{certificate: testEd25519Certificate, suite: tlsSuiteChacha20Poly1305Sha256},
	}
	for _, c := range cases {
		settings := testClientSettings()
		settings.suites = []uint16{c.suite}
		pair := testHandshake(t, &tls.Config{
			Certificates: []tls.Certificate{c.certificate(t)},
			MinVersion:   tls.VersionTLS13,
		}, settings)
		result := pair.result
		if result.version != tlsVersion13 || result.suite != c.suite {
			t.Fatalf("negotiated %#x %#x", result.version, result.suite)
		}

		// from HS and the two public hashes alone, as Z1 derives them
		shts := tls13TrafficSecret(result.handshakeSecret, "s hs traffic", result.helloHash)
		if !bytes.Equal(shts, pair.logged(t, "SERVER_HANDSHAKE_TRAFFIC_SECRET")) {
			t.Errorf("suite %#x: SHTS from HS differs from the server's", c.suite)
		}
		if !bytes.Equal(shts, result.shts) {
			t.Errorf("suite %#x: disclosed SHTS differs from HS's", c.suite)
		}
		chts := tls13TrafficSecret(result.handshakeSecret, "c hs traffic", result.helloHash)
		if !bytes.Equal(chts, pair.logged(t, "CLIENT_HANDSHAKE_TRAFFIC_SECRET")) {
			t.Errorf("suite %#x: CHTS from HS differs from the server's", c.suite)
		}
		masterSecret := tls13MasterSecret(result.handshakeSecret)
		cats := tls13TrafficSecret(masterSecret, "c ap traffic", result.finishedHash)
		if !bytes.Equal(cats, pair.logged(t, "CLIENT_TRAFFIC_SECRET_0")) {
			t.Errorf("suite %#x: CATS from HS differs from the server's", c.suite)
		}
		sats := tls13TrafficSecret(masterSecret, "s ap traffic", result.finishedHash)
		if !bytes.Equal(sats, pair.logged(t, "SERVER_TRAFFIC_SECRET_0")) {
			t.Errorf("suite %#x: SATS from HS differs from the server's", c.suite)
		}
		clientKey, clientIv := tls13TrafficKeys(c.suite, cats)
		if !bytes.Equal(clientKey, result.clientKey) || !bytes.Equal(clientIv, result.clientIv) {
			t.Errorf("suite %#x: client key differs from CATS's", c.suite)
		}
		testExchange(t, pair, 0)
	}
}

func TestTlsClient12ExportsTheServersMasterSecret(t *testing.T) {
	cases := []struct {
		certificate func(*testing.T) tls.Certificate
		suite       uint16
	}{
		{certificate: testEcdsaCertificate, suite: tlsSuiteEcdheEcdsaAes128GcmSha256},
		{certificate: testRsaCertificate, suite: tlsSuiteEcdheRsaAes128GcmSha256},
	}
	for _, c := range cases {
		pair := testHandshake(t, &tls.Config{
			Certificates: []tls.Certificate{c.certificate(t)},
			MaxVersion:   tls.VersionTLS12,
		}, testClientSettings())
		result := pair.result
		if result.version != tlsVersion12 || result.suite != c.suite {
			t.Fatalf("negotiated %#x %#x", result.version, result.suite)
		}
		if !bytes.Equal(result.masterSecret, pair.logged(t, "CLIENT_RANDOM")) {
			t.Errorf("suite %#x: master secret differs from the server's", c.suite)
		}
		// the client's Finished took sequence number 0
		testExchange(t, pair, 1)
	}
}

func TestTlsClientFollowsHelloRetryRequest(t *testing.T) {
	pair := testHandshake(t, &tls.Config{
		Certificates:     []tls.Certificate{testEcdsaCertificate(t)},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.CurveP256},
	}, testClientSettings())
	// H_sh includes the retry: a wrong transcript would fail this comparison and the handshake
	shts := tls13TrafficSecret(pair.result.handshakeSecret, "s hs traffic", pair.result.helloHash)
	if !bytes.Equal(shts, pair.logged(t, "SERVER_HANDSHAKE_TRAFFIC_SECRET")) {
		t.Error("SHTS after a retry differs from the server's")
	}
	testExchange(t, pair, 0)
}

func TestTlsClientAnswersCertificateRequest(t *testing.T) {
	for _, maxVersion := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		pair := testHandshake(t, &tls.Config{
			Certificates: []tls.Certificate{testEcdsaCertificate(t)},
			MaxVersion:   maxVersion,
			ClientAuth:   tls.RequestClientCert,
		}, testClientSettings())
		firstSeq := uint64(0)
		if maxVersion == tls.VersionTLS12 {
			firstSeq = 1
		}
		testExchange(t, pair, firstSeq)
	}
}

func TestTlsClientOffersNothingThatInvitesATicket(t *testing.T) {
	// tickets stay enabled on the server, which still sends none: the hello omits
	// psk_key_exchange_modes, so the first record after the handshake is the reply itself
	pair := testHandshake(t, &tls.Config{
		Certificates: []tls.Certificate{testEcdsaCertificate(t)},
		MinVersion:   tls.VersionTLS13,
	}, testClientSettings())
	testExchange(t, pair, 0)
}

func TestTlsClientHelloMeetsE1(t *testing.T) {
	clientConn, serverConn := testPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	client := newTlsClient(clientConn, testClientSettings())
	go client.handshake(context.Background())

	header := make([]byte, tlsRecordHeaderBytes)
	if _, err := io.ReadFull(serverConn, header); err != nil {
		t.Fatal(err)
	}
	if header[0] != tlsRecordHandshake {
		t.Fatalf("first record type %d", header[0])
	}
	payload := make([]byte, int(header[3])<<8|int(header[4]))
	if _, err := io.ReadFull(serverConn, payload); err != nil {
		t.Fatal(err)
	}
	hello, err := tlsParseClientHello(payload[4:])
	if err != nil {
		t.Fatal(err)
	}
	if hello.serverName != testMxHost {
		t.Errorf("sni %q", hello.serverName)
	}
	if len(hello.sessionId) != 0 {
		t.Errorf("session id %x", hello.sessionId)
	}
	const pskKeyExchangeModes = 45
	for _, extensionId := range []uint16{tlsExtensionPreSharedKey, tlsExtensionEarlyData, tlsExtensionSessionTicket, pskKeyExchangeModes} {
		if hello.hasExtension(extensionId) {
			t.Errorf("hello offers extension %d", extensionId)
		}
	}
	for _, suite := range hello.suites {
		if !tlsSuiteCovered(tlsVersion13, suite) && !tlsSuiteCovered(tlsVersion12, suite) {
			t.Errorf("hello offers uncovered suite %#x", suite)
		}
	}
}

func TestTlsClientFailsClosedWithoutAVerifier(t *testing.T) {
	clientConn, serverConn := testPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	settings := testClientSettings()
	settings.verifyPeer = nil
	if _, err := newTlsClient(clientConn, settings).handshake(context.Background()); err == nil {
		t.Fatal("handshake ran with no peer verifier")
	}
}

func TestTlsClientRefusesWhatTheVerifierRefuses(t *testing.T) {
	refusal := errors.New("synthetic refusal")
	for _, maxVersion := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		clientConn, serverConn := testPipe()
		defer clientConn.Close()
		defer serverConn.Close()
		server := tls.Server(serverConn, &tls.Config{
			Certificates: []tls.Certificate{testEcdsaCertificate(t)},
			MaxVersion:   maxVersion,
		})
		go server.Handshake()
		settings := testClientSettings()
		settings.verifyPeer = func(chain []*x509.Certificate) error {
			return refusal
		}
		_, err := newTlsClient(clientConn, settings).handshake(context.Background())
		if !errors.Is(err, refusal) {
			t.Errorf("version %#x: err %v", maxVersion, err)
		}
	}
}

// Flips one octet of what the server sends, past a given offset, to prove nothing tampered with
// survives to the end of a handshake.
type testFlipConn struct {
	net.Conn
	stateLock sync.Mutex
	offset    int
}

func (self *testFlipConn) Read(buffer []byte) (int, error) {
	size, err := self.Conn.Read(buffer)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 <= self.offset && self.offset < size {
		buffer[self.offset] ^= 0x01
	}
	self.offset -= size
	return size, err
}

func TestTlsClientRefusesATamperedFlight(t *testing.T) {
	// offsets land past the ServerHello, inside the flight
	for _, maxVersion := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, offset := range []int{200, 300, 400} {
			clientConn, serverConn := testPipe()
			defer clientConn.Close()
			defer serverConn.Close()
			server := tls.Server(serverConn, &tls.Config{
				Certificates: []tls.Certificate{testEcdsaCertificate(t)},
				MaxVersion:   maxVersion,
			})
			go server.Handshake()
			client := newTlsClient(&testFlipConn{Conn: clientConn, offset: offset}, testClientSettings())
			if _, err := client.handshake(context.Background()); err == nil {
				t.Errorf("version %#x offset %d: tampered handshake succeeded", maxVersion, offset)
			}
		}
	}
}

// A scripted server: reads the hello, then writes whatever the test says.
func testScriptedServerHello(t *testing.T, serverConn net.Conn, helloBody []byte) {
	t.Helper()
	header := make([]byte, tlsRecordHeaderBytes)
	if _, err := io.ReadFull(serverConn, header); err != nil {
		t.Error(err)
		return
	}
	if _, err := io.ReadFull(serverConn, make([]byte, int(header[3])<<8|int(header[4]))); err != nil {
		t.Error(err)
		return
	}
	message := tlsHandshakeMessage(tlsHandshakeServerHello, helloBody)
	if _, err := serverConn.Write(tlsFrameRecord(tlsRecordHandshake, tlsVersion12, message)); err != nil {
		t.Error(err)
	}
}

func testServerHelloBody(random []byte, suite uint16, extensions []byte) []byte {
	body := []byte{0x03, 0x03}
	body = append(body, random...)
	body = append(body, 0, byte(suite>>8), byte(suite), 0)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	return append(body, extensions...)
}

func TestTlsClientRefusesTheDowngradeSentinel(t *testing.T) {
	random := make([]byte, tlsRandomBytes)
	copy(random[tlsRandomBytes-len(tlsDowngrade12):], tlsDowngrade12)
	clientConn, serverConn := testPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go testScriptedServerHello(t, serverConn, testServerHelloBody(random, tlsSuiteEcdheRsaAes128GcmSha256, nil))
	_, err := newTlsClient(clientConn, testClientSettings()).handshake(context.Background())
	if err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("err %v", err)
	}
}

func TestTlsClientRefusesAnUncoveredSuite(t *testing.T) {
	const tlsSuiteAes256GcmSha384 = 0x1302
	supportedVersions := []byte{0, 43, 0, 2, 0x03, 0x04}
	clientConn, serverConn := testPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	go testScriptedServerHello(t, serverConn, testServerHelloBody(make([]byte, tlsRandomBytes), tlsSuiteAes256GcmSha384, supportedVersions))
	_, err := newTlsClient(clientConn, testClientSettings()).handshake(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not covered") {
		t.Fatalf("err %v", err)
	}
}

func TestTlsClientHonorsCancellation(t *testing.T) {
	clientConn, serverConn := testPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	ctx, cancel := context.WithCancel(context.Background())
	// the server reads the hello and then says nothing, so the client blocks in its read
	go func() {
		header := make([]byte, tlsRecordHeaderBytes)
		io.ReadFull(serverConn, header)
		io.ReadFull(serverConn, make([]byte, int(header[3])<<8|int(header[4])))
		cancel()
	}()
	_, err := newTlsClient(clientConn, testClientSettings()).handshake(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
}

func TestTlsCipherRefusesARecordFromAnotherSequenceNumber(t *testing.T) {
	key := bytes.Repeat([]byte{7}, tlsAes128KeyBytes)
	cases := []struct {
		version uint16
		suite   uint16
		iv      []byte
	}{
		{version: tlsVersion13, suite: tlsSuiteAes128GcmSha256, iv: make([]byte, tlsIv13Bytes)},
		{version: tlsVersion12, suite: tlsSuiteEcdheRsaAes128GcmSha256, iv: make([]byte, tlsSalt12Bytes)},
	}
	for _, c := range cases {
		sender, err := newTlsCipher(c.version, c.suite, key, c.iv)
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := newTlsCipher(c.version, c.suite, key, c.iv)
		if err != nil {
			t.Fatal(err)
		}
		first, err := sender.seal(tlsRecordApplicationData, []byte("first"))
		if err != nil {
			t.Fatal(err)
		}
		second, err := sender.seal(tlsRecordApplicationData, []byte("second"))
		if err != nil {
			t.Fatal(err)
		}
		// a replay or reorder fails its tag, which is what lets the edge's count fix Z2's nonce
		if _, _, err := receiver.open(second); err == nil {
			t.Errorf("version %#x: opened a record at the wrong sequence number", c.version)
		}
		if _, content, err := receiver.open(first); err != nil || string(content) != "first" {
			t.Errorf("version %#x: %q %v", c.version, content, err)
		}
	}
}
