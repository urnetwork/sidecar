// T1 for ClientHello reading (§22.5's §13 row): what a hello gives, what it costs, and each refusal,
// against crypto/tls wherever crypto/tls has an opinion.

package tlsedgeservice

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Used wherever a test needs a name and any will do.
const testServerName = "blog.a1b2c3d4e5.ur.example"

// The bound config/<env>/tlsedge.yml sets (§13.5).
const testMaxBytes = 16 * 1024

// One extension of a hello a test builds.
type testExtension struct {
	extensionType uint16
	data          []byte
}

// A big-endian length of byteCount bytes in front of data.
func testPrefixed(byteCount int, data []byte) []byte {
	prefix := binary.BigEndian.AppendUint32(nil, uint32(len(data)))
	return append(prefix[len(prefix)-byteCount:], data...)
}

// A server_name extension of host_name entries, as RFC 6066 §3 lays them out.
func testServerNameExtension(names ...string) testExtension {
	entries := []byte{}
	for _, name := range names {
		entries = append(entries, tlsServerNameTypeHostName)
		entries = append(entries, testPrefixed(2, []byte(name))...)
	}
	return testExtension{extensionType: tlsExtensionServerName, data: testPrefixed(2, entries)}
}

// An ALPN extension, as RFC 7301 §3.1 lays it out.
func testAlpnExtension(ids ...string) testExtension {
	entries := []byte{}
	for _, id := range ids {
		entries = append(entries, testPrefixed(1, []byte(id))...)
	}
	return testExtension{extensionType: tlsExtensionAlpn, data: testPrefixed(2, entries)}
}

// An encrypted_client_hello in the outer form a client sends as GREASE: a cipher suite, a config id
// and random-looking enc and payload for a server that holds no key.
func testGreaseEchExtension() testExtension {
	data := []byte{0, 0, 1, 0, 1, 0x2a}
	data = append(data, testPrefixed(2, bytes.Repeat([]byte{0x5c}, 32))...)
	data = append(data, testPrefixed(2, bytes.Repeat([]byte{0xa3}, 144))...)
	return testExtension{extensionType: tlsExtensionEncryptedClientHello, data: data}
}

// The body of a hello up to its extensions, the smallest crypto/tls reads.
func testHelloPrefix() []byte {
	prefix := []byte{3, 3}
	prefix = append(prefix, bytes.Repeat([]byte{0x11}, 32)...)
	prefix = append(prefix, 0)
	prefix = append(prefix, testPrefixed(2, []byte{0x13, 0x01})...)
	return append(prefix, 1, 0)
}

// body behind a handshake header.
func testHandshakeMessage(messageType uint8, body []byte) []byte {
	return append([]byte{messageType}, testPrefixed(3, body)...)
}

// A whole ClientHello message holding extensions.
func testHelloMessage(extensions ...testExtension) []byte {
	block := []byte{}
	for _, extension := range extensions {
		block = binary.BigEndian.AppendUint16(block, extension.extensionType)
		block = append(block, testPrefixed(2, extension.data)...)
	}
	return testHandshakeMessage(tlsHandshakeTypeClientHello, append(testHelloPrefix(), testPrefixed(2, block)...))
}

// One record of recordType.
func testRecord(recordType uint8, body []byte) []byte {
	return append([]byte{recordType, 3, 1}, testPrefixed(2, body)...)
}

// message cut into handshake records at the offsets, in order, none of them empty.
func testRecords(message []byte, cutOffsets ...int) []byte {
	stream := []byte{}
	start := 0
	for _, cutOffset := range append(cutOffsets, len(message)) {
		stream = append(stream, testRecord(tlsRecordTypeHandshake, message[start:cutOffset])...)
		start = cutOffset
	}
	return stream
}

// Serves a stream to crypto/tls, which writes only alerts back.
type testStreamConn struct {
	reader bytes.Reader
}

func (self *testStreamConn) Read(b []byte) (int, error)         { return self.reader.Read(b) }
func (self *testStreamConn) Write(b []byte) (int, error)        { return len(b), nil }
func (self *testStreamConn) Close() error                       { return nil }
func (self *testStreamConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (self *testStreamConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (self *testStreamConn) SetDeadline(t time.Time) error      { return nil }
func (self *testStreamConn) SetReadDeadline(t time.Time) error  { return nil }
func (self *testStreamConn) SetWriteDeadline(t time.Time) error { return nil }

// What crypto/tls hands GetConfigForClient for stream, or nil if it never gets that far. A listener's
// crypto/tls reads the same bytes, so this is the answer tlsedge's routing has to match.
func testCryptoTlsHello(stream []byte) *tls.ClientHelloInfo {
	errStop := errors.New("stop at the callback")
	var seen *tls.ClientHelloInfo
	conn := &testStreamConn{}
	conn.reader.Reset(stream)
	err := tls.Server(conn, &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			seen = info
			return nil, errStop
		},
	}).Handshake()
	if !errors.Is(err, errStop) {
		return nil
	}
	return seen
}

// Takes what crypto/tls writes as a client, and fails its first write so that it stops there.
type testCaptureConn struct {
	testStreamConn
	stream []byte
}

func (self *testCaptureConn) Write(b []byte) (int, error) {
	self.stream = append(self.stream, b...)
	return 0, io.ErrClosedPipe
}

// The record Go's own client opens with, X25519MLKEM768 first, whose key share puts a hello over a
// kilobyte.
func testGoClientHello(t testing.TB) []byte {
	t.Helper()
	conn := &testCaptureConn{}
	config := &tls.Config{
		ServerName:       testServerName,
		NextProtos:       []string{"h2", "http/1.1"},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
	}
	if err := tls.Client(conn, config).Handshake(); err == nil {
		t.Fatal("handshake finished on a conn that fails its writes")
	}
	if len(conn.stream) == 0 {
		t.Fatal("no hello was written")
	}
	return conn.stream
}

// Gives out a stream cut at one offset: a read never crosses it, as a TCP segment boundary would not.
type testCutReader struct {
	stream    []byte
	offset    int
	cutOffset int
}

func (self *testCutReader) Read(b []byte) (int, error) {
	if self.offset == len(self.stream) {
		return 0, io.EOF
	}
	end := len(self.stream)
	if self.offset < self.cutOffset {
		end = self.cutOffset
	}
	byteCount := copy(b, self.stream[self.offset:end])
	self.offset += byteCount
	return byteCount, nil
}

// Gives out a stream in pieces of at most byteCount bytes, all at once for 0.
type testChunkReader struct {
	stream    []byte
	byteCount int
}

func (self *testChunkReader) Read(b []byte) (int, error) {
	if len(self.stream) == 0 {
		return 0, io.EOF
	}
	if 0 < self.byteCount && self.byteCount < len(b) {
		b = b[:self.byteCount]
	}
	byteCount := copy(b, self.stream)
	self.stream = self.stream[byteCount:]
	return byteCount, nil
}

func TestReadClientHelloGivesWhatAGoClientOffers(t *testing.T) {
	stream := testGoClientHello(t)
	if len(stream) <= 1024 {
		t.Fatalf("a post-quantum hello should be over a kilobyte, and this is %d B", len(stream))
	}
	hello, err := ReadClientHello(bytes.NewReader(stream), testMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if hello.ServerName != testServerName {
		t.Errorf("server name %q", hello.ServerName)
	}
	if !slices.Equal(hello.AlpnIds, []string{"h2", "http/1.1"}) {
		t.Errorf("alpn %q", hello.AlpnIds)
	}
	if hello.EchPresent {
		t.Error("ECH present on a hello that offered none")
	}
	if !bytes.Equal(hello.RawBytes, stream) {
		t.Error("raw bytes differ from the stream")
	}
}

func TestReadClientHelloLeavesWhatFollowsInTheConn(t *testing.T) {
	stream := testRecords(testHelloMessage(testServerNameExtension(testServerName)))
	following := []byte{23, 3, 3, 0, 1, 0xee}
	reader := bytes.NewReader(append(slices.Clone(stream), following...))
	hello, err := ReadClientHello(reader, testMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hello.RawBytes, stream) {
		t.Error("raw bytes are not exactly the hello's records")
	}
	rest, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rest, following) {
		t.Errorf("left %x in the conn", rest)
	}
}

func TestReadClientHelloKeepsRecordFramingVerbatim(t *testing.T) {
	message := testHelloMessage(testServerNameExtension(testServerName), testAlpnExtension("h2"))
	// a record boundary inside the handshake header, and one in the middle of the name
	stream := testRecords(message, 1, 3, len(message)/2)
	// the version byte may differ from record to record, and must survive
	stream[2] = 3
	hello, err := ReadClientHello(bytes.NewReader(stream), testMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hello.RawBytes, stream) {
		t.Error("raw bytes lost the record framing")
	}
	if hello.ServerName != testServerName || !slices.Equal(hello.AlpnIds, []string{"h2"}) {
		t.Errorf("read %q and %q", hello.ServerName, hello.AlpnIds)
	}
}

func TestReadClientHelloAcceptsTrailingBytesInItsLastRecord(t *testing.T) {
	message := testHelloMessage(testServerNameExtension(testServerName))
	stream := testRecord(tlsRecordTypeHandshake, append(slices.Clone(message), 0xee, 0xee))
	if testCryptoTlsHello(stream) == nil {
		t.Fatal("crypto/tls should read past nothing until a later message")
	}
	hello, err := ReadClientHello(bytes.NewReader(stream), testMaxBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hello.RawBytes, stream) {
		t.Error("the record's tail was dropped from raw bytes")
	}
}

func TestReadClientHelloRefusesAtEveryBound(t *testing.T) {
	stream := testRecords(testHelloMessage(testServerNameExtension(testServerName)))
	if _, err := ReadClientHello(bytes.NewReader(stream), len(stream)); err != nil {
		t.Errorf("a hello of exactly max bytes: %v", err)
	}
	reader := bytes.NewReader(stream)
	if _, err := ReadClientHello(reader, len(stream)-1); !errors.Is(err, ErrClientHelloRefused) {
		t.Errorf("a hello one past max bytes: %v", err)
	}
	if reader.Len() != len(stream)-tlsRecordHeaderByteCount {
		t.Errorf("read %d B past the record header that gave it away", len(stream)-tlsRecordHeaderByteCount-reader.Len())
	}
	for _, maxBytes := range []int{-1, 0, tlsRecordHeaderByteCount - 1} {
		reader := bytes.NewReader(stream)
		if _, err := ReadClientHello(reader, maxBytes); !errors.Is(err, ErrClientHelloRefused) {
			t.Errorf("max bytes %d: %v", maxBytes, err)
		}
		if reader.Len() != len(stream) {
			t.Errorf("max bytes %d read %d B", maxBytes, len(stream)-reader.Len())
		}
	}
}

func TestReadClientHelloRefusesAHelloDeclaringMoreThanMaxBytes(t *testing.T) {
	// a first record declaring a hello that cannot fit, followed by nothing: waiting for the rest
	// would hold the visitor to the deadline for no reason
	message := testHelloMessage(testServerNameExtension(strings.Repeat("a", 200)))
	cut := len(message) / 2
	first := testRecord(tlsRecordTypeHandshake, message[:cut])
	_, err := ReadClientHello(bytes.NewReader(first), len(first)+tlsRecordHeaderByteCount+len(message)-cut-1)
	if !errors.Is(err, ErrClientHelloRefused) {
		t.Errorf("one byte short of room: %v", err)
	}
	_, err = ReadClientHello(bytes.NewReader(first), len(first)+tlsRecordHeaderByteCount+len(message)-cut)
	if !errors.Is(err, io.EOF) {
		t.Errorf("room for the rest should wait for it, and read gave %v", err)
	}
}

func TestReadClientHelloRefusals(t *testing.T) {
	message := testHelloMessage(testServerNameExtension(testServerName))
	versioned := func(version uint16) []byte {
		stream := testRecords(message)
		binary.BigEndian.PutUint16(stream[1:], version)
		return stream
	}
	cases := []struct {
		name   string
		stream []byte
	}{
		{name: "application data first", stream: testRecord(23, message)},
		{name: "change cipher spec first", stream: testRecord(20, []byte{1})},
		{name: "fatal alert first", stream: testRecord(21, []byte{2, 40})},
		{name: "SSLv2", stream: []byte{0x80, 0x2e, 1, 0, 2, 0, 21, 0, 0, 0, 16}},
		{name: "plaintext http", stream: []byte("GET / HTTP/1.1\r\n\r\n")},
		{name: "server hello", stream: testRecord(tlsRecordTypeHandshake, testHandshakeMessage(2, testHelloPrefix()))},
		{name: "hello request", stream: testRecord(tlsRecordTypeHandshake, testHandshakeMessage(0, nil))},
		{name: "record version past tls", stream: versioned(tlsRecordVersionRefused)},
		{name: "empty record", stream: testRecord(tlsRecordTypeHandshake, nil)},
		{name: "empty record inside a hello", stream: append(testRecords(message[:9]), append(testRecord(tlsRecordTypeHandshake, nil), testRecords(message[9:])...)...)},
		{name: "record past 2^14", stream: testRecord(tlsRecordTypeHandshake, testHelloMessage(testExtension{
			extensionType: 21,
			data:          make([]byte, tlsRecordMaxByteCount),
		}))},
		{name: "another record type inside a hello", stream: append(testRecords(message[:9]), testRecord(21, []byte{1, 112})...)},
	}
	for _, c := range cases {
		if testCryptoTlsHello(c.stream) != nil {
			t.Errorf("%s: crypto/tls accepted it", c.name)
		}
		hello, err := ReadClientHello(bytes.NewReader(c.stream), 2*testMaxBytes)
		if !errors.Is(err, ErrClientHelloRefused) {
			t.Errorf("%s: read gave %v and %v", c.name, hello, err)
		}
	}
}

// Its first byte gives a message away, so a peer that sent only that is answered, not waited for.
func TestReadClientHelloRefusesAnotherMessageAtItsFirstByte(t *testing.T) {
	stream := testRecord(tlsRecordTypeHandshake, []byte{2})
	if _, err := ReadClientHello(bytes.NewReader(stream), testMaxBytes); !errors.Is(err, ErrClientHelloRefused) {
		t.Errorf("read gave %v", err)
	}
	stream = testRecord(tlsRecordTypeHandshake, []byte{tlsHandshakeTypeClientHello})
	if _, err := ReadClientHello(bytes.NewReader(stream), testMaxBytes); !errors.Is(err, io.EOF) {
		t.Errorf("a ClientHello's first byte should wait for its second, and read gave %v", err)
	}
}

func TestReadClientHelloRefusesAWarningAlertCryptoTlsSkips(t *testing.T) {
	// the one place this refuses what crypto/tls passes: §13.5 refuses any non-handshake record
	stream := append(testRecord(21, []byte{1, 112}), testRecords(testHelloMessage(testServerNameExtension(testServerName)))...)
	if testCryptoTlsHello(stream) == nil {
		t.Fatal("crypto/tls should skip a warning alert")
	}
	if _, err := ReadClientHello(bytes.NewReader(stream), testMaxBytes); !errors.Is(err, ErrClientHelloRefused) {
		t.Errorf("read gave %v", err)
	}
}

func TestReadClientHelloPassesConnErrorsThrough(t *testing.T) {
	stream := testRecords(testHelloMessage(testServerNameExtension(testServerName)))
	cases := []struct {
		byteCount int
		want      error
	}{
		{byteCount: 0, want: io.EOF},
		{byteCount: 3, want: io.ErrUnexpectedEOF},
		{byteCount: tlsRecordHeaderByteCount, want: io.EOF},
		{byteCount: tlsRecordHeaderByteCount + 2, want: io.ErrUnexpectedEOF},
		{byteCount: len(stream) - 1, want: io.ErrUnexpectedEOF},
	}
	for _, c := range cases {
		_, err := ReadClientHello(bytes.NewReader(stream[:c.byteCount]), testMaxBytes)
		if !errors.Is(err, c.want) {
			t.Errorf("%d B: %v", c.byteCount, err)
		}
		if errors.Is(err, ErrClientHelloRefused) {
			t.Errorf("%d B: a visitor leaving reads as a refusal", c.byteCount)
		}
	}
}

// Everything crypto/tls refuses in the fields this file reads, each proved on both.
func TestParseClientHelloRefusesWhatCryptoTlsRefuses(t *testing.T) {
	serverNameData := func(data ...byte) testExtension {
		return testExtension{extensionType: tlsExtensionServerName, data: data}
	}
	alpnData := func(data ...byte) testExtension {
		return testExtension{extensionType: tlsExtensionAlpn, data: data}
	}
	withBody := func(mutate func(body []byte) []byte) []byte {
		body := testHelloMessage(testServerNameExtension(testServerName))[tlsHandshakeHeaderByteCount:]
		return testHandshakeMessage(tlsHandshakeTypeClientHello, mutate(slices.Clone(body)))
	}
	prefixLength := len(testHelloPrefix())
	cases := []struct {
		name    string
		message []byte
	}{
		{name: "two host names", message: testHelloMessage(testServerNameExtension("a.example", "b.example"))},
		{name: "a repeated extension", message: testHelloMessage(testExtension{extensionType: 0x1234}, testExtension{extensionType: 0x1234})},
		{name: "a repeated server_name", message: testHelloMessage(testServerNameExtension("a.example"), testServerNameExtension("a.example"))},
		{name: "a repeated alpn", message: testHelloMessage(testAlpnExtension("h2"), testAlpnExtension("h2"))},
		{name: "an empty alpn id", message: testHelloMessage(testAlpnExtension("h2", ""))},
		{name: "an empty alpn list", message: testHelloMessage(testAlpnExtension())},
		{name: "an alpn id past its list", message: testHelloMessage(alpnData(0, 3, 9, 'h', '2'))},
		{name: "bytes after the alpn list", message: testHelloMessage(alpnData(0, 3, 2, 'h', '2', 0))},
		{name: "no alpn list", message: testHelloMessage(alpnData())},
		{name: "an empty name list", message: testHelloMessage(testServerNameExtension())},
		{name: "an empty host name", message: testHelloMessage(testServerNameExtension(""))},
		{name: "an empty name of another type", message: testHelloMessage(serverNameData(0, 3, 1, 0, 0))},
		{name: "a name past its list", message: testHelloMessage(serverNameData(0, 4, 0, 0, 9, 'a'))},
		{name: "bytes after the name list", message: testHelloMessage(serverNameData(0, 4, 0, 0, 1, 'a', 0))},
		{name: "no name list", message: testHelloMessage(serverNameData())},
		{name: "an extension block past the hello", message: withBody(func(body []byte) []byte {
			return body[:len(body)-1]
		})},
		{name: "an extension past its block", message: withBody(func(body []byte) []byte {
			body[prefixLength+2+2] = 0xff
			return body
		})},
		{name: "an extension whose length leaves its block even", message: testHandshakeMessage(
			tlsHandshakeTypeClientHello,
			append(testHelloPrefix(), testPrefixed(2, []byte{0x12, 0x34, 0xff, 0xff})...),
		)},
		{name: "bytes after the extensions", message: withBody(func(body []byte) []byte {
			return append(body, 0)
		})},
		{name: "an odd cipher suite list", message: withBody(func(body []byte) []byte {
			body[2+32+1+1] = 3
			return body
		})},
		{name: "a cipher suite list past the hello", message: withBody(func(body []byte) []byte {
			body[2+32+1] = 0xff
			return body
		})},
		{name: "a session id past the hello", message: withBody(func(body []byte) []byte {
			body[2+32] = 0xff
			return body
		})},
		{name: "no extension block after its length", message: withBody(func(body []byte) []byte {
			return body[:prefixLength+1]
		})},
		{name: "a hello cut inside random", message: withBody(func(body []byte) []byte {
			return body[:10]
		})},
	}
	for _, c := range cases {
		if testCryptoTlsHello(testRecord(tlsRecordTypeHandshake, c.message)) != nil {
			t.Errorf("%s: crypto/tls accepted it", c.name)
		}
		if hello, err := ParseClientHello(c.message); !errors.Is(err, ErrClientHelloRefused) {
			t.Errorf("%s: parsed %v, %v", c.name, hello, err)
		}
	}
}

func TestParseClientHelloRefusesAnythingButExactlyOneMessage(t *testing.T) {
	message := testHelloMessage(testServerNameExtension(testServerName))
	cases := [][]byte{
		nil,
		{tlsHandshakeTypeClientHello},
		{tlsHandshakeTypeClientHello, 0, 0},
		message[:len(message)-1],
		append(slices.Clone(message), 0),
		testHandshakeMessage(2, message[tlsHandshakeHeaderByteCount:]),
	}
	for _, c := range cases {
		if hello, err := ParseClientHello(c); !errors.Is(err, ErrClientHelloRefused) {
			t.Errorf("%x: parsed %v, %v", c, hello, err)
		}
	}
	if _, err := ParseClientHello(message); err != nil {
		t.Error(err)
	}
}

func TestParseClientHelloReadsAHelloWithNoExtensions(t *testing.T) {
	message := testHandshakeMessage(tlsHandshakeTypeClientHello, testHelloPrefix())
	seen := testCryptoTlsHello(testRecord(tlsRecordTypeHandshake, message))
	if seen == nil {
		t.Fatal("crypto/tls refused it")
	}
	hello, err := ParseClientHello(message)
	if err != nil {
		t.Fatal(err)
	}
	if hello.ServerName != "" || len(hello.AlpnIds) != 0 || hello.EchPresent {
		t.Errorf("parsed %+v", hello)
	}
	if hello.RawBytes != nil {
		t.Error("parsing a message read nothing, so it has no raw bytes to give")
	}
}

func TestParseClientHelloSkipsNamesOfAnotherType(t *testing.T) {
	names := []byte{1}
	names = append(names, testPrefixed(2, []byte("other"))...)
	names = append(names, tlsServerNameTypeHostName)
	names = append(names, testPrefixed(2, []byte(testServerName))...)
	names = append(names, 7)
	names = append(names, testPrefixed(2, []byte("another"))...)
	message := testHelloMessage(testExtension{extensionType: tlsExtensionServerName, data: testPrefixed(2, names)})
	seen := testCryptoTlsHello(testRecord(tlsRecordTypeHandshake, message))
	if seen == nil || seen.ServerName != testServerName {
		t.Fatalf("crypto/tls saw %v", seen)
	}
	hello, err := ParseClientHello(message)
	if err != nil {
		t.Fatal(err)
	}
	if hello.ServerName != testServerName {
		t.Errorf("server name %q", hello.ServerName)
	}
}

func TestParseClientHelloReadsANameListWithNoHostName(t *testing.T) {
	names := append([]byte{1}, testPrefixed(2, []byte("other"))...)
	message := testHelloMessage(testExtension{extensionType: tlsExtensionServerName, data: testPrefixed(2, names)})
	seen := testCryptoTlsHello(testRecord(tlsRecordTypeHandshake, message))
	if seen == nil || seen.ServerName != "" {
		t.Fatalf("crypto/tls saw %v", seen)
	}
	hello, err := ParseClientHello(message)
	if err != nil {
		t.Fatal(err)
	}
	if hello.ServerName != "" {
		t.Errorf("server name %q", hello.ServerName)
	}
}

func TestParseClientHelloKeepsAlpnOrderAndRepeats(t *testing.T) {
	ids := []string{"http/1.1", "h2", "http/1.1", string([]byte{0xff, 0})}
	message := testHelloMessage(testAlpnExtension(ids...))
	seen := testCryptoTlsHello(testRecord(tlsRecordTypeHandshake, message))
	if seen == nil || !slices.Equal(seen.SupportedProtos, ids) {
		t.Fatalf("crypto/tls saw %v", seen)
	}
	hello, err := ParseClientHello(message)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(hello.AlpnIds, ids) {
		t.Errorf("alpn %q", hello.AlpnIds)
	}
}

// The trailing dot on its own, as the plan's trap says: crypto/tls refuses it and §13.5 normalizes it.
func TestParseClientHelloPassesATrailingDotCryptoTlsRefuses(t *testing.T) {
	message := testHelloMessage(testServerNameExtension(testServerName + "."))
	if testCryptoTlsHello(testRecord(tlsRecordTypeHandshake, message)) != nil {
		t.Fatal("crypto/tls should refuse a trailing dot")
	}
	hello, err := ParseClientHello(message)
	if err != nil {
		t.Fatal(err)
	}
	if hello.ServerName != testServerName+"." {
		t.Errorf("server name %q is not as sent", hello.ServerName)
	}
	if name, ok := NormalizeSni(hello.ServerName); !ok || name != testServerName {
		t.Errorf("normalized to %q, %t", name, ok)
	}
}

func TestParseClientHelloRoutesAGreaseEchHelloOnItsOuterName(t *testing.T) {
	message := testHelloMessage(testServerNameExtension(testServerName), testGreaseEchExtension(), testAlpnExtension("h2"))
	seen := testCryptoTlsHello(testRecord(tlsRecordTypeHandshake, message))
	if seen == nil {
		t.Fatal("crypto/tls refused GREASE ECH")
	}
	hello, err := ParseClientHello(message)
	if err != nil {
		t.Fatal(err)
	}
	if !hello.EchPresent {
		t.Error("ECH not noted")
	}
	if hello.ServerName != seen.ServerName || !slices.Equal(hello.AlpnIds, seen.SupportedProtos) {
		t.Errorf("read %q and %q, and crypto/tls saw %q and %q", hello.ServerName, hello.AlpnIds, seen.ServerName, seen.SupportedProtos)
	}
	without, err := ParseClientHello(testHelloMessage(testServerNameExtension(testServerName), testAlpnExtension("h2")))
	if err != nil {
		t.Fatal(err)
	}
	if without.ServerName != hello.ServerName || !slices.Equal(without.AlpnIds, hello.AlpnIds) {
		t.Error("ECH changed what the hello routes on")
	}
}

func TestParseClientHelloNotesAnEchOfAnyShape(t *testing.T) {
	for _, data := range [][]byte{nil, {0xff}, {1}} {
		hello, err := ParseClientHello(testHelloMessage(testExtension{extensionType: tlsExtensionEncryptedClientHello, data: data}))
		if err != nil {
			t.Errorf("%x: %v", data, err)
			continue
		}
		if !hello.EchPresent {
			t.Errorf("%x: ECH not noted", data)
		}
	}
}

func TestOffersRouteProbe(t *testing.T) {
	cases := []struct {
		ids  []string
		want bool
	}{
		{ids: nil, want: false},
		{ids: []string{"http/1.1"}, want: false},
		{ids: []string{tlsAlpnRouteProbe, "http/1.1"}, want: true},
		{ids: []string{"h2", "http/1.1", tlsAlpnRouteProbe}, want: true},
		{ids: []string{strings.ToUpper(tlsAlpnRouteProbe)}, want: false},
		{ids: []string{tlsAlpnRouteProbe + "2"}, want: false},
	}
	for _, c := range cases {
		extensions := []testExtension{testServerNameExtension(testServerName)}
		if c.ids != nil {
			extensions = append(extensions, testAlpnExtension(c.ids...))
		}
		hello, err := ParseClientHello(testHelloMessage(extensions...))
		if err != nil {
			t.Fatal(err)
		}
		if hello.OffersRouteProbe() != c.want {
			t.Errorf("%q: %t", c.ids, hello.OffersRouteProbe())
		}
	}
}

// §13.4 names this id, and probes built apart from this package must match it byte for byte.
func TestRouteProbeIdIsTheOneTheDesignNames(t *testing.T) {
	if tlsAlpnRouteProbe != "ur-route-probe" {
		t.Errorf("%q", tlsAlpnRouteProbe)
	}
}

func TestParseClientHelloDoesNotAllocateByTheId(t *testing.T) {
	ids := make([]string, 4000)
	for index := range ids {
		ids[index] = "x"
	}
	extensions := []testExtension{testAlpnExtension(ids...)}
	for extensionType := range 2000 {
		extensions = append(extensions, testExtension{extensionType: uint16(0x4000 + extensionType)})
	}
	message := testHelloMessage(extensions...)
	allocationCount := testing.AllocsPerRun(10, func() {
		hello, err := ParseClientHello(message)
		if err != nil || len(hello.AlpnIds) != len(ids) {
			t.Fatal(err)
		}
	})
	if 40 < allocationCount {
		t.Errorf("%.0f allocations for %d ids and %d extensions", allocationCount, len(ids), len(extensions))
	}
}

func TestReadClientHelloDoesNotAllocateByTheByte(t *testing.T) {
	stream := testPaddedHelloStream(t, testMaxBytes)
	reader := bytes.NewReader(nil)
	allocationCount := testing.AllocsPerRun(10, func() {
		reader.Reset(stream)
		if _, err := ReadClientHello(reader, testMaxBytes); err != nil {
			t.Fatal(err)
		}
	})
	if 10 < allocationCount {
		t.Errorf("%.0f allocations for a %d B hello", allocationCount, len(stream))
	}
}

// Parsing what a hostile hello can hold stays linear: a sort, and no scan of what came before.
func TestParseClientHelloRefusesARepeatAmongThousands(t *testing.T) {
	extensions := []testExtension{}
	for extensionType := range 3000 {
		extensions = append(extensions, testExtension{extensionType: uint16(0x4000 + extensionType)})
	}
	extensions = append(extensions, testExtension{extensionType: 0x4000})
	message := testHelloMessage(extensions...)
	if testCryptoTlsHello(testRecord(tlsRecordTypeHandshake, message)) != nil {
		t.Fatal("crypto/tls accepted it")
	}
	if _, err := ParseClientHello(message); !errors.Is(err, errClientHelloExtension) {
		t.Errorf("parsed with %v", err)
	}
}

// The files behind §13.5's step 1 and step 7, by what X1 and the plan forbid them: no TLS library can
// present a certificate, no goroutine, no clock and no logger is in the way of a visitor's bytes.
func TestHelloFilesHoldNoTlsLibraryGoroutineClockOrLogger(t *testing.T) {
	refusedImports := []string{"crypto/tls", "crypto/x509", "time", "log", "github.com/" + "urnetwork/glog"}
	fileSet := token.NewFileSet()
	for _, goFile := range []string{"clienthello.go", "sni.go", "alert.go"} {
		file, err := parser.ParseFile(fileSet, goFile, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, importSpec := range file.Imports {
			importPath, err := strconv.Unquote(importSpec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(refusedImports, importPath) {
				t.Errorf("%s imports %s", goFile, importPath)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if _, ok := node.(*ast.GoStmt); ok {
				t.Errorf("%s starts a goroutine", goFile)
			}
			return true
		})
	}
}

// The same rule for the whole package, on X1's half of it: as files land, none may bring a TLS
// library in. A visitor's bytes pass through tlsedge unread past the hello (D-TLS-1).
func TestPackageImportsNoTlsLibrary(t *testing.T) {
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	for _, goFile := range goFiles {
		if strings.HasSuffix(goFile, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, goFile, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, importSpec := range file.Imports {
			if importSpec.Path.Value == `"crypto/tls"` || importSpec.Path.Value == `"crypto/x509"` {
				t.Errorf("%s imports %s", goFile, importSpec.Path.Value)
			}
		}
	}
}

func BenchmarkReadClientHello(b *testing.B) {
	stream := testGoClientHello(b)
	reader := bytes.NewReader(nil)
	b.ReportAllocs()
	b.SetBytes(int64(len(stream)))
	for b.Loop() {
		reader.Reset(stream)
		if _, err := ReadClientHello(reader, testMaxBytes); err != nil {
			b.Fatal(err)
		}
	}
}
