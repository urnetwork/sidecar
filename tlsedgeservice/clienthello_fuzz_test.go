// FuzzClientHelloRecords (§22.6): a hello, however it is cut into records and reads, gives the SNI and
// ALPN that crypto/tls's GetConfigForClient gives, and never more than the records that carried it.
// The differential runs on what crypto/tls accepts: a hello it refuses for a field this file does not
// read has no answer to compare, and the places the two differ on purpose are clienthello.go's.
//
// Seeds live in the repo's testdata/fuzz, the home §22.6 and the fuzz registry give them, not in this
// package's, which is where go test looks on its own: so this reads them in with f.Add. Their files
// are go test -fuzz's corpus encoding, so a crasher moves in as it is. A plain go test runs every
// seed. Rewrite the files from the builders here with go test -run '^TestClientHelloSeedFiles$'
// ./tlsedgeservice -args -write-fuzz-seeds

package tlsedgeservice

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var testWriteFuzzSeeds = flag.Bool("write-fuzz-seeds", false, "rewrite testdata/fuzz from the seed builders")

// The first line of a corpus file.
const testFuzzCorpusHeader = "go test fuzz v1"

// The directory of a target's seeds, by what §22.6 and the plan name it.
func testFuzzSeedDirectory(target string) string {
	return filepath.Join("..", "testdata", "fuzz", target)
}

// A seed's arguments in corpus encoding.
func testEncodeFuzzSeed(t testing.TB, arguments ...any) []byte {
	t.Helper()
	encoded := &bytes.Buffer{}
	fmt.Fprintln(encoded, testFuzzCorpusHeader)
	for _, argument := range arguments {
		switch value := argument.(type) {
		case []byte:
			fmt.Fprintf(encoded, "[]byte(%q)\n", value)
		case uint16:
			fmt.Fprintf(encoded, "uint16(%d)\n", value)
		default:
			t.Fatalf("no encoding for a %T", argument)
		}
	}
	return encoded.Bytes()
}

// Every seed of target by file name, each as the arguments f.Add takes. A directory with nothing in
// it fails, since an empty one is a target that runs nothing (§22.6).
func testReadFuzzSeeds(t testing.TB, target string) map[string][]any {
	t.Helper()
	directory := testFuzzSeedDirectory(target)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	seeds := map[string][]any{}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
		if lines[0] != testFuzzCorpusHeader {
			t.Fatalf("%s is not a corpus file", entry.Name())
		}
		arguments := []any{}
		for _, line := range lines[1:] {
			if text, ok := strings.CutPrefix(line, "[]byte("); ok {
				unquoted, err := strconv.Unquote(strings.TrimSuffix(text, ")"))
				if err != nil {
					t.Fatalf("%s: %v", entry.Name(), err)
				}
				arguments = append(arguments, []byte(unquoted))
			} else if text, ok := strings.CutPrefix(line, "uint16("); ok {
				value, err := strconv.ParseUint(strings.TrimSuffix(text, ")"), 10, 16)
				if err != nil {
					t.Fatalf("%s: %v", entry.Name(), err)
				}
				arguments = append(arguments, uint16(value))
			} else {
				t.Fatalf("%s: cannot read %q", entry.Name(), line)
			}
		}
		seeds[entry.Name()] = arguments
	}
	if len(seeds) == 0 {
		t.Fatalf("no seeds for %s", target)
	}
	return seeds
}

// Replaces target's seeds with these, by file name.
func testWriteFuzzSeedFiles(t testing.TB, target string, seeds map[string][]any) {
	t.Helper()
	directory := testFuzzSeedDirectory(target)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, arguments := range seeds {
		if err := os.WriteFile(filepath.Join(directory, name), testEncodeFuzzSeed(t, arguments...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A hello of exactly byteCount bytes on the wire in one record, grown with RFC 7685's padding
// extension, as §22.6 asks of a hello at tlsedge's bound.
func testPaddedHelloStream(t testing.TB, byteCount int) []byte {
	t.Helper()
	const paddingExtension = 21
	extensions := []testExtension{testServerNameExtension(testServerName), testAlpnExtension("h2", "http/1.1")}
	unpadded := testRecords(testHelloMessage(append(extensions, testExtension{extensionType: paddingExtension})...))
	padding := make([]byte, byteCount-len(unpadded))
	stream := testRecords(testHelloMessage(append(extensions, testExtension{extensionType: paddingExtension, data: padding})...))
	if len(stream) != byteCount {
		t.Fatalf("padded to %d B", len(stream))
	}
	return stream
}

// What a Chromium-family client sends: GREASE in the cipher suites, extension types, groups and
// versions, which a server must ignore (RFC 8701).
func testGreaseHelloStream() []byte {
	const grease = 0x1a1a
	greaseData := binary.BigEndian.AppendUint16(nil, grease)
	groups := binary.BigEndian.AppendUint16(slices.Clone(greaseData), uint16(29))
	versions := binary.BigEndian.AppendUint16(slices.Clone(greaseData), uint16(0x0304))
	extensions := []testExtension{
		{extensionType: grease},
		testServerNameExtension(testServerName),
		{extensionType: 10, data: testPrefixed(2, groups)},
		{extensionType: 43, data: testPrefixed(1, versions)},
		testAlpnExtension("h2", "http/1.1"),
		{extensionType: 0x2a2a, data: []byte{0}},
	}
	block := []byte{}
	for _, extension := range extensions {
		block = binary.BigEndian.AppendUint16(block, extension.extensionType)
		block = append(block, testPrefixed(2, extension.data)...)
	}
	body := []byte{3, 3}
	body = append(body, bytes.Repeat([]byte{0x22}, 32)...)
	body = append(body, testPrefixed(1, bytes.Repeat([]byte{0x33}, 32))...)
	body = append(body, testPrefixed(2, append(slices.Clone(greaseData), 0x13, 0x01))...)
	body = append(body, 1, 0)
	body = append(body, testPrefixed(2, block)...)
	return testRecords(testHandshakeMessage(tlsHandshakeTypeClientHello, body))
}

// The seeds §22.6's bullet and the plan name, by file name. Each is a stream as a client sends it,
// and the arguments after it cut the hello differently for the target's two splits.
func testClientHelloSeeds(t testing.TB) map[string][]any {
	t.Helper()
	serverName := testServerNameExtension(testServerName)
	alpn := testAlpnExtension("h2", "http/1.1")
	goHello := testGoClientHello(t)
	message := testHelloMessage(serverName, alpn)
	badLength := func(mutate func(stream []byte)) []byte {
		stream := testRecords(message)
		mutate(stream)
		return stream
	}
	return map[string][]any{
		"go-x25519mlkem768":              {goHello, uint16(0), uint16(0)},
		"go-x25519mlkem768-many-records": {goHello, uint16(100), uint16(7)},
		"grease":                         {testGreaseHelloStream(), uint16(0), uint16(0)},
		"grease-ech":                     {testRecords(testHelloMessage(serverName, testGreaseEchExtension(), alpn)), uint16(0), uint16(3)},
		"padded-16k":                     {testPaddedHelloStream(t, testMaxBytes), uint16(0), uint16(0)},
		"padded-16k-two-records":         {testPaddedHelloStream(t, testMaxBytes), uint16(8192), uint16(1500)},
		"one-byte-records":               {testRecords(message), uint16(1), uint16(1)},
		"no-extensions":                  {testRecords(testHandshakeMessage(tlsHandshakeTypeClientHello, testHelloPrefix())), uint16(0), uint16(0)},
		"trailing-dot":                   {testRecords(testHelloMessage(testServerNameExtension(testServerName + "."))), uint16(0), uint16(0)},
		"route-probe":                    {testRecords(testHelloMessage(serverName, testAlpnExtension(tlsAlpnRouteProbe, "http/1.1"))), uint16(0), uint16(0)},
		"warning-alert-first":            {append(testRecord(21, []byte{1, 112}), testRecords(message)...), uint16(0), uint16(0)},
		"sslv2":                          {[]byte{0x80, 0x2e, 1, 0, 2, 0, 21, 0, 0, 0, 16}, uint16(0), uint16(0)},
		"two-host-names":                 {testRecords(testHelloMessage(testServerNameExtension("a.example", "b.example"))), uint16(0), uint16(0)},
		"repeated-extension":             {testRecords(testHelloMessage(alpn, alpn)), uint16(0), uint16(0)},
		"empty-alpn-id":                  {testRecords(testHelloMessage(testAlpnExtension("h2", ""))), uint16(0), uint16(0)},
		"malformed-record-length": {badLength(func(stream []byte) {
			binary.BigEndian.PutUint16(stream[3:], uint16(len(stream)))
		}), uint16(0), uint16(0)},
		"malformed-handshake-length": {badLength(func(stream []byte) {
			stream[tlsRecordHeaderByteCount+1] = 1
		}), uint16(0), uint16(0)},
		"malformed-short-handshake-length": {badLength(func(stream []byte) {
			stream[tlsRecordHeaderByteCount+3] -= 1
		}), uint16(0), uint16(0)},
		"malformed-extension-length": {badLength(func(stream []byte) {
			offset := tlsRecordHeaderByteCount + tlsHandshakeHeaderByteCount + len(testHelloPrefix())
			binary.BigEndian.PutUint16(stream[offset+2+2:], 0xffff)
		}), uint16(0), uint16(0)},
		"malformed-extension-block-length": {badLength(func(stream []byte) {
			offset := tlsRecordHeaderByteCount + tlsHandshakeHeaderByteCount + len(testHelloPrefix())
			binary.BigEndian.PutUint16(stream[offset:], 1)
		}), uint16(0), uint16(0)},
		"malformed-session-id-length": {badLength(func(stream []byte) {
			stream[tlsRecordHeaderByteCount+tlsHandshakeHeaderByteCount+tlsClientHelloFixedByteCount] = 0xff
		}), uint16(0), uint16(0)},
	}
}

// The handshake message a stream's records open with, when only handshake records carry it whole.
func testFirstHandshakeMessage(stream []byte) ([]byte, bool) {
	message := []byte{}
	for {
		if len(stream) < tlsRecordHeaderByteCount || stream[0] != tlsRecordTypeHandshake {
			return nil, false
		}
		end := tlsRecordHeaderByteCount + int(binary.BigEndian.Uint16(stream[3:]))
		if len(stream) < end {
			return nil, false
		}
		message = append(message, stream[tlsRecordHeaderByteCount:end]...)
		stream = stream[end:]
		if len(message) < tlsHandshakeHeaderByteCount {
			continue
		}
		byteCount := tlsHandshakeHeaderByteCount + int(message[1])<<16 + int(message[2])<<8 + int(message[3])
		if byteCount <= len(message) {
			return message[:byteCount], true
		}
	}
}

// True when a and b read alike: both a hello with the same fields, or both a refusal, or both the
// connection's error.
func testSameRead(a *TlsClientHello, aErr error, b *TlsClientHello, bErr error) bool {
	if aErr != nil || bErr != nil {
		return errors.Is(aErr, ErrClientHelloRefused) == errors.Is(bErr, ErrClientHelloRefused) && (aErr == nil) == (bErr == nil)
	}
	return a.ServerName == b.ServerName && slices.Equal(a.AlpnIds, b.AlpnIds) && a.EchPresent == b.EchPresent &&
		bytes.Equal(a.RawBytes, b.RawBytes)
}

// §22.6's bullet on one stream read in pieces of readByteCount.
func testCheckStream(t *testing.T, stream []byte, readByteCount int) {
	t.Helper()
	reader := &testChunkReader{stream: stream, byteCount: readByteCount}
	hello, err := ReadClientHello(reader, len(stream))
	whole, wholeErr := ReadClientHello(bytes.NewReader(stream), len(stream))
	if !testSameRead(hello, err, whole, wholeErr) {
		t.Fatalf("reads of %d B gave %+v, %v, and one read gave %+v, %v", readByteCount, hello, err, whole, wholeErr)
	}

	if err == nil {
		if !bytes.HasPrefix(stream, hello.RawBytes) {
			t.Fatal("raw bytes are not the stream's own")
		}
		if len(reader.stream) != len(stream)-len(hello.RawBytes) {
			t.Fatalf("read %d B and kept %d", len(stream)-len(reader.stream), len(hello.RawBytes))
		}
		if _, ok := testFirstHandshakeMessage(hello.RawBytes); !ok {
			t.Fatal("raw bytes hold no whole hello")
		}
	}

	seen := testCryptoTlsHello(stream)
	if seen == nil {
		return
	}
	if _, ok := testFirstHandshakeMessage(stream); !ok {
		// crypto/tls skipped a warning alert, which is clienthello.go's one refusal of what it takes
		if err == nil {
			t.Fatal("read past a record that is no handshake record")
		}
		return
	}
	if err != nil {
		t.Fatalf("crypto/tls took %q, %q, and this refused: %v", seen.ServerName, seen.SupportedProtos, err)
	}
	if hello.ServerName != seen.ServerName {
		t.Fatalf("server name %q, and crypto/tls saw %q", hello.ServerName, seen.ServerName)
	}
	if !slices.Equal(hello.AlpnIds, seen.SupportedProtos) {
		t.Fatalf("alpn %q, and crypto/tls saw %q", hello.AlpnIds, seen.SupportedProtos)
	}
}

// message cut into records of at most recordByteCount bytes.
func testRecordsOf(message []byte, recordByteCount int) []byte {
	cutOffsets := []int{}
	for offset := recordByteCount; offset < len(message); offset += recordByteCount {
		cutOffsets = append(cutOffsets, offset)
	}
	return testRecords(message, cutOffsets...)
}

func FuzzClientHelloRecords(f *testing.F) {
	for _, arguments := range testReadFuzzSeeds(f, "FuzzClientHelloRecords") {
		f.Add(arguments[0].([]byte), arguments[1].(uint16), arguments[2].(uint16))
	}
	// this toolchain's own hello, which the file on disk was only once
	f.Add(testGoClientHello(f), uint16(1000), uint16(1))
	f.Fuzz(func(t *testing.T, stream []byte, recordByteCount uint16, readByteCount uint16) {
		testCheckStream(t, stream, int(readByteCount))
		if message, ok := testFirstHandshakeMessage(stream); ok && recordByteCount != 0 {
			testCheckStream(t, testRecordsOf(message, int(recordByteCount)), int(readByteCount))
		}
	})
}

// The bullet's every boundary, on each seed crypto/tls takes: a read cut at each byte of the stream,
// and two records cut at each byte of the message. The fuzz target takes one cut per input.
func TestClientHelloSeedsAtEveryBoundary(t *testing.T) {
	seeds := testReadFuzzSeeds(t, "FuzzClientHelloRecords")
	walkedStreams := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(seeds)) {
		stream := seeds[name][0].([]byte)
		message, ok := testFirstHandshakeMessage(stream)
		seen := testCryptoTlsHello(stream)
		// two seeds may hold one stream and differ only in their cuts, which this walks anyway
		if !ok || seen == nil || walkedStreams[string(stream)] {
			continue
		}
		walkedStreams[string(stream)] = true
		for cutOffset := 1; cutOffset < len(stream); cutOffset += 1 {
			hello, err := ReadClientHello(&testCutReader{stream: stream, cutOffset: cutOffset}, len(stream))
			if err != nil {
				t.Fatalf("%s read cut at %d: %v", name, cutOffset, err)
			}
			if hello.ServerName != seen.ServerName || !slices.Equal(hello.AlpnIds, seen.SupportedProtos) || !bytes.Equal(hello.RawBytes, stream) {
				t.Fatalf("%s read cut at %d: %+v", name, cutOffset, hello)
			}
		}
		for cutOffset := 1; cutOffset < len(message); cutOffset += 1 {
			split := testRecords(message, cutOffset)
			seen := testCryptoTlsHello(split)
			if seen == nil {
				t.Fatalf("%s cut at %d: crypto/tls refused it", name, cutOffset)
			}
			hello, err := ReadClientHello(bytes.NewReader(split), len(split))
			if err != nil {
				t.Fatalf("%s record cut at %d: %v", name, cutOffset, err)
			}
			if hello.ServerName != seen.ServerName || !slices.Equal(hello.AlpnIds, seen.SupportedProtos) || !bytes.Equal(hello.RawBytes, split) {
				t.Fatalf("%s record cut at %d: %+v", name, cutOffset, hello)
			}
		}
	}
	if len(walkedStreams) == 0 {
		t.Error("no seed reached crypto/tls's callback")
	}
}

// Each hello the plan names is on disk and reaches both parsers as the plan says it should.
func TestClientHelloSeedFiles(t *testing.T) {
	builders := testClientHelloSeeds(t)
	if *testWriteFuzzSeeds {
		testWriteFuzzSeedFiles(t, "FuzzClientHelloRecords", builders)
	}
	seeds := testReadFuzzSeeds(t, "FuzzClientHelloRecords")
	for name := range builders {
		if _, ok := seeds[name]; !ok {
			t.Errorf("no seed file %s", name)
		}
	}
	for _, name := range []string{"go-x25519mlkem768", "grease", "grease-ech", "padded-16k"} {
		stream := seeds[name][0].([]byte)
		if testCryptoTlsHello(stream) == nil {
			t.Errorf("crypto/tls refused the %s seed", name)
		}
		hello, err := ReadClientHello(bytes.NewReader(stream), testMaxBytes)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if hello.ServerName != testServerName {
			t.Errorf("%s: server name %q", name, hello.ServerName)
		}
		if hello.EchPresent != (name == "grease-ech") {
			t.Errorf("%s: ECH %t", name, hello.EchPresent)
		}
	}
	if stream := seeds["padded-16k"][0].([]byte); len(stream) != testMaxBytes {
		t.Errorf("the padded seed is %d B", len(stream))
	}
	for _, name := range []string{"sslv2", "warning-alert-first", "two-host-names", "repeated-extension", "empty-alpn-id"} {
		stream := seeds[name][0].([]byte)
		if _, err := ReadClientHello(bytes.NewReader(stream), testMaxBytes); !errors.Is(err, ErrClientHelloRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name := range seeds {
		if !strings.HasPrefix(name, "malformed-") {
			continue
		}
		stream := seeds[name][0].([]byte)
		if _, err := ReadClientHello(bytes.NewReader(stream), testMaxBytes); err == nil {
			t.Errorf("%s: read a hello", name)
		} else if !errors.Is(err, ErrClientHelloRefused) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
