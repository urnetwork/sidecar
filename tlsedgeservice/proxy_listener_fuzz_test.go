// FuzzProxyHeader (§22.6). The bullet asks that pires/go-proxyproto agree with mailgun/proxyproto, and
// mailgun/proxyproto cannot be linked here: it has no license at any version, §4.7 refuses the
// unlicensed on every leg, and make check's license row holds that for test legs too. So until
// .stack/questions/tls-hello-mailgun-proxyproto-license.md is answered, this compares pires with the
// second reader below, written from haproxy's proxy-protocol.txt and sharing no code with it. It is a
// stand-in for what §22.6 names, and no substitute: the point of mailgun is that it is what server's
// connect runs today, and this file does not show the two agree.
//
// Seeds are read as clienthello_fuzz_test.go says, and written by the same flag:
// go test -run '^TestProxyHeaderSeedFiles$' ./tlsedgeservice -args -write-fuzz-seeds

package tlsedgeservice

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	proxyproto "github.com/pires/go-proxyproto"
)

// The most a header may take in these tests, tlsedge.yml's max_bytes.
const testProxyMaxByteCount = 2048

// What a header gives and how long it was.
type testProxyRead struct {
	visitorAddr netip.AddrPort
	byteCount   int
}

// A v1 port as the spec writes it: decimal, 0 to 65535, no sign and no leading zero.
func testReferencePort(text string) (uint16, bool) {
	if text == "" || 5 < len(text) || (1 < len(text) && text[0] == '0') {
		return 0, false
	}
	for _, c := range []byte(text) {
		if c < '0' || '9' < c {
			return 0, false
		}
	}
	port, err := strconv.ParseUint(text, 10, 16)
	return uint16(port), err == nil
}

// A v1 line: "PROXY", the family, two addresses and two ports, one space between each, ending in CRLF
// inside 107 bytes. A TCP4 line holds IPv4 addresses and a TCP6 line IPv6 ones.
func testReferenceProxyV1(stream []byte) (testProxyRead, bool) {
	lineFeed := bytes.IndexByte(stream[:min(len(stream), proxyHeaderV1MaxByteCount)], '\n')
	if lineFeed < 1 || stream[lineFeed-1] != '\r' {
		return testProxyRead{}, false
	}
	fields := strings.Split(string(stream[:lineFeed-1]), " ")
	if len(fields) != 6 || fields[0] != "PROXY" {
		return testProxyRead{}, false
	}
	addrs := [2]netip.Addr{}
	for index, text := range fields[2:4] {
		addr, err := netip.ParseAddr(text)
		if err != nil || addr.Zone() != "" {
			return testProxyRead{}, false
		}
		if (fields[1] == "TCP4" && !addr.Is4()) || (fields[1] == "TCP6" && !addr.Is6()) || (fields[1] != "TCP4" && fields[1] != "TCP6") {
			return testProxyRead{}, false
		}
		addrs[index] = addr
	}
	sourcePort, ok := testReferencePort(fields[4])
	if !ok {
		return testProxyRead{}, false
	}
	if _, ok := testReferencePort(fields[5]); !ok {
		return testProxyRead{}, false
	}
	return testProxyRead{
		visitorAddr: netip.AddrPortFrom(addrs[0].Unmap(), sourcePort),
		byteCount:   lineFeed + 1,
	}, true
}

// A v2 header: the signature, 0x21 for version 2 and PROXY, 0x11 or 0x21 for TCP over IPv4 or IPv6, a
// big-endian length of what follows, then addresses and ports, then TLVs this does not read.
func testReferenceProxyV2(stream []byte, maxByteCount int) (testProxyRead, bool) {
	if len(stream) < 16 || stream[12] != 0x21 {
		return testProxyRead{}, false
	}
	byteCount := 16 + int(binary.BigEndian.Uint16(stream[14:]))
	if len(stream) < byteCount || maxByteCount < byteCount {
		return testProxyRead{}, false
	}
	block := stream[16:byteCount]
	switch {
	case stream[13] == 0x11 && 12 <= len(block):
		addr := netip.AddrFrom4([4]byte(block[0:4]))
		return testProxyRead{netip.AddrPortFrom(addr, binary.BigEndian.Uint16(block[8:])), byteCount}, true
	case stream[13] == 0x21 && 36 <= len(block):
		addr := netip.AddrFrom16([16]byte(block[0:16]))
		return testProxyRead{netip.AddrPortFrom(addr.Unmap(), binary.BigEndian.Uint16(block[32:])), byteCount}, true
	}
	return testProxyRead{}, false
}

// The second reader, which takes exactly what tlsedge takes: a TCP visitor by v1 or v2.
func testReferenceProxyHeader(stream []byte, maxByteCount int) (testProxyRead, bool) {
	if bytes.HasPrefix(stream, []byte("PROXY ")) {
		return testReferenceProxyV1(stream)
	}
	if bytes.HasPrefix(stream, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
		return testReferenceProxyV2(stream, maxByteCount)
	}
	return testProxyRead{}, false
}

// readProxyHeader over stream in pieces of readByteCount, and everything it left unread.
func testReadProxyHeaderLeaving(stream []byte, readByteCount int) (netip.AddrPort, []byte, error) {
	chunkReader := &testChunkReader{stream: stream, byteCount: readByteCount}
	reader := bufio.NewReaderSize(chunkReader, testProxyMaxByteCount)
	visitorAddr, err := readProxyHeader(reader, testProxyMaxByteCount)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	unread, readErr := io.ReadAll(reader)
	if readErr != nil {
		return netip.AddrPort{}, nil, readErr
	}
	return visitorAddr, unread, nil
}

// The same without what it left.
func testReadProxyHeader(stream []byte, readByteCount int) (netip.AddrPort, error) {
	visitorAddr, _, err := testReadProxyHeaderLeaving(stream, readByteCount)
	return visitorAddr, err
}

// §22.6's bullet on one stream read in pieces of readByteCount. Also holds what the listener depends
// on: a header ends where the second reader says, so every byte after it survives, and how the bytes
// arrive changes nothing.
func testCheckProxyStream(t *testing.T, stream []byte, readByteCount int) {
	t.Helper()
	visitorAddr, unread, err := testReadProxyHeaderLeaving(stream, readByteCount)
	want, ok := testReferenceProxyHeader(stream, testProxyMaxByteCount)
	if ok != (err == nil) {
		t.Fatalf("%q: read gave %v, %v, and the second reader %v, %t", stream, visitorAddr, err, want, ok)
	}
	if !ok {
		return
	}
	if visitorAddr != want.visitorAddr {
		t.Fatalf("%q: visitor %v, and the second reader %v", stream, visitorAddr, want.visitorAddr)
	}
	if !bytes.Equal(unread, stream[want.byteCount:]) {
		t.Fatalf("%q: left %q past a header of %d B", stream, unread, want.byteCount)
	}
}

// The seeds, by file name: each header the listener takes and each shape it refuses.
func testProxyHeaderSeeds() map[string][]byte {
	hello := testRecords(testHelloMessage(testServerNameExtension(testServerName)))
	addresses4 := testProxyV2Addresses4("192.0.2.1", 56324, "198.51.100.2", 443)
	addresses6 := testProxyV2Addresses6("2001:db8::1", 56324, "2001:db8::2", 443)
	longest := "PROXY TCP6 ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"
	return map[string][]byte{
		"v1-tcp4":                append(testProxyV1("192.0.2.1", 56324, "198.51.100.2", 443), hello...),
		"v1-tcp6":                append(testProxyV1("2001:db8::1", 56324, "2001:db8::2", 443), hello...),
		"v1-4-in-6":              testProxyV1("::ffff:192.0.2.1", 56324, "::ffff:198.51.100.2", 443),
		"v1-longest":             []byte(longest),
		"v1-unknown":             []byte("PROXY UNKNOWN\r\n"),
		"v1-unknown-long":        []byte("PROXY UNKNOWN ffff::1 ffff::2 65535 65535\r\n"),
		"v1-port-past-range":     []byte("PROXY TCP4 192.0.2.1 198.51.100.2 99999 443\r\n"),
		"v1-port-leading-zero":   []byte("PROXY TCP4 192.0.2.1 198.51.100.2 056 443\r\n"),
		"v1-port-negative":       []byte("PROXY TCP4 192.0.2.1 198.51.100.2 -1 443\r\n"),
		"v1-extra-field":         []byte("PROXY TCP4 192.0.2.1 198.51.100.2 1 443 extra\r\n"),
		"v1-family-mismatch-4":   []byte("PROXY TCP4 2001:db8::1 2001:db8::2 1 2\r\n"),
		"v1-family-mismatch-6":   []byte("PROXY TCP6 192.0.2.1 198.51.100.2 1 2\r\n"),
		"v1-zoned-address":       []byte("PROXY TCP6 fe80::1%eth0 fe80::2 1 2\r\n"),
		"v1-no-cr":               []byte("PROXY TCP4 192.0.2.1 198.51.100.2 1 2\n"),
		"v1-double-space":        []byte("PROXY TCP4  192.0.2.1 198.51.100.2 1 2\r\n"),
		"v1-over-107":            []byte("PROXY TCP6 " + strings.Repeat("a", 95) + "\r\n"),
		"v2-tcp4":                append(testProxyV2(0x21, 0x11, addresses4), hello...),
		"v2-tcp6":                append(testProxyV2(0x21, 0x21, addresses6), hello...),
		"v2-tlvs":                testProxyV2OfByteCount(300),
		"v2-2048":                testProxyV2OfByteCount(2048),
		"v2-2049":                testProxyV2OfByteCount(2049),
		"v2-local":               testProxyV2(0x20, 0x00, nil),
		"v2-local-addresses":     testProxyV2(0x20, 0x11, addresses4),
		"v2-unspec":              testProxyV2(0x21, 0x00, nil),
		"v2-unspec-addresses":    testProxyV2(0x21, 0x00, addresses4),
		"v2-udp":                 testProxyV2(0x21, 0x12, addresses4),
		"v2-unix":                testProxyV2(0x21, 0x31, make([]byte, 216)),
		"v2-unknown-family":      testProxyV2(0x21, 0x13, addresses4),
		"v2-unknown-command":     testProxyV2(0x22, 0x11, addresses4),
		"v2-unknown-version":     testProxyV2(0x11, 0x11, addresses4),
		"v2-short-addresses":     testProxyV2(0x21, 0x11, addresses4[:5]),
		"v2-length-past-stream":  testProxyV2(0x21, 0x11, addresses4)[:20],
		"no-header-tls":          hello,
		"no-header-http":         []byte("GET / HTTP/1.1\r\n\r\n"),
		"no-header-starts-like":  []byte("PROXIES\r\n"),
		"no-header-v2-signature": []byte("\r\n\r\n\x00\r\nQUIT"),
	}
}

func FuzzProxyHeader(f *testing.F) {
	for _, arguments := range testReadFuzzSeeds(f, "FuzzProxyHeader") {
		f.Add(arguments[0].([]byte), arguments[1].(uint16))
	}
	f.Fuzz(func(t *testing.T, stream []byte, readByteCount uint16) {
		testCheckProxyStream(t, stream, int(readByteCount))
		testCheckProxyStream(t, stream, 1)
	})
}

// Each seed is on disk and answers as the name says, and the spec's worst-case line is the longest
// that passes.
func TestProxyHeaderSeedFiles(t *testing.T) {
	builders := testProxyHeaderSeeds()
	if *testWriteFuzzSeeds {
		seeds := map[string][]any{}
		for name, stream := range builders {
			seeds[name] = []any{stream, uint16(0)}
		}
		testWriteFuzzSeedFiles(t, "FuzzProxyHeader", seeds)
	}
	seeds := testReadFuzzSeeds(t, "FuzzProxyHeader")
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for name := range builders {
			if !yield(name) {
				return
			}
		}
	}) {
		arguments, ok := seeds[name]
		if !ok {
			t.Errorf("no seed file %s", name)
			continue
		}
		stream := arguments[0].([]byte)
		_, err := testReadProxyHeader(stream, 0)
		taken := slices.Contains([]string{"v1-tcp4", "v1-tcp6", "v1-4-in-6", "v2-tcp4", "v2-tcp6", "v2-tlvs", "v2-2048", "v1-longest"}, name)
		if taken != (err == nil) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if longest := builders["v1-longest"]; len(longest) != 104 {
		t.Errorf("the longest TCP6 line is %d B", len(longest))
	}
}

// pires's own constants must keep meaning what the framing assumes of them.
func TestProxyHeaderFramingMatchesPires(t *testing.T) {
	if !bytes.Equal(proxyproto.SIGV2, []byte("\r\n\r\n\x00\r\nQUIT\n")) {
		t.Errorf("signature %q", proxyproto.SIGV2)
	}
	if proxyHeaderV2FixedByteCount != len(proxyproto.SIGV2)+4 {
		t.Errorf("fixed part %d", proxyHeaderV2FixedByteCount)
	}
}
