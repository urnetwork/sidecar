// TlsEdgeOpen's 512 B (§13.5) against the longest name and a long ALPN list (plan-TLS-small-readings#6), what a
// listener's parse refuses, and the seeds and check of FuzzTlsEdgeOpen (tls_edge_open_fuzz_test.go): decoding is total,
// and what passes keeps the rules. Addresses are RFC 3849's and RFC 5737's documentation ranges.

package sidecar

import (
	"bytes"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A 253-byte name of canonical labels: 63, 63, 63 and 61 bytes.
func testTlsEdgeOpenLongestName() string {
	return strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." +
		strings.Repeat("d", 61)
}

// A TlsEdgeOpen with every field but alpn at its widest: an IPv6 address, and each number at its largest.
func testTlsEdgeOpenWidest(serverName string, alpn []string) *protocol.TlsEdgeOpen {
	return &protocol.TlsEdgeOpen{
		ClientIp:             []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
		ClientPort:           math.MaxUint32,
		ServerName:           serverName,
		Alpn:                 alpn,
		ClientHelloByteCount: math.MaxUint32,
		ConnectionId:         bytes.Repeat([]byte{0x5c}, 16),
		ExpireTimeMillis:     math.MaxUint64,
	}
}

// ids a hello may offer, far past what the bound holds: 120 ids of 1 to 255 bytes
func testTlsEdgeOpenLongAlpn() []string {
	offered := []string{"h2", "http/1.1"}
	for index := range 120 {
		offered = append(offered, strings.Repeat(string(rune('a'+index%26)), 1+(index*37)%255))
	}
	return offered
}

func TestTlsEdgeOpenFitsItsBoundWithTheLongestName(t *testing.T) {
	serverName := testTlsEdgeOpenLongestName()
	if len(serverName) != 253 {
		t.Fatalf("a %d-byte name", len(serverName))
	}
	offered := testTlsEdgeOpenLongAlpn()
	alpn := TrimTlsEdgeOpenAlpn(serverName, offered)
	if len(alpn) == 0 || len(offered) <= len(alpn) {
		t.Fatalf("kept %d of %d ids", len(alpn), len(offered))
	}
	encoded, err := proto.Marshal(testTlsEdgeOpenWidest(serverName, alpn))
	if err != nil {
		t.Fatal(err)
	}
	if TlsEdgeOpenMaxByteCount < len(encoded) {
		t.Errorf("%d B, over %d", len(encoded), TlsEdgeOpenMaxByteCount)
	}
	// the trim is the bound, not short of it: the next offered id would not have fit
	grown, err := proto.Marshal(testTlsEdgeOpenWidest(serverName, offered[:len(alpn)+1]))
	if err != nil {
		t.Fatal(err)
	}
	if len(grown) <= TlsEdgeOpenMaxByteCount {
		t.Errorf("the next id fits too, at %d B", len(grown))
	}
	// with a port a visitor can have, 2 bytes under what the bound was taken at, a listener reads it
	open := testTlsEdgeOpenWidest(serverName, alpn)
	open.ClientPort = 65535
	listened, err := proto.Marshal(open)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTlsEdgeOpen(listened); err != nil {
		t.Errorf("a listener refuses it: %v", err)
	}
}

// Ids stay in hello order, and none after the first that does not fit, so a short id cannot jump the visitor's order.
func TestTrimTlsEdgeOpenAlpnKeepsHelloOrder(t *testing.T) {
	serverName := testTlsEdgeOpenLongestName()
	// 59 B of other fields and 256 of name leave 197: "h2" takes 4 and the long id 195, so "x" no longer fits after it
	offered := []string{"h2", strings.Repeat("p", 192), "x", "http/1.1"}
	alpn := TrimTlsEdgeOpenAlpn(serverName, offered)
	if !slices.Equal(alpn, offered[:1]) {
		t.Errorf("kept %q", alpn)
	}
	short := []string{"h2", "http/1.1", "acme-tls/1"}
	if alpn := TrimTlsEdgeOpenAlpn("blog.k7m2q9xa.ur.example", short); !slices.Equal(alpn, short) {
		t.Errorf("a short list came back %q", alpn)
	}
	if alpn := TrimTlsEdgeOpenAlpn(serverName, nil); alpn == nil || len(alpn) != 0 {
		t.Errorf("no ids came back %q", alpn)
	}
}

// An id a proto3 string cannot hold is passed over, so one visitor's GREASE does not refuse the whole message.
func TestTrimTlsEdgeOpenAlpnPassesOverWhatIsNotUtf8(t *testing.T) {
	offered := []string{"\xda\xda", "h2", "\x0a\x0a", "\xff", "http/1.1"}
	alpn := TrimTlsEdgeOpenAlpn("blog.k7m2q9xa.ur.example", offered)
	if want := []string{"h2", "\x0a\x0a", "http/1.1"}; !slices.Equal(alpn, want) {
		t.Errorf("kept %q", alpn)
	}
	if _, err := proto.Marshal(testTlsEdgeOpenWidest("blog.k7m2q9xa.ur.example", alpn)); err != nil {
		t.Errorf("the kept list does not encode: %v", err)
	}
}

func TestParseTlsEdgeOpenReadsWhatTlsedgeWrites(t *testing.T) {
	for _, clientIp := range [][]byte{{192, 0, 2, 7}, bytes.Repeat([]byte{0x20}, 16)} {
		open := &protocol.TlsEdgeOpen{
			ClientIp:             clientIp,
			ClientPort:           65535,
			ServerName:           "blog.k7m2q9xa.ur.example",
			Alpn:                 []string{"h2", "http/1.1"},
			ClientHelloByteCount: 1789,
			ConnectionId:         bytes.Repeat([]byte{0x01}, 16),
			// a standing name's grant has no expiry
			ExpireTimeMillis: 0,
		}
		encoded, err := proto.Marshal(open)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseTlsEdgeOpen(encoded)
		if err != nil || !proto.Equal(parsed, open) {
			t.Errorf("%x: %v %v", clientIp, parsed, err)
		}
	}
}

func TestParseTlsEdgeOpenRefusesWhatTlsedgeNeverWrites(t *testing.T) {
	valid := func() *protocol.TlsEdgeOpen {
		return &protocol.TlsEdgeOpen{
			ClientIp:     []byte{192, 0, 2, 7},
			ClientPort:   443,
			ServerName:   "blog.k7m2q9xa.ur.example",
			ConnectionId: bytes.Repeat([]byte{0x01}, 16),
		}
	}
	cases := []func(*protocol.TlsEdgeOpen){
		func(open *protocol.TlsEdgeOpen) { open.ClientIp = nil },
		func(open *protocol.TlsEdgeOpen) { open.ClientIp = []byte{192, 0, 2, 7, 0} },
		func(open *protocol.TlsEdgeOpen) { open.ClientPort = 65536 },
		func(open *protocol.TlsEdgeOpen) { open.ServerName = "" },
		func(open *protocol.TlsEdgeOpen) { open.ServerName = "Blog.k7m2q9xa.ur.example" },
		func(open *protocol.TlsEdgeOpen) { open.ServerName = "blog.k7m2q9xa.ur.example." },
		func(open *protocol.TlsEdgeOpen) { open.ServerName = "*.k7m2q9xa.ur.example" },
		func(open *protocol.TlsEdgeOpen) { open.ServerName = "bl_og.k7m2q9xa.ur.example" },
		func(open *protocol.TlsEdgeOpen) { open.ConnectionId = nil },
		func(open *protocol.TlsEdgeOpen) { open.ConnectionId = bytes.Repeat([]byte{0x01}, 15) },
		// past the bound, though every field is well formed
		func(open *protocol.TlsEdgeOpen) {
			open.Alpn = []string{strings.Repeat("h", 255), strings.Repeat("i", 255)}
		},
	}
	for index, mutate := range cases {
		open := valid()
		mutate(open)
		encoded, err := proto.Marshal(open)
		if err != nil {
			t.Fatal(err)
		}
		if parsed, err := ParseTlsEdgeOpen(encoded); !errors.Is(err, ErrTlsEdgeOpen) || parsed != nil {
			t.Errorf("case %d: %v %v", index, parsed, err)
		}
	}
	// bytes that are no message at all: a truncated length and a string that is not UTF-8
	for _, encoded := range [][]byte{{0x0a, 0x10, 0x01}, {0x1a, 0x01, 0xff}} {
		if parsed, err := ParseTlsEdgeOpen(encoded); !errors.Is(err, ErrTlsEdgeOpen) || parsed != nil {
			t.Errorf("%x: %v %v", encoded, parsed, err)
		}
	}
}

// What FuzzTlsEdgeOpen starts from: the widest message, cut short, grown, repeated, with a field no tlsedge writes yet,
// and bytes that are no message.
func testTlsEdgeOpenSeeds(t testing.TB) [][]byte {
	serverName := testTlsEdgeOpenLongestName()
	widest, err := proto.Marshal(testTlsEdgeOpenWidest(serverName, TrimTlsEdgeOpenAlpn(serverName, testTlsEdgeOpenLongAlpn())))
	if err != nil {
		t.Fatal(err)
	}
	short, err := proto.Marshal(&protocol.TlsEdgeOpen{
		ClientIp:     []byte{198, 51, 100, 9},
		ClientPort:   8443,
		ServerName:   "k7m2q9xa.ur.example",
		Alpn:         []string{"h2"},
		ConnectionId: bytes.Repeat([]byte{0x02}, 16),
	})
	if err != nil {
		t.Fatal(err)
	}
	return [][]byte{
		widest,
		widest[:len(widest)/2],
		append(slices.Clone(widest), 0x38, 0x01),
		short,
		append(slices.Clone(short), short...),
		append(slices.Clone(short), 0x40, 0x07),
		{},
		bytes.Repeat([]byte{0x22, 0x00}, 300),
	}
}

// Decoding is total: any bytes give a TlsEdgeOpen that keeps §13.5's rules, or an error and nothing, and what passes
// re-encodes inside the bound and parses again to the same message.
func testTlsEdgeOpenDecodesTotally(t testing.TB, metadata []byte) {
	open, err := ParseTlsEdgeOpen(metadata)
	if err != nil {
		if open != nil || !errors.Is(err, ErrTlsEdgeOpen) {
			t.Fatalf("a refusal came back with %v, %v", open, err)
		}
		return
	}
	if n := len(open.GetClientIp()); n != 4 && n != 16 {
		t.Fatalf("a %d-byte client_ip", n)
	}
	if 65535 < open.GetClientPort() || len(open.GetConnectionId()) != 16 {
		t.Fatalf("port %d, connection_id %x", open.GetClientPort(), open.GetConnectionId())
	}
	if !tlsDnsNameCanonical(open.GetServerName()) {
		t.Fatalf("server_name %q", open.GetServerName())
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(open)
	if err != nil {
		t.Fatal(err)
	}
	if TlsEdgeOpenMaxByteCount < len(encoded) {
		t.Fatalf("re-encoded at %d B", len(encoded))
	}
	again, err := ParseTlsEdgeOpen(encoded)
	if err != nil || !proto.Equal(again, open) {
		t.Fatalf("re-encoded, it reads as %v, %v", again, err)
	}
}

// FuzzTlsEdgeOpen's seeds on every leg, the sidecar_http Worker's included, where a fuzz target cannot run.
func TestTlsEdgeOpenSeedsDecodeTotally(t *testing.T) {
	for _, metadata := range testTlsEdgeOpenSeeds(t) {
		testTlsEdgeOpenDecodesTotally(t, metadata)
	}
}
