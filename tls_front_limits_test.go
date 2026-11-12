//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"crypto/tls"
	"net/netip"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// §13.7: one visitor, a /64 or a /32, holds at most 1/8 of max_streams and at least one; another visitor has its own
// share; a released stream frees its slot.
func TestTlsFrontVisitorShareIsAnEighth(t *testing.T) {
	visitors := newTlsFrontVisitors(DefaultTlsFrontSettings(), 16)
	same := [][]byte{
		netip.MustParseAddr("2001:db8::1").AsSlice(),
		netip.MustParseAddr("2001:db8::ffff:2").AsSlice(),
	}
	releases := []func(){}
	for _, clientIp := range same {
		release, ok := visitors.take(clientIp)
		if !ok {
			t.Fatal("a visitor within its share refused")
		}
		releases = append(releases, release)
	}
	if _, ok := visitors.take(netip.MustParseAddr("2001:db8::3").AsSlice()); ok {
		t.Error("a third stream of one /64 under 16 max_streams")
	}
	if release, ok := visitors.take(netip.MustParseAddr("2001:db8:0:1::1").AsSlice()); !ok {
		t.Error("another /64 refused")
	} else {
		release()
	}
	releases[0]()
	releases[0]()
	if visitors.heldBy(same[0]) != 1 {
		t.Errorf("held %d after one release", visitors.heldBy(same[0]))
	}
	if _, ok := visitors.take(same[0]); !ok {
		t.Error("a released slot stayed taken")
	}

	ipv4 := newTlsFrontVisitors(DefaultTlsFrontSettings(), 7)
	if _, ok := ipv4.take(netip.MustParseAddr("192.0.2.1").AsSlice()); !ok {
		t.Fatal("an IPv4 visitor refused its one stream")
	}
	if _, ok := ipv4.take(netip.MustParseAddr("::ffff:192.0.2.1").AsSlice()); ok {
		t.Error("an IPv4-mapped address took a second stream of its /32")
	}
	if _, ok := ipv4.take(netip.MustParseAddr("192.0.2.2").AsSlice()); !ok {
		t.Error("another /32 refused")
	}
	if _, ok := ipv4.take([]byte{1, 2, 3}); ok {
		t.Error("an address that is none")
	}
}

// A stream past its visitor's share resets with RST_CANCELLED before its hello is read; one from another visitor
// goes on.
func TestTlsFrontResetsAVisitorPastItsShare(t *testing.T) {
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.target.MaxStreams = 8
	})
	if _, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil); err != nil {
		t.Fatal(err)
	}
	if code := tlsFrontTestResetCode(t, fixture.openStream(nil)); code != protocol.StreamResetCode_RST_CANCELLED {
		t.Errorf("past the share: reset %s", code)
	}
	other := fixture.openStream(func(ticket *protocol.SocketTicket, open *protocol.TlsEdgeOpen) []byte {
		open.ClientIp = netip.MustParseAddr("2001:db8:0:9::1").AsSlice()
		return nil
	})
	conn := tls.Client(other, tlsFrontTestClientConfig(tlsAlpnHttp11))
	if err := conn.Handshake(); err != nil {
		t.Errorf("another visitor: %v", err)
	}
	conn.Close()
}
