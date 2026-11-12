//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// RFC 7301 §3.2 on http: an id the mode does not serve fails the handshake with no_application_protocol, and one it
// serves wins over any other the hello offers.
func TestTlsDispatchRefusesAnUnservedAlpnOnHttp(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	for _, offered := range [][]string{{"imap"}, {"imap", "smtp"}, {"h3"}} {
		if _, err := fixture.dialTls(tlsFrontTestClientConfig(offered...), nil); !tlsFrontTestAlert(err, "no application protocol") {
			t.Errorf("%v: %v", offered, err)
		}
	}
	for _, c := range []struct {
		offered []string
		want    string
	}{
		{offered: []string{"imap", tlsAlpnH2}, want: tlsAlpnH2},
		{offered: []string{tlsAlpnHttp11, "imap"}, want: tlsAlpnHttp11},
		{offered: nil, want: ""},
	} {
		conn, err := fixture.dialTls(tlsFrontTestClientConfig(c.offered...), nil)
		if err != nil || conn.ConnectionState().NegotiatedProtocol != c.want {
			t.Errorf("%v: %v", c.offered, err)
		}
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}

// D-TLS-13: the registration's mode and the grant's must agree, and a raw registration stands only on public or a
// pinned link; anything else refuses the handshake, whatever ALPN offers.
func TestTlsDispatchRefusesAGrantOfAnotherMode(t *testing.T) {
	for _, c := range []struct {
		appMode   string
		audience  protocol.AclAudience
		grantMode protocol.AclAppMode
		pin       []byte
	}{
		{appMode: "http", audience: protocol.AclAudience_ACL_AUDIENCE_PUBLIC, grantMode: protocol.AclAppMode_ACL_APP_MODE_RAW},
		{appMode: "raw", audience: protocol.AclAudience_ACL_AUDIENCE_PUBLIC, grantMode: protocol.AclAppMode_ACL_APP_MODE_HTTP},
		{appMode: "raw", audience: protocol.AclAudience_ACL_AUDIENCE_MEMBERS, grantMode: protocol.AclAppMode_ACL_APP_MODE_RAW},
		{appMode: "raw", audience: protocol.AclAudience_ACL_AUDIENCE_LINK, grantMode: protocol.AclAppMode_ACL_APP_MODE_RAW},
		{appMode: "raw", audience: protocol.AclAudience_ACL_AUDIENCE_LINK, grantMode: protocol.AclAppMode_ACL_APP_MODE_RAW, pin: []byte{1}},
	} {
		fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
			fixture.target.AppMode = c.appMode
			fixture.policy.setGrant(c.audience, c.grantMode, c.pin)
		})
		for _, offered := range [][]string{nil, {tlsAlpnHttp11}, {tlsAlpnH2}} {
			if _, err := fixture.dialTls(tlsFrontTestClientConfig(offered...), nil); err == nil {
				t.Errorf("%s under %s %s: %v completed", c.appMode, c.audience, c.grantMode, offered)
			}
		}
	}
}

// With no grant at all, nothing completes.
func TestTlsDispatchRefusesWithoutAGrant(t *testing.T) {
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.policy.grant = nil
	})
	if _, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil); err == nil {
		t.Fatal("a handshake with no grant completed")
	}
}

// NextProtos pins crypto/tls to the decision: one id picked in served order, served's list when nothing is
// offered, and the refusal alone when nothing offered is served.
func TestTlsSelectAlpn(t *testing.T) {
	for _, c := range []struct {
		offered []string
		served  []string
		want    []string
	}{
		{offered: nil, served: []string{tlsAlpnH2, tlsAlpnHttp11}, want: []string{tlsAlpnH2, tlsAlpnHttp11}},
		{offered: []string{tlsAlpnHttp11, tlsAlpnH2}, served: []string{tlsAlpnH2, tlsAlpnHttp11}, want: []string{tlsAlpnH2}},
		{offered: []string{tlsAlpnHttp11}, served: []string{tlsAlpnH2, tlsAlpnHttp11}, want: []string{tlsAlpnHttp11}},
		{offered: []string{"imap"}, served: []string{tlsAlpnH2, tlsAlpnHttp11}, want: []string{tlsAlpnRefuseAll}},
		// RFC 7301's h2 fallback for an http/1.1 client never applies: raw serving h2 alone refuses it
		{offered: []string{tlsAlpnHttp11}, served: []string{tlsAlpnH2}, want: []string{tlsAlpnRefuseAll}},
		{offered: nil, served: nil, want: nil},
		{offered: []string{"mqtt"}, served: nil, want: []string{tlsAlpnRefuseAll}},
	} {
		if got := tlsSelectAlpn(c.offered, c.served); !slices.Equal(got, c.want) {
			t.Errorf("%v of %v: %v", c.offered, c.served, got)
		}
	}
}

// The route never follows ALPN's absence: http with nothing offered is the HTTP front, raw with nothing offered the
// forward, each only under the grant its mode needs.
func TestTlsDispatchRouteKeysOnTheMode(t *testing.T) {
	http := &TlsFrontTarget{AppMode: "http"}
	raw := &TlsFrontTarget{AppMode: "raw", Alpn: []string{"mqtt"}}
	publicHttp := &TlsPublishGrant{Audience: protocol.AclAudience_ACL_AUDIENCE_PUBLIC, AppMode: protocol.AclAppMode_ACL_APP_MODE_HTTP}
	membersHttp := &TlsPublishGrant{Audience: protocol.AclAudience_ACL_AUDIENCE_MEMBERS, AppMode: protocol.AclAppMode_ACL_APP_MODE_HTTP}
	publicRaw := &TlsPublishGrant{Audience: protocol.AclAudience_ACL_AUDIENCE_PUBLIC, AppMode: protocol.AclAppMode_ACL_APP_MODE_RAW}
	linkRaw := &TlsPublishGrant{Audience: protocol.AclAudience_ACL_AUDIENCE_LINK, AppMode: protocol.AclAppMode_ACL_APP_MODE_RAW, LinkSpkiSha256: make([]byte, 32)}
	for _, c := range []struct {
		target *TlsFrontTarget
		grant  *TlsPublishGrant
		route  tlsFrontRoute
	}{
		{target: http, grant: publicHttp, route: tlsFrontRouteHttp},
		{target: http, grant: membersHttp, route: tlsFrontRouteHttp},
		{target: raw, grant: publicRaw, route: tlsFrontRouteRaw},
		{target: raw, grant: linkRaw, route: tlsFrontRouteRaw},
		{target: http, grant: publicRaw, route: tlsFrontRouteNone},
		{target: raw, grant: publicHttp, route: tlsFrontRouteNone},
		{target: raw, grant: nil, route: tlsFrontRouteNone},
	} {
		route, _, err := tlsDispatchRoute(c.target, c.grant, nil)
		if route != c.route || (c.route == tlsFrontRouteNone) != (err != nil) {
			t.Errorf("%s under %+v: route %d, %v", c.target.AppMode, c.grant, route, err)
		}
	}
}
