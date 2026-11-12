//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bufio"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// One raw HTTP/1.1 request over a fresh visitor connection, and the front's answer.
func (self *tlsFrontFixture) rawRequest(request string) *http.Response {
	self.t.Helper()
	conn, err := self.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := io.WriteString(conn, request); err != nil {
		self.t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		self.t.Fatal(err)
	}
	io.ReadAll(response.Body)
	response.Body.Close()
	return response
}

// §22.5's 421 (RFC 9113 §9.1.1): a Host, an :authority or an absolute-form target for another host is answered 421 and
// reaches nothing, the network's other hosts included; the SNI's own, port and case aside, passes.
func TestTlsHttpAnswers421ForAnotherHost(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	misdirected := []string{
		"GET / HTTP/1.1\r\nHost: " + tlsFrontTestOtherName + "\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + tlsFrontTestOtherName + ":443\r\n\r\n",
		"GET https://" + tlsFrontTestOtherName + "/ HTTP/1.1\r\nHost: " + tlsFrontTestServerName + "\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: [2001:db8::1]:443\r\n\r\n",
	}
	for _, request := range misdirected {
		if response := fixture.rawRequest(request); response.StatusCode != http.StatusMisdirectedRequest {
			t.Errorf("%q: %d", request, response.StatusCode)
		}
	}
	// h2's :authority
	client := fixture.httpClient(tlsAlpnH2)
	request := tlsFrontTestNavigation(t, http.MethodGet, "/")
	request.Host = tlsFrontTestOtherName
	if response, _ := tlsFrontTestDo(t, client, request); response.StatusCode != http.StatusMisdirectedRequest || response.ProtoMajor != 2 {
		t.Errorf(":authority: %d over HTTP/%d", response.StatusCode, response.ProtoMajor)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Fatalf("%d dials for misdirected requests", dials)
	}
	matching := []string{
		"GET / HTTP/1.1\r\nHost: " + tlsFrontTestServerName + "\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + tlsFrontTestServerName + ":443\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + tlsFrontTestServerName + ":8443\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: " + strings.ToUpper(tlsFrontTestServerName) + "\r\n\r\n",
		"GET https://" + tlsFrontTestServerName + "/ HTTP/1.1\r\nHost: " + tlsFrontTestServerName + "\r\n\r\n",
	}
	for _, request := range matching {
		if response := fixture.rawRequest(request); response.StatusCode != http.StatusOK {
			t.Errorf("%q: %d", request, response.StatusCode)
		}
		fixture.backend.nextRequest(t)
	}
}

// §13.7's HTTP/3 row: the service's Alt-Svc loses its h3 entries, drafts included, and keeps the rest in order.
func TestTlsHttpStripsAltSvcH3(t *testing.T) {
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.backend.answerHeader.Add("Alt-Svc", `h3=":443"; ma=86400, h3-29=":443"; ma=86400, h2="alt.example:443"; ma=60`)
		fixture.backend.answerHeader.Add("Alt-Svc", `h3=":8443"`)
	})
	response, _ := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), tlsFrontTestNavigation(t, http.MethodGet, "/"))
	if values := response.Header.Values("Alt-Svc"); !slices.Equal(values, []string{`h2="alt.example:443"; ma=60`}) {
		t.Errorf("Alt-Svc %q", values)
	}
	header := http.Header{}
	header.Add("Alt-Svc", `h3=":443", H3-34=":443"`)
	tlsHttpStripAltSvcH3(header)
	if _, ok := header["Alt-Svc"]; ok {
		t.Errorf("an all-h3 Alt-Svc kept %q", header.Values("Alt-Svc"))
	}
	header.Set("Alt-Svc", "clear")
	tlsHttpStripAltSvcH3(header)
	if header.Get("Alt-Svc") != "clear" {
		t.Errorf("clear became %q", header.Get("Alt-Svc"))
	}
	if got := tlsHttpSplitAltSvc(`h2="a,b:443"; ma=1, h3=":443"`); !slices.Equal(got, []string{`h2="a,b:443"; ma=1`, `h3=":443"`}) {
		t.Errorf("split %q", got)
	}
}

// The front's own cookies never reach the service, every other cookie does, and the service can neither set nor
// clear one of the front's.
func TestTlsHttpFrontCookiesNeverReachTheBackend(t *testing.T) {
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.backend.answerHeader.Add("Set-Cookie", "__Host-ur-session=forged; Path=/; Secure")
		fixture.backend.answerHeader.Add("Set-Cookie", "__HOST-UR-link=forged; Path=/; Secure")
		fixture.backend.answerHeader.Add("Set-Cookie", "theme=dark; Path=/")
	})
	request := tlsFrontTestNavigation(t, http.MethodGet, "/")
	request.Header.Add("Cookie", "__Host-ur-session=sealed; theme=light; __Host-ur-pre=pending")
	request.Header.Add("Cookie", "__Host-ur-link=token; __host-ur-notice=1")
	response, _ := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), request)
	backendRequest := fixture.backend.nextRequest(t)
	if cookies := backendRequest.header.Values("Cookie"); !slices.Equal(cookies, []string{"theme=light"}) {
		t.Errorf("the backend saw cookies %q", cookies)
	}
	if setCookies := response.Header.Values("Set-Cookie"); !slices.Equal(setCookies, []string{"theme=dark; Path=/"}) {
		t.Errorf("the visitor got %q", setCookies)
	}
	header := http.Header{}
	header.Set("Cookie", "__Host-ur-session=x")
	tlsHttpStripFrontCookies(header)
	if _, ok := header["Cookie"]; ok {
		t.Error("an empty Cookie header was kept")
	}
}

// §13.7's visitor address row: none by default and no client-sent Forwarded or X-Forwarded- header either way; with
// the option on, Forwarded carries the edge's visitor address.
func TestTlsHttpForwardedOnlyOnRequest(t *testing.T) {
	for _, forwarded := range []bool{false, true} {
		fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
			fixture.target.Forwarded = forwarded
		})
		request := tlsFrontTestNavigation(t, http.MethodGet, "/")
		request.Header.Set("Forwarded", `for="198.51.100.66"`)
		request.Header.Set("X-Forwarded-For", "198.51.100.66")
		request.Header.Set("X-Forwarded-Host", "spoofed.example")
		tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), request)
		header := fixture.backend.nextRequest(t).header
		for _, name := range []string{"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
			if values := header.Values(name); 0 < len(values) {
				t.Errorf("forwarded %t: %s %q", forwarded, name, values)
			}
		}
		want := []string{}
		if forwarded {
			want = []string{`for="[2001:db8::7]:40000";proto=https;host=` + tlsFrontTestServerName}
		}
		if values := header.Values("Forwarded"); !slices.Equal(values, want) && !(len(values) == 0 && len(want) == 0) {
			t.Errorf("forwarded %t: Forwarded %q", forwarded, values)
		}
	}
}

// --proxy-protocol's PROXY v2 option on http: each target connection begins with the visitor's header.
func TestTlsHttpSendsProxyV2OnRequest(t *testing.T) {
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.target.ProxyProtocol = true
		fixture.backend = newTlsFrontTestBackend(false)
	})
	conn, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+tlsFrontTestServerName+"\r\n\r\n")
	first := <-fixture.backend.firstReads
	// the header goes in a write of its own, ahead of the request's first byte
	if header := tlsProxyV2Header(tlsFrontTestVisitor(), 443); string(first) != string(header) {
		t.Errorf("the backend read %q first", first)
	}
}

// /.well-known/ur/ is the front's in every spelling the service could take for it, and no request under it reaches
// the service.
func TestTlsHttpWellKnownNeverReachesTheService(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	for _, path := range []string{"/.well-known/ur", "/.well-known/ur/", "/.well-known/ur/other", "/x/../.well-known/ur/callback",
		"/./.well-known/ur/link", "/.well-known/ur/callback?code=c&state=s"} {
		response := fixture.rawRequest("GET " + path + " HTTP/1.1\r\nHost: " + tlsFrontTestServerName + "\r\n\r\n")
		if response.StatusCode == http.StatusOK {
			t.Errorf("%s: %d", path, response.StatusCode)
		}
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
	for _, path := range []string{"/.well-known/urx", "/.well-known/acme-challenge/x", "/well-known/ur/"} {
		if tlsHttpFrontPath(path) {
			t.Errorf("%s read as the front's", path)
		}
	}
}

// A WebSocket upgrade passes once its request passes the audience check, and the hijacked stream then carries bytes
// both ways.
func TestTlsHttpWebSocketPassesAfterTheCheck(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	conn, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: "+tlsFrontTestServerName+"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-Fetch-Site: same-origin\r\n"+
		"Sec-Fetch-Mode: websocket\r\nSec-Fetch-Dest: websocket\r\n\r\n")
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, nil)
	if err != nil || response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v", err)
	}
	if fixture.backend.nextRequest(t).header.Get("Upgrade") != "websocket" {
		t.Error("the backend saw no upgrade")
	}
	io.WriteString(conn, "frame")
	echo := make([]byte, len("frame"))
	if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "frame" {
		t.Errorf("echo %q: %v", echo, err)
	}
}

// Under link, with no link cookie, a request is refused with 403 and reaches nothing.
func TestTlsHttpLinkWithoutItsCookieIsRefused(t *testing.T) {
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_LINK, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	})
	response, _ := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), tlsFrontTestNavigation(t, http.MethodGet, "/"))
	if response.StatusCode != http.StatusForbidden {
		t.Errorf("%d", response.StatusCode)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}

// A request reaching the target transport without a pass is refused there, whatever else it carries (FI-11).
func TestTlsHttpTargetTransportNeedsAPass(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (tlsHttpTargetTransport{}).RoundTrip(request); err != errTlsFrontNoPass {
		t.Errorf("no pass: %v", err)
	}
	conn := &TlsFrontConn{}
	if _, err := conn.openTarget(request.Context(), nil); err != errTlsFrontNoPass {
		t.Errorf("open without a pass: %v", err)
	}
	if _, err := conn.openTarget(request.Context(), &tlsAudiencePass{conn: &TlsFrontConn{}}); err != errTlsFrontNoPass {
		t.Errorf("another connection's pass: %v", err)
	}
}
