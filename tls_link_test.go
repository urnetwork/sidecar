//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A publishing device: its sidecar id and identity key, signing as Sidecar.Sign does.
type tlsLinkTestPublisher struct {
	sidecarId  Id
	privateKey ed25519.PrivateKey
}

// A publisher with a fresh key.
func newTlsLinkTestPublisher(t *testing.T) *tlsLinkTestPublisher {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsLinkTestPublisher{sidecarId: NewId(), privateKey: privateKey}
}

// Sidecar.Sign's shape over this publisher's key.
func (self *tlsLinkTestPublisher) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Type:      uint32(signedType),
		Body:      body,
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.privateKey, bridge.SignedBytes(purpose, signedType, body)),
	}, nil
}

// A link fixture: the endpoint published to link, the publisher admitted and holding the same grant.
func newTlsLinkFixture(t *testing.T) (*tlsFrontFixture, *tlsLinkTestPublisher, *TlsPublishGrant) {
	t.Helper()
	publisher := newTlsLinkTestPublisher(t)
	var grant *TlsPublishGrant
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		grant = fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_LINK, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
		grant.Expires = fixture.clock.Now().Add(48 * time.Hour)
		fixture.policy.signerGrants[publisher.sidecarId] = grant
		fixture.policy.identityKeys[publisher.sidecarId] = publisher.privateKey.Public().(ed25519.PublicKey)
	})
	return fixture, publisher, grant
}

// A signed token for the endpoint under grantId until expireTime, its encoded Signed.
func (self *tlsLinkTestPublisher) token(t *testing.T, grantId []byte, host string, expireTime time.Time) []byte {
	t.Helper()
	token, err := NewTlsLinkToken(grantId, host, expireTime)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignTlsLinkToken(token, self.sign)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// GET of a link's URL as a guest's browser opens it from a chat, and the front's answer.
func tlsLinkTestOpen(t *testing.T, client *http.Client, link string) *http.Response {
	t.Helper()
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	request := tlsFrontTestNavigation(t, http.MethodGet, parsed.RequestURI())
	request.Header.Set(tlsHttpHeaderFetchSite, "cross-site")
	response, _ := tlsFrontTestDo(t, client, request)
	return response
}

// A navigation to path carrying linkCookie's value.
func tlsLinkTestVisit(t *testing.T, client *http.Client, value string) *http.Response {
	t.Helper()
	request := tlsFrontTestNavigation(t, http.MethodGet, "/shared")
	request.AddCookie(&http.Cookie{Name: tlsLinkCookieName, Value: value})
	response, _ := tlsFrontTestDo(t, client, request)
	return response
}

// QD-134's trade: the link's token becomes __Host-ur-link holding the same token, 12 h or the token's expiry, then a
// 302 to / with no referrer; the cookie then reaches the service, which never sees the cookie or the token.
func TestTlsLinkTradesATokenForACookie(t *testing.T) {
	fixture, publisher, grant := newTlsLinkFixture(t)
	client := fixture.httpClient(tlsAlpnHttp11)
	signed := publisher.token(t, grant.GrantIds[0], tlsFrontTestServerName, fixture.clock.Now().Add(24*time.Hour))
	link := TlsLinkUrl(tlsFrontTestServerName, signed)
	if want := "https://" + tlsFrontTestServerName + "/.well-known/ur/link?t=" + base64.RawURLEncoding.EncodeToString(signed); link != want {
		t.Fatalf("url %q", link)
	}
	response := tlsLinkTestOpen(t, client, link)
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/" || response.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("trade: %d to %q", response.StatusCode, response.Header.Get("Location"))
	}
	cookie := tlsEdgeTestCookie(response, tlsLinkCookieName)
	if cookie == nil || cookie.Value != base64.RawURLEncoding.EncodeToString(signed) || !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.MaxAge != int((12*time.Hour)/time.Second) {
		t.Fatalf("cookie %+v", cookie)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Fatalf("%d dials during the trade", dials)
	}
	if response := tlsLinkTestVisit(t, client, cookie.Value); response.StatusCode != http.StatusOK {
		t.Fatalf("with the cookie: %d", response.StatusCode)
	}
	if request := fixture.backend.nextRequest(t); 0 < len(request.header.Values("Cookie")) {
		t.Errorf("the backend saw %q", request.header.Values("Cookie"))
	}

	// a token ending within 12 h caps the cookie
	shortLived := publisher.token(t, grant.GrantIds[0], tlsFrontTestServerName, fixture.clock.Now().Add(90*time.Minute))
	if cookie := tlsEdgeTestCookie(tlsLinkTestOpen(t, client, TlsLinkUrl(tlsFrontTestServerName, shortLived)), tlsLinkCookieName); cookie == nil ||
		cookie.MaxAge != int((90*time.Minute)/time.Second) {
		t.Errorf("a short token's cookie %+v", cookie)
	}
}

// QD-134: a link is reusable until its grant ends, so it trades again and again; a revoked grant, the grant's own
// expiry or the token's ends every link of it at the next request, the cookie with it.
func TestTlsLinkTokenLastsAsLongAsItsGrant(t *testing.T) {
	fixture, publisher, grant := newTlsLinkFixture(t)
	client := fixture.httpClient(tlsAlpnHttp11)
	signed := publisher.token(t, grant.GrantIds[0], tlsFrontTestServerName, fixture.clock.Now().Add(24*time.Hour))
	link := TlsLinkUrl(tlsFrontTestServerName, signed)
	for i := 0; i < 3; i += 1 {
		if response := tlsLinkTestOpen(t, client, link); response.StatusCode != http.StatusFound {
			t.Fatalf("use %d: %d", i, response.StatusCode)
		}
	}
	value := base64.RawURLEncoding.EncodeToString(signed)
	fixture.clock.advance(24 * time.Hour)
	if response := tlsLinkTestVisit(t, client, value); response.StatusCode != http.StatusForbidden {
		t.Errorf("past the token's expiry: %d", response.StatusCode)
	}
	if response := tlsLinkTestOpen(t, client, link); response.StatusCode != http.StatusForbidden {
		t.Errorf("an expired link traded: %d", response.StatusCode)
	}
	fresh := publisher.token(t, grant.GrantIds[0], tlsFrontTestServerName, fixture.clock.Now().Add(12*time.Hour))
	if response := tlsLinkTestVisit(t, client, base64.RawURLEncoding.EncodeToString(fresh)); response.StatusCode != http.StatusOK {
		t.Fatalf("a fresh link: %d", response.StatusCode)
	}
	fixture.backend.nextRequest(t)
	// GrantRevoke: the endpoint's evaluation no longer holds the grant
	fixture.policy.stateLock.Lock()
	fixture.policy.grant = nil
	fixture.policy.stateLock.Unlock()
	if response := tlsLinkTestVisit(t, client, base64.RawURLEncoding.EncodeToString(fresh)); response.StatusCode != http.StatusForbidden {
		t.Errorf("after the grant went: %d", response.StatusCode)
	}
	if dials, _ := fixture.backend.counts(); dials != 1 {
		t.Errorf("%d dials", dials)
	}
}

// A token verifies only when every one of QD-134's checks holds: signer, signature, grant, host and expiry.
func TestTlsLinkRefusesBadTokens(t *testing.T) {
	fixture, publisher, grant := newTlsLinkFixture(t)
	client := fixture.httpClient(tlsAlpnHttp11)
	now := fixture.clock.Now()
	stranger := newTlsLinkTestPublisher(t)
	fixture.policy.identityKeys[stranger.sidecarId] = stranger.privateKey.Public().(ed25519.PublicKey)
	unknown := newTlsLinkTestPublisher(t)
	tampered := publisher.token(t, grant.GrantIds[0], tlsFrontTestServerName, now.Add(time.Hour))
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(tampered, signed); err != nil {
		t.Fatal(err)
	}
	signed.Body[len(signed.Body)-1] ^= 1
	tamperedBytes, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	attestationType := &bridge.Signed{}
	proto.Unmarshal(publisher.token(t, grant.GrantIds[0], tlsFrontTestServerName, now.Add(time.Hour)), attestationType)
	attestationType.Type = uint32(bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION)
	attestationTypeBytes, _ := proto.Marshal(attestationType)
	for _, c := range []struct {
		name   string
		signed []byte
	}{
		{name: "another host", signed: publisher.token(t, grant.GrantIds[0], tlsFrontTestOtherName, now.Add(time.Hour))},
		{name: "another grant", signed: publisher.token(t, NewId().Bytes(), tlsFrontTestServerName, now.Add(time.Hour))},
		{name: "past the grant's expiry", signed: publisher.token(t, grant.GrantIds[0], tlsFrontTestServerName, now.Add(72*time.Hour))},
		{name: "a signer holding no grant", signed: stranger.token(t, grant.GrantIds[0], tlsFrontTestServerName, now.Add(time.Hour))},
		{name: "a signer this config does not hold", signed: unknown.token(t, grant.GrantIds[0], tlsFrontTestServerName, now.Add(time.Hour))},
		{name: "a changed body", signed: tamperedBytes},
		{name: "another statement's type", signed: attestationTypeBytes},
		{name: "not a Signed", signed: []byte("synthetic")},
	} {
		if response := tlsLinkTestOpen(t, client, TlsLinkUrl(tlsFrontTestServerName, c.signed)); response.StatusCode != http.StatusForbidden ||
			tlsEdgeTestCookie(response, tlsLinkCookieName) != nil {
			t.Errorf("%s: %d", c.name, response.StatusCode)
		}
		if response := tlsLinkTestVisit(t, client, base64.RawURLEncoding.EncodeToString(c.signed)); response.StatusCode != http.StatusForbidden {
			t.Errorf("%s as a cookie: %d", c.name, response.StatusCode)
		}
	}
	if response := tlsLinkTestOpen(t, client, "https://"+tlsFrontTestServerName+tlsLinkPath); response.StatusCode != http.StatusForbidden {
		t.Errorf("no token: %d", response.StatusCode)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}

// The link path is the front's under a link grant alone: elsewhere it is 404, and it takes GET and HEAD only.
func TestTlsLinkPathOnlyUnderLink(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	client := fixture.httpClient(tlsAlpnHttp11)
	if response := tlsLinkTestOpen(t, client, "https://"+tlsFrontTestServerName+tlsLinkPath+"?t=x"); response.StatusCode != http.StatusNotFound {
		t.Errorf("under public: %d", response.StatusCode)
	}
	linkFixture, _, _ := newTlsLinkFixture(t)
	request, err := http.NewRequest(http.MethodPost, "https://"+tlsFrontTestServerName+tlsLinkPath+"?t=x", nil)
	if err != nil {
		t.Fatal(err)
	}
	if response, _ := tlsFrontTestDo(t, linkFixture.httpClient(tlsAlpnHttp11), request); response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST: %d", response.StatusCode)
	}
}

// The identity key signs a link token under tls-link alone, and a token's fields are checked before it is made.
func TestTlsLinkTokenSigning(t *testing.T) {
	if purpose, ok := sidecarIdentitySignedPurpose(bridge.SignedType_SIGNED_TLS_LINK); !ok || purpose != TlsLinkPurpose {
		t.Errorf("Sign's table: %q %t", purpose, ok)
	}
	now := time.Date(2026, time.November, 11, 9, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		grantId []byte
		host    string
	}{
		{grantId: []byte{1}, host: tlsFrontTestServerName},
		{grantId: NewId().Bytes(), host: "Not A Host"},
	} {
		if _, err := NewTlsLinkToken(c.grantId, c.host, now); err == nil {
			t.Errorf("%x %q made a token", c.grantId, c.host)
		}
	}
	first, err := NewTlsLinkToken(NewId().Bytes(), tlsFrontTestServerName, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewTlsLinkToken(first.GetGrantId(), tlsFrontTestServerName, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.GetNonce()) == string(second.GetNonce()) || len(first.GetNonce()) != tlsLinkNonceByteCount {
		t.Error("two links of one grant alike")
	}
	publisher := newTlsLinkTestPublisher(t)
	wrongType := func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
		signed, err := publisher.sign(purpose, signedType, body, agentId)
		signed.Type = uint32(bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION)
		return signed, err
	}
	if _, err := SignTlsLinkToken(first, wrongType); err == nil {
		t.Error("a sign answering another statement passed")
	}
}
