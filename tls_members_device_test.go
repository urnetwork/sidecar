//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A member's device as the front's config holds it: its id and identity key.
type tlsMembersDeviceTestDevice struct {
	sidecarId Id
	key       ed25519.PrivateKey
}

// A fresh device whose key the policy holds, consented for memberId when consented.
func newTlsMembersDeviceTestDevice(t *testing.T, policy *tlsFrontTestPolicy, memberId Id, consented bool) *tlsMembersDeviceTestDevice {
	t.Helper()
	public, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device := &tlsMembersDeviceTestDevice{sidecarId: NewId(), key: private}
	policy.stateLock.Lock()
	defer policy.stateLock.Unlock()
	policy.identityKeys[device.sidecarId] = public
	if consented {
		policy.consentedDevices[[2]Id{device.sidecarId, memberId}] = true
	}
	return device
}

// Signs as the device's identity key does, any purpose and type: Sidecar.Sign's shape.
func (self *tlsMembersDeviceTestDevice) sign(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
	return &bridge.Signed{
		Body:      bytes.Clone(body),
		SignerId:  self.sidecarId.Bytes(),
		Signature: ed25519.Sign(self.key, bridge.SignedBytes(purpose, signedType, body)),
		Type:      uint32(signedType),
	}, nil
}

// The base64url of the device's statement for origin and nonce, as the device step's s carries it.
func (self *tlsMembersDeviceTestDevice) statement(t *testing.T, origin string, nonce []byte) string {
	t.Helper()
	login, err := NewTlsEdgeLogin(origin, nonce)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignTlsEdgeLogin(login, self.sign)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(signed)
}

// The base64url of a Signed holding body as signedType under purpose, by the device: what a statement of another kind
// looks like.
func (self *tlsMembersDeviceTestDevice) signedAs(t *testing.T, purpose string, signedType bridge.SignedType, body []byte) string {
	t.Helper()
	signed, err := self.sign(purpose, signedType, body, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := proto.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// A members-device fixture whose issuer is the fake, memberId a member.
func newTlsMembersDeviceFixture(t *testing.T, memberId Id) (*tlsFrontFixture, *tlsEdgeTestIssuer) {
	t.Helper()
	return newTlsEdgeLoginFixture(t, memberId, func(fixture *tlsFrontFixture) {
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	})
}

// Edge login through the issuer for memberId, from a navigation to path: the callback's answer, which begins the
// device step, and its pending cookie.
func tlsMembersDeviceTestLogin(t *testing.T, fixture *tlsFrontFixture, issuer *tlsEdgeTestIssuer, client *http.Client, memberId Id, path string) (*http.Response, *http.Cookie) {
	t.Helper()
	query, preCookie := tlsEdgeTestStart(t, client, path)
	response := tlsEdgeTestCallback(t, client, issuer.grant(query, memberId, fixture.networkId), query.Get("state"), preCookie)
	return response, tlsEdgeTestCookie(response, tlsDevicePendingCookieName)
}

// The device step's challenge, fetched by the visitor's own page with pending.
func tlsMembersDeviceTestChallenge(t *testing.T, client *http.Client, pending *http.Cookie) (*http.Response, *tlsMembersDeviceChallenge) {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://"+tlsFrontTestServerName+tlsMembersDevicePath, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(tlsHttpHeaderFetchSite, tlsFetchSiteSameOrigin)
	if pending != nil {
		request.AddCookie(&http.Cookie{Name: pending.Name, Value: pending.Value})
	}
	response, body := tlsFrontTestDo(t, client, request)
	challenge := &tlsMembersDeviceChallenge{}
	if response.StatusCode == http.StatusOK {
		if err := json.Unmarshal([]byte(body), challenge); err != nil {
			t.Fatal(err)
		}
	}
	return response, challenge
}

// The visitor's page's post of statement with pending, from the same origin.
func tlsMembersDeviceTestPostRequest(t *testing.T, pending *http.Cookie, statement string) *http.Request {
	t.Helper()
	form := url.Values{tlsMembersDeviceStatementField: {statement}}.Encode()
	request, err := http.NewRequest(http.MethodPost, "https://"+tlsFrontTestServerName+tlsMembersDevicePath, strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set(tlsHttpHeaderFetchSite, tlsFetchSiteSameOrigin)
	if pending != nil {
		request.AddCookie(&http.Cookie{Name: pending.Name, Value: pending.Value})
	}
	return request
}

// The visitor's page posting statement with pending, from fetchSite.
func tlsMembersDeviceTestPost(t *testing.T, client *http.Client, pending *http.Cookie, statement string, fetchSite string) *http.Response {
	t.Helper()
	request := tlsMembersDeviceTestPostRequest(t, pending, statement)
	request.Header.Set(tlsHttpHeaderFetchSite, fetchSite)
	response, _ := tlsFrontTestDo(t, client, request)
	return response
}

// The challenge's nonce, decoded.
func tlsMembersDeviceTestNonce(t *testing.T, challenge *tlsMembersDeviceChallenge) []byte {
	t.Helper()
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	if err != nil || len(nonce) != tlsEdgeLoginNonceByteCount {
		t.Fatalf("nonce %q", challenge.Nonce)
	}
	return nonce
}

// A navigation to path carrying session.
func tlsMembersDeviceTestVisit(t *testing.T, client *http.Client, session *http.Cookie, path string) *http.Response {
	t.Helper()
	request := tlsFrontTestNavigation(t, http.MethodGet, path)
	request.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	response, _ := tlsFrontTestDo(t, client, request)
	return response
}

// §13.7's members-device end to end: edge login names the member and sets no session, the device step's challenge is
// this origin and a fresh nonce, the consented device's statement sets a session that names it and returns the visitor
// where it began, and only then does a request reach the service.
func TestTlsMembersDeviceFullFlow(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsMembersDeviceFixture(t, memberId)
	device := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, true)
	client := fixture.httpClient(tlsAlpnHttp11)

	response, pending := tlsMembersDeviceTestLogin(t, fixture, issuer, client, memberId, "/private?x=1")
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != tlsMembersDevicePath {
		t.Fatalf("callback: %d to %q", response.StatusCode, response.Header.Get("Location"))
	}
	if session := tlsEdgeTestCookie(response, tlsSessionCookieName); session != nil {
		t.Fatalf("the ID token alone set a session: %+v", session)
	}
	if pending == nil || !pending.Secure || !pending.HttpOnly || pending.SameSite != http.SameSiteLaxMode || pending.Path != "/" ||
		pending.MaxAge != int(fixture.settings.DeviceLoginLifetime/time.Second) {
		t.Fatalf("pending %+v", pending)
	}

	response, challenge := tlsMembersDeviceTestChallenge(t, client, pending)
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/json" ||
		response.Header.Get("Cache-Control") != "no-store" || challenge.Origin != tlsFrontTestOrigin {
		t.Fatalf("challenge: %d %+v", response.StatusCode, challenge)
	}
	nonce := tlsMembersDeviceTestNonce(t, challenge)
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Fatalf("%d dials before the statement", dials)
	}

	response = tlsMembersDeviceTestPost(t, client, pending, device.statement(t, challenge.Origin, nonce), tlsFetchSiteSameOrigin)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/private?x=1" {
		t.Fatalf("statement: %d to %q", response.StatusCode, response.Header.Get("Location"))
	}
	session := tlsEdgeTestCookie(response, tlsSessionCookieName)
	if session == nil || !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode ||
		session.MaxAge != int(fixture.settings.SessionLifetime/time.Second) {
		t.Fatalf("session %+v", session)
	}
	if cleared := tlsEdgeTestCookie(response, tlsDevicePendingCookieName); cleared == nil || 0 <= cleared.MaxAge {
		t.Errorf("the pending cookie stayed: %+v", cleared)
	}
	opened := fixture.front.sessions.openSession(session.Value, tlsFrontTestOrigin, fixture.clock.Now())
	if opened == nil || opened.memberId != memberId || opened.deviceSidecarId != device.sidecarId {
		t.Fatalf("the session names %+v", opened)
	}

	if response := tlsMembersDeviceTestVisit(t, client, session, "/private?x=1"); response.StatusCode != http.StatusOK {
		t.Fatalf("signed in: %d", response.StatusCode)
	}
	if backendRequest := fixture.backend.nextRequest(t); backendRequest.path != "/private?x=1" || 0 < len(backendRequest.header.Values("Cookie")) {
		t.Errorf("the backend saw %s with cookies %q", backendRequest.path, backendRequest.header.Values("Cookie"))
	}
}

// T2: a device the member's config does not consent sets no session, nor does a statement signed by a device whose
// key the config does not hold, and neither reaches the service.
func TestTlsMembersDeviceRefusesAnUnconsentedDevice(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsMembersDeviceFixture(t, memberId)
	unconsented := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, false)
	// consented for another member
	otherMember := newTlsMembersDeviceTestDevice(t, fixture.policy, NewId(), true)
	unknown := &tlsMembersDeviceTestDevice{sidecarId: NewId()}
	_, unknown.key, _ = ed25519.GenerateKey(cryptorand.Reader)
	client := fixture.httpClient(tlsAlpnHttp11)
	_, pending := tlsMembersDeviceTestLogin(t, fixture, issuer, client, memberId, "/")
	_, challenge := tlsMembersDeviceTestChallenge(t, client, pending)
	nonce := tlsMembersDeviceTestNonce(t, challenge)
	for name, device := range map[string]*tlsMembersDeviceTestDevice{"unconsented": unconsented, "another member's": otherMember, "unknown": unknown} {
		response := tlsMembersDeviceTestPost(t, client, pending, device.statement(t, challenge.Origin, nonce), tlsFetchSiteSameOrigin)
		if response.StatusCode != http.StatusForbidden || tlsEdgeTestCookie(response, tlsSessionCookieName) != nil {
			t.Errorf("%s device: %d", name, response.StatusCode)
		}
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
	// none of them spent the login, which the member's consented device still completes
	consented := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, true)
	if response := tlsMembersDeviceTestPost(t, client, pending, consented.statement(t, challenge.Origin, nonce), tlsFetchSiteSameOrigin); response.StatusCode != http.StatusSeeOther {
		t.Errorf("the consented device: %d", response.StatusCode)
	}
}

// T2: a statement completes one login once, so posting it again, or racing it, sets no second session, though the
// pending cookie still opens.
func TestTlsMembersDeviceRefusesAReplayedNonce(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsMembersDeviceFixture(t, memberId)
	device := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, true)
	client := fixture.httpClient(tlsAlpnHttp11)
	_, pending := tlsMembersDeviceTestLogin(t, fixture, issuer, client, memberId, "/")
	_, challenge := tlsMembersDeviceTestChallenge(t, client, pending)
	statement := device.statement(t, challenge.Origin, tlsMembersDeviceTestNonce(t, challenge))
	if response := tlsMembersDeviceTestPost(t, client, pending, statement, tlsFetchSiteSameOrigin); response.StatusCode != http.StatusSeeOther {
		t.Fatalf("first: %d", response.StatusCode)
	}
	response := tlsMembersDeviceTestPost(t, client, pending, statement, tlsFetchSiteSameOrigin)
	if response.StatusCode != http.StatusForbidden || tlsEdgeTestCookie(response, tlsSessionCookieName) != nil {
		t.Errorf("replayed: %d", response.StatusCode)
	}
}

// T2: a statement for another origin, the same host on another port included, or for another nonce, is refused, so
// one host's login never opens another.
func TestTlsMembersDeviceRefusesAnotherOrigin(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsMembersDeviceFixture(t, memberId)
	device := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, true)
	client := fixture.httpClient(tlsAlpnHttp11)
	_, pending := tlsMembersDeviceTestLogin(t, fixture, issuer, client, memberId, "/")
	_, challenge := tlsMembersDeviceTestChallenge(t, client, pending)
	nonce := tlsMembersDeviceTestNonce(t, challenge)
	otherNonce := bytes.Clone(nonce)
	otherNonce[0] ^= 0xff
	for name, statement := range map[string]string{
		"another host":    device.statement(t, "https://"+tlsFrontTestOtherName, nonce),
		"another port":    device.statement(t, tlsFrontTestOrigin+":8443", nonce),
		"another nonce":   device.statement(t, challenge.Origin, otherNonce),
		"no statement":    "",
		"not base64url":   "not a statement!",
		"not a Signed":    base64.RawURLEncoding.EncodeToString([]byte{0xff, 0xff}),
		"over its length": strings.Repeat("A", base64.RawURLEncoding.EncodedLen(fixture.settings.EdgeLoginMaxByteCount)+1),
	} {
		response := tlsMembersDeviceTestPost(t, client, pending, statement, tlsFetchSiteSameOrigin)
		if response.StatusCode == http.StatusSeeOther || tlsEdgeTestCookie(response, tlsSessionCookieName) != nil {
			t.Errorf("%s: %d", name, response.StatusCode)
		}
	}
	// the right statement still completes the login none of those took
	if response := tlsMembersDeviceTestPost(t, client, pending, device.statement(t, challenge.Origin, nonce), tlsFetchSiteSameOrigin); response.StatusCode != http.StatusSeeOther {
		t.Errorf("the right statement: %d", response.StatusCode)
	}
}

// A statement of another type or purpose, signed by the consented device over the same bytes, is refused: only
// SIGNED_TLS_EDGE_LOGIN under edge-login is one (§6.9).
func TestTlsMembersDeviceRefusesAnotherStatement(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsMembersDeviceFixture(t, memberId)
	device := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, true)
	client := fixture.httpClient(tlsAlpnHttp11)
	_, pending := tlsMembersDeviceTestLogin(t, fixture, issuer, client, memberId, "/")
	_, challenge := tlsMembersDeviceTestChallenge(t, client, pending)
	body, err := proto.Marshal(&protocol.TlsEdgeLogin{Origin: challenge.Origin, Nonce: tlsMembersDeviceTestNonce(t, challenge)})
	if err != nil {
		t.Fatal(err)
	}
	for name, statement := range map[string]string{
		"a link token's type":      device.signedAs(t, TlsEdgeLoginPurpose, bridge.SignedType_SIGNED_TLS_LINK, body),
		"a link token's purpose":   device.signedAs(t, TlsLinkPurpose, bridge.SignedType_SIGNED_TLS_EDGE_LOGIN, body),
		"an attestation's both":    device.signedAs(t, TlsKeyAttestationPurpose, bridge.SignedType_SIGNED_TLS_KEY_ATTESTATION, body),
		"an authority statement's": device.signedAs(t, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_MEMBER_ADMIT, body),
		"no type":                  device.signedAs(t, TlsEdgeLoginPurpose, bridge.SignedType_SIGNED_TYPE_NONE, body),
	} {
		if response := tlsMembersDeviceTestPost(t, client, pending, statement, tlsFetchSiteSameOrigin); response.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", name, response.StatusCode)
		}
	}
	if response := tlsMembersDeviceTestPost(t, client, pending, device.signedAs(t, TlsEdgeLoginPurpose, bridge.SignedType_SIGNED_TLS_EDGE_LOGIN, body), tlsFetchSiteSameOrigin); response.StatusCode != http.StatusSeeOther {
		t.Errorf("the edge login itself: %d", response.StatusCode)
	}
}

// The device step stands only on its own pending cookie, from the visitor's own page, while it lasts: a cross-site
// post, a post with no cookie and one after DeviceLoginLifetime are refused, and so is the challenge, which another
// audience's endpoint does not serve at all.
func TestTlsMembersDeviceStepNeedsItsPendingCookie(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsMembersDeviceFixture(t, memberId)
	device := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, true)
	client := fixture.httpClient(tlsAlpnHttp11)
	_, pending := tlsMembersDeviceTestLogin(t, fixture, issuer, client, memberId, "/")
	_, challenge := tlsMembersDeviceTestChallenge(t, client, pending)
	statement := device.statement(t, challenge.Origin, tlsMembersDeviceTestNonce(t, challenge))

	if response := tlsMembersDeviceTestPost(t, client, pending, statement, "cross-site"); response.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site: %d", response.StatusCode)
	}
	if response := tlsMembersDeviceTestPost(t, client, nil, statement, tlsFetchSiteSameOrigin); response.StatusCode != http.StatusForbidden {
		t.Errorf("no cookie: %d", response.StatusCode)
	}
	if response, _ := tlsMembersDeviceTestChallenge(t, client, nil); response.StatusCode != http.StatusBadRequest {
		t.Errorf("a challenge with no cookie: %d", response.StatusCode)
	}
	// the cookie itself still opens until its end
	fixture.clock.advance(fixture.settings.DeviceLoginLifetime - time.Millisecond)
	if response, again := tlsMembersDeviceTestChallenge(t, client, pending); response.StatusCode != http.StatusOK || again.Nonce != challenge.Nonce {
		t.Errorf("a challenge within its life: %d", response.StatusCode)
	}

	fixture.clock.advance(time.Millisecond)
	if response := tlsMembersDeviceTestPost(t, client, pending, statement, tlsFetchSiteSameOrigin); response.StatusCode != http.StatusForbidden {
		t.Errorf("past its life: %d", response.StatusCode)
	}
	if response, _ := tlsMembersDeviceTestChallenge(t, client, pending); response.StatusCode != http.StatusBadRequest {
		t.Errorf("a challenge past its life: %d", response.StatusCode)
	}

	fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
	if response, _ := tlsMembersDeviceTestChallenge(t, client, pending); response.StatusCode != http.StatusNotFound {
		t.Errorf("under members: %d", response.StatusCode)
	}
}

// A members-device session counts while its device stays consented for its member and the member a member: a lost
// consent or a removal ends it at the next request, which goes back to edge login or is refused.
func TestTlsMembersDeviceSessionEndsWithItsDevicesStanding(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsMembersDeviceFixture(t, memberId)
	device := newTlsMembersDeviceTestDevice(t, fixture.policy, memberId, true)
	client := fixture.httpClient(tlsAlpnHttp11)
	_, pending := tlsMembersDeviceTestLogin(t, fixture, issuer, client, memberId, "/")
	_, challenge := tlsMembersDeviceTestChallenge(t, client, pending)
	response := tlsMembersDeviceTestPost(t, client, pending, device.statement(t, challenge.Origin, tlsMembersDeviceTestNonce(t, challenge)), tlsFetchSiteSameOrigin)
	session := tlsEdgeTestCookie(response, tlsSessionCookieName)
	if session == nil {
		t.Fatalf("no session: %d", response.StatusCode)
	}
	if response := tlsMembersDeviceTestVisit(t, client, session, "/"); response.StatusCode != http.StatusOK {
		t.Fatalf("signed in: %d", response.StatusCode)
	}
	fixture.backend.nextRequest(t)

	func() {
		fixture.policy.stateLock.Lock()
		defer fixture.policy.stateLock.Unlock()
		delete(fixture.policy.consentedDevices, [2]Id{device.sidecarId, memberId})
	}()
	response = tlsMembersDeviceTestVisit(t, client, session, "/")
	if response.StatusCode != http.StatusFound || !strings.HasPrefix(response.Header.Get("Location"), tlsFrontTestIssuer+tlsEdgeLoginAuthorizePath) {
		t.Errorf("consent gone, a navigation: %d to %q", response.StatusCode, response.Header.Get("Location"))
	}

	func() {
		fixture.policy.stateLock.Lock()
		defer fixture.policy.stateLock.Unlock()
		fixture.policy.consentedDevices[[2]Id{device.sidecarId, memberId}] = true
		delete(fixture.policy.members, memberId)
	}()
	request, err := http.NewRequest(http.MethodGet, "https://"+tlsFrontTestServerName+"/api", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(tlsHttpHeaderFetchSite, tlsFetchSiteSameOrigin)
	request.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	if response, _ := tlsFrontTestDo(t, client, request); response.StatusCode != http.StatusUnauthorized {
		t.Errorf("member gone, a fetch: %d", response.StatusCode)
	}
	if dials, _ := fixture.backend.counts(); dials != 1 {
		t.Errorf("%d dials", dials)
	}
}

// A device session counts on a members endpoint too, being a members session and more, while a members session never
// counts on a members-device one (TestTlsAudienceMembersDeviceRefusesAMembersSession).
func TestTlsMembersDeviceSessionCountsUnderMembers(t *testing.T) {
	memberId := NewId()
	fixture, _ := newTlsEdgeLoginFixture(t, memberId, nil)
	now := fixture.clock.Now()
	value, err := fixture.front.sessions.sealSession(tlsFrontTestOrigin, &tlsSession{
		memberId:        memberId,
		issueTime:       now,
		expireTime:      now.Add(fixture.settings.SessionLifetime),
		deviceSidecarId: NewId(),
	})
	if err != nil {
		t.Fatal(err)
	}
	response := tlsMembersDeviceTestVisit(t, fixture.httpClient(tlsAlpnHttp11), &http.Cookie{Name: tlsSessionCookieName, Value: value}, "/")
	if response.StatusCode != http.StatusOK {
		t.Errorf("%d", response.StatusCode)
	}
}

// Sessions keep the device they name across a restart of the sealer, and a session plaintext of neither length, or
// with a zero device, does not open.
func TestTlsSessionKeepsItsDevice(t *testing.T) {
	secrets := newTlsFrontTestSecrets()
	networkId := NewId()
	sealer, err := newTlsSessionSealer(secrets, networkId)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.November, 11, 9, 0, 0, 0, time.UTC)
	session := &tlsSession{memberId: NewId(), issueTime: now, expireTime: now.Add(time.Hour), deviceSidecarId: NewId()}
	value, err := sealer.sealSession(tlsFrontTestOrigin, session)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := newTlsSessionSealer(secrets, networkId)
	if err != nil {
		t.Fatal(err)
	}
	opened := restarted.openSession(value, tlsFrontTestOrigin, now)
	if opened == nil || opened.memberId != session.memberId || opened.deviceSidecarId != session.deviceSidecarId {
		t.Fatalf("opened %+v", opened)
	}
	plaintext := make([]byte, 0, tlsSessionPlaintextByteCount+len(Id{}))
	plaintext = append(plaintext, make([]byte, tlsSessionIdByteCount)...)
	plaintext = append(plaintext, session.memberId.Bytes()...)
	plaintext = append(plaintext, 0, 0, 0, 0, 0, 0, 0, 0)
	plaintext = append(plaintext, 0x7f, 0, 0, 0, 0, 0, 0, 0)
	for name, sealed := range map[string][]byte{
		"a zero device":  append(bytes.Clone(plaintext), make([]byte, len(Id{}))...),
		"a short device": append(bytes.Clone(plaintext), 1, 2, 3),
	} {
		value, err := restarted.seal(restarted.session, tlsSessionCookieName, tlsFrontTestOrigin, sealed)
		if err != nil {
			t.Fatal(err)
		}
		if opened := restarted.openSession(value, tlsFrontTestOrigin, now); opened != nil {
			t.Errorf("%s opened %+v", name, opened)
		}
	}
}

// The origins a statement takes: what a front issues, https and a canonical host, with a port other than 443 written
// after it, and nothing else.
func TestNewTlsEdgeLoginTakesAFrontsOrigins(t *testing.T) {
	nonce := make([]byte, tlsEdgeLoginNonceByteCount)
	for _, c := range []struct {
		origin string
		ok     bool
	}{
		{origin: "https://app.abcdefghij.ur.example", ok: true},
		{origin: "https://app.abcdefghij.ur.example:8443", ok: true},
		{origin: "https://app.abcdefghij.ur.example:443"},
		{origin: "https://app.abcdefghij.ur.example:08443"},
		{origin: "https://app.abcdefghij.ur.example:0"},
		{origin: "https://app.abcdefghij.ur.example:65536"},
		{origin: "https://app.abcdefghij.ur.example:"},
		{origin: "https://App.abcdefghij.ur.example"},
		{origin: "https://app.abcdefghij.ur.example/"},
		{origin: "https://app.abcdefghij.ur.example/path"},
		{origin: "https://user@app.abcdefghij.ur.example"},
		{origin: "http://app.abcdefghij.ur.example"},
		{origin: "app.abcdefghij.ur.example"},
		{origin: "https://"},
		{origin: "https://*.abcdefghij.ur.example"},
		{origin: ""},
	} {
		if _, err := NewTlsEdgeLogin(c.origin, nonce); (err == nil) != c.ok {
			t.Errorf("%q: %v", c.origin, err)
		}
	}
	if _, err := NewTlsEdgeLogin(tlsFrontTestOrigin, nonce[:16]); err == nil {
		t.Error("a short nonce")
	}
}

// Sidecar.SignTlsEdgeLogin: only a member's consented device signs, and what it signs is the edge-login statement the
// front's check takes for that origin and nonce, under the identity key, and no other.
func TestSidecarSignTlsEdgeLoginNeedsAConsentedDevice(t *testing.T) {
	sidecar, _, keys := newIdentityTestSidecar(t)
	sidecarId := sidecar.Identity().SidecarId
	memberId := NewId()
	nonce := make([]byte, tlsEdgeLoginNonceByteCount)
	if _, err := cryptorand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.SignTlsEdgeLogin(tlsFrontTestOrigin, nonce); !errors.Is(err, ErrSidecarActNoAuthority) {
		t.Errorf("no authority: %v", err)
	}
	authority := newTestActAuthority()
	t.Cleanup(sidecar.InstallAuthority(authority))
	setAdmission := func(admission *AclSidecar, consented bool) {
		authority.stateLock.Lock()
		defer authority.stateLock.Unlock()
		authority.sidecars[sidecarId] = admission
		authority.consents[[2]Id{sidecarId, memberId}] = consented
	}
	setAdmission(&AclSidecar{Row: &bridge.SidecarRow{SidecarId: sidecarId.Bytes()}, MemberId: memberId}, false)
	if _, err := sidecar.SignTlsEdgeLogin(tlsFrontTestOrigin, nonce); !errors.Is(err, ErrTlsEdgeLoginNotConsented) {
		t.Errorf("unconsented: %v", err)
	}
	setAdmission(&AclSidecar{Row: &bridge.SidecarRow{SidecarId: sidecarId.Bytes()}, MemberId: memberId}, true)
	if _, err := sidecar.SignTlsEdgeLogin("http://"+tlsFrontTestServerName, nonce); !errors.Is(err, ErrTlsEdgeLoginStatement) {
		t.Errorf("an origin no front issues: %v", err)
	}
	signed, err := sidecar.SignTlsEdgeLogin(tlsFrontTestOrigin, nonce)
	if err != nil {
		t.Fatal(err)
	}
	policy := newTlsFrontTestPolicy()
	policy.members[memberId] = true
	policy.identityKeys[sidecarId] = keys.identityPublicKey()
	policy.consentedDevices[[2]Id{sidecarId, memberId}] = true
	value := base64.RawURLEncoding.EncodeToString(signed)
	now := time.Now()
	maxByteCount := DefaultTlsFrontSettings().EdgeLoginMaxByteCount
	if deviceId, err := tlsEdgeLoginVerify(value, tlsFrontTestOrigin, nonce, memberId, policy, maxByteCount, now); err != nil || deviceId != sidecarId {
		t.Fatalf("the front's check: %s %v", deviceId, err)
	}
	if _, err := tlsEdgeLoginVerify(value, "https://"+tlsFrontTestOtherName, nonce, memberId, policy, maxByteCount, now); err == nil {
		t.Error("taken at another origin")
	}

	// a tagged sidecar is no member's device, whatever the consents say
	setAdmission(&AclSidecar{Row: &bridge.SidecarRow{SidecarId: sidecarId.Bytes()}, TagIds: []Id{NewId()}}, true)
	if _, err := sidecar.SignTlsEdgeLogin(tlsFrontTestOrigin, nonce); !errors.Is(err, ErrTlsEdgeLoginNotConsented) {
		t.Errorf("tagged: %v", err)
	}
}

// The front's config policy over a real log: the member's consented device vouches for its member alone; a device an
// admin admitted without the member's consent, a read_only one and a revoked one vouch for nothing; and with no state
// nothing does.
func TestTlsFrontConfigPolicyDeviceConsented(t *testing.T) {
	now := time.Now()
	if NewTlsFrontConfigPolicy(NewId(), func() *ConfigState { return nil }).DeviceConsented(NewId(), NewId(), now) {
		t.Error("consented with no state")
	}
	net := newTestConfigNet(t)
	member, first := net.consentedMember("m")
	policy := NewTlsFrontConfigPolicy(net.owner.sidecarId, func() *ConfigState { return net.log.State() })
	if !policy.DeviceConsented(first.sidecarId, member, now) {
		t.Error("the member's consented device")
	}
	if policy.DeviceConsented(first.sidecarId, net.ownerMemberId, now) {
		t.Error("for another member")
	}

	// the owner, an admin, admits one of m's devices alone: parked until m's consented device confirms it
	adminAdmitted := net.device("m admin admitted", member)
	net.admitDevice(net.owner, adminAdmitted, 0)
	readOnly := net.device("m read only", member)
	net.admitDevice(first, readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	second := net.device("m second", member)
	net.admitDevice(first, second, 0)
	acl, err := net.log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	if acl.ConsentedFor(adminAdmitted.sidecarId, member) || policy.DeviceConsented(adminAdmitted.sidecarId, member, now) {
		t.Error("a device the member has not consented")
	}
	if !acl.ConsentedFor(readOnly.sidecarId, member) || policy.DeviceConsented(readOnly.sidecarId, member, now) {
		t.Error("a read_only device, consented, vouches")
	}
	if !policy.DeviceConsented(second.sidecarId, member, now) {
		t.Error("the member's second consented device")
	}
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	if policy.DeviceConsented(second.sidecarId, member, now) || policy.IdentityKey(second.sidecarId) != nil {
		t.Error("a revoked device")
	}
}

// The statements FuzzTlsEdgeLogin and TestTlsEdgeLoginSeedsVerifyOnlyTheGenuine start from: the genuine one, and the
// same body signed by the same device as every other type the registry holds, under edge-login and under the type's
// own purpose, and each a byte off.
type tlsEdgeLoginTestWorld struct {
	policy   *tlsFrontTestPolicy
	device   *tlsMembersDeviceTestDevice
	memberId Id
	nonce    []byte
	genuine  string
	seeds    []string
}

// The world, deterministic, so a seed means the same each run.
func newTlsEdgeLoginTestWorld(t testing.TB) *tlsEdgeLoginTestWorld {
	t.Helper()
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	key := ed25519.NewKeyFromSeed(seed)
	memberId := Id(bytes.Repeat([]byte{0x01}, len(Id{})))
	device := &tlsMembersDeviceTestDevice{sidecarId: Id(bytes.Repeat([]byte{0x02}, len(Id{}))), key: key}
	policy := newTlsFrontTestPolicy()
	policy.members[memberId] = true
	policy.identityKeys[device.sidecarId] = key.Public().(ed25519.PublicKey)
	policy.consentedDevices[[2]Id{device.sidecarId, memberId}] = true
	world := &tlsEdgeLoginTestWorld{
		policy:   policy,
		device:   device,
		memberId: memberId,
		nonce:    bytes.Repeat([]byte{0x03}, tlsEdgeLoginNonceByteCount),
	}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.TlsEdgeLogin{Origin: tlsFrontTestOrigin, Nonce: world.nonce})
	if err != nil {
		t.Fatal(err)
	}
	sign := func(purpose string, signedType bridge.SignedType) string {
		signed, _ := device.sign(purpose, signedType, body, nil)
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	world.genuine = sign(TlsEdgeLoginPurpose, bridge.SignedType_SIGNED_TLS_EDGE_LOGIN)
	// from the descriptor, so a type an owner adds joins by being declared
	values := bridge.SignedType(0).Descriptor().Values()
	for i := range values.Len() {
		signedType := bridge.SignedType(values.Get(i).Number())
		if signedType != bridge.SignedType_SIGNED_TLS_EDGE_LOGIN {
			world.seeds = append(world.seeds, sign(TlsEdgeLoginPurpose, signedType))
		}
		if purpose, ok := sidecarIdentitySignedPurpose(signedType); ok && purpose != TlsEdgeLoginPurpose {
			world.seeds = append(world.seeds, sign(purpose, signedType))
		}
	}
	for _, value := range append([]string{world.genuine}, slices.Clone(world.seeds)...) {
		decoded, _ := base64.RawURLEncoding.DecodeString(value)
		for _, index := range []int{0, len(decoded) / 2, len(decoded) - 1} {
			flipped := bytes.Clone(decoded)
			flipped[index] ^= 0x01
			world.seeds = append(world.seeds, base64.RawURLEncoding.EncodeToString(flipped))
		}
	}
	world.seeds = append(world.seeds, "", "AA", strings.Repeat("A", 64))
	return world
}

// Whatever value holds, the check never panics, and it passes only the genuine statement's own signed body: the
// origin and nonce this login issued, under edge-login as SIGNED_TLS_EDGE_LOGIN, by the consented device.
func testTlsEdgeLoginVerifiesOnlyTheGenuine(t *testing.T, world *tlsEdgeLoginTestWorld, value string) {
	maxByteCount := DefaultTlsFrontSettings().EdgeLoginMaxByteCount
	deviceId, err := tlsEdgeLoginVerify(value, tlsFrontTestOrigin, world.nonce, world.memberId, world.policy, maxByteCount, time.Unix(0, 0))
	if err != nil {
		return
	}
	if deviceId != world.device.sidecarId {
		t.Fatalf("passed for %s", deviceId)
	}
	decoded, _ := base64.RawURLEncoding.DecodeString(value)
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(decoded, signed); err != nil {
		t.Fatal(err)
	}
	login := &protocol.TlsEdgeLogin{}
	if err := proto.Unmarshal(signed.GetBody(), login); err != nil || login.GetOrigin() != tlsFrontTestOrigin || !bytes.Equal(login.GetNonce(), world.nonce) {
		t.Fatalf("passed a body for %q", login.GetOrigin())
	}
	if signed.GetType() != uint32(bridge.SignedType_SIGNED_TLS_EDGE_LOGIN) ||
		!ed25519.Verify(world.policy.identityKeys[deviceId], bridge.SignedBytes(TlsEdgeLoginPurpose, bridge.SignedType_SIGNED_TLS_EDGE_LOGIN, signed.GetBody()), signed.GetSignature()) {
		t.Fatal("passed a statement the device did not sign as an edge login")
	}
}

// FuzzTlsEdgeLogin's seeds as an ordinary test, for the legs where testing.F does not run: only the genuine
// statement passes, and every other type, purpose and flipped byte is refused.
func TestTlsEdgeLoginSeedsVerifyOnlyTheGenuine(t *testing.T) {
	world := newTlsEdgeLoginTestWorld(t)
	maxByteCount := DefaultTlsFrontSettings().EdgeLoginMaxByteCount
	passed := 0
	for _, value := range append([]string{world.genuine}, world.seeds...) {
		if _, err := tlsEdgeLoginVerify(value, tlsFrontTestOrigin, world.nonce, world.memberId, world.policy, maxByteCount, time.Unix(0, 0)); err == nil {
			passed += 1
		}
		testTlsEdgeLoginVerifiesOnlyTheGenuine(t, world, value)
	}
	if passed != 1 {
		t.Errorf("%d passed", passed)
	}
}
