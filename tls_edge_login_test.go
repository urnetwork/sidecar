//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One code the fake issuer granted: what its redemption must match and what its token says.
type tlsEdgeTestCode struct {
	clientId    string
	redirectUri string
	challenge   string
	nonce       string
	memberId    Id
	networkId   Id
}

// TEAM-M5-01's issuer as the front reaches it: codes it granted redeem once, with their PKCE verifier, for an ES256 ID
// token under its id- key, whose key set it serves.
type tlsEdgeTestIssuer struct {
	clock *tlsFrontTestClock
	key   *ecdsa.PrivateKey
	kid   string

	stateLock sync.Mutex
	codes     map[string]*tlsEdgeTestCode
	// changes the next token's header and claims before it is signed
	mutate func(header map[string]any, claims map[string]any)
	// signs the next token with this key in place of its own
	signKey    *ecdsa.PrivateKey
	tokenCalls int
	jwksCalls  int
}

// An issuer with one id- key.
func newTlsEdgeTestIssuer(t *testing.T, clock *tlsFrontTestClock) *tlsEdgeTestIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &tlsEdgeTestIssuer{clock: clock, key: key, kid: "id-synthetic-1", codes: map[string]*tlsEdgeTestCode{}}
}

// A response with body.
func tlsEdgeTestAnswer(status int, body []byte) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// See http.RoundTripper: the token route and the key set, as TEAM-M5-01 serves them.
func (self *tlsEdgeTestIssuer) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != "issuer.example" {
		return tlsEdgeTestAnswer(http.StatusNotFound, nil), nil
	}
	switch request.URL.Path {
	case tlsEdgeLoginTokenPath:
		if err := request.ParseForm(); err != nil {
			return tlsEdgeTestAnswer(http.StatusBadRequest, nil), nil
		}
		form := request.PostForm
		self.stateLock.Lock()
		self.tokenCalls += 1
		code := self.codes[form.Get("code")]
		delete(self.codes, form.Get("code"))
		mutate := self.mutate
		self.mutate = nil
		signKey := self.signKey
		self.signKey = nil
		self.stateLock.Unlock()
		challenge := sha256.Sum256([]byte(form.Get("code_verifier")))
		if code == nil || form.Get("grant_type") != "authorization_code" || form.Get("client_id") != code.clientId ||
			form.Get("redirect_uri") != code.redirectUri || base64.RawURLEncoding.EncodeToString(challenge[:]) != code.challenge {
			return tlsEdgeTestAnswer(http.StatusBadRequest, []byte(`{"error":"invalid_grant"}`)), nil
		}
		now := self.clock.Now()
		header := map[string]any{"alg": "ES256", "kid": self.kid, "typ": "JWT"}
		claims := map[string]any{
			"iss":        tlsFrontTestIssuer,
			"sub":        code.memberId.String(),
			"aud":        []string{code.clientId},
			"iat":        now.Unix(),
			"exp":        now.Add(60 * time.Second).Unix(),
			"jti":        NewId().String(),
			"nonce":      code.nonce,
			"network_id": code.networkId.String(),
		}
		if mutate != nil {
			mutate(header, claims)
		}
		if signKey == nil {
			signKey = self.key
		}
		token, err := tlsEdgeTestSign(signKey, header, claims)
		if err != nil {
			return nil, err
		}
		body, _ := json.Marshal(map[string]any{"id_token": token, "token_type": "Bearer", "expires_in": 60})
		return tlsEdgeTestAnswer(http.StatusOK, body), nil
	case tlsEdgeLoginJwksPath:
		self.stateLock.Lock()
		self.jwksCalls += 1
		self.stateLock.Unlock()
		x, y := self.key.PublicKey.X.FillBytes(make([]byte, 32)), self.key.PublicKey.Y.FillBytes(make([]byte, 32))
		body, _ := json.Marshal(map[string]any{"keys": []map[string]string{
			{"kty": "EC", "crv": "P-256", "kid": self.kid, "alg": "ES256", "use": "sig",
				"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)},
			// a key of another set, which the front leaves out
			{"kty": "EC", "crv": "P-256", "kid": "mcp-other", "alg": "ES256", "use": "sig",
				"x": base64.RawURLEncoding.EncodeToString(x), "y": base64.RawURLEncoding.EncodeToString(y)},
		}})
		return tlsEdgeTestAnswer(http.StatusOK, body), nil
	}
	return tlsEdgeTestAnswer(http.StatusNotFound, nil), nil
}

// How many redemptions reached the issuer.
func (self *tlsEdgeTestIssuer) calls() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.tokenCalls
}

// Sets what the next token's signing changes.
func (self *tlsEdgeTestIssuer) nextToken(mutate func(header map[string]any, claims map[string]any), signKey *ecdsa.PrivateKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.mutate = mutate
	self.signKey = signKey
}

// A compact ES256 JWS of header and claims under key.
func tlsEdgeTestSign(key *ecdsa.PrivateKey, header map[string]any, claims map[string]any) (string, error) {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(cryptorand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return input + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// Grants a code for the authorize request query names, signing memberId in to networkId.
func (self *tlsEdgeTestIssuer) grant(query url.Values, memberId Id, networkId Id) string {
	code := "code-" + NewId().String()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.codes[code] = &tlsEdgeTestCode{
		clientId:    query.Get("client_id"),
		redirectUri: query.Get("redirect_uri"),
		challenge:   query.Get("code_challenge"),
		nonce:       query.Get("nonce"),
		memberId:    memberId,
		networkId:   networkId,
	}
	return code
}

// A members fixture whose issuer is the fake, memberId a member.
func newTlsEdgeLoginFixture(t *testing.T, memberId Id, configure func(fixture *tlsFrontFixture)) (*tlsFrontFixture, *tlsEdgeTestIssuer) {
	t.Helper()
	var issuer *tlsEdgeTestIssuer
	fixture := newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		issuer = newTlsEdgeTestIssuer(t, fixture.clock)
		fixture.issuerClient = &http.Client{Transport: issuer}
		fixture.policy.setGrant(protocol.AclAudience_ACL_AUDIENCE_MEMBERS, protocol.AclAppMode_ACL_APP_MODE_HTTP, nil)
		fixture.policy.members[memberId] = true
		if configure != nil {
			configure(fixture)
		}
	})
	return fixture, issuer
}

// A navigation to path with no session: the front's redirect to the issuer, its query, and the pre-cookie.
func tlsEdgeTestStart(t *testing.T, client *http.Client, path string) (url.Values, *http.Cookie) {
	t.Helper()
	response, _ := tlsFrontTestDo(t, client, tlsFrontTestNavigation(t, http.MethodGet, path))
	location, err := url.Parse(response.Header.Get("Location"))
	if response.StatusCode != http.StatusFound || err != nil || location.Scheme+"://"+location.Host != tlsFrontTestIssuer ||
		location.Path != tlsEdgeLoginAuthorizePath {
		t.Fatalf("start: %d to %q", response.StatusCode, response.Header.Get("Location"))
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == tlsPreLoginCookieName {
			return location.Query(), cookie
		}
	}
	t.Fatal("start set no pre-cookie")
	return nil, nil
}

// The issuer's redirect back: the callback with code and state, as a top-level navigation from the issuer's site,
// carrying preCookie when it is not nil.
func tlsEdgeTestCallback(t *testing.T, client *http.Client, code string, state string, preCookie *http.Cookie) *http.Response {
	t.Helper()
	request := tlsFrontTestNavigation(t, http.MethodGet, tlsEdgeLoginCallbackPath+"?"+url.Values{"code": {code}, "state": {state}}.Encode())
	request.Header.Set(tlsHttpHeaderFetchSite, "cross-site")
	if preCookie != nil {
		request.AddCookie(&http.Cookie{Name: preCookie.Name, Value: preCookie.Value})
	}
	response, _ := tlsFrontTestDo(t, client, request)
	return response
}

// The cookie named name a response sets, nil for none.
func tlsEdgeTestCookie(response *http.Response, name string) *http.Cookie {
	for _, cookie := range response.Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

// §7.8 end to end: a navigation with no session goes to the issuer with the origin's client_id and callback, openid,
// S256, a state and a nonce; the callback redeems, verifies and sets a 12 h session, returning the visitor where it
// began; the session then reaches the service, and neither the login nor the callback ever did.
func TestTlsEdgeLoginFullFlow(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsEdgeLoginFixture(t, memberId, nil)
	client := fixture.httpClient(tlsAlpnHttp11)
	query, preCookie := tlsEdgeTestStart(t, client, "/private?x=1")
	origin := "https://" + tlsFrontTestServerName
	for name, want := range map[string]string{
		"response_type": "code", "client_id": origin, "redirect_uri": origin + tlsEdgeLoginCallbackPath, "scope": "openid",
		"code_challenge_method": "S256",
	} {
		if query.Get(name) != want {
			t.Errorf("%s %q", name, query.Get(name))
		}
	}
	for _, name := range []string{"state", "nonce", "code_challenge"} {
		if len(query.Get(name)) < 43 {
			t.Errorf("%s %q", name, query.Get(name))
		}
	}
	if !preCookie.Secure || !preCookie.HttpOnly || preCookie.SameSite != http.SameSiteLaxMode || preCookie.Path != "/" || preCookie.MaxAge <= 0 {
		t.Errorf("pre-cookie %+v", preCookie)
	}

	response := tlsEdgeTestCallback(t, client, issuer.grant(query, memberId, fixture.networkId), query.Get("state"), preCookie)
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/private?x=1" {
		t.Fatalf("callback: %d to %q", response.StatusCode, response.Header.Get("Location"))
	}
	session := tlsEdgeTestCookie(response, tlsSessionCookieName)
	if session == nil || !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode || session.Path != "/" ||
		session.MaxAge != int((12*time.Hour)/time.Second) {
		t.Fatalf("session %+v", session)
	}
	if cleared := tlsEdgeTestCookie(response, tlsPreLoginCookieName); cleared == nil || 0 <= cleared.MaxAge {
		t.Errorf("the pre-cookie stayed: %+v", cleared)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Fatalf("%d dials during the login", dials)
	}

	request := tlsFrontTestNavigation(t, http.MethodGet, "/private?x=1")
	request.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	if response, body := tlsFrontTestDo(t, client, request); response.StatusCode != http.StatusOK || body != "backend" {
		t.Fatalf("signed in: %d %q", response.StatusCode, body)
	}
	if backendRequest := fixture.backend.nextRequest(t); backendRequest.path != "/private?x=1" || 0 < len(backendRequest.header.Values("Cookie")) {
		t.Errorf("the backend saw %s with cookies %q", backendRequest.path, backendRequest.header.Values("Cookie"))
	}
}

// §7.8's front row: a token whose aud, nonce, issuer, network, times, signature or key is wrong sets no session.
func TestTlsEdgeLoginRefusesBadTokens(t *testing.T) {
	memberId := NewId()
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		mutate  func(header map[string]any, claims map[string]any)
		signKey *ecdsa.PrivateKey
	}{
		{name: "another aud", mutate: func(header map[string]any, claims map[string]any) {
			claims["aud"] = []string{"https://" + tlsFrontTestOtherName}
		}},
		{name: "two auds", mutate: func(header map[string]any, claims map[string]any) {
			claims["aud"] = []string{claims["aud"].([]string)[0], "https://" + tlsFrontTestOtherName}
		}},
		{name: "another nonce", mutate: func(header map[string]any, claims map[string]any) { claims["nonce"] = "other" }},
		{name: "another issuer", mutate: func(header map[string]any, claims map[string]any) { claims["iss"] = "https://other.example" }},
		{name: "another network", mutate: func(header map[string]any, claims map[string]any) { claims["network_id"] = NewId().String() }},
		{name: "expired", mutate: func(header map[string]any, claims map[string]any) {
			claims["exp"] = claims["iat"].(int64) - 120
			claims["iat"] = claims["iat"].(int64) - 180
		}},
		{name: "a long life", mutate: func(header map[string]any, claims map[string]any) {
			claims["exp"] = claims["iat"].(int64) + int64((time.Hour)/time.Second)
		}},
		{name: "issued ahead", mutate: func(header map[string]any, claims map[string]any) {
			claims["iat"] = claims["iat"].(int64) + 600
			claims["exp"] = claims["iat"].(int64) + 60
		}},
		{name: "no sub", mutate: func(header map[string]any, claims map[string]any) { claims["sub"] = "member" }},
		{name: "another key", signKey: otherKey},
		{name: "another set's kid", mutate: func(header map[string]any, claims map[string]any) { header["kid"] = "mcp-other" }},
		{name: "an unknown kid", mutate: func(header map[string]any, claims map[string]any) { header["kid"] = "id-unknown" }},
		{name: "alg none", mutate: func(header map[string]any, claims map[string]any) { header["alg"] = "none" }},
	}
	for _, c := range cases {
		fixture, issuer := newTlsEdgeLoginFixture(t, memberId, nil)
		client := fixture.httpClient(tlsAlpnHttp11)
		query, preCookie := tlsEdgeTestStart(t, client, "/")
		issuer.nextToken(c.mutate, c.signKey)
		response := tlsEdgeTestCallback(t, client, issuer.grant(query, memberId, fixture.networkId), query.Get("state"), preCookie)
		if response.StatusCode != http.StatusForbidden || tlsEdgeTestCookie(response, tlsSessionCookieName) != nil {
			t.Errorf("%s: %d", c.name, response.StatusCode)
		}
		if dials, _ := fixture.backend.counts(); dials != 0 {
			t.Errorf("%s: %d dials", c.name, dials)
		}
	}
}

// §2.8 EX8 stands: the issuer's word that someone signed in is checked against this config, so a member of another
// network, or one this config does not hold, gets no session.
func TestTlsEdgeLoginRefusesANonMember(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsEdgeLoginFixture(t, memberId, nil)
	client := fixture.httpClient(tlsAlpnHttp11)
	for _, signedIn := range []struct {
		memberId  Id
		networkId Id
	}{
		{memberId: NewId(), networkId: fixture.networkId},
		{memberId: memberId, networkId: NewId()},
	} {
		query, preCookie := tlsEdgeTestStart(t, client, "/")
		response := tlsEdgeTestCallback(t, client, issuer.grant(query, signedIn.memberId, signedIn.networkId), query.Get("state"), preCookie)
		if response.StatusCode != http.StatusForbidden || tlsEdgeTestCookie(response, tlsSessionCookieName) != nil {
			t.Errorf("%+v: %d", signedIn, response.StatusCode)
		}
	}
}

// A pending login's state is single use: the same callback twice, or a copied pre-cookie with a fresh code, fails
// the second time, before any redemption.
func TestTlsEdgeLoginStateIsSingleUse(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsEdgeLoginFixture(t, memberId, nil)
	client := fixture.httpClient(tlsAlpnHttp11)
	query, preCookie := tlsEdgeTestStart(t, client, "/")
	code := issuer.grant(query, memberId, fixture.networkId)
	if response := tlsEdgeTestCallback(t, client, code, query.Get("state"), preCookie); response.StatusCode != http.StatusFound {
		t.Fatalf("first: %d", response.StatusCode)
	}
	tokenCalls := issuer.calls()
	for _, replayCode := range []string{code, issuer.grant(query, memberId, fixture.networkId)} {
		if response := tlsEdgeTestCallback(t, client, replayCode, query.Get("state"), preCookie); response.StatusCode != http.StatusBadRequest ||
			tlsEdgeTestCookie(response, tlsSessionCookieName) != nil {
			t.Errorf("a replay: %d", response.StatusCode)
		}
	}
	if issuer.calls() != tokenCalls {
		t.Errorf("a replay reached the issuer")
	}
}

// The callback needs its own counted pre-cookie: none, another login's, or one a cross-site subresource carries all
// fail before any redemption.
func TestTlsEdgeLoginNeedsItsPreCookie(t *testing.T) {
	memberId := NewId()
	fixture, issuer := newTlsEdgeLoginFixture(t, memberId, nil)
	client := fixture.httpClient(tlsAlpnHttp11)
	query, preCookie := tlsEdgeTestStart(t, client, "/")
	_, otherCookie := tlsEdgeTestStart(t, client, "/")
	code := issuer.grant(query, memberId, fixture.networkId)
	if response := tlsEdgeTestCallback(t, client, code, query.Get("state"), nil); response.StatusCode != http.StatusBadRequest {
		t.Errorf("no pre-cookie: %d", response.StatusCode)
	}
	if response := tlsEdgeTestCallback(t, client, code, query.Get("state"), otherCookie); response.StatusCode != http.StatusBadRequest {
		t.Errorf("another login's pre-cookie: %d", response.StatusCode)
	}
	request := tlsFrontTestNavigation(t, http.MethodGet, tlsEdgeLoginCallbackPath+"?"+url.Values{"code": {code}, "state": {query.Get("state")}}.Encode())
	request.Header.Set(tlsHttpHeaderFetchSite, "cross-site")
	request.Header.Set(tlsHttpHeaderFetchMode, "no-cors")
	request.Header.Set(tlsHttpHeaderFetchDest, "image")
	request.AddCookie(&http.Cookie{Name: preCookie.Name, Value: preCookie.Value})
	if response, _ := tlsFrontTestDo(t, client, request); response.StatusCode != http.StatusBadRequest {
		t.Errorf("a cross-site subresource: %d", response.StatusCode)
	}
	if calls := issuer.calls(); calls != 0 {
		t.Errorf("%d redemptions", calls)
	}
	// the right pair as a navigation still completes, so none of the refusals spent the state
	if response := tlsEdgeTestCallback(t, client, code, query.Get("state"), preCookie); response.StatusCode != http.StatusFound {
		t.Errorf("the right pair afterwards: %d", response.StatusCode)
	}
}

// With no issuer set a login answers 503 and reaches nothing, on any port.
func TestTlsEdgeLoginWithoutAnIssuerIsUnavailable(t *testing.T) {
	memberId := NewId()
	for _, name := range []string{"tls/443/app", "tls/8443/app"} {
		fixture, _ := newTlsEdgeLoginFixture(t, memberId, func(fixture *tlsFrontFixture) {
			fixture.issuerUrl = ""
			fixture.target.Name = name
		})
		response, _ := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), tlsFrontTestNavigation(t, http.MethodGet, "/"))
		if response.StatusCode != http.StatusServiceUnavailable || tlsEdgeTestCookie(response, tlsPreLoginCookieName) != nil {
			t.Errorf("%s: %d", name, response.StatusCode)
		}
	}
}

// QD-723: a members endpoint on each of tlsedge's other ports signs its visitors in as its own origin, the port
// written in client_id and redirect_uri, and its session then reaches the service; 443's origin stays bare.
func TestTlsEdgeLoginOnEveryPort(t *testing.T) {
	for _, c := range []struct {
		name   string
		origin string
	}{
		{name: "tls/443/app", origin: "https://" + tlsFrontTestServerName},
		{name: "tls/8443/app", origin: "https://" + tlsFrontTestServerName + ":8443"},
		{name: "tls/8883/app", origin: "https://" + tlsFrontTestServerName + ":8883"},
		{name: "tls/5671/app", origin: "https://" + tlsFrontTestServerName + ":5671"},
	} {
		memberId := NewId()
		fixture, issuer := newTlsEdgeLoginFixture(t, memberId, func(fixture *tlsFrontFixture) { fixture.target.Name = c.name })
		client := fixture.httpClient(tlsAlpnHttp11)
		query, preCookie := tlsEdgeTestStart(t, client, "/private?x=1")
		if query.Get("client_id") != c.origin || query.Get("redirect_uri") != c.origin+tlsEdgeLoginCallbackPath {
			t.Fatalf("%s: client_id %q, redirect_uri %q", c.name, query.Get("client_id"), query.Get("redirect_uri"))
		}
		response := tlsEdgeTestCallback(t, client, issuer.grant(query, memberId, fixture.networkId), query.Get("state"), preCookie)
		session := tlsEdgeTestCookie(response, tlsSessionCookieName)
		if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/private?x=1" || session == nil {
			t.Fatalf("%s: callback %d to %q", c.name, response.StatusCode, response.Header.Get("Location"))
		}
		if dials, _ := fixture.backend.counts(); dials != 0 {
			t.Fatalf("%s: %d dials during the login", c.name, dials)
		}
		request := tlsFrontTestNavigation(t, http.MethodGet, "/private?x=1")
		request.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
		if response, body := tlsFrontTestDo(t, client, request); response.StatusCode != http.StatusOK || body != "backend" {
			t.Fatalf("%s: signed in: %d %q", c.name, response.StatusCode, body)
		}
	}
}

// Two fronts of one device, network and host, on 443 and on 8443, with one keychain and clock between them, as a
// device publishing both runs them.
func newTlsEdgeLoginPortFixtures(t *testing.T, memberId Id) (bare *tlsFrontFixture, bareIssuer *tlsEdgeTestIssuer, ported *tlsFrontFixture, portedIssuer *tlsEdgeTestIssuer) {
	t.Helper()
	bare, bareIssuer = newTlsEdgeLoginFixture(t, memberId, nil)
	ported, portedIssuer = newTlsEdgeLoginFixture(t, memberId, func(fixture *tlsFrontFixture) {
		fixture.target.Name = "tls/8443/app"
		fixture.secrets = bare.secrets
		fixture.networkId = bare.networkId
		fixture.sidecarId = bare.sidecarId
	})
	return bare, bareIssuer, ported, portedIssuer
}

// D-TEAM-15's one origin across ports (QD-723): with both endpoints sealing under one keychain, a session either
// front set counts on its own and not on the other, in both directions, though the browser sends it to both.
func TestTlsEdgeLoginSessionStaysOnItsPort(t *testing.T) {
	memberId := NewId()
	bare, bareIssuer, ported, portedIssuer := newTlsEdgeLoginPortFixtures(t, memberId)
	login := func(fixture *tlsFrontFixture, issuer *tlsEdgeTestIssuer) *http.Cookie {
		client := fixture.httpClient(tlsAlpnHttp11)
		query, preCookie := tlsEdgeTestStart(t, client, "/")
		response := tlsEdgeTestCallback(t, client, issuer.grant(query, memberId, fixture.networkId), query.Get("state"), preCookie)
		session := tlsEdgeTestCookie(response, tlsSessionCookieName)
		if response.StatusCode != http.StatusFound || session == nil {
			t.Fatalf("%s: login %d", fixture.target.Name, response.StatusCode)
		}
		return session
	}
	fetch := func(fixture *tlsFrontFixture, session *http.Cookie) int {
		request := tlsFrontTestNavigation(t, http.MethodGet, "/api")
		request.Header.Set(tlsHttpHeaderFetchSite, tlsFetchSiteSameOrigin)
		request.Header.Set(tlsHttpHeaderFetchMode, "cors")
		request.Header.Set(tlsHttpHeaderFetchDest, "empty")
		request.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
		response, _ := tlsFrontTestDo(t, fixture.httpClient(tlsAlpnHttp11), request)
		return response.StatusCode
	}
	bareSession, portedSession := login(bare, bareIssuer), login(ported, portedIssuer)
	if status := fetch(bare, bareSession); status != http.StatusOK {
		t.Errorf("443's session on 443: %d", status)
	}
	if status := fetch(ported, portedSession); status != http.StatusOK {
		t.Errorf("8443's session on 8443: %d", status)
	}
	bareDials, _ := bare.backend.counts()
	portedDials, _ := ported.backend.counts()
	if status := fetch(ported, bareSession); status != http.StatusUnauthorized {
		t.Errorf("443's session on 8443: %d", status)
	}
	if status := fetch(bare, portedSession); status != http.StatusUnauthorized {
		t.Errorf("8443's session on 443: %d", status)
	}
	if dials, _ := bare.backend.counts(); dials != bareDials {
		t.Errorf("443 dialed for 8443's session")
	}
	if dials, _ := ported.backend.counts(); dials != portedDials {
		t.Errorf("8443 dialed for 443's session")
	}
}

// A login begun on one port completes on no other (QD-723): its pre-cookie does not open there, before any
// redemption, and an ID token whose aud is the host's other endpoint sets no session, in both directions.
func TestTlsEdgeLoginTokenStaysOnItsPort(t *testing.T) {
	memberId := NewId()
	bare, bareIssuer, ported, portedIssuer := newTlsEdgeLoginPortFixtures(t, memberId)
	bareOrigin, portedOrigin := "https://"+tlsFrontTestServerName, "https://"+tlsFrontTestServerName+":8443"
	for _, c := range []struct {
		name        string
		fixture     *tlsFrontFixture
		issuer      *tlsEdgeTestIssuer
		other       *tlsFrontFixture
		otherIssuer *tlsEdgeTestIssuer
		otherOrigin string
	}{
		{name: "443's on 8443", fixture: bare, issuer: bareIssuer, other: ported, otherIssuer: portedIssuer, otherOrigin: bareOrigin},
		{name: "8443's on 443", fixture: ported, issuer: portedIssuer, other: bare, otherIssuer: bareIssuer, otherOrigin: portedOrigin},
	} {
		// this port's pending login, carried whole to the other port's callback
		query, preCookie := tlsEdgeTestStart(t, c.fixture.httpClient(tlsAlpnHttp11), "/")
		otherClient := c.other.httpClient(tlsAlpnHttp11)
		response := tlsEdgeTestCallback(t, otherClient, c.otherIssuer.grant(query, memberId, c.other.networkId), query.Get("state"), preCookie)
		if response.StatusCode != http.StatusBadRequest || tlsEdgeTestCookie(response, tlsSessionCookieName) != nil {
			t.Errorf("%s: a pending login: %d", c.name, response.StatusCode)
		}
		if calls := c.otherIssuer.calls(); calls != 0 {
			t.Errorf("%s: %d redemptions", c.name, calls)
		}
		// the other port's own login, answered with a token for this port's origin
		otherQuery, otherPreCookie := tlsEdgeTestStart(t, otherClient, "/")
		c.otherIssuer.nextToken(func(header map[string]any, claims map[string]any) {
			claims["aud"] = []string{c.otherOrigin}
		}, nil)
		response = tlsEdgeTestCallback(t, otherClient, c.otherIssuer.grant(otherQuery, memberId, c.other.networkId), otherQuery.Get("state"), otherPreCookie)
		if response.StatusCode != http.StatusForbidden || tlsEdgeTestCookie(response, tlsSessionCookieName) != nil {
			t.Errorf("%s: an ID token: %d", c.name, response.StatusCode)
		}
		if dials, _ := c.other.backend.counts(); dials != 0 {
			t.Errorf("%s: %d dials", c.name, dials)
		}
	}
}

// Where a login returns: the request's own path and query, unless it is too long, not a plain path or the front's.
func TestTlsEdgeLoginReturnPath(t *testing.T) {
	for _, c := range []struct {
		target string
		want   string
	}{
		{target: "/private?x=1", want: "/private?x=1"},
		{target: "/a%20b", want: "/a%20b"},
		{target: "//evil.example/", want: "/"},
		{target: "/.well-known/ur/callback?code=c", want: "/"},
		{target: "/" + strings.Repeat("a", 3000), want: "/"},
	} {
		request, err := http.NewRequest(http.MethodGet, "https://"+tlsFrontTestServerName+c.target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := tlsEdgeLoginReturnPath(request, DefaultTlsFrontSettings().ReturnPathMaxByteCount); got != c.want {
			t.Errorf("%.40q: %q", c.target, got)
		}
	}
}

// A Logger that keeps every line, for a test that reads them.
type tlsFrontTestLogger struct {
	stateLock sync.Mutex
	lines     []string
}

var _ Logger = (*tlsFrontTestLogger)(nil)

// Keeps one line.
func (self *tlsFrontTestLogger) keep(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

// See Logger.
func (self *tlsFrontTestLogger) Info(args ...any) { self.keep(fmt.Sprint(args...)) }

// See Logger.
func (self *tlsFrontTestLogger) Infof(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

// See Logger.
func (self *tlsFrontTestLogger) Warningf(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

// See Logger.
func (self *tlsFrontTestLogger) Errorf(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

// See Logger: every level is on, so nothing hides behind one.
func (self *tlsFrontTestLogger) V(level int32) Verbose { return tlsFrontTestVerbose{logger: self} }

// Every level of a tlsFrontTestLogger.
type tlsFrontTestVerbose struct {
	logger *tlsFrontTestLogger
}

// See Verbose.
func (self tlsFrontTestVerbose) Enabled() bool { return true }

// See Verbose.
func (self tlsFrontTestVerbose) Info(args ...any) { self.logger.keep(fmt.Sprint(args...)) }

// See Verbose.
func (self tlsFrontTestVerbose) Infof(format string, args ...any) {
	self.logger.keep(fmt.Sprintf(format, args...))
}

// I-7, I-13: through a whole login and a refused one, no log line carries a code, a state, a nonce, a cookie, a
// token, the visitor's address or a host.
func TestTlsEdgeLoginLogsNoSecret(t *testing.T) {
	memberId := NewId()
	logger := &tlsFrontTestLogger{}
	fixture, issuer := newTlsEdgeLoginFixture(t, memberId, func(fixture *tlsFrontFixture) {
		fixture.log = logger
	})
	client := fixture.httpClient(tlsAlpnHttp11)
	query, preCookie := tlsEdgeTestStart(t, client, "/secret-path")
	code := issuer.grant(query, memberId, fixture.networkId)
	response := tlsEdgeTestCallback(t, client, code, query.Get("state"), preCookie)
	session := tlsEdgeTestCookie(response, tlsSessionCookieName)
	if session == nil {
		t.Fatal("no session")
	}
	tlsEdgeTestCallback(t, client, code, query.Get("state"), preCookie)
	secrets := []string{code, query.Get("state"), query.Get("nonce"), preCookie.Value, session.Value, "secret-path",
		tlsFrontTestServerName, "2001:db8::7"}
	logger.stateLock.Lock()
	defer logger.stateLock.Unlock()
	for _, line := range logger.lines {
		for _, secret := range secrets {
			if strings.Contains(line, secret) {
				t.Errorf("a log line carries %.12q", secret)
			}
		}
	}
}
