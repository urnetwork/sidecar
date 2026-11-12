//go:build !sidecar_http && !ios_extension

// §7.8's edge login, the front's side (R-TLS-5, D-TEAM-15, R-CTX-22, §2.8 EX8): how a members endpoint signs its
// visitors in through the issuer, whose word it checks against this device's own config and never takes alone.
//
//	start     a navigation with no counted session: a fresh state, nonce and PKCE verifier, sealed into
//	          __Host-ur-pre (HttpOnly, Secure, SameSite=Lax, PreLoginLifetime), the state kept pending here; 302 to
//	          <issuer>/oauth/authorize with client_id and redirect_uri the origin's, scope openid, the nonce, the
//	          state and the S256 challenge, which is all the issuer accepts for an origin (TEAM-M5-01)
//	callback  GET /.well-known/ur/callback: the counted pre-cookie opens and its state is the query's and still
//	          pending, then leaves the pending set, so a copied pre-cookie never completes twice; the code redeems
//	          at <issuer>/oauth/token for an ID token, which must verify under the issuer's id- key set (ES256),
//	          with iss the issuer, aud the origin alone, the nonce the cookie's, network_id this network, a live
//	          exp no further than IdTokenMaxLifetime past iat, and sub a member this config holds now; then
//	          __Host-ur-session (HttpOnly, Secure, SameSite=Lax, 12 h), and 302 back to where the visitor began
//
// The login path and the callback are the front's (/.well-known/ur/), so neither reaches the local service. An origin
// is https://<sni>, with :<port> where the endpoint's port is not 443 and never :443, which is how the issuer takes
// each of tlsedge's four ports (QD-723): every endpoint is its own origin, client and audience, so a code, an ID
// token, a pending login and a session of the host's 443 endpoint count for nothing on its 8443 one, or the reverse.
// With no issuer set every login answers 503.
//
// Nothing here logs a code, a token, a cookie, a state or a name (I-7, I-13). Safe for concurrent use.

package sidecar

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The issuer's routes the front calls (TEAM-M5-01), the callback's path, and the JWS a front takes.
const (
	tlsEdgeLoginCallbackPath  = "/.well-known/ur/callback"
	tlsEdgeLoginAuthorizePath = "/oauth/authorize"
	tlsEdgeLoginTokenPath     = "/oauth/token"
	tlsEdgeLoginJwksPath      = "/.well-known/ur/id-jwks.json"
	tlsEdgeLoginScope         = "openid"
	tlsEdgeLoginKidPrefix     = "id-"
	tlsEdgeLoginAlg           = "ES256"
	// r || s, 32 bytes each (RFC 7518 §3.4)
	tlsEdgeLoginSignatureByteCount  = 64
	tlsEdgeLoginCoordinateByteCount = 32
	// https's own port, which an origin never writes: the issuer takes 443 bare alone (QD-723).
	tlsEdgeLoginBarePort = 443
)

var (
	// The ID token, the code's redemption or the key set did not check out. It names nothing it read.
	errTlsEdgeLogin = errors.New("tls edge login refused")
)

// One front's edge login.
type tlsEdgeLogin struct {
	front     *TlsFront
	issuerUrl string
	client    *http.Client

	stateLock sync.Mutex
	// each pending login's state, as base64url, to when it ends
	pendingStates map[string]time.Time
	// the issuer's id- keys by kid, when they were read and when a read was last tried
	jwksKeys      map[string]*ecdsa.PublicKey
	jwksReadTime  time.Time
	jwksTriedTime time.Time
}

// A login against issuerUrl, through client or a client of its own.
func newTlsEdgeLogin(front *TlsFront, issuerUrl string, client *http.Client) *tlsEdgeLogin {
	if client == nil {
		client = &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true}}
	}
	return &tlsEdgeLogin{
		front:         front,
		issuerUrl:     strings.TrimSuffix(issuerUrl, "/"),
		client:        client,
		pendingStates: map[string]time.Time{},
		jwksKeys:      map[string]*ecdsa.PublicKey{},
	}
}

// The origin a connection's visitors are at: the issuer's client_id, the ID token's aud, and what its sessions and
// pending logins are sealed to, so a session counts on its own origin alone (D-TEAM-15), never on another port of the
// host, though cookies do not tell ports apart. The port is the target name's, one of tlsedge's four by the name's
// grammar (ParseSocketName), written unless it is 443.
func tlsEdgeLoginOrigin(conn *TlsFrontConn) string {
	origin := "https://" + conn.ServerName()
	if port := conn.front.target.port(); port != tlsEdgeLoginBarePort {
		origin += ":" + strconv.Itoa(int(port))
	}
	return origin
}

// Where the visitor returns after login: the request's own path and query, unless it is too long, not a plain path,
// or the front's, which return to /.
func tlsEdgeLoginReturnPath(r *http.Request, maxByteCount int) string {
	returnPath := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		returnPath += "?" + r.URL.RawQuery
	}
	switch {
	case maxByteCount < len(returnPath), !strings.HasPrefix(returnPath, "/"), strings.HasPrefix(returnPath, "//"),
		strings.HasPrefix(returnPath, "/\\"), tlsHttpFrontPath(r.URL.Path):
		return "/"
	}
	return returnPath
}

// Sends a navigation with no counted session to the issuer (see the file header).
func (self *tlsEdgeLogin) start(w http.ResponseWriter, r *http.Request, conn *TlsFrontConn) {
	if self.issuerUrl == "" {
		tlsHttpAnswer(w, http.StatusServiceUnavailable)
		return
	}
	now := self.front.clock.Now()
	preLogin := &tlsPreLogin{
		expireTime: now.Add(self.front.settings.PreLoginLifetime),
		returnPath: tlsEdgeLoginReturnPath(r, self.front.settings.ReturnPathMaxByteCount),
	}
	for _, random := range [][]byte{preLogin.state[:], preLogin.nonce[:], preLogin.verifier[:]} {
		if _, err := cryptorand.Read(random); err != nil {
			tlsHttpAnswer(w, http.StatusServiceUnavailable)
			return
		}
	}
	origin := tlsEdgeLoginOrigin(conn)
	value, err := self.front.sessions.sealPreLogin(origin, preLogin)
	if err != nil {
		tlsHttpAnswer(w, http.StatusServiceUnavailable)
		return
	}
	state := base64.RawURLEncoding.EncodeToString(preLogin.state[:])
	nonce := base64.RawURLEncoding.EncodeToString(preLogin.nonce[:])
	verifier := base64.RawURLEncoding.EncodeToString(preLogin.verifier[:])
	challenge := sha256.Sum256([]byte(verifier))
	self.addPending(state, preLogin.expireTime, now)

	query := url.Values{
		"response_type":         {"code"},
		"client_id":             {origin},
		"redirect_uri":          {origin + tlsEdgeLoginCallbackPath},
		"scope":                 {tlsEdgeLoginScope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	http.SetCookie(w, &http.Cookie{
		Name:     tlsPreLoginCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(self.front.settings.PreLoginLifetime / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Location", self.issuerUrl+tlsEdgeLoginAuthorizePath+"?"+query.Encode())
	w.WriteHeader(http.StatusFound)
}

// Records state as pending until expireTime, dropping what ended, and the oldest past PendingLoginMaxCount.
func (self *tlsEdgeLogin) addPending(state string, expireTime time.Time, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for pendingState, pendingExpireTime := range self.pendingStates {
		if !now.Before(pendingExpireTime) {
			delete(self.pendingStates, pendingState)
		}
	}
	for self.front.settings.PendingLoginMaxCount <= len(self.pendingStates) {
		oldestState := ""
		oldestExpireTime := time.Time{}
		for pendingState, pendingExpireTime := range self.pendingStates {
			if oldestState == "" || pendingExpireTime.Before(oldestExpireTime) {
				oldestState = pendingState
				oldestExpireTime = pendingExpireTime
			}
		}
		delete(self.pendingStates, oldestState)
	}
	self.pendingStates[state] = expireTime
}

// Takes state out of the pending set: true once, while it is live.
func (self *tlsEdgeLogin) takePending(state string, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	expireTime, ok := self.pendingStates[state]
	delete(self.pendingStates, state)
	return ok && now.Before(expireTime)
}

// GET /.well-known/ur/callback (see the file header), under a members grant alone.
func (self *tlsEdgeLogin) callback(w http.ResponseWriter, r *http.Request, conn *TlsFrontConn, view *tlsHttpSessionView) {
	if r.Method != http.MethodGet {
		tlsHttpAnswer(w, http.StatusMethodNotAllowed)
		return
	}
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	now := self.front.clock.Now()
	grant := self.front.audience.grant(protocol.AclAppMode_ACL_APP_MODE_HTTP, now)
	if grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_MEMBERS || self.issuerUrl == "" {
		tlsHttpAnswer(w, http.StatusNotFound)
		return
	}
	origin := tlsEdgeLoginOrigin(conn)
	preLogin := self.front.sessions.openPreLogin(view.preLogin, origin, now)
	query := r.URL.Query()
	state := query.Get("state")
	if preLogin == nil || subtle.ConstantTimeCompare([]byte(state), []byte(base64.RawURLEncoding.EncodeToString(preLogin.state[:]))) != 1 ||
		!self.takePending(state, now) {
		tlsHttpAnswer(w, http.StatusBadRequest)
		return
	}
	// the pre-cookie is spent whatever follows
	http.SetCookie(w, &http.Cookie{Name: tlsPreLoginCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	code := query.Get("code")
	if code == "" {
		tlsHttpAnswer(w, http.StatusForbidden)
		return
	}
	idToken, err := self.redeem(r.Context(), origin, code, base64.RawURLEncoding.EncodeToString(preLogin.verifier[:]))
	if err != nil {
		tlsHttpAnswer(w, http.StatusBadGateway)
		return
	}
	memberId, err := self.verify(r.Context(), idToken, origin, base64.RawURLEncoding.EncodeToString(preLogin.nonce[:]), now)
	if err != nil || !self.front.policy.MemberActive(memberId, now) {
		tlsHttpAnswer(w, http.StatusForbidden)
		return
	}
	session := &tlsSession{memberId: memberId, issueTime: now, expireTime: now.Add(self.front.settings.SessionLifetime)}
	if _, err := cryptorand.Read(session.sessionId[:]); err != nil {
		tlsHttpAnswer(w, http.StatusServiceUnavailable)
		return
	}
	value, err := self.front.sessions.sealSession(origin, session)
	if err != nil {
		tlsHttpAnswer(w, http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     tlsSessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(self.front.settings.SessionLifetime / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	header.Set("Location", preLogin.returnPath)
	w.WriteHeader(http.StatusFound)
}

// The issuer's answer to one call, bounded, within IssuerRequestTimeout on the clock.
func (self *tlsEdgeLogin) call(ctx context.Context, request func(ctx context.Context) (*http.Request, error)) ([]byte, error) {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := self.front.clock.AfterFunc(self.front.settings.IssuerRequestTimeout, cancel)
	defer stop()
	httpRequest, err := request(callCtx)
	if err != nil {
		return nil, errTlsEdgeLogin
	}
	response, err := self.client.Do(httpRequest)
	if err != nil {
		return nil, errTlsEdgeLogin
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, self.front.settings.IssuerResponseMaxByteCount+1))
	if err != nil || response.StatusCode != http.StatusOK || self.front.settings.IssuerResponseMaxByteCount < int64(len(body)) {
		return nil, errTlsEdgeLogin
	}
	return body, nil
}

// Redeems code with its verifier for the ID token (TEAM-M5-01's ExchangeEdgeCode).
func (self *tlsEdgeLogin) redeem(ctx context.Context, origin string, code string, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {origin},
		"code":          {code},
		"redirect_uri":  {origin + tlsEdgeLoginCallbackPath},
		"code_verifier": {verifier},
	}
	body, err := self.call(ctx, func(ctx context.Context) (*http.Request, error) {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, self.issuerUrl+tlsEdgeLoginTokenPath, strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return request, nil
	})
	if err != nil {
		return "", err
	}
	answer := struct {
		IdToken string `json:"id_token"`
	}{}
	if err := json.Unmarshal(body, &answer); err != nil || answer.IdToken == "" {
		return "", errTlsEdgeLogin
	}
	return answer.IdToken, nil
}

// The id- key kid names, reading the issuer's key set when it is older than JwksLifetime or lacks kid, at most once
// per JwksRefetchMinInterval. Nil when no such key is known.
func (self *tlsEdgeLogin) key(ctx context.Context, kid string, now time.Time) *ecdsa.PublicKey {
	settings := self.front.settings
	key, read := func() (*ecdsa.PublicKey, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		key := self.jwksKeys[kid]
		fresh := !self.jwksReadTime.IsZero() && now.Before(self.jwksReadTime.Add(settings.JwksLifetime))
		if key != nil && fresh {
			return key, false
		}
		if !self.jwksTriedTime.IsZero() && now.Before(self.jwksTriedTime.Add(settings.JwksRefetchMinInterval)) {
			return key, false
		}
		self.jwksTriedTime = now
		return key, true
	}()
	if !read {
		return key
	}
	body, err := self.call(ctx, func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, self.issuerUrl+tlsEdgeLoginJwksPath, nil)
	})
	if err != nil {
		return key
	}
	keys, err := tlsEdgeLoginParseJwks(body)
	if err != nil {
		return key
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.jwksKeys = keys
	self.jwksReadTime = now
	return keys[kid]
}

// The P-256 ES256 keys of the id- set in a JWKS: every other key is left out.
func tlsEdgeLoginParseJwks(body []byte) (map[string]*ecdsa.PublicKey, error) {
	jwks := struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}{}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, errTlsEdgeLogin
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, jwk := range jwks.Keys {
		if jwk.Kty != "EC" || jwk.Crv != "P-256" || !strings.HasPrefix(jwk.Kid, tlsEdgeLoginKidPrefix) ||
			(jwk.Alg != "" && jwk.Alg != tlsEdgeLoginAlg) || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		x, xErr := base64.RawURLEncoding.DecodeString(jwk.X)
		y, yErr := base64.RawURLEncoding.DecodeString(jwk.Y)
		if xErr != nil || yErr != nil || len(x) != tlsEdgeLoginCoordinateByteCount || len(y) != tlsEdgeLoginCoordinateByteCount {
			continue
		}
		point := append(append([]byte{4}, x...), y...)
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
		if err != nil {
			continue
		}
		keys[jwk.Kid] = key
	}
	return keys, nil
}

// The ID token's claims a front reads.
type tlsEdgeIdTokenClaims struct {
	Issuer    string          `json:"iss"`
	Subject   string          `json:"sub"`
	Audience  json.RawMessage `json:"aud"`
	ExpiresAt int64           `json:"exp"`
	IssuedAt  int64           `json:"iat"`
	Nonce     string          `json:"nonce"`
	NetworkId string          `json:"network_id"`
}

// The member an ID token names, once it verifies for origin and nonce at now (see the file header). The member's
// standing in this config is the caller's to check.
func (self *tlsEdgeLogin) verify(ctx context.Context, idToken string, origin string, nonce string, now time.Time) (Id, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return Id{}, errTlsEdgeLogin
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Id{}, errTlsEdgeLogin
	}
	header := struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{}
	if err := json.Unmarshal(headerBytes, &header); err != nil || header.Alg != tlsEdgeLoginAlg || !strings.HasPrefix(header.Kid, tlsEdgeLoginKidPrefix) {
		return Id{}, errTlsEdgeLogin
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != tlsEdgeLoginSignatureByteCount {
		return Id{}, errTlsEdgeLogin
	}
	key := self.key(ctx, header.Kid, now)
	if key == nil {
		return Id{}, errTlsEdgeLogin
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	half := tlsEdgeLoginSignatureByteCount / 2
	if !ecdsa.Verify(key, digest[:], new(big.Int).SetBytes(signature[:half]), new(big.Int).SetBytes(signature[half:])) {
		return Id{}, errTlsEdgeLogin
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Id{}, errTlsEdgeLogin
	}
	claims := &tlsEdgeIdTokenClaims{}
	if err := json.Unmarshal(payload, claims); err != nil {
		return Id{}, errTlsEdgeLogin
	}
	return tlsEdgeLoginCheckClaims(claims, self.issuerUrl, origin, nonce, self.front.networkId, now, self.front.settings)
}

// The member claims name, once every claim but the signature checks out (see the file header).
func tlsEdgeLoginCheckClaims(claims *tlsEdgeIdTokenClaims, issuer string, origin string, nonce string, networkId Id, now time.Time, settings *TlsFrontSettings) (Id, error) {
	audiences := []string{}
	single := ""
	if json.Unmarshal(claims.Audience, &single) == nil {
		audiences = append(audiences, single)
	} else if json.Unmarshal(claims.Audience, &audiences) != nil {
		return Id{}, errTlsEdgeLogin
	}
	if len(audiences) != 1 || audiences[0] != origin || claims.Issuer != issuer {
		return Id{}, errTlsEdgeLogin
	}
	if claims.Nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return Id{}, errTlsEdgeLogin
	}
	expireTime := time.Unix(claims.ExpiresAt, 0)
	issueTime := time.Unix(claims.IssuedAt, 0)
	if claims.ExpiresAt == 0 || claims.IssuedAt == 0 || !now.Before(expireTime.Add(settings.IdTokenClockSkew)) ||
		now.Add(settings.IdTokenClockSkew).Before(issueTime) || settings.IdTokenMaxLifetime < expireTime.Sub(issueTime) {
		return Id{}, errTlsEdgeLogin
	}
	tokenNetworkId, err := ParseId(claims.NetworkId)
	if err != nil || tokenNetworkId != networkId {
		return Id{}, errTlsEdgeLogin
	}
	memberId, err := ParseId(claims.Subject)
	if err != nil {
		return Id{}, errTlsEdgeLogin
	}
	return memberId, nil
}
