// §7.4's proof of the ClientKey on the fake api (RFC 9449), as server's session.VerifyDpopProof checks it: a strict_exp
// bearer proves it holds its ClientKey to renew, exchange or mint, so a token copied alone does none of them.
//
//	header  {typ dpop+jwt, alg EdDSA, jwk {kty OKP, crv Ed25519, x}}, x the client's newest bound key
//	claims  {jti, htm, htu, iat, ath = SHA-256(token)}
//	replay  each jti once per client, kept DpopReplayTimeout; iat within DpopIatWindow of the api's clock
//
// htu must name the uri the route is configured with, https only, with the same host and path, whatever the request's
// own Host says. A proof that fails any check spends no jti, so nobody without the key can burn one. The exchange
// calls it (fake_api_exchange.go), and CORE-M1-13's refresh and auth-client routes take the same check.

package sidecartest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

const (
	fakeApiDpopType = "dpop+jwt"
	fakeApiDpopAlg  = "EdDSA"
)

// A proof that did not verify. Its detail is for the test reading it; a route answers with a fixed message.
var errFakeApiDpopRefused = errors.New("DPoP proof refused")

func fakeApiDpopRefused(detail string) error {
	return fmt.Errorf("%w: %s", errFakeApiDpopRefused, detail)
}

// One proof's check: what it must name and bind, and the key that must sign it.
type fakeApiDpopRequest struct {
	// the request's one DPoP header
	proof string
	// htm: the request's method
	method string
	// htu: the route's uri at the origin the api is configured with, with no query or fragment
	uri string
	// the token the proof is presented with, whose SHA-256 is ath
	token string
	// the key the proof must be signed by
	key ed25519.PublicKey
	// whose jti space the proof spends: the client's
	replayId sidecar.Id
}

// A proof's header as its JSON holds it.
type fakeApiDpopHeader struct {
	Typ string                     `json:"typ"`
	Alg string                     `json:"alg"`
	Jwk map[string]json.RawMessage `json:"jwk"`
}

// A proof's claims. iat is a JSON number, which may carry a fraction that gojwt's NumericDate drops.
type fakeApiDpopClaims struct {
	Jti string       `json:"jti"`
	Htm string       `json:"htm"`
	Htu string       `json:"htu"`
	Ath string       `json:"ath"`
	Iat *json.Number `json:"iat"`
}

// A jwk member's string value, false when it is absent or not a string.
func fakeApiJwkString(jwk map[string]json.RawMessage, name string) (string, bool) {
	raw, ok := jwk[name]
	if !ok {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

// host as URIs compare equal in (RFC 3986 §6.2.3): lower case, without https's default port.
func fakeApiDpopCanonicalHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ":443")
}

// Whether htu names uri, ignoring htu's query and fragment (RFC 9449 §4.3). Only https is ever named.
func fakeApiDpopHtuMatches(htu string, uri string) bool {
	target, err := url.Parse(htu)
	if err != nil || target.Scheme != "https" || target.User != nil {
		return false
	}
	expected, err := url.Parse(uri)
	if err != nil || expected.Scheme != "https" {
		return false
	}
	return fakeApiDpopCanonicalHost(target.Host) == fakeApiDpopCanonicalHost(expected.Host) && target.Path == expected.Path
}

// Checks one proof against its request and returns its jti, unspent. Reads no state.
func fakeApiCheckDpop(dpopRequest *fakeApiDpopRequest, now time.Time, settings *FakeApiSettings) (string, error) {
	if len(dpopRequest.key) != ed25519.PublicKeySize {
		return "", fakeApiDpopRefused("the bound key is not an Ed25519 key")
	}
	parts := strings.Split(dpopRequest.proof, ".")
	if len(parts) != 3 {
		return "", fakeApiDpopRefused("not a compact JWS")
	}
	headerBytes, headerErr := base64.RawURLEncoding.DecodeString(parts[0])
	claimsBytes, claimsErr := base64.RawURLEncoding.DecodeString(parts[1])
	signature, signatureErr := base64.RawURLEncoding.DecodeString(parts[2])
	if headerErr != nil || claimsErr != nil || signatureErr != nil {
		return "", fakeApiDpopRefused("a part is not base64url")
	}
	header := &fakeApiDpopHeader{}
	if err := json.Unmarshal(headerBytes, header); err != nil {
		return "", fakeApiDpopRefused("the header is not JSON")
	}
	if header.Typ != fakeApiDpopType {
		return "", fakeApiDpopRefused("typ is not dpop+jwt")
	}
	if header.Alg != fakeApiDpopAlg {
		return "", fakeApiDpopRefused("alg is not EdDSA")
	}
	if header.Jwk == nil {
		return "", fakeApiDpopRefused("no jwk")
	}
	if _, private := header.Jwk["d"]; private {
		return "", fakeApiDpopRefused("jwk holds a private key")
	}
	kty, _ := fakeApiJwkString(header.Jwk, "kty")
	crv, _ := fakeApiJwkString(header.Jwk, "crv")
	if kty != "OKP" || crv != "Ed25519" {
		return "", fakeApiDpopRefused("jwk is not an Ed25519 key")
	}
	x, ok := fakeApiJwkString(header.Jwk, "x")
	if !ok {
		return "", fakeApiDpopRefused("jwk has no x")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return "", fakeApiDpopRefused("jwk x is not a public key")
	}
	// the proof names the key it was signed by, and only the bound key counts: an older binding's is refused
	if !bytes.Equal(publicKey, dpopRequest.key) {
		return "", fakeApiDpopRefused("jwk is not the bound key")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(parts[0]+"."+parts[1]), signature) {
		return "", fakeApiDpopRefused("the signature does not verify")
	}
	claims := &fakeApiDpopClaims{}
	decoder := json.NewDecoder(bytes.NewReader(claimsBytes))
	decoder.UseNumber()
	if err := decoder.Decode(claims); err != nil {
		return "", fakeApiDpopRefused("the claims are not JSON")
	}
	if claims.Jti == "" || settings.DpopMaxJtiByteCount < len(claims.Jti) {
		return "", fakeApiDpopRefused("jti is missing or too long")
	}
	if claims.Htm != dpopRequest.method {
		return "", fakeApiDpopRefused("htm is not the request's method")
	}
	if !fakeApiDpopHtuMatches(claims.Htu, dpopRequest.uri) {
		return "", fakeApiDpopRefused("htu is not the request's uri")
	}
	if claims.Iat == nil {
		return "", fakeApiDpopRefused("no iat")
	}
	iatSeconds, err := claims.Iat.Float64()
	if err != nil || math.IsNaN(iatSeconds) || math.IsInf(iatSeconds, 0) || math.Abs(iatSeconds) > float64(math.MaxInt64/int64(time.Second)) {
		return "", fakeApiDpopRefused("iat is not a time")
	}
	// whole seconds, as gojwt's NumericDate keeps it
	iat := time.Unix(int64(math.Floor(iatSeconds)), 0)
	if age := now.Sub(iat); age < -settings.DpopIatWindow || settings.DpopIatWindow < age {
		return "", fakeApiDpopRefused("iat is outside its window")
	}
	hash := sha256.Sum256([]byte(dpopRequest.token))
	if subtle.ConstantTimeCompare([]byte(claims.Ath), []byte(base64.RawURLEncoding.EncodeToString(hash[:]))) != 1 {
		return "", fakeApiDpopRefused("ath is not the token's hash")
	}
	return claims.Jti, nil
}

// Verifies the proof and spends its jti in its client's space, or returns an error wrapping errFakeApiDpopRefused.
func (self *FakeApi) verifyDpop(dpopRequest *fakeApiDpopRequest) error {
	now := self.clock.Now()
	jti, err := fakeApiCheckDpop(dpopRequest, now, self.settings)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for key, expireTime := range self.exchange.spentJtiExpireTimes {
		if !now.Before(expireTime) {
			delete(self.exchange.spentJtiExpireTimes, key)
		}
	}
	key := fakeApiJtiKey{clientId: dpopRequest.replayId, jti: jti}
	if _, spent := self.exchange.spentJtiExpireTimes[key]; spent {
		return fakeApiDpopRefused("jti was already used")
	}
	self.exchange.spentJtiExpireTimes[key] = now.Add(self.settings.DpopReplayTimeout)
	return nil
}
