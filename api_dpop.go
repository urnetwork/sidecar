// DPoP proofs of the ClientKey (§7.4, RFC 9449), on every leg: crypto/ed25519 signs them, in the page
// Worker too. A strict_exp bearer proves it holds its ClientKey to renew, exchange or mint, so only
// GET /auth/refresh, POST /oauth/token's exchange and POST /network/auth-client carry a proof, each
// over the token it presents. The ClientKey signs only these proofs and the identity binding, never a
// statement (D-CORE-6).
//
// A proof is a compact JWS:
//
//	header  {typ dpop+jwt, alg EdDSA, jwk {kty OKP, crv Ed25519, x}}
//	claims  {jti, htm, htu, iat, ath = SHA-256(token)}
//
// with a 128-bit random jti, iat in whole seconds, and htu the request's url with no query or
// fragment. iat is the api's clock as this device reads it, its own time plus the offset the api's
// answers gave (§7.4, QD-757; api_client.go keeps it), since api holds iat within its window of its
// own clock and a device's may run minutes off. The header and claims are written here with their keys in sorted order, as RFC 8785 puts
// them, so a proof's bytes depend only on its inputs, and testdata/dpop/vectors.json holds the same
// bytes on every leg. Verifiers decode the JSON, so they need not know the order.

package sidecar

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"time"
)

const (
	// The proof's JOSE type (RFC 9449 §4.2).
	dpopProofType = "dpop+jwt"
	// Ed25519 under its JOSE name (RFC 8037).
	dpopProofAlg = "EdDSA"
	// The bytes a jti draws: 128 bits, past RFC 9449 §4.2's 96.
	dpopJtiByteCount = 16
	// The longest htm a signer takes. Every method a route uses is shorter.
	dpopMaxMethodByteCount = 16
)

// A proof the signer refused to make. The error names what was wrong with an argument, never its
// value: a url may hold an id or a query (I-13).
var errDpopProof = errors.New("dpop proof refused")

// The ath claim for token: the unpadded base64url of SHA-256 over its ASCII bytes (RFC 9449 §4.2).
func dpopAth(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// The htu claim for requestUrl: the url with its query and fragment dropped (RFC 9449 §4.2), and an
// empty path read as "/", which RFC 3986 §6.2.3 makes the same. Only an absolute http or https url
// with no credentials of its own is taken, as absoluteUrlTransport takes nothing else.
func dpopHtu(requestUrl string) (string, error) {
	parsed, err := url.Parse(requestUrl)
	if err != nil || !isAbsoluteServiceUrl(parsed, "http", "https") {
		return "", fmt.Errorf("%w: the url is not absolute", errDpopProof)
	}
	htu := &url.URL{
		Scheme:  parsed.Scheme,
		Host:    parsed.Host,
		Path:    parsed.Path,
		RawPath: parsed.RawPath,
	}
	if htu.Path == "" {
		htu.Path = "/"
		htu.RawPath = ""
	}
	return htu.String(), nil
}

// Whether method is an HTTP method a proof may name: uppercase letters only, as every method a route
// uses is, so nothing in htm needs escaping.
func isDpopMethod(method string) bool {
	if method == "" || dpopMaxMethodByteCount < len(method) {
		return false
	}
	for i := 0; i < len(method); i += 1 {
		if method[i] < 'A' || 'Z' < method[i] {
			return false
		}
	}
	return true
}

// Whether ath is what dpopAth returns for some token: 32 bytes in unpadded base64url.
func isDpopAth(ath string) bool {
	hash, err := base64.RawURLEncoding.DecodeString(ath)
	return err == nil && len(hash) == sha256.Size
}

// value as a JSON string, with nothing escaped that JSON does not require, so a url keeps its & and
// its < and > as RFC 8785 would write them.
func dpopJsonString(value string) []byte {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	// encoding a string never fails
	encoder.Encode(value)
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
}

// The proof's header for the key whose public half is publicKey, which every proof of one key
// shares.
func dpopHeader(publicKey ed25519.PublicKey) []byte {
	x := base64.RawURLEncoding.EncodeToString(publicKey)
	return []byte(`{"alg":"` + dpopProofAlg + `","jwk":{"crv":"Ed25519","kty":"OKP","x":"` + x + `"},"typ":"` + dpopProofType + `"}`)
}

// The proof's claims, keys sorted. jti and ath are base64url and htm is uppercase letters, so only
// htu is escaped.
func dpopClaims(ath string, htm string, htu string, iat int64, jti string) []byte {
	claims := []byte(`{"ath":"` + ath + `","htm":"` + htm + `","htu":`)
	claims = append(claims, dpopJsonString(htu)...)
	claims = append(claims, `,"iat":`+strconv.FormatInt(iat, 10)+`,"jti":"`+jti+`"}`...)
	return claims
}

// The compact JWS of header and claims, signed by privateKey (RFC 7515 §7.1).
func dpopSign(privateKey ed25519.PrivateKey, header []byte, claims []byte) string {
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature := ed25519.Sign(privateKey, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// A signer of proofs by the ClientKey whose seed is clientKeySeed: 32 bytes, as
// connect.ClientSettings.ClientKeySeed holds it. The seed is read here and not kept, so the caller
// may zero it on return. now is this device's clock and apiClockOffset the api's clock less it,
// read at each proof, so iat is the api's time as this device knows it (SidecarApi's
// currentApiClockOffset); nil is no offset, this device's clock alone. random is the jti's source.
// A test fixes each; a failed draw signs nothing.
//
// The signer takes a request's method and url as the request carries them, and ath, dpopAth of the
// token the request presents, and is SidecarApi's dpopSigner and the shape sdk's Api.SetDpopSigner
// takes (§7.4). It is safe for concurrent use when random is, as crypto/rand.Reader is.
func newDpopSigner(clientKeySeed []byte, now func() time.Time, apiClockOffset func() time.Duration, random io.Reader) (func(method string, url string, ath string) (string, error), error) {
	if len(clientKeySeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: a ClientKey seed is %d bytes", errDpopProof, ed25519.SeedSize)
	}
	privateKey := ed25519.NewKeyFromSeed(clientKeySeed)
	testHookSecret("ClientKey", privateKey)
	header := dpopHeader(privateKey.Public().(ed25519.PublicKey))

	return func(method string, requestUrl string, ath string) (string, error) {
		if !isDpopMethod(method) {
			return "", fmt.Errorf("%w: the method is not an uppercase token", errDpopProof)
		}
		htu, err := dpopHtu(requestUrl)
		if err != nil {
			return "", err
		}
		if !isDpopAth(ath) {
			return "", fmt.Errorf("%w: ath is not a token's hash", errDpopProof)
		}
		jtiBytes := make([]byte, dpopJtiByteCount)
		if _, err := io.ReadFull(random, jtiBytes); err != nil {
			return "", fmt.Errorf("%w: no jti: %w", errDpopProof, err)
		}
		jti := base64.RawURLEncoding.EncodeToString(jtiBytes)
		iat := now()
		if apiClockOffset != nil {
			iat = iat.Add(apiClockOffset())
		}
		claims := dpopClaims(ath, method, htu, iat.Unix(), jti)
		return dpopSign(privateKey, header, claims), nil
	}, nil
}
