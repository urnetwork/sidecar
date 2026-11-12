//go:build !sidecar_http && !ios_extension

// A link audience's guest link (QD-134, the owner's answer to plan-TLS-small-readings#8): a TlsLinkToken
// {grant_id, host, expire_time_millis, nonce}, signed as SIGNED_TLS_LINK under purpose tls-link by the publishing
// device's identity key, reusable until its grant ends. The URL is https://<host>/.well-known/ur/link?t=<base64url of
// the Signed>. At that path the front verifies the token and sets __Host-ur-link (HttpOnly, Secure, SameSite=Lax,
// 12 h, capped by the token's expiry) holding the same token, then answers 302 to / with Referrer-Policy: no-referrer,
// so the token leaves the address bar.
//
// A token verifies when its signature holds under the signer's identity key in this device's config, the signer is a
// sidecar the grant names (it holds that rule's publish grant for the endpoint), the grant is one this endpoint is
// published under now with audience link, host is the SNI, and the token has not expired and asks no more life than
// its grant has. The cookie is checked the same way on every request, so a GrantRevoke or the grant's expiry ends
// every link of the grant at the next request, and any listener of the grant honors it with no shared state.
//
// Nothing here logs a token or a host (I-7, I-13).

package sidecar

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose SIGNED_TLS_LINK signs under (QD-134). identity_sign.go names it as a literal on legs this file is off.
const TlsLinkPurpose = "tls-link"

// The front's path that trades a token for the cookie, its query parameter, and the token's nonce length.
const (
	tlsLinkPath           = "/.well-known/ur/link"
	tlsLinkQueryParameter = "t"
	tlsLinkNonceByteCount = 16
)

var (
	// A token that does not verify here, for any of the file header's reasons. It names none of them.
	ErrTlsLinkToken = errors.New("tls link token refused")
)

// A new token for one grant and host until expireTime, with a fresh nonce: what `ur bridge public-tls --audience
// link` signs (§13.10), its expiry at most the grant's.
func NewTlsLinkToken(grantId []byte, host string, expireTime time.Time) (*protocol.TlsLinkToken, error) {
	if len(grantId) != len(Id{}) || !tlsDnsNameCanonical(host) || expireTime.UnixMilli() <= 0 {
		return nil, fmt.Errorf("%w: a grant id, a host and an expiry", ErrTlsLinkToken)
	}
	nonce := make([]byte, tlsLinkNonceByteCount)
	if _, err := cryptorand.Read(nonce); err != nil {
		return nil, err
	}
	return &protocol.TlsLinkToken{
		GrantId:          bytes.Clone(grantId),
		Host:             host,
		ExpireTimeMillis: uint64(expireTime.UnixMilli()),
		Nonce:            nonce,
	}, nil
}

// Signs token through sign, Sidecar.Sign's shape, and answers the Signed's encoded bytes, which a link carries.
func SignTlsLinkToken(token *protocol.TlsLinkToken, sign TlsKeyAttestationSignFunction) ([]byte, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(token)
	if err != nil {
		return nil, err
	}
	signed, err := sign(TlsLinkPurpose, bridge.SignedType_SIGNED_TLS_LINK, body, nil)
	if err != nil {
		return nil, err
	}
	if signed.GetType() != uint32(bridge.SignedType_SIGNED_TLS_LINK) || !bytes.Equal(signed.GetBody(), body) {
		return nil, fmt.Errorf("%w: sign answered another statement", ErrTlsLinkToken)
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(signed)
}

// The link a guest opens: https://<host>/.well-known/ur/link?t=<base64url of signedToken>.
func TlsLinkUrl(host string, signedToken []byte) string {
	return "https://" + host + tlsLinkPath + "?" + tlsLinkQueryParameter + "=" + base64.RawURLEncoding.EncodeToString(signedToken)
}

// The token value holds, a link URL's t or a __Host-ur-link cookie, if it verifies for conn under grant, the
// endpoint's grant at now: see the file header.
func (self *tlsAudienceCheck) verifyLink(value string, conn *TlsFrontConn, grant *TlsPublishGrant, now time.Time) (*protocol.TlsLinkToken, error) {
	settings := self.front.settings
	if value == "" || grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_LINK ||
		base64.RawURLEncoding.EncodedLen(settings.LinkTokenMaxByteCount) < len(value) {
		return nil, ErrTlsLinkToken
	}
	signedBytes, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, ErrTlsLinkToken
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, ErrTlsLinkToken
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return nil, ErrTlsLinkToken
	}
	identityKey := self.front.policy.IdentityKey(signerId)
	if identityKey == nil {
		return nil, ErrTlsLinkToken
	}
	if err := bridge.VerifySigned(signed, TlsLinkPurpose, bridge.SignedType_SIGNED_TLS_LINK, bridge.SignedKeyAlgEd25519, identityKey); err != nil {
		return nil, ErrTlsLinkToken
	}
	token := &protocol.TlsLinkToken{}
	if err := proto.Unmarshal(signed.GetBody(), token); err != nil {
		return nil, ErrTlsLinkToken
	}
	expireTime := time.UnixMilli(int64(token.GetExpireTimeMillis()))
	if token.GetHost() != conn.ServerName() || !now.Before(expireTime) || len(token.GetNonce()) != tlsLinkNonceByteCount ||
		!grant.holds(token.GetGrantId()) {
		return nil, ErrTlsLinkToken
	}
	target := self.front.target
	signerGrant := self.front.policy.PublishGrantOf(signerId, token.GetGrantId(), target.Name, target.host(), now)
	if signerGrant == nil || signerGrant.Audience != protocol.AclAudience_ACL_AUDIENCE_LINK ||
		(!signerGrant.Expires.IsZero() && signerGrant.Expires.Before(expireTime)) {
		return nil, ErrTlsLinkToken
	}
	return token, nil
}

// GET /.well-known/ur/link?t=...: the token traded for __Host-ur-link, then 302 to /, under a link grant alone.
func (self *tlsHttpFront) serveLink(w http.ResponseWriter, r *http.Request, conn *TlsFrontConn) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		tlsHttpAnswer(w, http.StatusMethodNotAllowed)
		return
	}
	now := self.front.clock.Now()
	grant := self.front.audience.grant(protocol.AclAppMode_ACL_APP_MODE_HTTP, now)
	if grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_LINK {
		tlsHttpAnswer(w, http.StatusNotFound)
		return
	}
	value := r.URL.Query().Get(tlsLinkQueryParameter)
	token, err := self.front.audience.verifyLink(value, conn, grant, now)
	header := w.Header()
	header.Set("Referrer-Policy", "no-referrer")
	if err != nil {
		tlsHttpAnswer(w, http.StatusForbidden)
		return
	}
	lifetime := min(self.front.settings.LinkCookieLifetime, time.UnixMilli(int64(token.GetExpireTimeMillis())).Sub(now))
	http.SetCookie(w, &http.Cookie{
		Name:     tlsLinkCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   max(1, int(lifetime/time.Second)),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	header.Set("Cache-Control", "no-store")
	header.Set("Location", "/")
	w.WriteHeader(http.StatusFound)
}
