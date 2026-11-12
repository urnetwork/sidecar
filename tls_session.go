//go:build !sidecar_http && !ios_extension

// The front's sealed cookies (§7.8, §13.7): __Host-ur-session, a members session, and __Host-ur-pre, a pending edge
// login's state, nonce and PKCE verifier. Each is XChaCha20-Poly1305 under a key derived from one 32-byte root in
// this network's keychain.ur, tls namespace (§5.9), so a session survives a daemon restart, no server ever holds a
// key that opens one, and a cookie read on another origin, another network or as the other cookie fails to open: the
// additional data binds the cookie's name, the network and the origin, https://<sni> with its port where it is not
// 443, so a session counts on its own origin alone, though cookies do not tell ports apart.
//
//	cookie   base64url, no padding, of version || nonce (24 B) || ciphertext and tag
//	session  session_id (16 B) || member_id (16 B) || issue ms (8 B) || expire ms (8 B), big endian
//	pre      state (32 B) || nonce (32 B) || PKCE verifier (32 B) || expire ms (8 B) || return path, the rest
//
// The root reaches testHookSecret where it is made and each time it is read back, each derived key where it is
// derived. Nothing here logs, and no error repeats a value (I-7, I-13). Safe for concurrent use.

package sidecar

import (
	"crypto/cipher"
	"crypto/hkdf"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// The record and the format's values.
const (
	tlsFrontSessionRootRecordName = "front-session-root"
	tlsFrontSessionRootByteCount  = 32
	tlsFrontCookieVersion         = 1
	tlsSessionKeyInfo             = "urnetwork-sidecar-v1/tls-front-session"
	tlsPreLoginKeyInfo            = "urnetwork-sidecar-v1/tls-front-pre-login"
	tlsSessionIdByteCount         = 16
	tlsPreLoginRandomByteCount    = 32
	tlsSessionPlaintextByteCount  = tlsSessionIdByteCount + len(Id{}) + 8 + 8
	tlsPreLoginFixedByteCount     = 3*tlsPreLoginRandomByteCount + 8
)

// The front's cookies, which the local service never sees (tls_http.go strips every __Host-ur- cookie).
const (
	tlsFrontCookiePrefix  = "__Host-ur-"
	tlsSessionCookieName  = "__Host-ur-session"
	tlsPreLoginCookieName = "__Host-ur-pre"
	tlsLinkCookieName     = "__Host-ur-link"
	tlsNoticeCookieName   = "__Host-ur-notice"
)

// A cookie that does not open here: malformed, sealed for another name, network or origin, or expired.
var errTlsCookie = errors.New("tls front cookie refused")

// Serializes making the root, so two fronts of one network starting at once never each write their own.
var tlsFrontSessionRootLock sync.Mutex

// One members session (§7.8): who it names, until when.
type tlsSession struct {
	sessionId  [tlsSessionIdByteCount]byte
	memberId   Id
	issueTime  time.Time
	expireTime time.Time
}

// One pending edge login: what the callback checks and where it returns.
type tlsPreLogin struct {
	state      [tlsPreLoginRandomByteCount]byte
	nonce      [tlsPreLoginRandomByteCount]byte
	verifier   [tlsPreLoginRandomByteCount]byte
	expireTime time.Time
	returnPath string
}

// The sealer of one network's front cookies.
type tlsSessionSealer struct {
	networkId Id
	session   cipher.AEAD
	preLogin  cipher.AEAD
}

// The sealer under the root secrets holds, making the root on first use. A locked or failed keychain answers its
// error, and nothing is written over what may be there (D-CORE-15).
func newTlsSessionSealer(secrets SidecarSecrets, networkId Id) (*tlsSessionSealer, error) {
	root, err := loadOrCreateTlsFrontSessionRoot(secrets)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	sessionKey, err := hkdf.Key(sha256.New, root, networkId.Bytes(), tlsSessionKeyInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(sessionKey)
	testHookSecret("tls_front_session_key", sessionKey)
	preLoginKey, err := hkdf.Key(sha256.New, root, networkId.Bytes(), tlsPreLoginKeyInfo, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	defer clear(preLoginKey)
	testHookSecret("tls_front_pre_login_key", preLoginKey)
	session, err := chacha20poly1305.NewX(sessionKey)
	if err != nil {
		return nil, err
	}
	preLogin, err := chacha20poly1305.NewX(preLoginKey)
	if err != nil {
		return nil, err
	}
	return &tlsSessionSealer{networkId: networkId, session: session, preLogin: preLogin}, nil
}

// The root the keychain holds, made and sealed there when it holds none.
func loadOrCreateTlsFrontSessionRoot(secrets SidecarSecrets) ([]byte, error) {
	tlsFrontSessionRootLock.Lock()
	defer tlsFrontSessionRootLock.Unlock()
	root, err := secrets.Get(tlsFrontSessionRootRecordName)
	if err == nil {
		if len(root) != tlsFrontSessionRootByteCount {
			clear(root)
			return nil, fmt.Errorf("%w: the front's session root does not decode", ErrSidecarStoreFailed)
		}
		testHookSecret("tls_front_session_root", root)
		return root, nil
	}
	if !errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, err
	}
	root = make([]byte, tlsFrontSessionRootByteCount)
	if _, err := cryptorand.Read(root); err != nil {
		return nil, err
	}
	testHookSecret("tls_front_session_root", root)
	if err := secrets.Put(tlsFrontSessionRootRecordName, root); err != nil {
		clear(root)
		return nil, err
	}
	return root, nil
}

// What the additional data binds: the cookie's name, the network and the origin.
func (self *tlsSessionSealer) additionalData(cookieName string, origin string) []byte {
	data := make([]byte, 0, len(cookieName)+1+len(Id{})+len(origin))
	data = append(data, cookieName...)
	data = append(data, 0)
	data = append(data, self.networkId.Bytes()...)
	return append(data, origin...)
}

// plaintext sealed under aead as cookieName's value for origin.
func (self *tlsSessionSealer) seal(aead cipher.AEAD, cookieName string, origin string, plaintext []byte) (string, error) {
	sealed := make([]byte, 1+aead.NonceSize(), 1+aead.NonceSize()+len(plaintext)+aead.Overhead())
	sealed[0] = tlsFrontCookieVersion
	if _, err := cryptorand.Read(sealed[1:]); err != nil {
		return "", err
	}
	sealed = aead.Seal(sealed, sealed[1:1+aead.NonceSize()], plaintext, self.additionalData(cookieName, origin))
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// The plaintext of cookieName's value for origin, or errTlsCookie.
func (self *tlsSessionSealer) open(aead cipher.AEAD, cookieName string, origin string, value string) ([]byte, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(sealed) < 1+aead.NonceSize()+aead.Overhead() || sealed[0] != tlsFrontCookieVersion {
		return nil, errTlsCookie
	}
	plaintext, err := aead.Open(nil, sealed[1:1+aead.NonceSize()], sealed[1+aead.NonceSize():], self.additionalData(cookieName, origin))
	if err != nil {
		return nil, errTlsCookie
	}
	return plaintext, nil
}

// session as origin's __Host-ur-session value.
func (self *tlsSessionSealer) sealSession(origin string, session *tlsSession) (string, error) {
	plaintext := make([]byte, 0, tlsSessionPlaintextByteCount)
	plaintext = append(plaintext, session.sessionId[:]...)
	plaintext = append(plaintext, session.memberId.Bytes()...)
	plaintext = binary.BigEndian.AppendUint64(plaintext, uint64(session.issueTime.UnixMilli()))
	plaintext = binary.BigEndian.AppendUint64(plaintext, uint64(session.expireTime.UnixMilli()))
	return self.seal(self.session, tlsSessionCookieName, origin, plaintext)
}

// The session origin's __Host-ur-session value holds while it is live at now, nil for any other value.
func (self *tlsSessionSealer) openSession(value string, origin string, now time.Time) *tlsSession {
	if value == "" {
		return nil
	}
	plaintext, err := self.open(self.session, tlsSessionCookieName, origin, value)
	if err != nil || len(plaintext) != tlsSessionPlaintextByteCount {
		return nil
	}
	session := &tlsSession{}
	cursor := plaintext
	copy(session.sessionId[:], cursor[:tlsSessionIdByteCount])
	cursor = cursor[tlsSessionIdByteCount:]
	copy(session.memberId[:], cursor[:len(Id{})])
	cursor = cursor[len(Id{}):]
	session.issueTime = time.UnixMilli(int64(binary.BigEndian.Uint64(cursor[:8])))
	session.expireTime = time.UnixMilli(int64(binary.BigEndian.Uint64(cursor[8:16])))
	if !now.Before(session.expireTime) {
		return nil
	}
	return session
}

// preLogin as origin's __Host-ur-pre value.
func (self *tlsSessionSealer) sealPreLogin(origin string, preLogin *tlsPreLogin) (string, error) {
	plaintext := make([]byte, 0, tlsPreLoginFixedByteCount+len(preLogin.returnPath))
	plaintext = append(plaintext, preLogin.state[:]...)
	plaintext = append(plaintext, preLogin.nonce[:]...)
	plaintext = append(plaintext, preLogin.verifier[:]...)
	plaintext = binary.BigEndian.AppendUint64(plaintext, uint64(preLogin.expireTime.UnixMilli()))
	plaintext = append(plaintext, preLogin.returnPath...)
	value, err := self.seal(self.preLogin, tlsPreLoginCookieName, origin, plaintext)
	clear(plaintext)
	return value, err
}

// The pending login origin's __Host-ur-pre value holds while it is live at now, nil for any other value.
func (self *tlsSessionSealer) openPreLogin(value string, origin string, now time.Time) *tlsPreLogin {
	if value == "" {
		return nil
	}
	plaintext, err := self.open(self.preLogin, tlsPreLoginCookieName, origin, value)
	if err != nil || len(plaintext) < tlsPreLoginFixedByteCount {
		return nil
	}
	defer clear(plaintext)
	preLogin := &tlsPreLogin{}
	copy(preLogin.state[:], plaintext[0:tlsPreLoginRandomByteCount])
	copy(preLogin.nonce[:], plaintext[tlsPreLoginRandomByteCount:2*tlsPreLoginRandomByteCount])
	copy(preLogin.verifier[:], plaintext[2*tlsPreLoginRandomByteCount:3*tlsPreLoginRandomByteCount])
	preLogin.expireTime = time.UnixMilli(int64(binary.BigEndian.Uint64(plaintext[3*tlsPreLoginRandomByteCount : tlsPreLoginFixedByteCount])))
	preLogin.returnPath = string(plaintext[tlsPreLoginFixedByteCount:])
	if !now.Before(preLogin.expireTime) {
		return nil
	}
	return preLogin
}
