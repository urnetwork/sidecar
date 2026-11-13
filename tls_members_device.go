//go:build !sidecar_http && !ios_extension

// §13.7's members-device audience (R-TLS-5, D-TLS-5, I-4, owner decision 42): members' edge login, and then a §6
// Signed, SIGNED_TLS_EDGE_LOGIN under purpose edge-login, over the origin and a nonce the front issued, by a consented
// device of the member the ID token named (§8.5), which the member's app or extension has its device sign (§18's
// SignEdgeLogin over Sidecar.SignTlsEdgeLogin). The session is set only after both pass, and it names the device, whose
// standing every request checks again (tls_audience.go).
//
//	login      a navigation with no counted device session goes through §7.8's edge login as members does
//	           (tls_edge_login.go), and its callback, the ID token checked, sets no session: it seals the member, a
//	           fresh 32-byte nonce, its end and the return path into __Host-ur-device-pre (HttpOnly, Secure,
//	           SameSite=Lax, DeviceLoginLifetime), keeps the nonce pending, and answers 302 to /.well-known/ur/device
//	challenge  GET /.well-known/ur/device, that cookie counted: {"origin", "nonce"} as JSON, the nonce base64url, what
//	           the app or extension has the member's device sign
//	statement  POST /.well-known/ur/device, same-origin, its form's one field s the base64url of the Signed: it
//	           verifies under the signer's identity key in this device's config; its origin is this connection's and
//	           its nonce the cookie's; the signer is a consented device of the cookie's member, neither read_only nor
//	           suspended, and the member is still a member; only then does the nonce leave the pending set, once, so
//	           one statement completes one login, and __Host-ur-session names the member and the device; 303 to where
//	           the visitor began
//
// A statement for one origin fails at every other, so one host's login never opens another, and a nonce from an
// expired or completed login opens nothing. The front logs no statement, nonce, cookie or name (I-7, I-13). Safe for
// concurrent use.

package sidecar

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The purpose SIGNED_TLS_EDGE_LOGIN signs under (§13.7). identity_sign.go names it as a literal on legs this file is
// off.
const TlsEdgeLoginPurpose = "edge-login"

// The device step's path, its form's field and cookie, an origin's scheme, and the nonce's length, a cryptographic
// constant like the front's other random values.
const (
	tlsMembersDevicePath           = "/.well-known/ur/device"
	tlsMembersDeviceStatementField = "s"
	tlsDevicePendingCookieName     = "__Host-ur-device-pre"
	tlsEdgeLoginOriginScheme       = "https://"
	tlsEdgeLoginNonceByteCount     = 32
	tlsDevicePendingFixedByteCount = tlsEdgeLoginNonceByteCount + len(Id{}) + 8
)

var (
	// A statement that does not verify here, or an origin or nonce no front issues. It names none of the reasons.
	ErrTlsEdgeLoginStatement = errors.New("tls edge login statement refused")
	// This sidecar is not a member's consented device, so it vouches for no login (§13.7, §8.5).
	ErrTlsEdgeLoginNotConsented = fmt.Errorf("%w: only a member's consented device signs an edge login", ErrSidecarSignRefused)
)

// Whether origin is one a front issues: https://<a canonical host>, with :<port> where the port is not 443, and
// nothing else (QD-723's origins).
func tlsEdgeLoginOriginValid(origin string) bool {
	host, found := strings.CutPrefix(origin, tlsEdgeLoginOriginScheme)
	if !found {
		return false
	}
	hostname, portText, hasPort := strings.Cut(host, ":")
	if hasPort {
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 || port == tlsEdgeLoginBarePort || strconv.FormatUint(port, 10) != portText {
			return false
		}
	}
	return tlsDnsNameCanonical(hostname)
}

// A statement for the login the front issued nonce for at origin.
func NewTlsEdgeLogin(origin string, nonce []byte) (*protocol.TlsEdgeLogin, error) {
	if !tlsEdgeLoginOriginValid(origin) || len(nonce) != tlsEdgeLoginNonceByteCount {
		return nil, fmt.Errorf("%w: an origin and a nonce a front issues", ErrTlsEdgeLoginStatement)
	}
	return &protocol.TlsEdgeLogin{Origin: origin, Nonce: bytes.Clone(nonce)}, nil
}

// Signs login through sign, Sidecar.Sign's shape, and answers the Signed's encoded bytes, which the visitor posts in
// base64url as the device step's s.
func SignTlsEdgeLogin(login *protocol.TlsEdgeLogin, sign TlsKeyAttestationSignFunction) ([]byte, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(login)
	if err != nil {
		return nil, err
	}
	signed, err := sign(TlsEdgeLoginPurpose, bridge.SignedType_SIGNED_TLS_EDGE_LOGIN, body, nil)
	if err != nil {
		return nil, err
	}
	if signed.GetType() != uint32(bridge.SignedType_SIGNED_TLS_EDGE_LOGIN) || !bytes.Equal(signed.GetBody(), body) {
		return nil, fmt.Errorf("%w: sign answered another statement", ErrTlsEdgeLoginStatement)
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(signed)
}

// This device's statement for the members-device login a front issued nonce for at origin (§13.7): the encoded Signed,
// which the app or extension hands the visitor's browser to post. Only a member's consented device signs one
// (ErrTlsEdgeLoginNotConsented), so a tagged, ephemeral or parked sidecar never does, and Sign refuses it on a
// read_only device. The caller passes the origin of the page that asked, never one the page names for itself.
func (self *Sidecar) SignTlsEdgeLogin(origin string, nonce []byte) ([]byte, error) {
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	identity := self.currentIdentity()
	if identity == nil {
		return nil, ErrSidecarNoIdentity
	}
	admission := authority.Admission(identity.SidecarId)
	if admission == nil || admission.MemberId == (Id{}) || !authority.Consented(identity.SidecarId, admission.MemberId) {
		return nil, ErrTlsEdgeLoginNotConsented
	}
	login, err := NewTlsEdgeLogin(origin, nonce)
	if err != nil {
		return nil, err
	}
	return SignTlsEdgeLogin(login, self.Sign)
}

// The device whose statement value, the base64url of a Signed TlsEdgeLogin of at most maxByteCount bytes, verifies
// for the login at origin that issued nonce to memberId, under policy at now (see the file header). The nonce's single
// use is the caller's.
func tlsEdgeLoginVerify(value string, origin string, nonce []byte, memberId Id, policy TlsFrontPolicy, maxByteCount int, now time.Time) (Id, error) {
	if value == "" || base64.RawURLEncoding.EncodedLen(maxByteCount) < len(value) || len(nonce) != tlsEdgeLoginNonceByteCount {
		return Id{}, ErrTlsEdgeLoginStatement
	}
	signedBytes, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return Id{}, ErrTlsEdgeLoginStatement
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return Id{}, ErrTlsEdgeLoginStatement
	}
	signerId, err := IdFromBytes(signed.GetSignerId())
	if err != nil {
		return Id{}, ErrTlsEdgeLoginStatement
	}
	// from this device's own config: an unknown or revoked signer has no key here
	identityKey := policy.IdentityKey(signerId)
	if identityKey == nil {
		return Id{}, ErrTlsEdgeLoginStatement
	}
	if err := bridge.VerifySigned(signed, TlsEdgeLoginPurpose, bridge.SignedType_SIGNED_TLS_EDGE_LOGIN, bridge.SignedKeyAlgEd25519, identityKey); err != nil {
		return Id{}, ErrTlsEdgeLoginStatement
	}
	login := &protocol.TlsEdgeLogin{}
	if err := proto.Unmarshal(signed.GetBody(), login); err != nil {
		return Id{}, ErrTlsEdgeLoginStatement
	}
	if login.GetOrigin() != origin || subtle.ConstantTimeCompare(login.GetNonce(), nonce) != 1 {
		return Id{}, ErrTlsEdgeLoginStatement
	}
	if !policy.MemberActive(memberId, now) || !policy.DeviceConsented(signerId, memberId, now) {
		return Id{}, ErrTlsEdgeLoginStatement
	}
	return signerId, nil
}

// One pending device step, as __Host-ur-device-pre holds it.
type tlsDevicePending struct {
	nonce [tlsEdgeLoginNonceByteCount]byte
	// whom the ID token named
	memberId   Id
	expireTime time.Time
	returnPath string
}

// pending as origin's __Host-ur-device-pre value: nonce || member_id || expire ms || return path, under the pre-login
// key, the cookie's name in the additional data keeping it apart from __Host-ur-pre (tls_session.go).
func (self *tlsSessionSealer) sealDevicePending(origin string, pending *tlsDevicePending) (string, error) {
	plaintext := make([]byte, 0, tlsDevicePendingFixedByteCount+len(pending.returnPath))
	plaintext = append(plaintext, pending.nonce[:]...)
	plaintext = append(plaintext, pending.memberId.Bytes()...)
	plaintext = binary.BigEndian.AppendUint64(plaintext, uint64(pending.expireTime.UnixMilli()))
	plaintext = append(plaintext, pending.returnPath...)
	value, err := self.seal(self.preLogin, tlsDevicePendingCookieName, origin, plaintext)
	clear(plaintext)
	return value, err
}

// The pending step origin's __Host-ur-device-pre value holds while it is live at now, nil for any other value.
func (self *tlsSessionSealer) openDevicePending(value string, origin string, now time.Time) *tlsDevicePending {
	if value == "" {
		return nil
	}
	plaintext, err := self.open(self.preLogin, tlsDevicePendingCookieName, origin, value)
	if err != nil || len(plaintext) < tlsDevicePendingFixedByteCount {
		return nil
	}
	defer clear(plaintext)
	pending := &tlsDevicePending{}
	copy(pending.nonce[:], plaintext[:tlsEdgeLoginNonceByteCount])
	copy(pending.memberId[:], plaintext[tlsEdgeLoginNonceByteCount:tlsEdgeLoginNonceByteCount+len(Id{})])
	pending.expireTime = time.UnixMilli(int64(binary.BigEndian.Uint64(plaintext[tlsEdgeLoginNonceByteCount+len(Id{}) : tlsDevicePendingFixedByteCount])))
	pending.returnPath = string(plaintext[tlsDevicePendingFixedByteCount:])
	if !now.Before(pending.expireTime) {
		return nil
	}
	return pending
}

// One front's device step: the nonces of its pending device logins.
type tlsMembersDevice struct {
	front *TlsFront

	stateLock sync.Mutex
	// each pending device login's nonce, as base64url, to when it ends
	pendingNonces map[string]time.Time
}

// The device step of front.
func newTlsMembersDevice(front *TlsFront) *tlsMembersDevice {
	return &tlsMembersDevice{front: front, pendingNonces: map[string]time.Time{}}
}

// Records nonce as pending until expireTime, dropping what ended, and the oldest past PendingLoginMaxCount.
func (self *tlsMembersDevice) addPending(nonce string, expireTime time.Time, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for pendingNonce, pendingExpireTime := range self.pendingNonces {
		if !now.Before(pendingExpireTime) {
			delete(self.pendingNonces, pendingNonce)
		}
	}
	for self.front.settings.PendingLoginMaxCount <= len(self.pendingNonces) {
		oldestNonce := ""
		oldestExpireTime := time.Time{}
		for pendingNonce, pendingExpireTime := range self.pendingNonces {
			if oldestNonce == "" || pendingExpireTime.Before(oldestExpireTime) {
				oldestNonce = pendingNonce
				oldestExpireTime = pendingExpireTime
			}
		}
		delete(self.pendingNonces, oldestNonce)
	}
	self.pendingNonces[nonce] = expireTime
}

// Takes nonce out of the pending set: true once, while it is live.
func (self *tlsMembersDevice) takePending(nonce string, now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	expireTime, ok := self.pendingNonces[nonce]
	delete(self.pendingNonces, nonce)
	return ok && now.Before(expireTime)
}

// Begins the device step for memberId at origin, the edge login's callback having checked its ID token: the pending
// cookie, the nonce kept, and 302 to the step. The callback has set the answer's headers.
func (self *tlsMembersDevice) begin(w http.ResponseWriter, origin string, memberId Id, returnPath string, now time.Time) {
	settings := self.front.settings
	pending := &tlsDevicePending{memberId: memberId, expireTime: now.Add(settings.DeviceLoginLifetime), returnPath: returnPath}
	if _, err := cryptorand.Read(pending.nonce[:]); err != nil {
		tlsHttpAnswer(w, http.StatusServiceUnavailable)
		return
	}
	value, err := self.front.sessions.sealDevicePending(origin, pending)
	if err != nil {
		tlsHttpAnswer(w, http.StatusServiceUnavailable)
		return
	}
	self.addPending(base64.RawURLEncoding.EncodeToString(pending.nonce[:]), pending.expireTime, now)
	http.SetCookie(w, &http.Cookie{
		Name:     tlsDevicePendingCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(settings.DeviceLoginLifetime / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Location", tlsMembersDevicePath)
	w.WriteHeader(http.StatusFound)
}

// The device step's challenge, as GET answers it.
type tlsMembersDeviceChallenge struct {
	Origin string `json:"origin"`
	Nonce  string `json:"nonce"`
}

// /.well-known/ur/device (see the file header), under a members-device grant alone.
func (self *tlsMembersDevice) serve(w http.ResponseWriter, r *http.Request, conn *TlsFrontConn, view *tlsHttpSessionView) {
	header := w.Header()
	header.Set("Cache-Control", "no-store")
	header.Set("Referrer-Policy", "no-referrer")
	now := self.front.clock.Now()
	grant := self.front.audience.grant(protocol.AclAppMode_ACL_APP_MODE_HTTP, now)
	if grant == nil || grant.Audience != protocol.AclAudience_ACL_AUDIENCE_MEMBERS_DEVICE {
		tlsHttpAnswer(w, http.StatusNotFound)
		return
	}
	origin := tlsEdgeLoginOrigin(conn)
	pending := self.front.sessions.openDevicePending(view.devicePending, origin, now)
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if pending == nil {
			tlsHttpAnswer(w, http.StatusBadRequest)
			return
		}
		body, err := json.Marshal(&tlsMembersDeviceChallenge{Origin: origin, Nonce: base64.RawURLEncoding.EncodeToString(pending.nonce[:])})
		if err != nil {
			tlsHttpAnswer(w, http.StatusInternalServerError)
			return
		}
		header.Set("Content-Type", "application/json")
		header.Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			w.Write(body)
		}
	case http.MethodPost:
		// a front form's post: the visitor's own page, with the pending cookie it counts
		if !view.sameOrigin || pending == nil {
			tlsHttpAnswer(w, http.StatusForbidden)
			return
		}
		self.complete(w, r, conn, origin, pending, now)
	default:
		tlsHttpAnswer(w, http.StatusMethodNotAllowed)
	}
}

// POST's statement checked and the session set (see the file header).
func (self *tlsMembersDevice) complete(w http.ResponseWriter, r *http.Request, conn *TlsFrontConn, origin string, pending *tlsDevicePending, now time.Time) {
	settings := self.front.settings
	// s= and the statement's base64url, and no more
	r.Body = http.MaxBytesReader(w, r.Body, int64(len(tlsMembersDeviceStatementField)+1+base64.RawURLEncoding.EncodedLen(settings.EdgeLoginMaxByteCount)))
	if err := r.ParseForm(); err != nil {
		tlsHttpAnswer(w, http.StatusBadRequest)
		return
	}
	value := r.PostForm.Get(tlsMembersDeviceStatementField)
	nonce := base64.RawURLEncoding.EncodeToString(pending.nonce[:])
	deviceSidecarId, completed := func() (Id, bool) {
		testHookBarrier("tls.front_device.before", conn.barrierKey)
		defer testHookBarrier("tls.front_device.after", conn.barrierKey)
		deviceSidecarId, err := tlsEdgeLoginVerify(value, origin, pending.nonce[:], pending.memberId, self.front.policy, settings.EdgeLoginMaxByteCount, now)
		// the statement checked, the nonce leaves the pending set once, so a replay or a race completes nothing
		if err != nil || !self.takePending(nonce, now) {
			return Id{}, false
		}
		return deviceSidecarId, true
	}()
	if !completed {
		tlsHttpAnswer(w, http.StatusForbidden)
		return
	}
	session := &tlsSession{
		memberId:        pending.memberId,
		issueTime:       now,
		expireTime:      now.Add(settings.SessionLifetime),
		deviceSidecarId: deviceSidecarId,
	}
	if _, err := cryptorand.Read(session.sessionId[:]); err != nil {
		tlsHttpAnswer(w, http.StatusServiceUnavailable)
		return
	}
	sessionValue, err := self.front.sessions.sealSession(origin, session)
	if err != nil {
		tlsHttpAnswer(w, http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: tlsDevicePendingCookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{
		Name:     tlsSessionCookieName,
		Value:    sessionValue,
		Path:     "/",
		MaxAge:   int(settings.SessionLifetime / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	w.Header().Set("Location", pending.returnPath)
	w.WriteHeader(http.StatusSeeOther)
}
