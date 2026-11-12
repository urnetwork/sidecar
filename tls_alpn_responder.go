//go:build !sidecar_http && !ios_extension

// RFC 8737's TLS-ALPN-01 responder (§13.7's dispatch row, §13.8): a hello offering acme-tls/1 reaches only this,
// whatever else it offers. For a server name with a pending challenge it answers that challenge's self-signed
// certificate, whose one dNSName is the name and whose critical acmeIdentifier extension holds the SHA-256 of the key
// authorization, negotiates acme-tls/1 and closes: the validator reads the certificate and nothing else moves, so no
// byte reaches the local service. With no pending challenge the handshake fails.
//
// A challenge's certificate is on a P-256 key of its own, made when the challenge is set and dropped with it, never
// the device key: it proves control of the name to the CA and is worth nothing after. While any challenge is
// pending the registration lists acme-tls/1 (TlsFront.ListenSettings), and the owner hears each change of that
// through the front's AlpnChanged. Safe for concurrent use.

package sidecar

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// A challenge certificate's serial is this many random bytes, as RFC 5280 §4.1.2.2 allows up to 20.
const tlsAlpnSerialByteCount = 16

// A challenge that cannot be answered: no key authorization, or an expiry already past.
var errTlsAlpnChallenge = errors.New("tls-alpn-01 challenge refused")

// id-pe-acmeIdentifier (RFC 8737 §6.1), 1.3.6.1.5.5.7.1.31.
func tlsAcmeIdentifierOid() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}
}

// One pending challenge.
type tlsAlpnChallenge struct {
	certificate *tls.Certificate
	expireTime  time.Time
}

// One front's pending challenges, by server name.
type tlsAlpnResponder struct {
	clock    Clock
	settings *TlsFrontSettings
	// called, without the lock, when the set moves between empty and not
	changed func()

	stateLock  sync.Mutex
	challenges map[string]*tlsAlpnChallenge
}

// A responder with nothing pending.
func newTlsAlpnResponder(clock Clock, settings *TlsFrontSettings, changed func()) *tlsAlpnResponder {
	return &tlsAlpnResponder{
		clock:      clock,
		settings:   settings,
		changed:    changed,
		challenges: map[string]*tlsAlpnChallenge{},
	}
}

// Sets serverName's challenge until expireTime, replacing one already pending.
func (self *tlsAlpnResponder) set(serverName string, keyAuthorization string, expireTime time.Time) error {
	now := self.clock.Now()
	if keyAuthorization == "" || !now.Before(expireTime) {
		return errTlsAlpnChallenge
	}
	certificate, err := newTlsAlpnCertificate(serverName, keyAuthorization, now, expireTime, self.settings.ChallengeBackdate)
	if err != nil {
		return err
	}
	wasEmpty := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.dropExpiredWithLock(now)
		wasEmpty := len(self.challenges) == 0
		self.challenges[serverName] = &tlsAlpnChallenge{certificate: certificate, expireTime: expireTime}
		return wasEmpty
	}()
	if wasEmpty {
		self.changed()
	}
	return nil
}

// Ends serverName's challenge, if one is pending.
func (self *tlsAlpnResponder) clear(serverName string) {
	nowEmpty := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if _, ok := self.challenges[serverName]; !ok {
			return false
		}
		delete(self.challenges, serverName)
		return len(self.challenges) == 0
	}()
	if nowEmpty {
		self.changed()
	}
}

// The certificate answering serverName's challenge at now, nil when none is pending.
func (self *tlsAlpnResponder) certificate(serverName string, now time.Time) *tls.Certificate {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dropExpiredWithLock(now)
	challenge := self.challenges[serverName]
	if challenge == nil {
		return nil
	}
	return challenge.certificate
}

// Whether any challenge is pending at now.
func (self *tlsAlpnResponder) pending(now time.Time) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.dropExpiredWithLock(now)
	return 0 < len(self.challenges)
}

// Drops what expired by now. An expiry that empties the set tells nobody: the registration keeps acme-tls/1 until
// its owner registers again, which costs at most a handshake that fails.
func (self *tlsAlpnResponder) dropExpiredWithLock(now time.Time) {
	for serverName, challenge := range self.challenges {
		if !now.Before(challenge.expireTime) {
			delete(self.challenges, serverName)
		}
	}
}

// RFC 8737 §3's certificate for serverName: self-signed on a key of its own, its one dNSName serverName, and a
// critical acmeIdentifier extension holding SHA-256(keyAuthorization) as an OCTET STRING, valid from backdate before
// now to expireTime.
func newTlsAlpnCertificate(serverName string, keyAuthorization string, now time.Time, expireTime time.Time, backdate time.Duration) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		return nil, fmt.Errorf("a challenge key: %w", err)
	}
	scalar, err := key.Bytes()
	if err != nil {
		return nil, fmt.Errorf("a challenge key: %w", err)
	}
	testHookSecret("tls_alpn_challenge_key", scalar)
	clear(scalar)
	digest := sha256.Sum256([]byte(keyAuthorization))
	extensionValue, err := asn1.Marshal(digest[:])
	if err != nil {
		return nil, err
	}
	serialBytes := make([]byte, tlsAlpnSerialByteCount)
	if _, err := cryptorand.Read(serialBytes); err != nil {
		return nil, fmt.Errorf("no randomness for a serial: %w", err)
	}
	// clear the top bit, so the serial is positive in DER whatever the draw
	serialBytes[0] &= 0x7f
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serialBytes),
		NotBefore:             now.Add(-backdate).Truncate(time.Second),
		NotAfter:              expireTime,
		DNSNames:              []string{serverName},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions: []pkix.Extension{
			{Id: tlsAcmeIdentifierOid(), Critical: true, Value: extensionValue},
		},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("a challenge certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
