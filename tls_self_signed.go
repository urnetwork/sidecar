//go:build !sidecar_http

// The certificate a device presents on its own key (§13.8, §15.5, §11.11): the chain §13 issued once TLS-M5-18's
// certificate manager installs a source that holds one for the names asked, else a self-signed leaf on the same key.
// EVS1-M2-37's https mount and §15.5's mail host take it before §13 issues anything, so both land with the key: the
// self-signed leaf is the fallback, never a second key.
//
// TlsCertificateFingerprint pins the key, not the leaf's bytes, so `ur mount` prints one value for the key's life:
// across a restart, a new self-signed leaf and the issued chain that replaces it on the same key. Its form is the pin
// git's http.pinnedPubkey and curl's --pinnedpubkey take, sha256// and the base64 of the SPKI's SHA-256.
//
// A leaf is made on the Sidecar's clock and kept in memory, answering the same leaf for the same names until it
// passes half its life. Nothing here writes a store: the leaf is cheap to make, and the key it pins is in the
// keychain. Names never reach a log or an error (I-13).
//
// Off the sidecar_http leg, as tls_key.go is.

package sidecar

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

// The prefix of a TlsCertificateFingerprint: curl's pinned public key form.
const tlsCertificateFingerprintPrefix = "sha256//"

// A self-signed leaf's serial number is this many random bytes, as RFC 5280 §4.1.2.2 allows up to 20.
const tlsSelfSignedSerialByteCount = 16

var (
	// A names list a certificate cannot carry: empty, or with an entry that is neither a DNS name, a wildcard over one,
	// nor an IP address.
	ErrTlsCertificateNames = errors.New("tls certificate names refused")
	// A certificate with no leaf to read.
	ErrTlsCertificateNoLeaf = errors.New("tls certificate has no leaf")
)

// Where Sidecar.TlsDeviceCertificate looks before it makes a self-signed leaf: TLS-M5-18's certificate manager, which
// installs itself with setTlsCertificateSource. Safe for concurrent use.
type TlsCertificateSource interface {
	// The issued chain on this device's current key whose names cover names, canonical and sorted, at now, or nil
	// when it holds none: never ordered, not yet issued, expired or revoked. A nil answer falls back to the
	// self-signed leaf, which serves local listeners only; publishing checks for an issued chain itself.
	IssuedTlsCertificate(names []string, now time.Time) *tls.Certificate
}

// What one Sidecar keeps for its device certificate: the lock that serializes the device-key record's read and
// write, the source TLS-M5-18 installs, and the self-signed leaves already made. Safe for concurrent use.
type tlsDeviceState struct {
	settings *SidecarTlsSettings
	// Held across the device-key record's read and write, so two first calls never make two keys and two rotations
	// never set two successors. A lock of its own, never stateLock, since it is held across keychain I/O.
	keyLock sync.Mutex

	stateLock sync.Mutex
	source    TlsCertificateSource
	// by tlsSelfSignedCacheKey; only the current key's leaves, each until half its life has passed
	selfSignedLeaves map[string]*tls.Certificate
}

func newTlsDeviceState(settings *SidecarTlsSettings) *tlsDeviceState {
	return &tlsDeviceState{
		settings:         settings,
		selfSignedLeaves: map[string]*tls.Certificate{},
	}
}

// Installs source; nil removes it.
func (self *tlsDeviceState) setSource(source TlsCertificateSource) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.source = source
}

// The source installed, or nil.
func (self *tlsDeviceState) installedSource() TlsCertificateSource {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.source
}

// The keys secrets holds, made at now for a network that has none.
func (self *tlsDeviceState) keys(secrets SidecarSecrets, now time.Time) (*tlsDeviceKeys, error) {
	self.keyLock.Lock()
	defer self.keyLock.Unlock()
	return loadOrCreateTlsDeviceKeys(secrets, now)
}

// Sets a pending successor for reason, or answers the one pending.
func (self *tlsDeviceState) rotate(secrets SidecarSecrets, now time.Time, reason TlsKeyRotationReason) (*tlsDeviceKeys, error) {
	self.keyLock.Lock()
	defer self.keyLock.Unlock()
	return rotateTlsDeviceKey(secrets, now, reason)
}

// Promotes the pending key whose SPKI hashes to spkiSha256.
func (self *tlsDeviceState) promote(secrets SidecarSecrets, spkiSha256 [sha256.Size]byte) (*tlsDeviceKeys, error) {
	self.keyLock.Lock()
	defer self.keyLock.Unlock()
	return promoteTlsDeviceKey(secrets, spkiSha256)
}

// The cache key of key's leaf for names.
func tlsSelfSignedCacheKey(key *TlsDeviceKey, names []string) string {
	spkiSha256 := key.SpkiSha256()
	return string(spkiSha256[:]) + "\x00" + strings.Join(names, "\x00")
}

// A self-signed leaf on key for names at now: the one made earlier while it has more than half its life left, else a
// new one. Leaves of any other key, and those past half their life, are dropped as one is added, so the map holds
// only what can still be answered.
func (self *tlsDeviceState) selfSigned(key *TlsDeviceKey, names []string, now time.Time) (*tls.Certificate, error) {
	cacheKey := tlsSelfSignedCacheKey(key, names)
	halfLife := self.settings.SelfSignedLifetime / 2
	fresh := func(leaf *tls.Certificate) bool {
		return now.Before(leaf.Leaf.NotBefore.Add(self.settings.SelfSignedBackdate + halfLife))
	}
	cached := func() *tls.Certificate {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		leaf, ok := self.selfSignedLeaves[cacheKey]
		if ok && fresh(leaf) {
			return leaf
		}
		return nil
	}()
	if cached != nil {
		return cached, nil
	}
	leaf, err := newTlsSelfSignedCertificate(key, names, now, self.settings)
	if err != nil {
		return nil, err
	}
	spkiSha256 := key.SpkiSha256()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for otherKey, otherLeaf := range self.selfSignedLeaves {
			if !strings.HasPrefix(otherKey, string(spkiSha256[:])) || !fresh(otherLeaf) {
				delete(self.selfSignedLeaves, otherKey)
			}
		}
		self.selfSignedLeaves[cacheKey] = leaf
	}()
	return leaf, nil
}

// names as a certificate carries them: each a DNS name, lowercased, a wildcard written *.x, or an IP address in its
// canonical text, sorted and each once. ErrTlsCertificateNames for an empty list or an entry that is none of those.
func tlsCertificateNames(names []string) ([]string, error) {
	canonical := []string{}
	for _, name := range names {
		if address, err := netip.ParseAddr(name); err == nil {
			if address.Zone() != "" {
				return nil, ErrTlsCertificateNames
			}
			canonical = append(canonical, address.Unmap().String())
			continue
		}
		lowered := strings.ToLower(name)
		if !tlsIdentifierCanonical(lowered) {
			return nil, ErrTlsCertificateNames
		}
		canonical = append(canonical, lowered)
	}
	if len(canonical) == 0 {
		return nil, ErrTlsCertificateNames
	}
	slices.Sort(canonical)
	return slices.Compact(canonical), nil
}

// A new self-signed leaf on key for canonical names, valid from now less the backdate for the lifetime: a server
// certificate that is no CA, signed by key itself, so a client that trusts it pins exactly this leaf.
func newTlsSelfSignedCertificate(key *TlsDeviceKey, names []string, now time.Time, settings *SidecarTlsSettings) (*tls.Certificate, error) {
	serialBytes := make([]byte, tlsSelfSignedSerialByteCount)
	if _, err := cryptorand.Read(serialBytes); err != nil {
		return nil, fmt.Errorf("no randomness for a serial: %w", err)
	}
	// clear the top bit, so the serial is positive in DER whatever the draw
	serialBytes[0] &= 0x7f
	notBefore := now.Add(-settings.SelfSignedBackdate).Truncate(time.Second)
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serialBytes),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(settings.SelfSignedBackdate + settings.SelfSignedLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, name := range names {
		if address, err := netip.ParseAddr(name); err == nil {
			template.IPAddresses = append(template.IPAddresses, net.IP(address.AsSlice()))
		} else {
			template.DNSNames = append(template.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("self-signed leaf: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("self-signed leaf: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// The pin a person compares or a client takes for certificate's key: sha256// and the base64 of its leaf's SPKI's
// SHA-256, the form git's http.pinnedPubkey and curl's --pinnedpubkey read. The same for every certificate on one
// key, so the self-signed leaf and the issued chain that replaces it print alike.
func TlsCertificateFingerprint(certificate *tls.Certificate) (string, error) {
	if certificate == nil {
		return "", ErrTlsCertificateNoLeaf
	}
	leaf := certificate.Leaf
	if leaf == nil {
		if len(certificate.Certificate) == 0 {
			return "", ErrTlsCertificateNoLeaf
		}
		parsed, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrTlsCertificateNoLeaf, err)
		}
		leaf = parsed
	}
	spkiSha256 := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return tlsCertificateFingerprintPrefix + base64.StdEncoding.EncodeToString(spkiSha256[:]), nil
}

// The tls state of this Sidecar and its network's tls namespace of keychain.ur: ErrSidecarClosed for a Sidecar that
// runs no tls, ErrSidecarNoIdentity before it is enrolled.
func (self *Sidecar) tlsDevice() (*tlsDeviceState, SidecarSecrets, error) {
	leg, ok := self.leg.(*sidecarConnectLeg)
	if !ok || leg.tls == nil || self.instance == nil {
		return nil, nil, fmt.Errorf("%w: this Sidecar runs no tls", ErrSidecarClosed)
	}
	networkId := self.enrolledNetworkId()
	if networkId == nil {
		return nil, nil, ErrSidecarNoIdentity
	}
	return leg.tls, self.instance.secrets(*networkId, tlsSecretsNamespace), nil
}

// Installs source behind TlsDeviceCertificate; nil removes it. TLS-M5-18's tls component calls this as it attaches.
func (self *Sidecar) setTlsCertificateSource(source TlsCertificateSource) error {
	state, _, err := self.tlsDevice()
	if err != nil {
		return err
	}
	state.setSource(source)
	return nil
}

// This device's current TLS key for the network, made and sealed in the keychain on the first call (§13.8). It signs
// and gives out its SPKI, and never its private half. ErrSidecarStoreLocked while the keychain is locked.
func (self *Sidecar) TlsDeviceKey() (*TlsDeviceKey, error) {
	state, secrets, err := self.tlsDevice()
	if err != nil {
		return nil, err
	}
	keys, err := state.keys(secrets, self.clock.Now())
	if err != nil {
		return nil, err
	}
	return keys.current, nil
}

// The certificate this device presents for names (§13.8, §15.5, §11.11): the chain §13 issued on its key, once
// TLS-M5-18 installs a source that holds one covering names, else a self-signed leaf on the same key for names, which
// TlsCertificateFingerprint pins. names are DNS names, wildcards over them, or IP addresses. ErrTlsCertificateNames
// for a list a certificate cannot carry, and the keychain's error while it is locked or failed.
func (self *Sidecar) TlsDeviceCertificate(names []string) (*tls.Certificate, error) {
	canonicalNames, err := tlsCertificateNames(names)
	if err != nil {
		return nil, err
	}
	state, secrets, err := self.tlsDevice()
	if err != nil {
		return nil, err
	}
	now := self.clock.Now()
	if source := state.installedSource(); source != nil {
		if certificate := source.IssuedTlsCertificate(canonicalNames, now); certificate != nil {
			return certificate, nil
		}
	}
	keys, err := state.keys(secrets, now)
	if err != nil {
		return nil, err
	}
	return state.selfSigned(keys.current, canonicalNames, now)
}
