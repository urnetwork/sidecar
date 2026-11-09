//go:build !sidecar_http

package sidecar

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

// A Sidecar enrolled in testNetworkId on an unlocked instance, on clock, with the connect leg's tls state and nothing
// else running: what TlsDeviceCertificate reads.
func newTlsTestSidecar(t *testing.T, clock Clock) (*Sidecar, *SidecarInstance) {
	t.Helper()
	instance, _, _, _ := newTlsTestSecrets(t)
	settings := validSidecarSettings()
	settings.Log = NewNoopLogger()
	settings.Clock = clock
	sidecar := newSidecarBase(nil, settings)
	sidecar.instance = instance
	networkId := testNetworkId
	sidecar.networkId = &networkId
	sidecar.leg = &sidecarConnectLeg{sidecar: sidecar, tls: newTlsDeviceState(settings.Tls)}
	return sidecar, instance
}

// A source holding one issued certificate for one canonical name list, recording what it was asked.
type tlsTestCertificateSource struct {
	stateLock   sync.Mutex
	names       []string
	certificate *tls.Certificate
	asked       [][]string
}

func (self *tlsTestCertificateSource) IssuedTlsCertificate(names []string, now time.Time) *tls.Certificate {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.asked = append(self.asked, slices.Clone(names))
	if slices.Equal(names, self.names) {
		return self.certificate
	}
	return nil
}

// The pin of key, as TlsCertificateFingerprint writes it.
func tlsTestPin(key *TlsDeviceKey) string {
	spkiSha256 := key.SpkiSha256()
	return "sha256//" + base64.StdEncoding.EncodeToString(spkiSha256[:])
}

// The self-signed leaf is a server certificate on the device key for exactly the names asked: its signature verifies
// under its own key, a client that trusts it verifies each name and no other, and it is no CA.
func TestTlsSelfSignedLeafVerifiesUnderItsOwnKey(t *testing.T) {
	clock := newTlsTestClock()
	sidecar, _ := newTlsTestSidecar(t, clock)
	certificate, err := sidecar.TlsDeviceCertificate([]string{"mount.example", "192.0.2.7", "*.n1.root.example", "2001:db8::7"})
	if err != nil {
		t.Fatal(err)
	}
	key, err := sidecar.TlsDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf := certificate.Leaf
	if leaf == nil || len(certificate.Certificate) != 1 {
		t.Fatal("not one parsed leaf")
	}
	if signer, ok := certificate.PrivateKey.(*TlsDeviceKey); !ok || signer.SpkiSha256() != key.SpkiSha256() {
		t.Error("the leaf is not on the device key")
	}
	if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		t.Fatalf("the leaf does not verify under its own key: %v", err)
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(key.Public()) {
		t.Fatal("the leaf names another key")
	}
	if leaf.IsCA || !leaf.BasicConstraintsValid || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Errorf("leaf ca %t, usage %v", leaf.IsCA, leaf.ExtKeyUsage)
	}
	if !slices.Equal(leaf.DNSNames, []string{"*.n1.root.example", "mount.example"}) || len(leaf.IPAddresses) != 2 {
		t.Errorf("names %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	// validity: backdated an hour, then the lifetime, on the Sidecar's clock
	if !leaf.NotBefore.Equal(clock.Now().Add(-time.Hour)) || !leaf.NotAfter.Equal(clock.Now().Add(30*24*time.Hour)) {
		t.Errorf("valid %v to %v", leaf.NotBefore, leaf.NotAfter)
	}

	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	for _, name := range []string{"mount.example", "192.0.2.7", "2001:db8::7", "web.n1.root.example"} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, CurrentTime: clock.Now()}); err != nil {
			t.Errorf("%s does not verify: %v", name, err)
		}
	}
	for _, name := range []string{"other.example", "192.0.2.8", "deep.web.n1.root.example"} {
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, CurrentTime: clock.Now()}); err == nil {
			t.Errorf("%s verifies", name)
		}
	}

	// and a TLS handshake completes on it, the client trusting only this leaf
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	serverDone := make(chan error, 1)
	go func() {
		server := tls.Server(serverConn, &tls.Config{Certificates: []tls.Certificate{*certificate}, Time: clock.Now})
		serverDone <- server.Handshake()
	}()
	client := tls.Client(clientConn, &tls.Config{ServerName: "mount.example", RootCAs: roots, Time: clock.Now})
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

// The fingerprint pins the key: the same for the same leaf, for a new leaf past half its life, and after a restart
// of the state, and it is the SPKI's SHA-256 in curl's pin form.
func TestTlsSelfSignedFingerprintIsStable(t *testing.T) {
	clock := newTlsTestClock()
	sidecar, instance := newTlsTestSidecar(t, clock)
	names := []string{"mount.example"}
	first, err := sidecar.TlsDeviceCertificate(names)
	if err != nil {
		t.Fatal(err)
	}
	key, err := sidecar.TlsDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	firstPin, err := TlsCertificateFingerprint(first)
	if err != nil {
		t.Fatal(err)
	}
	if firstPin != tlsTestPin(key) {
		t.Fatalf("pin %s, want %s", firstPin, tlsTestPin(key))
	}

	clock.advance(time.Hour)
	second, err := sidecar.TlsDeviceCertificate(names)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Error("a second call inside half the lifetime made a new leaf")
	}

	// past half the lifetime: a new leaf, new bytes, the same pin
	clock.advance(15 * 24 * time.Hour)
	third, err := sidecar.TlsDeviceCertificate(names)
	if err != nil {
		t.Fatal(err)
	}
	if third == first || slices.Equal(third.Certificate[0], first.Certificate[0]) {
		t.Fatal("no new leaf past half the lifetime")
	}
	if !third.Leaf.NotBefore.After(first.Leaf.NotBefore) {
		t.Error("the new leaf starts no later")
	}
	thirdPin, err := TlsCertificateFingerprint(third)
	if err != nil {
		t.Fatal(err)
	}
	if thirdPin != firstPin {
		t.Error("a new leaf on the same key changed the pin")
	}

	// a parsed chain without Leaf set answers the same
	unparsed := &tls.Certificate{Certificate: third.Certificate, PrivateKey: third.PrivateKey}
	if pin, err := TlsCertificateFingerprint(unparsed); err != nil || pin != firstPin {
		t.Errorf("pin from DER %s, %v", pin, err)
	}

	// a restart: a new Sidecar's state on the same keychain answers the same pin
	restarted := newSidecarBase(nil, sidecar.settings)
	restarted.instance = instance
	restarted.networkId = sidecar.networkId
	restarted.leg = &sidecarConnectLeg{sidecar: restarted, tls: newTlsDeviceState(sidecar.settings.Tls)}
	afterRestart, err := restarted.TlsDeviceCertificate(names)
	if err != nil {
		t.Fatal(err)
	}
	if pin, _ := TlsCertificateFingerprint(afterRestart); pin != firstPin {
		t.Error("the pin changed across a restart")
	}

	for _, broken := range []*tls.Certificate{nil, {}, {Certificate: [][]byte{[]byte("synthetic not der")}}} {
		if _, err := TlsCertificateFingerprint(broken); !errors.Is(err, ErrTlsCertificateNoLeaf) {
			t.Errorf("a certificate with no leaf: %v", err)
		}
	}
}

// Names reach the leaf in one canonical form: lowercase, each once, in order, an IPv4-mapped address as IPv4. The
// same set however it is written answers the same leaf.
func TestTlsDeviceCertificateNamesAreCanonical(t *testing.T) {
	sidecar, _ := newTlsTestSidecar(t, newTlsTestClock())
	first, err := sidecar.TlsDeviceCertificate([]string{"B.Example", "*.Net.Example", "b.example", "::ffff:192.0.2.9"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := sidecar.TlsDeviceCertificate([]string{"192.0.2.9", "*.net.example", "b.example"})
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("one set written two ways made two leaves")
	}
	if !slices.Equal(first.Leaf.DNSNames, []string{"*.net.example", "b.example"}) || len(first.Leaf.IPAddresses) != 1 ||
		!first.Leaf.IPAddresses[0].Equal(net.ParseIP("192.0.2.9")) {
		t.Errorf("names %v %v", first.Leaf.DNSNames, first.Leaf.IPAddresses)
	}
	other, err := sidecar.TlsDeviceCertificate([]string{"b.example"})
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Error("another set answered the same leaf")
	}
}

// A list a certificate cannot carry is refused before anything reads the keychain.
func TestTlsDeviceCertificateRefusesNamesItCannotCarry(t *testing.T) {
	sidecar, _ := newTlsTestSidecar(t, newTlsTestClock())
	for _, names := range [][]string{
		nil,
		{},
		{""},
		{"under_score.example"},
		{"-dash.example"},
		{"trailing.example."},
		{"a..example"},
		{"*.*.example"},
		{"sub.*.example"},
		{"fe80::1%eth0"},
		{"mount.example", "bad name"},
	} {
		if _, err := sidecar.TlsDeviceCertificate(names); !errors.Is(err, ErrTlsCertificateNames) {
			t.Errorf("%q: %v", names, err)
		}
	}
}

// An issued chain from the installed source wins; with none for the names, or no source, the self-signed leaf on the
// same key answers, so a revoked or missing chain still serves local listeners.
func TestTlsDeviceCertificatePrefersTheInstalledSource(t *testing.T) {
	clock := newTlsTestClock()
	sidecar, _ := newTlsTestSidecar(t, clock)
	selfSigned, err := sidecar.TlsDeviceCertificate([]string{"web.n1.root.example"})
	if err != nil {
		t.Fatal(err)
	}
	issued := &tls.Certificate{Certificate: [][]byte{[]byte("synthetic issued chain")}}
	source := &tlsTestCertificateSource{names: []string{"*.n1.root.example", "n1.root.example"}, certificate: issued}
	if err := sidecar.setTlsCertificateSource(source); err != nil {
		t.Fatal(err)
	}
	got, err := sidecar.TlsDeviceCertificate([]string{"N1.root.example", "*.n1.root.example"})
	if err != nil {
		t.Fatal(err)
	}
	if got != issued {
		t.Error("the issued chain did not answer")
	}
	if asked := source.asked[len(source.asked)-1]; !slices.Equal(asked, []string{"*.n1.root.example", "n1.root.example"}) {
		t.Errorf("the source was asked %v", asked)
	}
	fallback, err := sidecar.TlsDeviceCertificate([]string{"web.n1.root.example"})
	if err != nil {
		t.Fatal(err)
	}
	if fallback != selfSigned {
		t.Error("with no issued chain for the names, the self-signed leaf did not answer")
	}
	if err := sidecar.setTlsCertificateSource(nil); err != nil {
		t.Fatal(err)
	}
	removed, err := sidecar.TlsDeviceCertificate([]string{"*.n1.root.example", "n1.root.example"})
	if err != nil {
		t.Fatal(err)
	}
	if removed == issued || removed.Leaf == nil {
		t.Error("a removed source still answered")
	}
}

// After a promotion the self-signed leaf moves to the new key, and the pin with it.
func TestTlsSelfSignedLeafFollowsAPromotedKey(t *testing.T) {
	clock := newTlsTestClock()
	sidecar, _ := newTlsTestSidecar(t, clock)
	before, err := sidecar.TlsDeviceCertificate([]string{"mount.example"})
	if err != nil {
		t.Fatal(err)
	}
	state, secrets, err := sidecar.tlsDevice()
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := state.rotate(secrets, clock.Now(), TlsKeyRotationRequest)
	if err != nil {
		t.Fatal(err)
	}
	// still the old key until the successor's certificate installs
	during, err := sidecar.TlsDeviceCertificate([]string{"mount.example"})
	if err != nil {
		t.Fatal(err)
	}
	if during != before {
		t.Error("a pending rotation changed what serves")
	}
	if _, err := state.promote(secrets, rotated.pending.SpkiSha256()); err != nil {
		t.Fatal(err)
	}
	after, err := sidecar.TlsDeviceCertificate([]string{"mount.example"})
	if err != nil {
		t.Fatal(err)
	}
	if pin, _ := TlsCertificateFingerprint(after); pin != tlsTestPin(rotated.pending) {
		t.Error("the leaf is not on the promoted key")
	}
	if after.PrivateKey.(*TlsDeviceKey).SpkiSha256() != rotated.pending.SpkiSha256() {
		t.Error("the leaf signs with another key")
	}
}

// Before enrollment there is no network, so no key; a Sidecar with no tls state runs no tls; a locked keychain
// answers locked.
func TestTlsDeviceCertificateNeedsAnOpenEnrolledNetwork(t *testing.T) {
	sidecar, instance := newTlsTestSidecar(t, newTlsTestClock())
	sidecar.networkId = nil
	if _, err := sidecar.TlsDeviceCertificate([]string{"mount.example"}); !errors.Is(err, ErrSidecarNoIdentity) {
		t.Errorf("unenrolled: %v", err)
	}
	if _, err := sidecar.TlsDeviceKey(); !errors.Is(err, ErrSidecarNoIdentity) {
		t.Errorf("unenrolled key: %v", err)
	}
	networkId := testNetworkId
	sidecar.networkId = &networkId

	instance.Lock()
	if _, err := sidecar.TlsDeviceCertificate([]string{"mount.example"}); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Errorf("locked: %v", err)
	}

	bare := newTestSidecar(t)
	if _, err := bare.TlsDeviceCertificate([]string{"mount.example"}); !errors.Is(err, ErrSidecarClosed) {
		t.Errorf("no tls state: %v", err)
	}
	if err := bare.setTlsCertificateSource(&tlsTestCertificateSource{}); !errors.Is(err, ErrSidecarClosed) {
		t.Errorf("no tls state, source: %v", err)
	}
}

// The cache keeps only the current key's leaves that can still be answered.
func TestTlsSelfSignedCacheDropsWhatCanNoLongerAnswer(t *testing.T) {
	clock := newTlsTestClock()
	sidecar, _ := newTlsTestSidecar(t, clock)
	state, secrets, err := sidecar.tlsDevice()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.example", "b.example", "c.example"} {
		if _, err := sidecar.TlsDeviceCertificate([]string{name}); err != nil {
			t.Fatal(err)
		}
	}
	rotated, err := state.rotate(secrets, clock.Now(), TlsKeyRotationRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.promote(secrets, rotated.pending.SpkiSha256()); err != nil {
		t.Fatal(err)
	}
	if _, err := sidecar.TlsDeviceCertificate([]string{"d.example"}); err != nil {
		t.Fatal(err)
	}
	cacheCount := func() int {
		state.stateLock.Lock()
		defer state.stateLock.Unlock()
		return len(state.selfSignedLeaves)
	}
	if count := cacheCount(); count != 1 {
		t.Errorf("%d leaves cached after a promotion, want the new key's one", count)
	}
	if _, err := sidecar.TlsDeviceCertificate([]string{"e.example"}); err != nil {
		t.Fatal(err)
	}
	clock.advance(16 * 24 * time.Hour)
	if _, err := sidecar.TlsDeviceCertificate([]string{"f.example"}); err != nil {
		t.Fatal(err)
	}
	if count := cacheCount(); count != 1 {
		t.Errorf("%d leaves cached past half their life, want the fresh one", count)
	}
}
