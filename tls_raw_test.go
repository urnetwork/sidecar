//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A raw fixture: tls/443/app forwarding mqtt or no ALPN to an echoing backend under grant's audience.
func newTlsRawFixture(t *testing.T, audience protocol.AclAudience, pin []byte, configure func(fixture *tlsFrontFixture)) *tlsFrontFixture {
	t.Helper()
	return newTlsFrontFixture(t, func(fixture *tlsFrontFixture) {
		fixture.target.AppMode = "raw"
		fixture.target.Alpn = []string{"mqtt"}
		fixture.backend = newTlsFrontTestBackend(false)
		fixture.policy.setGrant(audience, protocol.AclAppMode_ACL_APP_MODE_RAW, pin)
		if configure != nil {
			configure(fixture)
		}
	})
}

// A client certificate on a key of its own, and its SPKI's SHA-256, a link grant's pin.
func tlsRawTestClientCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "guest"},
		NotBefore:    time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(cryptorand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pin[:]
}

// Writes message and reads its echo back, or the error that ended the read.
func tlsRawTestEcho(conn *tls.Conn, message string) (string, error) {
	if _, err := io.WriteString(conn, message); err != nil {
		return "", err
	}
	echo := make([]byte, len(message))
	conn.SetReadDeadline(time.Now().Add(tlsFrontTestGuard))
	_, err := io.ReadFull(conn, echo)
	return string(echo), err
}

// §13.7's raw row under public: the declared id or none forwards decrypted bytes both ways, and an undeclared id fails
// the handshake with no_application_protocol.
func TestTlsRawPublicForwards(t *testing.T) {
	fixture := newTlsRawFixture(t, protocol.AclAudience_ACL_AUDIENCE_PUBLIC, nil, nil)
	for _, offered := range [][]string{nil, {"mqtt"}, {"amqp", "mqtt"}} {
		conn, err := fixture.dialTls(tlsFrontTestClientConfig(offered...), nil)
		if err != nil {
			t.Fatalf("%v: %v", offered, err)
		}
		if echo, err := tlsRawTestEcho(conn, "hello"); err != nil || echo != "hello" {
			t.Errorf("%v: %q %v", offered, echo, err)
		}
	}
	if _, err := fixture.dialTls(tlsFrontTestClientConfig("amqp"), nil); !tlsFrontTestAlert(err, "no application protocol") {
		t.Errorf("an undeclared id: %v", err)
	}
	if _, err := fixture.dialTls(tlsFrontTestClientConfig(tlsAlpnHttp11), nil); !tlsFrontTestAlert(err, "no application protocol") {
		t.Errorf("http/1.1 on raw: %v", err)
	}
}

// §13.7's raw link: a client certificate whose SPKI SHA-256 is the grant's pin, over TLS 1.3, forwards; a wrong pin,
// no certificate and TLS 1.2 are refused, and the backend is never dialed for them.
func TestTlsRawLinkNeedsThePinnedCertificate(t *testing.T) {
	certificate, pin := tlsRawTestClientCertificate(t)
	other, _ := tlsRawTestClientCertificate(t)
	fixture := newTlsRawFixture(t, protocol.AclAudience_ACL_AUDIENCE_LINK, pin, nil)

	refused := func(name string, config *tls.Config) {
		conn, err := fixture.dialTls(config, nil)
		if err != nil {
			return
		}
		// TLS 1.3 finishes the client's side before the server reads its certificate, so the refusal is the first read
		if echo, err := tlsRawTestEcho(conn, "hello"); err == nil {
			t.Errorf("%s: forwarded %q", name, echo)
		}
	}
	wrongPin := tlsFrontTestClientConfig()
	wrongPin.Certificates = []tls.Certificate{other}
	refused("a wrong pin", wrongPin)
	refused("no certificate", tlsFrontTestClientConfig())
	oldVersion := tlsFrontTestClientConfig()
	oldVersion.Certificates = []tls.Certificate{certificate}
	oldVersion.MaxVersion = tls.VersionTLS12
	refused("TLS 1.2", oldVersion)
	if dials, byteCount := fixture.backend.counts(); dials != 0 || byteCount != 0 {
		t.Fatalf("%d dials, %d bytes before the pin held", dials, byteCount)
	}

	pinned := tlsFrontTestClientConfig("mqtt")
	pinned.Certificates = []tls.Certificate{certificate}
	conn, err := fixture.dialTls(pinned, nil)
	if err != nil {
		t.Fatal(err)
	}
	if echo, err := tlsRawTestEcho(conn, "hello"); err != nil || echo != "hello" {
		t.Errorf("the pinned certificate: %q %v", echo, err)
	}
}

// A grant revoked between the handshake's read of it and the forward stops the forward: the audience check reads the
// grant again.
func TestTlsRawChecksTheGrantAfterTheHandshake(t *testing.T) {
	var fixture *tlsFrontFixture
	fixture = newTlsRawFixture(t, protocol.AclAudience_ACL_AUDIENCE_PUBLIC, nil, func(configured *tlsFrontFixture) {
		configured.onCertificate = func() {
			configured.policy.stateLock.Lock()
			defer configured.policy.stateLock.Unlock()
			configured.policy.grant = nil
		}
	})
	conn, err := fixture.dialTls(tlsFrontTestClientConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if echo, err := tlsRawTestEcho(conn, "hello"); err == nil {
		t.Errorf("forwarded %q after the grant went", echo)
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}

// --proxy-protocol on raw: the backend reads a PROXY v2 header carrying the visitor's address before any byte.
func TestTlsRawSendsProxyV2OnRequest(t *testing.T) {
	fixture := newTlsRawFixture(t, protocol.AclAudience_ACL_AUDIENCE_PUBLIC, nil, func(fixture *tlsFrontFixture) {
		fixture.target.ProxyProtocol = true
	})
	conn, err := fixture.dialTls(tlsFrontTestClientConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "x"); err != nil {
		t.Fatal(err)
	}
	var first []byte
	select {
	case first = <-fixture.backend.firstReads:
	case <-time.After(tlsFrontTestGuard):
		t.Fatal("the backend read nothing")
	}
	header := tlsProxyV2Header(tlsFrontTestVisitor(), 443)
	if len(first) < len(header) || string(first[:len(header)]) != string(header) {
		t.Fatalf("the backend read %x first", first)
	}
}

// PROXY v2's bytes for each family: signature, version and command, family, length, addresses, ports.
func TestTlsProxyV2Header(t *testing.T) {
	ipv4 := tlsProxyV2Header(netip.MustParseAddrPort("192.0.2.9:40000"), 443)
	want4 := append([]byte(tlsProxyV2Signature), 0x21, 0x11, 0, 12, 192, 0, 2, 9, 0, 0, 0, 0)
	want4 = binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(want4, 40000), 443)
	if string(ipv4) != string(want4) {
		t.Errorf("ipv4: %x", ipv4)
	}
	mapped := tlsProxyV2Header(netip.MustParseAddrPort("[::ffff:192.0.2.9]:40000"), 443)
	if string(mapped) != string(want4) {
		t.Errorf("an IPv4-mapped address: %x", mapped)
	}
	ipv6 := tlsProxyV2Header(netip.MustParseAddrPort("[2001:db8::7]:40000"), 8443)
	if len(ipv6) != len(tlsProxyV2Signature)+4+36 || ipv6[13] != 0x21 || binary.BigEndian.Uint16(ipv6[14:16]) != 36 {
		t.Errorf("ipv6: %x", ipv6)
	}
	if source := netip.AddrFrom16([16]byte(ipv6[16:32])); source != netip.MustParseAddr("2001:db8::7") {
		t.Errorf("ipv6 source %s", source)
	}
	if binary.BigEndian.Uint16(ipv6[48:50]) != 40000 || binary.BigEndian.Uint16(ipv6[50:52]) != 8443 {
		t.Errorf("ipv6 ports %x", ipv6[48:52])
	}
}
