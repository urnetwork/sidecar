//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"slices"
	"testing"
	"time"
)

// RFC 8737 §3 as a validator reads it: acme-tls/1 negotiated, one dNSName, the name, and a critical acmeIdentifier
// holding SHA-256 of the key authorization; the backend never dialed.
func TestTlsAlpnResponderAnswersAPendingChallenge(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	keyAuthorization := "token-synthetic.thumbprint-synthetic"
	if err := fixture.front.SetAlpnChallenge(tlsFrontTestServerName, keyAuthorization, fixture.clock.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, offered := range [][]string{{tlsAlpnAcme}, {tlsAlpnH2, tlsAlpnAcme}} {
		conn, err := fixture.dialTls(tlsFrontTestClientConfig(offered...), nil)
		if err != nil {
			t.Fatalf("%v: %v", offered, err)
		}
		state := conn.ConnectionState()
		if state.NegotiatedProtocol != tlsAlpnAcme || len(state.PeerCertificates) != 1 {
			t.Fatalf("%v: %s, %d certificates", offered, state.NegotiatedProtocol, len(state.PeerCertificates))
		}
		leaf := state.PeerCertificates[0]
		if !slices.Equal(leaf.DNSNames, []string{tlsFrontTestServerName}) {
			t.Errorf("names %v", leaf.DNSNames)
		}
		digest := sha256.Sum256([]byte(keyAuthorization))
		found := false
		for _, extension := range leaf.Extensions {
			if !extension.Id.Equal(tlsAcmeIdentifierOid()) {
				continue
			}
			found = true
			var value []byte
			if rest, err := asn1.Unmarshal(extension.Value, &value); err != nil || len(rest) != 0 || string(value) != string(digest[:]) {
				t.Errorf("acmeIdentifier %x: %v", extension.Value, err)
			}
			if !extension.Critical {
				t.Error("acmeIdentifier is not critical")
			}
		}
		if !found {
			t.Error("no acmeIdentifier")
		}
		if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
			t.Errorf("not self-signed: %v", err)
		}
		if leaf.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("key %s", leaf.PublicKeyAlgorithm)
		}
	}
	if dials, _ := fixture.backend.counts(); dials != 0 {
		t.Errorf("%d dials", dials)
	}
}

// With no pending challenge acme-tls/1 fails the handshake, whatever else is offered.
func TestTlsAlpnResponderWithoutAChallengeFails(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	for _, offered := range [][]string{{tlsAlpnAcme}, {tlsAlpnHttp11, tlsAlpnAcme}} {
		if _, err := fixture.dialTls(tlsFrontTestClientConfig(offered...), nil); err == nil {
			t.Errorf("%v completed", offered)
		}
	}
}

// A challenge ends at its expiry and at ClearAlpnChallenge, and while one is pending the registration lists
// acme-tls/1, its owner hearing each change between none and some.
func TestTlsAlpnChallengeChangesTheRegistration(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	if slices.Contains(fixture.front.ListenSettings().Alpn, tlsAlpnAcme) {
		t.Fatal("acme-tls/1 listed with nothing pending")
	}
	expireTime := fixture.clock.Now().Add(time.Hour)
	if err := fixture.front.SetAlpnChallenge(tlsFrontTestServerName, "token.thumbprint", expireTime); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fixture.alpnChanges:
	default:
		t.Fatal("no change told")
	}
	if !slices.Contains(fixture.front.ListenSettings().Alpn, tlsAlpnAcme) {
		t.Error("acme-tls/1 not listed while pending")
	}
	fixture.front.ClearAlpnChallenge(tlsFrontTestServerName)
	select {
	case <-fixture.alpnChanges:
	default:
		t.Fatal("no change told at the clear")
	}
	if slices.Contains(fixture.front.ListenSettings().Alpn, tlsAlpnAcme) {
		t.Error("acme-tls/1 listed after the clear")
	}
	if err := fixture.front.SetAlpnChallenge(tlsFrontTestServerName, "token.thumbprint", expireTime); err != nil {
		t.Fatal(err)
	}
	fixture.clock.advance(time.Hour)
	if fixture.front.responder.certificate(tlsFrontTestServerName, fixture.clock.Now()) != nil {
		t.Error("a challenge answered past its expiry")
	}
}

// A challenge for a name the endpoint does not serve, with no key authorization, or already expired is refused.
func TestTlsAlpnChallengeRefusals(t *testing.T) {
	fixture := newTlsFrontFixture(t, nil)
	now := fixture.clock.Now()
	if err := fixture.front.SetAlpnChallenge(tlsFrontTestOtherName, "token.thumbprint", now.Add(time.Hour)); err == nil {
		t.Error("a name the endpoint does not serve")
	}
	if err := fixture.front.SetAlpnChallenge(tlsFrontTestServerName, "", now.Add(time.Hour)); err == nil {
		t.Error("no key authorization")
	}
	if err := fixture.front.SetAlpnChallenge(tlsFrontTestServerName, "token.thumbprint", now); err == nil {
		t.Error("an expiry already past")
	}
}
