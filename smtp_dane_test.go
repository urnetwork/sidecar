//go:build !sidecar_http

// TL1 held to RFC 7672 over MxWorld's chains: DANE-EE and DANE-TA match, PKIX usages are ignored, a
// mismatch refuses the MX, and a bogus chain or no TLSA is no authentication. The last test is the exit
// row's TLS half: an MX whose certificate no PKIX root vouches for is reached through TL1 alone.

package sidecar_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A certificate signed by issuer (self-signed when nil), for names, valid from notBefore to notAfter.
func newTestDaneCertificate(t *testing.T, name string, isCa bool, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, notBefore time.Time, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  isCa,
	}
	if isCa {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.ExtKeyUsage = nil
	} else {
		template.DNSNames = []string{name}
	}
	if issuer == nil {
		issuer, issuerKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

// testDnssecHost's MX with records, and TL1's check on the world's root and clock.
func newTestDaneWorld(t *testing.T, options *sidecartest.MxWorldZoneOptions, records ...*sidecar.SmtpTlsaRecord) (*sidecartest.MxWorld, *sidecar.SmtpDane, []byte) {
	t.Helper()
	world := newTestDnssecWorld(t, options)
	if err := world.AddMx(testDnssecHost, testDnssecAddress, nil, records...); err != nil {
		t.Fatal(err)
	}
	chain, err := world.Chain(testDnssecDomain, testDnssecHost)
	if err != nil {
		t.Fatal(err)
	}
	dane := sidecar.NewSmtpDane(testDnssecAnchors(t, world), sidecartest.NewFakeClock(testDnssecNow), nil)
	return world, dane, chain
}

func testDaneSha256(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

var (
	testDaneValidFrom = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	testDaneValidTo   = time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
)

// DANE-EE (3 1 1 and 3 0 1) matches the leaf and ignores its names and expiry (RFC 7672 §3.1.1).
func TestSmtpDaneEeMatchesTheLeafWhateverItsNameAndExpiry(t *testing.T) {
	leaf, _ := newTestDaneCertificate(t, "elsewhere.example", false, nil, nil, testDaneValidFrom, testDaneValidFrom.Add(time.Hour))
	for _, record := range []*sidecar.SmtpTlsaRecord{
		sidecartest.MxTlsaFor(leaf),
		{Usage: 3, Selector: 0, MatchingType: 1, Data: testDaneSha256(leaf.Raw)},
		{Usage: 3, Selector: 0, MatchingType: 0, Data: leaf.Raw},
	} {
		_, dane, chain := newTestDaneWorld(t, nil, record)
		result, err := dane.Authenticate(testDnssecDomain, testDnssecHost, chain, []*x509.Certificate{leaf})
		if err != nil || result.Status != sidecar.SmtpDaneStatusAuthenticated || result.MatchedUsage != 3 {
			t.Errorf("%d %d %d: %+v %v", record.Usage, record.Selector, record.MatchingType, result, err)
		}
	}
}

// DANE-TA (2 0 1) matches an issuer the MX presented, which then anchors a chain check of the leaf for
// the MX host, expiry included (RFC 7672 §3.1.2).
func TestSmtpDaneTaAnchorsTheLeafsChain(t *testing.T) {
	ca, caKey := newTestDaneCertificate(t, "Synthetic Test CA", true, nil, nil, testDaneValidFrom, testDaneValidTo)
	record := &sidecar.SmtpTlsaRecord{Usage: 2, Selector: 0, MatchingType: 1, Data: testDaneSha256(ca.Raw)}
	_, dane, chain := newTestDaneWorld(t, nil, record)
	leaf, _ := newTestDaneCertificate(t, testDnssecHost, false, ca, caKey, testDaneValidFrom, testDaneValidTo)
	result, err := dane.Authenticate(testDnssecDomain, testDnssecHost, chain, []*x509.Certificate{leaf, ca})
	if err != nil || result.Status != sidecar.SmtpDaneStatusAuthenticated || result.MatchedUsage != 2 {
		t.Errorf("%+v %v", result, err)
	}
	for name, peerChain := range map[string][]*x509.Certificate{
		"another name": {func() *x509.Certificate {
			other, _ := newTestDaneCertificate(t, "mx.other.example", false, ca, caKey, testDaneValidFrom, testDaneValidTo)
			return other
		}(), ca},
		"expired": {func() *x509.Certificate {
			expired, _ := newTestDaneCertificate(t, testDnssecHost, false, ca, caKey, testDaneValidFrom, testDaneValidFrom.Add(time.Hour))
			return expired
		}(), ca},
		"no issuer presented": {leaf},
	} {
		result, err := dane.Authenticate(testDnssecDomain, testDnssecHost, chain, peerChain)
		if !errors.Is(err, sidecar.ErrSmtpDaneMismatch) || result.Status != sidecar.SmtpDaneStatusMismatch {
			t.Errorf("%s: %+v %v", name, result, err)
		}
	}
}

// PKIX-TA (0) and PKIX-EE (1) are not SMTP's (RFC 7672 §3.1.3): records of only those usages leave
// DANE not applying, even when they match.
func TestSmtpDanePkixUsagesAreIgnored(t *testing.T) {
	leaf, _ := newTestDaneCertificate(t, testDnssecHost, false, nil, nil, testDaneValidFrom, testDaneValidTo)
	_, dane, chain := newTestDaneWorld(t, nil,
		&sidecar.SmtpTlsaRecord{Usage: 0, Selector: 0, MatchingType: 1, Data: testDaneSha256(leaf.Raw)},
		&sidecar.SmtpTlsaRecord{Usage: 1, Selector: 1, MatchingType: 1, Data: testDaneSha256(leaf.RawSubjectPublicKeyInfo)},
	)
	result, err := dane.Authenticate(testDnssecDomain, testDnssecHost, chain, []*x509.Certificate{leaf})
	if err != nil || result.Status != sidecar.SmtpDaneStatusNotApplicable || result.Dnssec != sidecar.SmtpDnssecStatusTlsa {
		t.Errorf("%+v %v", result, err)
	}
}

// A validated, usable TLSA RRset the MX's certificate does not match refuses that MX (RFC 7672 §2.2).
func TestSmtpDaneMismatchRefusesTheMx(t *testing.T) {
	leaf, _ := newTestDaneCertificate(t, testDnssecHost, false, nil, nil, testDaneValidFrom, testDaneValidTo)
	other, _ := newTestDaneCertificate(t, testDnssecHost, false, nil, nil, testDaneValidFrom, testDaneValidTo)
	_, dane, chain := newTestDaneWorld(t, nil, sidecartest.MxTlsaFor(other))
	result, err := dane.Authenticate(testDnssecDomain, testDnssecHost, chain, []*x509.Certificate{leaf})
	if !errors.Is(err, sidecar.ErrSmtpDaneMismatch) || result.Status != sidecar.SmtpDaneStatusMismatch {
		t.Errorf("%+v %v", result, err)
	}
	if result, err := dane.Authenticate(testDnssecDomain, testDnssecHost, chain, nil); !errors.Is(err, sidecar.ErrSmtpDaneMismatch) || result.Status != sidecar.SmtpDaneStatusMismatch {
		t.Errorf("no certificate: %+v %v", result, err)
	}
}

// A chain that does not validate is no authentication and no refusal: the caller tries TL2 and TL3
// under the pin rule. So is a chain proving no TLSA, an insecure one, and an empty one.
func TestSmtpDaneWithoutAProvenTlsaIsNoAuthentication(t *testing.T) {
	leaf, _ := newTestDaneCertificate(t, testDnssecHost, false, nil, nil, testDaneValidFrom, testDaneValidTo)
	for _, c := range []struct {
		name    string
		options *sidecartest.MxWorldZoneOptions
		records []*sidecar.SmtpTlsaRecord
		status  sidecar.SmtpDaneStatus
		dnssec  sidecar.SmtpDnssecStatus
	}{
		{name: "expired", options: &sidecartest.MxWorldZoneOptions{ExpiredSignatures: true}, records: []*sidecar.SmtpTlsaRecord{sidecartest.MxTlsaFor(leaf)}, status: sidecar.SmtpDaneStatusBogus},
		{name: "no tlsa", status: sidecar.SmtpDaneStatusNotApplicable, dnssec: sidecar.SmtpDnssecStatusNoTlsa},
		{name: "insecure", options: &sidecartest.MxWorldZoneOptions{Unsigned: true}, records: []*sidecar.SmtpTlsaRecord{sidecartest.MxTlsaFor(leaf)}, status: sidecar.SmtpDaneStatusNotApplicable, dnssec: sidecar.SmtpDnssecStatusInsecure},
	} {
		_, dane, chain := newTestDaneWorld(t, c.options, c.records...)
		result, err := dane.Authenticate(testDnssecDomain, testDnssecHost, chain, []*x509.Certificate{leaf})
		if err != nil || result.Status != c.status || result.Dnssec != c.dnssec {
			t.Errorf("%s: %+v %v", c.name, result, err)
		}
	}
	_, dane, _ := newTestDaneWorld(t, nil, sidecartest.MxTlsaFor(leaf))
	if result, err := dane.Authenticate(testDnssecDomain, testDnssecHost, nil, []*x509.Certificate{leaf}); err != nil || result.Status != sidecar.SmtpDaneStatusBogus {
		t.Errorf("empty chain: %+v %v", result, err)
	}
}

// Reads one SMTP reply, every line of it, and returns its last line.
func readTestDaneReply(t *testing.T, reader *bufio.Reader) string {
	t.Helper()
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if len(line) < 4 || line[3] != '-' {
			return strings.TrimRight(line, "\r\n")
		}
	}
}

// The exit row's TLS half: an MX whose self-signed certificate no PKIX root vouches for is reached
// through TL1 alone, and refused when its TLSA names another key.
func TestSmtpDaneOnlyMxIsReached(t *testing.T) {
	for _, matching := range []bool{true, false} {
		mx, err := sidecartest.NewScriptedMx(testDnssecHost, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		record := sidecartest.MxTlsaFor(mx.Certificate())
		if !matching {
			other, _ := newTestDaneCertificate(t, testDnssecHost, false, nil, nil, testDaneValidFrom, testDaneValidTo)
			record = sidecartest.MxTlsaFor(other)
		}
		world := newTestDnssecWorld(t, nil)
		if err := world.AddMx(testDnssecHost, testDnssecAddress, mx, record); err != nil {
			t.Fatal(err)
		}
		chain, err := world.Chain(testDnssecDomain, testDnssecHost)
		if err != nil {
			t.Fatal(err)
		}
		dane := sidecar.NewSmtpDane(testDnssecAnchors(t, world), sidecartest.NewFakeClock(testDnssecNow), nil)
		conn, err := world.DialMx(t.Context(), netip.MustParseAddr("192.0.2.25"), testDnssecAddress)
		if err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		readTestDaneReply(t, reader)
		conn.Write([]byte("EHLO o1.out.bringyour.example\r\n"))
		readTestDaneReply(t, reader)
		conn.Write([]byte("STARTTLS\r\n"))
		if reply := readTestDaneReply(t, reader); !strings.HasPrefix(reply, "220") {
			t.Fatalf("STARTTLS: %q", reply)
		}
		var daneResult *sidecar.SmtpDaneResult
		client := tls.Client(conn, &tls.Config{
			ServerName: testDnssecHost,
			// TL1 is the only check: no PKIX root vouches for this certificate
			InsecureSkipVerify: true,
			VerifyPeerCertificate: func(rawCertificates [][]byte, _ [][]*x509.Certificate) error {
				var peerChain []*x509.Certificate
				for _, raw := range rawCertificates {
					certificate, err := x509.ParseCertificate(raw)
					if err != nil {
						return err
					}
					peerChain = append(peerChain, certificate)
				}
				var err error
				daneResult, err = dane.Authenticate(testDnssecDomain, testDnssecHost, chain, peerChain)
				if err != nil {
					return err
				}
				if daneResult.Status != sidecar.SmtpDaneStatusAuthenticated {
					return errors.New("no tl1")
				}
				return nil
			},
		})
		err = client.Handshake()
		if matching {
			if err != nil || daneResult.Status != sidecar.SmtpDaneStatusAuthenticated {
				t.Fatalf("a DANE-only MX was not reached: %v", err)
			}
			client.Write([]byte("EHLO o1.out.bringyour.example\r\n"))
			if reply := readTestDaneReply(t, bufio.NewReader(client)); !strings.HasPrefix(reply, "250") {
				t.Errorf("EHLO inside TLS: %q", reply)
			}
			if _, err := mx.Certificate().Verify(x509.VerifyOptions{DNSName: testDnssecHost}); err == nil {
				t.Error("a PKIX root vouches for the MX, so TL1 was not alone")
			}
		} else if err == nil || !errors.Is(err, sidecar.ErrSmtpDaneMismatch) {
			t.Errorf("a mismatched MX was reached: %v", err)
		}
		client.Close()
		conn.Close()
		world.Wait()
	}
}
