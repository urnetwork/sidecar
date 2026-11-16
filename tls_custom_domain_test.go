//go:build !sidecar_http && !ios_extension

// The ordering desktop's pure parts (TLS-M6-05; DESIGN-DETAILS 17.2.3, 17.2.7): RFC 7638's thumbprint, the key
// file's format and the check that picks its key against the account row, a dead order by its status, and the
// chain check of step 6. The orderer's passes run against the real store in server's schedule tests. Names are under
// .example, keys generated.

package sidecar

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

func TestTlsCustomKeyThumbprintIsRfc7638s(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	coordinate := func(value *big.Int) string {
		bytes := make([]byte, 32)
		value.FillBytes(bytes)
		return base64.RawURLEncoding.EncodeToString(bytes)
	}
	// the required members, lexicographic, no whitespace (RFC 7638 §3.2, §3.3's EC example's shape)
	want := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + coordinate(key.X) + `","y":"` + coordinate(key.Y) + `"}`))
	if got := TlsCustomKeyThumbprint(&key.PublicKey); string(got) != string(want[:]) {
		t.Fatalf("%x, want %x", got, want)
	}
}

func TestTlsCustomKeyFilePicksTheRowsKey(t *testing.T) {
	currentDer, err := NewTlsCustomAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	nextDer, err := NewTlsCustomAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	current, _ := tlsCustomParseKey(currentDer)
	next, _ := tlsCustomParseKey(nextDer)
	file := &TlsCustomKeyFile{Format: 1, Domain: "customer.example", Ca: "letsencrypt", KeySeq: 3, Key: currentDer, ShrunkAt: 7}
	data, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTlsCustomKeyFile(data, "customer.example")
	if err != nil {
		t.Fatal(err)
	}
	account := &TlsCustomAccount{Domain: "customer.example", KeySeq: 3, KeyThumbprint: TlsCustomKeyThumbprint(&current.PublicKey)}
	if key, keySeq := parsed.KeyFor(account); key == nil || keySeq != 3 {
		t.Fatalf("the row's key: %v, %d", key, keySeq)
	}
	// a row at another sequence or thumbprint takes nothing from the file
	for _, other := range []*TlsCustomAccount{
		{Domain: "customer.example", KeySeq: 4, KeyThumbprint: TlsCustomKeyThumbprint(&current.PublicKey)},
		{Domain: "customer.example", KeySeq: 3, KeyThumbprint: TlsCustomKeyThumbprint(&next.PublicKey)},
	} {
		if key, _ := parsed.KeyFor(other); key != nil {
			t.Errorf("a key for %+v", other)
		}
	}
	// the file at s + 1 and the row at s with that key as next: R7 is owed and the file passes
	advanced := &TlsCustomKeyFile{Format: 1, Domain: "customer.example", KeySeq: 4, Key: nextDer}
	owed := &TlsCustomAccount{Domain: "customer.example", KeySeq: 3, KeyThumbprint: TlsCustomKeyThumbprint(&current.PublicKey), NextKeyThumbprint: TlsCustomKeyThumbprint(&next.PublicKey)}
	if key, keySeq := advanced.KeyFor(owed); key == nil || keySeq != 4 {
		t.Fatalf("an owed R7: %v, %d", key, keySeq)
	}
	// refused: another domain, another format, a next that is not the one after
	for _, bad := range []*TlsCustomKeyFile{
		{Format: 1, Domain: "other.example", KeySeq: 3, Key: currentDer},
		{Format: 2, Domain: "customer.example", KeySeq: 3, Key: currentDer},
		{Format: 1, Domain: "customer.example", KeySeq: 3, Key: currentDer, Next: &TlsCustomKeyFileNext{KeySeq: 5, Key: nextDer}},
		{Format: 1, Domain: "customer.example", KeySeq: 3, Key: []byte{1, 2, 3}},
	} {
		data, _ := bad.Marshal()
		if _, err := ParseTlsCustomKeyFile(data, "customer.example"); err == nil {
			t.Errorf("a key file passed: %+v", bad)
		}
	}
	if TlsCustomKeyFilePath("customer.example") != "tls/acme/customer.example.json" {
		t.Errorf("path %s", TlsCustomKeyFilePath("customer.example"))
	}
}

func TestTlsAcmeOrderDeadByStatus(t *testing.T) {
	for status, dead := range map[string]bool{
		TlsAcmeStatusPending:     false,
		TlsAcmeStatusReady:       false,
		TlsAcmeStatusProcessing:  false,
		TlsAcmeStatusValid:       false,
		TlsAcmeStatusInvalid:     true,
		TlsAcmeStatusDeactivated: true,
		"expired":                true,
	} {
		if got := tlsAcmeOrderDead(&TlsAcmeOrder{Status: status}); got != dead {
			t.Errorf("%s: %v", status, got)
		}
	}
	if !tlsAcmeOrderDead(nil) {
		t.Error("no order read as live")
	}
}

func TestTlsCustomOrdererChecksTheChainItRegisters(t *testing.T) {
	now := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour * 24 * 365), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDer, _ := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDer)
	deviceKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"www.customer.example"}}, deviceKey)
	leaf := func(publicKey any, names []string, notAfter time.Time) [][]byte {
		der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: now, NotAfter: notAfter, DNSNames: names}, caCert, publicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return [][]byte{der, caDer}
	}
	orderer := &TlsCustomDomainOrderer{clock: &tlsCustomTestClock{now: now}, settings: DefaultTlsCustomSettings()}
	row := &TlsCertRecord{CustomHost: "www.customer.example", Csr: csr}
	if _, ok := orderer.checkChain(row, leaf(&deviceKey.PublicKey, []string{"www.customer.example"}, now.Add(time.Hour))); !ok {
		t.Fatal("the row's own chain refused")
	}
	for name, chain := range map[string][][]byte{
		"another key":   leaf(&otherKey.PublicKey, []string{"www.customer.example"}, now.Add(time.Hour)),
		"a second name": leaf(&deviceKey.PublicKey, []string{"www.customer.example", "api.customer.example"}, now.Add(time.Hour)),
		"expired":       leaf(&deviceKey.PublicKey, []string{"www.customer.example"}, now.Add(-time.Second)),
		"unchained":     {leaf(&deviceKey.PublicKey, []string{"www.customer.example"}, now.Add(time.Hour))[0], leaf(&otherKey.PublicKey, []string{"x.example"}, now.Add(time.Hour))[0]},
		"empty":         {},
	} {
		if _, ok := orderer.checkChain(row, chain); ok {
			t.Errorf("%s passed", name)
		}
	}
}

// A clock that stands still.
type tlsCustomTestClock struct {
	now time.Time
}

func (self *tlsCustomTestClock) Now() time.Time {
	return self.now
}

func (self *tlsCustomTestClock) After(timeout time.Duration) <-chan time.Time {
	fired := make(chan time.Time, 1)
	fired <- self.now
	return fired
}

func (self *tlsCustomTestClock) AfterFunc(timeout time.Duration, function func()) func() bool {
	return func() bool { return false }
}
