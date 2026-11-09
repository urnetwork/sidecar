package certsservice_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/certsservice"
)

// A key PEM of each kind ACME takes, as an account file holds it.
func testKeyPems(t *testing.T) map[string]string {
	t.Helper()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec1, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]string{
		"pkcs8 ec": testAccountKeyPem(t),
		"sec1 ec":  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})),
		"pkcs1":    string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)})),
	}
}

// Each key kind loads, and the set names its CA.
func TestCertsAccountSetLoadsEachKeyKind(t *testing.T) {
	for kind, keyPem := range testKeyPems(t) {
		accounts, err := certsservice.NewCertsAccountSet([][]byte{[]byte("ca: letsencrypt\nprivate_key: |\n" + testIndent(keyPem))})
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if cas := accounts.Cas(); !slices.Equal(cas, []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}) {
			t.Fatalf("%s: cas %v", kind, cas)
		}
		if _, ok := accounts.AccountUri(certsservice.CertsCaLetsEncrypt); ok {
			t.Fatalf("%s: an account named a URI before it resolved", kind)
		}
	}
}

// A file certs cannot use is refused, naming its field: no key, a key that is none, an unknown CA, two
// accounts for one CA, half an EAB, an EAB key that is not base64url.
func TestCertsAccountSetRefusals(t *testing.T) {
	key := testIndent(testAccountKeyPem(t))
	for _, files := range [][]string{
		{"ca: letsencrypt\n"},
		{"ca: letsencrypt\nprivate_key: not a key\n"},
		{"ca: other\nprivate_key: |\n" + key},
		{"ca: letsencrypt\nprivate_key: |\n" + key, "ca: letsencrypt\nprivate_key: |\n" + key},
		{"ca: gts\nprivate_key: |\n" + key + "eab_key_id: kid\n"},
		{"ca: gts\nprivate_key: |\n" + key + "eab_key_id: kid\neab_mac_key: '***'\n"},
		{"ca: letsencrypt\nprivate_key: |\n" + key + "next_private_key: not a key\n"},
		{"{"},
	} {
		data := [][]byte{}
		for _, file := range files {
			data = append(data, []byte(file))
		}
		if _, err := certsservice.NewCertsAccountSet(data); !errors.Is(err, certsservice.ErrCertsAccountFileRefused) {
			t.Errorf("%q: %v", files, err)
		}
	}
}

// A key rolls over once it is a year old, and is ready to only with a next key in its file.
func TestCertsAccountRolloverDue(t *testing.T) {
	created := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
	age := testSettings().AccountRolloverAge
	without := []byte("ca: letsencrypt\nkey_create_time: " + created.Format(time.RFC3339) + "\nprivate_key: |\n" + testIndent(testAccountKeyPem(t)))
	with := append(append([]byte{}, without...), []byte("next_private_key: |\n"+testIndent(testAccountKeyPem(t)))...)
	for _, c := range []struct {
		file  []byte
		at    time.Time
		due   bool
		ready bool
	}{
		{file: without, at: created.Add(age - time.Second), due: false, ready: false},
		{file: without, at: created.Add(age), due: true, ready: false},
		{file: with, at: created.Add(age), due: true, ready: true},
	} {
		accounts, err := certsservice.NewCertsAccountSet([][]byte{c.file})
		if err != nil {
			t.Fatal(err)
		}
		due, ready := accounts.RolloverDue(certsservice.CertsCaLetsEncrypt, c.at, age)
		if due != c.due || ready != c.ready {
			t.Errorf("at %v: due %v, ready %v", c.at, due, ready)
		}
	}
}
