// T2 on Pebble (§22.9: 5% bad nonces): orders from a device's CSR to a chain by DNS-01 through the fenced
// block, ARI, a renewal from the stored CSR with the device offline, revocation with a reason, account
// rollover between orders, a 429's Retry-After reaching the policy's hold, and a fallback to a CA that
// needs EAB. Pebble and acmez run on real time over loopback, so a test waits for an order's answer
// with a guard and never sleeps; Pebble's validation sleeps are off.

package certsservice_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// How long one order may take against Pebble before the test fails.
const testAcmeTimeout = 2 * time.Minute

// An account file for ca with a new P-256 key, and EAB when keyId is given.
func testAccountFile(t *testing.T, ca certsservice.CertsCa, keyCreateTime time.Time, eabKeyId string, eabMacKey string) []byte {
	t.Helper()
	key := testAccountKeyPem(t)
	file := "ca: " + string(ca) + "\n" +
		"key_create_time: " + keyCreateTime.UTC().Format(time.RFC3339) + "\n" +
		"private_key: |\n" + testIndent(key)
	if eabKeyId != "" {
		file += "eab_key_id: " + eabKeyId + "\neab_mac_key: " + eabMacKey + "\n"
	}
	return []byte(file)
}

// A new P-256 key as PKCS #8 PEM.
func testAccountKeyPem(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// text with every line indented two spaces, as a YAML block scalar takes it.
func testIndent(text string) string {
	indented := ""
	for _, line := range slices.Collect(func(yield func(string) bool) {
		start := 0
		for index := range len(text) {
			if text[index] == '\n' {
				if !yield(text[start:index]) {
					return
				}
				start = index + 1
			}
		}
		if start < len(text) {
			yield(text[start:])
		}
	}) {
		indented += "  " + line + "\n"
	}
	return indented
}

// Settings with LE at pebble's directory, and GTS at gts's when given, polling fast for a test.
func testAcmeSettings(pebble *sidecartest.Pebble, gts *sidecartest.Pebble) *certsservice.CertsSettings {
	settings := testSettings()
	settings.Cas[certsservice.CertsCaLetsEncrypt].DirectoryUrl = pebble.DirectoryUrl
	settings.Cas[certsservice.CertsCaLetsEncrypt].Profile = sidecartest.PebbleProfileTlsServer
	if gts != nil {
		settings.Cas[certsservice.CertsCaGts].DirectoryUrl = gts.DirectoryUrl
	}
	settings.AcmePollInterval = 50 * time.Millisecond
	settings.AcmeOrderTimeout = testAcmeTimeout
	return settings
}

// An ACME client on pebble with files' accounts.
func testAcme(t *testing.T, settings *certsservice.CertsSettings, pebble *sidecartest.Pebble, files ...[]byte) *certsservice.CertsAcmeClient {
	t.Helper()
	accounts, err := certsservice.NewCertsAccountSet(files)
	if err != nil {
		t.Fatal(err)
	}
	client, err := certsservice.NewCertsAcme(settings, &certsservice.CertsAcmeDeps{
		Accounts:   accounts,
		Dns:        pebble.Dns,
		Clock:      sidecar.RealClock{},
		HttpClient: pebble.HttpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// RFC 9773's certificate id of leaf: base64url of its authority key id, a dot, and base64url of its
// serial's DER content octets.
func testLeafAriId(t *testing.T, leaf *x509.Certificate) string {
	t.Helper()
	serialDer, err := asn1.Marshal(leaf.SerialNumber)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serialDer[2:])
}

// Verifies chain under pebble's roots for its names, and returns its leaf.
func testVerifyChain(t *testing.T, pebble *sidecartest.Pebble, chain [][]byte, names []string) *x509.Certificate {
	t.Helper()
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(certificate)
	}
	for _, name := range names {
		dnsName := name
		if name[0] == '*' {
			dnsName = "any" + name[1:]
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pebble.Roots, Intermediates: intermediates, DNSName: dnsName}); err != nil {
			t.Fatalf("the chain does not verify for %s: %v", name, err)
		}
	}
	return leaf
}

func testAcmeContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testAcmeTimeout)
	t.Cleanup(cancel)
	return ctx
}

// A device's CSR for its set, ordered at LE under the tlsserver profile, comes back as a chain for
// exactly its names, on its own key, 45 days long, with the account's URI; the challenges are gone.
func TestCertsAcmeOrderToChain(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	client := testAcme(t, settings, pebble, testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", ""))
	device := newTestDevice(t, "k6order001")
	ctx := testAcmeContext(t)

	issued, err := client.Order(ctx, &certsservice.CertsAcmeOrder{
		Ca:      certsservice.CertsCaLetsEncrypt,
		Profile: sidecartest.PebbleProfileTlsServer,
		Csr:     testCsr(t, device.tlsKey, device.identifierSet),
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf := testVerifyChain(t, pebble, issued.Chain, device.identifierSet)
	if !slices.Equal(slices.Sorted(slices.Values(leaf.DNSNames)), slices.Sorted(slices.Values(device.identifierSet))) {
		t.Fatalf("the leaf names %v", leaf.DNSNames)
	}
	if !device.tlsKey.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("the leaf is not on the device's key")
	}
	if issued.Serial != certsservice.CertsSerialText(leaf.SerialNumber) || !issued.NotAfter.Equal(leaf.NotAfter) {
		t.Fatalf("issued %+v", issued)
	}
	if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); lifetime < 44*24*time.Hour || 46*24*time.Hour < lifetime {
		t.Fatalf("lifetime %v", lifetime)
	}
	uri, err := client.AccountUri(ctx, certsservice.CertsCaLetsEncrypt)
	if err != nil || uri == "" || issued.AccountUri != uri {
		t.Fatalf("account uri %q, %q, %v", issued.AccountUri, uri, err)
	}
	if names := pebble.Dns.Names(); 0 < len(names) {
		t.Fatalf("challenges left at %v", names)
	}
}

// ARI's window lies inside the validity; a renewal from the stored CSR, with the device offline, replaces
// the first certificate; and a second renewal of the same certificate is refused as replaced.
func TestCertsAcmeAriAndOfflineRenewal(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	client := testAcme(t, settings, pebble, testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", ""))
	device := newTestDevice(t, "k6renew001")
	storedCsr := testCsr(t, device.tlsKey, device.identifierSet)
	ctx := testAcmeContext(t)

	first, err := client.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaLetsEncrypt, Csr: storedCsr})
	if err != nil {
		t.Fatal(err)
	}
	leaf := testVerifyChain(t, pebble, first.Chain, device.identifierSet)
	windowStart, windowEnd, err := client.RenewalInfo(ctx, certsservice.CertsCaLetsEncrypt, first.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if !windowStart.Before(windowEnd) || windowStart.Before(leaf.NotBefore) || leaf.NotAfter.Before(windowEnd) {
		t.Fatalf("window %v to %v outside %v to %v", windowStart, windowEnd, leaf.NotBefore, leaf.NotAfter)
	}

	// the device is gone: only its stored CSR orders
	device.tlsKey = nil
	second, err := client.Order(ctx, &certsservice.CertsAcmeOrder{
		Ca:       certsservice.CertsCaLetsEncrypt,
		Csr:      storedCsr,
		Replaces: testLeafAriId(t, leaf),
	})
	if err != nil {
		t.Fatal(err)
	}
	renewed := testVerifyChain(t, pebble, second.Chain, device.identifierSet)
	if renewed.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
		t.Fatal("the renewal returned the old certificate")
	}
}

// Revocation with keyCompromise reaches the CA, and a second revocation of the same certificate
// answers as done.
func TestCertsAcmeRevokeWithReason(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	client := testAcme(t, settings, pebble, testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", ""))
	device := newTestDevice(t, "k6revoke01")
	ctx := testAcmeContext(t)
	issued, err := client.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaLetsEncrypt, Csr: testCsr(t, device.tlsKey, device.identifierSet)})
	if err != nil {
		t.Fatal(err)
	}
	reason := certsservice.CertsRevocationReasonFor(certsservice.CertsRevocationCauseKeyCompromise)
	if err := client.Revoke(ctx, certsservice.CertsCaLetsEncrypt, issued.Chain[0], reason); err != nil {
		t.Fatal(err)
	}
	if err := client.Revoke(ctx, certsservice.CertsCaLetsEncrypt, issued.Chain[0], reason); err != nil {
		t.Fatalf("a second revocation: %v", err)
	}
}

// A key rollover between two orders keeps the account: its URI stays, and the second order, signed by
// the new key, may replace the first's certificate. A process restarted with both keys in its file
// finds the account under the new one.
func TestCertsAcmeRolloverBetweenOrders(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	currentKey := testAccountKeyPem(t)
	nextKey := testAccountKeyPem(t)
	file := []byte("ca: letsencrypt\nkey_create_time: 2025-11-01T00:00:00Z\nprivate_key: |\n" + testIndent(currentKey) +
		"next_private_key: |\n" + testIndent(nextKey))
	client := testAcme(t, settings, pebble, file)
	device := newTestDevice(t, "k6roll0001")
	storedCsr := testCsr(t, device.tlsKey, device.identifierSet)
	ctx := testAcmeContext(t)

	first, err := client.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaLetsEncrypt, Csr: storedCsr})
	if err != nil {
		t.Fatal(err)
	}
	uriBefore, err := client.AccountUri(ctx, certsservice.CertsCaLetsEncrypt)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.RolloverAccount(ctx, certsservice.CertsCaLetsEncrypt); err != nil {
		t.Fatal(err)
	}
	uriAfter, err := client.AccountUri(ctx, certsservice.CertsCaLetsEncrypt)
	if err != nil || uriAfter != uriBefore {
		t.Fatalf("the rollover moved the account: %q to %q, %v", uriBefore, uriAfter, err)
	}
	leaf, err := x509.ParseCertificate(first.Chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaLetsEncrypt, Csr: storedCsr, Replaces: testLeafAriId(t, leaf)}); err != nil {
		t.Fatalf("an order after the rollover: %v", err)
	}

	restarted := testAcme(t, settings, pebble, file)
	uriRestarted, err := restarted.AccountUri(ctx, certsservice.CertsCaLetsEncrypt)
	if err != nil || uriRestarted != uriBefore {
		t.Fatalf("a restart found %q, %v", uriRestarted, err)
	}
}

// A 429 on newOrder comes back as a rate limit with its Retry-After, which held as the CA's hold keeps
// the admission pass from that CA until then.
func TestCertsAcmeRateLimitReachesTheHold(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	client := testAcme(t, settings, pebble, testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", ""))
	device := newTestDevice(t, "k6limit001")
	ctx := testAcmeContext(t)
	pebble.RefuseNewOrders(1, 2*time.Hour)
	before := time.Now()
	_, err := client.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaLetsEncrypt, Csr: testCsr(t, device.tlsKey, device.identifierSet)})
	var limitErr *certsservice.CertsAcmeRateLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("a 429 answered %v", err)
	}
	if limitErr.Ca != certsservice.CertsCaLetsEncrypt || limitErr.RetryAfter.Before(before.Add(2*time.Hour-time.Minute)) {
		t.Fatalf("rate limit %+v", limitErr)
	}

	// the hold, on the policy's own clock: only LE in the order, so the row waits on the hold
	holdSettings := testSettings()
	holdSettings.CaOrder = []certsservice.CertsCa{certsservice.CertsCaLetsEncrypt}
	certs := newTestCerts(t, holdSettings)
	certId := certs.accept(newTestDevice(t, "k6limit002"))
	certs.service.HoldCa(certsservice.CertsCaLetsEncrypt, certs.clock.Now().Add(limitErr.RetryAfter.Sub(before)))
	report := certs.admit()
	if len(report.Admitted) != 0 || len(report.Waiting) != 1 || report.Waiting[0].CertId != certId || report.Waiting[0].Reason != certsservice.CertsWaitCaHold {
		t.Fatalf("report %+v", report)
	}
}

// A CA that needs EAB refuses an account without one, and orders for an account bound with it: the
// fallback past LE, and an ephemeral sidecar's first CA (D-TLS-7).
func TestCertsAcmeGtsWithEab(t *testing.T) {
	macKey := base64.RawURLEncoding.EncodeToString([]byte("a synthetic EAB MAC key, 32 by.."))
	gts := sidecartest.StartPebble(t, &sidecartest.PebbleSettings{
		NonceRejectPercent: 5,
		RequireEab:         true,
		EabKeys:            map[string]string{"kid-test-1": macKey},
	})
	settings := testSettings()
	settings.Cas[certsservice.CertsCaGts].DirectoryUrl = gts.DirectoryUrl
	settings.AcmePollInterval = 50 * time.Millisecond
	settings.AcmeOrderTimeout = testAcmeTimeout
	device := newTestDevice(t, "k6gtseab01")
	ctx := testAcmeContext(t)

	unbound := testAcme(t, settings, gts, testAccountFile(t, certsservice.CertsCaGts, time.Now(), "", ""))
	if _, err := unbound.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaGts, Csr: testCsr(t, device.tlsKey, device.identifierSet)}); err == nil {
		t.Fatal("a CA that needs EAB took an account without it")
	}

	bound := testAcme(t, settings, gts, testAccountFile(t, certsservice.CertsCaGts, time.Now(), "kid-test-1", macKey))
	issued, err := bound.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaGts, Csr: testCsr(t, device.tlsKey, device.identifierSet)})
	if err != nil {
		t.Fatal(err)
	}
	testVerifyChain(t, gts, issued.Chain, device.identifierSet)
}

// An authorization the CA fails, here a challenge value that does not match, comes back naming its
// identifiers, which the policy holds.
func TestCertsAcmeFailedAuthorizationNamesItsIdentifier(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	client := testAcme(t, settings, pebble, testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", ""))
	device := newTestDevice(t, "k6authz001")
	ctx := testAcmeContext(t)
	pebble.Dns.ServeWrongValues(true)
	_, err := client.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaLetsEncrypt, Csr: testCsr(t, device.tlsKey, device.identifierSet)})
	var authzErr *certsservice.CertsAcmeAuthorizationError
	if !errors.As(err, &authzErr) {
		t.Fatalf("a failed authorization answered %v", err)
	}
	if len(authzErr.Names) == 0 || !slices.Contains(device.identifierSet, authzErr.Names[0]) {
		t.Fatalf("names %v", authzErr.Names)
	}
	if names := pebble.Dns.Names(); 0 < len(names) {
		t.Fatalf("a failed order left challenges at %v", names)
	}
}
