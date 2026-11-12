// T2 on Pebble (§22.9: 5% bad nonces): orders from a device's CSR to a chain by DNS-01 through the fenced
// block, ARI, a renewal from the stored CSR with the device offline, revocation with a reason, account
// rollover between orders, a 429's Retry-After reaching the policy's hold, and a fallback to a CA that
// needs EAB. Pebble and acmez run on real time over loopback, so a test waits for an order's answer
// with a guard and never sleeps; Pebble's validation sleeps are off.
//
// Pebble v2.10.1 cannot find the order behind about 1 in 255 of its own certificates when a new order
// names one in replaces (see testOrderReplaceable), so a test that replaces a certificate takes one
// Pebble can find, and what certs sends as replaces is read from the request itself, for every shape
// of serial, whatever Pebble answers.

package certsservice_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"slices"
	"sync"
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
	return testAcmeOver(t, settings, pebble, pebble.HttpClient, files...)
}

// An ACME client on pebble with files' accounts, reaching it through httpClient.
func testAcmeOver(t *testing.T, settings *certsservice.CertsSettings, pebble *sidecartest.Pebble, httpClient *http.Client, files ...[]byte) *certsservice.CertsAcmeClient {
	t.Helper()
	accounts, err := certsservice.NewCertsAccountSet(files)
	if err != nil {
		t.Fatal(err)
	}
	client, err := certsservice.NewCertsAcme(settings, &certsservice.CertsAcmeDeps{
		Accounts:   accounts,
		Dns:        pebble.Dns,
		Clock:      sidecar.RealClock{},
		HttpClient: httpClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// Keeps the replaces of every newOrder on its way to the CA, read from the request's JWS payload, so a
// test sees what certs sent whatever the CA answers. A newOrder posted again, after a bad nonce or a
// 5xx, is kept again.
type testReplacesRecorder struct {
	base http.RoundTripper

	stateLock sync.Mutex
	replaces  []string
}

// pebble's HTTP client with a recorder under it.
func newTestReplacesRecorder(pebble *sidecartest.Pebble) (*testReplacesRecorder, *http.Client) {
	recorder := &testReplacesRecorder{base: pebble.HttpClient.Transport}
	httpClient := *pebble.HttpClient
	httpClient.Transport = recorder
	return recorder, &httpClient
}

func (self *testReplacesRecorder) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost || request.Body == nil {
		return self.base.RoundTrip(request)
	}
	body, err := io.ReadAll(request.Body)
	request.Body.Close()
	if err != nil {
		return nil, err
	}
	// only a newOrder's payload holds identifiers (RFC 8555 §7.4)
	var jws struct {
		Payload string `json:"payload"`
	}
	var newOrder struct {
		Identifiers []json.RawMessage `json:"identifiers"`
		Replaces    string            `json:"replaces"`
	}
	if json.Unmarshal(body, &jws) == nil {
		if payload, err := base64.RawURLEncoding.DecodeString(jws.Payload); err == nil && json.Unmarshal(payload, &newOrder) == nil && 0 < len(newOrder.Identifiers) {
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.replaces = append(self.replaces, newOrder.Replaces)
			}()
		}
	}
	forwarded := request.Clone(request.Context())
	forwarded.Body = io.NopCloser(bytes.NewReader(body))
	return self.base.RoundTrip(forwarded)
}

// The replaces of each newOrder since the last take.
func (self *testReplacesRecorder) take() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	replaces := self.replaces
	self.replaces = nil
	return replaces
}

// RFC 9773's certificate id of leaf.
func testLeafAriId(t *testing.T, leaf *x509.Certificate) string {
	t.Helper()
	return testCertificateId(leaf.AuthorityKeyId, leaf.SerialNumber)
}

// Orders csr's certificate at LE's Pebble for a test that goes on to replace it, and returns it with
// its verified leaf.
//
// Pebble v2.10.1 files an issued order under its certificate's serial as the hex of the serial's bare
// unsigned octets, and looks a replaces up under the hex of the certificate id's serial octets, which
// are DER's and lead with a zero octet when the serial's top bit is set. So it answers a newOrder that
// replaces such a certificate with a 500, "could not find an order for the given certificate", though
// its own ARI finds it. Its serials are random below 2^63, so that is the 1 in 256 of 7 octets with the
// top bit set and the few shorter ones (question certs-ari-flake-pebble-replaces-serial). The id certs
// sends for such a certificate is right, which TestCertsAcmeReplacesNamesTheCertificateIdOnTheWire
// holds; Pebble is a fetched module and is not patched, so this orders again until Pebble issues a
// certificate it can find. It tries four times: each order writes its name's challenges twice, and the
// DNS routes take 10 writes a name an hour (D-DNS-8), so a set has five orders in a test, these and
// the one that replaces.
func testOrderReplaceable(t *testing.T, client *certsservice.CertsAcmeClient, pebble *sidecartest.Pebble, csr []byte, names []string) (*certsservice.CertsAcmeIssued, *x509.Certificate) {
	t.Helper()
	ctx := testAcmeContext(t)
	for range 4 {
		issued, err := client.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaLetsEncrypt, Csr: csr})
		if err != nil {
			t.Fatal(err)
		}
		leaf := testVerifyChain(t, pebble, issued.Chain, names)
		// the top bit of the serial's first octet is set exactly when its bit length fills its octets
		if leaf.SerialNumber.BitLen()%8 != 0 {
			return issued, leaf
		}
		t.Logf("Pebble cannot replace its certificate with serial %s; ordering another", certsservice.CertsSerialText(leaf.SerialNumber))
	}
	t.Fatal("Pebble issued no certificate it can replace")
	return nil, nil
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
	recorder, httpClient := newTestReplacesRecorder(pebble)
	client := testAcmeOver(t, settings, pebble, httpClient, testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", ""))
	device := newTestDevice(t, "k6renew001")
	storedCsr := testCsr(t, device.tlsKey, device.identifierSet)
	ctx := testAcmeContext(t)

	first, leaf := testOrderReplaceable(t, client, pebble, storedCsr, device.identifierSet)
	if sent := recorder.take(); len(sent) == 0 || slices.ContainsFunc(sent, func(replaces string) bool { return replaces != "" }) {
		t.Fatalf("a first order sent replaces %q", sent)
	}
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
	// every newOrder of the renewal named the first certificate: none fell back to an order without it
	leafId := testLeafAriId(t, leaf)
	if sent := recorder.take(); len(sent) == 0 || slices.ContainsFunc(sent, func(replaces string) bool { return replaces != leafId }) {
		t.Fatalf("the renewal sent replaces %q, not %q", sent, leafId)
	}
}

// What a renewal names to the CA is RFC 9773's certificate id of the certificate it replaces, octet for
// octet, whatever its serial's shape: top bit clear; top bit set, where DER's content octets lead with
// a zero octet that the serial's bare unsigned octets lack; one octet; 20 octets. An id whose serial
// octets are not a DER integer's, bare unsigned octets with the top bit set or padded with zeros, goes
// out as the DER of the same positive serial. Read from each newOrder on its way to Pebble, whose
// answer about a certificate it never issued is not what is tested here.
func TestCertsAcmeReplacesNamesTheCertificateIdOnTheWire(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	recorder, httpClient := newTestReplacesRecorder(pebble)
	client := testAcmeOver(t, settings, pebble, httpClient, testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", ""))
	device := newTestDevice(t, "k6wire0001")
	storedCsr := testCsr(t, device.tlsKey, device.identifierSet)
	ctx := testAcmeContext(t)

	for _, shape := range []struct {
		// the id an order names
		replaces string
		// the id its newOrder carries
		sent string
	}{
		// RFC 9773 §4.1's example: serial 00:87:65:43:21
		{"aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE", "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE"},
		{testAriIdOfOctets("7f223344556677"), testAriIdOfOctets("7f223344556677")},
		{testAriIdOfOctets("0080223344556677"), testAriIdOfOctets("0080223344556677")},
		{testAriIdOfOctets("00ff223344556677"), testAriIdOfOctets("00ff223344556677")},
		{testAriIdOfOctets("01"), testAriIdOfOctets("01")},
		{testAriIdOfOctets("0080"), testAriIdOfOctets("0080")},
		{testAriIdOfOctets("7f65432187654321876543218765432187654321"), testAriIdOfOctets("7f65432187654321876543218765432187654321")},
		{testAriIdOfOctets("008765432187654321876543218765432187654321"), testAriIdOfOctets("008765432187654321876543218765432187654321")},
		{testAriIdOfOctets("80223344556677"), testAriIdOfOctets("0080223344556677")},
		{testAriIdOfOctets("00007f2233"), testAriIdOfOctets("7f2233")},
	} {
		// Pebble knows none of these certificates and says so one way or another
		_, _ = client.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaLetsEncrypt, Csr: storedCsr, Replaces: shape.replaces})
		if sent := recorder.take(); len(sent) == 0 || slices.ContainsFunc(sent, func(replaces string) bool { return replaces != shape.sent }) {
			t.Fatalf("replaces %q sent %q, not %q", shape.replaces, sent, shape.sent)
		}
	}

	// an id that is not one reaches no CA
	for _, replaces := range []string{"not an ARI id", "aYhba4dGQEHhs3uEe6CuLN4ByNQ.", "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdl=yE", "a+b.AIdlQyE"} {
		if _, err := client.Order(ctx, &certsservice.CertsAcmeOrder{Ca: certsservice.CertsCaLetsEncrypt, Csr: storedCsr, Replaces: replaces}); err == nil {
			t.Fatalf("replaces %q ordered", replaces)
		}
		if sent := recorder.take(); 0 < len(sent) {
			t.Fatalf("replaces %q sent %q", replaces, sent)
		}
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

	_, leaf := testOrderReplaceable(t, client, pebble, storedCsr, device.identifierSet)
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
