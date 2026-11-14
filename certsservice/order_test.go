// POST /tls/cert-order's acceptance (TLS-M5-14): the CSR table, the attestation's mismatches and an
// ungranted caller each refused with no row and no budget spent, and a good order written queued before
// anything else, once however often it is posted, a replaces of a live certificate linking it as its
// predecessor's successor.
package certsservice_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/protocol"
)

// A good order is written queued, with cert-1's fields from the CSR and the attestation, and spends no
// budget until it is admitted.
func TestAcceptWritesTheRowFirst(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "alpha")
	order := device.order(t)
	result, err := certs.service.Accept(certs.ctx, order)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != sidecar.TlsCertStateQueued || result.RetryAfterMs == 0 {
		t.Fatalf("result %+v", result)
	}
	row := certs.row(result.CertId)
	spkiSha256 := testSpkiSha256(t, &device.tlsKey.PublicKey)
	setSha256, _ := sidecar.TlsIdentifierSetHash(device.identifierSet)
	if row.NetworkId != device.networkId || row.ClientId != device.clientId || row.SidecarId != device.sidecarId ||
		string(row.SpkiSha256) != string(spkiSha256[:]) || string(row.IdentifierSetSha256) != string(setSha256[:]) ||
		string(row.Csr) != string(order.Args.Csr) || string(row.Attestation) != string(order.Args.Attestation) ||
		row.State != sidecar.TlsCertStateQueued || row.Ca != "" || row.Serial != "" {
		t.Fatalf("row %+v", row)
	}
	if members := certs.host.Redis.Dump(); len(members) != 0 {
		t.Fatalf("accepting spent budget: %v", members)
	}
}

// Every CSR that is not exactly the caller's set under a P-256 key it signed: refused, no row.
func TestAcceptRefusesTheCsrTable(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "beta")
	set := device.identifierSet
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	badSignature := testCsr(t, device.tlsKey, set)
	badSignature[len(badSignature)-3] ^= 0x40
	withIp, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: set, IPAddresses: []net.IP{net.ParseIP("192.0.2.1")}}, device.tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	withCommonName := func(commonName string) []byte {
		template := &x509.CertificateRequest{DNSNames: set}
		template.Subject.CommonName = commonName
		csr, err := x509.CreateCertificateRequest(rand.Reader, template, device.tlsKey)
		if err != nil {
			t.Fatal(err)
		}
		return csr
	}
	for _, test := range []struct {
		name string
		csr  []byte
	}{
		{"not a CSR", []byte("not a certificate request")},
		{"an RSA key", testCsr(t, rsaKey, set)},
		{"a P-384 key", testCsr(t, p384Key, set)},
		{"an Ed25519 key", testCsr(t, edKey, set)},
		{"a bad signature", badSignature},
		{"an extra name", testCsr(t, device.tlsKey, append(slices.Clone(set), "other.root.example"))},
		{"a missing name", testCsr(t, device.tlsKey, set[:1])},
		{"another network's set", testCsr(t, device.tlsKey, []string{"*.gamma.root.example", "gamma.root.example"})},
		{"a name twice", testCsr(t, device.tlsKey, append(slices.Clone(set), set[0]))},
		{"a name in another case", testCsr(t, device.tlsKey, []string{"*.Beta.root.example", "Beta.root.example"})},
		{"an address beside the names", withIp},
		{"a common name outside the set", withCommonName("other.root.example")},
	} {
		order := device.request(&sidecar.TlsCertOrderArgs{Csr: test.csr, Attestation: device.attestation(t)})
		if _, err := certs.service.Accept(certs.ctx, order); !errors.Is(err, certsservice.ErrCertsCsr) {
			t.Errorf("%s: %v", test.name, err)
		}
	}
	// a common name inside the set is no refusal
	if _, err := certs.service.Accept(certs.ctx, device.request(&sidecar.TlsCertOrderArgs{Csr: withCommonName(set[1]), Attestation: device.attestation(t)})); err != nil {
		t.Errorf("a common name inside the set: %v", err)
	}
	if rows := certs.store.Rows(); len(rows) != 1 {
		t.Fatalf("%d rows written", len(rows))
	}
}

// An attestation for another network, sidecar, key or set, by another identity key, or not one at all:
// refused, no row.
func TestAcceptRefusesAttestationMismatches(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "delta")
	csr := testCsr(t, device.tlsKey, device.identifierSet)
	spkiSha256 := testSpkiSha256(t, &device.tlsKey.PublicKey)
	setSha256, _ := sidecar.TlsIdentifierSetHash(device.identifierSet)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSpkiSha256 := testSpkiSha256(t, &otherKey.PublicKey)
	otherSetSha256, _ := sidecar.TlsIdentifierSetHash([]string{"*.other.root.example", "other.root.example"})
	_, otherIdentityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestation := func(change func(attestation *protocol.TlsKeyAttestation)) *protocol.TlsKeyAttestation {
		body := &protocol.TlsKeyAttestation{
			NetworkId:           device.networkId[:],
			SidecarId:           device.sidecarId[:],
			SpkiSha256:          spkiSha256[:],
			IdentifierSetSha256: setSha256[:],
			IssueTimeMillis:     1,
		}
		change(body)
		return body
	}
	otherNetwork := sidecar.NewId()
	otherSidecar := sidecar.NewId()
	for _, test := range []struct {
		name        string
		attestation []byte
	}{
		{"another network", testAttest(t, device.identityKey, device.sidecarId, attestation(func(body *protocol.TlsKeyAttestation) { body.NetworkId = otherNetwork[:] }))},
		{"another sidecar", testAttest(t, device.identityKey, otherSidecar, attestation(func(body *protocol.TlsKeyAttestation) { body.SidecarId = otherSidecar[:] }))},
		{"another key", testAttest(t, device.identityKey, device.sidecarId, attestation(func(body *protocol.TlsKeyAttestation) { body.SpkiSha256 = otherSpkiSha256[:] }))},
		{"another set", testAttest(t, device.identityKey, device.sidecarId, attestation(func(body *protocol.TlsKeyAttestation) { body.IdentifierSetSha256 = otherSetSha256[:] }))},
		{"another identity key", testAttest(t, otherIdentityKey, device.sidecarId, attestation(func(body *protocol.TlsKeyAttestation) {}))},
		{"no attestation", nil},
		{"garbage", []byte("not a signed statement")},
	} {
		order := device.request(&sidecar.TlsCertOrderArgs{Csr: csr, Attestation: test.attestation})
		if _, err := certs.service.Accept(certs.ctx, order); !errors.Is(err, certsservice.ErrCertsAttestation) {
			t.Errorf("%s: %v", test.name, err)
		}
	}
	if rows := certs.store.Rows(); len(rows) != 0 {
		t.Fatalf("%d rows written", len(rows))
	}
}

// A caller with no grant, or a request missing what the token and gate give, is refused before its CSR
// is read.
func TestAcceptRefusesAnUngrantedOrIncompleteCaller(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "epsilon")
	ungranted := device.order(t)
	ungranted.Granted = false
	if _, err := certs.service.Accept(certs.ctx, ungranted); !errors.Is(err, certsservice.ErrCertsNotGranted) {
		t.Errorf("ungranted: %v", err)
	}
	for name, change := range map[string]func(request *certsservice.CertsOrderRequest){
		"no network":      func(request *certsservice.CertsOrderRequest) { request.NetworkId = sidecar.Id{} },
		"no sidecar":      func(request *certsservice.CertsOrderRequest) { request.SidecarId = sidecar.Id{} },
		"no identity key": func(request *certsservice.CertsOrderRequest) { request.IdentityPublicKey = nil },
		"no set":          func(request *certsservice.CertsOrderRequest) { request.IdentifierSet = nil },
		"no body":         func(request *certsservice.CertsOrderRequest) { request.Args = nil },
	} {
		request := device.order(t)
		change(request)
		if _, err := certs.service.Accept(certs.ctx, request); !errors.Is(err, certsservice.ErrCertsRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if rows := certs.store.Rows(); len(rows) != 0 {
		t.Fatalf("%d rows written", len(rows))
	}
}

// The same order posted again while it is under way answers its first row, so a retry after a lost
// answer queues nothing twice.
func TestAcceptAgainAnswersTheOpenOrder(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "zeta")
	first := certs.accept(device)
	if again := certs.accept(device); again != first {
		t.Fatalf("a second post made %s beside %s", again, first)
	}
	if rows := certs.store.Rows(); len(rows) != 1 {
		t.Fatalf("%d rows", len(rows))
	}
}

// A synthetic authority key id.
var testAuthorityKeyId = []byte("synthetic aki")

// RFC 9773's certificate id for a serial in hex, its authority key id synthetic.
func testAriId(serial string) string {
	serialInt, ok := new(big.Int).SetString(serial, 16)
	if !ok {
		panic(serial)
	}
	return testCertificateId(testAuthorityKeyId, serialInt)
}

// A certificate id whose serial part is exactly these octets, in hex, whether or not they are a DER
// integer's.
func testAriIdOfOctets(serialOctets string) string {
	octets, err := hex.DecodeString(serialOctets)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(testAuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(octets)
}

// A replaces naming a live certificate of the same sidecar and set links the new row as its successor;
// one naming another sidecar's certificate, or none at all, links nothing.
func TestAcceptLinksAReplacedCertificate(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "eta")
	firstId := certs.accept(device)
	if report := certs.admit(); len(report.Admitted) != 1 {
		t.Fatalf("admitted %+v", report)
	}
	certs.issue(firstId, "1a2b")
	device.tlsKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	renewal := device.order(t)
	renewal.Args.Replaces = testAriId("1a2b")
	result, err := certs.service.Accept(certs.ctx, renewal)
	if err != nil {
		t.Fatal(err)
	}
	if successor := certs.row(firstId).SuccessorCertId; successor != result.CertId {
		t.Fatalf("the replaced row's successor is %s, not %s", successor, result.CertId)
	}

	other := newTestDeviceOf(t, device.networkId, device.identifierSet)
	stranger := other.order(t)
	stranger.Args.Replaces = testAriId("1a2b")
	strangerResult, err := certs.service.Accept(certs.ctx, stranger)
	if err != nil {
		t.Fatal(err)
	}
	if predecessor, _ := certs.store.GetPredecessor(certs.ctx, strangerResult.CertId); predecessor != nil {
		t.Fatal("another sidecar's order took over a certificate it does not hold")
	}
	garbled := other.order(t)
	garbled.Args.Replaces = "not an ARI id"
	if _, err := certs.service.Accept(certs.ctx, garbled); err != nil {
		t.Fatalf("an unreadable replaces refused the order: %v", err)
	}
}

// A replaces finds its certificate by serial whatever the serial's shape. The row holds the serial as
// hex with no leading zeros and the id holds its DER content octets, which differ by a leading zero
// octet when the serial's top bit is set; an id from a client that sent the serial's bare unsigned
// octets, or padded them, names the same certificate.
func TestAcceptReadsAReplacedSerialOfEveryShape(t *testing.T) {
	for index, shape := range []struct {
		// the row's serial
		serial string
		// the serial octets of the id that replaces it, in hex
		idOctets string
	}{
		{"7f223344556677", "7f223344556677"},
		{"80223344556677", "0080223344556677"},
		{"ff223344556677", "00ff223344556677"},
		{"80", "0080"},
		{"1", "01"},
		{"8765432187654321876543218765432187654321", "008765432187654321876543218765432187654321"},
		{"80223344556677", "80223344556677"},
		{"7f2233", "00007f2233"},
	} {
		certs := newTestCerts(t, nil)
		device := newTestDevice(t, "shape"+string(rune('a'+index)))
		firstId := certs.accept(device)
		if report := certs.admit(); len(report.Admitted) != 1 {
			t.Fatalf("admitted %+v", report)
		}
		certs.issue(firstId, shape.serial)
		device.tlsKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		renewal := device.order(t)
		renewal.Args.Replaces = testAriIdOfOctets(shape.idOctets)
		result, err := certs.service.Accept(certs.ctx, renewal)
		if err != nil {
			t.Fatal(err)
		}
		if successor := certs.row(firstId).SuccessorCertId; successor != result.CertId {
			t.Fatalf("serial %s by octets %s: the replaced row's successor is %s, not %s", shape.serial, shape.idOctets, successor, result.CertId)
		}
	}
}
