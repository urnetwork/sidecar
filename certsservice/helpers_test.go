// What this package's tests share: a service on a fake clock, store and Redis, and devices that make
// their own P-256 keys, CSRs and attestations as §13.8's devices do. Names are under root.example, and
// every key is generated or derived from a synthetic seed. Nothing here sleeps.

package certsservice_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

const testRoot = "root.example"

// RFC 9773's certificate id of the certificate with this authority key id and serial: base64url of the
// key id, a dot, and base64url of the serial's DER content octets, which lead with a zero octet when
// the serial's top bit is set.
func testCertificateId(authorityKeyId []byte, serial *big.Int) string {
	serialDer, err := asn1.Marshal(serial)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(authorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serialDer[2:])
}

// Settings that pass Validate, under testRoot.
func testSettings() *certsservice.CertsSettings {
	settings := certsservice.DefaultCertsSettings()
	settings.RootDomain = testRoot
	return settings
}

// A service and everything behind it.
type testCerts struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	store    *sidecartest.FakeCertsStore
	settings *certsservice.CertsSettings
	service  *certsservice.CertsService
}

// A service on settings, nil taking testSettings.
func newTestCerts(t *testing.T, settings *certsservice.CertsSettings) *testCerts {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	if settings == nil {
		settings = testSettings()
	}
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterCertsBudgetTwins(host.Redis)
	store := sidecartest.NewFakeCertsStore(host.Redis.Faults())
	service, err := certsservice.NewCertsService(ctx, host.ServiceHost(), store, nil, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	return &testCerts{t: t, ctx: ctx, clock: clock, host: host, store: store, settings: settings, service: service}
}

// One device of a network: its identity key, its own P-256 key, and the set its config gives it.
type testDevice struct {
	networkId     sidecar.Id
	clientId      sidecar.Id
	sidecarId     sidecar.Id
	identityKey   ed25519.PrivateKey
	tlsKey        *ecdsa.PrivateKey
	identifierSet []string
}

// A device of a new network whose label is label.
func newTestDevice(t *testing.T, label string) *testDevice {
	t.Helper()
	identifierSet, err := sidecar.TlsIdentifierSet(testRoot, label, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return newTestDeviceOf(t, sidecar.NewId(), identifierSet)
}

// Another device of networkId holding identifierSet.
func newTestDeviceOf(t *testing.T, networkId sidecar.Id, identifierSet []string) *testDevice {
	t.Helper()
	_, identityKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testDevice{
		networkId:     networkId,
		clientId:      sidecar.NewId(),
		sidecarId:     sidecar.NewId(),
		identityKey:   identityKey,
		tlsKey:        tlsKey,
		identifierSet: identifierSet,
	}
}

// A CSR by key for names.
func testCsr(t *testing.T, key any, names []string) []byte {
	t.Helper()
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

// The SHA-256 of a key's DER SubjectPublicKeyInfo.
func testSpkiSha256(t *testing.T, publicKey any) [sha256.Size]byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(spki)
}

// An attestation by identityKey, as sidecar_id sidecarId, of the attestation's fields.
func testAttest(t *testing.T, identityKey ed25519.PrivateKey, sidecarId sidecar.Id, attestation *protocol.TlsKeyAttestation) []byte {
	t.Helper()
	sign := func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      body,
			SignerId:  sidecarId[:],
			Signature: ed25519.Sign(identityKey, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
	signed, err := sidecar.SignTlsKeyAttestation(attestation, sign)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// The device's own attestation of its key and set.
func (self *testDevice) attestation(t *testing.T) []byte {
	t.Helper()
	spkiSha256 := testSpkiSha256(t, &self.tlsKey.PublicKey)
	setSha256, err := sidecar.TlsIdentifierSetHash(self.identifierSet)
	if err != nil {
		t.Fatal(err)
	}
	return testAttest(t, self.identityKey, self.sidecarId, &protocol.TlsKeyAttestation{
		NetworkId:           self.networkId[:],
		SidecarId:           self.sidecarId[:],
		SpkiSha256:          spkiSha256[:],
		IdentifierSetSha256: setSha256[:],
		IssueTimeMillis:     uint64(time.Date(2026, time.November, 1, 0, 0, 0, 0, time.UTC).UnixMilli()),
	})
}

// The request the device's gate and token give for args, granted.
func (self *testDevice) request(args *sidecar.TlsCertOrderArgs) *certsservice.CertsOrderRequest {
	return &certsservice.CertsOrderRequest{
		NetworkId:         self.networkId,
		ClientId:          self.clientId,
		SidecarId:         self.sidecarId,
		IdentifierSet:     self.identifierSet,
		IdentityPublicKey: self.identityKey.Public().(ed25519.PublicKey),
		Granted:           true,
		Args:              args,
	}
}

// The device's well-formed order.
func (self *testDevice) order(t *testing.T) *certsservice.CertsOrderRequest {
	t.Helper()
	return self.request(&sidecar.TlsCertOrderArgs{
		Csr:         testCsr(t, self.tlsKey, self.identifierSet),
		Attestation: self.attestation(t),
	})
}

// Accepts the device's order, failing the test on a refusal.
func (self *testCerts) accept(device *testDevice) sidecar.Id {
	self.t.Helper()
	result, err := self.service.Accept(self.ctx, device.order(self.t))
	if err != nil {
		self.t.Fatal(err)
	}
	return result.CertId
}

// The row, failing the test when it is absent.
func (self *testCerts) row(certId sidecar.Id) *sidecar.TlsCertRecord {
	self.t.Helper()
	row, err := self.store.GetCert(self.ctx, certId)
	if err != nil {
		self.t.Fatal(err)
	}
	return row
}

// Moves an ordering row to issued with serial, as a CA's answer does, valid from now for 45 days.
func (self *testCerts) issue(certId sidecar.Id, serial string) {
	self.t.Helper()
	now := self.clock.Now()
	applied, err := self.store.TransitionCert(self.ctx, &certsservice.CertsTransition{
		CertId:     certId,
		From:       []sidecar.TlsCertState{sidecar.TlsCertStateOrdering, sidecar.TlsCertStateWaitingDns},
		To:         sidecar.TlsCertStateIssued,
		AccountUri: "https://ca.example/acct/1",
		Serial:     serial,
		NotBefore:  now,
		NotAfter:   now.Add(45 * 24 * time.Hour),
	})
	if err != nil || !applied {
		self.t.Fatalf("issue: %v, %v", applied, err)
	}
}

// One admission pass from the queue's start.
func (self *testCerts) admit() *certsservice.CertsAdmitReport {
	self.t.Helper()
	report, err := self.service.Admit(self.ctx, sidecar.Id{})
	if err != nil {
		self.t.Fatal(err)
	}
	return report
}
