package certsservice_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// §13.8's causes to RFC 5280's reasons: keyCompromise on compromise, cessationOfOperation when names stop
// being served, none otherwise.
func TestCertsRevocationReasonFor(t *testing.T) {
	for cause, reason := range map[certsservice.CertsRevocationCause]certsservice.CertsRevocationReason{
		certsservice.CertsRevocationCauseKeyCompromise: certsservice.CertsRevocationKeyCompromise,
		certsservice.CertsRevocationCauseRemoval:       certsservice.CertsRevocationCessationOfOperation,
		certsservice.CertsRevocationCauseTakedown:      certsservice.CertsRevocationCessationOfOperation,
		certsservice.CertsRevocationCauseDeletion:      certsservice.CertsRevocationCessationOfOperation,
		certsservice.CertsRevocationCauseAliasRetired:  certsservice.CertsRevocationCessationOfOperation,
		"something else": certsservice.CertsRevocationUnspecified,
	} {
		if got := certsservice.CertsRevocationReasonFor(cause); got != reason {
			t.Errorf("%s: %d", cause, got)
		}
	}
}

// A reason reads back from the name a row keeps for it; no reason has no name, and a name this build
// does not know is no reason.
func TestCertsRevocationReasonNames(t *testing.T) {
	for reason, name := range map[certsservice.CertsRevocationReason]sidecar.TlsCertRevocationReason{
		certsservice.CertsRevocationKeyCompromise:        sidecar.TlsCertRevocationReasonKeyCompromise,
		certsservice.CertsRevocationCessationOfOperation: sidecar.TlsCertRevocationReasonCessationOfOperation,
		certsservice.CertsRevocationUnspecified:          "",
	} {
		if got := certsservice.CertsRevocationReasonName(reason); got != name {
			t.Errorf("%d is named %q", reason, got)
		}
		if got := certsservice.CertsRevocationReasonNamed(name); got != reason {
			t.Errorf("%q reads as %d", name, got)
		}
	}
	if got := certsservice.CertsRevocationReasonNamed("aReasonOfALaterBuild"); got != certsservice.CertsRevocationUnspecified {
		t.Errorf("an unknown name reads as %d", got)
	}
	if sidecar.TlsCertRevocationReasonKeyCompromise != "keyCompromise" || sidecar.TlsCertRevocationReasonCessationOfOperation != "cessationOfOperation" {
		t.Error("a stored reason is not RFC 5280's name")
	}
}

// A CertsAcme that records the revocations it took, and refuses while err is set.
type testRevokeAcme struct {
	certsservice.ClosedCertsAcme
	stateLock sync.Mutex
	reasons   []certsservice.CertsRevocationReason
	err       error
}

func (self *testRevokeAcme) Revoke(ctx context.Context, ca certsservice.CertsCa, leaf []byte, reason certsservice.CertsRevocationReason) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err != nil {
		return self.err
	}
	self.reasons = append(self.reasons, reason)
	return nil
}

func (self *testRevokeAcme) revocations() []certsservice.CertsRevocationReason {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]certsservice.CertsRevocationReason{}, self.reasons...)
}

// A leaf on the device's key with serial, as a CA would issue for its set.
func testLeaf(t *testing.T, device *testDevice, serial *big.Int) []byte {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: serial,
		DNSNames:     device.identifierSet,
		NotBefore:    time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2026, 12, 16, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &device.tlsKey.PublicKey, device.tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// The row moves issued, revoking, revoked around the CA's answer with the reason given; a leaf that is
// not the row's is refused with no CA call; a revoked row answers done; a queued row cannot be revoked.
func TestCertsRevokeIssued(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterCertsBudgetTwins(host.Redis)
	store := sidecartest.NewFakeCertsStore(host.Redis.Faults())
	acme := &testRevokeAcme{}
	service, err := certsservice.NewCertsService(ctx, host.ServiceHost(), store, nil, acme, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	certs := &testCerts{t: t, ctx: ctx, clock: clock, host: host, store: store, settings: testSettings(), service: service}
	device := newTestDevice(t, "k8revoke01")
	certId := certs.accept(device)
	certs.admit()
	serial := big.NewInt(0xabc123)
	certs.issue(certId, certsservice.CertsSerialText(serial))

	otherDevice := newTestDevice(t, "k8revoke02")
	if err := service.RevokeIssued(ctx, certId, testLeaf(t, otherDevice, serial), certsservice.CertsRevocationKeyCompromise); !errors.Is(err, certsservice.ErrCertsLeafMismatch) {
		t.Fatalf("another key's leaf: %v", err)
	}
	if err := service.RevokeIssued(ctx, certId, testLeaf(t, device, big.NewInt(7)), certsservice.CertsRevocationKeyCompromise); !errors.Is(err, certsservice.ErrCertsLeafMismatch) {
		t.Fatalf("another serial's leaf: %v", err)
	}
	if 0 < len(acme.revocations()) {
		t.Fatal("a mismatched leaf reached the CA")
	}

	leaf := testLeaf(t, device, serial)
	// a CA that refuses leaves the row revoking, holding the reason for whoever asks next
	acme.stateLock.Lock()
	acme.err = errors.New("the CA is down")
	acme.stateLock.Unlock()
	clock.Advance(time.Minute)
	markedAt := clock.Now()
	if err := service.RevokeIssued(ctx, certId, leaf, certsservice.CertsRevocationKeyCompromise); err == nil {
		t.Fatal("a refused revocation answered no error")
	}
	if row := certs.row(certId); row.State != sidecar.TlsCertStateRevoking || row.RevocationReason != sidecar.TlsCertRevocationReasonKeyCompromise || !row.StateTime.Equal(markedAt) {
		t.Fatalf("the row its CA refused: %+v", row)
	}
	acme.stateLock.Lock()
	acme.err = nil
	acme.stateLock.Unlock()
	clock.Advance(time.Minute)
	if err := service.RevokeIssued(ctx, certId, leaf, certsservice.CertsRevocationKeyCompromise); err != nil {
		t.Fatal(err)
	}
	if reasons := acme.revocations(); len(reasons) != 1 || reasons[0] != certsservice.CertsRevocationKeyCompromise {
		t.Fatalf("reasons %v", reasons)
	}
	if row := certs.row(certId); row.State != sidecar.TlsCertStateRevoked || row.RevocationReason != "" || !row.StateTime.Equal(clock.Now()) {
		t.Fatalf("the revoked row: %+v", row)
	}
	if err := service.RevokeIssued(ctx, certId, leaf, certsservice.CertsRevocationKeyCompromise); err != nil || len(acme.revocations()) != 1 {
		t.Fatalf("a revoked row: %v, %d calls", err, len(acme.revocations()))
	}

	queuedId := certs.accept(newTestDevice(t, "k8revoke03"))
	if err := service.RevokeIssued(ctx, queuedId, leaf, certsservice.CertsRevocationKeyCompromise); err == nil {
		t.Fatal("a queued row was revoked")
	}
}
