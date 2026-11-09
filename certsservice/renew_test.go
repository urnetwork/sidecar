package certsservice_test

import (
	"errors"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
)

// With no ARI window a 45-day certificate renews at day 30; with one, at a point inside it that every
// reader picks alike.
func TestCertsRenewalTime(t *testing.T) {
	notBefore := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	row := &sidecar.TlsCertRecord{CertId: sidecar.NewId(), NotBefore: notBefore, NotAfter: notBefore.Add(45 * 24 * time.Hour)}
	if at := certsservice.CertsRenewalTime(row, 2.0/3.0); !at.Equal(notBefore.Add(30 * 24 * time.Hour)) {
		t.Fatalf("two thirds of 45 days: %v", at)
	}
	row.AriWindowStart = notBefore.Add(28 * 24 * time.Hour)
	row.AriWindowEnd = notBefore.Add(31 * 24 * time.Hour)
	at := certsservice.CertsRenewalTime(row, 2.0/3.0)
	if at.Before(row.AriWindowStart) || !at.Before(row.AriWindowEnd) {
		t.Fatalf("outside the window: %v", at)
	}
	if again := certsservice.CertsRenewalTime(row, 2.0/3.0); !again.Equal(at) {
		t.Fatal("two reads of one row picked two times")
	}
	if at := certsservice.CertsRenewalTime(&sidecar.TlsCertRecord{}, 2.0/3.0); !at.IsZero() {
		t.Fatal("a row with no validity has a renewal time")
	}
}

// A certificate is due past its renewal time and not before; its renewal queues the stored CSR as a
// successor, which the admission pass takes as a renewal past every limit; and it renews once.
func TestCertsQueueRenewal(t *testing.T) {
	certs := newTestCerts(t, nil)
	device := newTestDevice(t, "k7renewq01")
	certId := certs.accept(device)
	if report := certs.admit(); len(report.Admitted) != 1 || report.Admitted[0].Kind != certsservice.CertsOrderNewSet {
		t.Fatalf("the first order: %+v", report)
	}
	certs.issue(certId, "abc123")
	issued := certs.row(certId)
	if certs.service.RenewalDue(issued, certs.clock.Now().Add(30*24*time.Hour-time.Second)) {
		t.Fatal("due before two thirds")
	}
	if !certs.service.RenewalDue(issued, certs.clock.Now().Add(30*24*time.Hour)) {
		t.Fatal("not due at two thirds")
	}

	renewal, err := certs.service.QueueRenewal(certs.ctx, certId)
	if err != nil {
		t.Fatal(err)
	}
	if renewal.State != sidecar.TlsCertStateQueued || string(renewal.Csr) != string(issued.Csr) ||
		string(renewal.Attestation) != string(issued.Attestation) || string(renewal.SpkiSha256) != string(issued.SpkiSha256) {
		t.Fatalf("renewal %+v", renewal)
	}
	if certs.row(certId).SuccessorCertId != renewal.CertId {
		t.Fatal("the old row does not name its successor")
	}
	report := certs.admit()
	if len(report.Admitted) != 1 || report.Admitted[0].Cert.CertId != renewal.CertId || report.Admitted[0].Kind != certsservice.CertsOrderRenewal {
		t.Fatalf("report %+v", report)
	}
	if _, err := certs.service.QueueRenewal(certs.ctx, certId); !errors.Is(err, certsservice.ErrCertsNotRenewable) {
		t.Fatalf("a second renewal: %v", err)
	}
	if certs.service.RenewalDue(certs.row(certId), certs.clock.Now().Add(31*24*time.Hour)) {
		t.Fatal("a renewed certificate is due again")
	}
}
