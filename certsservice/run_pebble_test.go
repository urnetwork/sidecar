// The chains' passes against Pebble (T2; §22.9), for what a row carries between them (cert-1; QD-741):
// the chain a real ACME server issued is in the row for a device that asks after a restart, and the
// reason a revocation was requested with is the one Pebble records, whichever pass and whichever
// engine takes it there.

package certsservice_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// An engine on store and pebble: a restart is another one on the same store. Its clock stands at the
// wall's time, since Pebble's certificates are valid from it.
func testPebbleService(t *testing.T, ctx context.Context, host *sidecartest.FakeHost, store certsservice.CertsStore, pebble *sidecartest.Pebble, settings *certsservice.CertsSettings, accountFile []byte) *certsservice.CertsService {
	t.Helper()
	service, err := certsservice.NewCertsService(ctx, host.ServiceHost(), store, nil, testAcme(t, settings, pebble, accountFile), settings)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestCertsRunOnPebbleKeepsTheChainAndTheReason(t *testing.T) {
	pebble := sidecartest.StartPebble(t, nil)
	settings := testAcmeSettings(pebble, nil)
	ctx := testAcmeContext(t)
	clock := sidecartest.NewFakeClock(time.Now().UTC().Truncate(time.Microsecond))
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	sidecartest.RegisterCertsBudgetTwins(host.Redis)
	store := sidecartest.NewFakeCertsStore(host.Redis.Faults())
	accountFile := testAccountFile(t, certsservice.CertsCaLetsEncrypt, time.Now(), "", "")
	service := testPebbleService(t, ctx, host, store, pebble, settings, accountFile)
	certs := &testCerts{t: t, ctx: ctx, clock: clock, host: host, store: store, settings: settings, service: service}

	compromised := newTestDevice(t, "k7pebble01")
	removed := newTestDevice(t, "k7pebble02")
	compromisedId := certs.accept(compromised)
	clock.Advance(time.Millisecond)
	removedId := certs.accept(removed)
	orders, err := service.RunOrders(ctx, sidecar.Id{})
	if err != nil {
		t.Fatal(err)
	}
	issued := slices.Clone(orders.Issued)
	slices.SortFunc(issued, func(a sidecar.Id, b sidecar.Id) int { return a.Cmp(b) })
	if !slices.Equal(issued, []sidecar.Id{compromisedId, removedId}) {
		t.Fatalf("orders %+v", orders)
	}

	// a restart, then the device's GET: the chain Pebble issued, for its names and on its key
	service = testPebbleService(t, ctx, host, store, pebble, settings, accountFile)
	status, err := service.OrderStatus(ctx, compromised.networkId, compromised.clientId, compromisedId)
	if err != nil || status.State != sidecar.TlsCertStateIssued {
		t.Fatalf("status %+v, %v", status, err)
	}
	leaf := testVerifyChain(t, pebble, status.Chain, compromised.identifierSet)
	if !compromised.tlsKey.PublicKey.Equal(leaf.PublicKey) {
		t.Fatal("the served chain is not on the device's key")
	}
	removedChain := certs.row(removedId).Chain
	testVerifyChain(t, pebble, removedChain, removed.identifierSet)

	// POST /tls/cert-revoke with key_compromise writes the reason and returns; the sweep finds the
	// other device removed
	if moved, err := store.TransitionCert(ctx, &certsservice.CertsTransition{
		CertId: compromisedId, From: []sidecar.TlsCertState{sidecar.TlsCertStateIssued}, To: sidecar.TlsCertStateRevoking, At: clock.Now(),
		RevocationReason: sidecar.TlsCertRevocationReasonKeyCompromise,
	}); err != nil || !moved {
		t.Fatalf("marking: %v, %v", moved, err)
	}
	if _, revoked := pebble.RevocationReason(status.Chain[0]); revoked {
		t.Fatal("Pebble holds a certificate revoked that no pass has taken to it")
	}
	source := newTestRevocationSource()
	source.set(removedId, certsservice.CertsRevocationCauseRemoval)

	// another restart before the sweep: the reason is the row's, not the process's
	service = testPebbleService(t, ctx, host, store, pebble, settings, accountFile)
	report, err := service.RunRevocations(ctx, source, nil)
	if err != nil || len(report.Revoked) != 2 || report.FailedCount != 0 || report.WaitingCount != 0 {
		t.Fatalf("revocations %+v, %v", report, err)
	}
	if reason, revoked := pebble.RevocationReason(status.Chain[0]); !revoked || reason != int(certsservice.CertsRevocationKeyCompromise) {
		t.Fatalf("Pebble holds the compromised certificate revoked %v with reason %d", revoked, reason)
	}
	if reason, revoked := pebble.RevocationReason(removedChain[0]); !revoked || reason != int(certsservice.CertsRevocationCessationOfOperation) {
		t.Fatalf("Pebble holds the removed device's certificate revoked %v with reason %d", revoked, reason)
	}
	for _, certId := range []sidecar.Id{compromisedId, removedId} {
		if row := certs.row(certId); row.State != sidecar.TlsCertStateRevoked || row.RevocationReason != "" || len(row.Chain) == 0 {
			t.Fatalf("a revoked row %+v", row)
		}
	}
}
