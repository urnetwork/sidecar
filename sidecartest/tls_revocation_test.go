// §22.7's revocation suite for §13 (TLS-M5-25; I-15, R-TLS-8, §13.8's Revocation row, X10), on the composed world
// (tls_suite_test.go): a removed device's certificate is revoked and its sockets end. The listener device holds a
// certificate certs ordered from Pebble for the network's set and a tls/443/blog lease a visitor reaches through
// tlsedge; the network's owner revokes the device in the log. The revocation's load queues the network's sweep, which
// ends its lease with SOCKET_HINT_REVOKED, so tlsedge's next visitor gets internal_error from a Find that answers
// no_listener and the device's next page is refused; and certs' revocation sweep, whose source reads the same verified
// state and finds the device no longer admitted, revokes its certificate at the CA with cessationOfOperation, the row
// ending revoked with its chain kept (cert-1).
//
// Not here: an open splice of the revoked device ends when connect closes its clients (within 90 s) or its listener
// resets its streams (socket_admission.go), which the in-memory stream does not carry.

package sidecartest_test

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/socketsservice"
)

// certs' revocation source on the world's own verified state: a row whose sidecar the network's newest state no longer
// admits is removed, as server's work.TlsCertRevocations reads it from the projection's rows.
type tlsRevocationSource struct {
	edge *tlsSuiteEdge
}

func (self *tlsRevocationSource) RevocationCauses(ctx context.Context, candidates []*certsservice.CertsRevocationCandidate) (map[sidecar.Id]certsservice.CertsRevocationCause, error) {
	view, err := self.edge.gate.View(self.edge.networkId)
	if err != nil {
		return nil, err
	}
	causes := map[sidecar.Id]certsservice.CertsRevocationCause{}
	for _, candidate := range candidates {
		if candidate.Cert.NetworkId != sidecar.Id(self.edge.networkId) {
			continue
		}
		if _, admitted := view.IdentityKey(connect.Id(candidate.Cert.SidecarId)); !admitted {
			causes[candidate.Cert.CertId] = certsservice.CertsRevocationCauseRemoval
		}
	}
	return causes, nil
}

func TestTlsRevocationEndsARemovedDevicesCertificateAndSockets(t *testing.T) {
	edge := newTlsSuiteEdge(t)
	certs := newTlsSuiteCerts(t)
	identifierSet, err := sidecar.TlsIdentifierSet(tlsSuiteRoot, edge.label, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	device := certs.issue(edge.listener.device, sidecar.Id(edge.networkId), sidecar.Id(edge.listener.clientId), identifierSet)
	source := &tlsRevocationSource{edge: edge}
	// before the removal the sweep finds nothing to revoke, and a visitor reaches the listener
	report, err := certs.service.RunRevocations(certs.ctx, source, nil)
	if err != nil || len(report.Marked) != 0 || len(report.Revoked) != 0 {
		t.Fatalf("a sweep before the removal %+v, %v", report, err)
	}
	serverName := edge.serverName("blog")
	edge.handshake(serverName, []string{"http/1.1"}, nil)
	if stream := edge.dialer.awaitOpened(t); stream.ticket.GetName() != "tls/443/blog" {
		t.Fatal("the visitor reached another name")
	}
	// the publish's policy was an entry that may narrow, so its load swept the network; a network is swept at most
	// once per SweepMinInterval, so the clock moves past it, as it would before any removal a minute later
	tlsSuiteAwait(t, "the publish's sweep", edge.engine.Sweeps, 0)
	edge.net.Clock().Advance(socketsservice.DefaultSocketsSettings().SweepMinInterval)

	// the network's owner revokes the member's lost device
	edge.admission.MustLand(edge.admission.Sign(edge.admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_REVOKE,
		edge.admission.Revocation(edge.listener.device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	sweeps, _ := edge.engine.Sweeps()
	count, _ := edge.gate.Loads()
	edge.engine.ProjectionChanged(edge.networkId)
	edge.awaitLoadsPast(count)
	edge.awaitSweepsPast(sweeps)

	if hints := socketSuiteRevokedHints(t, edge.socketSuiteWorld, edge.listener.clientId); hints != 1 {
		t.Fatalf("%d revocation hints for the device's one lease", hints)
	}
	if code, _ := edge.edgeFind("tls/443/blog"); code != sidecar.SocketErrorCodeNoListener {
		t.Fatalf("the edge's Find of the removed device's host answered %q", code)
	}
	dials := edge.dialer.dials.Load()
	refused := edge.awaitHandshake(edge.handshake(serverName, []string{"http/1.1"}, nil))
	if refused.err == nil || !strings.Contains(refused.err.Error(), "internal error") || edge.dialer.dials.Load() != dials+1 {
		t.Fatalf("a visitor of the removed device's host: %v after %d Finds", refused.err, edge.dialer.dials.Load()-dials)
	}
	if status := edge.nextStatus("tls/443/blog"); status == sidecar.SocketRegistrationStatusOk {
		t.Fatal("the removed device's next page was admitted")
	}

	// certs' sweep revokes the device's certificate at the CA
	report, err = certs.service.RunRevocations(certs.ctx, source, nil)
	if err != nil || !slices.Equal(report.Revoked, []sidecar.Id{device.certId}) || report.FailedCount != 0 {
		t.Fatalf("the sweep after the removal %+v, %v", report, err)
	}
	if reason, revoked := certs.pebble.RevocationReason(device.chain[0]); !revoked || reason != int(certsservice.CertsRevocationCessationOfOperation) {
		t.Fatalf("Pebble holds the removed device's certificate revoked %v with reason %d", revoked, reason)
	}
	row, err := certs.store.GetCert(certs.ctx, device.certId)
	if err != nil || row.State != sidecar.TlsCertStateRevoked || len(row.Chain) == 0 {
		t.Fatalf("the revoked row %+v, %v", row, err)
	}
}
