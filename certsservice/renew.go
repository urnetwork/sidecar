// Renewal (§13.8): ARI (RFC 9773) when the CA gave a window, else two thirds into the certificate's
// validity, LE's tlsserver renewing at day 30 of 45. A renewal orders the row's stored CSR, so a device
// that is offline still renews, and its row is the old one's successor, which the admission pass reads
// as a renewal past every limit (queue.go).
//
// The CA's own exemption, `replaces`, names the old certificate by its RFC 9773 id, which needs the
// leaf's authority key id. A row keeps the chain its CA issued (cert-1; QD-741), so a renewal certs
// queues on its own carries replaces, and the renewal pass asks the CA for the window again through
// the certificate's life (run.go). A row with no chain, one issued before rows kept theirs, renews
// with no replaces, which its CA counts as a repeated order, on the window read when it issued.

package certsservice

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
)

// When row renews: a point of its ARI window, the same for every reader since it is drawn from the
// row's id, uniform across rows as RFC 9773 §4.2 asks; else fraction into its validity. Zero for a row
// with no validity.
func CertsRenewalTime(row *sidecar.TlsCertRecord, fraction float64) time.Time {
	if !row.AriWindowStart.IsZero() && row.AriWindowStart.Before(row.AriWindowEnd) {
		window := row.AriWindowEnd.Sub(row.AriWindowStart)
		// the id's entropy, past its millisecond timestamp, picks the point
		draw := binary.BigEndian.Uint64(row.CertId[8:16])
		return row.AriWindowStart.Add(time.Duration(draw % uint64(window)))
	}
	if row.NotBefore.IsZero() || !row.NotBefore.Before(row.NotAfter) {
		return time.Time{}
	}
	lifetime := row.NotAfter.Sub(row.NotBefore)
	return row.NotBefore.Add(time.Duration(float64(lifetime) * fraction))
}

// Whether row should renew at now: issued, not replaced yet, still valid, and past its renewal time.
func (self *CertsService) RenewalDue(row *sidecar.TlsCertRecord, now time.Time) bool {
	if row.State != sidecar.TlsCertStateIssued || row.SuccessorCertId != (sidecar.Id{}) || !now.Before(row.NotAfter) {
		return false
	}
	renewalTime := CertsRenewalTime(row, self.settings.RenewalLifetimeFraction)
	return !renewalTime.IsZero() && !now.Before(renewalTime)
}

// A row that cannot renew: not issued, expired, or replaced already.
var ErrCertsNotRenewable = errors.New("certificate cannot renew")

// Queues certId's renewal: a new row with its CSR, attestation, key and set, written queued, and the
// old row linked to it as its successor, so the device need not be online. The attestation is the
// device's, signed when it ordered: it binds the same key and set, which is all the new row asks of
// it. A row with a successor already queues nothing and answers ErrCertsNotRenewable.
func (self *CertsService) QueueRenewal(ctx context.Context, certId sidecar.Id) (*sidecar.TlsCertRecord, error) {
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	now := self.clock.Now()
	row, err := self.store.GetCert(callCtx, certId)
	if err != nil {
		return nil, err
	}
	if row.State != sidecar.TlsCertStateIssued || row.SuccessorCertId != (sidecar.Id{}) || !now.Before(row.NotAfter) || len(row.Csr) == 0 {
		return nil, ErrCertsNotRenewable
	}
	renewal := &sidecar.TlsCertRecord{
		CertId:              self.newCertId(),
		NetworkId:           row.NetworkId,
		ClientId:            row.ClientId,
		SidecarId:           row.SidecarId,
		IdentifierSetSha256: row.IdentifierSetSha256,
		SpkiSha256:          row.SpkiSha256,
		Attestation:         row.Attestation,
		Csr:                 row.Csr,
		State:               sidecar.TlsCertStateQueued,
		StateTime:           now,
	}
	if err := self.store.InsertCert(callCtx, renewal); err != nil {
		return nil, err
	}
	linked, err := self.store.SetSuccessor(callCtx, row.CertId, renewal.CertId)
	if err != nil {
		return nil, err
	}
	if !linked {
		// another pass renewed it first: this row goes, so the queue holds one renewal
		if _, err := self.store.TransitionCert(callCtx, &CertsTransition{
			CertId: renewal.CertId,
			From:   []sidecar.TlsCertState{sidecar.TlsCertStateQueued},
			To:     sidecar.TlsCertStateFailed,
			At:     now,
		}); err != nil {
			return nil, err
		}
		return nil, ErrCertsNotRenewable
	}
	return renewal, nil
}
