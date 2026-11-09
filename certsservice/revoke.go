// Revocation (§13.8, I-15): why a certificate goes, the RFC 5280 reason a CA is told, and the row's way
// from issued through revoking to revoked. LE ended OCSP, so a revocation reaches visitors only through
// CRLs, and the kill switch and 45-day lifetimes carry the load; certs still revokes each, because a
// removed device's certificate must not stay good for weeks (I-15).
//
// A revocation needs the certificate itself (RFC 8555 §7.6), which cert-1 does not keep for a
// URnetwork-zone row (tls-m5-05-cert-row-values): RevokeIssued takes the leaf from its caller, and until
// a chain is kept the revocation sweep (TLS-M5-17) has none to give, so such a row waits in revoking.

package certsservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"

	"github.com/urnetwork/sidecar"
)

// Why a certificate is revoked, as §13.8 lists the causes.
type CertsRevocationCause string

const (
	// A device's certificate on its removal (§5).
	CertsRevocationCauseRemoval CertsRevocationCause = "removal"
	// A network's on takedown (§21.6).
	CertsRevocationCauseTakedown CertsRevocationCause = "takedown"
	// A network's on its deletion.
	CertsRevocationCauseDeletion CertsRevocationCause = "deletion"
	// An alias's when §12.5 retires it (I-14).
	CertsRevocationCauseAliasRetired CertsRevocationCause = "alias_retired"
	// The key is compromised, by the device's or an admin's word.
	CertsRevocationCauseKeyCompromise CertsRevocationCause = "key_compromise"
)

// The reason a CA is told for cause: keyCompromise on compromise, cessationOfOperation when the names
// stop being served, and none for a cause this build does not know.
func CertsRevocationReasonFor(cause CertsRevocationCause) CertsRevocationReason {
	switch cause {
	case CertsRevocationCauseKeyCompromise:
		return CertsRevocationKeyCompromise
	case CertsRevocationCauseRemoval, CertsRevocationCauseTakedown, CertsRevocationCauseDeletion, CertsRevocationCauseAliasRetired:
		return CertsRevocationCessationOfOperation
	}
	return CertsRevocationUnspecified
}

var (
	// A leaf that is not the row's certificate.
	ErrCertsLeafMismatch = errors.New("the leaf is not the row's certificate")
	// A row in no state a revocation starts from: not issued, or ended.
	ErrCertsNotRevocable = errors.New("certificate cannot be revoked")
)

// Revokes certId's certificate, leaf, at its CA with reason: the row moves issued to revoking before the
// CA is asked, and to revoked once the CA takes it, so a pass that dies between asks again. A leaf
// whose serial or key is not the row's is refused, so no other certificate is revoked by mistake.
func (self *CertsService) RevokeIssued(ctx context.Context, certId sidecar.Id, leaf []byte, reason CertsRevocationReason) error {
	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	row, err := self.store.GetCert(callCtx, certId)
	if err != nil {
		return err
	}
	certificate, err := x509.ParseCertificate(leaf)
	if err != nil {
		return ErrCertsLeafMismatch
	}
	spkiSha256 := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	if CertsSerialText(certificate.SerialNumber) != row.Serial || !bytes.Equal(spkiSha256[:], row.SpkiSha256) {
		return ErrCertsLeafMismatch
	}
	switch row.State {
	case sidecar.TlsCertStateRevoked:
		return nil
	case sidecar.TlsCertStateIssued, sidecar.TlsCertStateRevoking:
	default:
		return ErrCertsNotRevocable
	}
	// a revoking row is a pass that died before the CA answered: asked again
	moved, err := self.store.TransitionCert(callCtx, &CertsTransition{
		CertId: certId,
		From:   []sidecar.TlsCertState{sidecar.TlsCertStateIssued, sidecar.TlsCertStateRevoking},
		To:     sidecar.TlsCertStateRevoking,
	})
	if err != nil {
		return err
	}
	if !moved {
		return ErrCertsNotRevocable
	}
	testHookBarrier("certs.revoke.before", certId.String())
	// the CA call runs on the caller's ctx, not the store's bound: a CA may take longer than a row
	if err := self.acme.Revoke(ctx, CertsCa(row.Ca), leaf, reason); err != nil {
		return err
	}
	testHookBarrier("certs.revoke.after", certId.String())
	callCtx, cancel = self.callContext(ctx)
	defer cancel()
	_, err = self.store.TransitionCert(callCtx, &CertsTransition{
		CertId: certId,
		From:   []sidecar.TlsCertState{sidecar.TlsCertStateRevoking},
		To:     sidecar.TlsCertStateRevoked,
	})
	return err
}
