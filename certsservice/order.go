// POST /tls/cert-order's acceptance (§13.8, §13.15; D-TLS-6): a device's CSR and its key attestation,
// checked, then written as a queued row before anything else happens. certs never sees a private key:
// the CSR carries the device's public key and names, and the attestation binds that key and those names
// to the device's identity key (X1, R-TLS-4).
//
// What is refused costs nothing: no row, no budget unit and no CA call, since only the admission pass
// (queue.go) spends. The caller's grant is an input, so this package stays free of the gate's shape:
// TLS-M5-16's handler asks §8's gate and passes the answer, with the identity key the projection holds.
// Every refusal names its rule, never a value from the request (I-13).

package certsservice

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
)

var (
	// The caller holds no active §8 tls/ or smtp/ grant for the set.
	ErrCertsNotGranted = errors.New("no grant for the certificate's names")
	// The CSR does not parse, its signature does not verify, its key is not P-256, or its names are not
	// exactly the caller's set.
	ErrCertsCsr = errors.New("certificate request refused")
	// The attestation does not verify under the caller's identity key, or names another network,
	// sidecar, key or set.
	ErrCertsAttestation = errors.New("key attestation refused")
	// The request is not one a row can hold: no network, client or sidecar, no identity key or no set.
	ErrCertsRequest = errors.New("certificate order refused")
)

// One POST /tls/cert-order, as the handler resolved it. Everything but Args comes from the caller's token
// and the gate, never the body (§13.15).
type CertsOrderRequest struct {
	NetworkId sidecar.Id
	ClientId  sidecar.Id
	SidecarId sidecar.Id
	// §13.8's set the caller's grant and config give it, sidecar.TlsIdentifierSet's answer. The CSR must
	// name exactly these.
	IdentifierSet []string
	// The caller's Ed25519 identity key, from the projection the gate reads, never from the request.
	IdentityPublicKey []byte
	// Whether §8's gate found an active tls/ or smtp/ grant covering IdentifierSet for the caller.
	Granted bool
	Args    *sidecar.TlsCertOrderArgs
}

// What a CSR says, once checked.
type certsCheckedCsr struct {
	spkiSha256          [sha256.Size]byte
	identifierSetSha256 [sha256.Size]byte
}

// Parses and checks a CSR against the caller's set: its signature, a P-256 key and SANs exactly equal to
// the set, each once, with no other kind of name and no common name outside it.
func certsCheckCsr(csrDer []byte, identifierSet []string) (*certsCheckedCsr, error) {
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return nil, fmt.Errorf("%w: it does not parse", ErrCertsCsr)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: its signature does not verify", ErrCertsCsr)
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: its key is not P-256", ErrCertsCsr)
	}
	if 0 < len(csr.IPAddresses) || 0 < len(csr.EmailAddresses) || 0 < len(csr.URIs) {
		return nil, fmt.Errorf("%w: it names something other than DNS names", ErrCertsCsr)
	}
	names := slices.Clone(csr.DNSNames)
	slices.Sort(names)
	if len(slices.Compact(slices.Clone(names))) != len(names) {
		return nil, fmt.Errorf("%w: it names one name twice", ErrCertsCsr)
	}
	want := slices.Sorted(slices.Values(identifierSet))
	if !slices.Equal(names, want) {
		return nil, fmt.Errorf("%w: its names are not the caller's set", ErrCertsCsr)
	}
	if csr.Subject.CommonName != "" && !slices.Contains(want, csr.Subject.CommonName) {
		return nil, fmt.Errorf("%w: its common name is outside the set", ErrCertsCsr)
	}
	identifierSetSha256, err := sidecar.TlsIdentifierSetHash(names)
	if err != nil {
		return nil, fmt.Errorf("%w: its names are not a canonical set", ErrCertsCsr)
	}
	return &certsCheckedCsr{
		spkiSha256:          sha256.Sum256(csr.RawSubjectPublicKeyInfo),
		identifierSetSha256: identifierSetSha256,
	}, nil
}

// The DNS names a stored CSR asks for, which the admission pass reads for name holds.
func certsCsrNames(csrDer []byte) ([]string, error) {
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		return nil, err
	}
	return csr.DNSNames, nil
}

// The serial RFC 9773's certificate id names, as network_tls_cert.serial holds it: lowercase hex with
// no leading zeros. The id is base64url(AKI keyIdentifier) "." base64url(serial's DER content octets).
func certsAriSerial(certificateId string) (string, error) {
	_, serialText, found := strings.Cut(certificateId, ".")
	if !found {
		return "", errors.New("not an ARI certificate id")
	}
	serialBytes, err := base64.RawURLEncoding.DecodeString(serialText)
	if err != nil || len(serialBytes) == 0 {
		return "", errors.New("not an ARI certificate id")
	}
	return CertsSerialText(new(big.Int).SetBytes(serialBytes)), nil
}

// A new cert_id whose time is the service's clock's, so an order's time and the policy's agree on any
// clock: crypto/rand's id with its 48-bit millisecond timestamp set to now, the ULID layout
// connect/CODESTYLE.md describes.
func certsNewId(now time.Time) sidecar.Id {
	id := sidecar.NewId()
	ms := uint64(now.UnixMilli())
	for index := range 6 {
		id[index] = byte(ms >> (8 * (5 - index)))
	}
	return id
}

// The id one above id: its 80 entropy bits as a counter, carrying into the millisecond only when they
// overflow.
func certsIdAfter(id sidecar.Id) sidecar.Id {
	next := id
	for index := len(next) - 1; 0 <= index; index -= 1 {
		next[index] += 1
		if next[index] != 0 {
			break
		}
	}
	return next
}

// A cert_id above every one this service minted before, at its clock's millisecond where that is newer.
// The queue is read in id order and SetIssuedBefore compares ids, so one service's orders keep the order
// they were accepted in even within one millisecond. Ids of two processes in one millisecond have no
// order between them, as any two ULID sources have none (connect/CODESTYLE.md's identifiers).
func (self *CertsService) newCertId() sidecar.Id {
	id := certsNewId(self.clock.Now())
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if id.Cmp(self.lastCertId) <= 0 {
		id = certsIdAfter(self.lastCertId)
	}
	self.lastCertId = id
	return id
}

// An id's millisecond timestamp, the order time of a row.
func certsIdTime(id sidecar.Id) time.Time {
	var ms uint64
	for index := range 6 {
		ms = ms<<8 | uint64(id[index])
	}
	return time.UnixMilli(int64(ms)).UTC()
}

// Checks request and writes its row, queued, before anything else happens (§13.8), answering it. A
// request posted again for a key and set whose order is still under way answers that order's row, so a
// retry after a lost answer queues nothing twice. A replaces naming a live certificate of the same
// sidecar and set makes the order a renewal, which skips every limit; the replaced row takes the new
// one as its successor, since no column holds what an order replaces.
func (self *CertsService) Accept(ctx context.Context, request *CertsOrderRequest) (*sidecar.TlsCertOrderResult, error) {
	if request == nil || request.Args == nil || request.NetworkId == (sidecar.Id{}) || request.ClientId == (sidecar.Id{}) ||
		request.SidecarId == (sidecar.Id{}) || len(request.IdentityPublicKey) == 0 || len(request.IdentifierSet) == 0 {
		return nil, ErrCertsRequest
	}
	if !request.Granted {
		return nil, ErrCertsNotGranted
	}
	checked, err := certsCheckCsr(request.Args.Csr, request.IdentifierSet)
	if err != nil {
		return nil, err
	}
	if _, err := sidecar.VerifyTlsKeyAttestation(
		request.Args.Attestation,
		request.IdentityPublicKey,
		request.NetworkId,
		request.SidecarId,
		checked.spkiSha256,
		checked.identifierSetSha256,
	); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCertsAttestation, err)
	}

	callCtx, cancel := self.callContext(ctx)
	defer cancel()
	now := self.clock.Now()
	open, err := self.store.FindOpenOrder(callCtx, request.NetworkId, request.SidecarId, checked.spkiSha256[:], checked.identifierSetSha256[:])
	if err != nil {
		return nil, err
	}
	if open != nil {
		return &sidecar.TlsCertOrderResult{CertId: open.CertId, State: open.State, RetryAfterMs: uint32(self.settings.OrderRetryAfter.Milliseconds())}, nil
	}
	// a replaces that names no live certificate of this sidecar's set is an ordinary order, under the
	// limits, never a refusal: the device learns of the row's loss later (TLS reading 7)
	var replaced *sidecar.TlsCertRecord
	if request.Args.Replaces != "" {
		if serial, serialErr := certsAriSerial(request.Args.Replaces); serialErr == nil {
			live, findErr := self.store.FindLiveCertBySerial(callCtx, request.NetworkId, serial, now)
			if findErr != nil {
				return nil, findErr
			}
			if live != nil && live.SidecarId == request.SidecarId && bytes.Equal(live.IdentifierSetSha256, checked.identifierSetSha256[:]) &&
				live.SuccessorCertId == (sidecar.Id{}) {
				replaced = live
			}
		}
	}
	row := &sidecar.TlsCertRecord{
		CertId:              self.newCertId(),
		NetworkId:           request.NetworkId,
		ClientId:            request.ClientId,
		SidecarId:           request.SidecarId,
		IdentifierSetSha256: checked.identifierSetSha256[:],
		SpkiSha256:          checked.spkiSha256[:],
		Attestation:         bytes.Clone(request.Args.Attestation),
		Csr:                 bytes.Clone(request.Args.Csr),
		State:               sidecar.TlsCertStateQueued,
	}
	testHookBarrier("certs.accept.write", row.CertId.String())
	if err := self.store.InsertCert(callCtx, row); err != nil {
		return nil, err
	}
	if replaced != nil {
		if _, err := self.store.SetSuccessor(callCtx, replaced.CertId, row.CertId); err != nil {
			return nil, err
		}
	}
	return &sidecar.TlsCertOrderResult{CertId: row.CertId, State: row.State, RetryAfterMs: uint32(self.settings.OrderRetryAfter.Milliseconds())}, nil
}

// A serial as network_tls_cert.serial holds it: lowercase hex with no leading zeros, the form an ARI
// certificate id's serial compares in. TLS-M5-15 writes serials through this.
func CertsSerialText(serial *big.Int) string {
	return serial.Text(16)
}
