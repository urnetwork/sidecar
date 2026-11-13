// What certs keeps in Postgres, network_tls_cert (§13.8, §13.15; cert-1), behind an interface so this
// engine imports no server package (§4.5). server implements it (TLS-M5-16's model.NewCertsStore), and
// sidecartest.FakeCertsStore stands in until then; sidecartest.RunCertsStoreSuite holds both to these
// rules.
//
// A row is sidecar.TlsCertRecord, cert-1's fields and no other: an order's time is its cert_id's, which
// certs mints on its own clock (certsNewId), and a row's kind is read from what it links to, never
// stored. A store keeps no clock: every time comes from the caller, the time of a row's state among
// them (state_time), which a row is written with and each change of state sets. Every method is safe
// for concurrent use, and none is called on a connection's path.
//
// Two values wait in a row between the steps that need them (cert-1; QD-741): the chain a CA issued,
// from its issuance until ChainRetention past the certificate's expiry or revocation, which answers a
// device's GET after a restart; and a requested revocation's reason, from the request until the CA
// has taken it, which a store holds only while the row is revoking.

package certsservice

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
)

var (
	// No row has that id, or the caller may not see it.
	ErrCertsNotFound = errors.New("certificate not found")
	// A row with that id exists already.
	ErrCertsConflict = errors.New("certificate row exists")
	// A row written, or a state changed, with no time: a store refuses it, since a revoked or failed
	// row's 30 days count from that time and a zero would end them at once.
	ErrCertsStateTime = errors.New("certificate row needs the time of its state")
)

// One state change of a row, applied only while the row is in one of From, so two passes cannot both
// move it. Every other field is written when set: an empty string, a zero time or no chain leaves the
// column as it is.
type CertsTransition struct {
	CertId sidecar.Id
	From   []sidecar.TlsCertState
	To     sidecar.TlsCertState
	// The caller's clock, which becomes the row's state time when To is not the state it was in: a
	// transition that keeps the state keeps its time. Required, or ErrCertsStateTime.
	At time.Time
	// Set when an order reaches its CA.
	Ca         CertsCa
	AccountUri string
	Profile    string
	// Set when it issues: lowercase hex, the validity, and the chain, each certificate in DER, leaf
	// first.
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	Chain     [][]byte
	// Set when the CA gives one (RFC 9773).
	AriWindowStart time.Time
	AriWindowEnd   time.Time
	// What the CA is to be told, set with To revoking. A row keeps a reason only while it is revoking:
	// a transition to any other state clears it, and one set with another To is not written.
	RevocationReason sidecar.TlsCertRevocationReason
}

type CertsStore interface {
	// Writes a new row. A row with its id already is ErrCertsConflict, and one with no StateTime
	// ErrCertsStateTime.
	InsertCert(ctx context.Context, row *sidecar.TlsCertRecord) error
	// The row, or ErrCertsNotFound.
	GetCert(ctx context.Context, certId sidecar.Id) (*sidecar.TlsCertRecord, error)
	// The network's rows, oldest first: GET /tls/certs.
	ListNetworkCerts(ctx context.Context, networkId sidecar.Id) ([]*sidecar.TlsCertRecord, error)
	// The sidecar's newest row for this key and set still under way (queued, ordering or waiting_dns),
	// nil when none: a request posted again finds its first row.
	FindOpenOrder(ctx context.Context, networkId sidecar.Id, sidecarId sidecar.Id, spkiSha256 []byte, identifierSetSha256 []byte) (*sidecar.TlsCertRecord, error)
	// The network's issued row with this serial whose validity has not ended at now, nil when none: the
	// certificate an order replaces (RFC 9773's replaces names its serial).
	FindLiveCertBySerial(ctx context.Context, networkId sidecar.Id, serial string, now time.Time) (*sidecar.TlsCertRecord, error)
	// The row whose successor certId is, nil when none.
	GetPredecessor(ctx context.Context, certId sidecar.Id) (*sidecar.TlsCertRecord, error)
	// Whether a certificate was issued for the set before the row beforeCertId: any older row of the set
	// with a serial. What makes an order a repeated set, not a new one.
	SetIssuedBefore(ctx context.Context, identifierSetSha256 []byte, beforeCertId sidecar.Id) (bool, error)
	// The set's rows that reached ca, whose order time (their id's) is at or after since: the
	// repeated-set rule's history.
	ListSetOrders(ctx context.Context, identifierSetSha256 []byte, ca CertsCa, since time.Time) ([]*sidecar.TlsCertRecord, error)
	// The rows that reached ca, are still under way (ordering, waiting_dns) or were issued with a
	// not_before at or after since, and whose set had no certificate issued before them: what <root>'s
	// budget at ca counts, which rebuilds a lost budget key (budget.go).
	ListNewSetOrders(ctx context.Context, ca CertsCa, since time.Time) ([]*sidecar.TlsCertRecord, error)
	// Whether the client is an ephemeral sidecar's (CI, cloud agents; network_client_owner.ephemeral),
	// which orders from GTS and ZeroSSL ahead of LE (D-TLS-7). An unknown client is not.
	ClientEphemeral(ctx context.Context, clientId sidecar.Id) (bool, error)
	// Queued rows after afterCertId, oldest first, at most count: the admission pass's cursor.
	ListQueued(ctx context.Context, afterCertId sidecar.Id, count int) ([]*sidecar.TlsCertRecord, error)
	// Rows in one of states after afterCertId, oldest first, at most count: the chains' cursors (run.go)
	// over what is under way at a CA (ordering, waiting_dns), what is issued, and what waits for its CA
	// to revoke it (revoking). No states, or a count that is not positive, reads nothing.
	ListInStates(ctx context.Context, states []sidecar.TlsCertState, afterCertId sidecar.Id, count int) ([]*sidecar.TlsCertRecord, error)
	// Applies transition while the row is in one of its From states. Returns whether it applied. A
	// transition with no At is ErrCertsStateTime.
	TransitionCert(ctx context.Context, transition *CertsTransition) (bool, error)
	// Links a row to the row that took over from it, unless it has a successor already. Returns whether
	// it linked.
	SetSuccessor(ctx context.Context, certId sidecar.Id, successorCertId sidecar.Id) (bool, error)
	// Deletes the rows that ended before before (cert-1's ttl; QD-742): a revoked or failed row whose
	// state time is before it, and a row in any other state whose certificate's validity ended before
	// it. A row with neither, an order still on its way, stays. Returns how many went.
	PurgeEnded(ctx context.Context, before time.Time) (int, error)
	// Drops the chain of each row whose certificate ended before before, keeping the row: a revoked
	// row whose state time is before it, and a row in any other state whose validity ended before it
	// (cert-1's "issued chains until 30 d after expiry or revocation"). Returns how many rows lost one.
	PurgeChains(ctx context.Context, before time.Time) (int, error)
}
