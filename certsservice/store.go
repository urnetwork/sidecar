// What certs keeps in Postgres, network_tls_cert (§13.8, §13.15; cert-1), behind an interface so this
// engine imports no server package (§4.5). server implements it (TLS-M5-16's model.NewCertsStore), and
// sidecartest.FakeCertsStore stands in until then; sidecartest.RunCertsStoreSuite holds both to these
// rules.
//
// A row is sidecar.TlsCertRecord, cert-1's fields and no other: an order's time is its cert_id's, which
// certs mints on its own clock (certsNewId), and a row's kind is read from what it links to, never
// stored. A store keeps no clock: every time comes from the caller. Every method is safe for
// concurrent use, and none is called on a connection's path.

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
)

// One state change of a row, applied only while the row is in one of From, so two passes cannot both
// move it. Every other field is written when set: an empty string or a zero time leaves the column as
// it is.
type CertsTransition struct {
	CertId sidecar.Id
	From   []sidecar.TlsCertState
	To     sidecar.TlsCertState
	// Set when an order reaches its CA.
	Ca         CertsCa
	AccountUri string
	Profile    string
	// Set when it issues: lowercase hex, and the validity.
	Serial    string
	NotBefore time.Time
	NotAfter  time.Time
	// Set when the CA gives one (RFC 9773).
	AriWindowStart time.Time
	AriWindowEnd   time.Time
}

type CertsStore interface {
	// Writes a new row. A row with its id already is ErrCertsConflict.
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
	// Applies transition while the row is in one of its From states. Returns whether it applied.
	TransitionCert(ctx context.Context, transition *CertsTransition) (bool, error)
	// Links a row to the row that took over from it, unless it has a successor already. Returns whether
	// it linked.
	SetSuccessor(ctx context.Context, certId sidecar.Id, successorCertId sidecar.Id) (bool, error)
	// Deletes the rows whose certificate's validity ended before before, in any state: an expired row 30
	// days past its end (cert-1), and a revoked one no later. A failed row, and a revoked one whose
	// validity has not ended, have no time here to count from and stay until
	// tls-m5-14-cert-row-end-time gives them one. Returns how many went.
	PurgeEnded(ctx context.Context, before time.Time) (int, error)
}
