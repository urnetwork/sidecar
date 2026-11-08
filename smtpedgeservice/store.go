// What smtpedge keeps in Postgres, behind interfaces so the engine imports no server package (§4.5).
// server implements them (SMTP-M5-06's report tables, SMTP-M9-18's MG9), and
// sidecartest.FakeSmtpEdgeStore stands in until then, held to the same promises by
// sidecartest.RunSmtpEdgeStoreSuite.
//
// Every call is batched and off the connection path (§14.9): the preamble path never touches
// Postgres (§22.5), so a preamble waits on none of these.

package smtpedgeservice

import (
	"context"
	"errors"
	"time"

	"github.com/urnetwork/sidecar"
)

// A FindSends key that names nothing but a time range, which would scan the whole send log.
var ErrSmtpJoinKeyEmpty = errors.New("smtp join key names no send")

// §14.9's six methods, verbatim (plan-SMTP-small-readings#17). Safe for concurrent use.
type SmtpEdgeStore interface {
	// Writes send records. A record whose (SmtpSendDay(StartTime), SendId) is already stored is
	// skipped, so a retried batch inserts nothing twice.
	InsertSends(ctx context.Context, sends []*SmtpSendRecord) error
	// Every stored send matching key, oldest first. ErrSmtpJoinKeyEmpty when key is not selective.
	FindSends(ctx context.Context, key *SmtpJoinKey) ([]*SmtpSendRecord, error)
	InsertComplaint(ctx context.Context, complaint *SmtpComplaint) error
	// Stores a report's counts once per (Reporter, ReportId): inserted is false, and nothing changes,
	// when that pair is already stored.
	InsertAggregate(ctx context.Context, report *SmtpAggregateReport) (inserted bool, err error)
	// Writes a halt, replacing one stored under the same HaltId.
	SetHalt(ctx context.Context, halt *SmtpHalt) error
	// Every halt still holding at the store's own time, by start.
	ActiveHalts(ctx context.Context) ([]*SmtpHalt, error)
}

// What reports need beyond §14.9's six (plan-SMTP-small-readings#17). Safe for concurrent use.
type SmtpReportLookups interface {
	// The key published under selector at domain, retired ones included, compared without case. nil
	// and no error when there is none.
	FindDkimKey(ctx context.Context, selector string, domain string) (*SmtpDkimKey, error)
	// The proven recipients of the network's sends started at or after since, for §14.8's rates.
	RecipientCount(ctx context.Context, networkId sidecar.Id, since time.Time) (uint64, error)
}
