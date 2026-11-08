// What mxedge keeps in Postgres, behind an interface so the engine imports no server package (§4.5).
// server implements it (MAIL-M7-21's model.NewMxEdgeStore), and sidecartest.FakeMxEdgeStore stands in
// until then.

package mxedgeservice

import (
	"context"
	"time"

	"github.com/urnetwork/sidecar"
)

// One mail_connection_record row (§15.15; §2.8 mx-2): what a session that named a network leaves. No
// sender address and no burner label, so neither has a field here.
type MxConnectionRecord struct {
	// The receiving network.
	NetworkId sidecar.Id
	StartTime time.Time
	// Bytes the session passed, both ways.
	ByteCount int64
	// A word from a closed set, as a metric's result is.
	Result string
}

// Called only from batch goroutines, off the connection path, as §14.9's store is, so no session ever
// waits on Postgres (I-12). Safe for concurrent use.
type MxEdgeStore interface {
	// Whether the tables answer: readiness's §19.4 column.
	Ping(ctx context.Context) error
	// One batch of mail_connection_record rows.
	InsertConnectionRecords(ctx context.Context, records []*MxConnectionRecord) error
}
