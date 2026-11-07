// The two seams every other part of §12 codes against. DnsStore is the only way an engine reaches
// §12.14's tables and {dns}serial:<root>, and DnsFeed the only way an edge reaches an API block. Each
// has a fake in sidecartest, and sidecartest.RunDnsStoreSuite holds the fake and dnshost.Store to
// these same promises (D-TEST-2).
//
// An edge is given a DnsFeed and never a DnsStore, so it has no way to reach Postgres (I-12).

package dnsservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// How far above every serial it may have missed a restore lands (§12.6). 2^24 is well under the 2^31
// RFC 1982 allows a jump. A protocol value: a store and a test must use the same.
const DnsRestoreSerialJump uint64 = 16 * 1024 * 1024

var (
	// No dns_root row names this root.
	ErrDnsRootUnknown = errors.New("dns root unknown")
	// dns_root.restoring is set: every write answers 503 and takes no serial (§12.6).
	ErrDnsRestoring = errors.New("dns root restoring")
	// CommitRestore on a root whose restoring is not set.
	ErrDnsNotRestoring = errors.New("dns root not restoring")
	// CommitRestore for another incident than the one this restoring already committed.
	ErrDnsRestoreIncident = errors.New("dns restore committed by another incident")
	// A write's ExpectVersion is not the zone's version, and nothing was written.
	ErrDnsVersionConflict = errors.New("dns zone version conflict")
	// A write with nothing in it, which would take a serial for no change.
	ErrDnsWriteEmpty = errors.New("dns write empty")
)

// What one read of dns_root says. A restore's life across it: SetRestoring on, then CommitRestore,
// then SetRestoring off.
type DnsRootState struct {
	Root string
	// The serial of the last committed write or restore.
	Serial uint64
	// Where the last restore landed, zero before any. Every serial at or below it may be gone from
	// what an edge serves, so GET /dns/ready answers stale for it (§12.6).
	RestoreSerial uint64
	// Writes answer 503. Set as the dumps load and cleared once every running NS serves
	// RestoreSerial.
	Restoring bool
	// The incident of the restore transaction that ran since Restoring was set. nil while Restoring
	// has yet to reach that transaction, when a reload is not yet answered (plan reading 8).
	RestoreIncidentId *sidecar.Id
}

// What one read of the journal found.
type DnsJournalRead struct {
	// Rows above the caller's serial, in serial order with no hole. Empty when Gap is true.
	Rows []DnsJournalRow
	// The root's serial as this was read. Above the last row when the limit stopped the read.
	Serial uint64
	// The journal cannot continue from the caller's serial: it is below Serial and no row follows
	// it, after a 7-day purge or a restore. A caller at or above Serial is never in a gap, since after
	// a Postgres restore edges are ahead of the database (plan reading 8).
	Gap bool
}

// One write through §12.6's one transaction: it takes one serial and one journal row, or nothing
// happens.
type DnsZoneWrite struct {
	Root string
	// The zone this changes, whose version moves to the new serial. Zero for <root>'s own records,
	// which no network holds.
	NetworkId sidecar.Id
	// When set, the write goes ahead only while the zone's version equals this: the record API's
	// compare-and-swap (plan reading 3).
	ExpectVersion *uint64
	Upserts       []DnsRecordSet
	Deletes       []DnsRecordKey
}

// The row this write commits at serial.
func (self *DnsZoneWrite) Row(serial uint64) *DnsJournalRow {
	return &DnsJournalRow{
		Format:  DnsFormat,
		Root:    self.Root,
		Serial:  serial,
		Upserts: self.Upserts,
		Deletes: self.Deletes,
	}
}

// Whether this write could commit, by the rules every store holds it to. A write that fails this
// takes no serial.
func (self *DnsZoneWrite) Validate() error {
	if len(self.Upserts) == 0 && len(self.Deletes) == 0 {
		return fmt.Errorf("%w: %s", ErrDnsWriteEmpty, self.Root)
	}
	// any serial above zero reads alike
	return self.Row(1).Validate()
}

// §12.14's tables and {dns}serial:<root>, as an engine sees them. Every method is safe for concurrent
// use, and none may be called with a state lock held. A root's name is canonical, as settings give it.
// The serial never lowers, and a write that returns an error other than a transport's took no serial.
type DnsStore interface {
	// Adds root's dns_root row at serial zero, and leaves an existing one as it is.
	EnsureRoot(ctx context.Context, root string) error
	// One read of the root's row.
	RootState(ctx context.Context, root string) (*DnsRootState, error)
	// Rows above after, at most limit, which must be positive. See DnsJournalRead.
	Journal(ctx context.Context, root string, after uint64, limit int) (*DnsJournalRead, error)
	// Every row at the current serial, as one transaction sees them, so a write landing during the
	// read changes nothing it returns. The caller closes what comes back.
	Snapshot(ctx context.Context, root string) (DnsSnapshotRows, error)
	// §12.6's transaction: under the root's lock, ErrDnsRestoring while restoring, then serial+1,
	// the rows, one journal row and the zone's version, committed together. After the commit it raises
	// {dns}serial:<root>, whose failure loses nothing, since the feed rereads the journal at the end
	// of each hold. Returns the serial taken.
	Write(ctx context.Context, write *DnsZoneWrite) (serial uint64, err error)
	// The serial of a zone's last write, or zero for one never written (plan reading 3). A restore's
	// jump outdates every earlier one, so a stale compare-and-swap cannot collide.
	ZoneVersion(ctx context.Context, root string, networkId sidecar.Id) (version uint64, err error)
	// Deletes journal rows committed before before, oldest first, leaving a gap readers report
	// (§12.14's 7 days). Returns how many went.
	PurgeJournal(ctx context.Context, root string, before time.Time) (purgedCount int, err error)
	// Sets or clears dns_root.restoring (§19.10). Setting it forgets the last restore's incident, so a
	// reload waits for this restore's own transaction.
	SetRestoring(ctx context.Context, root string, restoring bool) error
	// §12.6's restore transaction: serial and restore_serial become the highest of the restored
	// serial, observedSerial and {dns}serial:<root>, plus DnsRestoreSerialJump, recording incidentId
	// and raising the key. Run again for the incident it recorded, it changes nothing and answers the
	// same serial, so a crash after it reruns to the same result. ErrDnsNotRestoring unless restoring,
	// and ErrDnsRestoreIncident for a second incident in one restoring.
	CommitRestore(ctx context.Context, root string, incidentId sidecar.Id, observedSerial uint64) (restoreSerial uint64, err error)
	// Keeps an edge's diff for the restore step's lists.
	RecordReloadDiff(ctx context.Context, diff *DnsReloadDiff) error
	// Every diff kept for root, oldest first.
	ReloadDiffs(ctx context.Context, root string) ([]*DnsReloadDiff, error)
	// {dns}serial:<root>: the last serial raised, zero when the key is absent. Soft state, so never
	// the root's serial for anything but a wake and the restore's max.
	RaisedSerial(ctx context.Context, root string) (serial uint64, err error)
	// Closes at the next raise this process sees, through the host's one shared key-event subscriber
	// and never per caller (server/model/peer_model.go:32-37). An edge, as a monitor's channel is:
	// take it immediately before reading the store and take a new one after it fires. A raise can be
	// lost, so a caller rereads at the end of each hold too.
	SerialRaised(root string) <-chan struct{}
}

// §12.6's three feed routes, as an edge sees them: over HTTP from DNS-M5-08's client, or through
// sidecartest's fake. Every method is safe for concurrent use, and none may be called with a state lock
// held.
type DnsFeed interface {
	// GET /dns/journal?root=&after=: rows above after, reload, or an empty answer once the hold ends
	// with nothing new. Returns at the end of the hold (at most 25 s) or when ctx ends.
	Journal(ctx context.Context, root string, after uint64) (*DnsFeedAnswer, error)
	// GET /dns/snapshot?root=: every row at one serial. The caller closes what comes back.
	Snapshot(ctx context.Context, root string) (DnsSnapshotRows, error)
	// POST /dns/reload-diff.
	ReloadDiff(ctx context.Context, diff *DnsReloadDiff) error
}
