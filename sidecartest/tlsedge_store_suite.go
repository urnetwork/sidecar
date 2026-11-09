// The conformance suite for tlsedgeservice.TlsEdgeStore (§13.5, §13.9; TLS-M5-08): what store.go
// promises, run on FakeTlsEdgeStore here and on server's model.NewTlsEdgeStore (TLS-M5-11), so the fake
// stays honest (D-TEST-2). The interface reads the label map and the kill rows and writes records, so a
// store comes with hooks that write what it reads and read what it writes, through the same models
// production uses. Every case uses networks of its own and keeps only its own names and rows from what a
// read returns, so one store serves the whole run and a shared database's other rows change no verdict.
//
// A case is a plain function returning its first failure, and RunTlsEdgeStoreSuite loops over them, as
// blobsuite does (connect/CODESTYLE.md:216). A failure in one does not stop the next. A case whose hooks
// a store's test does not give is skipped, and the run says so.

package sidecartest

import (
	"context"
	"crypto/rand"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// How long one case may wait on a store before it fails. Real time, so only ever a failure's bound
// (§22.8): nothing here sleeps.
const tlsEdgeSuiteCaseTimeout = 30 * time.Second

// What a store's own test does that the interface cannot. Each writes through the models production
// uses (DNS-M5-10, DNS-M5-14, TLS-M5-13, TLS-M5-12); nil skips the cases that need it.
type TlsEdgeStoreSuiteHooks struct {
	// The root the store's label map is read for, which the label hooks write under.
	Root string
	// Gives networkId a live label in Root, allocated as §12.5 allocates one, and returns it.
	AddLabel func(ctx context.Context, networkId sidecar.Id) (string, error)
	// Gives networkId a live alias in Root (§12.5, M6).
	AddAlias func(ctx context.Context, networkId sidecar.Id, alias string) error
	// Tombstones every name of networkId, as deleting the network does.
	WithdrawNetwork func(ctx context.Context, networkId sidecar.Id) error
	// §12.9's SuspendZone, SuspendHost and Restore. A zero until holds until a lift; Restore's host empty
	// lifts the zone's suspension.
	SuspendZone func(ctx context.Context, networkId sidecar.Id, until time.Time) error
	SuspendHost func(ctx context.Context, networkId sidecar.Id, host string) error
	Restore     func(ctx context.Context, networkId sidecar.Id, host string) error
	// §13.9's kill switch: writes a row of network_tls_suspension, and lifts one by network and host.
	SetSuspension  func(ctx context.Context, row *sidecar.TlsSuspendArgs) error
	LiftSuspension func(ctx context.Context, networkId sidecar.Id, host string) error
	// networkId's tls_connection_record rows ending at or after since, in any order.
	ReadRecords func(ctx context.Context, networkId sidecar.Id, since time.Time) ([]*tlsedgeservice.TlsConnectionRecord, error)
	// The time a record written now may carry: near the store's clock, since a store refuses a record of
	// an hour already retired or far ahead. Nil takes the real clock.
	Now func() time.Time
}

type tlsEdgeSuiteCase struct {
	name string
	// the hooks the case needs, by name, all non-nil to run
	needs []string
	run   func(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error
}

// Runs every case on store whose hooks are given.
func RunTlsEdgeStoreSuite(t testing.TB, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) {
	t.Helper()
	if hooks == nil {
		hooks = &TlsEdgeStoreSuiteHooks{}
	}
	given := map[string]bool{
		"AddLabel":        hooks.AddLabel != nil,
		"AddAlias":        hooks.AddAlias != nil,
		"WithdrawNetwork": hooks.WithdrawNetwork != nil,
		"SuspendZone":     hooks.SuspendZone != nil,
		"SuspendHost":     hooks.SuspendHost != nil,
		"Restore":         hooks.Restore != nil,
		"SetSuspension":   hooks.SetSuspension != nil,
		"LiftSuspension":  hooks.LiftSuspension != nil,
		"ReadRecords":     hooks.ReadRecords != nil,
	}
	for _, suiteCase := range tlsEdgeSuiteCases() {
		missing := []string{}
		for _, need := range suiteCase.needs {
			if !given[need] {
				missing = append(missing, need)
			}
		}
		if 0 < len(missing) {
			t.Logf("%s: skipped, no %v hook", suiteCase.name, missing)
			continue
		}
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), tlsEdgeSuiteCaseTimeout)
			defer cancel()
			if err := suiteCase.run(ctx, store, hooks); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

func tlsEdgeSuiteCases() []tlsEdgeSuiteCase {
	return []tlsEdgeSuiteCase{
		{name: "a snapshot holds a new label, live, with its network", needs: []string{"AddLabel"}, run: caseTlsEdgeSnapshotHoldsLabel},
		{name: "changes since a serial hold what changed after it and nothing before", needs: []string{"AddLabel"}, run: caseTlsEdgeChangesSince},
		{name: "a read past the newest change holds none of the case's names", needs: []string{"AddLabel"}, run: caseTlsEdgeNothingNew},
		{name: "an alias reads as an alias of its network", needs: []string{"AddLabel", "AddAlias"}, run: caseTlsEdgeAlias},
		{name: "a withdrawn network's names come back no longer live", needs: []string{"AddLabel", "WithdrawNetwork"}, run: caseTlsEdgeWithdrawn},
		{name: "a zone suspension rides its network's names until restored", needs: []string{"AddLabel", "SuspendZone", "Restore"}, run: caseTlsEdgeZoneSuspension},
		{name: "a host suspension withholds its host until restored", needs: []string{"AddLabel", "SuspendHost", "Restore"}, run: caseTlsEdgeHostSuspension},
		{name: "a kill row reads back field for field until lifted", needs: []string{"SetSuspension", "LiftSuspension"}, run: caseTlsEdgeKillRows},
		{name: "a batch of records lands as given", needs: []string{"ReadRecords"}, run: caseTlsEdgeRecordsLand},
		{name: "an empty batch answers and stores nothing", needs: []string{"ReadRecords"}, run: caseTlsEdgeEmptyBatch},
	}
}

func tlsEdgeSuiteNow(hooks *TlsEdgeStoreSuiteHooks) time.Time {
	if hooks.Now != nil {
		return hooks.Now()
	}
	return time.Now()
}

// The entries of nameMap naming name, in order.
func tlsEdgeSuiteEntries(nameMap *tlsedgeservice.TlsEdgeNameMap, name string) []*tlsedgeservice.TlsEdgeNameEntry {
	entries := []*tlsedgeservice.TlsEdgeNameEntry{}
	for _, entry := range nameMap.Entries {
		if entry.Name == name {
			entries = append(entries, entry)
		}
	}
	return entries
}

// The one entry of nameMap naming name, or an error.
func tlsEdgeSuiteEntry(nameMap *tlsedgeservice.TlsEdgeNameMap, name string) (*tlsedgeservice.TlsEdgeNameEntry, error) {
	entries := tlsEdgeSuiteEntries(nameMap, name)
	if len(entries) != 1 {
		return nil, fmt.Errorf("%d entries name the case's name", len(entries))
	}
	return entries[0], nil
}

// The serial a read from now on follows from: the store's newest.
func tlsEdgeSuiteSerial(ctx context.Context, store tlsedgeservice.TlsEdgeStore, root string) (uint64, error) {
	snapshot, err := store.NameSnapshot(ctx, root)
	if err != nil {
		return 0, err
	}
	return snapshot.Serial, nil
}

func caseTlsEdgeSnapshotHoldsLabel(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	networkId := sidecar.NewId()
	label, err := hooks.AddLabel(ctx, networkId)
	if err != nil {
		return err
	}
	snapshot, err := store.NameSnapshot(ctx, hooks.Root)
	if err != nil {
		return err
	}
	entry, err := tlsEdgeSuiteEntry(snapshot, label)
	if err != nil {
		return err
	}
	if entry.NetworkId != networkId || entry.Kind != tlsedgeservice.TlsEdgeNameKindLabel || entry.State != tlsedgeservice.TlsEdgeNameStateLive {
		return fmt.Errorf("entry %+v", entry)
	}
	if entry.ZoneSuspended || 0 < len(entry.WithheldHosts) {
		return fmt.Errorf("a new label reads suspended: %+v", entry)
	}
	return nil
}

func caseTlsEdgeChangesSince(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	firstLabel, err := hooks.AddLabel(ctx, sidecar.NewId())
	if err != nil {
		return err
	}
	after, err := tlsEdgeSuiteSerial(ctx, store, hooks.Root)
	if err != nil {
		return err
	}
	secondNetworkId := sidecar.NewId()
	secondLabel, err := hooks.AddLabel(ctx, secondNetworkId)
	if err != nil {
		return err
	}
	changes, err := store.NamesSince(ctx, hooks.Root, after)
	if err != nil {
		return err
	}
	if changes.Serial <= after {
		return fmt.Errorf("serial %d did not pass %d", changes.Serial, after)
	}
	if 0 < len(tlsEdgeSuiteEntries(changes, firstLabel)) {
		return fmt.Errorf("a change before the serial came back")
	}
	entry, err := tlsEdgeSuiteEntry(changes, secondLabel)
	if err != nil {
		return err
	}
	if entry.NetworkId != secondNetworkId {
		return fmt.Errorf("the change names another network")
	}
	return nil
}

func caseTlsEdgeNothingNew(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	label, err := hooks.AddLabel(ctx, sidecar.NewId())
	if err != nil {
		return err
	}
	after, err := tlsEdgeSuiteSerial(ctx, store, hooks.Root)
	if err != nil {
		return err
	}
	changes, err := store.NamesSince(ctx, hooks.Root, after)
	if err != nil {
		return err
	}
	if changes.Serial < after {
		return fmt.Errorf("serial %d went back from %d", changes.Serial, after)
	}
	if 0 < len(tlsEdgeSuiteEntries(changes, label)) {
		return fmt.Errorf("a name at or before the serial came back")
	}
	return nil
}

func caseTlsEdgeAlias(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	networkId := sidecar.NewId()
	if _, err := hooks.AddLabel(ctx, networkId); err != nil {
		return err
	}
	// an alias of the case's own: five letters drawn per run, so a shared store holds no other
	suffix, err := sidecar.NewDnsLabel(rand.Reader)
	if err != nil {
		return err
	}
	alias := "alias-" + suffix[:6]
	if err := hooks.AddAlias(ctx, networkId, alias); err != nil {
		return err
	}
	snapshot, err := store.NameSnapshot(ctx, hooks.Root)
	if err != nil {
		return err
	}
	entry, err := tlsEdgeSuiteEntry(snapshot, alias)
	if err != nil {
		return err
	}
	if entry.NetworkId != networkId || entry.Kind != tlsedgeservice.TlsEdgeNameKindAlias || entry.State != tlsedgeservice.TlsEdgeNameStateLive {
		return fmt.Errorf("entry %+v", entry)
	}
	return nil
}

func caseTlsEdgeWithdrawn(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	networkId := sidecar.NewId()
	label, err := hooks.AddLabel(ctx, networkId)
	if err != nil {
		return err
	}
	after, err := tlsEdgeSuiteSerial(ctx, store, hooks.Root)
	if err != nil {
		return err
	}
	if err := hooks.WithdrawNetwork(ctx, networkId); err != nil {
		return err
	}
	changes, err := store.NamesSince(ctx, hooks.Root, after)
	if err != nil {
		return err
	}
	entry, err := tlsEdgeSuiteEntry(changes, label)
	if err != nil {
		return err
	}
	if entry.State == tlsedgeservice.TlsEdgeNameStateLive {
		return fmt.Errorf("a withdrawn label reads live")
	}
	return nil
}

func caseTlsEdgeZoneSuspension(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	networkId := sidecar.NewId()
	label, err := hooks.AddLabel(ctx, networkId)
	if err != nil {
		return err
	}
	after, err := tlsEdgeSuiteSerial(ctx, store, hooks.Root)
	if err != nil {
		return err
	}
	until := tlsEdgeSuiteNow(hooks).Add(time.Hour).Truncate(time.Microsecond)
	if err := hooks.SuspendZone(ctx, networkId, until); err != nil {
		return err
	}
	changes, err := store.NamesSince(ctx, hooks.Root, after)
	if err != nil {
		return err
	}
	entry, err := tlsEdgeSuiteEntry(changes, label)
	if err != nil {
		return err
	}
	if !entry.ZoneSuspended || !entry.ZoneSuspendUntil.Equal(until) {
		return fmt.Errorf("the suspension did not ride the label: %+v", entry)
	}
	after = changes.Serial
	if err := hooks.Restore(ctx, networkId, ""); err != nil {
		return err
	}
	changes, err = store.NamesSince(ctx, hooks.Root, after)
	if err != nil {
		return err
	}
	entry, err = tlsEdgeSuiteEntry(changes, label)
	if err != nil {
		return err
	}
	if entry.ZoneSuspended {
		return fmt.Errorf("the restore did not ride the label")
	}
	return nil
}

func caseTlsEdgeHostSuspension(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	networkId := sidecar.NewId()
	label, err := hooks.AddLabel(ctx, networkId)
	if err != nil {
		return err
	}
	after, err := tlsEdgeSuiteSerial(ctx, store, hooks.Root)
	if err != nil {
		return err
	}
	if err := hooks.SuspendHost(ctx, networkId, "shop"); err != nil {
		return err
	}
	changes, err := store.NamesSince(ctx, hooks.Root, after)
	if err != nil {
		return err
	}
	entry, err := tlsEdgeSuiteEntry(changes, label)
	if err != nil {
		return err
	}
	if !slices.Equal(entry.WithheldHosts, []string{"shop"}) || entry.ZoneSuspended {
		return fmt.Errorf("the host suspension reads %+v", entry)
	}
	after = changes.Serial
	if err := hooks.Restore(ctx, networkId, "shop"); err != nil {
		return err
	}
	changes, err = store.NamesSince(ctx, hooks.Root, after)
	if err != nil {
		return err
	}
	entry, err = tlsEdgeSuiteEntry(changes, label)
	if err != nil {
		return err
	}
	if 0 < len(entry.WithheldHosts) {
		return fmt.Errorf("the restore left %v withheld", entry.WithheldHosts)
	}
	return nil
}

// The rows of suspensions naming networkId.
func tlsEdgeSuiteRows(rows []*sidecar.TlsSuspendArgs, networkId sidecar.Id) []*sidecar.TlsSuspendArgs {
	kept := []*sidecar.TlsSuspendArgs{}
	for _, row := range rows {
		if row.NetworkId == networkId {
			kept = append(kept, row)
		}
	}
	return kept
}

func caseTlsEdgeKillRows(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	networkId := sidecar.NewId()
	until := tlsEdgeSuiteNow(hooks).Add(time.Hour).Truncate(time.Microsecond)
	written := []*sidecar.TlsSuspendArgs{
		{NetworkId: networkId, Host: sidecar.TlsKillAllHosts, Reason: "case", Until: until},
		{NetworkId: networkId, Host: "blog", Reason: "case"},
	}
	for _, row := range written {
		if err := hooks.SetSuspension(ctx, row); err != nil {
			return err
		}
	}
	rows, err := store.Suspensions(ctx)
	if err != nil {
		return err
	}
	read := tlsEdgeSuiteRows(rows, networkId)
	if len(read) != len(written) {
		return fmt.Errorf("%d rows read back, %d written", len(read), len(written))
	}
	for _, row := range written {
		found := slices.ContainsFunc(read, func(readRow *sidecar.TlsSuspendArgs) bool {
			return readRow.Host == row.Host && readRow.Reason == row.Reason && readRow.Until.Equal(row.Until)
		})
		if !found {
			return fmt.Errorf("the row for %q did not read back", row.Host)
		}
	}
	if err := hooks.LiftSuspension(ctx, networkId, "blog"); err != nil {
		return err
	}
	rows, err = store.Suspensions(ctx)
	if err != nil {
		return err
	}
	read = tlsEdgeSuiteRows(rows, networkId)
	if len(read) != 1 || read[0].Host != sidecar.TlsKillAllHosts {
		return fmt.Errorf("the lift left %d rows", len(read))
	}
	return hooks.LiftSuspension(ctx, networkId, sidecar.TlsKillAllHosts)
}

func caseTlsEdgeRecordsLand(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	networkId := sidecar.NewId()
	now := tlsEdgeSuiteNow(hooks).Truncate(time.Microsecond)
	since := now.Add(-time.Minute)
	written := []*tlsedgeservice.TlsConnectionRecord{}
	for index, host := range []string{"@", "blog", "shop"} {
		visitorHash := make([]byte, 16)
		rand.Read(visitorHash)
		written = append(written, &tlsedgeservice.TlsConnectionRecord{
			ConnectionId: sidecar.NewId(),
			NetworkId:    networkId,
			Host:         host,
			StartTime:    now.Add(-time.Duration(index+2) * time.Second),
			EndTime:      now.Add(-time.Duration(index) * time.Second),
			ByteCount:    int64(1000 * (index + 1)),
			VisitorHash:  visitorHash,
		})
	}
	if err := store.InsertConnectionRecords(ctx, written); err != nil {
		return err
	}
	read, err := hooks.ReadRecords(ctx, networkId, since)
	if err != nil {
		return err
	}
	if len(read) != len(written) {
		return fmt.Errorf("%d records read back, %d written", len(read), len(written))
	}
	for _, record := range written {
		found := slices.ContainsFunc(read, func(readRecord *tlsedgeservice.TlsConnectionRecord) bool {
			return readRecord.ConnectionId == record.ConnectionId && readRecord.NetworkId == record.NetworkId &&
				readRecord.Host == record.Host && readRecord.StartTime.Equal(record.StartTime) &&
				readRecord.EndTime.Equal(record.EndTime) && readRecord.ByteCount == record.ByteCount &&
				slices.Equal(readRecord.VisitorHash, record.VisitorHash)
		})
		if !found {
			return fmt.Errorf("the record for %q did not read back field for field", record.Host)
		}
	}
	return nil
}

func caseTlsEdgeEmptyBatch(ctx context.Context, store tlsedgeservice.TlsEdgeStore, hooks *TlsEdgeStoreSuiteHooks) error {
	if err := store.InsertConnectionRecords(ctx, []*tlsedgeservice.TlsConnectionRecord{}); err != nil {
		return err
	}
	return store.InsertConnectionRecords(ctx, nil)
}
