// The conformance suite for dnsservice.DnsStore (§12.14; DNS-M5-01): what store.go declares, run on
// FakeDnsStore here and on dnshost.Store in server, so the fake stays honest (D-TEST-2). Every case
// runs through the interface alone, on a root of its own, so one store serves the whole run.
//
// A case is a plain function returning its first failure, and RunDnsStoreSuite loops over them, as
// blobsuite does, since one store's cases are homogeneous variations (connect/CODESTYLE.md:216). A
// failure in one does not stop the next.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

// A time after every commit a run can make, on any clock, so a purge takes the whole journal.
var dnsSuiteFarFuture = time.Date(2100, time.January, 1, 0, 0, 0, 0, time.UTC)

// How long one case may wait on a store before it fails with what it was waiting for. Real time, so
// only ever a failure's bound (§22.8): nothing here sleeps.
const dnsSuiteCaseTimeout = 30 * time.Second

// The most rows one read in the suite asks for.
const dnsSuiteJournalLimit = 1000

type dnsSuiteCase struct {
	name string
	run  func(ctx context.Context, store dnsservice.DnsStore, root string) error
}

// Runs every case on store, each on a fresh root under .example. t is a TB so a server test env's
// attempt can run it.
func RunDnsStoreSuite(t testing.TB, store dnsservice.DnsStore) {
	t.Helper()
	runId := sidecar.NewId().String()
	for index, suiteCase := range dnsSuiteCases() {
		root := fmt.Sprintf("case%d-%s.example.", index, runId[len(runId)-8:])
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), dnsSuiteCaseTimeout)
			defer cancel()
			if err := store.EnsureRoot(ctx, root); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
				return
			}
			if err := suiteCase.run(ctx, store, root); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

func dnsSuiteCases() []dnsSuiteCase {
	return []dnsSuiteCase{
		{name: "a root starts at zero and ensuring it again changes nothing", run: caseDnsEnsureRoot},
		{name: "an unknown root is an error, not an empty one", run: caseDnsUnknownRoot},
		{name: "one write is one serial and one journal row", run: caseDnsOneRowPerWrite},
		{name: "the row reads back as written", run: caseDnsRowReadsBack},
		{name: "the serial never lowers", run: caseDnsSerialNeverLowers},
		{name: "a refused write takes no serial", run: caseDnsRefusedWrites},
		{name: "an empty write takes no serial", run: caseDnsEmptyWrite},
		{name: "racing writers take consecutive serials", run: caseDnsRacingWriters},
		{name: "a read past the limit continues where it stopped", run: caseDnsJournalLimit},
		{name: "a purged journal reports a gap", run: caseDnsGapReported},
		{name: "a caller at or ahead of the serial is in no gap", run: caseDnsNoGapAtOrAhead},
		{name: "a limit that is not positive is refused", run: caseDnsJournalLimitPositive},
		{name: "a snapshot holds one serial", run: caseDnsSnapshotOneSerial},
		{name: "a snapshot holds what upserts and deletes left", run: caseDnsSnapshotRows},
		{name: "restoring refuses writes", run: caseDnsRestoringRefusesWrites},
		{name: "a restore lands above every serial it could have missed", run: caseDnsRestoreLands},
		{name: "a restore reruns to the same serial", run: caseDnsRestoreIdempotent},
		{name: "a restore needs restoring set, and one incident", run: caseDnsRestoreRefusals},
		{name: "a new restoring forgets the last incident", run: caseDnsRestoringForgetsIncident},
		{name: "a stale compare-and-swap writes nothing", run: caseDnsCompareAndSwap},
		{name: "a zone's version is the serial of its last write", run: caseDnsZoneVersion},
		{name: "a reload diff is kept", run: caseDnsReloadDiffs},
		{name: "a write wakes a watcher", run: caseDnsSerialRaised},
	}
}

// An upsert of one TXT at <label>.<root>.
func dnsSuiteWrite(root string, label string, text string) *dnsservice.DnsZoneWrite {
	return &dnsservice.DnsZoneWrite{
		Root: root,
		Upserts: []dnsservice.DnsRecordSet{{
			Owner: label + "." + root,
			Type:  dns.TypeTXT,
			Ttl:   300,
			Kind:  dnsservice.DnsRecordKindUser,
			Rdata: []string{`"` + text + `"`},
		}},
	}
}

// count writes of distinct owners, and the serial of the last.
func dnsSuiteWrites(ctx context.Context, store dnsservice.DnsStore, root string, count int) (uint64, error) {
	var serial uint64
	for index := range count {
		var err error
		serial, err = store.Write(ctx, dnsSuiteWrite(root, fmt.Sprintf("w%d", index), "text"))
		if err != nil {
			return 0, err
		}
	}
	return serial, nil
}

// Reads a snapshot to its end and closes it.
func readAllDnsSnapshotRows(rows dnsservice.DnsSnapshotRows) ([]dnsservice.DnsRecordSet, error) {
	defer rows.Close()
	sets := []dnsservice.DnsRecordSet{}
	for {
		set, err := rows.Next()
		if errors.Is(err, io.EOF) {
			return sets, nil
		}
		if err != nil {
			return nil, err
		}
		sets = append(sets, *set)
	}
}

func wantDnsSerial(ctx context.Context, store dnsservice.DnsStore, root string, want uint64) error {
	state, err := store.RootState(ctx, root)
	if err != nil {
		return err
	}
	if state.Serial != want {
		return fmt.Errorf("serial %d, want %d", state.Serial, want)
	}
	return nil
}

func wantDnsJournalRows(ctx context.Context, store dnsservice.DnsStore, root string, after uint64, want int) error {
	read, err := store.Journal(ctx, root, after, dnsSuiteJournalLimit)
	if err != nil {
		return err
	}
	if len(read.Rows) != want {
		return fmt.Errorf("%d journal rows above %d, want %d", len(read.Rows), after, want)
	}
	return nil
}

func caseDnsEnsureRoot(ctx context.Context, store dnsservice.DnsStore, root string) error {
	state, err := store.RootState(ctx, root)
	if err != nil {
		return err
	}
	if state.Root != root || state.Serial != 0 || state.RestoreSerial != 0 || state.Restoring || state.RestoreIncidentId != nil {
		return fmt.Errorf("a new root reads %+v", state)
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "a", "one")); err != nil {
		return err
	}
	if err := store.EnsureRoot(ctx, root); err != nil {
		return err
	}
	return wantDnsSerial(ctx, store, root, 1)
}

func caseDnsUnknownRoot(ctx context.Context, store dnsservice.DnsStore, root string) error {
	unknown := "unknown-" + root
	if _, err := store.RootState(ctx, unknown); !errors.Is(err, dnsservice.ErrDnsRootUnknown) {
		return fmt.Errorf("RootState: %v", err)
	}
	if _, err := store.Journal(ctx, unknown, 0, 1); !errors.Is(err, dnsservice.ErrDnsRootUnknown) {
		return fmt.Errorf("Journal: %v", err)
	}
	if _, err := store.Snapshot(ctx, unknown); !errors.Is(err, dnsservice.ErrDnsRootUnknown) {
		return fmt.Errorf("Snapshot: %v", err)
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(unknown, "a", "one")); !errors.Is(err, dnsservice.ErrDnsRootUnknown) {
		return fmt.Errorf("Write: %v", err)
	}
	return nil
}

func caseDnsOneRowPerWrite(ctx context.Context, store dnsservice.DnsStore, root string) error {
	wide := &dnsservice.DnsZoneWrite{Root: root}
	for index := range 5 {
		wide.Upserts = append(wide.Upserts, dnsSuiteWrite(root, fmt.Sprintf("a%d", index), "one").Upserts[0])
	}
	for want := uint64(1); want <= 3; want += 1 {
		serial, err := store.Write(ctx, wide)
		if err != nil {
			return err
		}
		if serial != want {
			return fmt.Errorf("serial %d, want %d", serial, want)
		}
		if err := wantDnsJournalRows(ctx, store, root, 0, int(want)); err != nil {
			return err
		}
		if err := wantDnsSerial(ctx, store, root, want); err != nil {
			return err
		}
	}
	return nil
}

func caseDnsRowReadsBack(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "gone", "one")); err != nil {
		return err
	}
	write := dnsSuiteWrite(root, "a", "one")
	write.Upserts = append(write.Upserts, dnsservice.DnsRecordSet{Owner: "*." + root, Type: dns.TypeA, Ttl: 60, Kind: dnsservice.DnsRecordKindEdge})
	write.Upserts = append(write.Upserts, dnsservice.DnsRecordSet{Owner: "blog." + root, Kind: dnsservice.DnsRecordKindCopy})
	write.Deletes = []dnsservice.DnsRecordKey{{Owner: "gone." + root, Type: dns.TypeTXT}}
	serial, err := store.Write(ctx, write)
	if err != nil {
		return err
	}
	read, err := store.Journal(ctx, root, serial-1, dnsSuiteJournalLimit)
	if err != nil {
		return err
	}
	if len(read.Rows) != 1 {
		return fmt.Errorf("%d rows", len(read.Rows))
	}
	row := &read.Rows[0]
	if err := row.Validate(); err != nil {
		return err
	}
	if row.Format != dnsservice.DnsFormat || row.Root != root || row.Serial != serial {
		return fmt.Errorf("row %+v", row)
	}
	if len(row.Upserts) != len(write.Upserts) || len(row.Deletes) != 1 || row.Deletes[0] != write.Deletes[0] {
		return fmt.Errorf("row %+v", row)
	}
	for index := range row.Upserts {
		got, want := &row.Upserts[index], &write.Upserts[index]
		if got.Key() != want.Key() || got.Ttl != want.Ttl || got.Kind != want.Kind || !slices.Equal(got.Rdata, want.Rdata) {
			return fmt.Errorf("upsert %+v, want %+v", got, want)
		}
	}
	return nil
}

func caseDnsSerialNeverLowers(ctx context.Context, store dnsservice.DnsStore, root string) error {
	floor := uint64(0)
	check := func(step string) error {
		state, err := store.RootState(ctx, root)
		if err != nil {
			return err
		}
		if state.Serial < floor {
			return fmt.Errorf("%s: serial %d below %d", step, state.Serial, floor)
		}
		raised, err := store.RaisedSerial(ctx, root)
		if err != nil {
			return err
		}
		if raised != state.Serial {
			return fmt.Errorf("%s: the key holds %d at serial %d", step, raised, state.Serial)
		}
		floor = state.Serial
		return nil
	}
	if _, err := dnsSuiteWrites(ctx, store, root, 3); err != nil {
		return err
	}
	if err := check("after writes"); err != nil {
		return err
	}
	if err := store.EnsureRoot(ctx, root); err != nil {
		return err
	}
	if err := check("after ensuring"); err != nil {
		return err
	}
	if _, err := store.PurgeJournal(ctx, root, dnsSuiteFarFuture); err != nil {
		return err
	}
	if err := check("after a purge"); err != nil {
		return err
	}
	if err := store.SetRestoring(ctx, root, true); err != nil {
		return err
	}
	if _, err := store.CommitRestore(ctx, root, sidecar.NewId(), 0); err != nil {
		return err
	}
	if err := store.SetRestoring(ctx, root, false); err != nil {
		return err
	}
	if err := check("after a restore"); err != nil {
		return err
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "a", "one")); err != nil {
		return err
	}
	return check("after a write past the restore")
}

func caseDnsRefusedWrites(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "a", "one")); err != nil {
		return err
	}
	outside := dnsSuiteWrite(root, "a", "one")
	outside.Upserts[0].Owner = "a.outside.invalid."
	unparsable := dnsSuiteWrite(root, "a", "one")
	unparsable.Upserts[0].Type = dns.TypeA
	unparsable.Upserts[0].Rdata = []string{"not an address"}
	twice := dnsSuiteWrite(root, "a", "one")
	twice.Deletes = []dnsservice.DnsRecordKey{twice.Upserts[0].Key()}
	for _, write := range []*dnsservice.DnsZoneWrite{outside, unparsable, twice} {
		if _, err := store.Write(ctx, write); !errors.Is(err, dnsservice.ErrDnsRowMalformed) {
			return fmt.Errorf("a malformed write answered %v", err)
		}
	}
	if err := wantDnsSerial(ctx, store, root, 1); err != nil {
		return err
	}
	return wantDnsJournalRows(ctx, store, root, 0, 1)
}

func caseDnsEmptyWrite(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := store.Write(ctx, &dnsservice.DnsZoneWrite{Root: root}); !errors.Is(err, dnsservice.ErrDnsWriteEmpty) {
		return fmt.Errorf("an empty write answered %v", err)
	}
	return wantDnsSerial(ctx, store, root, 0)
}

func caseDnsRacingWriters(ctx context.Context, store dnsservice.DnsStore, root string) error {
	writerCount := 16
	serials := make([]uint64, writerCount)
	errs := make([]error, writerCount)
	waitGroup := sync.WaitGroup{}
	for index := range writerCount {
		waitGroup.Go(func() {
			serials[index], errs[index] = store.Write(ctx, dnsSuiteWrite(root, fmt.Sprintf("w%d", index), "text"))
		})
	}
	waitGroup.Wait()
	if err := errors.Join(errs...); err != nil {
		return err
	}
	slices.Sort(serials)
	for index, serial := range serials {
		if serial != uint64(index+1) {
			return fmt.Errorf("serials %v", serials)
		}
	}
	read, err := store.Journal(ctx, root, 0, dnsSuiteJournalLimit)
	if err != nil {
		return err
	}
	if len(read.Rows) != writerCount || read.Gap {
		return fmt.Errorf("%d rows, gap %v", len(read.Rows), read.Gap)
	}
	for index := range read.Rows {
		if read.Rows[index].Serial != uint64(index+1) {
			return fmt.Errorf("row %d at serial %d", index, read.Rows[index].Serial)
		}
	}
	return nil
}

func caseDnsJournalLimit(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := dnsSuiteWrites(ctx, store, root, 5); err != nil {
		return err
	}
	read, err := store.Journal(ctx, root, 0, 2)
	if err != nil {
		return err
	}
	if len(read.Rows) != 2 || read.Rows[0].Serial != 1 || read.Rows[1].Serial != 2 || read.Serial != 5 || read.Gap {
		return fmt.Errorf("first read %+v", read)
	}
	read, err = store.Journal(ctx, root, 2, 2)
	if err != nil {
		return err
	}
	if len(read.Rows) != 2 || read.Rows[0].Serial != 3 || read.Gap {
		return fmt.Errorf("second read %+v", read)
	}
	return nil
}

func caseDnsGapReported(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := dnsSuiteWrites(ctx, store, root, 3); err != nil {
		return err
	}
	purgedCount, err := store.PurgeJournal(ctx, root, dnsSuiteFarFuture)
	if err != nil {
		return err
	}
	if purgedCount != 3 {
		return fmt.Errorf("purged %d rows", purgedCount)
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "a", "one")); err != nil {
		return err
	}
	read, err := store.Journal(ctx, root, 1, dnsSuiteJournalLimit)
	if err != nil {
		return err
	}
	if !read.Gap || len(read.Rows) != 0 || read.Serial != 4 {
		return fmt.Errorf("below the purge: %+v", read)
	}
	read, err = store.Journal(ctx, root, 3, dnsSuiteJournalLimit)
	if err != nil {
		return err
	}
	if read.Gap || len(read.Rows) != 1 {
		return fmt.Errorf("at the purge: %+v", read)
	}
	return nil
}

func caseDnsNoGapAtOrAhead(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := dnsSuiteWrites(ctx, store, root, 2); err != nil {
		return err
	}
	for _, after := range []uint64{2, 3, dnsservice.DnsRestoreSerialJump} {
		read, err := store.Journal(ctx, root, after, dnsSuiteJournalLimit)
		if err != nil {
			return err
		}
		if read.Gap || len(read.Rows) != 0 || read.Serial != 2 {
			return fmt.Errorf("after %d: %+v", after, read)
		}
	}
	return nil
}

func caseDnsJournalLimitPositive(ctx context.Context, store dnsservice.DnsStore, root string) error {
	for _, limit := range []int{0, -1} {
		if read, err := store.Journal(ctx, root, 0, limit); err == nil {
			return fmt.Errorf("limit %d answered %+v", limit, read)
		}
	}
	return nil
}

func caseDnsSnapshotOneSerial(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "a", "before")); err != nil {
		return err
	}
	rows, err := store.Snapshot(ctx, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	snapshot := rows.Snapshot()
	if snapshot.Serial != 1 || snapshot.Root != root || snapshot.Format != dnsservice.DnsFormat {
		return fmt.Errorf("snapshot %+v", snapshot)
	}
	// a write landing during the read is a later serial's
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "a", "after")); err != nil {
		return err
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "b", "after")); err != nil {
		return err
	}
	sets, err := readAllDnsSnapshotRows(rows)
	if err != nil {
		return err
	}
	if len(sets) != 1 || sets[0].Rdata[0] != `"before"` {
		return fmt.Errorf("rows %+v", sets)
	}
	return nil
}

func caseDnsSnapshotRows(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "kept", "one")); err != nil {
		return err
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "replaced", "one")); err != nil {
		return err
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "replaced", "two")); err != nil {
		return err
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "gone", "one")); err != nil {
		return err
	}
	gone := dnsSuiteWrite(root, "gone", "one").Upserts[0].Key()
	serial, err := store.Write(ctx, &dnsservice.DnsZoneWrite{Root: root, Deletes: []dnsservice.DnsRecordKey{gone}})
	if err != nil {
		return err
	}
	rows, err := store.Snapshot(ctx, root)
	if err != nil {
		return err
	}
	if rows.Snapshot().Serial != serial {
		return fmt.Errorf("snapshot %+v", rows.Snapshot())
	}
	sets, err := readAllDnsSnapshotRows(rows)
	if err != nil {
		return err
	}
	texts := map[string]string{}
	for index := range sets {
		texts[sets[index].Owner] = sets[index].Rdata[0]
	}
	if len(texts) != 2 || texts["kept."+root] != `"one"` || texts["replaced."+root] != `"two"` {
		return fmt.Errorf("rows %+v", sets)
	}
	return nil
}

func caseDnsRestoringRefusesWrites(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "a", "one")); err != nil {
		return err
	}
	if err := store.SetRestoring(ctx, root, true); err != nil {
		return err
	}
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "b", "two")); !errors.Is(err, dnsservice.ErrDnsRestoring) {
		return fmt.Errorf("a write while restoring answered %v", err)
	}
	if err := wantDnsSerial(ctx, store, root, 1); err != nil {
		return err
	}
	if err := wantDnsJournalRows(ctx, store, root, 0, 1); err != nil {
		return err
	}
	if err := store.SetRestoring(ctx, root, false); err != nil {
		return err
	}
	serial, err := store.Write(ctx, dnsSuiteWrite(root, "b", "two"))
	if err != nil {
		return err
	}
	if serial != 2 {
		return fmt.Errorf("serial %d", serial)
	}
	return nil
}

func caseDnsRestoreLands(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := dnsSuiteWrites(ctx, store, root, 3); err != nil {
		return err
	}
	if err := store.SetRestoring(ctx, root, true); err != nil {
		return err
	}
	// an edge answered above the database and the key both
	observedSerial := uint64(1000)
	incidentId := sidecar.NewId()
	restoreSerial, err := store.CommitRestore(ctx, root, incidentId, observedSerial)
	if err != nil {
		return err
	}
	if want := observedSerial + dnsservice.DnsRestoreSerialJump; restoreSerial != want {
		return fmt.Errorf("restore serial %d, want %d", restoreSerial, want)
	}
	state, err := store.RootState(ctx, root)
	if err != nil {
		return err
	}
	if state.Serial != restoreSerial || state.RestoreSerial != restoreSerial || !state.Restoring {
		return fmt.Errorf("state %+v", state)
	}
	if state.RestoreIncidentId == nil || *state.RestoreIncidentId != incidentId {
		return fmt.Errorf("incident %v", state.RestoreIncidentId)
	}
	raised, err := store.RaisedSerial(ctx, root)
	if err != nil {
		return err
	}
	if raised != restoreSerial {
		return fmt.Errorf("the key holds %d", raised)
	}
	// still restoring, so writes wait for the edges
	if _, err := store.Write(ctx, dnsSuiteWrite(root, "a", "one")); !errors.Is(err, dnsservice.ErrDnsRestoring) {
		return fmt.Errorf("a write after the transaction answered %v", err)
	}
	// and a key above the observed serial wins in turn
	if err := store.SetRestoring(ctx, root, false); err != nil {
		return err
	}
	if err := store.SetRestoring(ctx, root, true); err != nil {
		return err
	}
	again, err := store.CommitRestore(ctx, root, sidecar.NewId(), 1)
	if err != nil {
		return err
	}
	if again != restoreSerial+dnsservice.DnsRestoreSerialJump {
		return fmt.Errorf("a second restore landed at %d", again)
	}
	return nil
}

func caseDnsRestoreIdempotent(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if err := store.SetRestoring(ctx, root, true); err != nil {
		return err
	}
	incidentId := sidecar.NewId()
	first, err := store.CommitRestore(ctx, root, incidentId, 7)
	if err != nil {
		return err
	}
	second, err := store.CommitRestore(ctx, root, incidentId, 8)
	if err != nil {
		return err
	}
	if first != second {
		return fmt.Errorf("first %d, second %d", first, second)
	}
	return wantDnsSerial(ctx, store, root, first)
}

func caseDnsRestoreRefusals(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if _, err := store.CommitRestore(ctx, root, sidecar.NewId(), 0); !errors.Is(err, dnsservice.ErrDnsNotRestoring) {
		return fmt.Errorf("a restore with restoring clear answered %v", err)
	}
	if err := store.SetRestoring(ctx, root, true); err != nil {
		return err
	}
	if _, err := store.CommitRestore(ctx, root, sidecar.NewId(), 0); err != nil {
		return err
	}
	if _, err := store.CommitRestore(ctx, root, sidecar.NewId(), 0); !errors.Is(err, dnsservice.ErrDnsRestoreIncident) {
		return fmt.Errorf("a second incident answered %v", err)
	}
	return nil
}

func caseDnsRestoringForgetsIncident(ctx context.Context, store dnsservice.DnsStore, root string) error {
	if err := store.SetRestoring(ctx, root, true); err != nil {
		return err
	}
	if _, err := store.CommitRestore(ctx, root, sidecar.NewId(), 0); err != nil {
		return err
	}
	// a rerun of the step keeps what the transaction recorded
	if err := store.SetRestoring(ctx, root, true); err != nil {
		return err
	}
	state, err := store.RootState(ctx, root)
	if err != nil {
		return err
	}
	if state.RestoreIncidentId == nil {
		return errors.New("setting restoring again forgot the incident")
	}
	if err := store.SetRestoring(ctx, root, false); err != nil {
		return err
	}
	state, err = store.RootState(ctx, root)
	if err != nil {
		return err
	}
	if state.RestoreIncidentId == nil {
		return errors.New("clearing restoring forgot the incident")
	}
	if err := store.SetRestoring(ctx, root, true); err != nil {
		return err
	}
	state, err = store.RootState(ctx, root)
	if err != nil {
		return err
	}
	if state.RestoreIncidentId != nil {
		return fmt.Errorf("a new restoring reads incident %v, so a reload would run before its transaction", state.RestoreIncidentId)
	}
	return nil
}

func caseDnsCompareAndSwap(ctx context.Context, store dnsservice.DnsStore, root string) error {
	networkId := sidecar.NewId()
	stale := uint64(99)
	write := dnsSuiteWrite(root, "a", "one")
	write.NetworkId = networkId
	write.ExpectVersion = &stale
	if _, err := store.Write(ctx, write); !errors.Is(err, dnsservice.ErrDnsVersionConflict) {
		return fmt.Errorf("a stale version answered %v", err)
	}
	if err := wantDnsSerial(ctx, store, root, 0); err != nil {
		return err
	}
	if err := wantDnsJournalRows(ctx, store, root, 0, 0); err != nil {
		return err
	}
	fresh := uint64(0)
	write.ExpectVersion = &fresh
	serial, err := store.Write(ctx, write)
	if err != nil {
		return err
	}
	// the version it just read is now out of date
	if _, err := store.Write(ctx, write); !errors.Is(err, dnsservice.ErrDnsVersionConflict) {
		return fmt.Errorf("a repeated version answered %v", err)
	}
	write.ExpectVersion = &serial
	if _, err := store.Write(ctx, write); err != nil {
		return err
	}
	return nil
}

func caseDnsZoneVersion(ctx context.Context, store dnsservice.DnsStore, root string) error {
	networkId := sidecar.NewId()
	otherNetworkId := sidecar.NewId()
	version, err := store.ZoneVersion(ctx, root, networkId)
	if err != nil {
		return err
	}
	if version != 0 {
		return fmt.Errorf("a new zone at version %d", version)
	}
	write := dnsSuiteWrite(root, "a", "one")
	write.NetworkId = networkId
	if _, err := store.Write(ctx, write); err != nil {
		return err
	}
	otherWrite := dnsSuiteWrite(root, "b", "two")
	otherWrite.NetworkId = otherNetworkId
	otherSerial, err := store.Write(ctx, otherWrite)
	if err != nil {
		return err
	}
	if version, err = store.ZoneVersion(ctx, root, networkId); err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("zone at version %d after another zone's write", version)
	}
	if version, err = store.ZoneVersion(ctx, root, otherNetworkId); err != nil {
		return err
	}
	if version != otherSerial {
		return fmt.Errorf("other zone at version %d", version)
	}
	return nil
}

func caseDnsReloadDiffs(ctx context.Context, store dnsservice.DnsStore, root string) error {
	diff := &dnsservice.DnsReloadDiff{
		Root:           root,
		ReplacedSerial: 3,
		Serial:         dnsservice.DnsRestoreSerialJump + 3,
		Rrsets:         []dnsservice.DnsRecordKey{{Owner: "a." + root, Type: dns.TypeTXT}},
	}
	if err := store.RecordReloadDiff(ctx, diff); err != nil {
		return err
	}
	diffs, err := store.ReloadDiffs(ctx, root)
	if err != nil {
		return err
	}
	if len(diffs) != 1 || diffs[0].ReplacedSerial != 3 || !slices.Equal(diffs[0].Rrsets, diff.Rrsets) {
		return fmt.Errorf("diffs %+v", diffs)
	}
	return nil
}

func caseDnsSerialRaised(ctx context.Context, store dnsservice.DnsStore, root string) error {
	raised := store.SerialRaised(root)
	serial, err := store.Write(ctx, dnsSuiteWrite(root, "a", "one"))
	if err != nil {
		return err
	}
	select {
	case <-raised:
	case <-ctx.Done():
		return fmt.Errorf("no wake for serial %d: %w", serial, ctx.Err())
	}
	return nil
}
