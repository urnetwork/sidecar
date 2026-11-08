// The conformance suite for mxedgeservice.MxEdgeStore (§15.15; MAIL-M7-21): what store.go promises,
// run on FakeMxEdgeStore here and on server's model.NewMxEdgeStore, so the fake stays honest (D-TEST-2).
// The interface writes and never reads, so each store comes with a reader of its own rows, a test's
// window onto what landed. Every case uses networks of its own, so one store serves the whole run and a
// shared database's other rows change no verdict.
//
// Times are near the real clock and whole microseconds, as Postgres keeps them, since a store may refuse
// a record of an hour it has already retired or of one far ahead.
//
// A case is a plain function returning its first failure, and RunMxEdgeStoreSuite loops over them, as
// blobsuite does (connect/CODESTYLE.md:216). A failure in one does not stop the next.

package sidecartest

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
)

// How long one case may wait on a store before it fails. Real time, so only ever a failure's bound
// (§22.8): nothing here sleeps.
const mxEdgeSuiteCaseTimeout = 30 * time.Second

// What a store's own test reads back: networkId's records starting at since or later, in any order.
type MxEdgeStoreReadFunction func(ctx context.Context, networkId sidecar.Id, since time.Time) ([]*mxedgeservice.MxConnectionRecord, error)

type mxEdgeSuiteCase struct {
	name string
	run  func(ctx context.Context, store mxedgeservice.MxEdgeStore, read MxEdgeStoreReadFunction) error
}

// Runs every case on store, reading back through read.
func RunMxEdgeStoreSuite(t testing.TB, store mxedgeservice.MxEdgeStore, read MxEdgeStoreReadFunction) {
	t.Helper()
	for _, suiteCase := range mxEdgeSuiteCases() {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), mxEdgeSuiteCaseTimeout)
			defer cancel()
			if err := suiteCase.run(ctx, store, read); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

func mxEdgeSuiteCases() []mxEdgeSuiteCase {
	return []mxEdgeSuiteCase{
		{name: "ping answers", run: caseMxEdgePing},
		{name: "a batch's records land as given", run: caseMxEdgeBatchLands},
		{name: "an empty batch answers and stores nothing", run: caseMxEdgeEmptyBatch},
		{name: "two networks' records stay apart", run: caseMxEdgeNetworksApart},
		{name: "records either side of an hour's start both land", run: caseMxEdgeAcrossAnHour},
		{name: "a session that passed no bytes lands", run: caseMxEdgeZeroBytes},
	}
}

// A minute ago, to the microsecond.
func mxEdgeSuiteNow() time.Time {
	return time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
}

// A record of networkId.
func mxEdgeSuiteRecord(networkId sidecar.Id, startTime time.Time, byteCount int64, result string) *mxedgeservice.MxConnectionRecord {
	return &mxedgeservice.MxConnectionRecord{
		NetworkId: networkId,
		StartTime: startTime,
		ByteCount: byteCount,
		Result:    result,
	}
}

// A record's fields as one comparable line, its time in UTC.
func mxEdgeSuiteKey(record *mxedgeservice.MxConnectionRecord) string {
	return fmt.Sprintf("%s %s %d %s", record.NetworkId, record.StartTime.UTC().Format(time.RFC3339Nano), record.ByteCount, record.Result)
}

// Whether got holds exactly want's records, in any order.
func mxEdgeSuiteSameRecords(got []*mxedgeservice.MxConnectionRecord, want []*mxedgeservice.MxConnectionRecord) error {
	gotKeys := []string{}
	for _, record := range got {
		gotKeys = append(gotKeys, mxEdgeSuiteKey(record))
	}
	wantKeys := []string{}
	for _, record := range want {
		wantKeys = append(wantKeys, mxEdgeSuiteKey(record))
	}
	slices.Sort(gotKeys)
	slices.Sort(wantKeys)
	if !slices.Equal(gotKeys, wantKeys) {
		return fmt.Errorf("read %v, want %v", gotKeys, wantKeys)
	}
	return nil
}

func caseMxEdgePing(ctx context.Context, store mxedgeservice.MxEdgeStore, read MxEdgeStoreReadFunction) error {
	return store.Ping(ctx)
}

func caseMxEdgeBatchLands(ctx context.Context, store mxedgeservice.MxEdgeStore, read MxEdgeStoreReadFunction) error {
	networkId := sidecar.NewId()
	now := mxEdgeSuiteNow()
	records := []*mxedgeservice.MxConnectionRecord{
		mxEdgeSuiteRecord(networkId, now.Add(-3*time.Second), 4096, "spliced"),
		mxEdgeSuiteRecord(networkId, now.Add(-2*time.Second), 512, "closed_handshake"),
		mxEdgeSuiteRecord(networkId, now.Add(-time.Second), 70000, "spliced"),
	}
	if err := store.InsertConnectionRecords(ctx, records); err != nil {
		return err
	}
	got, err := read(ctx, networkId, now.Add(-time.Minute))
	if err != nil {
		return err
	}
	return mxEdgeSuiteSameRecords(got, records)
}

func caseMxEdgeEmptyBatch(ctx context.Context, store mxedgeservice.MxEdgeStore, read MxEdgeStoreReadFunction) error {
	if err := store.InsertConnectionRecords(ctx, nil); err != nil {
		return err
	}
	return store.InsertConnectionRecords(ctx, []*mxedgeservice.MxConnectionRecord{})
}

func caseMxEdgeNetworksApart(ctx context.Context, store mxedgeservice.MxEdgeStore, read MxEdgeStoreReadFunction) error {
	networkId := sidecar.NewId()
	otherNetworkId := sidecar.NewId()
	now := mxEdgeSuiteNow()
	mine := mxEdgeSuiteRecord(networkId, now, 100, "spliced")
	other := mxEdgeSuiteRecord(otherNetworkId, now, 200, "spliced")
	if err := store.InsertConnectionRecords(ctx, []*mxedgeservice.MxConnectionRecord{mine, other}); err != nil {
		return err
	}
	got, err := read(ctx, networkId, now.Add(-time.Minute))
	if err != nil {
		return err
	}
	if err := mxEdgeSuiteSameRecords(got, []*mxedgeservice.MxConnectionRecord{mine}); err != nil {
		return err
	}
	got, err = read(ctx, otherNetworkId, now.Add(-time.Minute))
	if err != nil {
		return err
	}
	return mxEdgeSuiteSameRecords(got, []*mxedgeservice.MxConnectionRecord{other})
}

func caseMxEdgeAcrossAnHour(ctx context.Context, store mxedgeservice.MxEdgeStore, read MxEdgeStoreReadFunction) error {
	networkId := sidecar.NewId()
	hourStart := mxEdgeSuiteNow().Truncate(time.Hour)
	records := []*mxedgeservice.MxConnectionRecord{
		mxEdgeSuiteRecord(networkId, hourStart.Add(-time.Microsecond), 10, "spliced"),
		mxEdgeSuiteRecord(networkId, hourStart, 20, "spliced"),
	}
	if err := store.InsertConnectionRecords(ctx, records); err != nil {
		return err
	}
	got, err := read(ctx, networkId, hourStart.Add(-time.Hour))
	if err != nil {
		return err
	}
	return mxEdgeSuiteSameRecords(got, records)
}

func caseMxEdgeZeroBytes(ctx context.Context, store mxedgeservice.MxEdgeStore, read MxEdgeStoreReadFunction) error {
	networkId := sidecar.NewId()
	now := mxEdgeSuiteNow()
	record := mxEdgeSuiteRecord(networkId, now, 0, "closed_handshake")
	if err := store.InsertConnectionRecords(ctx, []*mxedgeservice.MxConnectionRecord{record}); err != nil {
		return err
	}
	got, err := read(ctx, networkId, now.Add(-time.Minute))
	if err != nil {
		return err
	}
	return mxEdgeSuiteSameRecords(got, []*mxedgeservice.MxConnectionRecord{record})
}
