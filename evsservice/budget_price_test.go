package evsservice

import (
	"errors"
	"math"
	"testing"

	"github.com/urnetwork/sidecar"
)

// §11.13's rows for objects under ~14 KiB on 4 KiB blocks, and a larger object's shard on top.
func TestPriceTableHoldsTheCostRows(t *testing.T) {
	table, err := DefaultPriceTable(4 * 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		operation WriteOperation
		want      int64
	}{
		{operation: WriteOperation{Kind: WriteOperationCreate, ObjectByteCount: 2000, Count: 1}, want: 9 * 1024},
		{operation: WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: 14 * 1024, Count: 1}, want: 14 * 1024},
		{operation: WriteOperation{Kind: WriteOperationDelete, Count: 1}, want: 3584},
		// 16 KiB past the small rows is a 4 KiB shard on each drive
		{operation: WriteOperation{Kind: WriteOperationCreate, ObjectByteCount: 30 * 1024, Count: 1}, want: 13 * 1024},
		// a shard of a byte still takes a block
		{operation: WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: 14*1024 + 1, Count: 1}, want: 18 * 1024},
		// 0.2 slots a push
		{operation: WriteOperation{Kind: WriteOperationCreate, ObjectByteCount: 100, Count: 0.2}, want: int64(math.Ceil(0.2 * 9 * 1024))},
		{operation: WriteOperation{Kind: WriteOperationCreate, ObjectByteCount: 100, Count: 0}, want: 0},
	} {
		price, err := table.Price(c.operation)
		if err != nil || price != c.want {
			t.Errorf("%+v: %d, %v, want %d", c.operation, price, err, c.want)
		}
	}
	oneKiB, err := DefaultPriceTable(1024)
	if err != nil {
		t.Fatal(err)
	}
	// the head's overwrite on 1 KiB blocks, ~10.5 KiB
	if price, _ := oneKiB.Price(WriteOperation{Kind: WriteOperationOverwrite, ObjectByteCount: 1000, Count: 1}); price != 10752 {
		t.Errorf("1 KiB overwrite %d", price)
	}
	if _, err := DefaultPriceTable(2048); !errors.Is(err, ErrPriceTableBlockSize) {
		t.Errorf("2 KiB blocks: %v", err)
	}
}

// A push's writes now are its immediate cost, and the P2 work it causes its deferred cost.
func TestPricePushSplitsImmediateAndDeferred(t *testing.T) {
	table := DefaultPriceTable4KiB()
	cost, err := PricePush(table, &PushOperations{
		Immediate: []WriteOperation{
			{Kind: WriteOperationOverwrite, ObjectByteCount: 1500, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: 3000, Count: 1},
		},
		Deferred: []WriteOperation{
			{Kind: WriteOperationCreate, ObjectByteCount: 800, Count: 1},
			{Kind: WriteOperationDelete, Count: 1},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := sidecar.WriteCost{ImmediateByteCount: 14*1024 + 9*1024, DeferredByteCount: 9*1024 + 3584}
	if cost != want || cost.ByteCount() != want.ImmediateByteCount+want.DeferredByteCount {
		t.Errorf("cost %+v, want %+v", cost, want)
	}
}

func TestPriceTableRefusesWhatItCannotPrice(t *testing.T) {
	table := DefaultPriceTable4KiB()
	for _, operation := range []WriteOperation{
		{Kind: WriteOperationCreate, ObjectByteCount: 10, Count: -1},
		{Kind: WriteOperationCreate, ObjectByteCount: -10, Count: 1},
		{Kind: WriteOperationCreate, ObjectByteCount: 10, Count: math.NaN()},
		{Kind: WriteOperationCreate, ObjectByteCount: 10, Count: math.Inf(1)},
		{Kind: 0, ObjectByteCount: 10, Count: 1},
	} {
		if _, err := table.Price(operation); !errors.Is(err, ErrWriteOperation) {
			t.Errorf("%+v: %v", operation, err)
		}
	}
	if _, err := PricePush(table, &PushOperations{Deferred: []WriteOperation{{Kind: 9, Count: 1}}}); !errors.Is(err, ErrWriteOperation) {
		t.Errorf("a push with an unknown kind: %v", err)
	}
}

// Staged bytes cost their shard, rounded up to the block, and nothing more.
func TestPriceTablePricesStagedBytesAtTheirShard(t *testing.T) {
	for _, c := range []struct {
		table     *PriceTable
		byteCount int64
		want      int64
	}{
		{table: DefaultPriceTable4KiB(), byteCount: 12 * 1024, want: 4 * 1024},
		{table: DefaultPriceTable4KiB(), byteCount: 16*1024 + 1, want: 8 * 1024},
		{table: DefaultPriceTable1KiB(), byteCount: 12 * 1024, want: 3 * 1024},
		{table: DefaultPriceTable1KiB(), byteCount: 1, want: 1024},
		{table: DefaultPriceTable4KiB(), byteCount: 0, want: 0},
	} {
		price, err := c.table.Price(WriteOperation{Kind: WriteOperationStaged, ObjectByteCount: c.byteCount, Count: 1})
		if err != nil || price != c.want {
			t.Errorf("%d B staged on %d B blocks: %d, %v, want %d", c.byteCount, c.table.BlockByteCount, price, err, c.want)
		}
	}
}

// §11.13's format-2 rows price on the 4 KiB table near the figures §11.13, §11.15 and §16.11 give them, every row
// is there once in §11.13's order, and the 1 KiB table prices each for less.
func TestPriceRowsHoldSection11s4KiBFigures(t *testing.T) {
	rows, err := PriceRows(nil)
	if err != nil {
		t.Fatal(err)
	}
	figures := []struct {
		event PriceEvent
		// §11.13's figure in KiB a drive on 4 KiB blocks, and how far the row may sit from it
		kib       float64
		tolerance float64
	}{
		{event: PriceEventIndexedPush, kib: 7, tolerance: 0.15},
		{event: PriceEventCompanionPush, kib: 44, tolerance: 0.15},
		{event: PriceEventDirectoryCardChange, kib: 55, tolerance: 0.15},
		{event: PriceEventDirectoryCardRenewal, kib: 37, tolerance: 0.15},
		{event: PriceEventDirectoryNoticeCreate, kib: 46, tolerance: 0.15},
		{event: PriceEventDirectoryNoticeRewrite, kib: 37, tolerance: 0.15},
		{event: PriceEventDirectoryNoticeRemove, kib: 53, tolerance: 0.15},
		// a push of ~27-43 KiB and an indexed push's ~7
		{event: PriceEventDropPush, kib: 42, tolerance: 0.2},
		// ~14-22 KiB an append, and ~1.3 MB a job-hour
		{event: PriceEventDropTableAppend, kib: 22, tolerance: 0.1},
		{event: PriceEventDropJobMinute, kib: 1.3 * 1000 * 1000 / 60 / 1024, tolerance: 0.1},
		{event: PriceEventDropSlotDelete, kib: 3.5, tolerance: 0.01},
	}
	if len(rows) != len(figures) {
		t.Fatalf("%d rows, want %d", len(rows), len(figures))
	}
	fourKiB, oneKiB := DefaultPriceTable4KiB(), DefaultPriceTable1KiB()
	for i, figure := range figures {
		if rows[i].Event != figure.event {
			t.Fatalf("row %d is %s, want %s", i, rows[i].Event, figure.event)
		}
		row, err := PriceRowOf(rows, figure.event)
		if err != nil {
			t.Fatal(err)
		}
		cost, err := fourKiB.PriceRow(row)
		if err != nil {
			t.Fatal(err)
		}
		kib := float64(cost.ByteCount()) / 1024
		if kib < figure.kib*(1-figure.tolerance) || figure.kib*(1+figure.tolerance) < kib {
			t.Errorf("%s: %.2f KiB a drive on 4 KiB blocks, §11.13's ~%.1f", figure.event, kib, figure.kib)
		}
		small, err := oneKiB.PriceRow(row)
		if err != nil || cost.ByteCount() <= small.ByteCount() {
			t.Errorf("%s: %d B on 1 KiB blocks against %d on 4 KiB: %v", figure.event, small.ByteCount(), cost.ByteCount(), err)
		}
	}
	// the merge's HDD shard rides the indexed rows only, and a job's checkpoint file its minute
	for _, row := range rows {
		hdd := 0 < row.HddPutCount
		want := row.Event == PriceEventIndexedPush || row.Event == PriceEventDirectoryCardChange || row.Event == PriceEventDropPush || row.Event == PriceEventDropJobMinute
		if hdd != want || row.HddDeleteCount != 0 {
			t.Errorf("%s: %v HDD PUTs and %v DELETEs", row.Event, row.HddPutCount, row.HddDeleteCount)
		}
	}
	if _, err := PriceRowOf(rows, "nothing"); !errors.Is(err, ErrPriceEvent) {
		t.Errorf("an unknown event: %v", err)
	}
}

// A row's own writes and the P2 work it causes stay apart: a push's fold, batch DELETE and pidx/ entry are
// deferred, so a P1 admission moves them into the wallet.
func TestPriceRowsSplitImmediateAndDeferred(t *testing.T) {
	rows, err := PriceRows(nil)
	if err != nil {
		t.Fatal(err)
	}
	table := DefaultPriceTable4KiB()
	for _, event := range []PriceEvent{PriceEventCompanionPush, PriceEventDirectoryCardRenewal, PriceEventDropPush} {
		row, _ := PriceRowOf(rows, event)
		cost, err := table.PriceRow(row)
		if err != nil {
			t.Fatal(err)
		}
		// a head's overwrite and a batch record's create now; a fold share, a DELETE and a pidx/ create later
		if cost.ImmediateByteCount < 14*1024+9*1024 || cost.DeferredByteCount < 3584+9*1024 {
			t.Errorf("%s: %+v", event, cost)
		}
	}
	for _, event := range []PriceEvent{PriceEventDropTableAppend, PriceEventDropJobMinute, PriceEventDropSlotDelete} {
		row, _ := PriceRowOf(rows, event)
		if cost, _ := table.PriceRow(row); cost.DeferredByteCount != 0 {
			t.Errorf("%s defers %d B", event, cost.DeferredByteCount)
		}
	}
}

// Settings no row can be built from are refused.
func TestPriceRowsRefuseSettingsTheyCannotUse(t *testing.T) {
	for _, change := range []func(settings *PriceRowSettings){
		func(settings *PriceRowSettings) { settings.IndexSealPushCount = 0 },
		func(settings *PriceRowSettings) { settings.IndexMergeEntryByteCount = 0 },
		func(settings *PriceRowSettings) { settings.IndexHeadByteCount = -1 },
		func(settings *PriceRowSettings) { settings.PushFoldShare = -0.1 },
		func(settings *PriceRowSettings) { settings.DropCheckpointFileCount = -1 },
	} {
		settings := DefaultPriceRowSettings()
		change(settings)
		if _, err := PriceRows(settings); !errors.Is(err, ErrPriceRowSettings) {
			t.Errorf("%+v: %v", settings, err)
		}
	}
}
