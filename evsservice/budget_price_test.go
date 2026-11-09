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
