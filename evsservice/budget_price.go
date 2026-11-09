// §11.13's cost rows: what each write costs each drive of a metadata cluster, before it is issued. A
// write's priced bytes are the rows' figures for what it does; the governor's calibration k, measured
// over priced bytes, turns them into drive bytes, so a table that is off by a constant factor costs
// nothing but k (§11.13's price row).
//
// Every drive takes every metadata write at EC:4 on eight drives, so a row is per drive. Objects up to
// SmallObjectByteCount cost the row as it stands: §11.13's inferred figures for objects under ~14 KiB on
// 4 KiB XFS blocks, a create ~9 KiB, an overwrite ~14 KiB (the old xl.meta written again) and a delete
// ~3.5 KiB, and on 1 KiB blocks the head's overwrite ~10.5 KiB. A larger object adds its shard of the
// bytes past that size, a quarter of them, rounded up to the block. A GET or LIST costs nothing.
//
// The figures are inferred until §22.8's nvme run measures the table on the PM9A3 set and chooses the
// block size (D-TEST-11), which replaces the defaults below in config. 1 KiB blocks' create and delete
// rows are not in §11.13: they are the 4 KiB rows scaled by its push figures, ~33 KiB a push against
// ~43, until the run measures them.

package evsservice

import (
	"errors"
	"fmt"
	"math"

	"github.com/urnetwork/sidecar"
)

// What a write does to an object.
type WriteOperationKind int

const (
	WriteOperationCreate    WriteOperationKind = 1
	WriteOperationOverwrite WriteOperationKind = 2
	WriteOperationDelete    WriteOperationKind = 3
)

// One kind of write, as many times as Count says.
type WriteOperation struct {
	Kind WriteOperationKind
	// The object's size, for a create or an overwrite. A delete's does not count.
	ObjectByteCount int64
	// How many: a share is a fraction, as §11.13's push row counts 1 batch share, ~0.9 folded entries
	// and 0.2 slots.
	Count float64
}

// A push's writes, split by when they are issued (§11.13's price and accounts rows).
type PushOperations struct {
	// What the push writes now: its head's overwrite, its batch share, slots, a part's batch record, a
	// marker.
	Immediate []WriteOperation
	// The P2 work it causes: its fold's entry writes, its batch's delete at evacuation, parcel and pidx/
	// writes, its purge.
	Deferred []WriteOperation
}

// §11.13's cost rows for one XFS block size, in drive bytes per drive. Immutable once built.
type PriceTable struct {
	// The XFS block size the rows are for.
	BlockByteCount int64
	// Objects up to this size cost their row as it stands: ~14 KiB.
	SmallObjectByteCount int64
	CreateByteCount      int64
	OverwriteByteCount   int64
	DeleteByteCount      int64
	// What a larger object's bytes past SmallObjectByteCount spread over: EC:4's four data shards.
	ShardCount int64
}

// The 4 KiB block table: §11.13's inferred figures.
func DefaultPriceTable4KiB() *PriceTable {
	return &PriceTable{
		BlockByteCount:       4 * 1024,
		SmallObjectByteCount: 14 * 1024,
		CreateByteCount:      9 * 1024,
		OverwriteByteCount:   14 * 1024,
		DeleteByteCount:      3584,
		ShardCount:           4,
	}
}

// The 1 KiB block table: §11.13's head overwrite, its create and delete scaled as the file header says.
func DefaultPriceTable1KiB() *PriceTable {
	return &PriceTable{
		BlockByteCount:       1024,
		SmallObjectByteCount: 14 * 1024,
		CreateByteCount:      7 * 1024,
		OverwriteByteCount:   10752,
		DeleteByteCount:      2816,
		ShardCount:           4,
	}
}

// A block size the defaults have no table for.
var ErrPriceTableBlockSize = errors.New("no price table for this block size")

// An operation the table cannot price.
var ErrWriteOperation = errors.New("write operation invalid")

// The default table for an XFS block size, 1 KiB or 4 KiB.
func DefaultPriceTable(blockByteCount int64) (*PriceTable, error) {
	switch blockByteCount {
	case 1024:
		return DefaultPriceTable1KiB(), nil
	case 4 * 1024:
		return DefaultPriceTable4KiB(), nil
	}
	return nil, fmt.Errorf("%w: %d", ErrPriceTableBlockSize, blockByteCount)
}

// What an object's bytes past the small rows add to each drive: its shard, rounded up to the block.
func (self *PriceTable) largeObjectByteCount(objectByteCount int64) int64 {
	if objectByteCount <= self.SmallObjectByteCount {
		return 0
	}
	shardByteCount := (objectByteCount - self.SmallObjectByteCount + self.ShardCount - 1) / self.ShardCount
	return (shardByteCount + self.BlockByteCount - 1) / self.BlockByteCount * self.BlockByteCount
}

// One operation's priced bytes, all of its Count, rounded up.
func (self *PriceTable) Price(operation WriteOperation) (int64, error) {
	if operation.Count < 0 || math.IsNaN(operation.Count) || math.IsInf(operation.Count, 0) || operation.ObjectByteCount < 0 {
		return 0, fmt.Errorf("%w: %+v", ErrWriteOperation, operation)
	}
	var each int64
	switch operation.Kind {
	case WriteOperationCreate:
		each = self.CreateByteCount + self.largeObjectByteCount(operation.ObjectByteCount)
	case WriteOperationOverwrite:
		each = self.OverwriteByteCount + self.largeObjectByteCount(operation.ObjectByteCount)
	case WriteOperationDelete:
		each = self.DeleteByteCount
	default:
		return 0, fmt.Errorf("%w: kind %d", ErrWriteOperation, operation.Kind)
	}
	return int64(math.Ceil(float64(each) * operation.Count)), nil
}

// The sum of operations' prices.
func (self *PriceTable) PriceOperations(operations []WriteOperation) (int64, error) {
	var byteCount int64
	for _, operation := range operations {
		price, err := self.Price(operation)
		if err != nil {
			return 0, err
		}
		byteCount += price
	}
	return byteCount, nil
}

// A push's cost: its immediate writes and the P2 work it causes, which AdmitP1 debits together and
// whose deferred part moves into the wallet.
func PricePush(table *PriceTable, operations *PushOperations) (sidecar.WriteCost, error) {
	immediateByteCount, err := table.PriceOperations(operations.Immediate)
	if err != nil {
		return sidecar.WriteCost{}, err
	}
	deferredByteCount, err := table.PriceOperations(operations.Deferred)
	if err != nil {
		return sidecar.WriteCost{}, err
	}
	return sidecar.WriteCost{ImmediateByteCount: immediateByteCount, DeferredByteCount: deferredByteCount}, nil
}
