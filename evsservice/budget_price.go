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
//
// Beside the cost rows are §11.13's format-2 event rows (EVSB-M10-08; R-EVS-24, D-TEST-13, D-TEST-17): an
// indexed push, a companion push, a team directory push and a drop, each the operations one event writes,
// which the table prices as it prices any write (PriceRow), so a measured table prices them too. Their
// operations are §11.13's inferred figures (PriceRowSettings) until §22.8's M10 index, directory and drop
// rows count them on T3; D-TEST-13's projection reads those counts in their place and never takes these
// rows as its evidence.

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
	// Bytes staged inside an object another operation writes, as an indexed push's index head rides its
	// batch record (§11.13's indexed push row): their shard, rounded up to the block, with no row of their
	// own, since the object's own write is priced where it is counted.
	WriteOperationStaged WriteOperationKind = 4
)

// One kind of write, as many times as Count says.
type WriteOperation struct {
	Kind WriteOperationKind
	// The object's size, for a create or an overwrite, and the bytes staged, for a staged write. A delete's
	// does not count.
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
	return self.shardByteCount(objectByteCount - self.SmallObjectByteCount)
}

// What byteCount spread over the shards writes on each drive, rounded up to the block.
func (self *PriceTable) shardByteCount(byteCount int64) int64 {
	if byteCount <= 0 {
		return 0
	}
	shardByteCount := (byteCount + self.ShardCount - 1) / self.ShardCount
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
	case WriteOperationStaged:
		each = self.shardByteCount(operation.ObjectByteCount)
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

// One of §11.13's format-2 event rows (see the file header), by the name reports and measurement files give it.
type PriceEvent string

const (
	// What an in-ref indexed push adds to its own push: its index head staged in its batch, the head's entry
	// once a fold, a seal per ~14 pushes and its share of a merge, one push and a <= 1 MiB HDD shard per ~128
	// KiB of entries (§11.13's indexed push row; §11.15: ~7 KiB a drive on 4 KiB blocks, ~4.3 on 1 KiB).
	PriceEventIndexedPush PriceEvent = "indexed_push"
	// A git-mode ref's or record stream's companion push on ur/index: a one-change push whose record stages
	// the index head (owner decision 172's cadence is the mix's, not the row's).
	PriceEventCompanionPush PriceEvent = "companion_push"
	// §16.11's team directory pushes, each as a push (§11.13's directory row, per drive on 4 KiB blocks): a
	// card's content change ~55 KiB with its index head's entry at folds, a renewal ~37, a notice created ~46,
	// rewritten ~37 and removed ~53 with its marker.
	PriceEventDirectoryCardChange    PriceEvent = "directory_card_change"
	PriceEventDirectoryCardRenewal   PriceEvent = "directory_card_renewal"
	PriceEventDirectoryNoticeCreate  PriceEvent = "directory_notice_create"
	PriceEventDirectoryNoticeRewrite PriceEvent = "directory_notice_rewrite"
	PriceEventDirectoryNoticeRemove  PriceEvent = "directory_notice_remove"
	// A DROP push as a push (~27-43 KiB, its written version's fold included), its index rewrites as an
	// indexed push's.
	PriceEventDropPush PriceEvent = "drop_push"
	// Its append to drops/<repo>/_, ~14-22 KiB.
	PriceEventDropTableAppend PriceEvent = "drop_table_append"
	// A running job's minute: its one overwrite of the table (~1.3 MB a job-hour) and the dropscan/ file its
	// checkpoint writes on the segment cluster.
	PriceEventDropJobMinute PriceEvent = "drop_job_minute"
	// One slot DELETE of a job, ~3.5 KiB.
	PriceEventDropSlotDelete PriceEvent = "drop_slot_delete"
)

// One event's writes: on the metadata cluster, its own and the P2 work it causes, and the segment cluster's
// PUTs and DELETEs, which spend no NVMe budget (§11.13's hdd row) and which the row counts by object.
type PriceRow struct {
	Event      PriceEvent
	Operations PushOperations
	// Whole objects the event writes or deletes on the segment cluster.
	HddPutCount    float64
	HddDeleteCount float64
}

// The figures the format-2 rows are built from: §11.13's, §11.15's and §16.11's inferred ones, until §22.8's
// M10 rows count them on T3. DefaultPriceRowSettings is their only source.
type PriceRowSettings struct {
	// A row's push: its head and its batch record, both under the small rows: 2 KiB and 4 KiB.
	PushHeadByteCount   int64
	PushRecordByteCount int64
	// The entry writes a push's fold makes for each path it changed: 0.3, §11.13's ~0.9 folded entries for
	// k = 3 entry writes.
	PushFoldShare float64
	// A batch's parcels a push, ~0.01 (§11.13's evacuation row), and its share of a log page, 1/64 of one
	// LogPageByteCount create: 16 KiB.
	PushParcelShare  float64
	PushLogPageShare float64
	LogPageByteCount int64
	// An indexed push's index head, which its batch record stages: 12 KiB, ~3 KiB a drive at four shards.
	IndexHeadByteCount int64
	// The head's entry once a fold: an entry overwrite at this share of the indexed pushes, 0.1.
	IndexEntryFoldShare float64
	// A seal per this many indexed pushes, each adding one slot of IndexSealByteCount: 14 and 12 KiB.
	IndexSealPushCount float64
	IndexSealByteCount int64
	// A merge, one push and one HDD shard, per IndexMergeEntryByteCount of entries, of which an indexed push
	// writes IndexEntryByteCount: 128 KiB and 3 KiB.
	IndexMergeEntryByteCount int64
	IndexEntryByteCount      int64
	// A notice's created path takes its idx/ entry as a create at its fold, beyond the push's overwrite
	// share: 0.7 of one.
	DirectoryCreateShare float64
	// drops/<repo>/_ as an append and a running job overwrite it: 32 KiB, inside §11.8's 64 KiB bound.
	DropTableByteCount int64
	// The dropscan/ files a running job's checkpoint writes a minute on the segment cluster: 1.
	DropCheckpointFileCount float64
}

func DefaultPriceRowSettings() *PriceRowSettings {
	return &PriceRowSettings{
		PushHeadByteCount:        2 * 1024,
		PushRecordByteCount:      4 * 1024,
		PushFoldShare:            0.3,
		PushParcelShare:          0.01,
		PushLogPageShare:         1.0 / 64,
		LogPageByteCount:         16 * 1024,
		IndexHeadByteCount:       12 * 1024,
		IndexEntryFoldShare:      0.1,
		IndexSealPushCount:       14,
		IndexSealByteCount:       12 * 1024,
		IndexMergeEntryByteCount: 128 * 1024,
		IndexEntryByteCount:      3 * 1024,
		DirectoryCreateShare:     0.7,
		DropTableByteCount:       32 * 1024,
		DropCheckpointFileCount:  1,
	}
}

// Settings no row can be built from.
var ErrPriceRowSettings = errors.New("price row settings invalid")

func (self *PriceRowSettings) validate() error {
	switch {
	case self.IndexSealPushCount <= 0 || self.IndexMergeEntryByteCount <= 0:
		return fmt.Errorf("%w: a seal every %v pushes, a merge every %d B", ErrPriceRowSettings, self.IndexSealPushCount, self.IndexMergeEntryByteCount)
	case self.PushHeadByteCount < 0 || self.PushRecordByteCount < 0 || self.LogPageByteCount < 0 || self.IndexHeadByteCount < 0 ||
		self.IndexSealByteCount < 0 || self.IndexEntryByteCount < 0 || self.DropTableByteCount < 0:
		return fmt.Errorf("%w: a size below zero", ErrPriceRowSettings)
	case self.PushFoldShare < 0 || self.PushParcelShare < 0 || self.PushLogPageShare < 0 || self.IndexEntryFoldShare < 0 ||
		self.DirectoryCreateShare < 0 || self.DropCheckpointFileCount < 0:
		return fmt.Errorf("%w: a share below zero", ErrPriceRowSettings)
	}
	return nil
}

// §11.13's push row for a push of changeCount entry writes at one record a batch: now its head's overwrite
// and its batch share; deferred its fold share, its batch's DELETE at evacuation, its share of a parcel, its
// pidx/ entry and its share of a log page.
func (self *PriceRowSettings) pushOperations(changeCount float64) PushOperations {
	return PushOperations{
		Immediate: []WriteOperation{
			{Kind: WriteOperationOverwrite, ObjectByteCount: self.PushHeadByteCount, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: self.PushRecordByteCount, Count: 1},
		},
		Deferred: []WriteOperation{
			{Kind: WriteOperationOverwrite, Count: self.PushFoldShare * changeCount},
			{Kind: WriteOperationDelete, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: self.PushRecordByteCount, Count: self.PushParcelShare},
			{Kind: WriteOperationCreate, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: self.LogPageByteCount, Count: self.PushLogPageShare},
		},
	}
}

// What an in-ref indexed push adds to its own push, and the HDD shard PUTs its merges write.
func (self *PriceRowSettings) indexedOperations() (PushOperations, float64) {
	mergeShare := float64(self.IndexEntryByteCount) / float64(self.IndexMergeEntryByteCount)
	merge := scaledPushOperations(self.pushOperations(1), mergeShare)
	return PushOperations{
		Immediate: append([]WriteOperation{
			{Kind: WriteOperationStaged, ObjectByteCount: self.IndexHeadByteCount, Count: 1},
			{Kind: WriteOperationCreate, ObjectByteCount: self.IndexSealByteCount, Count: 1 / self.IndexSealPushCount},
		}, merge.Immediate...),
		Deferred: append([]WriteOperation{
			{Kind: WriteOperationOverwrite, Count: self.IndexEntryFoldShare},
		}, merge.Deferred...),
	}, mergeShare
}

// operations with every count times share.
func scaledPushOperations(operations PushOperations, share float64) PushOperations {
	scale := func(from []WriteOperation) []WriteOperation {
		to := make([]WriteOperation, 0, len(from))
		for _, operation := range from {
			operation.Count *= share
			to = append(to, operation)
		}
		return to
	}
	return PushOperations{Immediate: scale(operations.Immediate), Deferred: scale(operations.Deferred)}
}

// The operations of a and then b, now and deferred.
func joinedPushOperations(a PushOperations, b PushOperations) PushOperations {
	return PushOperations{
		Immediate: append(append([]WriteOperation{}, a.Immediate...), b.Immediate...),
		Deferred:  append(append([]WriteOperation{}, a.Deferred...), b.Deferred...),
	}
}

// Every format-2 row, in §11.13's order, built from settings (nil takes the defaults).
func PriceRows(settings *PriceRowSettings) ([]*PriceRow, error) {
	if settings == nil {
		settings = DefaultPriceRowSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	indexed, mergeShare := settings.indexedOperations()
	oneChange := settings.pushOperations(1)
	table := []WriteOperation{{Kind: WriteOperationOverwrite, ObjectByteCount: settings.DropTableByteCount, Count: 1}}
	return []*PriceRow{
		{Event: PriceEventIndexedPush, Operations: indexed, HddPutCount: mergeShare},
		{Event: PriceEventCompanionPush, Operations: joinedPushOperations(oneChange, PushOperations{
			Immediate: []WriteOperation{{Kind: WriteOperationStaged, ObjectByteCount: settings.IndexHeadByteCount, Count: 1}},
		})},
		// the card file and its index head, the head's other writes as an indexed push's
		{Event: PriceEventDirectoryCardChange, Operations: joinedPushOperations(settings.pushOperations(2), indexed), HddPutCount: mergeShare},
		{Event: PriceEventDirectoryCardRenewal, Operations: oneChange},
		{Event: PriceEventDirectoryNoticeCreate, Operations: joinedPushOperations(oneChange, PushOperations{
			Deferred: []WriteOperation{{Kind: WriteOperationCreate, Count: settings.DirectoryCreateShare}},
		})},
		{Event: PriceEventDirectoryNoticeRewrite, Operations: oneChange},
		// its marker, written at its fold, and the marker's collection
		{Event: PriceEventDirectoryNoticeRemove, Operations: joinedPushOperations(oneChange, PushOperations{
			Deferred: []WriteOperation{{Kind: WriteOperationOverwrite, Count: 1}, {Kind: WriteOperationDelete, Count: 1}},
		})},
		{Event: PriceEventDropPush, Operations: joinedPushOperations(oneChange, indexed), HddPutCount: mergeShare},
		{Event: PriceEventDropTableAppend, Operations: PushOperations{Immediate: table}},
		{Event: PriceEventDropJobMinute, Operations: PushOperations{Immediate: table}, HddPutCount: settings.DropCheckpointFileCount},
		{Event: PriceEventDropSlotDelete, Operations: PushOperations{Immediate: []WriteOperation{{Kind: WriteOperationDelete, Count: 1}}}},
	}, nil
}

// No row for the event asked.
var ErrPriceEvent = errors.New("no such price row")

// The row of rows for event.
func PriceRowOf(rows []*PriceRow, event PriceEvent) (*PriceRow, error) {
	for _, row := range rows {
		if row.Event == event {
			return row, nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrPriceEvent, event)
}

// A row's metadata writes in this table's priced bytes, now and deferred.
func (self *PriceTable) PriceRow(row *PriceRow) (sidecar.WriteCost, error) {
	return PricePush(self, &row.Operations)
}
